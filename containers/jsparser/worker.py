"""ReverseAI jsparser worker: one jsparser.syntax request on /snapshot/input, one reverseai.worker/1 JSON object on stdout.

Entrypoint (docs/contract.md, "JavaScript syntax through a pinned parser (M5b, contract/3)"):
    python3 -I -B /opt/reverseai/worker.py jsparser.syntax <canonical JSON of the request>

The request (decision m5b-seams-w) is {"files": [{"artifact", "dialect"}], "kind", "start", "limit", "callees"}: 1..64
files in the host's order, each a ZIP or ASAR member named by its contract artifact (member, method, data_offset,
compressed_size, size, crc32, sha256; at most 32 MiB in all), a file inside an npm tarball named by a method 1 artifact
(the same keys and inner_offset, decision m5c-contract), or, for a single file, null for the snapshot itself; the
dialect js, jsx, ts or tsx (it fixes the parser plugins); kind modules, calls or parse; the page start and limit; and
the callee entries, sorted, one name or a receiver and a name (decision m5b-callee-suffix). The worker re-materializes
every member from the snapshot into /tmp with a bounded inflate and refuses the run ("input") unless its size, CRC-32
and SHA-256 equal the artifact. A method 1 artifact names a range of the stream obtained by inflating one whole gzip
member at data_offset..data_offset + compressed_size, checked as contract.inflate_stream checks it (header, bounded
chunks within min(128 MiB, 100 x compressed_size), trailer CRC-32 and ISIZE, nothing after it); each distinct stream
is inflated once per run. It then runs the fixed driver baked into the image (Node.js 24.22.1 and @babel/parser
8.0.4, decision m5b-w-plan) with a fixed heap, code generation from strings disallowed, the permission model limited to
reading the driver's folder and the work folder, and a timeout below the 120 s wall. It checks the driver's answer
before emitting one reply whose observations are one row per file in request order (decision m5b-seams-h):
{"file", "status", "errors", "count", "items"}, status ok (errors 0), syntax_error (errors > 0, items allowed),
decode_error exactly when UTF-8 decoding fails, or too_large (over 4 MiB; errors, count 0, no items); items
{"kind", "start", "end"} in UTF-16 units after one leading BOM, sorted by start, end and form, no duplicates, and
together exactly the page the counts define; kind parse has count 0 and no items (decision m5b-seams-h2).
Whole-run failures are the fixed errors "memory", "timeout" and "input"; any other failure is its class name. Nothing
but the one JSON object is written, to stdout only; the driver's stderr is read only for the heap-limit marker.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import zlib

PROTOCOL = "reverseai.worker/1"
ADAPTER_VERSION = "8.0.4-r2"
OPERATION = "jsparser.syntax"
SNAPSHOT = "/snapshot/input"
MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_FILES = 64
MAX_FILE_BYTES = 4 * 1024 * 1024  # larger files are reported too_large, never parsed
MAX_CHILDREN_BYTES = 32 * 1024 * 1024
MAX_RATIO = 100
MAX_START = 1048575
MAX_LIMIT = 256
MAX_CALLEES = 128
MAX_REPLY_BYTES = 262_144
MAX_DRIVER_BYTES = 262_144
DIALECTS = ("js", "jsx", "ts", "tsx")
KINDS = ("modules", "calls", "parse")
STATUSES = ("ok", "syntax_error", "decode_error", "too_large")
FORMS = {"modules": ("import", "export_from", "require", "dynamic_import"), "calls": ("call",), "parse": ()}
ORDER = ("import", "export_from", "require", "dynamic_import", "call")
ARTIFACT_KEYS = frozenset({"member", "method", "data_offset", "compressed_size", "size", "crc32", "sha256"})
GZIP_ARTIFACT_KEYS = ARTIFACT_KEYS | {"inner_offset"}  # method 1 (M5c): a range of an inflated gzip stream
MAX_STREAM_BYTES = 128 * 1024 * 1024
CALLEE = re.compile(r"[$A-Za-z_][$A-Za-z0-9_]{0,63}(?:\.[$A-Za-z_][$A-Za-z0-9_]{0,63})?")
NODE = "/opt/node/bin/node"
DRIVER = "/opt/reverseai/driver.mjs"
WORK = Path("/tmp/reverseai-jsparser")
HEAP_MIB = 1536
DRIVER_SECONDS = 100  # below the 120 s container wall
HEAP_MARKER = b"heap out of memory"
CHUNK = 1 << 20


class WorkerFailure(Exception):
    """Base of every refusal; the reply names the class (or the fixed name below) only."""


class InvalidRequest(WorkerFailure):
    pass


class SnapshotUnreadable(WorkerFailure):
    pass


class InputTooLarge(WorkerFailure):
    pass


class InputMismatch(WorkerFailure):
    """A member does not re-materialize to its artifact: the contract's whole-run error "input"."""


class DriverMemory(WorkerFailure):
    """Node reached its heap limit or was killed for memory: the contract's whole-run error "memory"."""


class DriverTimeout(WorkerFailure):
    """The driver exceeded its time: the contract's whole-run error "timeout"."""


class ParserFailed(WorkerFailure):
    """The driver ended without a well-formed answer."""


class ReplyTooLarge(WorkerFailure):
    pass


FIXED_ERRORS = {InputMismatch: "input", DriverMemory: "memory", DriverTimeout: "timeout"}


def _no_duplicates(pairs):
    if len({key for key, _ in pairs}) != len(pairs):
        raise InvalidRequest()
    return dict(pairs)


def _int(value, low, high):
    return type(value) is int and low <= value <= high


def _artifact(value):
    if not (isinstance(value, dict) and set(value) == (GZIP_ARTIFACT_KEYS if value.get("method") == 1 else ARTIFACT_KEYS)):
        raise InvalidRequest()
    member, method, sha = value["member"], value["method"], value["sha256"]
    if not (isinstance(member, str) and 0 < len(member) <= 255 and member.isprintable()
            and type(method) is int and method in (0, 1, 8)
            and all(_int(value[key], 0, 2**64 - 1)
                    for key in ("data_offset", "compressed_size", "size", "crc32", "inner_offset") if key in value)
            and value["crc32"] < 2**32 and 0 < value["size"] <= MAX_CHILDREN_BYTES
            and isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{64}", sha)):
        raise InvalidRequest()
    if method == 0 and value["compressed_size"] != value["size"]:
        raise InvalidRequest()
    if method == 8 and not (0 < value["compressed_size"] and value["size"] <= MAX_RATIO * value["compressed_size"]):
        raise InvalidRequest()
    if method == 1 and not (18 <= value["compressed_size"]
                            and value["inner_offset"] + value["size"] <= min(MAX_STREAM_BYTES,
                                                                             MAX_RATIO * value["compressed_size"])):
        raise InvalidRequest()
    return dict(value)


def parse_request(argv):
    """(files, kind, start, limit, callees) from `jsparser.syntax <JSON>`; every bound re-checked here."""
    if len(argv) != 2 or argv[0] != OPERATION:
        raise InvalidRequest()
    try:
        args = json.loads(argv[1], object_pairs_hook=_no_duplicates)
    except ValueError:
        raise InvalidRequest() from None
    if not (isinstance(args, dict) and set(args) == {"files", "kind", "start", "limit", "callees"}):
        raise InvalidRequest()
    files, callees = args["files"], args["callees"]
    if not (isinstance(files, list) and 1 <= len(files) <= MAX_FILES and args["kind"] in KINDS
            and isinstance(args["kind"], str) and _int(args["start"], 0, MAX_START) and _int(args["limit"], 1, MAX_LIMIT)
            and isinstance(callees, list) and 1 <= len(callees) <= MAX_CALLEES
            and all(isinstance(entry, str) and CALLEE.fullmatch(entry) for entry in callees)
            and callees == sorted(set(callees))):
        raise InvalidRequest()
    checked = []
    for file in files:
        if not (isinstance(file, dict) and set(file) == {"artifact", "dialect"} and isinstance(file["dialect"], str)
                and file["dialect"] in DIALECTS):
            raise InvalidRequest()
        checked.append({"artifact": None if file["artifact"] is None else _artifact(file["artifact"]),
                        "dialect": file["dialect"]})
    artifacts = [file["artifact"] for file in checked]
    if None in artifacts:
        if len(checked) != 1:  # the snapshot itself is the file only for a single-file input
            raise InvalidRequest()
    elif (len({a["member"] for a in artifacts}) != len(artifacts)
          or sum(a["size"] for a in artifacts) > MAX_CHILDREN_BYTES):
        raise InvalidRequest()
    return checked, args["kind"], args["start"], args["limit"], list(callees)


def inflate_stream(data, start, length):
    """One whole gzip member (RFC 1952) at data[start:start + length], as contract.inflate_stream accepts it: magic,
    method 8, reserved flags zero, FEXTRA, FNAME and FCOMMENT inside the range, FHCRC checked; inflated in bounded
    chunks within min(MAX_STREAM_BYTES, 100 x length); the 8-byte trailer's CRC-32 and ISIZE equal; nothing after it."""
    if not (type(start) is int and type(length) is int and 0 <= start and 18 <= length and start + length <= len(data)):
        raise InputMismatch()
    raw = bytes(data[start:start + length])
    if raw[:3] != b"\x1f\x8b\x08" or raw[3] & 0xE0:
        raise InputMismatch()
    flags, at = raw[3], 10
    if flags & 4:
        if at + 2 > len(raw):
            raise InputMismatch()
        at += 2 + int.from_bytes(raw[at:at + 2], "little")
    for flag in (8, 16):
        if flags & flag:
            end = raw.find(b"\x00", at, len(raw) - 8)
            if end == -1:
                raise InputMismatch()
            at = end + 1
    if flags & 2:
        if at + 2 > len(raw) or int.from_bytes(raw[at:at + 2], "little") != zlib.crc32(raw[:at]) & 0xFFFF:
            raise InputMismatch()
        at += 2
    if at > len(raw) - 8:
        raise InputMismatch()
    limit = min(MAX_STREAM_BYTES, MAX_RATIO * length)
    body = memoryview(raw)[at:]
    inflater, stream, position = zlib.decompressobj(-15), bytearray(), 0
    try:
        while position < len(body) and not inflater.eof:
            chunk = body[position:position + CHUNK]
            position += len(chunk)
            stream += inflater.decompress(chunk, limit + 1 - len(stream))
            if len(stream) > limit or inflater.unconsumed_tail:
                raise InputMismatch()
    except zlib.error:
        raise InputMismatch() from None
    trailer = inflater.unused_data + bytes(body[position:])
    if (not inflater.eof or len(trailer) != 8 or int.from_bytes(trailer[:4], "little") != zlib.crc32(stream)
            or int.from_bytes(trailer[4:], "little") != len(stream) & 0xFFFFFFFF):
        raise InputMismatch()
    return bytes(stream)


def materialize(data, artifact, streams=None):
    """The member's bytes from the snapshot: in range, inflated in bounded chunks to exactly its size, CRC and hash equal.

    streams caches inflated gzip streams by (data_offset, compressed_size), so each is inflated once per run."""
    start, length, size = artifact["data_offset"], artifact["compressed_size"], artifact["size"]
    if start + length > len(data):
        raise InputMismatch()
    if artifact["method"] == 1:
        key = (start, length)
        stream = streams.get(key) if streams is not None else None
        if stream is None:
            stream = inflate_stream(data, start, length)
            if streams is not None:
                streams[key] = stream
        inner = artifact["inner_offset"]
        if inner + size > len(stream):
            raise InputMismatch()
        child = stream[inner:inner + size]
        if zlib.crc32(child) != artifact["crc32"] or hashlib.sha256(child).hexdigest() != artifact["sha256"]:
            raise InputMismatch()
        return child
    raw = memoryview(data)[start:start + length]
    if artifact["method"] == 0:
        child = bytes(raw)
    else:
        inflater, out = zlib.decompressobj(-15), bytearray()
        try:
            for at in range(0, length, CHUNK):
                out += inflater.decompress(raw[at:at + CHUNK], size + 1 - len(out))
                if len(out) > size or inflater.unconsumed_tail:
                    raise InputMismatch()
            out += inflater.flush(size + 1 - len(out))
        except zlib.error:
            raise InputMismatch() from None
        if len(out) != size or not inflater.eof or inflater.unused_data or inflater.unconsumed_tail:
            raise InputMismatch()
        child = bytes(out)
    if zlib.crc32(child) != artifact["crc32"] or hashlib.sha256(child).hexdigest() != artifact["sha256"]:
        raise InputMismatch()
    return child


def text_units(data):
    """UTF-16 length of the decoded text after one leading BOM, or None when UTF-8 decoding fails."""
    try:
        text = data.removeprefix(b"\xef\xbb\xbf").decode("utf-8")
    except UnicodeDecodeError:
        return None
    return len(text.encode("utf-16-le")) // 2


def driver_argv():
    return [NODE, f"--max-old-space-size={HEAP_MIB}", "--disallow-code-generation-from-strings", "--no-addons",
            "--permission", "--allow-fs-read=" + str(Path(DRIVER).parent) + "/", "--allow-fs-read=" + str(WORK) + "/",
            DRIVER]


def run_driver(request):
    """(exit code, stdout bytes, whether stderr named the heap limit) of one driver run in its own process group."""
    reply, errors = WORK / "driver.json", WORK / "driver.err"
    with open(reply, "xb") as out, open(errors, "xb") as err:
        process = subprocess.Popen(driver_argv(), stdin=subprocess.PIPE, stdout=out, stderr=err,
                                   env={"PATH": "/usr/bin:/bin", "HOME": str(WORK), "LANG": "C.UTF-8"},
                                   cwd=str(WORK), start_new_session=True)
        try:
            process.communicate(json.dumps(request).encode("ascii"), timeout=DRIVER_SECONDS)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise DriverTimeout() from None
    with open(reply, "rb") as stream:
        raw = stream.read(MAX_DRIVER_BYTES + 1)
    with open(errors, "rb") as stream:
        heap = HEAP_MARKER in stream.read(65_536)
    return process.returncode, raw, heap


def check_answer(raw, units, kind, start, limit):
    """The driver's rows, one per file in order, coherent with the statuses, the counts and the page."""
    if len(raw) > MAX_DRIVER_BYTES:
        raise ParserFailed()
    try:
        answer = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates)
    except (UnicodeDecodeError, ValueError, InvalidRequest):
        raise ParserFailed() from None
    if not (isinstance(answer, dict) and set(answer) == {"files"} and isinstance(answer["files"], list)
            and len(answer["files"]) == len(units)):
        raise ParserFailed()
    rows, before = [], 0
    for index, (row, length) in enumerate(zip(answer["files"], units)):
        if not (isinstance(row, dict) and set(row) == {"status", "errors", "count", "items"}
                and row["status"] in STATUSES and isinstance(row["status"], str)
                and _int(row["errors"], 0, 2**31 - 1) and _int(row["count"], 0, 2**31 - 1)
                and isinstance(row["items"], list)):
            raise ParserFailed()
        status, errors, count, items = row["status"], row["errors"], row["count"], row["items"]
        if (status == "decode_error") != (length is None) or (status == "too_large") != (length == "too_large"):
            raise ParserFailed()
        if status in ("decode_error", "too_large") and (errors, count, items) != (0, 0, []):
            raise ParserFailed()
        if (status == "ok") != (errors == 0) and status in ("ok", "syntax_error"):
            raise ParserFailed()
        if kind == "parse" and (count, items) != (0, []):
            raise ParserFailed()
        wanted = max(0, min(before + count, start + limit) - max(before, start))
        if len(items) != wanted:
            raise ParserFailed()
        checked = []
        for item in items:
            if not (isinstance(item, list) and len(item) == 3 and item[0] in FORMS[kind] and isinstance(item[0], str)
                    and _int(item[1], 0, 2**31 - 1) and _int(item[2], 0, 2**31 - 1)
                    and item[1] < item[2] <= length):
                raise ParserFailed()
            checked.append((item[1], item[2], ORDER.index(item[0]), item[0]))
        if checked != sorted(set(checked)):  # sorted by start, end and form, no duplicates
            raise ParserFailed()
        rows.append({"file": index, "status": status, "errors": errors, "count": count,
                     "items": [{"kind": form, "start": a, "end": b} for a, b, _, form in checked]})
        before += count
    return rows


def run(files, kind, start, limit, callees, data, driver=run_driver):
    shutil.rmtree(WORK, ignore_errors=True)
    WORK.mkdir(mode=0o700)
    paths, units, streams = [], [], {}
    for index, file in enumerate(files):
        child = data if file["artifact"] is None else materialize(data, file["artifact"], streams)
        path = WORK / f"{index}.src"
        path.write_bytes(child)
        paths.append({"path": str(path), "dialect": file["dialect"]})
        units.append("too_large" if len(child) > MAX_FILE_BYTES else text_units(child))
    code, raw, heap = driver({"files": paths, "kind": kind, "start": start, "limit": limit, "callees": callees})
    if heap or code == -signal.SIGKILL:
        raise DriverMemory()
    if code != 0:
        raise ParserFailed()
    return check_answer(raw, units, kind, start, limit)


def error_name(exc):
    for kind, name in FIXED_ERRORS.items():
        if isinstance(exc, kind):
            return name
    name = type(exc).__name__
    return name if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", name) else "WorkerError"


def encode(message):
    return (json.dumps(message, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def reply(argv, data, digest=None, driver=run_driver):
    """One reply; data None means the snapshot could not be read, digest defaults to the SHA-256 of data."""
    digest = digest or hashlib.sha256(data or b"").hexdigest()
    try:
        if data is None:
            raise SnapshotUnreadable()
        files, kind, start, limit, callees = parse_request(argv)
        if len(data) > MAX_INPUT_BYTES:
            raise InputTooLarge()
        message = {"protocol": PROTOCOL, "status": "ok", "snapshot_sha256": digest,
                   "observations": run(files, kind, start, limit, callees, data, driver)}
        if len(encode(message)) > MAX_REPLY_BYTES:
            raise ReplyTooLarge()
        return message
    except Exception as exc:  # every failure is one short, inert error reply
        return {"protocol": PROTOCOL, "status": "error", "snapshot_sha256": digest, "error": error_name(exc)}


def read_snapshot(path):
    """At most MAX_INPUT_BYTES + 1 bytes, and the SHA-256 of the whole file: the digest the host compares."""
    digest, kept = hashlib.sha256(), bytearray()
    with open(path, "rb") as handle:
        while chunk := handle.read(CHUNK):
            digest.update(chunk)
            kept += chunk[:MAX_INPUT_BYTES + 1 - len(kept)]
    return bytes(kept), digest.hexdigest()


def main(argv=None, snapshot=SNAPSHOT):
    try:
        data, digest = read_snapshot(snapshot)
    except OSError:
        data, digest = None, None
    sys.stdout.buffer.write(encode(reply(sys.argv[1:] if argv is None else argv, data, digest=digest)))
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
