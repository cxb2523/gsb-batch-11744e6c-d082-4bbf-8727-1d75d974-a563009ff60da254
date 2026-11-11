"""ReverseAI JADX worker: one jadx.method request on /snapshot/input, one reverseai.worker/1 JSON object on stdout.

Entrypoint (docs/contract.md, "Decompiled Java through JADX (M4b, contract/3)"):
    python3 -I -B /opt/reverseai/worker.py jadx.method <canonical JSON of the request>

The request names the package's clean classes*.dex members by their contract artifacts (member, method, data_offset,
compressed_size, size, crc32, sha256; at most 16 members and 128 MiB) and 1..16 target methods: a member index and the
class descriptor, method name and prototype as hex of their raw decoded text (UTF-8, surrogates passed through), so no
escaping or injection question reaches Java; then start and max_chars. The worker re-materializes every member from
the snapshot into /tmp with a bounded inflate and refuses the run ("input") unless its size, CRC-32 and SHA-256 equal
the artifact; JADX never sees the ZIP. It then runs the fixed driver baked into the image (decision m4b-w-plan: JADX
1.5.6 with only its DEX input plugin, one thread, no resources, no deobfuscation or renames, comments at WARN) with a
fixed JVM heap and a timeout below the 120 s wall, and checks the driver's answer before emitting one reply: for each
target, in order, {"target", "status", "code_offset", "insns_count", "total", "text"} (decision m4b-host-bounds:
statuses other than ok and fallback carry null offsets, total 0 and text ""; a page at or past the end is ""; "omitted"
for a method JADX prints no text for by design, decision m4b-omitted).
Whole-run failures are the fixed errors "memory", "timeout" and "input"; any other failure is its class name. Nothing
but the one JSON object is written, to stdout only; the driver's stderr is discarded.
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
ADAPTER_VERSION = "1.5.6-r1"
OPERATION = "jadx.method"
SNAPSHOT = "/snapshot/input"
MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_MEMBERS = 16
MAX_CHILD_BYTES = 32 * 1024 * 1024
MAX_CHILDREN_BYTES = 128 * 1024 * 1024
MAX_RATIO = 100
MAX_TARGETS = 16
MAX_IDENTITY_HEX = 2 * 3 * 255  # 255 UTF-16 units at most 3 bytes each
MAX_START = 1048575
MAX_CHARS = (64, 2048)
MAX_REPLY_BYTES = 262_144
MAX_DRIVER_BYTES = 262_144
STATUSES = ("ok", "fallback", "decompile_failed", "class_not_found", "method_not_found", "no_code", "omitted")
ARTIFACT_KEYS = frozenset({"member", "method", "data_offset", "compressed_size", "size", "crc32", "sha256"})
JAVA = "/opt/jdk/bin/java"
JAR = "/opt/jadx/jadx-1.5.6-all.jar"
DRIVER = "/opt/reverseai/driver"
WORK = Path("/tmp/reverseai-jadx")
HEAP = "1536m"
DRIVER_SECONDS = 100  # below the 120 s container wall
OOM_EXIT = 3  # -XX:+ExitOnOutOfMemoryError
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
    """The JVM ran out of heap: the contract's whole-run error "memory"."""


class DriverTimeout(WorkerFailure):
    """The driver exceeded its time: the contract's whole-run error "timeout"."""


class JadxFailed(WorkerFailure):
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


def _identity(value, minimum_bytes):
    """Hex of raw decoded text: lowercase, even length, decodable with surrogates passed through."""
    if not (isinstance(value, str) and 2 * minimum_bytes <= len(value) <= MAX_IDENTITY_HEX and len(value) % 2 == 0
            and re.fullmatch(r"[0-9a-f]*", value)):
        raise InvalidRequest()
    try:
        return bytes.fromhex(value).decode("utf-8", "surrogatepass")
    except UnicodeDecodeError:
        raise InvalidRequest() from None


def _artifact(value):
    if not (isinstance(value, dict) and set(value) == ARTIFACT_KEYS):
        raise InvalidRequest()
    member, method, sha = value["member"], value["method"], value["sha256"]
    if not (isinstance(member, str) and 0 < len(member) <= 255 and member.isprintable()
            and type(method) is int and method in (0, 8)
            and all(_int(value[key], 0, 2**64 - 1) for key in ("data_offset", "compressed_size", "size", "crc32"))
            and value["crc32"] < 2**32 and 0 < value["size"] <= MAX_CHILD_BYTES
            and isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{64}", sha)):
        raise InvalidRequest()
    if method == 0 and value["compressed_size"] != value["size"]:
        raise InvalidRequest()
    if method == 8 and not (0 < value["compressed_size"] and value["size"] <= MAX_RATIO * value["compressed_size"]):
        raise InvalidRequest()
    return dict(value)


def parse_request(argv):
    """(members, targets, start, max_chars) from `jadx.method <JSON>`; every bound re-checked here."""
    if len(argv) != 2 or argv[0] != OPERATION:
        raise InvalidRequest()
    try:
        args = json.loads(argv[1], object_pairs_hook=_no_duplicates)
    except ValueError:
        raise InvalidRequest() from None
    if not (isinstance(args, dict) and set(args) == {"members", "targets", "start", "max_chars"}):
        raise InvalidRequest()
    members, targets = args["members"], args["targets"]
    if not (isinstance(members, list) and 1 <= len(members) <= MAX_MEMBERS
            and isinstance(targets, list) and 1 <= len(targets) <= MAX_TARGETS
            and _int(args["start"], 0, MAX_START) and _int(args["max_chars"], *MAX_CHARS)):
        raise InvalidRequest()
    members = [_artifact(member) for member in members]
    if len({m["member"] for m in members}) != len(members) or sum(m["size"] for m in members) > MAX_CHILDREN_BYTES:
        raise InvalidRequest()
    checked = []
    for target in targets:
        if not (isinstance(target, dict) and set(target) == {"member", "class", "method", "prototype"}
                and _int(target["member"], 0, len(members) - 1)):
            raise InvalidRequest()
        checked.append({"dex": target["member"], "class": _identity(target["class"], 3),
                        "method": _identity(target["method"], 1), "prototype": _identity(target["prototype"], 3)})
    return members, checked, args["start"], args["max_chars"]


def materialize(data, artifact):
    """The member's bytes from the snapshot: in range, inflated in bounded chunks to exactly its size, CRC and hash equal."""
    start, length, size = artifact["data_offset"], artifact["compressed_size"], artifact["size"]
    if start + length > len(data):
        raise InputMismatch()
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


def driver_argv():
    return [JAVA, "-Xmx" + HEAP, "-Xss4m", "-XX:+UseSerialGC", "-XX:-UsePerfData", "-XX:+ExitOnOutOfMemoryError",
            "-Djava.awt.headless=true", "-Djava.io.tmpdir=" + str(WORK / "jvm"), "-Duser.home=" + str(WORK / "home"),
            "-cp", DRIVER + ":" + JAR, "ReverseAIJadx"]


def run_driver(request):
    """(exit code, stdout bytes) of one driver run in its own process group; stdout goes to a bounded file."""
    reply = WORK / "driver.json"
    with open(reply, "xb") as out:
        process = subprocess.Popen(driver_argv(), stdin=subprocess.PIPE, stdout=out, stderr=subprocess.DEVNULL,
                                   env={"PATH": "/usr/bin:/bin", "HOME": str(WORK / "home"), "LANG": "C.UTF-8"},
                                   cwd=str(WORK), start_new_session=True)
        try:
            process.communicate(json.dumps(request).encode("ascii"), timeout=DRIVER_SECONDS)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise DriverTimeout() from None
    with open(reply, "rb") as stream:
        return process.returncode, stream.read(MAX_DRIVER_BYTES + 1)


def check_answer(raw, count, start, max_chars):
    """The driver's rows, one per target in order, each within the contract's bounds."""
    if len(raw) > MAX_DRIVER_BYTES:
        raise JadxFailed()
    try:
        answer = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates)
    except (UnicodeDecodeError, ValueError, InvalidRequest):
        raise JadxFailed() from None
    if not (isinstance(answer, dict) and set(answer) == {"targets"} and isinstance(answer["targets"], list)
            and len(answer["targets"]) == count):
        raise JadxFailed()
    rows = []
    for index, row in enumerate(answer["targets"]):
        if not (isinstance(row, dict) and set(row) == {"target", "status", "code_offset", "insns_count", "total", "text"}
                and row["target"] == index and type(row["target"]) is int and row["status"] in STATUSES
                and isinstance(row["text"], str) and _int(row["total"], 0, 2**31 - 1)):
            raise JadxFailed()
        text, total = row["text"], row["total"]
        if row["status"] in ("ok", "fallback"):
            if not (_int(row["code_offset"], 0, 2**32 - 1) and _int(row["insns_count"], 1, 2**32 - 1) and total > 0):
                raise JadxFailed()
            if not re.fullmatch(r"[\x20-\x7e\n\t]*", text) or len(text) != max(0, min(max_chars, total - start)):
                raise JadxFailed()
        elif (row["code_offset"], row["insns_count"], total, text) != (None, None, 0, ""):
            raise JadxFailed()
        rows.append(dict(row))
    return rows


def run(members, targets, start, max_chars, data, driver=run_driver):
    shutil.rmtree(WORK, ignore_errors=True)
    for folder in (WORK, WORK / "jvm", WORK / "home"):
        folder.mkdir(mode=0o700)
    paths = []
    for index, artifact in enumerate(members):
        path = WORK / f"{index}.dex"
        path.write_bytes(materialize(data, artifact))
        paths.append(str(path))
    code, raw = driver({"dex": paths, "targets": targets, "start": start, "max_chars": max_chars})
    if code == OOM_EXIT:
        raise DriverMemory()
    if code != 0:
        raise JadxFailed()
    return check_answer(raw, len(targets), start, max_chars)


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
        members, targets, start, max_chars = parse_request(argv)
        if len(data) > MAX_INPUT_BYTES:
            raise InputTooLarge()
        message = {"protocol": PROTOCOL, "status": "ok", "snapshot_sha256": digest,
                   "observations": run(members, targets, start, max_chars, data, driver)}
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
