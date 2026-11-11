"""The jsparser worker, its build helper and its build tool without Docker, Node or the internet: request bounds, the
members re-materialized from the snapshot, the driver's answer checked file by file and against the page, the
whole-run errors, the fixed driver command, the unpack rules, the Dockerfile shape, the image lock and the exact docker
calls. The driver itself runs only natively (tests/verify_m2_runtime.py --tool jsparser)."""

import base64
import contextlib
import hashlib
import importlib.util
import io
import json
import lzma
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zlib

from tests import fixtures_js as J

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


worker = load("jsparser_worker", ROOT / "containers" / "jsparser" / "worker.py")
unpack = load("jsparser_unpack", ROOT / "containers" / "jsparser" / "unpack.py")
build = load("build_jsparser_image", ROOT / "tools" / "build_jsparser_image.py")
CALLEES = ["Buffer.from", "eval", "exec", "fetch", "http.get", "require"]


def app():
    data, layout = J.app_zip()
    files = [f for f in layout["files"] if f["name"].rsplit("/", 1)[-1] != "package.json"]
    return data, files


def request(files, kind="calls", start=0, limit=128, callees=CALLEES):
    return ["jsparser.syntax", json.dumps({"files": files, "kind": kind, "start": start, "limit": limit,
                                           "callees": callees})]


def entries(files):
    return [{"artifact": f["artifact"], "dialect": "ts" if f["name"].endswith(".ts") else "js"} for f in files]


def row(status="ok", errors=0, count=0, items=()):
    return {"status": status, "errors": errors, "count": count, "items": [list(item) for item in items]}


def answer(*rows):
    return json.dumps({"files": list(rows)}).encode()


class RequestTests(unittest.TestCase):
    def setUp(self):
        self.data, self.files = app()
        self.good = entries(self.files)

    def test_valid_requests_keep_their_files_and_bounds(self):
        files, kind, start, limit, callees = worker.parse_request(request(self.good, "modules", 5, 256))
        self.assertEqual((files, kind, start, limit, callees), (self.good, "modules", 5, 256, CALLEES))
        single = worker.parse_request(request([{"artifact": None, "dialect": "tsx"}], "parse"))
        self.assertEqual(single[0], [{"artifact": None, "dialect": "tsx"}])
        for count in (1, 64):
            files = [{"artifact": {**self.good[0]["artifact"], "member": f"m{i}.js"}, "dialect": "js"} for i in range(count)]
            self.assertEqual(len(worker.parse_request(request(files))[0]), count)

    def test_every_other_request_is_refused(self):
        good = json.loads(request(self.good)[1])
        artifact = self.good[0]["artifact"]

        def variant(**change):
            return ["jsparser.syntax", json.dumps({**good, **change})]

        def member(**change):
            return variant(files=[{"artifact": {**artifact, **change}, "dialect": "js"}])

        many = [{"artifact": {**artifact, "member": f"m{i}.js"}, "dialect": "js"} for i in range(65)]
        big = [{"artifact": {**artifact, "member": f"m{i}.js", "method": 0, "size": 8 * 1024 * 1024 + i,
                             "compressed_size": 8 * 1024 * 1024 + i}, "dialect": "js"} for i in range(4)]
        bad = [["jadx.method", request(self.good)[1]], ["jsparser.syntax"], request(self.good) + ["x"],
               ["jsparser.syntax", "not json"], ["jsparser.syntax", "[]"],
               ["jsparser.syntax", '{"files": [], "files": [], "kind": "calls", "start": 0, "limit": 1, "callees": ["a"]}'],
               variant(extra=1), variant(files=[]), variant(files=many), variant(files=[self.good[0]] * 2), variant(files=big),
               variant(files=[{"artifact": None, "dialect": "js"}] * 2),
               variant(files=[{"artifact": None, "dialect": "js"}, self.good[0]]),
               variant(files=[{"artifact": artifact, "dialect": "py"}]), variant(files=[{"artifact": artifact}]),
               variant(files=[{"artifact": artifact, "dialect": "js", "path": "/etc/passwd"}]),
               variant(kind="ast"), variant(kind=None), variant(start=-1), variant(start=1048576), variant(start=True),
               variant(limit=0), variant(limit=257), variant(callees=[]), variant(callees=["eval", "Buffer.from"]),
               variant(callees=["eval", "eval"]), variant(callees=["a.b.c"]), variant(callees=["1x"]),
               variant(callees=["ev al"]), variant(callees=["\\u0065val"]), variant(callees=[7]),
               variant(callees=[f"n{i:03d}" for i in range(129)]), variant(callees=["x" * 65]),
               member(method=12), member(size=0), member(size=32 * 1024 * 1024 + 1), member(crc32=2**32),
               member(sha256="A" * 64), member(member=""), member(member="a\nb"), member(data_offset=-1), member(extra=1),
               member(method=0, compressed_size=artifact["size"] + 1), member(method=8, compressed_size=1, size=101)]
        for argv in bad:
            with self.subTest(argv=argv[:1] + [a[:100] for a in argv[1:]]), self.assertRaises(worker.InvalidRequest):
                worker.parse_request(argv)


    def test_a_duplicate_key_alone_refuses_an_otherwise_valid_request(self):
        # The same envelope without the repeated key is valid, so the refusal is the duplicate's
        text = request(self.good)[1]
        self.assertEqual(worker.parse_request(["jsparser.syntax", text])[2], 0)
        repeated = text.replace('"start": 0', '"start": 0, "start": 0', 1)
        self.assertNotEqual(repeated, text)
        with self.assertRaises(worker.InvalidRequest):
            worker.parse_request(["jsparser.syntax", repeated])


class MaterializeTests(unittest.TestCase):
    def test_stored_and_deflated_members_equal_their_children(self):
        data, files = app()
        methods = {f["artifact"]["method"] for f in files}
        self.assertEqual(methods, {0, 8})
        for f in files:
            self.assertEqual(worker.materialize(data, f["artifact"]), f["data"])

    def test_any_difference_from_the_artifact_is_the_input_error(self):
        data, files = app()
        deflated = next(f["artifact"] for f in files if f["artifact"]["method"] == 8)
        stored = next(f["artifact"] for f in files if f["artifact"]["method"] == 0)
        bad = [(deflated, {"crc32": deflated["crc32"] ^ 1}), (deflated, {"sha256": "0" * 64}),
               (deflated, {"size": deflated["size"] + 1}), (deflated, {"size": deflated["size"] - 1}),
               (deflated, {"compressed_size": deflated["compressed_size"] - 1}),
               (deflated, {"data_offset": len(data) - 2}), (stored, {"data_offset": stored["data_offset"] + 1}),
               (stored, {"sha256": "0" * 64})]
        for artifact, change in bad:
            with self.subTest(change=change), self.assertRaises(worker.InputMismatch):
                worker.materialize(data, {**artifact, **change})

    def test_text_units_count_utf16_after_one_bom_and_refuse_invalid_utf8(self):
        self.assertEqual(worker.text_units(b""), 0)
        self.assertEqual(worker.text_units(b"abc"), 3)
        self.assertEqual(worker.text_units(b"\xef\xbb\xbfabc"), 3)
        self.assertEqual(worker.text_units(b"\xef\xbb\xbf\xef\xbb\xbfa"), 2)  # only one BOM is skipped
        self.assertEqual(worker.text_units("caf\u00e9 \U0001F600".encode()), 7)
        for raw in (b"\xff", b"caf\xe9", b"\xed\xa0\x80", b"\xc0\xaf"):
            self.assertIsNone(worker.text_units(raw), raw)


def gzip_member(body, *, flags=0, extra=b"", name=b"", comment=b"", trailer=None):
    """One gzip member (RFC 1952) built here: raw deflate of body between a header with the given optional fields and
    its trailer; FHCRC (flag 2) is computed over the header written before it."""
    header = b"\x1f\x8b\x08" + bytes([flags]) + bytes(4) + b"\x00\xff"
    if flags & 4:
        header += len(extra).to_bytes(2, "little") + extra
    if flags & 8:
        header += name + b"\x00"
    if flags & 16:
        header += comment + b"\x00"
    if flags & 2:
        header += (zlib.crc32(header) & 0xFFFF).to_bytes(2, "little")
    packer = zlib.compressobj(9, zlib.DEFLATED, -15)
    packed = packer.compress(body) + packer.flush()
    end = trailer if trailer is not None else (zlib.crc32(body).to_bytes(4, "little")
                                               + (len(body) & 0xFFFFFFFF).to_bytes(4, "little"))
    return header + packed + end


def npm_tarball(files):
    """(input bytes, [(name, method 1 artifact)]) of a gzip-compressed tar of these files, built in code."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, body in files:
            info = tarfile.TarInfo("package/" + name)
            info.size = len(body)
            archive.addfile(info, io.BytesIO(body))
    tar = buffer.getvalue()
    data = gzip_member(tar, flags=8, name=b"package.tgz")
    with tarfile.open(fileobj=io.BytesIO(tar)) as archive:
        artifacts = [(info.name, {"member": info.name, "method": 1, "data_offset": 0, "compressed_size": len(data),
                                  "inner_offset": info.offset_data, "size": info.size,
                                  "crc32": zlib.crc32(tar[info.offset_data:info.offset_data + info.size]),
                                  "sha256": hashlib.sha256(tar[info.offset_data:info.offset_data + info.size]).hexdigest()})
                     for info in archive.getmembers()]
    return data, artifacts


TARBALL_FILES = (("index.js", b"const cp = require('child_process');\ncp.exec(cmd);\n"),
                 ("lib/util.ts", b"export const x: number = 1;\n"))


class GzipStreamTests(unittest.TestCase):
    """Method 1 children: the worker's own inflater, equal to contract.inflate_stream on the same inputs."""

    def test_the_inflater_accepts_and_refuses_exactly_as_the_contract_does(self):
        from reverseai import contract
        body = b"package/index.js\x00" + bytes(range(256)) * 40
        good = gzip_member(body)
        cases = {"plain": good, "extra": gzip_member(body, flags=4, extra=b"AB\x02\x00xy"),
                 "name_comment": gzip_member(body, flags=8 | 16, name=b"a.tar", comment=b"note"),
                 "header_crc": gzip_member(body, flags=2 | 8, name=b"a.tar"),
                 "empty_body": gzip_member(b""),
                 "bad_magic": b"\x1f\x8c" + good[2:], "bad_method": good[:2] + b"\x07" + good[3:],
                 "reserved_flag": good[:3] + b"\x20" + good[4:],
                 "bad_header_crc": gzip_member(body, flags=2)[:10] + b"\x00\x00" + gzip_member(body)[10:],
                 "bad_trailer_crc": gzip_member(body, trailer=b"\x00" * 4 + len(body).to_bytes(4, "little")),
                 "bad_isize": gzip_member(body, trailer=zlib.crc32(body).to_bytes(4, "little") + b"\x00" * 4),
                 "trailing_byte": good + b"\x00", "two_members": good + good, "truncated": good[:-1],
                 "short": good[:17], "unterminated_name": b"\x1f\x8b\x08\x08" + bytes(6) + b"a" * 30,
                 "extra_past_end": b"\x1f\x8b\x08\x04" + bytes(6) + b"\xff\xff" + bytes(20),
                 "not_deflate": b"\x1f\x8b\x08\x00" + bytes(6) + b"\xff" * 12}
        for name, data in cases.items():
            with self.subTest(case=name):
                try:
                    expected = contract.inflate_stream(data, 0, len(data))
                except contract.ContractError:
                    expected = None
                try:
                    got = worker.inflate_stream(data, 0, len(data))
                except worker.InputMismatch:
                    got = None
                self.assertEqual(got, expected)
        self.assertEqual(worker.inflate_stream(cases["plain"], 0, len(good)), body)
        # inside a larger input, at an offset
        framed = b"x" * 7 + good + b"y" * 3
        self.assertEqual(worker.inflate_stream(framed, 7, len(good)), contract.inflate_stream(framed, 7, len(good)))
        for start, length in ((7, len(good) + 1), (6, len(good)), (0, len(framed) + 1)):
            with self.assertRaises(worker.InputMismatch):
                worker.inflate_stream(framed, start, length)

    def test_a_stream_beyond_100_times_its_size_is_refused_in_bounded_chunks(self):
        bomb = gzip_member(bytes(4 * 1024 * 1024))  # about 4 KiB packed: far past 100 x
        seen, real = [], zlib.decompressobj

        class Counting:
            def __init__(self, *args):
                self.inner = real(*args)

            def decompress(self, data, max_length=0):
                out = self.inner.decompress(data, max_length)
                seen.append((max_length, len(out)))
                return out

            def __getattr__(self, name):
                return getattr(self.inner, name)

        with patch.object(worker.zlib, "decompressobj", Counting), self.assertRaises(worker.InputMismatch):
            worker.inflate_stream(bomb, 0, len(bomb))
        limit = 100 * len(bomb)
        self.assertTrue(seen and all(0 < cap <= limit + 1 and length <= cap for cap, length in seen))
        with patch.object(worker, "MAX_STREAM_BYTES", 1024):
            fine = gzip_member(bytes(range(256)) * 8)  # 2,048 bytes inflated, past a 1,024 limit
            with self.assertRaises(worker.InputMismatch):
                worker.inflate_stream(fine, 0, len(fine))

    def test_method_1_artifacts_are_admitted_and_bound_by_their_stream(self):
        data, artifacts = npm_tarball(TARBALL_FILES)
        request_files = [{"artifact": artifact, "dialect": "ts" if name.endswith(".ts") else "js"}
                         for name, artifact in artifacts]
        files = worker.parse_request(request(request_files))[0]
        self.assertEqual([f["artifact"]["method"] for f in files], [1, 1])
        streams = {}
        self.assertEqual([worker.materialize(data, f["artifact"], streams) for f in files],
                         [body for _, body in TARBALL_FILES])
        self.assertEqual(list(streams), [(0, len(data))])
        base = artifacts[0][1]
        refused = [{k: v for k, v in base.items() if k != "inner_offset"}, {**base, "method": 0},
                   {**base, "extra": 1}, {**base, "compressed_size": 17},
                   {**base, "inner_offset": 100 * base["compressed_size"]}, {**base, "inner_offset": -1},
                   {**base, "inner_offset": True}, {**base, "inner_offset": 128 * 1024 * 1024}]
        for artifact in refused:
            with self.subTest(artifact={k: artifact.get(k) for k in ("method", "compressed_size", "inner_offset")}), \
                    self.assertRaises(worker.InvalidRequest):
                worker.parse_request(request([{"artifact": artifact, "dialect": "js"}]))
        for change in ({"sha256": "0" * 64}, {"crc32": base["crc32"] ^ 1}, {"size": base["size"] + 1},
                       {"inner_offset": base["inner_offset"] + 1}, {"inner_offset": 10**6},
                       {"data_offset": 1}, {"compressed_size": len(data) - 1}):
            with self.subTest(change=change), self.assertRaises(worker.InputMismatch):
                worker.materialize(data, {**base, **change}, {})
        with self.assertRaises(worker.InputMismatch):
            worker.materialize(data[:-1] + bytes([data[-1] ^ 1]), base, {})


class AnswerTests(unittest.TestCase):
    def test_rows_become_observations_and_the_page_spans_files(self):
        # three files with 3, 0 and 4 items; the page start 2, limit 3 takes one item of the first and two of the third
        rows = worker.check_answer(answer(row(count=3, items=[("call", 20, 24)]), row(errors=0),
                                          row("syntax_error", 2, 4, [("call", 1, 5), ("call", 1, 9)])),
                                   [40, 10, 30], "calls", 2, 3)
        self.assertEqual(rows, [
            {"file": 0, "status": "ok", "errors": 0, "count": 3, "items": [{"kind": "call", "start": 20, "end": 24}]},
            {"file": 1, "status": "ok", "errors": 0, "count": 0, "items": []},
            {"file": 2, "status": "syntax_error", "errors": 2, "count": 4,
             "items": [{"kind": "call", "start": 1, "end": 5}, {"kind": "call", "start": 1, "end": 9}]}])
        modules = worker.check_answer(answer(row(count=2, items=[("import", 0, 3), ("require", 0, 3)])), [10],
                                      "modules", 0, 128)
        self.assertEqual([item["kind"] for item in modules[0]["items"]], ["import", "require"])
        statuses = worker.check_answer(answer(row("decode_error"), row("too_large"), row()), [None, "too_large", 0],
                                       "parse", 0, 1)
        self.assertEqual([r["status"] for r in statuses], ["decode_error", "too_large", "ok"])

    def test_a_duplicate_key_alone_refuses_an_otherwise_valid_answer(self):
        valid = json.dumps(row()).encode()
        self.assertEqual(len(worker.check_answer(b'{"files": [' + valid + b"]}", [10], "calls", 0, 128)), 1)
        for raw in (b'{"files": [' + valid + b'], "files": [' + valid + b"]}",
                    b'{"files": [' + valid.replace(b'"errors": 0', b'"errors": 0, "errors": 0', 1) + b"]}"):
            with self.subTest(raw=raw[:80]), self.assertRaises(worker.ParserFailed):
                worker.check_answer(raw, [10], "calls", 0, 128)

    def test_every_incoherent_answer_is_refused(self):
        units = [40]
        bad = [(b"[]", units, "calls"), (json.dumps({"files": [], "x": 1}).encode(), units, "calls"),
               (answer(), units, "calls"), (answer(row(), row()), units, "calls"),
               (answer({**row(), "extra": 1}), units, "calls"), (answer(row("unknown")), units, "calls"),
               (answer(row(errors=1)), units, "calls"), (answer(row("syntax_error", 0)), units, "calls"),
               (answer(row(errors=True)), units, "calls"), (answer(row(count=-1)), units, "calls"),
               (answer(row("decode_error")), units, "calls"), (answer(row()), [None], "calls"),
               (answer(row("too_large")), units, "calls"), (answer(row()), ["too_large"], "calls"),
               (answer(row("decode_error", 1)), [None], "calls"), (answer(row("too_large", 0, 1)), ["too_large"], "calls"),
               (answer(row(count=1, items=[("call", 0, 1)])), units, "parse"),
               (answer(row(count=1)), units, "calls"), (answer(row(count=1, items=[("call", 0, 1)] * 2)), units, "calls"),
               (answer(row(count=2, items=[("call", 0, 1), ("call", 0, 1)])), units, "calls"),
               (answer(row(count=2, items=[("call", 5, 9), ("call", 0, 1)])), units, "calls"),
               (answer(row(count=1, items=[("import", 0, 1)])), units, "calls"),
               (answer(row(count=1, items=[("call", 0, 1)])), units, "modules"),
               (answer(row(count=1, items=[("call", 3, 3)])), units, "calls"),
               (answer(row(count=1, items=[("call", 0, 41)])), units, "calls"),
               (answer(row(count=1, items=[("call", -1, 2)])), units, "calls"),
               (answer(row(count=1, items=[("call", True, 2)])), units, "calls"),
               (answer(row(count=1, items=[["call", 0]])), units, "calls"),
               (answer({**row(count=1), "items": [{"kind": "call", "start": 0, "end": 1}]}), units, "calls"),
               (b'{"files": [], "files": []}', units, "calls"), (b"\xff", units, "calls"),
               (b"x" * (worker.MAX_DRIVER_BYTES + 1), units, "calls")]
        for raw, lengths, kind in bad:
            with self.subTest(raw=raw[:120], kind=kind), self.assertRaises(worker.ParserFailed):
                worker.check_answer(raw, lengths, kind, 0, 128)
        # a page that should hold more, or fewer, items than sent
        with self.assertRaises(worker.ParserFailed):
            worker.check_answer(answer(row(count=5, items=[("call", 0, 1)])), units, "calls", 0, 2)
        with self.assertRaises(worker.ParserFailed):
            worker.check_answer(answer(row(count=5, items=[("call", 0, 1)])), units, "calls", 5, 2)


class RunTests(unittest.TestCase):
    def setUp(self):
        self.data, self.files = app()
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        patcher = patch.object(worker, "WORK", Path(self.folder.name) / "reverseai-jsparser")
        patcher.start()
        self.addCleanup(patcher.stop)

    def reply(self, driver, argv=None, data=None):
        return worker.reply(argv or request(entries(self.files)), self.data if data is None else data, driver=driver)

    def test_the_driver_gets_the_files_and_the_page_and_its_rows_become_the_observations(self):
        seen = {}

        def driver(sent):
            seen.update(sent)
            seen["bytes"] = [Path(f["path"]).read_bytes() for f in sent["files"]]
            return 0, answer(*[row() for _ in sent["files"]]), False

        message = self.reply(driver, request(entries(self.files), "modules", 3, 9))
        self.assertEqual((message["status"], message["snapshot_sha256"]), ("ok", hashlib.sha256(self.data).hexdigest()))
        self.assertEqual([o["file"] for o in message["observations"]], list(range(len(self.files))))
        self.assertEqual(seen["bytes"], [f["data"] for f in self.files])
        self.assertEqual([f["dialect"] for f in seen["files"]], [e["dialect"] for e in entries(self.files)])
        self.assertEqual([Path(f["path"]).name for f in seen["files"]], [f"{i}.src" for i in range(len(self.files))])
        self.assertEqual((seen["kind"], seen["start"], seen["limit"], seen["callees"]), ("modules", 3, 9, CALLEES))
        self.assertEqual(json.loads(worker.encode(message)), message)
        single, layout = J.bundle_js()
        message = worker.reply(request([{"artifact": None, "dialect": "js"}]), single,
                               driver=lambda sent: (0, answer(row()), False))
        self.assertEqual(message["observations"], [{"file": 0, "status": "ok", "errors": 0, "count": 0, "items": []}])

    def test_a_file_over_4_mib_must_be_reported_too_large_and_invalid_utf8_decode_error(self):
        big = b"a" * (worker.MAX_FILE_BYTES + 1)
        reply = worker.reply(request([{"artifact": None, "dialect": "js"}]), big,
                             driver=lambda sent: (0, answer(row("too_large")), False))
        self.assertEqual(reply["observations"][0]["status"], "too_large")
        reply = worker.reply(request([{"artifact": None, "dialect": "js"}]), big,
                             driver=lambda sent: (0, answer(row()), False))
        self.assertEqual(reply["error"], "ParserFailed")
        reply = worker.reply(request([{"artifact": None, "dialect": "js"}]), b"caf\xe9",
                             driver=lambda sent: (0, answer(row("decode_error")), False))
        self.assertEqual(reply["observations"][0]["status"], "decode_error")

    def test_whole_run_failures_have_their_fixed_names(self):
        def timeout(sent):
            raise worker.DriverTimeout()

        ok = answer(*[row() for _ in self.files])
        cases = [(lambda sent: (134, b"", True), "memory"), (lambda sent: (0, ok, True), "memory"),
                 (lambda sent: (-signal.SIGKILL, b"", False), "memory"), (timeout, "timeout"),
                 (lambda sent: (1, ok, False), "ParserFailed"), (lambda sent: (0, b"not json", False), "ParserFailed")]
        for driver, name in cases:
            with self.subTest(name=name):
                message = self.reply(driver)
                self.assertEqual((set(message), message["status"], message["error"]),
                                 ({"protocol", "status", "snapshot_sha256", "error"}, "error", name))
        tampered = entries(self.files)
        tampered[1] = {**tampered[1], "artifact": {**tampered[1]["artifact"], "crc32": tampered[1]["artifact"]["crc32"] ^ 1}}
        self.assertEqual(self.reply(lambda sent: (0, ok, False), request(tampered))["error"], "input")
        self.assertEqual(worker.reply(request(entries(self.files)), None)["error"], "SnapshotUnreadable")
        self.assertEqual(self.reply(lambda sent: (0, b"", False), ["jsparser.syntax", "{}"])["error"], "InvalidRequest")
        with patch.object(worker, "MAX_INPUT_BYTES", len(self.data) - 1):
            self.assertEqual(self.reply(lambda sent: (0, ok, False))["error"], "InputTooLarge")

    def test_tarball_children_reach_the_driver_and_each_stream_is_inflated_once(self):
        data, artifacts = npm_tarball(TARBALL_FILES)
        files = [{"artifact": artifact, "dialect": "js"} for _, artifact in artifacts]
        seen, calls, real = {}, [], worker.inflate_stream

        def counting(*args):
            calls.append(args[1:])
            return real(*args)

        def driver(sent):
            seen["bytes"] = [Path(f["path"]).read_bytes() for f in sent["files"]]
            return 0, answer(*[row() for _ in sent["files"]]), False

        with patch.object(worker, "inflate_stream", counting):
            message = worker.reply(request(files), data, driver=driver)
        self.assertEqual(message["status"], "ok", message)
        self.assertEqual(seen["bytes"], [body for _, body in TARBALL_FILES])
        self.assertEqual(calls, [(0, len(data))])
        tampered = data[:-5] + bytes([data[-5] ^ 1]) + data[-4:]  # trailer CRC-32
        self.assertEqual(worker.reply(request(files), tampered, driver=driver)["error"], "input")
        # One byte past the inflated stream: the slice is empty, so its CRC-32 and hash match; only the range refuses.
        past = [{"artifact": {**artifacts[0][1], "inner_offset": len(zlib.decompress(data, 31)), "size": 1,
                              "crc32": zlib.crc32(b""), "sha256": hashlib.sha256(b"").hexdigest()}, "dialect": "js"}]
        worker.parse_request(request(past))
        seen.clear()
        message = worker.reply(request(past), data, driver=driver)
        self.assertEqual((message.get("error"), seen), ("input", {}), message)

    def test_the_driver_command_is_fixed(self):
        self.assertEqual(worker.driver_argv(), [
            "/opt/node/bin/node", "--max-old-space-size=1536", "--disallow-code-generation-from-strings", "--no-addons",
            "--permission", "--allow-fs-read=/opt/reverseai/", "--allow-fs-read=" + str(worker.WORK) + "/",
            "/opt/reverseai/driver.mjs"])
        self.assertLess(worker.DRIVER_SECONDS, 120)
        self.assertEqual((worker.ADAPTER_VERSION, worker.MAX_FILES, worker.MAX_FILE_BYTES, worker.MAX_CHILDREN_BYTES),
                         ("8.0.4-r2", 64, 4 * 1024 * 1024, 32 * 1024 * 1024))

    def test_a_slow_driver_is_killed_its_output_is_bounded_and_the_heap_marker_is_read(self):
        worker.WORK.mkdir()
        slow = [sys.executable, "-c", "import time; time.sleep(30)"]
        with patch.object(worker, "driver_argv", lambda: slow), patch.object(worker, "DRIVER_SECONDS", 0.5):
            with self.assertRaises(worker.DriverTimeout):
                worker.run_driver({"files": []})
        for name in ("driver.json", "driver.err"):
            (worker.WORK / name).unlink()
        loud = [sys.executable, "-c", "import sys; sys.stdin.read(); sys.stdout.write('x' * %d); "
                "sys.stderr.write('FATAL ERROR: Reached heap limit Allocation failed - JavaScript heap out of memory')"
                % (worker.MAX_DRIVER_BYTES + 10)]
        with patch.object(worker, "driver_argv", lambda: loud):
            code, raw, heap = worker.run_driver({"files": []})
        self.assertEqual((code, len(raw), heap), (0, worker.MAX_DRIVER_BYTES + 1, True))

    def test_the_driver_source_reads_text_as_data_only(self):
        source = (ROOT / "containers" / "jsparser" / "driver.mjs").read_text(encoding="ascii")
        imports = [line for line in source.splitlines() if line.startswith("import ")]
        self.assertEqual(imports, ['import { parse } from "@babel/parser";', 'import { readFileSync } from "node:fs";'])
        for word in ("eval(", "Function(", "child_process", "require(", "import(", "vm.", "writeFile", "spawn"):
            self.assertNotIn(word, "\n".join(line for line in source.splitlines() if not line.lstrip().startswith("//")),
                             word)
        self.assertIn('{ sourceType: "unambiguous", errorRecovery: true, plugins: PLUGINS[file.dialect] }', source)
        self.assertIn('const PLUGINS = { js: [], jsx: ["jsx"], ts: ["typescript"], tsx: ["typescript", "jsx"] };', source)


def tar_xz(path, members):
    """members: (name, bytes or None for a directory, symlink target or None)."""
    with tarfile.open(path, "w:xz") as bundle:
        for name, data, link in members:
            info = tarfile.TarInfo(name)
            if link is not None:
                info.type, info.linkname = tarfile.SYMTYPE, link
                bundle.addfile(info)
            elif data is None:
                info.type = tarfile.DIRTYPE
                bundle.addfile(info)
            else:
                info.size = len(data)
                bundle.addfile(info, io.BytesIO(data))


def tgz(path, members):
    with tarfile.open(path, "w:gz") as bundle:
        for name, data, link in members:
            info = tarfile.TarInfo(name)
            if link is not None:
                info.type, info.linkname = tarfile.SYMTYPE, link
                bundle.addfile(info)
            else:
                info.size = len(data)
                bundle.addfile(info, io.BytesIO(data))


def integrity(path):
    return "sha512-" + base64.b64encode(hashlib.sha512(Path(path).read_bytes()).digest()).decode()


class UnpackTests(unittest.TestCase):
    def setUp(self):
        self.folder = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.folder)

    def test_node_takes_only_the_binary_and_licence_after_its_checks(self):
        root = unpack.NODE_ROOT
        path = self.folder / "node.tar.xz"
        tar_xz(path, [(root, None, None), (f"{root}/bin/node", b"\x7fELF stand-in", None), (f"{root}/LICENSE", b"MIT", None),
                      (f"{root}/bin/npm", None, "../lib/node_modules/npm/bin/npm-cli.js"),
                      (f"{root}/lib/node_modules/npm/bin/npm-cli.js", b"cli", None)])
        sha, size = hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_size
        out = self.folder / "out"
        unpack.node(path, sha, size, out)
        self.assertEqual(sorted(str(p.relative_to(out)) for p in out.rglob("*")), ["LICENSE", "bin", "bin/node"])
        self.assertEqual(((out / "bin/node").stat().st_mode & 0o777, (out / "LICENSE").stat().st_mode & 0o777), (0o755, 0o644))
        for checks in ((sha, size + 1), ("0" * 64, size)):
            with self.subTest(checks=checks), self.assertRaises(SystemExit):
                unpack.node(path, *checks, self.folder / "other")
        for members in ([(f"{root}/LICENSE", b"MIT", None)],
                        [(f"{root}/bin/node", None, "/usr/bin/env"), (f"{root}/LICENSE", b"MIT", None)],
                        [(f"{root}/bin/node", b"a", None), (f"{root}/bin/node", b"b", None), (f"{root}/LICENSE", b"MIT", None)]):
            bad = self.folder / f"bad{len(list(self.folder.iterdir()))}.tar.xz"
            tar_xz(bad, members)
            with self.subTest(members=[m[0] for m in members]), self.assertRaises(SystemExit):
                unpack.node(bad, hashlib.sha256(bad.read_bytes()).hexdigest(), bad.stat().st_size,
                            self.folder / f"o{bad.stem}")

    def test_npm_writes_only_safe_regular_files_after_the_integrity_check(self):
        path = self.folder / "parser.tgz"
        tgz(path, [("package/package.json", b'{"name": "@babel/parser"}', None), ("package/lib/index.js", b"export {}", None),
                   ("package/bin/babel-parser.js", b"#!/usr/bin/env node", None)])
        out = self.folder / "node_modules/@babel/parser"
        unpack.npm(path, integrity(path), out)
        self.assertEqual(sorted(str(p.relative_to(out)) for p in out.rglob("*") if p.is_file()),
                         ["bin/babel-parser.js", "lib/index.js", "package.json"])
        self.assertTrue(all(p.stat().st_mode & 0o777 == 0o644 for p in out.rglob("*") if p.is_file()))
        with self.assertRaises(SystemExit):
            unpack.npm(path, "sha512-" + base64.b64encode(bytes(64)).decode(), self.folder / "x")
        with self.assertRaises(SystemExit):
            unpack.npm(path, "sha256-" + base64.b64encode(hashlib.sha256(path.read_bytes()).digest()).decode(),
                       self.folder / "y")
        refused = [[("package/package.json", b"{}", None), ("other/x.js", b"x", None)],
                   [("package/package.json", b"{}", None), ("package/../x.js", b"x", None)],
                   [("package/package.json", b"{}", None), ("/package/x.js", b"x", None)],
                   [("package/package.json", b"{}", None), ("package/link.js", b"", "/etc/passwd")],
                   [("package/package.json", b"{}", None), ("package/a b.js", b"x", None)],
                   [("package/lib/index.js", b"x", None)],
                   [("package/package.json", b"{}", None)] + [(f"package/f{i}.js", b"x", None) for i in range(256)]]
        for index, members in enumerate(refused):
            bad = self.folder / f"bad{index}.tgz"
            tgz(bad, members)
            with self.subTest(index=index), self.assertRaises(SystemExit):
                unpack.npm(bad, integrity(bad), self.folder / f"out{index}")
        with patch.object(unpack, "MAX_NPM_BYTES", 10):
            with self.assertRaises(SystemExit):
                unpack.npm(path, integrity(path), self.folder / "capped")


class FakeDocker:
    def __init__(self, image_id="sha256:" + "a" * 64, base_present=True, on_build=None):
        self.calls, self.context, self.image_id, self.base_present = [], None, image_id, base_present
        self.on_build, self.built = on_build, {}

    def __call__(self, *args, capture=False):
        self.calls.append(args)
        if args[:2] == ("image", "inspect") and not self.base_present:
            raise subprocess.CalledProcessError(1, "docker")
        if args[0] == "build":
            context = Path(args[-1])
            self.context = sorted(str(path.relative_to(context)) for path in context.rglob("*"))
            self.built = {name: build.file_sha256(context / name) for name in ("worker.py", "driver.mjs")}
            if self.on_build:
                self.on_build()
            Path(args[args.index("--iidfile") + 1]).write_text(self.image_id)
        return "sha256:" + "b" * 64 if capture else None


class BuildToolTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.downloads = Path(self.folder.name)
        self.assets = {}
        for key, (name, _, check) in build.ASSETS.items():
            data = f"stand-in {name}".encode()
            (self.downloads / name).write_bytes(data)
            pin = ("sha256:" + hashlib.sha256(data).hexdigest() if check.startswith("sha256:")
                   else "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode())
            self.assets[key] = (name, len(data), pin)
        self.lock = self.downloads / "image.lock.json"

    def main(self, docker, assets=None):
        with patch.object(build, "ASSETS", assets or self.assets), patch.object(build, "docker", docker), \
                contextlib.redirect_stdout(io.StringIO()):
            return build.main(["--download-dir", str(self.downloads), "--lock", str(self.lock)])

    def private_source(self):
        source = Path(self.folder.name) / "source"
        shutil.copytree(build.SOURCE, source, ignore=shutil.ignore_patterns("image.lock.json"))
        patcher = patch.object(build, "SOURCE", source)
        patcher.start()
        self.addCleanup(patcher.stop)
        return source

    def test_the_pinned_downloads_are_the_contract_ones(self):
        self.assertEqual({key: value[0] for key, value in build.ASSETS.items()}, {
            "node_sha256": "node-v24.22.1-linux-arm64.tar.xz", "babel_parser_integrity": "parser-8.0.4.tgz",
            "babel_types_integrity": "types-8.0.4.tgz", "helper_string_parser_integrity": "helper-string-parser-8.0.6.tgz",
            "helper_validator_identifier_integrity": "helper-validator-identifier-8.0.6.tgz"})
        self.assertEqual(build.ASSETS["node_sha256"][1:], (30_978_868, "sha256:dbabf7a1cbf947e6059ffad2c27b80041db97dea"
                                                                       "1e553b62afdee7f13fca336e"))
        dockerfile = (build.SOURCE / "Dockerfile").read_text()
        for name, size, check in build.ASSETS.values():
            self.assertIn("downloads/" + name, dockerfile)
            self.assertIn(check.removeprefix("sha256:"), dockerfile)

    def test_a_build_never_pulls_runs_offline_and_writes_the_eleven_lock_keys(self):
        docker = FakeDocker()
        self.assertEqual(self.main(docker), 0)
        self.assertEqual(docker.calls[0], ("image", "inspect", "--format", "{{.Id}}", build.BASE))
        self.assertEqual(len(docker.calls), 2)
        self.assertEqual(docker.calls[1][:5], ("build", "--platform", "linux/arm64", "--pull=false", "--network=none"))
        self.assertEqual(sorted(name for name in docker.context if not name.startswith("downloads/")),
                         ["Dockerfile", "downloads", "driver.mjs", "unpack.py", "worker.py"])
        lock = json.loads(self.lock.read_text())
        self.assertEqual(set(lock), {"adapter_version", "platform", "base_digest", "node_sha256", "babel_parser_integrity",
                                     "babel_types_integrity", "helper_string_parser_integrity",
                                     "helper_validator_identifier_integrity", "driver_sha256", "worker_sha256", "image_id"})
        self.assertEqual((lock["adapter_version"], lock["platform"], lock["image_id"], lock["base_digest"]),
                         ("8.0.4-r2", "linux/arm64", docker.image_id, build.BASE_DIGEST))
        self.assertEqual(lock["node_sha256"], self.assets["node_sha256"][2].removeprefix("sha256:"))
        self.assertEqual(lock["babel_parser_integrity"], self.assets["babel_parser_integrity"][2])
        self.assertEqual(lock["driver_sha256"], build.file_sha256(build.SOURCE / "driver.mjs"))
        self.assertEqual(lock["worker_sha256"], build.file_sha256(build.SOURCE / "worker.py"))

    def test_missing_or_changed_downloads_and_a_missing_base_refuse_before_any_build(self):
        for key in self.assets:
            for change in ("size", "check"):
                name, size, check = self.assets[key]
                broken = dict(self.assets)
                broken[key] = (name, size + 1, check) if change == "size" else (name, size, check[:-4] + "AAA=")
                docker = FakeDocker()
                with self.subTest(key=key, change=change), self.assertRaises(SystemExit):
                    self.main(docker, broken)
                self.assertEqual(docker.calls, [])
        docker = FakeDocker(base_present=False)
        with self.assertRaises(SystemExit):
            self.main(docker)
        self.assertEqual(len(docker.calls), 1)
        self.assertFalse(self.lock.exists())

    def test_the_dockerfile_shape_is_checked_and_checked_again_after_the_copy(self):
        source = self.private_source()
        original = (source / "Dockerfile").read_text()
        for old, new in (("COPY --from=build /opt/node /opt/node", "COPY --from=build /etc /opt/node"),
                         ("RUN --network=none python3", "RUN python3"), ("FROM python:3.12-slim@", "FROM python:3.13-slim@"),
                         ("USER 65534:65534", "USER 0:0"), ("COPY driver.mjs", "ADD driver.mjs")):
            with self.subTest(change=new):
                self.assertIn(old, original)
                (source / "Dockerfile").write_text(original.replace(old, new, 1))
                docker = FakeDocker()
                with self.assertRaises(SystemExit):
                    self.main(docker)
                self.assertEqual(docker.calls, [])
        (source / "Dockerfile").write_text(original)
        real_copy = shutil.copy2

        def copy(src, dst, *args, **kwargs):
            result = real_copy(src, dst, *args, **kwargs)
            if Path(dst).name == "Dockerfile":
                Path(dst).write_text(original.replace("RUN --network=none python3", "RUN python3", 1))
            return result

        docker = FakeDocker()
        with patch.object(build.shutil, "copy2", copy), self.assertRaises(SystemExit):
            self.main(docker)
        self.assertFalse(any(call[0] == "build" for call in docker.calls))

    def test_the_lock_names_the_copied_bytes_and_an_edit_during_or_after_the_copy_writes_no_lock(self):
        source = self.private_source()
        for name in ("worker.py", "driver.mjs"):
            original = (source / name).read_bytes()

            def edit(name=name):
                with open(source / name, "ab") as stream:
                    stream.write(b"\n# edited during the build\n" if name.endswith(".py") else b"\n// edited\n")

            docker = FakeDocker(on_build=edit)
            with self.subTest(during=name), self.assertRaisesRegex(SystemExit, "changed during the build"):
                self.main(docker)
            self.assertEqual(docker.built[name], hashlib.sha256(original).hexdigest())
            self.assertFalse(self.lock.exists())
            (source / name).write_bytes(original)
            real_copy = shutil.copy2

            def copy(src, dst, *args, name=name, **kwargs):
                result = real_copy(src, dst, *args, **kwargs)
                if Path(src) == source / name:
                    edit(name)
                return result

            docker = FakeDocker()
            with self.subTest(after_copy=name), patch.object(build.shutil, "copy2", copy), \
                    self.assertRaisesRegex(SystemExit, "changed during the build"):
                self.main(docker)
            self.assertEqual(docker.built[name], hashlib.sha256(original).hexdigest())
            self.assertFalse(self.lock.exists())
            (source / name).write_bytes(original)

    def test_the_committed_lock_names_the_committed_worker_and_driver(self):
        lock = json.loads((build.SOURCE / "image.lock.json").read_text())
        self.assertEqual(lock["driver_sha256"], build.file_sha256(build.SOURCE / "driver.mjs"))
        self.assertEqual(lock["worker_sha256"], build.file_sha256(build.SOURCE / "worker.py"))
        self.assertEqual({key: lock[key] for key in build.ASSETS},
                         {key: check.removeprefix("sha256:") for key, (_, _, check) in build.ASSETS.items()})
        self.assertRegex(lock["image_id"], r"^sha256:[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
