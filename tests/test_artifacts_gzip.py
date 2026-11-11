"""Children inside one whole gzip stream (artifact method 1)."""

import gzip
import io
import tarfile
import unittest
import zlib

import reverseai.contract as contract_module
import reverseai.gateway as gateway_module
import reverseai.review as review_module
from reverseai import claims
from reverseai.contract import (
    AnalysisResult, AnalysisTask, Budget, ContractError, InputRef, Location, Observation, OperationRequest,
    OperationSpec, ToolRef, ToolSpec, check_artifact, content_id, inflate_stream, make_evidence, make_finding,
    materialize, sha256_hex,
)
from reverseai.gateway import Gateway
from reverseai.review import review


def tarball(files):
    """A code-built npm-style tarball and the decompressed offset of each file (test inputs only)."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, body in files:
            info = tarfile.TarInfo("package/" + name)
            info.size, info.mtime = len(body), 0
            archive.addfile(info, io.BytesIO(body))
    stream = raw.getvalue()
    offsets = {name: stream.index(body) for name, body in files}
    return gzip.compress(stream, mtime=0), stream, offsets


FILES = [("index.js", b"fetch('https://example.test/x');\n"), ("lib/a.js", b"eval(atob('eA=='));\n")]
DATA, STREAM, OFFSETS = tarball(FILES)
INPUT = InputRef(sha256_hex(DATA), len(DATA), "pkg.tgz")
B_JS = b"atob('eA==');\n"
SECOND, _, SECOND_OFFSETS = tarball([("b.js", B_JS)])  # a second stream, right after DATA in a two-stream input


def artifact(name, **change):
    body = dict(FILES)[name]
    value = {"member": "package/" + name, "method": 1, "data_offset": 0, "compressed_size": len(DATA),
             "inner_offset": OFFSETS[name], "size": len(body), "crc32": zlib.crc32(body), "sha256": sha256_hex(body)}
    value.update(change)
    return value


def second_artifact():
    return {"member": "package/b.js", "method": 1, "data_offset": len(DATA), "compressed_size": len(SECOND),
            "inner_offset": SECOND_OFFSETS["b.js"], "size": len(B_JS), "crc32": zlib.crc32(B_JS), "sha256": sha256_hex(B_JS)}


def patched(module, name, value):
    """Set a module constant for one test step and give back a restore function."""
    real = getattr(module, name)
    setattr(module, name, value)
    return lambda: setattr(module, name, real)


def reviewed(data, artifacts, bodies):
    """Review one observed finding per child of data: sorted verdict statuses and the reviewer's gzip inflations."""
    tool = ToolRef("js", "0.1.0")
    tools = {"js": ToolSpec(tool, {"js.files": OperationSpec("js.files", {}, lambda d, a: [])})}
    evidence = [make_evidence(data, tool, "js.files", Observation(Location(0, 4), {"kind": "x"}, value), child=body)
                for value, body in zip(artifacts, bodies)]
    findings = [make_finding("structural", "Gz %d." % i, "test.gz", "gz", [e.id], "observed")
                for i, e in enumerate(evidence)]
    calls, real = [], review_module.inflate_stream
    review_module.inflate_stream = lambda *args: calls.append(args) or real(*args)
    try:
        result = AnalysisResult(content_id("tk", {"t": "gz"}), "structural", "ok", tuple(evidence), tuple(findings))
        verdicts = review(data, InputRef(sha256_hex(data), len(data), "pkg.tgz"), [result], tools)
    finally:
        review_module.inflate_stream = real
    return sorted(v.status for v in verdicts), len(calls)


class GzipStreamTests(unittest.TestCase):
    def test_the_whole_stream_inflates_with_header_options_and_trailer_checked(self):
        self.assertEqual(inflate_stream(DATA, 0, len(DATA)), STREAM)
        header = bytearray(DATA[:10])
        header[3] = 8 | 2  # FNAME and FHCRC
        named = bytes(header) + b"pkg.tar\x00"
        named += zlib.crc32(named).to_bytes(4, "little")[:2]
        with_name = named + DATA[10:]
        self.assertEqual(inflate_stream(with_name, 0, len(with_name)), STREAM)
        bad = [DATA + b"x", DATA[:-1], DATA[:-8] + bytes(8), b"\x1f\x8b\x07" + DATA[3:], DATA[:3] + b"\x20" + DATA[4:]]
        for value in bad:
            with self.assertRaises(ContractError):
                inflate_stream(value, 0, len(value))
        bomb = gzip.compress(bytes(1 << 20), mtime=0)
        self.assertGreater(1 << 20, 100 * len(bomb))
        with self.assertRaises(ContractError):
            inflate_stream(bomb, 0, len(bomb))

    def test_a_member_is_its_exact_range_of_the_stream(self):
        for name, body in FILES:
            self.assertEqual(materialize(DATA, artifact(name)), body)
        for value in (artifact("index.js", inner_offset=OFFSETS["index.js"] + 1), artifact("index.js", crc32=1),
                      artifact("index.js", size=len(STREAM)), artifact("index.js", compressed_size=len(DATA) - 1),
                      artifact("index.js", method=8), {**artifact("index.js"), "extra": 1}):
            with self.assertRaises(ContractError, msg=value):
                materialize(DATA, value)
        stored = {k: v for k, v in artifact("index.js").items() if k != "inner_offset"}
        with self.assertRaises(ContractError):
            check_artifact(stored)  # method 1 needs inner_offset
        with self.assertRaises(ContractError):
            check_artifact({**artifact("index.js"), "inner_offset": 10**9, "compressed_size": 10})  # past 100:1

    def test_one_inflation_serves_every_member_through_the_cache(self):
        streams, calls, real = {}, [], inflate_stream
        contract_module.inflate_stream = lambda *args: calls.append(args) or real(*args)
        try:
            for name, _ in FILES:
                materialize(DATA, artifact(name), streams=streams)
        finally:
            contract_module.inflate_stream = real
        self.assertEqual(len(calls), 1)

    def test_the_reviewer_inflates_a_stream_once_and_charges_its_bound(self):
        claims.RULES["test.gz"] = ("observed", {"js.files": lambda observations: "gz"})
        self.addCleanup(claims.RULES.pop, "test.gz")
        names = [name for name, _ in FILES]
        self.assertEqual(reviewed(DATA, [artifact(n) for n in names], [dict(FILES)[n] for n in names]),
                         (["supported", "supported"], 1))

    # Each stream guard pinned on its own, with a positive control
    def test_a_wrong_header_crc_refuses_the_stream(self):
        header = bytearray(DATA[:10])
        header[3] = 2  # FHCRC alone
        crc = zlib.crc32(bytes(header)) & 0xFFFF
        for value, accepted in ((crc, True), (crc ^ 1, False)):
            framed = bytes(header) + value.to_bytes(2, "little") + DATA[10:]
            if accepted:
                self.assertEqual(inflate_stream(framed, 0, len(framed)), STREAM)
            else:
                with self.assertRaises(ContractError):
                    inflate_stream(framed, 0, len(framed))

    def test_the_absolute_stream_cap_holds_apart_from_the_ratio(self):
        self.assertGreater(100 * len(DATA), len(STREAM))  # the ratio alone admits this stream
        for cap, accepted in ((len(STREAM), True), (len(STREAM) - 1, False)):
            restore = patched(contract_module, "MAX_STREAM_BYTES", cap)
            try:
                if accepted:
                    self.assertEqual(inflate_stream(DATA, 0, len(DATA)), STREAM)
                else:
                    with self.assertRaises(ContractError):
                        inflate_stream(DATA, 0, len(DATA))
            finally:
                restore()

    def test_the_reviewer_remembers_a_failed_stream_for_every_child(self):
        claims.RULES["test.gz"] = ("observed", {"js.files": lambda observations: "gz"})
        self.addCleanup(claims.RULES.pop, "test.gz")
        bad = DATA[:-8] + bytes([DATA[-8] ^ 1]) + DATA[-7:]  # trailer CRC-32 off by one bit
        names = [name for name, _ in FILES]
        bodies = [dict(FILES)[n] for n in names]
        statuses, calls = reviewed(bad, [artifact(n, compressed_size=len(bad)) for n in names], bodies)
        self.assertEqual((calls, "supported" in statuses), (1, False))

    def test_the_reviewer_refuses_a_stream_over_its_budget_before_inflating_it(self):
        claims.RULES["test.gz"] = ("observed", {"js.files": lambda observations: "gz"})
        self.addCleanup(claims.RULES.pop, "test.gz")
        data, bounds = DATA + SECOND, 100 * len(DATA) + 100 * len(SECOND)  # each below the cap, so each bound is its ratio
        for budget, expected in ((bounds, (["supported", "supported"], 2)), (bounds - 1, (["supported", "unsupported"], 1))):
            restore = patched(review_module, "MAX_STREAM_BYTES", budget)
            try:
                result = reviewed(data, [artifact("index.js"), second_artifact()], [FILES[0][1], B_JS])
            finally:
                restore()
            self.assertEqual(result, expected)

    # The gateway charges a new stream's bound before inflating it
    def test_the_gateway_refuses_a_new_stream_before_inflating_past_the_cap(self):
        data, bounds = DATA + SECOND, 100 * len(DATA) + 100 * len(SECOND)
        tool = ToolRef("js", "0.1.0")
        operation = OperationSpec("js.files", {}, lambda d, a: [
            Observation(Location(0, 4), {"kind": "x"}, artifact("index.js")),
            Observation(Location(0, 4), {"kind": "x"}, second_artifact())])
        task = AnalysisTask(content_id("tk", {"t": "two"}), "structural", InputRef(sha256_hex(data), len(data), "two.tgz"),
                            (OperationRequest("js.files"),), Budget())
        # Over the cap, the first child is kept and the second stream is never inflated.
        for cap, expected in ((bounds, ("ok", 2, 2)), (bounds - 1, ("budget_exceeded", 1, 1))):
            calls, real = [], contract_module.inflate_stream
            contract_module.inflate_stream = lambda *args: calls.append(args) or real(*args)
            restore = patched(gateway_module, "MAX_STREAM_BYTES", cap)
            try:
                result = Gateway((ToolSpec(tool, {"js.files": operation}),), Budget()).run(task, data)
            finally:
                restore()
                contract_module.inflate_stream = real
            self.assertEqual((result.status, len(calls), len(result.evidence)), expected)

if __name__ == "__main__":
    unittest.main()
