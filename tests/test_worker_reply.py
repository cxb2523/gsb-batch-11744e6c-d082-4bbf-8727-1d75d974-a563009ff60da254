import json
import unittest

from reverseai.contract import (
    MAX_WORKER_REPLY_BYTES, WORKER_PROTOCOL, ContractError, Location, ToolRef, ToolSpec, WorkerError, parse_worker_reply,
)

DIGEST = "ab" * 32


def reply(**changes):
    body = {"protocol": WORKER_PROTOCOL, "status": "ok", "snapshot_sha256": DIGEST,
            "observations": [{"location": {"offset": 0, "length": 64}, "value": {"format": "elf", "shnum": 5}}]}
    body.update(changes)
    return json.dumps(body).encode()


class WorkerReplyTests(unittest.TestCase):
    def parse(self, raw, cap=3):
        return parse_worker_reply(raw, input_sha256=DIGEST, max_observations=cap)

    def test_a_valid_reply_becomes_observations(self):
        (observation,) = self.parse(reply())
        self.assertEqual((observation.location, observation.value), (Location(0, 64), {"format": "elf", "shnum": 5}))

    def test_a_worker_error_carries_only_a_class_name(self):
        with self.assertRaises(WorkerError) as caught:
            self.parse(json.dumps({"protocol": WORKER_PROTOCOL, "status": "error", "snapshot_sha256": DIGEST, "error": "LiefError"}).encode())
        self.assertEqual(str(caught.exception), "LiefError")
        for bad in ("/etc/passwd", "Error: secret bytes", ""):
            with self.subTest(bad=bad), self.assertRaises(ContractError) as refused:
                self.parse(json.dumps({"protocol": WORKER_PROTOCOL, "status": "error", "snapshot_sha256": DIGEST, "error": bad}).encode())
            self.assertNotIsInstance(refused.exception, WorkerError)

    def test_refusals(self):
        too_many = [{"location": {"offset": i, "length": 1}, "value": {}} for i in range(4)]
        cases = {
            "other snapshot": reply(snapshot_sha256="cd" * 32),
            "unknown protocol": reply(protocol="reverseai.worker/2"),
            "worker evidence id": reply(id="ev-0123456789abcdef"),
            "excerpt hash smuggled": reply(observations=[{"location": {"offset": 0, "length": 4}, "value": {}, "excerpt_sha256": DIGEST}]),
            "over the cap": reply(observations=too_many),
            "bad location": reply(observations=[{"location": {"offset": -1, "length": 4}, "value": {}}]),
            "oversized location": reply(observations=[{"location": {"offset": 0, "length": 5000}, "value": {}}]),
            "non-JSON value": b'{"protocol": "reverseai.worker/1", "status": "ok", "snapshot_sha256": "' + DIGEST.encode() + b'", "observations": [{"location": {"offset": 0, "length": 1}, "value": {"x": NaN}}]}',
            "duplicate keys": b'{"protocol": "reverseai.worker/1", "status": "ok", "status": "ok", "snapshot_sha256": "' + DIGEST.encode() + b'", "observations": []}',
            "not UTF-8": b"\xff\xfe{}",
            "not an object": b"[]",
            "too large": b" " * (MAX_WORKER_REPLY_BYTES + 1),
        }
        for label, raw in cases.items():
            with self.subTest(label), self.assertRaises(ContractError):
                self.parse(raw)

    def test_runtime_identity_belongs_to_contained_tools_only(self):
        ToolSpec(ToolRef("lief", "1.0.0-r2"), {}, contained=True, runtime={"image": "sha256:" + "0" * 64, "platform": "linux/arm64"})
        with self.assertRaises(ContractError):
            ToolSpec(ToolRef("structure", "0.1.0"), {}, runtime={"image": "x"})
        with self.assertRaises(ContractError):
            ToolSpec(ToolRef("lief", "1.0.0-r2"), {}, contained=True, runtime={"image": "bad\nvalue"})


if __name__ == "__main__":
    unittest.main()
