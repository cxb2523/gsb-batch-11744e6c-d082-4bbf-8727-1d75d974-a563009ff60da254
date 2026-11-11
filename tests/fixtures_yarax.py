"""Inert signature fixtures with declared bytes and exact expected matches; no scanning library."""

import copy
import json

from reverseai.contract import WORKER_PROTOCOL, sha256_hex
from tests.test_contained import lock

RULESET_SHA256 = "e2217ff703858af17fe8eee8ac0d4cc44dfefd632e096bb4b527b89b08a062a7"


def yarax_lock():
    return dict(lock(), adapter_version="1.21.0-r2", ruleset_sha256=RULESET_SHA256)


def match(offset, literal=b"UPX!", rule="upx_packed", pattern="$a"):
    return {"location": {"offset": offset, "length": len(literal)},
            "value": {"ruleset": "m2_fixture_v1", "rule": rule, "pattern": pattern}}


def known_matches():
    chunks = ((b"UPX!", "upx_packed", "$a"),
              (b"-EncodedCommand", "powershell_encoded_command", "$a"),
              ("FromBase64String".encode("utf-16le"), "base64_decode_api", "$w"),
              (b"UPX0", "upx_packed", "$b"))
    data, observations = b"", []
    for literal, rule, pattern in chunks:
        data += b"\x00"
        observations.append(match(len(data), literal, rule, pattern))
        data += literal
    return data + b"\x00", observations


def pattern_table(count=16, repeats=4):
    """A synthetic ruleset at the 64-observation budget, with declared disjoint four-byte literals."""
    data, observations, patterns = b"", [], []
    for index in range(count):
        literal, pattern = bytes((0x55, index, 0x50, 0x58)), f"$p{index}"
        patterns.append({"id": pattern, "hex": literal.hex()})
        for _ in range(repeats):
            observations.append(match(len(data), literal, "table", pattern))
            data += literal
    ruleset = {"ruleset": "m2_fixture_v1", "rules": [{"id": "table", "category": "packer", "patterns": patterns}]}
    return json.dumps(ruleset).encode(), data, observations


def reply(data, observations=()):
    return {"protocol": WORKER_PROTOCOL, "status": "ok", "snapshot_sha256": sha256_hex(data),
            "observations": copy.deepcopy(list(observations))}


class FakeExecutor:
    def __init__(self, response):
        self.lock = yarax_lock()
        self.response = response
        self.calls = []

    def run(self, *args):
        self.calls.append(args)
        return json.dumps(self.response).encode()
