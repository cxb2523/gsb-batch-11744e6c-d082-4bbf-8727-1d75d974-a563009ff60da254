"""The YARA-X worker's pure logic, without yara_x: ruleset checks, generated source, requests, cross-checks and the reply.

A fake yara_x stands in for the bindings; it reports matches the way yara_x groups them (rule, then pattern, then
offset), so the worker's own ordering, deduplication and cut are what the tests see. Expected matches come from an
independent oracle: bytes.find over the fixture for every pattern of the ruleset file, read here with json alone.
"""

import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

from reverseai.contract import WorkerError, parse_worker_reply, sha256_hex

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "containers" / "yarax"
SPEC = importlib.util.spec_from_file_location("yarax_worker", SOURCE / "worker.py")
worker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(worker)
RULESET = json.loads((SOURCE / "m2_fixture_v1.json").read_text(encoding="utf-8"))
PATTERNS = [(rule["id"], pattern["id"], bytes.fromhex(pattern["hex"])) for rule in RULESET["rules"] for pattern in rule["patterns"]]


def oracle(data, limit=32):
    """The first 4 occurrences of every pattern, as (offset, rule, pattern, length),
    ascending and cut at limit."""
    found = set()
    for rule, pattern, needle in PATTERNS:
        at, kept = data.find(needle), 0
        while at != -1 and kept < 4:
            found.add((at, rule, pattern, len(needle)))
            at, kept = data.find(needle, at + 1), kept + 1
    return sorted(found)[:limit]


def u16(text):
    return text.encode("utf-16-le")


FIXTURES = {
    "upx markers": b"MZ" + bytes(62) + b"UPX0" + bytes(28) + b"UPX1" + bytes(60) + b"UPX!\x0d\x24\x08\x09" + bytes(32),
    "utf16le strings": (b"\xff\xfe" + u16("powershell -EncodedCommand ") + bytes(6) + u16("[Convert]::FromBase64String")
                        + bytes(4) + u16("sekurlsa::logonpasswords") + b"FromBase64String" + b"-EncodedCommand" + b"sekurlsa::"),
    "clean control": b"ReverseAI clean control: UPX UPX? -Encoded FromBase64 sekurlsa: " * 32 + bytes(range(256)),
    "flood of repeats": b"UPX!" * 300 + b"sekurlsa::" + b"UPX0" * 100,
    "flood then a later rule": b"UPX!" * 64 + b"sekurlsa::",
    "every pattern four times": b"|".join(needle * 4 for _, _, needle in PATTERNS),
    "rules interleaved": b"sekurlsa::" + b"UPX1" + u16("-EncodedCommand") + b"UPX!",
    "empty": b"",
}


class FakeYaraX:
    """yara_x's Compiler/Scanner surface; scan() reports what report(data, source) returns, grouped like yara_x."""

    class CompileError(Exception):
        pass

    class ScanError(Exception):
        pass

    class TimeoutError(Exception):
        pass

    def __init__(self, report=None, warnings=(), imports=(), namespace="default", fail=None):
        self.report = report or self.honest
        self.warnings, self.imports, self.namespace, self.fail = list(warnings), list(imports), namespace, fail
        self.compiler_options, self.sources, self.scanner_settings = None, [], {}
        fake = self

        class Compiler:
            def __init__(self, **options):
                fake.compiler_options = options

            def add_source(self, src, origin=None):
                fake.sources.append((src, origin))
                if fake.fail == "compile":
                    raise fake.CompileError("rule error")

            def warnings(self):
                return fake.warnings

            def build(self):
                return types.SimpleNamespace(imports=lambda: fake.imports)

        class Scanner:
            def __init__(self, rules):
                pass

            def set_timeout(self, seconds):
                fake.scanner_settings["timeout"] = seconds

            def max_matches_per_pattern(self, matches):
                fake.scanner_settings["per_pattern"] = matches

            def fast_scan(self, yes):
                fake.scanner_settings["fast_scan"] = yes

            def scan(self, data):
                if fake.fail == "timeout":
                    raise fake.TimeoutError("timeout")
                if fake.fail == "scan":
                    raise fake.ScanError("scan")
                grouped = {}
                for rule, pattern, offset, length in fake.report(data, fake.sources[-1][0]):
                    grouped.setdefault(rule, {}).setdefault(pattern, []).append(
                        types.SimpleNamespace(offset=offset, length=length, xor_key=None))
                return types.SimpleNamespace(matching_rules=tuple(
                    types.SimpleNamespace(identifier=rule, namespace=fake.namespace, patterns=tuple(
                        types.SimpleNamespace(identifier=pattern, matches=tuple(matches)) for pattern, matches in patterns.items()))
                    for rule, patterns in grouped.items()))

        self.Compiler, self.Scanner = Compiler, Scanner

    def honest(self, data, source):
        """Matches found by comparing at every offset, at most the per-pattern limit each, per rule and pattern."""
        limit = self.scanner_settings.get("per_pattern", 10**9)
        found = []
        for rule, pattern, needle in PATTERNS:
            hits = [at for at in range(len(data) - len(needle) + 1) if data[at:at + len(needle)] == needle]
            found += [(rule, pattern, at, len(needle)) for at in hits[:limit]]
        return found


def run(data, fake=None, **args):
    fake = fake or FakeYaraX()
    return worker.reply(["yarax.matches", json.dumps(args)], data, lambda data_, name: worker.yara_matches(data_, name, yara_x=fake))


def rows(reply):
    return [(item["location"]["offset"], item["value"]["rule"], item["value"]["pattern"], item["location"]["length"])
            for item in reply["observations"]]


class SourceTests(unittest.TestCase):
    def test_generated_source_is_exact(self):
        ruleset = dict(worker.check_ruleset({"ruleset": "m2_fixture_v1", "rules": [
            {"id": "first_rule", "category": "packer", "patterns": [{"id": "$a", "hex": "00ff10ab"}, {"id": "$w", "hex": "41004200"}]},
            {"id": "second", "category": "execution", "patterns": [{"id": "$z9", "hex": "deadbeef"}]}]}, "m2_fixture_v1"))
        self.assertEqual(worker.yara_source(ruleset),
                         "rule first_rule {\n  strings:\n    $a = { 00 ff 10 ab }\n    $w = { 41 00 42 00 }\n"
                         "  condition:\n    any of them\n}\n\n"
                         "rule second {\n  strings:\n    $z9 = { de ad be ef }\n  condition:\n    any of them\n}\n")

    def test_the_reviewed_ruleset_generates_one_hex_string_per_pattern_and_nothing_else(self):
        source = worker.yara_source(worker.load_ruleset("m2_fixture_v1"))
        self.assertEqual(re.findall(r"^rule (\w+) \{$", source, re.M), [rule["id"] for rule in RULESET["rules"]])
        strings = re.findall(r"^    (\$\w+) = \{ ([0-9a-f ]+) \}$", source, re.M)
        self.assertEqual([(name, bytes.fromhex(text)) for name, text in strings], [(p, b) for _, p, b in PATTERNS])
        self.assertEqual(source.count("any of them"), len(RULESET["rules"]))
        for word in ("import", "include", "external", "\"", "/", "?", "[", "("):
            self.assertNotIn(word, source)

    def test_compiler_and_scanner_settings_are_explicit(self):
        fake = FakeYaraX()
        self.assertEqual(run(FIXTURES["upx markers"], fake)["status"], "ok")
        self.assertEqual(fake.compiler_options, {"relaxed_re_syntax": False, "error_on_slow_pattern": True,
                                                 "includes_enabled": False})
        self.assertEqual(fake.sources, [(worker.yara_source(worker.load_ruleset("m2_fixture_v1")), "m2_fixture_v1")])
        self.assertEqual(fake.scanner_settings, {"timeout": 30, "per_pattern": 4, "fast_scan": False})
        self.assertLess(worker.SCAN_TIMEOUT, 45)

    def test_compile_errors_other_warnings_and_module_imports_refuse_the_ruleset(self):
        text_as_hex = {"code": "text_as_hex", "title": "hex pattern could be written as text literal"}
        self.assertEqual(run(b"UPX!", FakeYaraX(warnings=[text_as_hex, text_as_hex]))["status"], "ok")
        for label, fake in (("compile error", FakeYaraX(fail="compile")),
                            ("other warning", FakeYaraX(warnings=[text_as_hex, {"code": "slow_pattern"}])),
                            ("warning of another shape", FakeYaraX(warnings=["text_as_hex"])),
                            ("module import", FakeYaraX(imports=["pe"]))):
            with self.subTest(label):
                self.assertEqual(run(b"UPX!", fake)["error"], "RulesetInvalid")


class RulesetTests(unittest.TestCase):
    def check(self, change):
        value = json.loads(json.dumps(RULESET))
        change(value)
        return worker.check_ruleset(value, "m2_fixture_v1")

    def test_the_reviewed_file_is_accepted(self):
        self.assertEqual(worker.load_ruleset("m2_fixture_v1"),
                         {rule: {p: b for r, p, b in PATTERNS if r == rule} for rule in dict.fromkeys(r for r, _, _ in PATTERNS)})

    def test_a_pattern_id_may_have_32_characters_after_the_dollar(self):
        self.check(lambda v: v["rules"][0]["patterns"][0].update(id="$" + "a" * 32))

    def test_at_most_16_patterns_so_every_one_fits_max_matches_at_4_each(self):
        def patterns(count):
            return [{"id": f"$p{i}", "hex": f"{i:08x}"} for i in range(count)]
        self.check(lambda v: v.update(rules=[{"id": "many", "category": "packer", "patterns": patterns(16)}]))
        for rules in ([{"id": "many", "category": "packer", "patterns": patterns(17)}],
                      [{"id": "first", "category": "packer", "patterns": patterns(9)},
                       {"id": "second", "category": "packer", "patterns": patterns(8)}]):
            with self.subTest(patterns=sum(len(r["patterns"]) for r in rules)), self.assertRaises(worker.RulesetInvalid):
                self.check(lambda v, rules=rules: v.update(rules=rules))

    def test_pattern_length_bounds_are_4_and_256_bytes(self):
        for size in (4, 256):
            with self.subTest(size=size):
                self.check(lambda v: v["rules"][0]["patterns"][0].update(hex="ab" * size))

    def test_every_other_shape_is_refused(self):
        first = lambda v: v["rules"][0]
        pattern = lambda v: v["rules"][0]["patterns"][0]
        cases = {
            "other ruleset name": lambda v: v.update(ruleset="other"),
            "extra top-level key": lambda v: v.update(imports=[]),
            "no rules": lambda v: v.update(rules=[]),
            "rule not an object": lambda v: v["rules"].append("rule x"),
            "rule extra key": lambda v: first(v).update(condition="true"),
            "rule missing category": lambda v: first(v).pop("category"),
            "duplicate rule id": lambda v: v["rules"].append(json.loads(json.dumps(first(v)))),
            "keyword rule id": lambda v: first(v).update(id="condition"),
            "upper-case rule id": lambda v: first(v).update(id="UPX"),
            "rule id with a space": lambda v: first(v).update(id="upx packed"),
            "category not an identifier": lambda v: first(v).update(category="packer; import"),
            "no patterns": lambda v: first(v).update(patterns=[]),
            "pattern extra key": lambda v: pattern(v).update(modifiers="nocase"),
            "pattern id without $": lambda v: pattern(v).update(id="a"),
            "pattern id with a space": lambda v: pattern(v).update(id="$a b"),
            "pattern id with an assignment": lambda v: pattern(v).update(id='$a = "x"'),
            "upper-case pattern id": lambda v: pattern(v).update(id="$A"),
            "pattern id of 33 characters after $": lambda v: pattern(v).update(id="$" + "a" * 33),
            "duplicate pattern id": lambda v: first(v)["patterns"].append(dict(pattern(v), hex="00000000")),
            "odd hex": lambda v: pattern(v).update(hex="5550582"),
            "upper-case hex": lambda v: pattern(v).update(hex="5550582A"),
            "wildcard": lambda v: pattern(v).update(hex="5550??21"),
            "jump": lambda v: pattern(v).update(hex="5550[2]21"),
            "spaces": lambda v: pattern(v).update(hex="55 50 58 21"),
            "3 bytes": lambda v: pattern(v).update(hex="555058"),
            "257 bytes": lambda v: pattern(v).update(hex="ab" * 257),
            "hex not a string": lambda v: pattern(v).update(hex=1431330849),
        }
        for label, change in cases.items():
            with self.subTest(label), self.assertRaises(worker.RulesetInvalid):
                self.check(change)

    def test_the_file_must_be_small_unique_json_with_a_known_name(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder, "m2_fixture_v1.json")
            text = json.dumps(RULESET)
            for label, content in (("duplicate key", text[:-1] + ', "ruleset": "m2_fixture_v1"}'),
                                   ("not JSON", "rule upx { condition: true }"),
                                   ("too large", text + " " * worker.MAX_RULESET_BYTES)):
                with self.subTest(label), self.assertRaises(worker.RulesetInvalid):
                    path.write_text(content)
                    worker.load_ruleset("m2_fixture_v1", folder)
            path.unlink()
            with self.assertRaises(worker.RulesetInvalid):
                worker.load_ruleset("m2_fixture_v1", folder)
        with self.assertRaises(worker.RulesetInvalid):
            worker.load_ruleset("other")


class MatchTests(unittest.TestCase):
    def test_matches_equal_the_oracle_for_every_fixture_and_cut(self):
        for label, data in FIXTURES.items():
            for limit in (1, 32, 64):
                with self.subTest(label, max_matches=limit):
                    reply = run(data, max_matches=limit)
                    self.assertEqual(reply["status"], "ok")
                    self.assertEqual(rows(reply), oracle(data, limit))
                    self.assertTrue(all(item["value"]["ruleset"] == "m2_fixture_v1" and set(item["value"]) == {"ruleset", "rule", "pattern"}
                                        for item in reply["observations"]))

    def test_known_answers(self):
        self.assertEqual(rows(run(FIXTURES["upx markers"])), [(64, "upx_packed", "$b", 4), (96, "upx_packed", "$c", 4),
                                                             (160, "upx_packed", "$a", 4)])
        self.assertEqual(rows(run(FIXTURES["rules interleaved"])), [(0, "credential_dump_marker", "$a", 10), (10, "upx_packed", "$c", 4),
                                                                   (14, "powershell_encoded_command", "$w", 30), (44, "upx_packed", "$a", 4)])
        self.assertEqual(rows(run(FIXTURES["clean control"])), [])
        upx_a = [(4 * i, "upx_packed", "$a", 4) for i in range(4)]
        self.assertEqual(rows(run(FIXTURES["flood of repeats"], max_matches=64)),
                         upx_a + [(1200, "credential_dump_marker", "$a", 10)] + [(1210 + 4 * i, "upx_packed", "$b", 4) for i in range(4)])

    def test_a_flood_of_one_pattern_cannot_hide_a_later_rule(self):
        """64 early repeats used to fill max_matches and drop credential_dump_marker."""
        reply = run(FIXTURES["flood then a later rule"], max_matches=64)
        self.assertEqual(rows(reply), [(4 * i, "upx_packed", "$a", 4) for i in range(4)] + [(256, "credential_dump_marker", "$a", 10)])

    def test_the_default_cut_is_32_and_the_cap_leaves_every_pattern_room(self):
        data = FIXTURES["every pattern four times"]
        self.assertEqual(len(run(data)["observations"]), 32)
        self.assertEqual(len(run(data, max_matches=64)["observations"]), 4 * len(PATTERNS))
        self.assertLessEqual(4 * len(PATTERNS), worker.MATCHES[1])

    def test_reported_order_and_repeats_do_not_change_the_reply(self):
        data = FIXTURES["utf16le strings"]

        def scrambled(data_, source):
            honest = FakeYaraX().honest(data_, source)
            return list(reversed(honest)) + honest[:3]

        self.assertEqual(rows(run(data, FakeYaraX(report=scrambled))), oracle(data))

    def test_every_match_the_bytes_or_the_ruleset_do_not_confirm_is_refused(self):
        data = b"x" + b"UPX!" + b"UPX!" + b"yy"  # True is 1, where "UPX!" starts
        good = [("upx_packed", "$a", 5, 4)]
        for label, bad in (("bytes differ at the offset", ("upx_packed", "$a", 6, 4)),
                           ("length differs from the pattern", ("upx_packed", "$a", 5, 3)),
                           ("other pattern's bytes", ("upx_packed", "$b", 5, 4)),
                           ("pattern of another rule", ("credential_dump_marker", "$a", 5, 4)),
                           ("unknown rule", ("other_rule", "$a", 5, 4)),
                           ("unknown pattern", ("upx_packed", "$z", 5, 4)),
                           ("negative offset", ("upx_packed", "$a", -2, 4)),
                           ("offset past the input", ("upx_packed", "$a", len(data), 4)),
                           ("offset not an int", ("upx_packed", "$a", 5.0, 4)),
                           ("offset a bool", ("upx_packed", "$a", True, 4))):
            with self.subTest(label):
                fake = FakeYaraX(report=lambda data_, source, bad=bad: good + [bad])
                self.assertEqual(run(data, fake)["error"], "InconsistentMatch")
        self.assertEqual(run(data, FakeYaraX(namespace="other"))["error"], "InconsistentMatch")
        ends, tail = b"x" * 8 + b"UPX!", b"x" * 8 + b"UPX!yy"
        for label, data_, bad in (("length past the end, bytes still equal", ends, ("upx_packed", "$a", len(ends) - 4, 100)),
                                  ("negative offset whose slice holds the pattern", tail, ("upx_packed", "$a", -6, 4))):
            with self.subTest(label):
                self.assertEqual(data_[bad[2]:bad[2] + bad[3]], b"UPX!")  # only the length or offset check can refuse it
                self.assertEqual(run(data_, FakeYaraX(report=lambda d, s, bad=bad: [bad]))["error"], "InconsistentMatch")
        self.assertEqual(rows(run(data, FakeYaraX(report=lambda data_, source: good))), [(5, "upx_packed", "$a", 4)])

    def test_scan_failures_have_their_own_errors(self):
        self.assertEqual(run(b"UPX!", FakeYaraX(fail="timeout"))["error"], "ScanTimeout")
        self.assertEqual(run(b"UPX!", FakeYaraX(fail="scan"))["error"], "ScanFailed")


class RequestTests(unittest.TestCase):
    def test_requests_are_exact(self):
        for text, expected in (("{}", {"ruleset": "m2_fixture_v1", "max_matches": 32}),
                               ('{"max_matches": 1}', {"ruleset": "m2_fixture_v1", "max_matches": 1}),
                               ('{"max_matches": 64, "ruleset": "m2_fixture_v1"}', {"ruleset": "m2_fixture_v1", "max_matches": 64})):
            with self.subTest(text):
                self.assertEqual(worker.parse_request(["yarax.matches", text]), ("yarax.matches", expected))
        for argv in (["yarax.matches"], ["yarax.matches", "{}", "x"], ["lief.headers", "{}"], ["yarax.rules", "{}"],
                     ["yarax.matches", '{"max_matches": 0}'], ["yarax.matches", '{"max_matches": 65}'],
                     ["yarax.matches", '{"max_matches": true}'], ["yarax.matches", '{"max_matches": "8"}'],
                     ["yarax.matches", '{"max_matches": 8.0}'], ["yarax.matches", '{"ruleset": "other"}'],
                     ["yarax.matches", '{"ruleset": null}'], ["yarax.matches", '{"path": "/snapshot/input"}'],
                     ["yarax.matches", '{"max_matches": 8, "max_matches": 9}'], ["yarax.matches", "[]"],
                     ["yarax.matches", "{"]):
            with self.subTest(argv=argv), self.assertRaises(worker.InvalidRequest):
                worker.parse_request(argv)

    def test_an_invalid_request_never_reaches_the_scanner(self):
        fake = FakeYaraX()
        self.assertEqual(worker.reply(["yarax.matches", '{"max_matches": 65}'], b"UPX!",
                                      lambda data, name: worker.yara_matches(data, name, yara_x=fake))["error"], "InvalidRequest")
        self.assertEqual(fake.sources, [])


class ProtocolTests(unittest.TestCase):
    def test_replies_pass_the_hosts_parser(self):
        data = FIXTURES["utf16le strings"]
        observations = parse_worker_reply(json.dumps(run(data)).encode(), input_sha256=sha256_hex(data), max_observations=64)
        self.assertEqual([(o.location.offset, o.value["rule"], o.value["pattern"], o.location.length) for o in observations],
                         oracle(data))
        error = run(data, max_matches=65)
        self.assertEqual(error, {"protocol": "reverseai.worker/1", "status": "error", "snapshot_sha256": sha256_hex(data),
                                 "error": "InvalidRequest"})
        with self.assertRaisesRegex(WorkerError, "^InvalidRequest$"):
            parse_worker_reply(json.dumps(error).encode(), input_sha256=sha256_hex(data), max_observations=64)

    def test_unexpected_failures_become_short_error_names(self):
        def broken(data, name):
            raise RuntimeError("/private/path " + data.hex())

        reply = worker.reply(["yarax.matches", "{}"], b"secret", broken)
        self.assertEqual(reply["error"], "RuntimeError")
        self.assertNotIn("secret", json.dumps(reply))

    def test_main_reads_the_snapshot_scans_with_yara_x_and_prints_one_json_object(self):
        data = FIXTURES["rules interleaved"]
        with tempfile.TemporaryDirectory() as folder, patch.dict(sys.modules, {"yara_x": FakeYaraX()}):
            snapshot = Path(folder, "input")
            snapshot.write_bytes(data)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(worker.main(["yarax.matches", "{}"], snapshot=snapshot), 0)
        text = out.getvalue()
        self.assertTrue(text.endswith("\n") and text.count("\n") == 1)
        self.assertEqual(rows(json.loads(text)), oracle(data))

    def test_an_unreadable_snapshot_has_its_own_error(self):
        with tempfile.TemporaryDirectory() as folder:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                worker.main(["yarax.matches", "{}"], snapshot=Path(folder, "missing"))
        self.assertEqual(json.loads(out.getvalue()), {"protocol": "reverseai.worker/1", "status": "error",
                                                      "snapshot_sha256": hashlib.sha256(b"").hexdigest(), "error": "SnapshotUnreadable"})

    def test_a_too_large_snapshot_reports_the_digest_of_the_whole_file(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(worker, "MAX_INPUT_BYTES", 8):
            snapshot = Path(folder, "input")
            snapshot.write_bytes(b"UPX!" * 4)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                worker.main(["yarax.matches", "{}"], snapshot=snapshot)
        reply = json.loads(out.getvalue())
        self.assertEqual((reply["error"], reply["snapshot_sha256"]), ("InputTooLarge", hashlib.sha256(b"UPX!" * 4).hexdigest()))


class BuildInputTests(unittest.TestCase):
    def test_build_inputs_and_lock_are_pinned_consistently(self):
        lief_lock = json.loads((ROOT / "containers" / "lief" / "image.lock.json").read_text(encoding="utf-8"))
        lock = json.loads((SOURCE / "image.lock.json").read_text(encoding="utf-8"))
        self.assertEqual(set(lock), {"adapter_version", "base_digest", "image_id", "platform", "ruleset_sha256", "wheel_sha256"})
        self.assertEqual((lock["adapter_version"], lock["platform"], lock["base_digest"]),
                         ("1.21.0-r2", "linux/arm64", lief_lock["base_digest"]))
        self.assertEqual(lock["wheel_sha256"], "9bd9961b44b47dd747d526e61c703a2a8170426d003e789e7724bc7862de6d56")
        self.assertEqual(lock["ruleset_sha256"], hashlib.sha256((SOURCE / "m2_fixture_v1.json").read_bytes()).hexdigest())
        self.assertRegex(lock["image_id"], r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(worker.ADAPTER_VERSION, lock["adapter_version"])
        requirements = (SOURCE / "requirements.txt").read_text(encoding="utf-8")
        self.assertEqual(re.findall(r"^yara-x==1\.21\.0 --hash=sha256:([0-9a-f]{64})$", requirements, re.M), [lock["wheel_sha256"]])
        dockerfile = (SOURCE / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("FROM python:3.12-slim@" + lock["base_digest"] + "\n", dockerfile)
        self.assertIn("COPY m2_fixture_v1.json /opt/reverseai/m2_fixture_v1.json\n", dockerfile)
        self.assertEqual(re.findall(r"^USER .*$", dockerfile, re.M | re.I), ["USER 65534:65534"])
        self.assertLess(dockerfile.index("USER 65534:65534"), dockerfile.index("w.compiled('m2_fixture_v1')"))
        self.assertEqual(worker.SNAPSHOT, "/snapshot/input")
        self.assertTrue(dockerfile.rstrip().endswith('ENTRYPOINT ["python3", "-I", "-B", "/opt/reverseai/worker.py"]'))


if __name__ == "__main__":
    unittest.main()
