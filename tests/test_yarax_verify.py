import copy
import json
from pathlib import Path
import tempfile
import unittest

from reverseai.contained import ContainedError
from reverseai.contract import ContractError, Location, Observation, sha256_hex
from reverseai.tools import yarax_verify
from tests.fixtures_yarax import RULESET_SHA256, known_matches, match, pattern_table
from tests.test_yarax_worker_logic import worker

RULESET_PATH = Path(__file__).resolve().parents[1] / "containers/yarax/m2_fixture_v1.json"
ARGS = {"ruleset": "m2_fixture_v1", "max_matches": 64}


def observation(item):
    return Observation(Location(**item["location"]), item["value"])


class RulesetTests(unittest.TestCase):
    def test_duplicate_rule_ids_are_refused_even_when_pattern_ids_are_distinct(self):
        value = {"ruleset": "m2_fixture_v1", "rules": [
            {"id": "first", "category": "packer", "patterns": [{"id": "$a", "hex": "55505821"}]},
            {"id": "second", "category": "packer", "patterns": [{"id": "$b", "hex": "55505830"}]}]}
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "rules.json"
            raw = json.dumps(value).encode()
            path.write_bytes(raw)
            self.assertEqual(dict(yarax_verify.load_patterns(path, sha256_hex(raw))),
                             {("first", "$a"): b"UPX!", ("second", "$b"): b"UPX0"})
            value["rules"][1]["id"] = "first"
            raw = json.dumps(value).encode()
            path.write_bytes(raw)
            with self.assertRaisesRegex(ContainedError, "^InvalidRuleset$"):
                yarax_verify.load_patterns(path, sha256_hex(raw))

    def test_duplicate_pattern_ids_are_refused_even_when_literals_are_distinct(self):
        value = {"ruleset": "m2_fixture_v1", "rules": [
            {"id": "first", "category": "packer", "patterns": [
                {"id": "$a", "hex": "55505821"}, {"id": "$b", "hex": "55505830"}]}]}
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "rules.json"
            raw = json.dumps(value).encode()
            path.write_bytes(raw)
            self.assertEqual(dict(yarax_verify.load_patterns(path, sha256_hex(raw))),
                             {("first", "$a"): b"UPX!", ("first", "$b"): b"UPX0"})
            value["rules"][0]["patterns"][1]["id"] = "$a"
            raw = json.dumps(value).encode()
            path.write_bytes(raw)
            with self.assertRaisesRegex(ContainedError, "^InvalidRuleset$"):
                yarax_verify.load_patterns(path, sha256_hex(raw))

    def test_pattern_budget_accepts_sixteen_and_refuses_seventeen(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "rules.json"
            for count in (16, 17):
                raw, _, _ = pattern_table(count)
                path.write_bytes(raw)
                with self.subTest(count=count):
                    if count == 16:
                        self.assertEqual(len(yarax_verify.load_patterns(path, sha256_hex(raw))), 16)
                    else:
                        with self.assertRaisesRegex(ContainedError, "^InvalidRuleset$"):
                            yarax_verify.load_patterns(path, sha256_hex(raw))

    def test_host_and_worker_agree_on_identifier_category_and_hex_grammar(self):
        original = {"ruleset": "m2_fixture_v1", "rules": [
            {"id": "test_rule", "category": "packer", "patterns": [{"id": "$a", "hex": "55505821"}]}]}
        cases = [("id", name, False) for name in sorted(worker.KEYWORDS)]
        cases += [("id", "r" + "a" * 63, True), ("id", "r" + "a" * 64, False),
                  ("id", "Bad", False), ("category", "c" * 64, True), ("category", "", False),
                  ("category", "Bad", False), ("category", "c" * 65, False),
                  ("pattern", "$0", True), ("pattern", "$" + "a" * 32, True),
                  ("pattern", "$" + "a" * 33, False), ("pattern", "$A", False), ("pattern", "$", False),
                  ("hex", "aabbccdd", True), ("hex", "AABBCCDD", False), ("hex", "aabbcc", False),
                  ("hex", "aa" * 256, True), ("hex", "aa" * 257, False), ("hex", "aabbccd", False)]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "rules.json"
            for field, text, expected in cases:
                value = copy.deepcopy(original)
                if field in ("pattern", "hex"):
                    value["rules"][0]["patterns"][0]["id" if field == "pattern" else "hex"] = text
                else:
                    value["rules"][0][field] = text
                raw = json.dumps(value).encode()
                path.write_bytes(raw)
                try:
                    yarax_verify.load_patterns(path, sha256_hex(raw))
                    host_accepts = True
                except ContainedError:
                    host_accepts = False
                try:
                    worker.check_ruleset(value, "m2_fixture_v1")
                    worker_accepts = True
                except worker.RulesetInvalid:
                    worker_accepts = False
                with self.subTest(field=field, text=text):
                    self.assertEqual(host_accepts, expected)
                    self.assertEqual(worker_accepts, expected)

    def test_duplicate_json_keys_are_refused_even_with_the_matching_test_hash(self):
        raw = RULESET_PATH.read_bytes().replace(b'"ruleset": "m2_fixture_v1"',
                                                b'"ruleset": "other", "ruleset": "m2_fixture_v1"')
        self.assertNotEqual(raw, RULESET_PATH.read_bytes())
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "m2_fixture_v1.json"
            path.write_bytes(raw)
            with self.assertRaisesRegex(ContainedError, "^InvalidRuleset$"):
                yarax_verify.load_patterns(path, sha256_hex(raw))
            with self.assertRaises(worker.RulesetInvalid):
                worker.load_ruleset("m2_fixture_v1", folder)

    def test_reviewed_hash_and_literal_patterns_are_frozen(self):
        patterns = yarax_verify.load_patterns(RULESET_PATH, RULESET_SHA256)
        self.assertEqual(len(patterns), 9)
        self.assertEqual(patterns[("upx_packed", "$a")], b"UPX!")
        self.assertEqual(patterns[("credential_dump_marker", "$w")], "sekurlsa::".encode("utf-16le"))
        with self.assertRaises(TypeError):
            patterns[("upx_packed", "$a")] = b"evil"

    def test_missing_file_bad_hash_malformed_and_oversized_rulesets_are_constant_errors(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "private.json"
            cases = (None, b"{}", b"\xff", b"[1]", b"x" * 65_537, RULESET_PATH.read_bytes())
            for raw in cases:
                with self.subTest(raw=None if raw is None else len(raw)):
                    if raw is not None:
                        path.write_bytes(raw)
                    digest = "0" * 64 if raw is None or raw == RULESET_PATH.read_bytes() else sha256_hex(raw)
                    with self.assertRaisesRegex(ContainedError, "^InvalidRuleset$") as error:
                        yarax_verify.load_patterns(path, digest)
                    self.assertNotIn(folder, str(error.exception))

    def test_duplicate_unknown_or_nonliteral_rule_definitions_are_refused(self):
        original = json.loads(RULESET_PATH.read_bytes())
        variants = []
        for change in (
                lambda x: x.update(ruleset="other"),
                lambda x: x.update(extra=True),
                lambda x: x["rules"].append(copy.deepcopy(x["rules"][0])),
                lambda x: x["rules"][0]["patterns"].append(copy.deepcopy(x["rules"][0]["patterns"][0])),
                lambda x: x["rules"][0]["patterns"][0].update(hex="?? ?? ?? ??"),
                lambda x: x["rules"][0]["patterns"][0].update(hex="aa"),
                lambda x: x["rules"][0]["patterns"][0].update(hex="aa" * 257),
                lambda x: x["rules"][0]["patterns"][0].update(id="$a;include")):
            value = copy.deepcopy(original)
            change(value)
            variants.append(json.dumps(value).encode())
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "rules.json"
            for raw in variants:
                with self.subTest(raw=raw[:60]):
                    path.write_bytes(raw)
                    with self.assertRaisesRegex(ContainedError, "^InvalidRuleset$"):
                        yarax_verify.load_patterns(path, sha256_hex(raw))


class VerifyTests(unittest.TestCase):
    def setUp(self):
        self.patterns = yarax_verify.load_patterns(RULESET_PATH, RULESET_SHA256)
        self.data, self.items = known_matches()

    def verify(self, items, *, data=None, args=ARGS):
        return yarax_verify.verify(self.data if data is None else data, tuple(map(observation, items)), args, self.patterns)

    def test_real_ascii_and_wide_matches_empty_reply_and_withheld_matches_are_allowed(self):
        self.verify(self.items)
        self.verify([])
        self.verify(self.items[2:3])

    def test_every_value_field_is_checked_and_no_extra_or_missing_field_is_allowed(self):
        for key, value in (("ruleset", "other"), ("rule", "invented"), ("pattern", "$unknown"),
                           ("rule", ["upx_packed"]), ("pattern", True), ("extra", "ignored")):
            items = copy.deepcopy(self.items)
            items[0]["value"][key] = value
            with self.subTest(key=key, value=value), self.assertRaisesRegex(ContractError, "^" + yarax_verify.REFUSED + "$"):
                self.verify(items)
        for key in ("ruleset", "rule", "pattern"):
            item = copy.deepcopy(self.items[0])
            del item["value"][key]
            with self.subTest(missing=key), self.assertRaises(ContractError):
                self.verify([item])

    def test_offsets_length_and_actual_bytes_must_match_the_named_pattern(self):
        for changes in ({"offset": 0}, {"offset": len(self.data)}, {"length": 3}, {"length": 5}):
            item = copy.deepcopy(self.items[0])
            item["location"].update(changes)
            with self.subTest(changes=changes), self.assertRaises(ContractError):
                self.verify([item])
        with self.assertRaises(ContractError):
            self.verify(self.items, data=self.data.replace(b"UPX!", b"FAKE"))
        item = match(0, literal=b"UPX!", pattern="$b")
        with self.assertRaises(ContractError):
            self.verify([item], data=b"UPX!")

    def test_duplicate_and_descending_offset_rule_or_pattern_order_are_refused(self):
        for items in ([self.items[0], self.items[0]], list(reversed(self.items))):
            with self.subTest(items=items), self.assertRaises(ContractError):
                self.verify(items)
        patterns = {("a", "$a"): b"UPX!", ("a", "$b"): b"UPX!", ("b", "$a"): b"UPX!"}
        first, second, third = [observation(match(0, rule=r, pattern=p)) for r, p in patterns]
        yarax_verify.verify(b"UPX!", (first, second, third), ARGS, patterns)
        for pair in ((second, first), (third, first)):
            with self.assertRaises(ContractError):
                yarax_verify.verify(b"UPX!", pair, ARGS, patterns)

    def test_requested_ruleset_and_exact_requested_count_are_enforced(self):
        self.verify(self.items[:1], args=dict(ARGS, max_matches=1))
        for args in (dict(ARGS, max_matches=1), dict(ARGS, ruleset="other")):
            with self.subTest(args=args), self.assertRaises(ContractError):
                self.verify(self.items, args=args)

    def test_four_matches_per_rule_pattern_are_allowed_but_the_fifth_is_refused(self):
        data = b"UPX!" * 5
        items = [match(4 * index) for index in range(5)]
        self.verify(items[:4], data=data)
        with self.assertRaisesRegex(ContractError, "^" + yarax_verify.REFUSED + "$"):
            self.verify(items, data=data)

    def test_same_pattern_id_under_different_rules_has_a_separate_cap(self):
        patterns = {("one", "$a"): b"UPX!", ("two", "$a"): b"UPX!"}
        items = [observation(match(offset, rule=rule)) for offset in range(0, 16, 4) for rule in ("one", "two")]
        yarax_verify.verify(b"UPX!" * 4, items, ARGS, patterns)
