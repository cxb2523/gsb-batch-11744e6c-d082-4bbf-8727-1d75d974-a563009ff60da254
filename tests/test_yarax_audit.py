import copy
import json
from pathlib import Path
import unittest

from reverseai.contract import ContractError, Location, Observation
from reverseai.tools import yarax_audit, yarax_verify
from tests.fixtures_yarax import RULESET_SHA256, known_matches, match

RULESET_PATH = Path(__file__).resolve().parents[1] / "containers/yarax/m2_fixture_v1.json"
ARGS = {"ruleset": "m2_fixture_v1", "max_matches": 64}


def observation(item):
    return Observation(Location(**item["location"]), item["value"])


def check(result, name):
    for entry in result["checks"]:
        if entry["name"] == name:
            return entry
    raise AssertionError(f"no check named {name}")


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.patterns = yarax_verify.load_patterns(RULESET_PATH, RULESET_SHA256)
        self.data, self.items = known_matches()

    def audit(self, items, *, data=None, args=ARGS, patterns=None):
        return yarax_audit.audit_matches(self.data if data is None else data, args, items,
                                         self.patterns if patterns is None else patterns)

    def verify_raises(self, items, *, data=None, args=ARGS):
        try:
            yarax_verify.verify(self.data if data is None else data,
                                tuple(map(observation, items)), args, self.patterns)
        except ContractError:
            return True
        return False

    def assert_consistent(self, items, *, data=None, args=ARGS):
        """The audit's all_accepted must mirror verify raising ContractError."""
        result = self.audit(items, data=data, args=args)
        self.assertEqual(result["all_accepted"], not self.verify_raises(items, data=data, args=args))
        return result

    def test_known_matches_are_all_accepted_and_agree_with_verify(self):
        result = self.assert_consistent(self.items)
        self.assertTrue(result["all_accepted"])
        self.assertTrue(result["args"]["valid"])
        self.assertEqual(result["accepted_count"], 4)
        self.assertEqual(result["rejected"], [])
        self.assertEqual([entry["occurrence_count"] for entry in result["observations"]], [1, 1, 1, 1])
        self.assertTrue(all(entry["passed"] for entry in result["checks"]))

    def test_empty_reply_and_withheld_matches_are_accepted_like_verify(self):
        for items in ([], self.items[2:3]):
            with self.subTest(items=items):
                result = self.assert_consistent(items)
                self.assertTrue(result["all_accepted"])
                self.assertEqual(result["accepted_count"], len(items))

    def test_extra_value_key_rejects_that_observation(self):
        items = copy.deepcopy(self.items)
        items[0]["value"]["extra"] = "ignored"
        result = self.assert_consistent(items)
        self.assertFalse(result["all_accepted"])
        self.assertEqual([entry["index"] for entry in result["rejected"]], [0])
        self.assertFalse(check(result, "observation[0].value_keys_exact")["passed"])
        self.assertTrue(any("extra" in reason for reason in result["rejected"][0]["reasons"]))

    def test_value_ruleset_mismatch_rejects_that_observation(self):
        items = copy.deepcopy(self.items)
        items[1]["value"]["ruleset"] = "other"
        result = self.assert_consistent(items)
        self.assertFalse(result["all_accepted"])
        self.assertEqual([entry["index"] for entry in result["rejected"]], [1])
        self.assertFalse(check(result, "observation[1].value_ruleset_matches_request")["passed"])

    def test_non_string_rule_rejects_that_observation(self):
        items = copy.deepcopy(self.items)
        items[2]["value"]["rule"] = ["upx_packed"]
        result = self.assert_consistent(items)
        self.assertFalse(result["all_accepted"])
        self.assertEqual([entry["index"] for entry in result["rejected"]], [2])
        self.assertFalse(check(result, "observation[2].rule_is_string")["passed"])

    def test_fifth_occurrence_fails_the_occurrence_cap(self):
        data = b"UPX!" * 5
        items = [match(4 * index) for index in range(5)]
        result = self.assert_consistent(items, data=data)
        self.assertFalse(result["all_accepted"])
        self.assertEqual([entry["index"] for entry in result["rejected"]], [4])
        self.assertEqual(result["observations"][4]["occurrence_count"], 5)
        self.assertFalse(check(result, "observation[4].occurrence_cap_at_most_4")["passed"])
        first_four = self.assert_consistent(items[:4], data=data)
        self.assertTrue(first_four["all_accepted"])

    def test_equal_offset_fails_strictly_increasing(self):
        items = [self.items[0], copy.deepcopy(self.items[0])]
        result = self.assert_consistent(items)
        self.assertFalse(result["all_accepted"])
        self.assertEqual([entry["index"] for entry in result["rejected"]], [1])
        self.assertFalse(check(result, "observation[1].strictly_increasing")["passed"])

    def test_request_arguments_are_checked(self):
        for args in (dict(ARGS, ruleset="other"), dict(ARGS, max_matches=0),
                     dict(ARGS, max_matches=65), dict(ARGS, max_matches=True),
                     dict(ARGS, max_matches="64")):
            with self.subTest(args=args):
                result = self.audit(self.items, args=args)
                self.assertFalse(result["args"]["valid"])
                self.assertFalse(result["all_accepted"])
                self.assertTrue(result["args"]["errors"])
        result = self.assert_consistent(self.items, args=dict(ARGS, ruleset="other"))
        self.assertFalse(check(result, "args_ruleset_is_m2_fixture_v1")["passed"])
        result = self.assert_consistent(self.items, args=dict(ARGS, max_matches=1))
        self.assertFalse(check(result, "observation_count_within_max_matches")["passed"])

    def test_audit_result_is_json_serializable(self):
        cases = [self.audit(self.items)]
        items = copy.deepcopy(self.items)
        items[0]["value"]["rule"] = ["upx_packed"]
        cases.append(self.audit(items))
        cases.append(yarax_audit.audit_matches(b"", ARGS, [{"value": "not-a-dict"}, {}]))
        for result in cases:
            with self.subTest(all_accepted=result["all_accepted"]):
                self.assertEqual(json.loads(json.dumps(result)), result)

    def test_degraded_inputs_return_reasons_instead_of_raising(self):
        result = yarax_audit.audit_matches(b"", ARGS, [])
        self.assertTrue(result["all_accepted"])
        self.assertEqual(result["accepted_count"], 0)
        broken = [{}, {"value": "not-a-dict"}, {"offset": 0, "length": 1},
                  {"location": {"offset": 0, "length": 1}, "value": {"ruleset": "m2_fixture_v1"}},
                  "not-an-observation"]
        result = yarax_audit.audit_matches(self.data, ARGS, broken, self.patterns)
        self.assertFalse(result["all_accepted"])
        self.assertEqual([entry["index"] for entry in result["rejected"]], [0, 1, 2, 3, 4])
        self.assertTrue(all(entry["reasons"] for entry in result["rejected"]))
        self.assertFalse(check(result, "observation[1].value_is_dict")["passed"])
        json.dumps(result)

    def test_default_patterns_are_loaded_from_the_local_ruleset(self):
        result = yarax_audit.audit_matches(self.data, ARGS, self.items)
        self.assertTrue(result["all_accepted"])
        self.assertEqual(result["patterns"]["source"], "default")
        self.assertEqual(result["patterns"]["count"], 9)
        self.assertIsNone(result["patterns"]["error"])

    def test_observation_objects_and_flat_mappings_are_accepted(self):
        objects = [observation(item) for item in self.items]
        self.assertTrue(self.audit(objects)["all_accepted"])
        flat = [{"offset": item["location"]["offset"], "length": item["location"]["length"],
                 "value": item["value"]} for item in self.items]
        self.assertTrue(self.audit(flat)["all_accepted"])


if __name__ == "__main__":
    unittest.main()
