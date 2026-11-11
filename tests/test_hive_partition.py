"""Contract tests for the model-free first stage of planning."""

import copy
import hashlib
import importlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

try:
    partition = importlib.import_module("hive.partition")
except ModuleNotFoundError as error:
    if error.name != "hive.partition":
        raise
    partition = None


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def program(count):
    return {"file": "fixture", "input_sha256": "ab" * 32,
            "functions": [{"entry": 0x1000 + 16 * i, "hex": hex(0x1000 + 16 * i),
                           "name": f"fn_{i}", "size": 16, "signature": "int f(void)"}
                          for i in range(count)],
            "calls": [], "strings": [], "imports": []}


def owner(result):
    return {entry: group["id"] for group in result["groups"] for entry in group["functions"]}


class PartitionTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(partition, "Phase A partitioner is not implemented on the original base")

    def valid_partition(self, source, **limits):
        try:
            return partition.partition(source, **limits)
        except ValueError as error:
            self.fail(f"valid map must partition instead of aborting: {error}")

    def check_bounds(self, source, result, count, size, summary):
        entries = [entry for group in result["groups"] for entry in group["functions"]]
        self.assertEqual(sorted(entries), sorted(row["hex"] for row in source["functions"]))
        self.assertEqual(len(entries), len(set(entries)))
        self.assertEqual(len({g["id"] for g in result["groups"]}), len(result["groups"]))
        for group in result["groups"]:
            self.assertGreater(len(group["functions"]), 0)
            self.assertLessEqual(len(group["functions"]), count)
            self.assertEqual(group["bytes"], len(encoded(group["map"])))
            self.assertLessEqual(group["bytes"], size)
            self.assertEqual(set(group["map"]), set(source))
            self.assertEqual({f["hex"] for f in group["map"]["functions"]}, set(group["functions"]))
        self.assertEqual(result["summary_bytes"], len(encoded(result["summary"])))
        self.assertLessEqual(result["summary_bytes"], summary)
        self.assertEqual(result["summary"]["totals"]["functions"], len(entries))
        self.assertEqual(result["summary"]["totals"]["groups"], len(result["groups"]))
        self.assertEqual(result["summary"]["totals"]["cut_edges"], len(result["cut_edges"]))

    def test_empty_map(self):
        source = program(0)
        result = partition.partition(source)
        self.assertEqual(result["groups"], [])
        self.assertEqual(result["cut_edges"], [])
        self.check_bounds(source, result, 128, 65536, 8192)

    def test_every_function_is_assigned_once_even_without_relations(self):
        source = program(173)
        result = partition.partition(source, max_functions=7, max_bytes=5000)
        self.check_bounds(source, result, 7, 5000, 8192)
        self.assertEqual(len(result["groups"]), 25)

    def test_mutually_calling_pairs_stay_together(self):
        source = program(6)
        entries = [f["hex"] for f in source["functions"]]
        pairs = [(entries[i], entries[i + 3]) for i in range(3)]
        source["calls"] = [{"from": a, "to": b, "to_name": "callee"}
                           for a, b in pairs + [(b, a) for a, b in pairs]]
        result = partition.partition(source, max_functions=2)
        owners = owner(result)
        self.assertTrue(all(owners[a] == owners[b] for a, b in pairs))
        self.assertEqual(result["cut_edges"], [])

    def test_shared_string_bytes_join_functions_at_different_addresses(self):
        source = program(4)
        source["strings"] = [{"from": f["hex"], "address": hex(0x8000 + i * 32),
                              "text": "even" if i % 2 == 0 else "odd"}
                             for i, f in enumerate(source["functions"])]
        result = partition.partition(source, max_functions=2)
        owners = owner(result)
        self.assertEqual(owners["0x1000"], owners["0x1020"])
        self.assertEqual(owners["0x1010"], owners["0x1030"])

    def test_shared_data_references_join_functions_and_preserve_rows(self):
        for table in ("references", "data_refs"):
            with self.subTest(table=table):
                source = program(4)
                source[table] = [{"from": f["hex"], "to": "0x9000" if i % 2 == 0 else "0xa000",
                                  "type": "READ" if i < 2 else "WRITE", "at": f["entry"] + 1}
                                 for i, f in enumerate(source["functions"])]
                result = partition.partition(source, max_functions=2)
                owners = owner(result)
                self.assertEqual(owners["0x1000"], owners["0x1020"])
                self.assertEqual(owners["0x1010"], owners["0x1030"])
                actual = [r for g in result["groups"] for r in g["map"][table]]
                self.assertEqual(sorted(map(encoded, actual)), sorted(map(encoded, source[table])))

    def test_utf8_slice_limit_includes_metadata_and_all_rows(self):
        source = program(12)
        for function in source["functions"]:
            function["signature"] = "é漢" * 80
        result = partition.partition(source, max_functions=12, max_bytes=900)
        self.check_bounds(source, result, 12, 900, 8192)
        self.assertEqual(len(result["groups"]), 12)
        self.assertTrue(all(g["map"]["functions"][0]["signature"] == "é漢" * 80 for g in result["groups"]))

    def test_large_string_row_has_an_oversized_group_and_full_side_file(self):
        source = program(1)
        source["strings"] = [{"from": "0x1000", "address": "0x8000", "text": "x" * 5000}]
        result = self.valid_partition(source, max_bytes=1000)
        group = result["groups"][0]
        self.assertTrue(group["oversized"])
        self.assertLessEqual(group["bytes"], 1000)
        detail = group["overflow"]["strings"]
        self.assertEqual((detail["total"], detail["retained"], detail["deferred"]), (1, 0, 1))
        self.assertEqual(result["side_files"][detail["file"]]["rows"], source["strings"])
        source = program(1)
        source["file"] = "x" * 2000
        with self.assertRaises(ValueError):
            partition.partition(source, max_bytes=1000)

    def test_exact_limit_is_allowed(self):
        source = program(1)
        limit = len(encoded(source))
        result = partition.partition(source, max_bytes=limit)
        self.assertEqual(result["groups"][0]["bytes"], limit)
        with self.assertRaises(ValueError):
            partition.partition(source, max_bytes=limit - 1)

    def test_all_directed_cut_calls_are_listed_including_distinct_callsites(self):
        source = program(3)
        source["calls"] = [
            {"from": "0x1000", "to": "0x1010", "at": "0x1001", "to_name": "first"},
            {"from": "0x1000", "to": "0x1010", "at": "0x1002", "to_name": "first"},
            {"from": "0x1010", "to": "0x1000", "at": "0x1011"},
            {"from": "0x1020", "to": "0x1020"},
            {"from": "0x1020", "to": "0x9999", "to_name": "puts"}]
        source["imports"] = ["unused", "puts"]
        result = partition.partition(source, max_functions=1)
        owners = owner(result)
        expected = [{**row, "from_group": owners[row["from"]], "to_group": owners[row["to"]]}
                    for row in source["calls"] if row["to"] in owners and owners[row["from"]] != owners[row["to"]]]
        self.assertEqual(sorted(map(encoded, result["cut_edges"])), sorted(map(encoded, expected)))
        self.assertEqual(len(result["cut_edges"]), 3)
        for group in result["groups"]:
            mine = set(group["functions"])
            touched = [r for r in source["calls"] if r["from"] in mine or r["to"] in mine]
            self.assertEqual(sorted(map(encoded, group["map"]["calls"])), sorted(map(encoded, touched)))
            self.assertEqual(group["map"]["imports"], ["puts"] if "0x1020" in mine else [])

    def test_table_order_and_json_key_order_do_not_change_partition(self):
        source = program(31)
        source["calls"] = [{"from": f["hex"], "to": source["functions"][(i + 3) % 31]["hex"]}
                           for i, f in enumerate(source["functions"])]
        shuffled = {key: list(reversed(value)) if isinstance(value, list) else value
                    for key, value in reversed(list(source.items()))}
        self.assertEqual(encoded(partition.partition(source, max_functions=5)),
                         encoded(partition.partition(shuffled, max_functions=5)))

    def test_hash_seed_does_not_change_serialized_result(self):
        source = program(24)
        source["strings"] = [{"from": f["hex"], "address": "0x8000", "text": "common"}
                             for f in source["functions"]]
        source["strings"].append({"from": "0x1000", "address": "0x9000", "text": "manual" * 12000})
        source["references"] = [{"from": "0xbeef", "to": "0xdead", "type": "DATA"}]
        script = ("import json,sys,hashlib; from hive.partition import partition,encode; "
                  "print(hashlib.sha256(encode(partition(json.load(sys.stdin),max_functions=5))).hexdigest())")
        digests = []
        for seed in ("1", "917"):
            env = dict(os.environ, PYTHONHASHSEED=seed)
            done = subprocess.run([sys.executable, "-B", "-c", script], env=env,
                                  cwd=Path(__file__).resolve().parents[1], input=json.dumps(source),
                                  text=True, capture_output=True, timeout=20)
            self.assertEqual(done.returncode, 0, done.stderr)
            digests.append(done.stdout.strip())
        self.assertEqual(digests[0], digests[1])
        self.assertEqual(len(digests[0]), hashlib.sha256().digest_size * 2)

    def test_summary_omissions_are_explicit_and_complete_edges_stay_available(self):
        source = program(350)
        source["entry_points"] = [f["hex"] for f in source["functions"]]
        source["calls"] = [{"from": source["functions"][i]["hex"], "to": source["functions"][i + 1]["hex"]}
                           for i in range(349)]
        result = partition.partition(source, max_functions=1, max_bytes=30000, summary_bytes=512)
        self.check_bounds(source, result, 1, 30000, 512)
        self.assertEqual(len(result["cut_edges"]), 349)
        summary = result["summary"]
        for key in ("groups", "cut_edges", "entry_points", "entry_hints"):
            self.assertEqual(len(summary[key]) + summary["omitted"][key], summary["totals"][key])
        self.assertGreater(summary["omitted"]["groups"], 0)
        self.assertGreater(summary["omitted"]["cut_edges"], 0)
        with self.assertRaisesRegex(ValueError, "summary"):
            partition.partition(source, summary_bytes=1)

    def test_runtime_hints_and_declared_entries_are_preserved_without_skipping(self):
        source = program(4)
        source["functions"][0].update(name="main")
        source["functions"][1].update(library_hint="libc", is_thunk=True)
        source["functions"][2].update(runtime=True, is_entry=True)
        source["entry_points"] = ["0x1030"]
        before = copy.deepcopy(source)
        result = partition.partition(source, max_functions=2)
        self.check_bounds(source, result, 2, 65536, 8192)
        actual = {f["hex"]: f for g in result["groups"] for f in g["map"]["functions"]}
        self.assertEqual(actual, {f["hex"]: f for f in source["functions"]})
        self.assertEqual(result["summary"]["entry_points"], ["0x1020", "0x1030"])
        self.assertEqual(result["summary"]["entry_hints"], ["0x1000", "0x1010"])
        result["groups"][0]["map"]["functions"][0]["name"] = "changed"
        self.assertEqual(source, before)

    def test_invalid_limits_addresses_or_duplicate_functions_fail(self):
        for limits in ({"max_functions": 0}, {"max_functions": True}, {"max_bytes": -1},
                       {"summary_bytes": 0}, {"max_bytes": 2.5}):
            with self.subTest(limits=limits), self.assertRaises(ValueError):
                partition.partition(program(1), **limits)
        for update in (lambda m: m["functions"].append(dict(m["functions"][0])),
                       lambda m: m["functions"][0].update(hex="0xffff"),
                       lambda m: m["calls"].append({"from": "bad", "to": "0x1000"})):
            source = program(2)
            update(source)
            with self.assertRaises(ValueError):
                partition.partition(source)

    def test_three_thousand_functions_have_bounded_lossless_slices(self):
        source = program(3000)
        for i, function in enumerate(source["functions"]):
            source["calls"].append({"from": function["hex"],
                                    "to": source["functions"][(i + 1) % 3000]["hex"]})
            source["strings"].append({"from": function["hex"], "address": hex(0x80000 + i // 30),
                                      "text": f"cluster {i // 30}"})
        result = partition.partition(source, max_functions=64, max_bytes=32768, summary_bytes=4096)
        self.check_bounds(source, result, 64, 32768, 4096)
        owners = owner(result)
        cuts = [r for r in source["calls"] if owners[r["from"]] != owners[r["to"]]]
        self.assertEqual(sorted((r["from"], r["to"]) for r in result["cut_edges"]),
                         sorted((r["from"], r["to"]) for r in cuts))
        self.assertGreaterEqual(len(result["groups"]), 47)
        self.assertLessEqual(len(result["groups"]), 100)

    def test_reference_target_also_gets_the_full_reference_row(self):
        source = program(4)
        row = {"from": "0x1000", "to": "0x1030", "type": "DATA"}
        source["references"] = [row]
        result = partition.partition(source, max_functions=1)
        self.check_bounds(source, result, 1, 65536, 8192)
        by_entry = {g["functions"][0]: g["map"] for g in result["groups"]}
        self.assertEqual(by_entry["0x1030"]["references"], [row])
        self.assertEqual(by_entry["0x1000"]["references"], [row])
        self.assertEqual(by_entry["0x1010"]["references"], [])

    def test_explicit_entries_are_restricted_to_their_slice(self):
        source = program(4)
        source["entry_points"] = [f["hex"] for f in source["functions"]]
        result = partition.partition(source, max_functions=1)
        for group in result["groups"]:
            self.assertEqual(group["map"]["entry_points"], group["functions"])

    def test_declared_entry_is_excluded_from_hints(self):
        source = program(1)
        source["functions"][0]["name"] = "main"
        source["entry_points"] = ["0x1000"]
        result = partition.partition(source)
        self.assertEqual(result["summary"]["entry_points"], ["0x1000"])
        self.assertEqual(result["summary"]["entry_hints"], [])

    def test_entry_name_and_roots_are_hints_not_declared_entries(self):
        source = program(4)
        source["functions"][0]["name"] = "main"
        source["functions"][2]["name"] = "entry"
        source["entry_points"] = ["0x1000"]
        source["calls"] = [{"from": "0x1000", "to": "0x1010"},
                           {"from": "0x1010", "to": "0x1000"},
                           {"from": "0x1030", "to": "0x1020"}]
        result = partition.partition(source)
        self.assertEqual(result["summary"]["entry_points"], ["0x1000"])
        self.assertEqual(result["summary"]["entry_hints"], ["0x1020", "0x1030"])

    def test_call_affinity_wins_over_an_unrelated_shared_text(self):
        source = program(4)
        source["calls"] = [{"from": "0x1000", "to": "0x1020"}]
        source["strings"] = [{"from": "0x1000", "address": "0x8000", "text": "shared"},
                             {"from": "0x1010", "address": "0x9000", "text": "shared"}]
        result = partition.partition(source, max_functions=2)
        owners = owner(result)
        self.assertEqual(owners["0x1000"], owners["0x1020"])
        self.assertNotEqual(owners["0x1000"], owners["0x1010"])

    def test_named_entry_hint_precedes_roots_in_a_small_summary(self):
        source = program(200)
        source["functions"][-1]["name"] = "entry"
        result = partition.partition(source, max_functions=1, summary_bytes=512)
        self.assertTrue(result["summary"]["entry_hints"])
        self.assertEqual(result["summary"]["entry_hints"][0], source["functions"][-1]["hex"])
        self.assertGreater(result["summary"]["omitted"]["entry_hints"], 0)

    def test_high_fan_in_uses_an_isolated_group_and_exact_caller_group_counts(self):
        source = program(1301)
        hub = source["functions"][-1]["hex"]
        source["calls"] = [{"from": f["hex"], "to": hub, "to_name": "helper", "at": f["entry"] + 1}
                           for f in source["functions"][:-1]]
        result = self.valid_partition(source)
        self.check_bounds(source, result, 128, 65536, 8192)
        group = next(g for g in result["groups"] if hub in g["functions"])
        self.assertEqual(group["functions"], [hub])
        self.assertTrue(group["oversized"])
        self.assertEqual(result["summary"]["oversized"], 1)
        detail = group["overflow"]["incoming_calls"]
        self.assertEqual(detail["total"], 1300)
        self.assertLessEqual(detail["retained"], 128)
        self.assertEqual(detail["retained"] + detail["deferred"], 1300)
        payload = result["side_files"][detail["file"]]
        self.assertEqual(sorted(map(encoded, payload["rows"])), sorted(map(encoded, source["calls"])))
        owners = owner(result)
        expected = {}
        for row in source["calls"]:
            mid = owners[row["from"]]
            expected[mid] = expected.get(mid, 0) + 1
        self.assertEqual(payload["by_group"], expected)
        self.assertEqual(len(result["cut_edges"]), 1300)
        self.assertEqual(len(group["map"]["calls"]), detail["retained"])

    def test_hugehelp_strings_are_counted_and_the_complete_file_is_written(self):
        source = program(3)
        source["strings"] = [{"from": "0x1010", "address": hex(0x100000 + i * 80),
                              "text": "é" * 73 + str(i)} for i in range(5704)]
        before = copy.deepcopy(source)
        result = self.valid_partition(source)
        self.check_bounds(source, result, 128, 65536, 8192)
        group = next(g for g in result["groups"] if "0x1010" in g["functions"])
        self.assertEqual(group["functions"], ["0x1010"])
        self.assertTrue(group["oversized"])
        detail = group["overflow"]["strings"]
        self.assertEqual(detail["total"], 5704)
        self.assertLessEqual(detail["retained"], 128)
        self.assertEqual(detail["retained"], len(group["map"]["strings"]))
        self.assertEqual(detail["deferred"], 5704 - detail["retained"])
        with tempfile.TemporaryDirectory() as folder:
            partition.write_side_files(result, folder)
            raw = (Path(folder) / detail["file"]).read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), detail["sha256"])
            self.assertEqual(sorted(map(encoded, json.loads(raw)["rows"])), sorted(map(encoded, source["strings"])))
        self.assertEqual(source, before)

    def test_incoming_and_string_sample_limits_also_obey_the_byte_cap(self):
        source = program(4)
        source["calls"] = [{"from": hex(0x3000 + i * 16), "to": "0x1030", "at": i, "to_name": "x" * 200}
                           for i in range(15)]
        source["strings"] = [{"from": "0x1030", "address": hex(0x8000 + i), "text": "x" * 500}
                             for i in range(15)]
        import inspect
        self.assertIn("incoming_limit", inspect.signature(partition.partition).parameters)
        self.assertIn("string_limit", inspect.signature(partition.partition).parameters)
        result = self.valid_partition(source, max_bytes=1000, incoming_limit=2, string_limit=2)
        group = next(g for g in result["groups"] if "0x1030" in g["functions"])
        self.assertTrue(group["oversized"])
        self.assertLessEqual(group["bytes"], 1000)
        self.assertLessEqual(group["overflow"]["incoming_calls"]["retained"], 2)
        self.assertLessEqual(group["overflow"]["strings"]["retained"], 2)
        for limits in ({"incoming_limit": 0}, {"string_limit": True}):
            with self.subTest(limits=limits), self.assertRaises(ValueError):
                partition.partition(source, **limits)

    def test_orphan_rows_are_preserved_and_counted_even_without_functions(self):
        for count in (0, 2):
            with self.subTest(functions=count):
                source = program(count)
                source["calls"] = [{"from": "0xbeef", "to": "0xdead", "at": 1}] * 2
                source["strings"] = [{"from": "0xbeef", "address": "0x8000", "text": "manual" * 1000}]
                source["references"] = [{"from": "0xbeef", "to": "0x9000", "type": "DATA"}]
                source["data_refs"] = [{"from": "0xcafe", "to": "0xa000"}]
                result = partition.partition(source)
                self.assertIn("unattached", result)
                for key in ("calls", "strings", "references", "data_refs"):
                    self.assertEqual(result["unattached"][key], source[key])
                    self.assertEqual(result["summary"]["unattached"][key], len(source[key]))
                with tempfile.TemporaryDirectory() as folder:
                    partition.write_side_files(result, folder)
                    self.assertEqual(json.loads((Path(folder) / "unattached.json").read_text()), result["unattached"])

    def test_all_irreducible_offenders_are_reported_together(self):
        source = program(3)
        source["functions"][0]["signature"] = "x" * 5000
        source["functions"][2]["signature"] = "y" * 5000
        with self.assertRaises(ValueError) as caught:
            partition.partition(source, max_bytes=1000)
        self.assertIn("0x1000", str(caught.exception))
        self.assertIn("0x1020", str(caught.exception))
        self.assertIn("bytes", str(caught.exception))

    def test_malformed_map_rows_have_contextual_value_errors(self):
        cases = [([], "map"), ({}, "functions"), ({"functions": None}, "functions"),
                 ({"functions": [42]}, "functions"), ({"functions": [{}]}, "functions"),
                 ({"functions": [], "calls": {}}, "calls"),
                 ({"functions": [], "calls": ["bad"]}, "calls"),
                 ({"functions": [], "calls": [{"from": "0x1000"}]}, "calls"),
                 ({"functions": [], "strings": [{"from": "0x1000", "address": 8192, "text": 5}]}, "strings"),
                 ({"functions": [], "strings": [{"from": "0x1000", "address": 8192, "text": "\ud800"}]}, "JSON"),
                 ({"functions": [], "file": "\ud800"}, "JSON"),
                 ({"functions": [], "imports": [1]}, "imports"),
                 ({"functions": [], "entry_points": None}, "entry_points"),
                 ({"functions": [], "extra": {1, 2}}, "JSON")]
        for source, message in cases:
            with self.subTest(source=repr(source)):
                try:
                    partition.partition(source)
                except Exception as error:
                    self.assertIs(type(error), ValueError, f"malformed input raised {type(error).__name__}")
                    self.assertRegex(str(error), message)
                else:
                    self.fail("malformed input was accepted")

    def test_manifest_counts_only_deferred_incoming_rows_by_caller_group(self):
        from collections import Counter
        source = program(1301)
        hub = source["functions"][-1]["hex"]
        source["calls"] = [{"from": f["hex"], "to": hub, "at": f["entry"]}
                           for f in source["functions"][:-1]]
        source["calls"] += [{"from": "0x0001", "to": hub, "at": i} for i in range(400)]
        result = self.valid_partition(source)
        group = next(g for g in result["groups"] if hub in g["functions"])
        manifest = group["overflow"]["incoming_calls"]
        self.assertIn("by_group", manifest)
        owners = owner(result)
        deferred = Counter(map(encoded, source["calls"])) - Counter(map(encoded, group["map"]["calls"]))
        expected = Counter()
        for row, count in deferred.items():
            expected[owners.get(json.loads(row)["from"], "unknown_caller")] += count
        self.assertEqual(manifest["by_group"], dict(expected))
        self.assertEqual(sum(manifest["by_group"].values()), manifest["deferred"])
        self.assertLessEqual(len(manifest["by_group"]), len(result["groups"]) + 1)
        self.assertEqual(result["unattached"]["calls"], [])
        payload = result["side_files"][manifest["file"]]
        self.assertNotIn("unattached", payload["by_group"])
        self.assertEqual(payload["by_group"]["unknown_caller"], 400)
        self.assertEqual(sum(payload["by_group"].values()), manifest["total"])

    def test_large_outgoing_call_list_has_a_complete_side_file(self):
        from collections import Counter
        source = program(1301)
        source["calls"] = [{"from": "0x1000", "to": f["hex"], "at": i, "to_name": "callee"}
                           for i, f in enumerate(source["functions"][1:])]
        result = self.valid_partition(source)
        self.check_bounds(source, result, 128, 65536, 8192)
        group = next(g for g in result["groups"] if "0x1000" in g["functions"])
        self.assertEqual(group["functions"], ["0x1000"])
        self.assertTrue(group["oversized"])
        self.assertIn("outgoing_calls", group["overflow"])
        manifest = group["overflow"]["outgoing_calls"]
        payload = result["side_files"][manifest["file"]]
        self.assertEqual(Counter(map(encoded, payload["rows"])), Counter(map(encoded, source["calls"])))
        self.assertLessEqual(manifest["retained"], 128)
        self.assertEqual(manifest["retained"] + manifest["deferred"], 1300)
        self.assertEqual(sum(manifest["by_group"].values()), manifest["deferred"])
        self.assertEqual(len(result["cut_edges"]), 1300)

    def test_large_references_and_data_refs_are_sampled_in_both_directions(self):
        from collections import Counter
        for table in ("references", "data_refs"):
            for direction in ("incoming", "outgoing"):
                with self.subTest(table=table, direction=direction):
                    source = program(3)
                    if direction == "incoming":
                        source[table] = [{"from": hex(0x90000 + i * 16), "to": "0x1000", "type": "READ"}
                                         for i in range(1900)]
                        bucket = "unknown_source"
                    else:
                        source[table] = [{"from": "0x1000", "to": hex(0x90000 + i * 16), "type": "WRITE"}
                                         for i in range(1900)]
                        bucket = "unknown_target"
                    result = self.valid_partition(source)
                    self.check_bounds(source, result, 128, 65536, 8192)
                    group = next(g for g in result["groups"] if "0x1000" in g["functions"])
                    manifest = group["overflow"][table]
                    self.assertTrue(group["oversized"])
                    self.assertLessEqual(manifest["retained"], 128)
                    self.assertEqual(manifest["total"], 1900)
                    self.assertEqual(manifest["by_group"], {bucket: manifest["deferred"]})
                    payload = result["side_files"][manifest["file"]]
                    self.assertEqual(Counter(map(encoded, payload["rows"])), Counter(map(encoded, source[table])))
                    self.assertEqual(len(group["map"][table]), manifest["retained"])

    def test_oversized_view_keeps_strings_that_fit_and_its_self_call(self):
        source = program(1)
        source["calls"] = [{"from": "0x0001", "to": "0x1000", "at": i} for i in range(1800)]
        self_call = {"from": "0x1000", "to": "0x1000", "at": 4097}
        source["calls"].append(self_call)
        source["strings"] = [{"from": "0x1000", "address": "0x9000", "text": "usage"},
                             {"from": "0x1000", "address": "0x9010", "text": "help"}]
        result = self.valid_partition(source)
        group = result["groups"][0]
        self.assertTrue(group["oversized"])
        self.assertEqual(group["original_bytes"], len(encoded(source)))
        self.assertEqual(sorted(map(encoded, group["map"]["strings"])), sorted(map(encoded, source["strings"])))
        self.assertIn(self_call, group["map"]["calls"])
        self.assertEqual(group["overflow"]["incoming_calls"]["total"], 1800)
        self.assertNotIn("strings", group["overflow"])
        self.assertNotIn("outgoing_calls", group["overflow"])
        summarized = next(g for g in result["summary"]["groups"] if g["id"] == group["id"])
        self.assertIs(summarized.get("oversized"), True)

    def test_side_file_objects_are_independent_of_every_result_container(self):
        source = program(1)
        source["calls"] = [{"from": "0xbeef", "to": "0xdead", "meta": {"values": [1]}}]
        source["strings"] = [{"from": "0xbeef", "address": "0x9000", "text": "orphan"}]
        result = partition.partition(source)
        result["unattached"]["calls"][0]["meta"]["values"].append(2)
        self.assertEqual(result["side_files"]["unattached.json"]["calls"][0]["meta"]["values"], [1])
        result["side_files"]["unattached.json"]["strings"][0]["text"] = "side"
        self.assertEqual(result["unattached"]["strings"][0]["text"], "orphan")
        self.assertEqual(source["calls"][0]["meta"]["values"], [1])
        source = program(2)
        source["calls"] = [{"from": "0x1000", "to": "0x1010", "at": i, "meta": {"values": [1]}}
                           for i in range(1300)]
        result = self.valid_partition(source)
        names = list(result["side_files"])
        self.assertEqual(len(names), 2)
        result["side_files"][names[0]]["rows"][0]["meta"]["values"].append(2)
        self.assertEqual(result["side_files"][names[1]]["rows"][0]["meta"]["values"], [1])
        self.assertTrue(all(row["meta"]["values"] == [1] for row in result["cut_edges"]))
        self.assertTrue(all(row["meta"]["values"] == [1] for row in source["calls"]))

    def test_many_self_calls_are_sampled_without_aborting(self):
        source = program(1)
        source["calls"] = [{"from": "0x1000", "to": "0x1000", "at": i} for i in range(2000)]
        source["calls"] += [{"from": "0x1000", "to": "0x0001", "at": -i - 1} for i in range(1000)]
        result = self.valid_partition(source)
        group = result["groups"][0]
        self.assertTrue(group["oversized"])
        self.assertLessEqual(group["bytes"], 65536)
        manifest = group["overflow"]["outgoing_calls"]
        self.assertEqual((manifest["total"], manifest["retained"], manifest["deferred"]), (3000, 128, 2872))
        self.assertEqual(manifest["by_group"], {group["id"]: 1872, "unknown_target": 1000})
        self.assertTrue(all(row["to"] == "0x1000" for row in group["map"]["calls"]))
        self.assertEqual(len(result["side_files"][manifest["file"]]["rows"]), 3000)

    def test_writer_removes_only_stale_files_it_owns(self):
        source = program(1)
        source["strings"] = [{"from": "0x1000", "address": "0x9000", "text": "x" * 70000},
                             {"from": "0xbeef", "address": "0x9010", "text": "orphan"}]
        result = self.valid_partition(source)
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            partition.write_side_files(result, folder)
            created = set(result["side_files"])
            self.assertTrue(created)
            self.assertTrue(all((folder / name).is_file() for name in created))
            protected = ["notes.json", "g0001-custom.json", "g1234x-strings.json", "README"]
            for name in protected:
                (folder / name).write_text("keep")
            (folder / "g10000-data_refs.json").write_text("stale")
            (folder / "g0009-incoming_calls.json").mkdir()
            partition.write_side_files(partition.partition(program(1)), folder)
            self.assertTrue(all(not (folder / name).exists() for name in created))
            self.assertFalse((folder / "g10000-data_refs.json").exists())
            self.assertTrue((folder / "g0009-incoming_calls.json").is_dir())
            self.assertTrue(all((folder / name).read_text() == "keep" for name in protected))

    def test_new_relation_limits_validate_and_keep_deferred_counts_exact(self):
        import inspect
        self.assertIn("outgoing_limit", inspect.signature(partition.partition).parameters)
        self.assertIn("reference_limit", inspect.signature(partition.partition).parameters)
        source = program(1)
        source["calls"] = [{"from": "0x1000", "to": "0x9000", "at": i} for i in range(80)]
        source["references"] = [{"from": "0xbeef", "to": "0x1000", "at": i} for i in range(80)]
        source["data_refs"] = [{"from": "0x1000", "to": "0xa000", "at": i} for i in range(80)]
        result = self.valid_partition(source, max_bytes=1000, outgoing_limit=2, reference_limit=2)
        self.assertLessEqual(result["groups"][0]["bytes"], 1000)
        for kind in ("outgoing_calls", "references", "data_refs"):
            manifest = result["groups"][0]["overflow"][kind]
            self.assertLessEqual(manifest["retained"], 2)
            self.assertEqual(sum(manifest["by_group"].values()), manifest["deferred"])
        for limits in ({"outgoing_limit": 0}, {"reference_limit": True}):
            with self.subTest(limits=limits), self.assertRaises(ValueError):
                partition.partition(program(1), **limits)


if __name__ == "__main__":
    unittest.main()
