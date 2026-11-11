"""Group planning contracts, evidence paging and restart bindings without inference."""
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest

from hive import partition, planning


def program(count):
    return {"file": "synthetic", "input_sha256": "ab" * 32,
            "functions": [{"entry": 0x1000 + i * 16, "hex": hex(0x1000 + i * 16),
                           "name": f"fn_{i}", "size": 16, "signature": "int f(void)"} for i in range(count)],
            "calls": [], "strings": [], "imports": []}


def declaration(kind, key, text, *, entry=None, owner=None, linkage=None, requires=()):
    return {"entity_id": kind + ":" + key, "kind": kind, "entry": entry, "owner_entry": owner,
            "linkage": linkage, "text": text, "requires": list(requires), "evidence": [entry or "0x1000"]}


def proposal(entries):
    return {"modules": [{"id": "local", "title": "Synthetic functions", "functions": list(entries)}] if entries else [],
            "skipped": [], "unknowns": [], "declarations": [
                declaration("function", e, f"int fn_{int(e, 16):x}(void); /* {e} */", entry=e) for e in entries]}


class FakeInvoke:
    def __init__(self, partitioned):
        self.outputs = {"planner-" + g["id"]: proposal(g["functions"]) for g in partitioned["groups"]}
        self.calls, self.fail, self.prior = [], {}, []
        self.prefix = "physical-"

    def __call__(self, role, name, task, folder, *, schema=None):
        self.calls.append((role, name, task, Path(folder), schema))
        if name in self.fail:
            return self.fail[name]
        if name.startswith("planner-interface-"):
            data = json.loads((Path(folder) / "interfaces.json").read_bytes())
            output = {"choices": [{"entity_id": data["entity_id"],
                                    "variant_sha256": data["variants"][0]["variant_sha256"], "evidence": ["0x1000"]}]}
        else:
            output = self.outputs[name]
        return {"ok": True, "outcome": "ok", "output": copy.deepcopy(output), "error": None,
                "provenance": {"attempt_id": self.prefix + name, "prior_attempt_ids": list(self.prior)}}


class PlanningTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hive-planning-")
        self.addCleanup(self.temporary.cleanup)
        self.out = Path(self.temporary.name).resolve() / "run"
        self.source = program(5)
        self.parts = partition.partition(self.source, max_functions=2)
        self.invoke = FakeInvoke(self.parts)

    def run_plan(self, **kwargs):
        return planning.plan(self.source, self.parts, out=self.out, invoke=self.invoke, language="c", **kwargs)

    def validate(self, bundle, **kwargs):
        return planning.validate_bundle(bundle, self.source, out=self.out, language="c", max_functions=kwargs.get("max_functions", 12))

    def assert_error(self, code, call):
        with self.assertRaises(planning.PlanningError) as raised:
            call()
        self.assertEqual(raised.exception.code, code, raised.exception)
        return raised.exception

    def test_groups_have_exact_coverage_and_do_not_receive_the_global_map(self):
        before = copy.deepcopy((self.source, self.parts))
        bundle = self.run_plan(max_functions=1)
        self.assertEqual([m["id"] for m in bundle["modules"]], [f"m{i:02d}" for i in range(1, 6)])
        self.assertEqual([m["functions"] for m in bundle["modules"]], [[row["hex"]] for row in self.source["functions"]])
        self.assertEqual([c[1] for c in self.invoke.calls], ["planner-g0001", "planner-g0002", "planner-g0003"])
        for call, group in zip(self.invoke.calls, self.parts["groups"]):
            role, _, _, folder, schema = call
            self.assertEqual(role, "planner")
            self.assertEqual(schema, planning.GROUP_SCHEMA)
            self.assertEqual(json.loads((folder / "map.json").read_bytes()), group["map"])
            self.assertEqual(stat.S_IMODE((folder / "map.json").stat().st_mode), 0o444)
        self.assertEqual(before, (self.source, self.parts))
        self.validate(bundle, max_functions=1)

    def test_empty_program_needs_no_bee(self):
        self.source = program(0)
        self.parts = partition.partition(self.source)
        bundle = self.run_plan()
        self.assertEqual(bundle["modules"], [])
        self.assertEqual(self.invoke.calls, [])
        self.validate(bundle)

    def test_identity_is_independent_of_paths_and_attempt_ids(self):
        self.invoke.prior = ["primary-refusal"]
        first = self.run_plan()
        self.out = self.out.parent / "another"
        self.invoke.prefix = "other-"
        self.invoke.prior = []
        second = self.run_plan()
        self.assertEqual(first["plan_id"], second["plan_id"])
        self.assertNotEqual(first["planner_attempts"], second["planner_attempts"])
        self.assertIn("primary-refusal", first["planner_attempts"])

    def test_complete_manifest_is_reused_without_invoke(self):
        first = self.run_plan()
        self.invoke.calls.clear()
        self.assertEqual(self.run_plan(), first)
        self.assertEqual(self.invoke.calls, [])

    def test_refusal_preserves_valid_groups_and_resume_skips_them(self):
        refused = {"ok": False, "outcome": "provider_refusal", "output": None, "error": "refused", "provenance": {}}
        self.invoke.fail["planner-g0002"] = refused
        error = self.assert_error("provider_refusal", self.run_plan)
        self.assertIs(error.bee_result, refused)
        saved = json.loads((self.out / error.details["progress_path"]).read_bytes())
        self.assertEqual(list(saved["groups"]), ["g0001"])
        self.assertFalse((self.out / "plan/manifest.json").exists())
        self.invoke.fail.clear()
        self.invoke.calls.clear()
        bundle = self.run_plan(saved=saved)
        self.assertEqual([c[1] for c in self.invoke.calls], ["planner-g0002", "planner-g0003"])
        self.validate(bundle)

    def test_non_ok_outcomes_retain_their_exact_cause(self):
        for outcome in ("timeout", "rate_limit", "context_limit", "invalid_schema", "failure", "not_started"):
            with self.subTest(outcome=outcome):
                result = {"ok": False, "outcome": outcome, "output": None}
                self.invoke.fail["planner-g0001"] = result
                error = self.assert_error(outcome, self.run_plan)
                self.assertIs(error.bee_result, result)
        self.assertFalse((self.out / "plan/manifest.json").exists())

    def test_coverage_holes_duplicates_and_foreign_assignments_are_errors(self):
        for entries in (["0x1000"], ["0x1000", "0x1000"], ["0x1000", "0x1020"]):
            with self.subTest(entries=entries):
                self.invoke.outputs["planner-g0001"] = proposal(entries)
                self.assert_error("planning_coverage", self.run_plan)
        self.assertFalse((self.out / "plan/manifest.json").exists())

    def test_unknowns_prevent_freezing_and_incomplete_group_restarts(self):
        self.invoke.outputs["planner-g0001"]["unknowns"] = ["Unknown structure layout"]
        self.assert_error("interface_conflict", self.run_plan)
        saved = json.loads((self.out / "plan/progress.json").read_bytes())
        self.assertEqual(saved["groups"], {})
        self.invoke.outputs["planner-g0001"]["unknowns"] = []
        self.invoke.calls.clear()
        self.run_plan(saved=saved)
        self.assertEqual(self.invoke.calls[0][1], "planner-g0001")

    def test_skips_need_evidence_and_remain_in_the_bundle(self):
        for output in self.invoke.outputs.values():
            entries = output["modules"][0]["functions"]
            output.update(modules=[], declarations=[], skipped=[{"entry": e, "reason": "runtime thunk", "evidence": [e]} for e in entries])
        bundle = self.run_plan()
        self.assertEqual(len(bundle["skipped"]), 5)
        self.assertEqual(bundle["modules"], [])
        self.validate(bundle)

    def test_structural_schema_rejects_unknown_or_missing_fields(self):
        for mutation in (lambda o: o.update(extra=True), lambda o: o.pop("unknowns"), lambda o: o["modules"][0].update(extra=1)):
            with self.subTest(mutation=mutation):
                self.invoke.outputs["planner-g0001"] = proposal(self.parts["groups"][0]["functions"])
                mutation(self.invoke.outputs["planner-g0001"])
                self.assert_error("invalid_schema", self.run_plan)

    def test_global_owner_follows_the_split_module(self):
        value = declaration("global", "0x2000", "extern int counter;", entry="0x2000", owner="0x1010", linkage="defined")
        self.invoke.outputs["planner-g0001"]["declarations"].append(value)
        bundle = self.run_plan(max_functions=1)
        self.assertEqual(bundle["modules"][1]["globals"], ["global:0x2000"])
        self.assertEqual(json.loads((self.out / "plan/interfaces.json").read_bytes())["owners"], {"global:0x2000": "m02"})
        self.validate(bundle, max_functions=1)

    def test_global_owner_must_be_a_built_function(self):
        self.invoke.outputs["planner-g0001"]["declarations"].append(
            declaration("global", "0x2000", "extern int counter;", entry="0x2000", owner="0xdead", linkage="defined"))
        self.assert_error("interface_conflict", self.run_plan)

    def test_external_global_has_no_generated_owner(self):
        self.invoke.outputs["planner-g0001"]["declarations"].append(
            declaration("global", "0x2000", "extern int counter;", entry="0x2000", linkage="external"))
        self.run_plan()
        self.assertEqual(json.loads((self.out / "plan/interfaces.json").read_bytes())["owners"], {})

    def test_conflicts_use_bounded_named_calls_and_existing_variants(self):
        self.invoke.outputs["planner-g0002"]["declarations"].append(
            declaration("function", "0x1000", "long fn_1000(void); /* 0x1000 */", entry="0x1000"))
        bundle = self.run_plan()
        calls = [c for c in self.invoke.calls if c[1].startswith("planner-interface-")]
        self.assertEqual(len(calls), 1)
        self.assertRegex(calls[0][1], r"^planner-interface-[0-9a-f]{12}-r1$")
        self.assertEqual(calls[0][4], planning.INTERFACE_SCHEMA)
        self.assertLessEqual(len(calls[0][2].encode()) + (calls[0][3] / "interfaces.json").stat().st_size, 65536)
        self.assertIn("physical-" + calls[0][1], bundle["planner_attempts"])
        self.validate(bundle)

    def test_zero_conflict_rounds_never_invents_a_contract(self):
        self.invoke.outputs["planner-g0002"]["declarations"].append(
            declaration("function", "0x1000", "long fn_1000(void); /* 0x1000 */", entry="0x1000"))
        self.assert_error("interface_conflict", lambda: self.run_plan(interface_rounds=0))
        self.assertFalse((self.out / "plan/contract.h").exists())

    def test_text_deduplication_only_normalizes_line_endings_and_trailing_spaces(self):
        duplicate = copy.deepcopy(self.invoke.outputs["planner-g0001"]["declarations"][0])
        duplicate["text"] += "  \r\n"
        original = self.invoke.outputs["planner-g0001"]["declarations"][0]
        original["text"] += "\n"
        self.invoke.outputs["planner-g0002"]["declarations"].append(duplicate)
        self.run_plan()
        self.assertFalse(any("interface-" in c[1] for c in self.invoke.calls))

    def test_opaque_types_allow_pointers_but_reject_by_value(self):
        for pointer in (False, True):
            with self.subTest(pointer=pointer):
                self.out = self.out.parent / ("pointer" if pointer else "value")
                output = self.invoke.outputs["planner-g0001"]
                output["declarations"][0] = declaration("function", "0x1000",
                    "int use(struct Opaque " + ("*" if pointer else "") + "v); /* 0x1000 */",
                    entry="0x1000", requires=["type:Opaque"])
                output["declarations"] = [d for d in output["declarations"] if d["kind"] != "type"]
                output["declarations"].append(declaration("type", "Opaque", "struct Opaque;"))
                if pointer:
                    self.run_plan()
                else:
                    self.assert_error("interface_conflict", self.run_plan)

    def test_dependencies_must_resolve_and_cycles_are_explicit_errors(self):
        output = self.invoke.outputs["planner-g0001"]
        output["declarations"][0]["requires"] = ["type:Missing"]
        self.assert_error("interface_conflict", self.run_plan)
        output["declarations"][0]["requires"] = []
        output["declarations"].extend([
            declaration("type", "A", "struct A { int a; };", requires=["type:B"]),
            declaration("type", "B", "struct B { int b; };", requires=["type:A"])])
        self.assert_error("interface_conflict", self.run_plan)

    def test_cpp_qualified_types_and_header_path(self):
        self.invoke.outputs["planner-g0001"]["declarations"].append(
            declaration("type", "space::A", "namespace space { struct A { int a; }; }"))
        bundle = planning.plan(self.source, self.parts, out=self.out, invoke=self.invoke, language="cpp")
        self.assertEqual(bundle["contract_path"], "plan/contract.hpp")
        planning.validate_bundle(bundle, self.source, out=self.out, language="cpp", max_functions=12)

    def test_partition_corruption_is_rejected_before_any_invoke(self):
        original = copy.deepcopy(self.parts)
        mutations = [lambda p: p["groups"][0].update(bytes=1), lambda p: p["groups"][0]["functions"].pop(),
                     lambda p: p["summary"]["totals"].update(functions=99), lambda p: p["groups"][0]["map"]["functions"][0].update(name="changed")]
        for mutation in mutations:
            self.parts = copy.deepcopy(original)
            mutation(self.parts)
            with self.subTest(mutation=mutation):
                self.assert_error("invalid_partition", self.run_plan)
        self.assertEqual(self.invoke.calls, [])

    def test_large_views_page_complete_overflow_and_cut_edges_under_byte_caps(self):
        self.source = program(12)
        self.source["strings"] = [{"from": "0x1000", "address": hex(0x8000 + i), "text": "x" * 80 + str(i)} for i in range(80)]
        self.source["calls"] = [{"from": "0x1000", "to": row["hex"], "at": hex(i)} for i, row in enumerate(self.source["functions"][1:])]
        self.parts = partition.partition(self.source, max_functions=2, max_bytes=1800, string_limit=2)
        self.invoke = FakeInvoke(self.parts)
        self.run_plan(max_prompt_bytes=4096)
        for _, _, task, folder, _ in self.invoke.calls:
            initial = sum((folder / name).stat().st_size for name in ("map.json", "summary.json", "interfaces.json"))
            self.assertLessEqual(initial + len(task.encode()), 4096)
            for page in (folder / "pages").glob("*.json"):
                self.assertLessEqual(page.stat().st_size, 4096)
        evidence = json.loads((self.out / "plan/evidence/g0001-strings.json").read_bytes())
        self.assertEqual(len(evidence["rows"]), 80)
        self.assertTrue(list((self.out / "plan/groups/g0001/pages").glob("*.json")))

    def test_indivisible_record_above_limit_is_not_truncated(self):
        self.source = program(1)
        self.source["functions"][0]["signature"] = "X" * 8000
        self.parts = partition.partition(self.source, max_bytes=20000)
        self.invoke = FakeInvoke(self.parts)
        self.assert_error("planning_payload_too_large", lambda: self.run_plan(max_prompt_bytes=4096))
        self.assertEqual(self.invoke.calls, [])

    def test_bundle_detects_tampered_files_or_input_without_inference(self):
        bundle = self.run_plan()
        calls = len(self.invoke.calls)
        for name in ("plan/contract.h", "plan/interfaces.json", "plan/partition.json", "plan/policy.json", "plan/manifest.json"):
            path = self.out / name
            original = path.read_bytes()
            path.chmod(0o600)
            if name.endswith(".json"):
                changed = json.loads(original)
                changed["unexpected_tampering"] = True
                path.write_text(json.dumps(changed))
            else:
                path.write_bytes(original + b" ")
            with self.subTest(name=name):
                self.assert_error("resume_mismatch", lambda: self.validate(bundle))
            path.write_bytes(original)
            path.chmod(0o444)
        self.source["file"] = "other"
        self.assert_error("resume_mismatch", lambda: self.validate(bundle))
        self.assertEqual(len(self.invoke.calls), calls)

    def test_bundle_paths_symlinks_and_hardlinks_are_refused(self):
        bundle = self.run_plan()
        path = self.out / "plan/contract.h"
        copy_path = self.out / "outside"
        path.rename(copy_path)
        path.symlink_to(copy_path)
        self.assert_error("unsafe_planning_path", lambda: self.validate(bundle))
        path.unlink()
        os.link(copy_path, path)
        self.assert_error("unsafe_planning_path", lambda: self.validate(bundle))

    def test_saved_proposal_corruption_stops_resume(self):
        self.invoke.fail["planner-g0002"] = {"ok": False, "outcome": "timeout"}
        self.assert_error("timeout", self.run_plan)
        saved = json.loads((self.out / "plan/progress.json").read_bytes())
        path = self.out / saved["groups"]["g0001"]["proposal"]["path"]
        path.chmod(0o600)
        path.write_text("{}")
        self.invoke.calls.clear()
        self.assert_error("resume_mismatch", lambda: self.run_plan(saved=saved))
        self.assertEqual(self.invoke.calls, [])


    def test_refused_interface_keeps_group_proposals_and_attempt_provenance(self):
        self.invoke.outputs["planner-g0002"]["declarations"].append(
            declaration("function", "0x1000", "long fn_1000(void); /* 0x1000 */", entry="0x1000"))
        original = self.invoke
        refusal = {"ok": False, "outcome": "provider_refusal", "output": None}
        def refused(role, name, task, folder, *, schema=None):
            if name.startswith("planner-interface-"):
                return refusal
            return original(role, name, task, folder, schema=schema)
        self.invoke = refused
        error = self.assert_error("provider_refusal", self.run_plan)
        self.assertIs(error.bee_result, refusal)
        saved = json.loads((self.out / "plan/progress.json").read_bytes())
        self.assertEqual(len(saved["groups"]), 3)
        original.calls.clear()
        original.prior = ["refused-resolution"]
        self.invoke = original
        bundle = self.run_plan(saved=saved)
        self.assertEqual(len(original.calls), 1)
        self.assertTrue(original.calls[0][1].startswith("planner-interface-"))
        self.assertIn("refused-resolution", bundle["planner_attempts"])

    def test_invalid_conflict_choices_exhaust_two_rounds_even_across_resume(self):
        self.invoke.outputs["planner-g0002"]["declarations"].append(
            declaration("function", "0x1000", "long fn_1000(void); /* 0x1000 */", entry="0x1000"))
        original = self.invoke
        calls = []
        def invented(role, name, task, folder, *, schema=None):
            if name.startswith("planner-interface-"):
                calls.append(name)
                return {"ok": True, "outcome": "ok", "output": {"choices": [
                    {"entity_id": "function:0x1000", "variant_sha256": "invented", "evidence": ["0x1000"]}]},
                    "provenance": {"attempt_id": name, "prior_attempt_ids": []}}
            return original(role, name, task, folder, schema=schema)
        self.invoke = invented
        self.assert_error("interface_conflict", self.run_plan)
        saved = json.loads((self.out / "plan/progress.json").read_bytes())
        self.assertEqual(len(calls), 2)
        self.assert_error("interface_conflict", lambda: self.run_plan(saved=saved))
        self.assertEqual(len(calls), 2, "Resume must not reset the conflict round budget")
        self.assertFalse((self.out / "plan/manifest.json").exists())

    def test_a_planner_cannot_modify_its_read_only_inputs(self):
        original = self.invoke
        def changed(role, name, task, folder, *, schema=None):
            result = original(role, name, task, folder, schema=schema)
            target = folder / "map.json"
            target.chmod(0o600)
            target.write_text("{}")
            return result
        self.invoke = changed
        self.assert_error("planning_evidence_changed", self.run_plan)
        self.assertFalse((self.out / "plan/manifest.json").exists())

    def test_missing_actual_attempt_id_is_not_invented(self):
        original = self.invoke
        def missing(role, name, task, folder, *, schema=None):
            result = original(role, name, task, folder, schema=schema)
            result["provenance"] = {"requested_model": "not-an-attempt"}
            return result
        self.invoke = missing
        self.assert_error("invalid_schema", self.run_plan)

    def test_overflow_hashes_and_counts_are_rechecked_before_invoke(self):
        self.source = program(1)
        self.source["strings"] = [{"from": "0x1000", "address": hex(0x8000 + i), "text": "x" * 80} for i in range(30)]
        self.parts = partition.partition(self.source, max_bytes=1500, string_limit=1)
        self.invoke = FakeInvoke(self.parts)
        original = copy.deepcopy(self.parts)
        for mutation in (
                lambda p: p["groups"][0]["overflow"]["strings"].update(sha256="0" * 64),
                lambda p: p["groups"][0]["overflow"]["strings"].update(deferred=999),
                lambda p: p["groups"][0]["overflow"]["strings"].update(by_group={"g0001": 999})):
            self.parts = copy.deepcopy(original)
            mutation(self.parts)
            self.assert_error("invalid_partition", self.run_plan)
        self.assertEqual(self.invoke.calls, [])

    def test_evidence_is_an_address_or_bound_finding_id(self):
        output = self.invoke.outputs["planner-g0001"]
        output["declarations"][0]["evidence"] = ["unverified assertion"]
        self.assert_error("interface_conflict", self.run_plan)
        output["declarations"][0]["evidence"] = ["fi-0123456789abcdef"]
        self.run_plan()

    def test_an_explicit_forward_declaration_breaks_a_pointer_dependency_cycle(self):
        self.invoke.outputs["planner-g0001"]["declarations"].extend([
            declaration("type", "A", "struct B; struct A { struct B *b; };", requires=["type:B"]),
            declaration("type", "B", "struct A; struct B { struct A *a; };", requires=["type:A"])])
        self.run_plan()

    def test_group_card_limits_declarations_to_owned_entities(self):
        card = Path(planning.__file__).with_name("roles").joinpath("planner.md").read_text()
        group = " ".join(card.split("## Group planning", 1)[1].split("## Interface conflicts", 1)[0].lower().split())
        self.assertIn("declare only this group's own entities", group)
        self.assertIn("do not redeclare prototypes for callees owned by other groups", group)
        self.source = program(4)
        self.source["calls"] = [{"from": "0x1000", "to": row["hex"]} for row in self.source["functions"][1:]]
        self.parts = partition.partition(self.source, max_functions=1)
        self.invoke = FakeInvoke(self.parts)
        self.run_plan()
        self.assertEqual(len(self.parts["cut_edges"]), 3)
        self.assertEqual([call[1] for call in self.invoke.calls],
                         ["planner-g0001", "planner-g0002", "planner-g0003", "planner-g0004"])

    def test_function_declarations_must_reference_the_program_map(self):
        self.invoke.outputs["planner-g0001"]["declarations"].append(
            declaration("function", "0x9000", "int fabricated(void); /* 0x9000 */", entry="0x9000"))
        self.assert_error("interface_conflict", self.run_plan)
        self.assertFalse((self.out / "plan/manifest.json").exists())

    def test_global_declarations_must_not_alias_function_entries(self):
        self.invoke.outputs["planner-g0001"]["declarations"].append(
            declaration("global", "0x1000", "extern int counter;", entry="0x1000", owner="0x1010", linkage="defined"))
        self.assert_error("interface_conflict", self.run_plan)
        self.assertFalse((self.out / "plan/manifest.json").exists())

if __name__ == "__main__":
    unittest.main()
