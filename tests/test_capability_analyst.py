from dataclasses import replace
import unittest

from reverseai.analysts import capability
from reverseai.contract import (
    Budget, InputRef, Location, Observation, ToolRef, content_id, make_evidence, sha256_hex,
)
from reverseai.gateway import Gateway
from reverseai.tools.strings import TOOL
from tests.fixtures_strings import clean_control, known_strings
from tests.fixtures_yarax import FakeExecutor, known_matches, match, reply
from tests.fixtures_structure import elf_imports, macho, pe_imports
from reverseai import pipeline
from reverseai.contained import ContainedTimeout
from reverseai.tools import structure, yarax_tool


def input_ref(data):
    return InputRef(sha256_hex(data), len(data), "synthetic.bin")


class CapabilityTests(unittest.TestCase):
    def test_plan_is_content_bound_and_deterministic(self):
        data, _, _ = known_strings()
        task = capability.plan(input_ref(data))
        self.assertEqual(task.role, "capability")
        self.assertEqual(task.id, content_id("tk", {"input": sha256_hex(data), "role": "capability",
                         "operations": ["strings.extract", "strings.indicators", "structure.imports"]}))
        self.assertEqual([request.operation for request in task.operations], ["strings.extract", "strings.indicators", "structure.imports"])
        self.assertEqual(task, capability.plan(input_ref(data)))
        self.assertEqual(task.id, capability.plan(InputRef(sha256_hex(data), len(data), "alias.bin")).id)
        self.assertNotEqual(task.id, capability.plan(input_ref(data + b"\x00")).id)

    def test_exact_findings_and_exact_supporting_evidence(self):
        data, _, _ = known_strings()
        task = capability.plan(input_ref(data))
        result = Gateway([TOOL, structure.TOOL], Budget()).run(task, data)
        self.assertEqual(result.status, "ok")
        findings = capability.conclude(task, result.evidence)
        self.assertEqual({finding.claim_key: finding.value for finding in findings}, {
            "capability.anti_debug": ["check_remote_debugger_present", "is_debugger_present"],
            "capability.crypto": ["bcrypt_encrypt", "crypt_encrypt"],
            "capability.network": ["ipv4", "url", "winhttp_open", "wsa_startup"],
            "capability.persistence": ["reg_set_value_ex", "registry_run"],
            "capability.process_injection": ["create_remote_thread", "open_process", "virtual_alloc_ex", "write_process_memory"],
            "strings.urls": ["https://example.invalid/submit", "https://wide.example.invalid/path"],
        })
        for finding in findings:
            if finding.claim_key == "strings.urls":
                expected_ids = {item.id for item in result.evidence if item.operation == "strings.indicators"
                                and item.observation["rule"] == "url"}
                self.assertEqual(finding.confidence, "observed")
            else:
                category = finding.claim_key.removeprefix("capability.")
                expected_ids = {min(item.id for item in result.evidence
                                    if item.operation == "strings.indicators"
                                    and item.observation["category"] == category
                                    and item.observation["rule"] == rule) for rule in finding.value}
                self.assertEqual(finding.confidence, "inferred")
            self.assertEqual(set(finding.evidence_ids), expected_ids)
            self.assertTrue(expected_ids)
        self.assertEqual(findings, capability.conclude(task, tuple(reversed(result.evidence))))

    def test_all_gateway_evidence_has_exact_input_and_excerpt_hashes(self):
        data, _, _ = known_strings()
        result = Gateway([TOOL, structure.TOOL], Budget()).run(capability.plan(input_ref(data)), data)
        for item in result.evidence:
            self.assertEqual(item.input_sha256, sha256_hex(data))
            self.assertEqual(item.tool, ToolRef("strings", "0.1.0"))
            self.assertEqual(item.excerpt_sha256, sha256_hex(data[item.location.offset:item.location.offset + item.location.length]))

    def test_no_indicators_produces_no_findings(self):
        data = clean_control()
        task = capability.plan(input_ref(data))
        result = Gateway([TOOL, structure.TOOL], Budget()).run(task, data)
        self.assertEqual(result.status, "ok")
        self.assertTrue(result.evidence)
        self.assertEqual(capability.conclude(task, result.evidence), ())
        self.assertEqual(capability.conclude(task, ()), ())

    def test_foreign_input_tool_version_and_operation_do_not_support_findings(self):
        data = b"OpenProcess"
        task = capability.plan(input_ref(data))
        value = Observation(Location(0, 11), {"rule": "open_process", "category": "process_injection", "match": "OpenProcess"})
        foreign = (
            make_evidence(b"OtherString", TOOL.ref, "strings.indicators", value),
            make_evidence(data, ToolRef("strings", "0.2.0"), "strings.indicators", value),
            make_evidence(data, TOOL.ref, "strings.extract", value),
        )
        self.assertEqual(capability.conclude(task, foreign), ())
        self.assertEqual(capability.conclude(replace(task, role="structural"), foreign), ())

    def test_malformed_or_unknown_indicator_shapes_are_ignored(self):
        data = b"OpenProcess"
        task = capability.plan(input_ref(data))
        for value in ({"rule": "made_up", "category": "network", "match": "anything"},
                      {"rule": "open_process", "category": "crypto", "match": "OpenProcess"},
                      {"rule": "open_process", "category": "process_injection"},
                      {"rule": ["open_process"], "category": "process_injection", "match": "OpenProcess"}):
            with self.subTest(value=value):
                evidence = make_evidence(data, TOOL.ref, "strings.indicators", Observation(Location(0, 11), value))
                self.assertEqual(capability.conclude(task, (evidence,)), ())

    def test_repeated_indicators_need_only_one_representative_per_rule(self):
        data = b"OpenProcess " * 70
        task = capability.plan(input_ref(data))
        result = Gateway([TOOL, structure.TOOL], Budget()).run(task, data)
        findings = capability.conclude(task, result.evidence)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].value, ["open_process"])
        self.assertEqual(len(findings[0].evidence_ids), 1)

    def test_url_findings_are_bounded_and_cite_exactly_their_values(self):
        urls = [f"https://host{index:03d}.example.invalid" for index in range(70)]
        data = " ".join(urls).encode()
        task = capability.plan(input_ref(data))
        result = Gateway([TOOL, structure.TOOL], Budget()).run(task, data)
        url_finding = next(finding for finding in capability.conclude(task, result.evidence)
                           if finding.claim_key == "strings.urls")
        self.assertEqual(url_finding.value, urls[:64])
        cited = {item.id: item.observation["match"] for item in result.evidence if item.operation == "strings.indicators"}
        self.assertEqual(sorted(cited[item] for item in url_finding.evidence_ids), urls[:64])

    def test_partial_budget_result_only_concludes_from_retained_evidence(self):
        data = b"OpenProcess WinHttpOpen"
        task = capability.plan(input_ref(data))
        result = Gateway([TOOL, structure.TOOL], Budget(max_evidence=2)).run(task, data)
        self.assertEqual(result.status, "budget_exceeded")
        findings = capability.conclude(task, result.evidence)
        self.assertEqual([(finding.claim_key, finding.value) for finding in findings], [
            ("capability.process_injection", ["open_process"]),
        ])
        self.assertEqual(findings[0].evidence_ids, (result.evidence[1].id,))

    def test_yarax_plan_is_optional_content_bound_and_gives_worker_time_to_finish(self):
        data, matches = known_matches()
        tool = yarax_tool.make_tool(FakeExecutor(reply(data, matches)))
        plain, planned = capability.plan(input_ref(data)), capability.plan(input_ref(data), tools=(tool,))
        self.assertEqual([request.operation for request in planned.operations],
                         ["strings.extract", "strings.indicators", "structure.imports", "yarax.matches"])
        self.assertEqual(planned.operations[-1].args, {"max_matches": 64})
        self.assertNotEqual(plain.id, planned.id)
        self.assertEqual(planned, capability.plan(input_ref(data), tools=(tool,)))
        self.assertEqual(planned.budget.max_operations, 4)
        self.assertGreater(planned.budget.max_wall_seconds, 45)
        self.assertEqual(plain, capability.plan(input_ref(data), tools=(TOOL,)))

    def test_yarax_finding_cites_every_match_including_repeated_rule_occurrences(self):
        data, matches = known_matches()
        tool = yarax_tool.make_tool(FakeExecutor(reply(data, matches)))
        task = capability.plan(input_ref(data), tools=(tool,))
        result = Gateway([TOOL, structure.TOOL, tool], Budget(max_wall_seconds=60)).run(task, data)
        self.assertEqual(result.status, "ok")
        signatures = [f for f in capability.conclude(task, result.evidence) if f.claim_key == "signatures.rule_matches"]
        self.assertEqual(len(signatures), 1)
        finding = signatures[0]
        self.assertEqual(finding.value, ["base64_decode_api", "powershell_encoded_command", "upx_packed"])
        self.assertEqual(finding.confidence, "observed")
        self.assertEqual(set(finding.evidence_ids), {e.id for e in result.evidence if e.operation == "yarax.matches"})
        self.assertEqual(len(finding.evidence_ids), 4)
        self.assertEqual(capability.conclude(task, result.evidence), capability.conclude(task, tuple(reversed(result.evidence))))

    def test_a_capped_pattern_flood_keeps_the_later_rule_and_an_over_cap_reply_admits_nothing(self):
        data = b"UPX!" * 64 + b"sekurlsa::"
        matches = [match(index * 4) for index in range(4)] + [
            match(256, b"sekurlsa::", "credential_dump_marker")]
        for extra in (False, True):
            items = matches if not extra else matches[:4] + [match(16)] + matches[4:]
            tool = yarax_tool.make_tool(FakeExecutor(reply(data, items)))
            analysis = pipeline.analyze_bytes(data, input_ref(data), tools=pipeline.TOOLS + (tool,))
            result = next(result for result in analysis.results if result.role == "capability")
            signatures = [f for f in result.findings if f.claim_key == "signatures.rule_matches"]
            with self.subTest(over_cap=extra):
                if extra:
                    self.assertEqual(result.status, "error")
                    self.assertEqual(signatures, [])
                    self.assertFalse(any(e.operation == "yarax.matches" for e in result.evidence))
                else:
                    self.assertEqual(result.status, "ok")
                    self.assertEqual(signatures[0].value, ["credential_dump_marker", "upx_packed"])
                    self.assertEqual(len(signatures[0].evidence_ids), 5)
                    self.assertEqual(next(v.status for v in analysis.verdicts if v.finding_id == signatures[0].id), "supported")

    def test_fake_worker_pipeline_supports_real_signature_bytes_and_refuses_lies_atomically(self):
        data, matches = known_matches()
        for honest in (True, False):
            current = data if honest else data.replace(b"UPX0", b"FAKE")
            executor = FakeExecutor(reply(current, matches))
            tool = yarax_tool.make_tool(executor)
            analysis = pipeline.analyze_bytes(current, input_ref(current), tools=pipeline.TOOLS + (tool,))
            result = next(result for result in analysis.results if result.role == "capability")
            signatures = [f for f in result.findings if f.claim_key == "signatures.rule_matches"]
            with self.subTest(honest=honest):
                self.assertEqual(result.status, "ok" if honest else "error")
                if honest:
                    self.assertEqual(len(signatures), 1)
                    self.assertEqual(next(v.status for v in analysis.verdicts if v.finding_id == signatures[0].id), "supported")
                else:
                    self.assertEqual(signatures, [])
                    self.assertFalse(any(e.operation == "yarax.matches" for e in result.evidence))
                    self.assertEqual(result.errors, ("yarax.matches: ContractError",))

    def test_no_matches_and_worker_timeout_never_become_signature_findings(self):
        data = b"inert clean control"
        for failure in (False, True):
            executor = FakeExecutor(reply(data))
            if failure:
                def timeout(*args):
                    raise ContainedTimeout("WorkerTimeout")
                executor.run = timeout
            tool = yarax_tool.make_tool(executor)
            analysis = pipeline.analyze_bytes(data, input_ref(data), tools=pipeline.TOOLS + (tool,))
            result = next(result for result in analysis.results if result.role == "capability")
            with self.subTest(timeout=failure):
                self.assertFalse(any(f.claim_key == "signatures.rule_matches" for f in result.findings))
                self.assertEqual(result.status, "budget_exceeded" if failure else "ok")

    def test_foreign_input_yarax_version_and_operation_do_not_support_signatures(self):
        data = b"UPX!"
        task = capability.plan(input_ref(data))
        value = Observation(Location(0, 4), {"ruleset": "m2_fixture_v1", "rule": "upx_packed", "pattern": "$a"})
        foreign = (make_evidence(b"UPX0", yarax_tool.REF, "yarax.matches", value),
                   make_evidence(data, ToolRef("yarax", "1.21.0-r1"), "yarax.matches", value),
                   make_evidence(data, yarax_tool.REF, "yarax.other", value))
        self.assertEqual(capability.conclude(task, foreign), ())

    def test_import_planning_and_exact_single_supported_finding_of_each_kind(self):
        for data, _ in (elf_imports(), pe_imports(), macho(libraries=(b"lib.dylib",), symbols=(b"_foo", b"_bar"))):
            task = capability.plan(input_ref(data))
            self.assertEqual(task.operations[-1].operation, "structure.imports")
            self.assertEqual(task.budget.max_operations, 3)
            analysis = pipeline.analyze_bytes(data, input_ref(data))
            result = next(r for r in analysis.results if r.role == "capability")
            self.assertEqual(result.status, "ok")
            imports = [f for f in result.findings if f.claim_key.startswith("imports.")]
            self.assertEqual([f.claim_key for f in imports], ["imports.libraries", "imports.symbols"])
            by_id = {e.id: e for e in result.evidence}
            for finding in imports:
                citations = [by_id[i] for i in finding.evidence_ids]
                self.assertEqual(finding.confidence, "observed")
                self.assertTrue(all(e.operation == "structure.imports" and e.tool == structure.REF for e in citations))
                names = [e.observation["name"] for e in citations] if finding.claim_key.endswith("libraries") else [
                    name for e in citations for name in e.observation["names"]]
                self.assertEqual(finding.value, sorted(set(names)))
                self.assertEqual(next(v.status for v in analysis.verdicts if v.finding_id == finding.id), "supported")
            self.assertEqual(capability.conclude(task, result.evidence), capability.conclude(task, tuple(reversed(result.evidence))))

    def test_import_conclusions_refuse_foreign_provenance_and_malformed_names(self):
        data = b"synthetic inert bytes"
        task = capability.plan(input_ref(data))
        observation = Observation(Location(0, 4), {"kind": "library", "name": "lib"})
        foreign = (make_evidence(b"x" * len(data), structure.REF, "structure.imports", observation),
                   make_evidence(data, ToolRef("structure", "0.2.0"), "structure.imports", observation),
                   make_evidence(data, structure.REF, "structure.identify", observation))
        self.assertEqual(capability.conclude(task, foreign), ())
        for value in ({"kind": "other", "name": "lib"}, {"kind": "library", "name": ""},
                      {"kind": "library", "name": "\x1b[31m"}, {"kind": "library", "name": "x" * 129},
                      {"kind": "symbols", "names": []}, {"kind": "symbols", "names": "fake"},
                      {"kind": "symbols", "names": [None]}, {"kind": "symbols", "names": ["f"] * 33}):
            with self.subTest(value=value):
                evidence = make_evidence(data, structure.REF, "structure.imports", Observation(Location(0, 4), value))
                self.assertEqual(capability.conclude(task, (evidence,)), ())

    def test_import_finding_evidence_cap_keeps_full_values_of_exactly_the_cited_groups(self):
        data = bytes(256)
        task = capability.plan(input_ref(data))
        evidence = tuple(make_evidence(data, structure.REF, "structure.imports", Observation(Location(i, 1), value))
                         for i in range(80) for value in ({"kind": "library", "name": f"lib{i}"},
                           {"kind": "symbols", "library": None, "names": [f"sym{i}", f"other{i}"]}))
        findings = capability.conclude(task, evidence)
        self.assertEqual(len(findings), 2)
        by_id = {e.id: e.observation for e in evidence}
        for finding in findings:
            self.assertEqual(len(finding.evidence_ids), 64)
            cited = [by_id[i] for i in finding.evidence_ids]
            values = [o["name"] for o in cited] if finding.claim_key.endswith("libraries") else [name for o in cited for name in o["names"]]
            self.assertEqual(finding.value, sorted(set(values)))


if __name__ == "__main__":
    unittest.main()
