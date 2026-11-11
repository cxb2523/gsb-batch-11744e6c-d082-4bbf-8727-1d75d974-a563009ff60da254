import unittest

from reverseai.analysts import structural
from reverseai.contract import (
    AnalysisTask, InputRef, Observation, OperationRequest, ToolRef, content_id, make_evidence, make_finding, sha256_hex,
)
from tests.fixtures_structure import elf, pe, structure_evidence


def ref(data, name="sample"):
    return InputRef(sha256=sha256_hex(data), size=len(data), name=name)


def by_operation(evidence, operation):
    return [item for item in evidence if item.operation == operation]


class PlanTests(unittest.TestCase):
    def test_the_plan_is_deterministic(self):
        data, _ = elf()
        task = structural.plan(ref(data))
        self.assertEqual(task, AnalysisTask(
            id=content_id("tk", {"input": sha256_hex(data), "role": "structural"}), role="structural", input=ref(data),
            operations=(OperationRequest("structure.identify"), OperationRequest("structure.headers"),
                        OperationRequest("structure.sections", {"max_sections": 64}))))
        self.assertEqual(structural.plan(ref(data, name="other")).id, task.id)  # the display name is not identity


class ConcludeTests(unittest.TestCase):
    def conclude(self, data):
        task = structural.plan(ref(data))
        evidence = structure_evidence(data, task)
        return task, evidence, structural.conclude(task, evidence)

    def test_elf_findings_cite_their_evidence(self):
        data, _ = elf()
        _, evidence, findings = self.conclude(data)
        identify = by_operation(evidence, "structure.identify")
        headers = by_operation(evidence, "structure.headers")
        rwx = [item for item in by_operation(evidence, "structure.sections") if item.observation["name"] == ".rwx"]
        expected = (
            make_finding("structural", "The input is an ELF file.", "format.container", "elf", [identify[0].id]),
            make_finding("structural", "The header names the x86_64 machine.", "format.machine", "x86_64", [headers[0].id]),
            make_finding("structural", "The header declares 5 sections.", "format.section_count", 5, [headers[0].id]),
            make_finding("structural", "Some sections are both writable and executable.", "sections.writable_executable",
                         [".rwx"], [rwx[0].id], confidence="inferred"),
        )
        self.assertEqual(findings, tuple(sorted(expected, key=lambda f: (f.claim_key, f.id))))

    def test_pe_findings(self):
        data, _ = pe()
        _, evidence, findings = self.conclude(data)
        values = {finding.claim_key: finding.value for finding in findings}
        self.assertEqual(values, {"format.container": "pe", "format.machine": "x86_64", "format.section_count": 3,
                                  "sections.writable_executable": [".rwx"]})

    def test_no_writable_executable_finding_without_such_sections(self):
        data, _ = elf(sections=((b".text", 1, 0x6, 8), (b".data", 1, 0x3, 8)))
        _, _, findings = self.conclude(data)
        self.assertNotIn("sections.writable_executable", [finding.claim_key for finding in findings])

    def test_an_unknown_format_gives_only_the_container_finding(self):
        data = b"plain text, not a binary"
        _, evidence, findings = self.conclude(data)
        self.assertEqual(findings, (make_finding("structural", "The input is an unrecognized file.", "format.container", "unknown",
                                                 [evidence[0].id]),))

    def test_no_claim_for_an_unknown_machine_or_an_extended_section_count(self):
        _, _, findings = self.conclude(elf(machine=0x1234)[0])
        self.assertNotIn("format.machine", [finding.claim_key for finding in findings])
        _, _, findings = self.conclude(elf(extended=True)[0])
        values = {finding.claim_key: finding.value for finding in findings}
        self.assertNotIn("format.section_count", values)  # the header holds 0, not the count
        self.assertEqual(values["sections.writable_executable"], [".rwx"])

    def test_no_finding_without_evidence_and_foreign_evidence_is_ignored(self):
        data, _ = elf()
        task = structural.plan(ref(data))
        self.assertEqual(structural.conclude(task, ()), ())
        other, _ = pe()
        foreign = structure_evidence(other, structural.plan(ref(other)))
        self.assertEqual(structural.conclude(task, foreign), ())
        identify = structure_evidence(data, task)[0]
        other_tool = make_evidence(data, ToolRef("strings", "0.1.0"), "strings.ascii",
                                   Observation(identify.location, identify.observation))
        self.assertEqual(structural.conclude(task, (other_tool,)), ())

    def test_disagreeing_evidence_gives_one_finding_per_value(self):
        data, _ = elf()
        task = structural.plan(ref(data))
        evidence = list(structure_evidence(data, task))
        headers = by_operation(evidence, "structure.headers")[0]
        other = make_evidence(data, headers.tool, "structure.headers",
                              Observation(headers.location, dict(headers.observation, machine_name="aarch64")))
        findings = structural.conclude(task, evidence + [other])
        machines = sorted(finding.value for finding in findings if finding.claim_key == "format.machine")
        self.assertEqual(machines, ["aarch64", "x86_64"])


class LiefStructuralTests(unittest.TestCase):
    """Physical LIEF header observations must support exactly the fields cited."""

    def tool(self):
        from reverseai.tools.lief_tool import make_tool
        from tests.test_lief_tool import FakeExecutor, reply
        return make_tool(FakeExecutor(reply(b"")))

    def evidence(self, data, operation, offset, length, value):
        from reverseai.contract import Location
        return make_evidence(data, ToolRef("lief", "1.0.0-r2"), operation, Observation(Location(offset, length), value))

    def assert_supported(self, data, task, evidence, findings):
        from reverseai.contract import AnalysisResult
        from reverseai.review import review
        from reverseai.tools import structure
        result = AnalysisResult(task.id, task.role, "ok", tuple(evidence), tuple(findings))
        verdicts = review(data, task.input, (result,), {"structure": structure.TOOL, "lief": self.tool()})
        self.assertTrue(verdicts)
        self.assertTrue(all(verdict.status == "supported" for verdict in verdicts), verdicts)

    def test_only_an_available_lief_tool_extends_the_m1_plan(self):
        from reverseai.tools import structure, strings
        data, _ = elf()
        original = structural.plan(ref(data))
        self.assertEqual(structural.plan(ref(data), tools=(structure.TOOL, strings.TOOL)), original)
        contained = structural.plan(ref(data), tools=(structure.TOOL, self.tool()))
        self.assertEqual(contained.operations[:-2], original.operations)
        self.assertEqual(contained.operations[-2:], (OperationRequest("lief.headers"),
                                                    OperationRequest("lief.sections", {"max_sections": 64})))
        self.assertNotEqual(contained.id, original.id)
        self.assertEqual(contained.id, structural.plan(ref(data, "other"), tools=(self.tool(),)).id)

    def test_pe_claims_cite_the_coff_header_without_dos_or_optional_header(self):
        data, layout = pe()
        task = structural.plan(ref(data), tools=(self.tool(),))
        dos = self.evidence(data, "lief.headers", 0, 64, {"structure": "dos", "e_lfanew": layout["lfanew"]})
        coff = self.evidence(data, "lief.headers", layout["lfanew"], 24,
                             {"format": "pe", "machine_name": "x86_64", "number_of_sections": 3})
        optional = self.evidence(data, "lief.headers", layout["lfanew"] + 24, layout["optional_size"],
                                 {"magic": 0x20b, "entry_rva": 0x1000})
        findings = structural.conclude(task, (dos, coff, optional))
        self.assertEqual({finding.claim_key: finding.value for finding in findings},
                         {"format.container": "pe", "format.machine": "x86_64", "format.section_count": 3})
        for finding in findings:
            self.assertEqual(finding.evidence_ids, (coff.id,))
        self.assert_supported(data, task, (dos, coff, optional), findings)

    def test_elf_headers_merge_agreeing_m1_and_lief_citations(self):
        data, layout = elf()
        task = structural.plan(ref(data), tools=(self.tool(),))
        physical = self.evidence(data, "lief.headers", 0, layout["header_size"],
                                 {"format": "elf", "machine_name": "x86_64", "shnum": layout["shnum"], "shoff": layout["shoff"]})
        evidence = (*structure_evidence(data, structural.plan(ref(data))), physical)
        findings = structural.conclude(task, evidence)
        for finding in findings:
            if finding.claim_key.startswith("format."):
                self.assertEqual(len(finding.evidence_ids), 2)
                self.assertIn(physical.id, finding.evidence_ids)
        self.assert_supported(data, task, evidence, findings)

    def test_separate_header_fields_are_not_overcited(self):
        data, layout = elf()
        task = structural.plan(ref(data), tools=(self.tool(),))
        fields = (("format", "elf"), ("machine_name", "aarch64"), ("shnum", 5))
        evidence = tuple(self.evidence(data, "lief.headers", index * 4, 4, {key: value})
                         for index, (key, value) in enumerate(fields))
        findings = structural.conclude(task, evidence)
        expected = dict(zip(("format.container", "format.machine", "format.section_count"), evidence))
        for finding in findings:
            self.assertEqual(finding.evidence_ids, (expected[finding.claim_key].id,))
        self.assertEqual(len(findings), 3)
        self.assert_supported(data, task, evidence, findings)

    def test_lief_extended_count_unknown_machine_and_missing_fields_make_no_claim(self):
        data, layout = elf(extended=True)
        task = structural.plan(ref(data), tools=(self.tool(),))
        evidence = (self.evidence(data, "lief.headers", 0, 64,
                                  {"shnum": 0, "shoff": layout["shoff"], "machine_name": "unknown"}),)
        self.assertEqual(structural.conclude(task, evidence), ())

    def test_only_actual_writable_executable_indices_are_inferred(self):
        data, layout = elf()
        task = structural.plan(ref(data), tools=(self.tool(),))
        evidence = tuple(self.evidence(data, "lief.sections", layout["shoff"], layout["entry_size"], value) for value in (
            {"index": 3, "writable": True, "executable": True},
            {"index": 1, "writable": True, "executable": True},
            {"index": 3, "writable": True, "executable": True, "size": 8},
            {"index": 2, "writable": True, "executable": False},
            {"index": True, "writable": True, "executable": True},
            {"index": -1, "writable": True, "executable": True},
            {"writable": True, "executable": True},
        ))
        findings = structural.conclude(task, evidence)
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual((finding.claim_key, finding.value, finding.confidence),
                         ("sections.writable_executable_indices", [1, 3], "inferred"))
        self.assertEqual(set(finding.evidence_ids), {item.id for item in evidence[:3]})
        self.assert_supported(data, task, evidence, findings)

    def test_foreign_lief_snapshot_is_ignored(self):
        data, layout = elf()
        other, _ = pe()
        task = structural.plan(ref(data), tools=(self.tool(),))
        foreign = self.evidence(other, "lief.headers", 0, 64, {"format": "pe"})
        self.assertEqual(structural.conclude(task, (foreign,)), ())


if __name__ == "__main__":
    unittest.main()
