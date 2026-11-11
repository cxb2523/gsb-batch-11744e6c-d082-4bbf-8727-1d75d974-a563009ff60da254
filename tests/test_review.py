import re
import unittest
from unittest.mock import patch

from reverseai.analysts import structural
from reverseai.contract import (
    AnalysisResult, Evidence, InputRef, Location, Observation, ReviewVerdict, ToolRef, evidence_id, make_evidence, make_finding,
    sha256_hex,
)
from reverseai import review as review_module
from reverseai.review import review
from reverseai.tools import structure
from tests.fixtures_structure import elf, structure_evidence

TOOLS = {"structure": structure.TOOL}
REASON = re.compile(r"(ev-[0-9a-f]{16}: [a-zA-Z ]+|finding cites no evidence|finding does not match its ID"
                    r"|finding ID reused for different content|no claim rule for this claim_key"
                    r"|[a-z_.]+ may only cite [a-z_.]+(, [a-z_.]+)* evidence|[a-z_.]+ must be (observed|inferred)|cited evidence does not yield the claimed value"
                    r"|another finding gives [a-z_.]+ a different value)\Z")


def forged(evidence, **changes):
    """Evidence with altered fields and a matching ID, as a tampered result would carry it."""
    fields = {"input_sha256": evidence.input_sha256, "tool": evidence.tool, "operation": evidence.operation,
              "location": evidence.location, "excerpt_sha256": evidence.excerpt_sha256, "observation": evidence.observation}
    fields.update(changes)
    return Evidence(id=evidence_id(**fields), **fields)


class ReviewTests(unittest.TestCase):
    def setUp(self):
        self.data, _ = elf()
        self.input = InputRef(sha256=sha256_hex(self.data), size=len(self.data), name="sample")
        self.task = structural.plan(self.input)
        self.evidence = structure_evidence(self.data, self.task)
        self.identify = self.evidence[0]

    def result(self, findings, evidence=None, task_id=None):
        return AnalysisResult(task_id or self.task.id, "structural", "ok", tuple(self.evidence if evidence is None else evidence),
                              tuple(findings))

    def finding(self, value="elf", evidence_ids=None, claim_key="format.container"):
        ids = [self.identify.id] if evidence_ids is None else evidence_ids
        return make_finding("structural", "The input format.", claim_key, value, ids)

    def verdict(self, finding, evidence=None, data=None):
        verdicts = review(self.data if data is None else data, self.input, [self.result([finding], evidence)], TOOLS)
        self.assertEqual(len(verdicts), 1)
        for reason in verdicts[0].reasons:
            self.assertRegex(reason, REASON)  # short, names evidence IDs only
        return verdicts[0]

    def test_the_analyst_findings_are_supported(self):
        findings = structural.conclude(self.task, self.evidence)
        verdicts = review(self.data, self.input, [self.result(findings)], TOOLS)
        self.assertEqual(verdicts, tuple(ReviewVerdict(f.id, "supported") for f in sorted(findings, key=lambda f: f.id)))

    def test_missing_evidence(self):
        finding = self.finding(evidence_ids=["ev-0000000000000000"])
        self.assertEqual(self.verdict(finding), ReviewVerdict(finding.id, "unsupported", ("ev-0000000000000000: evidence missing",)))

    def test_tampered_excerpt(self):
        tampered = forged(self.identify, excerpt_sha256=sha256_hex(b"MZ\x90\x00"))
        finding = self.finding(evidence_ids=[tampered.id])
        self.assertEqual(self.verdict(finding, [tampered]),
                         ReviewVerdict(finding.id, "unsupported", (f"{tampered.id}: excerpt hash mismatch",)))

    def test_wrong_tool_version(self):
        newer = make_evidence(self.data, ToolRef("structure", "0.1.1"), "structure.identify",
                              structure.identify(self.data, {})[0])
        finding = self.finding(evidence_ids=[newer.id])
        self.assertEqual(self.verdict(finding, [newer]),
                         ReviewVerdict(finding.id, "unsupported", (f"{newer.id}: tool name or version not registered",)))
        unregistered = review(self.data, self.input, [self.result([self.finding()])], {})
        self.assertEqual(unregistered[0].reasons, (f"{self.identify.id}: tool name or version not registered",))

    def test_out_of_range_location(self):
        outside = forged(self.identify, location=Location(len(self.data) - 2, 4))
        finding = self.finding(evidence_ids=[outside.id])
        self.assertEqual(self.verdict(finding, [outside]),
                         ReviewVerdict(finding.id, "unsupported", (f"{outside.id}: location outside the input",)))

    def test_no_evidence_cited(self):
        finding = self.finding(evidence_ids=[])
        self.assertEqual(self.verdict(finding), ReviewVerdict(finding.id, "unsupported", ("finding cites no evidence",)))

    def identify_as(self, kind, length=4):
        """Intact identify evidence over the input's first bytes that says `kind`: two tools that disagree."""
        return make_evidence(self.data, structure.REF, "structure.identify",
                             Observation(Location(0, length), {"format": kind, "magic": self.data[:length].hex()}))

    def test_contradiction_by_claim_key(self):
        pe_evidence = self.identify_as("pe")
        elf_finding, pe_finding = self.finding("elf"), self.finding("pe", [pe_evidence.id])
        verdicts = review(self.data, self.input, [self.result([elf_finding]), self.result([pe_finding], [pe_evidence])], TOOLS)
        reason = ("another finding gives format.container a different value",)
        self.assertEqual(verdicts, tuple(sorted((ReviewVerdict(elf_finding.id, "contradicted", reason),
                                                 ReviewVerdict(pe_finding.id, "contradicted", reason)), key=lambda v: v.finding_id)))

    def test_an_unsupported_finding_never_contradicts_a_verified_one(self):
        verified = self.finding("elf")
        for label, bogus, reason in (
                ("missing evidence", self.finding("pe", evidence_ids=["ev-0000000000000000"]), "ev-0000000000000000: evidence missing"),
                ("no evidence", self.finding("pe", evidence_ids=[]), "finding cites no evidence")):
            with self.subTest(label):
                verdicts = review(self.data, self.input, [self.result([verified]), self.result([bogus])], TOOLS)
                self.assertEqual(verdicts, tuple(sorted((ReviewVerdict(verified.id, "supported"),
                                                         ReviewVerdict(bogus.id, "unsupported", (reason,))),
                                                        key=lambda v: v.finding_id)))

    def test_two_verified_findings_that_agree_are_contradicted_by_a_third_that_differs(self):
        elf_again, pe_evidence = self.identify_as("elf", length=2), self.identify_as("pe")
        first, second, other = self.finding("elf"), self.finding("elf", [elf_again.id]), self.finding("pe", [pe_evidence.id])
        self.assertEqual(len({first.id, second.id, other.id}), 3)
        evidence = [*self.evidence, elf_again, pe_evidence]
        verdicts = review(self.data, self.input, [self.result([first, second, other], evidence)], TOOLS)
        reason = ("another finding gives format.container a different value",)
        self.assertEqual(verdicts, tuple(ReviewVerdict(finding_id, "contradicted", reason)
                                         for finding_id in sorted((first.id, second.id, other.id))))

    def test_citations_resolve_only_inside_the_findings_own_result(self):
        finding = self.finding("elf")
        elsewhere = self.result([], task_id="tk-0000000000000001")
        verdicts = review(self.data, self.input, [self.result([finding], evidence=[]), elsewhere], TOOLS)
        self.assertEqual(verdicts, (ReviewVerdict(finding.id, "unsupported", (f"{self.identify.id}: evidence missing",)),))

    def test_a_mutating_analyst_cannot_get_altered_evidence_or_values_supported(self):
        evidence = make_evidence(self.data, structure.REF, "structure.identify", structure.identify(self.data, {})[0])
        finding = self.finding("elf", [evidence.id])
        evidence.observation["format"] = "pe"  # an analyst edits the record it was handed
        self.assertEqual(self.verdict(finding, [evidence]),
                         ReviewVerdict(finding.id, "unsupported", (f"{evidence.id}: record does not match its ID",)))
        sections = [item for item in self.evidence if item.operation == "structure.sections" and item.observation["name"] == ".rwx"]
        listed = make_finding("structural", "Writable and executable.", "sections.writable_executable", [".rwx"], [sections[0].id])
        listed.value.append(".text")  # a mutable value changed after the ID was bound
        self.assertEqual(self.verdict(listed), ReviewVerdict(listed.id, "unsupported", ("finding does not match its ID",)))

    def test_one_finding_id_with_different_content_is_unsupported(self):
        original = self.finding("elf")
        changed = self.finding("elf")
        object.__setattr__(changed, "claim", "A different claim.")  # as a 64-bit ID collision would look
        with patch.object(review_module, "finding_intact", return_value=True):
            verdicts = review(self.data, self.input, [self.result([original]), self.result([changed])], TOOLS)
        self.assertEqual(verdicts, (ReviewVerdict(original.id, "unsupported", ("finding ID reused for different content",)),))

    def test_evidence_from_an_unregistered_operation(self):
        bogus = make_evidence(self.data, structure.REF, "structure.bogus", structure.identify(self.data, {})[0])
        finding = self.finding(evidence_ids=[bogus.id])
        self.assertEqual(self.verdict(finding, [bogus]),
                         ReviewVerdict(finding.id, "unsupported", (f"{bogus.id}: operation not registered",)))

    def test_the_input_reference_must_describe_the_bytes(self):
        finding = self.finding("elf")
        for label, other, reason in (("size", InputRef(self.input.sha256, self.input.size + 1, "sample"), "input size mismatch"),
                                     ("hash", InputRef("0" * 64, self.input.size, "sample"), "input hash mismatch")):
            with self.subTest(label):
                verdicts = review(self.data, other, [self.result([finding])], TOOLS)
                self.assertEqual(verdicts, (ReviewVerdict(finding.id, "unsupported", (f"{self.identify.id}: {reason}",)),))

    def test_a_claim_must_follow_from_the_evidence_it_cites(self):
        headers = [item for item in self.evidence if item.operation == "structure.headers"][0]
        cases = (
            (self.finding("pe"), "cited evidence does not yield the claimed value"),
            (self.finding("elf", [headers.id]), "format.container may only cite lief.headers, structure.identify evidence"),
            (self.finding("elf", claim_key="format.colour"), "no claim rule for this claim_key"),
        )
        for finding, reason in cases:
            with self.subTest(reason=reason):
                self.assertEqual(self.verdict(finding), ReviewVerdict(finding.id, "unsupported", (reason,)))

    def test_changed_input_bytes_fail_every_item(self):
        changed = b"\x00" + self.data[1:]
        verdict = self.verdict(self.finding(), data=changed)
        self.assertEqual(verdict.status, "unsupported")
        self.assertEqual(verdict.reasons, (f"{self.identify.id}: input hash mismatch", f"{self.identify.id}: excerpt hash mismatch"))

    def test_one_verdict_per_finding_in_a_deterministic_order(self):
        findings = structural.conclude(self.task, self.evidence)
        twice = [self.result(findings), self.result(findings, task_id="tk-0000000000000001")]
        verdicts = review(self.data, self.input, twice, TOOLS)
        self.assertEqual([v.finding_id for v in verdicts], sorted(f.id for f in findings))
        self.assertEqual(verdicts, review(self.data, self.input, list(reversed(twice)), TOOLS))
        self.assertEqual(review(self.data, self.input, [], TOOLS), ())


if __name__ == "__main__":
    unittest.main()
