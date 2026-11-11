import unittest

from reverseai.contract import (
    ArgSpec, AnalysisTask, Budget, ContractError, Evidence, InputRef, Location, Observation,
    OperationRequest, OperationSpec, ReviewVerdict, ToolRef, ToolSpec, evidence_from_dict,
    evidence_intact, finding_intact, make_evidence, make_finding, operation_key, sha256_hex,
)

DATA = b"\x7fELF" + bytes(60) + b"hello world\x00"
TOOL = ToolRef("structure", "0.1.0")


def observation(offset=0, length=4, **value):
    return Observation(Location(offset, length), value or {"magic": "7f454c46"})


class EvidenceTests(unittest.TestCase):
    def test_make_evidence_binds_input_and_excerpt(self):
        evidence = make_evidence(DATA, TOOL, "structure.identify", observation())
        self.assertEqual(evidence.input_sha256, sha256_hex(DATA))
        self.assertEqual(evidence.excerpt_sha256, sha256_hex(DATA[:4]))
        self.assertTrue(evidence.id.startswith("ev-"))

    def test_evidence_id_is_deterministic_and_content_bound(self):
        first = make_evidence(DATA, TOOL, "structure.identify", observation())
        self.assertEqual(first, make_evidence(DATA, TOOL, "structure.identify", observation()))
        other = make_evidence(DATA, ToolRef("structure", "0.1.1"), "structure.identify", observation())
        self.assertNotEqual(first.id, other.id)

    def test_round_trip_and_tamper_detection(self):
        evidence = make_evidence(DATA, TOOL, "structure.identify", observation())
        self.assertEqual(evidence_from_dict(evidence.to_dict()), evidence)
        tampered = evidence.to_dict()
        tampered["observation"] = {"magic": "4d5a"}
        with self.assertRaises(ContractError):
            evidence_from_dict(tampered)

    def test_location_must_be_inside_input(self):
        with self.assertRaises(ContractError):
            make_evidence(DATA, TOOL, "structure.identify", observation(offset=len(DATA) - 2, length=4))

    def test_operation_must_belong_to_tool(self):
        with self.assertRaises(ContractError):
            make_evidence(DATA, TOOL, "strings.extract", observation())

    def test_observation_limits(self):
        with self.assertRaises(ContractError):
            Observation(Location(0, 4), {"blob": "x" * 5000})
        with self.assertRaises(ContractError):
            Observation(Location(0, 4), {"raw": b"bytes"})
        with self.assertRaises(ContractError):
            Location(0, 0)


class OperationTests(unittest.TestCase):
    def setUp(self):
        self.spec = OperationSpec(
            "strings.extract",
            {"min_length": ArgSpec("int", 4, 64, default=4), "encoding": ArgSpec("enum", choices=("ascii", "utf16le"), default="ascii")},
            lambda data, args: [],
        )

    def test_defaults_and_bounds(self):
        self.assertEqual(self.spec.validate_args({}), {"encoding": "ascii", "min_length": 4})
        with self.assertRaises(ContractError):
            self.spec.validate_args({"min_length": 1000})
        with self.assertRaises(ContractError):
            self.spec.validate_args({"encoding": "latin1"})

    def test_unknown_arguments_and_paths_are_refused(self):
        with self.assertRaises(ContractError):
            self.spec.validate_args({"output": "/tmp/x"})
        for bad in ("/etc/passwd", "..\\x", "--flag"):
            with self.assertRaises(ContractError):
                ArgSpec("str").check(bad)

    def test_literal_search_text_is_bounded_printable_and_never_contained(self):
        # Search text may hold "/" or start with "-", but only in-process tools take it.
        literal = ArgSpec("literal", 1, 128)
        for good in ("http://example.test/a", "-flag", "a b", "x" * 128, "café"):
            self.assertEqual(literal.check(good), good)
        for bad in ("", "x" * 129, "a\nb", "nul\x00", 7, None, b"bytes"):
            with self.assertRaises(ContractError):
                literal.check(bad)
        self.assertEqual(ArgSpec("literal", 0, 128).check(""), "")
        for low, high in ((-1, 4), (5, 4), (0, 257)):
            with self.assertRaises(ContractError):
                ArgSpec("literal", low, high)
        search = OperationSpec("strings.search", {"query": literal}, lambda data, args: [])
        ToolSpec(ToolRef("strings", "0.1.0"), {"strings.search": search})
        contained = OperationSpec("ghidra.functions", {"query": ArgSpec("literal", 0, 128, default="")}, lambda d, a: [])
        with self.assertRaises(ContractError):
            ToolSpec(ToolRef("ghidra", "12.1.4-r6"), {"ghidra.functions": contained}, contained=True)

    def test_tool_spec_requires_owned_operations(self):
        ToolSpec(ToolRef("strings", "0.1.0"), {"strings.extract": self.spec})
        with self.assertRaises(ContractError):
            ToolSpec(TOOL, {"strings.extract": self.spec})

    def test_operation_key_ignores_argument_order(self):
        a = operation_key("0" * 64, TOOL, "structure.sections", {"a": 1, "b": 2})
        b = operation_key("0" * 64, TOOL, "structure.sections", {"b": 2, "a": 1})
        self.assertEqual(a, b)
        self.assertNotEqual(a, operation_key("0" * 64, ToolRef("structure", "0.2.0"), "structure.sections", {"a": 1, "b": 2}))


class TaskFindingVerdictTests(unittest.TestCase):
    def test_task_validation(self):
        ref = InputRef(sha256_hex(DATA), len(DATA), "sample.bin")
        task = AnalysisTask("tk-0123456789abcdef", "structural", ref, (OperationRequest("structure.identify"),))
        self.assertEqual(task.budget.max_concurrency, 1)
        with self.assertRaises(ContractError):
            AnalysisTask("tk-0123456789abcdef", "dynamic", ref, (OperationRequest("structure.identify"),))
        with self.assertRaises(ContractError):
            Budget(max_concurrency=0)

    def test_finding_id_is_content_bound(self):
        evidence = make_evidence(DATA, TOOL, "structure.identify", observation())
        finding = make_finding("structural", "The input is an ELF file.", "format.container", "elf", [evidence.id, evidence.id])
        self.assertEqual(finding.evidence_ids, (evidence.id,))
        with self.assertRaises(ContractError):
            type(finding)(finding.id, "structural", finding.claim, finding.claim_key, "pe", finding.evidence_ids)

    def test_finding_id_binds_claim_text_and_confidence(self):
        evidence = make_evidence(DATA, TOOL, "structure.identify", observation())
        plain = make_finding("structural", "The input is an ELF file.", "format.container", "elf", [evidence.id])
        louder = make_finding("structural", "The input is definitely malware.", "format.container", "elf", [evidence.id])
        inferred = make_finding("structural", "The input is an ELF file.", "format.container", "elf", [evidence.id], "inferred")
        self.assertEqual(len({plain.id, louder.id, inferred.id}), 3)

    def test_in_place_mutation_is_detected(self):
        evidence = make_evidence(DATA, TOOL, "structure.identify", observation(magic="7f454c46", nested={"list": [1]}))
        finding = make_finding("structural", "Sections.", "sections.names", [".text"], [evidence.id])
        self.assertTrue(evidence_intact(evidence) and finding_intact(finding))
        evidence.observation["nested"]["list"].append(2)
        finding.value.append(".rwx")
        self.assertFalse(evidence_intact(evidence))
        self.assertFalse(finding_intact(finding))
        self.assertFalse(evidence_intact({"id": evidence.id}))

    def test_precomputed_input_hash(self):
        digest = sha256_hex(DATA)
        self.assertEqual(make_evidence(DATA, TOOL, "structure.identify", observation(), input_sha256=digest),
                         make_evidence(DATA, TOOL, "structure.identify", observation()))

    def test_rejected_verdict_needs_reason(self):
        ReviewVerdict("fi-0123456789abcdef", "supported")
        with self.assertRaises(ContractError):
            ReviewVerdict("fi-0123456789abcdef", "unsupported")


if __name__ == "__main__":
    unittest.main()
