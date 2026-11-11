"""Derived evidence: anchored in the input, reviewed as "derived", never verified or contradicting."""

import unittest

from reverseai import claims, report
from reverseai.contract import (
    AnalysisResult, ContractError, InputRef, Location, Observation, OperationSpec, ToolRef, ToolSpec,
    content_id, make_evidence, make_finding, sha256_hex,
)
from reverseai.review import review

DATA = bytes(range(256)) * 4
INPUT = InputRef(sha256_hex(DATA), len(DATA), "sample.bin")
GHIDRA = ToolRef("ghidra", "12.1.4-r1")
TASK = content_id("tk", {"test": "derived"})


def tool(derived=True):
    operation = OperationSpec("ghidra.analyze", {}, lambda data, args: [], max_observations=400, derived=derived)
    return {"ghidra": ToolSpec(GHIDRA, {"ghidra.analyze": operation})}


def observed(offset, **value):
    return make_evidence(DATA, GHIDRA, "ghidra.analyze", Observation(Location(offset, 16), value))


def verdicts(findings, evidence, tools=None):
    result = AnalysisResult(TASK, "code", "ok", tuple(evidence), tuple(findings))
    return {v.finding_id: v for v in review(DATA, INPUT, [result], tools or tool())}


FUNCTIONS = [observed(0, kind="function", index=0, name="entry", entry=0x1000, size=32),
             observed(64, kind="function", index=1, name="helper", entry=0x1040, size=16)]


class DerivedTests(unittest.TestCase):
    def test_a_derived_operation_yields_a_derived_verdict_with_a_reason(self):
        finding = make_finding("code", "Functions.", "code.functions", ["entry", "helper"], [e.id for e in FUNCTIONS], "inferred")
        verdict = verdicts([finding], FUNCTIONS)[finding.id]
        self.assertEqual(verdict.status, "derived")
        self.assertIn("not verified against the bytes", verdict.reasons[0])

    def test_code_claims_stay_derived_even_under_a_misregistered_spec(self):
        # The claim key, not only the spec flag, makes a finding derived.
        self.assertEqual(claims.DERIVED_CLAIMS, {"code.functions", "code.pseudocode", "code.calls",
                                                 "code.assembly", "code.references", "code.strings",
                                                 "code.function_list", "code.function_info", "code.instructions",
                                                 "code.callers", "code.xrefs", "android.java",
                                        "javascript.modules", "javascript.calls", "javascript.parse",
                                        "code.export_page", "code.export_functions", "code.export_calls",
                                        "code.export_references", "code.export_strings", "code.export_instructions",
                                        "code.pseudocode_page"})
        finding = make_finding("code", "Functions.", "code.functions", ["entry", "helper"], [e.id for e in FUNCTIONS], "inferred")
        self.assertEqual(verdicts([finding], FUNCTIONS, tool(derived=False))[finding.id].status, "derived")

    def test_derived_claims_still_need_their_rule_confidence_and_value(self):
        overstated = make_finding("code", "Functions.", "code.functions", ["entry", "helper"], [e.id for e in FUNCTIONS], "observed")
        wrong = make_finding("code", "Functions.", "code.functions", ["helper", "entry"], [e.id for e in FUNCTIONS], "inferred")
        judged = verdicts([overstated, wrong], FUNCTIONS)
        self.assertEqual({judged[f.id].status for f in (overstated, wrong)}, {"unsupported"})

    def test_derived_findings_neither_contradict_nor_are_contradicted(self):
        first = observed(0, kind="pseudocode", index=0, entry=0x1000, text="int entry(void) {}", truncated=False)
        second = observed(64, kind="pseudocode", index=1, entry=0x1040, text="void helper(void) {}", truncated=False)
        findings = [make_finding("code", "Code.", "code.pseudocode", {"entry": e.observation["entry"], "text": e.observation["text"],
                                                                     "truncated": False}, [e.id], "inferred") for e in (first, second)]
        self.assertEqual({v.status for v in verdicts(findings, [first, second]).values()}, {"derived"})

    def test_a_pseudocode_claim_cites_exactly_one_function(self):
        first = observed(0, kind="pseudocode", index=0, entry=0x1000, text="int entry(void) {}", truncated=False)
        second = observed(64, kind="pseudocode", index=1, entry=0x1040, text="int entry(void) {}", truncated=False)
        finding = make_finding("code", "Code.", "code.pseudocode", {"entry": 0x1000, "text": "int entry(void) {}", "truncated": False},
                               [first.id, second.id], "inferred")
        self.assertEqual(verdicts([finding], [first, second])[finding.id].status, "unsupported")
        # Two citations with equal values: only the one-observation rule refuses them, whatever the evidence ID order.
        twin = observed(128, kind="pseudocode", index=0, entry=0x1000, text="int entry(void) {}", truncated=False)
        same = make_finding("code", "Code.", "code.pseudocode", {"entry": 0x1000, "text": "int entry(void) {}", "truncated": False},
                            [first.id, twin.id], "inferred")
        self.assertEqual(verdicts([same], [first, twin])[same.id].status, "unsupported")

    def test_an_anchor_that_no_longer_matches_the_bytes_is_unsupported(self):
        evidence = observed(0, kind="function", index=0, name="entry", entry=0x1000, size=32)
        finding = make_finding("code", "Functions.", "code.functions", ["entry"], [evidence.id], "inferred")
        changed = bytes([DATA[0] ^ 1]) + DATA[1:]
        result = AnalysisResult(TASK, "code", "ok", (evidence,), (finding,))
        verdict = review(changed, InputRef(sha256_hex(changed), len(changed), "x"), [result], tool())[0]
        self.assertEqual(verdict.status, "unsupported")

    def test_reports_count_and_list_derived_findings_separately(self):
        finding = make_finding("code", "Functions.", "code.functions", ["entry", "helper"], [e.id for e in FUNCTIONS], "inferred")
        result = AnalysisResult(TASK, "code", "ok", tuple(FUNCTIONS), (finding,))
        analysis = report.Analysis(INPUT, (GHIDRA,), (result,), review(DATA, INPUT, [result], tool()))
        self.assertEqual(report.to_dict(analysis)["summary"]["derived"], 1)
        supported, derived = report.to_markdown(analysis).split("## Derived by analysis tools (not verified against the bytes)")
        self.assertIn("No finding was supported", supported)
        self.assertIn("Functions the analysis tool identified", derived.split("## Rejected")[0])

    def test_assembly_claims_cite_exactly_one_listing(self):
        rows = [[0, 1, "PUSH RBP"], [1, 3, "MOV RBP,RSP"]]
        listing = observed(0, kind="assembly", index=0, entry=0x1000, instructions=rows, truncated=False)
        twin = observed(64, kind="assembly", index=1, entry=0x1040, instructions=rows, truncated=False)
        value = {"entry": 0x1000, "instructions": rows, "truncated": False}
        good = make_finding("code", "Code.", "code.assembly", value, [listing.id], "inferred")
        two = make_finding("code", "Code.", "code.assembly", value, [listing.id, twin.id], "inferred")
        changed = make_finding("code", "Code.", "code.assembly", {**value, "truncated": True}, [listing.id], "inferred")
        mixed = make_finding("code", "Code.", "code.assembly", value, [listing.id, FUNCTIONS[0].id], "inferred")
        judged = verdicts([good, two, changed, mixed], [listing, twin, *FUNCTIONS])
        self.assertEqual(judged[good.id].status, "derived")
        self.assertEqual({judged[f.id].status for f in (two, changed, mixed)}, {"unsupported"})

    def test_reference_claims_are_the_sorted_unique_rows(self):
        refs = [observed(0, kind="ref", **{"from": 0x1000}, to=0x3000, type="read", to_name="counter"),
                observed(16, kind="ref", **{"from": 0x1000}, to=0x2000, type="data", to_name=""),
                observed(32, kind="ref", **{"from": 0x1000}, to=0x3000, type="read", to_name="counter")]
        rows = [[0x1000, "data", 0x2000, ""], [0x1000, "read", 0x3000, "counter"]]
        good = make_finding("code", "Refs.", "code.references", rows, [e.id for e in refs], "inferred")
        unsorted = make_finding("code", "Refs.", "code.references", rows[::-1], [e.id for e in refs], "inferred")
        odd = observed(48, kind="ref", **{"from": 0x1000}, to=0x2000, type="call", to_name="")
        typed = make_finding("code", "Refs.", "code.references", [[0x1000, "call", 0x2000, ""]], [odd.id], "inferred")
        judged = verdicts([good, unsorted, typed], [*refs, odd])
        self.assertEqual(judged[good.id].status, "derived")
        self.assertEqual({judged[f.id].status for f in (unsorted, typed)}, {"unsupported"})

    def test_string_claims_list_one_reading_per_address_in_address_order(self):
        def string(offset, address, text, sources=(0x1000,)):
            return observed(offset, kind="string", address=address, encoding="ascii", text=text, truncated=False,
                            **{"from": list(sources)})
        hello, world, again = string(0, 0x2010, "hello"), string(16, 0x2000, "world"), string(0, 0x2010, "hello")
        value = [{"address": 0x2000, "encoding": "ascii", "text": "world", "truncated": False, "from": [0x1000]},
                 {"address": 0x2010, "encoding": "ascii", "text": "hello", "truncated": False, "from": [0x1000]}]
        good = make_finding("code", "Strings.", "code.strings", value, [hello.id, world.id], "inferred")
        self.assertEqual(again.id, hello.id)  # equal content is one evidence record
        clash = string(32, 0x2010, "other")
        disagree = make_finding("code", "Strings.", "code.strings", value, [hello.id, world.id, clash.id], "inferred")
        reordered = make_finding("code", "Strings.", "code.strings", value[::-1], [hello.id, world.id], "inferred")
        judged = verdicts([good, disagree, reordered], [hello, world, clash])
        self.assertEqual(judged[good.id].status, "derived")
        self.assertEqual({judged[f.id].status for f in (disagree, reordered)}, {"unsupported"})

    def test_malformed_code_observations_yield_nothing_rather_than_fail(self):
        bad = [observed(0, kind="ref", **{"from": "x"}, to=1, type="read", to_name=""),
               observed(16, kind="ref", **{"from": 1}, to=None, type="read", to_name=""),
               observed(32, kind="string", address="0x10", text="hi"),
               observed(48, kind="assembly", index=0)]
        for item in bad:
            key = {"ref": "code.references", "string": "code.strings", "assembly": "code.assembly"}[item.observation["kind"]]
            finding = make_finding("code", "Code.", key, [], [item.id], "inferred")
            self.assertEqual(verdicts([finding], [item])[finding.id].status, "unsupported")

    def test_a_finding_that_repeats_a_malformed_reading_is_still_refused(self):
        # The rule checks each code shape itself; echoing a malformed projection is not enough.
        rows = [[0, 1, "PUSH RBP"]]
        good = {"assembly": dict(index=0, entry=0x1000, instructions=rows, truncated=False),
                "ref": {"from": 0x1000, "to": 0x2000, "type": "read", "to_name": "counter"},
                "string": dict(address=0x2000, encoding="ascii", text="hello", truncated=False, **{"from": [0x1000]})}
        changes = {
            "assembly": [{"entry": None}, {"instructions": []}, {"instructions": None}, {"truncated": None},
                         {"truncated": 0}, {"entry": True}, {"index": 128}, {"instructions": [[0, 17, "X"]]},
                         {"instructions": [[0, 2, "A"], [1, 1, "B"]]}, {"instructions": [[0, 1, ""]]},
                         {"instructions": [[0, 1, "A\nB"]]}, {"instructions": [[0, 1, "x" * 65]]},
                         {"instructions": [[0, 1, "A"]] * 65}, {"extra": 1}],
            "ref": [{"to_name": "x" * 129}, {"to_name": "a\nb"}, {"to": True}, {"from": False}, {"type": "call"},
                    {"to_name": None}],
            "string": [{"encoding": None}, {"encoding": "utf-8"}, {"text": "h"}, {"text": "x" * 129},
                       {"text": "café"}, {"truncated": None}, {"truncated": True}, {"from": []}, {"from": [2, 1]},
                       {"from": [1, 1]}, {"from": [True]}, {"from": list(range(9))}, {"address": True}],
        }
        for kind, variants in changes.items():
            key, fields = {"assembly": ("code.assembly", ("entry", "instructions", "truncated")),
                           "ref": ("code.references", ("from", "type", "to", "to_name")),
                           "string": ("code.strings", ("address", "encoding", "text", "truncated", "from"))}[kind]
            control = observed(0, kind=kind, **good[kind])
            projection = {name: control.observation[name] for name in fields}
            value = projection if kind == "assembly" else [list(projection.values()) if kind == "ref" else projection]
            finding = make_finding("code", "Code.", key, value, [control.id], "inferred")
            self.assertEqual(verdicts([finding], [control], tool(derived=False))[finding.id].status, "derived", kind)
            for change in variants:
                item = observed(0, kind=kind, **{**good[kind], **change})
                projection = {name: item.observation.get(name) for name in fields}
                value = projection if kind == "assembly" else [list(projection.values()) if kind == "ref" else projection]
                finding = make_finding("code", "Code.", key, value, [item.id], "inferred")
                self.assertEqual(verdicts([finding], [item])[finding.id].status, "unsupported", (kind, change))

    def test_single_listing_and_single_reading_guards_are_pinned(self):
        # Equal listings at two locations, and both orders of a conflicting string reading.
        rows = [[0, 1, "RET"]]
        one = observed(0, kind="assembly", index=0, entry=0x1000, instructions=rows, truncated=False)
        two = observed(64, kind="assembly", index=0, entry=0x1000, instructions=rows, truncated=False)
        value = {"entry": 0x1000, "instructions": rows, "truncated": False}
        both = make_finding("code", "Code.", "code.assembly", value, [one.id, two.id], "inferred")
        self.assertEqual(verdicts([both], [one, two])[both.id].status, "unsupported")

        def string(offset, text):
            return observed(offset, kind="string", address=0x2000, encoding="ascii", text=text, truncated=False,
                            **{"from": [0x1000]})
        first, second = string(0, "hello"), string(16, "world")
        for text in ("hello", "world"):
            claimed = [{"address": 0x2000, "encoding": "ascii", "text": text, "truncated": False, "from": [0x1000]}]
            for order in ([first, second], [second, first]):
                finding = make_finding("code", "Code.", "code.strings", claimed, [e.id for e in order], "inferred")
                self.assertEqual(verdicts([finding], order)[finding.id].status, "unsupported", (text, order[0].id))

    def test_derived_must_be_a_bool(self):
        with self.assertRaises(ContractError):
            OperationSpec("ghidra.analyze", {}, lambda data, args: [], derived="yes")


if __name__ == "__main__":
    unittest.main()
