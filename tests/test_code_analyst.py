"""Inert code observations and reviewer checks; no Ghidra, Docker or input execution."""

import copy
from dataclasses import replace
from types import SimpleNamespace
import unittest

from reverseai.analysts import code
from reverseai.contract import (
    MAX_EVIDENCE_PER_FINDING, AnalysisResult, ArgSpec, ContractError, Evidence, InputRef, Location, Observation,
    OperationRequest, OperationSpec, ToolRef, ToolSpec, content_id, evidence_id, make_evidence, sha256_hex,
)
from reverseai.review import review


DATA = bytes(range(256)) * 32
INPUT = InputRef(sha256_hex(DATA), len(DATA), "inline.bin")
REF = ToolRef("ghidra", "12.1.4-r7")


def tool(*, ref=REF, derived=True, operation="ghidra.analyze"):
    args = {"max_functions": ArgSpec("int", 1, 128, default=64),
            "decompile": ArgSpec("int", 0, 16, default=8),
            "max_chars": ArgSpec("int", 64, 2048, default=1024),
            "max_calls": ArgSpec("int", 0, 256, default=128),
            "assembly": ArgSpec("int", 0, 8, default=4),
            "max_instructions": ArgSpec("int", 1, 64, default=32),
            "max_refs": ArgSpec("int", 0, 128, default=64),
            "max_strings": ArgSpec("int", 0, 64, default=32)}
    spec = OperationSpec(operation, args, lambda data, args: (), max_observations=600, derived=derived)
    return ToolSpec(ref, {operation: spec})


def observed(offset=0, *, data=DATA, ref=REF, operation="ghidra.analyze", length=16, **value):
    return make_evidence(data, ref, operation, Observation(Location(offset, length), value))


def function(index=0, *, name="entry", **options):
    return observed(index * 32, kind="function", index=index, name=name, entry=0x1000 + index * 32, size=32, **options)


def pseudocode(index=0, *, text="void entry(void) {}", truncated=False):
    return observed(index * 32, kind="pseudocode", index=index, entry=0x1000 + index * 32,
                    text=text, truncated=truncated)


def call(offset=4, *, source=0x1000, target=0x1020, name="helper"):
    return observed(offset, length=5, **{"kind": "call", "from": source, "to": target, "to_name": name})


def assembly(index=0, *, instructions=None, truncated=False):
    return observed(index * 32, kind="assembly", index=index, entry=0x1000 + index * 32,
                    instructions=[[0, 5, "CALL helper"], [5, 1, "RET"]] if instructions is None else instructions,
                    truncated=truncated)


def reference(offset=4, *, source=0x1000, target=0x2000, type="read", name="message"):
    return observed(offset, length=5, **{"kind": "ref", "from": source, "to": target, "type": type, "to_name": name})


def string(address=0x2000, *, text="message", encoding="ascii", sources=None, truncated=False, offset=128):
    return observed(offset, length=len(text) * (2 if encoding == "utf-16le" else 1),
                    **{"kind": "string", "address": address, "encoding": encoding, "text": text,
                       "truncated": truncated, "from": [0x1000] if sources is None else sources})


class CodeAnalystTests(unittest.TestCase):
    def setUp(self):
        self.tool = tool()
        self.task = code.plan(INPUT, tools=(self.tool,))

    def verdicts(self, evidence, findings=None, *, data=DATA, input=INPUT):
        findings = code.conclude(self.task, evidence) if findings is None else findings
        result = AnalysisResult(self.task.id, "code", "ok", tuple(evidence), findings)
        return review(data, input, (result,), {"ghidra": self.tool})

    def test_plan_is_optional_and_requires_the_exact_derived_operation(self):
        self.assertIsNone(code.plan(INPUT))
        for other in (tool(ref=ToolRef("ghidra", "12.1.4-r1")), tool(ref=ToolRef("ghidra", "12.1.4-r2")),
                      tool(ref=ToolRef("ghidra", "12.1.4-r3")), tool(ref=ToolRef("ghidra", "12.1.4-r4")),
                      tool(derived=False), tool(operation="ghidra.other")):
            with self.subTest(tool=other.ref, operations=tuple(other.operations)):
                self.assertIsNone(code.plan(INPUT, tools=(other,)))
        self.assertIsNone(code.plan(INPUT, tools=(ToolSpec(REF, {}),)))

    def test_plan_is_content_bound_deterministic_and_uses_only_defaults(self):
        self.assertEqual(self.task.role, "code")
        self.assertEqual(self.task.id, content_id("tk", {"input": INPUT.sha256, "role": "code"}))
        self.assertEqual(self.task.operations, (OperationRequest("ghidra.analyze"),))
        self.assertEqual(self.tool.operations["ghidra.analyze"].validate_args(self.task.operations[0].args),
                         {"decompile": 8, "max_calls": 128, "max_chars": 1024, "max_functions": 64,
                          "assembly": 4, "max_instructions": 32, "max_refs": 64, "max_strings": 32})
        self.assertEqual(self.task, code.plan(INPUT, tools=(self.tool, self.tool)))
        self.assertEqual(self.task.id, code.plan(replace(INPUT, name="alias"), tools=(self.tool,)).id)
        self.assertNotEqual(self.task.id, code.plan(replace(INPUT, sha256="f" * 64), tools=(self.tool,)).id)
        self.assertEqual((self.task.budget.max_operations, self.task.budget.max_concurrency,
                          self.task.budget.max_wall_seconds), (1, 1, 300))

    def test_exact_values_and_citations_are_all_inferred_and_derived(self):
        evidence = (function(1, name="helper"), pseudocode(1, truncated=True), call(9), function(),
                    pseudocode(), call())
        findings = code.conclude(self.task, evidence)
        functions = next(f for f in findings if f.claim_key == "code.functions")
        calls = next(f for f in findings if f.claim_key == "code.calls")
        texts = [f for f in findings if f.claim_key == "code.pseudocode"]
        self.assertEqual(functions.value, ["entry", "helper"])
        self.assertEqual(set(functions.evidence_ids), {evidence[0].id, evidence[3].id})
        self.assertEqual(calls.value, [[0x1000, "helper"]])
        self.assertEqual(set(calls.evidence_ids), {evidence[2].id, evidence[5].id})
        self.assertEqual([f.value for f in texts], [
            {"entry": 0x1000, "text": "void entry(void) {}", "truncated": False},
            {"entry": 0x1020, "text": "void entry(void) {}", "truncated": True}])
        self.assertEqual([f.evidence_ids for f in texts], [(evidence[4].id,), (evidence[1].id,)])
        self.assertTrue(all(f.role == "code" and f.confidence == "inferred" for f in findings))
        self.assertEqual({v.status for v in self.verdicts(evidence, findings)}, {"derived"})
        self.assertEqual(findings, code.conclude(self.task, tuple(reversed(evidence))))
        self.assertEqual(findings, code.conclude(self.task, evidence + evidence))

    def test_empty_foreign_role_and_unplanned_operation_produce_no_findings(self):
        self.assertEqual(code.conclude(self.task, ()), ())
        self.assertEqual(code.conclude(replace(self.task, role="capability"), (function(),)), ())
        other = replace(self.task, operations=(OperationRequest("ghidra.other"),))
        self.assertEqual(code.conclude(other, (function(),)), ())

    def test_foreign_input_tool_version_and_operation_are_not_cited(self):
        value = dict(function().observation)
        foreign = (
            observed(data=DATA[:-1] + b"!", **value),
            observed(ref=ToolRef("ghidra", "12.1.4-r1"), **value),
            observed(ref=ToolRef("ghidra", "12.1.4-r2"), **value),
            observed(ref=ToolRef("ghidra", "12.1.4-r3"), **value),
            observed(ref=ToolRef("other", "12.1.4-r1"), operation="other.analyze", **value),
            observed(operation="ghidra.other", **value),
        )
        self.assertEqual(code.conclude(self.task, foreign), ())
        self.assertEqual(self.verdicts(foreign), ())
        honest = function()
        self.assertEqual(code.conclude(self.task, (*foreign, honest)), code.conclude(self.task, (honest,)))

    def test_an_out_of_range_anchor_cannot_be_cited_even_with_an_intact_forged_record(self):
        value = dict(function().observation)
        observation = Observation(Location(len(DATA), 16), value)
        outside = make_evidence(DATA + bytes(32), REF, "ghidra.analyze", observation, input_sha256=INPUT.sha256)
        self.assertEqual(code.conclude(self.task, (outside,)), ())

    def test_mutated_evidence_ids_or_observations_are_ignored(self):
        for field in ("id", "observation"):
            item = copy.deepcopy(function())
            if field == "id":
                object.__setattr__(item, "id", "ev-0000000000000000")
            else:
                item.observation["name"] = "invented"
            with self.subTest(field=field):
                self.assertEqual(code.conclude(self.task, (item,)), ())
        self.assertEqual(code.conclude(self.task, (None, {}, "evidence")), ())

    def test_a_rebound_false_excerpt_is_rejected_by_the_reviewer(self):
        item = function()
        fields = dict(input_sha256=item.input_sha256, tool=item.tool, operation=item.operation,
                      location=item.location, excerpt_sha256="f" * 64, observation=item.observation)
        forged = Evidence(id=evidence_id(**fields), **fields)
        verdicts = self.verdicts((forged,))
        self.assertTrue(verdicts)
        self.assertEqual({v.status for v in verdicts}, {"unsupported"})
        self.assertIn("excerpt hash mismatch", verdicts[0].reasons[0])

    def test_changed_input_bytes_cannot_get_a_derived_or_supported_verdict(self):
        evidence = (function(), pseudocode(), call())
        changed = b"!" + DATA[1:]
        verdicts = self.verdicts(evidence, data=changed, input=InputRef(sha256_hex(changed), len(changed), "changed"))
        self.assertEqual({v.status for v in verdicts}, {"unsupported"})

    def test_unknown_or_malformed_observations_do_not_create_claims(self):
        values = [dict(function().observation), dict(pseudocode().observation), dict(call().observation)]
        invalid = [{"kind": "unrecognized"}, {"kind": []}]
        for value in values:
            for field in value:
                changed = dict(value)
                del changed[field]
                invalid.append(changed)
            invalid.append(dict(value, extra="unexpected"))
        invalid.extend((dict(values[0], index=True), dict(values[0], index=-1), dict(values[0], index=128),
                        dict(values[0], entry=-1),
                        dict(values[0], size=0), dict(values[0], name="x" * 129),
                        dict(values[0], name="line\nname"), dict(values[1], text=[]),
                        dict(values[1], text="x" * 2049), dict(values[1], truncated=1),
                        dict(values[2], **{"from": True}), dict(values[2], to_name="bad\x00name")))
        for value in invalid:
            with self.subTest(value=value):
                self.assertEqual(code.conclude(self.task, (observed(length=5, **value),)), ())
        self.assertTrue(code.conclude(self.task, (observed(length=16, **values[2]),)))
        self.assertEqual(code.conclude(self.task, (observed(length=17, **values[2]),)), ())
        overflow = dict(values[0], entry=2**64)
        self.assertFalse(code._valid(SimpleNamespace(observation=overflow, location=Location(0, 5))))
        with self.assertRaises(ContractError):
            observed(length=5, **overflow)

    def test_sixty_five_reverse_named_functions_keep_index_order_across_chunks(self):
        self.task = replace(self.task, operations=(OperationRequest("ghidra.analyze", {"max_functions": 65}),))
        names = [f"function_{64 - index:03d}" for index in range(65)]
        evidence = tuple(function(index, name=name) for index, name in enumerate(names))
        findings = code.conclude(self.task, tuple(reversed(evidence)))
        self.assertEqual([f.claim_key for f in findings], ["code.functions", "code.functions"])
        self.assertEqual([f.value for f in findings], [names[:64], names[64:]])
        self.assertEqual([set(f.evidence_ids) for f in findings],
                         [{item.id for item in evidence[:64]}, {evidence[64].id}])
        self.assertEqual({v.status for v in self.verdicts(evidence, findings)}, {"derived"})

    def test_pseudocode_alone_keeps_exact_text_and_truncation(self):
        item = pseudocode(text="`<img src=x>\nreturn user_input;", truncated=True)
        finding, = code.conclude(self.task, (item,))
        self.assertEqual(finding.value, {"entry": 0x1000, "text": item.observation["text"], "truncated": True})
        self.assertEqual(self.verdicts((item,))[0].status, "derived")

    def test_all_four_hundred_observations_fit_deterministic_citation_chunks(self):
        self.task = replace(self.task, operations=(OperationRequest("ghidra.analyze", {
            "max_functions": 128, "decompile": 16, "max_chars": 2048, "max_calls": 256}),))
        functions = [function(i, name=f"f{i:03d}") for i in range(128)]
        texts = [pseudocode(i) for i in range(16)]
        calls = [call(4096 + 5 * i, source=0x1000 + (i // 2) * 32, name=f"f{i // 2:03d}") for i in range(256)]
        evidence = (*functions, *texts, *calls)
        findings = code.conclude(self.task, tuple(reversed(evidence)))
        self.assertEqual(findings, code.conclude(self.task, evidence))
        grouped = {key: [f for f in findings if f.claim_key == key] for key in
                   ("code.functions", "code.pseudocode", "code.calls")}
        self.assertEqual([len(grouped[key]) for key in grouped], [2, 16, 4])
        self.assertEqual([name for f in grouped["code.functions"] for name in f.value], [f"f{i:03d}" for i in range(128)])
        citations = [i for f in findings for i in f.evidence_ids]
        self.assertEqual(len(citations), 400)
        self.assertEqual(set(citations), {e.id for e in evidence})
        self.assertTrue(all(len(f.evidence_ids) <= MAX_EVIDENCE_PER_FINDING for f in findings))
        ordered_calls = sorted(calls, key=lambda e: (e.observation["from"], e.observation["to_name"], e.id))
        for index, finding in enumerate(grouped["code.calls"]):
            self.assertEqual(set(finding.evidence_ids), {e.id for e in ordered_calls[index * 64:(index + 1) * 64]})
        self.assertEqual({v.status for v in self.verdicts(evidence, findings)}, {"derived"})

    def test_m3c_exact_values_order_citations_and_real_derived_verdicts(self):
        evidence = (assembly(1, truncated=True), reference(target=0x3000, type="write"),
                    string(0x3000, text="later"), assembly(), reference(), string())
        findings = code.conclude(self.task, evidence)
        listings = [f for f in findings if f.claim_key == "code.assembly"]
        self.assertEqual([f.value for f in listings], [
            {"entry": 0x1000, "instructions": [[0, 5, "CALL helper"], [5, 1, "RET"]], "truncated": False},
            {"entry": 0x1020, "instructions": [[0, 5, "CALL helper"], [5, 1, "RET"]], "truncated": True}])
        self.assertEqual([f.evidence_ids for f in listings], [(evidence[3].id,), (evidence[0].id,)])
        refs = next(f for f in findings if f.claim_key == "code.references")
        self.assertEqual(refs.value, [[0x1000, "read", 0x2000, "message"], [0x1000, "write", 0x3000, "message"]])
        self.assertEqual(set(refs.evidence_ids), {evidence[1].id, evidence[4].id})
        strings = next(f for f in findings if f.claim_key == "code.strings")
        self.assertEqual(strings.value, [{k: e.observation[k] for k in ("address", "encoding", "text", "truncated", "from")}
                                         for e in (evidence[5], evidence[2])])
        self.assertEqual(set(strings.evidence_ids), {evidence[2].id, evidence[5].id})
        self.assertEqual({v.status for v in self.verdicts(evidence, findings)}, {"derived"})
        self.assertTrue(all(f.confidence == "inferred" for f in findings))
        self.assertEqual(findings, code.conclude(self.task, tuple(reversed(evidence)) + evidence))

    def test_m3c_shape_and_bounds_refuse_malformed_values(self):
        examples = [assembly(), reference(), string()]
        malformed = []
        for item in examples:
            value = item.observation
            for field in value:
                malformed.append({k: v for k, v in value.items() if k != field})
            malformed.append(dict(value, extra="unexpected"))
        listing, ref, text = [item.observation for item in examples]
        malformed += [dict(listing, **changes) for changes in (
            {"index": True}, {"index": 128}, {"entry": -1}, {"instructions": {}}, {"instructions": []},
            {"instructions": [[0, 0, "RET"]]}, {"instructions": [[True, 1, "RET"]]},
            {"instructions": [[0, True, "RET"]]}, {"instructions": [[0, 17, "RET"]]},
            {"instructions": [[15, 2, "RET"]]}, {"instructions": [[0, 2, "MOV"], [1, 1, "RET"]]},
            {"instructions": [[0, 1, ""]]}, {"instructions": [[0, 1, "x" * 65]]},
            {"instructions": [[0, 1, "line\nRET"]]}, {"instructions": [[0, 1, "é"]]},
            {"instructions": [[0, 1, "RET", "extra"]]}, {"instructions": [[0, 1, "RET"]] * 65},
            {"truncated": 1})]
        malformed += [dict(ref, **changes) for changes in (
            {"from": True}, {"to": -1}, {"type": "call"}, {"type": []},
            {"to_name": "x" * 129}, {"to_name": "bad\x00name"})]
        malformed += [dict(text, **changes) for changes in (
            {"address": True}, {"encoding": "utf-8"}, {"text": "x"}, {"text": "x" * 129},
            {"text": "a\nb"}, {"text": "éé"}, {"from": []}, {"from": [True]},
            {"from": [0x1000] * 2}, {"from": [0x1020, 0x1000]}, {"from": list(range(9))},
            {"truncated": 1}, {"truncated": True})]
        for value in malformed:
            with self.subTest(value=value):
                length = 16
                if value.get("kind") == "string" and isinstance(value.get("text"), str):
                    length = max(1, len(value["text"]) * (2 if value.get("encoding") == "utf-16le" else 1))
                self.assertEqual(code.conclude(self.task, (observed(length=length, **value),)), ())
        self.assertEqual(code.conclude(self.task, (observed(length=17, **ref),)), ())
        self.assertEqual(code.conclude(self.task, (observed(length=1, **text),)), ())

    def test_m3c_boundary_values_are_admitted(self):
        items = (assembly(instructions=[[0, 16, "x" * 64]]), reference(type="read_write", name=""), reference(type="data"),
                 reference(type="jump"), string(text="xy", encoding="utf-16le"),
                 string(0x3000, text="x" * 128, truncated=True, sources=list(range(8))))
        self.assertTrue(all(code._valid(item) for item in items))
        self.assertEqual({v.status for v in self.verdicts(items)}, {"derived"})

    def test_m3c_all_six_hundred_observations_have_bounded_citations(self):
        evidence = (*[function(i) for i in range(128)], *[pseudocode(i) for i in range(16)],
                    *[call(4096 + 5 * i, name=f"target{i}") for i in range(256)],
                    *[assembly(i) for i in range(8)],
                    *[reference(4096 + 5 * i, target=0x2000 + i) for i in range(128)],
                    *[string(0x2000 + i, text=f"string{i}") for i in range(64)])
        findings = code.conclude(self.task, tuple(reversed(evidence)))
        self.assertEqual(findings, code.conclude(self.task, evidence))
        ids = [identifier for finding in findings for identifier in finding.evidence_ids]
        self.assertEqual(len(ids), 600)
        self.assertEqual(set(ids), {item.id for item in evidence})
        self.assertTrue(all(len(f.evidence_ids) <= 64 for f in findings))
        refs = [f for f in findings if f.claim_key == "code.references"]
        self.assertEqual([len(f.evidence_ids) for f in refs], [64, 64])
        strings = [f for f in findings if f.claim_key == "code.strings"]
        self.assertEqual([entry["address"] for f in strings for entry in f.value], list(range(0x2000, 0x2040)))
        self.assertEqual({v.status for v in self.verdicts(evidence, findings)}, {"derived"})

    def test_m3c_never_cites_foreign_or_mutated_records(self):
        for original in (assembly(), reference(), string()):
            for changes in ({"data": DATA + b"!"}, {"ref": ToolRef("ghidra", "12.1.4-r4")},
                            {"operation": "ghidra.other"}):
                foreign = observed(length=original.location.length, **changes, **original.observation)
                self.assertEqual(code.conclude(self.task, (foreign,)), ())
            mutated = copy.deepcopy(original)
            mutated.observation["truncated" if original.observation["kind"] != "ref" else "to_name"] = "changed"
            self.assertEqual(code.conclude(self.task, (mutated,)), ())

    def test_conflicting_strings_at_one_address_do_not_create_a_claim(self):
        items = (string(), string(text="different"))
        self.assertEqual(code.conclude(self.task, items), ())
        self.assertEqual(code.conclude(self.task, tuple(reversed(items))), ())


if __name__ == "__main__":
    unittest.main()
