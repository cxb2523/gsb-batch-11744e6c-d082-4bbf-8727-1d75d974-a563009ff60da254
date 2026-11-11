"""Closed query routing, independent conclusions, paging and real reviewer wiring."""
import copy
from dataclasses import replace
import re
import unittest
from unittest.mock import patch

from reverseai import pipeline, queries, report
from reverseai.analysts import query
from reverseai.contract import (
    AnalysisTask, ArgSpec, Budget, ContractError, Evidence, InputRef, Location, Observation, OperationRequest,
    OperationSpec, ToolRef, ToolSpec, content_id, evidence_id, make_evidence, sha256_hex,
)
from reverseai.gateway import Gateway
from tests import fixtures_apk
from tests.test_cli_query import byte_tool

DATA = bytes(range(256)) * 8
REF = InputRef(sha256_hex(DATA), len(DATA), "inline")


def standin(operation, rows, schema):
    ref = query.REFS[operation.split(".")[0]]
    spec = OperationSpec(operation, schema, lambda data, args: rows, max_observations=643,
                         derived=operation.startswith("ghidra."))
    return ToolSpec(ref, {operation: spec})


def _int(low, high, default=None):
    return ArgSpec("int", low, high, default=default)


# Argument schemas for apk and dex operations (docs/contract.md).
ANDROID_SCHEMAS = {
    "apk.inventory": {"start": _int(0, 65535, 0), "limit": _int(1, 256, 128)},
    "apk.manifest": {"start": _int(0, 65535, 0), "limit": _int(1, 256, 256)},
    "dex.classes": {"member": ArgSpec("literal", 0, 255, default=""), "query": ArgSpec("literal", 0, 128, default=""),
                    "class": ArgSpec("literal", 0, 255, default=""),
                    "start": _int(0, 1048575, 0), "limit": _int(1, 256, 128)},
    "dex.methods": {"member": ArgSpec("literal", 0, 255, default=""), "class": ArgSpec("literal", 1, 255),
                    "start": _int(0, 65535, 0), "limit": _int(1, 256, 128)},
    "dex.references": {"member": ArgSpec("literal", 0, 255, default=""), "class": ArgSpec("literal", 1, 255),
                       "method": ArgSpec("literal", 1, 255), "prototype": ArgSpec("literal", 0, 255, default=""),
                       "direction": ArgSpec("enum", choices=("from", "to"), default="from"),
                       "start": _int(0, 65535, 0), "limit": _int(1, 256, 128)},
}


def android_standins(layout):
    """In-process apk and dex tools answering from a fixture layout with member provenance;
    the real gateway materializes every child and the real reviewer checks every row."""
    members = {row["name"]: row for row in layout["members"]}
    dex_names = [row["name"] for row in layout["members"] if re.fullmatch(r"classes[0-9]*\.dex", row["name"])]

    def page(rows, args):
        chosen = rows[args["start"]:args["start"] + args["limit"]]
        return [Observation(location, {**value, "index": args["start"] + i, "total": len(rows)}, artifact)
                for i, (location, value, artifact) in enumerate(chosen)]

    def selected(args):
        return [args["member"]] if args["member"] else dex_names

    def inventory(data, args):
        return page([(Location(m["central_offset"], m["central_length"]), {
            "kind": "member", "name": m["name"], "method": m["method"], "compressed_size": m["compressed_size"],
            "size": m["size"], "crc32": m["crc32"], "sha256": m["sha256"], "flags": []}, None)
            for m in layout["members"]], args)

    def manifest(data, args):
        return page([(Location(a["offset"], a["length"]), {
            "kind": "manifest_attribute", **{key: a[key] for key in ("element_index", "element", "attribute", "type",
                                                                     "value")}},
            members["AndroidManifest.xml"]["artifact"]) for a in layout["manifest"]["attributes"]], args)

    def classes(data, args):
        return page([(Location(c["offset"], 32), {
            "kind": "class", "dex": name, "name": c["name"], "access": c["access"], "superclass": c["superclass"],
            "interfaces": c["interfaces"], "interfaces_total": len(c["interfaces"]),
            "source_file": c["source_file"]}, members[name]["artifact"])
            for name in selected(args) for c in layout["dex"][name]["classes"]
            if (not args["class"] or args["class"] == c["name"]) and args["query"] in c["name"]], args)

    def methods(data, args):
        return page([(Location(m["offset"], 8), {
            "kind": "method", "dex": name, "class": c["name"], "name": m["name"], "prototype": m["prototype"],
            "access": m["access"], "code_offset": m["code_offset"], "code_units": m["code_units"]},
            members[name]["artifact"]) for name in selected(args) for c in layout["dex"][name]["classes"]
            if c["name"] == args["class"] for m in c["methods"]], args)

    def references(data, args):
        target = f"{args['class']}->{args['method']}" + (args["prototype"] or "(")

        def wanted(r):
            if args["direction"] == "to":
                return r["ref_kind"] == "method" and (r["target"] == target or not args["prototype"]
                                                      and r["target"].startswith(target))
            return (r["class"], r["method"]) == (args["class"], args["method"]) and args["prototype"] in ("", r["prototype"])

        return page([(Location(r["at"], r["length"]), {
            "kind": "dex_ref", "dex": name, "from_class": r["class"], "from_method": r["method"],
            "from_prototype": r["prototype"], "at": r["at"], "ref_kind": r["ref_kind"], "target": r["target"],
            "target_truncated": r["target_truncated"]}, members[name]["artifact"])
            for name in selected(args) for r in layout["dex"][name]["references"] if wanted(r)], args)

    handlers = {"apk.inventory": inventory, "apk.manifest": manifest, "dex.classes": classes, "dex.methods": methods,
                "dex.references": references}
    return tuple(ToolSpec(query.REFS[tool], {name: OperationSpec(name, ANDROID_SCHEMAS[name], handlers[name],
                                                                   max_observations=256)
                                              for name in handlers if name.startswith(tool + ".")})
                 for tool in ("apk", "dex"))


class QueryTests(unittest.TestCase):
    def test_real_host_queries_flow_through_the_gateway_analyst_and_reviewer_on_three_formats(self):
        from tests.fixtures_code import elf_refs, pe_refs, macho_refs
        for builder in (elf_refs, pe_refs, macho_refs):
            data, _ = builder()
            ref = InputRef(sha256_hex(data), len(data), "inline")
            for name, args in (("binary_overview", {}), ("list_segments", {}), ("inspect_native_load_image", {}),
                               ("list_names", {}), ("read_bytes", {"length": 2000}), ("list_strings", {"min_length": 4}),
                               ("search_strings", {"query": "ReverseAI"})):
                with self.subTest(format=builder.__name__, query=name):
                    analysis = pipeline.query_bytes(data, ref, name, args)
                    self.assertEqual({result.status for result in analysis.results}, {"ok"})
                    self.assertLessEqual({verdict.status for verdict in analysis.verdicts}, {"supported"})
                    if not analysis.results[0].evidence:
                        self.assertEqual(analysis.results[0].findings, ())
                    self.assertEqual(report.to_json(analysis), report.to_json(pipeline.query_bytes(data, ref, name, args)))

    def test_the_closed_table_names_and_operations_include_paged_exports(self):
        expected = {
            "binary_overview": ("structure.identify", "structure.headers", "structure.sections", "structure.imports", "structure.entry"),
            "list_segments": ("structure.segments",), "inspect_native_load_image": ("structure.segments", "structure.entry"),
            "list_names": ("structure.symbols",), "read_bytes": ("structure.read_bytes",),
            "list_strings": ("strings.list",), "search_strings": ("strings.search",),
            "list_procedures": ("ghidra.functions",), "search_procedures": ("ghidra.functions",),
            **{name: ("ghidra.function",) for name in ("procedure_info", "procedure_pseudo_code", "procedure_assembly",
                                                     "procedure_callees", "procedure_callers", "analyze_function")},
            "xrefs": ("ghidra.xrefs",),
        }
        expected.update({"procedure_pseudo_code": ("ghidra.function",),
                         "export_function": ("ghidra.export_function",), "export_program": ("ghidra.export_program",)})
        expected.update({  # The five Android names
            "inspect_android_package": ("apk.inventory", "apk.manifest"), "search_android_classes": ("dex.classes",),
            "inspect_android_class": ("dex.classes", "dex.methods"),
            "inspect_android_method": ("dex.methods", "dex.references"), "trace_android_references": ("dex.references",),
        })
        # The JavaScript name; its default summary detail reads all three js operations
        expected["analyze_javascript_application"] = ("js.files", "js.package", "js.hints")
        self.assertEqual(set(queries.TABLE), set(expected))
        for name, operations in expected.items():
            args = {"query": "hi"} if name == "search_strings" else {"address": 16} if name == "xrefs" else {}
            if name in ("inspect_android_class", "inspect_android_method", "trace_android_references"):
                args = {"member": "classes.dex", "class": "La;", **({"method": "m"} if "class" not in name else {})}
            spec, checked = queries.resolve(name, args)
            self.assertEqual(tuple(request.operation for request in spec.requests(checked)), operations)
            self.assertEqual(spec.role, "code" if operations[0].startswith("ghidra.") else "structural")
        spec, checked = queries.resolve("procedure_pseudo_code", {"mode": "paged", "text_start": 100})
        self.assertEqual([(r.operation, r.args["text_start"]) for r in spec.requests(checked)], [("ghidra.pseudocode", 100)])
        for name, part in (("procedure_info", "info"), ("procedure_assembly", "assembly"), ("analyze_function", "all")):
            spec, checked = queries.resolve(name, {})
            self.assertEqual(spec.requests(checked)[0].args["parts"], part)
        spec, args = queries.resolve("inspect_native_load_image", {"start": 3})
        self.assertEqual(spec.requests(args)[1].args, {})

    def test_argument_validation_separates_host_literal_text_from_contained_strings(self):
        self.assertEqual(queries.parse_args("list_names", ["query=-../a\\b"])["query"], "-../a\\b")
        self.assertEqual(queries.parse_args("search_strings", ["query=a=b"])["query"], "a=b")
        self.assertEqual(queries.parse_args("read_bytes", ["at=0XFF", "length=0004"])["at"], 255)
        for name, raw in (("procedure_info", {"name": "../x"}), ("list_procedures", {"query": "x"}),
                          ("procedure_info", {"parts": "all"}), ("read_bytes", {"at": True}),
                          ("xrefs", {"address": 2**64}), ("search_strings", {"query": "x\ny"}),
                          ("not_a_query", {})):
            with self.subTest(name=name, raw=raw), self.assertRaises(ContractError):
                queries.resolve(name, raw)

    def test_a_host_page_is_chunked_contiguously_with_all_citations_and_supported_values(self):
        rows = [Observation(Location(i, 1), {"kind": "segment", "index": 7+i, "total": 300, "name": "LOAD",
                                            "offset": i, "filesz": 1, "address": 0x1000+i, "memsz": 1,
                                            "readable": True, "writable": False, "executable": True}) for i in range(129)]
        tool = standin("structure.segments", rows, {"start": ArgSpec("int", 0, 65535, default=0),
                                                    "limit": ArgSpec("int", 1, 256, default=64)})
        result = pipeline.query_bytes(DATA, REF, "list_segments", {"start": 7, "limit": 129}, tools=(tool,))
        findings = result.results[0].findings
        self.assertEqual([(f.value["start"], len(f.value["rows"]), f.value["total"]) for f in findings],
                         [(7, 64, 300), (71, 64, 300), (135, 1, 300)])
        cited = [identifier for f in findings for identifier in f.evidence_ids]
        self.assertEqual(len(cited), len(set(cited)))
        self.assertEqual(set(cited), {e.id for e in result.results[0].evidence})
        self.assertEqual({v.status for v in result.verdicts}, {"supported"})
        text = report.to_markdown(result)
        self.assertIn("rows 7..70 of 300", text)
        self.assertIn("Next start: 71", text)
        self.assertIn("rows 135..135 of 300", text)
        self.assertIn("`0x1000`", text)
        self.assertIn('"query"', report.to_json(result))
        self.assertEqual(report.to_dict(result)["query"]["name"], "list_segments")

    def test_ghidra_query_uses_fixed_budget_and_stays_derived_even_if_spec_is_misregistered(self):
        row = Observation(Location(0, 16), {"kind": "function_row", "index": 0, "total": 1,
                                           "name": "entry", "entry": 0x1000, "size": 16})
        schema = {"query": ArgSpec("str", default=""), "start": ArgSpec("int", 0, 65535, default=0),
                  "limit": ArgSpec("int", 1, 128, default=64)}
        tool = standin("ghidra.functions", [row], schema)
        tool = replace(tool, operations={"ghidra.functions": replace(tool.operations["ghidra.functions"], derived=False)})
        with patch.object(pipeline, "Gateway", wraps=Gateway) as factory:
            result = pipeline.query_bytes(DATA, REF, "list_procedures", {}, tools=(tool,))
        self.assertEqual(factory.call_args.args[1], pipeline.GHIDRA_BUDGET)
        self.assertEqual({v.status for v in result.verdicts}, {"derived"})
        self.assertEqual(result.results[0].findings[0].value, {"start": 0, "total": 1, "rows": [["entry", 0x1000, 16]]})
        self.assertIn("0x1000", report.to_markdown(result))
        for tools in ((), (replace(tool, ref=ToolRef("ghidra", "12.1.4-r5")),)):
            with self.assertRaises(ContractError):
                pipeline.query_bytes(DATA, REF, "list_procedures", {}, tools=tools)

    def test_empty_page_makes_no_absence_claim_and_analyze_metadata_is_unchanged(self):
        tool = byte_tool()
        empty = replace(tool, operations={name: replace(spec, handler=lambda data, args: [])
                                          for name, spec in tool.operations.items()})
        analysis = pipeline.query_bytes(DATA, REF, "read_bytes", {}, tools=(empty,))
        self.assertEqual(analysis.results[0].findings, ())
        self.assertNotIn("query", report.to_dict(pipeline.analyze_bytes(DATA, REF)))
        self.assertNotIn("- Query:", report.to_markdown(pipeline.analyze_bytes(DATA, REF)))

    def test_query_analyst_refuses_foreign_input_undeclared_operation_and_mutated_evidence(self):
        obs = Observation(Location(0, 1), {"kind": "entry", "address": 0x1000, "offset": 0})
        item = make_evidence(DATA, query.REFS["structure"], "structure.entry", obs)
        task = AnalysisTask(content_id("tk", {"q": "test"}), "structural", REF, (OperationRequest("structure.entry"),))
        self.assertEqual(len(query.conclude(task, [item])), 1)
        altered = copy.deepcopy(item)
        altered.observation["address"] = 0
        foreign = replace(task, input=InputRef("0"*64, len(DATA), "other"))
        undeclared = replace(task, operations=(OperationRequest("structure.headers"),))
        for current, evidence in ((task, [altered]), (foreign, [item]), (undeclared, [item])):
            self.assertEqual(query.conclude(current, evidence), ())

    def test_query_analyst_refuses_a_gapped_page_of_intact_evidence(self):
        task = AnalysisTask(content_id("tk", {"q": "page-gap"}), "code", REF,
                            (OperationRequest("ghidra.functions", {"start": 7, "limit": 2}),))

        def evidence(indexes):
            return [make_evidence(DATA, query.REFS["ghidra"], "ghidra.functions", Observation(Location(i, 1), {
                "kind": "function_row", "index": index, "total": 20, "name": f"f{i}",
                "entry": 0x1000 + i, "size": 1})) for i, index in enumerate(indexes)]

        valid = query.conclude(task, evidence((7, 8)))
        self.assertEqual(len(valid), 1)
        self.assertEqual((valid[0].claim_key, valid[0].value["start"], len(valid[0].value["rows"])),
                         ("code.function_list", 7, 2))
        self.assertEqual(query.conclude(task, evidence((7, 9))), ())

    def test_query_analyst_refuses_xrefs_with_mixed_targets(self):
        task = AnalysisTask(content_id("tk", {"q": "xref-target"}), "code", REF,
                            (OperationRequest("ghidra.xrefs", {"address": 0x2000}),))

        def evidence(targets):
            return [make_evidence(DATA, query.REFS["ghidra"], "ghidra.xrefs", Observation(Location(i * 5, 5), {
                "kind": "xref", "index": i, "total": 2, "at": 0x1000 + i * 5,
                "from": None, "to": target, "type": "read"})) for i, target in enumerate(targets)]

        valid = query.conclude(task, evidence((0x2000, 0x2000)))
        self.assertEqual(len(valid), 1)
        self.assertEqual((valid[0].claim_key, valid[0].value["to"], len(valid[0].value["rows"])),
                         ("code.xrefs", 0x2000, 2))
        self.assertEqual(query.conclude(task, evidence((0x2000, 0x3000))), ())

    def test_query_analyst_refuses_callers_with_mixed_targets(self):
        task = AnalysisTask(content_id("tk", {"q": "caller-target"}), "code", REF,
                            (OperationRequest("ghidra.function", {"entry": 0x2000, "parts": "callers"}),))

        def evidence(targets):
            return [make_evidence(DATA, query.REFS["ghidra"], "ghidra.function", Observation(Location(i * 5, 5), {
                "kind": "caller", "at": 0x1000 + i * 5, "from": None, "to": target}))
                for i, target in enumerate(targets)]

        valid = query.conclude(task, evidence((0x2000, 0x2000)))
        self.assertEqual(len(valid), 1)
        self.assertEqual((valid[0].claim_key, valid[0].value),
                         ("code.callers", {"to": 0x2000, "rows": [[0x1000, None], [0x1005, None]]}))
        self.assertEqual(query.conclude(task, evidence((0x2000, 0x3000))), ())

    def test_xref_pages_preserve_target_and_nullable_sources(self):
        rows = [Observation(Location(i*5, 5), {"kind": "xref", "index": i, "total": 2, "at": 0x1000+i*5,
                                              "from": None if i == 0 else 0x1000, "to": 0x2000, "type": "read"}) for i in range(2)]
        schema = {"address": ArgSpec("int", 0, 2**64-1), "start": ArgSpec("int", 0, 65535, default=0),
                  "limit": ArgSpec("int", 1, 256, default=64)}
        result = pipeline.query_bytes(DATA, REF, "xrefs", {"address": 0x2000}, tools=(standin("ghidra.xrefs", rows, schema),))
        self.assertEqual(result.results[0].findings[0].value,
                         {"to": 0x2000, "start": 0, "total": 2, "rows": [[0x1000, None, "read"], [0x1005, 0x1000, "read"]]})
        self.assertEqual({v.status for v in result.verdicts}, {"derived"})
        self.assertNotIn("Next start:", report.to_markdown(result))

    def test_all_function_parts_are_cited_and_reviewed_as_derived(self):
        from reverseai.tools import ghidra_tool
        from tests.test_ghidra_tool import FakeExecutor, reply
        values = [
            (0, 32, {"kind": "target", "name": "entry", "entry": 0x1000, "size": 32, "matches": 1,
                     "callers_total": 1, "callees_total": 1}),
            (0, 32, {"kind": "pseudocode", "index": 0, "entry": 0x1000, "text": "return 1;", "truncated": False}),
            (16, 1, {"kind": "instructions", "entry": 0x1000, "start": 1, "total": 3,
                     "rows": [[16, 1, "RET"]], "truncated": True}),
            (1, 5, {"kind": "call", "from": 0x1000, "to": 0x2000, "to_name": "callee"}),
            (40, 5, {"kind": "caller", "at": 0x1028, "from": None, "to": 0x1000}),
            (8, 3, {"kind": "ref", "from": 0x1000, "to": 0x3000, "type": "read", "to_name": "counter"}),
        ]
        observations = [Observation(Location(at, size), value) for at, size, value in values]
        base = ghidra_tool.make_tool(FakeExecutor(reply(DATA, [])))
        spec = replace(base.operations["ghidra.function"], handler=lambda data, args: observations)
        tool = replace(base, operations={"ghidra.function": spec})
        result = pipeline.query_bytes(DATA, REF, "analyze_function", {"entry": 0x1000, "start": 1}, tools=(tool,))
        self.assertEqual({finding.claim_key for finding in result.results[0].findings},
                         {"code.function_info", "code.pseudocode", "code.instructions", "code.calls", "code.callers", "code.references"})
        self.assertEqual({verdict.status for verdict in result.verdicts}, {"derived"})
        all_ids = [identifier for finding in result.results[0].findings for identifier in finding.evidence_ids]
        self.assertEqual(set(all_ids), {e.id for e in result.results[0].evidence})
        self.assertEqual(len(all_ids), len(set(all_ids)))
        text = report.to_markdown(result)
        self.assertIn("rows 1..1 of 3", text)
        self.assertIn("| `0x1028` | `null` |", text)

    def test_overview_imports_use_one_bounded_supported_finding_per_claim(self):
        rows = [Observation(Location(i, 1), {"kind": "library", "name": f"lib{i:03}"}) for i in range(129)]
        operations = {name: OperationSpec(name, {}, lambda data, args: [], max_observations=256)
                      for name in ("structure.identify", "structure.headers", "structure.sections", "structure.entry")}
        operations["structure.imports"] = OperationSpec("structure.imports", {}, lambda data, args: rows, max_observations=256)
        tool = ToolSpec(query.REFS["structure"], operations)
        result = pipeline.query_bytes(DATA, REF, "binary_overview", {}, tools=(tool,))
        finding, = result.results[0].findings
        self.assertEqual(finding.claim_key, "imports.libraries")
        self.assertEqual(len(finding.evidence_ids), 64)
        self.assertEqual(finding.value, [f"lib{i:03}" for i in range(64)])
        self.assertEqual({v.status for v in result.verdicts}, {"supported"})


class AndroidQueryTests(unittest.TestCase):
    def setUp(self):
        self.data, self.layout = fixtures_apk.apk_basic()
        self.ref = InputRef(sha256_hex(self.data), len(self.data), "fixture.apk")
        self.tools = android_standins(self.layout)

    def run_query(self, name, args):
        analysis = pipeline.query_bytes(self.data, self.ref, name, args, tools=self.tools)
        self.assertEqual([result.status for result in analysis.results], ["ok"])
        self.assertEqual({verdict.status for verdict in analysis.verdicts}, {"supported"})
        return {finding.claim_key: [f.value for f in analysis.results[0].findings if f.claim_key == finding.claim_key]
                for finding in analysis.results[0].findings}, analysis

    def test_host_android_budgets_are_120_seconds_and_native_stays_30(self):
        cases = (
            ('inspect_android_package', {}),
            ('search_android_classes', {}),
            ('inspect_android_class', {'class': fixtures_apk.MAIN}),
            ('inspect_android_method', {'class': fixtures_apk.MAIN, 'method': 'helper'}),
            ('trace_android_references', {'class': fixtures_apk.HELPER, 'method': 'compute', 'direction': 'to'}),
            ('read_bytes', {'length': 16}),
        )
        real_run = Gateway.run
        for name, args in cases:
            tasks = []

            def capture(gateway, task, data):
                tasks.append(task)
                return real_run(gateway, task, data)

            with self.subTest(query=name), patch.object(pipeline, 'Gateway', wraps=Gateway) as factory, \
                    patch.object(Gateway, 'run', capture):
                analysis = pipeline.query_bytes(self.data, self.ref, name, args)
                self.assertEqual([result.status for result in analysis.results], ['ok'])
                self.assertEqual(len(tasks), 1)
                expected = 30 if name == 'read_bytes' else 120
                self.assertEqual((factory.call_args.args[1].max_wall_seconds, tasks[0].budget.max_wall_seconds),
                                 (expected, expected))
                self.assertNotIn('jadx.method', [request.operation for request in tasks[0].operations])

    def test_routed_arguments_reach_each_operation(self):
        spec, args = queries.resolve("inspect_android_package", {"member_limit": 2, "attribute_start": 3})
        self.assertEqual([(r.operation, dict(r.args)) for r in spec.requests(args)],
                         [("apk.inventory", {"start": 0, "limit": 2}), ("apk.manifest", {"start": 3, "limit": 256})])
        spec, args = queries.resolve("inspect_android_class", {"member": "classes.dex", "class": fixtures_apk.MAIN})
        self.assertEqual([(r.operation, dict(r.args)) for r in spec.requests(args)],
                         [("dex.classes", {"member": "classes.dex", "class": fixtures_apk.MAIN}),
                          ("dex.methods", {"member": "classes.dex", "class": fixtures_apk.MAIN, "start": 0, "limit": 128})])
        spec, args = queries.resolve("inspect_android_method", {"member": "classes.dex", "class": "La;", "method": "m",
                                                                "prototype": "(I)I", "limit": 5})
        self.assertEqual([(r.operation, dict(r.args)) for r in spec.requests(args)],
                         [("dex.methods", {"member": "classes.dex", "class": "La;"}),
                          ("dex.references", {"member": "classes.dex", "class": "La;", "method": "m",
                                              "prototype": "(I)I", "start": 0, "limit": 5, "direction": "from"})])
        self.assertEqual(queries.parse_args("trace_android_references", ["class=La;", "method=<init>", "direction=to"]),
                         {"member": "", "class": "La;", "method": "<init>", "prototype": "", "direction": "to",
                          "start": 0, "limit": 128})
        self.assertEqual({name: sorted(queries.TABLE[name].args) for name in queries.TABLE if "android" in name}, {
            "inspect_android_package": ["attribute_limit", "attribute_start", "member_limit", "member_start"],
            "search_android_classes": ["limit", "member", "query", "start"],
            "inspect_android_class": ["class", "limit", "member", "start"],
            "inspect_android_method": ["class", "java_start", "limit", "max_chars", "member", "method", "prototype", "start"],
            "trace_android_references": ["class", "direction", "limit", "member", "method", "prototype", "start"]})
        for spec in queries.TABLE.values():  # a routed query uses every argument it accepts
            if spec.routes:
                self.assertEqual({source for taken, _ in spec.routes.values() for source in taken.values()}, set(spec.args))
        self.assertEqual(queries.resolve("inspect_android_class", {"class": "La;"})[1]["member"], "")
        for name, raw in (("inspect_android_class", {}), ("inspect_android_class", {"member": "x" * 256, "class": "La;"}),
                          ("inspect_android_class", {"member": "classes.dex", "class": "L" + "a" * 254 + ";"}),
                          ("inspect_android_method", {"member": "classes.dex", "class": "La;", "method": "m",
                                                      "direction": "to"}),
                          ("trace_android_references", {"class": "La;", "method": "m", "direction": "both"}),
                          ("search_android_classes", {"query": "x" * 129}), ("inspect_android_package", {"start": 0}),
                          ("trace_android_references", {"class": "La;", "method": "m\n"})):
            with self.subTest(name=name, raw=raw), self.assertRaises(ContractError):
                queries.resolve(name, raw)

    def test_package_inventory_manifest_and_one_permissions_finding(self):
        values, analysis = self.run_query("inspect_android_package", {})
        members = values["android.members"]
        self.assertEqual([(page["start"], page["total"], [row[0] for row in page["rows"]]) for page in members],
                         [(0, 5, ["AndroidManifest.xml", "classes.dex", "classes2.dex", "resources.arsc",
                                  "META-INF/MANIFEST.MF"])])
        attributes = self.layout["manifest"]["attributes"]
        self.assertEqual(values["android.manifest"], [{"start": 0, "total": len(attributes), "rows": [
            [a["element_index"], a["element"], a["attribute"], a["type"], a["value"]] for a in attributes]}])
        self.assertEqual(values["android.permissions"], [["android.permission.INTERNET",
                                                          "android.permission.READ_CONTACTS"]])
        permissions, = [f for f in analysis.results[0].findings if f.claim_key == "android.permissions"]
        cited = {e.id: e for e in analysis.results[0].evidence}
        self.assertEqual([cited[i].location.offset for i in permissions.evidence_ids],
                         [a["offset"] for a in attributes if a["element"] == "uses-permission"])
        self.assertEqual({cited[i].artifact["member"] for i in permissions.evidence_ids}, {"AndroidManifest.xml"})
        values, _ = self.run_query("inspect_android_package", {"member_start": 4, "attribute_limit": 3})
        self.assertEqual(values["android.members"][0]["rows"][0][0], "META-INF/MANIFEST.MF")
        self.assertNotIn("android.permissions", values)  # the first three attributes declare none

    def test_class_search_and_inspection(self):
        values, _ = self.run_query("search_android_classes", {})
        self.assertEqual(values["android.classes"], [{"start": 0, "total": 4, "rows": [
            ["classes.dex", fixtures_apk.MAIN, 1, "Landroid/app/Activity;"],
            ["classes.dex", fixtures_apk.MARKER, 1, "Ljava/lang/Object;"],
            ["classes.dex", fixtures_apk.HELPER, 1, "Ljava/lang/Object;"],
            ["classes2.dex", fixtures_apk.WORKER, 1, "Ljava/lang/Object;"]]}])
        values, _ = self.run_query("search_android_classes", {"member": "classes2.dex", "query": "Worker"})
        self.assertEqual(values["android.classes"][0]["rows"], [["classes2.dex", fixtures_apk.WORKER, 1,
                                                                 "Ljava/lang/Object;"]])
        values, _ = self.run_query("inspect_android_class", {"member": "classes.dex", "class": fixtures_apk.MAIN})
        self.assertEqual(len(values["android.classes"][0]["rows"]), 1)
        main = self.layout["dex"]["classes.dex"]["classes"][0]
        self.assertEqual(values["android.methods"], [{"start": 0, "total": 4, "rows": [
            ["classes.dex", fixtures_apk.MAIN, m["name"], m["prototype"], m["access"], m["code_offset"], m["code_units"]]
            for m in main["methods"]]}])

    def test_method_inspection_and_traces_in_both_directions(self):
        values, _ = self.run_query("inspect_android_method", {"member": "classes.dex", "class": fixtures_apk.MAIN,
                                                              "method": "helper", "prototype": "(I)I"})
        self.assertEqual([row[4:] for row in values["android.references"][0]["rows"]], [
            [r["at"], r["ref_kind"], r["target"], False] for r in self.layout["dex"]["classes.dex"]["references"]
            if (r["method"], r["prototype"]) == ("helper", "(I)I")])
        self.assertEqual([row[6] for row in values["android.references"][0]["rows"]], [
            "Lorg/reverseai/fixture/Helper;->compute(II)I", "Lorg/reverseai/fixture/Marker;->count:I",
            "Lorg/reverseai/fixture/Marker;->count:I"])
        values, _ = self.run_query("trace_android_references", {"class": fixtures_apk.HELPER, "method": "compute",
                                                                "direction": "to"})
        self.assertEqual([(row[0], row[1], row[2]) for row in values["android.references"][0]["rows"]],
                         [("classes.dex", fixtures_apk.MAIN, "helper"), ("classes2.dex", fixtures_apk.WORKER, "run")])
        values, _ = self.run_query("trace_android_references", {"class": fixtures_apk.MAIN, "method": "helper",
                                                                "direction": "to"})
        self.assertEqual([row[6] for row in values["android.references"][0]["rows"]],
                         [f"{fixtures_apk.MAIN}->helper(Ljava/lang/String;)I", f"{fixtures_apk.MAIN}->helper(I)I"])

    def test_child_offsets_past_the_input_size_are_concluded(self):
        data, layout = fixtures_apk.apk_hostile("high_ratio")
        ref = InputRef(sha256_hex(data), len(data), "fixture.apk")
        artifact = layout["members"][5]["artifact"]
        self.assertGreater(artifact["size"] - 32, len(data))
        item = make_evidence(data, query.REFS["dex"], "dex.classes", Observation(Location(artifact["size"] - 32, 32), {
            "kind": "class", "index": 0, "total": 1, "dex": "classes.dex", "name": "La;", "access": 1,
            "superclass": None, "interfaces": [], "interfaces_total": 0, "source_file": None}, artifact))
        task = AnalysisTask(content_id("tk", {"q": "child"}), "structural", ref, (OperationRequest("dex.classes"),))
        finding, = query.conclude(task, [item])
        self.assertEqual(finding.value, {"start": 0, "total": 1, "rows": [["classes.dex", "La;", 1, None]]})
        past = Location(artifact["size"] - 16, 32)  # an intact record whose location runs past its child
        outside = Evidence(evidence_id(ref.sha256, item.tool, item.operation, past, item.excerpt_sha256,
                                       item.observation, artifact), ref.sha256, item.tool, item.operation, past,
                           item.excerpt_sha256, item.observation, artifact)
        self.assertEqual(query.conclude(task, [outside]), ())

    def test_permissions_are_concluded_in_chunks_of_64_in_document_order(self):
        artifact = self.layout["members"][0]["artifact"]
        rows = [("uses-permission", "android:name", "string", f"p.{i:02}") for i in range(70)]
        rows[3] = ("uses-permission", "android:name", "reference", "@0x7f0a0001")
        rows[4] = ("permission", "android:name", "string", "declared.not.used")
        rows[5] = ("uses-permission-sdk-23", "android:name", "string", "p.05")
        rows[6] = ("uses-permission", "android:label", "string", "not.a.permission")
        items = [make_evidence(self.data, query.REFS["apk"], "apk.manifest", Observation(Location(20 * i, 20), {
            "kind": "manifest_attribute", "index": i, "total": 70, "element_index": i, "element": element,
            "attribute": attribute, "type": kind, "value": value}, artifact))
            for i, (element, attribute, kind, value) in enumerate(rows)]
        task = AnalysisTask(content_id("tk", {"q": "permissions"}), "structural", self.ref,
                            (OperationRequest("apk.manifest"),))
        findings = query.conclude(task, items)
        self.assertEqual([(f.claim_key, len(f.evidence_ids)) for f in findings],
                         [("android.manifest", 64), ("android.manifest", 6), ("android.permissions", 64),
                          ("android.permissions", 3)])
        names = [item for item in items if item.observation["element"] != "permission"
                 and item.observation["type"] == "string" and item.observation["attribute"] == "android:name"]
        self.assertEqual([set(f.evidence_ids) for f in findings[2:]], [{item.id for item in names[:64]},
                                                                       {item.id for item in names[64:]}])
        self.assertEqual([f.value for f in findings[2:]], [sorted(item.observation["value"] for item in names[:64]),
                                                           sorted(item.observation["value"] for item in names[64:])])
        self.assertEqual(sorted(findings[2].value + findings[3].value),
                         sorted({f"p.{i:02}" for i in range(70) if i not in (3, 4, 6)}))

    def test_the_real_tools_give_the_fixture_answers_row_for_row(self):
        # Seam check: the apk and dex tools in pipeline.TOOLS and the stand-ins built from the fixture layout agree on
        # every finding and every evidence record (location, observation, child artifact).
        F = fixtures_apk
        cases = [("inspect_android_package", {}), ("search_android_classes", {}),
                 ("search_android_classes", {"member": "classes2.dex", "query": "Worker"}),
                 ("inspect_android_class", {"class": F.MAIN}), ("inspect_android_class", {"class": F.WORKER}),
                 ("inspect_android_method", {"class": F.MAIN, "method": "onCreate"}),
                 ("inspect_android_method", {"member": "classes.dex", "class": F.MAIN, "method": "helper",
                                             "prototype": "(I)I", "limit": 2}),
                 ("trace_android_references", {"class": F.HELPER, "method": "compute", "direction": "to"}),
                 ("trace_android_references", {"class": F.MAIN, "method": "helper", "direction": "to"}),
                 ("trace_android_references", {"class": F.MARKER, "method": "<init>"})]
        for utf8 in (False, True):
            data, layout = F.apk_basic(utf8_manifest=utf8)
            ref = InputRef(sha256_hex(data), len(data), "fixture.apk")
            for name, args in cases if not utf8 else cases[:1]:
                with self.subTest(utf8=utf8, query=name, args=args):
                    real = pipeline.query_bytes(data, ref, name, args)
                    known = pipeline.query_bytes(data, ref, name, args, tools=android_standins(layout))
                    self.assertEqual([r.status for r in real.results], ["ok"])
                    self.assertEqual({v.status for v in real.verdicts}, {"supported"})
                    self.assertEqual(sorted((f.claim_key, repr(f.value)) for f in real.results[0].findings),
                                     sorted((f.claim_key, repr(f.value)) for f in known.results[0].findings))
                    self.assertEqual({e.to_dict()["id"]: e.to_dict() for e in real.results[0].evidence},
                                     {e.to_dict()["id"]: e.to_dict() for e in known.results[0].evidence})

    def test_the_real_tools_give_each_hostile_package_its_declared_outcome(self):
        for kind, (flags, refused) in fixtures_apk.HOSTILE_KINDS.items():
            data, layout = fixtures_apk.apk_hostile(kind)
            ref = InputRef(sha256_hex(data), len(data), "hostile.apk")
            with self.subTest(kind=kind):
                analysis = pipeline.query_bytes(data, ref, "inspect_android_package", {})
                result = analysis.results[0]
                if refused:
                    self.assertEqual((result.status, result.findings), ("error", ()))
                    continue
                self.assertEqual({v.status for v in analysis.verdicts}, {"supported"})
                rows = [row for f in result.findings if f.claim_key == "android.members" for row in f.value["rows"]]
                if kind == "truncated_central":
                    self.assertEqual(len(rows), layout["anomaly"]["complete_entries"])
                    continue
                index = layout["anomaly"]["member"]
                self.assertEqual(rows[index][6], flags)
                self.assertEqual(rows[index][5] is None, bool(flags))
                if kind.startswith("dex_"):
                    classes = pipeline.query_bytes(data, ref, "search_android_classes", {"member": "classes2.dex"})
                    self.assertEqual((classes.results[0].status, classes.results[0].findings), ("error", ()))
                    other = pipeline.query_bytes(data, ref, "search_android_classes", {"member": "classes.dex"})
                    self.assertEqual({v.status for v in other.verdicts}, {"supported"})


class PermissionChunkTests(unittest.TestCase):
    def test_more_than_64_permissions_through_the_real_apk_tool_and_reviewer(self):
        # No permission is omitted; every chunk is supported (claims.SUBSET_CLAIMS).
        names = [f"org.reverseai.permission.P{i:03d}" for i in range(70)]
        tag, line, end, attributes, children = fixtures_apk.MANIFEST
        permissions = tuple(("uses-permission", 3, 3, ((True, "name", name),), ()) for name in names)
        permissions += (("uses-permission-sdk-23", 3, 3, ((True, "name", "android.permission.INTERNET"),), ()),)
        manifest = (tag, line, end, attributes, (children[0],) + permissions + children[3:])
        data, _ = fixtures_apk.zip_archive([fixtures_apk.member("AndroidManifest.xml",
                                                                fixtures_apk.manifest_axml(manifest=manifest)[0])])
        ref = InputRef(sha256_hex(data), len(data), "permissions.apk")
        analysis = pipeline.query_bytes(data, ref, "inspect_android_package", {})
        self.assertEqual({v.status for v in analysis.verdicts}, {"supported"})
        chunks = [f for f in analysis.results[0].findings if f.claim_key == "android.permissions"]
        self.assertEqual([len(f.evidence_ids) for f in chunks], [64, 7])
        self.assertEqual(sorted(name for f in chunks for name in f.value), sorted(names + ["android.permission.INTERNET"]))
        cited = {e.id: e for e in analysis.results[0].evidence}
        last_of_first = max(cited[i].observation["index"] for i in chunks[0].evidence_ids)
        self.assertTrue(all(cited[i].observation["index"] > last_of_first for i in chunks[1].evidence_ids))
