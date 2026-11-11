"""analyze_javascript_application: arguments, routing by detail, page conclusions and review through the js tool
on the fixtures, with exact answers from their layouts."""

import contextlib
from dataclasses import replace
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from reverseai import claims, cli, pipeline, queries
from reverseai.contract import ContractError, InputRef, MAX_EVIDENCE_PER_FINDING, materialize, sha256_hex
from reverseai.gateway import Gateway
from reverseai.tools import js, structure
from tests import fixtures_js as J

NAME = "analyze_javascript_application"


def dropping(index):
    """The js tool with a faulty js.files that leaves one row out of its page."""
    files = js.TOOL.operations["js.files"]
    handler = files.handler
    return replace(js.TOOL, operations={**js.TOOL.operations, "js.files": replace(
        files, handler=lambda data, args: [row for row in handler(data, args) if row.value["index"] != index])})


def run(built, args=None, *, tools=(js.TOOL,), name="app.zip"):
    data, _ = built
    return pipeline.query_bytes(data, InputRef(sha256_hex(data), len(data), name), NAME, args or {}, tools=tools)


def pages(analysis):
    """{claim key: [(verdict, value)]} of the query's findings."""
    verdicts = {verdict.finding_id: verdict.status for verdict in analysis.verdicts}
    found = {}
    for finding in analysis.results[0].findings:
        found.setdefault(finding.claim_key, []).append((verdicts[finding.id], finding.value))
    return found


def files_page(layout, start=0, stop=None):
    rows = layout["files"][start:stop]
    return {"start": start, "total": len(layout["files"]),
            "rows": [[f["row"][field] for field in ("file", "size", "sha256", "lines", "max_line", "flags")] for f in rows]}


class QueryTableTests(unittest.TestCase):
    def test_the_arguments_and_their_defaults(self):
        spec, args = queries.resolve(NAME, {})
        self.assertEqual(args, {"detail": "summary", "file": "", "category": "all", "start": 0, "limit": 128})
        self.assertEqual(spec.role, "structural")
        self.assertEqual(spec.operations, ("js.files", "js.package", "js.hints", "jsparser.syntax"))
        self.assertEqual(queries.JS_CATEGORIES, ("all", *claims.JS_CATEGORIES))

    def test_each_detail_routes_its_operations(self):
        def routed(raw):
            spec, args = queries.resolve(NAME, raw)
            return [(request.operation, request.args) for request in spec.requests(args)]
        self.assertEqual(routed({"limit": 5}), [
            ("js.files", {"start": 0, "limit": 5}), ("js.package", {"file": "", "start": 0, "limit": 5}),
            ("js.hints", {"file": "", "category": "all", "start": 0, "limit": 5})])
        self.assertEqual(routed({"detail": "files", "start": 3}), [("js.files", {"start": 3, "limit": 128})])
        self.assertEqual(routed({"detail": "package", "file": "a/package.json", "start": 1, "limit": 2}),
                         [("js.package", {"file": "a/package.json", "start": 1, "limit": 2})])
        self.assertEqual(routed({"detail": "hints", "file": "lib/index.js", "category": "shell", "start": 1048575}),
                         [("js.hints", {"file": "lib/index.js", "category": "shell", "start": 1048575, "limit": 128})])
        spec = queries.TABLE[NAME]  # every argument is passed on by some detail, or selects the detail
        used = {source for routes in spec.details.values() for taken, _ in routes.values() for source in taken.values()}
        self.assertEqual(used | {"detail"}, set(spec.args))

    def test_an_argument_the_detail_does_not_pass_on_is_refused(self):
        for raw in ({"file": "lib/index.js"}, {"category": "shell"}, {"start": 1},
                    {"detail": "files", "file": "a.js"}, {"detail": "files", "category": "network"},
                    {"detail": "package", "category": "credential"},
                    {"detail": "files", "start": 65536}, {"detail": "package", "start": 65536},
                    {"detail": "hints", "start": 1048576}, {"detail": "all"}, {"detail": "hints", "category": "behaviour"},
                    {"detail": "package", "file": "x" * 256}, {"detail": "hints", "file": "a\nb.js"},
                    {"limit": 0}, {"limit": 257}, {"query": "x"}):
            with self.subTest(raw=raw), self.assertRaises(ContractError):
                queries.resolve(NAME, raw)
        self.assertEqual(queries.resolve(NAME, {"detail": "package", "file": "x" * 255})[1]["file"], "x" * 255)

    def test_command_line_arguments(self):
        self.assertEqual(queries.parse_args(NAME, ["detail=hints", "category=credential", "start=0x10", "limit=5",
                                                   "file=lib/a b.js"]),
                         {"detail": "hints", "file": "lib/a b.js", "category": "credential", "start": 16, "limit": 5})
        for values in (["detail=files", "detail=hints"], ["mode=x"], ["limit=five"], ["detail"]):
            with self.subTest(values=values), self.assertRaises(ContractError):
                queries.parse_args(NAME, values)


class QueryRunTests(unittest.TestCase):
    def test_summary_reads_the_first_page_of_files_package_and_hints(self):
        built = J.app_zip()
        analysis = run(built)
        found = pages(analysis)
        self.assertEqual(set(found), {"javascript.files", "javascript.package", "javascript.hints"})
        self.assertEqual(found["javascript.files"], [("supported", files_page(built[1]))])
        package = built[1]["package"]["rows"]
        self.assertEqual(found["javascript.package"], [("supported", {"start": 0, "total": len(package), "rows": [
            [row["row"][field] for field in ("file", "path", "value", "truncated")] for row in package]})])
        (verdict, hints), = found["javascript.hints"]
        self.assertEqual((verdict, hints["start"], hints["total"]), ("supported", 0, 17))
        self.assertEqual(hints["rows"][:3], [["lib/index.js", "shell", "child_process", "child_process", False],
                                             ["lib/index.js", "endpoint", "url", "https://api.example.com/v1/collect",
                                              False], ["lib/index.js", "shell", "process_call", "exec(", False]])
        self.assertEqual({row[0] for row in hints["rows"]},
                         {"lib/index.js", "lib/loader.mjs", "src/config.ts", "dist/app.min.js"})  # never README.md
        # every hint cites the bytes of its text inside its member
        data = built[0]
        for item in analysis.results[0].evidence:
            if item.observation["kind"] == "js_hint":
                child = materialize(data, item.artifact)
                cited = child[item.location.offset:item.location.offset + item.location.length]
                self.assertEqual(cited.decode("latin-1"), item.observation["text"])

    def test_files_pages_cite_each_child_from_its_first_byte(self):
        built = J.app_zip()
        analysis = run(built, {"detail": "files", "start": 2, "limit": 3})
        self.assertEqual(pages(analysis), {"javascript.files": [("supported", files_page(built[1], 2, 5))]})
        result = analysis.results[0]
        cited = [item for item in result.evidence if item.id in result.findings[0].evidence_ids]
        self.assertEqual([(item.location.offset, item.location.length, item.artifact["member"]) for item in cited],
                         [(0, f["row"]["size"], f["name"]) for f in built[1]["files"][2:5]])
        self.assertEqual([item.artifact for item in cited], [f["artifact"] for f in built[1]["files"][2:5]])

    def test_a_single_file_is_named_empty_and_cited_in_the_input(self):
        data, layout = J.package_only()
        analysis = run((data, layout), {"detail": "package", "limit": 4}, name="package.json")
        (verdict, value), = pages(analysis)["javascript.package"]
        self.assertEqual((verdict, value["start"], value["total"]), ("supported", 0, len(J.APP_PACKAGE_PATHS)))
        self.assertEqual([row[:2] for row in value["rows"]], [["", path] for path in J.APP_PACKAGE_PATHS[:4]])
        result = analysis.results[0]
        self.assertEqual([(item.artifact, item.location.offset) for item in result.evidence],
                         [(None, row["offset"]) for row in layout["package"]["rows"][:4]])
        bundle = J.bundle_js()
        found = pages(run(bundle, name="bundle.js"))
        self.assertEqual(found["javascript.files"], [("supported", files_page(bundle[1]))])
        self.assertEqual({row[0] for _, value in found["javascript.hints"] for row in value["rows"]}, {""})

    def test_an_explicit_package_selector_picks_that_member_and_one_naming_none_gives_no_rows(self):
        built = J.app_zip()
        found = pages(run(built, {"detail": "package", "file": "node_modules/left-pad/package.json"}))
        self.assertEqual([row[1] for row in found["javascript.package"][0][1]["rows"]],
                         ["/name", "/version", "/main", "/license"])
        analysis = run(built, {"detail": "package", "file": "lib/missing/package.json"})
        self.assertEqual((analysis.results[0].status, pages(analysis)), ("ok", {}))

    def test_hint_pages_filter_by_category_and_split_at_64_citations(self):
        built = J.app_zip()
        found = pages(run(built, {"detail": "hints", "category": "credential"}))
        self.assertEqual([row[1:3] for row in found["javascript.hints"][0][1]["rows"]],
                         [["credential", "aws_access_key"], ["credential", "private_key"]])
        data, _ = J.source(*(("fetch(", ("url_https", f"https://e{i}.example.com/"), ");") for i in range(100)))
        found = pages(run(J.single(data), {"detail": "hints", "category": "endpoint", "limit": 100}, name="many.js"))
        self.assertEqual([(verdict, value["start"], len(value["rows"]), value["total"])
                          for verdict, value in found["javascript.hints"]],
                         [("supported", 0, MAX_EVIDENCE_PER_FINDING, 100), ("supported", 64, 36, 100)])

    def test_the_summary_limit_applies_to_every_page(self):
        found = pages(run(J.app_zip(), {"limit": 2}))
        self.assertEqual({key: [(value["start"], len(value["rows"])) for _, value in found[key]] for key in found},
                         {"javascript.files": [(0, 2)], "javascript.package": [(0, 2)], "javascript.hints": [(0, 2)]})

    def test_a_page_with_a_missing_row_concludes_nothing(self):
        built = J.app_zip()
        analysis = run(built, {"detail": "files"}, tools=(dropping(1),))
        self.assertEqual(len(analysis.results[0].evidence), len(built[1]["files"]) - 1)
        self.assertEqual(pages(analysis), {})

    def test_every_detail_runs_with_150_seconds_for_task_and_gateway(self):
        # The native 30 s and Android 120 s stay as test_queries pins them.
        built = J.app_zip()
        real_run = Gateway.run
        for detail in ("summary", "files", "package", "hints"):
            tasks = []

            def capture(gateway, task, data):
                tasks.append(task)
                return real_run(gateway, task, data)

            with self.subTest(detail=detail), patch.object(pipeline, "Gateway", wraps=Gateway) as factory, \
                    patch.object(Gateway, "run", capture):
                analysis = run(built, {"detail": detail})
                self.assertEqual([result.status for result in analysis.results], ["ok"])
                self.assertEqual((factory.call_args.args[1].max_wall_seconds, [task.budget.max_wall_seconds
                                                                                for task in tasks]), (150, [150]))
        self.assertEqual(pipeline.JAVASCRIPT_QUERY_BUDGET.max_wall_seconds, 150)

    def test_the_query_needs_the_js_operations(self):
        data, _ = J.app_zip()
        with self.assertRaisesRegex(ContractError, "Query operation unavailable"):
            pipeline.query_bytes(data, InputRef(sha256_hex(data), len(data), "app.zip"), NAME, {}, tools=(structure.TOOL,))
        built = J.app_zip()
        partial = replace(js.TOOL, operations={k: v for k, v in js.TOOL.operations.items() if k != "js.hints"})
        with self.assertRaisesRegex(ContractError, "Query operation unavailable"):
            run(built, tools=(partial,))
        self.assertEqual(set(pages(run(built, {"detail": "files"}, tools=(partial,)))), {"javascript.files"})



class RealToolTests(unittest.TestCase):
    """The registered tools through the query, the reviewer and the command."""

    def query(self, built, args, name="app.zip"):
        data, _ = built
        return pipeline.query_bytes(data, InputRef(sha256_hex(data), len(data), name), NAME, args)

    def test_the_pipeline_registers_the_js_tool(self):
        self.assertIn(js.TOOL, pipeline.TOOLS)
        built = J.app_zip()
        self.assertEqual(pages(self.query(built, {"detail": "files"})),
                         {"javascript.files": [("supported", files_page(built[1]))]})
        found = pages(self.query(built, {"detail": "package", "start": 28}))
        self.assertEqual(found, {"javascript.package": [("supported", {"start": 28, "total": 30, "rows": [
            ["package.json", "/optionalDependencies/fsevents", "2.3.3", False],
            ["package.json", "/bundledDependencies/0", "left-pad", False]]})]})

    def test_edge_cases_reach_the_reviewer(self):
        data, layout = J.js_edge("empty_file")
        analysis = self.query((data, layout), {"detail": "files"})
        self.assertEqual(pages(analysis), {"javascript.files": [("supported", files_page(layout))]})
        empty = next(item for item in analysis.results[0].evidence if item.observation["file"] == "lib/empty.js")
        self.assertEqual((empty.artifact, empty.location.offset, empty.location.length),
                         (None, layout["files"][0]["anchor"]["offset"], layout["files"][0]["anchor"]["length"]))
        analysis = self.query(J.js_edge("empty_input"), {"detail": "files"}, name="empty.js")
        self.assertEqual((analysis.results[0].status, pages(analysis)), ("ok", {}))
        for kind in ("long_value", "package_tie"):
            data, layout = J.js_edge(kind)
            (verdict, value), = pages(self.query((data, layout), {"detail": "package"}))["javascript.package"]
            self.assertEqual((verdict, value["rows"]), ("supported", [
                [row["row"][field] for field in ("file", "path", "value", "truncated")] for row in layout["package"]["rows"]]))

    def test_refused_documents_and_archives_fail_and_flagged_members_are_never_read(self):
        for kind in ("duplicate_key", "duplicate_nested_key", "invalid_json", "deep_nesting", "huge_string", "non_utf8",
                     "long_pointer"):
            built = J.js_hostile(kind)
            with self.subTest(kind=kind):
                self.assertEqual(self.query(built, {"detail": "package"}).results[0].status, "error")
                self.assertEqual(pages(self.query(built, {"detail": "files"})),
                                 {"javascript.files": [("supported", files_page(built[1]))]})
        for text in J.INVALID_JSON.values():
            self.assertEqual(self.query(J.package_zip(text), {"detail": "package"}).results[0].status, "error")
        built = J.js_hostile("zip_refused")
        for detail in ("files", "package"):
            self.assertEqual(self.query(built, {"detail": detail}).results[0].status, "error")
        built = J.js_hostile("flagged_members")
        self.assertEqual(pages(self.query(built, {"detail": "files"})),
                         {"javascript.files": [("supported", files_page(built[1]))]})
        analysis = self.query(J.js_hostile("declared_over_128mib"), {"detail": "package"})
        self.assertEqual((analysis.results[0].status, pages(analysis)), ("ok", {}))

    def test_the_command_writes_both_reports(self):
        data, layout = J.app_zip()
        with tempfile.TemporaryDirectory() as folder:
            sample, out = Path(folder, "app.zip"), Path(folder, "report")
            sample.write_bytes(data)
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = cli.main(["query", str(sample), "--query", NAME, "--arg", "detail=package", "--arg", "limit=3",
                                 "--out", str(out)])
            self.assertEqual(code, 0, stderr.getvalue())
            parsed = json.loads((out / "report.json").read_text())
            self.assertEqual([(f["claim_key"], f["verdict"]) for f in parsed["results"][0]["findings"]],
                             [("javascript.package", "supported")])
            markdown = (out / "report.md").read_text()
            self.assertIn("## JavaScript application", markdown)
            self.assertIn("| 0 | `package.json` | `/name` | `@fixture/app` | `false` | - |", markdown)
            self.assertNotIn(folder, markdown + json.dumps(parsed))


if __name__ == "__main__":
    unittest.main()
