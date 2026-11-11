"""Derived JavaScript syntax reports using inert bytes and an in-process parser stand-in."""

from dataclasses import replace
import json
import re
import unittest

from reverseai import claims, pipeline, report
from reverseai.contract import (
    ArgSpec, ContractError, InputRef, Location, Observation, OperationSpec,
    ReviewVerdict, ToolRef, ToolSpec, sha256_hex,
)
from reverseai.review import review


DATA = b"/* inert report fixture; never evaluated */\n" * 32
INPUT = InputRef(sha256_hex(DATA), len(DATA), "fixture.js")
PARSER = ToolRef("jsparser", "8.0.4-r2")
DERIVED = "## Derived by analysis tools (not verified against the bytes)"
SYNTAX = "### JavaScript syntax (parser's reading)"
CASES = {
    "modules": ({"file": "lib/main.js", "form": "import", "source": "child_process", "truncated": False},
                ("File", "Form", "Source", "Truncated")),
    "calls": ({"file": "lib/main.js", "callee": "globalThis.fetch"}, ("File", "Callee")),
    "parse": ({"file": "lib/broken.js", "status": "syntax_error", "errors": 2},
              ("File", "Status", "Errors")),
}
KINDS = {"modules": "js_module", "calls": "js_call", "parse": "js_parse"}


def parser_tool(detail, rows):
    observations = tuple(Observation(Location(i, 1), {
        "kind": KINDS[detail], "index": i, "total": len(rows), **row}) for i, row in enumerate(rows))
    schema = {
        "file": ArgSpec("identity", 0, 255, default=""),
        "kind": ArgSpec("enum", choices=("modules", "calls", "parse"), default="modules"),
        "start": ArgSpec("int", 0, 1048575, default=0),
        "limit": ArgSpec("int", 1, 256, default=128),
    }
    operation = OperationSpec("jsparser.syntax", schema,
                              lambda data, args: observations[args["start"]:args["start"] + args["limit"]],
                              max_observations=256, derived=True)
    return ToolSpec(PARSER, {operation.name: operation})


class JavaScriptSyntaxReportTests(unittest.TestCase):
    def query(self, detail, rows, **args):
        tool = parser_tool(detail, rows)
        try:
            analysis = pipeline.query_bytes(DATA, INPUT, "analyze_javascript_application",
                                            {"detail": detail, **args}, tools=(tool,))
        except ContractError as error:
            self.fail(f"The syntax query did not reach its parser stand-in: {error}")
        self.assertEqual([result.status for result in analysis.results], ["ok"])
        return analysis, tool

    def syntax_lines(self, analysis):
        markdown = report.to_markdown(analysis)
        self.assertIn(DERIVED, markdown)
        self.assertIn(SYNTAX, markdown)
        self.assertLess(markdown.index(DERIVED), markdown.index(SYNTAX))
        self.assertNotIn("## JavaScript application", markdown)
        lines = markdown.splitlines()
        start = lines.index(SYNTAX)
        end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("## ")), len(lines))
        return lines[start:end]

    def test_each_syntax_kind_has_its_readable_table_under_the_derived_section(self):
        for detail, (row, columns) in CASES.items():
            with self.subTest(detail=detail):
                analysis, _ = self.query(detail, (row,))
                before = report.to_json(analysis)
                lines = self.syntax_lines(analysis)
                key = "javascript." + detail
                self.assertEqual([line for line in lines if line.startswith("#### ")],
                                 ["#### " + claims.statement(key)])
                self.assertIn("| Index | " + " | ".join(columns) + " |", lines)
                fields = claims.PAGES[KINDS[detail]][0]
                expected = "| 0 | " + " | ".join("`" + (str(row[field]).lower() if type(row[field]) is bool
                                                          else str(row[field])) + "`" for field in fields) + " |"
                self.assertIn(expected, lines)
                self.assertIn("rows 0..0 of 1", lines)
                self.assertFalse(any(line.startswith("Next start:") for line in lines))
                supported = report.to_markdown(analysis).split(DERIVED, 1)[0]
                self.assertNotIn(SYNTAX, supported)
                self.assertEqual(report.to_json(analysis), before)
                document = json.loads(before)
                finding, = document["results"][0]["findings"]
                self.assertEqual((finding["claim_key"], finding["confidence"], finding["verdict"]),
                                 (key, "inferred", "derived"))
                self.assertEqual(finding["value"], {"start": 0, "total": 1,
                                                   "rows": [[row[field] for field in fields]]})
                self.assertEqual((document["summary"]["derived"], document["summary"]["supported"]), (1, 0))

    def test_nonzero_pages_keep_absolute_indexes_and_continue_from_the_first_unshown_row(self):
        rows = [{"file": f"lib/file{i}.js", "callee": "fetch"} for i in range(10)]
        analysis, _ = self.query("calls", rows, start=3, limit=2)
        lines = self.syntax_lines(analysis)
        self.assertIn("rows 3..4 of 10", lines)
        self.assertIn("Next start: 5", lines)
        self.assertEqual([line for line in lines if re.match(r"^\| \d+ \|", line)],
                         ["| 3 | `lib/file3.js` | `fetch` |", "| 4 | `lib/file4.js` | `fetch` |"])

    def test_dropped_findings_show_only_present_runs_and_resume_at_the_first_gap(self):
        rows = [{"file": f"lib/file{i}.js", "callee": "fetch"} for i in range(192)]
        analysis, tool = self.query("calls", rows, limit=192)
        result, = analysis.results
        findings = sorted(result.findings, key=lambda finding: finding.value["start"])
        self.assertEqual([(f.value["start"], len(f.value["rows"])) for f in findings],
                         [(0, 64), (64, 64), (128, 64)])
        for kept, expected_range, following in (((0, 1, 2), "0..191", None),
                                                ((0, 2), "0..63, 128..191", 64),
                                                ((1, 2), "64..191", 0),
                                                ((0, 1), "0..127", 128)):
            with self.subTest(kept=kept):
                partial = replace(result, findings=tuple(findings[i] for i in kept))
                verdicts = review(DATA, INPUT, (partial,), {"jsparser": tool})
                self.assertEqual({verdict.status for verdict in verdicts}, {"derived"})
                lines = self.syntax_lines(replace(analysis, results=(partial,), verdicts=verdicts))
                self.assertIn(f"rows {expected_range} of 192", lines)
                self.assertEqual([line for line in lines if line.startswith("Next start:")],
                                 [] if following is None else [f"Next start: {following}"])
                shown = [int(match[1]) for line in lines if (match := re.match(r"^\| (\d+) \|", line))]
                self.assertEqual(shown, [index for i in kept for index in range(i * 64, (i + 1) * 64)])

    def test_hostile_admitted_names_and_sources_stay_inert_and_callees_stay_in_code_spans(self):
        file = "<img src=x>[file](y)`part`|.js"
        source = "<img src=x onerror=alert(1)>[source](https://evil.invalid/)`body`|tail"
        callee = "$module.__proto__.constructor.eval"
        cases = {
            "modules": {"file": file, "form": "dynamic_import", "source": source, "truncated": False},
            "calls": {"file": file, "callee": callee},
        }
        for detail, row in cases.items():
            with self.subTest(detail=detail):
                analysis, _ = self.query(detail, (row,))
                self.assertEqual({verdict.status for verdict in analysis.verdicts}, {"derived"})
                lines = self.syntax_lines(analysis)
                for text in (file, source if detail == "modules" else callee):
                    escaped = "`" + text.replace("`", "'").replace("|", "\\|") + "`"
                    self.assertTrue(any(escaped in line for line in lines), escaped)
                for line in report.to_markdown(analysis).splitlines():
                    outside = re.sub(r"`[^`]*`", "", line)
                    self.assertNotIn("<img", outside)
                    self.assertNotIn("](", outside)
                self.assertEqual(json.loads(report.to_json(analysis))["results"][0]["findings"][0]["value"]["rows"],
                                 [[row[field] for field in claims.PAGES[KINDS[detail]][0]]])

    def test_empty_pages_do_not_claim_successful_syntax_or_emit_lexical_details(self):
        for detail in CASES:
            with self.subTest(detail=detail):
                analysis, _ = self.query(detail, ())
                result, = analysis.results
                self.assertEqual((result.evidence, result.findings, analysis.verdicts), ((), (), ()))
                document = json.loads(report.to_json(analysis))
                self.assertEqual((document["summary"]["derived"], document["summary"]["supported"]), (0, 0))
                markdown = report.to_markdown(analysis)
                self.assertNotIn("## JavaScript application", markdown)
                self.assertNotIn("#### " + claims.statement("javascript." + detail), markdown)
                self.assertFalse(any(re.match(r"^\| \d+ \|", line) for line in markdown.splitlines()))
                self.assertNotIn("| `ok` |", markdown)

    def test_unreviewed_or_rejected_syntax_findings_never_get_readable_detail_tables(self):
        analysis, _ = self.query("modules", (CASES["modules"][0],))
        finding, = analysis.results[0].findings
        for status in (None, "unsupported"):
            with self.subTest(status=status):
                verdicts = () if status is None else (ReviewVerdict(finding.id, status, ("Rejected for this test.",)),)
                markdown = report.to_markdown(replace(analysis, verdicts=verdicts))
                self.assertNotIn(SYNTAX, markdown)
                self.assertNotIn("| Index | File | Form | Source | Truncated |", markdown)
                self.assertNotIn("## JavaScript application", markdown)


if __name__ == "__main__":
    unittest.main()
