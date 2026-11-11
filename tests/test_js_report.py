"""The JavaScript section of query reports: files, package.json declarations with install-time scripts marked,
hints grouped by category, a plain statement of what the lexical tools read, and sample text kept inert."""

from dataclasses import replace
import hashlib
import json
import re
import unittest

from reverseai import claims, report
from reverseai.review import review
from reverseai.tools import js
from tests import fixtures_apk as F
from tests import fixtures_js as J
from tests.test_js_queries import run

SECTION = "## JavaScript application"
LEXICAL = ("Hints are lexical: occurrences of fixed patterns in the bytes, comments and strings included, not evidence "
           "that the code runs. This reading uses no JavaScript syntax and runs nothing.")


def section(markdown):
    """The lines of the JavaScript section, up to the next level-two heading."""
    lines = markdown.splitlines()
    start = lines.index(SECTION)
    end = next(i for i in range(start + 1, len(lines)) if lines[i].startswith("## "))
    return lines[start:end]


def outside_code(line):
    return re.sub(r"`[^`]*`", "", line)


class JavaScriptReportTests(unittest.TestCase):
    def test_flagged_files_show_the_declared_size_and_why_they_were_not_read(self):
        analysis = run(J.js_hostile('flagged_members'), {'detail': 'files'})
        lines = section(report.to_markdown(analysis))
        self.assertIn('| Index | File | Size | SHA-256 | Lines | Longest line (bytes) | Flags |', lines)
        observations = analysis.results[0].evidence
        flagged = [item for item in observations if item.observation.get('flags')]
        self.assertGreaterEqual(len(flagged), 7)
        for item in flagged:
            value = item.observation
            line, = [line for line in lines if line.startswith(f"| {value['index']} | ")]
            self.assertIn(f"| `{value['size']}` | `not read` | `not read` | `not read` |", line)
            for flag in value['flags']:
                self.assertIn(flag, line)
        document = json.loads(report.to_json(analysis))
        rows = document['results'][0]['findings'][0]['value']['rows']
        self.assertTrue(all(row[2:5] == [None, None, None] for row in rows if row[5]))
        self.assertTrue(all(finding['verdict'] == 'supported' for finding in document['results'][0]['findings']))

    def test_the_summary_shows_files_declarations_and_hints_by_category(self):
        built = J.app_zip()
        lines = section(report.to_markdown(run(built)))
        self.assertEqual(lines[2], LEXICAL)
        headings = [line for line in lines if line.startswith("### ")]
        self.assertEqual(headings, [f"### {claims.statement(key)}" for key in
                                    ("javascript.files", "javascript.package", "javascript.hints")])
        self.assertIn("| Index | File | Size | SHA-256 | Lines | Longest line (bytes) | Flags |", lines)
        minified = next(f["row"] for f in built[1]["files"] if f["name"] == "dist/app.min.js")
        self.assertIn(f"| 6 | `dist/app.min.js` | `{minified['size']}` | `{minified['sha256']}` | `1` | "
                      f"`{minified['max_line']}` | `[]` |", lines)
        self.assertIn("rows 0..8 of 9", lines)
        categories = [line[5:] for line in lines if line.startswith("#### ")]
        self.assertEqual(categories, ["`endpoint`", "`dynamic_code`", "`shell`", "`network`", "`credential`",
                                      "`encoding`"])
        credential = lines.index("#### `credential`")
        self.assertEqual(lines[credential + 2:credential + 6], [
            "| Index | File | Category | Hint | Text | Truncated |", "|---|---|---|---|---|---|",
            f"| 11 | `src/config.ts` | `credential` | `aws_access_key` | `{J.FAKE_AWS_KEY_ID}` | `false` |",
            f"| 12 | `src/config.ts` | `credential` | `private_key` | `{J.PRIVATE_KEY_BEGIN}` | `false` |"])

    def test_install_time_scripts_are_marked_and_nothing_else(self):
        package, strings = J.json_text({"name": "marks", "scripts": {
            "preinstall": "a", "install": "b", "postinstall": "c", "prepare": "d", "build": "e", "prepublish": "f"},
            "dependencies": {"postinstall": "1.0.0"}})
        built = J.archive([F.member("package.json", package)], strings={"package.json": strings})
        lines = section(report.to_markdown(run(built, {"detail": "package"})))
        marked = {line.split(" | ")[2]: line.endswith("| yes |") for line in lines if line.startswith("| ")
                  and line.split(" | ")[2].startswith("`/")}
        self.assertEqual(marked, {"`/name`": False, "`/scripts/preinstall`": True, "`/scripts/install`": True,
                                  "`/scripts/postinstall`": True, "`/scripts/prepare`": True, "`/scripts/build`": False,
                                  "`/scripts/prepublish`": False, "`/dependencies/postinstall`": False})
        self.assertTrue(any(line.startswith("Runs on install marks the scripts npm runs") for line in lines))

    def test_a_single_file_is_shown_as_the_input_and_the_next_page_is_named(self):
        lines = section(report.to_markdown(run(J.bundle_js(), {"detail": "files"}, name="bundle.js")))
        self.assertTrue(any(line.startswith("| 0 | (input) | ") for line in lines))
        lines = section(report.to_markdown(run(J.app_zip(), {"detail": "files", "limit": 3})))
        self.assertEqual(lines[lines.index("rows 0..2 of 9") + 1], "Next start: 3")
        self.assertNotIn("Next start", "\n".join(section(report.to_markdown(run(J.app_zip(), {"detail": "files"})))))

    def test_a_page_missing_a_finding_shows_each_run_and_continues_at_the_first_missing_row(self):
        # One hint page of 192 rows in three findings of 64; drop findings and review again
        data, _ = J.source(*(("fetch(", ("url_https", f"https://e{i}.example.com/"), ");") for i in range(192)))
        heading = f"### {claims.statement('javascript.hints')}"

        def shown(args, kept):
            analysis = run(J.single(data), {"detail": "hints", "category": "endpoint", **args}, name="many.js")
            result = analysis.results[0]
            findings = sorted(result.findings, key=lambda finding: finding.value["start"])
            partial = replace(result, findings=tuple(findings[i] for i in kept))
            verdicts = tuple(review(data, analysis.input, (partial,), {"js": js.TOOL}))
            self.assertEqual({verdict.status for verdict in verdicts}, {"supported"})
            lines = section(report.to_markdown(replace(analysis, results=(partial,), verdicts=verdicts)))
            at = lines.index(heading)
            return [(f.value["start"], len(f.value["rows"])) for f in findings], lines[at + 2:at + 4]

        self.assertEqual(shown({"limit": 192}, (0, 1, 2)), ([(0, 64), (64, 64), (128, 64)], ["rows 0..191 of 192", ""]))
        for kept, expected in (((0, 2), ["rows 0..63, 128..191 of 192", "Next start: 64"]),
                               ((1, 2), ["rows 64..191 of 192", "Next start: 0"]),
                               ((0, 1), ["rows 0..127 of 192", "Next start: 128"]),
                               ((1,), ["rows 64..127 of 192", "Next start: 0"])):
            with self.subTest(kept=kept):
                self.assertEqual(shown({"limit": 192}, kept)[1], expected)
        # a later page continues from its own start
        self.assertEqual(shown({"start": 64, "limit": 128}, (1,)), ([(64, 64), (128, 64)],
                                                                    ["rows 128..191 of 192", "Next start: 64"]))
        self.assertEqual(shown({"start": 64, "limit": 64}, (0,))[1], ["rows 64..127 of 192", "Next start: 128"])

    def test_without_rows_the_section_says_so(self):
        analysis = run(J.app_zip(), {"detail": "package", "file": "none/package.json"})
        self.assertEqual(section(report.to_markdown(analysis)),
                         [SECTION, "", LEXICAL, "", "No JavaScript row was supported.", ""])
        analysis = run(J.app_zip(), {"detail": "files"})
        self.assertNotIn(SECTION, report.to_markdown(analysis).replace(SECTION, "", 1))  # one section only

    def test_sample_names_values_and_texts_stay_inert(self):
        # HTML, links and backticks from the sample never render. The JavaScript member's
        # name has no slash or colon, so it is admitted, and its hint text is the matched hostile literal.
        hostile = "<img src=x onerror=alert(1)>[x](https://evil.example/)`b`"
        name = "<img src=x onerror=alert(1)>[x](y)`b`.js"
        package, strings = J.json_text({"name": hostile, "scripts": {"postinstall": hostile}})
        script = b'const token = "<img src=x>[x](https://evil.example/)`b`";\n'
        built = J.archive([F.member("package.json", package), F.member(name, script)], strings={"package.json": strings})
        analysis = run(built)
        statuses = {verdict.finding_id: verdict.status for verdict in analysis.verdicts}
        rows = {(finding.claim_key, tuple(tuple(cell) if isinstance(cell, list) else cell for cell in row))
                for finding in analysis.results[0].findings
                if statuses[finding.id] == "supported" for row in finding.value["rows"]}
        literal = 'token = "<img src=x>[x](https://evil.example/)`b`"'
        self.assertLessEqual({("javascript.files", (name, len(script), hashlib.sha256(script).hexdigest(), 1,
                                                    len(script) - 1, ())),
                              ("javascript.hints", (name, "credential", "credential_assignment", literal, False)),
                              ("javascript.package", ("package.json", "/name", hostile, False))}, rows)
        markdown = report.to_markdown(analysis)
        lines = section(markdown)
        for shown in (hostile, name, literal):  # each inside one code span, its backticks replaced
            self.assertTrue(any("`" + shown.replace("`", "'") + "`" in line for line in lines), shown)
        for line in markdown.splitlines():
            self.assertNotIn("<img", outside_code(line), line)
            self.assertNotIn("](", outside_code(line), line)

    def test_the_json_report_keeps_the_query_and_page_findings(self):
        document = json.loads(report.to_json(run(J.app_zip(), {"limit": 2})))
        self.assertEqual(document["query"], {"name": "analyze_javascript_application", "args": {
            "detail": "summary", "file": "", "category": "all", "start": 0, "limit": 2}})
        self.assertEqual(sorted((f["claim_key"], f["verdict"]) for f in document["results"][0]["findings"]),
                         [("javascript.files", "supported"), ("javascript.hints", "supported"),
                          ("javascript.package", "supported")])


if __name__ == "__main__":
    unittest.main()
