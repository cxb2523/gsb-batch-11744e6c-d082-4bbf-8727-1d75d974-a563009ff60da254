"""JADX query conclusions and safe paged Java reports using synthetic APKs."""
from dataclasses import replace
import json
import re
import unittest

from reverseai import pipeline, report
from reverseai.analysts import query
from reverseai.contract import (
    AnalysisResult, AnalysisTask, Evidence, InputRef, Location, Observation,
    OperationRequest, OperationSpec, ReviewVerdict, ToolRef, ToolSpec, content_id,
    evidence_id, make_evidence, make_finding, sha256_hex,
)
from reverseai.review import review
from tests import fixtures_apk
from tests.test_queries import android_standins

JADX = ToolRef("jadx", "1.5.6-r1")
IMAGE = "sha256:" + "0123456789abcdef" * 4
DERIVED_HEADING = "## Derived by analysis tools (not verified against the bytes)"
DATA, LAYOUT = fixtures_apk.apk_basic()
INPUT = InputRef(sha256_hex(DATA), len(DATA), "fixture.apk")
MEMBER = next(row for row in LAYOUT["members"] if row["name"] == "classes.dex")
HELPERS = [method for cls in LAYOUT["dex"]["classes.dex"]["classes"]
           if cls["name"] == fixtures_apk.MAIN for method in cls["methods"]
           if method["name"] == "helper"]
TASK = AnalysisTask(content_id("tk", {"test": "java surface"}), "structural", INPUT,
                    (OperationRequest("jadx.method", {}),))


def java_row(index=0, **change):
    method = HELPERS[index]
    text = "int helper(int value) {\n\treturn value + 1;\n}"
    row = dict(kind="java", dex="classes.dex", **{"class": fixtures_apk.MAIN},
               name=method["name"], prototype=method["prototype"], form="java",
               start=7, total=7 + len(text) + 23, text=text)
    row.update(change)
    return row


def java_evidence(index=0, *, row=None, tool=JADX, operation="jadx.method", input_sha256=None):
    method = HELPERS[index]
    return make_evidence(DATA, tool, operation,
                         Observation(Location(method["code_offset"] + 16, 2 * method["code_units"]),
                                     row if row is not None else java_row(index), MEMBER["artifact"]),
                         input_sha256=input_sha256)


def value_of(item):
    return {key: value for key, value in item.observation.items() if key != "kind"}


def java_finding(item, *, confidence="inferred", cited=None, value=None):
    return make_finding("structural", "Decompiler reading.", "android.java",
                        value if value is not None else value_of(item),
                        [item.id] if cited is None else cited, confidence)


def registry(*, derived=True):
    operation = OperationSpec("jadx.method", {}, lambda data, args: [],
                              max_observations=16, derived=derived)
    return {"jadx": ToolSpec(JADX, {"jadx.method": operation})}


def result_for(evidence, findings):
    return AnalysisResult(TASK.id, TASK.role, "ok", tuple(evidence), tuple(findings))


def judged(evidence, finding, *, tools=None):
    return review(DATA, INPUT, (result_for(evidence, (finding,)),), tools or registry())[0].status


def java_analysis(rows, *, status="derived", with_query=True):
    items = tuple(java_evidence(i % len(HELPERS), row=row) for i, row in enumerate(rows))
    findings = tuple(java_finding(item) for item in items)
    verdicts = tuple(ReviewVerdict(f.id, status, ("Tool reading or rejected claim.",)) for f in findings) if status else ()
    return report.Analysis(INPUT, (JADX,), (result_for(items, findings),), verdicts,
                           (("jadx", {"image": IMAGE, "platform": "linux/arm64"}),),
                           {"name": "inspect_android_method", "args": {"class": fixtures_apk.MAIN,
                                                                     "method": "helper"}} if with_query else None)


def fenced_blocks(markdown):
    """Parse the CommonMark fence rule needed to detect malicious early closers.

    An opener/closer may be indented by at most three spaces. A closer uses the
    opener's marker, at least its length, followed by whitespace only.
    """
    blocks, current, body = [], None, []
    for line in markdown.split("\n"):
        if current is None:
            match = re.fullmatch(r" {0,3}(`{3,}|~{3,})(.*)", line)
            if match and not (match[1][0] == "`" and "`" in match[2]):
                current, body = match[1], []
        elif re.fullmatch(r" {0,3}" + re.escape(current[0]) + "{" + str(len(current)) + r",}[ \t]*", line):
            blocks.append("\n".join(body))
            current, body = None, []
        else:
            body.append(line)
    if current is not None:
        raise AssertionError("Report contains an unclosed fenced block")
    return blocks


class JavaQueryAnalystTests(unittest.TestCase):
    def test_each_java_observation_becomes_one_inferred_finding_with_only_its_own_citation(self):
        items = (java_evidence(0), java_evidence(1, row=java_row(1, form="fallback")))
        findings = query.conclude(TASK, items)
        self.assertEqual(len(findings), len(items))
        by_citation = {f.evidence_ids: f for f in findings}
        self.assertEqual(set(by_citation), {(item.id,) for item in items})
        for item in items:
            finding = by_citation[(item.id,)]
            self.assertEqual((finding.claim_key, finding.confidence, finding.value),
                             ("android.java", "inferred", value_of(item)))
        verdicts = review(DATA, INPUT, (result_for(items, findings),), registry())
        self.assertEqual({v.finding_id: v.status for v in verdicts},
                         {finding.id: "derived" for finding in findings})

    def test_analyst_refuses_wrong_tool_version_operation_input_and_outside_child(self):
        good = java_evidence()
        wrong_version = java_evidence(tool=ToolRef("jadx", "1.5.6-r2"))
        wrong_operation = java_evidence(operation="jadx.other")
        wrong_input = java_evidence(input_sha256="0" * 64)
        location = Location(MEMBER["size"], 1)
        fields = dict(input_sha256=good.input_sha256, tool=good.tool, operation=good.operation,
                      location=location, excerpt_sha256=sha256_hex(b"x"),
                      observation=good.observation, artifact=good.artifact)
        outside = Evidence(id=evidence_id(**fields), **fields)
        for item in (wrong_version, wrong_operation, wrong_input, outside):
            with self.subTest(item=item.id):
                self.assertEqual(query.conclude(TASK, (item,)), ())
        # The exact pinned ToolRef must also be accepted, not just the negatives refused.
        self.assertEqual(len(query.conclude(TASK, (good,))), 1)

    def test_reviewer_refuses_malformed_java_even_when_the_claim_repeats_it(self):
        base = java_row()
        for change in ({"form": "smali"}, {"start": True}, {"total": 1},
                       {"text": "a\rb"}, {"text": "\x1b[31m"}, {"extra": "x"},
                       {"form": "error", "text": "", "start": 1, "total": 1}):
            with self.subTest(change=change):
                item = java_evidence(row={**base, **change})
                self.assertEqual(judged((item,), java_finding(item)), "unsupported")

    def test_reviewer_keeps_forms_derived_and_rejects_extra_or_foreign_citations(self):
        for form in ("java", "fallback", "error"):
            row = java_row(form=form, **({"text": "", "start": 0, "total": 0} if form == "error" else {}))
            item = java_evidence(row=row)
            self.assertEqual(judged((item,), java_finding(item), tools=registry(derived=False)), "derived")
        first, other = java_evidence(), java_evidence(1)
        self.assertEqual(judged((first, other), java_finding(first, cited=[first.id, other.id])), "unsupported")
        local = result_for((), (java_finding(first),))
        foreign = replace(result_for((first,), ()), task_id=content_id("tk", {"test": "foreign result"}))
        self.assertEqual(review(DATA, INPUT, (local, foreign), registry())[0].status, "unsupported")
        # Keep a valid content ID but falsely declare the child's bytes: provenance must fail.
        artifact = {**first.artifact, "sha256": "0" * 64}
        fields = dict(input_sha256=first.input_sha256, tool=first.tool, operation=first.operation,
                      location=first.location, excerpt_sha256=first.excerpt_sha256,
                      observation=first.observation, artifact=artifact)
        forged = Evidence(id=evidence_id(**fields), **fields)
        self.assertEqual(judged((forged,), java_finding(forged)), "unsupported")


class JavaReportTests(unittest.TestCase):
    def test_next_start_is_shown_when_exactly_one_character_remains(self):
        for remaining in (0, 1, 2):
            with self.subTest(remaining=remaining):
                row = java_row(start=23, text="x;", total=25 + remaining)
                markdown = report.to_markdown(java_analysis((row,)))
                derived = markdown.split(DERIVED_HEADING, 1)[1].split("## Rejected or unreviewed claims", 1)[0]
                self.assertIn(f"characters 23..24 of {25 + remaining}", derived)
                if remaining:
                    self.assertIn("Next start: 25", derived)
                else:
                    self.assertNotIn("Next start:", derived)

    def test_java_header_keeps_every_hostile_identity_in_a_code_span(self):
        row = java_row(dex="classes<img>.dex", **{"class": "Ldemo/[link](https://evil.invalid/);"},
                       name="*method*", prototype="(Ldemo/`type`|<T>;)V")
        markdown = report.to_markdown(java_analysis((row,)))
        header, = [line for line in markdown.splitlines() if line.startswith("Method: ")]
        self.assertEqual(header, "Method: `classes<img>.dex` · `Ldemo/[link](https://evil.invalid/);` · "
                         "`*method*` `(Ldemo/'type'\\|<T>;)V`")

    def test_report_shows_full_java_pages_metadata_and_inclusive_character_bounds(self):
        rows = [java_row(), java_row(1, start=101, total=102, text=";")]
        for with_query in (True, False):
            with self.subTest(with_query=with_query):
                analysis = java_analysis(rows, with_query=with_query)
                before = report.to_json(analysis)
                markdown = report.to_markdown(analysis)
                self.assertEqual(report.to_json(analysis), before)
                derived = markdown.split(DERIVED_HEADING, 1)[1].split("## Rejected or unreviewed claims", 1)[0]
                blocks = fenced_blocks(derived)
                self.assertEqual(len(blocks), 2)
                for row in rows:
                    self.assertIn(row["text"], blocks)
                    end = row["start"] + len(row["text"]) - 1
                    self.assertIn(f"characters {row['start']}..{end} of {row['total']}", derived)
                    self.assertIn(row["prototype"], derived)
                self.assertIn(f"Next start: {rows[0]['start'] + len(rows[0]['text'])}", derived)
                self.assertNotIn("Next start: 102", derived)
                for marker in ("jadx", "1.5.6-r1", IMAGE, fixtures_apk.MAIN, "helper", "classes.dex", "java"):
                    self.assertIn(marker, derived)
                self.assertEqual(json.loads(before)["results"][0]["findings"][0]["value"],
                                 {k: v for k, v in rows[0].items() if k != "kind"})

    def test_report_renders_fallback_and_empty_error_with_explicit_forms(self):
        for form in ("fallback", "error"):
            row = java_row(form=form, **({"text": "", "start": 0, "total": 0} if form == "error" else {}))
            with self.subTest(form=form):
                markdown = report.to_markdown(java_analysis((row,)))
                derived = markdown.split(DERIVED_HEADING, 1)[1].split("## Rejected or unreviewed claims", 1)[0]
                self.assertIn(form, derived)
                blocks = fenced_blocks(derived)
                self.assertEqual(blocks, [row["text"]])
                if form == "error":
                    self.assertIn("no text (form error)", derived)
                    self.assertNotIn("characters ", derived)
                    self.assertNotIn("Next start:", derived)
        for form in ("java", "fallback"):
            with self.subTest(empty_form=form):
                row = java_row(form=form, text="", start=31, total=31)
                markdown = report.to_markdown(java_analysis((row,)))
                derived = markdown.split(DERIVED_HEADING, 1)[1].split("## Rejected or unreviewed claims", 1)[0]
                self.assertIn(f"no text (form {form})", derived)
                self.assertNotIn("characters ", derived)
                self.assertNotIn("Next start:", derived)
                self.assertEqual(fenced_blocks(derived), [""])

    def test_hostile_java_stays_in_one_fence_and_controls_are_sanitized(self):
        hostile = ('first();\n```\n<img src=x onerror=evil()>\n![image](https://evil.invalid/)\n'
                   '~~~\n   ``````\n# ESCAPE_SENTINEL\n\x00\r\x1b[31m\x7f\tlast();')
        row = java_row(start=3, total=3 + len(hostile), text=hostile)
        # Bypass the reviewer deliberately: rendering must be safe even if a caller
        # supplies an already-derived Analysis with hostile control characters.
        analysis = java_analysis((row,))
        before = report.to_json(analysis)
        markdown = report.to_markdown(analysis)
        derived = markdown.split(DERIVED_HEADING, 1)[1].split("## Rejected or unreviewed claims", 1)[0]
        blocks = fenced_blocks(derived)
        self.assertEqual(len(blocks), 1)
        for line in hostile.split("\n")[:-1]:
            self.assertIn(line, blocks[0])
        self.assertIn("\tlast();", blocks[0])
        self.assertTrue(all(char.isprintable() or char in "\n\t" for char in markdown))
        self.assertIn(f"characters 3..{3 + len(hostile) - 1} of {3 + len(hostile)}", derived)
        self.assertEqual(report.to_json(analysis), before)

    def test_rejected_unreviewed_java_has_no_readable_derived_listing(self):
        for status in ("unsupported", "contradicted", None):
            with self.subTest(status=status):
                markdown = report.to_markdown(java_analysis((java_row(),), status=status))
                self.assertEqual(fenced_blocks(markdown), [])
                self.assertNotIn("characters ", markdown)

    def test_absent_jadx_keeps_android_results_and_explains_how_to_enable_java(self):
        analysis = pipeline.query_bytes(DATA, INPUT, "inspect_android_method",
                                        {"class": fixtures_apk.MAIN, "method": "helper"},
                                        tools=android_standins(LAYOUT))
        self.assertEqual({result.status for result in analysis.results}, {"ok"})
        self.assertEqual({verdict.status for verdict in analysis.verdicts}, {"supported"})
        self.assertNotIn("android.java", {f.claim_key for r in analysis.results for f in r.findings})
        markdown = report.to_markdown(analysis)
        self.assertIn("--with-jadx", markdown)
        self.assertIn("Java", markdown)


if __name__ == "__main__":
    unittest.main()
