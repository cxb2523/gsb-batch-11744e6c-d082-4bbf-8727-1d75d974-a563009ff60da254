"""Derived JavaScript syntax pages from the contained parser."""

import unittest

from reverseai import claims
from reverseai.contract import (
    AnalysisResult, InputRef, Location, Observation, OperationSpec, ToolRef, ToolSpec, content_id, make_evidence,
    make_finding, sha256_hex,
)
from reverseai.review import review

DATA = bytes(range(256)) * 4
INPUT = InputRef(sha256_hex(DATA), len(DATA), "app.zip")
PARSER = ToolRef("jsparser", "8.0.4-r2")
CASES = {
    ("javascript.modules", "js_module"): (
        {"file": "lib/index.js", "form": "require", "source": "child_process", "truncated": False},
        [("form", "include"), ("source", "a\nb"), ("source", "x" * 257), ("truncated", True), ("file", "a\tb")]),
    ("javascript.calls", "js_call"): (
        {"file": "", "callee": "child_process.exec"},
        [("callee", ""), ("callee", "a..b"), ("callee", "a.b.c.d.e"), ("callee", "1x"), ("callee", "a b"),
         ("callee", "café"), ("callee", "x(")]),
    ("javascript.parse", "js_parse"): (
        {"file": "dist/app.min.js", "status": "syntax_error", "errors": 2},
        [("status", "broken"), ("errors", -1), ("errors", 0), ("errors", True)]),
}


def judge(key, kind, row, derived=True):
    tools = {"jsparser": ToolSpec(PARSER, {"jsparser.syntax": OperationSpec(
        "jsparser.syntax", {}, lambda d, a: [], derived=derived)})}
    item = make_evidence(DATA, PARSER, "jsparser.syntax", Observation(Location(0, 8), {
        "kind": kind, "index": 0, "total": 1, **row}))
    fields = claims.PAGES[kind][0]
    finding = make_finding("code", "Rows.", key, {"start": 0, "total": 1, "rows": [[row[f] for f in fields]]},
                           [item.id], "inferred")
    result = AnalysisResult(content_id("tk", {"k": key}), "code", "ok", (item,), (finding,))
    return review(DATA, INPUT, [result], tools)[0].status


class JavaScriptSyntaxClaimTests(unittest.TestCase):
    def test_each_page_is_derived_and_refuses_each_bad_field(self):
        for (key, kind), (row, bad) in CASES.items():
            self.assertIn(key, claims.DERIVED_CLAIMS)
            self.assertIn(key, claims.PAGE_CLAIMS)
            self.assertEqual(judge(key, kind, row), "derived", key)
            self.assertEqual(judge(key, kind, row, derived=False), "derived", key)
            for field, value in bad:
                self.assertEqual(judge(key, kind, {**row, field: value}), "unsupported", (key, field, value))

    def test_a_clean_parse_has_no_errors(self):
        self.assertEqual(judge("javascript.parse", "js_parse", {"file": "", "status": "ok", "errors": 0}), "derived")
        self.assertEqual(judge("javascript.parse", "js_parse", {"file": "", "status": "ok", "errors": 1}), "unsupported")


if __name__ == "__main__":
    unittest.main()
