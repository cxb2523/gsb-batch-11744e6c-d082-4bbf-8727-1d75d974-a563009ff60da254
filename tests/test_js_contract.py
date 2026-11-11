"""JavaScript page claims and their row shapes."""

import unittest

from reverseai import claims
from reverseai.contract import (
    AnalysisResult, InputRef, Location, Observation, OperationSpec, ToolRef, ToolSpec, content_id, make_evidence,
    make_finding, sha256_hex,
)
from reverseai.review import review

DATA = bytes(range(256)) * 4
INPUT = InputRef(sha256_hex(DATA), len(DATA), "app.zip")
JS = ToolRef("js", "0.1.0")
TOOLS = {"js": ToolSpec(JS, {name: OperationSpec(name, {}, lambda d, a: []) for name in
                             ("js.files", "js.package", "js.hints")})}
CASES = {
    ("javascript.files", "js.files", "js_file"): (
        {"file": "app/index.js", "size": 120, "sha256": "ab" * 32, "lines": 4, "max_line": 60, "flags": []},
        [("file", "a\nb"), ("size", -1), ("sha256", "AB" * 32), ("sha256", "ab"), ("lines", 122),
         ("max_line", 121), ("max_line", None)]),
    ("javascript.package", "js.package", "package_field"): (
        {"file": "package.json", "path": "/scripts/postinstall", "value": "node setup.js", "truncated": False},
        [("path", "scripts/postinstall"), ("path", ""), ("value", "a\nb"), ("value", "x" * 257),
         ("truncated", True), ("truncated", 0)]),
    ("javascript.hints", "js.hints", "js_hint"): (
        {"file": "", "category": "dynamic_code", "hint": "eval", "text": "eval(", "truncated": False},
        [("category", "behaviour"), ("hint", ""), ("hint", "x" * 65), ("text", ""), ("text", "x" * 300),
         ("truncated", True), ("file", "a\tb")]),
}


def judge(key, operation, kind, row):
    item = make_evidence(DATA, JS, operation, Observation(Location(0, 8), {"kind": kind, "index": 0, "total": 1, **row}))
    fields = claims.PAGES[kind][0]
    finding = make_finding("structural", "Rows.", key, {"start": 0, "total": 1, "rows": [[row[f] for f in fields]]},
                           [item.id], "observed")
    result = AnalysisResult(content_id("tk", {"k": key}), "structural", "ok", (item,), (finding,))
    return review(DATA, INPUT, [result], TOOLS)[0].status


class JavaScriptClaimTests(unittest.TestCase):
    def test_clean_file_line_statistics_have_exact_empty_and_nonempty_bounds(self):
        key, operation, kind = 'javascript.files', 'js.files', 'js_file'
        row = {'file': 'a.js', 'size': 1, 'sha256': 'ab' * 32, 'lines': 1, 'max_line': 1, 'flags': []}
        for size, lines, longest in ((0, 0, 0), (1, 1, 0), (1, 1, 1), (2, 2, 0), (2, 1, 2)):
            with self.subTest(valid=(size, lines, longest)):
                self.assertEqual(judge(key, operation, kind, {**row, 'size': size, 'lines': lines, 'max_line': longest}),
                                 'supported')
        for size, lines, longest in ((0, 1, 0), (1, 2, 0), (1, 0, 0), (1, 0, 1), (0, 0, 1),
                                     (2, 1, 3), (1, True, 0), (1, 1, False), (True, 1, 1)):
            with self.subTest(invalid=(size, lines, longest)):
                self.assertEqual(judge(key, operation, kind, {**row, 'size': size, 'lines': lines, 'max_line': longest}),
                                 'unsupported')

    def test_flagged_files_admit_only_sorted_known_flags_and_null_computed_metadata(self):
        key, operation, kind = 'javascript.files', 'js.files', 'js_file'
        row = {'file': '../a.js', 'size': 30 * 1024 * 1024, 'sha256': None, 'lines': None, 'max_line': None,
               'flags': ['ratio', 'too_large', 'traversing_name']}
        for flags in (['encrypted'], list(claims.MEMBER_FLAGS), row['flags']):
            with self.subTest(valid=flags):
                self.assertEqual(judge(key, operation, kind, {**row, 'flags': flags}), 'supported')
        for field, value in (('flags', []), ('flags', None), ('flags', ['unknown']), ('flags', ['crc', 'crc']),
                             ('flags', ['too_large', 'ratio']), ('flags', [True]), ('flags', [[]]),
                             ('sha256', 'ab' * 32), ('lines', 0), ('max_line', 0), ('size', -1)):
            with self.subTest(invalid=(field, value)):
                self.assertEqual(judge(key, operation, kind, {**row, field: value}), 'unsupported')

    def test_each_page_kind_accepts_its_row_and_refuses_each_bad_field(self):
        for (key, operation, kind), (row, bad) in CASES.items():
            self.assertIn(key, claims.PAGE_CLAIMS)
            self.assertEqual(judge(key, operation, kind, row), "supported", key)
            for field, value in bad:
                self.assertEqual(judge(key, operation, kind, {**row, field: value}), "unsupported", (key, field, value))

    def test_a_cut_value_is_exactly_256_characters(self):
        row = {"file": "package.json", "path": "/description", "value": "d" * 256, "truncated": True}
        self.assertEqual(judge("javascript.package", "js.package", "package_field", row), "supported")


if __name__ == "__main__":
    unittest.main()
