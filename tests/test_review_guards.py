"""Isolated reviewer guards for package-pointer bounds and permission page metadata."""

import unittest

from reverseai.contract import (
    AnalysisResult, InputRef, Location, Observation, OperationSpec, ToolRef, ToolSpec, content_id, make_evidence,
    make_finding, sha256_hex,
)
from reverseai.review import review

DATA = bytes(range(256)) * 4
INPUT = InputRef(sha256_hex(DATA), len(DATA), "fixture.bin")


def verdict(tool, operation, observation, key, value):
    ref = ToolRef(tool, "0.1.0")
    tools = {tool: ToolSpec(ref, {operation: OperationSpec(operation, {}, lambda d, a: [])})}
    item = make_evidence(DATA, ref, operation, Observation(Location(0, 8), observation))
    finding = make_finding("structural", "Rows.", key, value, [item.id], "observed")
    result = AnalysisResult(content_id("tk", {"k": key}), "structural", "ok", (item,), (finding,))
    return review(DATA, INPUT, [result], tools)[0].status


class ReviewerGuardTests(unittest.TestCase):
    def test_a_package_pointer_longer_than_255_characters_is_refused(self):
        for path, expected in (("/" + "p" * 254, "supported"), ("/" + "p" * 255, "unsupported")):
            row = {"file": "package.json", "path": path, "value": "x", "truncated": False}
            page = {"start": 0, "total": 1, "rows": [["package.json", path, "x", False]]}
            self.assertEqual(verdict("js", "js.package", {"kind": "package_field", "index": 0, "total": 1, **row},
                                     "javascript.package", page), expected, len(path))

    def test_permission_index_and_total_must_be_integers_not_booleans(self):
        def attribute(index, total):
            return {"kind": "manifest_attribute", "index": index, "total": total, "element_index": 1,
                    "element": "uses-permission", "attribute": "android:name", "type": "string", "value": "p.A"}
        self.assertEqual(verdict("apk", "apk.manifest", attribute(0, 1), "android.permissions", ["p.A"]), "supported")
        for index, total in ((False, 1), (0, True), (True, 2)):
            self.assertEqual(verdict("apk", "apk.manifest", attribute(index, total), "android.permissions", ["p.A"]),
                             "unsupported", (index, total))


if __name__ == "__main__":
    unittest.main()
