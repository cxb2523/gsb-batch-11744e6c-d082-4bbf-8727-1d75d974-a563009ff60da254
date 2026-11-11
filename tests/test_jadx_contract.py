"""Identity arguments for contained tools and the derived android.java claim."""

import unittest

from reverseai import claims
from reverseai.contract import (
    AnalysisResult, ArgSpec, ContractError, InputRef, Location, Observation, OperationSpec, ToolRef, ToolSpec,
    content_id, make_evidence, make_finding, sha256_hex,
)
from reverseai.review import review

DATA = bytes(range(256)) * 4
INPUT = InputRef(sha256_hex(DATA), len(DATA), "fixture.apk")
JADX = ToolRef("jadx", "1.5.6-r1")
ROW = {"dex": "classes.dex", "class": "Lorg/reverseai/fixture/Helper;", "name": "compute", "prototype": "(II)I",
       "form": "java", "start": 0, "total": 52, "text": "public static int compute(int i, int i2) {\n\treturn i + i2;\n}"[:52]}


def tools(derived=True):
    operation = OperationSpec("jadx.method", {}, lambda data, args: [], max_observations=16, derived=derived)
    return {"jadx": ToolSpec(JADX, {"jadx.method": operation})}


def judge(value, spec=None):
    item = make_evidence(DATA, JADX, "jadx.method", Observation(Location(0, 16), {"kind": "java", **value}))
    finding = make_finding("code", "Java.", "android.java", value, [item.id], "inferred")
    result = AnalysisResult(content_id("tk", {"t": "java"}), "code", "ok", (item,), (finding,))
    return review(DATA, INPUT, [result], spec or tools())[0].status


class IdentityArgumentTests(unittest.TestCase):
    def test_identity_is_printable_ascii_and_contained_tools_may_declare_it(self):
        identity = ArgSpec("identity", 0, 255, default="")
        for good in ("", "Lcom/obf/\\xe9\\u200b;", "-x", "(II)I", "<init>", "~" * 255):
            self.assertEqual(identity.check(good), good)
        for bad in ("café", "a\nb", "\x7f", "x" * 256, 7, None):
            with self.assertRaises(ContractError):
                identity.check(bad)
        self.assertEqual(ArgSpec("identity", 1, 255).check("L;"), "L;")
        with self.assertRaises(ContractError):
            ArgSpec("identity", 1, 255).check("")
        method = OperationSpec("jadx.method", {"class": ArgSpec("identity", 1, 255)}, lambda d, a: [], derived=True)
        ToolSpec(JADX, {"jadx.method": method}, contained=True)
        literal = OperationSpec("jadx.method", {"class": ArgSpec("literal", 1, 255)}, lambda d, a: [], derived=True)
        with self.assertRaises(ContractError):
            ToolSpec(JADX, {"jadx.method": literal}, contained=True)
        with self.assertRaises(ContractError):  # The contract bound is 255
            ArgSpec("identity", 0, 256)


class JavaClaimTests(unittest.TestCase):
    def test_a_well_formed_java_page_is_derived_even_under_a_misregistered_spec(self):
        self.assertEqual(judge(ROW), "derived")
        self.assertEqual(judge(ROW, tools(derived=False)), "derived")
        self.assertIn("android.java", claims.DERIVED_CLAIMS)
        self.assertEqual(judge({**ROW, "form": "error", "text": "", "start": 0, "total": 0}), "derived")
        self.assertEqual(judge({**ROW, "form": "fallback", "start": 10, "total": 62}), "derived")
        self.assertEqual(judge({**ROW, "form": "omitted", "text": "", "start": 0, "total": 0}), "derived")

    def test_each_malformed_field_is_refused(self):
        bad = [("dex", ""), ("class", "Lé;"), ("prototype", ""), ("form", "smali"), ("start", -1),
               ("total", 51), ("text", "café"), ("text", "a\rb"), ("text", "x" * 2049)]
        for field, value in bad:
            self.assertEqual(judge({**ROW, field: value}), "unsupported", (field, value))
        self.assertEqual(judge({**ROW, "form": "error"}), "unsupported")
        self.assertEqual(judge({**ROW, "form": "omitted"}), "unsupported")  # No text
        self.assertEqual(judge({**ROW, "extra": 1}), "unsupported")


if __name__ == "__main__":
    unittest.main()
