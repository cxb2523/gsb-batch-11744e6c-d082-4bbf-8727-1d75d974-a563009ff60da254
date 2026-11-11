"""Child artifacts: evidence inside a stored or deflated member, re-derived from the input."""

import unittest
import zlib

from reverseai import claims
from reverseai.contract import (
    AnalysisResult, AnalysisTask, Budget, ContractError, Evidence, InputRef, Location, Observation, OperationRequest,
    OperationSpec, ToolRef, ToolSpec, check_artifact, content_id, evidence_from_dict, evidence_id, evidence_intact,
    make_evidence, make_finding, materialize, sha256_hex,
)
from reverseai.gateway import Gateway
from reverseai.review import review

CHILD = b"dex\n035\x00" + bytes(range(200)) * 8 + b"ReverseAI marker\x00"
PACKED = zlib.compressobj(9, zlib.DEFLATED, -15)
DEFLATED = PACKED.compress(CHILD) + PACKED.flush()
PREFIX, GAP = b"PK\x03\x04" + bytes(26), b"\x00" * 7
DATA = PREFIX + DEFLATED + GAP + CHILD + b"trailer"
INPUT = InputRef(sha256_hex(DATA), len(DATA), "fixture.apk")
TOOL = ToolRef("dex", "0.1.0")


def artifact(method=8, **change):
    deflated = method == 8
    value = {"member": "classes.dex", "method": method,
             "data_offset": len(PREFIX) if deflated else len(PREFIX) + len(DEFLATED) + len(GAP),
             "compressed_size": len(DEFLATED) if deflated else len(CHILD), "size": len(CHILD),
             "crc32": zlib.crc32(CHILD), "sha256": sha256_hex(CHILD)}
    value.update(change)
    return value


MARKER = CHILD.index(b"ReverseAI marker")


def observation(art=None, offset=MARKER, length=16, **value):
    return Observation(Location(offset, length), value or {"kind": "marker"}, art if art is not None else artifact())


class MaterializeTests(unittest.TestCase):
    def test_stored_and_deflated_members_give_the_same_child(self):
        self.assertEqual(materialize(DATA, artifact(0)), CHILD)
        self.assertEqual(materialize(DATA, artifact(8)), CHILD)

    def test_every_declared_field_must_match_the_bytes(self):
        bad = [artifact(crc32=zlib.crc32(CHILD) ^ 1), artifact(sha256="0" * 64), artifact(size=len(CHILD) - 1),
               artifact(size=len(CHILD) + 1), artifact(data_offset=len(PREFIX) + 1),
               artifact(compressed_size=len(DEFLATED) - 1), artifact(compressed_size=len(DEFLATED) + 3),
               artifact(data_offset=len(DATA) - 4), artifact(0, size=len(CHILD) + 1),
               artifact(0, compressed_size=len(CHILD) - 1, size=len(CHILD) - 1)]
        for value in bad:
            with self.assertRaises(ContractError, msg=value):
                materialize(DATA, value)

    def test_shape_bounds_and_ratio_are_checked_before_any_inflate(self):
        for value in (artifact(method=12), artifact(member=""), artifact(member="a\nb"), artifact(member="x" * 256),
                      artifact(size=32 * 1024 * 1024 + 1), artifact(compressed_size=1), artifact(crc32=2**32),
                      artifact(sha256="ABC"), {**artifact(), "extra": 1}, artifact(size=True), "classes.dex"):
            with self.assertRaises(ContractError, msg=value):
                materialize(DATA, value)
        bomb = zlib.compressobj(9, zlib.DEFLATED, -15)
        zeros = bomb.compress(bytes(1 << 20)) + bomb.flush()
        data = zeros
        declared = {"member": "z", "method": 8, "data_offset": 0, "compressed_size": len(zeros), "size": 1 << 20,
                    "crc32": zlib.crc32(bytes(1 << 20)), "sha256": sha256_hex(bytes(1 << 20))}
        self.assertGreater(1 << 20, 100 * len(zeros))
        with self.assertRaises(ContractError):
            materialize(data, declared)


class ChildEvidenceTests(unittest.TestCase):
    def test_child_evidence_is_bound_to_the_child_bytes_and_keeps_contract2_ids(self):
        item = make_evidence(DATA, TOOL, "dex.classes", observation())
        self.assertEqual(item.excerpt_sha256, sha256_hex(b"ReverseAI marker"))
        self.assertEqual(item.artifact, artifact())
        self.assertTrue(evidence_intact(item))
        self.assertEqual(evidence_from_dict(item.to_dict()), item)
        plain = make_evidence(DATA, TOOL, "dex.classes", Observation(Location(0, 4), {"kind": "marker"}))
        self.assertNotIn("artifact", plain.to_dict())
        self.assertEqual(plain.id, evidence_id(plain.input_sha256, TOOL, "dex.classes", plain.location,
                                               plain.excerpt_sha256, plain.observation))
        with self.assertRaises(ContractError):
            make_evidence(DATA, TOOL, "dex.classes", observation(offset=len(CHILD) - 4, length=8))
        with self.assertRaises(ContractError):
            make_evidence(DATA, TOOL, "dex.classes", observation(artifact(crc32=1)))

    def test_the_reviewer_re_derives_the_child_and_refuses_one_that_does_not_match(self):
        operation = OperationSpec("dex.classes", {}, lambda data, args: [], max_observations=8)
        tools = {"dex": ToolSpec(TOOL, {"dex.classes": operation})}
        claims.RULES["test.marker"] = ("observed", {"dex.classes": lambda observations: "marker"})
        self.addCleanup(claims.RULES.pop, "test.marker")
        good = make_evidence(DATA, TOOL, "dex.classes", observation())
        stored = make_evidence(DATA, TOOL, "dex.classes", observation(artifact(0)))
        lie = artifact(crc32=zlib.crc32(CHILD) ^ 1)
        forged = Evidence(evidence_id(INPUT.sha256, TOOL, "dex.classes", good.location, good.excerpt_sha256,
                                      good.observation, lie), INPUT.sha256, TOOL, "dex.classes", good.location,
                          good.excerpt_sha256, good.observation, lie)
        shifted = make_evidence(DATA, TOOL, "dex.classes", observation(offset=MARKER + 1))
        moved = Evidence(evidence_id(INPUT.sha256, TOOL, "dex.classes", shifted.location, good.excerpt_sha256,
                                     shifted.observation, shifted.artifact), INPUT.sha256, TOOL, "dex.classes",
                         shifted.location, good.excerpt_sha256, shifted.observation, shifted.artifact)
        findings, evidence = [], []
        for item in (good, stored, forged, moved):
            findings.append(make_finding("structural", "Marker.", "test.marker", "marker", [item.id], "observed"))
            evidence.append(item)
        result = AnalysisResult(content_id("tk", {"t": "child"}), "structural", "ok", tuple(evidence), tuple(findings))
        verdicts = {v.finding_id: v for v in review(DATA, INPUT, [result], tools)}
        self.assertEqual([verdicts[f.id].status for f in findings], ["supported", "supported", "unsupported", "unsupported"])
        self.assertIn("child artifact does not match the input", verdicts[findings[2].id].reasons[0])
        self.assertIn("excerpt hash mismatch", verdicts[findings[3].id].reasons[0])

    def test_the_gateway_materializes_each_child_once_and_records_it(self):
        calls = []
        import reverseai.gateway as gateway_module
        real = gateway_module.materialize

        def counting(data, value, **options):
            calls.append(value["method"])
            return real(data, value, **options)

        def handler(data, args):
            return [observation(), observation(offset=0, length=4, kind="head"), observation(artifact(0), offset=0,
                                                                                           length=4, kind="head")]
        operation = OperationSpec("dex.classes", {}, handler)
        tools = (ToolSpec(TOOL, {"dex.classes": operation}),)
        task = AnalysisTask(content_id("tk", {"t": "gw"}), "structural", INPUT, (OperationRequest("dex.classes"),), Budget())
        gateway_module.materialize = counting
        try:
            result = Gateway(tools, Budget()).run(task, DATA)
        finally:
            gateway_module.materialize = real
        self.assertEqual(result.status, "ok")
        self.assertEqual(sorted(calls), [0, 8])
        self.assertEqual([item.artifact["method"] for item in result.evidence], [8, 8, 0])

    def test_a_tool_that_names_a_child_not_in_the_input_fails_its_operation(self):
        operation = OperationSpec("dex.classes", {}, lambda data, args: [observation(artifact(sha256="1" * 64))])
        task = AnalysisTask(content_id("tk", {"t": "bad"}), "structural", INPUT, (OperationRequest("dex.classes"),), Budget())
        result = Gateway((ToolSpec(TOOL, {"dex.classes": operation}),), Budget()).run(task, DATA)
        self.assertEqual((result.status, result.evidence), ("error", ()))


class AndroidClaimTests(unittest.TestCase):
    def test_android_pages_and_permissions(self):
        dex = ToolRef("dex", "0.1.0")
        apk = ToolRef("apk", "0.1.0")
        tools = {"dex": ToolSpec(dex, {name: OperationSpec(name, {}, lambda d, a: []) for name in
                                        ("dex.classes", "dex.methods", "dex.references")}),
                 "apk": ToolSpec(apk, {name: OperationSpec(name, {}, lambda d, a: []) for name in
                                        ("apk.inventory", "apk.manifest")})}

        def judge(key, value, cited):
            finding = make_finding("structural", "A claim.", key, value, [item.id for item in cited], "observed")
            result = AnalysisResult(content_id("tk", {"k": key}), "structural", "ok", tuple(cited), (finding,))
            return review(DATA, INPUT, [result], tools)[0].status

        def row(offset, **value):
            return make_evidence(DATA, dex, "dex.classes", observation(offset=offset, length=4, **value))

        cls = row(0, kind="class", index=0, total=1, dex="classes.dex", name="Lorg/reverseai/fixture/Marker;",
                  access=1, superclass="Ljava/lang/Object;", interfaces=[], interfaces_total=0, source_file=None)
        value = {"start": 0, "total": 1, "rows": [["classes.dex", "Lorg/reverseai/fixture/Marker;", 1, "Ljava/lang/Object;"]]}
        self.assertEqual(judge("android.classes", value, [cls]), "supported")
        odd = row(0, kind="class", index=0, total=1, dex="classes.dex", name="Lx;", access=1, superclass=None,
                  interfaces="Ly;", interfaces_total=1, source_file=None)
        self.assertEqual(judge("android.classes", {"start": 0, "total": 1, "rows": [["classes.dex", "Lx;", 1, None]]},
                               [odd]), "unsupported")

        def attribute(offset, element, name, kind, val, element_index=1, index=0, total=2):
            return make_evidence(DATA, apk, "apk.manifest", Observation(Location(offset, 20), {
                "kind": "manifest_attribute", "index": index, "total": total, "element_index": element_index,
                "element": element, "attribute": name, "type": kind, "value": val}, artifact()))

        internet = attribute(0, "uses-permission", "android:name", "string", "android.permission.INTERNET")
        contacts = attribute(20, "uses-permission", "android:name", "string", "android.permission.READ_CONTACTS",
                             element_index=2, index=1)
        self.assertEqual(judge("android.permissions", ["android.permission.INTERNET", "android.permission.READ_CONTACTS"],
                               [contacts, internet]), "supported")
        package = attribute(40, "manifest", "package", "string", "org.reverseai.fixture", element_index=0)
        self.assertEqual(judge("android.permissions", ["org.reverseai.fixture"], [package]), "unsupported")
        page = {"start": 0, "total": 2, "rows": [[1, "uses-permission", "android:name", "string",
                                                  "android.permission.INTERNET"],
                                                 [2, "uses-permission", "android:name", "string",
                                                  "android.permission.READ_CONTACTS"]]}
        self.assertEqual(judge("android.manifest", page, [internet, contacts]), "supported")
        wrong_type = attribute(0, "manifest", "android:versionCode", "int", "7", element_index=0, total=1)
        self.assertEqual(judge("android.manifest", {"start": 0, "total": 1, "rows": [
            [0, "manifest", "android:versionCode", "int", "7"]]}, [wrong_type]), "unsupported")


class AndroidReviewerFixTests(unittest.TestCase):
    """Valid empty source files, malformed member flags refused without failing, permission subsets."""

    def setUp(self):
        self.dex, self.apk = ToolRef("dex", "0.1.0"), ToolRef("apk", "0.1.0")
        self.tools = {"dex": ToolSpec(self.dex, {"dex.classes": OperationSpec("dex.classes", {}, lambda d, a: [])}),
                      "apk": ToolSpec(self.apk, {name: OperationSpec(name, {}, lambda d, a: [])
                                                 for name in ("apk.inventory", "apk.manifest")})}

    def judge(self, findings, evidence):
        result = AnalysisResult(content_id("tk", {"t": "fix"}), "structural", "ok", tuple(evidence), tuple(findings))
        verdicts = {v.finding_id: v.status for v in review(DATA, INPUT, [result], self.tools)}
        return [verdicts[f.id] for f in findings]

    def test_an_empty_source_file_is_a_valid_dex_value(self):
        row = make_evidence(DATA, self.dex, "dex.classes", observation(offset=0, length=4, kind="class", index=0, total=1,
            dex="classes.dex", name="Lx;", access=1, superclass=None, interfaces=[], interfaces_total=0, source_file=""))
        finding = make_finding("structural", "Classes.", "android.classes",
                               {"start": 0, "total": 1, "rows": [["classes.dex", "Lx;", 1, None]]}, [row.id], "observed")
        self.assertEqual(self.judge([finding], [row]), ["supported"])

    def test_malformed_member_flags_are_refused_not_raised(self):
        for flags in ([[]], [{}], ["crc", 1], [None], "crc"):
            row = make_evidence(DATA, self.apk, "apk.inventory", Observation(Location(0, 4), {
                "kind": "member", "index": 0, "total": 1, "name": "x", "method": 8, "compressed_size": 1, "size": 1,
                "crc32": 0, "sha256": None, "flags": flags}))
            finding = make_finding("structural", "Members.", "android.members", {"start": 0, "total": 1, "rows": [
                ["x", 8, 1, 1, 0, None, flags]]}, [row.id], "observed")
            self.assertEqual(self.judge([finding], [row]), ["unsupported"], flags)

    def test_permission_subsets_never_contradict(self):
        def permission(offset, name, element_index):
            return make_evidence(DATA, self.apk, "apk.manifest", Observation(Location(offset, 20), {
                "kind": "manifest_attribute", "index": element_index, "total": 70, "element_index": element_index,
                "element": "uses-permission", "attribute": "android:name", "type": "string", "value": name}, artifact()))
        first, second = permission(0, "android.permission.A", 1), permission(20, "android.permission.B", 2)
        a = make_finding("structural", "Permissions.", "android.permissions", ["android.permission.A"], [first.id], "observed")
        b = make_finding("structural", "Permissions.", "android.permissions", ["android.permission.B"], [second.id], "observed")
        self.assertEqual(self.judge([a, b], [first, second]), ["supported", "supported"])

    def test_permission_page_metadata_must_be_coherent(self):
        # One total, distinct indexes below it.
        def permission(offset, name, index, total):
            return make_evidence(DATA, self.apk, "apk.manifest", Observation(Location(offset, 20), {
                "kind": "manifest_attribute", "index": index, "total": total, "element_index": index,
                "element": "uses-permission", "attribute": "android:name", "type": "string", "value": name}, artifact()))
        for pair in ((permission(0, "p.A", 1, 5), permission(20, "p.B", 2, 5)),):
            good = make_finding("structural", "P.", "android.permissions", ["p.A", "p.B"], [i.id for i in pair], "observed")
            self.assertEqual(self.judge([good], list(pair)), ["supported"])
        for bad in ((permission(0, "p.A", 5, 5), permission(20, "p.B", 2, 5)),
                    (permission(0, "p.A", 1, 5), permission(20, "p.B", 2, 6)),
                    (permission(0, "p.A", 1, 5), permission(20, "p.B", 1, 5))):
            finding = make_finding("structural", "P.", "android.permissions", ["p.A", "p.B"], [i.id for i in bad], "observed")
            self.assertEqual(self.judge([finding], list(bad)), ["unsupported"])


class SharedFindingTests(unittest.TestCase):
    def test_a_finding_in_two_tasks_is_judged_the_same_whatever_the_order(self):
        # It joins every producing task's page family.
        structure = ToolRef("structure", "0.1.0")
        tools = {"structure": ToolSpec(structure, {"structure.segments": OperationSpec("structure.segments", {},
                                                                                       lambda d, a: [])})}

        def segment(index, total, name="LOAD"):
            return make_evidence(DATA, structure, "structure.segments", Observation(Location(index * 8, 8), {
                "kind": "segment", "index": index, "total": total, "name": name, "offset": 0, "filesz": 1,
                "address": 0, "memsz": 1, "readable": True, "writable": False, "executable": False}))

        def page(rows):
            value = {"start": rows[0].observation["index"], "total": rows[0].observation["total"], "rows": [
                [r.observation[k] for k in ("name", "offset", "filesz", "address", "memsz", "readable", "writable",
                                            "executable")] for r in rows]}
            return make_finding("structural", "Segments.", "segments.list", value, [r.id for r in rows], "observed")

        f_rows, g_rows = [segment(0, 2)], [segment(1, 3)]
        f, g = page(f_rows), page(g_rows)
        a = AnalysisResult(content_id("tk", {"t": "a"}), "structural", "ok", tuple(f_rows), (f,))
        b = AnalysisResult(content_id("tk", {"t": "b"}), "structural", "ok", tuple(f_rows + g_rows), (f, g))
        for order in ([a, b], [b, a]):
            judged = {v.finding_id: v.status for v in review(DATA, INPUT, order, tools)}
            self.assertEqual((judged[f.id], judged[g.id]), ("contradicted", "contradicted"))


class ReviewerBudgetAndShapeTests(unittest.TestCase):
    """Failed children spend the budget; each guard pinned alone."""

    def test_the_child_size_cap_holds_on_its_own(self):
        cap = 32 * 1024 * 1024
        check_artifact(artifact(0, compressed_size=cap, size=cap))
        with self.assertRaises(ContractError):  # stored, so the ratio cannot be what refuses it
            check_artifact(artifact(0, compressed_size=cap + 1, size=cap + 1))

    def test_failed_children_spend_the_review_budget_and_stay_cached(self):
        import reverseai.review as review_module
        operation = OperationSpec("dex.classes", {}, lambda data, args: [])
        tools = {"dex": ToolSpec(TOOL, {"dex.classes": operation})}
        claims.RULES["test.marker"] = ("observed", {"dex.classes": lambda observations: "marker"})
        self.addCleanup(claims.RULES.pop, "test.marker")
        good = make_evidence(DATA, TOOL, "dex.classes", observation())

        def wrong(member):  # range, size and CRC right, hash wrong: the child is inflated before it fails
            art = artifact(member=member, sha256="0" * 64)
            return Evidence(evidence_id(INPUT.sha256, TOOL, "dex.classes", good.location, good.excerpt_sha256,
                                        good.observation, art), INPUT.sha256, TOOL, "dex.classes", good.location,
                            good.excerpt_sha256, good.observation, art)
        evidence = [wrong("a.dex"), wrong("a.dex"), wrong("b.dex"), wrong("c.dex"), good]
        findings = [make_finding("structural", "Marker %d." % i, "test.marker", "marker", [item.id], "observed")
                    for i, item in enumerate(evidence)]
        calls, real, budget = [], review_module.materialize, review_module.MAX_REVIEW_CHILD_BYTES

        def counting(data, value, **options):
            calls.append(value["member"])
            return real(data, value, **options)
        review_module.materialize, review_module.MAX_REVIEW_CHILD_BYTES = counting, 2 * len(CHILD)
        try:
            result = AnalysisResult(content_id("tk", {"t": "budget"}), "structural", "ok", tuple(evidence), tuple(findings))
            verdicts = {v.finding_id: v for v in review(DATA, INPUT, [result], tools)}
        finally:
            review_module.materialize, review_module.MAX_REVIEW_CHILD_BYTES = real, budget
        self.assertEqual(calls, ["a.dex", "b.dex"])
        self.assertEqual([verdicts[f.id].status for f in findings], ["unsupported"] * 5)
        self.assertIn("exceed the review budget", verdicts[findings[3].id].reasons[0])
        self.assertIn("exceed the review budget", verdicts[findings[4].id].reasons[0])

    def test_member_method_and_reference_rows_refuse_each_bad_field(self):
        dex, apk = ToolRef("dex", "0.1.0"), ToolRef("apk", "0.1.0")
        tools = {"dex": ToolSpec(dex, {name: OperationSpec(name, {}, lambda d, a: [])
                                       for name in ("dex.methods", "dex.references")}),
                 "apk": ToolSpec(apk, {"apk.inventory": OperationSpec("apk.inventory", {}, lambda d, a: [])})}
        cases = {
            ("android.members", apk, "apk.inventory", "member"): (
                {"name": "classes.dex", "method": 8, "compressed_size": 10, "size": 20, "crc32": 7, "sha256": None,
                 "flags": ["crc", "ratio"]},
                [("name", ""), ("name", "a\nb"), ("method", 2**16), ("compressed_size", -1), ("size", True),
                 ("crc32", 2**32), ("sha256", "ab"), ("sha256", "A" * 64), ("flags", ["ratio", "crc"]),
                 ("flags", ["crc", "crc"]), ("flags", ["unknown"]), ("flags", "crc")]),
            ("android.methods", dex, "dex.methods", "method"): (
                {"dex": "classes.dex", "class": "Lx;", "name": "run", "prototype": "()V", "access": 1,
                 "code_offset": 112, "code_units": 4},
                [("dex", ""), ("class", "L\n;"), ("name", ""), ("prototype", "x" * 256), ("access", -1),
                 ("code_offset", -1), ("code_units", None), ("code_units", "4")]),
            ("android.references", dex, "dex.references", "dex_ref"): (
                {"dex": "classes.dex", "from_class": "Lx;", "from_method": "run", "from_prototype": "()V", "at": 8,
                 "ref_kind": "string", "target": "s" * 256, "target_truncated": True},
                [("dex", ""), ("from_class", ""), ("from_method", "a\tb"), ("from_prototype", ""), ("at", -1),
                 ("ref_kind", "class"), ("target", "s" * 513), ("target", "a\nb"), ("target_truncated", 1),
                 ("target", "s" * 255), ("ref_kind", "method")]),
        }
        for (key, ref, operation, kind), (row, bad) in cases.items():
            fields = claims.PAGES[kind][0]

            def judge(value):
                item = make_evidence(DATA, ref, operation, Observation(Location(0, 4), {
                    "kind": kind, "index": 0, "total": 1, **value}, artifact()))
                finding = make_finding("structural", "Rows.", key, {"start": 0, "total": 1, "rows": [
                    [value[field] for field in fields]]}, [item.id], "observed")
                result = AnalysisResult(content_id("tk", {"k": key}), "structural", "ok", (item,), (finding,))
                return review(DATA, INPUT, [result], tools)[0].status
            self.assertEqual(judge(row), "supported", key)
            for field, value in bad:
                self.assertEqual(judge({**row, field: value}), "unsupported", (key, field, value))


if __name__ == "__main__":
    unittest.main()
