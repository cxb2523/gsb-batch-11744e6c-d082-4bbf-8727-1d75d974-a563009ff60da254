from dataclasses import replace
import json
import unittest

from reverseai import pipeline, report
from reverseai.report import Analysis
from reverseai.contract import (
    AnalysisResult, InputRef, Location, Observation, ReviewVerdict, ToolRef, make_evidence, make_finding, sha256_hex,
)

DATA = b"MZ" + bytes(62) + b"http://example.invalid/a|b`c\x00"
TOOL = ToolRef("strings", "0.1.0")


def analysis(verdict_status="supported"):
    evidence = make_evidence(DATA, TOOL, "strings.extract", Observation(Location(64, 27), {"text": "http://example.invalid/a|b`c"}))
    finding = make_finding("capability", "The input contains a URL.", "strings.urls", ["http://example.invalid/a|b`c"], [evidence.id])
    orphan = make_finding("capability", "Claim with no evidence.", "capability.network", ["net"], [], "inferred")
    result = AnalysisResult("tk-0123456789abcdef", "capability", "ok", (evidence,), (finding, orphan))
    verdicts = (
        ReviewVerdict(finding.id, verdict_status, () if verdict_status == "supported" else ("cited evidence failed",)),
        ReviewVerdict(orphan.id, "unsupported", ("no evidence cited",)),
    )
    ref = InputRef(sha256_hex(DATA), len(DATA), "sample.exe")
    return Analysis(ref, (TOOL,), (result,), verdicts)


def code_analysis(*, status="derived", instruction="MOV rax, [message]", name="message", text="hello"):
    tool = ToolRef("ghidra", "12.1.4-r5")
    values = (
        (Location(8, 16), {"kind": "assembly", "index": 0, "entry": 0x1000,
                          "instructions": [[2, 3, instruction]], "truncated": True}, "code.assembly",
         {"entry": 0x1000, "instructions": [[2, 3, instruction]], "truncated": True}),
        (Location(10, 3), {"kind": "ref", "from": 0x1000, "to": 0x2000, "type": "read", "to_name": name},
         "code.references", [[0x1000, "read", 0x2000, name]]),
        (Location(64, len(text)), {"kind": "string", "address": 0x2000, "encoding": "ascii", "text": text,
                                 "truncated": False, "from": [0x1000]}, "code.strings",
         [{"address": 0x2000, "encoding": "ascii", "text": text, "truncated": False, "from": [0x1000]}]),
    )
    evidence = tuple(make_evidence(DATA, tool, "ghidra.analyze", Observation(location, value))
                     for location, value, _, _ in values)
    findings = tuple(make_finding("code", "Tool interpretation.", key, value, [item.id], "inferred")
                     for item, (_, _, key, value) in zip(evidence, values))
    result = AnalysisResult("tk-0123456789abcdef", "code", "ok", evidence, findings)
    return Analysis(InputRef(sha256_hex(DATA), len(DATA), "inline"), (tool,), (result,),
                    tuple(ReviewVerdict(f.id, status, ("Tool reading; not verified.",)) for f in findings))


def android_query(name, args, layout_change=None):
    from tests import fixtures_apk
    from tests.test_queries import android_standins
    data, layout = fixtures_apk.apk_basic()
    if layout_change:
        layout_change(layout)
    ref = InputRef(sha256_hex(data), len(data), "fixture.apk")
    return pipeline.query_bytes(data, ref, name, args, tools=android_standins(layout))


class ReportTests(unittest.TestCase):
    def test_json_is_deterministic_and_complete(self):
        first, second = report.to_json(analysis()), report.to_json(analysis())
        self.assertEqual(first, second)
        data = json.loads(first)
        self.assertEqual(data["contract"], "reverseai.contract/3")
        self.assertEqual(data["input"]["sha256"], sha256_hex(DATA))
        self.assertEqual(data["summary"], {"supported": 1, "derived": 0, "unsupported": 1, "contradicted": 0, "unreviewed": 0})
        verdicts = {f["claim_key"]: f["verdict"] for f in data["results"][0]["findings"]}
        self.assertEqual(verdicts, {"strings.urls": "supported", "capability.network": "unsupported"})

    def test_unreviewed_findings_are_counted_not_hidden(self):
        partial = analysis()
        partial = Analysis(partial.input, partial.tools, partial.results, partial.verdicts[:1])
        data = report.to_dict(partial)
        self.assertEqual(data["summary"]["unreviewed"], 1)

    def test_markdown_separates_rejected_claims_and_escapes_cells(self):
        text = report.to_markdown(analysis())
        supported, rejected = text.split("## Rejected or unreviewed claims")
        self.assertIn("URL strings in the input", supported)
        self.assertNotIn("The input contains a URL.", supported)
        self.assertIn("strings.extract @ 64+27", supported)
        self.assertIn("Claim with no evidence.", rejected)
        self.assertNotIn("Claim with no evidence.", supported)
        self.assertIn("a\\|b'c", supported)
        self.assertIn("The sample was not executed.", text)

    def test_cells_are_inert_code_spans(self):
        self.assertEqual(report._cell("x" * 300), "`" + "x" * 199 + "…`")
        self.assertEqual(report._cell("a|b`c"), "`a\\|b'c`")
        self.assertEqual(report._cell("\udcff\x00"), "`\ufffd\ufffd`")
        self.assertEqual(report._cell(""), "-")

    def test_analyst_prose_is_never_shown_as_a_verified_statement(self):
        data = report.to_dict(analysis())
        urls = [f for f in data["results"][0]["findings"] if f["claim_key"] == "strings.urls"][0]
        self.assertEqual((urls["claim"], urls["statement"]), ("The input contains a URL.", "URL strings in the input"))
        self.assertEqual(report.claims.statement("capability.ransomware"), "No claim rule")

    def test_no_supported_findings(self):
        text = report.to_markdown(analysis("unsupported"))
        self.assertIn("No finding was supported by the evidence.", text)

    def test_m3c_markdown_has_full_readable_derived_details_and_exact_json_values(self):
        original = code_analysis()
        text = report.to_markdown(original)
        supported, derived = text.split("## Derived by analysis tools (not verified against the bytes)")
        self.assertNotIn("MOV rax", supported)
        for marker in ("### Assembly (derived)", "### References (derived)", "### Referenced strings (derived)",
                       "| File offset | Length | Instruction |", "| `10` | `3` | `MOV rax, [message]` |",
                       "`message`", "`hello`", "`ascii`", "`0x1000`", "`0x2000`"):
            self.assertIn(marker, derived)
        self.assertIn("Truncated: `true`", derived)
        parsed = json.loads(report.to_json(original))
        self.assertEqual([f["value"] for f in parsed["results"][0]["findings"]],
                         [f.value for f in original.results[0].findings])

    def test_code_detail_addresses_are_hex_but_file_offsets_and_lengths_stay_decimal(self):
        text = report.to_markdown(code_analysis())
        self.assertIn("#### Function at `0x1000`", text)
        self.assertIn("| `0x1000` | `read` | `0x2000` | `message` |", text)
        self.assertIn('| `0x2000` | `ascii` | `hello` | `false` | `["0x1000"]` |', text)
        self.assertIn("| `10` | `3` | `MOV rax, [message]` |", text)

    def test_generic_m3c_values_format_only_addresses_without_mutating_json(self):
        original = code_analysis(instruction="MOV rax, 4096", name="8192", text="4096")
        before = report.to_json(original)
        generic = report.to_markdown(original).split("### Assembly (derived)")[0]
        expected = (
            {"entry": "0x1000", "instructions": [[2, 3, "MOV rax, 4096"]], "truncated": True},
            [["0x1000", "read", "0x2000", "8192"]],
            [{"address": "0x2000", "encoding": "ascii", "text": "4096", "truncated": False, "from": ["0x1000"]}],
        )
        for value in expected:
            self.assertIn(report._cell(value), generic)
        self.assertEqual(report.to_json(original), before)
        values = [f["value"] for f in json.loads(before)["results"][0]["findings"]]
        self.assertEqual(values[0]["entry"], 4096)
        self.assertEqual(values[1][0][2], 8192)
        self.assertEqual(values[2][0]["from"], [4096])

    def test_legacy_code_values_use_lowercase_hex_including_zero_and_uint64(self):
        original = code_analysis()
        result, = original.results
        values = (
            ("code.functions", ["4096"]),
            ("code.calls", [[0xFFFFFFFFFFFFFFFF, "8192"]]),
            ("code.pseudocode", {"entry": 0, "text": "return 4096;", "truncated": False}),
        )
        findings = tuple(make_finding("code", "Tool reading.", key, value, [result.evidence[0].id], "inferred")
                         for key, value in values)
        changed = Analysis(original.input, original.tools,
                           (AnalysisResult(result.task_id, "code", "ok", result.evidence, findings),),
                           tuple(ReviewVerdict(f.id, "derived", ("Tool reading; not verified.",)) for f in findings))
        before = report.to_json(changed)
        text = report.to_markdown(changed)
        for value in (["4096"], [["0xffffffffffffffff", "8192"]],
                      {"entry": "0x0", "text": "return 4096;", "truncated": False}):
            self.assertIn(report._cell(value), text)
        self.assertEqual(report.to_json(changed), before)
        parsed = json.loads(before)["results"][0]["findings"]
        self.assertEqual(parsed[1]["value"], [[18446744073709551615, "8192"]])
        self.assertEqual(parsed[2]["value"]["entry"], 0)

    def test_m3c_detail_cells_keep_hostile_text_inert(self):
        text = report.to_markdown(code_analysis(instruction="`<img src=x>|\nRET", name="[x](https://evil.invalid)",
                                               text="![p](x)`|"))
        import re
        count = 0
        for line in text.splitlines():
            if not line.startswith("|"):
                continue
            for cell in re.split(r"(?<!\\)\|", line)[1:-1]:
                cell = cell.strip()
                if any(marker in cell for marker in ("<img", "](", "RET")):
                    count += 1
                    self.assertTrue(cell.startswith("`") and cell.endswith("`") and "`" not in cell[1:-1], cell)
        self.assertGreaterEqual(count, 3)

    def test_rejected_or_unreviewed_code_never_gets_derived_detail_tables(self):
        for status in ("unsupported", "unreviewed"):
            original = code_analysis(status="unsupported")
            if status == "unreviewed":
                original = Analysis(original.input, original.tools, original.results, ())
            text = report.to_markdown(original)
            self.assertNotIn("### Assembly", text)
            self.assertNotIn("### References", text)
            self.assertNotIn("### Referenced strings", text)

    def test_assembly_offsets_resolve_only_its_own_result_evidence(self):
        original = code_analysis()
        result, = original.results
        isolated = AnalysisResult(result.task_id, result.role, result.status, (), result.findings)
        foreign = AnalysisResult("tk-fedcba9876543210", "code", "ok", result.evidence, ())
        changed = Analysis(original.input, original.tools, (isolated, foreign), original.verdicts)
        text = report.to_markdown(changed)
        self.assertNotIn("| `10` | `3` |", text)

    def test_query_instruction_page_is_complete_paged_hex_and_inert_without_json_mutation(self):
        original = code_analysis()
        result, = original.results
        value = {"entry": 0x1000, "start": 64, "total": 100,
                 "rows": [[16, 1, "RET`|<img src=x>"], [17, 2, "CALL [4096]"]], "truncated": True}
        finding = make_finding("code", "Tool reading.", "code.instructions", value, [result.evidence[0].id], "inferred")
        current = Analysis(original.input, original.tools,
                           (AnalysisResult(result.task_id, "code", "ok", result.evidence, (finding,)),),
                           (ReviewVerdict(finding.id, "derived", ("Tool reading.",)),), (),
                           {"name": "procedure_assembly", "args": {"entry": 0x1000, "start": 64}})
        before = report.to_json(current)
        text = report.to_markdown(current)
        for marker in ('"entry":"0x1000"', "rows 64..65 of 100", "Next start: 66", "Truncated: `true`",
                       "| 64 | `0x1010` | `1` | `RET'\\|<img src=x>` |", "| 65 | `0x1011` | `2` | `CALL [4096]` |"):
            self.assertIn(marker, text)
        self.assertEqual(report.to_json(current), before)
        parsed = json.loads(before)
        self.assertEqual(parsed["query"]["args"]["entry"], 4096)
        self.assertEqual(parsed["results"][0]["findings"][0]["value"], value)

    def test_complete_query_page_has_no_next_start_and_addresses_are_hex(self):
        original = code_analysis()
        result, = original.results
        value = {"start": 9, "total": 10, "rows": [["<img src=x>|`", 0x2000, "func", "global", True]]}
        finding = make_finding("structural", "Reading.", "symbols.list", value, [result.evidence[0].id])
        current = Analysis(original.input, original.tools,
                           (AnalysisResult(result.task_id, "structural", "ok", result.evidence, (finding,)),),
                           (ReviewVerdict(finding.id, "supported", ()),), (), {"name": "list_names", "args": {"query": "x"}})
        text = report.to_markdown(current)
        self.assertIn("rows 9..9 of 10", text)
        self.assertNotIn("Next start:", text)
        self.assertIn("| 9 | `<img src=x>\\|'` | `0x2000` | `func` | `global` | `true` |", text)

    def test_android_evidence_names_its_member_and_child_offset(self):
        analysis = android_query("inspect_android_package", {})
        text = report.to_markdown(analysis)
        self.assertIn("apk.inventory @ ", text)  # central directory entries are in the input itself
        self.assertIn("apk.manifest in `AndroidManifest.xml` @ 0x", text)
        evidence = report.to_dict(analysis)["results"][0]["evidence"]
        manifest = [e for e in evidence if e["operation"] == "apk.manifest"]
        self.assertEqual({e["artifact"]["member"] for e in manifest}, {"AndroidManifest.xml"})
        self.assertIn(f"apk.manifest in `AndroidManifest.xml` @ {hex(manifest[0]['location']['offset'])}+20", text)
        self.assertTrue(all("artifact" not in e for e in evidence if e["operation"] == "apk.inventory"))

    def test_android_pages_are_readable_and_json_keeps_raw_values(self):
        analysis = android_query("inspect_android_package", {})
        text = report.to_markdown(analysis)
        self.assertIn("### Members the package's ZIP central directory declares (one page)", text)
        self.assertIn("| Index | Name | Method | Compressed size | Size | CRC-32 | SHA-256 | Flags |", text)
        self.assertRegex(text, r"\| 1 \| `classes.dex` \| `deflate` \| `730` \| `1228` \| `0x[0-9a-f]{8}` \| `[0-9a-f]{64}` \| `-` \|")
        self.assertRegex(text, r"\| 2 \| `classes2.dex` \| `stored` \|")
        self.assertIn("### Permissions the Android manifest declares (not evidence of use)", text)
        self.assertIn("- `android.permission.INTERNET`", text)
        self.assertIn("| 7 | `4` | `application` | `android:label` | `reference` | `@0x7f010000` |", text)
        self.assertIn("| 11 | `6` | `service` | `android:exported` | `bool` | `false` |", text)
        members = [f for f in report.to_dict(analysis)["results"][0]["findings"] if f["claim_key"] == "android.members"]
        self.assertEqual(members[0]["value"]["rows"][1][1:3], [8, 730])

        text = report.to_markdown(android_query("inspect_android_class", {"member": "classes.dex",
                                                                          "class": "Lorg/reverseai/fixture/MainActivity;"}))
        self.assertIn("| 0 | `classes.dex` | `Lorg/reverseai/fixture/MainActivity;` | `0x1 public` | `Landroid/app/Activity;` |",
                      text)
        self.assertRegex(text, r"\| 0 \| `classes.dex` \| `Lorg/reverseai/fixture/MainActivity;` \| `<init>` \| `\(\)V` \| "
                               r"`0x10001 public constructor` \| `0x[0-9a-f]+` \| `4` \|")
        self.assertIn("`0x4 protected`", text)

        text = report.to_markdown(android_query("trace_android_references", {
            "class": "Lorg/reverseai/fixture/Helper;", "method": "compute", "direction": "to"}))
        self.assertIn("| Index | DEX | From class | From method | From prototype | At | Kind | Target | Truncated |", text)
        self.assertRegex(text, r"\| 1 \| `classes2.dex` \| `Lorg/reverseai/fixture/Worker;` \| `run` \| `\(\)V` \| "
                               r"`0x[0-9a-f]+` \| `method` \| `Lorg/reverseai/fixture/Helper;->compute\(II\)I` \| `false` \|")

    def test_flagged_members_show_their_flags_and_no_hash(self):
        from tests import fixtures_apk
        data, _ = fixtures_apk.apk_hostile("crc")
        analysis = pipeline.query_bytes(data, InputRef(sha256_hex(data), len(data), "hostile.apk"),
                                        "inspect_android_package", {})
        self.assertRegex(report.to_markdown(analysis),
                         r"\| 5 \| `assets/hostile.txt` \| `deflate` \| `[0-9]+` \| `264` \| `0x[0-9a-f]{8}` \| `null` \| `crc` \|")

    def test_hostile_android_text_stays_inert(self):
        def rename(layout):
            layout["members"][4] = {**layout["members"][4], "name": "META-INF/a|b`<img src=x>`"}
        text = report.to_markdown(android_query("inspect_android_package", {}, rename))
        self.assertIn("`META-INF/a\\|b'<img src=x>'`", text)
        self.assertNotIn("a|b`", text)


if __name__ == "__main__":
    unittest.main()
