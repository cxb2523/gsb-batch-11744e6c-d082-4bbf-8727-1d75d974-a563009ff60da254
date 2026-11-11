import contextlib
import io
import json
import os
from pathlib import Path
import re
import tempfile
import unittest
from unittest import mock

from reverseai import cli, pipeline, report
from reverseai.analysts import capability
from reverseai.contract import (
    ArgSpec, Budget, ContractError, InputRef, Location, Observation, OperationSpec, ToolRef, ToolSpec, evidence_intact,
    make_finding, sha256_hex,
)
from tests.fixtures_strings import KNOWN, clean_control, known_strings
from tests.fixtures_structure import elf, pe
from tests.fixtures_code import elf_refs, pe_refs, macho_refs
from tests import fixtures_apk


def ref(data, name="sample.bin"):
    return InputRef(sha256_hex(data), len(data), name)


def findings(analysis):
    return {(r.role, f.claim_key): f for r in analysis.results for f in r.findings}


def verdicts(analysis):
    return {v.finding_id: v for v in analysis.verdicts}


def expected_capabilities():
    expected = {}
    for _, rule, category in KNOWN:
        expected.setdefault("capability." + category, set()).add(rule)
    expected = {key: sorted(rules) for key, rules in expected.items()}
    expected["strings.urls"] = sorted(match for match, rule, _ in KNOWN if rule == "url")
    return expected


class Fabricating:
    """An untrusted capability analyst that adds claims its evidence does not support."""

    plan = staticmethod(capability.plan)

    @staticmethod
    def conclude(task, evidence):
        return capability.conclude(task, evidence) + (
            make_finding("capability", "Invented: the input is an ELF file.", "format.container", "elf", []),
            make_finding("capability", "Invented: ransomware.", "capability.ransomware", ["encrypt_all"], ["ev-0000000000000000"]),
        )


class PipelineKnownAnswerTests(unittest.TestCase):
    def test_pe_with_indicator_strings(self):
        data = pe()[0] + known_strings()[0]
        analysis = pipeline.analyze_bytes(data, ref(data, "sample.exe"))
        self.assertEqual([(r.role, r.status, r.errors) for r in analysis.results], [("structural", "ok", ()), ("capability", "ok", ())])
        found = findings(analysis)
        expected = {
            ("structural", "format.container"): "pe",
            ("structural", "format.machine"): "x86_64",
            ("structural", "format.section_count"): 3,
            ("structural", "sections.writable_executable"): [".rwx"],
            **{("capability", key): value for key, value in expected_capabilities().items()},
        }
        self.assertEqual({key: f.value for key, f in found.items()}, expected)
        self.assertEqual({v.status for v in analysis.verdicts}, {"supported"})
        self.assertEqual(len(analysis.verdicts), len(expected))
        self.assertEqual(report.to_dict(analysis)["summary"], {"supported": len(expected), "derived": 0, "unsupported": 0, "contradicted": 0, "unreviewed": 0})

    def test_clean_elf_control_has_no_capability_findings(self):
        data = elf()[0] + clean_control()
        analysis = pipeline.analyze_bytes(data, ref(data))
        found = findings(analysis)
        self.assertEqual(found[("structural", "format.container")].value, "elf")
        self.assertEqual(found[("structural", "format.machine")].value, "x86_64")
        self.assertFalse([key for key in found if key[0] == "capability"])
        self.assertEqual({v.status for v in analysis.verdicts}, {"supported"})

    def test_report_is_deterministic(self):
        data = pe()[0] + known_strings()[0]
        first = report.to_json(pipeline.analyze_bytes(data, ref(data)))
        self.assertEqual(first, report.to_json(pipeline.analyze_bytes(data, ref(data))))

    def test_the_capped_input_name_is_not_cut_again_in_markdown(self):
        data = pe()[0]
        name = "n" * 251 + "\\x80"  # 255 characters, the intake cap, ending in an escape
        self.assertIn("`" + name + "`", report.to_markdown(pipeline.analyze_bytes(data, ref(data, name))))

    def test_fabricated_claims_are_rejected_and_cannot_cancel_verified_ones(self):
        data = pe()[0] + known_strings()[0]
        analysis = pipeline.analyze_bytes(data, ref(data), analysts=(pipeline.ANALYSTS[0], Fabricating))
        found, judged = findings(analysis), verdicts(analysis)
        self.assertEqual(judged[found[("capability", "format.container")].id].status, "unsupported")
        self.assertEqual(judged[found[("capability", "capability.ransomware")].id].status, "unsupported")
        self.assertEqual(judged[found[("structural", "format.container")].id].status, "supported")
        rendered = report.to_markdown(analysis).split("## Rejected or unreviewed claims")
        self.assertNotIn("Invented", rendered[0])
        self.assertIn("Invented: ransomware.", rendered[1])

    def test_analyst_cannot_alter_the_gateway_evidence(self):
        class Tampering:
            plan = staticmethod(pipeline.ANALYSTS[0].plan)

            @staticmethod
            def conclude(task, evidence):
                for item in evidence:
                    if "format" in item.observation:
                        item.observation["format"] = "elf"
                return pipeline.ANALYSTS[0].conclude(task, evidence)

        data = pe()[0]
        analysis = pipeline.analyze_bytes(data, ref(data), analysts=(Tampering,))
        result = analysis.results[0]
        self.assertTrue(all(evidence_intact(item) for item in result.evidence))
        self.assertEqual({item.observation.get("format") for item in result.evidence} - {None}, {"pe"})
        claimed = findings(analysis)[("structural", "format.container")]
        self.assertEqual(claimed.value, "elf")
        self.assertEqual(verdicts(analysis)[claimed.id].status, "unsupported")

    def test_budget_exhaustion_is_reported_not_raised(self):
        data = pe()[0] + known_strings()[0]
        analysis = pipeline.analyze_bytes(data, ref(data), budget=Budget(max_evidence=4))
        self.assertIn("budget_exceeded", {r.status for r in analysis.results})
        self.assertNotIn("contradicted", {v.status for v in analysis.verdicts})
        self.assertIn("budget_exceeded", report.to_markdown(analysis))


class ContainedToolWiringTests(unittest.TestCase):
    def fake_lief(self, data, layout):
        """A contained ToolSpec whose handlers return what the worker would report for the pe() fixture; no Docker."""
        lfanew = layout["lfanew"]

        def headers(_, args):
            return [Observation(Location(0, 64), {"structure": "dos", "e_lfanew": lfanew}),
                    Observation(Location(lfanew, 24), {"structure": "coff", "format": "pe", "machine_name": "x86_64",
                                                       "number_of_sections": 3})]

        def sections(_, args):
            return [Observation(Location(layout["table_offset"] + 40 * i, 40),
                                {"index": i, "offset": 0, "size": 0, "writable": i == 2 or i == 1, "executable": i in (0, 2)})
                    for i in range(3)]

        ops = {"lief.headers": OperationSpec("lief.headers", {}, headers, max_observations=3),
               "lief.sections": OperationSpec("lief.sections", {"max_sections": ArgSpec("int", 1, 64, default=32)}, sections,
                                              max_observations=64)}
        return ToolSpec(ToolRef("lief", "1.0.0-r2"), ops, contained=True, runtime={"image": "sha256:" + "1" * 64, "platform": "linux/arm64"})

    @staticmethod
    def fake_ghidra(observations):
        args = {"max_functions": ArgSpec("int", 1, 128, default=64), "decompile": ArgSpec("int", 0, 16, default=8),
                "max_chars": ArgSpec("int", 64, 2048, default=1024), "max_calls": ArgSpec("int", 0, 256, default=128),
                "assembly": ArgSpec("int", 0, 8, default=4), "max_instructions": ArgSpec("int", 1, 64, default=32),
                "max_refs": ArgSpec("int", 0, 128, default=64), "max_strings": ArgSpec("int", 0, 64, default=32)}
        op = OperationSpec("ghidra.analyze", args, lambda data, checked: observations, max_observations=600, derived=True)
        return ToolSpec(ToolRef("ghidra", "12.1.4-r7"), {"ghidra.analyze": op}, contained=True,
                        runtime={"image": "sha256:" + "2" * 64, "platform": "linux/arm64"})

    def test_ghidra_findings_are_reported_as_derived_and_get_the_ghidra_budget(self):
        data = elf()[0]
        function = Observation(Location(0, 16), {"kind": "function", "index": 0, "name": "entry", "entry": 0x400000, "size": 16})
        tools = pipeline.TOOLS + (self.fake_ghidra([function]),)
        self.assertEqual(pipeline._budget(tools), pipeline.GHIDRA_BUDGET)
        # The global budget must outlast the 240 s Ghidra worker wall and the code task's 300 s.
        self.assertGreater(pipeline.GHIDRA_BUDGET.max_wall_seconds, 300)
        analysis = pipeline.analyze_bytes(data, ref(data), tools=tools)
        code = [r for r in analysis.results if r.role == "code"]
        self.assertEqual(len(code), 1)
        judged = verdicts(analysis)
        self.assertEqual([(f.claim_key, f.value, judged[f.id].status) for f in code[0].findings],
                         [("code.functions", ["entry"], "derived")])
        self.assertIn("## Derived by analysis tools (not verified against the bytes)", report.to_markdown(analysis))

    def test_without_ghidra_the_code_analyst_takes_no_part(self):
        data = elf()[0]
        analysis = pipeline.analyze_bytes(data, ref(data))
        self.assertEqual([r.role for r in analysis.results], ["structural", "capability"])
        self.assertEqual(pipeline._budget(pipeline.TOOLS), Budget())

    def test_m3c_fake_run_keeps_new_kinds_derived_in_json_and_readable_markdown(self):
        data = elf()[0]
        observations = [
            Observation(Location(0, 16), {"kind": "function", "index": 0, "name": "entry", "entry": 0x400000, "size": 16}),
            Observation(Location(0, 16), {"kind": "assembly", "index": 0, "entry": 0x400000,
                                         "instructions": [[0, 1, "RET"]], "truncated": False}),
            Observation(Location(0, 1), {"kind": "ref", "from": 0x400000, "to": 0x500000,
                                        "type": "read", "to_name": "message"}),
            Observation(Location(4, 3), {"kind": "string", "address": 0x500000, "encoding": "ascii",
                                        "text": "abc", "truncated": False, "from": [0x400000]}),
        ]
        analysis = pipeline.analyze_bytes(data, ref(data), tools=pipeline.TOOLS + (self.fake_ghidra(observations),))
        results = [r for r in analysis.results if r.role == "code"]
        self.assertEqual(len(results), 1)
        result = results[0]
        self.assertEqual({f.claim_key for f in result.findings},
                         {"code.functions", "code.assembly", "code.references", "code.strings"})
        judged = verdicts(analysis)
        self.assertEqual({judged[f.id].status for f in result.findings}, {"derived"})
        json_findings = next(r for r in report.to_dict(analysis)["results"] if r["role"] == "code")["findings"]
        self.assertEqual({f["verdict"] for f in json_findings}, {"derived"})
        markdown = report.to_markdown(analysis)
        supported, derived = markdown.split("## Derived by analysis tools (not verified against the bytes)")
        self.assertNotIn("RET", supported)
        for text in ("### Assembly (derived)", "### References (derived)", "### Referenced strings (derived)", "`RET`", "`abc`"):
            self.assertIn(text, derived)

    def test_m3c_shared_fixtures_round_trip_through_the_analyst_reviewer_and_reports(self):
        # Declared fake readings exercise wiring; they are not native Ghidra oracles.
        for builder in (elf_refs, pe_refs, macho_refs):
            with self.subTest(format=builder.__name__):
                data, layout = builder()
                functions = layout["functions"]
                observations = [Observation(Location(f["offset"], f["size"]), {
                    "kind": "function", "index": i, "entry": f["entry"], "size": f["size"], "name": f["name"] or f"f{i}"})
                    for i, f in enumerate(functions)]
                selection = sorted(range(len(functions)), key=lambda i: (
                    functions[i]["entry"] != layout["entry"], -functions[i]["size"], functions[i]["entry"]))[:4]
                observations += [Observation(Location(functions[i]["offset"], functions[i]["size"]), {
                    "kind": "assembly", "index": i, "entry": functions[i]["entry"], "truncated": False,
                    "instructions": [[delta, length, f"instruction {n}"]
                                     for n, (delta, length) in enumerate(functions[i]["instructions"])]}) for i in selection]
                observations += [Observation(Location(r["offset"], r["length"]), {
                    "kind": "ref", "from": r["from"], "to": r["to"], "type": r["type"], "to_name": r["to_name"] or ""})
                    for r in layout["refs"]]
                observations += [Observation(Location(s["offset"], s["length"]), {
                    "kind": "string", **{key: s[key] for key in ("address", "encoding", "text", "truncated", "from")}})
                    for s in layout["strings"]]
                analysis = pipeline.analyze_bytes(data, ref(data), tools=pipeline.TOOLS + (self.fake_ghidra(observations),))
                code, = [r for r in analysis.results if r.role == "code"]
                judged = verdicts(analysis)
                self.assertEqual({judged[f.id].status for f in code.findings}, {"derived"})
                listings = [f for f in code.findings if f.claim_key == "code.assembly"]
                self.assertEqual([f.value["entry"] for f in listings], [functions[i]["entry"] for i in sorted(selection)])
                refs = next(f for f in code.findings if f.claim_key == "code.references")
                self.assertEqual(refs.value, [list(row) for row in sorted({
                    (r["from"], r["type"], r["to"], r["to_name"] or "") for r in layout["refs"]})])
                strings = next(f for f in code.findings if f.claim_key == "code.strings")
                self.assertEqual(strings.value, [{k: s[k] for k in ("address", "encoding", "text", "truncated", "from")}
                                                 for s in layout["strings"]])
                markdown = report.to_markdown(analysis)
                for s in layout["strings"]:
                    self.assertEqual(data[s["offset"]:s["offset"] + s["length"]].decode(s["encoding"]), s["text"])
                    self.assertIn(f"`{s['text']}`", markdown)
                first = functions[0]
                self.assertIn(f"| `{first['offset']}` | `{first['instructions'][0][1]}` | `instruction 0` |", markdown)
                self.assertEqual(report.to_json(analysis), report.to_json(pipeline.analyze_bytes(
                    data, ref(data), tools=pipeline.TOOLS + (self.fake_ghidra(observations),))))

    def test_contained_findings_agree_with_the_stdlib_parser_and_name_the_image(self):
        data, layout = pe()
        analysis = pipeline.analyze_bytes(data, ref(data), tools=pipeline.TOOLS + (self.fake_lief(data, layout),))
        structural = [r for r in analysis.results if r.role == "structural"][0]
        self.assertEqual(structural.status, "ok")
        self.assertTrue({"lief.headers", "lief.sections"} <= {e.operation for e in structural.evidence})
        found, judged = findings(analysis), verdicts(analysis)
        self.assertEqual(found[("structural", "sections.writable_executable_indices")].value, [2])
        for key in ("format.container", "format.machine", "format.section_count", "sections.writable_executable_indices"):
            self.assertEqual(judged[found[("structural", key)].id].status, "supported", key)
        cited = {e.id: e.operation for e in structural.evidence}
        operations = {cited[i] for i in found[("structural", "format.machine")].evidence_ids}
        self.assertEqual(operations, {"structure.headers", "lief.headers"})
        tools = report.to_dict(analysis)["tools"]
        self.assertEqual([t.get("runtime", {}).get("platform") for t in tools if t["name"] == "lief"], ["linux/arm64"])
        self.assertIn("lief 1.0.0-r2 (contained, image sha256:111111111111, linux/arm64)", report.to_markdown(analysis))

    def test_with_lief_refuses_cleanly_when_the_worker_is_unavailable(self):
        from reverseai.tools import lief_tool
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(lief_tool, "available", return_value=False):
            sample = Path(temporary, "sample.bin")
            sample.write_bytes(pe()[0])
            out = io.StringIO()
            with contextlib.redirect_stderr(out), self.assertRaises(SystemExit) as stopped:
                cli.main(["analyze", str(sample), "--out", str(Path(temporary, "r")), "--with-lief"])
            self.assertEqual(stopped.exception.code, 1)
            self.assertIn("LIEF worker is unavailable", out.getvalue())
            self.assertFalse(Path(temporary, "r").exists())

    def test_with_yarax_refuses_cleanly_when_the_worker_is_unavailable(self):
        self.check_contained_refusal("yarax_tool", "--with-yarax", "YARA-X")

    def test_with_ghidra_refuses_cleanly_when_the_worker_is_unavailable(self):
        self.check_contained_refusal("ghidra_tool", "--with-ghidra", "Ghidra")

    def check_contained_refusal(self, module, flag, label):
        from importlib import import_module
        from reverseai.contained import ContainedError
        yarax_tool = import_module(f"reverseai.tools.{module}")
        for patch in ({"available": mock.DEFAULT}, {"make_tool": ContainedError("InvalidImageLock")}):
            with self.subTest(patch=sorted(patch)), tempfile.TemporaryDirectory() as temporary, \
                    mock.patch.object(yarax_tool, "available", return_value="make_tool" in patch), \
                    mock.patch.object(yarax_tool, "make_tool", side_effect=patch.get("make_tool")):
                sample = Path(temporary, "sample.bin")
                sample.write_bytes(pe()[0])
                out = io.StringIO()
                with contextlib.redirect_stderr(out), self.assertRaises(SystemExit) as stopped:
                    cli.main(["analyze", str(sample), "--out", str(Path(temporary, "r")), flag])
                self.assertEqual(stopped.exception.code, 1)
                self.assertIn(f"{label} worker is unavailable", out.getvalue())
                self.assertNotIn("Traceback", out.getvalue())
                self.assertFalse(Path(temporary, "r").exists())

    def test_with_lief_refuses_cleanly_when_the_lock_breaks_after_the_check(self):
        from reverseai.contained import ContainedError
        from reverseai.tools import lief_tool
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(lief_tool, "available", return_value=True), \
                mock.patch.object(lief_tool, "make_tool", side_effect=ContainedError("InvalidImageLock")):
            sample = Path(temporary, "sample.bin")
            sample.write_bytes(pe()[0])
            out = io.StringIO()
            with contextlib.redirect_stderr(out), self.assertRaises(SystemExit) as stopped:
                cli.main(["analyze", str(sample), "--out", str(Path(temporary, "r")), "--with-lief"])
            self.assertEqual(stopped.exception.code, 1)
            self.assertIn("LIEF worker is unavailable", out.getvalue())
            self.assertNotIn("Traceback", out.getvalue())
            self.assertFalse(Path(temporary, "r").exists())


class HostileTextTests(unittest.TestCase):
    NAMES = (b"<img src=x onerror=alert(1)>", b"[click](https://evil.example/x)", b"![p](http://e.invalid/p.png)")

    def test_sample_text_renders_only_inside_code_spans(self):
        data = elf(sections=tuple((name, 1, 0x7, 8) for name in self.NAMES))[0]
        analysis = pipeline.analyze_bytes(data, ref(data))
        names = findings(analysis)[("structural", "sections.writable_executable")].value
        self.assertEqual(sorted(names), sorted(name.decode() for name in self.NAMES))
        table = [line for line in report.to_markdown(analysis).splitlines() if line.startswith("|")]
        hostile = 0
        for line in table:
            for cell in re.split(r"(?<!\\)\|", line)[1:-1]:
                cell = cell.strip()
                if any(marker in cell for marker in ("<", "](", "://")):
                    hostile += 1
                    self.assertTrue(cell.startswith("`") and cell.endswith("`") and "`" not in cell[1:-1], cell)
        self.assertGreater(hostile, 0)


class CliTests(unittest.TestCase):
    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = cli.main(list(argv))
            except SystemExit as exit:
                code = exit.code
        return code, out.getvalue(), err.getvalue()

    def test_analyze_writes_both_reports_without_host_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            sample, out = Path(temporary, "sample.exe"), Path(temporary, "report")
            sample.write_bytes(pe()[0] + known_strings()[0])
            code, stdout, _ = self.run_cli("analyze", str(sample), "--out", str(out))
            self.assertEqual(code, 0)
            self.assertTrue(stdout.startswith(sha256_hex(sample.read_bytes())))
            data = json.loads((out / "report.json").read_text())
            self.assertEqual(data["input"]["name"], "sample.exe")
            self.assertEqual(data["summary"]["supported"], 10)
            for name in ("report.json", "report.md"):
                self.assertNotIn(temporary, (out / name).read_text())

    def test_refuses_used_output_and_unsafe_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            sample, out = Path(temporary, "sample.bin"), Path(temporary, "report")
            sample.write_bytes(elf()[0])
            self.assertEqual(self.run_cli("analyze", str(sample), "--out", str(out))[0], 0)
            code, _, err = self.run_cli("analyze", str(sample), "--out", str(out))
            self.assertEqual(code, 1)
            self.assertIn("new or empty directory", err)
            link = Path(temporary, "link.bin")
            os.symlink(sample, link)
            code, _, err = self.run_cli("analyze", str(link), "--out", str(Path(temporary, "other")))
            self.assertEqual(code, 1)
            self.assertIn("input refused", err)
            self.assertNotIn(temporary, err)
            self.assertFalse(Path(temporary, "other").exists())

    def test_reports_are_private(self):
        with tempfile.TemporaryDirectory() as temporary:
            sample, out = Path(temporary, "sample.bin"), Path(temporary, "report")
            sample.write_bytes(elf()[0])
            self.assertEqual(self.run_cli("analyze", str(sample), "--out", str(out))[0], 0)
            self.assertEqual(out.stat().st_mode & 0o777, 0o700)
            for name in ("report.json", "report.md"):
                self.assertEqual((out / name).stat().st_mode & 0o777, 0o600)

    def test_swapping_the_output_path_during_analysis_cannot_redirect_reports(self):
        with tempfile.TemporaryDirectory() as temporary:
            sample, out = Path(temporary, "sample.bin"), Path(temporary, "report")
            moved, elsewhere = Path(temporary, "moved"), Path(temporary, "elsewhere")
            sample.write_bytes(elf()[0])
            elsewhere.mkdir()
            original = pipeline.analyze_bytes

            def swap_then_analyze(*args, **kwargs):
                os.rename(out, moved)
                os.symlink(elsewhere, out)
                return original(*args, **kwargs)

            with mock.patch.object(pipeline, "analyze_bytes", swap_then_analyze):
                code, _, _ = self.run_cli("analyze", str(sample), "--out", str(out))
            self.assertEqual(code, 0)
            self.assertEqual(list(elsewhere.iterdir()), [])
            self.assertEqual(sorted(p.name for p in moved.iterdir()), ["report.json", "report.md"])

    def test_output_failures_are_short_and_name_what_was_written(self):
        with tempfile.TemporaryDirectory() as temporary:
            sample, out = Path(temporary, "sample.bin"), Path(temporary, "report")
            sample.write_bytes(elf()[0])
            out.mkdir()
            out.chmod(0o500)
            try:
                code, stdout, err = self.run_cli("analyze", str(sample), "--out", str(out))
            finally:
                out.chmod(0o700)
            self.assertEqual((code, stdout), (1, ""))
            self.assertEqual(err, "reverseai: output failed: PermissionError; written: nothing\n")
            other = Path(temporary, "other")
            with mock.patch.object(report, "to_markdown", side_effect=ValueError("secret /path")):
                code, _, err = self.run_cli("analyze", str(sample), "--out", str(other))
            self.assertEqual(code, 1)
            self.assertEqual(err, "reverseai: output failed: ValueError; written: report.json\n")
            self.assertNotIn(temporary, err)

    def test_unreadable_output_directory_is_refused_without_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            sample, out = Path(temporary, "sample.bin"), Path(temporary, "locked", "report")
            sample.write_bytes(elf()[0])
            out.parent.mkdir()
            out.parent.chmod(0)
            try:
                code, _, err = self.run_cli("analyze", str(sample), "--out", str(out))
            finally:
                out.parent.chmod(0o700)
            self.assertEqual(code, 1)
            self.assertTrue(err.startswith("reverseai: output refused:") or err.startswith("reverseai: --out must be"), err)
            self.assertNotIn(temporary, err)
            self.assertNotIn("Traceback", err)

    def test_an_unreadable_empty_output_directory_is_refused_without_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            sample, out = Path(temporary, "sample.bin"), Path(temporary, "report")
            sample.write_bytes(elf()[0])
            out.mkdir()
            out.chmod(0)
            try:
                code, _, err = self.run_cli("analyze", str(sample), "--out", str(out))
            finally:
                out.chmod(0o700)
            self.assertEqual((code, err), (1, "reverseai: --out must be a new or empty directory\n"))

    def test_analysis_errors_are_not_reported_as_output_errors(self):
        with tempfile.TemporaryDirectory() as temporary:
            sample, out = Path(temporary, "sample.bin"), Path(temporary, "report")
            sample.write_bytes(elf()[0])
            with mock.patch.object(pipeline, "analyze_bytes", side_effect=ContractError("detail")):
                code, _, err = self.run_cli("analyze", str(sample), "--out", str(out))
            self.assertEqual((code, err), (1, "reverseai: analysis failed: ContractError\n"))

    def test_uncreatable_output_is_refused_without_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            sample = Path(temporary, "sample.bin")
            sample.write_bytes(elf()[0])
            code, _, err = self.run_cli("analyze", str(sample), "--out", str(Path(temporary, "missing", "report")))
            self.assertEqual(code, 1)
            self.assertEqual(err, "reverseai: output refused: --out cannot be created\n")


class AndroidPipelineTests(unittest.TestCase):
    def test_apk_and_dex_tools_are_registered_and_the_analyze_run_does_not_use_them(self):
        # The js tool is registered after them.
        self.assertEqual([tool.ref for tool in pipeline.TOOLS][-3:],
                         [ToolRef("apk", "0.1.0"), ToolRef("dex", "0.1.0"), ToolRef("js", "0.1.0")])
        self.assertEqual(pipeline._budget(pipeline.TOOLS), Budget())
        data, _ = fixtures_apk.apk_basic()
        analysis = pipeline.analyze_bytes(data, ref(data, "fixture.apk"))
        self.assertFalse([f for r in analysis.results for f in r.findings if f.claim_key.startswith("android.")])
        self.assertFalse([e for r in analysis.results for e in r.evidence if e.tool.name in ("apk", "dex")])
        self.assertIn(("apk", "0.1.0"), [(t["name"], t["version"]) for t in report.to_dict(analysis)["tools"]])

    def test_android_query_from_the_command_line(self):
        with tempfile.TemporaryDirectory() as temporary:
            sample, out = Path(temporary, "fixture.apk"), Path(temporary, "report")
            sample.write_bytes(fixtures_apk.apk_basic()[0])
            code, stdout, stderr = CliTests.run_cli(self, "query", str(sample), "--query", "trace_android_references",
                                                    "--arg", "class=" + fixtures_apk.HELPER, "--arg", "method=compute",
                                                    "--arg", "direction=to", "--out", str(out))
            self.assertEqual(code, 0, stderr)
            parsed = json.loads((out / "report.json").read_text())
            finding, = parsed["results"][0]["findings"]
            self.assertEqual((finding["claim_key"], finding["verdict"]), ("android.references", "supported"))
            self.assertEqual([row[:3] for row in finding["value"]["rows"]],
                             [["classes.dex", fixtures_apk.MAIN, "helper"], ["classes2.dex", fixtures_apk.WORKER, "run"]])
            self.assertEqual({e["artifact"]["member"] for e in parsed["results"][0]["evidence"]},
                             {"classes.dex", "classes2.dex"})
            text = (out / "report.md").read_text()
            self.assertIn("dex.references in `classes2.dex` @ 0x", text)
            self.assertNotIn(temporary, text)


if __name__ == "__main__":
    unittest.main()
