import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools import hive_check


def report(findings, sha="ab" * 32):
    return {"input": {"sha256": sha, "size": 1, "name": "program"},
            "results": [{"evidence": [{"id": e} for f in findings for e in f.get("evidence_ids", [])],
                         "findings": findings}]}


class FakeRunner:
    """Stands in for `python -m reverseai`: writes a canned report into --out."""

    def __init__(self, reports, returncode=0):
        self.reports, self.returncode, self.calls = reports, returncode, []

    def __call__(self, argv, timeout):
        self.calls.append(argv)
        out = Path(argv[argv.index("--out") + 1])
        name = argv[argv.index("--query") + 1] if "--query" in argv else "analyze_file"
        if self.returncode == 0:
            out.mkdir(parents=True)
            (out / "report.json").write_text(json.dumps(self.reports[name]))
        return subprocess.CompletedProcess(argv, self.returncode, "", "boom\n")


FI_OK, FI_DER, FI_BAD = "fi-" + "1" * 16, "fi-" + "2" * 16, "fi-" + "3" * 16
EV_OK = "ev-" + "4" * 16


class HiveCheckTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.inputs = self.tmp / "inputs"
        self.inputs.mkdir()
        (self.inputs / "program").write_bytes(b"\x7fELF")
        self.reports = {
            "list_strings": report([{"id": FI_OK, "verdict": "supported", "evidence_ids": [EV_OK]},
                                    {"id": FI_BAD, "verdict": "unsupported", "evidence_ids": []}]),
            "procedure_info": report([{"id": FI_DER, "verdict": "derived", "evidence_ids": []}]),
        }

    def run_check(self, claims, runner=None, out="out", **kwargs):
        path = self.tmp / (out + "-claims.json")
        path.write_text(json.dumps(claims))
        runner = runner or FakeRunner(self.reports)
        summary, verdicts = hive_check.check(self.inputs, path, self.tmp / out, runner=runner, **kwargs)
        return summary, {v["id"]: v for v in verdicts}, runner

    def test_confirms_resolved_citations_and_rejects_the_rest(self):
        summary, verdicts, runner = self.run_check({"file": "program", "claims": [
            {"id": "a", "text": "s", "citations": [{"tool": "list_strings", "args": {}, "id": FI_OK}]},
            {"id": "b", "text": "s", "citations": [{"tool": "list_strings", "args": {}, "id": EV_OK},
                                                   {"tool": "procedure_info", "args": {"entry": 16},
                                                    "id": FI_DER}]},
            {"id": "c", "text": "s", "citations": [{"tool": "list_strings", "args": {}, "id": FI_BAD}]},
            {"id": "d", "text": "s", "citations": [{"tool": "list_strings", "args": {}, "id": "fi-" + "9" * 16}]},
            {"id": "e", "text": "s", "citations": []},
        ]}, enabled=frozenset({"ghidra"}))
        self.assertEqual(verdicts["a"]["verdict"], "confirmed")
        self.assertEqual(verdicts["a"]["basis"], "supported")
        self.assertEqual(verdicts["b"]["basis"], "derived")
        self.assertIn("unsupported", verdicts["c"]["reasons"][0])
        self.assertIn("not in the fresh report", verdicts["d"]["reasons"][0])
        self.assertEqual(verdicts["e"]["reasons"], ["no citation"])
        self.assertEqual((summary["confirmed"], summary["rejected"], summary["questions"]), (2, 3, 2))
        self.assertEqual(len(runner.calls), 2)  # each distinct question runs once
        written = json.loads((self.tmp / "out" / "verdicts.json").read_text())
        self.assertEqual(written["summary"]["claims"], 5)

    def test_questions_are_built_like_the_mcp_server(self):
        _, _, runner = self.run_check({"file": "program", "claims": [
            {"id": "a", "text": "s", "citations": [{"tool": "list_strings", "args": {"limit": 5}, "id": FI_OK}]}]})
        argv = runner.calls[0]
        self.assertEqual(argv[0], "query")
        self.assertEqual(Path(argv[1]).name, "program")
        self.assertIn("limit=5", argv)

    def test_refused_and_failed_questions_reject_their_claims(self):
        _, verdicts, runner = self.run_check({"file": "program", "claims": [
            {"id": "a", "text": "s", "citations": [{"tool": "procedure_info", "args": {"entry": 16},
                                                    "id": FI_DER}]},  # Ghidra not enabled
            {"id": "b", "text": "s", "citations": [{"tool": "no_such_tool", "args": {}, "id": FI_OK}]},
            {"id": "c", "text": "s", "citations": [{"tool": "list_strings", "args": {}, "file": "../escape",
                                                    "id": FI_OK}]},
        ]})
        for name in "abc":
            self.assertEqual(verdicts[name]["verdict"], "rejected")
            self.assertIn("question refused", verdicts[name]["reasons"][0])
        self.assertEqual(runner.calls, [])
        _, verdicts, _ = self.run_check({"file": "program", "claims": [
            {"id": "a", "text": "s", "citations": [{"tool": "list_strings", "args": {}, "id": FI_OK}]}]},
            runner=FakeRunner(self.reports, returncode=1), out="out2")
        self.assertIn("question failed", verdicts["a"]["reasons"][0])

    def test_malformed_claims_are_usage_errors(self):
        bad = [{"claims": []}, {"claims": [{"id": "a b", "text": "s", "citations": []}]},
               {"file": "p", "claims": [{"id": "a", "text": "s", "citations": [{"tool": "x", "id": "fi-1"}]}]},
               {"file": "p", "claims": [{"id": "a", "text": "s", "citations": []},
                                        {"id": "a", "text": "s", "citations": []}]}]
        for number, claims in enumerate(bad):
            path = self.tmp / f"bad{number}.json"
            path.write_text(json.dumps(claims))
            with self.assertRaises(hive_check.UsageError):
                hive_check.check(self.inputs, path, self.tmp / f"out{number}", runner=FakeRunner(self.reports))

    def test_output_directory_must_be_new_or_empty(self):
        (self.tmp / "out").mkdir()
        (self.tmp / "out" / "x").write_text("")
        with self.assertRaises(hive_check.UsageError):
            self.run_check({"file": "program", "claims": [{"id": "a", "text": "s", "citations": []}]})


if __name__ == "__main__":
    unittest.main()
