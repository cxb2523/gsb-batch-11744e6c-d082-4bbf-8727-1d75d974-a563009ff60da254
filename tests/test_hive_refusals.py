import json
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from hive import bees, codex_bees, queen
from tests.test_hive_queen import FakeEngine, FakeRouter, make_queen

USAGE_POLICY = ("API Error: Claude Code is unable to respond to this request, which appears to violate our Usage Policy "
                "(https://www.anthropic.com/legal/aup). Try rephrasing the request or attempting a different approach.")
CYBER = "API Error: Opus 5.5's safeguards flagged this message for a cybersecurity topic."


def completed(stdout="", stderr="", code=0):
    return subprocess.CompletedProcess([], code, stdout, stderr)


class RecogniseTests(unittest.TestCase):
    def runner(self, tmp):
        return bees.ClaudeBees(engine=tmp, inputs=tmp, config_dir=tmp / "cfg")

    def test_claude_refusals_are_marked_and_ordinary_failures_are_not(self):
        tmp = Path(tempfile.mkdtemp())
        cases = [
            (json.dumps({"type": "result", "is_error": True, "result": USAGE_POLICY}), True),
            (json.dumps({"type": "result", "is_error": True, "result": CYBER}), True),
            (json.dumps({"type": "result", "is_error": True, "stop_reason": "refusal", "result": ""}), True),
            (json.dumps({"type": "result", "is_error": True, "subtype": "error_max_turns", "result": "Max turns"}), False),
            (json.dumps({"type": "result", "is_error": False, "structured_output": {"verdict": "accept", "defects": []}}),
             False),
        ]
        for stdout, refused in cases:
            with self.subTest(stdout=stdout[:60]), mock.patch.object(bees, "run_cli", return_value=completed(stdout)):
                answer = self.runner(tmp)("councillor", "c", "task", tmp)
            self.assertEqual(bool(answer.get("refused")), refused)
            self.assertEqual(answer["ok"], not refused and "structured_output" in stdout)

    def test_a_refusal_on_stderr_without_json_is_marked(self):
        tmp = Path(tempfile.mkdtemp())
        with mock.patch.object(bees, "run_cli", return_value=completed("", USAGE_POLICY, 1)):
            answer = self.runner(tmp)("worker", "w", "task", tmp)
        self.assertTrue(answer["refused"])
        with mock.patch.object(bees, "run_cli", return_value=completed("", "segmentation fault", 1)):
            self.assertFalse(self.runner(tmp)("worker", "w", "task", tmp)["refused"])

    def test_codex_refusals_are_marked(self):
        tmp = Path(tempfile.mkdtemp())
        runner = codex_bees.CodexBees(engine=tmp, inputs=tmp, config_dir=tmp / "cfg", allow_network=True)
        with mock.patch.object(runner, "_execute", side_effect=ValueError("exit 1: this request violates our usage policy")):
            self.assertTrue(runner("worker", "w", "task", tmp)["refused"])
        with mock.patch.object(runner, "_execute", side_effect=ValueError("exit 1: rate limited")):
            self.assertFalse(runner("worker", "w", "task", tmp)["refused"])


class CodexDiagnosticTests(unittest.TestCase):
    """The whole Codex diagnostic is classified, not only the 240 characters kept for the report."""

    def call(self, stdout="", stderr=""):
        tmp = Path(tempfile.mkdtemp())
        runner = codex_bees.CodexBees(engine=tmp, inputs=tmp, config_dir=tmp / "cfg", allow_network=True)
        with mock.patch.object(bees, "run_cli", return_value=completed(stdout, stderr, 1)):
            return runner("worker", "w", "task", tmp)

    def test_a_refusal_far_from_the_tail_of_stderr_is_marked(self):
        answer = self.call(stderr=USAGE_POLICY + "\n" + "retrying the stream\n" * 200)
        self.assertTrue(answer["refused"])
        self.assertIn("Usage Policy", answer["error"])

    def test_a_refusal_in_a_failed_turn_event_is_marked(self):
        events = [{"type": "thread.started"}, {"type": "turn.failed", "error": {"message": CYBER}}]
        answer = self.call(stdout="\n".join(json.dumps(e) for e in events), stderr="x" * 2000)
        self.assertTrue(answer["refused"])

    def test_refusal_words_in_tool_output_are_not_a_refusal(self):
        events = [{"type": "item.completed", "item": {"type": "command_execution",
                                                       "aggregated_output": "strings: content filter, usage policy"}},
                  {"type": "turn.failed", "error": {"message": "rate limited"}}]
        answer = self.call(stdout="\n".join(json.dumps(e) for e in events))
        self.assertFalse(answer["refused"])
        self.assertIn("rate limited", answer["error"])


class QueenTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        (self.tmp / "inputs").mkdir()
        (self.tmp / "inputs" / "greet").write_bytes(b"x")
        self.calls = []

    def hive(self, refuse, **kwargs):
        def fake(role, name, task, folder):
            self.calls.append(name)
            if role in refuse:
                return {"ok": False, "refused": True, "error": USAGE_POLICY, "seconds": 1}
            if role == "planner":
                (Path(folder) / "contract.h").write_text("int greet_line(const char *name); /* 0x1040 */\n"
                                                         "int main(int argc, char **argv); /* 0x1000 */\n")
                return {"ok": True, "seconds": 1, "output": {
                    "modules": [{"id": "a", "functions": ["0x1040"], "title": "a"},
                                {"id": "b", "functions": ["0x1000"], "title": "b"}],
                    "skipped": [{"entry": "0x1080", "reason": "stub"}]}}
            raise AssertionError(f"unexpected bee {role} {name}")
        hive = make_queen(engine=FakeEngine(self.tmp / "inputs"), out=self.tmp / "run", bees=fake, slots=1,
                           check=lambda claims, out: ({"claims": 0, "confirmed": 0, "rejected": 0, "questions": 0,
                                                       "input_sha256": []}, []), **kwargs)
        patches = [mock.patch.object(queen.Build, "ensure_confinement", return_value=None),
                   mock.patch.object(queen.Build, "syntax", return_value=(True, ""))]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        return hive

    def test_a_refused_planner_stops_the_run_before_any_other_bee(self):
        with self.assertRaises(queen.HiveError) as raised:
            self.hive({"planner"}).run()
        self.assertIn("refused the planner", str(raised.exception))
        self.assertEqual(self.calls, ["planner"])

    def test_a_refused_planner_writes_a_not_started_verdict(self):
        run = self.tmp / "run"
        hive = self.hive({"planner"})
        with self.assertRaises(queen.ProviderRefused):
            hive.run()
        (run / "result.json").write_text(json.dumps({"verdict": "accepted"}))  # an earlier, accepted run
        (run / "REPORT.md").write_text("**Verdict: accepted.** every check passed.\n")
        hive.run()  # a stopped run never starts another planner without explicit recovery consent
        result = json.loads((run / "result.json").read_text())
        self.assertEqual(result["verdict"], "not started")
        self.assertIn("planner_refused", result["reason"])
        self.assertEqual([r["bee"] for r in result["refusals"]], ["planner"])
        report = (run / "REPORT.md").read_text()
        self.assertIn("Verdict: not started", report)
        self.assertNotIn("accepted.", report)
        self.assertIn("Provider refusals: 1 (planner)", report)

    def test_a_bee_queued_for_a_slot_does_not_start_after_the_limit(self):
        hive = self.hive(set())  # default limit: 3 refusals
        folder = self.tmp / "run" / "bees"
        folder.mkdir(parents=True)
        calls = []
        last_started, finish_last = threading.Event(), threading.Event()

        def provider(role, name, task, where):
            calls.append(name)
            if name == "last":  # hold the only slot until the next bee is queued behind it
                last_started.set()
                self.assertTrue(finish_last.wait(5))
            return {"ok": False, "refused": True, "error": USAGE_POLICY, "seconds": 1}
        hive.bees = FakeRouter(provider)
        hive.bee("worker", "first", "t", folder)
        hive.bee("worker", "second", "t", folder)
        holder = threading.Thread(target=hive.bee, args=("worker", "last", "t", folder))
        holder.start()
        self.assertTrue(last_started.wait(5))
        answers = []
        waiting = threading.Thread(target=lambda: answers.append(hive.bee("worker", "queued", "t", folder)))
        waiting.start()
        finish_last.set()
        waiting.join(5)
        holder.join()
        queued = answers[0]
        self.assertEqual(calls, ["first", "second", "last"])
        self.assertIn("run stopped", queued["error"])
        self.assertEqual(hive.spent["bees"], 3)  # a bee that never started is not counted
        self.assertEqual(len(hive.refusals), 3)

    def test_refusals_over_the_limit_stop_new_bees_and_are_reported(self):
        result = self.hive({"worker"}, refusal_limit=1).run()
        self.assertEqual(self.calls, ["planner", "m01-build"])  # m02's builder never starts
        self.assertEqual(result["modules"], {"m01": "refused", "m02": "not started"})
        self.assertEqual(result["verdict"], "not accepted")
        self.assertIn("refused 1 bee(s) (worker)", result["reason"])
        self.assertIn("stopped early", result["reason"])
        self.assertEqual([r["bee"] for r in result["refusals"]], ["m01-build"])
        report = (self.tmp / "run" / "REPORT.md").read_text()
        self.assertIn("Provider refusals: 1 (m01-build)", report)
        self.assertIn("REFUSED by the model provider", (self.tmp / "run" / "hive.log").read_text())


if __name__ == "__main__":
    unittest.main()
