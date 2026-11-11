"""Startup regression: a successful Read cannot certify ReverseAI MCP tools."""

import argparse
import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hive import bees, codex_bees, queen, selfhost
from tests.test_hive_queen import FakeEngine
from tests.test_hive_selfhost import accepted_mcp_events


class ModelMCPStartupTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hive-model-mcp-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.inputs = self.root / "inputs"
        self.inputs.mkdir()
        (self.inputs / "greet").write_bytes(b"inert input; never executed")
        self.calls = []
        self.mcp_accept = False

    def router(self, client="claude"):
        parser = argparse.ArgumentParser()
        parser.add_argument("--model")
        codex_bees.add_arguments(parser)
        args = parser.parse_args(["--model-server", "http://127.0.0.1:11434", "--model", "fixture"]
                                 + (["--bee-policy", "codex", "--codex-model", "fixture", "--codex-allow-network"]
                                    if client == "codex" else []))
        source = bees.ClaudeBees(engine=self.root, inputs=self.inputs, config_dir=self.root / "claude")
        return codex_bees.build_router(args, source, engine=self.root, inputs=self.inputs,
                                      config_dir=self.root / "codex")

    def cli(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        nonce = json.loads(Path(kwargs["cwd"], "capability-input.json").read_text())["nonce"]
        codex = "--output-schema" in argv
        if codex:
            config = next(arg for arg in argv if arg.startswith("mcp_servers="))
            self.assertIn(str(self.inputs), config)
            self.assertIn("http://127.0.0.1:11434/v1", " ".join(argv))
        else:
            config = json.loads(Path(argv[argv.index("--mcp-config") + 1]).read_text())
            mcp_args = config["mcpServers"]["reverseai"]["args"]
            self.assertEqual(Path(mcp_args[mcp_args.index("--inputs") + 1]).resolve(), self.inputs.resolve())
            self.assertEqual(kwargs["env"]["ANTHROPIC_BASE_URL"], "http://127.0.0.1:11434")
        events = [
            {"type": "assistant", "message": {"content": [{"type": "tool_use", "id": "read",
                "name": "Read", "input": {"file_path": "capability-input.json"}}]}},
            {"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": "read", "content": nonce}]}},
            {"type": "assistant", "message": {"content": [{"type": "tool_use", "id": "export",
                "name": "mcp__reverseai__export_function", "input": {"file": "greet", "entry": "0x1000"}}]}},
            {"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": "export",
                "is_error": True, "content": "Arguments must match this tool's input schema."}]}},
            {"type": "result", "structured_output": {"nonce": nonce}},
        ]
        if self.mcp_accept:
            events[2:4] = accepted_mcp_events("claude")
        if codex:
            events = [{"type": "item.completed", "item": {"type": "command_execution",
                "command": "cat capability-input.json", "exit_code": 0, "aggregated_output": nonce}}]
            if self.mcp_accept:
                events += accepted_mcp_events("codex")
            else:
                events += [{"type": "item.completed", "item": {"type": "mcp_tool_call", "server": "reverseai",
                    "tool": "export_function", "status": "failed", "arguments": {"file": "greet", "entry": "0x1000"},
                    "result": None, "error": {"code": -32602, "message": "Invalid arguments"}}}]
            events.append({"type": "turn.completed"})
            Path(argv[argv.index("-o") + 1]).write_text(json.dumps({"nonce": nonce}))
        return subprocess.CompletedProcess(argv, 0, "\n".join(map(json.dumps, events)), "")

    def rejected_export(self, client):
        def check(router, client, **kwargs):
            return selfhost.check_model(router, client, context_query=lambda server, model: 65536, **kwargs)

        q = queen.Queen(engine=FakeEngine(self.inputs), out=self.root / "run", bees=self.router(client),
                        model_check=check, attempt_not_started=bees.AttemptNotStarted)
        with patch("hive.bees.run_cli", side_effect=self.cli), \
             patch.object(queen.Build, "ensure_confinement"), \
             patch.object(q, "plan", side_effect=AssertionError("planner reached after rejected MCP arguments")) as planner, \
             patch("urllib.request.urlopen", side_effect=AssertionError("network forbidden")), \
             contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(queen.HiveError, "mcp_tool"):
                q.run()
        planner.assert_not_called()
        self.assertEqual(len(self.calls), 1)
        report = q.model_checks[0]
        self.assertEqual(report["checks"]["tool_roundtrip"]["status"], "ok")
        self.assertEqual(report["checks"]["structured_output"]["status"], "ok")
        self.assertNotEqual(report["checks"]["mcp_tool"]["status"], "ok")
        self.assertEqual(report["attempt"]["tool_rejections"], 1)
        self.assertEqual(q.stopped, "model_capability")
        self.assertEqual(q.spent["bees"], 1)
        attempts = list(q.state.data["attempts"].values())
        self.assertEqual([a["kind"] for a in attempts], ["network_probe"])
        self.assertIn("export_function", self.calls[0][1]["input"])
        self.assertIn("greet", self.calls[0][1]["input"])
        self.assertIn("4096", self.calls[0][1]["input"])
        self.assertFalse((q.out / "plan/manifest.json").exists())


    def test_read_success_with_rejected_export_stops_before_planning(self):
        self.rejected_export("claude")

    def test_codex_read_success_with_rejected_export_stops_before_planning(self):
        self.rejected_export("codex")

    def test_native_mcp_acceptance_allows_planning_for_both_clients(self):
        class PlanningReached(Exception):
            pass
        self.mcp_accept = True
        for client in ("claude", "codex"):
            with self.subTest(client=client):
                def check(router, selected, **kwargs):
                    self.assertEqual(kwargs["mcp_probe"], {"file": "greet", "entry": "0x1000"})
                    return selfhost.check_model(router, selected, context_query=lambda s, m: 65536, **kwargs)
                q = queen.Queen(engine=FakeEngine(self.inputs), out=self.root / client, bees=self.router(client),
                                model_check=check, attempt_not_started=bees.AttemptNotStarted)
                with patch("hive.bees.run_cli", side_effect=self.cli), patch.object(queen.Build, "ensure_confinement"), \
                     patch.object(q, "plan", side_effect=PlanningReached) as planner, \
                     patch("urllib.request.urlopen", side_effect=AssertionError("network forbidden")), \
                     contextlib.redirect_stdout(io.StringIO()), self.assertRaises(PlanningReached):
                    q.run()
                self.assertEqual(planner.call_count, 1)
                self.assertTrue(q.model_checks[0]["ok"], q.model_checks)
                self.assertEqual(q.model_checks[0]["checks"]["mcp_tool"]["status"], "ok")
                self.assertEqual(q.spent["bees"], 1)
                self.assertEqual(q.model_checks[0]["attempt"]["tool_rejections"], 0)
                self.assertIsNone(q.stopped)


if __name__ == "__main__":
    unittest.main()
