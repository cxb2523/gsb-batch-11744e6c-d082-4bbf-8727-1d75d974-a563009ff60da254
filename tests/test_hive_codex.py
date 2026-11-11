import argparse
import copy
import json
import subprocess
import tempfile
import tomllib
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import Mock, patch

from hive import bees
from hive.codex_bees import CodexBees, MixedBees, add_arguments, build, drop_nulls, strict_schema


ANSWERS = {
    "planner": {"modules": [{"id": "one", "title": "entry", "functions": ["0x1000"], "rationale": None}],
                "skipped": [], "notes": None},
    "worker": {"status": "done", "functions": [{"entry": "0x1000", "name": None,
                                               "status": "rebuilt", "notes": None}],
               "contract_requests": None, "unknowns": None},
    "repair": {"status": "done", "functions": [], "contract_requests": [], "unknowns": []},
    "councillor": {"verdict": "accept", "defects": [], "summary": None},
    "tester": {"cases": [{"id": "stdin", "files": [{"name": "input", "text": "abc", "base64": None}],
                          "steps": [{"args": [], "stdin": None}], "why": None}]},
}


def overrides(argv):
    return tomllib.loads("\n".join(argv[index + 1] for index, arg in enumerate(argv) if arg == "-c"))


class SchemaTests(unittest.TestCase):
    def test_all_role_schemas_are_strict_recursively_without_mutating_claude(self):
        original = copy.deepcopy(bees.SCHEMAS)

        def check(schema):
            if isinstance(schema, list):
                for item in schema:
                    check(item)
            elif isinstance(schema, dict):
                if schema.get("type") == "object":
                    self.assertEqual(schema["required"], list(schema["properties"]))
                    self.assertIs(schema["additionalProperties"], False)
                for item in schema.values():
                    check(item)

        for role in ("planner", "worker", "repair", "councillor", "tester"):
            check(strict_schema(bees.SCHEMAS[role]))
        self.assertEqual(bees.SCHEMAS, original)
        schema = strict_schema(bees.SCHEMAS["worker"])
        self.assertEqual(schema["required"], ["status", "functions", "contract_requests", "unknowns"])
        self.assertEqual(schema["properties"]["status"]["enum"], ["done", "partial", "blocked"])
        self.assertEqual(schema["properties"]["unknowns"]["anyOf"][1], {"type": "null"})

    def test_optional_enum_and_nested_objects_are_nullable(self):
        schema = strict_schema({"type": "object", "properties": {
            "mode": {"type": "string", "enum": ["a", "b"]},
            "child": {"type": "object", "properties": {"text": {"type": "string"}}}}})
        self.assertEqual(schema["properties"]["mode"], {
            "anyOf": [{"type": "string", "enum": ["a", "b"]}, {"type": "null"}]})
        child = schema["properties"]["child"]["anyOf"][0]
        self.assertEqual(child["required"], ["text"])
        self.assertIs(child["additionalProperties"], False)

    def test_null_removal_preserves_false_empty_values_and_array_positions(self):
        value = {"optional": None, "nested": [{"drop": None, "keep": ""}, None],
                 "false": False, "zero": 0, "empty": []}
        self.assertEqual(drop_nulls(value), {"nested": [{"keep": ""}, None],
                                            "false": False, "zero": 0, "empty": []})
        self.assertIn("optional", value)


class CodexRunnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.folder = self.root / "bee"
        self.folder.mkdir()
        self.runner = CodexBees(engine=self.root / 'engine "quoted"', inputs=self.root / "inputs with spaces",
                                python='/python "quoted"', config_dir=self.root / "config", timeout=7,
                                allow_network=True)

    def run_bee(self, role="worker", *, answer=None, returncode=0, stderr="", write=True):
        def run(argv, **kwargs):
            if write:
                Path(argv[argv.index("-o") + 1]).write_text(json.dumps(ANSWERS[role] if answer is None else answer))
            return subprocess.CompletedProcess(argv, returncode, stdout='{"type":"turn.completed"}', stderr=stderr)

        with patch("hive.bees.run_cli", side_effect=run) as process:
            result = self.runner(role, "bee-1", "TASK", self.folder)
        return result, process.call_args

    def test_argv_requests_sandbox_approvals_network_and_the_single_mcp_server(self):
        for role in ("planner", "worker", "repair", "councillor", "tester"):
            with self.subTest(role=role):
                result, call = self.run_bee(role)
                self.assertTrue(result["ok"], result)
                argv, kwargs = call.args[0], call.kwargs
                self.assertEqual(argv[:2], ["codex", "exec"])
                for flag in ("--ignore-user-config", "--skip-git-repo-check", "--ephemeral"):
                    self.assertIn(flag, argv)
                self.assertIn("--json", argv)
                self.assertNotIn("--dangerously-bypass-approvals-and-sandbox", argv)
                self.assertNotIn("--approve-for-me", argv)
                self.assertNotIn("--add-dir", argv)
                self.assertNotIn("-m", argv)
                self.assertEqual(argv[-1], "-")
                self.assertEqual(argv[argv.index("-C") + 1], str(self.folder.resolve()))
                self.assertEqual(argv[argv.index("--sandbox") + 1],
                                 "read-only" if role == "councillor" else "workspace-write")
                config = overrides(argv)
                self.assertEqual(config["approval_policy"], "never")
                self.assertIs(config["sandbox_workspace_write"]["network_access"], False)
                self.assertEqual(config["sandbox_workspace_write"]["writable_roots"], [])
                self.assertIs(config["sandbox_workspace_write"]["exclude_tmpdir_env_var"], True)
                self.assertIs(config["sandbox_workspace_write"]["exclude_slash_tmp"], True)
                self.assertEqual(config["web_search"], "disabled")
                self.assertEqual(set(config["mcp_servers"]), {"reverseai"})
                server = config["mcp_servers"]["reverseai"]
                self.assertEqual(server["command"], '/python "quoted"')
                self.assertEqual(server["args"], ["-B", "-m", "reverseai", "mcp", "--inputs",
                                                   str((self.root / "inputs with spaces").resolve()), "--with-ghidra"])
                self.assertEqual(server["env"], {"PYTHONPATH": str((self.root / 'engine "quoted"').resolve()),
                                                  "PYTHONDONTWRITEBYTECODE": "1"})
                schema_path = Path(argv[argv.index("--output-schema") + 1])
                self.assertFalse(schema_path.is_relative_to(self.folder))
                self.assertIs(json.loads(schema_path.read_text())["additionalProperties"], False)
                self.assertEqual(kwargs["input"], bees.brief(role, "TASK"))
                self.assertEqual(kwargs["cwd"], self.folder)
                self.assertEqual(kwargs["timeout"], 7)
                self.assertTrue(kwargs["capture_output"])
                self.assertTrue(kwargs["text"])
                self.assertFalse(kwargs["check"])

    def test_model_effort_and_enabled_tools_are_explicit(self):
        self.runner.model, self.runner.effort = "chosen-model", "high"
        self.runner.enabled = ("ghidra", "yara")
        result, call = self.run_bee()
        self.assertTrue(result["ok"])
        argv = call.args[0]
        self.assertEqual(argv[argv.index("-m") + 1], "chosen-model")
        config = overrides(argv)
        self.assertEqual(config["model_reasoning_effort"], "high")
        self.assertEqual(config["mcp_servers"]["reverseai"]["args"][-2:], ["--with-ghidra", "--with-yara"])

    def test_final_file_is_parsed_and_optional_nulls_removed_for_the_queen(self):
        result, _ = self.run_bee()
        self.assertEqual(result["output"], {"status": "done", "functions": [{"entry": "0x1000", "status": "rebuilt"}]})
        self.assertIn("seconds", result)
        result, _ = self.run_bee("tester")
        self.assertEqual(result["output"]["cases"][0], {
            "id": "stdin", "files": [{"name": "input", "text": "abc"}], "steps": [{"args": []}]})

    def test_nonzero_exit_cannot_accept_a_valid_answer(self):
        result, _ = self.run_bee(returncode=3, stderr="native refusal")
        self.assertFalse(result["ok"])
        self.assertIn("exit 3: native refusal", result["error"])

    def test_missing_file_cannot_reuse_a_previous_success(self):
        self.assertTrue(self.run_bee()[0]["ok"])
        result, _ = self.run_bee(write=False)
        self.assertFalse(result["ok"])
        self.assertIsNone(result["output"])

    def test_malformed_json_and_invalid_output_fail_closed(self):
        bad = [[], "text", 3, None, {}, {**ANSWERS["worker"], "extra": True},
               {**ANSWERS["worker"], "status": "accepted"},
               {**ANSWERS["worker"], "functions": [None]},
               {**ANSWERS["worker"], "functions": [{"entry": 123, "name": None,
                                                     "status": "rebuilt", "notes": None}]},
               {"status": "done", "functions": []}]
        for value in bad:
            with self.subTest(value=value):
                def run(argv, **kwargs):
                    Path(argv[argv.index("-o") + 1]).write_text(json.dumps(value))
                    return subprocess.CompletedProcess(argv, 0, '{"type":"turn.completed"}', "")
                with patch("hive.bees.run_cli", side_effect=run):
                    self.assertFalse(self.runner("worker", "bad", "TASK", self.folder)["ok"])
        def malformed(argv, **kwargs):
            Path(argv[argv.index("-o") + 1]).write_text("{broken")
            return subprocess.CompletedProcess(argv, 0, '{"type":"turn.completed"}', "")
        with patch("hive.bees.run_cli", side_effect=malformed):
            self.assertFalse(self.runner("worker", "bad", "TASK", self.folder)["ok"])

    def test_timeout_startup_io_and_invalid_role_fail_without_raising(self):
        for error in (subprocess.TimeoutExpired("codex", 7), FileNotFoundError("missing codex"),
                      OSError("native failure")):
            with self.subTest(error=error), patch("hive.bees.run_cli", side_effect=error):
                result = self.runner("worker", "failure", "TASK", self.folder)
                self.assertFalse(result["ok"])
                self.assertTrue(result["error"])
                if isinstance(error, subprocess.TimeoutExpired):
                    self.assertEqual(result["seconds"], 7)
        self.assertFalse(self.runner("unknown", "failure", "TASK", self.folder)["ok"])
        with patch("hive.bees.run_cli") as process:
            self.assertFalse(self.runner("worker", "../escape", "TASK", self.folder)["ok"])
            process.assert_not_called()
        self.runner.config_dir = self.folder / "not-a-directory"
        self.runner.config_dir.write_text("occupied")
        self.assertFalse(self.runner("worker", "failure", "TASK", self.folder)["ok"])

    def test_each_bee_has_separate_output_and_schema_paths(self):
        first = self.runner.argv("worker", "m01-build", self.folder)
        second = self.runner.argv("councillor", "m01-council-r1-io", self.folder)
        for flag in ("--output-schema", "-o"):
            self.assertNotEqual(first[first.index(flag) + 1], second[second.index(flag) + 1])


class NetworkGateTests(unittest.TestCase):
    def test_codex_stops_before_timeout_after_consecutive_mcp_schema_errors(self):
        import sys
        events = [{"type": "item.completed", "item": {"id": str(i), "type": "mcp_tool_call",
                   "tool": "export_function", "error": {"code": -32602, "message": "Invalid arguments"}}}
                  for i in range(2)]
        script = "import sys,time; sys.stdin.read(); print(" + repr("\n".join(map(json.dumps, events))) + ",flush=True); time.sleep(30)"
        runner = CodexBees(engine=self.root, inputs=self.root, config_dir=self.root / "stop-config",
                           allow_network=True, timeout=1)
        runner.max_tool_rejections = 2
        with patch.object(runner, "argv", return_value=[sys.executable, "-u", "-c", script]):
            result = runner("planner", "planner", "prompt", self.folder, schema={"type": "object"})
        self.assertEqual(result["outcome"], "tool_schema_failure")
        self.assertFalse(result["refused"])
        self.assertIsNone(result["output"])
        self.assertEqual(result["tool_rejections"], 2)
        self.assertEqual(result["consecutive_tool_rejections"], 2)
        self.assertEqual(result["tool_name"], "export_function")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.folder = self.root / "bee"
        self.folder.mkdir()
        self.runner = CodexBees(engine=self.root, inputs=self.root, config_dir=self.root / "config", timeout=7)
        self.calls = []
        self.probe_exit = 6
        self.probe_report = None
        self.probe_events = None
        self.probe_cli_rc = 0
        self.probe_error = None
        self.probe_write = True
        self.probe_stdout = None

    def fake_codex(self, argv, **kwargs):
        schema = json.loads(Path(argv[argv.index("--output-schema") + 1]).read_text())
        probe = list(schema["properties"]) == ["exit_code"]
        self.calls.append((probe, argv, kwargs))
        if probe and self.probe_error:
            raise self.probe_error
        output = Path(argv[argv.index("-o") + 1])
        if probe:
            command = "curl --max-time 5 --silent --show-error --output /dev/null https://example.com"
            self.assertIn(command, kwargs["input"])
            events = self.probe_events if self.probe_events is not None else [
                {"type": "item.completed", "item": {"type": "command_execution", "command": command,
                 "exit_code": self.probe_exit, "status": "failed" if self.probe_exit else "completed"}},
                {"type": "turn.completed"}]
            if self.probe_write:
                output.write_text(json.dumps(self.probe_report if self.probe_report is not None else
                                            {"exit_code": self.probe_exit}))
            stdout = self.probe_stdout if self.probe_stdout is not None else "\n".join(json.dumps(event) for event in events)
            return subprocess.CompletedProcess(argv, self.probe_cli_rc, stdout, "")
        role = "councillor" if "verdict" in schema["properties"] else "worker"
        output.write_text(json.dumps(ANSWERS[role]))
        return subprocess.CompletedProcess(argv, 0, '{"type":"turn.completed"}', "")

    def test_network_success_refuses_worker_before_its_task(self):
        self.probe_exit = 0
        with patch("hive.bees.run_cli", side_effect=self.fake_codex):
            result = self.runner("worker", "m02-build", "PRIVATE TASK", self.folder)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "Codex sandbox allowed network access; Codex bees refused")
        self.assertEqual(len(self.calls), 1)
        self.assertTrue(self.calls[0][0])
        self.assertNotIn("PRIVATE TASK", self.calls[0][2]["input"])

    def test_native_network_refusal_allows_the_worker_with_identical_sandbox_config(self):
        self.runner.model, self.runner.effort = "chosen-model", "high"
        with patch("hive.bees.run_cli", side_effect=self.fake_codex):
            result = self.runner("worker", "m02-build", "PRIVATE TASK", self.folder)
        self.assertTrue(result["ok"], result)
        self.assertNotIn("warning", result)
        self.assertEqual([probe for probe, _, _ in self.calls], [True, False])
        probe, bee = [call[1] for call in self.calls]
        for flag in ("--sandbox", "-C", "-m"):
            self.assertEqual(probe[probe.index(flag) + 1], bee[bee.index(flag) + 1])
        self.assertEqual(overrides(probe), overrides(bee))
        self.assertEqual(probe[probe.index("--sandbox") + 1], "workspace-write")
        self.assertEqual(overrides(probe)["approval_policy"], "never")
        self.assertEqual(set(overrides(probe)["mcp_servers"]), {"reverseai"})
        for flag in ("--ignore-user-config", "--json", "--ephemeral", "--skip-git-repo-check"):
            self.assertIn(flag, probe)
        self.assertIsNotNone(result["output"])

    def test_probe_outcomes_are_cached_per_sandbox_mode(self):
        with patch("hive.bees.run_cli", side_effect=self.fake_codex):
            for name in ("m02-build", "m04-build"):
                self.assertTrue(self.runner("worker", name, "TASK", self.folder)["ok"])
            self.probe_exit = 0
            for name in ("m01-council-r1-io", "m01-council-r1-control"):
                self.assertFalse(self.runner("councillor", name, "TASK", self.folder)["ok"])
            self.assertTrue(self.runner("worker", "m06-build", "TASK", self.folder)["ok"])
        probes = [argv for probe, argv, _ in self.calls if probe]
        self.assertEqual([argv[argv.index("--sandbox") + 1] for argv in probes], ["workspace-write", "read-only"])
        self.assertEqual(sum(not probe for probe, _, _ in self.calls), 3)

    def test_read_only_probe_can_allow_councillors(self):
        with patch("hive.bees.run_cli", side_effect=self.fake_codex):
            result = self.runner("councillor", "m01-council-r1-io", "TASK", self.folder)
        self.assertTrue(result["ok"], result)
        self.assertTrue(all(argv[argv.index("--sandbox") + 1] == "read-only" for _, argv, _ in self.calls))

    def test_concurrent_workers_share_one_probe(self):
        with patch("hive.bees.run_cli", side_effect=self.fake_codex):
            with ThreadPoolExecutor(max_workers=4) as pool:
                results = list(pool.map(lambda n: self.runner("worker", f"m{n:02}-build", "TASK", self.folder),
                                        (2, 4, 6, 8)))
        self.assertTrue(all(result["ok"] for result in results), results)
        self.assertEqual(sum(probe for probe, _, _ in self.calls), 1)

    def test_probe_exceptions_missing_output_and_native_failure_are_refused_and_cached(self):
        for error in (subprocess.TimeoutExpired("codex", 7), FileNotFoundError("missing codex"),
                      OSError("cannot start")):
            with self.subTest(error=error):
                self.runner._network_checks.clear()
                self.calls.clear()
                self.probe_error = error
                with patch("hive.bees.run_cli", side_effect=self.fake_codex):
                    for name in ("m02-build", "m04-build"):
                        result = self.runner("worker", name, "TASK", self.folder)
                        self.assertFalse(result["ok"])
                        self.assertEqual(result["error"], "Codex sandbox allowed network access; Codex bees refused")
                self.assertEqual(len(self.calls), 1)
        self.probe_error = None
        for write, rc in ((False, 0), (True, 1)):
            self.runner._network_checks.clear()
            self.calls.clear()
            self.probe_write, self.probe_cli_rc = write, rc
            with patch("hive.bees.run_cli", side_effect=self.fake_codex):
                self.assertFalse(self.runner("worker", "m02-build", "TASK", self.folder)["ok"])
            self.assertEqual(len(self.calls), 1)

    def test_missing_malformed_and_inconsistent_native_evidence_never_allows_a_bee(self):
        command = "curl --max-time 5 --silent --show-error --output /dev/null https://example.com"
        for events in ([], [{"type": "turn.completed"}], [None],
                       [{"type": "item.completed", "item": {"type": "command_execution", "command": "echo blocked",
                         "exit_code": 6}}, {"type": "turn.completed"}],
                       [{"type": "item.completed", "item": {"type": "command_execution", "command": command,
                         "exit_code": 0}}, {"type": "turn.completed"}],
                       [{"type": "item.completed", "item": {"type": "command_execution", "command": command,
                         "exit_code": 6}}]):
            with self.subTest(events=events):
                self.runner._network_checks.clear()
                self.calls.clear()
                self.probe_events = events
                with patch("hive.bees.run_cli", side_effect=self.fake_codex):
                    self.assertFalse(self.runner("worker", "m02-build", "TASK", self.folder)["ok"])
                self.assertEqual(len(self.calls), 1)

    def test_only_definite_dns_or_connect_failures_qualify(self):
        for code in (-1, 2, 23, 28, 60, 126, 127, "6", True):
            with self.subTest(exit_code=code):
                self.runner._network_checks.clear()
                self.calls.clear()
                self.probe_exit = code
                with patch("hive.bees.run_cli", side_effect=self.fake_codex):
                    self.assertFalse(self.runner("worker", "m02-build", "TASK", self.folder)["ok"])
                self.assertEqual(len(self.calls), 1)
        self.runner._network_checks.clear()
        self.probe_exit = 7
        with patch("hive.bees.run_cli", side_effect=self.fake_codex):
            self.assertTrue(self.runner("worker", "m02-build", "TASK", self.folder)["ok"])

    def test_invalid_probe_report_extra_commands_and_broken_jsonl_are_refused(self):
        for report in ({}, {"exit_code": "6"}, {"exit_code": True}, {"exit_code": 0},
                       {"exit_code": 6, "extra": "claim"}):
            with self.subTest(report=report):
                self.runner._network_checks.clear()
                self.probe_report = report
                with patch("hive.bees.run_cli", side_effect=self.fake_codex):
                    self.assertFalse(self.runner("worker", "m02-build", "TASK", self.folder)["ok"])
        self.probe_report = None
        for stdout in ("{broken", "[]", "null"):
            self.runner._network_checks.clear()
            self.probe_stdout = stdout
            with patch("hive.bees.run_cli", side_effect=self.fake_codex):
                self.assertFalse(self.runner("worker", "m02-build", "TASK", self.folder)["ok"])
        self.probe_stdout = None
        self.runner._network_checks.clear()
        command = "curl --max-time 5 --silent --show-error --output /dev/null https://example.com"
        self.probe_events = [{"type": "item.completed", "item": {"type": "command_execution", "command": command,
                              "exit_code": code}} for code in (0, 6)] + [{"type": "turn.completed"}]
        with patch("hive.bees.run_cli", side_effect=self.fake_codex):
            self.assertFalse(self.runner("worker", "m02-build", "TASK", self.folder)["ok"])

    def test_shell_wrapped_exact_probe_command_is_recognized(self):
        self.probe_events = [
            {"type": "item.completed", "item": {"type": "command_execution", "exit_code": 6,
             "command": "/bin/zsh -lc 'curl --max-time 5 --silent --show-error --output /dev/null https://example.com'"}},
            {"type": "turn.completed"}]
        with patch("hive.bees.run_cli", side_effect=self.fake_codex):
            self.assertTrue(self.runner("worker", "m02-build", "TASK", self.folder)["ok"])

    def test_opt_out_skips_probe_and_warns_on_success_and_failure(self):
        self.runner.allow_network = True
        with patch("hive.bees.run_cli", side_effect=self.fake_codex):
            result = self.runner("worker", "m02-build", "TASK", self.folder)
        self.assertTrue(result["ok"])
        self.assertEqual(result["warning"], "Codex bees ran without network isolation")
        self.assertEqual([probe for probe, _, _ in self.calls], [False])
        self.assertEqual(self.runner._network_checks, {})
        with patch("hive.bees.run_cli", side_effect=OSError("cannot start")):
            result = self.runner("worker", "m04-build", "TASK", self.folder)
        self.assertFalse(result["ok"])
        self.assertEqual(result["warning"], "Codex bees ran without network isolation")
        with patch("hive.bees.run_cli", side_effect=subprocess.TimeoutExpired("codex", 7)):
            result = self.runner("worker", "m06-build", "TASK", self.folder)
        self.assertFalse(result["ok"])
        self.assertEqual(result["warning"], "Codex bees ran without network isolation")


class RoutingTests(unittest.TestCase):
    def setUp(self):
        self.claude = Mock(return_value={"ok": True, "output": {"runner": "claude"}})
        self.codex = Mock(return_value={"ok": True, "output": {"runner": "codex"}})

    def test_mixed_routing_covers_the_queens_names_and_all_repair_rounds(self):
        runner = MixedBees(self.claude, self.codex)
        routes = [("planner", "planner", "claude"), ("planner", "planner-fix2", "claude"),
                  ("tester", "tester", "claude"), ("repair", "behaviour-fix-2", "claude"),
                  ("worker", "m01-build", "claude"), ("worker", "m02-build", "codex"),
                  ("worker", "m03-build", "claude"), ("worker", "m100-build", "codex"),
                  ("repair", "m01-repair-b1", "claude"), ("repair", "m02-repair-b3", "codex"),
                  ("repair", "m01-repair-c2", "claude"), ("repair", "m02-repair-c2", "codex"),
                  ("repair", "m01-repair-l2", "claude"), ("repair", "m02-repair-l3", "codex"),
                  ("councillor", "m01-council-r1-control", "codex"),
                  ("councillor", "m01-council-r1-io", "codex"),
                  ("councillor", "m01-council-r1-data", "claude"),
                  ("councillor", "m02-council-r2-control", "claude"),
                  ("councillor", "m02-council-r2-io", "claude"),
                  ("councillor", "m02-council-r2-data", "codex")]
        for role, name, expected in routes:
            with self.subTest(name=name):
                self.claude.reset_mock()
                self.codex.reset_mock()
                result = runner(role, name, "TASK", Path("bee"))
                selected, other = ((self.claude, self.codex) if expected == "claude" else (self.codex, self.claude))
                selected.assert_called_once_with(role, name, "TASK", Path("bee"))
                other.assert_not_called()
                self.assertIs(result, selected.return_value)

    def test_single_model_policies_route_every_role_to_that_model(self):
        for policy, selected, other in (("claude", self.claude, self.codex), ("codex", self.codex, self.claude)):
            runner = MixedBees(self.claude, self.codex, policy)
            for role in ("planner", "worker", "repair", "councillor", "tester"):
                selected.reset_mock()
                other.reset_mock()
                self.assertIs(runner(role, "any-name", "TASK", "bee"), selected.return_value)
                selected.assert_called_once_with(role, "any-name", "TASK", "bee")
                other.assert_not_called()

    def test_unknown_policy_and_ambiguous_module_names_are_rejected(self):
        with self.assertRaises(ValueError):
            MixedBees(self.claude, self.codex, "other")
        runner = MixedBees(self.claude, self.codex)
        for role, name in (("worker", "unknown"), ("worker", "m00-build"),
                           ("councillor", "m01-council-r1-unknown"), ("repair", "m02-repair-x1"), ("unknown", "")):
            self.assertFalse(runner(role, name, "TASK", "bee")["ok"])
        self.claude.assert_not_called()
        self.codex.assert_not_called()

    def test_cli_factory_preserves_claude_default_and_separates_codex_settings(self):
        parser = argparse.ArgumentParser()
        add_arguments(parser)
        self.assertIs(build(parser.parse_args([]), self.claude), self.claude)
        settings = {"engine": ".", "inputs": ".", "config_dir": ".", "timeout": 123}
        args = parser.parse_args(["--bee-policy", "mixed", "--codex", "/bin/codex-test",
                                  "--codex-model", "chosen-model", "--codex-effort", "high"])
        runner = build(args, self.claude, **settings)
        self.assertIsInstance(runner, MixedBees)
        self.assertIs(runner.claude, self.claude)
        self.assertEqual(runner.codex.codex, "/bin/codex-test")
        self.assertEqual(runner.codex.model, "chosen-model")
        self.assertEqual(runner.codex.effort, "high")
        self.assertEqual(runner.codex.timeout, 123)
        self.assertFalse(runner.codex.allow_network)
        self.assertIsInstance(build(parser.parse_args(["--bee-policy", "codex"]), self.claude, **settings), CodexBees)
        opted_out = build(parser.parse_args(["--bee-policy", "codex", "--codex-allow-network"]),
                          self.claude, **settings)
        self.assertTrue(opted_out.allow_network)


if __name__ == "__main__":
    unittest.main()
