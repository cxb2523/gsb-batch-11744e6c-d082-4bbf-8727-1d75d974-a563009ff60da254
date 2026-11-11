import argparse
import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.hive_compiler import confined
from hive import bees as bees_module, codex_bees, planning, preflight, queen, selfhost
from tests import test_hive_queen as fixtures
from tests.test_hive_queen import FakeBees, FakeEngine, GOOD, make_queen

PACKED = {"verdict": "packed", "packers": ["UPX"], "signals": [
    {"strength": "strong", "signal": "packer section", "detail": "segment named 'UPX1' belongs to UPX"}],
    "advice": "Unpack it first.", "file_entropy": 7.9, "executable_bytes": 1}
CLEAN = {"verdict": "clean", "packers": [], "signals": [], "advice": "", "file_entropy": 5.0, "executable_bytes": 1}


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        (self.tmp / "inputs").mkdir()
        (self.tmp / "inputs" / "greet").write_bytes(b"x")

    def queen(self, bees, verdict, **kwargs):
        def check(claims, out):
            return {"claims": 1, "confirmed": 1, "rejected": 0, "questions": 1,
                    "input_sha256": ["cd" * 32]}, []
        return make_queen(engine=FakeEngine(self.tmp / "inputs"), out=self.tmp / "run", bees=bees, slots=2,
                           check=check, preflight=lambda engine, program_map, folder: verdict, **kwargs)

    def test_a_packed_program_stops_before_any_bee(self):
        bees = FakeBees(GOOD)
        result = self.queen(bees, PACKED).run()
        self.assertEqual(result["verdict"], "not started")
        self.assertIn("UPX", result["reason"])
        self.assertEqual(bees.calls, [])
        report = (self.tmp / "run" / "REPORT.md").read_text()
        self.assertIn("Pre-flight: packed", report)
        self.assertIn("Language: not chosen", report)

    @unittest.skipUnless(confined("c"), "needs a Clang compiler the hive can confine")
    def test_the_operator_can_allow_a_packed_program(self):
        bees = FakeBees(GOOD)
        result = self.queen(bees, PACKED, allow_packed=True).run()
        self.assertTrue(bees.calls)
        self.assertEqual(result["preflight"]["verdict"], "packed")

    @unittest.skipUnless(confined("c"), "needs a Clang compiler the hive can confine")
    def test_a_clean_program_runs_and_reports_its_preflight(self):
        result = self.queen(FakeBees(GOOD), CLEAN).run()
        self.assertEqual(result["verdict"], "accepted without behaviour proof")
        self.assertIn("Pre-flight: clean", (self.tmp / "run" / "REPORT.md").read_text())

    def test_main_options_choose_the_bee_runner(self):
        parser = argparse.ArgumentParser()
        codex_bees.add_arguments(parser)
        claude = object()
        kwargs = {"engine": self.tmp, "inputs": self.tmp / "inputs", "config_dir": self.tmp / "codex"}
        self.assertIs(codex_bees.build(parser.parse_args([]), claude, **kwargs), claude)
        self.assertIsInstance(codex_bees.build(parser.parse_args(["--bee-policy", "codex"]), claude, **kwargs),
                              codex_bees.CodexBees)
        mixed = codex_bees.build(parser.parse_args(["--bee-policy", "mixed"]), claude, **kwargs)
        self.assertIsInstance(mixed, codex_bees.MixedBees)
        self.assertIs(mixed.claude, claude)

    def test_the_command_line_offers_language_preflight_and_policy(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit):
            queen.main(["run", "--help"])
        for option in ("--language", "--allow-packed", "--bee-policy", "--codex-model", "--run-original"):
            self.assertIn(option, out.getvalue())

class RealSeamTests(unittest.TestCase):
    """Actual routing, CLI parsers, hooks and planning; only processes/server/engine are inert."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hive-real-seams-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.inputs, self.out = self.root / "inputs", self.root / "run"
        self.inputs.mkdir()
        (self.inputs / "greet").write_bytes(b"inert fixture")
        self.calls, self.declared, self.tool_evidence, self.refuse_second = [], 65536, True, False
        self.network_failure = False
        self.metadata_url = "http://127.0.0.1:11434/api/ps"
        for target, value in (("ensure_confinement", None), ("syntax", (True, ""))):
            stub = patch.object(queen.Build, target, return_value=value)
            stub.start()
            self.addCleanup(stub.stop)
        for target, operation in (("hive.bees.run_cli", self.cli), ("urllib.request.urlopen", self.metadata)):
            stub = patch(target, side_effect=operation)
            stub.start()
            self.addCleanup(stub.stop)

    def metadata(self, request, timeout):
        self.assertEqual(request.full_url, self.metadata_url)
        self.assertEqual(timeout, 5)
        payload = {"models": [{"name": model, "context_length": self.declared}
                              for model in ("fixture-local", "fixture-fallback")]}
        return contextlib.closing(io.BytesIO(json.dumps(payload).encode()))

    def cli(self, argv, **kwargs):
        folder = Path(kwargs["cwd"])
        codex = "--output-schema" in argv
        schema = json.loads(Path(argv[argv.index("--output-schema") + 1]).read_bytes()) if codex else json.loads(
            argv[argv.index("--json-schema") + 1])
        name = (Path(argv[argv.index("-o") + 1]).stem if codex else
                Path(argv[argv.index("--mcp-config") + 1]).stem)
        server = (kwargs.get("env") or {}).get("ANTHROPIC_BASE_URL")
        self.calls.append(("codex" if codex else "claude", name, server))
        events = []
        if name.startswith("network-probe-"):
            output = {"exit_code": 0 if self.network_failure else 7}
            events = [{"type": "item.completed", "item": {"type": "command_execution",
                "command": codex_bees.NETWORK_COMMAND, "exit_code": output["exit_code"]}},
                {"type": "turn.completed"}]
        elif (folder / "capability-input.json").exists():
            nonce = json.loads((folder / "capability-input.json").read_bytes())["nonce"]
            output = {"nonce": nonce}
            if self.tool_evidence:
                events = ([{"type": "item.completed", "item": {"type": "command_execution",
                    "command": "cat capability-input.json", "exit_code": 0, "aggregated_output": nonce}}] if codex else [
                    {"type": "assistant", "message": {"content": [{"type": "tool_use", "id": "read",
                        "name": "Read", "input": {"file_path": "capability-input.json"}}]}},
                    {"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": "read", "content": nonce}]}}])
            if self.tool_evidence:
                marker = "using these structured arguments: "
                self.assertIn(marker, kwargs["input"])
                arguments, _ = json.JSONDecoder().raw_decode(kwargs["input"].split(marker, 1)[1])
                self.assertEqual(arguments["file"], "greet")
                self.assertEqual(arguments["entry"], 0x1000)
                self.assertIs(type(arguments["entry"]), int)
                self.assertEqual(arguments["part"], "info")
                if codex:
                    events.append({"type": "item.completed", "item": {"type": "mcp_tool_call", "id": "export",
                        "server": "reverseai", "tool": "export_function", "arguments": arguments,
                        "status": "completed", "error": None,
                        "result": {"content": [{"type": "text", "text": "Derived function metadata"}]}}})
                else:
                    events.extend([
                        {"type": "assistant", "message": {"content": [{"type": "tool_use", "id": "export",
                            "name": "mcp__reverseai__export_function", "input": arguments}]}},
                        {"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": "export",
                            "content": [{"type": "text", "text": "Derived function metadata"}]}]}}])
        elif self.refuse_second and name == "planner-g0002" and server is None:
            events = [{"type": "result", "is_error": True, "error": {"type": "refusal"},
                       "result": "I cannot assist with this request."}]
            return subprocess.CompletedProcess(argv, 0, json.dumps(events[0]), "")
        else:
            self.assertTrue(name.startswith("planner-g"), name)
            self.assertIn("declarations", schema["properties"])
            self.assertIn("Plan only group", kwargs["input"])
            self.assertNotIn("Use the legacy schema", kwargs["input"])
            source = json.loads((folder / "map.json").read_bytes())
            output = {"modules": [], "skipped": [{"entry": row["hex"], "reason": "inert library",
                       "evidence": [row["hex"]]} for row in source["functions"]], "declarations": [], "unknowns": []}
        self.assertTrue(bees_module.matches_schema(output, schema), (output, schema))
        if codex:
            Path(argv[argv.index("-o") + 1]).write_text(json.dumps(output))
            if not any(e.get("type") == "turn.completed" for e in events):
                events.append({"type": "turn.completed"})
        else:
            events.append({"type": "result", "structured_output": output})
        return subprocess.CompletedProcess(argv, 0, "\n".join(json.dumps(e) for e in events), "")

    def router(self, *flags):
        parser = argparse.ArgumentParser()
        parser.add_argument("--model")
        codex_bees.add_arguments(parser)
        args = parser.parse_args(flags)
        claude = bees_module.ClaudeBees(engine=self.root, inputs=self.inputs, config_dir=self.root / "claude")
        return codex_bees.build_router(args, claude, engine=self.root, inputs=self.inputs, config_dir=self.root / "codex")

    def make(self, router, **kwargs):
        return queen.Queen(engine=fixtures.FakeEngine(self.inputs), out=self.out, bees=router,
                           attempt_not_started=bees_module.AttemptNotStarted, **kwargs)

    def run_quietly(self, q):
        with contextlib.redirect_stdout(io.StringIO()):
            return q.run()

    def test_s1_real_adapters_and_planning_resume_only_unfinished_groups(self):
        self.refuse_second = True
        original_partition = queen.partition.partition
        with patch.object(queen.partition, "partition", side_effect=lambda source: original_partition(source, max_functions=1)):
            first = self.make(self.router())
            with self.assertRaises(queen.ProviderRefused):
                self.run_quietly(first)
            progress = json.loads((self.out / "plan/progress.json").read_bytes())
            self.assertEqual(list(progress["groups"]), ["g0001"])
            preserved = progress["groups"]["g0001"]
            second = self.make(self.router("--fallback-model-server", "http://127.0.0.1:11434",
                "--fallback-model", "fixture-local", "--fallback-scope", "bee", "--fallback-bee", "planner-g0002"),
                resume_refused=True, model_check=selfhost.check_model)
            self.run_quietly(second)
        ordinary = [(name, server) for _, name, server in self.calls if not name.startswith("model-check-")]
        self.assertEqual(ordinary, [("planner-g0001", None), ("planner-g0002", None),
                                   ("planner-g0002", "http://127.0.0.1:11434"), ("planner-g0003", None)])
        self.assertEqual(json.loads((self.out / "plan/progress.json").read_bytes())["groups"]["g0001"], preserved)
        self.assertEqual(second.spent["bees"], 5)  # Four logical attempts plus the mandatory local capability probe.
        self.assertFalse(second.state.data["unresolved_refusals"])
        ids = second.plan_bundle["planner_attempts"]
        self.assertEqual(len(ids), 4)
        self.assertTrue(all(second.state.data["attempts"][aid]["kind"] == "bee" for aid in ids))
        self.assertEqual(len(second.model_checks), 1)
        planning.validate_bundle(second.plan_bundle, second.program_map, out=self.out, language="c", max_functions=12)
        third = self.make(self.router("--fallback-model-server", "http://127.0.0.1:11434",
            "--fallback-model", "fixture-local", "--fallback-scope", "bee", "--fallback-bee", "planner-g0002"))
        before = len(self.calls)
        self.run_quietly(third)
        self.assertEqual(len(self.calls), before + 1)  # Mandatory capability recheck, no planner.
        self.assertTrue(self.calls[-1][1].startswith("model-check-"))
        self.assertEqual(third.spent["bees"], 6)

    def test_real_codex_negative_isolation_cache_keeps_cause_without_spending_again(self):
        self.network_failure = True
        q = self.make(self.router("--bee-policy", "codex"))
        folder = self.out / "plan/groups/g0001"
        folder.mkdir(parents=True)
        first = q.bee("planner", "planner-g0001", "Task", folder, schema=planning.GROUP_SCHEMA)
        second = q.bee("planner", "planner-g0002", "Task", folder, schema=planning.GROUP_SCHEMA)
        for result in (first, second):
            self.assertEqual(result["outcome"], "failure")
            self.assertEqual(result["code"], "network_isolation")
            self.assertIsNone(result["output"])
        self.assertIsNotNone(first["provenance"]["attempt_id"])
        self.assertIsNone(second["provenance"].get("attempt_id"))
        self.assertEqual(q.spent["bees"], 1)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(next(iter(q.state.data["attempts"].values()))["kind"], "network_probe")

    def test_main_checks_selfhost_capabilities_before_actual_planning(self):
        with patch.object(queen, "Engine", side_effect=lambda **kw: fixtures.FakeEngine(kw["inputs"])), \
             patch.object(bees_module, "environment_ok", return_value=True), \
             patch.object(queen.preflight, "run", return_value=CLEAN), contextlib.redirect_stdout(io.StringIO()):
            rc = queen.main(["run", "--inputs", str(self.inputs), "--file", "greet", "--out", str(self.out),
                             "--model-server", "http://127.0.0.1:11434", "--model", "fixture-local"])
        self.assertEqual(rc, 1)  # Inert, all-skipped plan has no rebuilt binary or evidence claims.
        result = json.loads((self.out / "result.json").read_bytes())
        self.assertEqual(result["model_checks"][0]["required_context"], 65536)
        self.assertTrue(result["model_checks"][0]["ok"])
        self.assertEqual(result["spent"]["bees"], 2)
        self.assertTrue(self.calls[0][1].startswith("model-check-"))
        self.assertEqual(self.calls[1][1], "planner-g0001")
        self.assertTrue((self.out / "plan/manifest.json").is_file())

    def test_capabilities_block_bad_context_and_recheck_after_server_is_corrected(self):
        self.declared = 8192
        flags = ("--model-server", "http://127.0.0.1:11434", "--codex-model", "fixture-local", "--bee-policy", "codex")
        first = self.make(self.router(*flags), model_check=selfhost.check_model)
        with self.assertRaisesRegex(queen.HiveError, "Declared context 8192 is smaller than required 65536"):
            self.run_quietly(first)
        result = json.loads((self.out / "result.json").read_bytes())
        self.assertEqual(result["model_checks"][0]["checks"]["context"]["status"], "error")
        self.assertEqual(first.spent["bees"], 2)  # Isolation and capability processes.
        self.assertFalse((self.out / "plan/manifest.json").exists())
        self.declared = 65536
        second = self.make(self.router(*flags), model_check=selfhost.check_model)
        self.run_quietly(second)
        self.assertIsNotNone(second.plan_bundle)
        self.assertEqual(second.spent["bees"], 6)  # Fresh router: isolation+check, isolation+planner.
        self.assertEqual(len(self.calls), 6)

    def test_missing_native_tools_or_unknown_context_stop_before_planning(self):
        for index, tool_evidence, declared, label in ((0, False, 65536, "tool_roundtrip"), (1, True, None, "context")):
            with self.subTest(check=label):
                self.out = self.root / f"run-{index}"
                self.tool_evidence, self.declared = tool_evidence, declared
                q = self.make(self.router("--fallback-model-server", "http://127.0.0.1:11434",
                    "--fallback-model", "fixture-local", "--fallback-scope", "run"), model_check=selfhost.check_model)
                with self.assertRaisesRegex(queen.HiveError, label):
                    self.run_quietly(q)
                self.assertEqual(q.spent["bees"], 1)
                self.assertFalse((self.out / "plan/manifest.json").exists())

    def test_capability_budget_denies_before_any_cli_or_server_request(self):
        q = self.make(self.router("--model-server", "http://127.0.0.1:11434", "--codex-model", "fixture-local",
            "--bee-policy", "codex"), model_check=selfhost.check_model, max_bees=1)
        result = self.run_quietly(q)
        self.assertEqual(result["stop_reason"], "budget_insufficient")
        self.assertEqual(q.spent["bees"], 0)
        self.assertEqual(self.calls, [])

    def test_capability_hook_denial_converts_to_not_started_without_a_result(self):
        def stopping_check(router, client, **kwargs):
            q._stop("budget_exhausted")
            return selfhost.check_model(router, client, **kwargs)
        q = self.make(self.router("--model-server", "http://127.0.0.1:11434", "--model", "fixture-local"),
                      model_check=stopping_check)
        result = self.run_quietly(q)
        self.assertEqual(result["stop_reason"], "budget_exhausted")
        self.assertEqual(result["spent"]["bees"], 0)
        self.assertEqual(result["attempts"], [])
        self.assertEqual(self.calls, [])

    def test_main_checks_fallback_cli_and_rejects_invalid_required_context(self):
        common = ["run", "--inputs", str(self.inputs), "--file", "greet", "--out", str(self.out)]
        with patch.object(bees_module, "environment_ok", side_effect=[True, False]) as presence, \
             contextlib.redirect_stderr(io.StringIO()) as errors, self.assertRaises(SystemExit):
            queen.main(common + ["--fallback-model-server", "http://127.0.0.1:11434",
                                 "--fallback-model", "fixture-local", "--fallback-scope", "run"])
        self.assertEqual(presence.call_count, 2)
        self.assertIn("fallback_targets claude CLI", errors.getvalue())
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            queen.main(common + ["--required-context", "0"])
        self.assertEqual(self.calls, [])

    def test_main_cloud_skips_capability_probes_and_context_threshold_is_overridable(self):
        common = ["run", "--inputs", str(self.inputs), "--file", "greet"]
        for index, flags, count in ((0, [], 1), (1, ["--model-server", "http://127.0.0.1:11434",
                "--model", "fixture-local", "--required-context", "8192"], 2)):
            with self.subTest(flags=flags), patch.object(queen, "Engine", side_effect=lambda **kw: fixtures.FakeEngine(kw["inputs"])), \
                 patch.object(bees_module, "environment_ok", return_value=True), \
                 patch.object(queen.preflight, "run", return_value=CLEAN), contextlib.redirect_stdout(io.StringIO()):
                self.out = self.root / f"main-{index}"
                self.declared = 8192
                self.calls.clear()
                queen.main(common + ["--out", str(self.out)] + flags)
                self.assertEqual(len(self.calls), count)
                result = json.loads((self.out / "result.json").read_bytes())
                self.assertEqual(len(result["model_checks"]), index)
                if index:
                    self.assertEqual(result["model_checks"][0]["required_context"], 8192)

    def test_both_clients_and_destinations_are_checked_without_starting_ordinary_bees(self):
        router = self.router("--bee-policy", "mixed", "--model-server", "http://127.0.0.1:11434",
            "--model", "fixture-local", "--codex-model", "fixture-local", "--fallback-model-server", "http://127.0.0.1:11434",
            "--fallback-model", "fixture-fallback", "--fallback-codex-model", "fixture-fallback", "--fallback-scope", "run")
        q = self.make(router)
        q._ensure_state()
        with contextlib.redirect_stdout(io.StringIO()):
            q.check_models(queen.survey(q.engine, q.out / "survey", lambda _: None))
        self.assertEqual([(r["client"], r["attempt"]["provenance"]["origin"]) for r in q.model_checks],
                         [("claude", "primary"), ("codex", "primary"), ("claude", "fallback"), ("codex", "fallback")])
        self.assertEqual(q.spent["bees"], 6)
        self.assertTrue(all(a["kind"] == "network_probe" for a in q.state.data["attempts"].values()))
        self.assertFalse((self.out / "plan/manifest.json").exists())

    def test_explicit_remote_primary_keeps_remote_provenance_in_probe_and_plan(self):
        self.metadata_url = "https://models.example/api/ps"
        q = self.make(self.router("--model-server", "https://models.example", "--model-server-remote",
                                 "--model", "fixture-local"))
        self.run_quietly(q)
        self.assertEqual(q.spent["bees"], 2)
        for attempt in q.state.data["attempts"].values():
            self.assertEqual(attempt["server_kind"], "remote")
            self.assertEqual(attempt["result"]["provenance"]["server_kind"], "remote")


if __name__ == "__main__":
    unittest.main()
