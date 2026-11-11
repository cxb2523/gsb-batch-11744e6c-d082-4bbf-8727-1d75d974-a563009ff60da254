import argparse
import http.server
import json
import os
import shutil
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from hive import bees, codex_bees, selfhost

ANSWER = {"verdict": "accept", "defects": []}


class ServerUrlTests(unittest.TestCase):
    def test_this_machine_is_accepted(self):
        for url in ("http://127.0.0.1:11434", "http://localhost:1234/", "http://[::1]:8080", "https://127.0.0.2"):
            with self.subTest(url=url):
                self.assertFalse(selfhost.server_url(url).endswith("/"))

    def test_another_machine_needs_the_remote_flag(self):
        with self.assertRaisesRegex(ValueError, "--model-server-remote"):
            selfhost.server_url("http://gpu.lan:8000")
        self.assertEqual(selfhost.server_url("http://gpu.lan:8000/", allow_remote=True), "http://gpu.lan:8000")

    def test_credentials_queries_and_other_schemes_are_refused(self):
        for url in ("http://user:pw@127.0.0.1:11434", "http://127.0.0.1:11434?key=1", "file:///tmp/x", "127.0.0.1:11434",
                    ""):
            with self.subTest(url=url), self.assertRaises(ValueError):
                selfhost.server_url(url)


SENTINELS = {  # one owned sentinel per credential family; real credentials are never read
    "CLAUDE_CODE_OAUTH_TOKEN": "sentinel-1", "ANTHROPIC_API_KEY": "sentinel-2", "ANTHROPIC_AUTH_TOKEN": "sentinel-3",
    "AWS_ACCESS_KEY_ID": "sentinel-4", "AWS_SECRET_ACCESS_KEY": "sentinel-5", "AWS_SESSION_TOKEN": "sentinel-6",
    "AWS_PROFILE": "sentinel-7", "GOOGLE_APPLICATION_CREDENTIALS": "sentinel-8", "AZURE_CLIENT_SECRET": "sentinel-9",
    "OPENAI_API_KEY": "sentinel-10", "CODEX_API_KEY": "sentinel-11", "GITHUB_TOKEN": "sentinel-12",
    "GH_TOKEN": "sentinel-13", "HF_TOKEN": "sentinel-14", "NPM_TOKEN": "sentinel-15", "SSH_AUTH_SOCK": "sentinel-16",
    "DOCKER_AUTH_CONFIG": "sentinel-17", "MY_SERVICE_PASSWORD": "sentinel-18"}


class ChildEnvironmentTests(unittest.TestCase):
    """What the bee process receives, through the real build path, with every credential family present."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        parent = {"PATH": "/usr/bin:/bin", "HOME": str(self.tmp), "LANG": "C.UTF-8", "LC_ALL": "C", **SENTINELS}
        patch = mock.patch.dict(os.environ, parent, clear=True)
        patch.start()
        self.addCleanup(patch.stop)
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument("--model")
        codex_bees.add_arguments(self.parser)

    def assert_clean(self, env):
        self.assertIsNotNone(env, "a self-hosted bee must not inherit the parent environment")
        leaked = sorted(key for key, value in env.items() if value.startswith("sentinel-"))
        self.assertEqual(leaked, [])
        self.assertEqual((env["PATH"], env["LANG"], env["LC_ALL"]), ("/usr/bin:/bin", "C.UTF-8", "C"))

    def test_claude_bee_process(self):
        claude = bees.ClaudeBees(engine=self.tmp, inputs=self.tmp, config_dir=self.tmp / "cfg")
        args = self.parser.parse_args(["--model-server", "http://127.0.0.1:11434", "--model", "m1"])
        runner = codex_bees.build(args, claude, engine=self.tmp, inputs=self.tmp, config_dir=self.tmp / "codex")
        done = subprocess.CompletedProcess([], 0, json.dumps({"structured_output": ANSWER}), "")
        with mock.patch.object(bees, "run_cli", return_value=done) as run:
            self.assertTrue(runner("councillor", "c", "task", self.tmp)["ok"])
        env = run.call_args.kwargs["env"]
        self.assert_clean(env)
        self.assertEqual(env["ANTHROPIC_BASE_URL"], "http://127.0.0.1:11434")  # routing kept
        self.assertEqual(env["ANTHROPIC_AUTH_TOKEN"], selfhost.PLACEHOLDER_TOKEN)

    def test_codex_bee_process_and_its_network_probe(self):
        args = self.parser.parse_args(["--bee-policy", "codex", "--model-server", "http://127.0.0.1:11434",
                                       "--codex-model", "gpt-oss:20b"])
        claude = bees.ClaudeBees(engine=self.tmp, inputs=self.tmp, config_dir=self.tmp / "cfg")
        runner = codex_bees.build(args, claude, engine=self.tmp, inputs=self.tmp, config_dir=self.tmp / "codex")
        calls = []

        def fake_run(argv, **kwargs):
            calls.append(kwargs)
            Path(argv[argv.index("-o") + 1]).write_text(json.dumps({"verdict": "accept", "defects": [], "summary": None}))
            return subprocess.CompletedProcess(argv, 0, '{"type":"turn.completed"}', "")
        with mock.patch.object(bees, "run_cli", side_effect=fake_run), \
                mock.patch.object(runner, "_network_ok",  # a probe process like the real one, judged isolated
                                  wraps=lambda role, folder: bool(runner._execute(role, "probe", "t", folder))) as probe:
            answer = runner("councillor", "c", "task", self.tmp)
        self.assertTrue(answer["ok"], answer)
        self.assertTrue(probe.called)  # the network probe still decides
        self.assertEqual(len(calls), 2)  # the probe's process and the bee's process
        for kwargs in calls:
            self.assert_clean(kwargs["env"])

    def test_without_the_flag_the_parent_environment_is_inherited(self):
        claude = bees.ClaudeBees(engine=self.tmp, inputs=self.tmp, config_dir=self.tmp / "cfg")
        codex = codex_bees.build(self.parser.parse_args(["--bee-policy", "codex"]), claude, engine=self.tmp,
                                 inputs=self.tmp, config_dir=self.tmp / "codex")
        self.assertIsNone(claude.env)
        self.assertIsNone(codex.env)


class EnvironmentTests(unittest.TestCase):
    def test_no_subscription_or_cloud_credential_reaches_the_bee(self):
        base = {"PATH": "/usr/bin", "HOME": "/home/x", "CLAUDE_CODE_OAUTH_TOKEN": "secret-oauth",
                "ANTHROPIC_API_KEY": "secret-key", "ANTHROPIC_AUTH_TOKEN": "secret-token",
                "ANTHROPIC_BASE_URL": "https://api.anthropic.com", "CLAUDE_CODE_USE_BEDROCK": "1",
                "AWS_BEARER_TOKEN_BEDROCK": "secret-aws", "OPENAI_API_KEY": "secret-openai"}
        env = selfhost.claude_environment(base, "http://127.0.0.1:11434", "qwen3.6:35b")
        self.assertFalse([value for value in env.values() if "secret" in value])
        self.assertEqual(env["ANTHROPIC_BASE_URL"], "http://127.0.0.1:11434")
        self.assertEqual(env["ANTHROPIC_AUTH_TOKEN"], selfhost.PLACEHOLDER_TOKEN)
        self.assertEqual(env["ANTHROPIC_API_KEY"], "")
        self.assertEqual(env["ANTHROPIC_DEFAULT_HAIKU_MODEL"], "qwen3.6:35b")
        self.assertNotIn("CLAUDE_CODE_USE_BEDROCK", env)
        self.assertEqual((env["PATH"], env["HOME"]), ("/usr/bin", "/home/x"))

    def test_the_claude_runner_passes_its_environment(self):
        tmp = Path(tempfile.mkdtemp())
        runner = bees.ClaudeBees(engine=tmp, inputs=tmp, config_dir=tmp / "cfg", env={"PATH": "/usr/bin"})
        done = subprocess.CompletedProcess([], 0, json.dumps({"structured_output": ANSWER}), "")
        with mock.patch.object(bees, "run_cli", return_value=done) as run:
            self.assertTrue(runner("councillor", "c", "task", tmp)["ok"])
        self.assertEqual(run.call_args.kwargs["env"], {"PATH": "/usr/bin"})
        default = bees.ClaudeBees(engine=tmp, inputs=tmp, config_dir=tmp / "cfg")
        with mock.patch.object(bees, "run_cli", return_value=done) as run:
            default("councillor", "c", "task", tmp)
        self.assertIsNone(run.call_args.kwargs["env"])  # unchanged default: inherit


class CommandLineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument("--model")
        codex_bees.add_arguments(self.parser)
        self.kwargs = {"engine": self.tmp, "inputs": self.tmp, "config_dir": self.tmp / "codex"}

    def claude(self):
        return bees.ClaudeBees(engine=self.tmp, inputs=self.tmp, config_dir=self.tmp / "cfg")

    def test_without_a_model_server_nothing_changes(self):
        claude = self.claude()
        self.assertIs(codex_bees.build(self.parser.parse_args([]), claude, **self.kwargs), claude)
        self.assertIsNone(claude.env)
        codex = codex_bees.build(self.parser.parse_args(["--bee-policy", "codex"]), claude, **self.kwargs)
        self.assertIs(type(codex), codex_bees.CodexBees)

    def test_claude_bees_go_to_the_server_with_the_named_model(self):
        claude = self.claude()
        args = self.parser.parse_args(["--model-server", "http://127.0.0.1:11434", "--model", "qwen3.6:35b"])
        self.assertIs(codex_bees.build(args, claude, **self.kwargs), claude)
        self.assertEqual(claude.env["ANTHROPIC_BASE_URL"], "http://127.0.0.1:11434")
        self.assertIn("qwen3.6:35b", claude.argv("councillor", "c"))

    def test_codex_bees_use_a_selfhost_provider_and_keep_their_sandbox(self):
        args = self.parser.parse_args(["--bee-policy", "codex", "--model-server", "http://127.0.0.1:11434",
                                       "--codex-model", "gpt-oss:20b"])
        codex = codex_bees.build(args, self.claude(), **self.kwargs)
        self.assertIsInstance(codex, selfhost.SelfHostedCodexBees)
        argv = codex.argv("worker", "w", self.tmp)
        self.assertIn('model_provider="selfhost"', argv)
        provider = next(item for item in argv if item.startswith("model_providers.selfhost="))
        self.assertIn('base_url="http://127.0.0.1:11434/v1"', provider)
        self.assertIn('wire_api="responses"', provider)
        self.assertEqual(argv[argv.index("-m") + 1], "gpt-oss:20b")
        self.assertIn("sandbox_workspace_write.network_access=false", argv)
        self.assertEqual(argv[-1], "-")
        self.assertFalse(codex.allow_network)  # the network probe still decides

    def test_missing_model_names_and_remote_servers_stop_the_command(self):
        for argv, text in ((["--model-server", "http://127.0.0.1:11434"], "--model"),
                           (["--bee-policy", "codex", "--model-server", "http://127.0.0.1:1"], "--codex-model"),
                           (["--model-server", "http://gpu.lan:8000", "--model", "m"], "--model-server-remote"),
                           (["--model-server-remote"], "needs --model-server")):
            with self.subTest(argv=argv), self.assertRaisesRegex(SystemExit, text):
                codex_bees.build(self.parser.parse_args(argv), self.claude(), **self.kwargs)


class FakeAnthropic(http.server.BaseHTTPRequestHandler):
    """A model server that answers every bee with ANSWER through the CLI's structured-output tool."""

    seen = []

    def log_message(self, *args):
        pass

    def reply(self, status, payload, content_type="application/json"):
        data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        type(self).seen.append({"method": "GET", "path": self.path})
        self.reply(404, {"type": "error", "error": {"type": "not_found_error", "message": "not here"}})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("content-length", 0))) or b"{}")
        type(self).seen.append({"method": "POST", "path": self.path, "authorization": self.headers.get("authorization"),
                                "x-api-key": self.headers.get("x-api-key"), "model": body.get("model")})
        if "count_tokens" in self.path:
            return self.reply(200, {"input_tokens": 100})
        tools = [tool.get("name", "") for tool in body.get("tools", [])]
        structured = next((name for name in tools if "StructuredOutput" in name), None)
        answered = any(isinstance(m.get("content"), list) and any(c.get("type") == "tool_result" for c in m["content"])
                       for m in body.get("messages", []))
        if structured and not answered:
            blocks, stop = [{"type": "tool_use", "id": "toolu_selfhost", "name": structured, "input": ANSWER}], "tool_use"
        else:
            blocks, stop = [{"type": "text", "text": "Done."}], "end_turn"
        message = {"id": "msg_selfhost", "type": "message", "role": "assistant", "model": body.get("model"),
                   "content": blocks, "stop_reason": stop, "stop_sequence": None,
                   "usage": {"input_tokens": 10, "output_tokens": 10}}
        if not body.get("stream"):
            return self.reply(200, message)
        events = [("message_start", {"type": "message_start", "message": dict(message, content=[], stop_reason=None)})]
        for index, block in enumerate(blocks):
            start = dict(block, input={}) if block["type"] == "tool_use" else dict(block, text="")
            delta = ({"type": "input_json_delta", "partial_json": json.dumps(block["input"])}
                     if block["type"] == "tool_use" else {"type": "text_delta", "text": block["text"]})
            events += [("content_block_start", {"type": "content_block_start", "index": index, "content_block": start}),
                       ("content_block_delta", {"type": "content_block_delta", "index": index, "delta": delta}),
                       ("content_block_stop", {"type": "content_block_stop", "index": index})]
        events += [("message_delta", {"type": "message_delta", "delta": {"stop_reason": stop, "stop_sequence": None},
                                      "usage": {"output_tokens": 10}}),
                   ("message_stop", {"type": "message_stop"})]
        self.reply(200, "".join(f"event: {name}\ndata: {json.dumps(data)}\n\n" for name, data in events).encode(),
                   "text/event-stream")


@unittest.skipUnless(os.environ.get("HIVE_SELFHOST_LIVE") == "1" and shutil.which("claude"),
                     "live check: set HIVE_SELFHOST_LIVE=1 with Claude Code installed")
class LiveClaudeTests(unittest.TestCase):
    def test_a_real_claude_bee_answers_through_a_self_hosted_server(self):
        FakeAnthropic.seen = []
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeAnthropic)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        tmp = Path(tempfile.mkdtemp())
        url = f"http://127.0.0.1:{server.server_address[1]}"
        root = Path(__file__).resolve().parents[1]
        runner = bees.ClaudeBees(engine=root, inputs=tmp, config_dir=tmp / "cfg", model="local-test-model",
                                 env=selfhost.claude_environment(os.environ, url, "local-test-model"), timeout=300)
        answer = runner("councillor", "c", "Reply with the verdict accept and no defects.", tmp)
        self.assertTrue(answer["ok"], answer)
        self.assertEqual(answer["output"], ANSWER)
        posts = [request for request in FakeAnthropic.seen if request["method"] == "POST"]
        self.assertTrue(posts)
        for request in posts:  # never print a header value: a leak would put a real token in the test log
            placeholder = request["authorization"] in (None, f"Bearer {selfhost.PLACEHOLDER_TOKEN}")
            self.assertTrue(placeholder and request["x-api-key"] in (None, "", selfhost.PLACEHOLDER_TOKEN),
                            "a credential other than the placeholder reached the model server")
        self.assertEqual({request["model"] for request in posts if request["model"]}, {"local-test-model"})



class RouterFixture:
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.parser = argparse.ArgumentParser()
        codex_bees.add_arguments(self.parser)
        self.parser.add_argument("--model")

    def router(self, flags=()):
        args = self.parser.parse_args(flags)
        claude = bees.ClaudeBees(engine=self.root, inputs=self.root, config_dir=self.root / "claude", model=args.model)
        return codex_bees.build_router(args, claude, engine=self.root, inputs=self.root, config_dir=self.root / "codex")

    def fallback_flags(self, scope="run"):
        return ["--fallback-model-server", "http://localhost:11434", "--fallback-model", "configured-local",
                "--fallback-scope", scope]



class RouterTests(RouterFixture, unittest.TestCase):
    def test_construction_and_describe_are_pure_policy_copies_are_isolated(self):
        with mock.patch("hive.bees.run_cli") as run, mock.patch("urllib.request.urlopen") as network:
            router = self.router(self.fallback_flags())
            first = router.describe("planner", "planner-g0001")
            second = router.describe("planner", "planner-g0001", local=True)
            self.assertIsNone(first["context_id"])
            self.assertIsNone(second["observed_model"])
            self.assertEqual(second["origin"], "fallback")
            self.assertEqual(second["server"], "http://localhost:11434")
            policy = router.policy()
            policy["fallback"]["roles"].append("worker")
            policy["primary"]["claude"]["requested_model"] = "changed"
            self.assertEqual(router.policy()["fallback"]["roles"], [])
            self.assertIsNone(router.policy()["primary"]["claude"]["requested_model"])
        run.assert_not_called()
        network.assert_not_called()
        self.assertIsNone(self.router().policy()["fallback"])
        self.assertIsNone(self.router().fallback("planner", "planner-g0001"))

    def test_selectors_are_exact_and_never_activate_themselves(self):
        router = self.router(self.fallback_flags("role") + ["--fallback-role", "planner"])
        self.assertIsNotNone(router.fallback("planner", "planner-g0001"))
        self.assertIsNone(router.fallback("worker", "m01-build"))
        router = self.router(self.fallback_flags("bee") + ["--fallback-bee", "planner-g0001"])
        self.assertIsNotNone(router.fallback("planner", "planner-g0001"))
        self.assertIsNone(router.fallback("planner", "planner-g00010"))
        self.assertIs(router.primary("planner", "planner-g0001"), router.primary("planner", "planner-g0002"))

    def test_inconsistent_flags_remote_fallback_and_v1_roots_are_rejected(self):
        bad = [["--fallback-model", "x"], ["--fallback-role", "worker"],
               self.fallback_flags("run") + ["--fallback-role", "worker"],
               self.fallback_flags("role"), self.fallback_flags("bee"),
               self.fallback_flags("bee") + ["--fallback-bee", "m*-build"],
               self.fallback_flags() + ["--fallback-codex-model", "unused"],
               ["--fallback-model-server", "http://host.example", "--fallback-model", "x", "--fallback-scope", "run", "--model-server-remote", "--model-server", "http://host.example", "--model", "x"],
               ["--fallback-model-server", "http://localhost:11434/v1", "--fallback-model", "x", "--fallback-scope", "run"]]
        for flags in bad:
            with self.subTest(flags=flags), self.assertRaises(SystemExit):
                self.router(flags)
        for url in ("http://localhost/v1", "http://localhost/v1/", "http://localhost:bad", "http://u:p@localhost", "http://localhost/?token=secret", "http://localhost/#secret"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                selfhost.server_url(url)
        with self.assertRaises(SystemExit):
            self.router(["--model-server", "http://localhost/v1", "--model", "x"])

    def test_duplicate_normalized_target_model_client_is_not_an_alternative(self):
        flags = self.fallback_flags() + ["--model-server", "http://127.0.0.1:11434/", "--model", "configured-local"]
        router = self.router(flags)
        self.assertIsNone(router.fallback("planner", "planner-g0001"))
        self.assertIsNone(router.describe("planner", "planner-g0001", local=True))
        flags[-1] = "different"
        self.assertIsNotNone(self.router(flags).fallback("planner", "planner-g0001"))

    def test_mixed_client_mapping_and_models_are_explicit_on_both_destinations(self):
        flags = ["--bee-policy", "mixed", "--fallback-model-server", "http://localhost:11434", "--fallback-scope", "run"]
        for suffix in ([], ["--fallback-model", "local-c"], ["--fallback-codex-model", "local-x"]):
            with self.assertRaises(SystemExit):
                self.router(flags + suffix)
        router = self.router(flags + ["--fallback-model", "local-c", "--fallback-codex-model", "local-x"])
        for role, name, client in (("planner", "planner-g0001", "claude"), ("worker", "m01-build", "claude"),
                                  ("worker", "m02-build", "codex"), ("councillor", "m01-council-r1-io", "codex")):
            self.assertEqual(router.describe(role, name)["client"], client)
            self.assertEqual(router.describe(role, name, local=True)["client"], client)
        local = router.fallback("worker", "m02-build")
        argv = local.argv("worker", "m02-build", self.root)
        self.assertIn('base_url="http://localhost:11434/v1"', " ".join(argv))
        self.assertEqual(router.fallback("worker", "m01-build").env["ANTHROPIC_BASE_URL"], "http://localhost:11434")

    def test_probe_description_tracks_actual_pending_cache_without_running_it(self):
        router = self.router(["--bee-policy", "codex"])
        runner = router.primary("worker", "m02-build")
        first = router.describe("worker", "m02-build")
        same = router.describe("repair", "m02-repair-b1")
        council = router.describe("councillor", "m02-council-r1-io")
        self.assertEqual(first["probe_key"], same["probe_key"])
        self.assertNotEqual(first["probe_key"], council["probe_key"])
        self.assertTrue(first["probe_required"])
        runner._network_checks[first["probe_key"]] = False
        self.assertFalse(router.describe("worker", "m02-build")["probe_required"])
        runner.model = "changed"
        self.assertTrue(router.describe("worker", "m02-build")["probe_required"])

    def test_server_kind_distinguishes_remote_loopback_and_cloud(self):
        for policy in ("claude", "codex"):
            with self.subTest(client=policy):
                router = self.router(["--bee-policy", policy, "--model-server", "https://inference.example.test",
                                      "--model-server-remote", "--model", "chosen", "--codex-model", "chosen"])
                self.assertEqual(router.describe("planner", "planner-g0001")["server_kind"], "remote")
        for url in ("http://localhost:11434", "http://127.0.0.1:11434", "http://[::1]:11434"):
            with self.subTest(url=url):
                router = self.router(["--model-server", url, "--model", "chosen"])
                self.assertEqual(router.describe("planner", "planner-g0001")["server_kind"], "local")
        self.assertEqual(self.router().describe("planner", "planner-g0001")["server_kind"], "cloud")

    def test_fallback_environment_drops_cloud_credentials(self):
        with mock.patch.dict(os.environ, {"OPENAI_API_KEY": "SECRET", "ANTHROPIC_API_KEY": "SECRET", "GITHUB_TOKEN": "SECRET"}):
            router = self.router(self.fallback_flags())
        env = router.fallback("planner", "planner-g0001").env
        self.assertNotIn("SECRET", repr(env))
        self.assertEqual(env["ANTHROPIC_AUTH_TOKEN"], selfhost.PLACEHOLDER_TOKEN)


MCP_PROBE = {"file": "greet", "entry": "0x1000"}


def accepted_mcp_events(client, arguments=None):
    arguments = {"file": "greet", "entry": 4096, "select": "entry", "part": "info"} if arguments is None else arguments
    if client == "claude":
        return [{"type": "assistant", "message": {"content": [{"type": "tool_use", "id": "export",
                    "name": "mcp__reverseai__export_function", "input": arguments}]}},
                {"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": "export",
                    "content": [{"type": "text", "text": "Derived function metadata"}]}]}}]
    return [{"type": "item.completed", "item": {"type": "mcp_tool_call", "id": "export",
                "server": "reverseai", "tool": "export_function", "arguments": arguments,
                "status": "completed", "result": {"content": [{"type": "text", "text": "Derived function metadata"}]},
                "error": None}}]


class MCPNativeEvidenceTests(unittest.TestCase):
    def test_native_acceptance_for_both_clis_and_integer_schema(self):
        from reverseai.mcp_tools import catalog
        schema = next(tool["inputSchema"] for tool in catalog(frozenset({"ghidra"})) if tool["name"] == "export_function")
        arguments = {"file": "greet", "entry": 4096, "part": "info"}
        self.assertTrue(bees.matches_schema(arguments, schema))
        self.assertFalse(bees.matches_schema(dict(arguments, entry="0x1000"), schema))
        for client in ("claude", "codex"):
            with self.subTest(client=client):
                self.assertTrue(selfhost.mcp_tool_accepted(accepted_mcp_events(client, arguments), client, MCP_PROBE))

    def test_prose_and_final_json_do_not_establish_mcp_acceptance(self):
        claims = [{"type": "result", "structured_output": {"mcp_tool": "ok"}, "result": "export_function accepted"},
                  {"type": "assistant", "message": {"content": [{"type": "text", "text": json.dumps(accepted_mcp_events("claude"))}]}},
                  {"type": "item.completed", "item": {"type": "agent_message", "text": json.dumps(accepted_mcp_events("codex"))}}]
        for client in ("claude", "codex"):
            self.assertFalse(selfhost.mcp_tool_accepted(claims, client, MCP_PROBE))

    def test_acceptance_must_match_the_surveyed_function_and_selector(self):
        variants = [{"file": "other", "entry": 4096}, {"file": "greet", "entry": 8192},
                    {"file": "greet", "entry": "0x1000"}, {"file": "greet", "entry": True},
                    {"file": "greet", "entry": 4096, "select": "name"},
                    {"file": "greet", "entry": 4096, "name": "other"},
                    {"file": "greet", "entry": 4096, "part": "pseudocode"}]
        for client in ("claude", "codex"):
            for arguments in variants:
                with self.subTest(client=client, arguments=arguments):
                    self.assertFalse(selfhost.mcp_tool_accepted(accepted_mcp_events(client, arguments), client, MCP_PROBE))

    def test_claude_requires_correlated_nonerror_result_from_reverseai(self):
        for mutation in ("error", "wrong_id", "wrong_server", "missing_result", "result_first", "empty_content"):
            events = accepted_mcp_events("claude")
            call, result = events[0]["message"]["content"][0], events[1]["message"]["content"][0]
            if mutation == "error":
                result.update(is_error=True, content="Arguments must match this tool's input schema.")
            elif mutation == "wrong_id":
                result["tool_use_id"] = "other"
            elif mutation == "wrong_server":
                call["name"] = "mcp__other__export_function"
            elif mutation == "missing_result":
                events.pop()
            elif mutation == "result_first":
                events.reverse()
            else:
                result["content"] = []
            with self.subTest(mutation=mutation):
                self.assertFalse(selfhost.mcp_tool_accepted(events, "claude", MCP_PROBE))

    def test_codex_requires_completed_native_mcp_result_without_errors(self):
        for mutation in ("error", "isError", "is_error", "wrong_server", "wrong_tool", "started", "failed", "missing_result"):
            events = accepted_mcp_events("codex")
            call = events[0]["item"]
            if mutation == "error":
                call["error"] = {"code": -32602, "message": "Invalid arguments"}
            elif mutation in ("isError", "is_error"):
                call["result"][mutation] = True
            elif mutation == "wrong_server":
                call["server"] = "other"
            elif mutation == "wrong_tool":
                call["tool"] = "export_program"
            elif mutation == "started":
                events[0]["type"] = "item.started"
            elif mutation == "failed":
                call["status"] = "failed"
            else:
                call["result"] = None
            with self.subTest(mutation=mutation):
                self.assertFalse(selfhost.mcp_tool_accepted(events, "codex", MCP_PROBE))
        encoded = accepted_mcp_events("codex")
        encoded[0]["item"]["arguments"] = json.dumps(encoded[0]["item"]["arguments"])
        self.assertTrue(selfhost.mcp_tool_accepted(encoded, "codex", MCP_PROBE))

    def test_missing_target_and_malformed_events_never_pass(self):
        for target in (None, {}, {"file": "greet", "entry": 4096}, {"file": "greet", "entry": "0x10000000000000000"}):
            self.assertFalse(selfhost.mcp_tool_accepted(accepted_mcp_events("claude"), "claude", target))
        malformed = [None, {}, {"type": "assistant", "message": None}, {"type": "user", "message": {"content": "bad"}},
                     {"type": "item.completed", "item": None}]
        for client in ("claude", "codex", "unknown"):
            self.assertFalse(selfhost.mcp_tool_accepted(malformed, client, MCP_PROBE))


class CapabilityTests(RouterFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.hooks = []

    def fake_claude(self, argv, **kwargs):
        nonce = json.loads(Path(kwargs["cwd"], "capability-input.json").read_text())["nonce"]
        events = [{"type": "assistant", "message": {"content": [{"type": "tool_use", "id": "read", "name": "Read", "input": {"file_path": "capability-input.json"}}]}},
                  {"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": "read", "content": nonce}]}},
                  {"type": "result", "structured_output": {"nonce": nonce}}]
        events[2:2] = accepted_mcp_events("claude")
        self.assertEqual(kwargs["timeout"], 45)
        self.assertIn("--json-schema", argv)
        return subprocess.CompletedProcess(argv, 0, "\n".join(json.dumps(e) for e in events), "")

    def test_capabilities_through_actual_runner_cli_parser_with_budgeted_probe(self):
        from tests.test_hive_bees import Hooks
        router = self.router(self.fallback_flags())
        hooks = Hooks()
        with mock.patch("hive.bees.run_cli", side_effect=self.fake_claude) as run:
            report = selfhost.check_model(router, "claude", local=True, required_context=64000,
                                          before_start=hooks, context_query=lambda server, model: 65536, mcp_probe=MCP_PROBE)
        self.assertTrue(report["ok"], report)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(hooks.started, [("attempt-1", "network_probe")])
        self.assertEqual(len(hooks.results), 1)
        self.assertEqual(hooks.results[0][1]["provenance"]["kind"], "network_probe")
        self.assertTrue(all(c["status"] == "ok" for c in report["checks"].values()))
        self.assertEqual(router.fallback("councillor", "check").timeout, 2400)

    def test_context_check_rejects_insufficient_unknown_and_failing_metadata(self):
        router = self.router(self.fallback_flags())
        for declared, status in ((8192, "error"), (None, "unsupported"), ("65536", "unsupported")):
            with self.subTest(declared=declared), mock.patch("hive.bees.run_cli", side_effect=self.fake_claude):
                report = selfhost.check_model(router, "claude", local=True, context_query=lambda server, model: declared)
            self.assertFalse(report["ok"])
            self.assertEqual(report["checks"]["context"]["status"], status)
            self.assertTrue(report["checks"]["context"]["suggestion"])
        with mock.patch("hive.bees.run_cli", side_effect=self.fake_claude):
            report = selfhost.check_model(router, "claude", local=True, context_query=mock.Mock(side_effect=OSError("metadata unavailable")))
        self.assertEqual(report["checks"]["context"]["status"], "error")

    def test_claimed_tool_call_without_native_result_does_not_pass(self):
        def fake(argv, **kwargs):
            nonce = json.loads(Path(kwargs["cwd"], "capability-input.json").read_text())["nonce"]
            return subprocess.CompletedProcess(argv, 0, json.dumps({"type": "result", "structured_output": {"nonce": nonce}}), "")
        with mock.patch("hive.bees.run_cli", side_effect=fake):
            report = selfhost.check_model(self.router(), "claude", context_query=lambda s, m: 65536)
        self.assertFalse(report["ok"])
        self.assertEqual(report["checks"]["structured_output"]["status"], "ok")
        self.assertEqual(report["checks"]["tool_roundtrip"]["status"], "unsupported")

    def test_capability_budget_denial_propagates_without_network_or_process(self):
        from tests.test_hive_bees import Hooks
        with mock.patch("hive.bees.run_cli") as run, mock.patch("urllib.request.urlopen") as network, self.assertRaises(bees.AttemptNotStarted):
            selfhost.check_model(self.router(), "claude", before_start=Hooks("budget_exhausted"))
        run.assert_not_called()
        network.assert_not_called()

    def test_codex_tool_roundtrip_uses_cli_schema_and_native_command_evidence(self):
        from tests.test_hive_bees import Hooks
        router = self.router(["--bee-policy", "codex", "--codex-allow-network", "--codex-model", "chosen"])
        hooks = Hooks()
        def fake(argv, **kwargs):
            nonce = json.loads(Path(kwargs["cwd"], "capability-input.json").read_text())["nonce"]
            schema = json.loads(Path(argv[argv.index("--output-schema") + 1]).read_text())
            self.assertEqual(schema["required"], ["nonce"])
            Path(argv[argv.index("-o") + 1]).write_text(json.dumps({"nonce": nonce}))
            events = [{"type": "item.completed", "item": {"type": "command_execution", "command": "cat capability-input.json", "exit_code": 0, "aggregated_output": nonce}}, {"type": "turn.completed"}]
            events[1:1] = accepted_mcp_events("codex")
            return subprocess.CompletedProcess(argv, 0, "\n".join(json.dumps(e) for e in events), "")
        with mock.patch("hive.bees.run_cli", side_effect=fake):
            report = selfhost.check_model(router, "codex", before_start=hooks, context_query=lambda s, m: 65536, mcp_probe=MCP_PROBE)
        self.assertTrue(report["ok"], report)
        self.assertEqual(hooks.started, [("attempt-1", "network_probe")])

    def metadata_server(self, routes):
        """A simulated metadata server; no HTTP request leaves this process."""
        def respond(request, **kwargs):
            path = selfhost.urllib.parse.urlsplit(request.full_url).path
            payload = routes.get(path, 404)
            if type(payload) is int:
                raise selfhost.urllib.error.HTTPError(request.full_url, payload, "metadata unavailable", {}, None)
            response = mock.MagicMock()
            response.__enter__.return_value.read.return_value = json.dumps(payload).encode()
            return response
        return mock.patch("urllib.request.urlopen", side_effect=respond)

    def test_vllm_context_metadata_passes_the_capability_check(self):
        router = self.router(self.fallback_flags())
        routes = {"/v1/models": {"object": "list", "data": [
            {"id": "another", "max_model_len": 999999},
            {"id": "configured-local", "max_model_len": 65536}]}}
        with self.metadata_server(routes) as network, mock.patch("hive.bees.run_cli", side_effect=self.fake_claude):
            report = selfhost.check_model(router, "claude", local=True, required_context=65536, mcp_probe=MCP_PROBE)
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["declared_context"], 65536)
        self.assertEqual([call.args[0].full_url for call in network.call_args_list],
                         ["http://localhost:11434/api/ps", "http://localhost:11434/v1/models"])
        self.assertTrue(all(call.kwargs["timeout"] == 5 for call in network.call_args_list))

    def test_vllm_context_below_requirement_remains_an_error(self):
        routes = {"/v1/models": {"data": [{"id": "configured-local", "max_model_len": 8192}]}}
        with self.metadata_server(routes), mock.patch("hive.bees.run_cli", side_effect=self.fake_claude):
            report = selfhost.check_model(self.router(self.fallback_flags()), "claude", local=True, required_context=65536)
        self.assertFalse(report["ok"])
        self.assertEqual(report["declared_context"], 8192)
        self.assertEqual(report["checks"]["context"]["status"], "error")
        self.assertIn("smaller than required", report["checks"]["context"]["message"])

    def test_vllm_context_requires_exact_model_and_a_positive_integer(self):
        cards = [{"id": "another", "max_model_len": 999999}, {"id": "configured-local"}]
        cards += [{"id": "configured-local", "max_model_len": value} for value in (None, True, "65536", 0, -1)]
        for card in cards:
            with self.subTest(card=card), self.metadata_server({"/v1/models": {"data": [card]}}), \
                    mock.patch("hive.bees.run_cli", side_effect=self.fake_claude):
                report = selfhost.check_model(self.router(self.fallback_flags()), "claude", local=True)
            self.assertFalse(report["ok"])
            self.assertIsNone(report["declared_context"])
            self.assertEqual(report["checks"]["context"]["status"], "unsupported")
            self.assertIn("not verifiable on this server", report["checks"]["context"]["message"])

    def test_server_without_either_metadata_api_remains_unsupported(self):
        with self.metadata_server({}) as network, mock.patch("hive.bees.run_cli", side_effect=self.fake_claude):
            report = selfhost.check_model(self.router(self.fallback_flags()), "claude", local=True)
        self.assertFalse(report["ok"])
        self.assertEqual(report["checks"]["context"]["status"], "unsupported")
        self.assertIn("not verifiable on this server", report["checks"]["context"]["message"])
        self.assertEqual(network.call_count, 2)

    def test_active_ollama_context_takes_precedence_over_other_metadata(self):
        routes = {"/api/ps": {"models": [{"name": "configured-local", "context_length": 8192}]},
                  "/v1/models": {"data": [{"id": "configured-local", "max_model_len": 65536}]}}
        with self.metadata_server(routes) as network, mock.patch("hive.bees.run_cli", side_effect=self.fake_claude):
            report = selfhost.check_model(self.router(self.fallback_flags()), "claude", local=True, required_context=65536)
        self.assertFalse(report["ok"])
        self.assertEqual(report["declared_context"], 8192)
        self.assertEqual(report["checks"]["context"]["status"], "error")
        self.assertEqual(network.call_count, 1)

    def test_unrecognized_metadata_shapes_do_not_invent_context(self):
        for payload in ({}, [], {"data": {}}, {"data": [None, "configured-local", 65536]}):
            with self.subTest(payload=payload), self.metadata_server({"/v1/models": payload}), \
                    mock.patch("hive.bees.run_cli", side_effect=self.fake_claude):
                report = selfhost.check_model(self.router(self.fallback_flags()), "claude", local=True)
            self.assertFalse(report["ok"])
            self.assertEqual(report["checks"]["context"]["status"], "unsupported")

    def test_metadata_auth_and_server_errors_are_not_hidden_by_api_discovery(self):
        for endpoint in ("/api/ps", "/v1/models"):
            for status in (401, 403, 500):
                with self.subTest(endpoint=endpoint, status=status), self.metadata_server({endpoint: status}), \
                        mock.patch("hive.bees.run_cli", side_effect=self.fake_claude):
                    report = selfhost.check_model(self.router(self.fallback_flags()), "claude", local=True)
                self.assertFalse(report["ok"])
                self.assertEqual(report["checks"]["context"]["status"], "error")

    def test_read_only_without_a_real_survey_target_is_unsupported(self):
        with mock.patch("hive.bees.run_cli", side_effect=self.fake_claude):
            report = selfhost.check_model(self.router(), "claude", context_query=lambda s, m: 65536)
        self.assertFalse(report["ok"])
        self.assertEqual(report["checks"]["tool_roundtrip"]["status"], "ok")
        self.assertEqual(report["checks"]["mcp_tool"]["status"], "unsupported")
        self.assertIn("survey", report["checks"]["mcp_tool"]["suggestion"])

    def test_mcp_probe_does_not_reconfigure_the_original_runner(self):
        router = self.router()
        source = router.primary("councillor", "check")
        def inspect(argv, **kwargs):
            self.assertIn('"entry": 4096', kwargs["input"])
            self.assertIn('"file": "greet"', kwargs["input"])
            self.assertIn("export_function", kwargs["input"])
            return self.fake_claude(argv, **kwargs)
        with mock.patch("hive.bees.run_cli", side_effect=inspect) as run:
            selfhost.check_model(router, "claude", mcp_probe=MCP_PROBE, context_query=lambda s, m: 65536)
        self.assertEqual(run.call_count, 1)
        self.assertFalse(hasattr(source, "_capability_mcp"))
        self.assertFalse(hasattr(source, "_capability_nonce"))
        self.assertEqual(source.timeout, 2400)

    def test_mcp_probe_requires_ghidra_enabled_in_the_actual_runner(self):
        router = self.router()
        router.primary("councillor", "check").enabled = ()
        with mock.patch("hive.bees.run_cli", side_effect=self.fake_claude):
            report = selfhost.check_model(router, "claude", mcp_probe=MCP_PROBE, context_query=lambda s, m: 65536)
        self.assertFalse(report["ok"])
        self.assertEqual(report["checks"]["mcp_tool"]["status"], "unsupported")
        self.assertIn("Ghidra", report["checks"]["mcp_tool"]["suggestion"])


    def test_active_context_metadata_matches_configured_model_only(self):
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = json.dumps({"models": [
            {"name": "another", "context_length": 999999}, {"name": "chosen", "context_length": 65536}]}).encode()
        with mock.patch("urllib.request.urlopen", return_value=response) as request:
            self.assertEqual(selfhost._server_context("http://localhost:11434", "chosen"), 65536)
            self.assertIsNone(selfhost._server_context("http://localhost:11434", "missing"))
        self.assertEqual(request.call_args.args[0].full_url, "http://localhost:11434/api/ps")
        self.assertEqual(request.call_args.kwargs["timeout"], 5)

if __name__ == "__main__":
    unittest.main()
