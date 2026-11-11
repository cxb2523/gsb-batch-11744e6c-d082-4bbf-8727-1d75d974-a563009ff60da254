"""Bring your own model: run the hive's bees on a model server you host yourself (experimental).

The bees keep their agent CLI, so the fences do not depend on the model: Claude Code still enforces the
per-role tools, the folder-scoped write rules and `dontAsk`; Codex still runs in its sandbox behind the
network probe. Only the model behind the CLI changes:

- Claude bees talk to a server with the Anthropic Messages API (for example Ollama 0.14 or later,
  LM Studio 0.4.1 or later, llama.cpp `llama-server`), through ANTHROPIC_BASE_URL.
- Codex bees talk to a server with the OpenAI Responses API through a `selfhost` model provider.

No login or key reaches a self-hosted bee: it gets an allowlisted environment (system basics, locale,
certificates) plus the server routing, with a placeholder token for Claude bees. The queen's checks (council,
evidence checker, confined compiler, conformance) stay the gate whatever the model; nothing here claims
that a self-hosted model is good enough for a long reverse-engineering run. Measure it first.
"""

import copy
import ipaddress
import json
import os
import re
import secrets
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from hive.codex_bees import CodexBees
from hive.bees import TOOLSETS, provenance, redact

PLACEHOLDER_TOKEN = "self-hosted"
# A self-hosted bee gets an allowlist, not this process's environment: nothing else (subscription logins, cloud,
# API or repository tokens of any family) can reach it or the model server.
ALLOWED = frozenset({"PATH", "HOME", "USER", "LOGNAME", "SHELL", "TERM", "TMPDIR", "TMP", "TEMP", "LANG", "LANGUAGE",
                     "TZ", "__CF_USER_TEXT_ENCODING", "SSL_CERT_FILE", "SSL_CERT_DIR", "NODE_EXTRA_CA_CERTS",
                     "CODEX_HOME", "SYSTEMROOT", "COMSPEC", "PATHEXT", "USERPROFILE", "APPDATA", "LOCALAPPDATA"})


def base_environment(base):
    """The allowlisted part of an environment: the system basics a CLI needs, and locale settings."""
    return {key: value for key, value in base.items() if key in ALLOWED or key.startswith("LC_")}


def server_url(url, *, allow_remote=False):
    """The model server's base URL, refused when it could leak or is not what the owner meant."""
    parsed = urllib.parse.urlsplit(url or "")
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("--model-server must be an http:// or https:// URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("--model-server must not carry credentials, a query or a fragment")
    try:
        parsed.port
    except ValueError:
        raise ValueError("invalid model server port") from None
    if parsed.path.rstrip("/").endswith("/v1"):
        raise ValueError("model server must be a root URL without /v1")
    host = parsed.hostname.lower()
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = host == "localhost"
    if not loopback and not allow_remote:
        raise ValueError(f"--model-server {host} is not this machine; add --model-server-remote to send the bees' "
                         "prompts (program evidence included) to it")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", ""))


def claude_environment(base, url, model):
    """Environment for `claude -p` against a self-hosted Anthropic Messages server."""
    env = base_environment(base)
    env.update({
        "ANTHROPIC_BASE_URL": url,
        "ANTHROPIC_AUTH_TOKEN": PLACEHOLDER_TOKEN,
        "ANTHROPIC_API_KEY": "",
        "ANTHROPIC_MODEL": model,
        "ANTHROPIC_DEFAULT_OPUS_MODEL": model,
        "ANTHROPIC_DEFAULT_SONNET_MODEL": model,
        "ANTHROPIC_DEFAULT_HAIKU_MODEL": model,
        "CLAUDE_CODE_SUBAGENT_MODEL": model,
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        "DISABLE_TELEMETRY": "1",
        "DISABLE_ERROR_REPORTING": "1",
    })
    return env


class SelfHostedCodexBees(CodexBees):
    """Codex bees whose model is served by a self-hosted OpenAI Responses server."""

    def __init__(self, *, server, **kwargs):
        super().__init__(**dict(kwargs, env=base_environment(os.environ)))
        if not self.model:
            raise ValueError("self-hosted Codex bees need --codex-model")
        self.server = server

    def argv(self, role, name, folder, *, schema=None):
        argv = super().argv(role, name, folder, schema=schema)
        provider = ("model_providers.selfhost={name=\"selfhost\",base_url=" + json.dumps(self.server + "/v1")
                    + ",wire_api=\"responses\"}")
        return [*argv[:-1], "-c", 'model_provider="selfhost"', "-c", provider, argv[-1]]


def add_arguments(parser):
    parser.add_argument("--model-server", metavar="URL",
                        help="Experimental: run the bees on a model server you host (Claude bees: Anthropic Messages "
                             "API; Codex bees: OpenAI Responses API). Needs --model or --codex-model")
    parser.add_argument("--model-server-remote", action="store_true",
                        help="Allow a --model-server on another machine (the bees' prompts and evidence go there)")
    parser.add_argument("--fallback-model-server", metavar="URL", help="Explicit loopback model server for refusal fallback")
    parser.add_argument("--fallback-model", help="Fallback model for Claude client")
    parser.add_argument("--fallback-codex-model", help="Fallback model for Codex client")
    parser.add_argument("--fallback-scope", choices=("run", "role", "bee"))
    parser.add_argument("--fallback-role", choices=tuple(TOOLSETS), action="append")
    parser.add_argument("--fallback-bee", action="append", help="Exact logical bee name, repeatable")


def apply(args, claude_runner):
    """Point the Claude runner at the self-hosted server; returns the Codex runner class and its extra settings."""
    if not args.model_server:
        if args.model_server_remote:
            raise SystemExit("hive: --model-server-remote needs --model-server")
        return CodexBees, {}
    try:
        url = server_url(args.model_server, allow_remote=args.model_server_remote)
    except ValueError as error:
        raise SystemExit(f"hive: {error}") from None
    if args.bee_policy in ("claude", "mixed"):
        if not getattr(args, "model", None):
            raise SystemExit("hive: --model-server needs --model, the model name your server serves to Claude bees")
        claude_runner.env = claude_environment(os.environ, url, args.model)
        claude_runner.model = args.model
    if args.bee_policy in ("codex", "mixed") and not args.codex_model:
        raise SystemExit("hive: --model-server needs --codex-model, the model name your server serves to Codex bees")
    return SelfHostedCodexBees, {"server": url}


def _destination(runner):
    env = runner.env or {}
    url = getattr(runner, "server", None) or env.get("ANTHROPIC_BASE_URL")
    if url:
        parsed = urllib.parse.urlsplit(url)
        host = parsed.hostname.lower()
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = host == "localhost"
        if loopback:
            host = "loopback"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        url = (parsed.scheme.lower(), host, port, parsed.path.rstrip("/"))
    return ("codex" if hasattr(runner, "codex") else "claude", url, runner.model)


class BeeRouter:
    """Immutable routing configuration; fallback activation belongs to the queen."""
    def __init__(self, args, claude_runner, runner_kwargs):
        from hive.codex_bees import MixedBees, build
        policy = args.bee_policy
        server = getattr(args, "fallback_model_server", None)
        scope = getattr(args, "fallback_scope", None)
        roles = sorted(set(getattr(args, "fallback_role", None) or []))
        bees = sorted(set(getattr(args, "fallback_bee", None) or []))
        model = getattr(args, "fallback_model", None)
        codex_model = getattr(args, "fallback_codex_model", None)
        if not server and any((scope, roles, bees, model, codex_model)):
            raise SystemExit("hive: fallback selectors/models need --fallback-model-server")
        self._fallback_selector = None
        self._fallback_clients = {}
        if server:
            try:
                server = server_url(server)  # A remote-primary opt-in never authorizes remote fallback.
            except ValueError as error:
                raise SystemExit(f"hive: fallback: {error}") from None
            if scope not in ("run", "role", "bee"):
                raise SystemExit("hive: --fallback-model-server needs --fallback-scope")
            if (scope == "role") != bool(roles) or (scope == "bee") != bool(bees):
                raise SystemExit("hive: fallback roles/bees must match --fallback-scope exactly")
            if set(roles) - set(TOOLSETS) or any(not re.fullmatch(r"[A-Za-z0-9_-]+", b) for b in bees):
                raise SystemExit("hive: invalid fallback role or exact bee name")
            if policy in ("claude", "mixed") and not model:
                raise SystemExit("hive: fallback Claude bees need --fallback-model")
            if policy in ("codex", "mixed") and not codex_model:
                raise SystemExit("hive: fallback Codex bees need --fallback-codex-model")
            if policy == "claude" and codex_model or policy == "codex" and model:
                raise SystemExit("hive: fallback model configured for an unused client")
            self._fallback_selector = {"scope": scope, "roles": roles, "bees": bees}
        primary = build(args, claude_runner, **runner_kwargs)
        self._primary = primary
        self._primary_clients = ({"claude": primary.claude, "codex": primary.codex} if isinstance(primary, MixedBees)
                                 else {policy: primary})
        if server:
            if policy in ("claude", "mixed"):
                local = copy.copy(claude_runner)
                local.model, local.env = model, claude_environment(os.environ, server, model)
                local.config_dir = Path(claude_runner.config_dir) / "fallback-claude"
                local.origin = "fallback"
                self._fallback_clients["claude"] = local
            if policy in ("codex", "mixed"):
                kwargs = dict(runner_kwargs, codex=args.codex, model=codex_model, effort=args.codex_effort,
                              allow_network=args.codex_allow_network)
                kwargs["config_dir"] = Path(kwargs["config_dir"]) / "fallback-codex"
                local = SelfHostedCodexBees(server=server, **kwargs)
                local.origin = "fallback"
                self._fallback_clients["codex"] = local
        def config(runner):
            client, _, _ = _destination(runner)
            return {"client": client, "server": getattr(runner, "server", None) or (runner.env or {}).get("ANTHROPIC_BASE_URL"),
                    "requested_model": runner.model, "effort": runner.effort,
                    "executable": runner.codex if client == "codex" else runner.claude,
                    "allow_network": getattr(runner, "allow_network", False)}
        self._policy = {"bee_policy": policy,
                        "primary": {k: config(v) for k, v in self._primary_clients.items()},
                        "fallback": self._fallback_selector,
                        "fallback_targets": {k: config(v) for k, v in self._fallback_clients.items()}}

    def primary(self, role, name):
        from hive.codex_bees import MixedBees
        return self._primary.runner(role, name) if isinstance(self._primary, MixedBees) else self._primary

    def fallback(self, role, name):
        selection = self._fallback_selector
        if selection is None:
            return None
        if selection["scope"] == "role" and role not in selection["roles"]:
            return None
        if selection["scope"] == "bee" and name not in selection["bees"]:
            return None
        primary = self.primary(role, name)
        client = "codex" if hasattr(primary, "codex") else "claude"
        local = self._fallback_clients[client]
        return None if _destination(primary) == _destination(local) else local

    def describe(self, role, name, *, local=False):
        runner = self.fallback(role, name) if local else self.primary(role, name)
        if runner is None:
            return None
        result = provenance(runner, role, name)
        result["context_id"] = None  # No invocation has been created by this pure query.
        key = runner.probe_key(role) if isinstance(runner, CodexBees) and not runner.allow_network else None
        result.update(probe_key=key, probe_required=key is not None and key not in runner._network_checks)
        return result

    def policy(self):
        return copy.deepcopy(self._policy)


class _ProbeHooks:
    def __init__(self, wrapped):
        self.wrapped = wrapped

    def __call__(self, kind):
        return self.wrapped("network_probe")

    def finished(self, attempt_id, result):
        result["provenance"]["kind"] = "network_probe"
        self.wrapped.finished(attempt_id, result)


def _server_context(server, model):
    """Read serving context metadata for the exact configured model, never guess.

    Ollama /api/ps reports loaded context_length; /api/show's architecture limit
    alone does not establish the active serving context. vLLM /v1/models reports
    max_model_len from its serving model configuration (not the model name):
    https://docs.vllm.ai/en/latest/api/vllm/entrypoints/openai/models/serving/
    """
    if not server:
        return None
    sources = (("/api/ps", "models", ("name", "model"), "context_length"),
               ("/v1/models", "data", ("id",), "max_model_len"))
    for endpoint, collection, names, field in sources:
        request = urllib.request.Request(server + endpoint, headers={"Accept": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                data = json.loads(response.read(1024 * 1024 + 1))
        except urllib.error.HTTPError as error:
            if error.code in (404, 405, 501):
                continue
            raise
        if not isinstance(data, dict) or not isinstance(data.get(collection), list):
            continue
        candidates = [row for row in data[collection] if isinstance(row, dict)
                      and any(row.get(name) == model for name in names)]
        values = [row.get(field) for row in candidates]
        # A recognized API with missing/invalid model metadata is not permission
        # to substitute another model or a larger limit from another API.
        return min(values) if values and all(type(value) is int and value > 0 for value in values) else None
    return None


def _mcp_target(probe):
    if (not isinstance(probe, dict) or not isinstance(probe.get("file"), str) or not probe["file"]
            or not isinstance(probe.get("entry"), str) or not re.fullmatch(r"0x[0-9a-fA-F]{1,16}", probe["entry"])):
        return None
    return {"file": probe["file"], "entry": int(probe["entry"], 16)}


def mcp_tool_accepted(events, client, expected):
    """Match a real export_function call and its successful native MCP result.

    Assistant prose and final structured output never establish tool acceptance.
    The target comes from the input survey; MCP's entry argument is an integer.
    """
    target = _mcp_target(expected)
    if target is None:
        return False

    def matches(arguments):
        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments)
            except ValueError:
                return False
        return (isinstance(arguments, dict) and arguments.get("file") == target["file"]
                and type(arguments.get("entry")) is int and arguments["entry"] == target["entry"]
                and arguments.get("select", "entry") == "entry" and arguments.get("name", "") == ""
                and arguments.get("part", "info") == "info")

    pending = {}
    for event in events:
        if not isinstance(event, dict):
            continue
        if client == "claude" and event.get("type") in ("assistant", "user"):
            message = event.get("message")
            blocks = message.get("content") if isinstance(message, dict) else None
            for block in blocks if isinstance(blocks, list) else []:
                if not isinstance(block, dict):
                    continue
                if event["type"] == "assistant" and block.get("type") == "tool_use":
                    call_id = block.get("id")
                    if isinstance(call_id, str) and call_id:
                        pending[call_id] = (block.get("name") == "mcp__reverseai__export_function"
                                            and matches(block.get("input")))
                elif (event["type"] == "user" and block.get("type") == "tool_result"
                      and isinstance(block.get("tool_use_id"), str)
                      and pending.pop(block["tool_use_id"], False)
                      and not block.get("is_error") and block.get("content")):
                    return True
        elif client == "codex" and event.get("type") == "item.completed":
            call = event.get("item")
            if not isinstance(call, dict):
                continue
            result = call.get("result")
            if (call.get("type") == "mcp_tool_call" and call.get("server") == "reverseai"
                    and call.get("tool") == "export_function" and call.get("status") == "completed"
                    and matches(call.get("arguments")) and not call.get("error")
                    and isinstance(result, dict) and result.get("content")
                    and not result.get("isError") and not result.get("is_error")):
                return True
    return False


def check_model(router, client, *, before_start=None, required_context=32768, local=False,
                context_query=None, timeout=45, mcp_probe=None):
    """Brief capability probe through the configured CLI, without selecting/loading a model.

    Checks Read, an actual ReverseAI MCP export_function and CLI structured output
    in one process. mcp_probe identifies a real surveyed function as {file, entry}
    with entry in hexadecimal; missing target/configuration is never a success.
    Metadata is read from the configured server; context_query(server,
    model) can supply another server's *active* declared context. Unknown is not ok.
    The caller must explicitly invoke this function; construction never calls it.
    """
    if client not in ("claude", "codex") or type(required_context) is not int or required_context < 1:
        raise ValueError("client must be claude/codex and required_context a positive integer")
    source = (router._fallback_clients if local else router._primary_clients).get(client)
    if source is None:
        raise ValueError("client is not configured for this destination")
    runner = copy.copy(source)
    runner.timeout = min(timeout, source.timeout)
    runner._capability_nonce = secrets.token_hex(24)
    target = _mcp_target(mcp_probe)
    mcp_configured = target is not None and "ghidra" in source.enabled
    if mcp_configured:
        runner._capability_mcp = dict(mcp_probe)
    hooks = _ProbeHooks(before_start) if before_start is not None else None
    schema = {"type": "object", "properties": {"nonce": {"type": "string"}},
              "required": ["nonce"], "additionalProperties": False}
    def item(status, message, suggestion=None):
        return {"status": status, "message": message, "suggestion": suggestion}
    with tempfile.TemporaryDirectory(prefix="hive-model-check-") as folder:
        Path(folder, "capability-input.json").write_text(json.dumps({"nonce": runner._capability_nonce}), encoding="utf-8")
        task = ("Capability probe: read capability-input.json using the Read tool (Claude) or a single "
                "read-only cat command (Codex). Return the nonce from the tool result as the JSON instance "
                "requested by the output schema. Do not return the schema or Markdown. Do not change files.")
        if mcp_configured:
            arguments = {**target, "select": "entry", "part": "info"}
            task += (" Before the final answer, call the real ReverseAI MCP export_function tool once "
                     "on this surveyed function, using these structured arguments: " + json.dumps(arguments)
                     + ". entry is an integer, not a hexadecimal string. Observe the MCP result; "
                     "do not substitute a command or describe a hypothetical tool call.")
        name = "model-check-" + secrets.token_hex(6)
        result = runner("councillor", name, task, folder, schema=schema, before_start=hooks)
    result["provenance"]["kind"] = "network_probe"
    structured = (result["ok"] and result["output"]["nonce"] == runner._capability_nonce)
    checks = {"structured_output": item("ok" if structured else "error",
                    "CLI output matches the probe schema." if structured else result.get("error") or "The CLI returned an incorrect nonce.",
                    None if structured else "Configure schema support through this CLI; the JSON instance must satisfy its schema."),
              "tool_roundtrip": item("ok" if structured and result.get("capability_tool_roundtrip") else "unsupported" if result["ok"] else "error",
                    "Observed tool call, result and final answer." if structured and result.get("capability_tool_roundtrip") else "Tool round-trip was not demonstrated by native CLI events.",
                    None if structured and result.get("capability_tool_roundtrip") else "Configure a model and API that support tool calling and tool results through this CLI.")}
    if not mcp_configured:
        checks["mcp_tool"] = item("unsupported",
            "A real surveyed function and the ReverseAI Ghidra MCP configuration are required.",
            "Provide the input survey and enable the same ReverseAI Ghidra MCP server used by the bees.")
    elif result.get("capability_mcp_tool") is True:
        checks["mcp_tool"] = item("ok",
            "Native MCP events confirm export_function accepted the surveyed function's arguments.")
    else:
        checks["mcp_tool"] = item("unsupported" if result["ok"] and result.get("tool_rejections") is None else "error",
            "Native CLI events did not demonstrate an accepted ReverseAI export_function call with the requested arguments.",
            "Check the MCP configuration; use reliable tool calling or a larger context if the model does not follow tool argument schemas.")
    server = getattr(source, "server", None) or (source.env or {}).get("ANTHROPIC_BASE_URL")
    declared = None
    try:
        declared = (context_query or _server_context)(server, source.model)
        if type(declared) is not int or declared < 1:
            declared = None
            checks["context"] = item("unsupported", "Active context is not verifiable on this server for the configured model.",
                                     "Expose active context metadata, or supply context_query for this server API.")
        elif declared < required_context:
            checks["context"] = item("error", f"Declared context {declared} is smaller than required {required_context}.",
                                     f"Configure the server's active context to at least {required_context} tokens.")
        else:
            checks["context"] = item("ok", f"Declared context {declared} meets required {required_context}.")
    except Exception as error:
        checks["context"] = item("error", redact(str(error))[:300], "Check the configured server's context metadata endpoint.")
    return {"schema": "hive.model-check/1", "ok": all(c["status"] == "ok" for c in checks.values()),
            "client": client, "requested_model": source.model, "server": server,
            "required_context": required_context, "declared_context": declared,
            "checks": checks, "attempt": result}
