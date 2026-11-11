"""Codex bees and mixed Claude/Codex councils.

Codex bees have a shell, can read the disk and can execute programs. On macOS,
codex-cli 0.165.0 allowed network access through `codex exec` in both sandbox modes,
despite network_access=false; `codex sandbox` blocked the same command. A preliminary
probe decides whether each sandbox mode may run bees; an inconclusive probe refuses
them. This reachability check is not a guarantee of isolation against every destination.
An explicit --codex-allow-network opt-out warns on every result. Use Codex bees only
for software the operator would run anyway, never for malware.
"""

import hashlib
import json
import re
import shlex
import subprocess
import sys
import threading
import time
from pathlib import Path
from hive import bees as bees_module

from hive.bees import (REFUSAL, SCHEMAS, brief, is_refusal, AttemptNotStarted, classify_result,
                       matches_schema, parse_output, json_events, tool_rejections, run_attempt,
                       provenance, _text_outcome, capability_roundtrip, terminal_signals)

NETWORK_REFUSAL = "Codex sandbox allowed network access; Codex bees refused"
NETWORK_WARNING = "Codex bees ran without network isolation"
NETWORK_COMMAND = "curl --max-time 5 --silent --show-error --output /dev/null https://example.com"
NETWORK_SCHEMA = {"type": "object", "properties": {"exit_code": {"type": "integer"}},
                  "required": ["exit_code"], "additionalProperties": False}
NETWORK_TASK = ("Network isolation probe. Run exactly this shell command once, with no extra commands, "
                "wrappers, redirections or file reads:\n" + NETWORK_COMMAND
                + "\nReport its actual exit code. Never invent a result or substitute another command. "
                "If execution is unavailable, report -1.")


def strict_schema(schema):
    """Require every object property, allowing null for originally optional fields."""
    if isinstance(schema, list):
        return [strict_schema(item) for item in schema]
    if not isinstance(schema, dict):
        return schema
    result = {key: strict_schema(value) for key, value in schema.items()}
    if schema.get("type") == "object" or isinstance(schema.get("type"), list) and "object" in schema["type"]:
        required = schema.get("required", [])
        result["properties"] = {
            key: value if key in required else {"anyOf": [value, {"type": "null"}]}
            for key, value in result.get("properties", {}).items()
        }
        result["required"] = list(result["properties"])
        result["additionalProperties"] = False
    return result


def drop_nulls(value):
    """Restore omitted optional object fields without changing array positions."""
    if isinstance(value, dict):
        return {key: drop_nulls(item) for key, item in value.items() if item is not None}
    if isinstance(value, list):
        return [drop_nulls(item) for item in value]
    return value


def _matches(value, schema):
    return matches_schema(value, schema)


def restore_optionals(value, schema):
    """Remove only null placeholders introduced for optional fields in the wire schema."""
    for keyword in ("anyOf", "oneOf"):
        if keyword in schema:
            branch = next((s for s in schema[keyword] if matches_schema(value, strict_schema(s))), None)
            if branch is not None:
                return restore_optionals(value, branch)
    if isinstance(value, dict):
        properties, required = schema.get("properties", {}), schema.get("required", [])
        return {key: restore_optionals(item, properties.get(key, {})) for key, item in value.items()
                if item is not None or key in required}
    if isinstance(value, list):
        return [restore_optionals(item, schema.get("items", {})) for item in value]
    return value


class BeeExecutionError(ValueError):
    def __init__(self, result):
        self.result = result
        super().__init__(result["error"])


class ProviderRefusal(ValueError):
    """Codex ended because the model provider refused the request."""


def failure_messages(stdout):
    """Messages of the error events in `codex exec --json` output; tool output never counts."""
    messages = []
    for line in (stdout or "").splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if not isinstance(event, dict):
            continue
        if event.get("type") == "error":
            messages.append(str(event.get("message", "")))
        elif event.get("type") == "turn.failed":
            error = event.get("error")
            messages.append(str(error.get("message", "") if isinstance(error, dict) else error))
    return messages


def refusal_excerpt(*texts):
    """The text around the first provider refusal in any of the texts, or an empty string."""
    for text in texts:
        match = REFUSAL.search(text) if isinstance(text, str) else None
        if match:
            return " ".join(text[max(0, match.start() - 120):match.end() + 120].split())
    return ""


class CodexBees:
    """One non-interactive Codex process and ReverseAI MCP server per named bee."""

    def __init__(self, *, engine, inputs, enabled=("ghidra",), codex="codex", model=None, effort=None,
                 timeout=2400, python=sys.executable, config_dir, allow_network=False, env=None, max_tool_rejections=8):
        if type(max_tool_rejections) is not int or max_tool_rejections < 1:
            raise ValueError("max_tool_rejections must be a positive integer")
        self.max_tool_rejections = max_tool_rejections
        self.env = env  # None inherits this process's environment; hive.selfhost sets a self-hosted one
        self.engine, self.inputs = str(Path(engine).resolve()), str(Path(inputs).resolve())
        self.enabled, self.codex, self.model = tuple(enabled), codex, model
        self.effort, self.timeout, self.python = effort, timeout, str(python)
        self.config_dir = Path(config_dir).resolve()
        self.allow_network = allow_network
        self._network_checks = {}
        self._network_lock = threading.Lock()
        self._network_local = threading.local()

    def _paths(self, name):
        if not re.fullmatch(r"[A-Za-z0-9_-]+", name):
            raise ValueError("invalid bee name")
        return self.config_dir / f"{name}.schema.json", self.config_dir / f"{name}.output.json"

    def argv(self, role, name, folder, *, schema=None):
        schema_path, output_path = self._paths(name)
        self.config_dir.mkdir(parents=True, exist_ok=True)
        schema_path.write_text(json.dumps(strict_schema(SCHEMAS[role]) if schema is None else schema),
                               encoding="utf-8")
        output_path.unlink(missing_ok=True)  # A failed retry must not reuse an earlier answer.
        mcp_args = ["-B", "-m", "reverseai", "mcp", "--inputs", self.inputs,
                    *("--with-" + tool for tool in self.enabled)]
        mcp = ("mcp_servers={reverseai={command=" + json.dumps(self.python)
               + ",args=" + json.dumps(mcp_args) + ",env={PYTHONPATH=" + json.dumps(self.engine)
               + ',PYTHONDONTWRITEBYTECODE="1"}}}')
        argv = [self.codex, "exec", "--ignore-user-config", "--skip-git-repo-check", "--ephemeral", "--json",
                "-C", str(Path(folder).resolve()), "--sandbox",
                "read-only" if role == "councillor" else "workspace-write",
                "-c", 'approval_policy="never"', "-c", "sandbox_workspace_write.network_access=false",
                "-c", "sandbox_workspace_write.writable_roots=[]",
                "-c", "sandbox_workspace_write.exclude_tmpdir_env_var=true",
                "-c", "sandbox_workspace_write.exclude_slash_tmp=true", "-c", 'web_search="disabled"',
                "-c", mcp, "--output-schema", str(schema_path), "-o", str(output_path)]
        if self.model:
            argv += ["-m", self.model]
        if self.effort:
            argv += ["-c", "model_reasoning_effort=" + json.dumps(self.effort)]
        return [*argv, "-"]

    def _execute(self, role, name, task, folder, *, schema=None):
        expected = SCHEMAS[role] if schema is None else schema
        wire_schema = strict_schema(expected) if schema is None else schema
        completed = bees_module.run_cli(self.argv(role, name, folder, schema=wire_schema), input=task, cwd=folder,
                                       env=self.env, capture_output=True, text=True, timeout=self.timeout, check=False,
                                       client="codex", max_tool_rejections=self.max_tool_rejections)
        events = json_events(completed.stdout)
        errors = failure_messages(completed.stdout)
        signals = []
        for event in events:
            if event.get("type") in ("error", "turn.failed"):
                signals.extend(terminal_signals(event))
                error = event.get("error", event)
                if isinstance(error, dict):
                    native_code = str(error.get("code") or error.get("type") or "")
                    signal = _text_outcome(native_code)
                    if signal:
                        signals.append(signal)
        finished = any(e.get("type") == "turn.completed" for e in events)
        failed = any(e.get("type") == "turn.failed" for e in events)
        terminal = {"completed": finished and not errors, "returncode": completed.returncode,
                    "signals": signals, "inconsistent": finished and failed}
        native = "\n".join(filter(None, [completed.stderr, *errors]))
        if errors or completed.returncode:
            terminal["error"] = f"exit {completed.returncode}: {native or 'agent failed'}" if completed.returncode else native
        assistant = "\n".join(str(e.get("item", {}).get("text", "")) for e in events
                              if e.get("type") == "item.completed" and e.get("item", {}).get("type") == "agent_message")
        _, output_path = self._paths(name)
        output = None
        try:
            output = parse_output(output_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            pass
        result = classify_result(terminal=terminal, assistant_text=assistant, diagnostic=native,
                                 output=output, schema=wire_schema)
        result = bees_module.tool_schema_result(completed) or result
        result["tool_rejections"] = tool_rejections(events, client="codex")
        if hasattr(self, "_capability_nonce"):
            result["capability_tool_roundtrip"] = capability_roundtrip(events, "codex", self._capability_nonce)
        if hasattr(self, "_capability_mcp"):
            from hive import selfhost
            result["capability_mcp_tool"] = selfhost.mcp_tool_accepted(events, "codex", self._capability_mcp)
        if not result["ok"]:
            raise BeeExecutionError(result)
        completed.bee_result = result
        return completed, output

    def probe_key(self, role):
        mode = "read-only" if role == "councillor" else "workspace-write"
        payload = {"client": "codex", "server": getattr(self, "server", None), "model": self.model,
                   "executable": self.codex, "mode": mode, "network_access": False,
                   "writable_roots": [], "exclude_tmpdir_env_var": True, "exclude_slash_tmp": True,
                   "web_search": "disabled", "effort": self.effort}
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()

    def _network_ok(self, role, folder, *, before_start=None):
        key = self.probe_key(role)
        mode = "read-only" if role == "councillor" else "workspace-write"
        with self._network_lock:
            self._network_local.result = None
            if key not in self._network_checks:
                def probe():
                    try:
                        completed, output = self._execute(role, f"network-probe-{mode}", NETWORK_TASK,
                                                          folder, schema=NETWORK_SCHEMA)
                    except BeeExecutionError as error:
                        return error.result
                    events = json_events(completed.stdout)
                    commands = [event["item"] for event in events if event.get("type") == "item.completed"
                                and event.get("item", {}).get("type") == "command_execution"]
                    isolated = False
                    if len(commands) == 1:
                        command = commands[0]
                        argv = shlex.split(command["command"])
                        if (len(argv) == 3 and Path(argv[0]).name in ("sh", "bash", "zsh")
                                and argv[1] in ("-c", "-lc")):
                            argv = shlex.split(argv[2])
                        isolated = (argv == shlex.split(NETWORK_COMMAND)
                                    and type(command.get("exit_code")) is int and command["exit_code"] in (6, 7)
                                    and output["exit_code"] == command["exit_code"]
                                    and any(event.get("type") == "turn.completed" for event in events))
                    if not isolated:
                        return classify_result(terminal={"signals": ["failure"], "code": "network_isolation",
                                                        "error": NETWORK_REFUSAL}, schema={})
                    return getattr(completed, "bee_result", classify_result(
                        terminal={"completed": True}, output=output, schema=NETWORK_SCHEMA))
                result = run_attempt(self, role, f"network-probe-{mode}", probe, before_start, kind="network_probe")
                self._network_local.result = result
                self._network_checks[key] = result["ok"]
            return self._network_checks[key]

    def __call__(self, role, name, task, folder, *, schema=None, before_start=None):
        try:
            self._paths(name)
            if role not in SCHEMAS:
                raise ValueError(f"unknown bee role: {role}")
        except ValueError as error:
            result = classify_result(terminal={"error": str(error), "code": "configuration", "returncode": 1}, schema={})
            result["provenance"] = provenance(self, role, name)
            return result
        if not self.allow_network:
            # Keep the isolated adapter's historical two-argument probe seam.
            allowed = (self._network_ok(role, folder) if before_start is None else
                       self._network_ok(role, folder, before_start=before_start))
            if not allowed:
                result = classify_result(terminal={"signals": ["failure"], "code": "network_isolation",
                                                   "error": NETWORK_REFUSAL}, schema={})
                probe = getattr(self._network_local, "result", None)
                if probe is not None:
                    result["provenance"] = dict(probe["provenance"])
                    result["probe_outcome"] = probe["outcome"]
                    result["seconds"] = probe["seconds"]
                    for field in ("tool_rejections", "tool_name", "consecutive_tool_rejections"):
                        if field in probe:
                            result[field] = probe[field]
                else:
                    result["provenance"] = provenance(self, role, name)
                    result["provenance"]["context_id"] = None
                return result
        def execute():
            try:
                kwargs = {} if schema is None else {"schema": schema}
                completed, output = self._execute(role, name, brief(role, task), folder, **kwargs)
                result = getattr(completed, "bee_result", classify_result(
                    terminal={"completed": True}, output=output,
                    schema=strict_schema(SCHEMAS[role]) if schema is None else schema))
                if result["ok"] and schema is None:
                    result["output"] = restore_optionals(output, SCHEMAS[role])
            except BeeExecutionError as error:
                result = error.result
            except ProviderRefusal as error:
                result = classify_result(terminal={"signals": ["provider_refusal"], "error": str(error)}, schema={})
            if self.allow_network:
                result["warning"] = NETWORK_WARNING
            return result
        result = run_attempt(self, role, name, execute, before_start)
        if self.allow_network:
            result["warning"] = NETWORK_WARNING
        return result


class MixedBees:
    """Alternate module builders and give the other model two of three council seats."""

    def __init__(self, claude, codex, policy="mixed"):
        if policy not in ("claude", "codex", "mixed"):
            raise ValueError("bee policy must be claude, codex or mixed")
        self.claude, self.codex, self.policy = claude, codex, policy

    def runner(self, role, name):
        if self.policy != "mixed":
            runner = self.claude if self.policy == "claude" else self.codex
        elif role in ("planner", "tester") or (role == "repair" and re.fullmatch(r"behaviour-fix-\d+", name)):
            runner = self.claude
        else:
            pattern = (r"m(\d+)-council-r\d+-(control|io|data)" if role == "councillor" else
                       r"m(\d+)-build" if role == "worker" else
                       r"m(\d+)-repair-[bcl]\d+" if role == "repair" else "")
            match = re.fullmatch(pattern, name) if pattern else None
            if not match or int(match[1]) < 1:
                raise ValueError("cannot route bee role/name in mixed policy")
            use_claude = int(match[1]) % 2 == 1
            if role == "councillor" and match[2] in ("control", "io"):
                use_claude = not use_claude
            runner = self.claude if use_claude else self.codex
        return runner

    def __call__(self, role, name, task, folder, *, schema=None, before_start=None):
        try:
            runner = self.runner(role, name)
        except ValueError as error:
            return classify_result(terminal={"error": str(error), "returncode": 1}, schema={})
        kwargs = {}
        if schema is not None:
            kwargs["schema"] = schema
        if before_start is not None:
            kwargs["before_start"] = before_start
        return runner(role, name, task, folder, **kwargs)


def add_arguments(parser):
    parser.add_argument("--bee-policy", choices=("claude", "codex", "mixed"), default="claude",
                        help="Bee models: Claude only, Codex only, or alternating builders and mixed councils")
    parser.add_argument("--codex", default="codex", help="Codex CLI executable")
    parser.add_argument("--codex-model", help="Model for Codex bees (default: Codex CLI's default)")
    parser.add_argument("--codex-effort", help="Reasoning effort for Codex bees")
    parser.add_argument("--codex-allow-network", action="store_true",
                        help="Accept Codex network access: skip the isolation probe and warn on every bee result")
    from hive import selfhost
    selfhost.add_arguments(parser)


def build(args, claude_runner, **runner_kwargs):
    """Build from CLI options; kwargs are CodexBees' shared engine/input/config settings."""
    from hive import selfhost
    runner, extra = selfhost.apply(args, claude_runner)
    if args.bee_policy == "claude":
        return claude_runner
    codex = runner(**dict(runner_kwargs, codex=args.codex, model=args.codex_model, effort=args.codex_effort,
                          allow_network=args.codex_allow_network), **extra)
    return codex if args.bee_policy == "codex" else MixedBees(claude_runner, codex, args.bee_policy)


def build_router(args, claude_runner, **runner_kwargs):
    """Configure routing only. The queen owns fallback activation and attempts."""
    from hive.selfhost import BeeRouter
    return BeeRouter(args, claude_runner, runner_kwargs)
