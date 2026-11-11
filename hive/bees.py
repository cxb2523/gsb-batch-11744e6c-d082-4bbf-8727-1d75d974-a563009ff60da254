"""Bees: one headless coding-agent process per task, each with its own ReverseAI MCP server.

Every bee runs in its own folder, may write only there, and gets a fixed tool set for its role.
No role gets a shell or the web: bees read text that comes from untrusted binaries, so a
prompt-injection attempt in that text can at most change files in the bee's own folder, which
the queen then checks. Each bee starts its own `reverseai mcp` server, so contained Ghidra
questions from different bees run in parallel instead of queueing on one stdio server.

The default runner drives Claude Code in print mode on the user's own login (no API key).
"""

import ipaddress
import json
import math
import os
import re
import selectors
import signal
import shlex
import subprocess
import sys
import time
import urllib.parse
import uuid
from pathlib import Path

ROLES = Path(__file__).with_name("roles")
# Texts with which model providers and their CLIs report a refusal by usage policy or safety classifiers.
REFUSAL = re.compile(r"(?i)usage polic|safeguards? (?:flagged|blocked|prevented)|flagged (?:this|the) (?:message|request)"
                     r"|I (?:cannot|can't|am unable to) (?:help(?!\s+(?:but|thinking)\b)|assist)(?: with| you)?|cybersecurity topic|cyber safeguard|unable to respond to this request|violat\w* (?:our|the) "
                     r"(?:usage|acceptable)|content (?:policy|filter)|refused by the model|stop_reason.{0,4}refusal")

COMMON = "common.md"

# Built-in tools per role; every role also gets the read-only ReverseAI MCP tools. Claude Code governs
# file writes through Edit rules, so every role that writes also needs Edit (its rule is fenced too).
TOOLSETS = {
    "planner": ("Read", "Write", "Edit"),
    "worker": ("Read", "Write", "Edit"),
    "repair": ("Read", "Write", "Edit"),
    "councillor": ("Read",),
    "tester": ("Read", "Write", "Edit"),
}

_STR = {"type": "string"}
_STRS = {"type": "array", "items": _STR}

SCHEMAS = {
    "planner": {
        "type": "object",
        "properties": {
            "modules": {"type": "array", "items": {
                "type": "object",
                "properties": {"id": _STR, "title": _STR, "functions": _STRS, "rationale": _STR},
                "required": ["id", "title", "functions"]}},
            "skipped": {"type": "array", "items": {
                "type": "object", "properties": {"entry": _STR, "reason": _STR}, "required": ["entry", "reason"]}},
            "notes": _STR,
        },
        "required": ["modules", "skipped"],
    },
    "worker": {
        "type": "object",
        "properties": {
            "status": {"type": "string", "enum": ["done", "partial", "blocked"]},
            "functions": {"type": "array", "items": {
                "type": "object",
                "properties": {"entry": _STR, "name": _STR,
                               "status": {"type": "string", "enum": ["rebuilt", "stub", "skipped"]},
                               "notes": _STR},
                "required": ["entry", "status"]}},
            "contract_requests": _STRS,
            "unknowns": _STRS,
        },
        "required": ["status", "functions"],
    },
    "councillor": {
        "type": "object",
        "properties": {
            "verdict": {"type": "string", "enum": ["accept", "refute"]},
            "defects": {"type": "array", "items": {
                "type": "object",
                "properties": {"function": _STR, "problem": _STR, "evidence": _STR, "fix": _STR},
                "required": ["function", "problem", "evidence"]}},
            "summary": _STR,
        },
        "required": ["verdict", "defects"],
    },
    "tester": {
        "type": "object",
        "properties": {
            "cases": {"type": "array", "items": {
                "type": "object",
                "properties": {
                    "id": _STR,
                    "files": {"type": "array", "items": {
                        "type": "object",
                        "properties": {"name": _STR, "text": _STR, "base64": _STR},
                        "required": ["name"]}},
                    "steps": {"type": "array", "items": {
                        "type": "object",
                        "properties": {"args": _STRS, "stdin": _STR},
                        "required": ["args"]}},
                    "why": _STR},
                "required": ["id", "steps"]}},
        },
        "required": ["cases"],
    },
}
SCHEMAS["repair"] = SCHEMAS["worker"]


class AttemptNotStarted(Exception):
    """The queen denied a reservation; no subprocess has been started."""
    def __init__(self, code="run_stopped", message=None):
        self.code = code
        super().__init__(message or code)


class AttemptHooks:
    def __call__(self, kind):
        raise NotImplementedError

    def finished(self, attempt_id, result):
        raise NotImplementedError


def parse_output(text):
    """Accept a JSON instance or one whole json fence. Never extract or repair."""
    text = text.strip()
    fence = re.fullmatch(r"```json\s*\n(.*?)\n```", text, re.DOTALL)
    if fence:
        text = fence[1]
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    def invalid_constant(value):
        raise ValueError("non-finite JSON number")
    value = json.loads(text, object_pairs_hook=pairs, parse_constant=invalid_constant)
    if isinstance(value, dict) and ("$schema" in value or
            value.get("type") == "object" and "properties" in value):
        raise ValueError("schema wrapper instead of a JSON instance")
    return value


def matches_schema(value, schema):
    """Validate the shared Hive schema vocabulary, failing closed on unknown assertions."""
    if isinstance(schema, bool):
        return schema
    if not isinstance(schema, dict):
        return False
    supported = {"type", "properties", "required", "additionalProperties", "items", "enum", "const",
                 "anyOf", "oneOf", "allOf", "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum",
                 "minItems", "maxItems", "uniqueItems", "minLength", "maxLength", "pattern",
                 "minProperties", "maxProperties", "$schema", "title", "description", "default", "examples"}
    if set(schema) - supported:
        return False
    if "anyOf" in schema and not any(matches_schema(value, s) for s in schema["anyOf"]):
        return False
    if "oneOf" in schema and sum(matches_schema(value, s) for s in schema["oneOf"]) != 1:
        return False
    if "allOf" in schema and not all(matches_schema(value, s) for s in schema["allOf"]):
        return False
    if "enum" in schema and not any(type(value) is type(v) and value == v for v in schema["enum"]):
        return False
    if "const" in schema and (type(value) is not type(schema["const"]) or value != schema["const"]):
        return False
    types = schema.get("type", [])
    types = [types] if isinstance(types, str) else types
    kinds = {"object": isinstance(value, dict), "array": isinstance(value, list),
             "string": isinstance(value, str), "integer": type(value) is int,
             "number": type(value) is int or type(value) is float and math.isfinite(value),
             "boolean": type(value) is bool, "null": value is None}
    if types and not any(kinds.get(t, False) for t in types):
        return False
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        if not set(schema.get("required", [])).issubset(value):
            return False
        extra = schema.get("additionalProperties", True)
        for key, child in value.items():
            if key in properties:
                if not matches_schema(child, properties[key]):
                    return False
            elif extra is False or isinstance(extra, dict) and not matches_schema(child, extra):
                return False
        if len(value) < schema.get("minProperties", 0) or len(value) > schema.get("maxProperties", float("inf")):
            return False
    if isinstance(value, list):
        if not all(matches_schema(v, schema.get("items", True)) for v in value):
            return False
        if len(value) < schema.get("minItems", 0) or len(value) > schema.get("maxItems", float("inf")):
            return False
        if schema.get("uniqueItems") and len({json.dumps(v, sort_keys=True) for v in value}) != len(value):
            return False
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0) or len(value) > schema.get("maxLength", float("inf")):
            return False
        if "pattern" in schema and re.search(schema["pattern"], value) is None:
            return False
    if type(value) in (int, float):
        if type(value) is float and not math.isfinite(value):
            return False
        if value < schema.get("minimum", -float("inf")) or value > schema.get("maximum", float("inf")):
            return False
        if "exclusiveMinimum" in schema and value <= schema["exclusiveMinimum"]:
            return False
        if "exclusiveMaximum" in schema and value >= schema["exclusiveMaximum"]:
            return False
    return True


def _prose(text):
    # Code, Markdown quotes and quoted examples are evidence, not a provider statement.
    text = re.sub(r"```.*?```", "", str(text or ""), flags=re.DOTALL)
    text = re.sub(r"(?m)^\s*>.*$", "", text)
    text = re.sub(r'"[^"\n]*"|“[^”\n]*”|`[^`\n]*`', "", text)
    return text


def is_refusal(*texts):
    for text in texts:
        if not isinstance(text, str):
            continue
        for line in _prose(text).splitlines():
            line = re.sub(r"(?i)\b(?:no|without|not a|not any)\s+(?:\w+\s+){0,3}(?:usage policy(?: violation)?|policy violation|content filter)\b", "", line)
            line = re.sub(r"(?i)\bnot refused by the model\b", "", line)
            if REFUSAL.search(line):
                return True
    return False


def _text_outcome(text):
    if str(text).lower() in ("refusal", "content_policy_violation", "safety_refusal", "content_filter", "usage_policy_violation"):
        return "provider_refusal"
    if is_refusal(text):
        return "provider_refusal"
    if re.search(r"(?i)invalid[_ -](?:schema|json)|structured_output_retries|json_schema_error", text or ""):
        return "invalid_schema"
    if re.search(r"(?i)\b(?:429|rate[_ -]?limit(?:ed|[_ -](?:exceeded|error))?|(?:insufficient[_ -])?quota(?:[_ -](?:exceeded|exhausted))?|too many requests)\b", text or ""):
        return "rate_limit"
    if re.search(r"(?i)context[_ -]?(?:(?:length|window)[_ -]?)?(?:limit|exceeded)|maximum context|too many (?:input )?tokens|prompt (?:is )?too long", text or ""):
        return "context_limit"
    return None


def terminal_signals(data):
    """Only explicit native status/code fields; messages are classified separately."""
    if not isinstance(data, dict):
        return []
    result = []
    for key in ("code", "status_code", "http_status", "stop_reason", "finish_reason", "codex_error_info"):
        signal = _text_outcome(str(data.get(key) or ""))
        if signal:
            result.append(signal)
    error = data.get("error")
    if isinstance(error, dict):
        result.extend(terminal_signals(error))
        signal = _text_outcome(str(error.get("type") or ""))
        if signal:
            result.append(signal)
    elif isinstance(error, str):
        signal = _text_outcome(error)
        if signal:
            result.append(signal)
    return result


def redact(text):
    text = str(text or "")
    key = r"(?:(?:[A-Za-z0-9]+_)*(?:api[_-]?key|auth[_-]?token|access[_-]?token|refresh[_-]?token|token|password|client[_-]?secret)|authorization|proxy-authorization|x-api-key)"
    text = re.sub(r"[\"']?(" + key + r")[\"']?\s*[:=]\s*[\"'][^\"']*[\"']", r'\1: "[REDACTED]"', text, flags=re.IGNORECASE)
    text = re.sub(r"(?i)(\b" + key + r"\s*[:=]\s*)(?:Bearer\s+)?[^\s,;\"}]+", r"\1[REDACTED]", text)
    text = re.sub(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*", "Bearer [REDACTED]", text)
    text = re.sub(r"(?i)(--(?:api-key|token|password)\s+)\S+", r"\1[REDACTED]", text)
    text = re.sub(r"\b(?:sk-[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9_]+)\b", "[REDACTED]", text)
    text = re.sub(r"(https?://)[^/\s:@]+:[^/\s@]+@", r"\1[REDACTED]@", text)
    return text


def classify_result(*, terminal, assistant_text="", diagnostic="", output=None, schema):
    """Classify trusted terminal signals before diagnostics, prose and schema validation.

    terminal is normalized by each CLI: completed, timed_out, returncode, signals
    (outcome strings), error and optional code. Tool text never enters diagnostic.
    """
    terminal = terminal or {}
    wrapper = isinstance(output, dict) and ("$schema" in output or output.get("type") == "object" and "properties" in output)
    valid = isinstance(output, dict) and not wrapper and matches_schema(output, schema)
    signals = set(terminal.get("signals", [])) - {None}
    message = str(terminal.get("error") or diagnostic or "")
    code = terminal.get("code")
    if terminal.get("timed_out"):
        outcome, code = "timeout", "process_timeout"
    elif len(signals) > 1 or terminal.get("inconsistent"):
        outcome, code = "failure", "inconsistent_terminal"
    elif signals:
        outcome = next(iter(signals))
    elif _text_outcome(diagnostic):
        outcome = _text_outcome(diagnostic)
    elif not valid and _text_outcome(_prose(assistant_text)):
        outcome, message = _text_outcome(_prose(assistant_text)), assistant_text
    elif terminal.get("returncode", 0) or terminal.get("error"):
        outcome = "failure"
    elif not valid or not terminal.get("completed"):
        outcome, code = "invalid_schema", "invalid_output" if not valid else "incomplete_turn"
    else:
        outcome, code = "ok", None
    if outcome == "provider_refusal":
        # Preserve a refusal near the start even when a huge diagnostic follows it.
        source = message or assistant_text
        match = REFUSAL.search(source)
        if match:
            message = source[max(0, match.start() - 60):match.end() + 220]
    if outcome != "ok" and not message:
        message = assistant_text or ("answer does not match the bee's output schema" if not valid else "turn did not complete")
    native = redact(diagnostic)
    return {"schema": "hive.bee-result/1", "ok": outcome == "ok", "outcome": outcome,
            "output": output if outcome == "ok" else None,
            "error": None if outcome == "ok" else redact(message).strip()[:300],
            "seconds": 0, "refused": outcome == "provider_refusal", "code": code,
            "provenance": {}, "tool_rejections": None,
            "diagnostic": {"text": native[:4096], "truncated": len(native) > 4096,
                           "characters": len(native), "limit": 4096}}


def provenance(runner, role, name, attempt_id=None):
    env = runner.env or {}
    server = getattr(runner, "server", None) or env.get("ANTHROPIC_BASE_URL")
    server_kind = "cloud"
    if server:
        host = urllib.parse.urlsplit(server).hostname
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = host == "localhost"
        server_kind = "local" if loopback else "remote"
    return {"attempt_id": attempt_id, "logical_id": name, "kind": "bee", "role": role, "bee": name,
            "client": "codex" if hasattr(runner, "codex") else "claude",
            "server_kind": server_kind, "server": server,
            "requested_model": runner.model, "observed_model": None, "model_digest": None,
            "context_id": str(uuid.uuid4()), "origin": getattr(runner, "origin", "primary")}


def run_attempt(runner, role, name, operation, before_start=None, *, kind="bee"):
    # A denied hook propagates without a finished event or a subprocess.
    attempt_id = before_start(kind) if before_start is not None else None
    started = time.monotonic()
    metadata = provenance(runner, role, name, attempt_id)
    metadata["kind"] = kind
    try:
        result = operation()
    except AttemptNotStarted:
        raise
    except subprocess.TimeoutExpired as error:
        result = classify_result(terminal={"timed_out": True, "error": f"no answer within {runner.timeout} s"},
                                 diagnostic=str(error.stderr or ""), schema={})
        result["tool_rejections"] = getattr(error, "tool_rejections", None)
    except Exception as error:
        result = classify_result(terminal={"error": str(error), "returncode": 1},
                                 diagnostic=str(error), schema={})
    result["seconds"] = runner.timeout if result["outcome"] == "timeout" else round(time.monotonic() - started, 3)
    result["provenance"] = metadata
    if before_start is not None:
        before_start.finished(attempt_id, result)
    return result


def json_events(stdout):
    try:
        value = json.loads(stdout or "")
        if isinstance(value, dict):
            return [value]
    except ValueError:
        pass
    events = []
    for line in (stdout or "").splitlines():
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict):
            events.append(value)
    return events


class ToolRejectionMonitor:
    """Read native MCP results; prose and other tools cannot change the streak."""
    def __init__(self, client, limit=None):
        self.client, self.limit = client, limit
        self.observed, self.total, self.consecutive = False, 0, 0
        self.names, self.seen, self.stop = {}, set(), None

    @staticmethod
    def schema_error(error):
        if isinstance(error, dict) and error.get("code") == -32602:
            return True
        return bool(re.search(r"(?i)invalid (?:arguments|params|parameters)|arguments must match.{0,80}schema"
                              r"|(?:input|argument|parameter) (?:schema|validation)|validation error"
                              r"|does not match.{0,80}schema", str(error)))

    def result(self, identity, name, rejected):
        self.observed = True
        if identity is not None:
            if identity in self.seen:
                return
            self.seen.add(identity)
        self.total += int(rejected)
        self.consecutive = self.consecutive + 1 if rejected else 0
        if self.limit is not None and self.consecutive >= self.limit and self.stop is None:
            self.stop = {"tool_name": name or None, "consecutive_tool_rejections": self.consecutive}

    def feed(self, event):
        if self.client == "claude":
            if event.get("type") not in ("assistant", "user"):
                return
            for block in event.get("message", {}).get("content", []):
                if not isinstance(block, dict):
                    continue
                if block.get("type") == "tool_use":
                    self.names[block.get("id")] = block.get("name", "")
                name = self.names.get(block.get("tool_use_id"), "")
                if block.get("type") == "tool_result" and name.startswith("mcp__"):
                    self.result(block.get("tool_use_id"), name,
                                bool(block.get("is_error") and self.schema_error(block.get("content", ""))))
        elif event.get("type", "").startswith("item."):
            item = event.get("item", {})
            if item.get("type") == "mcp_tool_call":
                if event.get("type") == "item.completed":
                    self.result(item.get("id"), item.get("tool") or item.get("name"),
                                bool(item.get("error") and self.schema_error(item["error"])))


def tool_rejections(events, *, client):
    """Count observed MCP argument/schema errors, never infer missing tool traces."""
    monitor = ToolRejectionMonitor(client)
    for event in events:
        monitor.feed(event)
    return monitor.total if monitor.observed else None


def run_cli(argv, *, input, cwd, env, capture_output, text, timeout, check,
            client, max_tool_rejections):
    """Capture both pipes live and stop only the POSIX session created for this CLI.

    No shell or preexec_fn: concurrent bees each own a distinct process group.
    Keep the leader unreaped until group signalling finishes, preventing PID reuse.
    """
    if os.name != "posix":
        raise OSError("live tool monitoring requires POSIX process groups")
    if not capture_output or not text or check:
        raise ValueError("run_cli requires text capture and check=False")
    monitor = ToolRejectionMonitor(client, max_tool_rejections)
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    pending, payload, sent = bytearray(), input.encode("utf-8"), 0
    process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    deadline, stopped, timed_out = time.monotonic() + timeout, False, False
    drain_deadline = float("inf")

    def stop_group():
        # Reaping only happens below, after both signals target our original group.
        for signum in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(process.pid, signum)
            except ProcessLookupError:
                pass
            except PermissionError:
                # Darwin reports EPERM for a group containing only zombies.
                # Accept it only with an unreaped, exited leader.
                if os.waitid(
                        os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
                    raise
            if signum == signal.SIGTERM:
                time.sleep(0.1)

    def events(data):
        for event in json_events(data.decode("utf-8", errors="replace")):
            monitor.feed(event)

    try:
        with selectors.DefaultSelector() as selector:
            for pipe, name, mode in ((process.stdin, "stdin", selectors.EVENT_WRITE),
                                      (process.stdout, "stdout", selectors.EVENT_READ),
                                      (process.stderr, "stderr", selectors.EVENT_READ)):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, mode, name)
            while selector.get_map() and time.monotonic() < drain_deadline:
                if not stopped and (monitor.stop is not None or time.monotonic() >= deadline):
                    timed_out = monitor.stop is None
                    stop_group()
                    stopped = True
                    # Other sessions may retain inherited pipe writers. Bound
                    # our drain and close our read ends without signalling them.
                    drain_deadline = time.monotonic() + .25
                for key, _ in selector.select(min(.05, max(0, drain_deadline - time.monotonic()))):
                    pipe, name = key.fileobj, key.data
                    if name == "stdin":
                        try:
                            sent += os.write(pipe.fileno(), payload[sent:sent + 65536]) if sent < len(payload) else 0
                        except BrokenPipeError:
                            sent = len(payload)
                        if sent == len(payload):
                            selector.unregister(pipe)
                            pipe.close()
                        continue
                    data = os.read(pipe.fileno(), 65536)
                    if data:
                        captured[name].extend(data)
                        if name == "stdout":
                            pending.extend(data)
                            while b"\n" in pending:
                                line, _, rest = pending.partition(b"\n")
                                pending[:] = rest
                                events(line)
                                if monitor.stop is not None:
                                    break
                    else:
                        if name == "stdout" and pending:
                            events(pending)
                            pending.clear()
                        selector.unregister(pipe)
                        pipe.close()
                if monitor.stop is not None and not stopped:
                    stop_group()
                    stopped = True
                    drain_deadline = time.monotonic() + .25
            # A CLI may close its pipes before exiting. The deadline still applies.
            if not stopped:
                try:
                    process.wait(timeout=max(0, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    timed_out = True
                    stop_group()
            process.wait()
    except BaseException:
        if process.returncode is None:
            stop_group()
            process.wait()
        raise
    finally:
        for pipe in (process.stdin, process.stdout, process.stderr):
            pipe.close()
    stdout, stderr = (captured[key].decode("utf-8", errors="replace") for key in ("stdout", "stderr"))
    if timed_out:
        error = subprocess.TimeoutExpired(argv, timeout, output=stdout, stderr=stderr)
        error.tool_rejections = tool_rejections(json_events(stdout), client=client)
        raise error
    result = subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)
    result.tool_schema_stop = monitor.stop
    return result


def tool_schema_result(completed):
    """Only the live controller can issue this outcome, never assistant prose."""
    stop = getattr(completed, "tool_schema_stop", None)
    if not isinstance(stop, dict):
        return None
    name = stop["tool_name"] or "unknown MCP tool"
    result = classify_result(terminal={"signals": ["tool_schema_failure"], "code": "tool_schema_failure",
                                      "error": f"Stopped after {stop['consecutive_tool_rejections']} consecutive "
                                               f"MCP argument/schema rejections ({name})"}, schema={})
    result.update(stop)
    return result


def capability_roundtrip(events, client, nonce):
    """Native tool evidence for check_model; no generated tool claims count."""
    pending = set()
    for event in events:
        if client == "claude":
            for block in event.get("message", {}).get("content", []):
                if not isinstance(block, dict):
                    continue
                if (event.get("type") == "assistant" and block.get("type") == "tool_use"
                        and block.get("name") == "Read"
                        and Path(str(block.get("input", {}).get("file_path", ""))).name == "capability-input.json"):
                    pending.add(block.get("id"))
                if (event.get("type") == "user" and block.get("type") == "tool_result"
                        and block.get("tool_use_id") in pending and not block.get("is_error")
                        and nonce in str(block.get("content", ""))):
                    return True
        elif event.get("type") == "item.completed":
            item = event.get("item", {})
            if item.get("type") != "command_execution" or item.get("exit_code") != 0:
                continue
            try:
                argv = shlex.split(item.get("command", ""))
                if len(argv) == 3 and Path(argv[0]).name in ("sh", "bash", "zsh") and argv[1] in ("-c", "-lc"):
                    argv = shlex.split(argv[2])
            except ValueError:
                continue
            if (len(argv) == 2 and Path(argv[0]).name == "cat" and Path(argv[1]).name == "capability-input.json"
                    and nonce in str(item.get("aggregated_output", ""))):
                return True
    return False


def brief(role, task):
    """The shared role-card prefix first (identical across sibling bees), the task last."""
    common = (ROLES / COMMON).read_text(encoding="utf-8")
    card = (ROLES / f"{role if role != 'repair' else 'worker'}.md").read_text(encoding="utf-8")
    return f"{common}\n\n{card}\n\n# Your task\n\n{task}\n"


class ClaudeBees:
    """Run each bee as `claude -p` in its own folder with its own ReverseAI MCP server."""

    def __init__(self, *, engine, inputs, enabled=("ghidra",), claude="claude", model=None, effort=None,
                 timeout=2400, python=sys.executable, config_dir, env=None, max_tool_rejections=8):
        if type(max_tool_rejections) is not int or max_tool_rejections < 1:
            raise ValueError("max_tool_rejections must be a positive integer")
        self.max_tool_rejections = max_tool_rejections
        self.engine, self.inputs, self.enabled = str(engine), str(inputs), tuple(enabled)
        self.claude, self.model, self.effort, self.timeout, self.python = claude, model, effort, timeout, python
        self.config_dir = Path(config_dir)
        self.env = env  # None inherits this process's environment; hive.selfhost sets a self-hosted one

    def _mcp_config(self, name):
        if not re.fullmatch(r"[A-Za-z0-9_-]+", name):
            raise ValueError("invalid bee name")
        self.config_dir.mkdir(parents=True, exist_ok=True)
        path = self.config_dir / f"{name}.json"
        env = {"PYTHONPATH": self.engine, "PYTHONDONTWRITEBYTECODE": "1"}
        args = ["-B", "-m", "reverseai", "mcp", "--inputs", self.inputs, *("--with-" + t for t in self.enabled)]
        path.write_text(json.dumps({"mcpServers": {"reverseai": {
            "type": "stdio", "command": self.python, "args": args, "env": env}}}, indent=1), encoding="utf-8")
        return path

    def argv(self, role, name, *, schema=None):
        tools = TOOLSETS[role]
        argv = [self.claude, "-p", "--output-format", "stream-json", "--verbose", "--json-schema", json.dumps(SCHEMAS[role] if schema is None else schema),
                "--mcp-config", str(self._mcp_config(name)), "--strict-mcp-config",
                "--tools", ",".join(tools), "--permission-mode", "dontAsk", "--no-session-persistence",
                "--allowedTools", "mcp__reverseai__*", *(f"{tool}(./**)" for tool in tools)]
        if self.model:
            argv[2:2] = ["--model", self.model]
        if self.effort:
            argv[2:2] = ["--effort", self.effort]
        return argv

    def __call__(self, role, name, task, folder, *, schema=None, before_start=None):
        expected = SCHEMAS[role] if schema is None else schema
        def execute():
            completed = run_cli(self.argv(role, name, schema=schema), input=brief(role, task),
                                       cwd=folder, env=self.env, capture_output=True, text=True,
                                       timeout=self.timeout, check=False, client="claude",
                                       max_tool_rejections=self.max_tool_rejections)
            events = json_events(completed.stdout)
            finals = [e for e in events if e.get("type") == "result"]
            # Retain compatibility with a captured --output-format json result.
            if not finals and len(events) == 1 and any(k in events[0] for k in ("structured_output", "result", "is_error")):
                finals = events
            data = finals[-1] if finals else {}
            assistant_errors = [str(e["error"]) for e in events if e.get("type") == "assistant" and e.get("error")]
            has_error = bool(data.get("is_error") or data.get("error") or assistant_errors
                             or str(data.get("subtype", "")).startswith("error_"))
            assistant = str(data.get("result") or "")
            if not assistant:
                assistant = "\n".join(b.get("text", "") for e in events if e.get("type") == "assistant"
                                      for b in e.get("message", {}).get("content", []) if b.get("type") == "text")
            output = data.get("structured_output")
            if output is None:
                try:
                    output = parse_output(assistant)
                except (ValueError, TypeError):
                    pass
            signals = []
            for e in events:
                if e.get("type") in ("assistant", "result"):
                    signals.extend(terminal_signals(e))
                    message = e.get("message", {}) if e.get("type") == "assistant" else e
                    signals.extend(terminal_signals(message))
                    if any(isinstance(b, dict) and b.get("type") == "refusal" for b in message.get("content", [])):
                        signals.append("provider_refusal")
                if e.get("type") == "result" and e.get("is_error"):
                    signal = _text_outcome(str(e.get("subtype") or ""))
                    if signal:
                        signals.append(signal)
            native = "\n".join(filter(None, [completed.stderr, str(data.get("subtype") or "") if has_error else "",
                                               assistant if has_error else "", str(data.get("error") or ""), *assistant_errors]))
            terminal = {"completed": bool(finals) and not has_error, "signals": signals,
                        "returncode": completed.returncode}
            if has_error:
                terminal["error"] = assistant or str(data.get("error") or data.get("subtype") or "agent failed")
            result = classify_result(terminal=terminal, assistant_text=assistant,
                                     diagnostic=native, output=output, schema=expected)
            result = tool_schema_result(completed) or result
            result.update(turns=data.get("num_turns"), cost_usd=data.get("total_cost_usd"),
                          tool_rejections=tool_rejections(events, client="claude"))
            if hasattr(self, "_capability_nonce"):
                result["capability_tool_roundtrip"] = capability_roundtrip(events, "claude", self._capability_nonce)
            if hasattr(self, "_capability_mcp"):
                from hive import selfhost
                result["capability_mcp_tool"] = selfhost.mcp_tool_accepted(events, "claude", self._capability_mcp)
            return result
        return run_attempt(self, role, name, execute, before_start)


def environment_ok(claude="claude"):
    """True when the agent CLI can be found; the run itself proves the login."""
    return any((Path(p) / claude).is_file() for p in os.environ.get("PATH", "").split(os.pathsep)) or Path(claude).is_file()
