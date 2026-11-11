"""The queen: deterministic orchestration of a ReverseAI analyst team (the hive).

The queen is code, not a model. She exports the program map from ReverseAI, asks one planner
bee to split the work and freeze the shared interface (`contract.h`), runs builder bees in
parallel (one per module, each with its own MCP server), compiles and links what they write,
and sends every module to an independent council that tries to refute it. Then the binding
checks run: every claim's citations are re-run through ReverseAI (tools/hive_check.py) and,
only when the operator allows it, the original and the rebuild run the same conformance cases.
The final verdict is computed from those results by code; nothing can override a failed check.

    python -m hive run --inputs DIR --file NAME --out NEW_DIR [--bees 4] [--run-original]

Every run needs prepared exports (`reverseai prepare`, ReverseAI 0.8.0 or later) and a
contained Ghidra image. See docs/HIVE.md.
"""

import argparse
import base64
import contextlib
import concurrent.futures
import copy
import hashlib
import json
import math
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

from hive import bees as bees_module
from hive import codex_bees, languages, partition, planning as planning_module, preflight, selfhost
from hive import fuzz as fuzz_module
from reverseai import intake

ROOT = Path(__file__).resolve().parents[1]
WARNINGS = ("-O1", "-Wall", "-Wextra", "-Wno-unused-parameter", "-fwrapv", "-fno-strict-aliasing")
CFLAGS = (languages.C.standard, *WARNINGS)
FORBIDDEN = re.compile(r"\b(?:asm|__asm__|__asm)\b|\.incbin|#\s*embed\b|\bdlopen\b|#\s*pragma\s+comment\b")
EXPANDED_FORBIDDEN = re.compile(r"\.(?:incbin|include)\b|#\s*embed\b|\bdlopen\b|#\s*pragma\s+comment\b")
COMPILED_IDENTITY = ("source_sha256", "contract_sha256", "object_sha256", "compiler_sha256")
MAX_COMPILER_STDOUT = 16 * 1024 * 1024
MAX_COMPILER_STDERR = 256 * 1024
PROTOTYPE = re.compile(r"([A-Za-z_]\w*)\s*\([^;{}]*\)\s*;\s*/\*\s*0x([0-9a-fA-F]+)\s*\*/")
LENSES = (
    ("control", "control flow and arithmetic: conditions, loops, integer widths, signedness, overflow, "
                "shifts and return values, checked against the ASSEMBLY of every function"),
    ("io", "everything the program reads and writes: output bytes and formats, error messages, exit "
           "codes, files, stdin/stdout/stderr handling and the order of operations"),
    ("data", "data and memory: structs and offsets, constant tables, globals and their initial values, "
             "buffer sizes, endianness and pointer arithmetic"),
)
MAX_CASE_FILE = 64 * 1024
MIN_CASES = 2


class HiveError(RuntimeError):
    pass


class ProviderRefused(HiveError):
    """The model provider refused the planner, so no other bee can start."""


class StartDenied(HiveError):
    """Internal reservation failure; the adapter's AttemptNotStarted is injected separately."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def read_json(path):
    return json.loads(intake.snapshot(Path(path))[0])


@contextlib.contextmanager
def workspace_lock(folder):
    """An OS lock survives neither a dead process nor a second writer; its pathname may remain."""
    if folder.is_symlink():
        raise HiveError("unsafe workspace state directory")
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / "run.lock"
    if path.is_symlink() or (path.exists() and path.stat().st_nlink != 1):
        raise HiveError("unsafe workspace lock")
    with path.open("a+b") as handle:
        try:
            if os.name == "nt":
                import msvcrt
                handle.seek(0)
                if not handle.read(1):
                    handle.write(b"0")
                    handle.flush()
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise HiveError("another queen owns this workspace") from None
        try:
            yield
        finally:
            if os.name == "nt":
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


class RunState:
    """Durable counters and provenance, reconstructed from a checked append-only journal.

    run.json is a checkpoint, never a replacement for a missing journal tail. A committed
    journal suffix after a crash is replayed; a stale or changed checkpoint is refused.
    The owner serializes append() with the queen's lock and owns the workspace OS lock.
    """

    def __init__(self, folder):
        self.lock = threading.RLock()
        self.folder = Path(folder)
        self.folder.mkdir(parents=True, exist_ok=True)
        self.path, self.journal = self.folder / "run.json", self.folder / "attempts.jsonl"
        self.data = {"schema": "hive.run-state/1", "run_id": None, "binding": None, "plan": None,
                     "policy": None, "max_bees": 400, "spent": {"bees": 0, "seconds": 0.0, "cost_usd": 0.0},
                     "attempts": {}, "logical": {}, "refusals": [], "unresolved_refusals": {},
                     "activated": [], "stopped": None, "authors": {}, "planning_progress": None}
        self.seq, self.head = 0, "0" * 64
        try:
            checkpoint = read_json(self.path) if self.path.exists() else None
        except (OSError, ValueError, intake.IntakeError):
            raise HiveError("resume_mismatch: unreadable run checkpoint") from None
        if checkpoint and checkpoint.get("schema") != "hive.run-state/1":
            raise HiveError("resume_mismatch: unknown run state")
        matched = checkpoint is None
        if self.journal.exists():
            try:
                lines = intake.snapshot(self.journal)[0].splitlines()
                for line in lines:
                    row = json.loads(line)
                    hashed = row.pop("hash")
                    if row["seq"] != self.seq + 1 or row["previous"] != self.head or digest(row) != hashed:
                        raise ValueError("journal chain")
                    self.apply(row["kind"], row["data"])
                    self.seq, self.head = row["seq"], hashed
                    if checkpoint and checkpoint.get("journal_seq") == self.seq:
                        saved = {k: v for k, v in checkpoint.items() if k not in ("journal_seq", "journal_head")}
                        matched = checkpoint.get("journal_head") == self.head and saved == self.data
                        if not matched:
                            raise ValueError("checkpoint differs from journal")
            except (ValueError, KeyError, TypeError, intake.IntakeError) as error:
                raise HiveError(f"resume_mismatch: invalid run journal ({error})") from None
        if checkpoint and not matched:
            raise HiveError("resume_mismatch: missing journal/checkpoint history")
        if not self.seq:
            self.append("init", {"run_id": uuid.uuid4().hex})
        else:
            for aid, attempt in list(self.data["attempts"].items()):
                if attempt["status"] == "started":
                    self.append("interrupted", {"attempt_id": aid})
            self.save()

    def save(self):
        write_file(self.path, canonical(dict(self.data, journal_seq=self.seq, journal_head=self.head)))

    def append(self, kind, data):
        with self.lock:
            self._append(kind, data)

    def _append(self, kind, data):
        row = {"seq": self.seq + 1, "previous": self.head, "kind": kind, "data": data}
        row["hash"] = digest(row)
        if self.journal.is_symlink() or (self.journal.exists() and self.journal.stat().st_nlink != 1):
            raise HiveError("unsafe attempt journal")
        with self.journal.open("ab") as handle:
            handle.write(canonical(row) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        self.apply(kind, data)
        self.seq, self.head = row["seq"], row["hash"]
        self.save()

    def apply(self, kind, data):
        state = self.data
        if kind == "init":
            state["run_id"] = data["run_id"]
        elif kind in ("binding", "plan", "policy", "planning_progress"):
            state[kind] = copy.deepcopy(data)
        elif kind == "limit":
            state["max_bees"] = data["max_bees"]
        elif kind == "stop":
            state["stopped"] = data["reason"]
        elif kind == "activate":
            if data["key"] not in state["activated"]:
                state["activated"].append(data["key"])
        elif kind == "start":
            aid = data["attempt_id"]
            if aid in state["attempts"]:
                raise ValueError("duplicate attempt")
            state["attempts"][aid] = dict(data, status="started")
            state["spent"]["bees"] += 1
        elif kind == "finish":
            attempt = state["attempts"][data["attempt_id"]]
            if attempt["status"] != "started":
                raise ValueError("attempt already finished")
            answer = data["result"]
            attempt.update(status="finished", result=copy.deepcopy(answer))
            for metric in ("seconds", "cost_usd"):
                value = answer.get(metric)
                if isinstance(value, (int, float)) and math.isfinite(value) and value >= 0:
                    state["spent"][metric] += value
            if answer.get("outcome") == "provider_refusal":
                refusal = {k: attempt[k] for k in ("attempt_id", "logical_id", "bee", "role", "kind")}
                refusal["text"] = (answer.get("error") or "")[:300]
                state["refusals"].append(refusal)
                if attempt["kind"] == "network_probe":
                    state["unresolved_refusals"][data["attempt_id"]] = refusal
        elif kind == "interrupted":
            state["attempts"][data["attempt_id"]]["status"] = "interrupted"
        elif kind == "logical":
            lid, answer = data["logical_id"], data["result"]
            state["logical"][lid] = copy.deepcopy(data)
            refused = [r for r in state["refusals"] if r["logical_id"] == lid and r["kind"] == "bee"]
            if answer["outcome"] == "ok":
                state["unresolved_refusals"].pop(lid, None)
            elif refused:
                state["unresolved_refusals"][lid] = copy.deepcopy(refused[-1])
        elif kind == "author":
            authors = state["authors"].setdefault(data["module"], [])
            if data["attempt_id"] not in authors:
                authors.append(data["attempt_id"])
        else:
            raise ValueError("unknown run event")


class AttemptHooks:
    def __init__(self, queen, logical_id, role, name, local, descriptor, recovery):
        self.queen, self.logical_id, self.role, self.name = queen, logical_id, role, name
        self.local, self.descriptor, self.recovery = local, descriptor, recovery
        self.ids = []
        self.leased = 0

    def __call__(self, kind):
        q = self.queen
        if kind not in ("bee", "network_probe"):
            raise HiveError("unknown attempt kind")
        with q.lock:
            q._ensure_state()
            if q.stopped and not (self.recovery and (self.local or kind == "network_probe")
                                  and q.stopped in ("refusal_limit", "planner_refused")):
                raise q.attempt_not_started(q.stopped)
            if q.spent["bees"] + q.reserved - self.leased >= q.max_bees:
                if q.spent["bees"] >= q.max_bees:
                    q._stop("budget_exhausted")
                raise q.attempt_not_started("budget_exhausted")
            if self.leased:
                self.leased -= 1
                q.reserved -= 1
            aid = uuid.uuid4().hex
            record = dict(self.descriptor, attempt_id=aid, logical_id=self.logical_id,
                          role=self.role, bee=self.name, kind=kind, context_id=aid,
                          origin="fallback" if self.local else "primary")
            q.state.append("start", record)
            self.ids.append(aid)
            return aid

    def finished(self, attempt_id, result):
        with self.queen.lock:
            if attempt_id not in self.ids:
                raise HiveError("result for an unreserved attempt")
            answer = self.queen._answer(result)
            self.queen.state.append("finish", {"attempt_id": attempt_id, "result": answer})


def hexed(value):
    return f"0x{value:x}"


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_file(path, data, mode=0o644):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as handle:
        temporary = Path(handle.name)
        handle.write(data)
    try:
        temporary.chmod(mode)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


# --- ReverseAI, run as its command line from an engine checkout -----------------------------------

class Engine:
    def __init__(self, *, root, inputs, file, enabled=("ghidra",), python=sys.executable, timeout=1500):
        self.root, self.inputs, self.file = Path(root), Path(inputs), file
        self.enabled, self.python, self.timeout = tuple(enabled), python, timeout

    @property
    def path(self):
        return self.inputs / self.file

    def _run(self, argv, timeout=None):
        env = dict(os.environ, PYTHONPATH=str(self.root), PYTHONDONTWRITEBYTECODE="1")
        return subprocess.run([self.python, "-B", "-m", "reverseai", *argv], capture_output=True, text=True,
                              env=env, timeout=timeout or self.timeout, check=False)

    def prepare(self):
        done = self._run(["prepare", str(self.path), *("--with-" + t for t in self.enabled), "--json"], timeout=1100)
        if done.returncode != 0:
            raise HiveError("prepare failed: " + (done.stderr.strip().splitlines() or ["?"])[-1])
        return json.loads(done.stdout)

    def query(self, name, args, out):
        Path(out).parent.mkdir(parents=True, exist_ok=True)  # the CLI creates --out itself, not its parents
        argv = ["query", str(self.path), "--query", name, "--out", str(out), *("--with-" + t for t in self.enabled)]
        for key, value in args.items():
            argv += ["--arg", f"{key}={value}"]
        done = self._run(argv)
        report = Path(out) / "report.json"
        if done.returncode != 0 or not report.is_file():
            raise HiveError(f"{name} {args} failed: " + (done.stderr.strip().splitlines() or ["?"])[-1])
        return json.loads(report.read_text(encoding="utf-8"))


def export_rows(report, claim_key):
    rows, total = [], None
    for result in report.get("results", []):
        for finding in result.get("findings", []):
            if finding.get("claim_key") == claim_key and finding.get("verdict") in ("supported", "derived"):
                rows += finding["value"]["rows"]
                total = finding["value"]["total"]
    return sorted(rows, key=lambda row: row["index"]), total


def survey(engine, folder, log):
    """Export functions, calls and strings of the prepared program into map.json."""
    folder.mkdir(parents=True, exist_ok=True)
    receipt = engine.prepare()
    log(f"prepared {engine.file}: {json.dumps(receipt, sort_keys=True)[:200]}")
    tables = {}
    for part, key in (("functions", "code.export_functions"), ("calls", "code.export_calls"),
                      ("strings", "code.export_strings")):
        rows, start = [], 0
        while True:
            report = engine.query("export_program", {"part": part, "start": start, "limit": 128},
                                  folder / "pages" / f"{part}-{start:06d}")
            page, total = export_rows(report, key)
            rows += page
            start += len(page)
            if not page or total is None or start >= total:
                break
        tables[part] = rows
        log(f"survey: {len(rows)} {part}")
    report_sha = report["input"]["sha256"]
    functions = [{"entry": r["entry"], "hex": hexed(r["entry"]), "name": r["name"], "size": r["size"],
                  "signature": r.get("signature")} for r in tables["functions"]]
    known = {f["entry"] for f in functions}
    program_map = {
        "file": engine.file, "input_sha256": report_sha, "functions": functions,
        "calls": [{"from": hexed(r["from"]), "to": hexed(r["to"]), "to_name": r.get("to_name")} for r in tables["calls"]],
        "imports": sorted({r.get("to_name") for r in tables["calls"] if r["to"] not in known and r.get("to_name")}),
        "strings": [{"from": hexed(r["from"]), "address": hexed(r["address"]), "text": r["text"]} for r in tables["strings"]],
    }
    (folder / "map.json").write_text(json.dumps(program_map, indent=1, ensure_ascii=False), encoding="utf-8")
    return program_map


# --- Plan ------------------------------------------------------------------------------------------

def normalise_plan(plan, program_map, max_functions):
    """Every non-skipped function in exactly one module of bounded size; leftovers by address."""
    entries = {f["hex"]: f for f in program_map["functions"]}
    skipped = {s["entry"].lower(): s["reason"] for s in plan.get("skipped", []) if s.get("entry", "").lower() in entries}
    seen, modules = set(), []
    for module in plan.get("modules", []):
        functions = []
        for entry in (str(e).lower() for e in module.get("functions", [])):
            if entry in entries and entry not in skipped and entry not in seen:
                seen.add(entry)
                functions.append(entry)
        for chunk in range(0, len(functions), max_functions):
            modules.append({"title": module.get("title", "").strip()[:120] or "module",
                            "functions": functions[chunk:chunk + max_functions]})
    left = sorted((e for e in entries if e not in seen and e not in skipped), key=lambda e: int(e, 16))
    for chunk in range(0, len(left), max_functions):
        modules.append({"title": "functions the planner left unassigned", "functions": left[chunk:chunk + max_functions]})
    for number, module in enumerate(modules, 1):
        module["id"] = f"m{number:02d}"
    return modules, skipped


def contract_names(text):
    return {int(entry, 16): name for name, entry in PROTOTYPE.findall(text)}


# --- Building and checking -------------------------------------------------------------------------

class Build:
    def __init__(self, folder, cc=None, cflags=None, ldflags=("-lm",), language=languages.C):
        self.folder, self._cc = Path(folder).resolve(), cc
        self._cflags = tuple(cflags) if cflags is not None else None
        self.language, self.ldflags = language, tuple(ldflags)
        self.include_paths = {}
        self.checked_compiler = None
        (self.folder / "obj").mkdir(parents=True, exist_ok=True)

    @property
    def cc(self):
        return self._cc or self.language.cc()

    @property
    def cflags(self):
        return self._cflags if self._cflags is not None else (self.language.standard, *WARNINGS)

    @property
    def compiler_sha256(self):
        policy = [str(self.cc), [str(flag) for flag in self.cflags], self.language.name, "no-inline-asm-v2"]
        return hashlib.sha256(json.dumps(policy).encode()).hexdigest()

    def _run(self, argv, stage):
        env = {k: os.environ[k] for k in ("PATH", "SDKROOT", "DEVELOPER_DIR", "SystemRoot") if k in os.environ}
        env.update(HOME=str(stage), TMPDIR=str(stage), LC_ALL="C")
        process = None
        buffers = [bytearray(), bytearray()]
        overflow = threading.Event()
        capture_error = threading.Event()
        stopped = threading.Event()
        stop_lock = threading.Lock()
        def stop():
            with stop_lock:
                if stopped.is_set():
                    return
                stopped.set()
                try:
                    if os.name == "posix":
                        os.killpg(process.pid, signal.SIGKILL)
                    else:
                        process.kill()
                except ProcessLookupError:
                    pass
        def drain(pipe, buffer, limit):
            try:
                while chunk := os.read(pipe.fileno(), min(65536, limit + 1 - len(buffer))):
                    if len(buffer) + len(chunk) > limit:
                        overflow.set()
                        stop()
                        break
                    buffer.extend(chunk)
            except OSError:
                capture_error.set()
                stop()
            finally:
                pipe.close()
        try:
            process = subprocess.Popen(argv, cwd=stage, env=env, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       start_new_session=os.name == "posix")
            readers = [threading.Thread(target=drain, args=(pipe, buffer, limit), daemon=True)
                       for pipe, buffer, limit in zip((process.stdout, process.stderr), buffers,
                                                       (MAX_COMPILER_STDOUT, MAX_COMPILER_STDERR))]
            for reader in readers:
                reader.start()
            deadline = time.monotonic() + 60
            try:
                # Drain before reaping so a limiting reader still owns the process-group identity.
                for reader in readers:
                    reader.join(timeout=max(0, deadline - time.monotonic()))
                if any(reader.is_alive() for reader in readers):
                    raise subprocess.TimeoutExpired(argv, 60)
                code = process.wait(timeout=max(0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                stop()
                process.wait()
                return subprocess.CompletedProcess(argv, 124, "", "compiler timed out")
            finally:
                for reader in readers:
                    reader.join(timeout=1)
            if overflow.is_set():
                return subprocess.CompletedProcess(argv, 125, "", "compiler output limit exceeded")
            if capture_error.is_set():
                return subprocess.CompletedProcess(argv, 125, "", "compiler output could not be read")
            if any(reader.is_alive() for reader in readers):
                return subprocess.CompletedProcess(argv, 125, "", "compiler output streams did not close")
            return subprocess.CompletedProcess(argv, code, buffers[0].decode("utf-8", errors="replace"),
                                                buffers[1].decode("utf-8", errors="replace"))
        except OSError as error:
            return subprocess.CompletedProcess(argv, 127, "", f"compiler could not start: {type(error).__name__}")

    def _stage(self, unit, source, contract):
        stage = self.folder / "stage" / unit
        shutil.rmtree(stage, ignore_errors=True)
        stage.mkdir(parents=True)
        for path, name in ((contract, self.language.header), (source, self.language.source(unit))):
            if path is None:
                continue
            data, _ = intake.snapshot(path)
            text = data.decode("utf-8")
            # Reject location spoofing before inspecting the compiler's expanded source locations.
            logical = text.replace("??=", "#").replace("??/", "\\").replace("%:", "#")
            logical = re.sub(r"\\\r?\n|/\*.*?\*/", "", logical, flags=re.S)
            if re.search(r"(?m)^\s*#\s*(?:line\b|\d)", logical):
                raise HiveError("generated source may not override source locations")
            if FORBIDDEN.search(logical):
                raise HiveError("forbidden constructs in generated source or contract")
            (stage / name).write_bytes(data)
        if source is None:
            (stage / self.language.source(unit)).write_text(f'#include "{self.language.header}"\n')
        return stage

    def _closed(self, stage, unit):
        flags = [self.cc, *self.cflags, "--no-default-config", "-fno-modules",
                 "-fno-gnu-inline-asm", "-fno-asm-blocks"]
        key = (self.cc, self.cflags, self.language.name)
        if key not in self.include_paths:
            discovery = self._run([*flags, "-E", "-v", "-x", self.language.syntax_kind, "-"], stage)
            match = re.search(r"#include <\.\.\.> search starts here:(.*?)End of search list\.",
                              discovery.stderr, re.S)
            if discovery.returncode or not match:
                raise HiveError("a Clang compiler with a closed VFS is required")
            self.include_paths[key] = [line.strip().removesuffix(" (framework directory)")
                                       for line in match[1].splitlines() if line.strip()]
        roots = [{"type": "directory-remap", "name": str(path), "external-contents": str(path)}
                 for path in [stage, *self.include_paths[key]]]
        control = self.folder / "vfs" / f"{unit}.json"
        control.parent.mkdir(exist_ok=True)
        control.write_text(json.dumps({"version": 0, "case-sensitive": "true", "fallthrough": False, "roots": roots}))
        return [*flags, "-ivfsoverlay", str(control)]

    def ensure_confinement(self):
        if self.checked_compiler == self.compiler_sha256:
            return
        stage = self.folder / "stage" / "capability"
        stage.mkdir(parents=True, exist_ok=True)
        source = stage / self.language.source("capability")
        closed = self._closed(stage, "capability")
        outside = self.folder / "vfs" / "outside-capability.h"
        outside.write_text("#error outside capability marker\n")
        source.write_text('#include <stddef.h>\n#if __has_include(' + json.dumps(str(outside)) + ')\n'
                          '#error compiler VFS is not closed\n#endif\nint main(void) { return 0; }\n')
        positive = self._run([*closed, "-x", self.language.syntax_kind, "-c", source.name,
                              "-o", str(stage / "positive.o")], stage)
        if positive.returncode:
            raise HiveError("compiler confinement unavailable: " + positive.stderr[-1000:])
        source.write_text('#define J(a,b) a ## b\nJ(__as,m__)("nop");\n'
                          'int main(void) { J(__as,m__)("nop"); return 0; }\n')
        negative = self._run([*closed, "-x", self.language.syntax_kind, "-fsyntax-only", source.name], stage)
        if negative.returncode == 0 or negative.stderr.count("GNU-style inline assembly is disabled") != 2:
            raise HiveError("compiler does not refuse nonempty inline assembly")
        self.checked_compiler = self.compiler_sha256

    def _compile(self, stage, unit, *, syntax=False):
        closed = self._closed(stage, unit)
        expanded = self._run([*closed, "-E", "-x", self.language.syntax_kind, self.language.source(unit)], stage)
        if expanded.returncode:
            return expanded
        # Symbol labels in system declarations are not assembly statements; the compiler disables those.
        if EXPANDED_FORBIDDEN.search(expanded.stdout):
            return subprocess.CompletedProcess(closed, 1, "", "forbidden constructs after preprocessing")
        action = ["-fsyntax-only"] if syntax else ["-c", "-o", str(stage / "unit.o")]
        return self._run([*closed, "-x", self.language.syntax_kind, *action, self.language.source(unit)], stage)

    def syntax(self, header):
        try:
            stage = self._stage("syntax", None, header)
            done = self._compile(stage, "syntax", syntax=True)
            return done.returncode == 0, done.stderr[-4000:]
        except (intake.IntakeError, UnicodeError, HiveError) as error:
            return False, str(error)

    def compile(self, module_id, source, contract):
        """Compile one module from a clean stage holding only its source and the frozen contract."""
        obj = self.folder / "obj" / f"{module_id}.o"
        obj.unlink(missing_ok=True)
        try:
            stage = self._stage(module_id, source, contract)
            done = self._compile(stage, module_id)
            identity = {"source_sha256": sha256(stage / self.language.source(module_id)),
                        "contract_sha256": sha256(stage / self.language.header),
                        "compiler_sha256": self.compiler_sha256}
            if done.returncode == 0:
                (stage / "unit.o").replace(obj)
                identity["object_sha256"] = sha256(obj)
            return {"ok": done.returncode == 0, "errors": done.stderr[-4000:] if done.returncode else "",
                    "warnings": done.stderr[-4000:] if not done.returncode else "", "log": done.stderr[-4000:], **identity}
        except (intake.IntakeError, UnicodeError, HiveError) as error:
            return {"ok": False, "errors": str(error), "warnings": ""}

    def link(self, module_ids, name):
        output = self.folder / "bin" / name
        output.parent.mkdir(parents=True, exist_ok=True)
        temporary = output.with_name(output.name + ".link")
        output.unlink(missing_ok=True)
        temporary.unlink(missing_ok=True)
        objects = [str(self.folder / "obj" / f"{m}.o") for m in module_ids]
        done = self._run([self.cc, "--no-default-config", *objects, "-o", str(temporary), *self.ldflags], self.folder)
        if done.returncode == 0:
            temporary.replace(output)
        else:
            temporary.unlink(missing_ok=True)
        return {"ok": done.returncode == 0, "log": done.stderr[-8000:],
                "binary": str(output) if done.returncode == 0 else None}


def link_blame(log, owners, module_ids):
    """Map linker messages to the modules that must fix them."""
    blamed = {}
    for symbol in re.findall(r'"_?([A-Za-z_]\w*)", referenced from|undefined reference to `([A-Za-z_]\w*)\'', log):
        name = next(s for s in symbol if s)
        if name in owners:
            blamed.setdefault(owners[name], []).append(f"undefined symbol {name}: define it in this module")
    for name in re.findall(r"duplicate symbol '_?([A-Za-z_]\w*)'|multiple definition of `([A-Za-z_]\w*)'", log):
        name = next(s for s in name if s) if isinstance(name, tuple) else name
        for module in module_ids:
            if module != owners.get(name) and f"{module}.o" in log:
                blamed.setdefault(module, []).append(f"duplicate symbol {name}: only {owners.get(name, 'its owner')} may define it")
    for module in module_ids:
        if module not in blamed and re.search(rf"\b{module}\.o\b", log):
            blamed[module] = ["linker error mentioning this module; see the log"]
    return blamed


def run_cases(cases, binary, folder, timeout=20):
    """Run every case in a fresh folder; compare-ready results with the binary's path hidden."""
    results = {}
    for case in cases:
        work = Path(tempfile.mkdtemp(prefix=f"{case['id']}-", dir=folder))
        for item in case.get("files", []):
            target = (work / item["name"]).resolve()
            if work.resolve() not in target.parents:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            data = base64.b64decode(item["base64"]) if item.get("base64") else item.get("text", "").encode()
            target.write_bytes(data[:MAX_CASE_FILE])
        steps = []
        for step in case["steps"]:
            stdin = (work / step["stdin"]) if step.get("stdin") else None
            try:
                with (stdin.open("rb") if stdin and stdin.is_file() else open(os.devnull, "rb")) as handle:
                    done = subprocess.run([binary, *step["args"]], cwd=work, stdin=handle, capture_output=True,
                                          timeout=timeout, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
                steps.append({"code": done.returncode, "out": hashlib.sha256(done.stdout).hexdigest(),
                              "out_head": done.stdout[:200].decode("latin-1"),
                              "err": done.stderr.decode("latin-1").replace(str(binary), "PROG")[:2000]})
            except subprocess.TimeoutExpired:
                steps.append({"code": "timeout"})
        files = {str(p.relative_to(work)): sha256(p) for p in sorted(work.rglob("*")) if p.is_file()}
        results[case["id"]] = {"steps": steps, "files": files}
        shutil.rmtree(work, ignore_errors=True)
    return results


def compare(original, rebuilt):
    same, different = [], []
    for case_id, expected in original.items():
        (same if rebuilt.get(case_id) == expected else different).append(case_id)
    return same, different


# --- The hive --------------------------------------------------------------------------------------

class Queen:
    def __init__(self, *, engine, out, bees, slots=4, max_functions=12, compile_rounds=3, council_rounds=2,
                 lenses=len(LENSES), link_rounds=3, behaviour_rounds=2, run_original=False, cases=40,
                 max_bees=None, build=None, check=None, language="c", preflight=None, allow_packed=False,
                 refusal_limit=3, fuzz=0, planning=None, resume_refused=False, attempt_not_started=StartDenied,
                 model_check=selfhost.check_model, required_context=65536):
        self.engine, self.out, self.bees = engine, Path(out).resolve(), bees
        if any(type(value) is not int or value < 1 for value in (slots, max_functions, refusal_limit)):
            raise ValueError("slots, max_functions and refusal_limit must be positive integers")
        self.slots = threading.BoundedSemaphore(slots)
        self.workers = slots
        self.max_functions, self.compile_rounds, self.council_rounds = max_functions, compile_rounds, council_rounds
        self.lenses = LENSES[:max(1, min(lenses, len(LENSES)))]
        self.link_rounds, self.behaviour_rounds = link_rounds, behaviour_rounds
        self.run_original, self.case_target = run_original, cases
        self.requested_max_bees = max_bees
        self.max_bees = 400 if max_bees is None else max_bees
        if type(self.max_bees) is not int or self.max_bees < 0:
            raise ValueError("max_bees must be a nonnegative integer")
        self.fuzz = fuzz_module.count(fuzz)
        self.build = build or Build(self.out / "build")
        self.requested_language = language
        self.preflight, self.allow_packed, self.preflight_result = preflight, allow_packed, None
        self.lang = self.build.language
        self.check = check
        self.lock = threading.RLock()
        self.spent = {"bees": 0, "seconds": 0.0, "cost_usd": 0.0}
        self.events = []
        self.refusals, self.refusal_limit, self.stopped = [], refusal_limit, None
        self.statuses = {}
        self.planning = planning if planning is not None else planning_module
        self.resume_refused, self.attempt_not_started = resume_refused, attempt_not_started
        if type(required_context) is not int or required_context < 1:
            raise ValueError("required_context must be a positive integer")
        self.model_check, self.required_context, self.model_checks = model_check, required_context, []
        self.state, self.plan_bundle, self.forecast = None, None, None
        self.reserved = 0
        self._recovering, self._workspace_owned = set(), False

    # bookkeeping
    def log(self, message):
        line = f"[{time.strftime('%H:%M:%S')}] {message}"
        with self.lock:
            self.out.mkdir(parents=True, exist_ok=True)
            self.events.append(line)
            with (self.out / "hive.log").open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        print(line, flush=True)

    @staticmethod
    def _answer(answer):
        if not isinstance(answer, dict):
            answer = {"outcome": "failure", "error": "runner returned no result"}
        result = dict(answer)
        outcome = result.get("outcome")
        if outcome not in {"ok", "provider_refusal", "timeout", "rate_limit", "invalid_schema",
                           "context_limit", "failure", "not_started", "tool_schema_failure"}:
            outcome = "failure"
            result.update(error="runner did not return a contracted outcome", code="runner_protocol")
        ok = outcome == "ok" and result.get("ok") is True and isinstance(result.get("output"), dict)
        if outcome == "ok" and not ok:
            outcome = "invalid_schema"
        result.update(schema="hive.bee-result/1", outcome=outcome, ok=ok,
                      refused=outcome == "provider_refusal", output=result.get("output") if ok else None,
                      error=None if ok else str(result.get("error") or outcome)[:300],
                      seconds=result.get("seconds") or 0, code=result.get("code"),
                      provenance=dict(result.get("provenance") or {}))
        return result

    def _ensure_state(self):
        if self.state is not None:
            return
        self.state = RunState(self.out / ".hive")
        data = self.state.data
        self.spent, self.refusals = data["spent"], data["refusals"]
        self.stopped = data["stopped"]
        saved_limit = data["max_bees"]
        chosen = saved_limit if self.requested_max_bees is None else self.requested_max_bees
        if chosen < self.spent["bees"]:
            raise HiveError("resume_mismatch: --max-bees is below consumed attempts")
        self.max_bees = chosen
        if chosen != saved_limit:
            self.state.append("limit", {"max_bees": chosen})
            if chosen > saved_limit and self.stopped in ("budget_exhausted", "budget_insufficient"):
                self._stop(None)
        if self.stopped == "model_capability":
            # A corrected server configuration is verified again; consumed probes stay spent.
            self._stop(None)
        policy = self.bees.policy()
        if not isinstance(policy, dict) or "fallback" not in policy:
            raise HiveError("router policy lacks fallback consent")
        if data["activated"] and not policy["fallback"]:
            raise HiveError("resume_mismatch: active local routing needs explicit local configuration")
        if data["policy"] != policy:
            self.state.append("policy", policy)
        if self.resume_refused:
            if not policy["fallback"]:
                raise HiveError("--resume-refused needs explicit fallback consent")
            self._recovering = set(data["unresolved_refusals"])

    def _stop(self, reason):
        with self.lock:
            self.stopped = reason
            self.state.append("stop", {"reason": reason})

    def _activation_key(self, role, name):
        fallback = self.state.data["policy"]["fallback"]
        if fallback is None:
            return None
        scope = fallback["scope"]
        if scope == "run":
            return "run"
        if scope == "role" and role in fallback["roles"]:
            return "role:" + role
        if scope == "bee" and name in fallback["bees"]:
            return "bee:" + name
        return None

    def _baseline(self, folder):
        result = {}
        if folder.is_symlink():
            raise HiveError("linked bee folder")
        for path in sorted(folder.rglob("*")):
            if path.is_symlink():
                raise HiveError("linked bee input")
            if path.is_file() and not path.name.startswith(".answer-") and path.name != "status.json":
                result[str(path.relative_to(folder))] = intake.snapshot(path)[0]
        return result

    def _attempt(self, role, name, task, folder, baseline, logical_id, local, schema, recovery):
        descriptor = self.bees.describe(role, name, local=local)
        runner = self.bees.fallback(role, name) if local else self.bees.primary(role, name)
        if runner is None:
            return self._answer({"outcome": "not_started", "code": "no_local_consent"}), []
        hooks = AttemptHooks(self, logical_id, role, name, local, descriptor, recovery)
        hooks.descriptor = {**descriptor, "task_sha256": hashlib.sha256(task.encode()).hexdigest(),
                            "schema_sha256": digest(schema),
                            "baseline_sha256": digest({p: hashlib.sha256(b).hexdigest() for p, b in baseline.items()})}
        if descriptor.get("probe_required"):
            with self.lock:
                if self.max_bees - self.spent["bees"] - self.reserved < 2:
                    if self.max_bees - self.spent["bees"] < 2:
                        self._stop("budget_exhausted")
                    return self._answer({"outcome": "not_started", "code": "budget_exhausted"}), []
                hooks.leased = 2
                self.reserved += 2
        workspace = self.out / ".hive" / "attempts" / uuid.uuid4().hex / "work" / folder.relative_to(self.out)
        workspace.mkdir(parents=True)
        for relative, data in baseline.items():
            # Every attempt sees identical bytes; the source of truth stays outside its folder.
            write_file(workspace / relative, data, 0o644)
        try:
            answer = self._answer(runner(role, name, task, workspace, schema=schema, before_start=hooks))
        except (StartDenied, self.attempt_not_started) as error:
            answer = self._answer({"outcome": "not_started", "code": getattr(error, "code", str(error)),
                                   "error": "run stopped: " + str(getattr(error, "code", None) or error)})
        except Exception as error:
            answer = self._answer({"outcome": "failure", "error": f"runner failed: {type(error).__name__}"})
        finally:
            with self.lock:
                self.reserved -= hooks.leased
                hooks.leased = 0
        pending = [aid for aid in hooks.ids if self.state.data["attempts"][aid]["status"] == "started"]
        for aid in pending:
            # Missing completion hooks never turn unreported work into successful work.
            hooks.finished(aid, self._answer({"outcome": "failure", "code": "missing_completion"}))
            answer = self._answer({"outcome": "failure", "code": "missing_completion"})
        bee_ids = [aid for aid in hooks.ids if self.state.data["attempts"][aid]["kind"] == "bee"]
        aid = answer["provenance"].get("attempt_id")
        expected_ids = bee_ids or (hooks.ids if answer.get("code") == "network_isolation" else [])
        cached_isolation = (answer["outcome"] == "failure" and answer.get("code") == "network_isolation"
                            and not hooks.ids and aid is None and descriptor.get("probe_key") is not None
                            and descriptor.get("probe_required") is False)
        if (answer["outcome"] != "not_started" and not cached_isolation
                and (not expected_ids or aid != expected_ids[-1])):
            answer = self._answer({"outcome": "failure", "code": "unbound_result",
                                   "error": "runner result lacks its reserved bee attempt ID"})
        if bee_ids:
            aid = bee_ids[-1]
            record = self.state.data["attempts"][aid]
            answer["provenance"] = {**descriptor, **answer["provenance"], "attempt_id": aid,
                                    "context_id": record["context_id"]}
        if answer["ok"]:
            allowed = {"PLAN.md"} if role == "planner" else {"claims.json", "NOTES.md"}
            if role in ("worker", "repair"):
                allowed.update(relative for relative in baseline if re.fullmatch(r"m\d+\.(?:c|cpp)", relative))
                if re.fullmatch(r"m\d+", folder.name):
                    allowed.add(self.lang.source(folder.name))
            try:
                for relative, data in baseline.items():
                    if relative not in allowed and intake.snapshot(workspace / relative)[0] != data:
                        raise HiveError("bee changed protected input")
                produced = self._baseline(workspace)
                for relative in allowed & produced.keys():
                    write_file(folder / relative, produced[relative])
                if role in ("worker", "repair") and bee_ids:
                    for relative in allowed & produced.keys():
                        if re.fullmatch(r"m\d+\.(?:c|cpp)", relative) and (
                                role == "worker" or produced[relative] != baseline.get(relative)):
                            self.state.append("author", {"module": Path(relative).stem, "attempt_id": aid})
            except (OSError, HiveError, intake.IntakeError):
                answer = self._answer(dict(answer, ok=False, outcome="failure", code="unsafe_attempt_files",
                                           error="attempt files changed protected inputs or are unsafe"))
        return answer, hooks.ids

    def bee(self, role, name, task, folder, *, schema=None):
        if role not in bees_module.SCHEMAS or not re.fullmatch(r"[A-Za-z0-9_-]+", name):
            raise HiveError("invalid bee role/name")
        if role == "planner" and schema is None:
            task = "Use the legacy schema (modules/skipped without structured declarations). " + task
        folder = Path(folder).resolve()
        folder.relative_to(self.out)
        folder.mkdir(parents=True, exist_ok=True)
        with self.slots:
            with self.lock:
                self._ensure_state()
                baseline = self._baseline(folder)
                logical_id = digest({"run_id": self.state.data["run_id"], "role": role, "name": name,
                                     "plan": (self.state.data["plan"] or {}).get("plan_id")})
                key = self._activation_key(role, name)
                recovery = logical_id in self._recovering
                local = (key is not None and key in self.state.data["activated"]) or recovery
                previous_ids = [aid for aid, attempt in self.state.data["attempts"].items()
                                if attempt["logical_id"] == logical_id]
                if self.stopped and not (recovery and key is not None):
                    return self._answer({"outcome": "not_started", "code": self.stopped,
                                         "error": "run stopped: " + self.stopped})
            self.log(f"{name}: {role} started")
            answer, ids = self._attempt(role, name, task, folder, baseline, logical_id, local, schema, recovery)
            if answer["outcome"] == "provider_refusal" and not local and key is not None:
                alternative = self.bees.fallback(role, name)
                primary = self.bees.describe(role, name)
                other = self.bees.describe(role, name, local=True)
                same = all(primary.get(k) == other.get(k) for k in
                           ("client", "server_kind", "server", "server_id", "requested_model"))
                if alternative is not None and not same:
                    with self.lock:
                        self.state.append("activate", {"key": key})
                    answer, extra = self._attempt(role, name, task, folder, baseline, logical_id, True, schema, recovery)
                    ids.extend(extra)
            with self.lock:
                current = answer["provenance"].get("attempt_id")
                ids = list(dict.fromkeys(previous_ids + ids))
                answer["provenance"]["prior_attempt_ids"] = [aid for aid in ids if aid != current]
                self.state.append("logical", {"logical_id": logical_id, "role": role, "bee": name,
                                               "result": answer, "attempt_ids": ids})
                unresolved = self.state.data["unresolved_refusals"]
                if len(unresolved) >= self.refusal_limit and not self.stopped:
                    self._stop("refusal_limit")
                elif recovery and len(unresolved) < self.refusal_limit and self.stopped in ("refusal_limit", "planner_refused"):
                    self._stop(None)
            write_file(folder / f".answer-{name}.json", canonical(answer))
            label = "REFUSED by the model provider" if answer["refused"] else "done" if answer["ok"] else "FAILED"
            self.log(f"{name}: {label} ({answer['outcome']}): {answer.get('error') or ''}")
            return answer

    # phases
    def check_models(self, program_map=None):
        if self.model_check is None:
            return
        policy = self.bees.policy()
        targets = [(local, client, config) for local, configs in (
            (False, policy.get("primary", {})), (True, policy.get("fallback_targets", {})))
            for client, config in sorted(configs.items()) if config.get("server")]
        if not targets:
            return
        function = next((row for row in (program_map or {}).get("functions", [])
                         if type(row.get("entry")) is int and 0 <= row["entry"] < 2**64), None)
        mcp_probe = ({"file": self.engine.file, "entry": hex(function["entry"])}
                     if function is not None else None)
        # Each Codex capability process may need an isolation process first.
        costs = [1 + int(client == "codex" and not config.get("allow_network"))
                 for _, client, config in targets]
        self.check_budget(Q=sum(costs))
        for (local, client, config), cost in zip(targets, costs):
            name = "model-check-" + ("fallback-" if local else "primary-") + client
            target = SimpleNamespace(env=None, server=config["server"], model=config["requested_model"],
                                     origin="fallback" if local else "primary")
            if client == "codex":
                target.codex = config["executable"]
            descriptor = bees_module.provenance(target, "councillor", name)
            logical_id = digest({"run_id": self.state.data["run_id"], "check": name,
                                 "target": config, "required_context": self.required_context, "mcp_probe": mcp_probe})
            hooks = AttemptHooks(self, logical_id, "councillor", name, local, descriptor, bool(self._recovering))
            with self.slots:
                with self.lock:
                    hooks.leased = cost
                    self.reserved += cost
                try:
                    report = self.model_check(self.bees, client, local=local, before_start=hooks,
                                              required_context=self.required_context, mcp_probe=mcp_probe)
                except (StartDenied, self.attempt_not_started) as error:
                    raise StartDenied(getattr(error, "code", str(error))) from None
                finally:
                    with self.lock:
                        self.reserved -= hooks.leased
                        hooks.leased = 0
            self.model_checks.append(report)
            write_file(self.out / ".hive/model-checks.json", canonical(self.model_checks))
            failures = [f"{key}: {item['message']} {item.get('suggestion') or ''}".strip()
                        for key, item in report["checks"].items() if item["status"] != "ok"]
            if failures or not report["ok"]:
                self._stop("model_capability")
                raise HiveError(f"model capability check failed for {name}: " + "; ".join(failures))

    def plan(self, program_map):
        if self.planning is None:
            raise HiveError("planning backend is not integrated")
        saved = self.state.data["plan"]
        if saved:
            bundle = saved
            if read_json(self.out / "plan/manifest.json") != bundle:
                raise HiveError("resume_mismatch: frozen plan manifest changed")
            self._validate_bundle(bundle, program_map)
            frozen = self.out / "src" / self.lang.header
            if intake.snapshot(frozen)[1].sha256 != bundle["contract_sha256"]:
                raise HiveError("resume_mismatch: frozen contract changed")
            self.log(f"plan: reused frozen plan {bundle['plan_id'][:12]}; no planner started")
        else:
            partitioned = partition.partition(program_map)
            self.check_budget(P=len(partitioned["groups"]), Q=self._pending_probes([("planner", "planner-g0001")]))
            progress = self.state.data["planning_progress"]
            saved_progress = (read_json(self._bundle_path(progress["progress_path"]))
                              if progress is not None else None)
            try:
                bundle = self.planning.plan(program_map, partitioned, out=self.out, invoke=self.bee,
                                            language=self.lang.name, max_functions=self.max_functions,
                                            max_prompt_bytes=65536, interface_rounds=2,
                                            saved=saved_progress)
            except self.planning.PlanningError as error:
                progress = error.details.get("progress_path")
                if progress:
                    # The planning module owns interpretation and validation of its work files.
                    self.state.append("planning_progress", {"progress_path": str(progress)})
                if error.bee_result and error.bee_result["outcome"] == "provider_refusal":
                    raise ProviderRefused("the model provider refused the planner: "
                                          + (error.bee_result.get("error") or "")) from None
                if error.bee_result and error.bee_result["outcome"] == "tool_schema_failure":
                    raise HiveError("planning failed: " + error.bee_result["error"]) from None
                raise HiveError(f"planning failed ({error.code})") from None
            self._validate_bundle(bundle, program_map)
            contract = self._bundle_path(bundle["contract_path"])
            ok, errors = self.build.syntax(contract)
            if not ok:
                raise HiveError("contract does not compile: " + errors[-1000:])
            frozen = self.out / "src" / self.lang.header
            write_file(frozen, intake.snapshot(contract)[0], 0o444)
            self.state.append("plan", bundle)
            self.log(f"plan: {len(bundle['modules'])} modules, contract frozen (sha256 {sha256(frozen)[:12]})")
        self.plan_bundle = bundle
        return bundle["modules"], bundle["skipped"], frozen

    def _bundle_path(self, relative):
        if not isinstance(relative, str) or "\\" in relative:
            raise HiveError("resume_mismatch: invalid plan path")
        path = Path(relative)
        if path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] != "plan":
            raise HiveError("resume_mismatch: plan path escapes plan/")
        target = self.out / path
        if any(parent.is_symlink() for parent in [target, *target.parents] if parent != self.out.parent):
            raise HiveError("resume_mismatch: linked plan path")
        return target

    def _validate_bundle(self, bundle, program_map):
        try:
            self.planning.validate_bundle(bundle, program_map, out=self.out, language=self.lang.name,
                                           max_functions=self.max_functions)
            if (bundle["schema"] != "hive.plan/1" or bundle["input_sha256"] != program_map["input_sha256"]
                    or bundle["map_sha256"] != digest(program_map) or bundle["language"] != self.lang.name
                    or not re.fullmatch("[0-9a-f]{64}", bundle["plan_id"])):
                raise ValueError("plan binding")
            for path_key, hash_key in (("contract_path", "contract_sha256"), ("interfaces_path", "interfaces_sha256")):
                if intake.snapshot(self._bundle_path(bundle[path_key]))[1].sha256 != bundle[hash_key]:
                    raise ValueError("plan artifact hash")
            if read_json(self.out / "plan/manifest.json") != bundle:
                raise ValueError("manifest differs from bundle")
        except (ValueError, KeyError, OSError, intake.IntakeError) as error:
            raise HiveError(f"resume_mismatch: invalid plan ({error})") from None

    def _pending_probes(self, calls):
        keys = set()
        for role, name in calls:
            for local in (False, True):
                if local and self.bees.fallback(role, name) is None:
                    continue
                descriptor = self.bees.describe(role, name, local=local)
                if descriptor.get("probe_required"):
                    keys.add(descriptor["probe_key"])
        return len(keys)

    def check_budget(self, *, P=0, U=0, V=0, T=0, Q=0):
        self._ensure_state()
        minimum = P + U * (1 + len(self.lenses)) + V * len(self.lenses) + T + Q
        self.forecast = {"P": P, "U": U, "V": V, "T": T, "Q": Q, "remaining_min": minimum,
                         "spent": self.spent["bees"], "limit": self.max_bees,
                         "recommended_total": self.spent["bees"] + minimum + max(8, math.ceil(minimum * .25)),
                         "margin": "heuristic: max(8, ceil(25% of remaining_min)); not a completion guarantee"}
        self.log(f"budget forecast: {json.dumps(self.forecast, sort_keys=True)}")
        if self.max_bees - self.spent["bees"] < minimum:
            self._stop("budget_insufficient")
            raise StartDenied("budget_insufficient")
        if self.max_bees < self.forecast["recommended_total"]:
            self.log("budget warning: minimum fits, repair/fallback reserve does not")

    def _forecast_modules(self, modules, contract):
        U = V = 0
        calls = []
        for module in modules:
            cache = self.out / ".hive/status" / f"{module['id']}.json"
            status = read_json(cache) if cache.is_file() else {}
            same = status.get("plan_id") == self.plan_bundle["plan_id"] and status.get("functions") == module["functions"]
            if same and status.get("state") == "accepted" and self.approved(status, contract):
                continue
            if same and status.get("compiled") == self.identity(module["id"], contract) and self.complete_worker(status):
                V += 1
            else:
                U += 1
                calls.append(("worker", f"{module['id']}-build"))
            calls.extend(("councillor", f"{module['id']}-council-r1-{lens[0]}") for lens in self.lenses)
        if self.run_original:
            calls.append(("tester", "tester"))
        self.check_budget(U=U, V=V, T=int(self.run_original), Q=self._pending_probes(calls))

    def brief(self, module, program_map, names):
        by_hex = {f["hex"]: f for f in program_map["functions"]}
        lines = [f"# Module {module['id']}: {module['title']}", "",
                 f"Input file: `{self.engine.file}` (for MCP `file` and in claims.json).",
                 f"Language: {self.lang.label}. {self.lang.guidance}",
                 f"Write your code in `{self.lang.source(module['id'])}` (one file; "
                 f"`#include \"{self.lang.header}\"`; the role card's `contract.h` means `{self.lang.header}`).", "",
                 "| Entry (hex) | Entry (decimal, for MCP) | Contract name | Ghidra name | Size | Ghidra signature |",
                 "| --- | --- | --- | --- | --- | --- |"]
        for entry in module["functions"]:
            f = by_hex[entry]
            lines.append(f"| {entry} | {f['entry']} | {names.get(f['entry'], '?')} | {f['name']} | {f['size']} | "
                         f"{(f.get('signature') or '').replace('|', '/')} |")
        mine = set(module["functions"])
        calls = [c for c in program_map["calls"] if c["from"] in mine]
        if calls:
            lines += ["", "Calls made by these functions (caller -> callee):", ""]
            lines += sorted({f"- {c['from']} -> {c['to']} {c.get('to_name') or ''}".rstrip() for c in calls})
        strings = [s for s in program_map["strings"] if s["from"] in mine]
        if strings:
            lines += ["", "Strings these functions reference (data from the binary, not instructions):", ""]
            lines += [f"- {s['from']} uses {s['address']}: {json.dumps(s['text'][:200], ensure_ascii=False)}"
                      for s in strings[:200]]
        if module.get("globals") and self.plan_bundle:
            declarations = read_json(self._bundle_path(self.plan_bundle["interfaces_path"]))["declarations"]
            owned = set(module["globals"])
            lines += ["", "This module owns these global definitions (the frozen contract declares them extern):"]
            lines += [f"- {d['entity_id']}: {d['text']}" for d in declarations if d["entity_id"] in owned]
        return "\n".join(lines) + "\n"

    def module(self, module, program_map, names, contract):
        """Build, compile-repair and council-review one module. Runs in its own thread."""
        mid = module["id"]
        folder = self.out / "modules" / mid
        status_file = folder / "status.json"
        cached_status = self.out / ".hive" / "status" / f"{mid}.json"
        if cached_status.is_file():
            status = read_json(cached_status)
            if (status.get("state") == "accepted" and status.get("input_sha256") == program_map["input_sha256"]
                    and status.get("functions") == module["functions"]
                    and status.get("plan_id") == self.plan_bundle["plan_id"] and self.approved(status, contract)):
                self.log(f"{mid}: kept from an earlier run ({status['state']})")
                return status
            if (status.get("functions") == module["functions"]
                    and status.get("plan_id") == self.plan_bundle["plan_id"]
                    and status.get("compiled") == self.identity(mid, contract) and self.complete_worker(status)):
                self.review(status, folder, folder / self.lang.source(mid), contract)
                return self.finish(status_file, status)
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "BRIEF.md").write_text(self.brief(module, program_map, names), encoding="utf-8")
        local = folder / self.lang.header
        write_file(local, intake.snapshot(contract)[0], 0o444)
        source = folder / self.lang.source(mid)
        status = {"id": mid, "title": module["title"], "functions": module["functions"], "rounds": [],
                  "input_sha256": program_map["input_sha256"], "plan_id": self.plan_bundle["plan_id"]}
        answer = self.bee("worker", f"{mid}-build", f"Rebuild module {mid}. Read `BRIEF.md` first.", folder)
        if not answer.get("ok"):
            status["state"] = ("refused" if answer.get("refused") else "not started"
                               if answer.get("outcome") == "not_started" else "failed")
            status["errors"] = answer.get("error", "")[:2000]
            return self.finish(status_file, status)
        status["worker"] = answer.get("output")
        compiled = self.compile_loop(mid, folder, source, contract, status)
        if not compiled["ok"]:
            status["state"] = "failed"
            status["errors"] = compiled["errors"][-2000:]
            return self.finish(status_file, status)
        for round_number in range(1, self.council_rounds + 1):
            defects = self.review(status, folder, source, contract)
            if status["state"] in ("accepted", "incomplete", "unreviewed"):
                return self.finish(status_file, status)
            if round_number == self.council_rounds:
                break
            listing = "\n".join(f"- {d['function']}: {d['problem']} (evidence: {d['evidence']}; "
                                f"suggested fix: {d.get('fix', '-')})" for d in defects)
            self.repair(status, f"{mid}-repair-c{round_number}",
                     f"The independent council found these behavioural differences in `{source.name}`. Fix each one, "
                     f"or prove with the assembly or a finding ID that the original does the same:\n{listing}", folder)
            compiled = self.compile_loop(mid, folder, source, contract, status)
            if not compiled["ok"]:
                status["state"] = "failed"
                status["errors"] = compiled["errors"][-2000:]
                return self.finish(status_file, status)
        status["state"] = "disputed"
        return self.finish(status_file, status)

    def finish(self, status_file, status):
        if self.state:
            status["author_attempts"] = list(self.state.data["authors"].get(status["id"], []))
        data = json.dumps(status, indent=1, ensure_ascii=False).encode("utf-8")
        write_file(status_file, data)
        write_file(self.out / ".hive" / "status" / f"{status['id']}.json", data)
        self.log(f"{status['id']}: {status['state']}")
        return status

    def compile_loop(self, mid, folder, source, contract, status):
        for attempt in range(self.compile_rounds + 1):
            result = self.build.compile(mid, source, contract)
            status["compiled"] = {k: result[k] for k in COMPILED_IDENTITY if k in result}
            status.setdefault("compiles", []).append({"ok": result["ok"], "errors": result["errors"][-1000:]})
            if result["ok"] and not result["warnings"].strip():
                return result
            if attempt == self.compile_rounds:
                return result
            problem = result["errors"] if not result["ok"] else result["warnings"]
            self.repair(status, f"{mid}-repair-b{attempt + 1}",
                        f"`{source.name}` does not compile cleanly with `{self.build.cc} {' '.join(self.build.cflags)}`. "
                        "Fix exactly these "
                        f"messages without changing behaviour:\n```\n{problem[-4000:]}\n```", folder)
        return result

    def repair(self, status, name, task, folder):
        answer = self.bee("repair", name, task, folder)
        self.merge_worker(status, answer)
        return answer

    def merge_worker(self, status, answer, *, all_functions=None):
        report = answer.get("output") if answer.get("ok") else None
        previous = status.get("worker") or {}
        try:
            if not isinstance(report, dict) or report.get("status") not in ("done", "partial", "blocked"):
                raise ValueError
            expected = {int(entry, 16) for entry in status["functions"]}
            allowed = {int(entry, 16) for entry in all_functions} if all_functions is not None else expected
            def rows(data, permitted):
                result = {}
                for row in data:
                    entry = int(row["entry"], 0)
                    if entry not in permitted or entry in result or row.get("status") not in ("rebuilt", "stub", "skipped"):
                        raise ValueError
                    result[entry] = row
                return result
            updates = {entry: row for entry, row in rows(report["functions"], allowed).items() if entry in expected}
            merged = {} if set(updates) == expected else rows(previous.get("functions", []), expected)
            for entry, row in updates.items():
                merged[entry] = dict(merged.get(entry, {}), **row)
            status["worker"] = {**previous, **report, "functions": list(merged.values())}
        except (KeyError, TypeError, ValueError):
            status["worker"] = None

    def complete_worker(self, status):
        report = status.get("worker") or {}
        try:
            rows = report["functions"]
            expected = {int(entry, 16) for entry in status["functions"]}
            entries = [int(row["entry"], 0) for row in rows if row["status"] == "rebuilt"]
            return (report.get("status") == "done" and len(entries) == len(rows) == len(expected)
                    and set(entries) == expected)
        except (KeyError, TypeError, ValueError):
            return False

    def identity(self, mid, contract):
        try:
            source = self.out / "modules" / mid / self.lang.source(mid)
            return {"source_sha256": intake.snapshot(source)[1].sha256,
                    "contract_sha256": intake.snapshot(contract)[1].sha256,
                    "object_sha256": sha256(self.build.folder / "obj" / f"{mid}.o"),
                    "compiler_sha256": self.build.compiler_sha256}
        except (OSError, intake.IntakeError):
            return None

    def approved(self, status, contract):
        identity = self.identity(status["id"], contract)
        reviewed = status.get("reviewed")
        readers = status.get("reviewer_attempts", [])
        authors = set(self.state.data["authors"].get(status["id"], [])) if self.state else set()
        return bool(identity and status.get("compiled") == identity and self.complete_worker(status)
                    and reviewed == {k: identity[k] for k in ("source_sha256", "contract_sha256")}
                    and len(readers) == len(self.lenses) and not authors.intersection(readers)
                    and all(self.state.data["attempts"].get(aid, {}).get("status") == "finished" for aid in readers))

    def review(self, status, folder, source, contract):
        status.pop("reviewed", None)
        if not self.complete_worker(status):
            status["state"] = "incomplete"
            status["errors"] = "the builder did not report every assigned function rebuilt with status done"
            return []
        current = {"source_sha256": intake.snapshot(source)[1].sha256,
                   "contract_sha256": intake.snapshot(contract)[1].sha256}
        last = status["rounds"][-1] if status["rounds"] else None
        resume = last if last and not last["complete"] and last.get("reviewed") == current else None
        number = last["council"] if resume else len(status["rounds"]) + 1
        result = self.council(status["id"], folder, source, contract, number, previous=resume)
        if resume:
            status["rounds"][-1] = {"council": number, **result}
        else:
            status["rounds"].append({"council": number, **result})
        status["reviewed"] = result.get("reviewed")
        status["reviewer_attempts"] = [v["attempt_id"] for v in result["seats"].values() if v]
        status["state"] = ("incomplete" if not result["complete"] else "disputed" if result["defects"] else
                           "accepted" if self.approved(status, contract) else "unreviewed")
        return result["defects"]

    def council(self, mid, folder, source, contract, round_number, previous=None):
        unit = f"unit-{hashlib.sha256((mid + str(round_number)).encode()).hexdigest()[:6]}"
        source_bytes, source_ref = intake.snapshot(source)
        contract_bytes, contract_ref = intake.snapshot(contract)
        def review(lens):
            cached = (previous or {}).get("seats", {}).get(lens[0])
            if cached:
                return cached
            seat = self.out / "council" / f"{mid}-r{round_number}-{lens[0]}"
            shutil.rmtree(seat, ignore_errors=True)
            seat.mkdir(parents=True)
            (seat / f"{unit}{self.lang.extension}").write_bytes(source_bytes)
            (seat / self.lang.header).write_bytes(contract_bytes)
            shutil.copyfile(folder / "BRIEF.md", seat / "BRIEF.md")
            answer = self.bee("councillor", f"{mid}-council-r{round_number}-{lens[0]}",
                              f"Review `{unit}{self.lang.extension}` ({self.lang.label}) against the original "
                              "functions listed in `BRIEF.md`. "
                              f"Your lens: {lens[1]}.", seat)
            output = answer.get("output") if answer.get("ok") else None
            aid = answer.get("provenance", {}).get("attempt_id")
            authors = self.state.data["authors"].get(mid, [])
            if (isinstance(output, dict) and output.get("verdict") in ("accept", "refute") and aid
                    and aid not in authors and self.state.data["attempts"].get(aid, {}).get("role") == "councillor"):
                return {"output": output, "attempt_id": aid}
            return None
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(self.lenses)) as pool:
            verdicts = list(pool.map(review, self.lenses))
        defects = []
        for seat_result in verdicts:
            if seat_result is None:
                continue
            verdict = seat_result["output"]
            for defect in verdict.get("defects", []):
                if re.search(r"0x[0-9a-fA-F]+|(fi|ev)-[0-9a-f]{16}", defect.get("evidence", "")):
                    defects.append(defect)
        missing = sum(v is None for v in verdicts)
        if missing:
            self.log(f"{mid}: {missing} councillor(s) gave no verdict in round {round_number}")
        authors = self.state.data["authors"].get(mid, [])
        identities = []
        for aid in authors + [v["attempt_id"] for v in verdicts if v]:
            attempt = self.state.data["attempts"][aid]
            provenance = attempt.get("result", {}).get("provenance", {})
            identities.append(provenance.get("model_digest") or provenance.get("observed_model"))
        diversity = None if not identities or None in identities else len(set(identities)) > 1
        return {"complete": missing == 0, "missing": missing, "defects": defects,
                "seats": {lens[0]: verdict for lens, verdict in zip(self.lenses, verdicts)},
                "model_diversity": diversity,
                "reviewed": {"source_sha256": source_ref.sha256, "contract_sha256": contract_ref.sha256}}

    def integrate(self, modules, names, contract):
        owners = {}
        for module in modules:
            for entry in module["functions"]:
                if int(entry, 16) in names:
                    owners[names[int(entry, 16)]] = module["id"]
        result = {"ok": False, "log": "no module compiled"}
        for attempt in range(self.link_rounds + 1):
            built = [m["id"] for m in modules if (self.build.folder / "obj" / f"{m['id']}.o").is_file()]
            if not built:
                break
            result = self.build.link(built, self.engine.file)
            if result["ok"] or attempt == self.link_rounds:
                break
            blamed = link_blame(result["log"], owners, built)
            self.log(f"link round {attempt + 1}: errors in {', '.join(sorted(blamed)) or 'no module'}")
            if not blamed:
                break
            def repair(item):
                mid, problems = item
                folder = self.out / "modules" / mid
                status = self.statuses[mid]
                self.repair(status, f"{mid}-repair-l{attempt + 1}",
                         "Linking the whole program failed because of this module. Fix these problems:\n"
                         + "\n".join("- " + p for p in problems), folder)
                compiled = self.compile_loop(mid, folder, folder / self.lang.source(mid), contract, status)
                if compiled["ok"]:
                    self.review(status, folder, folder / self.lang.source(mid), contract)
                else:
                    status["state"], status["errors"] = "failed", compiled["errors"]
                self.finish(folder / "status.json", status)
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as pool:
                list(pool.map(repair, sorted(blamed.items())))
        self.log(f"link: {'ok' if result['ok'] else 'FAILED'}")
        return result

    def conformance(self, binary, modules, contract, *, link=None):
        link = link if link is not None else {"ok": True, "binary": binary}
        folder = self.out / "tests"
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "fuzz.json").unlink(missing_ok=True)
        shutil.copyfile(self.out / "survey" / "map.json", folder / "map.json")
        for module in modules:
            brief = self.out / "modules" / module["id"] / "BRIEF.md"
            if brief.is_file():
                shutil.copyfile(brief, folder / f"BRIEF-{module['id']}.md")
        answer = self.bee("tester", "tester", f"Write about {self.case_target} conformance cases for "
                          f"`{self.engine.file}`.", folder)
        if not answer.get("ok"):
            return {"ran": False, "reason": "the tester bee gave no cases"}
        cases = answer["output"]["cases"][:200]
        if len(cases) < MIN_CASES or any(not c.get("id") or not c.get("steps") for c in cases):
            return {"ran": False, "reason": f"behaviour proof requires at least {MIN_CASES} nonempty cases"}
        for case in cases:
            case["id"] = re.sub(r"[^A-Za-z0-9_.-]", "_", case["id"])[:64]
        if len({c["id"] for c in cases}) != len(cases):
            return {"ran": False, "reason": "case IDs must be unique after normalisation"}
        (folder / "cases.json").write_text(json.dumps(cases, indent=1, ensure_ascii=False))
        runs = folder / "runs"
        runs.mkdir(exist_ok=True)
        stage = folder / "original" / self.engine.file
        stage.parent.mkdir(parents=True, exist_ok=True)
        write_file(stage, intake.snapshot(self.engine.path)[0], 0o555)
        original = run_cases(cases, str(stage), runs)
        rebuilt_binary = binary
        for round_number in range(self.behaviour_rounds + 1):
            rebuilt = run_cases(cases, rebuilt_binary, runs)
            same, different = compare(original, rebuilt)
            self.log(f"conformance round {round_number}: {len(same)}/{len(cases)} identical")
            if not different or round_number == self.behaviour_rounds:
                break
            repaired = self.behaviour_fix(round_number + 1, cases, original, rebuilt, different, modules, contract)
            link.clear()
            link.update(repaired)
            if not link["ok"]:
                return {"ran": False, "reason": "the current objects failed to relink after a behaviour fix"}
            rebuilt_binary = link["binary"]
        (folder / "results.json").write_text(json.dumps({"original": original, "rebuilt": rebuilt}, indent=1))
        expected = {c["id"] for c in cases}
        complete = set(original) == set(rebuilt) == expected and all(
            len(results[c["id"]].get("steps", [])) == len(c["steps"])
            and all(type(step.get("code")) is int for step in results[c["id"]]["steps"])
            for results in (original, rebuilt) for c in cases if c["id"] in results)
        if not complete:
            return {"ran": False, "reason": "conformance execution is incomplete or timed out"}
        result = {"ran": True, "cases": len(cases), "identical": len(same), "different": different}
        if self.fuzz and self.run_original:
            seed = sha256(stage)
            mutants = fuzz_module.generate(cases, seed, self.fuzz, MAX_CASE_FILE)
            fuzz_original = run_cases(mutants, str(stage), runs) if mutants else {}
            fuzz_rebuilt = run_cases(mutants, rebuilt_binary, runs) if mutants else {}
            summary = fuzz_module.summarise(mutants, fuzz_original, fuzz_rebuilt, seed, compare)
            fuzz_module.write_report(folder / "fuzz.json", summary, mutants)
            result["plain"] = dict(result, different=list(result["different"]))
            result["fuzz"] = summary
            result["completed"] = result["cases"] + summary["completed"]
            result["cases"] += summary["cases"]
            result["identical"] += summary["identical"]
            result["different"] = result["different"] + summary["different"]
            result["incomplete"] = list(summary["incomplete"])
            if summary["incomplete"]:
                reason = summary["reason"]
                if result["different"]:
                    reason += (f"; {len(result['different'])} conformance case(s) differ: "
                               + ", ".join(result["different"]))
                result.update(ran=False, reason=reason)
            self.log(f"fuzz: {summary['identical']}/{summary['completed']} completed cases identical; "
                     f"{len(summary['incomplete'])} incomplete")
        return result

    def behaviour_fix(self, round_number, cases, original, rebuilt, different, modules, contract):
        folder = self.out / "fixes" / f"b{round_number}"
        folder.mkdir(parents=True, exist_ok=True)
        for module in modules:
            source = self.out / "modules" / module["id"] / self.lang.source(module["id"])
            if source.is_file():
                shutil.copyfile(source, folder / source.name)
        write_file(folder / self.lang.header, intake.snapshot(contract)[0], 0o444)
        by_id = {c["id"]: c for c in cases}
        lines = []
        for case_id in different[:25]:
            lines.append(f"## {case_id}\ncase: {json.dumps(by_id[case_id], ensure_ascii=False)[:1500]}\n"
                         f"original: {json.dumps(original[case_id], ensure_ascii=False)[:1500]}\n"
                         f"rebuild:  {json.dumps(rebuilt[case_id], ensure_ascii=False)[:1500]}\n")
        (folder / "FAILURES.md").write_text("\n".join(lines), encoding="utf-8")
        before = {p.name: sha256(p) for p in folder.glob(f"m*{self.lang.extension}")}
        answer = self.bee("repair", f"behaviour-fix-{round_number}",
                 "The rebuilt program behaves differently from the original in the cases listed in `FAILURES.md` "
                 "(stdout is compared by hash, with its first bytes shown). The module sources are in this "
                 "folder. Find the cause with the MCP tools and fix the modules; change nothing else.", folder)
        changed = [p for p in folder.glob(f"m*{self.lang.extension}") if before.get(p.name) != sha256(p)]
        for path in changed:
            mid = path.stem
            if mid not in self.statuses:
                continue
            status = self.statuses[mid]
            self.merge_worker(status, answer, all_functions=[entry for module in modules for entry in module["functions"]])
            compiled = self.build.compile(mid, path, contract)
            status["compiled"] = {k: compiled[k] for k in COMPILED_IDENTITY if k in compiled}
            module_folder = self.out / "modules" / mid
            if compiled["ok"]:
                write_file(module_folder / path.name,
                           (self.build.folder / "stage" / mid / path.name).read_bytes())
                self.review(status, module_folder, module_folder / path.name, contract)
            else:
                status["state"], status["errors"] = "failed", compiled["errors"]
            self.finish(module_folder / "status.json", status)
        self.log(f"behaviour fix {round_number}: {len(changed)} module(s) changed")
        result = self.build.link([m["id"] for m in modules if (self.out / "build" / "obj" / f"{m['id']}.o").is_file()],
                                 self.engine.file)
        return result

    def claims(self, modules):
        merged = []
        for module in modules:
            path = self.out / "modules" / module["id"] / "claims.json"
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            for claim in data.get("claims", []) if isinstance(data, dict) else []:
                if isinstance(claim, dict):
                    claim = dict(claim, id=f"{module['id']}.{claim.get('id', '')}"[:128])
                    for citation in claim.get("citations", []):
                        citation["file"] = self.engine.file
                        if isinstance(citation.get("args"), dict):
                            citation["args"].pop("file", None)
                    merged.append(claim)
        path = self.out / "check" / "claims.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"file": self.engine.file, "claims": merged}, indent=1, ensure_ascii=False))
        return path, len(merged)

    def run(self):
        self.out.mkdir(parents=True, exist_ok=True)
        with workspace_lock(self.out / ".hive"):
            legacy = not (self.out / ".hive/run.json").exists() and any(
                (self.out / p).exists() for p in ("result.json", "survey/map.json", "plan/manifest.json"))
            if legacy:
                raise HiveError("resume_mismatch: legacy workspace lacks authoritative run state; use a new --out")
            self.state, self.plan_bundle, self.forecast = None, None, None
            self._recovering = set()
            self.statuses = {}
            self.model_checks = []
            try:
                return self._run()
            except StartDenied as error:
                return self._stopped_result(error.code)
            except HiveError as error:
                # Never leave a prior accepted result visible after a binding or infrastructure error.
                if not isinstance(error, ProviderRefused):
                    self._stopped_result(str(error))
                raise
            except (OSError, ValueError, KeyError, TypeError, intake.IntakeError) as error:
                self._stopped_result("invalid or unreadable run artifact")
                raise HiveError(f"resume_mismatch: invalid run artifact ({type(error).__name__})") from None

    def _bind(self, program_map):
        self._ensure_state()
        chosen, _ = languages.choose(self.requested_language, program_map)
        binding = {"input_sha256": program_map["input_sha256"], "map_sha256": digest(program_map),
                   "input_snapshot_sha256": intake.snapshot(self.engine.path)[1].sha256,
                   "language": chosen.name, "max_functions": self.max_functions,
                   "planner_role_sha256": sha256(bees_module.ROLES / "planner.md")}
        old = self.state.data["binding"]
        if old is not None and old != binding:
            raise HiveError("resume_mismatch: input, map, language or planning policy changed")
        if old is None:
            self.state.append("binding", binding)
        self.program_map = program_map
        if self.stopped and not self._recovering:
            raise StartDenied(self.stopped)

    def _stopped_result(self, reason):
        program_map = getattr(self, "program_map", {})
        modules = (self.state.data["plan"] or {}).get("modules", []) if self.state else []
        states = {}
        for module in modules:
            cache = self.out / ".hive/status" / f"{module['id']}.json"
            try:
                states[module["id"]] = read_json(cache).get("state", "not started") if cache.is_file() else "not started"
            except (OSError, ValueError, intake.IntakeError):
                states[module["id"]] = "unverified"
        result = {"file": self.engine.file, "input_sha256": program_map.get("input_sha256", "unknown"),
                  "functions": len(program_map.get("functions", [])), "skipped": 0, "modules": states,
                  "link": False, "binary": None, "check": None, "claims": 0, "preflight": self.preflight_result,
                  "conformance": {"ran": False, "reason": "the run stopped"},
                  "verdict": "not accepted" if modules else "not started", "reason": "run stopped: " + reason,
                  "stop_reason": reason, "refusals": list(self.refusals), "spent": dict(self.spent),
                  "unresolved_refusals": list(self.state.data["unresolved_refusals"].values()) if self.state else [],
                  "attempts": list(self.state.data["attempts"].values()) if self.state else [],
                  "forecast": self.forecast, "model_checks": self.model_checks}
        write_file(self.out / "result.json", canonical(result))
        write_file(self.out / "REPORT.md", render(result).encode())
        self.log(result["reason"])
        return result

    def _run(self):
        self.out.mkdir(parents=True, exist_ok=True)
        started = time.monotonic()
        self.log(f"hive started on {self.engine.file}: {self.workers} bees at a time, councils of {len(self.lenses)}")
        map_file = self.out / "survey" / "map.json"
        program_map = (read_json(map_file) if map_file.is_file()
                       else survey(self.engine, self.out / "survey", self.log))
        self._bind(program_map)
        if self.preflight:
            self.preflight_result = self.preflight(self.engine, program_map, self.out / "survey" / "preflight")
            verdict = self.preflight_result["verdict"]
            self.log(f"pre-flight: {verdict}" + "".join(f"; {s['detail']}" for s in self.preflight_result["signals"]))
            if verdict == "packed" and not self.allow_packed:
                return self.stop_packed(program_map, started)
        self.lang, reasons = languages.choose(self.requested_language, program_map)
        self.build.language = self.lang
        self.language_reasons = reasons
        self.log(f"language: {self.lang.label} ({'; '.join(reasons)})")
        self.build.ensure_confinement()
        self.check_models(program_map)
        try:
            modules, skipped, contract = self.plan(program_map)
        except ProviderRefused as error:
            if not self.stopped:
                self._stop("planner_refused")
            self.stop_refused(program_map, started, error)
            raise
        self._forecast_modules(modules, contract)
        names = contract_names(contract.read_text(encoding="utf-8"))
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as pool:
            statuses = list(pool.map(lambda m: self.module(m, program_map, names, contract), modules))
        self.statuses = {s["id"]: s for s in statuses}
        link = self.integrate(modules, names, contract)
        conformance = {"ran": False, "reason": "not allowed: start with --run-original to run the original"}
        if self.run_original and link["ok"]:
            conformance = self.conformance(link["binary"], modules, contract, link=link)
        claims_path, claim_count = self.claims(modules)
        check = None
        if self.check and claim_count:
            shutil.rmtree(self.out / "check" / "result", ignore_errors=True)
            summary, _ = self.check(claims_path, self.out / "check" / "result")
            check = summary
            self.log(f"checker: {summary['confirmed']}/{summary['claims']} claims confirmed")
        for status in statuses:
            if status["state"] == "accepted" and not self.approved(status, contract):
                status["state"] = "unreviewed"
                self.finish(self.out / "modules" / status["id"] / "status.json", status)
        result = self.verdict(program_map, modules, skipped, statuses, link, check, claim_count, conformance)
        result["seconds"] = round(time.monotonic() - started)
        result["spent"] = self.spent
        result["forecast"] = self.forecast
        result["model_checks"] = self.model_checks
        (self.out / "result.json").write_text(json.dumps(result, indent=1, ensure_ascii=False))
        (self.out / "REPORT.md").write_text(render(result), encoding="utf-8")
        self.log(f"verdict: {result['verdict']} — {result['reason']}")
        return result

    def stop_packed(self, program_map, started):
        pre = self.preflight_result
        result = {"file": self.engine.file, "input_sha256": program_map["input_sha256"],
                  "functions": len(program_map["functions"]), "skipped": 0, "modules": {}, "link": False,
                  "binary": None, "check": None, "claims": 0, "preflight": pre,
                  "conformance": {"ran": False, "reason": "the run stopped at the pre-flight"},
                  "verdict": "not started",
                  "reason": "the pre-flight found a packed program (" + (", ".join(pre["packers"]) or "high entropy")
                            + "); " + pre["advice"] + " Start with --allow-packed to try anyway",
                  "seconds": round(time.monotonic() - started), "spent": self.spent}
        (self.out / "result.json").write_text(json.dumps(result, indent=1, ensure_ascii=False))
        (self.out / "REPORT.md").write_text(render(result), encoding="utf-8")
        self.log(f"verdict: {result['verdict']} — {result['reason']}")
        return result

    def stop_refused(self, program_map, started, error):
        """Write the verdict of a run the provider stopped at the planner, replacing any earlier verdict."""
        result = {"file": self.engine.file, "input_sha256": program_map["input_sha256"],
                  "language": self.lang.label, "language_reasons": getattr(self, "language_reasons", []),
                  "functions": len(program_map["functions"]), "skipped": 0, "modules": {}, "link": False,
                  "binary": None, "check": None, "claims": 0, "preflight": self.preflight_result,
                  "conformance": {"ran": False, "reason": "the run stopped at the planner"},
                  "refusals": list(self.refusals), "verdict": "not started", "reason": str(error),
                  "unresolved_refusals": list(self.state.data["unresolved_refusals"].values()),
                  "attempts": list(self.state.data["attempts"].values()),
                  "seconds": round(time.monotonic() - started), "spent": self.spent}
        (self.out / "result.json").write_text(json.dumps(result, indent=1, ensure_ascii=False))
        (self.out / "REPORT.md").write_text(render(result), encoding="utf-8")
        self.log(f"verdict: {result['verdict']} — {result['reason']}")
        return result

    def verdict(self, program_map, modules, skipped, statuses, link, check, claim_count, conformance):
        states = {s["id"]: s["state"] for s in statuses}
        stubs = sum(1 for s in statuses for f in (s.get("worker") or {}).get("functions", []) if f.get("status") != "rebuilt")
        reasons = []
        if not link["ok"]:
            reasons.append("the program does not link")
        bad = sorted(m for m, state in states.items() if state != "accepted")
        if bad:
            reasons.append(f"modules not accepted by the council: {', '.join(bad)}")
        if stubs:
            reasons.append(f"{stubs} function(s) reported as stub or skipped by their builder")
        incomplete = sorted(s["id"] for s in statuses if not self.complete_worker(s))
        if incomplete:
            reasons.append("incomplete builder reports: " + ", ".join(incomplete))
        if check is None:
            reasons.append("no claim was checked" if claim_count == 0 else "claims were not checked")
        elif check["rejected"]:
            reasons.append(f"{check['rejected']} claim(s) rejected by the evidence checker")
        if check is not None and check.get("input_sha256") != [program_map["input_sha256"]]:
            reasons.append("the evidence checker did not bind every question to the target input hash")
        if self.run_original and not conformance.get("ran"):
            reasons.append("behaviour proof incomplete: " + conformance.get("reason", "no results"))
        if conformance.get("ran") and (conformance.get("cases", 0) < MIN_CASES
                                       or conformance.get("identical", 0) != conformance.get("cases")):
            reasons.append("behaviour proof has too few or incomplete cases")
        if conformance.get("ran") and conformance["different"]:
            reasons.append(f"{len(conformance['different'])} conformance case(s) differ")
        unresolved = list(self.state.data["unresolved_refusals"].values()) if self.state else []
        if unresolved:
            roles = sorted({r["role"] for r in unresolved})
            reasons.append(f"the model provider refused {len(unresolved)} bee(s) ({', '.join(roles)}); unresolved")
        if self.stopped:
            reasons.append("stopped early: " + self.stopped)
        return {
            "refusals": list(self.refusals),
            "unresolved_refusals": unresolved,
            "attempts": list(self.state.data["attempts"].values()) if self.state else [],
            "model_diversity": {s["id"]: s["rounds"][-1].get("model_diversity") if s.get("rounds") else None
                                for s in statuses},
            "file": self.engine.file, "input_sha256": program_map["input_sha256"],
            "language": self.lang.label, "language_reasons": getattr(self, "language_reasons", []),
            "preflight": self.preflight_result,
            "functions": len(program_map["functions"]), "skipped": len(skipped), "modules": states,
            "link": link["ok"], "binary": link.get("binary") if link["ok"] else None,
            "check": check, "claims": claim_count, "conformance": conformance,
            "verdict": "accepted" if not reasons and conformance.get("ran") else
                       "accepted without behaviour proof" if not reasons else "not accepted",
            "reason": "; ".join(reasons) or ("every check passed" if conformance.get("ran") else
                                             "every static check passed; behaviour was not run"),
        }


def render(result):
    lines = [f"# Hive report: {result['file']}", "", f"**Verdict: {result['verdict']}.** {result['reason']}.", "",
             f"- Input SHA-256: `{result['input_sha256']}`",
             (f"- Language: {result['language']} ({'; '.join(result.get('language_reasons', []))})"
              if result.get("language") else "- Language: not chosen"),
             "- Pre-flight: " + (f"{result['preflight']['verdict']}" + "".join(
                 f"; {s['detail']}" for s in result["preflight"]["signals"]) if result.get("preflight") else "not run"),
             f"- Functions: {result['functions']} ({result['skipped']} skipped as library or runtime code)",
             f"- Modules: {len(result['modules'])}; accepted "
             f"{sum(s == 'accepted' for s in result['modules'].values())}",
             f"- Link: {'ok' if result['link'] else 'failed'}"]
    check = result["check"]
    lines.append(f"- Evidence checker: {check['confirmed']}/{check['claims']} claims confirmed" if check
                 else f"- Evidence checker: not run ({result['claims']} claims)")
    conformance = result["conformance"]
    proof = (f"{conformance['identical']}/{conformance['cases']} cases identical" if conformance.get("ran")
             else f"not run ({conformance.get('reason')})")
    if not conformance.get("ran") and "plain" in conformance:
        plain, extra = conformance["plain"], conformance["fuzz"]
        proof = (f"{plain['identical']}/{plain['cases']} plain cases identical; "
                 f"{extra['identical']}/{extra['completed']} completed fuzz cases identical; "
                 f"{len(extra['incomplete'])} incomplete")
    if "fuzz" in conformance:
        proof += f" ({conformance['fuzz']['cases']} fuzz)"
    lines.append("- Conformance: " + proof)
    spent = result.get("spent", {})
    if result.get("refusals"):
        lines.append(f"- Provider refusals: {len(result['refusals'])} (" + ", ".join(
            sorted({r['bee'] for r in result['refusals']})) + ")")
    if "unresolved_refusals" in result:
        lines.append(f"- Unresolved provider refusals: {len(result['unresolved_refusals'])}")
    if result.get("forecast"):
        forecast = result["forecast"]
        lines.append(f"- Budget forecast at phase start: minimum {forecast['remaining_min']}; recommended total "
                     f"{forecast['recommended_total']}; cap {forecast['limit']} (heuristic margin)")
    if result.get("attempts"):
        for attempt in result["attempts"]:
            answer = attempt.get("result", {})
            if answer.get("outcome") == "tool_schema_failure" or answer.get("probe_outcome") == "tool_schema_failure":
                lines.append(f"- {attempt['bee']}: stopped after {answer.get('consecutive_tool_rejections')} "
                             f"consecutive MCP argument/schema rejections; tool "
                             f"{answer.get('tool_name') or 'unknown'}; total observed {answer.get('tool_rejections')}.")
        unavailable = [attempt["bee"] for attempt in result["attempts"]
                       if attempt.get("result", {}).get("tool_rejections") is None]
        if unavailable:
            lines.append("- MCP rejection monitor unavailable (CLI exposes no tool results): " + ", ".join(unavailable))
        lines += ["", "| Attempt | Bee / role | Kind | Outcome | Client / target | Model |",
                  "| --- | --- | --- | --- | --- | --- |"]
        def cell(value):
            return str(value or "unknown").replace("|", "\\|").replace("\n", " ")[:160]
        for attempt in result["attempts"]:
            answer = attempt.get("result", {})
            provenance = answer.get("provenance", {})
            model = provenance.get("observed_model") or attempt.get("requested_model")
            lines.append("| " + " | ".join(cell(v) for v in (
                attempt["attempt_id"], attempt["bee"] + " / " + attempt["role"], attempt["kind"],
                answer.get("outcome", attempt["status"]),
                (attempt.get("client") or "unknown") + " / " + (attempt.get("server_kind") or "unknown"), model)) + " |")
    lines += [f"- Bees: {spent.get('bees', 0)}, agent time {round(spent.get('seconds', 0) / 60)} min, "
              f"wall time {round(result.get('seconds', 0) / 60)} min", "", "| Module | State |", "| --- | --- |"]
    lines += [f"| {m} | {s} |" for m, s in sorted(result["modules"].items())]
    lines += ["", "The verdict is computed by code from the checks above. Rebuilt code is derived from Ghidra's",
              "interpretation and the agents' reading of the assembly; it is not the original source."]
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m hive", description="Run the ReverseAI analyst team")
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="Analyse and rebuild one approved native program")
    run.add_argument("--inputs", required=True, type=Path, help="Directory of approved inputs")
    run.add_argument("--file", required=True, help="Program name inside --inputs")
    run.add_argument("--out", required=True, type=Path, help="Workspace folder (new, or an earlier run to resume)")
    run.add_argument("--bees", type=int, default=4, help="Bees working at the same time (default 4)")
    run.add_argument("--max-bees", type=int, default=None,
                     help="Agent CLI starts including probes and fallback (new run: 400; resume: saved cap)")
    run.add_argument("--resume-refused", action="store_true",
                     help="Recover unresolved refused calls through explicitly configured local fallback")
    run.add_argument("--max-functions", type=int, default=12, help="Functions per module (default 12)")
    run.add_argument("--council", type=int, default=3, choices=(1, 2, 3), help="Councillors per module (default 3)")
    run.add_argument("--model", help="Model for every bee (default: the agent CLI's default)")
    run.add_argument("--required-context", type=int, default=65536,
                     help="Minimum active context for mandatory self-hosted model checks (default 65536)")
    run.add_argument("--max-tool-rejections", type=int, default=8,
                     help="Stop a bee after this many consecutive MCP schema rejections (default 8)")
    run.add_argument("--claude", default="claude", help="Claude Code executable")
    run.add_argument("--check-jobs", type=int, default=2, help="Questions the evidence checker runs at once")
    run.add_argument("--run-original", action="store_true",
                     help="Allow running the original program on the conformance cases (benign software only)")
    run.add_argument("--cases", type=int, default=40, help="Conformance cases to ask for (default 40)")
    run.add_argument("--fuzz", type=fuzz_module.count, default=0,
                     help="Extra file-mutating conformance cases after behaviour repairs "
                          "(0-500, default 0; needs --run-original)")
    run.add_argument("--language", choices=("auto", "c", "cpp"), default="auto",
                     help="Language to rebuild in (default: detected from the program)")
    run.add_argument("--allow-packed", action="store_true",
                     help="Continue even when the pre-flight finds a packed program")
    codex_bees.add_arguments(run)
    args = parser.parse_args(argv)
    if not args.inputs.is_dir() or not (args.inputs / args.file).is_file():
        parser.error("--file must name a regular file inside --inputs")
    if args.required_context < 1:
        parser.error("--required-context must be a positive integer")
    if args.max_tool_rejections < 1:
        parser.error("--max-tool-rejections must be a positive integer")
    sys.path.insert(0, str(ROOT))
    from tools import hive_check
    inputs = args.inputs.resolve()
    engine = Engine(root=ROOT, inputs=inputs, file=args.file)
    config_dir = args.out.resolve() / ".hive" / "mcp"
    claude = bees_module.ClaudeBees(engine=ROOT, inputs=inputs, claude=args.claude, model=args.model,
                                    config_dir=config_dir, max_tool_rejections=args.max_tool_rejections)
    bees = codex_bees.build_router(args, claude, engine=ROOT, inputs=inputs, config_dir=config_dir.parent / "codex",
                                   max_tool_rejections=args.max_tool_rejections)
    policy = bees.policy()
    for destination in ("primary", "fallback_targets"):
        for client, config in policy[destination].items():
            if not bees_module.environment_ok(config["executable"]):
                parser.error(f"cannot find the configured {destination} {client} CLI: {config['executable']}")
    def check(claims, out):
        return hive_check.check(inputs, claims, out, enabled=frozenset({"ghidra"}), jobs=args.check_jobs)
    queen = Queen(engine=engine, out=args.out, bees=bees, slots=args.bees, max_functions=args.max_functions,
                  lenses=args.council, run_original=args.run_original, cases=args.cases, max_bees=args.max_bees,
                  check=check, language=args.language, preflight=preflight.run, allow_packed=args.allow_packed,
                  fuzz=args.fuzz, planning=planning_module, resume_refused=args.resume_refused,
                  attempt_not_started=bees_module.AttemptNotStarted,
                  model_check=selfhost.check_model, required_context=args.required_context)
    try:
        result = queen.run()
    except HiveError as error:
        print(f"hive: {error}", file=sys.stderr)
        return 2
    return 0 if result["verdict"].startswith("accepted") else 1
