"""Explicit offline R1 proof; unittest discovery never runs Docker.

python3 -B tests/verify_r1_runtime.py --offline --route B --lock NEW_LOCK --receipt NEW_RECEIPT
python3 -B tests/verify_r1_runtime.py --offline --smoke --lock EXISTING_R7_LOCK --receipt NEW_RECEIPT
The reviewed revision builder writes a new lock. Existing committed locks are never overwritten.
Every failed, missing, timed out or capped proof makes this command fail.
"""

from __future__ import annotations

import argparse
from collections import Counter
from contextlib import ExitStack, contextmanager, redirect_stderr, redirect_stdout
import importlib
import io
import math
import os
from pathlib import Path
import re
import selectors
import subprocess
import threading
import sys
import tarfile
import tempfile
import time
from types import MappingProxyType
from unittest.mock import patch

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from reverseai.contract import canonical_json, sha256_hex
from tests import verify_m2_runtime as old
from tests.fixtures_scale import elf_scale

ROOT = Path(__file__).resolve().parents[1]
PREPARE_SECONDS, PREPARE_BYTES = 900, 64 * 1024**2
MAX_DOCKER_STDERR_BYTES = 4096
PROGRAM_ARGS = {"part": "functions", "start": 0, "limit": 128}
RESTORE_CASES = ("traversal", "absolute", "symlink", "duplicate", "checksum", "truncated", "trailer", "base256")
REQUIRED_CHECKS = ("revision", *old.GHIDRA_REQUIRED_CHECKS,
                   *("prepare." + name for name in old.CONTROL_NAMES), "cache.write_refused",
                   "restore.valid", *("restore." + name for name in RESTORE_CASES),
                   *(name + ".cached_equal" for name in old.GHIDRA_FIXTURE_NAMES),
                   "function.parts", "function.pseudocode", "function.not_found",
                   "program.no_jvm", "scale.10000", "sources", "cleanup")
SOURCE_FILES = ("tests/verify_r1_runtime.py", "tests/verify_m2_runtime.py", "tests/fixtures_scale.py",
                "tests/fixtures_code.py", "tools/build_ghidra_image.py", "reverseai/contained.py",
                "reverseai/ghidra_cache.py", "reverseai/ghidra_args.py", "reverseai/cli.py",
                "reverseai/tools/ghidra_tool.py", "reverseai/tools/ghidra_verify.py",
                "reverseai/tools/ghidra_export.py", "reverseai/export_claims.py", "reverseai/queries.py",
                "reverseai/analysts/code.py", "reverseai/analysts/query.py", "reverseai/pipeline.py",
                "reverseai/report.py", "reverseai/review.py", "reverseai/claims.py", "reverseai/gateway.py",
                "reverseai/contract.py", "reverseai/intake.py",
                "reverseai/mcp.py", "reverseai/mcp_tools.py", "reverseai/__init__.py", "containers/ghidra/Dockerfile.revise",
                *("containers/ghidra/" + name for name in old.GHIDRA_BUNDLE_FILES))
BASE_NATIVE_RUNS = old.GHIDRA_NATIVE_RUNS + len(old.CONTROL_NAMES) + 1 + 1 + len(RESTORE_CASES) + 7 * 7 + 3 * 8 + 1 + 80
SMOKE_SOURCE_FILES = ("tests/verify_r1_runtime.py", "tests/verify_m2_runtime.py", "tests/fixtures_code.py",
                      "tests/fixtures_scale.py", "tools/build_ghidra_image.py", "reverseai/contained.py",
                      "reverseai/ghidra_args.py", "reverseai/contract.py", "reverseai/tools/ghidra_verify.py",
                      *("containers/ghidra/" + name for name in old.GHIDRA_BUNDLE_FILES))
SMOKE_CHECKS = ("local_daemon", "image", "prepare", "restore.export_program", "restore.export_function",
                "restore.reopen", "cleanup", "sources")


def source_hashes(files=SOURCE_FILES):
    try:
        return {name: sha256_hex((ROOT / name).read_bytes()) for name in files}
    except OSError:
        raise old.VerificationError("R1SourceUnavailable") from None


def verify_lock(lock):
    old.verify_ghidra_lock(lock)
    old.need(lock["adapter_version"] == old.GHIDRA_R7_VERSION, "R1RequiresRevision")
    old.need(lock["parent_image_id"] == old.GHIDRA_PARENT_IMAGE_ID, "R1RevisionParent")


def verify_profiles(boundary):
    old.verify_ghidra_executor_profile(boundary)
    expected = {"pids": 256, "memory": "2g", "cpus": 2,
                "tmpfs": "/tmp:rw,noexec,nosuid,nodev,size=512m", "wall_seconds": PREPARE_SECONDS}
    profile = boundary.resource_profile("ghidra.prepare")
    old.need(dict(profile) == expected and all(type(profile[key]) is type(value) for key, value in expected.items())
             and boundary.GHIDRA_PREPARE_WALL_SECONDS == PREPARE_SECONDS
             and type(boundary.GHIDRA_PREPARE_WALL_SECONDS) is int
             and boundary.GHIDRA_PREPARE_MAX_BYTES == PREPARE_BYTES
             and type(boundary.GHIDRA_PREPARE_MAX_BYTES) is int, "R1PrepareProfile")
    for operation in ("ghidra.pseudocode", "ghidra.export_function", "ghidra.export_program"):
        profile = boundary.resource_profile(operation)
        old.need(dict(profile) == {**expected, "wall_seconds": 240}
                 and all(type(profile[key]) is type(value) for key, value in expected.items()), "R1QueryProfile")


def preflight(boundary):
    parent = {"adapter_version": old.GHIDRA_ADAPTER_VERSION, "base_digest": old.GHIDRA_BASE_DIGEST,
              "ghidra_sha256": old.GHIDRA_SHA256, "jdk_sha256": old.GHIDRA_JDK_SHA256,
              "image_id": old.GHIDRA_PARENT_IMAGE_ID, "platform": old.PLATFORM}
    old.NativeVerifier(boundary, parent, {"checks": [], "cleanup": []}, tool="ghidra").local_daemon()


def empty_project(data, variant=None):
    """Generate declared USTAR bytes; never parse or extract an opaque project on the host."""
    old.need(variant is None or variant in RESTORE_CASES, "R1RestoreCase")
    target = io.BytesIO()
    members = [("cache/project/reverseai.gpr", b"not opened by table queries", False),
               ("cache/project/reverseai.rep", b"", True),
               ("cache/tables/meta.json", canonical_json({"format": 1, "input_sha256": sha256_hex(data),
                 "counts": {name: 0 for name in ("functions", "calls", "references", "strings")},
                 "complete": True}).encode(), False)]
    members += [(f"cache/tables/{name}.{suffix}", b"", False)
                for name in ("functions", "calls", "references", "strings") for suffix in ("jsonl", "idx")]
    if variant in ("traversal", "absolute", "symlink", "duplicate"):
        members.append(({"traversal": "../escape", "absolute": "/escape", "symlink": "cache/project/reverseai.rep/link",
                         "duplicate": "cache/project/reverseai.gpr"}[variant], b"", False))
    with tarfile.open(fileobj=target, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, body, directory in members:
            item = tarfile.TarInfo(name)
            item.mode, item.size = (0o700 if directory else 0o600), len(body)
            item.type = tarfile.DIRTYPE if directory else tarfile.REGTYPE
            if variant == "symlink" and name.endswith("/link"):
                item.type, item.linkname = tarfile.SYMTYPE, "/escape"
            archive.addfile(item, io.BytesIO(body))
    raw = bytearray(target.getvalue())
    if variant == "checksum":
        raw[148] = 48 + (raw[148] - 48 + 1) % 8
    elif variant == "truncated":
        del raw[-513:]
    elif variant == "trailer":
        raw[-1] = 1
    elif variant == "base256":
        raw[124:136] = b"\x80" + b"\0" * 11
        raw[148:156] = b" " * 8
        raw[148:156] = f"{sum(raw[:512]):06o}\0 ".encode("ascii")
    return bytes(raw)


class MemoryProject:
    """Trusted negative-control handle: fixed stage names, exact host-built manifest."""

    def __init__(self, body, data, lock):
        self.body = body
        self.manifest = MappingProxyType({"format": 1, "input_sha256": sha256_hex(data), "image_id": lock["image_id"],
            "bundle_sha256": lock["bundle_sha256"], "size": len(body), "artifact_sha256": sha256_hex(body)})

    def stage(self, directory):
        for name, body in (("project.tar", self.body), ("cache.json", canonical_json(dict(self.manifest)).encode())):
            with (Path(directory) / name).open("xb") as output:
                output.write(body)
                os.fchmod(output.fileno(), 0o444)


def validate_page(report, data, part, start, *, scope="program", entry=None, status="ok"):
    digest = sha256_hex(data)
    rows = [evidence for result in report["results"] for evidence in result["evidence"]
            if evidence.get("observation", {}).get("kind") in
            ("export_page", "function_export", "function_info", "instruction_export", "call_export", "reference_export",
             "string_export", "pseudocode_page")]
    metadata = [row["observation"] for row in rows if row["observation"]["kind"] == "export_page"]
    old.need(len(metadata) == 1, "R1PageMetadata")
    page = metadata[0]
    required = {"kind", "scope", "part", "entry", "status", "start", "total", "count", "next_start", "analysis_id"}
    old.need(set(page) == required and page["scope"] == scope and page["part"] == part
             and page["entry"] == entry and page["status"] == status
             and isinstance(page["analysis_id"], str) and re.fullmatch(r"[0-9a-f]{64}", page["analysis_id"]), "R1PageShape")
    units = (len(rows[1]["observation"].get("text", "")) if part == "pseudocode" and len(rows) == 2 else len(rows) - 1)
    old.need(all(type(page[key]) is int and page[key] >= 0 for key in ("start", "total", "count"))
             and page["start"] == min(start, page["total"]) and page["count"] == units
             and page["count"] <= 128, "R1PageCounts")
    next_start = page["start"] + page["count"]
    old.need((page["next_start"] is None or type(page["next_start"]) is int)
             and page["next_start"] == (next_start if next_start < page["total"] else None)
             and (page["next_start"] is None or page["count"] > 0), "R1PageProgress")
    if status != "ok":
        old.need(page["start"] == page["total"] == page["count"] == 0 and len(rows) == 1,
                 "R1PageNotFoundRows")
    old.need(all(row["input_sha256"] == digest and type(row["location"]["offset"]) is int
                 and type(row["location"]["length"]) is int and row["location"]["offset"] >= 0
                 and 0 < row["location"]["length"] <= 4096
                 and row["location"]["offset"] + row["location"]["length"] <= len(data)
                 and row["observation"].get("analysis_id") == page["analysis_id"] for row in rows), "R1PageBinding")
    findings = [finding for result in report["results"] for finding in result["findings"]
                if finding["claim_key"].startswith("code.export_") or finding["claim_key"] == "code.pseudocode_page"]
    old.need(findings and all(finding["verdict"] == "derived" for finding in findings), "R1PageVerdicts")
    return page, [row for row in rows if row["observation"]["kind"] != "export_page"]


def semantic_report(report):
    def without_id(value):
        return {key: item for key, item in value.items() if key != "analysis_id"}
    return [{"role": result["role"], "status": result["status"], "errors": result["errors"],
             "findings": [{key: without_id(value) if key == "value" and isinstance(value, dict) else value
                           for key, value in finding.items() if key not in ("id", "evidence_ids")}
                          for finding in result["findings"]],
             "evidence": [{"location": row["location"], "observation": without_id(row["observation"])}
                          for row in result["evidence"]]} for result in report["results"]]


def fixture_edges(layout):
    """Calls and references as the pinned Ghidra reports them.

    A refs fixture's jump to a function entry is a tail call (CALL_TERMINATOR): Ghidra and the prepare script count it
    as a call, not as a reference, exactly as compare_ghidra_observations in verify_m2_runtime models it.
    """
    entries = {row["entry"] for row in layout.get("functions", [])}
    tail_calls = [row for row in layout.get("refs", []) if row["type"] == "jump" and row["to"] in entries]
    calls = list(layout.get("calls", [])) + tail_calls
    refs = [row for row in layout.get("refs", []) if row not in tail_calls]
    return calls, refs


def fixture_program_totals(name, data):
    old.need(name in old.GHIDRA_FIXTURE_NAMES, "R1UnknownFixture")
    expected, layout = getattr(old, name)()
    old.need(data == expected, "R1FixtureBytes")
    calls, refs = fixture_edges(layout)
    return {"functions": len(layout.get("functions", [])), "calls": len(calls), "references": len(refs),
            "strings": len(layout.get("strings", []))}


def fixture_function_totals(layout, function):
    entry = function["entry"]
    calls, refs = fixture_edges(layout)
    return {"assembly": len(function["instructions"]),
            "callees": sum(row["from"] == entry for row in calls),
            "callers": sum(row["to"] == entry for row in calls),
            "references": sum(row["from"] == entry for row in refs),
            "strings": sum(entry in row["from"] for row in layout["strings"])}


def require_cache_files(requests, present):
    old.need(requests and all(set(row.get("cache_files", {})) == {"project.tar", "cache.json"}
             and all(type(value) is bool and value is present for value in row["cache_files"].values())
             for row in requests), "R1CacheUseNotObserved")
    return len(requests)


@contextmanager
def docker_stderr():
    """Observe the real bounded runner without changing its stdout, deadlines or argv.

    A separate drain discards bytes after the fixed diagnostic prefix; stderr can
    neither fill a pipe nor grow a host file. Only verifier-owned create/start/run
    commands are observed, and the production runner still owns each process.
    """
    original, captured, readers = subprocess.Popen, bytearray(), []
    mutex = threading.Lock()
    def popen(argv, *args, **kwargs):
        if not isinstance(argv, list) or argv[:2] not in (["docker", "create"], ["docker", "run"], ["docker", "start"]):
            return original(argv, *args, **kwargs)
        process = original(argv, *args, **dict(kwargs, stderr=subprocess.PIPE))
        stop = threading.Event()
        def drain():
            try:
                os.set_blocking(process.stderr.fileno(), False)
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stderr, selectors.EVENT_READ)
                    while not stop.is_set():
                        if not selector.select(.05):
                            continue
                        chunk = os.read(process.stderr.fileno(), 65536)
                        if not chunk:
                            break
                        with mutex:
                            captured.extend(chunk[:max(0, MAX_DOCKER_STDERR_BYTES - len(captured))])
            except (OSError, ValueError):
                pass
        reader = threading.Thread(target=drain, daemon=True)
        readers.append((process.stderr, stop, reader))
        reader.start()
        return process
    try:
        with patch.object(subprocess, "Popen", side_effect=popen):
            yield captured
    finally:
        for stream, stop, reader in readers:
            # A finished CLI closes its writer, so drain its remaining diagnostic first.
            reader.join(.2)
            stop.set()
            reader.join(1)
            try:
                stream.close()
            except OSError:
                pass


class R1Verifier(old.NativeVerifier):
    def __init__(self, boundary, lock, receipt, folder, *, reply_dir=None):
        verify_lock(lock)
        verify_profiles(boundary)
        super().__init__(boundary, lock, receipt, tool="ghidra")
        self.folder = Path(folder).resolve()
        self.stage_root = self.folder / "staging"
        self.stage_root.mkdir(mode=0o700)
        self.true_executor = boundary.DockerExecutor
        self.requests, self.allowed = [], set()
        self.stream, self.probe_result = None, None
        self.failed_stderr = b""
        self.reply_dir = None if reply_dir is None else Path(reply_dir)
        if self.reply_dir is not None:
            old.need(not self.reply_dir.exists() and not self.reply_dir.is_symlink(), "R1NewReplyDirectory")
            self.reply_dir.mkdir(mode=0o700)
            self.receipt["replies"] = []

    def save_reply(self, data, operation, args, raw):
        if self.reply_dir is None:
            return
        old.need(operation in ("ghidra.export_program", "ghidra.export_function", "ghidra.functions")
                 and type(raw) is bytes and 0 < len(raw) <= 262144, "R1ReplyOutput")
        name = "elf_code." + operation
        request = {"fixture": "elf_code", "input_sha256": sha256_hex(data), "operation": operation, "args": args}
        encoded = canonical_json(request).encode()
        for suffix, content in (("request.json", encoded), ("reply.json", raw)):
            with (self.reply_dir / (name + "." + suffix)).open("xb") as target:
                os.fchmod(target.fileno(), 0o600)
                target.write(content)
        self.receipt["replies"].append({**request, "file": name + ".reply.json", "bytes": len(raw),
                                       "sha256": sha256_hex(raw), "request_sha256": sha256_hex(encoded)})

    def ghidra_request_allowed(self, operation, args):
        return (operation == "ghidra.prepare" and args == {} or old.ghidra_request_allowed(operation, args)
                or (operation, canonical_json(args)) in self.allowed)

    def runner(self, argv, *, timeout, max_output):
        row, started = None, None
        if argv[:2] == ["docker", "run"]:
            at = argv.index(self.lock["image_id"])
            mount = next(old.csv.reader(io.StringIO(argv[argv.index("--mount") + 1])))
            sources = [item.removeprefix("source=") for item in mount if item.startswith("source=")]
            old.need(len(sources) == 1, "BuilderSnapshot")
            snapshot = Path(sources[0])
            row = {"operation": argv[at + 1], "args": old.decode(argv[at + 2]),
                   "probe": self.active, "timeout": timeout, "max_output": max_output,
                   "cache_files": {name: (snapshot / name).is_file() and not (snapshot / name).is_symlink()
                                   for name in ("project.tar", "cache.json")}}
            if self.active is not None:
                row["probe_evidence"] = None
            self.requests.append(row)
            started = time.monotonic()
        diagnostic = None
        try:
            with docker_stderr() as diagnostic:
                result = super().runner(argv, timeout=timeout, max_output=max_output)
            if row is not None and row["probe"] is not None and result is not None:
                try:
                    evidence = old.decode(result)
                except old.VerificationError:
                    pass  # Keep missing evidence explicit; the control still validates the reply.
                else:
                    if isinstance(evidence, dict):
                        row["probe_evidence"] = evidence
            return result
        finally:
            if row is not None:
                # This includes stopped inspection and cleanup; wall evidence times the attached process separately.
                row["elapsed_seconds"] = time.monotonic() - started
            if diagnostic:
                self.failed_stderr = diagnostic

    def record(self, name, check):
        self.failed_stderr = b""
        passed = super().record(name, check)
        if not passed and self.failed_stderr:
            raw = bytes(self.failed_stderr).decode("utf-8", errors="replace").encode("utf-8")
            self.receipt["checks"][-1]["docker_stderr"] = raw[:MAX_DOCKER_STDERR_BYTES].decode("utf-8", errors="ignore")
        return passed

    def run_bounded(self, argv, *, timeout, max_output):
        try:
            if self.stream is not None and argv[:3] == ["docker", "start", "--attach"]:
                old.need(timeout == PREPARE_SECONDS and max_output == PREPARE_BYTES, "R1PrepareDrainLimits")
                return self.boundary.run_prepare_bounded(argv, self.stream, timeout=PREPARE_SECONDS)
            return super().run_bounded(argv, timeout=timeout, max_output=max_output)
        except self.boundary.ContainedError as error:
            if (argv[:3] == ["docker", "start", "--attach"] and self.requests
                    and str(error) in ("WorkerTimeout", "WorkerOutputLimit", "WorkerProcessError")):
                self.requests[-1]["failure"] = str(error)
            raise

    def prepare_runner(self, argv, sink, *, timeout):
        old.need(timeout == PREPARE_SECONDS and self.stream is None, "R1PrepareDrainLimits")
        self.stream, self.wall = sink, PREPARE_SECONDS
        try:
            result = self.runner(argv, timeout=timeout, max_output=PREPARE_BYTES)
            if result is not None:
                self.probe_result = old.decode(result)
                raise self.boundary.ContainedError(self.probe_result.get("error", "WorkerProcessError"))
        finally:
            self.stream, self.wall = None, 240

    def executor(self):
        return self.true_executor(self.lock, runner=self.runner, prepare_runner=self.prepare_runner,
                                  inspect=lambda image: image if image == self.image["Id"] else None,
                                  staging_root=self.stage_root, **old.lock_options("ghidra", self.lock))

    def finish_call(self):
        if self.last is not None:
            row, snapshot = self.last
            row["staging_removed"] = not snapshot.exists()
            old.need(row["staging_removed"], "SnapshotCleanupUnverified")
        self.active = None

    def invoke(self, data, operation, args, *, probe=None, project=None):
        self.active, self.last = probe, None
        try:
            return self.executor().run(operation, args, data, sha256_hex(data), project=project)
        finally:
            self.finish_call()

    def control_code(self):
        if self.active == "cache_write":
            return ("import json,os\nr={'attempted':True,'blocked':False}\ntry:\n"
                    " f=open('/snapshot/project.tar','ab');f.write(b'x');f.close()\n"
                    "except OSError as e:r.update(blocked=True,errno=e.errno)\nprint(json.dumps(r))\n")
        if self.active == "program_no_jvm":
            return ("import importlib.util,json,pathlib,subprocess\n"
                    "s=importlib.util.spec_from_file_location('r1_worker','/opt/reverseai/worker.py')\n"
                    "w=importlib.util.module_from_spec(s);s.loader.exec_module(w)\n"
                    "calls=[]\ndef deny(*a,**k):\n calls.append(1);raise AssertionError('UnexpectedProcess')\n"
                    "subprocess.Popen=deny\ndata=pathlib.Path('/snapshot/input').read_bytes()\n"
                    "reply=w.reply(['ghidra.export_program',json.dumps({'part':'functions','start':0,'limit':128})],data)\n"
                    "print(json.dumps({'launches':len(calls),'reply':reply},separators=(',',':')))\n")
        if self.stream is not None and self.active in ("wall", "stdout"):
            return ("import time;time.sleep(915)" if self.active == "wall" else
                    f"import sys;sys.stdout.buffer.write(b'x'*{PREPARE_BYTES + 1});sys.stdout.buffer.flush()")
        return super().control_code()

    def prepare_control(self, name, data):
        self.active, self.last, self.probe_result = name, None, None
        request_start, value = len(self.requests), None
        try:
            with tempfile.TemporaryFile() as sink:
                try:
                    self.executor().prepare(data, sha256_hex(data), sink)
                    sink.seek(0)
                    value = old.decode(sink.read(16_385))
                except self.boundary.ContainedError as error:
                    old.need(name in ("wall", "stdout") and self.probe_result is not None
                             and str(error) == self.probe_result["error"], "R1PrepareControlFailure")
                    value = self.probe_result
            if name == "wall":
                old.need(value.get("timeout") == PREPARE_SECONDS and value.get("running_observed") is True
                         and PREPARE_SECONDS - .5 <= value.get("elapsed", -1) <= PREPARE_SECONDS + 5,
                         "R1PrepareWallNotObserved")
            elif name == "stdout":
                old.need(value.get("max_output") == PREPARE_BYTES and value.get("error") == "WorkerOutputLimit",
                         "R1PrepareFloodNotObserved")
            else:
                old.validate_probe(name, value, tool="ghidra")
            return value
        finally:
            if len(self.requests) > request_start:
                self.requests[request_start]["probe_evidence"] = value if isinstance(value, dict) else self.probe_result
            self.finish_call()

    def restore(self, data, variant=None):
        project = MemoryProject(empty_project(data, variant), data, self.lock)
        self.allowed.add(("ghidra.export_program", canonical_json(PROGRAM_ARGS)))
        value = old.decode(self.invoke(data, "ghidra.export_program", PROGRAM_ARGS, project=project))
        if variant is None:
            old.need(value.get("status") == "ok" and value["observations"][0]["value"]["total"] == 0,
                     "R1RestorePositive")
        else:
            old.need(value == {"protocol": "reverseai.worker/1", "status": "error", "snapshot_sha256": sha256_hex(data),
                               "error": "InvalidCachedProject"}, "R1RestoreNegativeNotRefused")
        return {"input_sha256": sha256_hex(data), "artifact_sha256": project.manifest["artifact_sha256"],
                "variant": variant, "refused": variant is not None}

    def cache_write(self, data):
        project = MemoryProject(empty_project(data), data, self.lock)
        self.allowed.add(("ghidra.export_program", canonical_json(PROGRAM_ARGS)))
        value = old.decode(self.invoke(data, "ghidra.export_program", PROGRAM_ARGS, project=project, probe="cache_write"))
        old.need(value.get("attempted") is True and value.get("blocked") is True and value.get("errno") in (1, 13, 30),
                 "R1CacheWriteNotRefused")
        return value

    def public_call(self, argv, cache_root):
        # The injection is a trusted controller choice; no analyst cache-path or runner flag is added.
        from reverseai import cli, ghidra_cache
        from reverseai.tools import ghidra_tool
        def factory(*args, **kwargs):
            old.need(not args or args[0] == self.lock, "R1PublicLockSelection")
            old.need(kwargs.get("adapter_version", old.GHIDRA_R7_VERSION) == old.GHIDRA_R7_VERSION,
                     "R1PublicAdapterSelection")
            return self.executor()
        stdout, stderr = io.StringIO(), io.StringIO()
        self.active, self.last = None, None
        try:
            with ExitStack() as stack:
                stack.enter_context(patch.object(ghidra_cache, "default_root", return_value=cache_root))
                stack.enter_context(patch.object(ghidra_tool, "DEFAULT_LOCK", self.lock))
                stack.enter_context(patch.object(ghidra_tool, "DockerExecutor", factory))
                stack.enter_context(patch.object(self.boundary, "DockerExecutor", factory))
                original_default = self.boundary.default_lock
                stack.enter_context(patch.object(self.boundary, "default_lock",
                    side_effect=lambda tool: self.lock if tool == "ghidra" else original_default(tool)))
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    try:
                        code = cli.main(argv)
                    except SystemExit as error:
                        code = error.code
            old.need(code is None or type(code) is int and code == 0, "R1PublicCliFailed")
            old.need(len(stdout.getvalue().encode()) <= 16_384, "R1PublicStdoutLimit")
            return stdout.getvalue()
        finally:
            self.finish_call()

    def public_query(self, sample, cache_root, name=None, args=None):
        from reverseai import queries
        from reverseai.tools import ghidra_tool
        if name is None:
            expected = [("ghidra.analyze", old.ghidra_args())]
            tail = ["analyze", str(sample)]
        else:
            spec, checked = queries.resolve(name, args or {})
            tool = ghidra_tool.make_tool(self.executor())
            expected = [(request.operation, tool.operations[request.operation].validate_args(request.args))
                        for request in spec.requests(checked)]
            tail = ["query", str(sample), "--query", name]
            for key, value in (args or {}).items():
                tail.extend(("--arg", f"{key}={value}"))
        self.allowed.update((operation, canonical_json(checked)) for operation, checked in expected)
        output = sample.parent / ("out-" + str(len(list(sample.parent.glob("out-*")))))
        before = len(self.requests)
        self.public_call([*tail, "--with-ghidra", "--out", str(output)], cache_root)
        actual = self.requests[before:]
        old.need([(row["operation"], row["args"]) for row in actual] == expected, "R1PublicInvocationCount")
        raw = (output / "report.json").read_bytes()
        old.need(len(raw) <= 1024**2, "R1PublicReportLimit")
        report = old.decode(raw)
        code = [row for row in report["results"] if row["role"] == "code"]
        old.need(len(code) == 1 and code[0]["status"] == "ok" and not code[0]["errors"], "R1CodeRoleFailed")
        return report

    def public_prepare(self, sample, cache_root, *, state):
        before = len(self.requests)
        raw = self.public_call(["prepare", str(sample), "--with-ghidra", "--json"], cache_root)
        receipt = old.decode(raw)
        keys = {"schema", "input", "analysis_id", "state", "runtime", "cache_format", "artifact_size", "elapsed_seconds"}
        old.need(isinstance(receipt, dict) and set(receipt) == keys and receipt["schema"] == "reverseai.prepare/1"
                 and receipt["input"] == {"sha256": sha256_hex(sample.read_bytes()), "size": sample.stat().st_size}
                 and receipt["state"] == state and receipt["runtime"] == {"image": self.lock["image_id"],
                    "platform": old.PLATFORM, "bundle_sha256": self.lock["bundle_sha256"]}
                 and type(receipt["cache_format"]) is int and receipt["cache_format"] == 1
                 and type(receipt["artifact_size"]) is int and 0 < receipt["artifact_size"] <= PREPARE_BYTES
                 and type(receipt["elapsed_seconds"]) in (int, float) and math.isfinite(receipt["elapsed_seconds"])
                 and receipt["elapsed_seconds"] >= 0, "R1PrepareReceipt")
        actual = self.requests[before:]
        old.need([row["operation"] for row in actual] == (["ghidra.prepare"] if state == "created" else []),
                 "R1PrepareInvocationCount")
        from reverseai import ghidra_cache
        with ghidra_cache.CacheStore(cache_root).lookup(ghidra_cache.identity(receipt["input"]["sha256"], self.lock)) as handle:
            old.need(receipt["analysis_id"] == handle.analysis_id
                     and receipt["artifact_size"] == handle.manifest["size"], "R1PrepareArtifactBinding")
        return receipt

    def cached_fixture(self, name, data):
        started = time.monotonic()
        folder = self.folder / name
        folder.mkdir(mode=0o700)
        sample, cache = folder / "fixture.bin", folder / "cache"
        sample.write_bytes(data)
        fresh_start = len(self.requests)
        fresh = self.public_query(sample, cache)
        cases = []
        if name in old.GHIDRA_QUERY_FIXTURES:
            requests = old.ghidra_query_requests(data)
            cases = [("list_procedures", {"start": 1, "limit": 2}),
                     ("analyze_function", {"entry": requests["function_add"][1]["entry"], "start": 1, "limit": 2}),
                     ("procedure_callers", {"entry": requests["function_constant"][1]["entry"]}),
                     ("xrefs", {"address": requests["xrefs_counter"][1]["address"]})]
        fresh_queries = [self.public_query(sample, cache, query, args) for query, args in cases]
        fresh_count = require_cache_files(self.requests[fresh_start:], False)
        prepared = self.public_prepare(sample, cache, state="created")
        reused = self.public_prepare(sample, cache, state="reused")
        old.need(reused["analysis_id"] == prepared["analysis_id"], "R1PrepareReusedIdentity")
        cached_start = len(self.requests)
        cached = self.public_query(sample, cache)
        old.need(semantic_report(fresh) == semantic_report(cached), "R1CachedAnswerChanged")
        for (query, args), original in zip(cases, fresh_queries):
            report = self.public_query(sample, cache, query, args)
            old.need(semantic_report(report) == semantic_report(original), "R1CachedQueryChanged")
        cached_count = require_cache_files(self.requests[cached_start:], True)
        program_start, totals = len(self.requests), {}
        expected_totals = fixture_program_totals(name, data)
        for part in ("functions", "calls", "references", "strings"):
            report = self.public_query(sample, cache, "export_program", {"part": part, "start": 0, "limit": 128})
            page, _ = validate_page(report, data, part, 0)
            old.need(page["analysis_id"] == prepared["analysis_id"], "R1PreparedPageIdentity")
            totals[part] = page["total"]
            old.need(type(totals[part]) is int and totals[part] == expected_totals[part], "R1ProgramTotal")
            if name == "elf_data_only":
                old.need(page["total"] == 0 and page["count"] == 0, "R1DataOnlyNotEmpty")
        return {"input_sha256": sha256_hex(data), "input_bytes": len(data), "prepare": prepared,
                "fresh_equal_cached": True, "prepare_operations": 1, "query_cases": len(cases),
                "cache_requests": {"fresh": fresh_count, "cached": cached_count,
                                   "program": require_cache_files(self.requests[program_start:], True)},
                "program_totals": totals,
                "fresh_semantics_sha256": sha256_hex(canonical_json(semantic_report(fresh)).encode()),
                "cached_semantics_sha256": sha256_hex(canonical_json(semantic_report(cached)).encode()),
                "elapsed_seconds": time.monotonic() - started}

    def program_no_jvm(self):
        from reverseai import ghidra_cache
        data, layout = old.elf_code()
        cache = ghidra_cache.CacheStore(self.folder / "elf_code/cache")
        with cache.lookup(ghidra_cache.identity(sha256_hex(data), self.lock)) as project:
            value = old.decode(self.invoke(data, "ghidra.export_program", PROGRAM_ARGS,
                                           project=project, probe="program_no_jvm"))
        old.need(isinstance(value, dict) and set(value) == {"launches", "reply"}
                 and type(value["launches"]) is int and value["launches"] == 0,
                 "R1ProgramLaunchedProcess")
        rows = old.parse_worker_reply(canonical_json(value["reply"]).encode(),
                                      input_sha256=sha256_hex(data), max_observations=129)
        count = len(layout["functions"])
        old.need(len(rows) == count + 1 and rows[0].value == {
            "kind": "export_page", "scope": "program", "part": "functions", "entry": None,
            "status": "ok", "start": 0, "total": count, "count": count, "next_start": None}
            and all(type(rows[0].value[key]) is int for key in ("start", "total", "count"))
            and rows[0].location == old.Location(0, min(64, len(data))), "R1ProgramFunctionsMetadata")
        old.need(all(row.value.get("kind") == "function_export"
                     and type(row.value.get("index")) is int and row.value["index"] == index
                     for index, row in enumerate(rows[1:])), "R1ProgramFunctionRows")
        return {"process_launches": 0, "rows": len(rows), "functions": count,
                "input_sha256": sha256_hex(data), "reply_protocol": value["reply"]["protocol"],
                "reply_status": value["reply"]["status"]}

    def function_parts(self):
        data, layout = old.elf_refs()
        function = next(row for row in layout["functions"] if row["name"] == "describe")
        sample, cache = self.folder / "elf_refs/fixture.bin", self.folder / "elf_refs/cache"
        before = len(self.requests)
        totals, identity = {}, None
        expected_totals = fixture_function_totals(layout, function)
        for part in ("info", "pseudocode", "assembly", "callees", "callers", "references", "strings"):
            args = {"entry": function["entry"], "part": part}
            if part == "pseudocode":
                args["max_chars"] = 64
            elif part != "info":
                args["limit"] = 128
            report = self.public_query(sample, cache, "export_function", args)
            page, rows = validate_page(report, data, part, 0, scope="function", entry=function["entry"])
            old.need(identity is None or identity == page["analysis_id"], "R1FunctionMixedAnalysis")
            identity, totals[part] = page["analysis_id"], page["total"]
            if part == "info":
                old.need(page["total"] == 1 and len(rows) == 1
                         and rows[0]["observation"].get("totals") == expected_totals
                         and all(type(value) is int for value in rows[0]["observation"]["totals"].values()),
                         "R1InfoTotals")
            elif part in expected_totals:
                old.need(page["total"] == expected_totals[part], "R1FunctionTotal")
            if part == "assembly":
                expected = function["instructions"]
                old.need(len(rows) == page["total"] == len(expected), "R1InstructionCompleteness")
                for index, (row, (delta, length)) in enumerate(zip(rows, expected)):
                    value = row["observation"]
                    old.need(value["kind"] == "instruction_export" and value["index"] == index
                             and value["from"] == function["entry"] and value["at"] == function["entry"] + delta
                             and value["length"] == length
                             and row["location"] == {"offset": function["offset"] + delta, "length": length},
                             "R1InstructionAnchor")
            if part == "strings":
                old.need(page["total"] == len(layout["strings"]), "R1FunctionStringsMissing")
        old.need(totals["info"] == 1 and totals["pseudocode"] > 64 and totals["references"] > 0,
                 "R1FunctionPartsIncomplete")
        return {"input_sha256": sha256_hex(data), "entry": function["entry"], "analysis_id": identity,
                "totals": totals, "requests": len(self.requests) - before}

    def pseudocode(self):
        data, layout = old.elf_refs()
        function = next(row for row in layout["functions"] if row["name"] == "describe")
        sample, cache = self.folder / "elf_refs/fixture.bin", self.folder / "elf_refs/cache"
        before, readings = len(self.requests), []
        for name in ("export_function", "procedure_pseudo_code"):
            cursor, pieces, identity, digest, total, pages = 0, [], None, None, None, 0
            while True:
                args = {"entry": function["entry"], "max_chars": 64, "text_start": cursor}
                args.update({"part": "pseudocode"} if name == "export_function" else {"mode": "paged"})
                report = self.public_query(sample, cache, name, args)
                page, rows = validate_page(report, data, "pseudocode", cursor, scope="function", entry=function["entry"])
                old.need(len(rows) == 1, "R1PseudocodeRow")
                value = rows[0]["observation"]
                old.need(value["kind"] == "pseudocode_page" and value["entry"] == function["entry"]
                         and type(value["text"]) is str and len(value["text"]) <= 64 and value["status"] == "ok"
                         and value["start"] == page["start"] and value["total"] == page["total"]
                         and value["next_start"] == page["next_start"]
                         and isinstance(value["text_sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", value["text_sha256"])
                         and (identity is None or identity == page["analysis_id"])
                         and (digest is None or digest == value["text_sha256"])
                         and (total is None or total == value["total"]), "R1PseudocodeBinding")
                identity, digest, total = page["analysis_id"], value["text_sha256"], value["total"]
                pieces.append(value["text"])
                pages += 1
                if page["next_start"] is None:
                    break
                cursor = page["next_start"]
                old.need(pages <= 16_384, "R1PseudocodePaginationLimit")
            joined = "".join(pieces)
            old.need(pages >= 2 and len(joined) == total and sha256_hex(joined.encode()) == digest,
                     "R1PseudocodeIncomplete")
            readings.append((identity, digest, total, joined, pages))
        old.need(readings[0][:4] == readings[1][:4], "R1PseudocodeRoutesDisagree")
        return {"input_sha256": sha256_hex(data), "entry": function["entry"], "analysis_id": readings[0][0],
                "text_sha256": readings[0][1], "characters": readings[0][2],
                "export_pages": readings[0][4], "procedure_pages": readings[1][4],
                "requests": len(self.requests) - before}

    def not_found(self):
        data = old.ghidra_fixtures()["elf_refs"]
        sample, cache = self.folder / "elf_refs/fixture.bin", self.folder / "elf_refs/cache"
        report = self.public_query(sample, cache, "export_function", {"entry": 2**64 - 1, "part": "info"})
        page, rows = validate_page(report, data, "info", 0, scope="function", status="not_found")
        old.need(not rows, "R1NotFoundRows")
        return {"input_sha256": sha256_hex(data), "analysis_id": page["analysis_id"], "rows": len(rows)}

    def scale(self):
        data, layout = elf_scale()
        folder = self.folder / "scale"
        folder.mkdir(mode=0o700)
        sample, cache = folder / "fixture.bin", folder / "cache"
        sample.write_bytes(data)
        started = time.monotonic()
        prepared = self.public_prepare(sample, cache, state="created")
        expected, cursor, actual, pages = layout["functions"], 0, [], 0
        while True:
            report = self.public_query(sample, cache, "export_program", {"part": "functions", "start": cursor, "limit": 128})
            page, rows = validate_page(report, data, "functions", cursor)
            old.need(page["total"] == 10_000 and page["analysis_id"] == prepared["analysis_id"], "R1ScaleTotal")
            for row in rows:
                index = len(actual)
                function = expected[index]
                value = row["observation"]
                old.need(value["index"] == index and value["entry"] == function["entry"]
                         and value["name"] == function["name"] and value["size"] == function["size"]
                         and row["location"] == {"offset": function["offset"], "length": min(16, function["size"])},
                         "R1ScaleFunctionMismatch")
                actual.append(value["entry"])
            pages += 1
            if page["next_start"] is None:
                break
            cursor = page["next_start"]
            old.need(pages <= 79, "R1ScalePaginationLimit")
        old.need(len(actual) == len(set(actual)) == 10_000 and pages == 79, "R1ScaleIncomplete")
        return {"input_sha256": sha256_hex(data), "input_bytes": len(data), "functions": len(actual), "pages": pages,
                "prepare": prepared, "elapsed_seconds": time.monotonic() - started}

    def smoke(self):
        data, layout = old.elf_code()
        project = None
        self.receipt["input"] = {"sha256": sha256_hex(data), "size": len(data)}
        if not self.record("local_daemon", self.local_daemon) or not self.record("image", self.image_check):
            return
        def prepare():
            nonlocal project
            started = time.monotonic()
            self.active, self.last = None, None
            try:
                with tempfile.TemporaryFile() as sink:
                    self.executor().prepare(data, sha256_hex(data), sink)
                    sink.seek(0)
                    body = sink.read(PREPARE_BYTES + 1)
                old.need(0 < len(body) <= PREPARE_BYTES, "R1SmokeArtifactLimit")
                project = MemoryProject(body, data, self.lock)
                self.receipt["manifest"] = dict(project.manifest)
                return {"artifact_size": len(body), "artifact_sha256": sha256_hex(body),
                        "elapsed_seconds": time.monotonic() - started}
            finally:
                self.finish_call()
        if not self.record("prepare", prepare):
            return
        def invoke(operation, args):
            self.allowed.add((operation, canonical_json(args)))
            raw = self.invoke(data, operation, args, project=project)
            self.save_reply(data, operation, args, raw)
            return old.parse_worker_reply(raw, input_sha256=sha256_hex(data), max_observations=129)
        def metadata(rows, scope, part, entry, count):
            old.need(len(rows) == count + 1 and rows[0].value == {
                "kind": "export_page", "scope": scope, "part": part, "entry": entry, "status": "ok",
                "start": 0, "total": count, "count": count, "next_start": None}, "R1SmokePage")
            old.need(all(type(rows[0].value[key]) is int for key in ("start", "total", "count")), "R1SmokePageTypes")
            old.need(rows[0].location == old.Location(0, min(64, len(data))), "R1SmokePageAnchor")
        def function_row(row, function):
            value = row.value
            old.need(type(value["entry"]) is int and type(value["size"]) is int
                     and value["entry"] == function["entry"] and value["size"] == function["size"]
                     and value["name"] == function["name"]
                     and row.location == old.Location(function["offset"], function["size"]), "R1SmokeFunctionOracle")
        def program():
            rows = invoke("ghidra.export_program", PROGRAM_ARGS)
            metadata(rows, "program", "functions", None, len(layout["functions"]))
            for index, (row, function) in enumerate(zip(rows[1:], layout["functions"])):
                old.need(set(row.value) == {"kind", "index", "name", "entry", "size", "signature",
                         "signature_truncated", "library_hint"} and row.value["kind"] == "function_export"
                         and type(row.value["index"]) is int and row.value["index"] == index and row.value["library_hint"] is None
                         and type(row.value["signature_truncated"]) is bool, "R1SmokeFunctionShape")
                function_row(row, function)
            return {"functions": len(rows) - 1, "input_sha256": sha256_hex(data)}
        self.record("restore.export_program", program)
        entry = layout["functions"][0]["entry"]
        info_args = {"select": "entry", "entry": entry, "name": "", "part": "info", "start": 0,
                     "limit": 32, "text_start": 0, "max_chars": 1024}
        def info():
            rows = invoke("ghidra.export_function", info_args)
            metadata(rows, "function", "info", entry, 1)
            value = rows[1].value
            old.need(set(value) == {"kind", "name", "entry", "size", "matches", "signature", "signature_truncated",
                     "library_hint", "totals", "pseudocode_status"} and value["kind"] == "function_info"
                     and type(value["matches"]) is int and value["matches"] == 1 and value["library_hint"] is None
                     and value["pseudocode_status"] == "not_requested"
                     and set(value["totals"]) == {"assembly", "callees", "callers", "references", "strings"}
                     and all(type(count) is int and count >= 0 for count in value["totals"].values())
                     and value["totals"]["callees"] == 2 and value["totals"]["callers"] == 0
                     and value["totals"]["references"] == value["totals"]["strings"] == 0, "R1SmokeInfoShape")
            function_row(rows[1], layout["functions"][0])
            return {"entry": entry, "totals": value["totals"], "input_sha256": sha256_hex(data)}
        self.record("restore.export_function", info)
        def reopen():
            args = {"query": "", "start": 0, "limit": 1}
            rows = invoke("ghidra.functions", args)
            old.need(len(rows) == 1, "R1SmokeReopenCount")
            for index, (row, function) in enumerate(zip(rows, layout["functions"][:1])):
                old.need(set(row.value) == {"kind", "index", "total", "entry", "size", "name"}
                         and row.value["kind"] == "function_row" and type(row.value["index"]) is int
                         and type(row.value["total"]) is int and row.value["index"] == index
                         and row.value["total"] == len(layout["functions"]), "R1SmokeReopenRow")
                function_row(row, function)
            return {"functions": len(rows), "total": len(layout["functions"]),
                    "input_sha256": sha256_hex(data), "operation": "ghidra.functions"}
        self.record("restore.reopen", reopen)
        self.record("cleanup", lambda: old.need(self.inspected == len(self.requests) == len(self.receipt["cleanup"]) == 4
                    and all(row["verified"] and row["staging_removed"] for row in self.receipt["cleanup"])
                    and not list(self.stage_root.iterdir()), "R1SmokeCleanupMissing"))

    def run_r1(self):
        super().run()
        if not all(row["status"] == "passed" for row in self.receipt["checks"]):
            return
        data = old.ghidra_fixtures()["elf_code"]
        for name in old.CONTROL_NAMES:
            self.record("prepare." + name, lambda name=name: self.prepare_control(name, data))
        self.record("cache.write_refused", lambda: self.cache_write(data))
        self.record("restore.valid", lambda: self.restore(data))
        for name in RESTORE_CASES:
            self.record("restore." + name, lambda name=name: self.restore(data, name))
        for name, data in old.ghidra_fixtures().items():
            self.record(name + ".cached_equal", lambda name=name, data=data: self.cached_fixture(name, data))
        self.record("function.parts", self.function_parts)
        self.record("function.pseudocode", self.pseudocode)
        self.record("function.not_found", self.not_found)
        self.record("program.no_jvm", self.program_no_jvm)
        self.record("scale.10000", self.scale)
        self.record("cleanup", lambda: old.need(self.inspected == len(self.requests) == len(self.receipt["cleanup"])
                    and all(row["verified"] and row["staging_removed"] for row in self.receipt["cleanup"])
                    and not list(self.stage_root.iterdir()), "R1CleanupMissing"))


def receipt_passes(receipt):
    try:
        verify_lock(receipt["lock"])
        old.need(receipt["schema"] == "reverseai.r1-runtime/1" and receipt["offline"] is True
                 and receipt["platform"] == old.PLATFORM and receipt["image_id"] == receipt["lock"]["image_id"]
                 and re.fullmatch(r"[0-9a-f]{64}", receipt["lock_sha256"])
                 and receipt["sources"] == source_hashes(), "R1ReceiptBinding")
        rows = receipt["checks"]
        old.need(len(rows) == len(REQUIRED_CHECKS) and {row["id"] for row in rows} == set(REQUIRED_CHECKS)
                 and all(row["status"] == "passed" for row in rows), "R1ReceiptChecks")
        evidence = {row["id"]: row.get("evidence") for row in rows}
        function, text = evidence["function.parts"], evidence["function.pseudocode"]
        old.need(function["requests"] == 7 and set(function["totals"]) == {
                    "info", "pseudocode", "assembly", "callees", "callers", "references", "strings"}
                 and function["totals"]["pseudocode"] > 64
                 and type(text["export_pages"]) is int and type(text["procedure_pages"]) is int
                 and text["export_pages"] >= 2 and text["procedure_pages"] >= 2
                 and text["requests"] == text["export_pages"] + text["procedure_pages"]
                 and type(text["characters"]) is int and text["characters"] > 64
                 and re.fullmatch(r"[0-9a-f]{64}", text["text_sha256"])
                 and evidence["function.not_found"]["rows"] == 0, "R1ReceiptFunctionProof")
        runs = BASE_NATIVE_RUNS + 8 + text["requests"]
        cleanup, requests = receipt["cleanup"], receipt["requests"]
        old.need(len(cleanup) == len(requests) == runs
                 and len({row["container_id"] for row in cleanup}) == runs
                 and all(re.fullmatch(r"[0-9a-f]{64}", row["container_id"]) and row["verified"] is True
                         and row["staging_removed"] is True for row in cleanup), "R1ReceiptCleanup")
        old.need(all(row["timeout"] == (PREPARE_SECONDS if row["operation"] == "ghidra.prepare" else 240)
                     and type(row["timeout"]) is int
                     and row["max_output"] == (PREPARE_BYTES if row["operation"] == "ghidra.prepare" else 262144)
                     and type(row["max_output"]) is int for row in requests), "R1ReceiptProfiles")
        counted = Counter((row["operation"], row["probe"]) for row in requests)
        expected = {("ghidra.prepare", None): 8, ("ghidra.analyze", None): 21, ("ghidra.functions", None): 9,
                    ("ghidra.function", None): 18, ("ghidra.xrefs", None): 9, ("ghidra.export_program", None): 116,
                    ("ghidra.export_function", None): 8 + text["export_pages"],
                    ("ghidra.pseudocode", None): text["procedure_pages"],
                    ("ghidra.export_program", "program_no_jvm"): 1, ("ghidra.export_program", "cache_write"): 1,
                    **{(operation, name): 1 for operation in ("ghidra.prepare", "ghidra.analyze")
                       for name in old.CONTROL_NAMES}}
        old.need(counted == expected, "R1ReceiptOperations")
        old.need(all("failure" not in row for row in requests if row["probe"] is None), "R1ReceiptWorkerFailed")
        for row in requests:
            files = row.get("cache_files", {})
            old.need(set(files) == {"project.tar", "cache.json"}
                     and all(type(value) is bool for value in files.values())
                     and files["project.tar"] is files["cache.json"], "R1ReceiptCacheFiles")
        cache_counted = Counter((row["operation"], row["probe"], row["cache_files"]["project.tar"]) for row in requests)
        fresh_legacy = {"ghidra.analyze": 14, "ghidra.functions": 6, "ghidra.function": 12, "ghidra.xrefs": 6}
        cache_expected = Counter()
        for (operation, probe), count in expected.items():
            fresh = (count if operation == "ghidra.prepare" or probe is not None and operation == "ghidra.analyze"
                     else fresh_legacy.get(operation, 0) if probe is None else 0)
            if fresh:
                cache_expected[operation, probe, False] = fresh
            if count > fresh:
                cache_expected[operation, probe, True] = count - fresh
        old.need(cache_counted == cache_expected, "R1ReceiptCacheUse")
        revision = evidence["revision"]
        old.need(revision == {"route": revision["route"], "parent_image_id": old.GHIDRA_PARENT_IMAGE_ID,
                              "bundle_sha256": receipt["lock"]["bundle_sha256"]}
                 and revision["route"] in ("A", "B"), "R1ReceiptRevision")
        fixtures = old.ghidra_fixtures()
        refs_hash = sha256_hex(fixtures["elf_refs"])
        _, layout = old.elf_refs()
        target = next(row for row in layout["functions"] if row["name"] == "describe")
        expected_totals = {"info": 1, **fixture_function_totals(layout, target)}
        old.need(all(type(function["totals"][key]) is int and function["totals"][key] == value
                     for key, value in expected_totals.items()) and function["entry"] == target["entry"],
                 "R1ReceiptFunctionTotals")
        old.need(function["input_sha256"] == text["input_sha256"] == refs_hash
                 and function["entry"] == text["entry"]
                 and function["analysis_id"] == text["analysis_id"] == evidence["function.not_found"]["analysis_id"]
                 and function["analysis_id"] == evidence["elf_refs.cached_equal"]["prepare"]["analysis_id"]
                 and evidence["function.not_found"]["input_sha256"] == refs_hash, "R1ReceiptFunctionBinding")
        for name, data in fixtures.items():
            item = evidence[name + ".cached_equal"]
            old.need(item["input_sha256"] == sha256_hex(data) and item["input_bytes"] == len(data)
                     and item["fresh_equal_cached"] is True and item["prepare_operations"] == 1
                     and item["query_cases"] == (4 if name in old.GHIDRA_QUERY_FIXTURES else 0)
                     and item["cache_requests"] == {"fresh": 1 + item["query_cases"],
                                                    "cached": 1 + item["query_cases"], "program": 4}
                     and all(type(value) is int for value in item["cache_requests"].values())
                     and item["program_totals"] == fixture_program_totals(name, data)
                     and all(type(value) is int for value in item["program_totals"].values())
                     and re.fullmatch(r"[0-9a-f]{64}", item["fresh_semantics_sha256"])
                     and item["fresh_semantics_sha256"] == item["cached_semantics_sha256"], "R1ReceiptCachedAnswer")
        no_jvm = evidence["program.no_jvm"]
        old.need(no_jvm == {"process_launches": 0, "rows": 5, "input_sha256": sha256_hex(fixtures["elf_code"]),
                           "reply_protocol": "reverseai.worker/1", "reply_status": "ok", "functions": 4}
                 and type(no_jvm["process_launches"]) is int and type(no_jvm["rows"]) is int
                 and type(no_jvm["functions"]) is int, "R1ReceiptProgramDispatch")
        scale = evidence["scale.10000"]
        scale_data, _ = elf_scale()
        old.need(scale["input_sha256"] == sha256_hex(scale_data) and scale["input_bytes"] == len(scale_data)
                 and type(scale["functions"]) is int and scale["functions"] == 10_000
                 and type(scale["pages"]) is int and scale["pages"] == 79, "R1ReceiptScale")
        for item in [*(evidence[name + ".cached_equal"] for name in fixtures), scale]:
            prepared = item["prepare"]
            old.need(prepared["input"]["sha256"] == item["input_sha256"] and prepared["input"]["size"] == item["input_bytes"]
                     and prepared["runtime"] == {"image": receipt["lock"]["image_id"], "platform": old.PLATFORM,
                                                 "bundle_sha256": receipt["lock"]["bundle_sha256"]}
                     and re.fullmatch(r"[0-9a-f]{64}", prepared["analysis_id"])
                     and type(prepared["artifact_size"]) is int and 0 < prepared["artifact_size"] <= PREPARE_BYTES
                     and type(prepared["elapsed_seconds"]) in (int, float) and math.isfinite(prepared["elapsed_seconds"])
                     and prepared["elapsed_seconds"] >= 0
                     and type(item["elapsed_seconds"]) in (int, float) and math.isfinite(item["elapsed_seconds"])
                     and item["elapsed_seconds"] >= 0, "R1ReceiptMeasurements")
        return True
    except (ValueError, KeyError, TypeError, AttributeError, OverflowError):
        return False


def smoke_passes(receipt):
    try:
        verify_lock(receipt["lock"])
        data, layout = old.elf_code()
        manifest = receipt["manifest"]
        old.need(receipt["schema"] == "reverseai.r1-smoke/1" and receipt["offline"] is True
                 and receipt["platform"] == old.PLATFORM and receipt["sources"] == source_hashes(SMOKE_SOURCE_FILES)
                 and receipt["image_id"] == receipt["lock"]["image_id"]
                 and receipt["input"] == {"sha256": sha256_hex(data), "size": len(data)}
                 and re.fullmatch(r"[0-9a-f]{64}", receipt["lock_sha256"]), "R1SmokeReceiptBinding")
        old.need(set(manifest) == {"format", "input_sha256", "image_id", "bundle_sha256", "size", "artifact_sha256"}
                 and type(manifest["format"]) is int and manifest["format"] == 1
                 and manifest["input_sha256"] == sha256_hex(data) and manifest["image_id"] == receipt["lock"]["image_id"]
                 and manifest["bundle_sha256"] == receipt["lock"]["bundle_sha256"]
                 and type(manifest["size"]) is int and 0 < manifest["size"] <= PREPARE_BYTES
                 and re.fullmatch(r"[0-9a-f]{64}", manifest["artifact_sha256"]), "R1SmokeReceiptManifest")
        rows = receipt["checks"]
        old.need(len(rows) == len(SMOKE_CHECKS) and {row["id"] for row in rows} == set(SMOKE_CHECKS)
                 and all(row["status"] == "passed" for row in rows), "R1SmokeReceiptChecks")
        evidence = {row["id"]: row.get("evidence") for row in rows}
        old.need(evidence["prepare"]["artifact_size"] == manifest["size"]
                 and evidence["prepare"]["artifact_sha256"] == manifest["artifact_sha256"]
                 and type(evidence["prepare"]["elapsed_seconds"]) in (int, float)
                 and math.isfinite(evidence["prepare"]["elapsed_seconds"]) and evidence["prepare"]["elapsed_seconds"] >= 0
                 and evidence["restore.export_program"]["functions"] == 4
                 and evidence["restore.export_function"]["entry"] == layout["functions"][0]["entry"]
                 and evidence["restore.reopen"]["functions"] == 1 and evidence["restore.reopen"]["total"] == 4,
                 "R1SmokeReceiptOracle")
        requests, cleanup = receipt["requests"], receipt["cleanup"]
        old.need(len(requests) == len(cleanup) == 4 and len({row["container_id"] for row in cleanup}) == 4
                 and all(re.fullmatch(r"[0-9a-f]{64}", row["container_id"]) and row["verified"] is True
                         and row["staging_removed"] is True for row in cleanup), "R1SmokeReceiptCleanup")
        expected = [("ghidra.prepare", {}), ("ghidra.export_program", PROGRAM_ARGS),
                    ("ghidra.export_function", {"select": "entry", "entry": layout["functions"][0]["entry"], "name": "",
                     "part": "info", "start": 0, "limit": 32, "text_start": 0, "max_chars": 1024}),
                    ("ghidra.functions", {"query": "", "start": 0, "limit": 1})]
        if "replies" in receipt:
            old.need(len(receipt["replies"]) == 3, "R1SmokeReplyFiles")
            for saved, (operation, arguments) in zip(receipt["replies"], expected[1:]):
                request = {"fixture": "elf_code", "input_sha256": sha256_hex(data),
                           "operation": operation, "args": arguments}
                old.need(all(saved[key] == value for key, value in request.items())
                         and saved["file"] == "elf_code." + operation + ".reply.json"
                         and type(saved["bytes"]) is int and 0 < saved["bytes"] <= 262144
                         and re.fullmatch(r"[0-9a-f]{64}", saved["sha256"])
                         and saved["request_sha256"] == sha256_hex(canonical_json(request).encode()), "R1SmokeReplyFiles")
        old.need([(row["operation"], row["args"]) for row in requests] == expected
                 and all(row["probe"] is None and type(row["timeout"]) is int and type(row["max_output"]) is int
                         and row["timeout"] == (900 if index == 0 else 240)
                         and row["max_output"] == (PREPARE_BYTES if index == 0 else 262144)
                         and "failure" not in row for index, row in enumerate(requests)), "R1SmokeReceiptRequests")
        return True
    except (ValueError, KeyError, TypeError, AttributeError, OverflowError):
        return False


def smoke_main(args):
    receipt = {"schema": "reverseai.r1-smoke/1", "offline": True, "platform": old.PLATFORM,
               "checks": [], "cleanup": [], "requests": []}
    interrupted = False
    try:
        old.need(args.route is None and args.lock.is_file() and not args.lock.is_symlink()
                 and not args.receipt.exists() and not args.receipt.is_symlink(), "R1SmokeOutputs")
        raw = args.lock.read_bytes()
        old.need(len(raw) <= 16384, "R1LockTooLarge")
        lock = old.decode(raw)
        verify_lock(lock)
        receipt.update(lock=lock, lock_sha256=sha256_hex(raw), sources=source_hashes(SMOKE_SOURCE_FILES))
        from reverseai import contained
        with tempfile.TemporaryDirectory(prefix="reverseai-r1-smoke-", dir=contained.STAGING_ROOT) as folder:
            options = {"reply_dir": args.reply_dir} if args.reply_dir is not None else {}
            native = R1Verifier(contained, lock, receipt, folder, **options)
            native.smoke()
            receipt["requests"] = native.requests
        old.need(receipt["sources"] == source_hashes(SMOKE_SOURCE_FILES), "R1SourcesChanged")
        receipt["checks"].append({"id": "sources", "status": "passed"})
    except KeyboardInterrupt:
        interrupted = True
        receipt["checks"].append({"id": "interrupted", "status": "failed"})
    except Exception as error:
        receipt["checks"].append({"id": "controller", "status": "failed", "reason":
            str(error) if isinstance(error, old.VerificationError) else type(error).__name__})
    recorded = {row["id"] for row in receipt["checks"]}
    receipt["checks"].extend({"id": name, "status": "not_run"} for name in SMOKE_CHECKS if name not in recorded)
    receipt["passed"] = smoke_passes(receipt)
    try:
        old.write_receipt(args.receipt, receipt)
    except (OSError, ValueError):
        print("R1 smoke receipt refused", file=sys.stderr)
        return 1
    print("R1 smoke " + ("passed" if receipt["passed"] else "failed"), file=sys.stderr)
    return 130 if interrupted else 0 if receipt["passed"] else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", required=True, action="store_true")
    parser.add_argument("--route", choices=("A", "B"))
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--reply-dir", type=Path, help="New private directory for bounded raw smoke replies")
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    args = parser.parse_args(argv)
    if args.smoke:
        return smoke_main(args)
    if args.reply_dir is not None:
        parser.error("--reply-dir requires --smoke")
    if args.route is None:
        parser.error("full verification requires --route A|B")
    receipt = {"schema": "reverseai.r1-runtime/1", "platform": old.PLATFORM, "offline": True,
               "checks": [], "cleanup": [], "requests": []}
    interrupted = False
    try:
        old.need(not args.lock.exists() and not args.lock.is_symlink() and not args.receipt.exists()
                 and not args.receipt.is_symlink() and args.lock != args.receipt, "R1NewOutputRequired")
        receipt["sources"] = source_hashes()
        from reverseai import contained
        preflight(contained)
        builder = importlib.import_module("tools.build_ghidra_image")
        # No shell, download switch, alternate parent or unreviewed build command is exposed.
        with redirect_stdout(io.StringIO()):
            code = builder.main(["revise", "--route", args.route, "--lock", str(args.lock)])
        old.need(type(code) is int and code == 0, "R1RevisionFailed")
        raw = args.lock.read_bytes()
        old.need(len(raw) <= 16_384, "R1LockTooLarge")
        lock = old.decode(raw)
        verify_lock(lock)
        receipt.update(lock=lock, lock_sha256=sha256_hex(raw))
        receipt["checks"].append({"id": "revision", "status": "passed", "evidence": {
            "route": args.route, "parent_image_id": lock["parent_image_id"], "bundle_sha256": lock["bundle_sha256"]}})
        with tempfile.TemporaryDirectory(prefix="reverseai-r1-proof-", dir=contained.STAGING_ROOT) as folder:
            native = R1Verifier(contained, lock, receipt, folder)
            native.run_r1()
            receipt["requests"] = native.requests
        old.need(receipt["sources"] == source_hashes(), "R1SourcesChanged")
        receipt["checks"].append({"id": "sources", "status": "passed"})
    except KeyboardInterrupt:
        interrupted = True
        receipt["checks"].append({"id": "interrupted", "status": "failed"})
    except (Exception, SystemExit) as error:
        receipt["checks"].append({"id": "controller", "status": "failed", "reason":
            str(error) if isinstance(error, old.VerificationError) else type(error).__name__})
    recorded = {row["id"] for row in receipt["checks"]}
    receipt["checks"].extend({"id": name, "status": "not_run"} for name in REQUIRED_CHECKS if name not in recorded)
    receipt["passed"] = receipt_passes(receipt)
    try:
        old.write_receipt(args.receipt, receipt)
    except (OSError, ValueError):
        print("R1 native receipt refused", file=sys.stderr)
        return 1
    print("R1 native proof " + ("passed" if receipt["passed"] else "failed"), file=sys.stderr)
    return 130 if interrupted else 0 if receipt["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
