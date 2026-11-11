"""R1 native-controller unit fakes. No Docker, probes or generated inputs are executed."""

import copy
import io
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import threading
import types
import unittest
from unittest.mock import Mock, patch

from reverseai import contained
from reverseai.contract import canonical_json, sha256_hex
from tests import verify_m2_runtime as old, verify_r1_runtime as verifier
from tests.fixtures_scale import elf_scale
from tests.test_verify_m2_runtime import GhidraFakeBoundary, ghidra_lock_fixture, ghidra_probe_fixture, image_fixture


def r7_lock():
    return {**ghidra_lock_fixture(), "adapter_version": old.GHIDRA_R7_VERSION,
            "parent_image_id": old.GHIDRA_PARENT_IMAGE_ID, "bundle_sha256": old.ghidra_bundle_hash(), "cache_format": 1}


class FakeBoundary(GhidraFakeBoundary):
    GHIDRA_PREPARE_WALL_SECONDS, GHIDRA_PREPARE_MAX_BYTES = 900, 64 * 1024**2
    default_lock = staticmethod(lambda tool: None)

    class ContainedTimeout(GhidraFakeBoundary.ContainedError, TimeoutError):
        pass

    @staticmethod
    def resource_profile(operation):
        return {"pids": 256, "memory": "2g", "cpus": 2, "tmpfs": "/tmp:rw,noexec,nosuid,nodev,size=512m",
                "wall_seconds": 900 if operation == "ghidra.prepare" else 240}

    def __init__(self):
        super().__init__()
        self.prepare_calls, self.projects = [], []
        self.prepare_error = None
        boundary = self
        class Executor:
            def __init__(self, lock, *, runner, prepare_runner, staging_root, **kwargs):
                self.lock, self.runner, self.prepare_runner, self.root = lock, runner, prepare_runner, staging_root

            def available(self):
                return True

            def _call(self, data, operation, args, project=None, sink=None):
                with tempfile.TemporaryDirectory(dir=self.root) as folder:
                    Path(folder, "input").write_bytes(data)
                    if project is not None:
                        project.stage(folder)
                        boundary.projects.append((dict(project.manifest), Path(folder, "project.tar").read_bytes(),
                                                  json.loads(Path(folder, "cache.json").read_bytes())))
                    argv = boundary.build_argv(self.lock["image_id"], "reverseai-unit", folder, operation, args)
                    if sink is not None:
                        return self.prepare_runner(argv, sink, timeout=900)
                    return self.runner(argv, timeout=240, max_output=262144)

            def run(self, operation, args, data, digest, *, project=None):
                if sha256_hex(data) != digest:
                    raise AssertionError("fake snapshot mismatch")
                return self._call(data, operation, args, project=project)

            def prepare(self, data, digest, sink):
                if sha256_hex(data) != digest:
                    raise AssertionError("fake snapshot mismatch")
                return self._call(data, "ghidra.prepare", {}, sink=sink)
        self.DockerExecutor = Executor

    def run_prepare_bounded(self, argv, sink, *, timeout):
        self.prepare_calls.append((list(argv), timeout))
        if self.prepare_error is not None:
            raise self.prepare_error
        sink.write(self.output)


def page_report(data, functions, start, *, analysis_id="f" * 64, total=None):
    digest = sha256_hex(data)
    total = len(functions) if total is None else total
    selected = functions[start:start + 128]
    metadata = {"kind": "export_page", "scope": "program", "part": "functions", "entry": None,
                "status": "ok", "start": start, "total": total, "count": len(selected),
                "next_start": start + len(selected) if start + len(selected) < total else None,
                "analysis_id": analysis_id}
    evidence = [{"id": "ev-meta", "input_sha256": digest, "location": {"offset": 0, "length": 1},
                 "observation": metadata}]
    for index, function in enumerate(selected, start):
        evidence.append({"id": f"ev-{index}", "input_sha256": digest,
                         "location": {"offset": function["offset"], "length": min(16, function["size"])},
                         "observation": {"kind": "function_export", "index": index, "entry": function["entry"],
                                         "name": function["name"], "size": function["size"], "analysis_id": analysis_id}})
    return {"results": [{"role": "code", "status": "ok", "errors": [], "evidence": evidence,
                         "findings": [{"claim_key": "code.export_page", "verdict": "derived", "value": metadata}]}]}


def function_report(data, entry, part, start, total, records, *, status="ok", count=None):
    count = len(records) if count is None else count
    page = {"kind": "export_page", "scope": "function", "part": part, "entry": entry, "status": status,
            "start": start, "total": total, "count": count, "next_start": start + count if start + count < total else None,
            "analysis_id": "f" * 64}
    evidence = [{"input_sha256": sha256_hex(data), "location": {"offset": 0, "length": 1}, "observation": page}]
    evidence.extend({"input_sha256": sha256_hex(data), "location": location, "observation": {**value, "analysis_id": "f" * 64}}
                    for location, value in records)
    return {"results": [{"role": "code", "status": "ok", "errors": [], "evidence": evidence,
                          "findings": [{"claim_key": "code.export_page", "verdict": "derived", "value": page}]}]}


class SourcePins(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.source = Path(self.folder.name)
        self.shared = self.source / "shared-staging"
        self.shared.mkdir(mode=0o700)
        staging = patch.object(contained, "STAGING_ROOT", self.shared)
        staging.start()
        self.addCleanup(staging.stop)
        for name in old.GHIDRA_BUNDLE_FILES:
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("reviewed " + name)
        self.pins = patch.object(old, "GHIDRA_SOURCE", self.source)
        self.pins.start()
        self.addCleanup(self.pins.stop)

    def test_r6_stays_exact_and_r7_requires_nine_exact_bound_keys(self):
        old.verify_ghidra_lock(ghidra_lock_fixture())
        old.verify_ghidra_lock(r7_lock())
        verifier.verify_lock(r7_lock())
        self.assertEqual(old.lock_options("ghidra", r7_lock()), {"adapter_version": "12.1.4-r7"})
        self.assertEqual(old.lock_options("ghidra", ghidra_lock_fixture()), {"adapter_version": "12.1.4-r6"})
        with self.assertRaises(old.VerificationError):
            verifier.verify_lock(ghidra_lock_fixture())
        for key in r7_lock():
            changed = r7_lock()
            del changed[key]
            with self.subTest(key=key), self.assertRaises(old.VerificationError):
                old.verify_ghidra_lock(changed)
        for key, value in (("adapter_version", "12.1.4-r8"), ("adapter_version", "12.1.4-r6"),
                           ("cache_format", True), ("cache_format", 2), ("bundle_sha256", "0" * 64),
                           ("unexpected", True)):
            with self.subTest(key=key, value=value), self.assertRaises(old.VerificationError):
                old.verify_ghidra_lock({**r7_lock(), key: value})
        for parent in (None, "sha256:" + "a" * 64):
            lock = {**r7_lock(), "parent_image_id": parent}
            old.verify_ghidra_lock(lock)
            with self.assertRaises(old.VerificationError):
                verifier.verify_lock(lock)

    def test_source_change_missing_file_or_symlink_invalidates_revision(self):
        lock = r7_lock()
        path = self.source / old.GHIDRA_BUNDLE_FILES[0]
        path.write_text("changed")
        with self.assertRaises(old.VerificationError):
            old.verify_ghidra_lock(lock)
        path.unlink()
        with self.assertRaises(old.VerificationError):
            old.ghidra_bundle_hash()
        path.symlink_to(self.source / old.GHIDRA_BUNDLE_FILES[1])
        with self.assertRaises(old.VerificationError):
            old.ghidra_bundle_hash()


class HarnessTests(SourcePins):
    def setUp(self):
        super().setUp()
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        self.boundary = FakeBoundary()
        self.receipt = {"checks": [], "cleanup": []}
        self.native = verifier.R1Verifier(self.boundary, r7_lock(), self.receipt, self.work.name)
        self.native.image = image_fixture()

    def test_both_profiles_are_fixed_and_checked_without_boundary_calls(self):
        verifier.verify_profiles(self.boundary)
        for field, value in (("wall_seconds", 901), ("pids", 257), ("memory", "3g"), ("cpus", 2.0)):
            original = self.boundary.resource_profile
            with patch.object(self.boundary, "resource_profile", side_effect=lambda operation, f=field, v=value:
                              {**original(operation), f: v} if operation == "ghidra.prepare" else original(operation)):
                with self.assertRaises(old.VerificationError):
                    verifier.verify_profiles(self.boundary)
        self.assertEqual(self.boundary.calls, [])

    def test_prepare_uses_true_stream_wrapper_and_stopped_inspection_and_cleanup(self):
        self.boundary.output = canonical_json(ghidra_probe_fixture("runtime_identity")).encode()
        result = self.native.prepare_control("runtime_identity", b"fixture")
        self.assertEqual(result["uid"], 65534)
        self.assertEqual(self.native.requests, [{"operation": "ghidra.prepare", "args": {}, "probe": "runtime_identity",
                                               "timeout": 900, "max_output": 64 * 1024**2,
                                               "cache_files": {"project.tar": False, "cache.json": False},
                                               "elapsed_seconds": self.native.requests[0].get("elapsed_seconds"),
                                               "probe_evidence": result}])
        self.assertGreaterEqual(self.native.requests[0]["elapsed_seconds"], 0)
        self.assertEqual(self.boundary.prepare_calls[0][1], 900)
        self.assertEqual(self.boundary.prepare_calls[0][0][:3], ["docker", "start", "--attach"])
        created = next(argv for argv, _, _ in self.boundary.calls if argv[:2] == ["docker", "create"])
        self.assertIn("--read-only", created)
        self.assertEqual(created[created.index("--pull") + 1], "never")
        self.assertEqual(created[created.index("--entrypoint") + 1], "python3")
        self.assertEqual(self.native.inspected, 1)
        self.assertTrue(self.receipt["cleanup"][0]["verified"])
        self.assertTrue(self.receipt["cleanup"][0]["staging_removed"])

    def test_fake_timeout_preserves_the_real_oserror_inheritance(self):
        self.assertIsInstance(self.boundary.ContainedTimeout("WorkerTimeout"), self.boundary.ContainedError)
        self.assertIsInstance(self.boundary.ContainedTimeout("WorkerTimeout"), TimeoutError)
        self.assertIsInstance(self.boundary.ContainedTimeout("WorkerTimeout"), OSError)

    def wall_control(self, elapsed):
        clock = Mock(return_value=100.0)
        def expire(argv, sink, *, timeout):
            self.assertTrue(self.boundary.running_observed.wait(timeout=1))
            clock.return_value += elapsed
            raise self.boundary.ContainedTimeout("WorkerTimeout")
        with patch.object(verifier.time, "monotonic", clock), \
                patch.object(self.boundary, "run_prepare_bounded", side_effect=expire):
            return self.native.record("prepare.wall", lambda: self.native.prepare_control("wall", b"fixture"))

    def test_prepare_wall_records_elapsed_and_the_observed_probe(self):
        self.assertTrue(self.wall_control(900.1))
        row = self.native.requests[0]
        self.assertAlmostEqual(row.get("elapsed_seconds", -1), 900.1)
        self.assertEqual(row.get("probe_evidence"), self.receipt["checks"][0]["evidence"])
        self.assertEqual(row["failure"], "WorkerTimeout")
        self.assertTrue(row["probe_evidence"]["running_observed"])
        self.assertTrue(self.receipt["cleanup"][0]["verified"])
        self.assertTrue(self.receipt["cleanup"][0]["staging_removed"])

    def test_failed_wall_keeps_its_short_elapsed_time_and_probe(self):
        self.assertFalse(self.wall_control(240.1))
        row = self.native.requests[0]
        self.assertEqual(self.receipt["checks"][0]["reason"], "R1PrepareWallNotObserved")
        self.assertAlmostEqual(row.get("elapsed_seconds", -1), 240.1)
        self.assertAlmostEqual(row.get("probe_evidence", {}).get("elapsed", -1), 240.1)

    def test_failed_prepare_keeps_elapsed_with_explicit_missing_probe(self):
        clock = Mock(return_value=100.0)
        def fail(argv, sink, *, timeout):
            clock.return_value = 100.25
            raise self.boundary.ContainedError("WorkerProcessError")
        with patch.object(verifier.time, "monotonic", clock), \
                patch.object(self.boundary, "run_prepare_bounded", side_effect=fail):
            self.assertFalse(self.native.record("prepare.wall", lambda: self.native.prepare_control("wall", b"fixture")))
        row = self.native.requests[0]
        self.assertEqual(row.get("elapsed_seconds"), .25)
        self.assertIn("probe_evidence", row)
        self.assertIsNone(row["probe_evidence"])
        self.assertEqual(row["failure"], "WorkerProcessError")

    def test_failed_prepare_validation_keeps_the_received_probe(self):
        evidence = {**ghidra_probe_fixture("runtime_identity"), "uid": 0}
        self.boundary.output = canonical_json(evidence).encode()
        self.assertFalse(self.native.record("prepare.runtime_identity",
                                          lambda: self.native.prepare_control("runtime_identity", b"fixture")))
        row = self.native.requests[0]
        self.assertEqual(row.get("probe_evidence"), evidence)
        self.assertIsInstance(row.get("elapsed_seconds"), float)

    def test_query_control_records_its_probe_and_elapsed_time(self):
        evidence = ghidra_probe_fixture("runtime_identity")
        self.boundary.output = canonical_json(evidence).encode()
        raw = self.native.invoke(b"fixture", "ghidra.analyze", old.ghidra_args(), probe="runtime_identity")
        row = self.native.requests[0]
        self.assertEqual(old.decode(raw), evidence)
        self.assertEqual(row.get("probe_evidence"), evidence)
        self.assertIsInstance(row.get("elapsed_seconds"), float)
        self.assertGreaterEqual(row["elapsed_seconds"], 0)

    def test_ordinary_query_records_elapsed_without_probe_evidence(self):
        self.native.invoke(b"fixture", "ghidra.analyze", old.ghidra_args())
        row = self.native.requests[0]
        self.assertIsInstance(row.get("elapsed_seconds"), float)
        self.assertGreaterEqual(row["elapsed_seconds"], 0)
        self.assertNotIn("probe_evidence", row)

    def test_request_records_cache_files_observed_in_the_actual_snapshot(self):
        data = b"fixture"
        self.native.invoke(data, "ghidra.analyze", old.ghidra_args())
        self.assertEqual(self.native.requests[-1].get("cache_files"), {"project.tar": False, "cache.json": False})
        project = verifier.MemoryProject(verifier.empty_project(data), data, self.native.lock)
        self.native.invoke(data, "ghidra.analyze", old.ghidra_args(), project=project)
        self.assertEqual(self.native.requests[-1].get("cache_files"), {"project.tar": True, "cache.json": True})

    def test_public_query_refuses_a_code_role_error_even_when_cli_exits_zero(self):
        sample = Path(self.work.name, "fixture.bin")
        sample.write_bytes(b"fixture")
        def public(argv, cache):
            self.native.requests.append({"operation": "ghidra.analyze", "args": old.ghidra_args()})
            output = Path(argv[argv.index("--out") + 1])
            output.mkdir()
            report = {"results": [{"role": "code", "status": "error", "errors": ["WorkerProcessError"],
                                   "findings": [], "evidence": []}]}
            (output / "report.json").write_text(canonical_json(report))
        with patch.object(self.native, "public_call", side_effect=public), self.assertRaises(old.VerificationError):
            self.native.public_query(sample, sample.parent / "cache")

    def test_cached_equality_requires_fresh_absence_and_cached_presence(self):
        data, layout = old.elf_code()
        for fault in (None, "fresh", "cached", "partial", "total"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(dir=self.work.name) as folder:
                self.native.folder = Path(folder)
                self.native.requests.clear()
                prepared = False
                def prepare(sample, cache, *, state):
                    nonlocal prepared
                    if state == "created":
                        self.native.requests.append({"operation": "ghidra.prepare"})
                    prepared = True
                    return {"analysis_id": "f" * 64}
                def query(sample, cache, name=None, args=None):
                    present = prepared
                    if name is None and fault in ("fresh", "cached"):
                        present = fault == "fresh"
                    files = {"project.tar": present, "cache.json": present}
                    if prepared and name is None and fault == "partial":
                        files["cache.json"] = False
                    self.native.requests.append({"operation": "ghidra.analyze" if name is None else "ghidra.export_program",
                                                 "cache_files": files})
                    report = page_report(data, layout["functions"] if name is None or args["part"] in ("functions", "calls") else [], 0)
                    if name is not None:
                        report["results"][0]["evidence"][0]["observation"]["part"] = args["part"]
                        if fault == "total" and args["part"] == "functions":
                            page = report["results"][0]["evidence"][0]["observation"]
                            report["results"][0]["evidence"].pop()
                            page.update(total=3, count=3, next_start=None)
                    return report
                with patch.object(self.native, "public_prepare", side_effect=prepare), \
                        patch.object(self.native, "public_query", side_effect=query):
                    if fault is None:
                        value = self.native.cached_fixture("elf_code", data)
                        self.assertEqual(value.get("cache_requests"), {"fresh": 1, "cached": 1, "program": 4})
                        self.assertEqual(value.get("program_totals"), {"functions": 4, "calls": 4, "references": 0, "strings": 0})
                    else:
                        with self.assertRaises(old.VerificationError):
                            self.native.cached_fixture("elf_code", data)

    def test_cleanup_error_cannot_replace_the_attached_worker_failure(self):
        self.boundary.prepare_error = self.boundary.ContainedError("WorkerOutputLimit")
        evidence = self.native.prepare_control("stdout", b"fixture")
        with patch.object(self.boundary, "run_bounded", side_effect=self.boundary.ContainedError("WorkerProcessError")):
            with self.assertRaises(self.boundary.ContainedError):
                self.native.runner(["docker", "kill", "reverseai-unit"], timeout=5, max_output=256)
        self.assertEqual(self.native.requests[0]["failure"], "WorkerOutputLimit")
        self.assertEqual(self.native.requests[0].get("probe_evidence"), evidence)

    def test_prepare_cap_plus_one_is_fixed_and_failure_is_observed_at_real_drain_seam(self):
        self.boundary.prepare_error = self.boundary.ContainedError("WorkerOutputLimit")
        result = self.native.prepare_control("stdout", b"fixture")
        self.assertEqual(result["max_output"], 64 * 1024**2)
        self.assertEqual(self.native.requests[0]["failure"], "WorkerOutputLimit")
        self.native.active, self.native.stream = "stdout", io.BytesIO()
        source = self.native.control_code()
        self.assertIn(str(64 * 1024**2 + 1), source)
        compile(source, "trusted-prepare-flood", "exec")
        self.native.active = "wall"
        self.assertIn("915", self.native.control_code())
        self.native.stream = None
        self.assertIn("262145", old.probe_code("stdout", tool="ghidra"))

    def test_new_fixed_probe_sources_compile_but_are_never_run(self):
        for name in ("cache_write", "program_no_jvm"):
            self.native.active = name
            source = self.native.control_code()
            compile(source, "trusted-r1-" + name, "exec")
            if name == "program_no_jvm":
                self.assertIn("subprocess.Popen=deny", source)
                self.assertIn("w.reply(", source)
                self.assertNotIn("w.export_rows(", source)
        self.native.active = "arbitrary;import os"
        with self.assertRaises(old.VerificationError):
            self.native.control_code()

    def test_program_no_jvm_control_executes_reply_with_process_launches_denied(self):
        self.native.active = "program_no_jvm"
        source = self.native.control_code()
        data = b"trusted inert fixture"
        reply = {"protocol": "reverseai.worker/1", "status": "ok",
                 "snapshot_sha256": sha256_hex(data), "observations": []}
        worker = types.SimpleNamespace(reply=Mock(return_value=reply),
                                       export_rows=Mock(side_effect=AssertionError("ReplyBypassed")))
        spec = types.SimpleNamespace(loader=types.SimpleNamespace(exec_module=Mock()))
        output, namespace = io.StringIO(), {}
        with patch.object(verifier.importlib.util, "spec_from_file_location", return_value=spec), \
                patch.object(verifier.importlib.util, "module_from_spec", return_value=worker), \
                patch.object(Path, "read_bytes", return_value=data), \
                patch.object(verifier.subprocess, "Popen"), verifier.redirect_stdout(output):
            exec(compile(source, "trusted-r1-program-no-jvm", "exec"), namespace)
            with self.assertRaisesRegex(AssertionError, "UnexpectedProcess"):
                verifier.subprocess.Popen(["java"])
        worker.reply.assert_called_once()
        argv, received = worker.reply.call_args.args
        self.assertEqual(argv[0], "ghidra.export_program")
        self.assertEqual(json.loads(argv[1]), verifier.PROGRAM_ARGS)
        self.assertEqual(received, data)
        worker.export_rows.assert_not_called()
        spec.loader.exec_module.assert_called_once_with(worker)
        self.assertEqual(json.loads(output.getvalue()), {"launches": 0, "reply": reply})

    def test_program_no_jvm_validates_standard_reply_and_functions_metadata(self):
        from reverseai import ghidra_cache

        data, layout = old.elf_code()
        report = page_report(data, layout["functions"], 0)
        observations = [{"location": row["location"], "value": {
            key: value for key, value in row["observation"].items() if key != "analysis_id"}}
            for row in report["results"][0]["evidence"]]
        observations[0]["location"] = {"offset": 0, "length": min(64, len(data))}
        reply = {"protocol": "reverseai.worker/1", "status": "ok",
                 "snapshot_sha256": sha256_hex(data), "observations": observations}
        value = {"launches": 0, "reply": reply}
        with patch.object(ghidra_cache, "CacheStore"), \
                patch.object(self.native, "invoke", return_value=canonical_json(value).encode()) as invoke:
            try:
                result = self.native.program_no_jvm()
            except old.VerificationError as error:
                self.fail("A valid ordinary worker reply was refused: " + str(error))
        self.assertEqual(result, {"process_launches": 0, "rows": 5, "functions": 4,
                                 "input_sha256": sha256_hex(data),
                                 "reply_protocol": "reverseai.worker/1", "reply_status": "ok"})
        self.assertEqual(invoke.call_args.args, (data, "ghidra.export_program", verifier.PROGRAM_ARGS))
        self.assertEqual(invoke.call_args.kwargs["probe"], "program_no_jvm")
        mutations = [(("launches",), True), (("launches",), 1),
                     (("reply", "protocol"), "other/1"), (("reply", "status"), "error"),
                     (("reply", "snapshot_sha256"), "0" * 64), (("reply", "observations"), [])]
        mutations += [(("reply", "observations", 0, "value", key), changed) for key, changed in (
            ("scope", "function"), ("part", "strings"), ("entry", 1), ("status", "error"),
            ("start", True), ("start", 1), ("total", True), ("total", 3),
            ("count", True), ("count", 3), ("next_start", 4))]
        mutations += [(("reply", "observations", 1, "value", "kind"), "function"),
                      (("reply", "observations", 1, "value", "index"), True)]
        for path, changed in mutations:
            invalid = copy.deepcopy(value)
            target = invalid
            for part in path[:-1]:
                target = target[part]
            target[path[-1]] = changed
            with self.subTest(path=path, changed=changed), patch.object(ghidra_cache, "CacheStore"), \
                    patch.object(self.native, "invoke", return_value=canonical_json(invalid).encode()), \
                    self.assertRaises((old.VerificationError, old.ContractError)):
                self.native.program_no_jvm()

    def test_restore_checksum_control_changes_only_checksum_and_worker_rejects_it(self):
        from tests.test_ghidra_worker_logic import worker

        data = b"trusted inert fixture"
        valid = verifier.empty_project(data)
        broken = verifier.empty_project(data, "checksum")
        changes = [index for index, pair in enumerate(zip(valid, broken)) if pair[0] != pair[1]]
        self.assertEqual(len(valid), len(broken))
        self.assertEqual(len(changes), 1)
        self.assertIn(changes[0], range(148, 156))
        self.assertIn(valid[changes[0]], b"01234567")
        self.assertIn(broken[changes[0]], b"01234567")
        repaired = broken[:148] + valid[148:156] + broken[156:]
        self.assertEqual(repaired, valid)
        module = worker.cache_module()
        lock = r7_lock()
        for label, body in (("valid", valid), ("checksum", broken), ("repaired", repaired)):
            snapshot = Path(self.work.name, "checksum-" + label)
            snapshot.mkdir()
            verifier.MemoryProject(body, data, lock).stage(snapshot)
            work = Path(self.work.name, "restore-" + label)
            with self.subTest(label=label), patch.object(worker, "SNAPSHOT", snapshot / "input"), \
                    patch.object(worker, "WORK", work), patch.object(worker, "cache_module", return_value=module), \
                    patch.object(worker, "bundle_hash", return_value=lock["bundle_sha256"]), \
                    patch.object(module, "_name", wraps=module._name) as names, \
                    patch.object(module, "_octal", wraps=module._octal) as octal:
                if label == "checksum":
                    with self.assertRaises(worker.InvalidCachedProject):
                        worker.restore_project(data)
                    octal.assert_called_once_with(broken[148:156])
                    names.assert_not_called()
                    self.assertFalse((work / "restored").exists())
                else:
                    restored = worker.restore_project(data)
                    self.assertEqual(restored, work / "restored/cache")
                    self.assertEqual((restored / "project/reverseai.gpr").read_bytes(),
                                     b"not opened by table queries")
                    self.assertGreater(names.call_count, 0)

    def test_public_cli_injection_uses_same_real_executor_and_isolates_cache_root(self):
        import reverseai
        from reverseai import cli
        from reverseai.tools import ghidra_tool
        cache = types.ModuleType("reverseai.ghidra_cache")
        cache.default_root = lambda: Path("/unselected")
        chosen = Path(self.work.name, "cache")
        def public(argv):
            self.assertEqual(cache.default_root(), chosen)
            self.assertEqual(ghidra_tool.DEFAULT_LOCK, self.native.lock)
            executor = ghidra_tool.DockerExecutor(ghidra_tool.DEFAULT_LOCK, adapter_version="12.1.4-r7")
            self.assertIsInstance(executor, self.native.true_executor)
            executor.run("ghidra.analyze", old.ghidra_args(), b"fixture", sha256_hex(b"fixture"))
            print("static CLI receipt")
            return 0
        with patch.dict(sys.modules, {"reverseai.ghidra_cache": cache}), \
                patch.object(reverseai, "ghidra_cache", cache, create=True), patch.object(cli, "main", side_effect=public):
            output = self.native.public_call(["analyze", "trusted-fixture"], chosen)
        self.assertEqual(output, "static CLI receipt\n")
        self.assertEqual(self.native.requests[0]["operation"], "ghidra.analyze")
        self.assertTrue(self.receipt["cleanup"][0]["staging_removed"])

    def test_unknown_operation_arguments_and_widened_limits_are_refused_before_create(self):
        for operation, args in (("ghidra.shell", {}), ("ghidra.prepare", {"timeout": 900}),
                                ("ghidra.export_program", {**verifier.PROGRAM_ARGS, "path": "/outside"})):
            argv = self.boundary.build_argv(self.native.lock["image_id"], "reverseai-unit", "/snapshot-test", operation, args)
            with self.subTest(operation=operation), self.assertRaises(old.VerificationError):
                self.native.runner(argv, timeout=240, max_output=262144)
        self.assertFalse(any(argv[:2] == ["docker", "create"] for argv, _, _ in self.boundary.calls))

    def test_restore_negatives_reach_worker_with_correct_host_manifest_and_body_hash(self):
        data = b"fixture"
        self.boundary.output = canonical_json({"protocol": "reverseai.worker/1", "status": "error",
            "snapshot_sha256": sha256_hex(data), "error": "InvalidCachedProject"}).encode()
        for variant in verifier.RESTORE_CASES:
            result = self.native.restore(data, variant)
            self.assertTrue(result["refused"])
            manifest, body, staged_manifest = self.boundary.projects[-1]
            self.assertEqual(manifest, staged_manifest)
            self.assertEqual(manifest["artifact_sha256"], sha256_hex(body))
            self.assertEqual(manifest["size"], len(body))
            self.assertEqual(set(manifest), {"format", "input_sha256", "image_id", "bundle_sha256", "size", "artifact_sha256"})
        self.boundary.output = b'{"status":"error","error":"anything"}'
        with self.assertRaises(old.VerificationError):
            self.native.restore(data, "traversal")

    def test_scale_enumerates_all_10000_functions_and_refuses_false_completeness(self):
        data, layout = elf_scale()
        prepared = {"analysis_id": "f" * 64, "artifact_size": 123, "elapsed_seconds": .1}
        def query(sample, cache, name, args):
            return page_report(data, layout["functions"], args["start"])
        with patch.object(self.native, "public_prepare", return_value=prepared) as prepare, \
                patch.object(self.native, "public_query", side_effect=query) as pages:
            result = self.native.scale()
        self.assertEqual((result["functions"], result["pages"]), (10_000, 79))
        prepare.assert_called_once()
        self.assertEqual(pages.call_count, 79)
        self.assertEqual(result["input_sha256"], sha256_hex(data))
        # A separate folder lets the same proof reject one dishonest native page.
        (Path(self.work.name) / "scale/fixture.bin").unlink()
        (Path(self.work.name) / "scale").rmdir()
        with patch.object(self.native, "public_prepare", return_value=prepared), \
                patch.object(self.native, "public_query", return_value=page_report(data, layout["functions"], 0, total=9999)), \
                self.assertRaises(old.VerificationError):
            self.native.scale()

    def test_function_parts_pseudocode_routes_and_not_found_use_real_shape_oracles(self):
        data, layout = old.elf_refs()
        function = next(row for row in layout["functions"] if row["name"] == "describe")
        anchor = {"offset": function["offset"], "length": min(16, function["size"])}
        text = "Derived statement;\n" * 10
        digest = sha256_hex(text.encode())
        def query(sample, cache, name, args):
            self.native.requests.append({"operation": "ghidra.pseudocode" if name == "procedure_pseudo_code" else "ghidra.export_function"})
            part = "pseudocode" if name == "procedure_pseudo_code" else args["part"]
            if args["entry"] == 2**64 - 1:
                return function_report(data, None, part, 0, 0, [], status="not_found")
            if part == "pseudocode":
                start = args.get("text_start", 0)
                piece = text[start:start + 64]
                value = {"kind": "pseudocode_page", "entry": function["entry"], "start": start, "total": len(text),
                         "text": piece, "text_sha256": digest, "status": "ok",
                         "next_start": start + len(piece) if start + len(piece) < len(text) else None}
                return function_report(data, function["entry"], part, start, len(text), [(anchor, value)], count=len(piece))
            records = []
            if part == "assembly":
                records = [({"offset": function["offset"] + delta, "length": length},
                    {"kind": "instruction_export", "index": index, "from": function["entry"],
                     "at": function["entry"] + delta, "length": length})
                    for index, (delta, length) in enumerate(function["instructions"])]
            else:
                kind = {"info": "function_info", "callees": "call_export", "callers": "call_export",
                        "references": "reference_export", "strings": "string_export"}[part]
                records = [(anchor, {"kind": kind}) for _ in range({"strings": 2, "references": 5}.get(part, 1))]
                if part == "info":
                    records[0][1]["totals"] = {"assembly": 6, "callees": 1, "callers": 1, "references": 5, "strings": 2}
            return function_report(data, function["entry"], part, 0, len(records), records)
        with patch.object(self.native, "public_query", side_effect=query) as public:
            parts = self.native.function_parts()
            reading = self.native.pseudocode()
            missing = self.native.not_found()
        self.assertEqual(parts["requests"], 7)
        self.assertEqual(reading["characters"], len(text))
        self.assertEqual(reading["text_sha256"], digest)
        self.assertEqual((reading["export_pages"], reading["procedure_pages"]), (3, 3))
        self.assertEqual(missing["rows"], 0)
        self.assertEqual(public.call_count, 14)
        def dishonest(sample, cache, name, args):
            report = query(sample, cache, name, args)
            if args.get("text_start", 0) > 0:
                report["results"][0]["evidence"][1]["observation"]["text_sha256"] = "0" * 64
            return report
        with patch.object(self.native, "public_query", side_effect=dishonest), self.assertRaises(old.VerificationError):
            self.native.pseudocode()
        for bad_part in ("info", "callers", "references"):
            def clipped(sample, cache, name, args):
                report = query(sample, cache, name, args)
                if args["part"] == bad_part:
                    rows = report["results"][0]["evidence"]
                    if bad_part == "info":
                        rows[1]["observation"]["totals"]["references"] -= 1
                    else:
                        rows.pop()
                        rows[0]["observation"]["total"] -= 1
                        rows[0]["observation"]["count"] -= 1
                return report
            with self.subTest(bad_part=bad_part), patch.object(self.native, "public_query", side_effect=clipped), \
                    self.assertRaises(old.VerificationError):
                self.native.function_parts()


class OracleTests(unittest.TestCase):
    def test_scale_is_deterministic_and_declares_exact_named_symbol_and_byte_oracles(self):
        data, layout = elf_scale()
        self.assertEqual(elf_scale()[0], data)
        self.assertEqual(len(layout["functions"]), 10_000)
        self.assertEqual(len({row["entry"] for row in layout["functions"]}), 10_000)
        section_at = struct.unpack_from("<Q", data, 40)[0]
        sym_at, sym_bytes = struct.unpack_from("<QQ", data, section_at + 2 * 64 + 24)
        self.assertEqual(sym_bytes, 24 * 10_001)
        self.assertEqual(struct.unpack_from("<Q", data, sym_at + 24 + 8)[0], layout["functions"][0]["entry"])
        for index in (0, 1, 9999):
            function = layout["functions"][index]
            self.assertEqual(data[function["offset"]:function["offset"] + 6], b"\xb8" + struct.pack("<I", index) + b"\xc3")
        for count in (True, 0, 65_538):
            with self.assertRaises(ValueError):
                elf_scale(count)

    def test_page_oracle_refuses_boolean_counts_no_progress_mixed_ids_or_non_derived_verdicts(self):
        data, layout = elf_scale(3)
        report = page_report(data, layout["functions"], 0)
        page, rows = verifier.validate_page(report, data, "functions", 0)
        self.assertEqual((page["count"], len(rows)), (3, 3))
        for mutate in (lambda r: r["results"][0]["evidence"][0]["observation"].update(count=True),
                       lambda r: r["results"][0]["evidence"][0]["observation"].update(next_start=0),
                       lambda r: r["results"][0]["evidence"][1]["observation"].update(analysis_id="0" * 64),
                       lambda r: r["results"][0]["findings"][0].update(verdict="supported"),
                       lambda r: r["results"][0]["evidence"][1]["location"].update(offset=len(data))):
            changed = copy.deepcopy(report)
            mutate(changed)
            with self.assertRaises(old.VerificationError):
                verifier.validate_page(changed, data, "functions", 0)

    def test_semantic_comparison_keeps_values_locations_and_verdicts(self):
        data, layout = elf_scale(2)
        left = page_report(data, layout["functions"], 0)
        right = page_report(data, layout["functions"], 0, analysis_id="0" * 64)
        self.assertEqual(verifier.semantic_report(left), verifier.semantic_report(right))
        right["results"][0]["findings"][0]["verdict"] = "supported"
        self.assertNotEqual(verifier.semantic_report(left), verifier.semantic_report(right))


class SmokeTests(SourcePins):
    def test_raw_smoke_prepares_once_restores_three_times_and_checks_exact_bytes_and_shapes(self):
        with tempfile.TemporaryDirectory() as folder:
            boundary, lock = FakeBoundary(), r7_lock()
            receipt = {"schema": "reverseai.r1-smoke/1", "offline": True, "platform": old.PLATFORM,
                       "checks": [], "cleanup": [], "lock": lock, "lock_sha256": "a" * 64,
                       "sources": {"trusted": "b" * 64}, "image_id": lock["image_id"]}
            reply_dir = Path(folder) / "replies"
            native = verifier.R1Verifier(boundary, lock, receipt, folder, reply_dir=reply_dir)
            native.image = image_fixture()
            data, layout = old.elf_code()
            def anchor(function):
                return {"offset": function["offset"], "length": function["size"]}
            def reply(rows):
                return canonical_json({"protocol": "reverseai.worker/1", "status": "ok",
                    "snapshot_sha256": sha256_hex(data), "observations": rows}).encode()
            def page(scope, part, entry, count):
                return {"location": {"offset": 0, "length": 64}, "value": {
                    "kind": "export_page", "scope": scope, "part": part, "entry": entry,
                    "status": "ok", "start": 0, "total": count, "count": count, "next_start": None}}
            original = boundary.run_bounded
            creates = 0
            def run(argv, **kwargs):
                nonlocal creates
                if argv[:2] == ["docker", "create"]:
                    creates += 1
                    boundary.CID = f"{creates:064x}"
                    boundary.created_id = (boundary.CID + "\n").encode()
                    boundary.inspect["Id"] = boundary.CID
                    operation = argv[argv.index(lock["image_id"]) + 1]
                    if operation == "ghidra.prepare":
                        boundary.output = b"bounded opaque project stand-in"
                    elif operation == "ghidra.export_program":
                        rows = [page("program", "functions", None, 4)]
                        rows += [{"location": anchor(function), "value": {"kind": "function_export", "index": index,
                            **{key: function[key] for key in ("entry", "size", "name")},
                            "signature": None, "signature_truncated": False, "library_hint": None}}
                            for index, function in enumerate(layout["functions"])]
                        boundary.output = reply(rows)
                    elif operation == "ghidra.export_function":
                        function = layout["functions"][0]
                        boundary.output = reply([page("function", "info", function["entry"], 1), {
                            "location": anchor(function), "value": {"kind": "function_info",
                            **{key: function[key] for key in ("entry", "size", "name")}, "matches": 1,
                            "signature": None, "signature_truncated": False, "library_hint": None,
                            "totals": {"assembly": 6, "callees": 2, "callers": 0, "references": 0, "strings": 0},
                            "pseudocode_status": "not_requested"}}])
                    elif operation == "ghidra.functions":
                        function = layout["functions"][0]
                        boundary.output = reply([{"location": anchor(function), "value": {"kind": "function_row", "index": 0,
                            "total": 4, **{key: function[key] for key in ("entry", "size", "name")}}}])
                    else:
                        self.fail("unexpected smoke operation")
                return original(argv, **kwargs)
            with patch.object(boundary, "run_bounded", side_effect=run), \
                    patch.object(native, "local_daemon", return_value={"os": "linux", "arch": "arm64"}), \
                    patch.object(native, "image_check", return_value={"image_id": lock["image_id"]}):
                native.smoke()
            receipt["checks"].append({"id": "sources", "status": "passed"})
            receipt["requests"] = native.requests
            with patch.object(verifier, "source_hashes", return_value={"trusted": "b" * 64}):
                self.assertTrue(verifier.smoke_passes(receipt), receipt["checks"])
                for mutate in (lambda r: r["checks"].pop(), lambda r: r["requests"].pop(),
                               lambda r: r["manifest"].update(input_sha256="0" * 64),
                               lambda r: r["requests"][0].update(timeout=240),
                               lambda r: r["checks"][2]["evidence"].update(artifact_sha256="0" * 64)):
                    changed = copy.deepcopy(receipt)
                    mutate(changed)
                    self.assertFalse(verifier.smoke_passes(changed))
            self.assertEqual(len(receipt["replies"]), 3)
            self.assertEqual(reply_dir.stat().st_mode & 0o077, 0)
            for saved in receipt["replies"]:
                path = reply_dir / saved["file"]
                self.assertEqual(sha256_hex(path.read_bytes()), saved["sha256"])
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                request = path.with_name(path.name.replace(".reply.json", ".request.json"))
                self.assertEqual(sha256_hex(request.read_bytes()), saved["request_sha256"])
                self.assertEqual(json.loads(request.read_bytes())["fixture"], "elf_code")
            with self.assertRaises(FileExistsError):
                native.save_reply(data, "ghidra.functions", {"query": "", "start": 0, "limit": 1}, b"no overwrite")
            self.assertEqual(len(boundary.prepare_calls), 1)
            self.assertEqual([row["operation"] for row in native.requests],
                             ["ghidra.prepare", "ghidra.export_program", "ghidra.export_function", "ghidra.functions"])
            self.assertEqual(len(boundary.projects), 3)
            self.assertTrue(all(body == b"bounded opaque project stand-in" for _, body, _ in boundary.projects))

    def test_smoke_cli_uses_existing_lock_and_never_calls_revision_builder(self):
        with tempfile.TemporaryDirectory() as folder:
            lock, receipt = Path(folder, "existing.lock"), Path(folder, "receipt.json")
            lock.write_text(canonical_json(r7_lock()))
            fake_native = Mock()
            fake_native.requests = []
            with patch.object(verifier, "source_hashes", return_value={"trusted": "b" * 64}), \
                    patch.object(verifier, "R1Verifier", return_value=fake_native), \
                    patch.object(verifier, "smoke_passes", return_value=False), \
                    patch.object(verifier.importlib, "import_module") as load, patch.object(sys, "stderr", io.StringIO()):
                result = verifier.main(["--offline", "--smoke", "--lock", str(lock), "--receipt", str(receipt)])
            self.assertEqual(result, 1)
            self.assertTrue(receipt.exists())
            load.assert_not_called()
            fake_native.smoke.assert_called_once()


class ReceiptTests(SourcePins):
    def receipt(self):
        lock = r7_lock()
        runtime = {"image": lock["image_id"], "platform": old.PLATFORM, "bundle_sha256": lock["bundle_sha256"]}
        def prepared(data):
            return {"schema": "reverseai.prepare/1", "input": {"sha256": sha256_hex(data), "size": len(data)},
                    "analysis_id": "f" * 64, "state": "created", "runtime": runtime, "cache_format": 1,
                    "artifact_size": 10_240, "elapsed_seconds": .1}
        evidence = {name: None for name in verifier.REQUIRED_CHECKS}
        evidence["revision"] = {"route": "B", "parent_image_id": old.GHIDRA_PARENT_IMAGE_ID,
                                "bundle_sha256": lock["bundle_sha256"]}
        for name, data in old.ghidra_fixtures().items():
            _, layout = getattr(old, name)()
            query_cases = 4 if name in old.GHIDRA_QUERY_FIXTURES else 0
            evidence[name + ".cached_equal"] = {"input_sha256": sha256_hex(data), "input_bytes": len(data),
                "prepare": prepared(data), "fresh_equal_cached": True, "prepare_operations": 1,
                "query_cases": query_cases,
                "cache_requests": {"fresh": 1 + query_cases, "cached": 1 + query_cases, "program": 4},
                "program_totals": verifier.fixture_program_totals(name, data),
                "fresh_semantics_sha256": "a" * 64, "cached_semantics_sha256": "a" * 64, "elapsed_seconds": .2}
        data, _ = elf_scale()
        evidence["scale.10000"] = {"input_sha256": sha256_hex(data), "input_bytes": len(data), "functions": 10_000,
                                   "pages": 79, "prepare": prepared(data), "elapsed_seconds": .5}
        refs, layout = old.elf_refs()
        entry = layout["functions"][-1]["entry"]
        evidence["function.parts"] = {"input_sha256": sha256_hex(refs), "entry": entry, "analysis_id": "f" * 64,
            "totals": {"info": 1, "pseudocode": 130, "assembly": 6, "callees": 1, "callers": 1,
                       "references": 5, "strings": 2}, "requests": 7}
        evidence["function.pseudocode"] = {"input_sha256": sha256_hex(refs), "entry": entry, "analysis_id": "f" * 64,
            "characters": 130, "text_sha256": "b" * 64, "export_pages": 3, "procedure_pages": 3, "requests": 6}
        evidence["function.not_found"] = {"input_sha256": sha256_hex(refs), "analysis_id": "f" * 64, "rows": 0}
        evidence["program.no_jvm"] = {"process_launches": 0, "rows": 5, "functions": 4,
            "input_sha256": sha256_hex(old.elf_code()[0]), "reply_protocol": "reverseai.worker/1", "reply_status": "ok"}
        counts = {("ghidra.prepare", None): 8, ("ghidra.analyze", None): 21, ("ghidra.functions", None): 9,
                  ("ghidra.function", None): 18, ("ghidra.xrefs", None): 9, ("ghidra.export_program", None): 116,
                  ("ghidra.export_function", None): 11, ("ghidra.pseudocode", None): 3,
                  ("ghidra.export_program", "program_no_jvm"): 1, ("ghidra.export_program", "cache_write"): 1,
                  **{(operation, name): 1 for operation in ("ghidra.prepare", "ghidra.analyze") for name in old.CONTROL_NAMES}}
        requests = []
        for (operation, probe), count in counts.items():
            for index in range(count):
                if operation == "ghidra.prepare" or probe is not None and operation == "ghidra.analyze":
                    present = False
                else:
                    present = index >= {"ghidra.analyze": 14, "ghidra.functions": 6,
                                        "ghidra.function": 12, "ghidra.xrefs": 6}.get(operation, 0)
                requests.append({"operation": operation, "probe": probe, "args": {},
                                 "timeout": 900 if operation == "ghidra.prepare" else 240,
                                 "max_output": 64 * 1024**2 if operation == "ghidra.prepare" else 262144,
                                 "cache_files": {"project.tar": present, "cache.json": present}})
        return {"schema": "reverseai.r1-runtime/1", "offline": True, "platform": old.PLATFORM, "lock": lock,
                "lock_sha256": "c" * 64, "image_id": lock["image_id"], "sources": {"trusted": "d" * 64},
                "checks": [{"id": name, "status": "passed", "evidence": evidence[name]} for name in verifier.REQUIRED_CHECKS],
                "requests": requests, "cleanup": [{"container_id": f"{index:064x}", "verified": True, "staging_removed": True}
                                                    for index in range(len(requests))]}

    def test_receipt_requires_actual_counts_profiles_measurements_and_current_sources(self):
        with patch.object(verifier, "source_hashes", return_value={"trusted": "d" * 64}):
            proof = self.receipt()
            self.assertTrue(verifier.receipt_passes(proof))
            mutations = [lambda r: r["checks"].pop(), lambda r: r["checks"].append(r["checks"][0]),
                         lambda r: r["checks"][0].update(status="not_run"), lambda r: r["requests"].pop(),
                         lambda r: r["cleanup"][0].update(verified=False), lambda r: r["cleanup"][0].update(staging_removed=False),
                         lambda r: r["sources"].update(trusted="0" * 64), lambda r: r["requests"][0].update(timeout=901),
                         lambda r: r["requests"][0].update(max_output=64 * 1024**2 + 1),
                         lambda r: r["requests"][0].update(operation="ghidra.arbitrary")]
            for mutate in mutations:
                changed = copy.deepcopy(proof)
                mutate(changed)
                self.assertFalse(verifier.receipt_passes(changed))
            for check, field, value in (("scale.10000", "functions", 9999), ("scale.10000", "pages", 78),
                                       ("function.pseudocode", "characters", 64), ("function.pseudocode", "export_pages", 1),
                                       ("elf_code.cached_equal", "prepare_operations", 2),
                                       ("elf_code.cached_equal", "cached_semantics_sha256", "0" * 64)):
                changed = copy.deepcopy(proof)
                row = next(row for row in changed["checks"] if row["id"] == check)
                row["evidence"][field] = value
                self.assertFalse(verifier.receipt_passes(changed))

    def test_full_builder_parent_is_informational_but_r1_receipt_binds_approved_revision_parent(self):
        proof = self.receipt()
        proof["lock"]["parent_image_id"] = None
        old.verify_ghidra_lock(proof["lock"])
        self.assertFalse(verifier.receipt_passes(proof))

    def test_receipt_refuses_failed_workers_missing_cache_evidence_and_clipped_totals(self):
        with patch.object(verifier, "source_hashes", return_value={"trusted": "d" * 64}):
            proof = self.receipt()
            self.assertTrue(verifier.receipt_passes(proof))
            for operation in {row["operation"] for row in proof["requests"] if row["probe"] is None}:
                changed = copy.deepcopy(proof)
                row = next(row for row in changed["requests"] if row["probe"] is None and row["operation"] == operation)
                row["failure"] = "WorkerProcessError"
                with self.subTest(operation=operation):
                    self.assertFalse(verifier.receipt_passes(changed))
            for files in (None, {}, {"project.tar": False, "cache.json": True},
                          {"project.tar": 0, "cache.json": 0}, {"project.tar": True, "cache.json": True}):
                changed = copy.deepcopy(proof)
                if files is None:
                    del changed["requests"][0]["cache_files"]
                else:
                    changed["requests"][0]["cache_files"] = files
                with self.subTest(files=files):
                    self.assertFalse(verifier.receipt_passes(changed))
            for check, field in (("function.parts", "totals"), ("elf_refs.cached_equal", "program_totals"),
                                 ("elf_refs.cached_equal", "cache_requests")):
                changed = copy.deepcopy(proof)
                item = next(row["evidence"] for row in changed["checks"] if row["id"] == check)[field]
                for key in item:
                    if type(item[key]) is int and item[key] > 0:
                        item[key] -= 1
                        break
                with self.subTest(check=check, field=field):
                    self.assertFalse(verifier.receipt_passes(changed))


class MainTests(SourcePins):
    def test_cli_only_selects_reviewed_revision_route_and_new_lock_and_receipt(self):
        with tempfile.TemporaryDirectory() as folder:
            target, receipt = Path(folder, "r7.lock"), Path(folder, "receipt.json")
            lock = r7_lock()
            def revise(argv):
                self.assertEqual(argv, ["revise", "--route", "B", "--lock", str(target)])
                target.write_text(canonical_json(lock))
                return 0
            builder = types.SimpleNamespace(main=Mock(side_effect=revise))
            fake_native = Mock()
            fake_native.requests = []
            with patch.object(verifier, "source_hashes", return_value={"source": "a" * 64}), \
                    patch.object(verifier.importlib, "import_module", return_value=builder), \
                    patch.object(verifier, "preflight") as preflight, \
                    patch.object(verifier, "R1Verifier", return_value=fake_native), \
                    patch.object(verifier, "receipt_passes", return_value=False), \
                    patch.object(sys, "stderr", io.StringIO()):
                self.assertEqual(verifier.main(["--offline", "--route", "B", "--lock", str(target), "--receipt", str(receipt)]), 1)
            self.assertTrue(target.exists())
            self.assertFalse(json.loads(receipt.read_bytes())["passed"])
            self.assertEqual(fake_native.run_r1.call_count, 1)
            preflight.assert_called_once()

    def test_existing_lock_is_never_overwritten_or_sent_to_builder(self):
        with tempfile.TemporaryDirectory() as folder:
            target, receipt = Path(folder, "r6.lock"), Path(folder, "receipt.json")
            target.write_text("existing lock")
            with patch.object(verifier.importlib, "import_module") as load, patch.object(sys, "stderr", io.StringIO()):
                self.assertEqual(verifier.main(["--offline", "--route", "B", "--lock", str(target), "--receipt", str(receipt)]), 1)
            load.assert_not_called()
            self.assertEqual(target.read_text(), "existing lock")
            proof = json.loads(receipt.read_bytes())
            self.assertFalse(proof["passed"])
            self.assertEqual(proof["checks"][0]["reason"], "R1NewOutputRequired")
            self.assertTrue(any(row["status"] == "not_run" for row in proof["checks"]))


class StagingAndDiagnosticsTests(SourcePins):
    def test_both_entrypoints_stage_privately_under_the_configured_share_and_clean_only_their_run(self):
        sibling = self.shared / "other-run"
        sibling.mkdir()
        (sibling / "keep").write_text("not ours")
        for smoke in (True, False):
            target, receipt = self.source / f"lock-{smoke}", self.source / f"receipt-{smoke}"
            if smoke:
                target.write_text(canonical_json(r7_lock()))
            def revise(argv):
                target.write_text(canonical_json(r7_lock()))
                return 0
            builder = types.SimpleNamespace(main=revise)
            created = []
            def make_native(boundary, lock, proof, folder):
                path = Path(folder)
                self.assertEqual(path.parent, self.shared)
                self.assertEqual(path.stat().st_mode & 0o077, 0)
                self.assertTrue(path.name.startswith("reverseai-r1-smoke-" if smoke else "reverseai-r1-proof-"))
                created.append(path)
                result = Mock()
                result.requests = []
                return result
            with patch.object(verifier, "source_hashes", return_value={"source": "a" * 64}), \
                    patch.object(verifier.importlib, "import_module", return_value=builder), \
                    patch.object(verifier, "preflight"), patch.object(verifier, "R1Verifier", side_effect=make_native), \
                    patch.object(verifier, "receipt_passes", return_value=False), \
                    patch.object(verifier, "smoke_passes", return_value=False), patch.object(sys, "stderr", io.StringIO()):
                args = ["--offline", "--lock", str(target), "--receipt", str(receipt)]
                args.extend(["--smoke"] if smoke else ["--route", "B"])
                self.assertEqual(verifier.main(args), 1)
            self.assertEqual(len(created), 1, json.loads(receipt.read_bytes()))
            self.assertFalse(created[0].exists())
            self.assertEqual(list(self.shared.iterdir()), [sibling])
            self.assertEqual((sibling / "keep").read_text(), "not ours")

    @unittest.skipIf(os.name == "nt", "native R1 Docker controller uses POSIX pipe selectors")
    def test_docker_stderr_is_drained_but_only_a_4096_byte_prefix_is_kept_and_handles_close(self):
        self.assertTrue(hasattr(verifier, "docker_stderr"))
        read_fd, write_fd = os.pipe()
        stream = os.fdopen(read_fd, "rb", buffering=0)
        process = types.SimpleNamespace(stderr=stream)
        text = b"bind source path does not exist: " + b"x" * (128 * 1024)
        def write():
            try:
                view = memoryview(text)
                while view:
                    view = view[os.write(write_fd, view):]
            finally:
                os.close(write_fd)
        with patch.object(verifier.subprocess, "Popen", return_value=process) as real:
            with verifier.docker_stderr() as captured:
                writer = threading.Thread(target=write, daemon=True)
                verifier.subprocess.Popen(["docker", "create", "fixed"], stderr=verifier.subprocess.DEVNULL)
                writer.start()
                writer.join(3)
                self.assertFalse(writer.is_alive(), "stderr flood blocked the trusted runner")
            self.assertEqual(bytes(captured), text[:4096])
            self.assertEqual(real.call_args.kwargs["stderr"], verifier.subprocess.PIPE)
            self.assertEqual(real.call_args.args[0], ["docker", "create", "fixed"])
        self.assertTrue(stream.closed)

    def test_failed_receipt_keeps_bounded_diagnostic_and_success_has_no_stderr_field(self):
        with tempfile.TemporaryDirectory() as folder:
            native = verifier.R1Verifier(FakeBoundary(), r7_lock(), {"checks": [], "cleanup": []}, folder)
            def fail():
                native.failed_stderr = ("bad UTF-8 \ufffd" * 1000).encode()
                raise old.VerificationError("WorkerProcessError")
            self.assertFalse(native.record("prepare", fail))
            row = native.receipt["checks"][-1]
            self.assertEqual(row["reason"], "WorkerProcessError")
            self.assertIn("docker_stderr", row)
            self.assertTrue(row["docker_stderr"].startswith("bad UTF-8"))
            self.assertLessEqual(len(row["docker_stderr"].encode()), 4096)
            self.assertTrue(native.record("success", lambda: {"ok": True}))
            self.assertNotIn("docker_stderr", native.receipt["checks"][-1])


if __name__ == "__main__":
    unittest.main()


class FixtureTotalsTailCallTests(unittest.TestCase):
    """The fixture totals follow the pinned Ghidra: a refs fixture's tail jump is a call, not a reference."""

    def test_describe_totals_match_the_native_receipt(self):
        _, layout = old.elf_refs()
        describe = next(row for row in layout["functions"] if row["name"] == "describe")
        # Recorded by the native run on this bundle (.coordination/r1/native/receipt-r1-full.json, function.parts).
        self.assertEqual(verifier.fixture_function_totals(layout, describe),
                         {"assembly": 6, "callees": 1, "callers": 1, "references": 5, "strings": 2})

    def test_edges_agree_with_the_m2_known_answer_model(self):
        for name in ("elf_refs", "pe_refs", "macho_refs"):
            data, layout = getattr(old, name)()
            entries = {row["entry"] for row in layout["functions"]}
            tail = [row for row in layout["refs"] if row["type"] == "jump" and row["to"] in entries]
            self.assertTrue(tail, name)
            calls, refs = verifier.fixture_edges(layout)
            self.assertEqual(len(calls), len(layout["calls"]) + len(tail), name)
            self.assertEqual(len(refs), len(layout["refs"]) - len(tail), name)
            totals = verifier.fixture_program_totals(name, data)
            self.assertEqual((totals["calls"], totals["references"]), (len(calls), len(refs)), name)
