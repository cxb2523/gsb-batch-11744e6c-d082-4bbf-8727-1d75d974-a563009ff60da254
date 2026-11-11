"""Controller tests use inert bytes and fake Docker; process probes run Python only."""

import json
import io
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, Mock, patch

from reverseai.contained import (
    DockerExecutor, ContainedError, ContainedTimeout, MAX_WORKER_REPLY_BYTES,
    build_argv, load_lock, resource_profile, run_bounded,
)
from reverseai.contract import sha256_hex


def lock():
    return {"image_id": "sha256:" + "a" * 64, "platform": "linux/arm64",
            "base_digest": "sha256:" + "b" * 64, "wheel_sha256": "c" * 64, "adapter_version": "1.0.0-r2"}


def ghidra_lock():
    return {"image_id": "sha256:" + "a" * 64, "platform": "linux/arm64", "adapter_version": "12.1.4-r7",
            "base_digest": "sha256:16bf2b5c59a08523519d3c8589deca849285dee1d62a3653e124c3dba340f15e",
            "ghidra_sha256": "ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db",
            "jdk_sha256": "23e37e026f12f3e706f18938ff611db3032d075b09d0879a25d06718c773e223",
            "parent_image_id": "sha256:" + "f" * 64, "bundle_sha256": "e" * 64, "cache_format": 1}


class ExecutorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.calls = []
        self.data = b"inert snapshot, never executed"

    def executor(self, runner=None, inspect=None):
        return DockerExecutor(lock(), runner=runner or self.runner,
                              inspect=inspect or (lambda image: image), staging_root=self.root)

    def runner(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        if argv[1] == "kill":
            return b""
        mount = argv[argv.index("--mount") + 1]
        folder = Path(mount.split("source=", 1)[1].split(",target=", 1)[0])
        self.assertEqual(folder.parent, self.root)
        self.assertEqual(stat.S_IMODE(folder.stat().st_mode), 0o555)
        self.assertEqual(stat.S_IMODE((folder / "input").stat().st_mode), 0o444)
        self.assertEqual((folder / "input").read_bytes(), self.data)
        self.assertEqual(list(folder.iterdir()), [folder / "input"])
        return b'{"synthetic":true}'

    def run_executor(self, executor):
        return executor.run("lief.sections", {"max_sections": 17}, self.data, sha256_hex(self.data))

    def test_success_uses_the_exact_contract_argv_and_removes_snapshot(self):
        self.assertEqual(self.run_executor(self.executor()), b'{"synthetic":true}')
        argv, kwargs = self.calls[0]
        name, mount = argv[argv.index("--name") + 1], argv[argv.index("--mount") + 1]
        self.assertRegex(name, r"^reverseai-[a-f0-9]{32}$")
        self.assertEqual(argv, [
            "docker", "run", "--rm", "--init", "--pull", "never", "--name", name, "--platform", "linux/arm64",
            "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--user", "65534:65534", "--pids-limit", "64", "--memory", "512m", "--memory-swap", "512m",
            "--cpus", "1", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m", "--log-driver", "none",
            "--mount", mount, lock()["image_id"], "lief.sections", '{"max_sections":17}',
        ])
        self.assertEqual(kwargs, {"timeout": 45, "max_output": MAX_WORKER_REPLY_BYTES})
        self.assertEqual(list(self.root.iterdir()), [])
        self.assertEqual(len(self.calls), 1)

    def test_failure_kills_only_its_named_container_and_cleans_up(self):
        for failure in (OSError("secret /host/path"), subprocess.TimeoutExpired(["private"], 45),
                        TimeoutError("private"), ContainedError("WorkerOutputLimit")):
            with self.subTest(failure=type(failure).__name__):
                self.calls.clear()

                def fail(argv, **kwargs):
                    self.runner(argv, **kwargs)
                    if argv[1] == "run":
                        raise failure
                    return b""

                expected = ContainedTimeout if isinstance(failure, (TimeoutError, subprocess.TimeoutExpired)) else ContainedError
                with self.assertRaises(expected) as caught:
                    self.run_executor(self.executor(runner=fail))
                self.assertNotIn("private", str(caught.exception))
                self.assertNotIn("/", str(caught.exception))
                self.assertEqual(list(self.root.iterdir()), [])
                argv = self.calls[0][0]
                self.assertEqual(self.calls[-1][0], ["docker", "kill", argv[argv.index("--name") + 1]])

    def test_failure_still_removes_snapshot_if_kill_fails(self):
        def fail(argv, **kwargs):
            self.runner(argv, **kwargs)
            raise OSError("hidden host path")

        with self.assertRaisesRegex(ContainedError, "^WorkerProcessError$"):
            self.run_executor(self.executor(runner=fail))
        self.assertEqual(list(self.root.iterdir()), [])

    def _run_with_failed_cleanup(self, failure=None, *, kill_fails=False):
        def runner(argv, **kwargs):
            result = self.runner(argv, **kwargs)
            if argv[1] == "run" and failure is not None:
                raise failure
            if argv[1] == "kill" and kill_fails:
                raise OSError("/private/kill-failure")
            return result

        with patch("reverseai.contained.shutil.rmtree", side_effect=OSError("/private/cleanup-failure")):
            return self.run_executor(self.executor(runner=runner))

    def test_cleanup_failure_preserves_each_primary_exception_and_adds_only_a_safe_note(self):
        class OtherFailure(BaseException):
            pass

        for failure in (ContainedTimeout("WorkerTimeout"), ContainedError("WorkerOutputLimit"),
                        KeyboardInterrupt(), SystemExit(17), OtherFailure("Stopped")):
            with self.subTest(failure=type(failure).__name__):
                failure.add_note("ExistingNotice")
                with self.assertRaises(BaseException) as caught:
                    self._run_with_failed_cleanup(failure)
                self.assertIs(caught.exception, failure)
                self.assertEqual(caught.exception.__notes__, ["ExistingNotice", "StagingCleanupError"])
                self.assertNotIn("/", str(caught.exception))
                self.assertNotIn("/", " ".join(caught.exception.__notes__))

    def test_cleanup_failure_keeps_plain_runner_errors_sanitized(self):
        with self.assertRaisesRegex(ContainedError, "^WorkerProcessError$") as caught:
            self._run_with_failed_cleanup(OSError("/private/runner-failure"))
        self.assertIs(type(caught.exception), ContainedError)
        self.assertEqual(caught.exception.__notes__, ["StagingCleanupError"])

    def test_cleanup_and_kill_failures_keep_the_original_timeout_retriable(self):
        failure = ContainedTimeout("WorkerTimeout")
        with self.assertRaises(BaseException) as caught:
            self._run_with_failed_cleanup(failure, kill_fails=True)
        self.assertIs(caught.exception, failure)
        self.assertIsInstance(caught.exception, TimeoutError)
        self.assertEqual(caught.exception.__notes__, ["StagingCleanupError"])
        self.assertEqual([argv[1] for argv, _ in self.calls], ["run", "kill"])

    def test_cleanup_failure_preserves_a_staging_error_before_the_runner_starts(self):
        with patch("reverseai.contained.build_argv", side_effect=OSError("/private/staging-failure")):
            with self.assertRaisesRegex(ContainedError, "^WorkerProcessError$") as caught:
                self._run_with_failed_cleanup()
        self.assertEqual(caught.exception.__notes__, ["StagingCleanupError"])
        self.assertEqual(self.calls, [])

    def test_successful_run_fails_closed_on_cleanup_error_even_inside_an_outer_handler(self):
        with self.assertRaisesRegex(ContainedError, "^StagingCleanupError$") as caught:
            self._run_with_failed_cleanup()
        self.assertFalse(getattr(caught.exception, "__notes__", []))
        try:
            raise ValueError("/private/caller-failure")
        except ValueError:
            with self.assertRaisesRegex(ContainedError, "^StagingCleanupError$") as caught:
                self._run_with_failed_cleanup()
            self.assertFalse(getattr(caught.exception, "__notes__", []))

    def test_stdout_cap_is_also_checked_for_an_injected_runner(self):
        def oversized(argv, **kwargs):
            self.runner(argv, **kwargs)
            return b"x" * (MAX_WORKER_REPLY_BYTES + 1)

        with self.assertRaisesRegex(ContainedError, "^WorkerOutputLimit$"):
            self.run_executor(self.executor(runner=oversized))
        self.assertEqual(self.calls[-1][0][1], "kill")
        self.assertEqual(list(self.root.iterdir()), [])

    def test_image_mismatch_or_inspect_failure_never_stages_or_runs(self):
        def unavailable(image):
            raise OSError("/hidden/docker/socket")

        for inspect in (lambda image: "sha256:" + "d" * 64, unavailable):
            with self.subTest(inspect=inspect):
                executor = self.executor(inspect=inspect)
                self.assertFalse(executor.available())
                with self.assertRaisesRegex(ContainedError, "^ImageUnavailable$"):
                    self.run_executor(executor)
                self.assertEqual(self.calls, [])
                self.assertEqual(list(self.root.iterdir()), [])

    def test_wrong_digest_and_unvalidated_operations_never_reach_runner(self):
        executor = self.executor()
        with self.assertRaisesRegex(ContainedError, "SnapshotMismatch"):
            executor.run("lief.headers", {}, self.data, "0" * 64)
        for operation, args in (("sh", {}), ("lief.headers", {"path": "/etc/passwd"}),
                                ("lief.sections", {"max_sections": True}), ("lief.sections", {"max_sections": 65}),
                                ("lief.sections", {"max_sections": "--privileged"})):
            with self.subTest(operation=operation, args=args), self.assertRaises(ContainedError):
                executor.run(operation, args, self.data, sha256_hex(self.data))
        self.assertEqual(self.calls, [])
        self.assertEqual(list(self.root.iterdir()), [])

    def test_staging_root_must_be_private_and_not_a_symlink(self):
        for mode in (0o777, 0o755):
            os.chmod(self.root, mode)
            with self.assertRaisesRegex(ContainedError, "^UnsafeStagingFolder$"):
                self.run_executor(self.executor())
        os.chmod(self.root, 0o700)
        alias = self.root / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        executor = self.executor()
        executor.staging_root = alias
        with self.assertRaisesRegex(ContainedError, "^UnsafeStagingFolder$"):
            self.run_executor(executor)
        alias.unlink()
        self.assertEqual(self.calls, [])

    def test_staging_io_failure_is_short_and_cleans_the_created_folder(self):
        with patch("reverseai.contained.build_argv", side_effect=OSError("private /path")):
            with self.assertRaisesRegex(ContainedError, "^WorkerProcessError$"):
                self.run_executor(self.executor())
        self.assertEqual(self.calls, [])
        self.assertEqual(list(self.root.iterdir()), [])


class LockAndArgvTests(unittest.TestCase):
    def test_tool_supplied_version_and_extra_digest_are_validated_and_frozen(self):
        value = dict(lock(), adapter_version="1.21.0-r2", ruleset_sha256="d" * 64)
        kwargs = {"adapter_version": "1.21.0-r2", "extra_keys": ("ruleset_sha256",)}
        self.assertEqual(load_lock(value, **kwargs), value)
        executor = DockerExecutor(value, **kwargs)
        value["ruleset_sha256"] = "e" * 64
        self.assertEqual(executor.lock["ruleset_sha256"], "d" * 64)
        with self.assertRaises(TypeError):
            executor.lock["ruleset_sha256"] = "e" * 64
        for bad in (dict(value, ruleset_sha256="sha256:" + "d" * 64), dict(value, ruleset_sha256=None),
                    dict(value, adapter_version="1.0.0-r2"), dict(value, extra="ignored"),
                    {key: val for key, val in value.items() if key != "ruleset_sha256"}):
            with self.subTest(bad=bad), self.assertRaisesRegex(ContainedError, "^InvalidImageLock$"):
                load_lock(bad, **kwargs)
        with self.assertRaises(ContainedError):
            load_lock(value)

    def test_yarax_defaults_and_limits_are_checked_before_building_argv(self):
        for args in ({}, {"max_matches": 1}, {"ruleset": "m2_fixture_v1", "max_matches": 64}):
            argv = build_argv(lock()["image_id"], "reverseai-abc", "/private/staging", "yarax.matches", args)
            control = build_argv(lock()["image_id"], "reverseai-abc", "/private/staging", "lief.headers", {})
            self.assertEqual(argv[:-2], control[:-2])
            self.assertEqual(argv[-2], "yarax.matches")
            self.assertEqual(json.loads(argv[-1]), {"ruleset": "m2_fixture_v1", "max_matches": args.get("max_matches", 32)})
        for args in ({"max_matches": True}, {"max_matches": 0}, {"max_matches": 65}, {"max_matches": "64"},
                     {"ruleset": "other"}, {"ruleset": "--privileged"}, {"path": "/host/input"}):
            with self.subTest(args=args), self.assertRaisesRegex(ContainedError, "^InvalidWorkerArguments$"):
                build_argv(lock()["image_id"], "reverseai-abc", "/private/staging", "yarax.matches", args)

    def test_yarax_executor_uses_the_same_staging_limits_and_cleanup(self):
        data, calls = b"inert UPX!", []
        with tempfile.TemporaryDirectory() as folder:
            def runner(argv, **kwargs):
                calls.append((argv, kwargs))
                mount = argv[argv.index("--mount") + 1]
                staged = Path(mount.split("source=", 1)[1].split(",target=", 1)[0])
                self.assertEqual((staged / "input").read_bytes(), data)
                self.assertEqual(stat.S_IMODE(staged.stat().st_mode), 0o555)
                self.assertEqual(stat.S_IMODE((staged / "input").stat().st_mode), 0o444)
                return b"reply"
            executor = DockerExecutor(dict(lock(), adapter_version="1.21.0-r2", ruleset_sha256="d" * 64),
                                      runner=runner, adapter_version="1.21.0-r2", extra_keys=("ruleset_sha256",),
                                      inspect=lambda image: image, staging_root=folder)
            self.assertEqual(executor.run("yarax.matches", {}, data, sha256_hex(data)), b"reply")
            self.assertEqual(list(Path(folder).iterdir()), [])
        self.assertEqual(calls[0][1], {"timeout": 45, "max_output": MAX_WORKER_REPLY_BYTES})
        self.assertEqual(calls[0][0][-2:], ["yarax.matches", '{"max_matches":32,"ruleset":"m2_fixture_v1"}'])

    def test_lock_file_pins_are_validated_and_copied(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "lock.json"
            path.write_text(json.dumps(lock()))
            self.assertEqual(load_lock(path), lock())
            original = lock()
            executor = DockerExecutor(original, inspect=lambda image: image)
            original["image_id"] = "changed"
            self.assertEqual(executor.lock["image_id"], lock()["image_id"])
            with self.assertRaises(TypeError):
                executor.lock["image_id"] = "changed"
            for key, bad in (("image_id", "latest"), ("platform", "linux/amd64"), ("base_digest", "unpinned"),
                             ("wheel_sha256", "short"), ("adapter_version", "other")):
                with self.subTest(key=key), self.assertRaisesRegex(ContainedError, "^InvalidImageLock$"):
                    load_lock(dict(lock(), **{key: bad}))
            for raw in (b"\xff", b"[1]", b"x" * 16_385):
                path.write_bytes(raw)
                with self.assertRaisesRegex(ContainedError, "^InvalidImageLock$"):
                    load_lock(path)
            with self.assertRaisesRegex(ContainedError, "^InvalidImageLock$"):
                load_lock(path.with_name("absent"))

    def test_builder_rejects_mount_option_injection_and_sets_defaults(self):
        argv = build_argv(lock()["image_id"], "reverseai-abc", "/private/staging", "lief.sections", {})
        self.assertEqual(argv[-1], '{"max_sections":32}')
        for folder in ("relative", "/tmp/staging,target=/host", "/tmp/line\n"):
            with self.subTest(folder=folder), self.assertRaises(ContainedError):
                build_argv(lock()["image_id"], "reverseai-abc", folder, "lief.headers", {})
        with self.assertRaises(ContainedError):
            build_argv("latest", "reverseai-abc", "/tmp/staging", "lief.headers", {})
        with self.assertRaises(ContainedError):
            build_argv(lock()["image_id"], "--privileged", "/tmp/staging", "lief.headers", {})


class GhidraBoundaryTests(unittest.TestCase):
    def test_lock_has_exact_pinned_ghidra_keys_and_no_wheel(self):
        kwargs = {"adapter_version": "12.1.4-r7"}
        self.assertEqual(load_lock(ghidra_lock(), **kwargs), ghidra_lock())
        for version in ("12.1.4-r1", "12.1.4-r2", "12.1.4-r3", "12.1.4-r4", "12.1.4-r5", "12.1.4-r6"):
            with self.subTest(version=version), self.assertRaises(ContainedError):
                load_lock(dict(ghidra_lock(), adapter_version=version), **kwargs)
        for field in ghidra_lock():
            value = ghidra_lock()
            del value[field]
            with self.subTest(missing=field), self.assertRaisesRegex(ContainedError, "^InvalidImageLock$"):
                load_lock(value, **kwargs)
        for field in ("base_digest", "ghidra_sha256", "jdk_sha256"):
            value = ghidra_lock()
            value[field] = ("sha256:" if field == "base_digest" else "") + "0" * 64
            with self.subTest(wrong_pin=field), self.assertRaises(ContainedError):
                load_lock(value, **kwargs)
        for extra in ({"wheel_sha256": "b" * 64}, {"extra": "b" * 64}):
            with self.subTest(extra=extra), self.assertRaises(ContainedError):
                load_lock(dict(ghidra_lock(), **extra), **kwargs)
        with self.assertRaises(ContainedError):
            load_lock(ghidra_lock())
        with self.assertRaises(ContainedError):
            load_lock(ghidra_lock(), **kwargs, extra_keys=("extra",))

    def test_fixed_profile_and_exact_argv_only_change_the_agreed_resources(self):
        expected = {"pids": 256, "memory": "2g", "cpus": 2,
                    "tmpfs": "/tmp:rw,noexec,nosuid,nodev,size=512m", "wall_seconds": 240}
        profile = resource_profile("ghidra.analyze")
        self.assertEqual(dict(profile), expected)
        with self.assertRaises(TypeError):
            profile["wall_seconds"] = 3600
        with self.assertRaises(ContainedError):
            resource_profile("unknown")
        argv = build_argv(ghidra_lock()["image_id"], "reverseai-abc", "/private/staging", "ghidra.analyze", {})
        self.assertEqual(argv, [
            "docker", "run", "--rm", "--init", "--pull", "never", "--name", "reverseai-abc", "--platform", "linux/arm64",
            "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--user", "65534:65534", "--pids-limit", "256", "--memory", "2g", "--memory-swap", "2g",
            "--cpus", "2", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=512m", "--log-driver", "none",
            "--mount", "type=bind,source=/private/staging,target=/snapshot,readonly", ghidra_lock()["image_id"],
            "ghidra.analyze", '{"assembly":4,"decompile":8,"max_calls":128,"max_chars":1024,"max_functions":64,"max_instructions":32,"max_refs":64,"max_strings":32}',
        ])
        for operation in ("lief.headers", "lief.sections", "yarax.matches"):
            self.assertEqual(resource_profile(operation)["wall_seconds"], 45)

    def test_all_argument_bounds_and_unknown_resource_or_script_knobs_are_refused(self):
        for key, low, high in (("max_functions", 1, 128), ("decompile", 0, 16),
                               ("max_chars", 64, 2048), ("max_calls", 0, 256), ("assembly", 0, 8),
                               ("max_instructions", 1, 64), ("max_refs", 0, 128), ("max_strings", 0, 64)):
            for value in (low, high):
                argv = build_argv(ghidra_lock()["image_id"], "reverseai-abc", "/tmp/staging", "ghidra.analyze", {key: value})
                self.assertEqual(json.loads(argv[-1])[key], value)
            for value in (low - 1, high + 1, True, str(low), float(low)):
                with self.subTest(key=key, value=value), self.assertRaises(ContainedError):
                    build_argv(ghidra_lock()["image_id"], "reverseai-abc", "/tmp/staging", "ghidra.analyze", {key: value})
        for key in ("profile", "timeout", "script", "loader", "path", "entrypoint"):
            with self.subTest(key=key), self.assertRaises(ContainedError):
                build_argv(ghidra_lock()["image_id"], "reverseai-abc", "/tmp/staging", "ghidra.analyze", {key: "ghidra"})

    def test_executor_profile_identity_timeout_staging_and_failure_cleanup(self):
        data = b"inert snapshot"
        for fail in (False, True):
            calls = []
            with tempfile.TemporaryDirectory() as folder:
                def runner(argv, **kwargs):
                    calls.append((argv, kwargs))
                    if argv[1] == "kill":
                        return b""
                    staged = Path(argv[argv.index("--mount") + 1].split("source=")[1].split(",target=")[0])
                    self.assertEqual((staged / "input").read_bytes(), data)
                    self.assertEqual(stat.S_IMODE(staged.stat().st_mode), 0o555)
                    self.assertEqual(stat.S_IMODE((staged / "input").stat().st_mode), 0o444)
                    if fail:
                        raise ContainedTimeout("WorkerTimeout")
                    return b"reply"
                executor = DockerExecutor(ghidra_lock(), runner=runner, adapter_version="12.1.4-r7",
                                          inspect=lambda image: image, staging_root=folder)
                with self.subTest(fail=fail):
                    if fail:
                        with self.assertRaises(ContainedTimeout):
                            executor.run("ghidra.analyze", {}, data, sha256_hex(data))
                    else:
                        self.assertEqual(executor.run("ghidra.analyze", {}, data, sha256_hex(data)), b"reply")
                    self.assertEqual(calls[0][1], {"timeout": 240, "max_output": MAX_WORKER_REPLY_BYTES})
                    self.assertEqual(list(Path(folder).iterdir()), [])
                    if fail:
                        self.assertEqual(calls[-1][0], ["docker", "kill", calls[0][0][calls[0][0].index("--name") + 1]])
                        self.assertEqual(calls[-1][1]["timeout"], 5)
                with self.assertRaises(ContainedError):
                    executor.run("lief.headers", {}, data, sha256_hex(data))
        with self.assertRaises(ContainedError):
            DockerExecutor(lock(), inspect=lambda image: image).run("ghidra.analyze", {}, data, sha256_hex(data))

    def test_default_ghidra_executor_selects_the_closed_profile_on_the_same_runner(self):
        with tempfile.TemporaryDirectory() as folder, patch("reverseai.contained.run_bounded", return_value=b"reply") as runner:
            executor = DockerExecutor(ghidra_lock(), adapter_version="12.1.4-r7", inspect=lambda image: image, staging_root=folder)
            executor.run("ghidra.analyze", {}, b"inert", sha256_hex(b"inert"))
            self.assertEqual(runner.call_args.kwargs,
                             {"profile": "ghidra", "timeout": 240, "max_output": MAX_WORKER_REPLY_BYTES})


class GhidraQueryBoundaryTests(unittest.TestCase):
    DEFAULTS = {
        "ghidra.functions": {"query": "", "start": 0, "limit": 64},
        "ghidra.function": {"select": "entry", "entry": 0, "name": "", "parts": "all", "start": 0,
                            "limit": 64, "max_chars": 1024, "max_calls": 64, "max_refs": 64},
        "ghidra.xrefs": {"address": 0, "start": 0, "limit": 64},
    }

    def argv(self, operation, args):
        return build_argv(ghidra_lock()["image_id"], "reverseai-abc", "/private/staging", operation, args)

    def test_query_defaults_keep_the_same_argv_and_fixed_resource_profile(self):
        control = self.argv("ghidra.analyze", {})
        for operation, expected in self.DEFAULTS.items():
            with self.subTest(operation=operation):
                args = {"address": 0} if operation == "ghidra.xrefs" else {}
                try:
                    argv = self.argv(operation, args)
                except ContainedError as failure:
                    self.fail(f"Declared query operation refused: {failure}")
                self.assertEqual(argv[:-2], control[:-2])
                self.assertEqual(argv[-2], operation)
                self.assertEqual(json.loads(argv[-1]), expected)
                self.assertEqual(resource_profile(operation), resource_profile("ghidra.analyze"))
                self.assertEqual(resource_profile(operation)["wall_seconds"], 240)
        for operation in ("ghidra.other", "ghidra", "ghidra.functions --privileged"):
            with self.subTest(operation=operation), self.assertRaises(ContainedError):
                self.argv(operation, {})

    def test_query_boundary_rejects_unknown_keys_invalid_bounds_and_non_str_search(self):
        ranges = {
            "ghidra.functions": {"start": (0, 65535), "limit": (1, 128)},
            "ghidra.function": {"entry": (0, 2 ** 64 - 1), "start": (0, 65535), "limit": (1, 256),
                                "max_chars": (64, 2048), "max_calls": (0, 256), "max_refs": (0, 128)},
            "ghidra.xrefs": {"address": (0, 2 ** 64 - 1), "start": (0, 65535), "limit": (1, 256)},
        }
        for operation, bounds in ranges.items():
            defaults = self.DEFAULTS[operation]
            for key, (low, high) in bounds.items():
                for number in (low, high):
                    with self.subTest(operation=operation, key=key, accepted=number):
                        try:
                            argv = self.argv(operation, dict(defaults, **{key: number}))
                        except ContainedError as failure:
                            self.fail(f"Declared query bound refused: {failure}")
                        self.assertEqual(json.loads(argv[-1])[key], number)
                for value in (low - 1, high + 1, True, str(low), float(low), None):
                    with self.subTest(operation=operation, key=key, value=value), self.assertRaises(ContainedError):
                        self.argv(operation, dict(defaults, **{key: value}))
            for key in ("profile", "timeout", "script", "loader", "path", "entrypoint", "max_functions"):
                with self.subTest(operation=operation, key=key), self.assertRaises(ContainedError):
                    self.argv(operation, dict(defaults, **{key: "untrusted"}))
        for operation, key in (("ghidra.functions", "query"), ("ghidra.function", "name")):
            for text in ("", "name with spaces", "name`$()", "a" * 256):
                with self.subTest(operation=operation, accepted=text):
                    self.assertEqual(json.loads(self.argv(operation, {key: text})[-1])[key], text)
            for text in ("/tmp/name", "with\\backslash", "-flag", "bad\x00name", "a" * 257, 0, None):
                with self.subTest(operation=operation, rejected=text), self.assertRaises(ContainedError):
                    self.argv(operation, {key: text})
        for key, values in (("select", ("offset", "--entrypoint", None)), ("parts", ("other", "--privileged", None))):
            for value in values:
                with self.subTest(key=key, value=value), self.assertRaises(ContainedError):
                    self.argv("ghidra.function", {key: value})
        with self.assertRaises(ContainedError):
            self.argv("ghidra.xrefs", {})

    def test_query_executor_identity_fixed_runner_limits_and_cleanup(self):
        data = b"inert query snapshot"
        for operation, args in self.DEFAULTS.items():
            calls = []
            with tempfile.TemporaryDirectory() as folder:
                def runner(argv, **kwargs):
                    calls.append((argv, kwargs))
                    mount = argv[argv.index("--mount") + 1]
                    staged = Path(mount.split("source=")[1].split(",target=")[0])
                    self.assertEqual((staged / "input").read_bytes(), data)
                    return b"reply"
                executor = DockerExecutor(ghidra_lock(), runner=runner, adapter_version="12.1.4-r7",
                                          inspect=lambda image: image, staging_root=folder)
                self.assertEqual(executor.run(operation, args, data, sha256_hex(data)), b"reply")
                self.assertEqual(calls[0][1], {"timeout": 240, "max_output": MAX_WORKER_REPLY_BYTES})
                self.assertEqual(calls[0][0][-2], operation)
                self.assertEqual(list(Path(folder).iterdir()), [])
            with self.subTest(operation=operation), self.assertRaises(ContainedError):
                DockerExecutor(lock(), inspect=lambda image: image).run(operation, args, data, sha256_hex(data))

    def test_each_default_query_executor_selects_the_closed_ghidra_runner(self):
        for operation, args in self.DEFAULTS.items():
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as folder, \
                    patch("reverseai.contained.run_bounded", return_value=b"reply") as runner:
                executor = DockerExecutor(ghidra_lock(), adapter_version="12.1.4-r7",
                                          inspect=lambda image: image, staging_root=folder)
                executor.run(operation, args, b"inert", sha256_hex(b"inert"))
                self.assertEqual(runner.call_args.kwargs,
                                 {"profile": "ghidra", "timeout": 240, "max_output": MAX_WORKER_REPLY_BYTES})


class ProcessRunnerTests(unittest.TestCase):
    def run_python(self, source, **kwargs):
        return run_bounded([sys.executable, "-I", "-B", "-c", source], **kwargs)

    def test_default_profile_never_waits_longer_than_45_seconds(self):
        for kwargs in ({}, {"timeout": 999}):
            with self.subTest(kwargs=kwargs), patch("reverseai.contained.subprocess.Popen") as process, \
                    patch("reverseai.contained.selectors.DefaultSelector") as selector, \
                    patch("reverseai.contained.time.monotonic", return_value=100):
                selected = selector.return_value.__enter__.return_value
                process.return_value.poll.return_value = None
                selected.get_map.return_value = {1: None}
                selected.select.return_value = []
                with self.assertRaisesRegex(ContainedTimeout, "^WorkerTimeout$"):
                    run_bounded(["inert-command"], **kwargs)
                selected.select.assert_called_once_with(45)
                process.return_value.kill.assert_called_once_with()

    def test_stdout_is_bytes_stderr_is_discarded_and_exact_cap_is_allowed(self):
        self.assertEqual(self.run_python("import os; os.write(2, b'private'); os.write(1, b'abcd')",
                                         timeout=5, max_output=4), b"abcd")

    def test_large_and_endless_outputs_are_stopped_at_the_byte_cap(self):
        with self.assertRaisesRegex(ContainedError, "^WorkerOutputLimit$"):
            self.run_python("import os\nwhile True: os.write(1, b'x' * 8192)", timeout=5, max_output=1024)

    def test_timeout_kills_and_reaps_the_cli_process(self):
        popen, processes = subprocess.Popen, []

        def record(*args, **kwargs):
            process = popen(*args, **kwargs)
            processes.append(process)
            self.assertIs(kwargs["shell"], False)
            self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
            self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)
            return process

        with patch("reverseai.contained.subprocess.Popen", side_effect=record):
            with self.assertRaisesRegex(ContainedTimeout, "^WorkerTimeout$"):
                self.run_python("import time; time.sleep(60)", timeout=0.1, max_output=1024)
        self.assertIsNotNone(processes[0].poll())

    def test_nonzero_exit_is_a_short_error(self):
        with self.assertRaisesRegex(ContainedError, "^WorkerProcessError$"):
            self.run_python("import sys; sys.stderr.write('/private/path'); sys.exit(17)", timeout=5, max_output=1024)

    def test_closed_stdout_does_not_bypass_the_wall_limit(self):
        with self.assertRaisesRegex(ContainedTimeout, "^WorkerTimeout$"):
            self.run_python("import os, time; os.close(1); time.sleep(60)", timeout=0.1, max_output=1024)

    def test_runner_callers_cannot_widen_the_production_limits(self):
        with patch("reverseai.contained.WALL_SECONDS", 0.1):
            with self.assertRaises(ContainedTimeout):
                self.run_python("import time; time.sleep(60)", timeout=60, max_output=1024)
        with self.assertRaisesRegex(ContainedError, "^WorkerOutputLimit$"):
            self.run_python(f"import os; os.write(1, b'x' * {MAX_WORKER_REPLY_BYTES + 1})",
                            timeout=5, max_output=MAX_WORKER_REPLY_BYTES * 2)

    def test_ghidra_profile_cannot_widen_its_module_limit_and_unknown_profiles_never_start(self):
        with patch("reverseai.contained.GHIDRA_WALL_SECONDS", 0.1):
            with self.assertRaises(ContainedTimeout):
                self.run_python("import time; time.sleep(60)", timeout=999, profile="ghidra")
        with patch("reverseai.contained.subprocess.Popen") as process:
            for profile in ("unknown", None, 240):
                with self.subTest(profile=profile), self.assertRaises(ContainedError):
                    self.run_python("pass", profile=profile)
            process.assert_not_called()


class PreparedGhidraTests(unittest.TestCase):
    def check_prepare_deadline(self, clocks, *, stdout_eof=False):
        from reverseai import contained
        process = Mock()
        process.stdout = io.BytesIO()
        process.poll.return_value = None
        process.wait.return_value = 0
        selector = MagicMock()
        selector.__enter__.return_value = selector
        selector.get_map.return_value = {} if stdout_eof else {"stdout": object()}
        selector.select.return_value = []
        with patch.object(contained.subprocess, "Popen", return_value=process), \
                patch.object(contained.selectors, "DefaultSelector", return_value=selector), \
                patch.object(contained.time, "monotonic", side_effect=clocks):
            with self.assertRaises(ContainedError) as caught:
                contained.run_prepare_bounded(["inert-command"], io.BytesIO())
        process.kill.assert_called_once_with()
        process.wait.assert_called_once_with()
        self.assertTrue(process.stdout.closed)
        self.assertIs(type(caught.exception), ContainedTimeout)
        self.assertEqual(str(caught.exception), "WorkerTimeout")
        return selector

    def test_prepare_deadline_before_select_preserves_timeout_and_cleanup(self):
        selector = self.check_prepare_deadline((100.0, 1000.0))
        selector.select.assert_not_called()

    def test_prepare_empty_select_preserves_timeout_and_cleanup(self):
        selector = self.check_prepare_deadline((100.0, 101.0))
        selector.select.assert_called_once_with(899.0)

    def test_prepare_deadline_after_stdout_eof_preserves_timeout_and_cleanup(self):
        selector = self.check_prepare_deadline((100.0, 1000.0), stdout_eof=True)
        selector.select.assert_not_called()

    def test_prepare_sink_deadline_becomes_a_contained_timeout_and_cleans_up(self):
        from reverseai import contained, ghidra_cache
        process = Mock()
        process.poll.return_value = None
        process.wait.return_value = 0
        selector = MagicMock()
        selector.__enter__.return_value = selector
        selector.get_map.return_value = {"stdout": object()}
        selector.select.return_value = [(object(), 1)]
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as target:
            stdout.write(b"opaque worker bytes")
            stdout.seek(0)
            process.stdout = stdout
            sink = ghidra_cache._Sink(target.fileno(), deadline=0)
            with patch.object(contained.subprocess, "Popen", return_value=process), \
                    patch.object(contained.selectors, "DefaultSelector", return_value=selector), \
                    patch.object(contained.time, "monotonic", return_value=100):
                with self.assertRaises(ContainedError) as caught:
                    contained.run_prepare_bounded(["inert-command"], sink)
            process.kill.assert_called_once_with()
            process.wait.assert_called_once_with()
            self.assertTrue(stdout.closed)
            self.assertEqual(target.tell(), 0)
            self.assertIs(type(caught.exception), ContainedTimeout)
            self.assertEqual(str(caught.exception), "WorkerTimeout")

    def test_prepare_nonzero_exit_never_publishes_partial_stdout(self):
        from reverseai import contained, ghidra_cache
        process = Mock()
        process.poll.return_value = 17
        process.wait.return_value = 17
        selector = MagicMock()
        selector.__enter__.return_value = selector
        selector.get_map.return_value = {"stdout": object()}
        selector.select.return_value = [(object(), 1)]
        with tempfile.TemporaryDirectory() as folder, tempfile.TemporaryFile() as stdout:
            store = ghidra_cache.CacheStore(Path(folder).resolve() / "cache")
            expected = ghidra_cache.identity(sha256_hex(b"inert"), ghidra_lock())
            stdout.write(b"partial opaque project")
            stdout.seek(0)
            process.stdout = stdout
            with patch.object(contained.subprocess, "Popen", return_value=process), \
                    patch.object(contained.selectors, "DefaultSelector", return_value=selector), \
                    patch.object(contained.time, "monotonic", return_value=100):
                with self.assertRaisesRegex(ContainedError, "^WorkerProcessError$"):
                    store.prepare(expected, lambda sink: contained.run_prepare_bounded(["inert-command"], sink))
            self.assertTrue(stdout.closed)
            process.wait.assert_called_once_with(timeout=900)
            process.kill.assert_not_called()
            self.assertIsNone(store.lookup(expected))
            self.assertFalse(any(p.suffix in (".tar",) or p.name.startswith(".tmp-") for p in store.root.iterdir()))

    def test_r7_lock_fields_are_closed_and_old_locks_are_refused(self):
        from reverseai.contained import GHIDRA_VERSION
        for change in ({"cache_format": True}, {"cache_format": 2}, {"bundle_sha256": "x"},
                       {"parent_image_id": "/tmp/project"}, {"extra": "x"}, {"adapter_version": "12.1.4-r6"}):
            with self.subTest(change=change), self.assertRaises(ContainedError):
                load_lock(dict(ghidra_lock(), **change), adapter_version=GHIDRA_VERSION)
        for parent in (None, "sha256:" + "d" * 64):
            value = dict(ghidra_lock(), parent_image_id=parent)
            self.assertEqual(load_lock(value, adapter_version=GHIDRA_VERSION), value)

    def test_prepare_uses_a_separate_stream_limit_and_fixed_argv(self):
        from reverseai.contained import GHIDRA_VERSION
        calls, sink = [], io.BytesIO()
        data = b"inert code-built input"
        with tempfile.TemporaryDirectory() as folder:
            def runner(argv, sink, **kwargs):
                calls.append((argv, kwargs))
                snapshot = Path(argv[argv.index("--mount") + 1].split("source=")[1].split(",target=")[0])
                self.assertEqual((snapshot / "input").read_bytes(), data)
                self.assertEqual({p.name for p in snapshot.iterdir()}, {"input"})
                sink.write(b"opaque TAR bytes")
            executor = DockerExecutor(ghidra_lock(), adapter_version=GHIDRA_VERSION, prepare_runner=runner,
                                      inspect=lambda image: image, staging_root=folder)
            self.assertIsNone(executor.prepare(data, sha256_hex(data), sink))
            self.assertEqual(sink.getvalue(), b"opaque TAR bytes")
            self.assertEqual(calls[0][0][-2:], ["ghidra.prepare", "{}"])
            self.assertEqual(calls[0][1], {"timeout": 900})
            self.assertEqual(dict(resource_profile("ghidra.prepare")), dict(resource_profile("ghidra.analyze"), wall_seconds=900))
            self.assertEqual(list(Path(folder).iterdir()), [])
            with self.assertRaises(ContainedError):
                executor.run("ghidra.prepare", {}, data, sha256_hex(data))

    def test_streamed_flood_and_timeout_remove_only_the_owned_container_and_snapshot(self):
        from reverseai import contained
        data = b"inert"
        for action in ("flood", "timeout", "empty"):
            calls = []
            def runner(argv, **kwargs):
                calls.append(argv)
                return b""
            def stream(argv, sink, **kwargs):
                calls.append(argv)
                if action == "timeout":
                    raise ContainedTimeout("WorkerTimeout")
                if action == "flood":
                    sink.write(b"x" * 17)
            with self.subTest(action=action), tempfile.TemporaryDirectory() as folder, \
                    patch.object(contained, "GHIDRA_PREPARE_MAX_BYTES", 16):
                executor = DockerExecutor(ghidra_lock(), adapter_version=contained.GHIDRA_VERSION,
                                          runner=runner, prepare_runner=stream, inspect=lambda image: image, staging_root=folder)
                with self.assertRaises(ContainedError):
                    executor.prepare(data, sha256_hex(data), io.BytesIO())
                self.assertEqual(calls[-1], ["docker", "kill", calls[0][calls[0].index("--name") + 1]])
                self.assertEqual(list(Path(folder).iterdir()), [])

    def test_cached_query_stages_only_the_three_fixed_files_in_one_readonly_mount(self):
        from reverseai import contained, ghidra_cache
        data, blob = b"inert input", b"opaque project"
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            staging = root / "stage"
            staging.mkdir(mode=0o700)
            store = ghidra_cache.CacheStore(root / "cache")
            expected = ghidra_cache.identity(sha256_hex(data), ghidra_lock())
            store.prepare(expected, lambda sink: sink.write(blob))
            def runner(argv, **kwargs):
                self.assertEqual(argv.count("--mount"), 1)
                snapshot = Path(argv[argv.index("--mount") + 1].split("source=")[1].split(",target=")[0])
                self.assertEqual({p.name for p in snapshot.iterdir()}, {"input", "project.tar", "cache.json"})
                self.assertEqual((snapshot / "input").read_bytes(), data)
                self.assertEqual((snapshot / "project.tar").read_bytes(), blob)
                manifest = json.loads((snapshot / "cache.json").read_text())
                self.assertEqual(set(manifest), {"format", "input_sha256", "image_id", "bundle_sha256", "size", "artifact_sha256"})
                for p in snapshot.iterdir():
                    self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o444)
                self.assertEqual(kwargs, {"timeout": 240, "max_output": MAX_WORKER_REPLY_BYTES})
                return b"reply"
            executor = DockerExecutor(ghidra_lock(), adapter_version=contained.GHIDRA_VERSION, runner=runner,
                                      inspect=lambda image: image, staging_root=staging)
            with store.lookup(expected) as project:
                self.assertEqual(executor.run("ghidra.export_program", {}, data, sha256_hex(data), project=project), b"reply")
            self.assertEqual(list(staging.iterdir()), [])

    def test_actual_prepare_runner_caps_stdout_and_keeps_json_runner_cap(self):
        from reverseai import contained
        with patch.object(contained, "GHIDRA_PREPARE_MAX_BYTES", 32):
            for size in (0, 32, 33):
                sink = io.BytesIO()
                argv = [sys.executable, "-I", "-B", "-c", "import os;os.write(1,b'x'*" + str(size) + ")"]
                if size != 32:
                    with self.subTest(size=size), self.assertRaises(ContainedError):
                        contained.run_prepare_bounded(argv, sink, timeout=5)
                else:
                    contained.run_prepare_bounded(argv, sink, timeout=5)
                    self.assertEqual(sink.getvalue(), b"x" * 32)
                self.assertLessEqual(len(sink.getvalue()), 32)
        self.assertEqual(MAX_WORKER_REPLY_BYTES, 262144)
