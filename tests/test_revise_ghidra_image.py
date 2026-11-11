"""Offline image revision protocol tests. All Docker interactions are inert fakes."""

import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tests.test_build_ghidra_image import FakeDocker, build


PARENT = "sha256:ac77fda75da8580e0479087580f83b6e5495fb16df97b9696a2bdf3ae100f452"
FILES = {"worker.py", "project_cache.py", "ghidra_scripts/ReverseAIOptions.java",
         "ghidra_scripts/ReverseAIQuery.java", "ghidra_scripts/ReverseAIPrepare.java"}
ENDPOINT_OVERRIDES = {key: "" for key in ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "BUILDX_BUILDER")}


class RevisionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "source"
        shutil.copytree(build.SOURCE, self.source)
        for name in FILES:
            (self.source / name).write_bytes(("reviewed " + name + "\n").encode())
        self.lock = self.root / "image.lock.json"
        self.docker = FakeDocker()

    def revise(self, route="B", *extra):
        with patch.object(build, "SOURCE", self.source), patch.object(build, "docker", self.docker), \
                patch.dict(os.environ, ENDPOINT_OVERRIDES), contextlib.redirect_stdout(io.StringIO()), \
                patch.object(build, "fetch", side_effect=AssertionError("offline route downloaded")):
            return build.main(["revise", "--route", route, "--lock", str(self.lock), *extra])

    def assert_clean(self):
        self.assertEqual(self.docker.containers, {})
        created = [args[args.index("--name") + 1] for args in self.docker.calls if args[0] == "create"]
        removed = [args[2] for args in self.docker.calls if args[0] == "rm"]
        self.assertCountEqual(created, removed)
        self.assertFalse(any(args[0] in ("start", "run", "exec", "pull") for args in self.docker.calls))

    def test_B_never_starts_or_builds_and_copies_only_the_reviewed_files(self):
        self.assertEqual(self.revise(), 0)
        self.assertEqual(self.docker.calls[0], ("image", "inspect", PARENT))
        creates = [args for args in self.docker.calls if args[0] == "create"]
        self.assertEqual(len(creates), 2)
        for args, image_id in zip(creates, (PARENT, self.docker.image_id)):
            self.assertEqual(args[:6], ("create", "--pull=never", "--platform", "linux/arm64", "--network=none", "--name"))
            self.assertEqual(args[7:], (image_id,))
        uploads = [args for args in self.docker.calls if args[0] == "cp" and ":/opt/" not in args[1]]
        self.assertEqual({args[2].split(":/opt/reverseai/")[1] for args in uploads}, FILES)
        self.assertEqual(len(uploads), 5)
        self.assertEqual([args[0] for args in self.docker.calls].count("commit"), 1)
        self.assertFalse(any(args[0] in ("build", "info", "context") for args in self.docker.calls))
        lock = json.loads(self.lock.read_text())
        self.assertEqual(set(lock), {"adapter_version", "base_digest", "ghidra_sha256", "jdk_sha256", "parent_image_id",
                                     "bundle_sha256", "cache_format", "image_id", "platform"})
        self.assertEqual((lock["parent_image_id"], lock["adapter_version"], lock["cache_format"]), (PARENT, "12.1.4-r7", 1))
        self.assertEqual(lock["ghidra_sha256"], "ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db")
        self.assertEqual(lock["jdk_sha256"], "23e37e026f12f3e706f18938ff611db3032d075b09d0879a25d06718c773e223")
        self.assert_clean()

    def test_A_uses_only_the_closed_context_and_forces_local_legacy_resolution(self):
        self.assertEqual(self.revise("A"), 0)
        self.assertEqual(self.docker.calls[0], ("image", "inspect", PARENT))
        built, = [args for args in self.docker.calls if args[0] == "build"]
        self.assertEqual(built[:5], ("build", "--platform", "linux/arm64", "--pull=false", "--network=none"))
        self.assertEqual(built[5:9], ("--iidfile", built[6], "--tag", "reverseai-ghidra:12.1.4-r7"))
        self.assertEqual(len(built), 10)
        self.assertEqual(self.docker.legacy_calls, [built])
        self.assertEqual(set(self.docker.context), {"Dockerfile", "ghidra_scripts", *FILES})
        self.assertFalse(any(args[0] == "commit" for args in self.docker.calls))
        self.assert_clean()

    def test_legacy_subprocess_explicitly_overrides_ambient_buildkit(self):
        completed = subprocess.CompletedProcess([], 0, stdout="ok\n")
        with patch.dict(os.environ, {"DOCKER_BUILDKIT": "1"}), patch.object(build.subprocess, "run", return_value=completed) as run:
            self.assertEqual(build.docker("build", "context", capture=True, legacy=True), "ok")
        self.assertEqual(run.call_args.args[0], ["docker", "build", "context"])
        self.assertEqual(run.call_args.kwargs["env"]["DOCKER_BUILDKIT"], "0")
        self.assertTrue(run.call_args.kwargs["check"])

    def test_missing_or_aliased_parent_fails_before_any_other_docker_command(self):
        for route in ("A", "B"):
            with self.subTest(route=route, reason="missing"):
                self.docker = FakeDocker()
                self.docker.failure = lambda args: args[:2] == ("image", "inspect")
                with self.assertRaises(subprocess.CalledProcessError):
                    self.revise(route)
                self.assertEqual(self.docker.calls, [("image", "inspect", PARENT)])
            with self.subTest(route=route, reason="wrong identity"):
                self.docker = FakeDocker()
                self.docker.info_changes[PARENT] = {"Id": "sha256:" + "b" * 64}
                with self.assertRaisesRegex(SystemExit, "image ID differs"):
                    self.revise(route)
                self.assertEqual(self.docker.calls, [("image", "inspect", PARENT)])
        self.assertFalse(self.lock.exists())

    def test_unknown_remote_or_containerd_A_backend_refuses_before_create_or_build(self):
        for key, value in (("Driver", "btrfs"), ("Driver", "overlayfs"), ("ServerVersion", "29.0.0"), ("ServerVersion", "28.5.1-vendor"),
                           ("OSType", "windows"), ("Architecture", "amd64"),
                           ("DriverStatus", [["driver-type", "io.containerd.snapshotter.v1"]])):
            with self.subTest(key=key, value=value):
                self.docker = FakeDocker()
                self.docker.server[key] = value
                with self.assertRaisesRegex(SystemExit, "recognized local legacy Engine"):
                    self.revise("A")
                self.assertFalse(any(args[0] in ("create", "build") for args in self.docker.calls))
        self.docker = FakeDocker()
        self.docker.endpoint = "tcp://docker.example:2375"
        with self.assertRaisesRegex(SystemExit, "recognized local legacy Engine"):
            self.revise("A")
        self.assertFalse(self.lock.exists())

    def test_A_endpoint_or_driver_environment_override_is_refused(self):
        for key in ENDPOINT_OVERRIDES:
            with self.subTest(key=key), patch.dict(os.environ, dict(ENDPOINT_OVERRIDES, **{key: "override"})), \
                    patch.object(build, "docker", self.docker):
                with self.assertRaisesRegex(SystemExit, "endpoint or builder overrides"):
                    build.preflight_legacy_builder()
        self.assertEqual(self.docker.calls, [])

    def test_unreviewed_revision_instructions_are_refused_before_creation(self):
        path = self.source / "Dockerfile.revise"
        original = path.read_text()
        mutations = [original + line + "\n" for line in ("RUN true", "ADD https://example.invalid/a /a",
                     "FROM busybox", "COPY --from=other /a /a", "ARG PARENT", "ENV PATH=/attacker", "USER root")]
        mutations += ["# syntax=docker/dockerfile:1\n" + original,
                      original.replace("COPY worker.py /opt/reverseai/worker.py", "COPY . /opt/reverseai/"),
                      original.replace("COPY worker.py", "CO\\\nPY worker.py").replace("USER 65534:65534", "RUN --network=none true\nUSER 65534:65534"),
                      original.replace(PARENT, "reverseai-ghidra:12.1.4-r6")]
        for index, text in enumerate(mutations):
            with self.subTest(index=index):
                self.docker = FakeDocker()
                path.write_text(text)
                with self.assertRaises(SystemExit):
                    self.revise()
                self.assertEqual(self.docker.calls, [("image", "inspect", PARENT)])
        self.assertFalse(self.lock.exists())

    def test_extra_script_or_symlink_bundle_is_refused_before_docker(self):
        extra = self.source / "ghidra_scripts/Evil.java"
        extra.write_bytes(b"unreviewed")
        with self.assertRaisesRegex(SystemExit, "script file set"):
            self.revise()
        extra.unlink()
        helper = self.source / "project_cache.py"
        helper.unlink()
        helper.symlink_to("worker.py")
        with self.assertRaisesRegex(SystemExit, "regular files"):
            self.revise()
        self.assertEqual(self.docker.calls, [])

    def test_staged_revision_dockerfile_is_rechecked_after_a_concurrent_source_change(self):
        original_copy = shutil.copy2

        def replace_during_copy(source, target, *args, **kwargs):
            result = original_copy(source, target, *args, **kwargs)
            if Path(source).name == "Dockerfile.revise":
                with Path(target).open("a") as stream:
                    stream.write("RUN true\n")
            return result

        with patch.object(build.shutil, "copy2", side_effect=replace_during_copy):
            with self.assertRaisesRegex(SystemExit, "revision Dockerfile"):
                self.revise()
        self.assertEqual(self.docker.calls, [("image", "inspect", PARENT)])
        self.assertFalse(self.lock.exists())

    def test_runtime_tree_hashes_symlink_targets_without_following_them(self):
        folder = self.root / "runtime"
        folder.mkdir()
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "secret").write_bytes(b"never hashed through the link")
        (folder / "linked").symlink_to(outside, target_is_directory=True)
        with patch.object(build, "file_sha256", side_effect=AssertionError("followed a symlink")):
            before = build.tree_hashes(folder)
            (folder / "linked").unlink()
            (folder / "linked").symlink_to(self.root, target_is_directory=True)
            after = build.tree_hashes(folder)
        self.assertEqual(set(before), {"linked"})
        self.assertEqual(before["linked"][0], "link")
        self.assertNotEqual(before, after)

    def test_parent_layer_or_runtime_configuration_drift_never_publishes(self):
        baseline = self.docker.image(self.docker.image_id)
        cases = [{"RootFS": {"Type": "layers", "Layers": ["sha256:" + "f" * 64]}}]
        for field, value in (("User", "0"), ("Entrypoint", ["sh"]), ("Env", ["PATH=/evil"]), ("Cmd", ["sh"]),
                             ("WorkingDir", "/evil"), ("Volumes", {"/samples": {}}), ("OnBuild", ["RUN touch /evil"]),
                             ("Healthcheck", {"Test": ["CMD", "sh"]})):
            config = dict(baseline["Config"], **{field: value})
            cases.append({"Config": config})
        for index, changed in enumerate(cases):
            with self.subTest(index=index):
                self.docker = FakeDocker()
                self.docker.info_changes[self.docker.image_id] = changed
                with self.assertRaises(SystemExit):
                    self.revise()
                self.assert_clean()
                self.assertFalse(self.lock.exists())

    def test_runtime_byte_mode_and_bundle_drift_are_detected_from_stopped_snapshots(self):
        changes = [{("jdk", "bin/java"): (b"changed JDK", 0o755)},
                   {("ghidra", "support/analyzeHeadless"): (b"changed Ghidra", 0o755)},
                   {("ghidra", "support/analyzeHeadless"): (b"fixed headless bytes", 0o644)},
                   {("reverseai", "worker.py"): (b"unreviewed worker", 0o644)},
                   {("reverseai", "project_cache.py"): ((self.source / "project_cache.py").read_bytes(), 0o600)},
                   {("reverseai", "ghidra_scripts/Unexpected.java"): (b"extra script", 0o644)}]
        for route in ("A", "B"):
            for changed in changes:
                with self.subTest(route=route, changed=list(changed)):
                    self.docker = FakeDocker()
                    self.docker.result_changes = changed
                    with self.assertRaises(SystemExit):
                        self.revise(route)
                    self.assert_clean()
                    self.assertFalse(self.lock.exists())

    def test_create_copy_commit_build_or_verification_failures_always_remove_stopped_containers(self):
        cases = [("B", lambda args: args[0] == "create"),
                 ("B", lambda args: args[:2] == ("container", "inspect")),
                 ("B", lambda args: args[0] == "cp" and ":/opt/" in args[1]),
                 ("B", lambda args: args[0] == "cp" and ":/opt/" not in args[1]),
                 ("B", lambda args: args[0] == "commit"),
                 ("A", lambda args: args[0] == "build"),
                 ("B", lambda args: args[:2] == ("image", "inspect") and args[2] != PARENT)]
        self.lock.write_bytes(b"existing approved lock\n")
        for route, failure in cases:
            with self.subTest(route=route, failure=failure):
                self.docker = FakeDocker()
                self.docker.failure = failure
                with self.assertRaises(subprocess.CalledProcessError):
                    self.revise(route)
                self.assert_clean()
                self.assertEqual(self.lock.read_bytes(), b"existing approved lock\n")
                self.assertEqual(sorted(path.name for path in self.root.glob("image.lock.json.*")), [])

    def test_bundle_identity_covers_every_file_and_is_independent_of_map_order(self):
        hashes = {name: hashlib.sha256((self.source / name).read_bytes()).hexdigest() for name in FILES}
        canonical = json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode("ascii")
        expected = hashlib.sha256(canonical).hexdigest()
        self.assertEqual(build.bundle_digest(dict(reversed(list(hashes.items())))), expected)
        self.revise()
        self.assertEqual(json.loads(self.lock.read_text())["bundle_sha256"], expected)
        for name in FILES:
            path = self.source / name
            body = path.read_bytes()
            path.write_bytes(body + b"changed\n")
            self.docker = FakeDocker()
            self.revise()
            self.assertNotEqual(json.loads(self.lock.read_text())["bundle_sha256"], expected)
            path.write_bytes(body)

    def test_revision_download_flags_are_rejected_even_if_assets_were_present(self):
        for extra in (("--download",), ("--download-dir", str(self.root))):
            with self.subTest(extra=extra), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    self.revise("B", *extra)
        self.assertEqual(self.docker.calls, [])


if __name__ == "__main__":
    unittest.main()
