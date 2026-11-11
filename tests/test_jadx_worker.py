"""The JADX worker, its build helper and its build tool without Docker, Java or the internet: request bounds, the
members re-materialized from the snapshot, the driver's answer checked row by row, the whole-run errors, the
Dockerfile shape, the image lock and the exact docker calls. The native proof runs the built image."""

import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile
import zlib

from reverseai.tools import apk
from tests import fixtures_apk as F

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


worker = load("jadx_worker", ROOT / "containers" / "jadx" / "worker.py")
unpack = load("jadx_unpack", ROOT / "containers" / "jadx" / "unpack.py")
build = load("build_jadx_image", ROOT / "tools" / "build_jadx_image.py")


def hexed(text):
    return text.encode("utf-8", "surrogatepass").hex()


def basic():
    data, layout = F.apk_basic()
    members = [m for m in apk.members(data) if m.name in ("classes.dex", "classes2.dex")]
    artifacts = [apk.artifact(m, apk.materialize(data, m)[0]) for m in members]
    return data, layout, artifacts


def request(artifacts, targets=None, start=0, max_chars=1024):
    targets = targets or [{"member": 0, "class": hexed(F.MAIN), "method": hexed("helper"), "prototype": hexed("(I)I")}]
    return ["jadx.method", json.dumps({"members": artifacts, "targets": targets, "start": start, "max_chars": max_chars})]


def row(index, status="ok", code_offset=536, insns_count=10, total=12, text="int x = 1;\n\t"):
    return {"target": index, "status": status, "code_offset": code_offset, "insns_count": insns_count, "total": total,
            "text": text}


def answer(*rows):
    return json.dumps({"targets": list(rows)}).encode()


class RequestTests(unittest.TestCase):
    def setUp(self):
        self.data, self.layout, self.artifacts = basic()

    def test_a_valid_request_decodes_raw_text_and_keeps_its_bounds(self):
        targets = [{"member": 1, "class": hexed(F.WORKER), "method": hexed("run"), "prototype": hexed("()V")},
                   {"member": 0, "class": hexed("La/" + chr(0xd800) + ";"), "method": hexed(chr(0x430)), "prototype": hexed("()V")}]
        members, checked, start, max_chars = worker.parse_request(request(self.artifacts, targets, 5, 64))
        self.assertEqual((members, start, max_chars), (self.artifacts, 5, 64))
        self.assertEqual(checked, [{"dex": 1, "class": F.WORKER, "method": "run", "prototype": "()V"},
                                   {"dex": 0, "class": "La/" + chr(0xd800) + ";", "method": chr(0x430), "prototype": "()V"}])

    def test_every_other_request_is_refused(self):
        good = json.loads(request(self.artifacts)[1])
        target = good["targets"][0]

        def variant(**change):
            return ["jadx.method", json.dumps({**good, **change})]

        def member(**change):
            return variant(members=[{**self.artifacts[0], **change}])

        def aim(**change):
            return variant(targets=[{**target, **change}])

        bad = [["ghidra.analyze", request(self.artifacts)[1]], ["jadx.method"], request(self.artifacts) + ["x"],
               ["jadx.method", "not json"], ["jadx.method", "[]"],
               ["jadx.method", '{"members": [], "members": [], "targets": [], "start": 0, "max_chars": 64}'],
               variant(extra=1), variant(members=[]), variant(members=[self.artifacts[0]] * 17),
               variant(members=[self.artifacts[0], self.artifacts[0]]), variant(targets=[]), variant(targets=[target] * 17),
               variant(start=-1), variant(start=1048576), variant(start=True), variant(max_chars=63), variant(max_chars=2049),
               member(method=12), member(size=0), member(size=32 * 1024 * 1024 + 1), member(crc32=2**32), member(sha256="A" * 64),
               member(member=""), member(member="a\nb"), member(data_offset=-1), member(extra=1),
               member(method=0, compressed_size=self.artifacts[0]["size"] + 1),
               member(method=8, compressed_size=1, size=101), aim(member=2), aim(member=-1), aim(member=True), aim(extra=1),
               aim(**{"class": "abc"}), aim(**{"class": "4C"}), aim(**{"class": "4c3b"}), aim(method=""),
               aim(prototype="ff"), aim(**{"class": "4c" + "61" * 765 + "3b"}), aim(method="c3")]
        for argv in bad:
            with self.subTest(argv=argv[:1] + [a[:80] for a in argv[1:]]), self.assertRaises(worker.InvalidRequest):
                worker.parse_request(argv)

    def test_members_beyond_128_mib_in_all_are_refused(self):
        big = [{**self.artifacts[0], "member": f"classes{i}.dex", "method": 0, "size": 32 * 1024 * 1024,
                "compressed_size": 32 * 1024 * 1024} for i in range(5)]
        with self.assertRaises(worker.InvalidRequest):
            worker.parse_request(request(big))
        worker.parse_request(request(big[:4]))


class MaterializeTests(unittest.TestCase):
    def test_stored_and_deflated_members_equal_their_children(self):
        data, layout, artifacts = basic()
        self.assertEqual([a["method"] for a in artifacts], [8, 0])
        self.assertEqual(worker.materialize(data, artifacts[0]), F.classes_dex()[0])
        self.assertEqual(worker.materialize(data, artifacts[1]), F.classes2_dex()[0])

    def test_any_difference_from_the_artifact_is_the_input_error(self):
        data, layout, artifacts = basic()
        deflated, stored = artifacts
        bad = [(deflated, {"crc32": deflated["crc32"] ^ 1}), (deflated, {"sha256": "0" * 64}),
               (deflated, {"size": deflated["size"] + 1}), (deflated, {"size": deflated["size"] - 1}),
               (deflated, {"compressed_size": deflated["compressed_size"] - 1}),
               (deflated, {"compressed_size": deflated["compressed_size"] + 4}),
               (deflated, {"data_offset": len(data) - 2}), (stored, {"data_offset": stored["data_offset"] + 1}),
               (stored, {"sha256": "0" * 64})]
        for artifact, change in bad:
            with self.subTest(change=change), self.assertRaises(worker.InputMismatch):
                worker.materialize(data, {**artifact, **change})

    def test_inflate_stops_one_byte_past_the_declared_size(self):
        zeros = bytes(1 << 20)
        packed = zlib.compressobj(9, zlib.DEFLATED, -15)
        raw = packed.compress(zeros) + packed.flush()
        artifact = {"member": "z", "method": 8, "data_offset": 0, "compressed_size": len(raw), "size": 4096,
                    "crc32": zlib.crc32(zeros[:4096]), "sha256": hashlib.sha256(zeros[:4096]).hexdigest()}
        seen = []
        real = zlib.decompressobj

        class Counting:
            def __init__(self, *args):
                self.inner = real(*args)

            def decompress(self, data, max_length=0):
                out = self.inner.decompress(data, max_length)
                seen.append((max_length, len(out)))
                return out

            def __getattr__(self, name):
                return getattr(self.inner, name)

        with patch.object(worker.zlib, "decompressobj", Counting), self.assertRaises(worker.InputMismatch):
            worker.materialize(raw, artifact)
        self.assertTrue(seen and all(0 < limit <= 4097 and length <= limit for limit, length in seen))


class RunTests(unittest.TestCase):
    def setUp(self):
        self.data, self.layout, self.artifacts = basic()
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        patcher = patch.object(worker, "WORK", Path(self.folder.name) / "reverseai-jadx")
        patcher.start()
        self.addCleanup(patcher.stop)

    def reply(self, driver, argv=None):
        return worker.reply(argv or request(self.artifacts), self.data, driver=driver)

    def test_the_driver_gets_the_members_and_raw_targets_and_its_rows_become_the_observations(self):
        seen = {}
        targets = [{"member": 0, "class": hexed(F.MAIN), "method": hexed("helper"), "prototype": hexed("(I)I")},
                   {"member": 1, "class": hexed(F.WORKER), "method": hexed("<init>"), "prototype": hexed("()V")}]

        def driver(sent):
            seen.update(sent)
            seen["bytes"] = [Path(p).read_bytes() for p in sent["dex"]]
            return 0, answer(row(0, total=30, text="x" * 20), row(1, "omitted", None, None, 0, ""))

        message = self.reply(driver, request(self.artifacts, targets, start=10, max_chars=64))
        self.assertEqual(set(message), {"protocol", "status", "snapshot_sha256", "observations"})
        self.assertEqual((message["status"], message["snapshot_sha256"]), ("ok", hashlib.sha256(self.data).hexdigest()))
        self.assertEqual(message["observations"], [row(0, total=30, text="x" * 20), row(1, "omitted", None, None, 0, "")])
        self.assertEqual(seen["bytes"], [F.classes_dex()[0], F.classes2_dex()[0]])
        self.assertEqual([Path(p).name for p in seen["dex"]], ["0.dex", "1.dex"])
        self.assertEqual(seen["targets"], [{"dex": 0, "class": F.MAIN, "method": "helper", "prototype": "(I)I"},
                                           {"dex": 1, "class": F.WORKER, "method": "<init>", "prototype": "()V"}])
        self.assertEqual((seen["start"], seen["max_chars"]), (10, 64))
        self.assertEqual(json.loads(worker.encode(message)), message)

    def test_whole_run_failures_have_their_fixed_names(self):
        def timeout(sent):
            raise worker.DriverTimeout()

        cases = [(lambda sent: (worker.OOM_EXIT, b""), "memory"), (timeout, "timeout"),
                 (lambda sent: (1, answer(row(0))), "JadxFailed"), (lambda sent: (0, b"not json"), "JadxFailed")]
        for driver, name in cases:
            with self.subTest(name=name):
                message = self.reply(driver)
                self.assertEqual((set(message), message["status"], message["error"]),
                                 ({"protocol", "status", "snapshot_sha256", "error"}, "error", name))
        tampered = [{**self.artifacts[0], "crc32": self.artifacts[0]["crc32"] ^ 1}, self.artifacts[1]]
        self.assertEqual(self.reply(lambda sent: (0, answer(row(0))), request(tampered))["error"], "input")
        self.assertEqual(worker.reply(request(self.artifacts), None)["error"], "SnapshotUnreadable")
        self.assertEqual(self.reply(lambda sent: (0, b""), ["jadx.method", "{}"])["error"], "InvalidRequest")
        with patch.object(worker, "MAX_INPUT_BYTES", len(self.data) - 1):
            self.assertEqual(self.reply(lambda sent: (0, answer(row(0))))["error"], "InputTooLarge")

    def test_the_driver_answer_is_checked_row_by_row(self):
        good = answer(row(0, total=12, text="int x = 1;\n\t"))
        self.assertEqual(worker.check_answer(good, 1, 0, 64), [row(0, total=12, text="int x = 1;\n\t")])
        self.assertEqual(worker.check_answer(answer(row(0, total=12, text="")), 1, 12, 64)[0]["text"], "")
        self.assertEqual(worker.check_answer(answer(row(0, total=100, text="a" * 64)), 1, 10, 64)[0]["total"], 100)
        for status in ("decompile_failed", "class_not_found", "method_not_found", "no_code", "omitted"):
            worker.check_answer(answer(row(0, status, None, None, 0, "")), 1, 0, 64)
        bad = [b"[]", json.dumps({"targets": [], "extra": 1}).encode(), answer(), answer(row(0), row(1)), answer(row(1)),
               answer({**row(0), "target": True}), answer(row(0, "unknown")), answer(row(0, code_offset=None)),
               answer(row(0, insns_count=0)), answer(row(0, code_offset=2**32)), answer(row(0, total=0, text="")),
               answer(row(0, text="caf" + chr(0xe9) + " x 12ch", total=12)), answer(row(0, text="a\rbcdefghijk", total=12)),
               answer(row(0, text="short", total=12)), answer(row(0, total=100, text="a" * 65)),
               answer(row(0, "no_code", 1, None, 0, "")), answer(row(0, "omitted", None, None, 3, "")),
               answer(row(0, "class_not_found", None, None, 0, "x")), answer({**row(0), "extra": 1}),
               b'{"targets": [], "targets": []}', b"\xff", b"x" * (worker.MAX_DRIVER_BYTES + 1)]
        for raw in bad:
            with self.subTest(raw=raw[:100]), self.assertRaises(worker.JadxFailed):
                worker.check_answer(raw, 1, 0, 64)

    def test_the_driver_command_is_fixed(self):
        argv = worker.driver_argv()
        self.assertEqual(argv[0], "/opt/jdk/bin/java")
        self.assertIn("-Xmx1536m", argv)
        self.assertIn("-XX:+ExitOnOutOfMemoryError", argv)
        self.assertEqual(argv[-3:], ["-cp", "/opt/reverseai/driver:/opt/jadx/jadx-1.5.6-all.jar", "ReverseAIJadx"])
        self.assertEqual(worker.OOM_EXIT, 3)
        self.assertLess(worker.DRIVER_SECONDS, 120)

    def test_a_slow_driver_is_killed_and_its_output_is_bounded(self):
        worker.WORK.mkdir()
        slow = [sys.executable, "-c", "import time; time.sleep(30)"]
        with patch.object(worker, "driver_argv", lambda: slow), patch.object(worker, "DRIVER_SECONDS", 0.5):
            with self.assertRaises(worker.DriverTimeout):
                worker.run_driver({"dex": []})
        (worker.WORK / "driver.json").unlink()
        loud = [sys.executable, "-c", f"import sys; sys.stdin.read(); sys.stdout.write('x' * {worker.MAX_DRIVER_BYTES + 10})"]
        with patch.object(worker, "driver_argv", lambda: loud):
            code, raw = worker.run_driver({"dex": []})
        self.assertEqual((code, len(raw)), (0, worker.MAX_DRIVER_BYTES + 1))


class UnpackTests(unittest.TestCase):
    def archive(self, folder, members):
        path = Path(folder) / "jadx.zip"
        with zipfile.ZipFile(path, "w") as bundle:
            for name, data in members:
                bundle.writestr(name, data)
        return path

    def test_only_the_jar_and_licence_are_taken_and_the_jar_hash_is_checked(self):
        jar = b"stand-in jar"
        with tempfile.TemporaryDirectory() as folder:
            path = self.archive(folder, [("README.md", b"r"), (unpack.JAR, jar), ("LICENSE", b"Apache"), ("bin/jadx", b"#!")])
            out = Path(folder) / "out"
            unpack.jadx(path, hashlib.sha256(jar).hexdigest(), out)
            self.assertEqual(sorted(p.name for p in out.iterdir()), ["LICENSE", "jadx-1.5.6-all.jar"])
            self.assertEqual((out / "jadx-1.5.6-all.jar").read_bytes(), jar)
            for members in ([(unpack.JAR, jar)], [("LICENSE", b"A")], [(unpack.JAR, jar), (unpack.JAR, jar), ("LICENSE", b"A")]):
                with self.subTest(members=[m[0] for m in members]), contextlib.redirect_stderr(io.StringIO()):
                    target = Path(tempfile.mkdtemp(dir=folder))
                    with self.assertRaises(SystemExit):
                        unpack.jadx(self.archive(target, members), hashlib.sha256(jar).hexdigest(), target / "out")
            with self.assertRaises(SystemExit):
                unpack.jadx(path, "0" * 64, Path(folder) / "other")
            self.assertFalse((Path(folder) / "other" / "jadx-1.5.6-all.jar").exists())
            with self.assertRaises(SystemExit):
                unpack.check(path, "0" * 64)


class FakeDocker:
    def __init__(self, image_id="sha256:" + "a" * 64, base_present=True, on_build=None):
        self.calls, self.context, self.image_id, self.base_present = [], None, image_id, base_present
        self.on_build, self.built = on_build, {}

    def __call__(self, *args, capture=False):
        self.calls.append(args)
        if args[:2] == ("image", "inspect") and not self.base_present:
            raise subprocess.CalledProcessError(1, "docker")
        if args[0] == "build":
            context = Path(args[-1])
            self.context = sorted(str(path.relative_to(context)) for path in context.rglob("*"))
            self.built = {name: build.file_sha256(context / name) for name in ("worker.py", "driver/ReverseAIJadx.java")}
            if self.on_build:
                self.on_build()
            Path(args[args.index("--iidfile") + 1]).write_text(self.image_id)
        return "sha256:" + "b" * 64 if capture else None


class BuildToolTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.downloads = Path(self.folder.name)
        self.fake = {"jadx": b"stand-in JADX zip", "jdk": b"stand-in JDK"}
        self.assets = {key: dict(asset, size=len(self.fake[key]), sha256=hashlib.sha256(self.fake[key]).hexdigest())
                       for key, asset in build.ASSETS.items()}
        for key, asset in self.assets.items():
            (self.downloads / asset["name"]).write_bytes(self.fake[key])
        self.lock = self.downloads / "image.lock.json"

    def main(self, docker):
        with patch.object(build, "ASSETS", self.assets), patch.object(build, "docker", docker), \
                contextlib.redirect_stdout(io.StringIO()):
            return build.main(["--download-dir", str(self.downloads), "--lock", str(self.lock)])

    def test_a_build_never_pulls_runs_offline_and_writes_the_nine_lock_keys(self):
        docker = FakeDocker()
        self.assertEqual(self.main(docker), 0)
        self.assertEqual(docker.calls[0], ("image", "inspect", "--format", "{{.Id}}", build.BASE))
        self.assertEqual(len(docker.calls), 2)
        call = docker.calls[1]
        self.assertEqual(call[:5], ("build", "--platform", "linux/arm64", "--pull=false", "--network=none"))
        self.assertNotIn("pull", [c[0] for c in docker.calls])
        self.assertIn("downloads/jadx-1.5.6.zip", docker.context)
        self.assertIn("driver/ReverseAIJadx.java", docker.context)
        lock = json.loads(self.lock.read_text())
        self.assertEqual(set(lock), {"adapter_version", "platform", "base_digest", "jadx_zip_sha256", "jadx_jar_sha256",
                                     "jdk_sha256", "driver_sha256", "worker_sha256", "image_id"})
        self.assertEqual((lock["adapter_version"], lock["platform"], lock["image_id"]), ("1.5.6-r1", "linux/arm64", docker.image_id))
        self.assertEqual(lock["driver_sha256"], build.file_sha256(build.SOURCE / "driver" / "ReverseAIJadx.java"))
        self.assertEqual(lock["worker_sha256"], build.file_sha256(build.SOURCE / "worker.py"))

    def test_missing_or_different_inputs_an_absent_base_and_a_bad_image_id_are_refused(self):
        for key in self.assets:
            path = self.downloads / self.assets[key]["name"]
            path.write_bytes(self.fake[key] + b"!")
            with self.subTest(changed=key), self.assertRaises(SystemExit):
                self.main(FakeDocker())
            path.write_bytes(self.fake[key])
        with self.assertRaises(SystemExit):
            self.main(FakeDocker(base_present=False))
        with self.assertRaises(SystemExit):
            self.main(FakeDocker(image_id="no id"))
        self.assertFalse(self.lock.exists())

    def private_source(self):
        source = self.downloads / "jadx-source"
        shutil.copytree(build.SOURCE, source)
        patcher = patch.object(build, "SOURCE", source)
        patcher.start()
        self.addCleanup(patcher.stop)
        return source

    def test_the_lock_names_the_built_context_and_an_edit_during_the_build_writes_no_lock(self):
        # The hashes are of the bytes Docker builds; a source changed meanwhile refuses the lock.
        source = self.private_source()
        docker = FakeDocker()
        self.assertEqual(self.main(docker), 0)
        lock = json.loads(self.lock.read_text())
        self.assertEqual((lock["worker_sha256"], lock["driver_sha256"]),
                         (docker.built["worker.py"], docker.built["driver/ReverseAIJadx.java"]))
        self.lock.unlink()
        for name in ("worker.py", "driver/ReverseAIJadx.java"):
            original = (source / name).read_bytes()

            def edit(name=name):
                with open(source / name, "ab") as stream:
                    stream.write(b"\n# edited during the build\n" if name.endswith(".py") else b"\n// edited during the build\n")
            with self.subTest(edited=name), self.assertRaisesRegex(SystemExit, "changed during the build"):
                self.main(FakeDocker(on_build=edit))
            self.assertFalse(self.lock.exists())
            (source / name).write_bytes(original)

    def test_a_source_edited_right_after_its_copy_writes_no_lock(self):
        # The lock must name the copied bytes, not the repository's at hashing time. An edit that
        # lands after a file is copied and before anything is hashed leaves the image with the old bytes: refused.
        source = self.private_source()
        real_copytree, real_copy = shutil.copytree, shutil.copy2

        def edit(path):
            with open(path, "ab") as stream:
                stream.write(b"\n# edited right after the copy\n" if path.suffix == ".py" else b"\n// edited right after the copy\n")

        for name in ("worker.py", "driver/ReverseAIJadx.java"):
            original = (source / name).read_bytes()

            def copytree(src, dst, *args, **kwargs):
                result = real_copytree(src, dst, *args, **kwargs)
                if name.startswith(Path(src).name + "/"):
                    edit(source / name)
                return result

            def copy(src, dst, *args, **kwargs):
                result = real_copy(src, dst, *args, **kwargs)
                if Path(src) == source / name:
                    edit(source / name)
                return result
            docker = FakeDocker()
            with self.subTest(edited=name), patch.object(build.shutil, "copytree", copytree), \
                    patch.object(build.shutil, "copy2", copy), self.assertRaisesRegex(SystemExit, "changed during the build"):
                self.main(docker)
            self.assertEqual(docker.built[name], hashlib.sha256(original).hexdigest())
            self.assertFalse(self.lock.exists())
            (source / name).write_bytes(original)

    def test_the_copied_dockerfile_is_checked_again_before_the_build(self):
        self.private_source()
        real_copy = shutil.copy2

        def copy(source, target, *args, **kwargs):
            result = real_copy(source, target, *args, **kwargs)
            if Path(target).name == "Dockerfile":
                with open(target, "a") as stream:
                    stream.write("ADD x /x\n")
            return result
        docker = FakeDocker()
        with patch.object(build.shutil, "copy2", copy), self.assertRaisesRegex(SystemExit, "ADD"):
            self.main(docker)
        self.assertNotIn("build", [call[0] for call in docker.calls])
        self.assertFalse(self.lock.exists())

    def test_the_pinned_inputs_are_the_approved_ones(self):
        self.assertEqual(build.ASSETS["jadx"]["sha256"], "545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974")
        self.assertEqual(build.ASSETS["jadx"]["size"], 72_646_741)
        self.assertEqual(build.ASSETS["jdk"]["sha256"], "23e37e026f12f3e706f18938ff611db3032d075b09d0879a25d06718c773e223")
        self.assertEqual(build.JAR_SHA256, "fe3e12c45acf75f92369685fd02d1d7a7323385dc725680a9b98a0dac0ea554b")

    def test_the_real_dockerfile_is_accepted_and_every_other_shape_refused(self):
        real = (build.SOURCE / "Dockerfile").read_text()
        build.check_dockerfile(build.SOURCE / "Dockerfile")
        self.assertIn("545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974", real)
        self.assertIn(build.JAR_SHA256, real)
        variants = [real.replace("RUN --network=none python3", "RUN python3"), real.replace("FROM python", "FROM debian", 1),
                    real + "ADD x /x\n", real + "COPY --from=build /etc /etc\n", real.replace("USER 65534:65534\n", ""),
                    "# syntax=docker/dockerfile:1\n" + real, real + "RUN --network=none --mount=from=other,target=/x true\n",
                    real.replace("COPY --from=build /opt/jadx /opt/jadx\n", ""), real + "\x07"]
        for text in variants:
            path = self.downloads / "Dockerfile"
            path.write_bytes(text.encode("latin-1"))
            with self.subTest(text=text[-60:]), self.assertRaises(SystemExit):
                build.check_dockerfile(path)


class LockTests(unittest.TestCase):
    def test_the_committed_lock_matches_the_sources_and_the_approved_inputs(self):
        lock = json.loads((ROOT / "containers" / "jadx" / "image.lock.json").read_text())
        self.assertEqual(set(lock), {"adapter_version", "platform", "base_digest", "jadx_zip_sha256", "jadx_jar_sha256",
                                     "jdk_sha256", "driver_sha256", "worker_sha256", "image_id"})
        self.assertEqual((lock["adapter_version"], lock["platform"], lock["base_digest"]),
                         (worker.ADAPTER_VERSION, build.PLATFORM, build.BASE_DIGEST))
        self.assertEqual((lock["jadx_zip_sha256"], lock["jadx_jar_sha256"], lock["jdk_sha256"]),
                         (build.ASSETS["jadx"]["sha256"], build.JAR_SHA256, build.ASSETS["jdk"]["sha256"]))
        self.assertEqual(lock["driver_sha256"], build.file_sha256(build.SOURCE / "driver" / "ReverseAIJadx.java"))
        self.assertEqual(lock["worker_sha256"], build.file_sha256(build.SOURCE / "worker.py"))
        self.assertRegex(lock["image_id"], r"^sha256:[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
