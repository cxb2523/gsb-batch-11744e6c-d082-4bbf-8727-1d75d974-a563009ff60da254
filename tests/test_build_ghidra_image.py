"""tools/build_ghidra_image.py without Docker or the internet: the Dockerfile shape, the download URL, redirect, size
and hash rules, the build context and the exact docker calls."""

import contextlib
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import tempfile
import subprocess
import unittest
import urllib.request
import zipfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("build_ghidra_image", ROOT / "tools" / "build_ghidra_image.py")
build = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(build)
FAKE = {"ghidra": b"stand-in Ghidra zip, never unpacked", "jdk": b"stand-in JDK tarball, never unpacked"}
BASE = "FROM " + build.BASE


def assets():
    return {key: dict(asset, sha256=hashlib.sha256(FAKE[key]).hexdigest()) for key, asset in build.ASSETS.items()}

PREFIX = ("FROM " + build.BASE + " AS natives\nRUN apt-get update\nFROM " + build.BASE
          + "\nCOPY --from=natives /opt/jdk /opt/jdk\nCOPY --from=natives /opt/ghidra /opt/ghidra\n").encode()


class FakeDocker:
    def __init__(self, image_id="sha256:" + "a" * 64):
        self.calls, self.context, self.image_id = [], None, image_id
        self.containers, self.bundle, self.legacy_calls = {}, {}, []
        self.info_changes, self.result_changes = {}, {}
        self.failure = None
        self.server = {"ServerVersion": "28.5.1", "OSType": "linux", "Architecture": "aarch64", "Driver": "overlay2",
                       "DriverStatus": [["Backing Filesystem", "extfs"]]}
        self.endpoint = "unix:///var/run/docker.sock"

    def image(self, image_id):
        value = {"Id": image_id, "Os": "linux", "Architecture": "arm64",
                 "RootFS": {"Type": "layers", "Layers": ["sha256:" + "1" * 64] +
                            ([] if image_id == build.PARENT_IMAGE_ID else ["sha256:" + "2" * 64])},
                 "Config": {"User": "65534:65534", "Entrypoint": ["python3", "-I", "-B", "/opt/reverseai/worker.py"],
                            "Env": ["PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8"], "Cmd": ["python3"],
                            "WorkingDir": "", "Volumes": None, "OnBuild": None}}
        value.update(copy.deepcopy(self.info_changes.get(image_id, {})))
        return value

    def runtime(self, image_id):
        files = {("jdk", "bin/java"): (b"fixed JDK java bytes", 0o755),
                 ("ghidra", "support/analyzeHeadless"): (b"fixed headless bytes", 0o755),
                 ("ghidra", "Ghidra/Features/Decompiler/os/linux_arm_64/decompile"): (b"fixed decompiler bytes", 0o755),
                 ("ghidra", "GPL/DemanglerGnu/os/linux_arm_64/demangler_gnu_v2_41"): (b"fixed demangler bytes", 0o755)}
        bundle = self.bundle if image_id != build.PARENT_IMAGE_ID else {"worker.py": b"old worker",
                  "ghidra_scripts/ReverseAIOptions.java": b"old options", "ghidra_scripts/ReverseAIQuery.java": b"old query"}
        files.update({("reverseai", name): (body, 0o644) for name, body in bundle.items()})
        if image_id != build.PARENT_IMAGE_ID:
            files.update(self.result_changes)
        return files

    def __call__(self, *args, capture=False, legacy=False):
        self.calls.append(args)
        if legacy:
            self.legacy_calls.append(args)
        if self.failure is not None and self.failure(args):
            raise subprocess.CalledProcessError(1, ["docker", *args])
        if args[0] == "build":
            context = Path(args[-1])
            self.context = sorted(str(path.relative_to(context)) for path in context.rglob("*"))
            self.downloads = {path.name: path.read_bytes() for path in (context / "downloads").iterdir()} if (context / "downloads").is_dir() else {}
            self.bundle = {name: (context / name).read_bytes() for name in (
                "worker.py", "project_cache.py", "ghidra_scripts/ReverseAIOptions.java",
                "ghidra_scripts/ReverseAIPrepare.java", "ghidra_scripts/ReverseAIQuery.java")}
            Path(args[args.index("--iidfile") + 1]).write_text(self.image_id + "\n")
        elif args[:2] == ("image", "inspect"):
            return json.dumps([self.image(args[2])])
        elif args[:2] == ("context", "inspect"):
            return json.dumps([{"Endpoints": {"docker": {"Host": self.endpoint}}}])
        elif args[0] == "info":
            return json.dumps(self.server)
        elif args[0] == "create":
            name = args[args.index("--name") + 1]
            self.containers[name] = (args[-1], self.runtime(args[-1]))
            return "c" * 64
        elif args[:2] == ("container", "inspect"):
            return json.dumps([{"Image": self.containers[args[2]][0], "State": {"Running": False, "Status": "created"},
                                "Mounts": [], "HostConfig": {"NetworkMode": "none", "Binds": None}}])
        elif args[0] == "cp":
            if ":/opt/" in args[1]:
                name, root = args[1].split(":/opt/", 1)
                root = root.removesuffix("/.")
                for (tree, relative), (body, mode) in self.containers[name][1].items():
                    if root == tree:
                        path = Path(args[2]) / relative
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_bytes(body)
                        path.chmod(mode)
            else:
                name, relative = args[2].split(":/opt/reverseai/", 1)
                self.containers[name][1][("reverseai", relative)] = (Path(args[1]).read_bytes(), 0o644)
        elif args[0] == "commit":
            self.bundle = {relative: body for (tree, relative), (body, _) in self.containers[args[1]][1].items()
                           if tree == "reverseai"}
            return self.image_id
        elif args[0] == "rm":
            self.containers.pop(args[2], None)


class BuildTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.downloads = self.root / "downloads"
        self.downloads.mkdir()
        for key, asset in build.ASSETS.items():
            (self.downloads / asset["name"]).write_bytes(FAKE[key])
        self.lock = self.root / "image.lock.json"
        self.docker = FakeDocker()
        self.source = self.root / "source"
        shutil.copytree(build.SOURCE, self.source)
        # The other R1 source owner can still be writing these files while this
        # isolated builder suite runs. Fake builds require only inert bytes.
        for name in ("project_cache.py", "ghidra_scripts/ReverseAIPrepare.java"):
            if not (self.source / name).exists():
                (self.source / name).write_bytes(b"fake reviewed bundle member\n")

    def build(self, *extra, source=None):
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(build, "docker", self.docker))
            stack.enter_context(patch.object(build, "ASSETS", assets()))
            stack.enter_context(patch.object(build, "SOURCE", source or self.source))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            return build.main(["--download-dir", str(self.downloads), "--lock", str(self.lock), *extra])

    def copy(self, label):
        source = self.root / label.replace(" ", "-")
        shutil.copytree(self.source, source, ignore=shutil.ignore_patterns("image.lock.json"))
        return source

    def dockerfile(self, label, lines):
        source = self.copy(label)
        (source / "Dockerfile").write_text("\n".join(lines) + "\n")
        return source

    def test_full_build_keeps_networked_assets_and_writes_the_nine_r7_lock_keys(self):
        self.assertEqual(self.build(), 0)
        pull, built = self.docker.calls[:2]
        self.assertEqual(pull, ("pull", "--platform", "linux/arm64", build.BASE))
        self.assertEqual(built[:4], ("build", "--platform", "linux/arm64", "--pull=false"))
        self.assertEqual(built[4:8], ("--iidfile", built[5], "--tag", "reverseai-ghidra:12.1.4-r7"))
        self.assertEqual(len(built), 9)  # network is restricted by the Dockerfile itself (one natives RUN)
        self.assertEqual(self.docker.context, [
            "Dockerfile", "downloads", "downloads/" + build.ASSETS["jdk"]["name"], "downloads/" + build.ASSETS["ghidra"]["name"],
            "ghidra_scripts", "ghidra_scripts/ReverseAIOptions.java", "ghidra_scripts/ReverseAIPrepare.java",
            "ghidra_scripts/ReverseAIQuery.java", "project_cache.py", "unpack.py", "worker.py"])
        self.assertEqual(self.docker.downloads, {build.ASSETS[key]["name"]: FAKE[key] for key in FAKE})
        self.assertEqual(json.loads(self.lock.read_text()), {
            "adapter_version": "12.1.4-r7", "base_digest": build.BASE_DIGEST, "image_id": "sha256:" + "a" * 64,
            "ghidra_sha256": hashlib.sha256(FAKE["ghidra"]).hexdigest(), "jdk_sha256": hashlib.sha256(FAKE["jdk"]).hexdigest(),
            "platform": "linux/arm64", "parent_image_id": None, "cache_format": 1,
            "bundle_sha256": hashlib.sha256(json.dumps({name: hashlib.sha256((self.source / name).read_bytes()).hexdigest()
                for name in ("worker.py", "project_cache.py", "ghidra_scripts/ReverseAIOptions.java",
                             "ghidra_scripts/ReverseAIQuery.java", "ghidra_scripts/ReverseAIPrepare.java")},
                sort_keys=True, separators=(",", ":")).encode()).hexdigest()})
        self.assertEqual(self.docker.containers, {})

    def test_the_pinned_assets_are_the_owner_approved_files(self):
        self.assertEqual(build.ASSETS["ghidra"]["sha256"], "ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db")
        self.assertEqual(build.ASSETS["jdk"]["sha256"], "23e37e026f12f3e706f18938ff611db3032d075b09d0879a25d06718c773e223")
        self.assertTrue(build.ASSETS["ghidra"]["url"].startswith("https://github.com/NationalSecurityAgency/ghidra/releases/download/"))
        self.assertTrue(build.ASSETS["jdk"]["url"].startswith("https://github.com/adoptium/temurin21-binaries/releases/download/"))
        self.assertEqual((build.ASSETS["ghidra"]["limit"], build.ASSETS["jdk"]["limit"]), (640 * 1024 * 1024, 256 * 1024 * 1024))

    def test_a_missing_or_different_download_is_refused_before_docker(self):
        (self.downloads / build.ASSETS["jdk"]["name"]).write_bytes(FAKE["jdk"] + b"!")
        with self.assertRaisesRegex(SystemExit, "does not match its pinned SHA-256"):
            self.build()
        (self.downloads / build.ASSETS["jdk"]["name"]).unlink()
        with self.assertRaisesRegex(SystemExit, r"missing .* \(or pass --download\)"):
            self.build()
        self.assertEqual(self.docker.calls, [])

    def test_download_fetches_only_what_is_missing(self):
        (self.downloads / build.ASSETS["jdk"]["name"]).unlink()
        fetched = []

        def fetch(asset, folder):
            fetched.append(asset["name"])
            (Path(folder) / asset["name"]).write_bytes(FAKE["jdk"])

        with patch.object(build, "fetch", fetch):
            self.assertEqual(self.build("--download"), 0)
        self.assertEqual(fetched, [build.ASSETS["jdk"]["name"]])

    def test_a_build_without_a_well_formed_image_id_writes_no_lock(self):
        for written in ("", "a" * 64, "sha256:" + "A" * 64, "sha256:" + "a" * 63):
            with self.subTest(image_id=written):
                self.docker = FakeDocker(written)
                with self.assertRaisesRegex(SystemExit, "no image ID"):
                    self.build()
                self.assertFalse(self.lock.exists())

    def test_trailing_backslash_runs_match_a_native_buildkit_parse(self):
        """Measured with buildx v0.37.2 (cache-only builds): only a single trailing backslash, with or without
        spaces after it, joins the next line; runs of 2 to 5 end the instruction."""
        joins = {1: True, 2: False, 3: False, 4: False, 5: False}
        for run, joined in joins.items():
            for tail in ("", "  "):
                with self.subTest(run=run, tail=tail):
                    lines = build.logical_instructions("RUN echo first " + "\\" * run + tail + "\nRUN echo SECOND\n")
                    self.assertEqual(len(lines), 1 if joined else 2)
                    source = self.copy(f"run-{run}{'-spaces' if tail else ''}")
                    (source / "Dockerfile").write_bytes(PREFIX + ("RUN --network=none true " + "\\" * run + tail + "\n").encode()
                                                        + b"ADD https://example.invalid/x /x\nUSER 65534:65534\n")
                    if joined:  # Parser check only: this is intentionally not the closed full Dockerfile.
                        build.check_dockerfile(source / "Dockerfile")
                    else:
                        with self.assertRaisesRegex(SystemExit, "ADD is refused"):
                            self.build(source=source)
                    self.docker.calls.clear()

    def test_control_bytes_and_escaped_backslashes_cannot_hide_an_instruction(self):
        body = PREFIX
        user = b"USER 65534:65534\n"
        add = b"ADD https://example.invalid/x /x\n"
        for label, content, reason in (
                ("backslash and form feed, then ADD", body + b"RUN --network=none true \\\x0c" + add + user, "without control bytes"),
                ("a continuation line of only 0x1f", body + b"RUN --network=none true \\\n\x1f\n" + add + user, "without control bytes"),
                ("vertical tab", body + b"RUN --network=none true\x0b" + add + user, "without control bytes"),
                ("a lone carriage return", body + b"RUN --network=none true\r" + add + user, "without control bytes"),
                ("NUL", body + b"RUN --network=none true\x00\n" + user, "without control bytes"),
                ("DEL", body + b"RUN --network=none true\x7f\n" + user, "without control bytes"),
                ("ADD split across a CRLF continuation", (body + b"A\\\nDD https://example.invalid/x /x\n" + user).replace(b"\n", b"\r\n"),
                 "ADD is refused"),
                ("escaped trailing backslash before ADD", body + b"RUN --network=none true \\\\\n" + add + user, "ADD is refused")):
            with self.subTest(label):
                source = self.copy(label)
                (source / "Dockerfile").write_bytes(content)
                with self.assertRaisesRegex(SystemExit, reason):
                    self.build(source=source)
                self.assertEqual(self.docker.calls, [])
        crlf = self.copy("CRLF line ends")
        (crlf / "Dockerfile").write_bytes((body + b"RUN --network=none true \\\n    && true\n" + user).replace(b"\n", b"\r\n"))
        build.check_dockerfile(crlf / "Dockerfile")

    def test_the_real_dockerfile_is_accepted(self):
        build.check_dockerfile(build.SOURCE / "Dockerfile")

    def test_the_dockerfile_content_is_pinned(self):
        instructions = [" ".join(words) for words in build.logical_instructions((build.SOURCE / "Dockerfile").read_text())]
        final = instructions[instructions.index("FROM " + build.BASE):]
        self.assertEqual(final[:9], [
            "FROM " + build.BASE, "COPY --from=natives /opt/jdk /opt/jdk", "COPY --from=natives /opt/ghidra /opt/ghidra",
            "COPY worker.py /opt/reverseai/worker.py", "COPY project_cache.py /opt/reverseai/project_cache.py",
            "COPY ghidra_scripts/ReverseAIOptions.java /opt/reverseai/ghidra_scripts/ReverseAIOptions.java",
            "COPY ghidra_scripts/ReverseAIQuery.java /opt/reverseai/ghidra_scripts/ReverseAIQuery.java",
            "COPY ghidra_scripts/ReverseAIPrepare.java /opt/reverseai/ghidra_scripts/ReverseAIPrepare.java", "USER 65534:65534"])
        self.assertEqual(len(final), 11)
        self.assertTrue(final[9].startswith('RUN --network=none ["python3", "-I", "-B", "-c", "import os, importlib.util as u;'))
        for piece in ("'/opt/jdk/bin/java'", "'/opt/ghidra/support/analyzeHeadless'", "os/linux_arm_64/decompile'",
                      "os/linux_arm_64/demangler_gnu_v2_41'", "['ReverseAIOptions.java', 'ReverseAIPrepare.java', 'ReverseAIQuery.java']",
                      "['ghidra_scripts', 'project_cache.py', 'worker.py']"):
            self.assertIn(piece, final[9])
        self.assertEqual(final[10], 'ENTRYPOINT ["python3", "-I", "-B", "/opt/reverseai/worker.py"]')
        self.assertFalse([line for line in instructions if line.split()[0].upper() in ("ENV", "VOLUME", "ARG", "ONBUILD", "SHELL")])
        natives = instructions[:instructions.index("FROM " + build.BASE)]
        self.assertEqual(natives[1], "RUN apt-get update && apt-get install -y --no-install-recommends g++=4:14.2.0-1 make=4.4.1-2 "
                                     "&& rm -rf /var/lib/apt/lists/*")
        unpack = next(line for line in natives if "unpack.py ghidra" in line)
        for key, mode in (("ghidra", "ghidra"), ("jdk", "check")):
            asset = build.ASSETS[key]
            with self.subTest(key):
                checked = unpack.index(f"/tmp/unpack.py {mode} /tmp/{asset['name']} {asset['sha256']}")
                uses = [i for i in range(len(unpack)) if unpack.startswith("/tmp/" + asset["name"], i)]
                self.assertEqual(min(uses), checked + len(f"/tmp/unpack.py {mode} "))  # checked before any other use
        self.assertIn("--strip-components=1 --no-same-owner", unpack)
        self.assertIn("rm /tmp/" + build.ASSETS["jdk"]["name"], unpack)
        self.assertIn("rm -rf /opt/ghidra/docs /tmp/" + build.ASSETS["ghidra"]["name"], unpack)

    def test_every_other_dockerfile_shape_is_refused_before_docker(self):
        natives, final = BASE + " AS natives", BASE
        apt = "RUN apt-get update && apt-get install -y g++ make"
        offline = "RUN --network=none true"
        copy = ["COPY --from=natives /opt/jdk /opt/jdk", "COPY --from=natives /opt/ghidra /opt/ghidra"]
        user = "USER 65534:65534"
        cases = (
            ("one stage only", [final, offline, user], "FROM differs"),
            ("stage under another name", [BASE + " AS builder", apt, final, user], "FROM differs"),
            ("other base for the natives", ["FROM debian:trixie AS natives", apt, final, user], "FROM differs"),
            ("a third stage", [natives, apt, BASE + " AS extra", final, user], "FROM differs"),
            ("stages swapped", [final, natives, apt, user], "FROM differs"),
            ("lower-case as", [BASE + " as natives", apt, final, user], "FROM differs"),
            ("FROM split by a continuation", [natives, apt, final, "FR\\", "OM busybox", user], "FROM differs"),
            ("COPY from another image", [natives, apt, final, "COPY --from=busybox /bin/sh /bin/sh", user], "another image or stage"),
            ("COPY from a stage index", [natives, apt, final, "COPY --from=0 /opt /opt", user], "another image or stage"),
            ("RUN from another image", [natives, apt, final, offline.replace("true", "") + "--mount=type=bind,from=natives,target=/x true", user],
             "another image or stage"),
            ("ADD", [natives, apt, final, "ADD https://example.invalid/x /x", user], "ADD is refused"),
            ("ADD split", [natives, apt, final, "A\\", "DD x /x", user], "ADD is refused"),
            ("directive", ["# syntax=docker/dockerfile:1", natives, apt, final, user], "parser directives"),
            ("non-ASCII", [natives, apt, final, "# caf\u00e9", user], "must be ASCII"),
            ("lower-case add", [natives, apt, final, *copy, "add https://example.invalid/x /x", user], "ADD is refused"),
            ("ADD after an escaped trailing backslash", [natives, apt, final, *copy, "RUN --network=none true \\\\",
                                                         "ADD https://example.invalid/x /x", user], "ADD is refused"),
            ("only the JDK copied", [natives, apt, final, copy[0], user], "copy only /opt/jdk and /opt/ghidra"),
            ("another path copied", [natives, apt, final, *copy, "COPY --from=natives /usr/bin /usr/bin", user],
             "copy only /opt/jdk and /opt/ghidra"),
            ("copied to another place", [natives, apt, final, copy[0], "COPY --from=natives /opt/ghidra /usr/local/ghidra", user],
             "copy only /opt/jdk and /opt/ghidra"),
            ("network in the image", [natives, apt, final, *copy, "RUN true", user], "network in one natives RUN only"),
            ("network twice in the natives", [natives, apt, "RUN make", final, *copy, user], "network in one natives RUN only"),
            ("no network step at all", [natives, offline, final, *copy, user], "network in one natives RUN only"),
            ("the one network step in the image", [natives, offline, final, *copy, "RUN apt-get update", user], "network in one natives RUN only"),
            ("network flag elsewhere", [natives, apt, final, *copy, "RUN true --network=none", user], "network in one natives RUN only"),
            ("no USER", [natives, apt, final, *copy], "exactly one USER"),
            ("lower-case extra user", [natives, apt, final, *copy, user, "user root"], "exactly one USER"),
            ("USER root", [natives, apt, final, *copy, "USER root"], "exactly one USER"),
        )
        for label, lines, reason in cases:
            with self.subTest(label):
                with self.assertRaisesRegex(SystemExit, reason):
                    self.build(source=self.dockerfile(label, lines))
                self.assertEqual(self.docker.calls, [])
        allowed = self.dockerfile("smallest accepted", [natives, apt, offline, final, *copy, offline, user])
        build.check_dockerfile(allowed / "Dockerfile")


UNPACK_SPEC = importlib.util.spec_from_file_location("ghidra_unpack", ROOT / "containers" / "ghidra" / "unpack.py")
unpack = importlib.util.module_from_spec(UNPACK_SPEC)
UNPACK_SPEC.loader.exec_module(unpack)


class UnpackTests(unittest.TestCase):
    """The natives-stage helper: hash first, members only inside the destination, exec bits kept."""

    def archive(self, folder, members):
        path = Path(folder, "g.zip")
        with zipfile.ZipFile(path, "w") as bundle:
            for name, mode, body in members:
                info = zipfile.ZipInfo(name)
                info.external_attr = mode << 16
                bundle.writestr(info, body)
        return path, hashlib.sha256(path.read_bytes()).hexdigest()

    def test_members_are_unpacked_with_their_exec_bits(self):
        with tempfile.TemporaryDirectory() as folder:
            path, digest = self.archive(folder, [("g/support/analyzeHeadless", 0o100755, b"#!/bin/bash\n"),
                                                 ("g/support/launch.properties", 0o100644, b"x=1\n"),
                                                 ("g/support/setuid", 0o104755, b"x"), ("g/support/sticky", 0o101666, b"y")])
            unpack.main(["ghidra", str(path), digest, str(Path(folder, "out"))])
            self.assertEqual(oct(Path(folder, "out/g/support/analyzeHeadless").stat().st_mode & 0o777), "0o755")
            self.assertEqual(oct(Path(folder, "out/g/support/launch.properties").stat().st_mode & 0o777), "0o644")
            self.assertEqual(oct(Path(folder, "out/g/support/setuid").stat().st_mode & 0o7777), "0o755")
            self.assertEqual(oct(Path(folder, "out/g/support/sticky").stat().st_mode & 0o7777), "0o644")

    def test_a_wrong_hash_or_an_escaping_member_is_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            path, digest = self.archive(folder, [("g/ok", 0o100644, b"ok")])
            with self.assertRaisesRegex(SystemExit, "pinned SHA-256"):
                unpack.main(["ghidra", str(path), "0" * 64, str(Path(folder, "out"))])
            with self.assertRaisesRegex(SystemExit, "pinned SHA-256"):
                unpack.main(["check", str(path), "0" * 64])
            unpack.main(["check", str(path), digest])
            Path(folder, "inside-src").mkdir()
            inside, inside_digest = self.archive(Path(folder, "inside-src"), [("g/sub/../kept", 0o100644, b"k")])
            unpack.main(["ghidra", str(inside), inside_digest, str(Path(folder, "inside"))])  # a ".." that stays inside is accepted
            self.assertEqual(Path(folder, "inside/g/kept").read_bytes(), b"k")
            for label, member in (("parent path", ("../escape", 0o100644, b"x")), ("absolute", ("/tmp/abs", 0o100644, b"x")),
                                  ("link", ("g/link", 0o120777, b"/etc/passwd"))):
                with self.subTest(label):
                    bad, bad_digest = self.archive(Path(folder), [member])
                    with self.assertRaisesRegex(SystemExit, "unsafe member"):
                        unpack.main(["ghidra", str(bad), bad_digest, str(Path(folder, label.replace(" ", "-")))])
            self.assertFalse(Path(folder, "escape").exists())
            self.assertFalse(Path(folder, "out").exists())  # a wrong hash is refused before anything is unpacked
            Path(folder, "dup").mkdir()
            duplicate, duplicate_digest = self.archive(Path(folder, "dup"), [("g/a", 0o100644, b"one"), ("g/a", 0o100644, b"two")])
            with self.assertRaisesRegex(SystemExit, "duplicate member"):
                unpack.main(["ghidra", str(duplicate), duplicate_digest, str(Path(folder, "dup-out"))])
            with self.assertRaisesRegex(SystemExit, "usage"):
                unpack.main(["ghidra", str(path)])


class Response(io.BytesIO):
    pass


class Opener:
    def __init__(self, body):
        self.body, self.calls = body, []

    def open(self, url, timeout):
        self.calls.append((url, timeout))
        return Response(self.body)


class DownloadTests(unittest.TestCase):
    def fetch(self, body, asset=None, limit=None):
        asset = dict(asset or assets()["jdk"])
        if limit is not None:
            asset["limit"] = limit
        opener = Opener(body)
        with tempfile.TemporaryDirectory() as folder, \
                patch.object(build.urllib.request, "build_opener", return_value=opener) as factory:
            try:
                return build.fetch(asset, folder).read_bytes(), opener, factory
            finally:
                self.left = sorted(path.name for path in Path(folder).iterdir())

    def test_pinned_bytes_are_kept_through_the_restricted_redirect_handler(self):
        kept, opener, factory = self.fetch(FAKE["jdk"])
        self.assertEqual(kept, FAKE["jdk"])
        factory.assert_called_once_with(build.ReleaseAssetRedirects)
        self.assertEqual(opener.calls, [(build.ASSETS["jdk"]["url"], 60)])
        self.assertEqual(self.left, [build.ASSETS["jdk"]["name"]])

    def test_other_bytes_or_too_many_are_refused_and_nothing_is_left(self):
        for label, body, limit, reason in (("other bytes", FAKE["jdk"] + b"!", None, "does not match its pinned SHA-256"),
                                           ("over the cap", FAKE["jdk"], len(FAKE["jdk"]) - 1, "larger than its size cap")):
            with self.subTest(label):
                with self.assertRaisesRegex(SystemExit, reason):
                    self.fetch(body, limit=limit)
                self.assertEqual(self.left, [])

    def test_the_first_url_must_be_the_pinned_github_release_url(self):
        asset = assets()["ghidra"]
        for url in ("http://github.com/x/" + asset["name"], "https://example.invalid/x/" + asset["name"],
                    "https://github.com:8443/x/" + asset["name"], "https://github.com.evil.invalid/x/" + asset["name"],
                    "https://github.com/x/" + asset["name"] + ".exe"):
            with self.subTest(url), tempfile.TemporaryDirectory() as folder, \
                    patch.object(build.urllib.request, "build_opener", side_effect=AssertionError("request made")):
                with self.assertRaisesRegex(SystemExit, "not its pinned GitHub release URL"):
                    build.fetch(dict(asset, url=url), folder)

    def test_redirects_go_only_to_release_asset_hosts_over_https(self):
        handler = build.ReleaseAssetRedirects()
        request = urllib.request.Request(build.ASSETS["ghidra"]["url"])
        for url in ("https://release-assets.githubusercontent.com/x?sig=1", "https://objects.githubusercontent.com/x"):
            with self.subTest(url):
                self.assertEqual(handler.redirect_request(request, None, 302, "Found", {}, url).full_url, url)
        for url in ("http://release-assets.githubusercontent.com/x", "https://example.invalid/x",
                    "https://release-assets.githubusercontent.com:8443/x", "https://user:pw@objects.githubusercontent.com/x",
                    "https://githubusercontent.com/x", "https://release-assets.githubusercontent.com.evil.invalid/x"):
            with self.subTest(url), self.assertRaisesRegex(SystemExit, "outside the GitHub release-asset hosts"):
                handler.redirect_request(request, None, 302, "Found", {}, url)
        self.assertEqual(build.ReleaseAssetRedirects.max_redirections, 2)


if __name__ == "__main__":
    unittest.main()
