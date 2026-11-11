"""tools/linux_proof.py with stand-in git, Docker and pip; nothing here builds, runs or pulls an image."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("linux_proof", ROOT / "tools/linux_proof.py")
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)

COMMIT = "c" * 40
IMAGE = "sha256:" + "e" * 64
WHEEL = "reverseai-0.9.0-py3-none-any.whl"


def doctor_facts(version="0.9.0"):
    return {"reverseai": version, "host_ok": True, "docker": {"answered": False},
            "tools": [{"tool": name, "lock_loads": True,
                       "lock": f"/tmp/venv/lib/python3.12/site-packages/reverseai/_locks/{name}.json"}
                      for name in ("lief", "yarax", "ghidra", "jadx", "jsparser")]}


def inside_facts(**changes):
    facts = {"python": "3.12.9", "platform": "Linux-6.10-aarch64-with-glibc2.36", "machine": "aarch64", "uid": 65534,
             "suite": {"ran": 1750, "skipped": 1, "failures": 0, "errors": 0, "expected_failures": 0,
                       "unexpected_successes": 0, "ok": True},
             "wheel": {"name": WHEEL, "size": 1, "sha256": "0" * 64}, "version": "reverseai 0.9.0",
             "imported_from": "/tmp/venv/lib/python3.12/site-packages/reverseai/__init__.py",
             "doctor": doctor_facts(), "analyze": {"reports": ["report.json", "report.md"]},
             "query": {"reports": ["report.json", "report.md"]}, "venv": "/tmp/venv",
             "steps": {name: {"exit": 0} for name in P.REQUIRED_STEPS}}
    facts.update(changes)
    return facts


def marker(**changes):
    return P.MARKER + json.dumps(inside_facts(**changes)) + "\n"


class HostDocker:
    """Stateful stand-in for git and docker on the host; records every argv.

    run is (exit, stdout, stderr) or an exception; leaves says whether --rm removed the container by itself, so a
    lost client connection (nonzero exit) leaves it running until "docker rm --force" removes it."""
    def __init__(self, base=True, run=None, leaves=None, build=0, silent=False):
        self.calls, self.base, self.build, self.silent = [], base, build, silent
        self.run = (0, "noise\n" + marker(), "") if run is None else run
        self.leaves = (isinstance(self.run, tuple) and self.run[0] == 0) if leaves is None else leaves
        self.containers, self.images = set(), set()

    def __call__(self, argv, *, timeout, cwd=None, env=None):
        self.calls.append(list(argv))
        if argv[:4] == ["git", "-C", str(P.ROOT), "rev-parse"]:
            return 0, COMMIT + "\n", ""
        if argv[:4] == ["git", "-C", str(P.ROOT), "archive"]:
            Path(argv[argv.index("-o") + 1]).write_bytes(b"tar")
            return 0, "", ""
        if argv[:4] == ["git", "-C", str(P.ROOT), "show"]:
            return 0, '"""ReverseAI."""\n\n__version__ = "0.9.0"\n', ""
        if self.silent and argv[:2] == ["docker", "image"] and argv[2] in ("rm", "inspect") and argv[-1] == IMAGE:
            return None, "", ""
        if argv[:5] == ["docker", "image", "inspect", "--format", "{{.Id}}"]:
            if argv[5] == P.BASE:
                return (0, "sha256:base\n", "") if self.base else (1, "", "Error: No such image")
            return (0, IMAGE, "") if argv[5] in self.images else (1, "", "Error: No such image: " + argv[5])
        if argv[:5] == ["docker", "container", "inspect", "--format", "{{.Id}}"]:
            return (0, "id", "") if argv[5] in self.containers else (1, "", "Error: No such container: " + argv[5])
        if argv[:2] == ["docker", "build"]:
            Path(argv[argv.index("--iidfile") + 1]).write_text(IMAGE)
            self.images.add(IMAGE)
            return self.build, "", "client lost" if self.build else ""
        if argv[:2] == ["docker", "run"]:
            name = argv[argv.index("--name") + 1]
            self.containers.add(name)
            if isinstance(self.run, BaseException):
                raise self.run
            if self.leaves:
                self.containers.discard(name)
            return self.run
        if argv[:3] == ["docker", "rm", "--force"]:
            if argv[3] not in self.containers:
                return 1, "", "Error: No such container: " + argv[3]
            self.containers.discard(argv[3])
            return 0, argv[3], ""
        if argv[:4] == ["docker", "image", "rm", "--no-prune"]:
            self.images.discard(argv[4])
            return 0, "", ""
        raise AssertionError(f"unexpected argv {argv}")


class DockerfileAndArgvTests(unittest.TestCase):
    def test_the_image_is_the_pinned_base_plus_the_archive_with_no_run_step(self):
        lines = P.DOCKERFILE.splitlines()
        self.assertEqual(lines[0], "FROM " + P.BASE)
        self.assertEqual(lines[1:3], ["ADD source.tar /opt/", "USER 65534:65534"])
        self.assertFalse(any(line.split()[0] in ("RUN", "COPY", "VOLUME", "EXPOSE") for line in lines))
        for tool in ("lief", "yarax", "ghidra", "jadx", "jsparser"):
            lock = json.loads((ROOT / f"containers/{tool}/image.lock.json").read_text())
            self.assertEqual(lock["base_digest"], P.BASE_DIGEST)
        self.assertTrue(P.DOCKERFILE.isascii())

    def test_docker_calls_never_pull_mount_or_open_the_network(self):
        build = P.build_argv(Path("/ctx"), Path("/ctx/image.id"), "reverseai-linux-proof:" + COMMIT[:12])
        self.assertEqual(build[:2], ["docker", "build"])
        self.assertIn("--pull=false", build)
        self.assertIn("--network=none", build)
        run = P.run_argv(IMAGE, "reverseai-linux-proof-0123")
        for flag in (["--pull", "never"], ["--network", "none"], ["--user", "65534:65534"], ["--cap-drop", "ALL"],
                     ["--security-opt", "no-new-privileges"], ["--platform", "linux/arm64"]):
            self.assertIn(flag, [run[i:i + 2] for i in range(len(run) - 1)])
        self.assertIn("--read-only", run)
        self.assertEqual(run[-1], IMAGE)
        self.assertFalse({"-v", "--volume", "--mount", "--privileged", "--network=host"} & set(run))
        self.assertEqual(P.remove_argv(IMAGE), ["docker", "image", "rm", "--no-prune", IMAGE])


class SuiteCountTests(unittest.TestCase):
    def test_closing_lines_give_exact_counts_or_none(self):
        self.assertEqual(P.suite_counts("....\nRan 1748 tests in 41.453s\n\nOK (skipped=1)\n"),
                         {"ran": 1748, "skipped": 1, "failures": 0, "errors": 0, "expected_failures": 0,
                          "unexpected_successes": 0, "ok": True})
        failed = P.suite_counts("Ran 9 tests in 1s\n\nFAILED (failures=2, errors=1, skipped=3, expected failures=1)")
        self.assertEqual((failed["ok"], failed["failures"], failed["errors"], failed["skipped"],
                          failed["expected_failures"]), (False, 2, 1, 3, 1))
        self.assertEqual(P.suite_counts("Ran 1 test in 0.1s\n\nOK")["ran"], 1)
        for text in ("", "OK", "Ran 3 tests in 1s\n\nOK (mystery=1)", "Ran 3 tests in 1s\n\nInterrupted"):
            with self.subTest(text=text):
                self.assertIsNone(P.suite_counts(text))


class ProveTests(unittest.TestCase):
    def prove(self, docker):
        with tempfile.TemporaryDirectory() as folder, contextlib.redirect_stdout(io.StringIO()) as stdout:
            receipt = Path(folder, "platform-linux-arm64.json")
            code = P.prove("m6-rc1", receipt, runner=docker, pause=0)
            return code, json.loads(receipt.read_text()), stdout.getvalue()

    def assert_cleaned(self, docker, receipt):
        self.assertEqual((docker.containers, docker.images), (set(), set()))
        self.assertIn(["docker", "image", "rm", "--no-prune", IMAGE], docker.calls)
        self.assertTrue(all(argv[3] == receipt["container"] for argv in docker.calls if argv[:2] == ["docker", "rm"]))
        self.assertEqual((receipt["container_removed"], receipt["image_removed"]), (True, True))

    def test_a_passing_run_writes_the_receipt_and_removes_its_image(self):
        docker = HostDocker()
        code, receipt, printed = self.prove(docker)
        self.assertEqual(code, 0, receipt)
        self.assertEqual((receipt["commit"], receipt["base_digest"], receipt["platform"], receipt["image_id"]),
                         (COMMIT, P.BASE_DIGEST, "linux/arm64", IMAGE))
        self.assertEqual((receipt["passed"], receipt["docker_exit"], receipt["error"]), (True, 0, None))
        self.assertEqual(receipt["inside"]["suite"]["ran"], 1750)
        self.assertIn("passed: " + COMMIT[:12], printed)
        self.assert_cleaned(docker, receipt)
        kinds = [" ".join(argv[:3]) for argv in docker.calls]
        self.assertEqual(kinds, ["git -C " + str(P.ROOT), "docker image inspect", "git -C " + str(P.ROOT),
                                 "git -C " + str(P.ROOT), "docker build --platform", "docker run --rm",
                                 "docker rm --force", "docker container inspect", "docker image rm",
                                 "docker image inspect"])
        archive = next(argv for argv in docker.calls if "archive" in argv)
        self.assertEqual(archive[-1], COMMIT)
        self.assertIn("--prefix=src/", archive)

    def test_failures_still_remove_the_owned_container_and_image_and_fail_the_receipt(self):
        bad_suite = {"ran": 3, "skipped": 0, "failures": 1, "errors": 0, "expected_failures": 0,
                     "unexpected_successes": 0, "ok": False}
        cases = {"timeout": (None, "", ""), "no marker": (1, "Traceback", "boom"),
                 "lost client after a success marker": (77, marker(), "connection lost"),
                 "suite failed": (0, marker(suite=bad_suite), ""),
                 "source tree imported": (0, marker(imported_from="/opt/src/reverseai/__init__.py"), ""),
                 "lock from the checkout": (0, marker(doctor={**doctor_facts(), "tools": [
                     {**doctor_facts()["tools"][0], "lock": "/opt/src/containers/x"}]}), ""),
                 "two markers": (0, marker() * 2, "")}
        for label, outcome in cases.items():
            with self.subTest(label=label):
                docker = HostDocker(run=outcome)
                code, receipt, printed = self.prove(docker)
                self.assertEqual((code, receipt["passed"], receipt["docker_exit"]), (1, False, outcome[0]))
                self.assert_cleaned(docker, receipt)
                self.assertTrue(printed.startswith("FAILED"))
        _, receipt, _ = self.prove(HostDocker(run=(77, marker(), "connection lost")))
        self.assertIn("docker run exited 77", receipt["error"])
        self.assertEqual(receipt["inside"]["suite"]["ran"], 1750)  # kept for diagnosis, not trusted

    def test_an_interrupt_after_the_container_started_still_removes_it_and_the_image(self):
        docker = HostDocker(run=KeyboardInterrupt())
        with tempfile.TemporaryDirectory() as folder, self.assertRaises(KeyboardInterrupt):
            P.prove("m6-rc1", Path(folder, "receipt.json"), runner=docker, pause=0)
        self.assertEqual((docker.containers, docker.images), (set(), set()))
        name = next(argv[argv.index("--name") + 1] for argv in docker.calls if argv[:2] == ["docker", "run"])
        self.assertIn(["docker", "rm", "--force", name], docker.calls)

    def test_a_build_that_named_an_image_and_then_failed_removes_that_image(self):
        docker = HostDocker(build=1)
        code, receipt, _ = self.prove(docker)
        self.assertEqual((code, receipt["passed"], receipt["image_id"]), (1, False, IMAGE))
        self.assertIn("docker build failed (exit 1)", receipt["error"])
        self.assertFalse(any(argv[:2] in (["docker", "run"], ["docker", "rm"]) for argv in docker.calls))
        self.assertEqual((docker.images, receipt["image_removed"], receipt["container_removed"]), (set(), True, True))

    def test_docker_silence_is_not_counted_as_removal(self):
        code, receipt, _ = self.prove(HostDocker(silent=True))
        self.assertEqual((code, receipt["passed"], receipt["image_removed"]), (1, False, False))

    def test_a_missing_base_refuses_before_any_build(self):
        docker = HostDocker(base=False)
        with tempfile.TemporaryDirectory() as folder, self.assertRaisesRegex(SystemExit, "never pulls"):
            P.prove("m6-rc1", Path(folder, "receipt.json"), runner=docker)
        self.assertFalse(any(argv[:2] in (["docker", "build"], ["docker", "run"]) for argv in docker.calls))

    def test_the_receipt_must_be_a_new_file(self):
        with tempfile.TemporaryDirectory() as folder, contextlib.redirect_stderr(io.StringIO()):
            existing = Path(folder, "receipt.json")
            existing.write_text("{}")
            with self.assertRaises(SystemExit) as raised:
                P.main(["--commit", "m6-rc1", "--receipt", str(existing)])
            self.assertEqual(raised.exception.code, 2)
            self.assertEqual(existing.read_text(), "{}")


class PassedTests(unittest.TestCase):
    def test_every_required_fact_is_needed(self):
        self.assertTrue(P.passed(inside_facts(), "0.9.0"))
        empty = {"ran": 0, "skipped": 0, "failures": 0, "errors": 0, "expected_failures": 0,
                 "unexpected_successes": 0, "ok": True}
        changes = {"zero tests": {"suite": empty}, "suite exit 17": {"steps": {
                       **inside_facts()["steps"], "suite": {"exit": 17}}},
                   "a missing step": {"steps": {name: {"exit": 0} for name in P.REQUIRED_STEPS[:-1]}},
                   "x86_64": {"machine": "x86_64"}, "macOS": {"platform": "macOS-27.0-arm64"},
                   "root": {"uid": 0}, "Python 3.13": {"python": "3.13.1"}, "no wheel": {"wheel": None}}
        for label, change in changes.items():
            with self.subTest(label=label):
                self.assertFalse(P.passed(inside_facts(**change), "0.9.0"))


class InsideTests(unittest.TestCase):
    """The in-container sequence with stand-in commands: offline pip, a fresh venv, the installed entry point."""

    def runner(self, work, *, wheel_ok=True):
        calls = []

        def run(argv, *, timeout, cwd=None, env=None):
            calls.append((list(argv), cwd, env))
            if argv[1:4] == ["-B", "-m", "unittest"]:
                return 0, "", "......\nRan 6 tests in 0.1s\n\nOK (skipped=1)\n"
            if argv[1:4] == ["-m", "pip", "wheel"]:
                if wheel_ok:
                    Path(argv[argv.index("--wheel-dir") + 1]).mkdir()
                    Path(argv[argv.index("--wheel-dir") + 1], WHEEL).write_bytes(b"PK")
                return (0 if wheel_ok else 1), "", ""
            if argv[1:3] == ["-m", "venv"] or argv[1:4] == ["-m", "pip", "install"]:
                return 0, "", ""
            if argv[1:] == ["--version"]:
                return 0, "reverseai 0.9.0\n", ""
            if argv[1:3] == ["-I", "-c"]:
                return 0, "/tmp/venv/lib/python3.12/site-packages/reverseai/__init__.py\n", ""
            if argv[1:] == ["doctor", "--json"]:
                return 0, json.dumps(doctor_facts()), ""
            if argv[1:3] == ["-B", "-c"]:
                return 0, "", ""
            if argv[1] in ("analyze", "query"):
                out = Path(argv[argv.index("--out") + 1])
                out.mkdir()
                (out / "report.json").write_text(json.dumps({"input": {"sha256": "1" * 64}, "summary": {"supported": 3}}))
                (out / "report.md").write_text("# report\n")
                return 0, "", ""
            raise AssertionError(f"unexpected argv {argv}")
        return run, calls

    def test_every_step_runs_offline_in_order_and_the_facts_pass(self):
        with tempfile.TemporaryDirectory() as folder:
            work, source = Path(folder, "tmp"), Path(folder, "src")
            work.mkdir()
            source.mkdir()
            (source / "pyproject.toml").write_text("[project]\n")
            run, calls = self.runner(work)
            facts = P.inside(runner=run, work=work, source=source)
        names = list(facts["steps"])
        self.assertEqual(names, ["suite", "wheel", "venv", "install", "version", "imported_from", "doctor", "fixture",
                                 "analyze", "query"])
        self.assertEqual(tuple(names), P.REQUIRED_STEPS)
        argvs = [argv for argv, _, _ in calls]
        self.assertIn("--no-index", argvs[1])
        self.assertEqual(argvs[1][-1], str(work / "build"))
        self.assertIn("--no-index", argvs[3])
        self.assertEqual(argvs[3][-1], str(work / "dist" / WHEEL))
        self.assertEqual(argvs[4], [str(work / "venv/bin/reverseai"), "--version"])
        self.assertFalse(any("sdist" in part or part.startswith("http") for argv in argvs for part in argv))
        self.assertEqual(calls[0][1], source)
        self.assertTrue(all(env["HOME"] == str(work / "home") and env["PIP_NO_CACHE_DIR"] == "1"
                            and not {"HTTP_PROXY", "HTTPS_PROXY"} & set(env) for _, _, env in calls))
        self.assertEqual(facts["suite"]["ran"], 6)
        self.assertEqual(facts["wheel"]["name"], WHEEL)
        self.assertEqual(facts["analyze"]["reports"], ["report.json", "report.md"])
        container = {"machine": "aarch64", "platform": "Linux-7.0-aarch64-with-glibc2.41", "python": "3.12.15",
                     "uid": 65534, "venv": "/tmp/venv"}  # this test runs on the host; the container reports these
        self.assertTrue(P.passed({**facts, **container}, "0.9.0"))
        self.assertFalse(P.passed({**facts, **container}, "0.7.1"))

    def test_a_failed_wheel_build_stops_before_any_install(self):
        with tempfile.TemporaryDirectory() as folder:
            work, source = Path(folder, "tmp"), Path(folder, "src")
            work.mkdir()
            source.mkdir()
            run, calls = self.runner(work, wheel_ok=False)
            facts = P.inside(runner=run, work=work, source=source)
        self.assertEqual(list(facts["steps"]), ["suite", "wheel"])
        self.assertIsNone(facts["wheel"])
        self.assertFalse(P.passed(facts, "0.9.0"))

    def test_a_suite_timeout_with_bytes_output_keeps_structured_timeout_facts(self):
        def timed_out(argv, *, timeout, cwd=None, env=None):
            if argv[1:4] == ["-B", "-m", "unittest"]:
                return None, b"", b"....\nFAIL: test_x (tests.test_y.Z.test_x)\n"
            return 1, "", ""
        with tempfile.TemporaryDirectory() as folder:
            work, source = Path(folder, "tmp"), Path(folder, "src")
            work.mkdir()
            source.mkdir()
            facts = P.inside(runner=timed_out, work=work, source=source)
        self.assertEqual((facts["suite"], facts["steps"]["suite"]["exit"], facts["steps"]["suite"]["timed_out"]),
                         (None, None, True))
        self.assertEqual(facts["steps"]["suite"]["failed_tests"], ["FAIL: test_x (tests.test_y.Z.test_x)"])
        json.dumps(facts)

    def test_a_real_timeout_returns_text_streams(self):
        helper = "import sys, time\nsys.stdout.write('out'); sys.stderr.write('err')\nsys.stdout.flush(); sys.stderr.flush()\ntime.sleep(30)"
        code, out, err = P.run([sys.executable, "-I", "-c", helper], timeout=1)
        self.assertEqual((code, type(out), type(err)), (None, str, str))
        self.assertEqual(P.suite_counts(err), None)


if __name__ == "__main__":
    unittest.main()
