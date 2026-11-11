"""tools/host_proof.py with stand-in commands: the shared steps, the POSIX and Windows predicates and the receipt."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("host_proof", ROOT / "tools/host_proof.py")
H = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(H)

COMMIT = "a" * 40
VERSION = H.expected_version(ROOT)
WHEEL = f"reverseai-{VERSION}-py3-none-any.whl"
CLEAN = "....\nRan 4 tests in 0.1s\n\nOK (skipped=1)\n"


class StandIn:
    """Answers every proof command without running it; suite and windows_tests answers are configurable."""
    def __init__(self, *, suite=CLEAN, windows_tests="..\nRan 2 tests in 0.1s\n\nOK\n", fail=(), git=0, real=False,
                 doctor=None):
        self.calls, self.suite, self.windows_tests, self.fail, self.git = [], suite, windows_tests, set(fail), git
        self.doctor = json.dumps({"reverseai": VERSION, "host_ok": True, "tools": []}) if doctor is None else doctor
        self.real = real  # answer the import path with links resolved, as Python does

    def __call__(self, argv, *, timeout, cwd=None, env=None):
        self.calls.append((list(argv), cwd, env))
        name = self.name(argv)
        if name in self.fail:
            return 1, "", "failed on purpose"
        if name == "git":
            return (0, COMMIT + "\n", "") if self.git == 0 else (128, "", "not a git repository")
        if name == "suite":
            return 0, "", self.suite
        if name == "windows_tests":
            return 0, "", self.windows_tests
        if name == "wheel":
            folder = Path(argv[argv.index("--wheel-dir") + 1])
            folder.mkdir()
            (folder / WHEEL).write_bytes(b"PK")
            return 0, "", ""
        if name == "version":
            return 0, f"reverseai {VERSION}\n", ""
        if name == "imported_from":
            venv = Path(argv[0]).parents[1]
            imported = venv / "lib/python3.12/site-packages/reverseai/__init__.py"
            return 0, (os.path.realpath(imported) if self.real else str(imported)) + "\n", ""
        if name == "doctor":
            return 0, self.doctor, ""
        if name in ("analyze", "query"):
            out = Path(argv[argv.index("--out") + 1])
            out.mkdir()
            (out / "report.json").write_text(json.dumps({"input": {"sha256": "1" * 64}, "summary": {"supported": 1}}))
            (out / "report.md").write_text("# report\n")
        return 0, "", ""

    @staticmethod
    def name(argv):
        if argv[0] == "git":
            return "git"
        if argv[1:4] == ["-B", "-m", "unittest"]:
            return "suite" if argv[4] == "discover" else "windows_tests"
        if argv[1:4] == ["-m", "pip", "wheel"]:
            return "wheel"
        if argv[1:3] == ["-m", "venv"]:
            return "venv"
        if argv[1:4] == ["-m", "pip", "install"]:
            return "install"
        if argv[1:3] == ["-I", "-c"]:
            return "imported_from"
        if argv[1:3] == ["-B", "-c"]:
            return "fixture"
        if argv[1:] == ["--version"]:
            return "version"
        if argv[1:] == ["doctor", "--json"]:
            return "doctor"
        if argv[1] in ("analyze", "query"):
            return argv[1]
        raise AssertionError(f"unexpected argv {argv}")


def run_steps(runner, *, windows=False):
    with tempfile.TemporaryDirectory() as folder:
        work, source = Path(folder, "work"), Path(folder, "src")
        work.mkdir()
        (source / ".git").mkdir(parents=True)
        (source / "pyproject.toml").write_text("[project]\n")
        facts = H.steps(runner, work, source, {"PIP_NO_CACHE_DIR": "1"}, windows=windows)
        copied = sorted(path.name for path in (work / "build").iterdir())
        return facts, work, source, copied


class StepTests(unittest.TestCase):
    def test_posix_steps_run_offline_in_order_from_a_copy_and_use_bin(self):
        runner = StandIn()
        facts, work, source, copied = run_steps(runner)
        self.assertEqual(tuple(facts["steps"]), H.POSIX_STEPS)
        self.assertEqual(copied, ["pyproject.toml"])  # .git and caches stay behind
        argvs = {StandIn.name(argv): (argv, cwd) for argv, cwd, _ in runner.calls}
        self.assertEqual(argvs["suite"], ([sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests", "-t", "."],
                                          source))
        self.assertEqual(argvs["wheel"][0], [sys.executable, "-m", "pip", "wheel", "--no-index", "--no-deps",
                                             "--wheel-dir", str(work / "dist"), str(work / "build")])
        self.assertEqual(argvs["install"][0], [str(work / "venv/bin/python"), "-m", "pip", "install", "--no-index",
                                               "--no-deps", str(work / "dist" / WHEEL)])
        self.assertEqual(argvs["query"][0], [str(work / "venv/bin/reverseai"), "query", str(work / "run/input.elf"),
                                             "--query", "list_segments", "--arg", "limit=16", "--out",
                                             str(work / "run/query")])
        self.assertEqual(argvs["fixture"][1], source)
        self.assertTrue(all(env == {"PIP_NO_CACHE_DIR": "1"} for _, _, env in runner.calls))
        self.assertNotIn("windows_tests", facts["steps"])
        self.assertEqual((facts["query"]["reports"], facts["analyze"]["reports"]), (["report.json", "report.md"],) * 2)
        self.assertTrue(H.passed(facts, VERSION))

    def test_windows_steps_use_scripts_and_add_the_windows_report_tests(self):
        runner = StandIn()
        facts, work, source, _ = run_steps(runner, windows=True)
        self.assertEqual(tuple(facts["steps"]), ("suite",) + H.WINDOWS_STEPS)
        argvs = {StandIn.name(argv): (argv, cwd) for argv, cwd, _ in runner.calls}
        self.assertEqual(argvs["install"][0][0], str(work / "venv/Scripts/python.exe"))
        self.assertEqual(argvs["version"][0], [str(work / "venv/Scripts/reverseai.exe"), "--version"])
        self.assertEqual(argvs["windows_tests"], ([sys.executable, "-B", "-m", "unittest", "tests.test_windows_output",
                                                   "-v"], source))
        self.assertEqual(facts["windows_tests"]["ran"], 2)
        self.assertTrue(H.passed(facts, VERSION, windows=True))

    def test_a_failed_wheel_stops_before_any_install(self):
        facts, _, _, _ = run_steps(StandIn(fail={"wheel"}))
        self.assertEqual(list(facts["steps"]), ["suite", "wheel"])
        self.assertIsNone(facts["wheel"])
        self.assertFalse(H.passed(facts, VERSION))


class PredicateTests(unittest.TestCase):
    def facts(self, windows=False, **runner):
        return run_steps(StandIn(**runner), windows=windows)[0]

    def test_posix_needs_every_step_and_a_clean_whole_suite(self):
        self.assertTrue(H.passed(self.facts(), VERSION))
        cases = {"suite failure": dict(suite="F\nRan 4 tests in 0.1s\n\nFAILED (failures=1)\n"),
                 "zero tests": dict(suite="\nRan 0 tests in 0.0s\n\nOK\n"),
                 "unparsed suite": dict(suite="Killed\n")}
        cases.update({f"{name} exit 1": dict(fail={name}) for name in H.POSIX_STEPS})
        for label, runner in cases.items():
            with self.subTest(label=label):
                self.assertFalse(H.passed(self.facts(**runner), VERSION))
        self.assertFalse(H.passed(self.facts(), VERSION + ".1"))
        outside = {**self.facts(), "imported_from": str(ROOT / "reverseai/__init__.py")}
        self.assertFalse(H.passed(outside, VERSION))

    def test_windows_gates_on_its_report_tests_not_on_the_whole_suite(self):
        failing_suite = dict(suite="F\nRan 4 tests in 0.1s\n\nFAILED (failures=1)\n")
        facts = self.facts(windows=True, **failing_suite)
        self.assertEqual(facts["suite"]["failures"], 1)  # recorded
        self.assertTrue(H.passed(facts, VERSION, windows=True))
        self.assertFalse(H.passed(facts, VERSION))
        cases = {"report test failure": dict(windows_tests="F\nRan 2 tests in 0.1s\n\nFAILED (failures=1)\n"),
                 "no report test": dict(windows_tests="\nRan 0 tests in 0.0s\n\nOK\n"),
                 "report tests all skipped": dict(windows_tests="sssssssss\nRan 9 tests in 0.0s\n\nOK (skipped=9)\n"),
                 "one report test skipped": dict(windows_tests="s.\nRan 2 tests in 0.0s\n\nOK (skipped=1)\n")}
        cases.update({f"{name} exit 1": dict(fail={name}) for name in H.WINDOWS_STEPS})
        for label, runner in cases.items():
            with self.subTest(label=label):
                self.assertFalse(H.passed(self.facts(windows=True, **runner), VERSION, windows=True))


    def test_both_hosts_need_doctor_json_saying_host_ok_for_this_version(self):
        doctors = {"malformed": "{not json", "a list": "[1]", "a string": json.dumps("ok"),
                   "host_ok false": json.dumps({"reverseai": VERSION, "host_ok": False, "tools": []}),
                   "host_ok string": json.dumps({"reverseai": VERSION, "host_ok": "true", "tools": []}),
                   "another version": json.dumps({"reverseai": VERSION + ".1", "host_ok": True, "tools": []})}
        for windows in (False, True):
            for label, output in doctors.items():
                with self.subTest(windows=windows, doctor=label):
                    facts = self.facts(windows=windows, doctor=output)
                    self.assertEqual(facts["steps"]["doctor"]["exit"], 0)
                    self.assertFalse(H.passed(facts, VERSION, windows=windows))


class ProveTests(unittest.TestCase):
    def prove(self, runner, *, windows=False, summary=False):
        with tempfile.TemporaryDirectory() as folder, contextlib.redirect_stdout(io.StringIO()) as stdout:
            receipt, summary_file = Path(folder, "receipt.json"), Path(folder, "summary.md")
            environment = {"GITHUB_STEP_SUMMARY": str(summary_file)} if summary else {}
            with patch.dict(os.environ, environment, clear=False):
                if not summary:
                    os.environ.pop("GITHUB_STEP_SUMMARY", None)
                code = H.prove(receipt, runner, windows=windows)
            return (code, json.loads(receipt.read_text()), stdout.getvalue(),
                    summary_file.read_text() if summary_file.exists() else None)

    def test_the_receipt_marker_and_step_summary_carry_the_same_facts(self):
        code, receipt, printed, summary = self.prove(StandIn(), summary=True)
        self.assertEqual(code, 0)
        self.assertEqual((receipt["commit"], receipt["passed"], receipt["expected_version"]), (COMMIT, True, VERSION))
        line, = [line for line in printed.splitlines() if line.startswith(H.MARKER)]
        self.assertEqual(json.loads(line[len(H.MARKER):]), receipt)
        self.assertIn(line, summary)
        self.assertTrue(summary.startswith("### ReverseAI host proof: passed"))
        for key in ("python", "platform", "machine", "steps", "suite", "wheel", "version", "doctor", "query"):
            self.assertIn(key, receipt)

    def test_failures_and_an_unknown_commit_fail_the_receipt(self):
        for runner in (StandIn(fail={"query"}), StandIn(git=1)):
            with self.subTest(fail=runner.fail, git=runner.git):
                code, receipt, printed, summary = self.prove(runner)
                self.assertEqual((code, receipt["passed"], summary), (1, False, None))
                self.assertIn(H.MARKER, printed)
        self.assertIsNone(self.prove(StandIn(git=1))[1]["commit"])

    def test_a_scratch_directory_reached_through_a_link_still_passes(self):
        with tempfile.TemporaryDirectory() as folder:
            real, link = Path(folder, "real"), Path(folder, "link")
            real.mkdir()
            try:
                link.symlink_to(real, target_is_directory=True)
            except OSError:
                self.skipTest("symbolic links are not available here")

            @contextlib.contextmanager
            def linked(prefix=None):
                (real / "work").mkdir()
                yield str(link / "work")

            with patch.object(H, "tempfile", types.SimpleNamespace(TemporaryDirectory=linked)):
                code, receipt, _, _ = self.prove(StandIn(real=True))
        self.assertEqual((code, receipt["passed"]), (0, True))
        self.assertEqual(receipt["venv"], str(real.resolve() / "work/venv"))

    def test_the_windows_receipt_names_windows_and_its_report_tests(self):
        code, receipt, _, _ = self.prove(StandIn(), windows=True)
        self.assertEqual((code, receipt["os"], receipt["windows_tests"]["ran"]), (0, "windows", 2))

    def test_the_environment_drops_python_and_index_redirections(self):
        planted = {"PYTHONPATH": "/elsewhere", "PIP_INDEX_URL": "https://index.invalid/", "PIP_FIND_LINKS": "/x",
                   "KEEP_ME": "1"}
        with patch.dict(os.environ, planted):
            env = H.host_env()
        self.assertFalse({"PYTHONPATH", "PIP_INDEX_URL", "PIP_FIND_LINKS"} & set(env))
        self.assertEqual((env["KEEP_ME"], env["PIP_NO_CACHE_DIR"], env["PYTHONDONTWRITEBYTECODE"]), ("1", "1", "1"))

    def test_the_receipt_must_be_a_new_file_and_posix_only_calls_are_absent(self):
        with tempfile.TemporaryDirectory() as folder, contextlib.redirect_stderr(io.StringIO()):
            existing = Path(folder, "receipt.json")
            existing.write_text("{}")
            with self.assertRaises(SystemExit) as raised:
                H.main(["--receipt", str(existing)])
            self.assertEqual((raised.exception.code, existing.read_text()), (2, "{}"))
        source = (ROOT / "tools/host_proof.py").read_text()
        self.assertNotIn("getuid", source)
        self.assertTrue(source.isascii())


if __name__ == "__main__":
    unittest.main()
