"""Prove the current checkout on this host: the whole suite, then its wheel built, installed offline and run.

Usage (from the repository root, also the manual CI's only step):
    python -B tools/host_proof.py --receipt NEW_FILE

Nothing is downloaded and no sample is run. steps() is the one implementation of the proof steps; the Linux
container proof (tools/linux_proof.py --inside) calls it too. In a scratch directory: the whole suite on the
checkout, pip wheel --no-index --no-deps from a copy (no sdist), a fresh venv (bin/ or Scripts\\) with the wheel
installed --no-index, then the installed reverseai answers --version, its import path, doctor --json, analyze and
query --out of one code-built ELF; on Windows also tests.test_windows_output. The receipt names the commit
(git rev-parse HEAD), Python, platform, machine and every step's exit and output tail; it is written to a new file,
printed on one line after the marker REVERSEAI-HOST-PROOF and appended to $GITHUB_STEP_SUMMARY when that is set.
POSIX passes when every step exits 0 and the whole suite runs clean; Windows when the install, version, doctor,
fixture, analyze, query and Windows report tests pass, the whole suite's counts being recorded without gating.
Every command is an argv list; nothing goes through a shell.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import platform
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
MARKER = "REVERSEAI-HOST-PROOF "
SUITE_SECONDS = 1200
STEP_SECONDS = 300
TAIL_LINES = 40
POSIX_STEPS = ("suite", "wheel", "venv", "install", "version", "imported_from", "doctor", "fixture", "analyze",
               "query")
WINDOWS_STEPS = POSIX_STEPS[1:] + ("windows_tests",)
# Writes the code-built ELF with imports (tests/fixtures_structure.py) to the path in argv[1]; inert bytes, never run.
FIXTURE = ("import sys\nfrom tests import fixtures_structure as F\n"
           "open(sys.argv[1], 'xb').write(F.elf_imports()[0])\n")
# Environment that could point Python or pip at other code or an index; the proof passes --no-index anyway.
DROPPED_ENV = ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_FIND_LINKS",
               "PIP_CONFIG_FILE")
PIP_ENV = {"PIP_NO_CACHE_DIR": "1", "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PIP_NO_INPUT": "1",
           "PYTHONDONTWRITEBYTECODE": "1"}


def as_text(value):
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else (value or "")


def run(argv, *, timeout, cwd=None, env=None):
    """(exit code, stdout, stderr) of one argv, always as text; a timeout gives exit code None."""
    try:
        done = subprocess.run(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                              errors="replace", timeout=timeout, shell=False)
    except subprocess.TimeoutExpired as expired:
        # TimeoutExpired keeps the bytes read so far even with text=True.
        return None, as_text(expired.stdout), as_text(expired.stderr)
    return done.returncode, done.stdout, done.stderr


def tail(text, lines=TAIL_LINES):
    return as_text(text).splitlines()[-lines:]


def suite_counts(stderr):
    """Counts from unittest's closing lines: {"ran", "skipped", "failures", "errors", "ok"}, or None."""
    ran = re.findall(r"^Ran (\d+) tests? in ", stderr, re.M)
    last = stderr.rstrip().splitlines()[-1] if stderr.strip() else ""
    status = re.fullmatch(r"(OK|FAILED)(?: \(([^)]*)\))?", last)
    if not ran or status is None:
        return None
    counts = {"ran": int(ran[-1]), "skipped": 0, "failures": 0, "errors": 0, "expected_failures": 0,
              "unexpected_successes": 0}
    for item in filter(None, (status.group(2) or "").split(", ")):
        key, _, value = item.partition("=")
        key = key.replace(" ", "_")
        if key not in counts or not value.isdigit():
            return None
        counts[key] = int(value)
    counts["ok"] = status.group(1) == "OK"
    return counts


def clean(counts, *, at_least=1):
    return bool(counts and counts["ok"] and counts["ran"] >= at_least
                and counts["failures"] == counts["errors"] == counts["unexpected_successes"] == 0)


def venv_programs(venv, windows):
    scripts, suffix = (venv / "Scripts", ".exe") if windows else (venv / "bin", "")
    return scripts / ("python" + suffix), scripts / ("reverseai" + suffix)


def reports(folder):
    if not (folder / "report.json").is_file():
        return None
    document = json.loads((folder / "report.json").read_text(encoding="utf-8"))
    return {"input_sha256": document["input"]["sha256"], "summary": document["summary"],
            "reports": sorted(path.name for path in folder.iterdir())}


def steps(runner, work, source, env, *, windows=False):
    """Run the proof steps in the empty directory work; return the facts (platform facts are the caller's)."""
    facts = {"steps": {}}
    record = facts["steps"]

    def step(name, argv, *, timeout=STEP_SECONDS, cwd=None):
        code, out, err = runner(argv, timeout=timeout, cwd=cwd, env=env)
        out, err = as_text(out), as_text(err)
        record[name] = {"exit": code, "timed_out": code is None, "stdout": tail(out), "stderr": tail(err)}
        return code, out, err

    _, _, err = step("suite", [sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests", "-t", "."],
                     timeout=SUITE_SECONDS, cwd=source)
    facts["suite"] = suite_counts(err)
    record["suite"]["failed_tests"] = [line for line in err.splitlines() if line.startswith(("FAIL: ", "ERROR: "))][:50]
    build, dist, venv, scratch = work / "build", work / "dist", work / "venv", work / "run"
    facts["venv"] = str(venv)
    shutil.copytree(source, build, symlinks=True, ignore=shutil.ignore_patterns(".git", "__pycache__"))
    scratch.mkdir()
    code, _, _ = step("wheel", [sys.executable, "-m", "pip", "wheel", "--no-index", "--no-deps", "--wheel-dir",
                                str(dist), str(build)])
    wheels = sorted(dist.glob("reverseai-*-py3-none-any.whl")) if code == 0 else []
    if len(wheels) != 1:
        facts["wheel"] = None
        return facts
    data = wheels[0].read_bytes()
    facts["wheel"] = {"name": wheels[0].name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    if step("venv", [sys.executable, "-m", "venv", str(venv)])[0] != 0:
        return facts
    python, reverseai = (str(path) for path in venv_programs(venv, windows))
    if step("install", [python, "-m", "pip", "install", "--no-index", "--no-deps", str(wheels[0])])[0] != 0:
        return facts
    code, out, _ = step("version", [reverseai, "--version"], cwd=scratch)
    facts["version"] = out.strip() if code == 0 else None
    code, out, _ = step("imported_from", [python, "-I", "-c", "import reverseai; print(reverseai.__file__)"],
                        cwd=scratch)
    facts["imported_from"] = out.strip() if code == 0 else None
    code, out, _ = step("doctor", [reverseai, "doctor", "--json"], cwd=scratch)
    try:
        facts["doctor"] = json.loads(out) if code == 0 else None
    except ValueError:
        facts["doctor"] = None
    sample = scratch / "input.elf"
    if step("fixture", [sys.executable, "-B", "-c", FIXTURE, str(sample)], cwd=source)[0] != 0:
        return facts
    step("analyze", [reverseai, "analyze", str(sample), "--out", str(scratch / "report")], cwd=scratch)
    facts["analyze"] = reports(scratch / "report")
    step("query", [reverseai, "query", str(sample), "--query", "list_segments", "--arg", "limit=16", "--out",
                   str(scratch / "query")], cwd=scratch)
    facts["query"] = reports(scratch / "query")
    if windows:
        _, _, err = step("windows_tests", [sys.executable, "-B", "-m", "unittest", "tests.test_windows_output", "-v"],
                         cwd=source)
        facts["windows_tests"] = suite_counts(err)
    return facts


def inside_venv(path, venv, windows):
    pure = PureWindowsPath if windows else PurePosixPath
    return bool(path and venv) and pure(venv) in pure(path).parents


def passed(facts, version, *, windows=False):
    """POSIX: every step exit 0 and a clean whole suite; Windows: the install-to-query steps and the Windows tests,
    every one of them run (unittest's count includes skips, so a skip fails). Both need doctor's JSON object to say
    host_ok true for the expected version."""
    record = facts.get("steps") if isinstance(facts.get("steps"), dict) else {}
    required = WINDOWS_STEPS if windows else POSIX_STEPS
    both = ["report.json", "report.md"]
    doctor, windows_tests = facts.get("doctor"), facts.get("windows_tests")
    return bool(all((record.get(name) or {}).get("exit") == 0 for name in required)
                and (clean(windows_tests) and windows_tests["skipped"] == 0 if windows else clean(facts.get("suite")))
                and isinstance(doctor, dict) and doctor.get("host_ok") is True and doctor.get("reverseai") == version
                and facts.get("wheel") and facts.get("version") == "reverseai " + version
                and inside_venv(facts.get("imported_from"), facts.get("venv"), windows)
                and (facts.get("analyze") or {}).get("reports") == both
                and (facts.get("query") or {}).get("reports") == both)


def expected_version(source):
    found = re.search(r'^__version__ = "([^"]+)"$', (source / "reverseai/__init__.py").read_text(encoding="utf-8"),
                      re.M)
    if found is None:
        raise SystemExit("the checkout names no reverseai.__version__")
    return found.group(1)


def host_env():
    env = {key: value for key, value in os.environ.items() if key not in DROPPED_ENV}
    env.update(PIP_ENV)
    return env


def prove(receipt, runner=run, *, source=ROOT, windows=None):
    """Run every step here, write the receipt, print the marker line; 0 only when the host's predicate passes."""
    windows = os.name == "nt" if windows is None else windows
    version = expected_version(source)
    code, out, _ = runner(["git", "-C", str(source), "rev-parse", "HEAD"], timeout=30)
    commit = out.strip() if code == 0 and re.fullmatch(r"[0-9a-f]{40}", out.strip()) else None
    with tempfile.TemporaryDirectory(prefix="reverseai-host-proof-") as work:
        # Resolved, so the venv path matches the import path Python reports (macOS /var is /private/var).
        facts = steps(runner, Path(work).resolve(), source, host_env(), windows=windows)
    ok = commit is not None and passed(facts, version, windows=windows)
    document = {"commit": commit, "expected_version": version, "os": "windows" if windows else os.name,
                "python": platform.python_version(), "platform": platform.platform(), "machine": platform.machine(),
                "passed": ok, **facts}
    text = json.dumps(document, sort_keys=True)
    with open(receipt, "x", encoding="utf-8") as stream:
        stream.write(json.dumps(document, indent=2, sort_keys=True) + "\n")
    print(MARKER + text)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as stream:
            stream.write(f"### ReverseAI host proof: {'passed' if ok else 'FAILED'}\n\n```\n{MARKER}{text}\n```\n")
    return 0 if ok else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--receipt", type=Path, required=True, help="A new file for the JSON receipt")
    args = parser.parse_args(argv)
    if args.receipt.exists() or args.receipt.is_symlink():
        parser.error("--receipt must name a new file")
    return prove(args.receipt)


if __name__ == "__main__":
    sys.exit(main())
