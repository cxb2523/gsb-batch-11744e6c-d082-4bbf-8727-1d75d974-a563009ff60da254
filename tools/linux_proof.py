"""Prove one commit on Linux arm64: the whole suite, then its wheel built, installed offline and run.

Usage (from the repository root, with docker-desktop reserved):
    python3 -B tools/linux_proof.py --commit REV --receipt NEW_FILE

Nothing is pulled or downloaded. The digest-pinned python:3.12-slim base must already be present locally. The
commit's Git-tracked files (git archive, no host mount) are added to a throwaway image FROM that base, with no RUN
step; the container runs as 65534:65534 with the network off, a read-only root, every capability dropped and a tmpfs
at /tmp. Inside, this file runs again with --inside from the archived copy and runs the steps of tools/host_proof.py (one implementation): the whole suite on
the read-only tree, then pip builds the wheel from a copy in /tmp (pip wheel --no-index, no sdist), a fresh venv
installs it with --no-index, and the installed reverseai answers --version, doctor --json, analyze and query of a
code-built ELF. The
inside run prints one marker line of JSON; the host writes the receipt (Python version, platform, commit, counts,
base digest) and removes its image and container whatever the outcome. Every command is an argv list; nothing goes
through a shell.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
PLATFORM = "linux/arm64"
BASE_DIGEST = "sha256:16bf2b5c59a08523519d3c8589deca849285dee1d62a3653e124c3dba340f15e"
BASE = "python:3.12-slim@" + BASE_DIGEST
SOURCE = "/opt/src"
MARKER = "REVERSEAI-LINUX-PROOF "
DOCKERFILE = (f"FROM {BASE}\n"
              "ADD source.tar /opt/\n"
              "USER 65534:65534\n"
              f"WORKDIR {SOURCE}\n"
              f'ENTRYPOINT ["python3", "-B", "{SOURCE}/tools/linux_proof.py", "--inside"]\n')
DOCKER_SECONDS = 120
RUN_SECONDS = 1800


def _host_proof():
    """tools/host_proof.py, the one implementation of the proof steps, loaded by path from this file's folder."""
    spec = importlib.util.spec_from_file_location("reverseai_host_proof", Path(__file__).with_name("host_proof.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


H = _host_proof()
as_text, run, tail, suite_counts = H.as_text, H.run, H.tail, H.suite_counts
REQUIRED_STEPS = H.POSIX_STEPS


# --- inside the container -------------------------------------------------------------------------------------------

def inside(runner=run, work=Path("/tmp"), source=Path(SOURCE)):
    """Run the shared steps inside the container with a fixed environment; add the container's own facts."""
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(work / "home"), "LANG": "C.UTF-8", **H.PIP_ENV}
    (work / "home").mkdir(exist_ok=True)
    facts = {"python": platform.python_version(), "platform": platform.platform(), "machine": platform.machine(),
             "uid": os.getuid()}
    facts.update(H.steps(runner, work, source, env))
    return facts


# --- on the host ----------------------------------------------------------------------------------------------------

def build_argv(context, iidfile, tag):
    return ["docker", "build", "--platform", PLATFORM, "--pull=false", "--network=none", "--iidfile", str(iidfile),
            "--tag", tag, str(context)]


def run_argv(image_id, name):
    return ["docker", "run", "--rm", "--init", "--pull", "never", "--name", name, "--platform", PLATFORM,
            "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--user", "65534:65534", "--pids-limit", "1024", "--memory", "4g", "--memory-swap", "4g",
            "--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=2g", image_id]


def remove_argv(image_id):
    return ["docker", "image", "rm", "--no-prune", image_id]


def marker_facts(stdout):
    lines = [line for line in stdout.splitlines() if line.startswith(MARKER)]
    if len(lines) != 1:
        raise ValueError("the container printed no single proof marker")
    facts = json.loads(lines[0][len(MARKER):])
    if not isinstance(facts, dict):
        raise ValueError("the proof marker is not an object")
    return facts


def passed(facts, version):
    """The host predicate, on Linux aarch64, Python 3.12, uid 65534, with every packaged lock loading from the venv."""
    doctor = facts.get("doctor")
    return bool(facts.get("machine") == "aarch64" and str(facts.get("platform", "")).startswith("Linux-")
                and str(facts.get("python", "")).startswith("3.12.") and facts.get("uid") == 65534
                and H.passed(facts, version)
                and doctor and doctor.get("host_ok") is True and doctor.get("reverseai") == version
                and len(doctor.get("tools", ())) == 5
                and all(tool["lock_loads"] and tool["lock"].startswith("/tmp/venv/") for tool in doctor["tools"]))


def utc():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def absent(runner, kind, ref):
    """True only when Docker answers that this container or image does not exist; silence is not absence."""
    code, out, err = runner(["docker", kind, "inspect", "--format", "{{.Id}}", ref], timeout=30)
    return code not in (0, None) and "no such" in (as_text(out) + as_text(err)).lower()


def remove_container(runner, name, *, attempts=10, pause=1.0):
    """Force-remove the owned, generated container name (--rm may still be removing it); never another name."""
    for _ in range(attempts):
        runner(["docker", "rm", "--force", name], timeout=30)
        if absent(runner, "container", name):
            return True
        time.sleep(pause)
    return False


def prove(commit, receipt, runner=run, *, pause=1.0):
    """Build, run and remove the throwaway image; write the receipt; return 0 only when every step passed.

    After the base check every outcome writes a receipt, and every exit, interrupts included, first removes the
    owned container (once its run started) and any image the build named, then checks that Docker no longer knows
    them."""
    code, out, _ = runner(["git", "-C", str(ROOT), "rev-parse", "--verify", commit + "^{commit}"], timeout=30)
    if code != 0 or not re.fullmatch(r"[0-9a-f]{40}", out.strip()):
        raise SystemExit("the commit does not resolve in this repository")
    commit = out.strip()
    if runner(["docker", "image", "inspect", "--format", "{{.Id}}", BASE], timeout=30)[0] != 0:
        raise SystemExit("the pinned base " + BASE + " is not present locally; this tool never pulls")
    started, image_id, facts, error, version, docker_exit = utc(), None, None, None, None, None
    name = "reverseai-linux-proof-" + uuid.uuid4().hex[:16]
    run_started = False
    try:
        with tempfile.TemporaryDirectory(prefix="reverseai-linux-proof-") as temporary:
            context = Path(temporary)
            archive = context / "source.tar"
            code, out, _ = runner(["git", "-C", str(ROOT), "show", commit + ":reverseai/__init__.py"], timeout=30)
            found = re.search(r'^__version__ = "([^"]+)"$', out, re.M) if code == 0 else None
            version = found.group(1) if found else None
            if version is None:
                error = "the commit names no reverseai.__version__"
            elif runner(["git", "-C", str(ROOT), "archive", "--format=tar", "--prefix=src/", "-o", str(archive),
                         commit], timeout=120)[0] != 0:
                error = "git archive failed"
            else:
                (context / "Dockerfile").write_text(DOCKERFILE, encoding="ascii")
                iidfile = context / "image.id"
                code, _, err = runner(build_argv(context, iidfile, "reverseai-linux-proof:" + commit[:12]),
                                      timeout=DOCKER_SECONDS)
                # An image the build named is ours to remove even when the client then failed.
                named = iidfile.read_text(encoding="ascii").strip() if iidfile.exists() else ""
                image_id = named if re.fullmatch(r"sha256:[0-9a-f]{64}", named) else None
                if code != 0 or image_id is None:
                    error = f"docker build failed (exit {code}): " + " | ".join(tail(err, 5))
        if error is None:
            run_started = True
            docker_exit, out, err = runner(run_argv(image_id, name), timeout=RUN_SECONDS)
            try:
                facts = marker_facts(out)
            except ValueError as problem:
                error = str(problem)
            if docker_exit is None:
                error = "the container did not finish within the time limit"
            elif docker_exit != 0:
                error = f"docker run exited {docker_exit}: " + " | ".join(tail(err, 5))
    finally:
        container_removed = not run_started or remove_container(runner, name, pause=pause)
        if image_id is not None:
            runner(remove_argv(image_id), timeout=DOCKER_SECONDS)
        image_removed = image_id is None or absent(runner, "image", image_id)
    ok = (error is None and docker_exit == 0 and facts is not None and passed(facts, version)
          and container_removed and image_removed)
    document = {"commit": commit, "platform": PLATFORM, "base": BASE, "base_digest": BASE_DIGEST,
                "expected_version": version, "image_id": image_id, "image_removed": image_removed,
                "container": name, "container_removed": container_removed, "docker_exit": docker_exit,
                "started": started, "ended": utc(), "passed": ok, "error": error, "inside": facts}
    with open(receipt, "x", encoding="utf-8") as stream:
        stream.write(json.dumps(document, indent=2, sort_keys=True) + "\n")
    suite = (facts or {}).get("suite") or {}
    print(f"{'passed' if ok else 'FAILED'}: {commit[:12]} on {PLATFORM}, Python {(facts or {}).get('python')}, "
          f"{suite.get('ran')} tests ({suite.get('skipped')} skipped), container removed: {container_removed}, "
          f"image removed: {image_removed}" + (f"; {error}" if error else ""))
    return 0 if ok else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--inside", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--commit", help="The candidate commit or tag")
    parser.add_argument("--receipt", type=Path, help="A new file for the JSON receipt")
    args = parser.parse_args(argv)
    if args.inside:
        print(MARKER + json.dumps(inside(), sort_keys=True))
        return 0
    if not args.commit or args.receipt is None:
        parser.error("--commit and --receipt are required")
    if args.receipt.exists() or args.receipt.is_symlink():
        parser.error("--receipt must name a new file")
    return prove(args.commit, args.receipt)


if __name__ == "__main__":
    sys.exit(main())
