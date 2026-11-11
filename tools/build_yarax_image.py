"""Build the pinned YARA-X worker image and write containers/yarax/image.lock.json.

Usage (from the repository root):
    python3 -B tools/build_yarax_image.py --wheel-dir DIR [--download] [--tag TAG] [--lock PATH]

The digest-pinned linux/arm64 base (the same one as the LIEF worker) must already be
present locally: the tool never pulls, and the Dockerfile must
build FROM exactly that reference and nothing else.
The YARA-X wheel must be in DIR (or, with --download, is fetched from the single PyPI
URL below, refusing any redirect) and must match the SHA-256 in
containers/yarax/requirements.txt. The build itself runs with --network none and
installs only from that local wheel; the image compiles the reviewed ruleset once,
so a bad rule fails the build. The lock records the SHA-256 of the ruleset file
copied into the build. Every docker call is an argv list; nothing goes through a shell.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "containers" / "yarax"
PLATFORM = "linux/arm64"
BASE_DIGEST = "sha256:16bf2b5c59a08523519d3c8589deca849285dee1d62a3653e124c3dba340f15e"
BASE = "python:3.12-slim@" + BASE_DIGEST
ADAPTER_VERSION = "1.21.0-r2"
RULESET = "m2_fixture_v1.json"
WHEEL = "yara_x-1.21.0-cp38-abi3-manylinux_2_28_aarch64.whl"
WHEEL_HOST = "https://files.pythonhosted.org/packages/"
WHEEL_URL = WHEEL_HOST + "9c/8e/63adf06593aff53180c7246f6b35c22ff9729705d1d31dd2e8a35a2e4643/" + WHEEL
WHEEL_BYTES_LIMIT = 16 * 1024 * 1024


def wheel_sha256():
    """The one hash pinned in requirements.txt."""
    pinned = re.findall(r"--hash=sha256:([0-9a-f]{64})", (SOURCE / "requirements.txt").read_text(encoding="utf-8"))
    if len(pinned) != 1:
        raise SystemExit("requirements.txt must pin exactly one SHA-256")
    return pinned[0]


def logical_instructions(text):
    """Logical instructions as BuildKit reads them: a line ending in exactly one backslash (then only spaces or tabs)
    continues on the next one, comment and empty lines inside a continuation are skipped, and nothing is inserted at
    the join (A\\ then DD is ADD). A run of two or more trailing backslashes ends its instruction: measured natively
    with buildx v0.37.2 for runs of 1 to 5. Lines are split on LF only: the caller has refused every other
    control byte."""
    joined, current = [], None
    for line in text.split("\n"):
        if current is None:
            line = line.lstrip(" \t")
            if not line or line.startswith("#"):
                continue
            current = ""
        elif not line.strip(" \t") or line.lstrip(" \t").startswith("#"):
            continue
        end = re.search(r"(\\+)[ \t]*$", line)
        if end and len(end.group(1)) == 1:
            current += line[:end.end(1) - 1]
        else:
            joined.append(current + line)
            current = None
    if current is not None:
        joined.append(current)
    return [words for words in (line.split() for line in joined) if words]


def check_dockerfile(path):
    """The lock records BASE_DIGEST, so the Dockerfile must build from exactly BASE and nothing else: ASCII without
    control bytes (a BOM or a form feed would hide a directive or an instruction), one FROM line, no ADD (remote URLs, Git), no COPY --from or RUN --mount ...from= (another
    image or stage), no parser directive (# syntax=, # escape=) and exactly one line USER 65534:65534. Instructions
    are counted case-insensitively and continuations are joined first, so neither hides one."""
    raw = path.read_bytes()
    if not raw.isascii() or re.search(rb"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]|\r(?!\n)", raw):
        raise SystemExit("Dockerfile must be ASCII without control bytes (tab, LF and CRLF only)")
    text = raw.decode("ascii").replace("\r\n", "\n")
    lines = [line.strip(" \t") for line in text.split("\n") if line.strip(" \t")]
    instructions = logical_instructions(text)
    if [words for words in instructions if words[0].upper() == "FROM"] != [["FROM", BASE]]:
        raise SystemExit("Dockerfile FROM differs from the pinned base " + BASE)
    if any(re.match(r"#\s*\w+\s*=", line) for line in lines):
        raise SystemExit("Dockerfile parser directives are refused")
    if any(words[0].upper() == "ADD" for words in instructions):
        raise SystemExit("Dockerfile ADD is refused")
    flags = [word.lower() for words in instructions for word in words if word.startswith("--")]
    if any(flag.startswith("--from") or (flag.startswith("--mount") and "from=" in flag) for flag in flags):
        raise SystemExit("Dockerfile reads from another image or stage")
    if [words for words in instructions if words[0].upper() == "USER"] != [["USER", "65534:65534"]]:
        raise SystemExit("Dockerfile must have exactly one USER 65534:65534")


def file_sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class RefuseRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise SystemExit("the wheel URL redirected; refusing to follow it")


def fetch_wheel(target, expected):
    # The one fixed HTTPS URL on PyPI's file host; any redirect is refused, so no other URL or host is ever requested.
    if not WHEEL_URL.startswith(WHEEL_HOST) or not WHEEL_URL.endswith("/" + WHEEL):
        raise SystemExit("the wheel URL is not the pinned PyPI file")
    with urllib.request.build_opener(RefuseRedirects).open(WHEEL_URL, timeout=60) as response:
        data = response.read(WHEEL_BYTES_LIMIT + 1)
    if len(data) > WHEEL_BYTES_LIMIT or hashlib.sha256(data).hexdigest() != expected:
        raise SystemExit("downloaded wheel does not match the pinned SHA-256")
    target.write_bytes(data)


def docker(*args, capture=False):
    result = subprocess.run(["docker", *args], check=True, text=True, capture_output=capture)
    return result.stdout.strip() if capture else None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--wheel-dir", type=Path, required=True, help="Private directory holding the pinned YARA-X wheel")
    parser.add_argument("--download", action="store_true", help="Fetch the pinned wheel into --wheel-dir if it is missing")
    parser.add_argument("--tag", default="reverseai-yarax:" + ADAPTER_VERSION)
    parser.add_argument("--lock", type=Path, default=SOURCE / "image.lock.json")
    args = parser.parse_args(argv)

    check_dockerfile(SOURCE / "Dockerfile")
    expected = wheel_sha256()
    wheel = args.wheel_dir / WHEEL
    if not wheel.is_file():
        if not args.download:
            raise SystemExit(f"missing {WHEEL} in --wheel-dir (or pass --download)")
        args.wheel_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        fetch_wheel(wheel, expected)
    if file_sha256(wheel) != expected:
        raise SystemExit("wheel does not match the pinned SHA-256")

    try:
        docker("image", "inspect", "--format", "{{.Id}}", BASE, capture=True)
    except subprocess.CalledProcessError:
        raise SystemExit("the pinned base " + BASE + " is not present locally; this tool never pulls") from None
    with tempfile.TemporaryDirectory(prefix="reverseai-yarax-build-") as temporary:
        context = Path(temporary)
        for name in ("Dockerfile", "requirements.txt", "worker.py", RULESET):
            shutil.copy2(SOURCE / name, context / name)
        ruleset_sha256 = file_sha256(context / RULESET)  # the bytes the image copies
        (context / "wheels").mkdir()
        shutil.copy2(wheel, context / "wheels" / WHEEL)
        iidfile = context / "image.id"
        docker("build", "--platform", PLATFORM, "--network", "none", "--pull=false", "--iidfile", str(iidfile),
               "--tag", args.tag, str(context))
        image_id = iidfile.read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
        raise SystemExit("docker build returned no image ID")
    lock = {"image_id": image_id, "platform": PLATFORM, "base_digest": BASE_DIGEST, "wheel_sha256": expected,
            "ruleset_sha256": ruleset_sha256, "adapter_version": ADAPTER_VERSION}
    text = json.dumps(lock, indent=2, sort_keys=True) + "\n"
    args.lock.write_text(text, encoding="utf-8")
    print(text, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
