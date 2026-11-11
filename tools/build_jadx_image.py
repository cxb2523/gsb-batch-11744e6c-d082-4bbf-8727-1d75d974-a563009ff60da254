"""Build the pinned JADX worker image and write containers/jadx/image.lock.json.

Usage (from the repository root):
    python3 -B tools/build_jadx_image.py --download-dir DIR [--tag TAG] [--lock PATH]

Nothing is downloaded here. --download-dir must already hold jadx-1.5.6.zip (pinned, checked against the
publisher's release metadata when it was fetched) and the Temurin JDK 21.0.12.1+1
(aarch64) tarball also used for Ghidra; both are checked by size cap and SHA-256 before use. The
digest-pinned python:3.12-slim base must already be present locally: the tool never pulls. The image is built with the network off: one internal "build" stage takes the jar and its licence from the
zip, unpacks the JDK and compiles the fixed driver against the jar, and the final stage copies only /opt/jdk,
/opt/jadx and /opt/reverseai/driver from it. The Dockerfile check allows exactly that shape and runs again on the copied
build context; the lock's driver and worker hashes are those of the copied context, the bytes Docker builds, and the tool
refuses to write a lock when the repository files differ from them after the build. Every docker
call is an argv list; nothing goes through a shell.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "containers" / "jadx"
PLATFORM = "linux/arm64"
BASE_DIGEST = "sha256:16bf2b5c59a08523519d3c8589deca849285dee1d62a3653e124c3dba340f15e"
BASE = "python:3.12-slim@" + BASE_DIGEST
STAGE = "build"
ADAPTER_VERSION = "1.5.6-r1"
CONTEXT_FILES = ("Dockerfile", "worker.py", "unpack.py", "driver")
STAGE_COPIES = ("/opt/jdk", "/opt/jadx", "/opt/reverseai/driver")
BUILT_SOURCES = {"driver_sha256": "driver/ReverseAIJadx.java", "worker_sha256": "worker.py"}  # lock key -> context path
ASSETS = {
    "jadx": {"name": "jadx-1.5.6.zip", "size": 72_646_741,
             "sha256": "545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974"},
    "jdk": {"name": "OpenJDK21U-jdk_aarch64_linux_hotspot_21.0.12.1_1.tar.gz", "size": 205_641_175,
            "sha256": "23e37e026f12f3e706f18938ff611db3032d075b09d0879a25d06718c773e223"},
}
JAR_SHA256 = "fe3e12c45acf75f92369685fd02d1d7a7323385dc725680a9b98a0dac0ea554b"
CHUNK = 1024 * 1024


def logical_instructions(text):
    """Logical instructions as BuildKit reads them (as tools/build_ghidra_image.py, measured with buildx v0.37.2): a
    line ending in exactly one backslash continues, comment and empty lines inside a continuation are skipped, a run
    of two or more trailing backslashes ends the instruction. Lines are split on LF only."""
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
    """The lock records BASE_DIGEST, so the Dockerfile must build from exactly BASE: ASCII without control bytes, FROM
    BASE AS build then FROM BASE, COPY --from=build of /opt/jdk, /opt/jadx and /opt/reverseai/driver as the only
    cross-stage reads, no ADD, no RUN --mount from another image or stage, no parser directive, every RUN starting
    --network=none and exactly one line USER 65534:65534."""
    raw = path.read_bytes()
    if not raw.isascii() or re.search(rb"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]|\r(?!\n)", raw):
        raise SystemExit("Dockerfile must be ASCII without control bytes (tab, LF and CRLF only)")
    text = raw.decode("ascii").replace("\r\n", "\n")
    lines = [line.strip(" \t") for line in text.split("\n") if line.strip(" \t")]
    instructions = logical_instructions(text)
    if [words for words in instructions if words[0].upper() == "FROM"] != [["FROM", BASE, "AS", STAGE], ["FROM", BASE]]:
        raise SystemExit("Dockerfile FROM differs from the pinned base " + BASE + " (one build stage, then the image)")
    if any(re.match(r"#\s*\w+\s*=", line) for line in lines):
        raise SystemExit("Dockerfile parser directives are refused")
    if any(words[0].upper() == "ADD" for words in instructions):
        raise SystemExit("Dockerfile ADD is refused")
    for words in instructions:
        for flag in (word.lower() for word in words if word.startswith("--")):
            if flag.startswith("--from") and not (words[0].upper() == "COPY" and flag == "--from=" + STAGE):
                raise SystemExit("Dockerfile reads from another image or stage")
            if flag.startswith("--mount") and "from=" in flag:
                raise SystemExit("Dockerfile reads from another image or stage")
    copies = [words for words in instructions if any(word.lower().startswith("--from") for word in words)]
    if copies != [["COPY", "--from=" + STAGE, path, path] for path in STAGE_COPIES]:
        raise SystemExit("Dockerfile may copy only /opt/jdk, /opt/jadx and /opt/reverseai/driver from the build stage")
    if any(words[0].upper() == "RUN" and (len(words) < 2 or words[1].lower() != "--network=none") for words in instructions):
        raise SystemExit("Dockerfile RUN steps must all start --network=none")
    if [words for words in instructions if words[0].upper() == "USER"] != [["USER", "65534:65534"]]:
        raise SystemExit("Dockerfile must have exactly one USER 65534:65534")


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        while chunk := stream.read(CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def docker(*args, capture=False):
    result = subprocess.run(["docker", *args], check=True, text=True, capture_output=capture)
    return result.stdout.strip() if capture else None


def place(source, target):
    """Hard-link a verified download into the build context, or copy it when the link is not possible."""
    try:
        os.link(source, target)
    except OSError:
        shutil.copy2(source, target)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--download-dir", type=Path, required=True, help="Private directory holding the verified files")
    parser.add_argument("--tag", default="reverseai-jadx:" + ADAPTER_VERSION)
    parser.add_argument("--lock", type=Path, default=SOURCE / "image.lock.json")
    args = parser.parse_args(argv)

    check_dockerfile(SOURCE / "Dockerfile")
    files = {}
    for key, asset in ASSETS.items():
        path = args.download_dir / asset["name"]
        if not path.is_file() or path.stat().st_size != asset["size"] or file_sha256(path) != asset["sha256"]:
            raise SystemExit(f"{asset['name']} is missing or does not match its pinned size and SHA-256")
        files[key] = path

    try:
        docker("image", "inspect", "--format", "{{.Id}}", BASE, capture=True)
    except subprocess.CalledProcessError:
        raise SystemExit("the pinned base " + BASE + " is not present locally; this tool never pulls") from None
    with tempfile.TemporaryDirectory(prefix="reverseai-jadx-build-") as temporary:
        context = Path(temporary)
        for name in CONTEXT_FILES:
            source = SOURCE / name
            (shutil.copytree if source.is_dir() else shutil.copy2)(source, context / name)
        check_dockerfile(context / "Dockerfile")
        built = {key: file_sha256(context / path) for key, path in BUILT_SOURCES.items()}
        (context / "downloads").mkdir()
        for path in files.values():
            place(path, context / "downloads" / path.name)
        iidfile = context / "image.id"
        docker("build", "--platform", PLATFORM, "--pull=false", "--network=none", "--iidfile", str(iidfile),
               "--tag", args.tag, str(context))
        image_id = iidfile.read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
        raise SystemExit("docker build returned no image ID")
    if any(file_sha256(SOURCE / path) != built[key] for key, path in BUILT_SOURCES.items()):
        raise SystemExit("the worker or driver changed during the build; no lock written")
    lock = {"adapter_version": ADAPTER_VERSION, "base_digest": BASE_DIGEST, "driver_sha256": built["driver_sha256"],
            "image_id": image_id, "jadx_jar_sha256": JAR_SHA256, "jadx_zip_sha256": ASSETS["jadx"]["sha256"],
            "jdk_sha256": ASSETS["jdk"]["sha256"], "platform": PLATFORM, "worker_sha256": built["worker_sha256"]}
    text = json.dumps(lock, indent=2, sort_keys=True) + "\n"
    args.lock.write_text(text, encoding="utf-8")
    print(text, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
