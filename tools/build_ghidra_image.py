"""Build the pinned Ghidra worker image and write containers/ghidra/image.lock.json.

Usage (from the repository root):
    python3 -B tools/build_ghidra_image.py --download-dir DIR [--download] [--tag TAG] [--lock PATH]
    python3 -B tools/build_ghidra_image.py revise --route A|B [--tag TAG] [--lock PATH]

Ghidra 12.1.4 and the Temurin JDK 21.0.12.1+1 (aarch64) are fetched on the host
from their fixed GitHub release URLs, following
redirects only to GitHub's release-asset hosts over HTTPS, with a size cap and the
SHA-256 checked before a file is kept. The image is built from the digest-pinned
python:3.12-slim base: one internal "natives" stage installs Debian's g++ and make
(signed archive, pinned versions) to build the arm64 decompiler and demangler from
the release's own sources, and the final stage copies only /opt/jdk and /opt/ghidra
from it. The Dockerfile check allows exactly that shape: network for the natives
stage's one package step only, every other RUN --network=none. Every docker call
is an argv list; nothing goes through a shell.

The explicit revise routes never fetch assets or run a container. Route A forces
the legacy builder on a recognized local Engine 27/28 overlay2 store, because a
BuildKit RUN network restriction does not constrain FROM resolution. Unknown
backends are refused; route B must be chosen explicitly. Both routes compare the
parent/result runtime trees using never-started containers before writing an r7
lock. Native engine behavior still needs a release-specific proof.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "containers" / "ghidra"
PLATFORM = "linux/arm64"
BASE_DIGEST = "sha256:16bf2b5c59a08523519d3c8589deca849285dee1d62a3653e124c3dba340f15e"
BASE = "python:3.12-slim@" + BASE_DIGEST
STAGE = "natives"
ADAPTER_VERSION = "12.1.4-r7"
PARENT_IMAGE_ID = "sha256:ac77fda75da8580e0479087580f83b6e5495fb16df97b9696a2bdf3ae100f452"
CACHE_FORMAT = 1
BUNDLE_FILES = ("worker.py", "project_cache.py", "ghidra_scripts/ReverseAIOptions.java",
                "ghidra_scripts/ReverseAIQuery.java", "ghidra_scripts/ReverseAIPrepare.java")
ENTRYPOINT = ["python3", "-I", "-B", "/opt/reverseai/worker.py"]
RUNTIME_CONFIG = ("User", "Env", "Entrypoint", "Cmd", "WorkingDir", "Volumes", "OnBuild", "Healthcheck",
                  "Shell", "StopSignal", "StopTimeout", "ExposedPorts")
ASSETS = {
    "ghidra": {
        "name": "ghidra_12.1.4_PUBLIC_20260921.zip",
        "url": "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.4_build/"
               "ghidra_12.1.4_PUBLIC_20260921.zip",
        "sha256": "ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db",
        "limit": 640 * 1024 * 1024,
    },
    "jdk": {
        "name": "OpenJDK21U-jdk_aarch64_linux_hotspot_21.0.12.1_1.tar.gz",
        "url": "https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.12.1%2B1/"
               "OpenJDK21U-jdk_aarch64_linux_hotspot_21.0.12.1_1.tar.gz",
        "sha256": "23e37e026f12f3e706f18938ff611db3032d075b09d0879a25d06718c773e223",
        "limit": 256 * 1024 * 1024,
    },
}
FIRST_HOST = "github.com"
REDIRECT_HOSTS = ("release-assets.githubusercontent.com", "objects.githubusercontent.com")
MAX_REDIRECTS = 2
CHUNK = 1024 * 1024


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
    control bytes, FROM BASE AS natives then FROM BASE, COPY --from=natives of /opt/jdk and /opt/ghidra as the only
    cross-stage reads, no ADD, no RUN --mount from another image or stage, no parser directive, network for one
    natives RUN only (every other RUN starts --network=none) and exactly one line USER 65534:65534. Continuations
    are joined first and instructions are counted case-insensitively, so neither hides one."""
    raw = path.read_bytes()
    if not raw.isascii() or re.search(rb"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]|\r(?!\n)", raw):
        raise SystemExit("Dockerfile must be ASCII without control bytes (tab, LF and CRLF only)")
    text = raw.decode("ascii").replace("\r\n", "\n")
    lines = [line.strip(" \t") for line in text.split("\n") if line.strip(" \t")]
    instructions = logical_instructions(text)
    if [words for words in instructions if words[0].upper() == "FROM"] != [["FROM", BASE, "AS", STAGE], ["FROM", BASE]]:
        raise SystemExit("Dockerfile FROM differs from the pinned base " + BASE + " (one natives stage, then the image)")
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
    if copies != [["COPY", "--from=" + STAGE, path, path] for path in ("/opt/jdk", "/opt/ghidra")]:
        raise SystemExit("Dockerfile may copy only /opt/jdk and /opt/ghidra from the natives stage")
    stage, networked = 0, []
    for words in instructions:
        if words[0].upper() == "FROM":
            stage += 1
        elif words[0].upper() == "RUN" and (len(words) < 2 or words[1].lower() != "--network=none"):
            networked.append(stage)
    if networked != [1]:
        raise SystemExit("Dockerfile may use the network in one natives RUN only")
    if [words for words in instructions if words[0].upper() == "USER"] != [["USER", "65534:65534"]]:
        raise SystemExit("Dockerfile must have exactly one USER 65534:65534")


def closed_instructions(path):
    raw = path.read_bytes()
    if not raw.isascii() or re.search(rb"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]|\r(?!\n)", raw):
        raise SystemExit("Dockerfile must be ASCII without control bytes")
    source = raw.decode("ascii").replace("\r\n", "\n")
    if any(re.match(r"\s*#\s*\w+\s*=", line) for line in source.split("\n")):
        raise SystemExit("Dockerfile parser directives are refused")
    return [" ".join(words) for words in logical_instructions(source)]


def bundle_copies():
    return [f"COPY {name} /opt/reverseai/{name}" for name in BUNDLE_FILES]


def check_bundle_dockerfile(path, *, revise=False):
    instructions = closed_instructions(path)
    ending = ['USER 65534:65534', 'ENTRYPOINT ' + json.dumps(ENTRYPOINT)]
    if revise:
        expected = ["FROM " + PARENT_IMAGE_ID, *bundle_copies(), *ending]
        if instructions != expected:
            raise SystemExit("revision Dockerfile must contain only the exact local FROM, fixed bundle COPY, USER and ENTRYPOINT")
    else:
        copies = [line for line in instructions if line.split()[0].upper() == "COPY"
                  and not line.startswith("COPY --from=" + STAGE + " ")]
        expected = ["COPY unpack.py " + " ".join("downloads/" + asset["name"] for asset in ASSETS.values()) + " /tmp/",
                    *bundle_copies()]
        if copies != expected or instructions[-1] != ending[-1]:
            raise SystemExit("full Dockerfile must copy the exact fixed bundle and entrypoint")


def bundle_hashes(source):
    """Closed relative names are shared by both routes and the cache identity."""
    scripts = source / "ghidra_scripts"
    expected = {Path(name).name for name in BUNDLE_FILES if name.startswith("ghidra_scripts/")}
    if scripts.is_symlink() or not scripts.is_dir() or {path.name for path in scripts.iterdir()} != expected:
        raise SystemExit("Ghidra script file set differs from the fixed bundle")
    hashes = {}
    for name in BUNDLE_FILES:
        path = source / name
        if path.is_symlink() or not path.is_file():
            raise SystemExit("bundle files must be regular files: " + name)
        hashes[name] = file_sha256(path)
    return hashes


def bundle_digest(hashes):
    return hashlib.sha256(json.dumps(hashes, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")).hexdigest()


def copy_bundle(source, context):
    for name in BUNDLE_FILES:
        target = context / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source / name, target)


class ReleaseAssetRedirects(urllib.request.HTTPRedirectHandler):
    """Follow at most MAX_REDIRECTS hops, each to an HTTPS GitHub release-asset host on the default port."""
    max_redirections = MAX_REDIRECTS

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urllib.parse.urlsplit(newurl)
        if (target.scheme != "https" or target.hostname not in REDIRECT_HOSTS or target.port not in (None, 443)
                or target.username or target.password):
            raise SystemExit("a download redirected outside the GitHub release-asset hosts")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        while chunk := stream.read(CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def fetch(asset, folder):
    """Download one pinned asset into folder; nothing is kept unless its size and SHA-256 are the pinned ones."""
    first = urllib.parse.urlsplit(asset["url"])
    if first.scheme != "https" or first.hostname != FIRST_HOST or first.port is not None or not first.path.endswith("/" + asset["name"]):
        raise SystemExit("a download URL is not its pinned GitHub release URL")
    target = Path(folder) / asset["name"]
    partial = target.with_name(target.name + ".partial")
    digest, size = hashlib.sha256(), 0
    try:
        with urllib.request.build_opener(ReleaseAssetRedirects).open(asset["url"], timeout=60) as response, \
                open(partial, "xb") as stream:
            while chunk := response.read(CHUNK):
                size += len(chunk)
                if size > asset["limit"]:
                    raise SystemExit("a download is larger than its size cap")
                digest.update(chunk)
                stream.write(chunk)
        if digest.hexdigest() != asset["sha256"]:
            raise SystemExit("a download does not match its pinned SHA-256")
        os.replace(partial, target)
    finally:
        partial.unlink(missing_ok=True)
    return target


def docker(*args, capture=False, legacy=False):
    env = dict(os.environ, DOCKER_BUILDKIT="0") if legacy else None
    result = subprocess.run(["docker", *args], check=True, text=True, capture_output=capture, env=env)
    return result.stdout.strip() if capture else None


def docker_json(*args):
    try:
        return json.loads(docker(*args, capture=True))
    except (ValueError, TypeError):
        raise SystemExit("Docker returned invalid inspection JSON") from None


def inspect_image(image_id):
    info = docker_json("image", "inspect", image_id)
    if not isinstance(info, list) or len(info) != 1 or not isinstance(info[0], dict):
        raise SystemExit("Docker image inspection shape differs")
    info = info[0]
    if info.get("Id") != image_id or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
        raise SystemExit("Docker image ID differs from the requested local image")
    if (info.get("Os"), info.get("Architecture")) != ("linux", "arm64"):
        raise SystemExit("Docker image platform differs from " + PLATFORM)
    config = info.get("Config")
    if not isinstance(config, dict) or config.get("User") != "65534:65534" or config.get("Entrypoint") != ENTRYPOINT:
        raise SystemExit("Docker image runtime user or entrypoint differs")
    env = config.get("Env")
    if not isinstance(env, list) or any(not isinstance(item, str) or "=" not in item for item in env):
        raise SystemExit("Docker image environment differs")
    if len({item.split("=", 1)[0] for item in env}) != len(env):
        raise SystemExit("Docker image environment has duplicate keys")
    if any(config.get(key) for key in ("Volumes", "OnBuild", "Healthcheck")):
        raise SystemExit("Docker image has an unexpected volume, trigger or healthcheck")
    rootfs = info.get("RootFS")
    if (not isinstance(rootfs, dict) or rootfs.get("Type") != "layers" or not isinstance(rootfs.get("Layers"), list)
            or not rootfs["Layers"] or any(not isinstance(layer, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", layer)
                                           for layer in rootfs["Layers"])):
        raise SystemExit("Docker image layer identity is missing")
    return info


def preflight_legacy_builder():
    """Route A is deliberately limited to the local Engine legacy image store.

    BuildKit's network flag does not fence its FROM resolver. Do not select an
    ambient buildx driver, probe by building, or fall back to another route.
    Unknown Engine versions or snapshotters require explicit route B instead.
    """
    overrides = ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "BUILDX_BUILDER")
    if any(os.environ.get(key) for key in overrides):
        raise SystemExit("route A requires the local Docker context without endpoint or builder overrides; use route B")
    contexts = docker_json("context", "inspect")
    try:
        host = contexts[0]["Endpoints"]["docker"]["Host"]
        local = len(contexts) == 1 and isinstance(host, str) and host.startswith("unix:///")
    except (KeyError, TypeError, IndexError):
        local = False
    info = docker_json("info", "--format", "{{json .}}")
    if not isinstance(info, dict):
        raise SystemExit("route A cannot establish the Docker Engine backend; use route B")
    # This allow-list is a compatibility restriction, not native proof for a release.
    version = str(info.get("ServerVersion", ""))
    status = info.get("DriverStatus", [])
    if (not local or info.get("OSType") != "linux" or info.get("Architecture") not in ("aarch64", "arm64")
            or not re.fullmatch(r"(?:27|28)\.[0-9]+\.[0-9]+", version)
            or info.get("Driver") != "overlay2"
            or not isinstance(status, list) or "containerd" in json.dumps(status).lower()):
        raise SystemExit("route A requires a recognized local legacy Engine image store; use route B")


@contextlib.contextmanager
def stopped_image(image_id):
    """Create only for copying/inspection. A name permits cleanup after ambiguous create failure."""
    name = "reverseai-ghidra-revise-" + uuid.uuid4().hex
    try:
        docker("create", "--pull=never", "--platform", PLATFORM, "--network=none", "--name", name, image_id, capture=True)
        inspection = docker_json("container", "inspect", name)
        if not isinstance(inspection, list) or len(inspection) != 1 or not isinstance(inspection[0], dict):
            raise SystemExit("build container inspection shape differs")
        info = inspection[0]
        host, state = info.get("HostConfig"), info.get("State")
        if (info.get("Image") != image_id or not isinstance(state, dict) or state.get("Running") is not False
                or state.get("Status") != "created" or not isinstance(host, dict) or host.get("NetworkMode") != "none"
                or info.get("Mounts") != [] or host.get("Binds") or host.get("Mounts")):
            raise SystemExit("build container must be a never-started local image without mounts or network")
        yield name
    finally:
        docker("rm", "--force", name, capture=True)


def tree_hashes(root):
    """Hash bytes, symlink targets and permissions without following directory links."""
    entries = {}
    for folder, dirs, files in os.walk(root, followlinks=False):
        for name in sorted(dirs + files):
            path = Path(folder) / name
            mode = path.lstat().st_mode
            relative = path.relative_to(root).as_posix()
            if stat.S_ISLNK(mode):
                value = ("link", stat.S_IMODE(mode), os.readlink(path))
            elif stat.S_ISREG(mode):
                value = ("file", stat.S_IMODE(mode), file_sha256(path))
            elif stat.S_ISDIR(mode):
                value = ("directory", stat.S_IMODE(mode))
            else:
                raise SystemExit("runtime tree contains a special file")
            entries[relative] = value
    return entries


def snapshot_runtime(container, folder):
    snapshots = {}
    for name in ("jdk", "ghidra", "reverseai"):
        target = folder / name
        target.mkdir()
        docker("cp", container + ":/opt/" + name + "/.", str(target))
        snapshots[name] = tree_hashes(target)
    for name, relative in (("jdk", "bin/java"), ("ghidra", "support/analyzeHeadless"),
                           ("ghidra", "Ghidra/Features/Decompiler/os/linux_arm_64/decompile"),
                           ("ghidra", "GPL/DemanglerGnu/os/linux_arm_64/demangler_gnu_v2_41")):
        entry = snapshots[name].get(relative, ())
        if len(entry) != 3 or entry[0] != "file" or not entry[1] & 0o111:
            raise SystemExit("fixed JDK or Ghidra runtime executable is missing")
    return snapshots


def verify_result(image_id, hashes, folder, *, parent=None, parent_runtime=None):
    image = inspect_image(image_id)
    if parent is not None:
        layers = parent["RootFS"]["Layers"]
        if image["RootFS"]["Layers"][:len(layers)] != layers:
            raise SystemExit("revised image does not preserve the parent RootFS layer prefix")
        if any(image["Config"].get(key) != parent["Config"].get(key) for key in RUNTIME_CONFIG):
            raise SystemExit("revised image runtime configuration differs from its parent")
    with stopped_image(image_id) as container:
        runtime = snapshot_runtime(container, folder)
    if parent_runtime is not None and any(runtime[key] != parent_runtime[key] for key in ("jdk", "ghidra")):
        raise SystemExit("revised image changed the JDK or Ghidra runtime hashes")
    expected = set(BUNDLE_FILES) | {"ghidra_scripts"}
    actual = runtime["reverseai"]
    if set(actual) != expected or actual["ghidra_scripts"][0] != "directory":
        raise SystemExit("image worker file set differs from the fixed bundle")
    for name, digest in hashes.items():
        entry = actual[name]
        if len(entry) != 3 or entry[0] != "file" or entry[2] != digest or entry[1] & 0o444 != 0o444:
            raise SystemExit("image worker bundle hash or readable mode differs: " + name)


def place(source, target):
    """Hard-link a verified download into the build context, or copy it when the link is not possible."""
    try:
        os.link(source, target)
    except OSError:
        shutil.copy2(source, target)


def full_build(args, hashes):
    check_dockerfile(SOURCE / "Dockerfile")
    check_bundle_dockerfile(SOURCE / "Dockerfile")
    files = {}
    for key, asset in ASSETS.items():
        path = args.download_dir / asset["name"]
        if not path.is_file():
            if not args.download:
                raise SystemExit(f"missing {asset['name']} in --download-dir (or pass --download)")
            args.download_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            fetch(asset, args.download_dir)
        if path.stat().st_size > asset["limit"] or file_sha256(path) != asset["sha256"]:
            raise SystemExit(f"{asset['name']} does not match its pinned SHA-256")
        files[key] = path

    docker("pull", "--platform", PLATFORM, BASE)
    with tempfile.TemporaryDirectory(prefix="reverseai-ghidra-build-") as temporary:
        context = Path(temporary)
        copy_bundle(SOURCE, context)
        for name in ("Dockerfile", "unpack.py"):
            shutil.copy2(SOURCE / name, context / name)
        check_dockerfile(context / "Dockerfile")
        check_bundle_dockerfile(context / "Dockerfile")
        if bundle_hashes(context) != hashes:
            raise SystemExit("source bundle changed while staging the build")
        (context / "downloads").mkdir()
        for path in files.values():
            place(path, context / "downloads" / path.name)
        iidfile = context / "image.id"
        docker("build", "--platform", PLATFORM, "--pull=false", "--iidfile", str(iidfile), "--tag", args.tag, str(context))
        image_id = iidfile.read_text(encoding="utf-8").strip()
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
            raise SystemExit("docker build returned no image ID")
        verification = context / "verification"
        verification.mkdir()
        verify_result(image_id, hashes, verification)
    return image_id


def revise(args, hashes):
    # Inspect the approved ID before creating containers, builds or preflight probes.
    parent = inspect_image(PARENT_IMAGE_ID)
    check_bundle_dockerfile(SOURCE / "Dockerfile.revise", revise=True)
    if args.route == "A":
        preflight_legacy_builder()
    with tempfile.TemporaryDirectory(prefix="reverseai-ghidra-revise-") as temporary:
        folder = Path(temporary)
        context = folder / "context"
        context.mkdir()
        copy_bundle(SOURCE, context)
        shutil.copy2(SOURCE / "Dockerfile.revise", context / "Dockerfile")
        check_bundle_dockerfile(context / "Dockerfile", revise=True)
        if bundle_hashes(context) != hashes:
            raise SystemExit("source bundle changed while staging the revision")
        before = folder / "parent"
        before.mkdir()
        with stopped_image(PARENT_IMAGE_ID) as container:
            parent_runtime = snapshot_runtime(container, before)
            if args.route == "B":
                for name in BUNDLE_FILES:
                    docker("cp", str(context / name), container + ":/opt/reverseai/" + name)
                image_id = docker("commit", container, args.tag, capture=True)
        if args.route == "A":
            iidfile = folder / "image.id"
            docker("build", "--platform", PLATFORM, "--pull=false", "--network=none", "--iidfile", str(iidfile),
                   "--tag", args.tag, str(context), legacy=True)
            image_id = iidfile.read_text(encoding="utf-8").strip()
        if not isinstance(image_id, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
            raise SystemExit("Docker revision returned no image ID")
        after = folder / "result"
        after.mkdir()
        verify_result(image_id, hashes, after, parent=parent, parent_runtime=parent_runtime)
    return image_id


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", nargs="?", choices=("build", "revise"), default="build")
    parser.add_argument("--route", type=str.upper, choices=("A", "B"), help="Explicit offline revision route (no fallback)")
    parser.add_argument("--download-dir", type=Path, help="Private directory holding the pinned downloads (full build only)")
    parser.add_argument("--download", action="store_true", help="Fetch a pinned file into --download-dir if it is missing")
    parser.add_argument("--tag", default="reverseai-ghidra:" + ADAPTER_VERSION)
    parser.add_argument("--lock", type=Path, default=SOURCE / "image.lock.json")
    args = parser.parse_args(argv)
    if args.command == "revise":
        if args.download or args.download_dir is not None or args.route is None:
            parser.error("revise requires --route A|B and refuses download options")
    elif args.download_dir is None or args.route is not None:
        parser.error("full build requires --download-dir and refuses --route")
    # No unreviewed helper or Java script is admitted into either build context.
    hashes = bundle_hashes(SOURCE)
    image_id = revise(args, hashes) if args.command == "revise" else full_build(args, hashes)
    lock = {"adapter_version": ADAPTER_VERSION, "base_digest": BASE_DIGEST, "ghidra_sha256": ASSETS["ghidra"]["sha256"],
            "image_id": image_id, "jdk_sha256": ASSETS["jdk"]["sha256"], "platform": PLATFORM,
            "parent_image_id": PARENT_IMAGE_ID if args.command == "revise" else None,
            "bundle_sha256": bundle_digest(hashes), "cache_format": CACHE_FORMAT}
    text = json.dumps(lock, indent=2, sort_keys=True) + "\n"
    temporary = args.lock.with_name(args.lock.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        with temporary.open("x", encoding="utf-8") as stream:
            stream.write(text)
        os.replace(temporary, args.lock)
    finally:
        temporary.unlink(missing_ok=True)
    print(text, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
