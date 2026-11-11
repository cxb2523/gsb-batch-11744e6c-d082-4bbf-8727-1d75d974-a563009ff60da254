"""Build-stage helper: check each pinned download before use, then take only what the image needs.

    python3 -I -B unpack.py node <tar.xz> <sha256> <size> <destination>
    python3 -I -B unpack.py npm <tgz> <sha512 integrity> <destination>

node: the Node.js tarball must match its size and SHA-256; only bin/node (mode 0755) and LICENSE (0644) are taken,
each exactly one regular file, so npm, npx and corepack never reach the image. npm: the tarball must match its registry
sha512 integrity ("sha512-" and base64); every member must be a regular file or directory under package/ with a safe
relative name, and only regular files are written (0644), bounded in count and bytes. Nothing is executed.
"""

import base64
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import sys
import tarfile

NODE_ROOT = "node-v24.22.1-linux-arm64"
NODE_FILES = {f"{NODE_ROOT}/bin/node": ("bin/node", 0o755), f"{NODE_ROOT}/LICENSE": ("LICENSE", 0o644)}
MAX_NPM_FILES = 256
MAX_NPM_BYTES = 16 * 1024 * 1024
CHUNK = 1 << 20


def digest(path, algorithm):
    value = hashlib.new(algorithm)
    with open(path, "rb") as stream:
        while chunk := stream.read(CHUNK):
            value.update(chunk)
    return value


def copy(source, target, mode, limit):
    written = 0
    with open(target, "xb") as out:
        while chunk := source.read(CHUNK):
            written += len(chunk)
            if written > limit:
                raise SystemExit("an archive member exceeds its limit")
            out.write(chunk)
    os.chmod(target, mode)
    return written


def node(archive, sha256, size, destination):
    if os.path.getsize(archive) != int(size) or digest(archive, "sha256").hexdigest() != sha256:
        raise SystemExit("the Node.js download does not match its pinned size and SHA-256")
    root = Path(destination)
    (root / "bin").mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, "r:xz") as bundle:
        members = bundle.getmembers()
        for name, (target, mode) in NODE_FILES.items():
            matches = [member for member in members if member.name == name]
            if len(matches) != 1 or not matches[0].isfile():
                raise SystemExit("the Node.js archive does not hold exactly one regular " + name)
            with bundle.extractfile(matches[0]) as source:
                copy(source, root / target, mode, 256 * 1024 * 1024)


def npm(archive, integrity, destination):
    algorithm, _, encoded = integrity.partition("-")
    if algorithm != "sha512" or base64.b64encode(digest(archive, "sha512").digest()).decode("ascii") != encoded:
        raise SystemExit("the npm download does not match its pinned sha512 integrity")
    root = Path(destination)
    root.mkdir(parents=True, exist_ok=True)
    total = 0
    with tarfile.open(archive, "r:gz") as bundle:
        members = bundle.getmembers()
        if len(members) > MAX_NPM_FILES:
            raise SystemExit("the npm archive has too many members")
        for member in members:
            path = PurePosixPath(member.name)
            parts = path.parts
            if (not (member.isfile() or member.isdir()) or path.is_absolute() or len(parts) < 1 or parts[0] != "package"
                    or any(part in ("", ".", "..") for part in parts)
                    or not all(re.fullmatch(r"[A-Za-z0-9._@+-]{1,128}", part) for part in parts)):
                raise SystemExit("the npm archive holds a refused member")
            if member.isfile() and len(parts) > 1:
                target = root.joinpath(*parts[1:])
                target.parent.mkdir(parents=True, exist_ok=True)
                with bundle.extractfile(member) as source:
                    total += copy(source, target, 0o644, MAX_NPM_BYTES - total)
    if not (root / "package.json").is_file():
        raise SystemExit("the npm archive has no package.json")


def main(argv):
    if len(argv) == 5 and argv[0] == "node":
        node(argv[1], argv[2], argv[3], argv[4])
    elif len(argv) == 4 and argv[0] == "npm":
        npm(argv[1], argv[2], argv[3])
    else:
        raise SystemExit("usage: unpack.py node TAR_XZ SHA256 SIZE DESTINATION | npm TGZ INTEGRITY DESTINATION")


if __name__ == "__main__":
    main(sys.argv[1:])
