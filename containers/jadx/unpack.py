"""Build-stage helper: check a pinned download's SHA-256, then take only the JADX jar and its licence from the zip.

    python3 -I -B unpack.py check <file> <sha256>
    python3 -I -B unpack.py jadx <zip> <zip sha256> <jar sha256> <destination>

The zip must hold exactly one lib/jadx-1.5.6-all.jar and one LICENSE, regular files; nothing else is extracted. The
jar's SHA-256 is checked before it is kept. Files become mode 0644.
"""

import hashlib
import os
from pathlib import Path
import stat
import sys
import zipfile

JAR = "lib/jadx-1.5.6-all.jar"
LICENSE = "LICENSE"


def check(path, expected):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        while chunk := stream.read(1 << 20):
            digest.update(chunk)
    if digest.hexdigest() != expected:
        raise SystemExit("download does not match its pinned SHA-256")


def jadx(archive, jar_sha256, destination):
    root = Path(destination)
    root.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as bundle:
        names = [info.filename for info in bundle.infolist()]
        for wanted, target in ((JAR, root / "jadx-1.5.6-all.jar"), (LICENSE, root / "LICENSE")):
            matches = [info for info in bundle.infolist() if info.filename == wanted]
            if len(matches) != 1 or names.count(wanted) != 1 or stat.S_ISLNK(matches[0].external_attr >> 16):
                raise SystemExit("the archive does not hold exactly one regular " + wanted)
            digest = hashlib.sha256()
            with bundle.open(matches[0]) as source, open(target, "xb") as out:
                while chunk := source.read(1 << 20):
                    digest.update(chunk)
                    out.write(chunk)
            os.chmod(target, 0o644)
            if wanted == JAR and digest.hexdigest() != jar_sha256:
                target.unlink()
                raise SystemExit("the JADX jar does not match its pinned SHA-256")


def main(argv):
    if len(argv) == 3 and argv[0] == "check":
        check(argv[1], argv[2])
    elif len(argv) == 5 and argv[0] == "jadx":
        check(argv[1], argv[2])
        jadx(argv[1], argv[3], argv[4])
    else:
        raise SystemExit("usage: unpack.py check FILE SHA256 | jadx ZIP ZIP_SHA256 JAR_SHA256 DESTINATION")


if __name__ == "__main__":
    main(sys.argv[1:])
