"""Dependency-free PEP 517 backend; also: python tools/reverseai_build.py wheel|sdist."""

import argparse
import ast
import base64
import csv
import gzip
import hashlib
import io
from pathlib import Path
import stat
import subprocess
import tarfile
import tomllib
import zipfile

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ("lief", "yarax", "ghidra", "jadx", "jsparser")
SOURCE_DIRS = ("reverseai", "tools", "containers", "docs", "tests", "media")
LICENSE_FILES = ("LICENSE", "THIRD_PARTY_NOTICES.md")
SOURCE_FILES = ("README.md", *LICENSE_FILES, "pyproject.toml")


def _version():
    tree = ast.parse((ROOT / "reverseai/__init__.py").read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets):
            return ast.literal_eval(node.value)
    raise ValueError("Missing ReverseAI version")


def _metadata():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    version = _version()
    if project["name"] != "reverseai" or project["version"] != version:
        raise ValueError("Inconsistent ReverseAI project identity")
    if project.get("license") != "MIT" or project.get("license-files") != list(LICENSE_FILES):
        raise ValueError("Unsupported project license declaration")
    headers = ("Metadata-Version: 2.4", "Name: reverseai", f"Version: {version}",
               f"Summary: {project['description']}", f"Requires-Python: {project['requires-python']}",
               "Description-Content-Type: text/markdown; charset=UTF-8", "License-Expression: MIT",
               *(f"License-File: {name}" for name in LICENSE_FILES))
    return ("\n".join(headers) + "\n\n").encode("utf-8") + (ROOT / project["readme"]).read_bytes()


def _read(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"Expected a regular source file: {path.relative_to(ROOT)}")
    return path.read_bytes()


def _wheel_files(*, editable=False):
    if editable:
        files = {"reverseai_editable.pth": (str(ROOT.resolve()) + "\n").encode("utf-8")}
    else:
        files = {path.relative_to(ROOT).as_posix(): _read(path)
                 for path in (ROOT / "reverseai").rglob("*.py") if "__pycache__" not in path.parts}
        for tool in TOOLS:
            files[f"reverseai/_locks/{tool}.json"] = _read(ROOT / "containers" / tool / "image.lock.json")
        files["reverseai/_locks/m2_fixture_v1.json"] = _read(ROOT / "containers/yarax/m2_fixture_v1.json")
    info = f"reverseai-{_version()}.dist-info"
    files[f"{info}/METADATA"] = _metadata()
    files[f"{info}/WHEEL"] = ("Wheel-Version: 1.0\nGenerator: reverseai_build\n"
                             "Root-Is-Purelib: true\nTag: py3-none-any\n").encode("ascii")
    files[f"{info}/entry_points.txt"] = b"[console_scripts]\nreverseai = reverseai.cli:main\n"
    for name in LICENSE_FILES:
        files[f"{info}/licenses/{name}"] = _read(ROOT / name)
    record = f"{info}/RECORD"
    rows = [(name, "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii"),
             str(len(data))) for name, data in files.items()]
    rows.append((record, "", ""))
    stream = io.StringIO(newline="")
    csv.writer(stream, lineterminator="\n").writerows(sorted(rows))
    files[record] = stream.getvalue().encode("utf-8")
    return files


def _write_wheel(wheel_directory, files):
    filename = f"reverseai-{_version()}-py3-none-any.whl"
    destination = Path(wheel_directory)
    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destination / filename, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data, compresslevel=9)
    return filename


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    """Build the universal wheel without importing the application or any input."""
    return _write_wheel(wheel_directory, _wheel_files())


def build_editable(wheel_directory, config_settings=None, metadata_directory=None):
    """Expose this trusted checkout through a .pth, retaining the normal metadata."""
    return _write_wheel(wheel_directory, _wheel_files(editable=True))


def _source_files():
    # Only this checkout's index selects files; never consult a parent repository.
    if (ROOT / ".git").exists():
        result = subprocess.run(["git", "-C", str(ROOT), "ls-files", "--stage", "-z"],
                                check=True, stdout=subprocess.PIPE)
        entries = []
        for row in result.stdout.split(b"\0"):
            if not row:
                continue
            attributes, raw_name = row.split(b"\t", 1)
            mode, _, stage = attributes.split()
            name = raw_name.decode("utf-8")
            if name not in SOURCE_FILES and name.split("/", 1)[0] not in SOURCE_DIRS:
                continue
            if stage != b"0" or mode not in (b"100644", b"100755"):
                raise ValueError("Source distribution requires regular, resolved Git entries")
            entries.append((name, int(mode, 8) & 0o777))
        return sorted(entries)
    if not (ROOT / "PKG-INFO").is_file():
        raise ValueError("Build the source distribution from a Git checkout or an unpacked sdist")
    paths = [ROOT / name for name in SOURCE_FILES]
    paths += [path for name in SOURCE_DIRS for path in (ROOT / name).rglob("*")
              if path.is_file() and "__pycache__" not in path.parts]
    return sorted((path.relative_to(ROOT).as_posix(), 0o755 if path.stat().st_mode & 0o111 else 0o644)
                  for path in paths)


def build_sdist(sdist_directory, config_settings=None):
    """Use Git's file list and modes, with deterministic tar and gzip metadata."""
    root = f"reverseai-{_version()}"
    filename = root + ".tar.gz"
    destination = Path(sdist_directory)
    destination.mkdir(parents=True, exist_ok=True)
    files = {name: (_read(ROOT / name), mode) for name, mode in _source_files()}
    files["PKG-INFO"] = (_metadata(), 0o644)
    with (destination / filename).open("wb") as output:
        with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0, compresslevel=9) as compressed:
            with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.PAX_FORMAT) as archive:
                for name, (data, mode) in sorted(files.items()):
                    info = tarfile.TarInfo(root + "/" + name)
                    info.size = len(data)
                    info.mode = mode
                    info.mtime = info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    archive.addfile(info, io.BytesIO(data))
    return filename


def get_requires_for_build_wheel(config_settings=None):
    return []


def get_requires_for_build_sdist(config_settings=None):
    return []


def get_requires_for_build_editable(config_settings=None):
    return []


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=("wheel", "sdist"))
    parser.add_argument("--out", type=Path, default=Path("dist"))
    args = parser.parse_args()
    print((build_wheel if args.kind == "wheel" else build_sdist)(args.out))
