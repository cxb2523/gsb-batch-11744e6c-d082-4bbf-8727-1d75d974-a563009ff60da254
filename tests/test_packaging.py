"""Distribution contents, reproducibility and real offline installation; no Docker."""

import base64
import csv
from email.parser import BytesParser
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import unittest
from unittest import mock
import zipfile

from reverseai import __version__, contained
from tests.fixtures_structure import elf
from tools import reverseai_build as build

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ("lief", "yarax", "ghidra", "jadx", "jsparser")
INFO = "reverseai-0.9.0.dist-info"


class PackagingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="reverseai-packaging-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.work = Path(cls.temporary.name)
        cls.wheel = cls.work / build.build_wheel(cls.work)
        cls.editable = cls.work / "editable" / build.build_editable(cls.work / "editable")
        cls.source = ROOT
        if not (ROOT / ".git").exists() and not (ROOT / "PKG-INFO").is_file():
            # Linux's git-archive proof has no index: exercise sdist hooks in a temporary unpacked source tree.
            cls.source = cls.work / "unpacked"
            cls.copy_sources(cls.source)
            (cls.source / "PKG-INFO").write_bytes(build._metadata())
        with mock.patch.object(build, "ROOT", cls.source):
            cls.sdist = cls.work / build.build_sdist(cls.work)

    @staticmethod
    def copy_sources(destination):
        destination.mkdir()
        for name in ("reverseai", "tools", "containers", "docs", "tests", "media"):
            if (ROOT / name).is_dir():
                shutil.copytree(ROOT / name, destination / name, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        for name in ("README.md", "LICENSE", "THIRD_PARTY_NOTICES.md", "pyproject.toml"):
            shutil.copyfile(ROOT / name, destination / name)

    def test_project_identity_and_dependency_free_build_contract(self):
        value = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        project = value["project"]
        self.assertEqual((project["name"], project["version"], __version__), ("reverseai", "0.9.0", "0.9.0"))
        self.assertEqual(project["requires-python"], ">=3.12")
        self.assertEqual(project["readme"], "README.md")
        self.assertEqual(project["dependencies"], [])
        self.assertEqual(project["license"], "MIT")
        self.assertEqual(project["license-files"], ["LICENSE", "THIRD_PARTY_NOTICES.md"])
        self.assertEqual(project["scripts"], {"reverseai": "reverseai.cli:main"})
        self.assertEqual(value["build-system"], {"requires": [], "build-backend": "reverseai_build", "backend-path": ["tools"]})
        self.assertEqual(build.get_requires_for_build_wheel(), [])
        self.assertEqual(build.get_requires_for_build_sdist(), [])
        self.assertEqual(build.get_requires_for_build_editable(), [])

    def test_wheel_has_exact_files_and_fixed_metadata(self):
        expected = {path.relative_to(ROOT).as_posix() for path in (ROOT / "reverseai").rglob("*.py")
                    if "__pycache__" not in path.parts}
        expected.update(f"reverseai/_locks/{name}.json" for name in TOOLS)
        expected.add("reverseai/_locks/m2_fixture_v1.json")  # Required by the host verifier
        expected.update(f"{INFO}/{name}" for name in ("METADATA", "WHEEL", "entry_points.txt", "RECORD",
                                                    "licenses/LICENSE", "licenses/THIRD_PARTY_NOTICES.md"))
        self.assertEqual(self.wheel.name, "reverseai-0.9.0-py3-none-any.whl")
        with zipfile.ZipFile(self.wheel) as archive:
            self.assertEqual(archive.namelist(), sorted(expected))
            self.assertEqual(len(archive.namelist()), len(expected))
            for entry in archive.infolist():
                with self.subTest(entry=entry.filename):
                    self.assertEqual(entry.date_time, (1980, 1, 1, 0, 0, 0))
                    self.assertEqual(stat.S_IMODE(entry.external_attr >> 16), 0o644)
                    self.assertTrue(stat.S_ISREG(entry.external_attr >> 16))
                    self.assertEqual(entry.create_system, 3)
                    if entry.filename.endswith(".py"):
                        self.assertEqual(archive.read(entry), (ROOT / entry.filename).read_bytes())
            wheel = BytesParser().parsebytes(archive.read(f"{INFO}/WHEEL"))
            self.assertEqual(dict(wheel), {"Wheel-Version": "1.0", "Generator": "reverseai_build",
                                          "Root-Is-Purelib": "true", "Tag": "py3-none-any"})
            self.assertEqual(archive.read(f"{INFO}/entry_points.txt"), b"[console_scripts]\nreverseai = reverseai.cli:main\n")
            for name in ("LICENSE", "THIRD_PARTY_NOTICES.md"):
                self.assertEqual(archive.read(f"{INFO}/licenses/{name}"), (ROOT / name).read_bytes())
            raw = archive.read(f"{INFO}/METADATA")
            metadata = BytesParser().parsebytes(raw)
            self.assertEqual(metadata.get_all("License-File"), ["LICENSE", "THIRD_PARTY_NOTICES.md"])
            self.assertEqual({key: value for key, value in metadata.items() if key != "License-File"}, {
                "Metadata-Version": "2.4", "Name": "reverseai", "Version": "0.9.0",
                "Summary": "Contained static analysis with verifiable evidence.", "Requires-Python": ">=3.12",
                "Description-Content-Type": "text/markdown; charset=UTF-8", "License-Expression": "MIT"})
            self.assertEqual(raw.split(b"\n\n", 1)[1], (ROOT / "README.md").read_bytes())

    def test_record_covers_every_entry_with_actual_hashes_and_sizes(self):
        for path in (self.wheel, self.editable):
            with self.subTest(wheel=path), zipfile.ZipFile(path) as archive:
                rows = list(csv.reader(io.StringIO(archive.read(f"{INFO}/RECORD").decode("utf-8"))))
                self.assertEqual([row[0] for row in rows], archive.namelist())
                for name, digest, size in rows:
                    if name == f"{INFO}/RECORD":
                        self.assertEqual((digest, size), ("", ""))
                        continue
                    data = archive.read(name)
                    expected = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode("ascii").rstrip("=")
                    self.assertEqual((digest, size), ("sha256=" + expected, str(len(data))))

    def test_editable_has_only_absolute_pth_and_the_normal_distribution_metadata(self):
        with zipfile.ZipFile(self.editable) as editable, zipfile.ZipFile(self.wheel) as wheel:
            metadata = {name for name in wheel.namelist() if name.startswith(INFO + "/")}
            self.assertEqual(editable.namelist(), sorted(["reverseai_editable.pth", *metadata]))
            self.assertEqual(editable.read("reverseai_editable.pth"), (str(ROOT.resolve()) + "\n").encode("utf-8"))
            for name in metadata - {f"{INFO}/RECORD"}:
                self.assertEqual(editable.read(name), wheel.read(name))
            for entry in editable.infolist():
                self.assertEqual(entry.date_time, (1980, 1, 1, 0, 0, 0))
                self.assertEqual(stat.S_IMODE(entry.external_attr >> 16), 0o644)
        second = self.work / "editable-again"
        self.assertEqual(self.editable.read_bytes(), (second / build.build_editable(second)).read_bytes())

    def test_all_build_hooks_refuse_other_license_declarations(self):
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
        invalid = ({"license": "Apache-2.0"}, {"license": "mit"}, {"license": {"text": "MIT"}},
                   {"license": None}, {"license-files": None}, {"license-files": []},
                   {"license-files": ["LICENSE"]}, {"license-files": ["THIRD_PARTY_NOTICES.md", "LICENSE"]},
                   {"license-files": ["LICENSE", "THIRD_PARTY_NOTICES.md", "extra.txt"]})
        for mutation in invalid:
            for hook in (build.build_wheel, build.build_editable, build.build_sdist):
                with self.subTest(mutation=mutation, hook=hook.__name__), \
                        mock.patch.object(build, "ROOT", self.source), \
                        mock.patch.object(build.tomllib, "loads", return_value={"project": {**project, **mutation}}):
                    with self.assertRaisesRegex(ValueError, "^Unsupported project license declaration$"):
                        hook(self.work / "invalid-license")

    def test_packaged_locks_and_ruleset_equal_the_checkout_bytes(self):
        with zipfile.ZipFile(self.wheel) as archive:
            for name in TOOLS:
                self.assertEqual(archive.read(f"reverseai/_locks/{name}.json"),
                                 (ROOT / "containers" / name / "image.lock.json").read_bytes())
            self.assertEqual(archive.read("reverseai/_locks/m2_fixture_v1.json"),
                             (ROOT / "containers/yarax/m2_fixture_v1.json").read_bytes())

    def test_wheel_and_sdist_builds_are_byte_identical_with_different_environment(self):
        # Separate output locations and environment values cannot affect archive metadata.
        with mock.patch.dict(os.environ, {"SOURCE_DATE_EPOCH": "1900000000", "TZ": "Pacific/Honolulu"}):
            other = self.work / "second"
            self.assertEqual(self.wheel.read_bytes(), (other / build.build_wheel(other)).read_bytes())
            with mock.patch.object(build, "ROOT", self.source):
                self.assertEqual(self.sdist.read_bytes(), (other / build.build_sdist(other)).read_bytes())

    def test_sdist_pins_level_nine_when_the_runtime_gzip_default_changes(self):
        gzip_file = build.gzip.GzipFile
        archives, levels = [], []
        for runtime_default in (6, 9):
            def runtime_gzip(*args, compresslevel=runtime_default, **kwargs):
                levels.append(compresslevel)
                return gzip_file(*args, compresslevel=compresslevel, **kwargs)

            destination = self.work / f"gzip-default-{runtime_default}"
            with mock.patch.object(build, "ROOT", self.source), mock.patch.object(build.gzip, "GzipFile", runtime_gzip):
                archives.append((destination / build.build_sdist(destination)).read_bytes())
        self.assertTrue(archives[0] == archives[1], "The runtime gzip default changed the sdist bytes")
        self.assertEqual(levels, [9, 9])

    def test_git_archive_copy_builds_identical_wheel_but_sdist_requires_provenance(self):
        source = self.work / "archive-copy"
        self.copy_sources(source)
        self.assertFalse((source / ".git").exists())
        self.assertFalse((source / "PKG-INFO").exists())
        for path in source.rglob("*"):
            if path.is_file():
                os.utime(path, (1234567890, 1234567890))
        (source / "reverseai/__init__.py").chmod(0o755)
        with mock.patch.object(build, "ROOT", source):
            self.assertEqual((self.work / "archive-wheel" / build.build_wheel(self.work / "archive-wheel")).read_bytes(),
                             self.wheel.read_bytes())
            # Neither Git nor PKG-INFO is a fixed refusal, never a guessed file list.
            with self.assertRaisesRegex(ValueError, "^Build the source distribution from a Git checkout or an unpacked sdist$"):
                build.build_sdist(self.work / "refused-sdist")

    def test_sdist_exact_source_list_modes_root_and_metadata(self):
        paths = {}
        if (ROOT / ".git").exists():
            raw = subprocess.run(["git", "ls-files", "--stage", "-z"], cwd=ROOT, check=True, capture_output=True).stdout
            for row in raw.split(b"\0"):
                if row:
                    attributes, name = row.split(b"\t", 1)
                    paths[name.decode("utf-8")] = int(attributes.split()[0], 8) & 0o777
        else:
            paths = {p.relative_to(ROOT).as_posix(): 0o755 if p.stat().st_mode & 0o111 else 0o644
                     for p in ROOT.rglob("*") if p.is_file() and "__pycache__" not in p.parts}
        selected = {name: mode for name, mode in paths.items()
                    if name in ("README.md", "LICENSE", "THIRD_PARTY_NOTICES.md", "pyproject.toml")
                    or name.split("/", 1)[0] in ("reverseai", "tools", "containers", "docs", "tests", "media")}
        selected["PKG-INFO"] = 0o644
        prefix = "reverseai-0.9.0/"
        with tarfile.open(self.sdist, "r:gz") as archive, zipfile.ZipFile(self.wheel) as wheel:
            self.assertEqual(archive.getnames(), [prefix + name for name in sorted(selected)])
            for entry in archive.getmembers():
                name = entry.name.removeprefix(prefix)
                with self.subTest(name=name):
                    self.assertTrue(entry.isfile())
                    self.assertEqual((entry.mtime, entry.uid, entry.gid, entry.uname, entry.gname), (0, 0, 0, "", ""))
                    self.assertEqual(entry.mode, selected[name])
                    expected = wheel.read(f"{INFO}/METADATA") if name == "PKG-INFO" else (ROOT / name).read_bytes()
                    self.assertEqual(archive.extractfile(entry).read(), expected)
        header = self.sdist.read_bytes()[:10]
        self.assertEqual(header[:4], b"\x1f\x8b\x08\x00")  # no source path in the gzip filename
        self.assertEqual(header[4:8], bytes(4))

    def test_default_lock_uses_package_data_before_checkout_and_rejects_unknown_tools(self):
        for name in TOOLS:
            module = importlib.import_module(f"reverseai.tools.{name}_tool")
            self.assertEqual(module.DEFAULT_LOCK, ROOT / "containers" / name / "image.lock.json")
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory).resolve() / "reverseai"
            (package / "_locks").mkdir(parents=True)
            with mock.patch.object(contained, "__file__", str(package / "contained.py")):
                for name in TOOLS:
                    self.assertEqual(contained.default_lock(name), package.parent / "containers" / name / "image.lock.json")
                    lock = package / "_locks" / f"{name}.json"
                    lock.write_text("{}")
                    self.assertEqual(contained.default_lock(name), lock)
                for name in ("other", "../lief", "LIEF", ""):
                    with self.assertRaises(ValueError):
                        contained.default_lock(name)

    def test_sdist_uses_git_executable_mode_and_excludes_untracked_files(self):
        source = self.work / "git-modes"
        self.copy_sources(source)
        (source / ".git").mkdir()
        (source / "tools/untracked.py").write_text("# Must not be distributed.\n")
        tracked = ["README.md", "LICENSE", "THIRD_PARTY_NOTICES.md", "pyproject.toml", "tools/reverseai_build.py"]
        manifest = b"".join((f"{'100755' if name.startswith('tools/') else '100644'} " + "0" * 40 +
                              f" 0\t{name}\0").encode("utf-8") for name in tracked)
        with mock.patch.object(build, "ROOT", source), mock.patch.object(build.subprocess, "run",
                return_value=subprocess.CompletedProcess([], 0, stdout=manifest)):
            path = self.work / "modes" / build.build_sdist(self.work / "modes")
        with tarfile.open(path, "r:gz") as archive:
            self.assertEqual(archive.getnames(), ["reverseai-0.9.0/" + name for name in sorted([*tracked, "PKG-INFO"])])
            self.assertEqual(archive.getmember("reverseai-0.9.0/tools/reverseai_build.py").mode, 0o755)
            self.assertEqual(archive.getmember("reverseai-0.9.0/README.md").mode, 0o644)

    def run_offline(self, argv, *, cwd=None):
        environment = {key: value for key, value in os.environ.items() if key not in ("PYTHONPATH", "PYTHONHOME")}
        environment.update(PIP_NO_INDEX="1", PIP_DISABLE_PIP_VERSION_CHECK="1", PIP_CONFIG_FILE=os.devnull,
                           PYTHONDONTWRITEBYTECODE="1")
        result = subprocess.run([str(value) for value in argv], cwd=self.work if cwd is None else cwd, env=environment,
                                capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout

    def venv_commands(self, name):
        venv = self.work / name
        self.run_offline([sys.executable, "-m", "venv", venv])
        bindir = venv / ("Scripts" if os.name == "nt" else "bin")
        return (bindir / ("python.exe" if os.name == "nt" else "python"),
                bindir / ("reverseai.exe" if os.name == "nt" else "reverseai"))

    def test_real_offline_editable_install_uses_checkout_code_and_locks(self):
        python, command = self.venv_commands("editable-venv")
        self.run_offline([python, "-I", "-m", "pip", "install", "--no-index", "--no-deps", "--editable", ROOT])
        self.assertEqual(self.run_offline([command, "--version"]), "reverseai 0.9.0\n")
        script = '''
import importlib, importlib.metadata, json, pathlib
from unittest.mock import patch
import reverseai
checks = {'source': str(pathlib.Path(reverseai.__file__).resolve()), 'locks': {}}
with patch('subprocess.run', side_effect=AssertionError('Docker must not run')):
    for name in ('lief', 'yarax', 'ghidra', 'jadx', 'jsparser'):
        module = importlib.import_module('reverseai.tools.' + name + '_tool')
        checks['locks'][name] = str(module.DEFAULT_LOCK)
dist = importlib.metadata.distribution('reverseai')
checks['license'] = dist.metadata['License-Expression']
checks['license_files'] = dist.metadata.get_all('License-File')
checks['notices'] = dist.read_text('licenses/THIRD_PARTY_NOTICES.md')
checks['editable'] = json.loads(dist.read_text('direct_url.json'))['dir_info']['editable']
print(json.dumps(checks))
'''
        facts = json.loads(self.run_offline([python, "-I", "-c", script]))
        self.assertEqual(facts["source"], str(ROOT / "reverseai/__init__.py"))
        self.assertEqual(facts["locks"], {name: str(ROOT / "containers" / name / "image.lock.json") for name in TOOLS})
        self.assertEqual(facts["license"], "MIT")
        self.assertEqual(facts["license_files"], ["LICENSE", "THIRD_PARTY_NOTICES.md"])
        self.assertEqual(facts["notices"], (ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8"))
        self.assertIs(facts["editable"], True)

    def test_real_offline_install_and_pep517_build_from_sdist(self):
        run = self.run_offline
        python, command = self.venv_commands("venv")
        run([python, "-I", "-m", "pip", "install", "--no-index", "--no-deps", self.wheel])
        sample = self.work / "inert.elf"
        sample.write_bytes(elf()[0])
        destination = self.work / "analysis"
        run([command, "analyze", sample, "--out", destination])
        result = json.loads((destination / "report.json").read_text(encoding="utf-8"))
        self.assertEqual(result["reverseai"], "0.9.0")
        self.assertGreater(result["summary"]["supported"], 0)
        self.assertTrue((destination / "report.md").is_file())
        script = '''
import importlib, json, pathlib, sys
from types import SimpleNamespace
from unittest.mock import patch
import reverseai
from reverseai import contained
checks = {}
with patch('subprocess.run', side_effect=AssertionError('Docker must not run')):
    for name in ('lief', 'yarax', 'ghidra', 'jadx', 'jsparser'):
        module = importlib.import_module('reverseai.tools.' + name + '_tool')
        path = module.DEFAULT_LOCK
        assert path == pathlib.Path(reverseai.__file__).parent / '_locks' / (name + '.json')
        assert path.is_relative_to(pathlib.Path(sys.prefix))
        extra = {'extra_keys': ('ruleset_sha256',)} if name == 'yarax' else {}
        lock = contained.load_lock(path, adapter_version=module.REF.version, **extra)
        tool = module.make_tool(SimpleNamespace(lock=lock))
        assert tool.ref == module.REF
        checks[name] = path.read_text()
print(json.dumps(checks))
'''
        checks = json.loads(run([python, "-I", "-c", script]))
        for name in TOOLS:
            self.assertEqual(checks[name].encode("utf-8"), (ROOT / "containers" / name / "image.lock.json").read_bytes())
        # pip's isolated build loads the in-tree backend with zero build dependencies, without Git.
        output = self.work / "from-sdist"
        run([python, "-I", "-m", "pip", "wheel", "--no-index", "--no-deps", "--no-cache-dir",
             "--wheel-dir", output, self.sdist])
        self.assertEqual((output / self.wheel.name).read_bytes(), self.wheel.read_bytes())


    def test_sdist_includes_the_closed_prepared_worker_source_bundle(self):
        with tarfile.open(self.sdist, "r:gz") as archive:
            names = set(archive.getnames())
        for name in ("containers/ghidra/project_cache.py", "containers/ghidra/Dockerfile.revise",
                     "containers/ghidra/ghidra_scripts/ReverseAIPrepare.java"):
            self.assertIn(f"reverseai-{__version__}/" + name, names)


if __name__ == "__main__":
    unittest.main()
