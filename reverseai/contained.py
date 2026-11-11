"""Fixed Docker boundary for contained tools; no native tool runs on the host."""

from collections.abc import Mapping
from functools import partial
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from types import MappingProxyType
import uuid

from reverseai.contract import ArgSpec, ContractError, MAX_WORKER_REPLY_BYTES, canonical_json, check_artifact, sha256_hex
from reverseai.ghidra_cache import CacheError

STAGING_ROOT = Path("/Users/Shared/rea-safe-staging-501")
WALL_SECONDS = 45
GHIDRA_WALL_SECONDS = 240
PLATFORM = "linux/arm64"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
GHIDRA_VERSION = "12.1.4-r7"
GHIDRA_PREPARE_WALL_SECONDS = 900
GHIDRA_PREPARE_MAX_BYTES = 64 * 1024 * 1024
GHIDRA_CACHE_FORMAT = 1
GHIDRA_OPERATIONS = frozenset(("ghidra.analyze", "ghidra.functions", "ghidra.function", "ghidra.xrefs",
                               "ghidra.prepare", "ghidra.pseudocode", "ghidra.export_function", "ghidra.export_program"))
JADX_VERSION = "1.5.6-r1"
JADX_WALL_SECONDS = 120
JSPARSER_VERSION = "8.0.4-r2"
JSPARSER_WALL_SECONDS = 120
GHIDRA_PINS = MappingProxyType({
    "base_digest": "sha256:16bf2b5c59a08523519d3c8589deca849285dee1d62a3653e124c3dba340f15e",
    "ghidra_sha256": "ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db",
    "jdk_sha256": "23e37e026f12f3e706f18938ff611db3032d075b09d0879a25d06718c773e223",
})
JADX_PINS = MappingProxyType({
    "base_digest": GHIDRA_PINS["base_digest"],
    "jadx_zip_sha256": "545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974",
    "jadx_jar_sha256": "fe3e12c45acf75f92369685fd02d1d7a7323385dc725680a9b98a0dac0ea554b",
    "jdk_sha256": GHIDRA_PINS["jdk_sha256"],
})
JSPARSER_PINS = MappingProxyType({
    "base_digest": GHIDRA_PINS["base_digest"],
    "node_sha256": "dbabf7a1cbf947e6059ffad2c27b80041db97dea1e553b62afdee7f13fca336e",
    "babel_parser_integrity": "sha512-srpptsAkEbbNIC/q8nT7o+m6CQe8CJUTV/t7MYc9NnWlgYVtHOb7JH6SorxMhN0kuRJjVqXbKClG6xSbPtzz+g==",
    "babel_types_integrity": "sha512-eY+Yn3dCqTGmyiq2QRU66lA5FL8lqqqvecHt0fF3uHONIa7ToYsaCiWV8lOKqAs0Rb2SjixiKFROngnulPtt2g==",
    "helper_string_parser_integrity": "sha512-+6HYEBnsDRZHJtUTAEfMQd0zMDqdFHS7C+5vAsEZqBUr3vEMWOWlHJ0Jz1gS8jJIlCvLsuA6ivmeoqzH936YcA==",
    "helper_validator_identifier_integrity": "sha512-HYx0YmuchRxRSpnjvcNffnPS8DCauKNmnumIuHG3jnQAVewRA7kfJGwF13ayEpSZs7s4R/oBH4eppuXcAQd5JQ==",
})
_LEGACY_PROFILE = MappingProxyType({"pids": 64, "memory": "512m", "cpus": 1,
    "tmpfs": "/tmp:rw,noexec,nosuid,nodev,size=64m", "wall_seconds": WALL_SECONDS})
_GHIDRA_PROFILE = MappingProxyType({"pids": 256, "memory": "2g", "cpus": 2,
    "tmpfs": "/tmp:rw,noexec,nosuid,nodev,size=512m", "wall_seconds": GHIDRA_WALL_SECONDS})
_GHIDRA_PREPARE_PROFILE = MappingProxyType({**_GHIDRA_PROFILE, "wall_seconds": GHIDRA_PREPARE_WALL_SECONDS})
_JADX_PROFILE = MappingProxyType({"pids": 256, "memory": "2g", "cpus": 2,
    "tmpfs": "/tmp:rw,noexec,nosuid,nodev,size=512m", "wall_seconds": JADX_WALL_SECONDS})
_JSPARSER_PROFILE = MappingProxyType({"pids": 64, "memory": "2g", "cpus": 2,
    "tmpfs": "/tmp:rw,noexec,nosuid,nodev,size=64m", "wall_seconds": JSPARSER_WALL_SECONDS})


def default_lock(tool):
    """Resolve installed lock data first, then the source checkout's container lock."""
    if tool not in ("lief", "yarax", "ghidra", "jadx", "jsparser"):
        raise ValueError("Unknown contained tool")
    package = Path(__file__).resolve().parent
    packaged = package / "_locks" / f"{tool}.json"
    return packaged if packaged.is_file() else package.parent / "containers" / tool / "image.lock.json"


def resource_profile(operation):
    """Only the validated operation selects resources; requests cannot override them."""
    if operation == "ghidra.prepare":
        return _GHIDRA_PREPARE_PROFILE
    if operation in GHIDRA_OPERATIONS:
        return _GHIDRA_PROFILE
    if operation == "jadx.method":
        return _JADX_PROFILE
    if operation == "jsparser.syntax":
        return _JSPARSER_PROFILE
    if operation in ("lief.headers", "lief.sections", "yarax.matches"):
        return _LEGACY_PROFILE
    raise ContainedError("InvalidWorkerArguments")


class ContainedError(RuntimeError):
    """A short controller-side error that never contains command output or paths."""


class ContainedTimeout(ContainedError, TimeoutError):
    pass


def load_lock(lock, *, adapter_version="1.0.0-r2", extra_keys=()):
    """Validate tool-provided pins; the default version is the LIEF adapter's, for callers that name none."""
    try:
        if isinstance(lock, Mapping):
            value = dict(lock)
        else:
            with Path(lock).open("rb") as stream:
                raw = stream.read(16_385)
            if len(raw) > 16_384:
                raise ValueError
            value = json.loads(raw)
        if not isinstance(value, dict) or not _DIGEST.fullmatch(value.get("image_id", "")):
            raise ValueError
        if value.get("platform") != PLATFORM or value.get("adapter_version") != adapter_version:
            raise ValueError
        if not _DIGEST.fullmatch(value.get("base_digest", "")):
            raise ValueError
        if adapter_version in (JADX_VERSION, JSPARSER_VERSION):
            pins = JSPARSER_PINS if adapter_version == JSPARSER_VERSION else JADX_PINS
            keys = ("image_id", "platform", "adapter_version", *pins, "driver_sha256", "worker_sha256")
            if (extra_keys or set(value) != set(keys) or any(value[key] != pin for key, pin in pins.items())
                    or any(not isinstance(value[key], str) or not re.fullmatch(r"[0-9a-f]{64}", value[key])
                           for key in ("driver_sha256", "worker_sha256"))):
                raise ValueError
        elif adapter_version == GHIDRA_VERSION:
            keys = ("image_id", "platform", "adapter_version", *GHIDRA_PINS,
                    "parent_image_id", "bundle_sha256", "cache_format")
            if (extra_keys or set(value) != set(keys) or any(value[key] != pin for key, pin in GHIDRA_PINS.items())
                    or type(value["cache_format"]) is not int or value["cache_format"] != GHIDRA_CACHE_FORMAT
                    or not isinstance(value["bundle_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["bundle_sha256"])
                    or value["parent_image_id"] is not None and (not isinstance(value["parent_image_id"], str)
                    or not _DIGEST.fullmatch(value["parent_image_id"]))):
                raise ValueError
        else:
            if not re.fullmatch(r"[0-9a-f]{64}", value.get("wheel_sha256", "")):
                raise ValueError
            keys = ("image_id", "platform", "base_digest", "wheel_sha256", "adapter_version") + tuple(extra_keys)
        if extra_keys and (set(value) != set(keys) or any(
                not re.fullmatch(r"[0-9a-f]{64}", value.get(key, "")) for key in extra_keys)):
            raise ValueError
        return {key: value[key] for key in keys}
    except (OSError, ValueError, TypeError):
        raise ContainedError("InvalidImageLock") from None


_GHIDRA_QUERY_ARGS = {
    "ghidra.functions": {
        "query": ArgSpec("str", default=""),
        "start": ArgSpec("int", 0, 65535, default=0),
        "limit": ArgSpec("int", 1, 128, default=64),
    },
    "ghidra.function": {
        "select": ArgSpec("enum", choices=("entry", "name"), default="entry"),
        "entry": ArgSpec("int", 0, 2 ** 64 - 1, default=0),
        "name": ArgSpec("str", default=""),
        "parts": ArgSpec("enum", choices=("info", "pseudocode", "assembly", "callees", "callers", "all"), default="all"),
        "start": ArgSpec("int", 0, 65535, default=0),
        "limit": ArgSpec("int", 1, 256, default=64),
        "max_chars": ArgSpec("int", 64, 2048, default=1024),
        "max_calls": ArgSpec("int", 0, 256, default=64),
        "max_refs": ArgSpec("int", 0, 128, default=64),
    },
    "ghidra.xrefs": {
        "address": ArgSpec("int", 0, 2 ** 64 - 1),
        "start": ArgSpec("int", 0, 65535, default=0),
        "limit": ArgSpec("int", 1, 256, default=64),
    },
}


def validate_jadx_request(args):
    """Only host-resolved artifacts and raw hex identities cross the worker boundary."""
    try:
        if set(args) != {"members", "targets", "start", "max_chars"}:
            raise ValueError
        start = ArgSpec("int", 0, 1048575).check(args["start"])
        maximum = ArgSpec("int", 64, 2048).check(args["max_chars"])
        members, targets = args["members"], args["targets"]
        if not (isinstance(members, list) and 1 <= len(members) <= 16
                and isinstance(targets, list) and 1 <= len(targets) <= 16):
            raise ValueError
        for member in members:
            check_artifact(member)
            if not re.fullmatch(r"classes[^/]*\.dex", member["member"]):
                raise ValueError
        if (len({member["member"] for member in members}) != len(members)
                or sum(member["size"] for member in members) > 128 * 1024 * 1024):
            raise ValueError
        seen, previous = set(), -1
        for target in targets:
            if (not isinstance(target, dict) or set(target) != {"member", "class", "method", "prototype"}
                    or type(target["member"]) is not int or not 0 <= target["member"] < len(members)
                    or target["member"] < previous
                    or any(not isinstance(target[key], str) or not re.fullmatch(r"(?:[0-9a-f]{2}){1,255}", target[key])
                           for key in ("class", "method", "prototype"))):
                raise ValueError
            identity = tuple(target[key] for key in ("member", "class", "method", "prototype"))
            for key in ("class", "method", "prototype"):
                bytes.fromhex(target[key]).decode("utf-8")
            if identity in seen:
                raise ValueError
            seen.add(identity)
            previous = target["member"]
        return {"members": [dict(member) for member in members], "targets": [dict(target) for target in targets],
                "start": start, "max_chars": maximum}
    except (ContractError, ValueError, TypeError, KeyError):
        raise ContainedError("InvalidWorkerArguments") from None


def validate_jsparser_request(args):
    """Only prepared artifacts, a fixed dialect and the host's callee list cross this seam."""
    from reverseai.tools.jshints import CALLEES
    from reverseai.tools import js

    try:
        if not isinstance(args, Mapping) or set(args) != {"files", "kind", "start", "limit", "callees"}:
            raise ValueError
        files = args["files"]
        if not isinstance(files, list) or not 1 <= len(files) <= 64:
            raise ValueError
        checked, identities, total = [], set(), 0
        for file in files:
            if not isinstance(file, dict) or set(file) != {"artifact", "dialect"} or file["dialect"] not in ("js", "jsx", "ts", "tsx"):
                raise ValueError
            artifact = file["artifact"]
            if artifact is None:
                if len(files) != 1 or file["dialect"] != "js":
                    raise ValueError
            else:
                check_artifact(artifact)
                if artifact["size"] > 4 * 1024 * 1024 or artifact["member"] in identities:
                    raise ValueError
                name = artifact["member"].translate(js._ASCII_LOWER)
                dialect = next((suffix for suffix in ("tsx", "jsx", "ts") if name.endswith('.' + suffix)), "js")
                if not js._javascript_name(name) or js._package_name(name) or file["dialect"] != dialect:
                    raise ValueError
                identities.add(artifact["member"])
                total += artifact["size"]
                artifact = dict(artifact)
            checked.append({"artifact": artifact, "dialect": file["dialect"]})
        if total > 32 * 1024 * 1024 or args["callees"] != sorted(CALLEES):
            raise ValueError
        return {"files": checked, "kind": ArgSpec("enum", choices=("modules", "calls", "parse")).check(args["kind"]),
                "start": ArgSpec("int", 0, 1048575).check(args["start"]),
                "limit": ArgSpec("int", 1, 256).check(args["limit"]), "callees": list(args["callees"])}
    except (ContractError, ValueError, TypeError, KeyError):
        raise ContainedError("InvalidWorkerArguments") from None


def _validated_args(operation, args):
    # Validate here as well as at the gateway: this is the last boundary before argv.
    if not isinstance(args, Mapping):
        raise ContainedError("InvalidWorkerArguments")
    if operation == "ghidra.prepare":
        if args:
            raise ContainedError("InvalidWorkerArguments")
        return {}
    from reverseai.ghidra_args import OPERATIONS, check
    if operation in OPERATIONS:
        try:
            return check(operation, args)
        except ContractError:
            raise ContainedError("InvalidWorkerArguments") from None
    if operation == "jadx.method":
        return validate_jadx_request(args)
    if operation == "jsparser.syntax":
        return validate_jsparser_request(args)
    if operation == "lief.headers" and not args:
        return {}
    if operation == "lief.sections" and not set(args) - {"max_sections"}:
        count = args.get("max_sections", 32)
        if type(count) is int and 1 <= count <= 64:
            return {"max_sections": count}
    if operation == "yarax.matches" and not set(args) - {"ruleset", "max_matches"}:
        count = args.get("max_matches", 32)
        if args.get("ruleset", "m2_fixture_v1") == "m2_fixture_v1" and type(count) is int and 1 <= count <= 64:
            return {"ruleset": "m2_fixture_v1", "max_matches": count}
    if operation == "ghidra.analyze" and not set(args) - {"max_functions", "decompile", "max_chars", "max_calls",
                                                       "assembly", "max_instructions", "max_refs", "max_strings"}:
        bounds = {"max_functions": (1, 128, 64), "decompile": (0, 16, 8),
                  "max_chars": (64, 2048, 1024), "max_calls": (0, 256, 128),
                  "assembly": (0, 8, 4), "max_instructions": (1, 64, 32),
                  "max_refs": (0, 128, 64), "max_strings": (0, 64, 32)}
        checked = {key: args.get(key, default) for key, (_, _, default) in bounds.items()}
        if all(type(checked[key]) is int and low <= checked[key] <= high for key, (low, high, _) in bounds.items()):
            return checked
    specs = _GHIDRA_QUERY_ARGS.get(operation)
    if specs is not None and not set(args) - set(specs):
        try:
            return {key: spec.check(args.get(key, spec.default)) for key, spec in specs.items()}
        except ContractError:
            pass
    raise ContainedError("InvalidWorkerArguments")


def build_argv(image_id, name, staging_folder, operation, args):
    """The single contract argv builder, also used by the native verifier."""
    args = _validated_args(operation, args)
    profile = resource_profile(operation)
    folder = os.fspath(staging_folder)
    if not isinstance(image_id, str) or not _DIGEST.fullmatch(image_id):
        raise ContainedError("InvalidImageLock")
    if not re.fullmatch(r"reverseai-[a-z0-9]{1,64}", name):
        raise ContainedError("InvalidContainerName")
    if not isinstance(folder, str) or not os.path.isabs(folder) or any(c in folder for c in ",\r\n\x00"):
        raise ContainedError("InvalidStagingFolder")
    return [
        "docker", "run", "--rm", "--init", "--pull", "never", "--name", name, "--platform", PLATFORM,
        "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--user", "65534:65534", "--pids-limit", str(profile["pids"]), "--memory", profile["memory"],
        "--memory-swap", profile["memory"], "--cpus", str(profile["cpus"]), "--tmpfs", profile["tmpfs"], "--log-driver", "none",
        "--mount", f"type=bind,source={folder},target=/snapshot,readonly", image_id, operation, canonical_json(args),
    ]


def run_bounded(argv, *, timeout=WALL_SECONDS, max_output=MAX_WORKER_REPLY_BYTES, profile="default"):
    """Drain at most cap+1 bytes; communicate()/capture_output would be unbounded."""
    # Trusted controllers select a fixed profile; calls may only tighten its limits.
    if profile not in ("default", "ghidra", "jadx", "jsparser"):
        raise ContainedError("InvalidWorkerArguments")
    timeout = min(timeout, {"default": WALL_SECONDS, "ghidra": GHIDRA_WALL_SECONDS, "jadx": JADX_WALL_SECONDS,
                            "jsparser": JSPARSER_WALL_SECONDS}[profile])
    max_output = min(max_output, MAX_WORKER_REPLY_BYTES)
    process = None
    try:
        deadline = time.monotonic() + timeout
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, shell=False)
        output = bytearray()
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise ContainedTimeout("WorkerTimeout")
                chunk = os.read(process.stdout.fileno(), min(65_536, max_output + 1 - len(output)))
                if not chunk:
                    selector.unregister(process.stdout)
                    break
                output.extend(chunk)
                if len(output) > max_output:
                    raise ContainedError("WorkerOutputLimit")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ContainedTimeout("WorkerTimeout")
        if process.wait(timeout=remaining) != 0:
            raise ContainedError("WorkerProcessError")
        return bytes(output)
    except ContainedError:
        raise
    except subprocess.TimeoutExpired:
        raise ContainedTimeout("WorkerTimeout") from None
    except OSError:
        raise ContainedError("WorkerProcessError") from None
    finally:
        if process is not None:
            if process.poll() is None:
                process.kill()
                process.wait()
            process.stdout.close()


class _PrepareSink:
    def __init__(self, sink):
        self.sink, self.count = sink, 0

    def write(self, chunk):
        if not isinstance(chunk, bytes) or self.count + len(chunk) > GHIDRA_PREPARE_MAX_BYTES:
            raise ContainedError("WorkerOutputLimit")
        if self.sink.write(chunk) != len(chunk):
            raise ContainedError("WorkerProcessError")
        self.count += len(chunk)
        return len(chunk)


def run_prepare_bounded(argv, sink, *, timeout=GHIDRA_PREPARE_WALL_SECONDS):
    """Only prepare streams opaque stdout; ordinary JSON runners retain their cap."""
    process = None
    try:
        deadline = time.monotonic() + min(timeout, GHIDRA_PREPARE_WALL_SECONDS)
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, shell=False)
        bounded = _PrepareSink(sink)
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise ContainedTimeout("WorkerTimeout")
                chunk = os.read(process.stdout.fileno(), min(65536, GHIDRA_PREPARE_MAX_BYTES + 1 - bounded.count))
                if not chunk:
                    selector.unregister(process.stdout)
                    break
                bounded.write(chunk)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ContainedTimeout("WorkerTimeout")
        if process.wait(timeout=remaining) != 0:
            raise ContainedError("WorkerProcessError")
        if not bounded.count:
            raise ContainedError("WorkerProcessError")
    except ContainedError:
        raise
    except (subprocess.TimeoutExpired, TimeoutError):
        raise ContainedTimeout("WorkerTimeout") from None
    except OSError:
        raise ContainedError("WorkerProcessError") from None
    finally:
        if process is not None:
            if process.poll() is None:
                process.kill()
                process.wait()
            process.stdout.close()


def inspect_image(image_id):
    raw = run_bounded(["docker", "image", "inspect", "--format", "{{.Id}}", image_id], timeout=5, max_output=128)
    try:
        return raw.decode("ascii").strip()
    except UnicodeError:
        raise ContainedError("ImageUnavailable") from None


class DockerExecutor:
    """runner(argv, *, timeout, max_output) -> bytes; inspect(image_id) -> local ID.

    Injections allow unit tests without Docker or the shared staging directory.
    The lock is frozen at construction so the reported identity matches every run.
    """

    def __init__(self, lock, runner=None, *, prepare_runner=None, adapter_version="1.0.0-r2", extra_keys=(),
                 inspect=inspect_image, staging_root=STAGING_ROOT):
        self.lock = MappingProxyType(load_lock(lock, adapter_version=adapter_version, extra_keys=extra_keys))
        profile = {GHIDRA_VERSION: "ghidra", JADX_VERSION: "jadx", JSPARSER_VERSION: "jsparser"}.get(adapter_version, "default")
        self.runner = runner if runner is not None else (run_bounded if profile == "default" else
                                                        partial(run_bounded, profile=profile))
        self.inspect = inspect
        self.staging_root = Path(staging_root)
        self.prepare_runner = run_prepare_bounded if prepare_runner is None else prepare_runner

    def available(self):
        try:
            return self.inspect(self.lock["image_id"]) == self.lock["image_id"]
        except Exception:
            return False

    def prepare(self, data, input_sha256, sink):
        self._execute("ghidra.prepare", {}, data, input_sha256, sink=_PrepareSink(sink))

    def run(self, operation, args, data, input_sha256, *, project=None):
        if operation == "ghidra.prepare":
            raise ContainedError("InvalidWorkerArguments")
        return self._execute(operation, args, data, input_sha256, project=project)

    def _execute(self, operation, args, data, input_sha256, *, project=None, sink=None):
        args = _validated_args(operation, args)
        if ((operation in GHIDRA_OPERATIONS) != (self.lock["adapter_version"] == GHIDRA_VERSION)
                or (operation == "jadx.method") != (self.lock["adapter_version"] == JADX_VERSION)
                or (operation == "jsparser.syntax") != (self.lock["adapter_version"] == JSPARSER_VERSION)):
            raise ContainedError("InvalidWorkerArguments")
        if not isinstance(data, bytes) or sha256_hex(data) != input_sha256:
            raise ContainedError("SnapshotMismatch")
        if project is not None:
            if operation not in GHIDRA_OPERATIONS or operation == "ghidra.prepare":
                raise ContainedError("InvalidWorkerArguments")
            manifest = project.manifest
            if (manifest["input_sha256"] != input_sha256 or manifest["image_id"] != self.lock["image_id"]
                    or manifest["bundle_sha256"] != self.lock["bundle_sha256"]):
                raise ContainedError("SnapshotMismatch")
        if (operation == "jsparser.syntax" and args["files"][0]["artifact"] is None
                and not 0 < len(data) <= 4 * 1024 * 1024):
            raise ContainedError("InvalidWorkerArguments")
        if not self.available():
            raise ContainedError("ImageUnavailable")
        folder, started, succeeded = None, False, False
        name = "reverseai-" + uuid.uuid4().hex
        try:
            # Caller-owned private root (0700); same-user lstat/mkdtemp swaps are out of scope.
            root = self.staging_root.lstat()
            if not stat.S_ISDIR(root.st_mode) or root.st_uid != os.geteuid() or root.st_mode & 0o077:
                raise ContainedError("UnsafeStagingFolder")
            folder = Path(tempfile.mkdtemp(prefix="reverseai-", dir=self.staging_root))
            os.chmod(folder, 0o700)
            with (folder / "input").open("xb") as stream:
                stream.write(data)
                os.fchmod(stream.fileno(), 0o444)
            if project is not None:
                project.stage(folder)
            os.chmod(folder, 0o555)
            argv = build_argv(self.lock["image_id"], name, folder, operation, args)
            started = True
            if sink is not None:
                self.prepare_runner(argv, sink, timeout=GHIDRA_PREPARE_WALL_SECONDS)
                if not sink.count:
                    raise ContainedError("WorkerProcessError")
                raw = None
            else:
                raw = self.runner(argv, timeout=resource_profile(operation)["wall_seconds"], max_output=MAX_WORKER_REPLY_BYTES)
                if not isinstance(raw, bytes) or len(raw) > MAX_WORKER_REPLY_BYTES:
                    raise ContainedError("WorkerOutputLimit")
            started = False  # --rm has removed the successfully completed container.
            succeeded = True
            return raw
        except (ContainedError, CacheError, KeyboardInterrupt, SystemExit):
            raise
        except (TimeoutError, subprocess.TimeoutExpired):
            raise ContainedTimeout("WorkerTimeout") from None
        except Exception:
            raise ContainedError("WorkerProcessError") from None
        finally:
            failure = None if succeeded else sys.exception()
            if started:
                try:
                    self.runner(["docker", "kill", name], timeout=5, max_output=256)
                except Exception:
                    pass  # Preserve the original failure; Docker may already have removed it.
            if folder is not None:
                try:
                    os.chmod(folder, 0o700)
                    shutil.rmtree(folder)
                except OSError:
                    if failure is None:
                        raise ContainedError("StagingCleanupError") from None
                    failure.add_note("StagingCleanupError")
