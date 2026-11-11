"""Private opaque Ghidra projects: storage integrity, never host deserialization."""

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
from types import MappingProxyType
import uuid

try:
    import fcntl
except ImportError:
    fcntl = None

from reverseai.contract import canonical_json

MAX_ENTRIES = 32
MAX_BYTES = 2 * 1024**3
MAX_ARTIFACT_BYTES = 64 * 1024**2
MANIFEST_BYTES = 8192
INDEX_BYTES = 32768
LOCK_SECONDS = 30
CONTROLLER_SECONDS = 1020
MISSING = "Prepared Ghidra analysis is missing or invalid; run reverseai prepare FILE --with-ghidra."
UNSAFE = "Private Ghidra cache is unsafe or unavailable."
BUSY = "Ghidra cache busy; retry prepare."
ERRORS = (MISSING, UNSAFE, BUSY)
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_IMAGE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_TEMP = re.compile(r"\.tmp-[0-9a-f]{32}\Z")


class CacheError(ValueError):
    pass


def identity(input_sha256, lock):
    value = {"input_sha256": input_sha256, "image_id": lock["image_id"],
             "bundle_sha256": lock["bundle_sha256"], "cache_format": lock["cache_format"]}
    if (not isinstance(input_sha256, str) or not _HASH.fullmatch(input_sha256)
            or not isinstance(value["image_id"], str) or not _IMAGE.fullmatch(value["image_id"])
            or not isinstance(value["bundle_sha256"], str) or not _HASH.fullmatch(value["bundle_sha256"])
            or type(value["cache_format"]) is not int or value["cache_format"] != 1):
        raise CacheError(UNSAFE)
    return value


def cache_key(value):
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def analysis_id(key, artifact_sha256):
    return hashlib.sha256(canonical_json({"key": key, "artifact_sha256": artifact_sha256}).encode()).hexdigest()


def default_root():
    home = Path.home().resolve()
    if os.name == "nt":
        return home / ".cache/reverseai/ghidra/v1"
    if sys.platform == "darwin":
        return home / "Library/Caches/ReverseAI/ghidra/v1"
    base = Path(os.environ.get("XDG_CACHE_HOME", ""))
    if not base.is_absolute() or not _safe_base(base):
        base = home / ".cache"
    return base / "reverseai/ghidra/v1"


def _safe_base(path):
    """An environment override is usable only through an owned, unlinked path."""
    try:
        if any(part in (".", "..") for part in path.parts):
            return False
        for ancestor in reversed((path, *path.parents)):
            value = ancestor.lstat()
            if (not stat.S_ISDIR(value.st_mode) or value.st_uid not in (0, os.geteuid())
                    or value.st_mode & 0o022 and not (value.st_uid == 0 and value.st_mode & stat.S_ISVTX)):
                return False
        return path.stat().st_uid == os.geteuid()
    except OSError:
        return False


def _pairs(pairs):
    if len({k for k, _ in pairs}) != len(pairs):
        raise CacheError(UNSAFE)
    return dict(pairs)


def _load(raw):
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(CacheError(UNSAFE)))
    except (UnicodeError, ValueError, RecursionError):
        raise CacheError(UNSAFE) from None


def _regular(fd):
    value = os.fstat(fd)
    _safe_file(value)
    return value


def _safe_file(value):
    if (not stat.S_ISREG(value.st_mode) or value.st_uid != os.geteuid()
            or stat.S_IMODE(value.st_mode) != 0o600 or value.st_nlink != 1):
        raise CacheError(UNSAFE)


def _open_file(directory, name, *, create=False):
    flags = os.O_RDWR if create else os.O_RDONLY
    flags |= os.O_NOFOLLOW | os.O_NONBLOCK
    if create:
        try:
            fd = os.open(name, flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=directory)
        except FileExistsError:
            fd = os.open(name, flags, dir_fd=directory)
    else:
        fd = os.open(name, flags, dir_fd=directory)
    try:
        _regular(fd)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read_json(directory, name, maximum):
    fd = _open_file(directory, name)
    try:
        if _regular(fd).st_size > maximum:
            raise CacheError(UNSAFE)
        raw = bytearray()
        while len(raw) <= maximum:
            block = os.read(fd, min(65536, maximum + 1 - len(raw)))
            if not block:
                return _load(bytes(raw))
            raw.extend(block)
        raise CacheError(UNSAFE)
    finally:
        os.close(fd)


def _write_all(fd, raw):
    pending = memoryview(raw)
    while pending:
        written = os.write(fd, pending)
        if written <= 0:
            raise CacheError(UNSAFE)
        pending = pending[written:]


def _atomic_json(directory, name, value):
    temporary = ".tmp-" + uuid.uuid4().hex
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
    try:
        _write_all(fd, canonical_json(value).encode("utf-8"))
        os.fsync(fd)
        os.close(fd)
        fd = None
        os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
    finally:
        if fd is not None:
            os.close(fd)
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass


@contextmanager
def _locked(directory, name, timeout=LOCK_SECONDS):
    try:
        fd = _open_file(directory, name, create=True)
    except OSError:
        raise CacheError(UNSAFE) from None
    try:
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise CacheError(BUSY) from None
                time.sleep(min(0.05, max(0, deadline - time.monotonic())))
        yield
    finally:
        os.close(fd)


class CacheHandle:
    """A held file and index lease; staging releases the lease before Docker starts."""

    def __init__(self, fd, manifest, key, lease):
        self.fd, self.manifest, self.key, self._lease = fd, MappingProxyType(manifest), key, lease
        self.analysis_id = analysis_id(key, manifest["artifact_sha256"])

    def _release(self):
        if self._lease is not None:
            lease, self._lease = self._lease, None
            lease.__exit__(None, None, None)

    def stage(self, directory):
        """Write only fixed names inside an executor-owned snapshot directory."""
        target = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            fd = os.open("project.tar", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444, dir_fd=target)
            try:
                os.fchmod(fd, 0o444)
                os.lseek(self.fd, 0, os.SEEK_SET)
                digest, size = hashlib.sha256(), 0
                while True:
                    block = os.read(self.fd, min(65536, self.manifest["size"] + 1 - size))
                    if not block:
                        break
                    size += len(block)
                    if size > self.manifest["size"]:
                        raise CacheError(MISSING)
                    digest.update(block)
                    _write_all(fd, block)
                if size != self.manifest["size"] or digest.hexdigest() != self.manifest["artifact_sha256"]:
                    raise CacheError(MISSING)
            finally:
                os.close(fd)
            fd = os.open("cache.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444, dir_fd=target)
            try:
                os.fchmod(fd, 0o444)
                _write_all(fd, canonical_json(dict(self.manifest)).encode("utf-8"))
            finally:
                os.close(fd)
        finally:
            os.close(target)
            self.close()

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        self._release()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class _Sink:
    def __init__(self, fd, deadline):
        self.fd, self.deadline, self.size, self.digest = fd, deadline, 0, hashlib.sha256()

    def write(self, block):
        if not isinstance(block, bytes) or self.size + len(block) > MAX_ARTIFACT_BYTES:
            raise CacheError(UNSAFE)
        if time.monotonic() >= self.deadline:
            raise TimeoutError("Ghidra preparation exceeded its limits")
        _write_all(self.fd, block)
        self.size += len(block)
        self.digest.update(block)
        return len(block)


class CacheStore:
    """The root injection is for trusted controllers/tests, never a query argument."""

    def __init__(self, root=None):
        self.root = Path(root) if root is not None else default_root()

    @contextmanager
    def _directory(self, create=False):
        if fcntl is None or os.name == "nt" or not self.root.is_absolute():
            raise CacheError(UNSAFE)
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        yielded = False
        try:
            parts = self.root.parts[1:]
            if not parts or any(part in (".", "..") for part in parts):
                raise CacheError(UNSAFE)
            for index, part in enumerate(parts):
                created = False
                try:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                except FileNotFoundError:
                    if not create:
                        raise
                    try:
                        os.mkdir(part, 0o700, dir_fd=fd)
                        created = True
                    except FileExistsError:
                        pass
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                value = os.fstat(child)
                private = created or index == len(parts) - 1 or (len(parts) >= 3 and index >= len(parts) - 3
                           and parts[-1] == "v1")
                valid = (stat.S_ISDIR(value.st_mode) and value.st_uid in (0, os.geteuid())
                         and (not value.st_mode & 0o022 or value.st_uid == 0 and value.st_mode & stat.S_ISVTX))
                if private:
                    valid = valid and value.st_uid == os.geteuid() and stat.S_IMODE(value.st_mode) == 0o700
                if not valid:
                    os.close(child)
                    raise CacheError(UNSAFE)
                os.close(fd)
                fd = child
            yielded = True
            yield fd
        except FileNotFoundError:
            raise
        except OSError:
            if yielded:
                raise
            raise CacheError(UNSAFE) from None
        finally:
            os.close(fd)

    def _index(self, directory):
        try:
            value = _read_json(directory, "index.json", INDEX_BYTES)
        except FileNotFoundError:
            return {"sequence": 0, "entries": {}}
        if (not isinstance(value, dict) or set(value) != {"sequence", "entries"}
                or type(value["sequence"]) is not int or not 0 <= value["sequence"] < 2**63
                or not isinstance(value["entries"], dict) or len(value["entries"]) > MAX_ENTRIES):
            raise CacheError(UNSAFE)
        for key, sequence in value["entries"].items():
            if not _HASH.fullmatch(key) or type(sequence) is not int or not 0 <= sequence <= value["sequence"]:
                raise CacheError(UNSAFE)
        return value

    def _manifest(self, directory, key, expected=None):
        value = _read_json(directory, key + ".json", MANIFEST_BYTES)
        if (not isinstance(value, dict) or set(value) != {"format", "input_sha256", "image_id", "bundle_sha256", "size", "artifact_sha256"}
                or type(value["format"]) is not int or value["format"] != 1
                or type(value["size"]) is not int or not 1 <= value["size"] <= MAX_ARTIFACT_BYTES
                or not isinstance(value["artifact_sha256"], str) or not _HASH.fullmatch(value["artifact_sha256"])):
            raise CacheError(UNSAFE)
        own = identity(value["input_sha256"], {**value, "cache_format": value["format"]})
        if cache_key(own) != key or expected is not None and own != expected:
            raise CacheError(UNSAFE)
        return value

    def _inventory(self, directory):
        total, names = 0, []
        with os.scandir(directory) as entries:
            for entry in entries:
                if len(names) >= 2 * MAX_ENTRIES + 16:
                    raise CacheError(UNSAFE)
                name = entry.name
                if not (name in ("prepare.lock", "index.lock", "index.json") or _TEMP.fullmatch(name)
                        or re.fullmatch(r"[0-9a-f]{64}\.(?:tar|json)", name)):
                    raise CacheError(UNSAFE)
                value = os.stat(name, dir_fd=directory, follow_symlinks=False)
                _safe_file(value)
                total += value.st_size
                names.append(name)
        return total, names

    def lookup(self, expected):
        key, lease = cache_key(expected), None
        try:
            with self._directory() as directory:
                lease = _locked(directory, "index.lock")
                lease.__enter__()
                index = self._index(directory)
                if key not in index["entries"]:
                    return None
                manifest = self._manifest(directory, key, expected)
                fd = _open_file(directory, key + ".tar")
                try:
                    if _regular(fd).st_size != manifest["size"]:
                        raise CacheError(MISSING)
                    digest, count = hashlib.sha256(), 0
                    while True:
                        block = os.read(fd, min(65536, manifest["size"] + 1 - count))
                        if not block:
                            break
                        count += len(block)
                        digest.update(block)
                    if count != manifest["size"] or digest.hexdigest() != manifest["artifact_sha256"]:
                        raise CacheError(MISSING)
                    index["sequence"] += 1
                    index["entries"][key] = index["sequence"]
                    _atomic_json(directory, "index.json", index)
                    os.fsync(directory)
                    handle = CacheHandle(fd, manifest, key, lease)
                    lease = None
                    return handle
                except BaseException:
                    os.close(fd)
                    raise
        except FileNotFoundError:
            return None
        except OSError:
            raise CacheError(UNSAFE) from None
        finally:
            if lease is not None:
                lease.__exit__(None, None, None)

    def prepare(self, expected, producer):
        started = time.monotonic()
        key = cache_key(expected)
        try:
            found = self.lookup(expected)
        except CacheError as error:
            if str(error) != MISSING:
                raise
            found = None
        if found is not None:
            with found:
                if time.monotonic() >= started + CONTROLLER_SECONDS:
                    raise TimeoutError("Ghidra preparation exceeded its limits")
                return dict(found.manifest), found.analysis_id, "reused", time.monotonic() - started
        with self._directory(create=True) as directory, _locked(directory, "prepare.lock"):
            corrupt = False
            try:
                found = self.lookup(expected)
            except CacheError as error:
                if str(error) != MISSING:
                    raise
                found = None
                corrupt = True
            if found is not None:
                with found:
                    if time.monotonic() >= started + CONTROLLER_SECONDS:
                        raise TimeoutError("Ghidra preparation exceeded its limits")
                    return dict(found.manifest), found.analysis_id, "reused", time.monotonic() - started
            with _locked(directory, "index.lock"):
                index = self._index(directory)
                _, names = self._inventory(directory)
                if corrupt:
                    index["entries"].pop(key, None)
                for existing in tuple(index["entries"]):
                    if existing + ".tar" not in names or existing + ".json" not in names:
                        del index["entries"][existing]
                for name in names:
                    if _TEMP.fullmatch(name) or (re.fullmatch(r"[0-9a-f]{64}\.(?:tar|json)", name)
                            and name[:64] not in index["entries"]):
                        os.unlink(name, dir_fd=directory)
                while True:
                    used, _ = self._inventory(directory)
                    if len(index["entries"]) < MAX_ENTRIES and used + MAX_ARTIFACT_BYTES + INDEX_BYTES + MANIFEST_BYTES <= MAX_BYTES:
                        break
                    if not index["entries"]:
                        raise CacheError(UNSAFE)
                    victim = min(index["entries"], key=lambda k: (index["entries"][k], k))
                    for suffix in (".tar", ".json"):
                        try:
                            os.unlink(victim + suffix, dir_fd=directory)
                        except FileNotFoundError:
                            pass
                    del index["entries"][victim]
                _atomic_json(directory, "index.json", index)
            temporary = ".tmp-" + uuid.uuid4().hex
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            published = False
            try:
                sink = _Sink(fd, started + CONTROLLER_SECONDS)
                producer(sink)
                if time.monotonic() >= sink.deadline:
                    raise TimeoutError("Ghidra preparation exceeded its limits")
                if not sink.size:
                    raise CacheError(UNSAFE)
                os.fsync(fd)
                manifest = {"format": 1, "input_sha256": expected["input_sha256"], "image_id": expected["image_id"],
                            "bundle_sha256": expected["bundle_sha256"], "size": sink.size,
                            "artifact_sha256": sink.digest.hexdigest()}
                with _locked(directory, "index.lock"):
                    index = self._index(directory)
                    try:
                        if time.monotonic() >= sink.deadline:
                            raise TimeoutError("Ghidra preparation exceeded its limits")
                        os.replace(temporary, key + ".tar", src_dir_fd=directory, dst_dir_fd=directory)
                        published = True
                        _atomic_json(directory, key + ".json", manifest)
                        index["sequence"] += 1
                        index["entries"][key] = index["sequence"]
                        _atomic_json(directory, "index.json", index)
                        os.fsync(directory)
                        if time.monotonic() >= sink.deadline:
                            raise TimeoutError("Ghidra preparation exceeded its limits")
                        return manifest, analysis_id(key, manifest["artifact_sha256"]), "created", time.monotonic() - started
                    except BaseException:
                        if published:
                            for suffix in (".tar", ".json"):
                                try:
                                    os.unlink(key + suffix, dir_fd=directory)
                                except FileNotFoundError:
                                    pass
                            index["entries"].pop(key, None)
                            _atomic_json(directory, "index.json", index)
                            os.fsync(directory)
                        raise
            finally:
                os.close(fd)
                try:
                    os.unlink(temporary, dir_fd=directory)
                except FileNotFoundError:
                    pass

    def facts(self):
        result = {"state": "unsupported" if fcntl is None or os.name == "nt" else "absent", "entries": None, "bytes": None,
                  "max_entries": MAX_ENTRIES, "max_bytes": MAX_BYTES, "artifact_max_bytes": MAX_ARTIFACT_BYTES}
        if result["state"] == "unsupported":
            return result
        opened = False
        try:
            with self._directory() as directory:
                opened = True
                index = self._index(directory)
                total, _ = self._inventory(directory)
                for key in index["entries"]:
                    self._manifest(directory, key)
                if total > MAX_BYTES:
                    raise CacheError(UNSAFE)
                result.update(state="ready", entries=len(index["entries"]), bytes=total)
        except FileNotFoundError:
            if opened:
                result["state"] = "unsafe"
        except (CacheError, OSError, KeyError, TypeError, ValueError):
            result["state"] = "unsafe"
        return result
