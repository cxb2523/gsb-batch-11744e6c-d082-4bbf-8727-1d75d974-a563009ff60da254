"""Opaque Ghidra project packaging and bounded restore, used only inside the worker."""

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import tarfile

MAX_TAR_BYTES = 64 * 1024 * 1024
MAX_FILES = 4096
MAX_UNPACKED_BYTES = 128 * 1024 * 1024
MAX_ROW_BYTES = 4096
MAX_METADATA_BYTES = 4096
FORMAT = 1
TABLES = ("functions", "calls", "references", "strings")
TABLE_FILES = frozenset({"cache/tables/meta.json", *(f"cache/tables/{name}.{suffix}"
                         for name in TABLES for suffix in ("jsonl", "idx"))})
_COMPONENT = re.compile(r"[A-Za-z0-9_.~+-]{1,64}\Z")
_HEX = re.compile(r"[0-9a-f]{64}\Z")


class InvalidCachedProject(ValueError):
    pass


class ProjectTooLarge(InvalidCachedProject):
    pass


def _need(condition):
    if not condition:
        raise InvalidCachedProject("InvalidCachedProject")


def _name(raw, directory):
    _need(isinstance(raw, str) and raw.isascii() and len(raw) <= 240)
    name = raw[:-1] if directory and raw.endswith("/") else raw
    parts = name.split("/")
    _need(len(parts) <= 16 and all(part not in (".", "..") and _COMPONENT.fullmatch(part) for part in parts))
    allowed = (name in ("cache", "cache/project", "cache/tables") and directory
               or name == "cache/project/reverseai.rep" and directory
               or name.startswith("cache/project/reverseai.rep/")
               or name == "cache/project/reverseai.gpr" and not directory
               or name in TABLE_FILES and not directory)
    _need(allowed)
    return name


def _field(raw):
    head, _, tail = raw.partition(b"\0")
    _need(not tail.strip(b"\0"))
    try:
        return head.decode("ascii")
    except UnicodeError:
        raise InvalidCachedProject("InvalidCachedProject") from None


def _octal(raw, optional=False):
    value = raw.strip(b"\0 ")
    if not value and optional:
        return 0
    _need(bool(value) and all(48 <= char <= 55 for char in value))
    return int(value, 8)


def _read_exact(source, size):
    data = source.read(size)
    _need(len(data) == size)
    return data


def inventory(source):
    """Validate every header and span before writing any archive member."""
    source.seek(0, os.SEEK_END)
    length = source.tell()
    if length > MAX_TAR_BYTES:
        raise ProjectTooLarge("ProjectTooLarge")
    _need(length >= 1024 and length % 512 == 0)
    source.seek(0)
    rows, names, folded, total = [], {}, {}, 0
    while source.tell() < length:
        header = _read_exact(source, 512)
        if header == b"\0" * 512:
            _need(_read_exact(source, 512) == b"\0" * 512)
            while block := source.read(65536):
                _need(not block.strip(b"\0"))
            required = {"cache/project/reverseai.gpr", "cache/project/reverseai.rep", *TABLE_FILES}
            _need(required <= names.keys())
            return rows
        if len(rows) >= MAX_FILES:
            raise ProjectTooLarge("ProjectTooLarge")
        _need(header[257:263] == b"ustar\0" and header[263:265] == b"00")
        expected = _octal(header[148:156])
        _need(sum(header[:148]) + 8 * 32 + sum(header[156:]) == expected)
        kind = header[156:157]
        _need(kind in (b"0", b"\0", b"5") and not header[157:257].strip(b"\0"))
        directory = kind == b"5"
        prefix, leaf = _field(header[345:500]), _field(header[:100])
        name = _name((prefix + "/" if prefix else "") + leaf, directory)
        size = _octal(header[124:136])
        mode = _octal(header[100:108])
        for field in (header[108:116], header[116:124], header[136:148], header[329:337], header[337:345]):
            _octal(field, optional=True)
        _need(not mode & 0o7000 and (not directory or size == 0))
        _need(name not in names)
        components = name.split("/")
        for end in range(1, len(components) + 1):
            component_path = "/".join(components[:end])
            _need(folded.get(component_path.casefold(), component_path) == component_path)
            folded[component_path.casefold()] = component_path
        for parent in Path(name).parents:
            _need(str(parent) not in names or names[str(parent)])
        if not directory:
            _need(not any(previous.startswith(name + "/") for previous in names))
        names[name] = directory
        total += size
        if total > MAX_UNPACKED_BYTES:
            raise ProjectTooLarge("ProjectTooLarge")
        offset = source.tell()
        after = offset + ((size + 511) // 512) * 512
        _need(after <= length)
        rows.append((name, offset, size, directory))
        source.seek(offset + size)
        _need(not _read_exact(source, after - offset - size).strip(b"\0"))
        source.seek(after)
    raise InvalidCachedProject("InvalidCachedProject")


def _hash(source):
    source.seek(0)
    digest = hashlib.sha256()
    while chunk := source.read(65536):
        digest.update(chunk)
    return digest.hexdigest()


def unpack_project(source, expected_sha256, fresh_root):
    _need(isinstance(expected_sha256, str) and _HEX.fullmatch(expected_sha256))
    rows = inventory(source)
    _need(_hash(source) == expected_sha256)
    root = Path(fresh_root)
    root.mkdir(mode=0o700)
    for name, offset, size, directory in rows:
        target = root / name
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if directory:
            target.mkdir(mode=0o700, exist_ok=True)
            continue
        source.seek(offset)
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as destination:
            left = size
            while left:
                chunk = _read_exact(source, min(left, 65536))
                destination.write(chunk)
                left -= len(chunk)
    return root / "cache"


class _BoundedSink:
    def __init__(self, sink):
        self.sink, self.size, self.digest = sink, 0, hashlib.sha256()

    def write(self, data):
        if self.size + len(data) > MAX_TAR_BYTES:
            raise ProjectTooLarge("ProjectTooLarge")
        left = memoryview(data)
        while left:
            written = self.sink.write(left)
            _need(type(written) is int and 0 < written <= len(left))
            self.digest.update(left[:written])
            self.size += written
            left = left[written:]
        return len(data)


def pack_project(work_root, sink):
    root, pending, rows, total = Path(work_root), [Path("cache")], [], 0
    while pending:
        relative = pending.pop()
        info = (root / relative).lstat()
        directory = stat.S_ISDIR(info.st_mode)
        _need(directory or stat.S_ISREG(info.st_mode))
        _name(relative.as_posix(), directory)
        total += 0 if directory else info.st_size
        rows.append((relative, info, directory))
        if len(rows) > MAX_FILES or total > MAX_UNPACKED_BYTES:
            raise ProjectTooLarge("ProjectTooLarge")
        if directory:
            for child in (root / relative).iterdir():
                pending.append(relative / child.name)
                if len(rows) + len(pending) > MAX_FILES:
                    raise ProjectTooLarge("ProjectTooLarge")
    _need({"cache/project/reverseai.gpr", "cache/project/reverseai.rep", *TABLE_FILES}
          <= {relative.as_posix() for relative, _, _ in rows})
    bounded = _BoundedSink(sink)
    with tarfile.open(fileobj=bounded, mode="w|", format=tarfile.USTAR_FORMAT) as archive:
        for relative, info, directory in sorted(rows):
            member = tarfile.TarInfo(relative.as_posix())
            member.type, member.mode = (tarfile.DIRTYPE, 0o700) if directory else (tarfile.REGTYPE, 0o600)
            member.size = 0 if directory else info.st_size
            if directory:
                archive.addfile(member)
            else:
                descriptor = os.open(root / relative, os.O_RDONLY | os.O_NOFOLLOW)
                with os.fdopen(descriptor, "rb") as source:
                    current = os.fstat(source.fileno())
                    _need(stat.S_ISREG(current.st_mode) and current.st_size == info.st_size
                          and current.st_ino == info.st_ino and current.st_dev == info.st_dev)
                    archive.addfile(member, source)
    return bounded.size, bounded.digest.hexdigest()


CAPS = {"functions": 65536, "calls": 262144, "references": 262144, "strings": 65536}


def _json(raw):
    def pairs(items):
        _need(len({key for key, _ in items}) == len(items))
        return dict(items)
    try:
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError):
        raise InvalidCachedProject("InvalidCachedProject") from None


def canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                          allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise InvalidCachedProject("InvalidCachedProject") from None


class TableWriter:
    """Append complete bounded rows; offsets always point to the start of one JSON line."""
    def __init__(self, folder, name, *, budget=None):
        _need(name in TABLES)
        self.name, self.count = name, 0
        self.budget = {"bytes": 0} if budget is None else budget
        self.body = open(Path(folder) / (name + ".jsonl"), "xb")
        try:
            self.index = open(Path(folder) / (name + ".idx"), "xb")
        except BaseException:
            self.body.close()
            raise

    def add(self, value):
        raw = canonical(value)
        _need(len(raw) <= MAX_ROW_BYTES and b"\n" not in raw)
        if self.count == CAPS[self.name]:
            raise ProjectTooLarge("ProjectTooLarge")
        if self.budget["bytes"] + len(raw) + 9 > MAX_UNPACKED_BYTES:
            raise ProjectTooLarge("ProjectTooLarge")
        self.index.write(struct.pack("<Q", self.body.tell()))
        self.body.write(raw + b"\n")
        self.budget["bytes"] += len(raw) + 9
        self.count += 1

    def close(self):
        try:
            self.body.close()
        finally:
            self.index.close()


class TableReader:
    """Validate both span endpoints before seeking; no JSON decoder sees an unbounded row."""
    def __init__(self, folder, name, count):
        _need(name in TABLES and type(count) is int and 0 <= count <= CAPS[name])
        self.count = count
        self.body = open(Path(folder) / (name + ".jsonl"), "rb")
        try:
            self.index = open(Path(folder) / (name + ".idx"), "rb")
            self.size = os.fstat(self.body.fileno()).st_size
            _need(os.fstat(self.index.fileno()).st_size == count * 8
                  and self.size <= count * (MAX_ROW_BYTES + 1)
                  and (count > 0 or self.size == 0))
            if count:
                _need(struct.unpack("<Q", _read_exact(self.index, 8))[0] == 0)
        except BaseException:
            self.body.close()
            if hasattr(self, "index"):
                self.index.close()
            raise

    def row(self, position):
        _need(type(position) is int and 0 <= position < self.count)
        self.index.seek(position * 8)
        offset = struct.unpack("<Q", _read_exact(self.index, 8))[0]
        after = (struct.unpack("<Q", _read_exact(self.index, 8))[0]
                 if position + 1 < self.count else self.size)
        _need(0 <= offset < after <= self.size and 1 < after - offset <= MAX_ROW_BYTES + 1)
        self.body.seek(offset)
        raw = _read_exact(self.body, after - offset)
        _need(raw.endswith(b"\n") and b"\n" not in raw[:-1])
        value = _json(raw)
        _need(canonical(value) + b"\n" == raw)
        return value

    def rows(self):
        for index in range(self.count):
            yield self.row(index)

    def close(self):
        try:
            self.body.close()
        finally:
            self.index.close()
