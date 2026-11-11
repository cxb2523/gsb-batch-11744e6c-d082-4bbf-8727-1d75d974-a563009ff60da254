"""Freeze the bytes of one approved regular file.

Copyright (c) 2026 Stefano D'Agostino. MIT License; see LICENSE.

Only the final path component is checked: the operator approves the path, and
parent directories may legitimately be links (for example /tmp on macOS).
Error messages never contain the path or input bytes.
"""

from __future__ import annotations

import os
from pathlib import Path
import stat

from reverseai.contract import ContractError, InputRef, sha256_hex

MAX_INPUT_BYTES = 64 * 1024 * 1024
_REPARSE_POINT = 0x400  # FILE_ATTRIBUTE_REPARSE_POINT on Windows


class IntakeError(ContractError):
    """The approved file cannot be frozen safely."""


def _require(condition, message):
    if not condition:
        raise IntakeError(message)


def display_name(path: Path) -> str:
    """The file name for reports, unambiguous and at most 255 characters.

    Host names are bytes: non-UTF-8 bytes, the backslash itself and the ellipsis
    character become \\xNN escapes (the ellipsis as its three UTF-8 bytes), so the
    text "\\xff" and the byte 0xFF never look alike, and a final ellipsis always
    means truncation. Truncation keeps whole escapes.
    """
    units = []
    for character in os.fsencode(path.name).decode("utf-8", "surrogateescape"):
        if character == "\\":
            units.append("\\x5c")
        elif character == "\u2026":  # reserved for truncation
            units.extend("\\x{:02x}".format(byte) for byte in character.encode())
        elif "\udc80" <= character <= "\udcff":
            units.append("\\x{:02x}".format(ord(character) - 0xDC00))
        else:
            units.append(character)
    if sum(map(len, units)) <= 255:
        return "".join(units)
    kept, length = [], 0
    for unit in units:
        if length + len(unit) > 254:
            break
        kept.append(unit)
        length += len(unit)
    return "".join(kept) + "\u2026"


def _regular_stat(path: Path):
    try:
        value = path.lstat()
    except (OSError, ValueError):  # ValueError: a NUL byte in the path
        raise IntakeError("Input file could not be inspected") from None
    _require(not stat.S_ISLNK(value.st_mode) and not getattr(value, "st_file_attributes", 0) & _REPARSE_POINT,
             "Symlinks and reparse points cannot be input files")
    _require(stat.S_ISREG(value.st_mode), "Only a regular file can be an input")
    _require(value.st_nlink == 1, "Hard-linked input files need a separate copy")
    _require(value.st_size <= MAX_INPUT_BYTES, "Input file exceeds the byte limit")
    return value


def snapshot(path) -> tuple[bytes, InputRef]:
    """Read one approved file once and return its frozen bytes with their InputRef."""
    _require(isinstance(path, (str, os.PathLike)), "Input path must be a string or path")
    path = Path(path)
    before = _regular_stat(path)
    try:
        # O_NONBLOCK keeps a FIFO swapped in after lstat from blocking the open;
        # the identity check below then refuses it.
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
                             | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0))
    except (OSError, ValueError):
        raise IntakeError("Input file could not be opened") from None
    try:
        with os.fdopen(descriptor, "rb") as handle:
            opened = os.fstat(handle.fileno())
            _require(stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1
                     and (opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino),
                     "Input file changed identity while opening")
            data = handle.read(MAX_INPUT_BYTES + 1)
            after = os.fstat(handle.fileno())
    except OSError:
        raise IntakeError("Input file could not be read") from None
    # Two reads of the open handle: a path stat can report stale times and
    # sizes on Windows, and the identity check ties the handle to the path.
    _require(len(data) <= MAX_INPUT_BYTES and len(data) == opened.st_size == after.st_size
             and (opened.st_mtime_ns, opened.st_ctime_ns) == (after.st_mtime_ns, after.st_ctime_ns),
             "Input changed while reading")
    return data, InputRef(sha256=sha256_hex(data), size=len(data), name=display_name(path))
