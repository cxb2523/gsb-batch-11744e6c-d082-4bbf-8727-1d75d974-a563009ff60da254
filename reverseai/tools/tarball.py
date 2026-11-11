"""Bounded gzip/tar bytes; archive names are never opened as host paths."""

from dataclasses import dataclass, field, replace
import struct
import zlib

from reverseai.contract import ContractError, MAX_CHILD_BYTES, sha256_hex
from reverseai.tools import apk

MAGIC = b'\x1f\x8b'
MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_TAR_BYTES = 128 * 1024 * 1024
MAX_RATIO = 100
MAX_MEMBERS = 65536
MAX_EXTENSION_BYTES = 1024 * 1024
MAX_TOTAL_EXTENSION_BYTES = 4 * 1024 * 1024
MAX_NAME_BYTES = 65535
INFLATE_CHUNK = 65536
BLOCK = 512


class TarballError(ContractError):
    """An unsupported, inconsistent or over-budget gzip/tar input."""


def _check(condition):
    if not condition:
        raise TarballError('Invalid or over-budget gzip/tar archive')


def gzip_header(data):
    """Return the raw-deflate offset after checking the RFC 1952 header."""
    _check(isinstance(data, bytes) and 18 <= len(data) <= MAX_INPUT_BYTES
           and data[:3] == MAGIC + b'\x08' and not data[3] & 0xe0)
    flags, at, end = data[3], 10, len(data) - 8
    if flags & 4:
        _check(at + 2 <= end)
        length = struct.unpack_from('<H', data, at)[0]
        at += 2
        at += length
        _check(at <= end)
    for flag in (8, 16):
        if flags & flag:
            stop = data.find(b'\0', at, end)
            _check(stop >= 0)
            at = stop + 1
    if flags & 2:
        _check(at + 2 <= end)
        _check(struct.unpack_from('<H', data, at)[0]
               == zlib.crc32(memoryview(data)[:at]) & 0xffff)
        at += 2
    _check(at < end)
    return at


class _GzipReader:
    """Forward-only inflation; a prefix does not certify the unread trailer."""

    def __init__(self, data):
        self.at = gzip_header(data)
        self.data = data
        self.limit = min(MAX_TAR_BYTES, MAX_RATIO * len(data))
        self.total = 0
        self.crc = 0
        self.pending = b''
        self.inflater = zlib.decompressobj(-15)

    @property
    def eof(self):
        return self.inflater.eof

    def read(self, length):
        _check(type(length) is int and length >= 0)
        pieces, left = [], length
        while left and not self.eof:
            block = self.pending
            if not block:
                block = self.data[self.at:self.at + INFLATE_CHUNK]
                self.at += len(block)
            _check(bool(block))
            # One excess byte detects a bomb without expanding the rest of it.
            maximum = min(left, INFLATE_CHUNK, self.limit - self.total + 1)
            try:
                output = self.inflater.decompress(block, maximum)
            except zlib.error:
                raise TarballError('Invalid or over-budget gzip/tar archive') from None
            self.pending = self.inflater.unconsumed_tail
            self.total += len(output)
            _check(self.total <= self.limit)
            self.crc = zlib.crc32(output, self.crc)
            pieces.append(output)
            left -= len(output)
            if self.eof:
                trailer = self.at - len(self.inflater.unused_data)
                _check(len(self.data) - trailer == 8)
                crc, size = struct.unpack_from('<II', self.data, trailer)
                _check(crc == self.crc and size == self.total)
            else:
                _check(output or len(self.pending) < len(block))
        return b''.join(pieces)


def read_prefix(data, length):
    """Derive exactly this prefix, without asserting validity of unread bytes."""
    reader = _GzipReader(data)
    _check(type(length) is int and 0 <= length <= reader.limit)
    result = reader.read(length)
    _check(len(result) == length)
    return result


def _inflate(data):
    reader, chunks = _GzipReader(data), []
    while not reader.eof:
        chunks.append(reader.read(INFLATE_CHUNK))
    return b''.join(chunks)


def _number(field):
    """Nonnegative octal or GNU base-256 integer, without decimal coercion."""
    if field[0] & 0x80:
        _check(not field[0] & 0x40)
        return int.from_bytes(bytes((field[0] & 0x7f,)) + field[1:], 'big')
    digits = field.strip(b'\0 ')
    _check(all(48 <= byte <= 55 for byte in digits))
    return int(digits, 8) if digits else 0


def _header(block):
    _check(len(block) == BLOCK)
    expected = _number(block[148:156])
    rest = block[:148] + block[156:]
    unsigned = 8 * 32 + sum(rest)
    signed = 8 * 32 + sum(byte if byte < 128 else byte - 256 for byte in rest)
    _check(expected in (unsigned, signed))
    _check(block[257:265] in (b'ustar\00000', b'ustar  \0'))
    name = block[:100].split(b'\0', 1)[0]
    if block[257:265] == b'ustar\00000':
        prefix = block[345:500].split(b'\0', 1)[0]
        if prefix:
            name = prefix + b'/' + name
    return name, block[156:157], _number(block[124:136])


def _pax(body):
    """Decode record framing before interpreting any extended attribute."""
    result, at = {}, 0
    while at < len(body):
        space = body.find(b' ', at)
        _check(space > at)
        digits = body[at:space]
        _check(all(48 <= byte <= 57 for byte in digits))
        significant = digits.lstrip(b'0') or b'0'
        _check(len(significant) <= 9)
        length = int(significant)
        stop = at + length
        _check(length >= 5 and space < stop - 1 <= len(body) - 1
               and body[stop - 1] == 10)
        key, equals, value = body[space + 1:stop - 1].partition(b'=')
        _check(bool(key) and equals == b'=' and b'\0' not in key)
        _check(key not in result)
        result[key] = value
        at = stop
    return result


@dataclass(frozen=True)
class TarMember:
    name: str
    type: str
    size: int
    data_offset: int
    header_offset: int
    flags: tuple = ()
    _source: bytes = field(default=b'', repr=False, compare=False)
    _stream: bytes = field(default=b'', repr=False, compare=False)

    @property
    def central_offset(self):
        return self.header_offset

    @property
    def central_length(self):
        return BLOCK


def _name(raw):
    _check(len(raw) <= MAX_NAME_BYTES)
    try:
        return raw.decode('utf-8'), False
    except UnicodeError:
        return raw.decode('utf-8', 'backslashreplace'), True


def _extensions(kind, body):
    if kind in (b'L', b'K'):
        name, nul, rest = body.partition(b'\0')
        _check(nul == b'\0' and not any(rest))
        _name(name)  # Apply the same byte bound to GNU and pax names.
        return {b'path' if kind == b'L' else b'linkpath': name}
    values = _pax(body)
    _check(kind != b'g' or set(values) <= {b'comment'})
    _check(not any(key.startswith(b'GNU.sparse.') for key in values))
    _check(values.get(b'hdrcharset', b'UTF-8') == b'UTF-8')
    result = {}
    for key in (b'path', b'linkpath', b'size'):
        if key not in values:
            continue
        value = values[key]
        if key == b'size':
            _check(bool(value) and all(48 <= byte <= 57 for byte in value))
            significant = value.lstrip(b'0') or b'0'
            _check(len(significant) <= 9)
            result[key] = int(significant)
        else:
            _name(value)
            result[key] = value
    return result


def members(data):
    """Validate the whole gzip/tar, then disclose logical members in archive order."""
    stream = _inflate(data)
    rows, at, count, extension_bytes, pending = [], 0, 0, 0, {}
    extended = False
    while True:
        _check(at + BLOCK <= len(stream))
        block = stream[at:at + BLOCK]
        if not any(block):
            _check(not extended and at + 2 * BLOCK <= len(stream)
                   and stream.count(b'\0', at + BLOCK) == len(stream) - at - BLOCK)
            break
        count += 1
        _check(count <= MAX_MEMBERS)
        raw_name, kind, size = _header(block)
        _check(kind not in (b'S', b'M', b'V'))
        header_offset, data_offset = at, at + BLOCK
        if kind in (b'x', b'g', b'L', b'K'):
            extension_bytes += size
            _check(size <= MAX_EXTENSION_BYTES and extension_bytes <= MAX_TOTAL_EXTENSION_BYTES)
            stop = data_offset + size
            _check(stop <= len(stream))
            pending.update(_extensions(kind, stream[data_offset:stop]))
            extended = True
        else:
            size = pending.get(b'size', size)
            raw_name = pending.get(b'path', raw_name)
            raw_link = pending.get(b'linkpath', block[157:257].split(b'\0', 1)[0])
            name, invalid_name = _name(raw_name)
            _, invalid_link = _name(raw_link)
            pending, extended = {}, False
            if kind in (b'1', b'2', b'3', b'4', b'5', b'6'):
                _check(size == 0)
            if kind != b'5':
                flags = set()
                if invalid_name or (invalid_link and kind in (b'1', b'2')):
                    flags.add('header_mismatch')
                if apk._traversing(name):
                    flags.add('traversing_name')
                if apk._member_name(name)[1]:
                    flags.add('long_name')
                if size > MAX_CHILD_BYTES:
                    flags.add('too_large')
                if kind in (b'1', b'2'):
                    flags.add('hardlink' if kind == b'1' else 'symlink')
                elif kind not in (b'0', b'\0', b'7'):
                    flags.add('unsupported_type')
                rows.append(TarMember(name, kind.decode('latin-1'), size, data_offset,
                                      header_offset, tuple(sorted(flags)), data, stream))
        at = data_offset + ((size + BLOCK - 1) // BLOCK) * BLOCK
        _check(at <= len(stream))
    duplicate = {}
    for i, row in enumerate(rows):
        duplicate.setdefault(apk._member_name(row.name)[0], []).append(i)
    for indexes in duplicate.values():
        if len(indexes) > 1:
            for i in indexes:
                rows[i] = replace(rows[i], flags=tuple(sorted((*rows[i].flags, 'duplicate_name'))))
    return tuple(rows)


def materialize(data, member):
    """Recheck a public descriptor and use the newly verified stream's bytes."""
    _check(isinstance(member, TarMember) and not member.flags)
    for current in members(data):
        if current == member:
            return _materialize(data, current)
    raise TarballError('Invalid or over-budget gzip/tar archive')


def _materialize(data, member):
    """Trusted core for clean descriptors from one parse of these exact bytes."""
    _check(isinstance(member, TarMember) and data is member._source and not member.flags
           and type(member.size) is int and 0 <= member.size <= MAX_CHILD_BYTES
           and type(member.data_offset) is int and 0 <= member.data_offset <= len(member._stream)
           and member.size <= len(member._stream) - member.data_offset)
    child = member._stream[member.data_offset:member.data_offset + member.size]
    return child, sha256_hex(child)


def _artifact(member, child, inner):
    return dict(member=apk.escape(member.name) or 'tar header', method=1, data_offset=0,
                compressed_size=len(member._source), inner_offset=inner, size=len(child),
                crc32=zlib.crc32(child), sha256=sha256_hex(child))


def artifact(member, child):
    _check(isinstance(member, TarMember) and not member.flags and isinstance(child, bytes)
           and len(child) == member.size and 0 < len(child) <= MAX_CHILD_BYTES)
    return _artifact(member, child, member.data_offset)


def header_artifact(member):
    """The entry header, also for empty or flagged files whose data is not read."""
    _check(isinstance(member, TarMember) and type(member.header_offset) is int
           and 0 <= member.header_offset <= len(member._stream) - BLOCK)
    child = member._stream[member.header_offset:member.header_offset + BLOCK]
    return _artifact(member, child, member.header_offset)
