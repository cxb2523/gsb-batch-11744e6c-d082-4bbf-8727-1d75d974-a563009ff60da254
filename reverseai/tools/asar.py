"""Bounded Electron ASAR headers and stored children; no paths are opened."""

from dataclasses import dataclass
import struct
import zlib

from reverseai.contract import ContractError, MAX_CHILD_BYTES, sha256_hex
from reverseai.tools import apk, jsonpos

MAGIC = b'\x04\x00\x00\x00'
MAX_HEADER_BYTES = 4 * 1024 * 1024
MAX_HEADER_TOKENS = 262144
MAX_MEMBERS = 65536
MAX_PATH_BYTES = 65535
MAX_TOTAL_PATH_BYTES = 32 * 1024 * 1024
_METADATA = frozenset(('unpacked', 'executable', 'integrity'))


class AsarError(ContractError):
    """An inconsistent or over-budget ASAR archive."""


def _check(condition):
    if not condition:
        raise AsarError('Invalid or over-budget ASAR archive')


def _uint(node, header):
    raw = header[node.start:node.end]
    _check(0 < len(raw) <= 20 and all(48 <= byte <= 57 for byte in raw))
    value = int(raw)
    _check(value < 2**64)
    return value


def _offset(value):
    _check(isinstance(value, str) and bool(value) and all('0' <= c <= '9' for c in value))
    digits = value.lstrip('0') or '0'
    _check(len(digits) <= 20)
    result = int(digits)
    _check(result < 2**64)
    return result


@dataclass(frozen=True)
class AsarMember:
    name: str
    size: int
    data_offset: int
    central_offset: int
    central_length: int
    flags: tuple = ()

    @property
    def method(self):
        return 0

    @property
    def compressed_size(self):
        return self.size

    @property
    def uncompressed_size(self):
        return self.size

    @property
    def local_offset(self):
        return self.central_offset


def members(data):
    """Depth-first header order; flagged leaves are disclosed but never read."""
    _check(isinstance(data, bytes) and len(data) >= 16 and data.startswith(MAGIC))
    pickle_size, payload_size, text_size = struct.unpack_from('<III', data, 4)
    _check(text_size <= MAX_HEADER_BYTES and payload_size == 4 + ((text_size + 3) // 4) * 4
           and pickle_size == payload_size + 4 and 8 + pickle_size <= len(data))
    header = data[16:16 + text_size]
    try:
        root = jsonpos.parse(header, max_bytes=MAX_HEADER_BYTES,
                             max_tokens=MAX_HEADER_TOKENS).root
    except ContractError:
        raise AsarError('Invalid or over-budget ASAR archive') from None
    _check(isinstance(root.value, dict) and set(root.value) == {'files'}
           and isinstance(root.value['files'], dict))
    first_data = 8 + pickle_size
    rows, ranges, names = [], [], set()
    count, path_bytes = 0, 0

    def walk(directory, parent=None, parent_bytes=0, inherited=False):
        nonlocal count, path_bytes
        for key, node in directory.children:
            count += 1
            _check(count <= MAX_MEMBERS)
            length = len(key.value.encode('utf-8')) + (parent_bytes + 1 if parent is not None else 0)
            path_bytes += length
            _check(length <= MAX_PATH_BYTES and path_bytes <= MAX_TOTAL_PATH_BYTES)
            name = key.value if parent is None else parent + '/' + key.value
            _check(name not in names)
            names.add(name)
            value = node.value
            _check(isinstance(value, dict))
            fields = {key.value: child for key, child in node.children}
            _check(all(k not in value or type(value[k]) is bool for k in ('unpacked', 'executable'))
                   and ('integrity' not in value or isinstance(value['integrity'], dict)))
            unpacked = inherited or value.get('unpacked', False)
            if 'files' in value:
                _check(set(value) <= {'files'} | _METADATA and isinstance(value['files'], dict))
                walk(fields['files'], name, length, unpacked)
                continue
            _check(set(value) <= {'size', 'offset', 'link'} | _METADATA)
            link = 'link' in value
            _check(not link or isinstance(value['link'], str) and bool(value['link']))
            _check(link or 'size' in value)
            size = _uint(fields['size'], header) if 'size' in value else 0
            relative = _offset(value['offset']) if 'offset' in value else None
            _check(link or unpacked or relative is not None)
            flags = set()
            if unpacked:
                flags.add('asar_unpacked')
            if link:
                flags.add('asar_link')
            if apk._traversing(name):
                flags.add('traversing_name')
            if apk._member_name(name)[1]:
                flags.add('long_name')
            if size > MAX_CHILD_BYTES:
                flags.add('too_large')
            at = first_data + relative if relative is not None else first_data
            if not link and not unpacked:
                _check(first_data <= at <= len(data) and size <= len(data) - at)
                if size:
                    ranges.append((at, at + size))
            rows.append(AsarMember(name, size, at, 16 + node.start, node.end - node.start,
                                   tuple(sorted(flags))))

    walk(dict((key.value, node) for key, node in root.children)['files'])
    previous = first_data
    for start, end in sorted(ranges):
        _check(start >= previous)
        previous = end
    return tuple(rows)


def materialize(data, member):
    """Revalidate the descriptor against this archive before reading its bytes."""
    _check(isinstance(member, AsarMember) and not member.flags and member in members(data))
    return _materialize(data, member)


def _materialize(data, member):
    """Trusted core for clean descriptors from one parse of these exact bytes."""
    _check(isinstance(data, bytes) and isinstance(member, AsarMember) and not member.flags
           and type(member.size) is int and type(member.data_offset) is int and 0 <= member.size <= MAX_CHILD_BYTES
           and 0 <= member.data_offset <= len(data) and member.size <= len(data) - member.data_offset)
    child = data[member.data_offset:member.data_offset + member.size]
    return child, sha256_hex(child)


def artifact(member, child):
    _check(isinstance(member, AsarMember) and not member.flags and isinstance(child, bytes)
           and type(member.data_offset) is int and type(member.size) is int and len(child) == member.size)
    return dict(member=apk.escape(member.name), method=0, data_offset=member.data_offset,
                compressed_size=len(child), size=len(child), crc32=zlib.crc32(child), sha256=sha256_hex(child))
