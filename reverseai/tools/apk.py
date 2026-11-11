"""Bounded ZIP and Android binary XML readers; members remain bytes, never host paths.

Format references: PKWARE APPNOTE 6.3.10, sections 4.3.7–4.3.16; AOSP
ResourceTypes.h (ResStringPool_header, ResXMLTree_node and attribute structures).
"""

from dataclasses import dataclass, replace
import stat
import struct
import zlib

from reverseai.contract import (
    ArgSpec, ContractError, Location, MAX_CHILD_BYTES, MAX_CHILD_RATIO, Observation, OperationSpec,
    ToolRef, ToolSpec, sha256_hex,
)

MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_MEMBERS = 2048
MAX_TOTAL_BYTES = 128 * 1024 * 1024
MAX_XML_ENTRIES = 65536
MAX_XML_DEPTH = 256
INFLATE_CHUNK = 65536
ANDROID_NAMESPACE = 'http://schemas.android.com/apk/res/android'
NONE = 0xFFFFFFFF


class ApkError(ContractError):
    """An unsupported, inconsistent or over-budget APK structure."""


def _check(condition, message):
    if not condition:
        raise ApkError(message)


def _need(data, at, size, end=None):
    _check(0 <= at and 0 <= size and at + size <= (len(data) if end is None else min(end, len(data))),
           'APK structure outside the input')


def _unpack(fmt, data, at, end=None):
    _need(data, at, struct.calcsize(fmt), end)
    return struct.unpack_from(fmt, data, at)


def escape(value, maximum=255):
    """The existing import-name escaping, also for UTF-8 text read from XML."""
    parts, length = [], 0
    for char in value:
        if ' ' <= char <= '~' and char != '\\':
            part = char
        else:
            point = ord(char)
            part = ('\\x%02x' if point <= 255 else '\\u%04x' if point <= 65535 else '\\U%08x') % point
        if length + len(part) > maximum:
            break
        parts.append(part)
        length += len(part)
    return ''.join(parts)


def _member_name(value):
    # Ten extra characters admit a complete \UXXXXXXXX escape across the cutoff.
    escaped = escape(value, maximum=255 + 10)
    return escaped[:255], len(escaped) > 255


@dataclass(frozen=True)
class ZipMember:
    name: str
    zip_flags: int
    method: int
    crc32: int
    compressed_size: int
    uncompressed_size: int
    local_offset: int
    data_offset: int
    central_offset: int
    central_length: int
    record_end: int
    flags: tuple = ()

    @property
    def size(self):
        return self.uncompressed_size


def _extras(data, at, size, end):
    stop = at + size
    _need(data, at, size, end)
    while at < stop:
        tag, length = _unpack('<HH', data, at, stop)
        _check(tag != 1, 'ZIP64 is unsupported')
        at += 4
        _need(data, at, length, stop)
        at += length


def _traversing(name):
    body = name[:-1] if name.endswith('/') else name
    return (not body or '\\' in name or ':' in name or not name.isprintable()
            or any(part in ('', '.', '..') for part in body.split('/')))


def _eocd(data):
    found, at = [], max(0, len(data) - 65557)
    while True:
        at = data.find(b'PK\x05\x06', at)
        if at < 0:
            break
        if at + 22 <= len(data) and at + 22 + _unpack('<H', data, at + 20)[0] == len(data):
            found.append(at)
        at += 1
    _check(len(found) == 1, 'Missing or ambiguous ZIP directory end')
    at = found[0]
    _, disk, cd_disk, disk_count, count, size, offset, _ = _unpack('<4s4H2IH', data, at)
    _check(count != 0xFFFF and size != NONE and offset != NONE
           and data[max(0, at - 20):at - 16] != b'PK\x06\x07', 'ZIP64 is unsupported')
    _check(disk == cd_disk == 0 and disk_count == count, 'Multi-disk ZIP is unsupported')
    _check(count <= MAX_MEMBERS, 'Too many ZIP members')
    _check(offset <= at <= offset + size, 'Inconsistent ZIP directory extent')
    return count, offset, at


def _descriptor_end(data, at, end, expected):
    possible = []
    for prefix in (0, 4):
        if prefix and data[at:at + 4] != b'PK\x07\x08':
            continue
        if at + prefix + 12 <= end and _unpack('<3I', data, at + prefix, end) == expected:
            possible.append(at + prefix + 12)
    _check(len(possible) == 1, 'APK data descriptor is missing or ambiguous')
    return possible[0]


def members(data):
    """Central-directory order; per-member refusal flags prevent any materialization."""
    _check(isinstance(data, bytes) and len(data) <= MAX_INPUT_BYTES, 'APK input exceeds its limit')
    count, at, end = _eocd(data)
    directory = at
    rows = []
    for _ in range(count):
        if at + 46 > end or data[at:at + 4] != b'PK\x01\x02':
            break  # only the fully parsed central-directory prefix is usable
        row = _unpack('<4s6H3I5H2I', data, at, end)
        _, made, version, bits, method, _, _, crc, packed, size, n, x, c, disk, _, external, local = row
        _check(NONE not in (packed, size, local), 'ZIP64 is unsupported')
        _check(disk == 0, 'Multi-disk ZIP is unsupported')
        length = 46 + n + x + c
        if at + length > end:
            break
        _extras(data, at + 46 + n, x, at + length)
        raw_name = data[at + 46:at + 46 + n]
        flags = set()
        try:
            name = raw_name.decode('utf-8' if bits & 0x800 else 'cp437')
        except UnicodeError:
            name = raw_name.decode('utf-8', 'backslashreplace')
            flags.add('header_mismatch')
        if _member_name(name)[1]:
            flags.add('long_name')
        if _traversing(name):
            flags.add('traversing_name')
        if bits & (1 | 0x40 | 0x2000):
            flags.add('encrypted')
        if method not in (0, 8):
            flags.add('unsupported_method')
        if bits & ~(0x800 | 8 | 6 | 1 | 0x40 | 0x2000):
            flags.add('header_mismatch')
        if stat.S_ISLNK(external >> 16):
            flags.add('symlink')
        if size > MAX_CHILD_BYTES:
            flags.add('too_large')
        if size > packed * MAX_CHILD_RATIO:
            flags.add('ratio')
        data_offset, record_end = 0, local
        try:
            fields = _unpack('<4s5H3I2H', data, local, directory)
            sig, lv, lb, lm, _, _, lc, lp, ls, ln, lx = fields
            _check(NONE not in (lp, ls), 'ZIP64 is unsupported')
            _extras(data, local + 30 + ln, lx, directory)
            data_offset = local + 30 + ln + lx
            _need(data, local + 30, ln + lx, directory)
            _need(data, data_offset, packed, directory)
            if (sig != b'PK\x03\x04' or bits != lb or method != lm
                    or data[local + 30:local + 30 + ln] != raw_name
                    or (not bits & 8 and (lc, lp, ls) != (crc, packed, size))
                    or (bits & 8 and any(a not in (0, b) for a, b in zip((lc, lp, ls), (crc, packed, size))))
                    or (method == 0 and packed != size)):
                flags.add('header_mismatch')
            record_end = data_offset + packed
            if bits & 8:
                record_end = _descriptor_end(data, record_end, directory, (crc, packed, size))
        except ApkError as exc:
            if str(exc) == 'ZIP64 is unsupported':
                raise
            flags.add('header_mismatch')
        rows.append(ZipMember(name, bits, method, crc, packed, size, local, data_offset, at, length,
                              record_end, tuple(sorted(flags))))
        at += length
    _check(not rows and end == 0 or rows and min(m.local_offset for m in rows) == 0,
           'Bytes before the first ZIP local header')
    duplicate = {}
    for i, row in enumerate(rows):
        duplicate.setdefault(_member_name(row.name)[0], []).append(i)
    bad = {i: set(row.flags) for i, row in enumerate(rows)}
    for indexes in duplicate.values():
        if len(indexes) > 1:
            for i in indexes:
                bad[i].add('duplicate_name')
    ordered = sorted(range(len(rows)), key=lambda i: rows[i].local_offset)
    high, previous = -1, None
    for i in ordered:
        if rows[i].local_offset < high:
            bad[i].add('header_mismatch')
            bad[previous].add('header_mismatch')
        if rows[i].record_end > high:
            high, previous = rows[i].record_end, i
    if sum(row.size for row in rows) > MAX_TOTAL_BYTES:
        for values in bad.values():
            values.add('too_large')
    return tuple(replace(row, flags=tuple(sorted(bad[i]))) for i, row in enumerate(rows))


def artifact(member, child):
    return dict(member=_member_name(member.name)[0], method=member.method, data_offset=member.data_offset,
                compressed_size=member.compressed_size, size=len(child), crc32=member.crc32, sha256=sha256_hex(child))


def materialize(data, member):
    """Revalidate identity, then inflate in bounded chunks; declared sizes are never allocation hints."""
    _check(isinstance(member, ZipMember) and member in members(data) and not member.flags,
           'APK member is refused')
    return _materialize(data, member)


def _materialize(data, member):
    """Only callers holding a clean member from a parse of these same bytes may use this core."""
    raw = memoryview(data)[member.data_offset:member.data_offset + member.compressed_size]
    if member.method == 0:
        child = bytes(raw)
    else:
        decoder, child = zlib.decompressobj(-15), bytearray()
        try:
            for at in range(0, len(raw), INFLATE_CHUNK):
                pending = raw[at:at + INFLATE_CHUNK]
                while pending:
                    out = decoder.decompress(pending, min(INFLATE_CHUNK, member.size - len(child) + 1))
                    child.extend(out)
                    _check(len(child) <= member.size, 'APK child exceeds its declared size')
                    _check(not decoder.unused_data, 'APK child has trailing compressed data')
                    pending = decoder.unconsumed_tail
            _check(decoder.eof and not decoder.unconsumed_tail, 'APK child is incomplete')
        except zlib.error:
            raise ApkError('APK child does not inflate') from None
        child = bytes(child)
    _check(len(child) == member.size and zlib.crc32(child) == member.crc32, 'APK child size or CRC differs')
    return child, sha256_hex(child)


def _chunk(data, at, end):
    kind, header, size = _unpack('<HHI', data, at, end)
    _check(8 <= header <= size and header % 4 == size % 4 == 0, 'Invalid Android XML chunk')
    _need(data, at, size, end)
    return kind, header, size


def _length(data, at, end, utf8):
    fmt, width, high = ('<B', 1, 0x80) if utf8 else ('<H', 2, 0x8000)
    value = _unpack(fmt, data, at, end)[0]
    at += width
    if value & high:
        value = ((value & (high - 1)) << (width * 8)) | _unpack(fmt, data, at, end)[0]
        at += width
    return value, at


def _string_pool(data, at, header, size):
    _check(header >= 28, 'Invalid Android XML string pool')
    count, styles, flags, start, style_start = _unpack('<5I', data, at + 8, at + header)
    _check(count + styles <= MAX_XML_ENTRIES, 'Too many Android XML strings')
    _check(header + 4 * (count + styles) <= start <= size, 'Invalid Android XML string offsets')
    _check(not style_start or start <= style_start <= size, 'Invalid Android XML style offsets')
    _check(not styles or style_start, 'Missing Android XML styles')
    end = at + (style_start or size)
    result, cache, scanned, decoded = [], {}, 0, 0
    for i in range(count):
        offset = _unpack('<I', data, at + header + i * 4, at + size)[0]
        position = at + start + offset
        if position not in cache:
            units, cursor = _length(data, position, end, bool(flags & 0x100))
            if flags & 0x100:
                length, cursor = _length(data, cursor, end, True)
                width, codec = 1, 'utf-8'
            else:
                length, width, codec = units * 2, 2, 'utf-16-le'
            _need(data, cursor, length + width, end)
            scanned += cursor + length + width - position
            _check(scanned <= MAX_CHILD_BYTES, 'Android XML string scan exceeds its limit')
            _check(data[cursor + length:cursor + length + width] == bytes(width), 'Unterminated Android XML string')
            try:
                text = data[cursor:cursor + length].decode(codec)
            except UnicodeError:
                raise ApkError('Invalid Android XML string encoding') from None
            _check(len(text.encode('utf-16-le')) // 2 == units, 'Android XML string length differs')
            decoded += len(text.encode('utf-8'))
            _check(decoded <= MAX_CHILD_BYTES, 'Android XML strings exceed their limit')
            cache[position] = text
        result.append(cache[position])
    for i in range(styles):
        offset = _unpack('<I', data, at + header + (count + i) * 4, at + size)[0]
        if offset != NONE:
            _need(data, at + style_start + offset, 12, at + size)
    return result


def binary_manifest(data):
    """Start elements and exact attribute-record offsets, without resolving resource references."""
    _check(isinstance(data, bytes) and len(data) <= MAX_CHILD_BYTES, 'Android XML exceeds its limit')
    kind, header, size = _chunk(data, 0, len(data))
    _check(kind == 3 and size == len(data), 'Not a complete Android binary XML document')
    at, chunks, attributes = header, 0, 0
    strings, resources, resource_seen = None, [], False
    elements, stack, namespaces, active_namespaces = [], [], [], {}

    def text(index, optional=False):
        if optional and index == NONE:
            return None
        _check(strings is not None and 0 <= index < len(strings), 'Android XML string index outside its pool')
        return strings[index]

    def namespace(index):
        value = text(index, True)
        _check(value is None or active_namespaces.get(value, 0), 'Undeclared Android XML namespace')
        return value

    while at < size:
        kind, header, length = _chunk(data, at, size)
        chunks += 1
        _check(chunks <= MAX_XML_ENTRIES, 'Too many Android XML chunks')
        if kind == 1:
            _check(strings is None and not elements, 'Repeated Android XML string pool')
            strings = _string_pool(data, at, header, length)
        elif kind == 0x180:
            _check(strings is not None and not resource_seen and not elements and (length - header) % 4 == 0,
                   'Invalid Android XML resource map')
            count = (length - header) // 4
            _check(count <= len(strings), 'Android XML resource map exceeds its pool')
            resources = [_unpack('<I', data, p, at + length)[0] for p in range(at + header, at + length, 4)]
            resource_seen = True
        elif kind in (0x100, 0x101, 0x102, 0x103):
            _check(header >= 16 and strings is not None, 'Invalid Android XML node')
            text(_unpack('<I', data, at + 12, at + header)[0], True)
            ext = at + header
            if kind in (0x100, 0x101):
                prefix, uri = _unpack('<II', data, ext, at + length)
                pair = (text(prefix, True), text(uri), len(stack))
                if kind == 0x100:
                    namespaces.append(pair)
                    active_namespaces[pair[1]] = active_namespaces.get(pair[1], 0) + 1
                else:
                    _check(namespaces and namespaces[-1] == pair, 'Unbalanced Android XML namespace')
                    namespaces.pop()
                    active_namespaces[pair[1]] -= 1
            elif kind == 0x102:
                ns, name, start, stride, count, id_, class_, style = _unpack('<II6H', data, ext, at + length)
                _check(start >= 20 and stride == 20 and max(id_, class_, style) <= count,
                       'Invalid Android XML attributes')
                _check(len(stack) < MAX_XML_DEPTH and (stack or not elements), 'Invalid Android XML element depth')
                attributes += count
                _check(attributes <= MAX_XML_ENTRIES, 'Too many Android XML attributes')
                first = ext + start
                _need(data, first, count * stride, at + length)
                element = dict(name=text(name), namespace=namespace(ns), parent=stack[-1] if stack else None,
                               depth=len(stack), offset=at, length=length, attributes=[])
                _check(element['name'], 'Empty Android XML element name')
                used = set()
                for i in range(count):
                    offset = first + i * stride
                    ans, aname, raw, value_size, reserved, type_, value = _unpack('<IIIHBBI', data, offset, at + length)
                    _check(value_size == 8 and reserved == 0, 'Invalid Android XML typed value')
                    label, uri = text(aname), namespace(ans)
                    _check(label, 'Empty Android XML attribute name')
                    _check((uri, label) not in used, 'Duplicate Android XML attribute')
                    used.add((uri, label))
                    raw_value = text(raw, True)
                    if type_ == 3:
                        value_type, decoded = 'string', text(value)
                    elif type_ in (16, 17):
                        value_type, decoded = 'int', value - 2**32 if type_ == 16 and value >= 2**31 else value
                    elif type_ == 18:
                        value_type, decoded = 'bool', bool(value)
                    elif type_ == 1:
                        value_type, decoded = 'reference', '@0x%08x' % value
                    else:
                        value_type, decoded = 'other', '0x%08x' % value
                    element['attributes'].append(dict(name=label, namespace=uri, raw_value=raw_value,
                        type=value_type, data=value, value=decoded, offset=offset, length=20,
                        resource_id=resources[aname] if aname < len(resources) else None))
                elements.append(element)
                stack.append(len(elements) - 1)
            else:
                ns, name = _unpack('<II', data, ext, at + length)
                _check(stack, 'Unexpected Android XML end element')
                element = elements[stack[-1]]
                _check((namespace(ns), text(name)) == (element['namespace'], element['name']),
                       'Unbalanced Android XML element')
                stack.pop()
        at += length
    _check(elements and not stack and not namespaces, 'Incomplete Android XML document')
    return tuple(elements)


def inventory(data, args):
    rows = members(data)
    result = []
    for index in range(args['start'], min(len(rows), args['start'] + args['limit'])):
        member = rows[index]
        flags, digest = list(member.flags), None
        if not flags:
            try:
                _, digest = _materialize(data, member)
            except ApkError:
                flags = ['crc']
        result.append(Observation(Location(member.central_offset, min(member.central_length, 4096)),
            dict(kind='member', index=index, total=len(rows), name=_member_name(member.name)[0], method=member.method,
                 compressed_size=member.compressed_size, size=member.size, crc32=member.crc32,
                 sha256=digest, flags=flags)))
    return result


def manifest(data, args):
    selected = [member for member in members(data) if member.name == 'AndroidManifest.xml']
    if not selected:
        return []
    _check(len(selected) == 1 and not selected[0].flags, 'APK manifest member is refused')
    member = selected[0]
    child, _ = materialize(data, member)
    source = artifact(member, child)
    rows = []
    for index, element in enumerate(binary_manifest(child)):
        for attr in element['attributes']:
            name = ('android:' if attr['namespace'] == ANDROID_NAMESPACE else '') + attr['name']
            value = escape(attr['value'], 256) if isinstance(attr['value'], str) else attr['value']
            rows.append((attr['offset'], dict(kind='manifest_attribute', element_index=index,
                element=escape(element['name'], 128), attribute=escape(name, 128), type=attr['type'], value=value)))
    return [Observation(Location(offset, 20), dict(index=index, total=len(rows), **value), source)
            for index, (offset, value) in enumerate(rows) if args['start'] <= index < args['start'] + args['limit']]


REF = ToolRef('apk', '0.1.0')
TOOL = ToolSpec(REF, {
    'apk.inventory': OperationSpec('apk.inventory', {
        'start': ArgSpec('int', 0, 65535, default=0), 'limit': ArgSpec('int', 1, 256, default=128)}, inventory,
        max_observations=256),
    'apk.manifest': OperationSpec('apk.manifest', {
        'start': ArgSpec('int', 0, 65535, default=0), 'limit': ArgSpec('int', 1, 256, default=256)}, manifest,
        max_observations=256),
})
