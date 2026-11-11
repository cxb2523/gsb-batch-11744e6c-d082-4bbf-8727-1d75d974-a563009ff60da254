"""Synthetic ZIP/AXML known answers, refusals and child-evidence round trips."""

from dataclasses import replace
import io
import random
import stat
import struct
import unittest
from unittest.mock import patch
import zipfile
import zlib

from reverseai import claims
from reverseai.contract import (
    AnalysisResult, AnalysisTask, Budget, ContractError, InputRef, Location, OperationRequest,
    content_id, make_finding, materialize, sha256_hex,
)
from reverseai.gateway import Gateway
from reverseai.review import review
from reverseai.tools import apk
from tests import fixtures_apk as shared

NONE = 0xffffffff


def zip_bytes(entries, *, method=0, descriptor=None, gap=b'', comment=b''):
    """Independent minimal writer; layout offsets refer to declaring fields, not parser output."""
    body, directory, layout = bytearray(), bytearray(), []
    for name, child in entries:
        name = name.encode('utf-8') if isinstance(name, str) else name
        bits = 0x800 | (8 if descriptor is not None else 0)
        compressor = zlib.compressobj(6, zlib.DEFLATED, -15)
        packed = compressor.compress(child) + compressor.flush() if method == 8 else child
        crc, local = zlib.crc32(child), len(body)
        values = (0, 0, 0) if descriptor is not None else (crc, len(packed), len(child))
        body += struct.pack('<4s5H3I2H', b'PK\x03\x04', 20, bits, method, 0, 0, *values, len(name), 0) + name
        data_offset = len(body)
        body += packed
        if descriptor is not None:
            body += (b'PK\x07\x08' if descriptor else b'') + struct.pack('<3I', crc, len(packed), len(child))
        layout.append(dict(local=local, data=data_offset, end=len(body), central=len(directory)))
        directory += struct.pack('<4s6H3I5H2I', b'PK\x01\x02', 0x314, 20, bits, method, 0, 0,
                                 crc, len(packed), len(child), len(name), 0, 0, 0, 0, 0, local) + name
    body += gap
    cd = len(body)
    for row in layout:
        row['central'] += cd
    body += directory
    end = len(body)
    body += struct.pack('<4s4H2IH', b'PK\x05\x06', 0, 0, len(entries), len(entries), len(directory), cd, len(comment))
    body += comment
    return bytes(body), dict(rows=layout, cd=cd, end=end)


def changed(data, at, fmt, value):
    data = bytearray(data)
    struct.pack_into(fmt, data, at, value)
    return bytes(data)


def length(value, utf8):
    if utf8:
        return bytes([value]) if value < 128 else bytes([0x80 | (value >> 8), value & 255])
    return struct.pack('<H', value) if value < 32768 else struct.pack('<HH', 0x8000 | (value >> 16), value & 65535)


def string_pool(strings, utf8=True):
    raw, offsets = bytearray(), []
    for text in strings:
        offsets.append(len(raw))
        units = len(text.encode('utf-16-le')) // 2
        encoded = text.encode('utf-8' if utf8 else 'utf-16-le')
        raw += length(units, utf8) + (length(len(encoded), True) if utf8 else b'') + encoded + bytes(1 if utf8 else 2)
    raw += bytes(-len(raw) % 4)
    start = 28 + 4 * len(strings)
    return (struct.pack('<HHI5I', 1, 28, start + len(raw), len(strings), 0, 0x100 if utf8 else 0, start, 0)
            + b''.join(struct.pack('<I', value) for value in offsets) + raw)


def node(kind, payload):
    return struct.pack('<HHIII', kind, 16, 16 + len(payload), 1, NONE) + payload


def xml_bytes(strings, chunks, utf8=True, resource_map=False):
    pool = string_pool(strings, utf8)
    mapping = (struct.pack('<HHI', 0x180, 8, 8 + 4 * len(strings))
               + b''.join(struct.pack('<I', 0x01010000 + i) for i in range(len(strings)))) if resource_map else b''
    body = pool + mapping + b''.join(chunks)
    return struct.pack('<HHI', 3, 8, 8 + len(body)) + body


def start_element(name, attrs=(), namespace=NONE):
    return node(0x102, struct.pack('<II6H', namespace, name, 20, 20, len(attrs), 0, 0, 0)
                + b''.join(struct.pack('<IIIHBBI', *attr[:3], 8, 0, *attr[3:]) for attr in attrs))


def end_element(name, namespace=NONE):
    return node(0x103, struct.pack('<II', namespace, name))


def manifest_bytes(utf8=True):
    strings = ['manifest', 'package', 'org.reverseai.fixture', 'android', apk.ANDROID_NAMESPACE,
               'uses-permission', 'name', 'android.permission.INTERNET', 'versionCode', 'enabled', 'icon', 'other', 'hex']
    attrs = [(NONE, 1, 2, 3, 2), (4, 8, NONE, 16, 0xfffffff9), (4, 9, NONE, 18, 0xffffffff),
             (4, 10, NONE, 1, 0x7f010001), (4, 11, NONE, 99, 42), (4, 12, NONE, 17, 0xbeef)]
    chunks = [node(0x100, struct.pack('<II', 3, 4)), start_element(0, attrs),
              start_element(5, [(4, 6, 7, 3, 7)]), end_element(5), end_element(0),
              node(0x101, struct.pack('<II', 3, 4))]
    data = xml_bytes(strings, chunks, utf8, True)
    root = 8 + len(string_pool(strings, utf8)) + 8 + 4 * len(strings) + len(chunks[0])
    child = root + len(chunks[1])
    return data, dict(root=root, child=child, attributes=[root + 36 + i * 20 for i in range(6)] + [child + 36])


def run(operation, data, **args):
    spec = apk.TOOL.operations['apk.' + operation]
    return spec.handler(data, spec.validate_args(args))


class ZipParsingTests(unittest.TestCase):
    def test_stored_deflated_and_descriptor_forms_have_exact_offsets_and_hashes(self):
        child = bytes(range(251)) * 4
        for method in (0, 8):
            for descriptor in (None, False, True):
                with self.subTest(method=method, descriptor=descriptor):
                    data, layout = zip_bytes([('classes.dex', child)], method=method, descriptor=descriptor,
                                             gap=b'APK signing block placeholder', comment=b'archive comment')
                    member, = apk.members(data)
                    row = layout['rows'][0]
                    self.assertEqual((member.name, member.method, member.zip_flags, member.crc32, member.size, member.flags),
                                     ('classes.dex', method, 0x800 | (8 if descriptor is not None else 0),
                                      zlib.crc32(child), len(child), ()))
                    self.assertEqual((member.local_offset, member.data_offset, member.central_offset,
                                      member.central_length, member.record_end),
                                     (0, row['data'], row['central'], 46 + len('classes.dex'), row['end']))
                    self.assertEqual(apk.materialize(data, member), (child, sha256_hex(child)))
                    self.assertEqual(materialize(data, apk.artifact(member, child)), child)
                    self.assertEqual(run('inventory', data)[0].location, Location(row['central'], 57))

    def test_stdlib_zip_interoperability_and_cp437(self):
        child = bytes(range(256)) * 2
        for method in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, 'w', compression=method) as archive:
                archive.writestr('folder/caf\u00e9.bin', child)
                archive.writestr('empty', b'')
            data = stream.getvalue()
            rows = apk.members(data)
            self.assertEqual(rows[0].name, 'folder/caf\u00e9.bin')
            self.assertEqual(apk.materialize(data, rows[0])[0], child)
            self.assertEqual(apk.materialize(data, rows[1])[0], b'')
        data, layout = zip_bytes([(b'caf\x82', child)])
        data = changed(changed(data, 6, '<H', 0), layout['rows'][0]['central'] + 8, '<H', 0)
        self.assertEqual(apk.members(data)[0].name, 'caf\u00e9')

    def test_empty_archive_and_directory_are_bounded(self):
        data, _ = zip_bytes([])
        self.assertEqual(apk.members(data), ())
        self.assertEqual(run('inventory', data), [])
        data, _ = zip_bytes([('assets/', b'')])
        member, = apk.members(data)
        self.assertEqual(member.flags, ())
        self.assertEqual(apk.materialize(data, member), (b'', sha256_hex(b'')))

    def test_traversing_names_and_display_aliases_never_materialize(self):
        for name in ('', '../a', './a', '/a', 'a//b', 'a/../b', 'a\\b', 'C:a', 'a\x00b', 'a\u202eb'):
            data, _ = zip_bytes([(name, b'value')])
            with self.subTest(name=repr(name)):
                member, = apk.members(data)
                self.assertIn('traversing_name', member.flags)
                with self.assertRaises(apk.ApkError):
                    apk.materialize(data, member)
                self.assertIsNone(run('inventory', data)[0].value['sha256'])
        for names in (('a', 'a'), ('a' * 256 + '1', 'a' * 256 + '2')):
            data, _ = zip_bytes([(name, b'value') for name in names])
            self.assertTrue(all('duplicate_name' in m.flags for m in apk.members(data)))

    def test_flags_encryption_methods_symlinks_and_bad_utf8(self):
        data, layout = zip_bytes([('x', b'value')])
        cd = layout['cd']
        cases = [changed(data, cd + 8, '<H', 0x801), changed(data, cd + 10, '<H', 99),
                 changed(data, cd + 38, '<I', (stat.S_IFLNK | 0o777) << 16),
                 changed(data, cd + 8, '<H', 0x810)]
        for bad, flag in zip(cases, ('encrypted', 'unsupported_method', 'symlink', 'header_mismatch')):
            with self.subTest(flag=flag):
                self.assertIn(flag, apk.members(bad)[0].flags)
                with self.assertRaises(apk.ApkError):
                    apk.materialize(bad, apk.members(bad)[0])
        invalid, _ = zip_bytes([(b'\xff', b'value')])
        self.assertIn('header_mismatch', apk.members(invalid)[0].flags)

    def test_long_names_are_flagged_at_the_escaped_character_boundary(self):
        # Disclose every cut member identity and never materialize it.
        cases = [('a' * 255, 'a' * 255, False), ('a' * 256, 'a' * 255, True),
                 ('a' * 251 + '\u00e9', 'a' * 251 + '\\xe9', False),
                 ('a' * 252 + '\u00e9', 'a' * 252 + '\\xe', True),
                 ('a' * 254 + '\u20ac', 'a' * 254 + '\\', True),
                 ('a' * 254 + '\U0001f600', 'a' * 254 + '\\', True)]
        for name, shown, long in cases:
            with self.subTest(name=name):
                data, _ = zip_bytes([(name, b'value')])
                member, = apk.members(data)
                self.assertEqual(member.name, name)
                self.assertEqual(member.flags, ('long_name',) if long else ())
                with patch.object(apk, '_materialize', wraps=apk._materialize) as inflate:
                    row, = run('inventory', data)
                self.assertEqual(row.value['name'], shown)
                self.assertEqual(len(row.value['name']), 255)
                self.assertEqual(row.value['flags'], ['long_name'] if long else [])
                self.assertEqual(inflate.call_count, 0 if long else 1)
                if long:
                    self.assertIsNone(row.value['sha256'])
                    with self.assertRaisesRegex(apk.ApkError, 'member is refused'):
                        apk.materialize(data, member)
                else:
                    self.assertEqual(row.value['sha256'], sha256_hex(b'value'))
                    self.assertEqual(apk.materialize(data, member)[0], b'value')

    def test_local_headers_descriptors_and_overlaps_are_checked(self):
        data, layout = zip_bytes([('x', b'value'), ('y', b'other')])
        cd = layout['rows'][0]['central']
        for at, fmt, value in ((0, '<I', 0), (6, '<H', 0), (8, '<H', 8), (14, '<I', 0),
                               (18, '<I', 1), (22, '<I', 1), (26, '<H', 500), (30, '<B', ord('z'))):
            with self.subTest(at=at):
                self.assertIn('header_mismatch', apk.members(changed(data, at, fmt, value))[0].flags)
        bad_local = changed(data, layout['rows'][1]['central'] + 42, '<I', len(data))
        self.assertIn('header_mismatch', apk.members(bad_local)[1].flags)
        first = layout['rows'][0]
        new_size = layout['rows'][1]['data'] - first['data'] + 2
        overlap = data
        for at in (18, 22, cd + 20, cd + 24):
            overlap = changed(overlap, at, '<I', new_size)
        self.assertTrue(all('header_mismatch' in m.flags for m in apk.members(overlap)))
        for signed in (True, False):
            desc, offsets = zip_bytes([('x', b'value')], descriptor=signed)
            bad = changed(desc, offsets['rows'][0]['end'] - 4, '<I', 999)
            self.assertIn('header_mismatch', apk.members(bad)[0].flags)

    def test_descriptor_ambiguity_is_refused_even_when_both_forms_match(self):
        signature = 0x08074b50
        data = struct.pack('<4I', *([signature] * 4))
        # Both layouts require these three equal values, beyond the archive/child limits.
        # Check the descriptor bound directly without allocating that payload.
        self.assertEqual(struct.unpack_from('<3I', data, 0), (signature,) * 3)
        self.assertEqual(struct.unpack_from('<3I', data, 4), (signature,) * 3)
        with self.assertRaises(apk.ApkError):
            apk._descriptor_end(data, 0, len(data), (signature,) * 3)

    def test_prefixed_descriptor_requires_every_signature_byte(self):
        data, layout = zip_bytes([('x', b'value')], descriptor=True)
        at = layout['rows'][0]['end'] - 16
        self.assertEqual(data[at:at + 4], b'PK\x07\x08')
        self.assertEqual(apk.materialize(data, apk.members(data)[0])[0], b'value')
        for byte in range(4):
            with self.subTest(byte=byte):
                bad = changed(data, at + byte, '<B', data[at + byte] ^ 1)
                member, = apk.members(bad)
                self.assertEqual(member.flags, ('header_mismatch',))
                self.assertEqual(run('inventory', bad)[0].value['flags'], ['header_mismatch'])
                with self.assertRaisesRegex(apk.ApkError, 'member is refused'):
                    apk.materialize(bad, member)

    def test_exact_ratio_boundary_is_admitted_and_one_byte_over_is_flagged(self):
        for size, flags in ((1000, []), (1001, ['ratio'])):
            data, _ = shared.zip_archive([shared.member('zeros', bytes(size))])
            member, = apk.members(data)
            with self.subTest(size=size):
                self.assertEqual(member.compressed_size, 10)
                self.assertEqual(list(member.flags), flags)
                row, = run('inventory', data)
                self.assertEqual(row.value['flags'], flags)
                if flags:
                    self.assertIsNone(row.value['sha256'])
                    with self.assertRaises(apk.ApkError):
                        apk.materialize(data, member)
                else:
                    self.assertEqual(apk.materialize(data, member)[0], bytes(size))
                    self.assertEqual(materialize(data, apk.artifact(member, bytes(size))), bytes(size))

    def test_whole_archive_refusals_zip64_multidisk_sfx_ambiguity_and_limits(self):
        data, layout = zip_bytes([('x', b'value')])
        cd, end = layout['cd'], layout['end']
        # Version-needed alone never establishes ZIP64.
        classic = changed(changed(data, cd + 6, '<H', 46), 4, '<H', 46)
        self.assertEqual(apk.materialize(classic, apk.members(classic)[0])[0], b'value')
        bad = [changed(data, end + 10, '<H', 0xffff), changed(data, cd + 24, '<I', NONE),
               changed(data, end + 4, '<H', 1), changed(data, cd + 34, '<H', 1),
               changed(data, end + 8, '<H', 0), changed(data, end + 16, '<I', cd + 1)]
        prefixed = b'prefix' + data
        prefixed = changed(prefixed, 6 + cd + 42, '<I', 6)
        prefixed = changed(prefixed, 6 + end + 16, '<I', 6 + cd)
        bad.append(prefixed)
        extra_end = struct.pack('<4s4H2IH', b'PK\x05\x06', 0, 0, 0, 0, 0, 0, 0)
        ambiguous, _ = zip_bytes([('x', b'value')], comment=extra_end)
        bad.append(ambiguous)
        for value in bad:
            with self.subTest(value=value[-30:]):
                with self.assertRaises(apk.ApkError):
                    apk.members(value)
        with patch.object(apk, 'MAX_INPUT_BYTES', len(data) - 1), self.assertRaises(apk.ApkError):
            apk.members(data)
        with patch.object(apk, 'MAX_MEMBERS', 0), self.assertRaises(apk.ApkError):
            apk.members(data)

    def test_zip64_extra_and_locator_are_refused(self):
        data, layout = zip_bytes([('x', b'value')])
        cd, end = layout['cd'], layout['end']
        extra = struct.pack('<HH', 1, 0)
        with_extra = changed(data[:end] + extra + data[end:], cd + 30, '<H', 4)
        with_extra = changed(with_extra, end + 4 + 12, '<I', end - cd + 4)
        with self.assertRaisesRegex(apk.ApkError, 'ZIP64'):
            apk.members(with_extra)
        locator = b'PK\x06\x07' + bytes(16)
        with_locator = data[:end] + locator + data[end:]
        with_locator = changed(with_locator, end + 20 + 12, '<I', end - cd + 20)
        with self.assertRaisesRegex(apk.ApkError, 'ZIP64'):
            apk.members(with_locator)

    def test_sizes_ratio_and_aggregate_are_refusal_flags(self):
        data, _ = zip_bytes([('x', b'12345'), ('y', b'67890')])
        with patch.object(apk, 'MAX_CHILD_BYTES', 4):
            self.assertTrue(all('too_large' in m.flags for m in apk.members(data)))
        with patch.object(apk, 'MAX_TOTAL_BYTES', 9):
            self.assertTrue(all('too_large' in m.flags for m in apk.members(data)))
        bomb, _ = zip_bytes([('zeros', bytes(10000))], method=8)
        self.assertIn('ratio', apk.members(bomb)[0].flags)
        with self.assertRaises(apk.ApkError):
            apk.materialize(bomb, apk.members(bomb)[0])

    def test_chunked_inflate_is_capped_and_agrees_with_contract(self):
        child = bytes(range(251)) * 8
        data, _ = zip_bytes([('x', child)], method=8)
        member, = apk.members(data)
        real, calls = zlib.decompressobj, []

        class BoundedDecoder:
            def __init__(self, *args):
                self.inner = real(*args)

            def decompress(self, value, limit):
                calls.append(limit)
                return self.inner.decompress(value, limit)

            def __getattr__(self, key):
                return getattr(self.inner, key)

        with patch.object(apk, 'INFLATE_CHUNK', 7), patch.object(apk.zlib, 'decompressobj', BoundedDecoder):
            self.assertEqual(apk.materialize(data, member)[0], child)
        self.assertGreater(len(calls), 100)
        self.assertTrue(all(0 < value <= 7 for value in calls))
        self.assertEqual(materialize(data, apk.artifact(member, child)), child)

    def test_corrupt_crc_deflate_size_trailing_and_forged_identity_fail_closed(self):
        for method in (0, 8):
            child = bytes(range(251)) * 2
            data, layout = zip_bytes([('x', child)], method=method)
            cd, offset = layout['cd'], layout['rows'][0]['data']
            crc = changed(changed(data, 14, '<I', 1), cd + 16, '<I', 1)
            corrupt = changed(data, offset, '<B', data[offset] ^ 255)
            for bad in (crc, corrupt):
                with self.subTest(method=method, bad=bad[offset]):
                    with self.assertRaises(apk.ApkError):
                        apk.materialize(bad, apk.members(bad)[0])
                    self.assertEqual(run('inventory', bad)[0].value['flags'], ['crc'])
                    self.assertIsNone(run('inventory', bad)[0].value['sha256'])
            member, = apk.members(data)
            for field, value in (('data_offset', offset + 1), ('crc32', 1), ('name', '../x'), ('size', 1)):
                forged = replace(member, **{field if field != 'size' else 'uncompressed_size': value})
                with self.assertRaises(apk.ApkError):
                    apk.materialize(data, forged)
        data, layout = zip_bytes([('x', child)], method=8, gap=b'x')
        packed = layout['rows'][0]['end'] - layout['rows'][0]['data']
        for size in (packed - 1, packed + 1):
            bad = changed(changed(data, 18, '<I', size), layout['cd'] + 20, '<I', size)
            with self.assertRaises(apk.ApkError):
                apk.materialize(bad, apk.members(bad)[0])
        bad = changed(changed(data, 22, '<I', len(child) - 1), layout['cd'] + 24, '<I', len(child) - 1)
        with self.assertRaisesRegex(apk.ApkError, 'declared size'):
            apk.materialize(bad, apk.members(bad)[0])

    def test_malformed_directory_keeps_only_the_valid_prefix_and_never_overreads(self):
        data, layout = zip_bytes([('x', b'value'), ('y', b'other')])
        truncated = changed(data, layout['rows'][1]['central'] + 28, '<H', 5000)
        self.assertEqual([m.name for m in apk.members(truncated)], ['x'])
        for at in range(len(data)):
            with self.subTest(at=at):
                try:
                    apk.members(data[:at])
                except apk.ApkError:
                    pass


class BinaryManifestTests(unittest.TestCase):
    def test_utf8_and_utf16_known_values_offsets_resource_map_and_parents(self):
        for utf8 in (True, False):
            data, layout = manifest_bytes(utf8)
            with self.subTest(utf8=utf8):
                root, permission = apk.binary_manifest(data)
                self.assertEqual((root['name'], root['parent'], root['depth'], root['offset']),
                                 ('manifest', None, 0, layout['root']))
                self.assertEqual((permission['name'], permission['parent'], permission['depth']), ('uses-permission', 0, 1))
                attrs = root['attributes'] + permission['attributes']
                self.assertEqual([a['offset'] for a in attrs], layout['attributes'])
                self.assertEqual([a['length'] for a in attrs], [20] * 7)
                self.assertEqual([(a['type'], a['value']) for a in attrs],
                                 [('string', 'org.reverseai.fixture'), ('int', -7), ('bool', True),
                                  ('reference', '@0x7f010001'), ('other', '0x0000002a'), ('int', 0xbeef),
                                  ('string', 'android.permission.INTERNET')])
                self.assertEqual(attrs[1]['namespace'], apk.ANDROID_NAMESPACE)
                self.assertEqual(attrs[1]['resource_id'], 0x01010008)
                self.assertEqual(attrs[0]['raw_value'], 'org.reverseai.fixture')

    def test_extended_string_lengths_supplementary_characters_and_unknown_chunks(self):
        for utf8, text in ((True, '\U0001f600' * 100), (False, 'x' * 32768)):
            strings = ['manifest', 'value', text]
            unknown = struct.pack('<HHII', 0x7777, 8, 12, 7)
            data = xml_bytes(strings, [unknown, start_element(0, [(NONE, 1, 2, 3, 2)]), end_element(0)], utf8)
            self.assertEqual(apk.binary_manifest(data)[0]['attributes'][0]['value'], text)

    def test_namespace_balance_element_balance_and_duplicate_attributes_are_required(self):
        pool = ['manifest', 'android', apk.ANDROID_NAMESPACE, 'value']
        cases = [[start_element(0)], [end_element(0)], [start_element(0), end_element(3)],
                 [start_element(0), end_element(0), start_element(0), end_element(0)],
                 [start_element(0, [(2, 3, NONE, 16, 1)]), end_element(0)],
                 [node(0x101, struct.pack('<II', 1, 2)), start_element(0), end_element(0)],
                 [node(0x100, struct.pack('<II', 1, 2)), start_element(0), end_element(0)],
                 [start_element(0, [(NONE, 3, NONE, 16, 1)] * 2), end_element(0)]]
        for chunks in cases:
            with self.subTest(chunks=chunks):
                with self.assertRaises(apk.ApkError):
                    apk.binary_manifest(xml_bytes(pool, chunks))

    def test_chunk_and_attribute_bounds_and_pool_indexes_are_checked(self):
        data, layout = manifest_bytes()
        root, attr = layout['root'], layout['attributes'][0]
        for at, fmt, value in ((0, '<H', 1), (2, '<H', 4), (4, '<I', len(data) - 4), (10, '<H', 12),
                               (root + 4, '<I', 0), (root + 24, '<H', 19), (root + 26, '<H', 16),
                               (root + 28, '<H', 5000), (root + 30, '<H', 5000),
                               (attr + 4, '<I', NONE), (attr + 8, '<I', 1000), (attr + 12, '<H', 7),
                               (attr + 14, '<B', 1), (attr + 16, '<I', 1000), (root + 20, '<I', NONE),
                               (8 + 28, '<I', NONE)):
            with self.subTest(at=at):
                with self.assertRaises(apk.ApkError):
                    apk.binary_manifest(changed(data, at, fmt, value))
        for at in range(len(data)):
            try:
                apk.binary_manifest(data[:at])
            except apk.ApkError:
                pass

    def test_string_terminators_lengths_and_encodings_are_checked(self):
        for utf8 in (True, False):
            data = xml_bytes(['manifest'], [start_element(0), end_element(0)], utf8)
            start = 8 + 28 + 4
            width = 1 if utf8 else 2
            terminator = start + (2 if utf8 else 2) + len('manifest') * width
            for bad in (changed(data, start, '<B', 100), changed(data, terminator, '<B', 1),
                        changed(data, start + 2, '<H', 0xd800) if not utf8 else changed(data, start + 2, '<B', 255)):
                with self.subTest(utf8=utf8):
                    with self.assertRaises(apk.ApkError):
                        apk.binary_manifest(bad)

    def test_depth_chunk_attribute_string_and_input_limits(self):
        strings = ['manifest', 'value']
        nested = xml_bytes(strings, [start_element(0)] * 3 + [end_element(0)] * 3)
        self.assertEqual(len(apk.binary_manifest(nested)), 3)
        with patch.object(apk, 'MAX_XML_DEPTH', 2), self.assertRaises(apk.ApkError):
            apk.binary_manifest(nested)
        with patch.object(apk, 'MAX_XML_ENTRIES', 2), self.assertRaises(apk.ApkError):
            apk.binary_manifest(nested)
        # Reach the aggregate attribute guard before the independent string/chunk guards.
        attrs = [(NONE, index, NONE, 16, index) for index in range(1, 5)]
        many = xml_bytes(['manifest', 'a', 'b', 'c', 'd'],
                         [start_element(0, attrs)] * 3 + [end_element(0)] * 3)
        with patch.object(apk, 'MAX_XML_ENTRIES', 8), self.assertRaisesRegex(apk.ApkError, 'Too many.*attributes'):
            apk.binary_manifest(many)
        pool = xml_bytes(['manifest', 'a', 'b'], [start_element(0), end_element(0)])
        with patch.object(apk, 'MAX_XML_ENTRIES', 2), self.assertRaisesRegex(apk.ApkError, 'Too many.*strings'):
            apk.binary_manifest(pool)
        data = xml_bytes(['manifest', '\u0800' * 180], [start_element(0), end_element(0)], False)
        self.assertLess(len(data), 512)
        with patch.object(apk, 'MAX_CHILD_BYTES', 512), self.assertRaisesRegex(apk.ApkError, 'strings exceed'):
            apk.binary_manifest(data)
        with patch.object(apk, 'MAX_CHILD_BYTES', len(data) - 1), self.assertRaises(apk.ApkError):
            apk.binary_manifest(data)

    def test_resource_maps_pool_shape_and_declared_utf16_units_are_checked(self):
        simple = xml_bytes(['manifest'], [start_element(0), end_element(0)])
        start = 8 + 28 + 4
        with self.assertRaisesRegex(apk.ApkError, 'length differs'):
            apk.binary_manifest(changed(simple, start, '<B', 7))
        for offset, fmt, value in ((8 + 8, '<I', 65537), (8 + 20, '<I', 27), (8 + 24, '<I', len(simple)),
                                   (8 + 12, '<I', 1), (8 + 28, '<I', NONE)):
            with self.subTest(offset=offset), self.assertRaises(apk.ApkError):
                apk.binary_manifest(changed(simple, offset, fmt, value))
        # A resource map may occur once, before elements, and cannot exceed its string pool.
        mapping = struct.pack('<HHII', 0x180, 8, 12, 0x01010000)
        for chunks in ([mapping, mapping, start_element(0), end_element(0)],
                       [start_element(0), mapping, end_element(0)],
                       [mapping + bytes(4), start_element(0), end_element(0)]):
            with self.subTest(chunks=chunks), self.assertRaises(apk.ApkError):
                apk.binary_manifest(xml_bytes(['manifest'], chunks))

    def test_string_pool_aliases_are_decoded_once_with_bounded_scan(self):
        raw = b'\x08\x08manifest\x00\x00'
        start = 28 + 40 * 4
        pool = struct.pack('<HHI5I', 1, 28, start + len(raw), 40, 0, 0x100, start, 0) + bytes(40 * 4) + raw
        body = pool + start_element(0) + end_element(0)
        data = struct.pack('<HHI', 3, 8, 8 + len(body)) + body
        # Forty offsets alias one string; charging each alias would exceed this 280-byte input.
        with patch.object(apk, 'MAX_CHILD_BYTES', len(data)):
            self.assertEqual(apk.binary_manifest(data)[0]['name'], 'manifest')

    def test_seeded_mutations_only_return_bounded_rows_or_contract_errors(self):
        rng = random.Random(71)
        for data, parser in ((manifest_bytes()[0], apk.binary_manifest), (zip_bytes([('x', b'value')])[0], apk.members)):
            for _ in range(160):
                at = rng.randrange(len(data))
                bad = changed(data, at, '<B', rng.randrange(256))
                try:
                    rows = parser(bad)
                    self.assertLessEqual(len(rows), 65536)
                except apk.ApkError:
                    pass


class ApkOperationTests(unittest.TestCase):
    def test_long_dex_names_are_reviewed_refusals_and_never_read_by_dex_operations(self):
        from reverseai.tools import dex
        child, _ = shared.classes2_dex()
        for size in (255, 256):
            name = 'classes' + 'x' * (size - 11) + '.dex'
            data, _ = zip_bytes([(name, child)])
            with self.subTest(size=size):
                input_ref = InputRef(sha256_hex(data), len(data), 'synthetic.apk')
                task = AnalysisTask(content_id('tk', {'long_name': size}), 'structural', input_ref,
                                    (OperationRequest('apk.inventory'),), Budget())
                result = Gateway((apk.TOOL,), Budget()).run(task, data)
                self.assertEqual(result.status, 'ok', result)
                evidence, = result.evidence
                self.assertEqual(evidence.observation['flags'], ['long_name'] if size > 255 else [])
                value = claims.RULES['android.members'][1]['apk.inventory']([evidence.observation])
                self.assertIsNotNone(value)
                finding = make_finding('structural', claims.statement('android.members'), 'android.members',
                                       value, [evidence.id], 'observed')
                final = AnalysisResult(task.id, 'structural', 'ok', result.evidence, (finding,))
                self.assertEqual([v.status for v in review(data, input_ref, [final], {'apk': apk.TOOL})], ['supported'])
                for operation, args in (('dex.classes', {}), ('dex.methods', {'class': shared.WORKER}),
                                        ('dex.references', {'class': shared.WORKER, 'method': 'run'})):
                    spec = dex.TOOL.operations[operation]
                    with patch.object(apk, '_materialize', wraps=apk._materialize) as inflate:
                        if size > 255:
                            with self.assertRaises(dex.DexError):
                                spec.handler(data, spec.validate_args(args))
                            inflate.assert_not_called()
                        else:
                            self.assertTrue(spec.handler(data, spec.validate_args(args)))
                            inflate.assert_called_once()

    def test_inventory_reuses_one_parse_and_preserves_rows_on_clean_and_hostile_pages(self):
        for builder in (shared.apk_basic, lambda: shared.apk_hostile('crc'),
                        lambda: shared.apk_hostile('descriptor_mismatch'), shared.apk_signing_block):
            data, _ = builder()
            parsed = apk.members(data)
            # Expected rows use the existing public identity-checking path, independent of reuse.
            expected = []
            for index, member in enumerate(parsed):
                digest, flags = None, list(member.flags)
                if not flags:
                    try:
                        _, digest = apk.materialize(data, member)
                    except apk.ApkError:
                        flags = ['crc']
                expected.append((Location(member.central_offset, min(member.central_length, 4096)),
                                 dict(kind='member', index=index, total=len(parsed), name=apk.escape(member.name),
                                      method=member.method, compressed_size=member.compressed_size, size=member.size,
                                      crc32=member.crc32, sha256=digest, flags=flags)))
            for start, limit in ((0, 256), (1, 2), (len(parsed), 1)):
                with self.subTest(builder=builder, start=start, limit=limit):
                    with patch.object(apk, 'members', wraps=apk.members) as parse:
                        rows = run('inventory', data, start=start, limit=limit)
                    self.assertEqual([(o.location, o.value) for o in rows], expected[start:start + limit])
                    self.assertEqual(parse.call_count, 1)

    def test_shared_fixture_members_and_manifest_match_declared_layouts(self):
        for builder in (shared.apk_basic, lambda: shared.apk_basic(True), shared.apk_signing_block):
            data, layout = builder()
            members = apk.members(data)
            self.assertEqual(len(members), len(layout['members']))
            for member, expected in zip(members, layout['members']):
                self.assertEqual(member.flags, ())
                self.assertEqual((member.name, member.zip_flags, member.method, member.crc32, member.size,
                                  member.compressed_size, member.data_offset, member.central_offset, member.central_length),
                                 tuple(expected[k] for k in ('name', 'flags', 'method', 'crc32', 'size', 'compressed_size',
                                                            'data_offset', 'central_offset', 'central_length')))
                child, digest = apk.materialize(data, member)
                self.assertEqual(digest, expected['sha256'])
                self.assertEqual(apk.artifact(member, child), expected['artifact'])
                self.assertEqual(materialize(data, expected['artifact']), child)
            expected_attrs = layout['manifest']['attributes']
            attrs = run('manifest', data)
            self.assertEqual([(o.location.offset, o.location.length) for o in attrs],
                             [(a['offset'], a['length']) for a in expected_attrs])
            self.assertEqual([o.value for o in attrs], [dict(kind='manifest_attribute', total=len(expected_attrs),
                             **{k: a[k] for k in ('index', 'element_index', 'element', 'attribute', 'type', 'value')})
                             for a in expected_attrs])

    def test_shared_hostile_archive_expectations(self):
        for kind, (expected_flags, refused) in shared.HOSTILE_KINDS.items():
            with self.subTest(kind=kind):
                data, layout = shared.apk_hostile(kind)
                if refused:
                    with self.assertRaises(apk.ApkError):
                        apk.members(data)
                    continue
                rows = run('inventory', data)
                anomaly = layout['anomaly']
                if kind == 'truncated_central':
                    self.assertEqual(len(rows), anomaly['complete_entries'])
                for index in anomaly.get('members', [anomaly['member']]):
                    if index is not None:
                        self.assertEqual(rows[index].value['flags'], expected_flags)
                        self.assertEqual(rows[index].value['sha256'], None if expected_flags else
                                         layout['members'][index]['sha256'])

    def test_operation_bounds_registration_and_paging(self):
        self.assertEqual(set(apk.TOOL.operations), {'apk.inventory', 'apk.manifest'})
        for name, spec in apk.TOOL.operations.items():
            self.assertFalse(spec.derived)
            self.assertEqual(spec.max_observations, 256)
            for args in ({'limit': 0}, {'limit': 257}, {'start': -1}, {'start': 65536}, {'extra': 1}):
                with self.subTest(name=name, args=args), self.assertRaises(ContractError):
                    spec.validate_args(args)
        child, _ = manifest_bytes()
        data, layout = zip_bytes([('first', b'hello'), ('AndroidManifest.xml', child), ('last', b'world')])
        rows = run('inventory', data, start=1, limit=1)
        self.assertEqual([o.value['index'] for o in rows], [1])
        self.assertEqual(rows[0].value['total'], 3)
        self.assertEqual(rows[0].location, Location(layout['rows'][1]['central'], 65))
        self.assertEqual(run('inventory', data, start=3), [])
        all_attrs = run('manifest', data)
        self.assertEqual(len(all_attrs), 7)
        self.assertEqual(run('manifest', data, start=2, limit=3), all_attrs[2:5])
        self.assertEqual(run('manifest', data, start=7), [])
        self.assertEqual(run('manifest', zip_bytes([('x', b'value')])[0]), [])
        duplicate, _ = zip_bytes([('AndroidManifest.xml', child)] * 2)
        with self.assertRaises(apk.ApkError):
            run('manifest', duplicate)

    def test_real_gateway_and_reviewer_bind_inventory_and_child_attribute_bytes(self):
        child, layout = manifest_bytes()
        for method in (0, 8):
            data, _ = zip_bytes([('AndroidManifest.xml', child), ('', b'unsafe')], method=method)
            input_ref = InputRef(sha256_hex(data), len(data), 'synthetic.apk')
            task = AnalysisTask(content_id('tk', {'apk': method}), 'structural', input_ref,
                                (OperationRequest('apk.inventory'), OperationRequest('apk.manifest')), Budget())
            result = Gateway((apk.TOOL,), Budget()).run(task, data)
            self.assertEqual(result.status, 'ok', result)
            self.assertEqual(len(result.evidence), 9)
            inventory = tuple(e for e in result.evidence if e.operation == 'apk.inventory')
            attrs = tuple(e for e in result.evidence if e.operation == 'apk.manifest')
            self.assertTrue(all(e.artifact is None for e in inventory))
            self.assertEqual(inventory[1].observation['name'], '')
            self.assertEqual(inventory[1].observation['flags'], ['traversing_name'])
            self.assertEqual([e.location for e in attrs], [Location(at, 20) for at in layout['attributes']])
            self.assertTrue(all(e.artifact['member'] == 'AndroidManifest.xml' for e in attrs))
            self.assertEqual([e.excerpt_sha256 for e in attrs],
                             [sha256_hex(child[at:at + 20]) for at in layout['attributes']])
            findings = []
            for operation, key, evidence in (('apk.inventory', 'android.members', inventory),
                                              ('apk.manifest', 'android.manifest', attrs)):
                value = claims.RULES[key][1][operation]([e.observation for e in evidence])
                findings.append(make_finding('structural', claims.statement(key), key, value,
                                             [e.id for e in evidence], 'observed'))
            key = 'android.permissions'
            findings.append(make_finding('structural', claims.statement(key), key, ['android.permission.INTERNET'],
                                         [attrs[-1].id], 'observed'))
            final = AnalysisResult(task.id, 'structural', 'ok', result.evidence, tuple(findings))
            self.assertEqual([v.status for v in review(data, input_ref, [final], {'apk': apk.TOOL})],
                             ['supported'] * 3)


if __name__ == '__main__':
    unittest.main()
