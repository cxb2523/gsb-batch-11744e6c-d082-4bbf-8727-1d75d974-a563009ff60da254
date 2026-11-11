"""Inert byte-built archives; tarfile is used only to construct fixtures."""

import gzip
import io
from dataclasses import replace
import struct
import tarfile
import unittest
from unittest.mock import patch
import zlib

from reverseai.contract import ContractError, inflate_stream, materialize, sha256_hex
from reverseai.tools import js, tarball
from tests import fixtures_tgz as shared


def gzip_bytes(body, *, flags=0, extra=b'', name=b'', comment=b'', level=0):
    header = tarball.MAGIC + bytes((8, flags)) + b'\0' * 4 + b'\0\xff'
    if flags & 4:
        header += struct.pack('<H', len(extra)) + extra
    if flags & 8:
        header += name + b'\0'
    if flags & 16:
        header += comment + b'\0'
    if flags & 2:
        header += struct.pack('<H', zlib.crc32(header) & 0xffff)
    compressor = zlib.compressobj(level, zlib.DEFLATED, -15)
    return header + compressor.compress(body) + compressor.flush() + struct.pack(
        '<II', zlib.crc32(body), len(body))


def tar_bytes(entries, *, format=tarfile.USTAR_FORMAT, pax_headers=None):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=format, pax_headers=pax_headers) as archive:
        for name, body in entries:
            member = tarfile.TarInfo(name)
            member.size = len(body)
            archive.addfile(member, io.BytesIO(body))
    return output.getvalue()


def checksum(block):
    result = bytearray(block)
    result[148:156] = b'        '
    result[148:156] = ('%06o\0 ' % sum(result)).encode('ascii')
    return bytes(result)


def record(name='package/a.js', body=b'', *, kind=b'0', link=''):
    info = tarfile.TarInfo(name)
    info.type, info.size, info.linkname = kind, len(body), link
    header = info.tobuf(format=tarfile.USTAR_FORMAT)
    return header + body + b'\0' * (-len(body) % 512)


def pax(key, value):
    tail = key + b'=' + value + b'\n'
    length = len(tail) + 2
    while len(str(length)) + 1 + len(tail) != length:
        length = len(str(length)) + 1 + len(tail)
    return str(length).encode() + b' ' + tail


def packed(*records, tail=b'\0' * 1024):
    return gzip_bytes(b''.join(records) + tail)


class GzipTests(unittest.TestCase):
    def test_optional_header_fields_and_header_crc(self):
        body = bytes(range(256)) * 8
        data = gzip_bytes(body, flags=31, extra=b'AB\x03\0xyz',
                          name=b'package.tar', comment=b'inert fixture')
        self.assertEqual(tarball.gzip_header(data), 47)
        self.assertEqual(tarball._inflate(data), body)
        self.assertEqual(tarball._inflate(gzip.compress(body, mtime=0)), body)
        self.assertEqual(tarball._inflate(gzip_bytes(body, flags=4, extra=b'x')), body)
        damaged = bytearray(data)
        damaged[8] ^= 1
        with self.assertRaises(tarball.TarballError):
            tarball._inflate(bytes(damaged))

    def test_header_rejects_bad_magic_method_reserved_flags_and_optional_fields(self):
        valid = gzip_bytes(b'fixture')
        cases = [b'', b'\x1f\x8b', valid[:17], valid[:3] + b'\x20' + valid[4:]]
        for at in (0, 1, 2):
            changed = bytearray(valid)
            changed[at] ^= 1
            cases.append(bytes(changed))
        cases += [valid[:3] + b'\x04' + valid[4:10] + b'\xff\xff' + valid[10:],
                  valid[:3] + b'\x08' + valid[4:10] + b'n' * 20 + valid[-8:],
                  valid[:3] + b'\x10' + valid[4:10] + b'n' * 20 + valid[-8:]]
        for data in cases:
            with self.subTest(data=data[:20]):
                with self.assertRaises(tarball.TarballError):
                    tarball._inflate(data)

    def test_deflate_trailer_and_single_member_are_checked(self):
        valid = gzip_bytes(bytes(range(256)) * 512)
        cases = [valid[:-1], valid[:-8], valid + b'\0', valid + valid,
                 valid[:10] + b'\x07' + valid[11:]]
        for at in (-8, -4):
            changed = bytearray(valid)
            changed[at] ^= 1
            cases.append(bytes(changed))
        for data in cases:
            with self.subTest(length=len(data), tail=data[-8:]):
                with self.assertRaises(tarball.TarballError):
                    tarball._inflate(data)

    def test_prefix_stops_at_the_requested_output_and_does_not_certify_the_tail(self):
        body = bytes(range(256)) * 4096
        data = gzip_bytes(body)
        damaged = data[:-8] + b'\0' * 8
        original = zlib.decompressobj
        produced, requests = [], []

        class Spy:
            def __init__(self, *args):
                self.reader = original(*args)

            def __getattr__(self, name):
                return getattr(self.reader, name)

            def decompress(self, block, maximum):
                requests.append(maximum)
                result = self.reader.decompress(block, maximum)
                produced.append(len(result))
                return result

        with patch.object(tarball.zlib, 'decompressobj', Spy):
            self.assertEqual(tarball.read_prefix(damaged, 513), body[:513])
        self.assertEqual(sum(produced), 513)
        self.assertLessEqual(max(requests), 513)
        with self.assertRaises(tarball.TarballError):
            tarball._inflate(damaged)

    def test_prefix_bounds_and_short_input(self):
        data = gzip_bytes(b'inert')
        self.assertEqual(tarball.read_prefix(data, 0), b'')
        self.assertEqual(tarball.read_prefix(data, 5), b'inert')
        for size in (-1, True, 1.5, 6, tarball.MAX_TAR_BYTES + 1):
            with self.subTest(size=size):
                with self.assertRaises(tarball.TarballError):
                    tarball.read_prefix(data, size)

    def test_bomb_stops_at_ratio_and_absolute_limits(self):
        data = gzip_bytes(b'A' * 1024 * 1024, level=9)
        reader = tarball._GzipReader(data)
        with self.assertRaises(tarball.TarballError):
            while not reader.eof:
                reader.read(tarball.INFLATE_CHUNK)
        self.assertEqual(reader.total, len(data) * 100 + 1)
        data = gzip_bytes(b'A' * 4096)
        with patch.object(tarball, 'MAX_TAR_BYTES', 1024):
            reader = tarball._GzipReader(data)
            with self.assertRaises(tarball.TarballError):
                reader.read(1025)
            self.assertEqual(reader.total, 1025)

    def test_exact_limit_finishes_without_false_refusal(self):
        body = b'X' * 1024
        with patch.object(tarball, 'MAX_TAR_BYTES', len(body)):
            self.assertEqual(tarball._inflate(gzip_bytes(body)), body)

    def test_input_type_and_size_are_bounded(self):
        valid = gzip_bytes(b'inert')
        for data in (None, bytearray(valid), 'not bytes'):
            with self.subTest(kind=type(data).__name__):
                with self.assertRaises(tarball.TarballError):
                    tarball.gzip_header(data)
        with patch.object(tarball, 'MAX_INPUT_BYTES', len(valid) - 1):
            with self.assertRaises(tarball.TarballError):
                tarball.gzip_header(valid)


class TarFramingTests(unittest.TestCase):
    def test_ustar_prefix_gnu_magic_and_sizes(self):
        data = tar_bytes([('package/' + 'subdir/' * 15 + 'index.js', b'inert')])
        self.assertEqual(tarball._header(data[:512]),
                         (b'package/' + b'subdir/' * 15 + b'index.js', b'0', 5))
        data = tar_bytes([('package/index.js', b'inert')], format=tarfile.GNU_FORMAT)
        self.assertEqual(tarball._header(data[:512]), (b'package/index.js', b'0', 5))
        changed = bytearray(data[:512])
        changed[124:136] = b'\x80' + b'\0' * 10 + b'\x05'
        self.assertEqual(tarball._header(checksum(changed))[2], 5)

    def test_checksum_magic_and_number_refusals(self):
        valid = tar_bytes([('package/a.js', b'inert')])[:512]
        changed = bytearray(valid)
        changed[0] ^= 1
        cases = [bytes(changed), valid[:-1]]
        for start, replacement in ((257, b'wrong!!!'), (124, b'-0000000001\0'),
                                   (124, b'00000000008\0'),
                                   (124, b'\xff' * 12), (124, b'12\0garbage  ')):
            changed = bytearray(valid)
            changed[start:start + len(replacement)] = replacement
            cases.append(checksum(changed))
        for data in cases:
            with self.subTest(header=data[124:136]):
                with self.assertRaises(tarball.TarballError):
                    tarball._header(data)

    def test_pax_length_is_bytes_and_values_can_include_newlines(self):
        # Use an independently counted record and an opaque value with an embedded newline.
        body = b'14 path=\xc3\xa9.js\n' + b'12 note=a\nb\n'
        self.assertEqual(tarball._pax(body), {b'path': b'\xc3\xa9.js', b'note': b'a\nb'})

    def test_pax_malformed_framing_never_leaks_a_conversion_error(self):
        for body in (b'x path=a\n', b'9999999999999999 x=a\n', b'0 x=a\n',
                     b'100 path=a\n', b'9 path=aX', b'8 badxx\n', b'6 =ab\n',
                     b'9 path=a\n9 path=b\n', b'9 path=a\n\0'):
            with self.subTest(body=body):
                with self.assertRaises(tarball.TarballError):
                    tarball._pax(body)


class TarballTests(unittest.TestCase):
    def test_known_members_materialization_and_method_one_artifacts(self):
        data = packed(record(body=b'fetch(1);'), record('package/empty.js'),
                      record('package/lib/b.js', b'xx'))
        rows = tarball.members(data)
        self.assertEqual([(m.name, m.type, m.size, m.header_offset, m.data_offset, m.flags) for m in rows], [
            ('package/a.js', '0', 9, 0, 512, ()),
            ('package/empty.js', '0', 0, 1024, 1536, ()),
            ('package/lib/b.js', '0', 2, 1536, 2048, ()),
        ])
        self.assertIs(rows[0]._stream, rows[2]._stream)
        for member, expected in zip(rows, (b'fetch(1);', b'', b'xx')):
            self.assertEqual(tarball.materialize(data, member), (expected, sha256_hex(expected)))
            if expected:
                artifact = tarball.artifact(member, expected)
                self.assertEqual(artifact, dict(member=member.name, method=1, data_offset=0,
                    compressed_size=len(data), inner_offset=member.data_offset, size=len(expected),
                    crc32=zlib.crc32(expected), sha256=sha256_hex(expected)))
                self.assertEqual(materialize(data, artifact), expected)
        self.assertEqual(materialize(data, tarball.header_artifact(rows[1])),
                         record('package/empty.js')[:512])

    def test_pax_and_gnu_names_and_size_apply_only_to_the_next_member(self):
        long = 'package/' + 'subdir/' * 30 + 'index.js'
        for format in (tarfile.PAX_FORMAT, tarfile.GNU_FORMAT):
            data = gzip_bytes(tar_bytes([(long, b'xx'), ('package/a.js', b'y')], format=format))
            rows = tarball.members(data)
            self.assertEqual([(m.name, m.size, m.flags) for m in rows], [(long, 2, ()), ('package/a.js', 1, ())])
            self.assertEqual(tarball.materialize(data, rows[0])[0], b'xx')
        extension = record('PaxHeader', pax(b'path', b'package/renamed.js') + pax(b'size', b'0' * 5000 + b'3'), kind=b'x')
        # The pax size, not the placeholder header size, locates the next header.
        declared_zero = record()
        data = packed(extension, declared_zero + b'abc' + bytes(509), record('package/next.js', b'd'))
        self.assertEqual([(m.name, m.size) for m in tarball.members(data)],
                         [('package/renamed.js', 3), ('package/next.js', 1)])

    def test_links_devices_unknown_types_and_directories(self):
        data = packed(record('package/', kind=b'5'), record('package/s.js', kind=b'2', link='a.js'),
                      record('package/h.js', kind=b'1', link='a.js'), record('package/device.js', kind=b'3'),
                      record('package/fifo.js', kind=b'6'), record('package/unknown.js', b'abc', kind=b'?'),
                      record('package/contiguous.js', b'x', kind=b'7'))
        rows = tarball.members(data)
        self.assertEqual([(m.name, m.flags) for m in rows], [
            ('package/s.js', ('symlink',)), ('package/h.js', ('hardlink',)),
            ('package/device.js', ('unsupported_type',)), ('package/fifo.js', ('unsupported_type',)),
            ('package/unknown.js', ('unsupported_type',)), ('package/contiguous.js', ()),
        ])
        for member in rows[:-1]:
            with self.assertRaises(tarball.TarballError):
                tarball.materialize(data, member)
        for kind in (b'1', b'2', b'3', b'4', b'5', b'6'):
            with self.subTest(kind=kind):
                with self.assertRaises(tarball.TarballError):
                    tarball.members(packed(record(body=b'x', kind=kind)))

    def test_unsafe_empty_long_duplicate_and_invalid_utf8_names_are_disclosed(self):
        names = ('../bad.js', '/absolute.js', 'C:drive.js', 'package//a.js', 'package/./a.js',
                 'package/../a.js', 'package\\a.js', '', 'package/\x1b.js',
                 'package/\u202e.js')
        for name in names:
            with self.subTest(name=name):
                member = tarball.members(packed(record(name)))[0]
                self.assertIn('traversing_name', member.flags)
        data = gzip_bytes(tar_bytes([('p/' + 'a' * 253, b''), ('p/' + 'a' * 254, b'')],
                                    format=tarfile.PAX_FORMAT))
        rows = tarball.members(data)
        self.assertEqual(rows[0].flags, ('duplicate_name',))
        self.assertEqual(rows[1].flags, ('duplicate_name', 'long_name'))
        raw = bytearray(record())
        raw[:13] = b'package/\xff.js\0'
        raw[:512] = checksum(raw[:512])
        member = tarball.members(packed(bytes(raw)))[0]
        self.assertIn('header_mismatch', member.flags)
        self.assertIn('traversing_name', member.flags)
        self.assertIn('\\xff', member.name)
        # Invalid link text is also disclosed safely, never followed.
        raw = bytearray(record(kind=b'2'))
        raw[157:160] = b'\xffx\0'
        raw[:512] = checksum(raw[:512])
        self.assertIn('header_mismatch', tarball.members(packed(bytes(raw)))[0].flags)

    def test_invalid_link_text_only_flags_links_and_keeps_pax_byte_bounds(self):
        for kind, body, flags in ((b'0', b'inert', ()),
                                  (b'1', b'', ('hardlink', 'header_mismatch')),
                                  (b'2', b'', ('header_mismatch', 'symlink'))):
            with self.subTest(kind=kind):
                raw = bytearray(record(body=body, kind=kind))
                raw[157:159] = b'\xff\0'
                raw[:512] = checksum(raw[:512])
                data = packed(bytes(raw))
                member, = tarball.members(data)
                self.assertEqual(member.flags, flags)
                if not flags:
                    self.assertEqual(tarball.materialize(data, member)[0], body)
                else:
                    with self.assertRaises(tarball.TarballError):
                        tarball.materialize(data, member)
        extension = record('Extension', pax(b'linkpath', b'x' * 65536), kind=b'x')
        with self.assertRaises(tarball.TarballError):
            tarball.members(packed(extension, record(body=b'inert')))

    def test_signed_checksum_and_nul_regular_file(self):
        raw = bytearray(record('package/é.js', b'x', kind=b'\0'))
        raw[148:156] = b'        '
        value = sum(byte if byte < 128 else byte - 256 for byte in raw[:512])
        raw[148:156] = ('%06o\0 ' % value).encode()
        member = tarball.members(packed(bytes(raw)))[0]
        self.assertEqual((member.name, member.type, member.flags), ('package/é.js', '\0', ()))

    def test_end_markers_and_complete_header_and_data_are_required(self):
        valid = record(body=b'abc')
        self.assertEqual(tarball.members(packed()), ())
        self.assertEqual(len(tarball.members(packed(valid, tail=bytes(1027)))), 1)
        for data in (packed(valid, tail=b''), packed(valid, tail=bytes(512)),
                     packed(valid, tail=bytes(1024) + b'x'), packed(valid[:511]),
                     packed(valid[:513], tail=b''), packed(valid, tail=bytes(512) + record())):
            with self.subTest(size=len(data)):
                with self.assertRaises(tarball.TarballError):
                    tarball.members(data)

    def test_pax_and_gnu_extensions_refuse_unsupported_or_dangling_metadata(self):
        cases = [(b'x', pax(b'path', b'a') + pax(b'path', b'a')),
                 (b'x', pax(b'hdrcharset', b'BINARY')), (b'x', pax(b'GNU.sparse.map', b'1,2')),
                 (b'g', pax(b'path', b'a')), (b'x', pax(b'size', b'-1')),
                 (b'x', pax(b'size', b'1.0')), (b'x', pax(b'size', b'9' * 10000)),
                 (b'L', b'nonterminated'), (b'K', b'name\0garbage')]
        for kind, body in cases:
            with self.subTest(kind=kind, body=body[:40]):
                with self.assertRaises(tarball.TarballError):
                    tarball.members(packed(record('Extension', body, kind=kind), record()))
        for kind in (b'x', b'g', b'L', b'K'):
            body = b'name\0' if kind in (b'L', b'K') else pax(b'comment', b'inert')
            with self.subTest(dangling=kind):
                with self.assertRaises(tarball.TarballError):
                    tarball.members(packed(record('Extension', body, kind=kind)))
        for kind in (b'S', b'M', b'V'):
            with self.subTest(kind=kind):
                with self.assertRaises(tarball.TarballError):
                    tarball.members(packed(record(kind=kind)))
        data = packed(record('Global', pax(b'comment', b'inert'), kind=b'g'),
                      record('Local', pax(b'hdrcharset', b'UTF-8') + pax(b'ignored', b'yes'), kind=b'x'),
                      record())
        self.assertEqual(tarball.members(data)[0].name, 'package/a.js')

    def test_physical_header_and_extension_and_name_budgets(self):
        self.assertEqual(tarball.MAX_MEMBERS, 65536)
        data = packed(record('package/', kind=b'5'), record('Extension', pax(b'comment', b'x'), kind=b'x'),
                      record())
        with patch.object(tarball, 'MAX_MEMBERS', 2):
            with self.assertRaises(tarball.TarballError):
                tarball.members(data)
        data = packed(record('L', b'package/a.js\0', kind=b'L'), record())
        with patch.object(tarball, 'MAX_EXTENSION_BYTES', 12):
            with self.assertRaises(tarball.TarballError):
                tarball.members(data)
        data = packed(record('L', b'package/a.js\0', kind=b'L'), record(),
                      record('L', b'package/b.js\0', kind=b'L'), record())
        with patch.object(tarball, 'MAX_TOTAL_EXTENSION_BYTES', 25):
            with self.assertRaises(tarball.TarballError):
                tarball.members(data)
        for kind, body in ((b'L', b'a' * 65536 + b'\0'), (b'K', b'a' * 65536 + b'\0'),
                           (b'x', pax(b'path', b'a' * 65536))):
            with self.subTest(kind=kind):
                with self.assertRaises(tarball.TarballError):
                    tarball.members(packed(record('Extension', body, kind=kind), record()))
        with patch.object(tarball, 'MAX_CHILD_BYTES', 2):
            self.assertEqual(tarball.members(packed(record(body=b'abc')))[0].flags, ('too_large',))

    def test_public_materialization_rechecks_descriptors_and_never_trusts_a_cached_stream(self):
        data = packed(record(body=b'abc'))
        member = tarball.members(data)[0]
        for forged in (replace(member, data_offset=513), replace(member, size=2),
                       replace(member, name='package/forged.js')):
            with self.subTest(forged=forged):
                with self.assertRaises(tarball.TarballError):
                    tarball.materialize(data, forged)
        forged = replace(member, _stream=b'X' * len(member._stream))
        self.assertEqual(tarball.materialize(data, forged)[0], b'abc')
        with self.assertRaises(tarball.TarballError):
            tarball._materialize(bytes(bytearray(data)), member)

    def test_own_inflater_matches_the_contract_on_acceptance_and_refusal(self):
        body = tar_bytes([('package/a.js', b'inert')])
        good = [gzip_bytes(body), gzip_bytes(body, flags=31, extra=b'opaque', name=b'tar', comment=b'x')]
        bad = [good[0] + b'x', good[0] + good[0], good[0][:-1], good[0][:-8] + bytes(8),
               gzip_bytes(bytes(1 << 20), level=9), b'\x1f\x8b\x07' + good[0][3:]]
        for data in good:
            self.assertEqual(tarball._inflate(data), inflate_stream(data, 0, len(data)))
        for data in bad:
            with self.subTest(length=len(data)):
                for inflate in (tarball._inflate, lambda data: inflate_stream(data, 0, len(data))):
                    with self.assertRaises(ContractError):
                        inflate(data)


class JavaScriptTarballTests(unittest.TestCase):
    def test_shared_known_answers_and_hostile_archives(self):
        data, layout = shared.npm_tgz()
        rows = js._files(data, dict(start=0, limit=128))
        self.assertEqual(len(rows), len(layout['files']))
        for index, (row, expected) in enumerate(zip(rows, layout['files'])):
            self.assertEqual(row.value, dict(kind='js_file', index=index, total=len(rows), **expected['row']))
            if expected['data']:
                self.assertEqual(row.artifact['inner_offset'], expected['data_offset'])
                self.assertEqual(materialize(data, row.artifact), expected['data'])
            else:
                self.assertEqual((row.location.offset, row.location.length), (0, 512))
                self.assertEqual(row.artifact['inner_offset'], expected['header_offset'])
        package = js._package(data, dict(file='', start=0, limit=128))
        for index, (row, expected) in enumerate(zip(package, layout['package']['rows'])):
            self.assertEqual(row.value, dict(kind='package_field', index=index, total=len(package), **expected['row']))
            self.assertEqual((row.location.offset, row.location.length), (expected['offset'], expected['length']))
        self.assertEqual(len(package), len(layout['package']['rows']))
        refused = set(shared.HOSTILE_KINDS) - {'symlink', 'hardlink', 'traversal', 'duplicate', 'long_name'}
        for kind in shared.HOSTILE_KINDS:
            with self.subTest(kind=kind):
                data, _ = shared.tgz_hostile(kind)
                if kind in refused:
                    with self.assertRaises(tarball.TarballError):
                        js._members(data, include_flagged=True)
                else:
                    members = js._members(data, include_flagged=True)
                    flag = {'traversal': 'traversing_name', 'duplicate': 'duplicate_name'}.get(kind, kind)
                    self.assertTrue(members)
                    self.assertTrue(all(flag in member.flags for member in members))
                    with patch.object(tarball, '_materialize', side_effect=AssertionError('flagged payload read')):
                        self.assertTrue(js._files(data, dict(start=0, limit=128)))
                        self.assertEqual(js._package(data, dict(file='', start=0, limit=128)), [])
                        self.assertEqual(js._hints(data, dict(file='', category='all', start=0, limit=128)), [])

    def test_parser_prepare_preserves_verified_artifacts_without_reading_empty_or_flagged_data(self):
        from reverseai.tools import jsparser_verify

        data, layout = shared.npm_tgz()
        request, files = jsparser_verify.prepare(data, dict(file='', kind='modules', start=0, limit=128))
        expected = [f for f in layout['files'] if f['data'] and not f['name'].endswith('package.json')]
        self.assertEqual([file.name for file in files], [f['name'] for f in expected])
        self.assertEqual(len(request['files']), len(expected))
        for spec, file in zip(request['files'], files):
            self.assertEqual(spec['artifact']['method'], 1)
            self.assertEqual(materialize(data, spec['artifact']), file.data)

    def test_real_gateway_and_reviewer_accept_child_and_header_anchors(self):
        from reverseai import pipeline
        from reverseai.contract import InputRef

        data = packed(record(body=b'fetch(1);'), record('package/empty.js'),
                      record('package/link.js', kind=b'2', link='../outside'))
        analysis = pipeline.query_bytes(data, InputRef(sha256_hex(data), len(data), 'fixture.tgz'),
            'analyze_javascript_application', {'detail': 'files'}, tools=(js.TOOL,))
        self.assertEqual([result.status for result in analysis.results], ['ok'])
        self.assertEqual([v.status for v in analysis.verdicts], ['supported'])
        self.assertEqual(len(analysis.results[0].evidence), 3)

    def test_files_read_once_and_empty_and_flagged_rows_anchor_the_header(self):
        data = packed(record(body=b'fetch(1);'), record('package/empty.js'),
                      record('package/link.js', kind=b'2', link='../outside'))
        with patch.object(tarball, 'members', wraps=tarball.members) as scan, \
                patch.object(tarball, '_inflate', wraps=tarball._inflate) as inflate, \
                patch.object(tarball, '_materialize', wraps=tarball._materialize) as read:
            rows = js._files(data, dict(start=0, limit=128))
        self.assertEqual((scan.call_count, inflate.call_count, read.call_count), (1, 1, 2))
        self.assertEqual([(r.value['file'], r.value['index'], r.value['total']) for r in rows],
                         [('package/a.js', 0, 3), ('package/empty.js', 1, 3), ('package/link.js', 2, 3)])
        self.assertEqual(rows[0].artifact['inner_offset'], 512)
        self.assertEqual([(r.location.offset, r.location.length, r.artifact['inner_offset']) for r in rows[1:]],
                         [(0, 512, 1024), (0, 512, 1536)])
        self.assertEqual(rows[2].value['flags'], ['symlink'])
        self.assertIsNone(rows[2].value['sha256'])
        for row in rows:
            child = materialize(data, row.artifact)
            self.assertGreaterEqual(len(child), row.location.length)

    def test_shallowest_package_selectors_and_hint_provenance(self):
        data = packed(record('package/node_modules/n/package.json', b'{"name":"nested"}'),
                      record('package/package.json', b'{"name":"outer"}'),
                      record('package/a.js', b"fetch('https://example.test');"))
        args = dict(file='', start=0, limit=128)
        rows = js._package(data, args)
        self.assertEqual([(r.value['file'], r.value['value']) for r in rows], [('package/package.json', 'outer')])
        self.assertEqual(js._package(data, {**args, 'file': 'package.json'}), [])
        self.assertEqual(js._package(data, {**args, 'file': 'package/node_modules/n/package.json'})[0].value['value'],
                         'nested')
        hints = js._hints(data, {**args, 'file': 'package/a.js', 'category': 'all'})
        self.assertTrue(hints)
        for row in hints:
            self.assertEqual(row.artifact['member'], 'package/a.js')
            self.assertIn(b'fetch', materialize(data, row.artifact))

    def test_gzip_magic_never_falls_back_to_raw_and_non_javascript_stays_empty(self):
        data = packed(record('README.md', b'inert'))
        self.assertEqual(js._members(data), ())
        self.assertEqual(js._files(data, dict(start=0, limit=128)), [])
        for data in (b'\x1f\x8b', gzip_bytes(b'raw script'), packed(record(), tail=bytes(512))):
            with self.subTest(data=data[:20]):
                with self.assertRaises(tarball.TarballError):
                    js._members(data)


if __name__ == '__main__':
    unittest.main()
