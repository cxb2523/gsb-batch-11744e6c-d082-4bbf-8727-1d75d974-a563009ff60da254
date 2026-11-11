"""Code-built Electron archives: headers and payloads are inert data."""

from dataclasses import replace
import json
import inspect
import random
import struct
import unittest
from unittest.mock import patch
import zlib

from reverseai import pipeline, report
from reverseai.contract import ContractError, InputRef, materialize, sha256_hex
from reverseai.tools import js, jsonpos

try:
    from reverseai.tools import asar
except ImportError:
    asar = None  # The same regression tests assert the reader is absent on the pre-ASAR base.


def archive(header, body=b'', *, raw=None):
    text = json.dumps(header, ensure_ascii=False, separators=(',', ':')).encode() if raw is None else raw
    padding = b'\0' * (-len(text) % 4)
    payload = 4 + len(text) + len(padding)
    return struct.pack('<IIII', 4, payload + 4, payload, len(text)) + text + padding + body


def app():
    payloads = [b'{"name":"asar-app","scripts":{"postinstall":"node setup.js"}}',
                b'fetch("https://fixture.invalid/");\n', b'eval(text);\n', b'not JavaScript']
    at, entries = 0, []
    for payload in payloads:
        entries.append({'size': len(payload), 'offset': str(at)})
        at += len(payload)
    header = {'files': {'package.json': entries[0], 'src': {'files': {
        'main.js': entries[1], 'café.ts': entries[2]}}, 'data.bin': entries[3]}}
    return archive(header, b''.join(payloads)), payloads


def operation(detail, data, **args):
    op = js.TOOL.operations['js.' + detail]
    return op.handler(data, op.validate_args(args))


class AsarTests(unittest.TestCase):
    def require_reader(self):
        self.assertTrue(callable(getattr(asar, 'members', None)), 'ASAR reader unavailable')

    def test_nested_members_have_exact_order_ranges_hashes_and_stored_artifacts(self):
        self.require_reader()
        data, payloads = app()
        members = asar.members(data)
        self.assertEqual([m.name for m in members], ['package.json', 'src/main.js', 'src/café.ts', 'data.bin'])
        for member, child in zip(members, payloads):
            with self.subTest(member=member.name):
                self.assertEqual((member.method, member.size, member.compressed_size, member.flags),
                                 (0, len(child), len(child), ()))
                self.assertEqual(data[member.data_offset:member.data_offset + member.size], child)
                self.assertEqual(data[member.central_offset:member.central_offset + 1], b'{')
                self.assertEqual(asar.materialize(data, member), (child, sha256_hex(child)))
                artifact = asar.artifact(member, child)
                self.assertEqual((artifact['crc32'], artifact['sha256']), (zlib.crc32(child), sha256_hex(child)))
                self.assertEqual(materialize(data, artifact), child)
        self.assertEqual(asar.artifact(members[2], payloads[2])['member'], r'src/caf\xe9.ts')

    def test_js_files_package_and_hints_use_the_same_stored_children(self):
        data, payloads = app()
        files = operation('files', data)
        self.assertEqual([r.value['file'] for r in files], ['package.json', 'src/main.js', r'src/caf\xe9.ts'])
        self.assertEqual([(r.value['index'], r.value['total']) for r in files], [(0, 3), (1, 3), (2, 3)])
        for row, child in zip(files, payloads):
            self.assertEqual(materialize(data, row.artifact), child)
            self.assertEqual(row.value['sha256'], sha256_hex(child))
        package = operation('package', data)
        self.assertEqual([(r.value['path'], r.value['value']) for r in package],
                         [('/name', 'asar-app'), ('/scripts/postinstall', 'node setup.js')])
        hints = operation('hints', data, file=r'src/caf\xe9.ts')
        self.assertEqual([(r.value['file'], r.value['hint']) for r in hints], [(r'src/caf\xe9.ts', 'eval')])
        self.assertEqual(materialize(data, hints[0].artifact), payloads[2])

    def test_real_query_reviewer_and_report_keep_child_evidence_supported(self):
        data, _ = app()
        ref = InputRef(sha256_hex(data), len(data), 'app.asar')
        result = pipeline.query_bytes(data, ref, 'analyze_javascript_application', {})
        self.assertEqual([r.status for r in result.results], ['ok'])
        self.assertTrue(result.verdicts)
        self.assertEqual({v.status for v in result.verdicts}, {'supported'})
        self.assertIn('asar-app', report.to_markdown(result))
        self.assertTrue(all(e.artifact is not None for r in result.results for e in r.evidence))

    def test_unpacked_links_and_unsafe_names_are_listed_without_payload_reads(self):
        self.require_reader()
        header = {'files': {
            'outside.js': {'size': 9000, 'unpacked': True},
            'link.js': {'link': '/outside/target.js'},
            'external': {'unpacked': True, 'files': {'child.ts': {'size': 5}}},
            '../bad.js': {'size': 1, 'offset': '0'},
            'bad\\name.js': {'size': 1, 'offset': '1'},
        }}
        data = archive(header, b'xy')
        expected = [('outside.js', ['asar_unpacked']), ('link.js', ['asar_link']),
                    ('external/child.ts', ['asar_unpacked']), ('../bad.js', ['traversing_name']),
                    (r'bad\x5cname.js', ['traversing_name'])]
        with patch.object(asar, '_materialize', side_effect=AssertionError('flagged bytes read')):
            files = operation('files', data)
            self.assertEqual([(r.value['file'], r.value['flags']) for r in files], expected)
            self.assertTrue(all(r.artifact is None and r.value['sha256'] is None for r in files))
            self.assertEqual(operation('hints', data), [])
            self.assertEqual(operation('package', data), [])
        for member in asar.members(data):
            with self.subTest(member=member.name), self.assertRaises(ContractError):
                asar.materialize(data, member)

    def test_only_selected_javascript_children_are_materialized_and_header_walks_once(self):
        self.require_reader()
        data, _ = app()
        original = asar._materialize
        def checked(data, member):
            self.assertFalse(member.flags)
            self.assertNotEqual(member.name, 'data.bin')
            return original(data, member)
        with patch.object(asar, '_materialize', side_effect=checked), \
                patch.object(asar, 'members', wraps=asar.members) as parsed:
            self.assertTrue(operation('hints', data, file=r'src/caf\xe9.ts'))
            self.assertEqual(parsed.call_count, 1)

    def test_empty_files_use_header_anchors_and_do_not_overlap_real_data(self):
        self.require_reader()
        data = archive({'files': {'empty.js': {'size': 0, 'offset': '0'},
                                   'a.js': {'size': 1, 'offset': '0'}}}, b'x')
        empty, full = operation('files', data)
        self.assertEqual((empty.value['size'], empty.value['lines'], empty.value['max_line']), (0, 0, 0))
        self.assertEqual(empty.value['sha256'], sha256_hex(b''))
        self.assertIsNone(empty.artifact)
        self.assertEqual(data[empty.location.offset:empty.location.offset + 1], b'{')
        self.assertEqual(materialize(data, full.artifact), b'x')

    def test_overlaps_and_out_of_range_offsets_fail_the_whole_operation(self):
        self.require_reader()
        for first, second in ((('0', 2), ('1', 1)), (('0', 1), ('2', 1)),
                              (('0', 1), ('99999999999999999999', 1))):
            h = {'files': {'a.js': {'offset': first[0], 'size': first[1]},
                           'b.js': {'offset': second[0], 'size': second[1]}}}
            with self.subTest(header=h), self.assertRaises(ContractError):
                operation('files', archive(h, b'xy'), limit=1)

    def test_malformed_entry_shapes_sizes_offsets_and_metadata_fail_closed(self):
        self.require_reader()
        bad = [None, [], {}, {'size': True, 'offset': '0'}, {'size': -1, 'offset': '0'},
               {'size': 0.5, 'offset': '0'}, {'size': 2**64, 'offset': '0'},
               {'size': 0, 'offset': 0}, {'size': 0, 'offset': ''}, {'size': 0, 'offset': '+0'},
               {'size': 0, 'offset': '٠'}, {'size': 0, 'offset': str(2**64)},
               {'size': 0}, {'size': 0, 'offset': '0', 'unknown': True},
               {'size': 0, 'offset': '0', 'unpacked': 'true'}, {'link': False}, {'link': ''},
               {'files': [], 'size': 0}, {'files': {}, 'offset': '0'},
               {'size': 0, 'offset': '0', 'integrity': []},
               {'size': 0, 'offset': '0', 'executable': 1}]
        for value in bad:
            with self.subTest(entry=value), self.assertRaises(ContractError):
                asar.members(archive({'files': {'bad.js': value}}))
        for root in ({}, {'files': []}, {'files': {}, 'other': 0}, []):
            with self.subTest(root=root), self.assertRaises(ContractError):
                asar.members(archive(root))

    def test_duplicate_decoded_names_and_joined_path_aliases_refuse(self):
        self.require_reader()
        duplicate = b'{"files":{"a.js":{"size":0,"offset":"0"},"\\u0061.js":{"size":0,"offset":"0"}}}'
        with self.assertRaises(ContractError):
            asar.members(archive(None, raw=duplicate))
        alias = {'files': {'a/b.js': {'size': 0, 'offset': '0'},
                           'a': {'files': {'b.js': {'size': 0, 'offset': '0'}}}}}
        with self.assertRaises(ContractError):
            asar.members(archive(alias))

    def test_sizes_require_unsigned_integer_tokens_and_offsets_require_digit_strings(self):
        self.require_reader()
        for spelling in (b'1.0', b'1e0', b'1E0', b'1e+0', b'1E-0', b'0.0', b'0e0', b'-0', b'-1', b'true', b'"1"'):
            raw = b'{"files":{"a.js":{"size":' + spelling + b',"offset":"0"}}}'
            with self.subTest(size=spelling), self.assertRaises(ContractError):
                asar.members(archive(None, b'x', raw=raw))
        for offset in ('1.0', '1e0', '1E0', 0, 1.0, True):
            with self.subTest(offset=offset), self.assertRaises(ContractError):
                asar.members(archive({'files': {'a.js': {'size': 0, 'offset': offset}}}))
        for size in (0, 1):
            data = archive({'files': {'a.js': {'size': size, 'offset': '0'}}}, b'x')
            member, = asar.members(data)
            self.assertEqual(asar.materialize(data, member)[0], b'x'[:size])

    def test_invalid_pickle_lengths_and_every_truncation_are_fixed_refusals(self):
        self.require_reader()
        data, _ = app()
        for at in range(len(data)):
            with self.subTest(length=at), self.assertRaises(ContractError):
                asar.members(data[:at])
        for at, value in ((0, 3), (4, 0), (4, 0xffffffff), (8, 0), (12, 0xffffffff)):
            changed = bytearray(data)
            struct.pack_into('<I', changed, at, value)
            with self.subTest(at=at, value=value), self.assertRaises(ContractError):
                asar.members(bytes(changed))

    def test_asar_magic_never_falls_back_to_scanning_invalid_archive_bytes(self):
        for data in (b'\4\0\0\0', b'\4\0\0\0eval(secret)', archive({'files': {'a.js': {'offset': 4, 'size': 3}}})):
            for detail in ('files', 'package', 'hints'):
                with self.subTest(detail=detail), self.assertRaises(ContractError):
                    operation(detail, data)

    def test_directory_entry_and_read_budgets_apply_beyond_the_page(self):
        self.require_reader()
        data = archive({'files': {'dir': {'files': {'a.js': {'size': 2, 'offset': '0'}}},
                                   'b.js': {'size': 2, 'offset': '2'}}}, b'abcd')
        with patch.object(asar, 'MAX_MEMBERS', 2), self.assertRaises(ContractError):
            operation('files', data, limit=1)
        with patch.object(asar, 'MAX_MEMBERS', 3):
            self.assertEqual(len(asar.members(data)), 2)
        with patch.object(js, 'MAX_READ_BYTES', 3):
            for detail in ('files', 'hints'):
                with self.subTest(detail=detail), self.assertRaises(ContractError):
                    operation(detail, data, limit=1)

    def test_joined_utf8_path_budgets_include_directories_and_stop_amplification(self):
        self.require_reader()
        data = archive({'files': {'a': {'files': {'éé.js': {'size': 0, 'offset': '0'},
                                                'f.js': {'size': 0, 'offset': '0'}}}}})
        with patch.object(asar, 'MAX_PATH_BYTES', 9), patch.object(asar, 'MAX_TOTAL_PATH_BYTES', 16):
            self.assertEqual([m.name for m in asar.members(data)], ['a/éé.js', 'a/f.js'])
        with patch.object(asar, 'MAX_PATH_BYTES', 8), self.assertRaises(ContractError):
            asar.members(data)
        with patch.object(asar, 'MAX_TOTAL_PATH_BYTES', 15), self.assertRaises(ContractError):
            asar.members(data)

    def test_long_and_oversized_names_keep_zip_flags_without_materialization(self):
        self.require_reader()
        name = 'x' * 256 + '.js'
        data = archive({'files': {name: {'size': 0, 'offset': '0'},
                                  'large.js': {'size': 2, 'offset': '0'}}}, b'xy')
        with patch.object(asar, 'MAX_CHILD_BYTES', 1), \
                patch.object(asar, '_materialize', side_effect=AssertionError('refused child read')):
            files = operation('files', data)
            self.assertEqual([(r.value['file'], r.value['flags']) for r in files],
                             [('x' * 255, ['long_name']), ('large.js', ['too_large'])])

    def test_materialization_refuses_forged_or_foreign_descriptors(self):
        self.require_reader()
        data, _ = app()
        member = asar.members(data)[0]
        for changed in (replace(member, name='other.js'), replace(member, size=1),
                        replace(member, data_offset=0), replace(member, flags=('asar_link',))):
            with self.subTest(member=changed), self.assertRaises(ContractError):
                asar.materialize(data, changed)
        tiny = archive({'files': {'a.js': {'size': 1, 'offset': '0'}}}, b'x')
        member = asar.members(tiny)[0]
        for size in (1.0, True):
            with self.subTest(size=size), self.assertRaises(ContractError):
                asar.materialize(tiny, replace(member, size=size))
        with self.assertRaises(ContractError):
            asar.artifact(None, b'x')

    def test_header_limits_override_json_defaults_without_mutating_them(self):
        self.require_reader()
        h = {'files': {'a.js': {'size': 0, 'offset': '0', 'integrity': {'padding': 'x' * (1024 * 1024)}}}}
        data = archive(h)
        self.assertEqual(len(asar.members(data)), 1)
        with self.assertRaises(ContractError):
            jsonpos.parse(data[16:-2])
        with patch.object(asar, 'MAX_HEADER_BYTES', 100), self.assertRaises(ContractError):
            asar.members(data)
        h['files']['a.js']['integrity'] = {'padding': [0] * 33000}
        data = archive(h)
        self.assertEqual(len(asar.members(data)), 1)
        with patch.object(asar, 'MAX_HEADER_TOKENS', 100), self.assertRaises(ContractError):
            asar.members(data)
        self.assertEqual((jsonpos.MAX_BYTES, jsonpos.MAX_TOKENS, jsonpos.MAX_DEPTH), (1048576, 65536, 64))

    def test_json_keyword_limits_keep_depth_and_default_behavior(self):
        self.assertIn('max_bytes', inspect.signature(jsonpos.parse).parameters)
        self.assertIn('max_tokens', inspect.signature(jsonpos.parse).parameters)
        for kw in ({'max_bytes': True}, {'max_bytes': -1}, {'max_tokens': True}, {'max_tokens': -1}):
            with self.subTest(kw=kw), self.assertRaises(ContractError):
                jsonpos.parse(b'0', **kw)
        self.assertEqual(jsonpos.parse(b'[0]', max_bytes=3, max_tokens=3).root.value, [0])
        for kw in ({'max_bytes': 2}, {'max_tokens': 2}):
            with self.subTest(kw=kw), self.assertRaises(ContractError):
                jsonpos.parse(b'[0]', **kw)
        with self.assertRaises(ContractError):
            jsonpos.parse(b'[' * 65 + b'0' + b']' * 65, max_bytes=1000, max_tokens=1000)

    def test_random_candidate_headers_never_leak_decoder_exceptions(self):
        self.require_reader()
        rng = random.Random(4210)
        for _ in range(200):
            data = asar.MAGIC + rng.randbytes(rng.randrange(0, 96))
            try:
                asar.members(data)
            except ContractError as error:
                self.assertEqual(str(error), 'Invalid or over-budget ASAR archive')


if __name__ == '__main__':
    unittest.main()
