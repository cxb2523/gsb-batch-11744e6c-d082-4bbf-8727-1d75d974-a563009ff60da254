"""Check fixture declarations using stdlib gzip/tar/JSON readers; never extract or execute."""

import gzip
import hashlib
import io
import json
import tarfile
import unittest

from tests import fixtures_tgz as F


class TarballFixtureTests(unittest.TestCase):
    def test_clean_tarball_is_deterministic_and_uses_fixed_gzip_metadata(self):
        data, layout = F.npm_tgz()
        self.assertEqual((data, layout), F.npm_tgz())
        self.assertEqual(data[:10], b'\x1f\x8b\x08\x00' + bytes(4) + b'\x00\xff')
        tar = gzip.decompress(data)
        self.assertEqual((len(tar), hashlib.sha256(tar).hexdigest()),
                         (layout['tar_size'], layout['tar_sha256']))
        self.assertEqual(layout['gzip_sha256'], hashlib.sha256(data).hexdigest())
        self.assertLessEqual(len(tar), 100 * len(data))

    def test_ustar_and_pax_members_have_exact_data_and_decompressed_offsets(self):
        data, layout = F.npm_tgz()
        tar = gzip.decompress(data)
        with tarfile.open(fileobj=io.BytesIO(tar), mode='r:') as reader:
            found = reader.getmembers()
        self.assertEqual([m.name.rstrip('/') for m in found], [m['name'].rstrip('/') for m in layout['members']])
        for item, declared in zip(found, layout['members']):
            with self.subTest(name=declared['name']):
                self.assertEqual(item.offset_data, declared['data_offset'])
                self.assertEqual(item.offset, declared['pax_offset'] if declared['pax_offset'] is not None
                                 else declared['header_offset'])
                self.assertEqual(tar[item.offset_data:item.offset_data + item.size], declared['data'])
        self.assertEqual(len(layout['entries']), len(layout['members']) + 1)
        self.assertTrue(tar.endswith(bytes(1024)))

    def test_every_physical_header_has_a_valid_independently_read_checksum(self):
        data, layout = F.npm_tgz()
        tar = gzip.decompress(data)
        for row in layout['entries']:
            at = row['header_offset']
            header = tarfile.TarInfo.frombuf(tar[at:at + 512], 'utf-8', 'strict')
            self.assertEqual((header.size, header.type), (row['size'], row['kind'].encode()))
            self.assertEqual(row['data_offset'], at + 512)

    def test_pax_path_is_long_for_ustar_and_short_for_the_query_selector(self):
        data, layout = F.npm_tgz()
        with tarfile.open(fileobj=io.BytesIO(gzip.decompress(data)), mode='r:') as reader:
            member = reader.getmember(F.PAX_PATH)
        self.assertGreater(len(F.PAX_PATH.encode()), 100)
        self.assertLessEqual(len(F.PAX_PATH), 255)
        self.assertEqual(member.pax_headers, {'path': F.PAX_PATH})
        self.assertIn(F.PAX_PATH, [f['row']['file'] for f in layout['files']])

    def test_file_rows_describe_only_declared_javascript_and_manifest_children(self):
        _, layout = F.npm_tgz()
        self.assertEqual([f['name'] for f in layout['files']], [
            'package/package.json', 'package/index.js', 'package/lib/net.mjs',
            'package/src/types.ts', F.PAX_PATH, 'package/empty.js'])
        for file in layout['files']:
            row = file['row']
            self.assertEqual(row['size'], len(file['data']))
            self.assertEqual(row['sha256'], hashlib.sha256(file['data']).hexdigest())
            self.assertEqual(row['flags'], [])
        self.assertEqual([f['row']['lines'] for f in layout['files']][-2:], [1, 0])
        self.assertEqual(layout['files'][-1]['row']['max_line'], 0)
        self.assertEqual(layout['files'][-1]['anchor_space'], 'tar')
        self.assertEqual(layout['files'][-1]['anchor'],
                         {'offset': layout['files'][-1]['header_offset'], 'length': 512})

    def test_package_rows_have_exact_json_value_tokens_and_script_declarations(self):
        _, layout = F.npm_tgz()
        package = layout['package']
        self.assertEqual(json.loads(package['data']), F.PACKAGE)
        paths = [row['row']['path'] for row in package['rows']]
        self.assertEqual(paths, ['/name', '/version', '/main', '/type', '/scripts/preinstall',
                                 '/scripts/postinstall', '/scripts/test', '/dependencies/left-pad',
                                 '/dependencies/@fixture~1helper'])
        for row in package['rows']:
            token = package['data'][row['offset']:row['offset'] + row['length']]
            self.assertEqual(json.loads(token), row['row']['value'])

    def test_hint_oracles_are_exact_known_occurrences_in_child_order(self):
        _, layout = F.npm_tgz()
        files = {f['name']: f['data'] for f in layout['files']}
        self.assertEqual([h['row']['hint'] for h in layout['hints']],
                         ['child_process', 'url', 'process_call', 'fetch', 'dynamic_import',
                          'web_socket', 'url', 'atob'])
        for hint in layout['hints']:
            row = hint['row']
            self.assertEqual(files[row['file']][hint['offset']:hint['offset'] + hint['length']].decode(), row['text'])

    def test_syntax_oracles_are_literal_module_and_callee_byte_spans(self):
        _, layout = F.npm_tgz()
        files = {f['name']: f['data'] for f in layout['files']}
        self.assertEqual([m['row']['source'] for m in layout['modules']], ['child_process', './decode.mjs'])
        self.assertEqual([c['row']['callee'] for c in layout['calls']], ['cp.exec', 'fetch', 'WebSocket', 'atob'])
        for span in layout['modules']:
            raw = files[span['row']['file']][span['offset']:span['offset'] + span['length']]
            self.assertEqual(raw, ("'" + span['row']['source'] + "'").encode())
        for span in layout['calls']:
            raw = files[span['row']['file']][span['offset']:span['offset'] + span['length']]
            self.assertEqual(raw.decode(), span['row']['callee'])

    def test_links_are_real_tar_link_entries_and_never_read_as_payload(self):
        for kind, flag in [('symlink', tarfile.SYMTYPE), ('hardlink', tarfile.LNKTYPE)]:
            with self.subTest(kind=kind):
                data, layout = F.tgz_hostile(kind)
                with tarfile.open(fileobj=io.BytesIO(gzip.decompress(data)), mode='r:') as reader:
                    member, = reader.getmembers()
                self.assertEqual((member.type, member.linkname, member.size), (flag, 'outside.js', 0))
                self.assertEqual(layout['members'][0]['data'], b'')

    def test_unsafe_duplicate_and_long_names_are_preserved_for_the_policy_reader(self):
        for kind in ('traversal', 'duplicate', 'long_name'):
            data, layout = F.tgz_hostile(kind)
            with tarfile.open(fileobj=io.BytesIO(gzip.decompress(data)), mode='r:') as reader:
                names = [member.name for member in reader.getmembers()]
            self.assertEqual(names, [member['name'] for member in layout['members']])
            if kind == 'traversal':
                self.assertEqual(names, ['../outside.js'])
            elif kind == 'duplicate':
                self.assertEqual(names, ['package/index.js', 'package/index.js'])
            else:
                self.assertGreater(len(names[0]), 255)

    def test_truncated_and_bad_checksum_tar_have_valid_gzip_but_invalid_tar(self):
        for kind in ('truncated_tar', 'bad_tar_checksum'):
            with self.subTest(kind=kind):
                data, _ = F.tgz_hostile(kind)
                tar = gzip.decompress(data)
                with self.assertRaises(tarfile.TarError):
                    with tarfile.open(fileobj=io.BytesIO(tar), mode='r:') as reader:
                        reader.getmembers()

    def test_bad_gzip_cases_are_distinct_from_valid_concatenated_members(self):
        for kind in ('gzip_crc', 'gzip_isize', 'not_gzip', 'gzip_trailing_data'):
            with self.subTest(kind=kind), self.assertRaises((OSError, EOFError)):
                gzip.decompress(F.tgz_hostile(kind)[0])
        data, layout = F.tgz_hostile('gzip_concatenated')
        plain = gzip.decompress(data)
        self.assertEqual(len(plain), 2 * layout['tar_size'])
        self.assertEqual(plain[:layout['tar_size']], plain[layout['tar_size']:])

    def test_ratio_bomb_is_a_valid_tar_while_the_entry_count_case_is_not_a_ratio_bomb(self):
        data, layout = F.tgz_hostile('ratio')
        plain = gzip.decompress(data)
        self.assertEqual(len(plain), layout['tar_size'])
        self.assertGreater(len(plain), 100 * len(data))
        with tarfile.open(fileobj=io.BytesIO(plain), mode='r:') as reader:
            self.assertEqual(reader.getmembers()[0].size, 256 * 1024)
        crowded, layout = F.tgz_hostile('too_many_entries')
        plain = gzip.decompress(crowded)
        self.assertLess(len(crowded), 64 * 1024 * 1024)
        self.assertLess(len(plain), 128 * 1024 * 1024)
        self.assertLessEqual(len(plain), 100 * len(crowded))
        self.assertEqual(layout['entry_count'], 65537)
        with tarfile.open(fileobj=io.BytesIO(plain), mode='r:') as reader:
            self.assertEqual(sum(1 for _ in reader), 65537)

    def test_unknown_hostile_kind_is_an_explicit_fixture_error(self):
        with self.assertRaisesRegex(ValueError, 'Unknown hostile'):
            F.tgz_hostile('typo')

    def test_method_one_artifacts_rebuild_the_declared_file_or_its_header(self):
        from reverseai.contract import materialize
        for kind in (None, 'symlink', 'hardlink', 'traversal', 'duplicate', 'long_name'):
            data, layout = F.npm_tgz() if kind is None else F.tgz_hostile(kind)
            tar, streams = gzip.decompress(data), {}
            for file in layout['files']:
                with self.subTest(kind=kind, file=file['name']):
                    artifact = file['artifact']
                    child = materialize(data, artifact, streams=streams)
                    self.assertEqual(artifact['method'], 1)
                    self.assertEqual(artifact['compressed_size'], len(data))
                    self.assertEqual(child, tar[artifact['inner_offset']:artifact['inner_offset'] + artifact['size']])
                    if file['row']['flags'] or not file['data']:
                        self.assertEqual((artifact['inner_offset'], artifact['size']), (file['header_offset'], 512))
                    else:
                        self.assertEqual(child, file['data'])
                    self.assertEqual(file['location'], {'offset': 0, 'length': min(len(child), 4096)})
            self.assertEqual(len(streams), 1)
