"""Synthetic application archives, exact declarations and lazy scanner stand-ins."""

from contextlib import contextmanager
import io
import json
import re
import sys
from types import SimpleNamespace
import unittest
import zipfile
from unittest.mock import patch

from reverseai import claims, tools
from reverseai.contract import (
    AnalysisResult, AnalysisTask, Budget, ContractError, InputRef, Location, OperationRequest,
    content_id, make_finding, materialize, sha256_hex,
)
from reverseai.gateway import Gateway
from reverseai.review import review
from reverseai.tools import apk, js
from tests.test_apk_parsing import zip_bytes
from tests import fixtures_js as shared


def run(operation, data, **args):
    spec = js.TOOL.operations['js.' + operation]
    return spec.handler(data, spec.validate_args(args))


def scan(data):
    patterns = ((b'eval(', 'dynamic_code', 'eval'), (b'https://example.test', 'endpoint', 'url'))
    found = []
    for pattern, category, hint in patterns:
        found.extend((m.start(), len(pattern), category, hint) for m in re.finditer(re.escape(pattern), data))
    yield from sorted(found)


@contextmanager
def scanner(function=scan):
    stand_in = SimpleNamespace(scan=function)
    with patch.dict(sys.modules, {'reverseai.tools.jshints': stand_in}), patch.object(
            tools, 'jshints', stand_in, create=True):
        yield


class JavaScriptFilesTests(unittest.TestCase):
    def test_flagged_files_are_disclosed_in_order_without_reading_their_payloads(self):
        data, _ = shared.js_hostile('flagged_members')
        members = apk.members(data)
        original = apk._materialize
        read = []

        def checked(data, member):
            self.assertFalse(member.flags)
            read.append(member.name)
            return original(data, member)

        with patch.object(apk, '_materialize', side_effect=checked), \
                scanner(lambda child: iter(((0, 1, 'dynamic_code', 'eval'),))):
            rows = run('files', data)
            self.assertEqual(len(rows), len(members))
            self.assertEqual([row.value['file'] for row in rows], [apk.escape(m.name) for m in members])
            for index, (row, member) in enumerate(zip(rows, members)):
                self.assertEqual((row.value['index'], row.value['total'], row.value['flags']),
                                 (index, len(members), list(member.flags)))
                if member.flags:
                    self.assertEqual((row.value['size'], row.value['sha256'], row.value['lines'], row.value['max_line']),
                                     (member.size, None, None, None))
                    self.assertEqual(row.location, Location(member.central_offset, min(member.central_length, 4096)))
                    self.assertIsNone(row.artifact)
            self.assertEqual(read, ['package.json', 'ok.js'])
            self.assertEqual([row.value['value'] for row in run('package', data)], ['flagged'])
            self.assertEqual({row.value['file'] for row in run('hints', data)}, {'ok.js'})
        page = run('files', data, start=2, limit=3)
        self.assertEqual([row.value['index'] for row in page], [2, 3, 4])
        self.assertEqual([row.value['total'] for row in page], [len(members)] * 3)

    def test_flagged_only_files_have_bounded_parent_anchors_and_cost_no_read_budget(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w') as archive:
            member = zipfile.ZipInfo('../blocked.js')
            member.comment = b'c' * 5000
            archive.writestr(member, b'eval(x)')
            archive.writestr('../package.json', b'{"name":"blocked"}')
        data = stream.getvalue()
        with patch.object(apk, '_materialize', side_effect=AssertionError('flagged payload read')), \
                patch.object(js, 'MAX_READ_BYTES', 0), scanner():
            rows = run('files', data)
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0].location.length, 4096)
            self.assertTrue(all(row.artifact is None for row in rows))
            self.assertEqual(run('package', data), [])
            self.assertEqual(run('hints', data), [])
            self.assertEqual(run('package', data, file='../package.json'), [])
            self.assertEqual(run('hints', data, file='../blocked.js'), [])
        data, layout = shared.js_hostile('declared_over_128mib')
        with patch.object(apk, '_materialize', side_effect=AssertionError('declared size allocated')):
            rows = run('files', data)
        self.assertEqual(len(rows), 5)
        self.assertEqual([row.value['size'] for row in rows], [30 * 1024 * 1024] * 5)
        self.assertEqual([row.value['flags'] for row in rows], [['ratio', 'too_large']] * 5)

    def test_archive_members_keep_order_exact_hashes_lines_and_child_anchors(self):
        entries = [('ignored.txt', b'eval(ignored)'), ('lib/B.TSX', b'a\nb\n'),
                   ('package.json', b'{"name":"app"}'), ('index.cjs', b'abc\r\ndef'),
                   ('empty.js', b''), ('other.JSON', b'{}'), ('index.JS', b'x' * 70000)]
        data, _ = zip_bytes(entries)
        rows = run('files', data, start=1, limit=3)
        selected = [entries[i] for i in (2, 3, 4)]
        self.assertEqual([r.value['file'] for r in rows], [name for name, _ in selected])
        self.assertEqual([r.value['index'] for r in rows], [1, 2, 3])
        self.assertEqual([r.value['total'] for r in rows], [5] * 3)
        self.assertEqual([(r.value['lines'], r.value['max_line']) for r in rows], [(1, 14), (2, 4), (0, 0)])
        for row, (name, child) in zip(rows, selected):
            self.assertEqual((row.value['size'], row.value['sha256']), (len(child), sha256_hex(child)))
            if child:
                self.assertEqual(materialize(data, row.artifact), child)
                self.assertEqual(row.location, Location(0, min(len(child), 4096)))
            else:
                member = next(m for m in apk.members(data) if m.name == name)
                self.assertIsNone(row.artifact)
                self.assertEqual(row.location, Location(member.central_offset, member.central_length))
        self.assertEqual(run('files', data, start=5), [])
        last, = run('files', data, start=4)
        self.assertEqual((last.value['lines'], last.value['max_line'], last.location.length), (1, 70000, 4096))

    def test_single_file_and_line_chunk_boundaries(self):
        for data in (b'a', b'\n', b'\n\n', b'a\n', b'a\r\nb', b'abc\n\nx',
                     b'x' * 65535 + b'\n' + b'zz', b'x' * 131073, b'\n' * 131073):
            with self.subTest(length=len(data)):
                row, = run('files', data)
                expected_lines = data.count(b'\n') + int(data[-1] != 10)
                self.assertEqual(row.value, {'kind': 'js_file', 'index': 0, 'total': 1, 'file': '',
                    'size': len(data), 'sha256': sha256_hex(data), 'lines': expected_lines,
                    'max_line': max(map(len, data.split(b'\n'))), 'flags': []})
                self.assertIsNone(row.artifact)
        self.assertEqual(run('files', b''), [])  # No bytes to cite.
        archive, _ = zip_bytes([])
        self.assertEqual(run('files', archive), [])

    def test_ascii_suffixes_and_empty_member_metadata_have_bounded_anchors(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            for name in ('one.js', 'two.MJS', 'three.cjs', 'four.JSX', 'five.ts', 'six.TSX', 'Package.JSON'):
                archive.writestr(name, b'{}')
            archive.writestr('pacKage.json', b'{}')  # Unicode lowercasing would admit this name.
            empty = zipfile.ZipInfo('empty.js')
            empty.comment = b'c' * 5000
            archive.writestr(empty, b'')
        data = stream.getvalue()
        rows = run('files', data)
        self.assertEqual([r.value['file'] for r in rows],
                         ['one.js', 'two.MJS', 'three.cjs', 'four.JSX', 'five.ts', 'six.TSX', 'Package.JSON', 'empty.js'])
        self.assertEqual(rows[-1].location.length, 4096)
        self.assertIsNone(rows[-1].artifact)
        self.assertEqual(rows[-1].value['size'], 0)

    def test_flagged_and_non_javascript_members_are_never_materialized(self):
        data, _ = zip_bytes([('../bad.js', b'eval(x)'), ('safe.js', b'ok'), ('data.bin', b'eval(x)'),
                             ('package.json', b'{"name":"safe"}')])
        original = apk._materialize
        def checked(data, member):
            self.assertFalse(member.flags)
            self.assertNotEqual(member.name, 'data.bin')
            return original(data, member)
        with patch.object(apk, '_materialize', side_effect=checked) as called, scanner():
            self.assertEqual([r.value['file'] for r in run('files', data)], ['../bad.js', 'safe.js', 'package.json'])
            self.assertEqual(run('hints', data, file='../bad.js'), [])
            self.assertEqual(run('package', data, file='../bad.js'), [])
            self.assertTrue(called.call_count)
        only_flagged, _ = zip_bytes([('../bad.js', b'eval(x)')])
        with scanner():
            row, = run('files', only_flagged)
            self.assertEqual(row.value['flags'], ['traversing_name'])
            self.assertEqual(run('hints', only_flagged), [])

    def test_read_budget_fails_even_beyond_the_requested_page(self):
        data, _ = zip_bytes([('a.js', b'0123456789'), ('b.js', b'abcdefghij')])
        with patch.object(js, 'MAX_READ_BYTES', 19), scanner():
            for operation in ('files', 'hints'):
                with self.subTest(operation=operation), self.assertRaisesRegex(ContractError, 'JavaScript read budget exceeded'):
                    run(operation, data, limit=1)
            with self.assertRaises(ContractError):
                run('files', b'x' * 20)
        with patch.object(js, 'MAX_READ_BYTES', 20):
            self.assertEqual(len(run('files', data)), 2)
            self.assertEqual(len(run('files', b'x' * 20)), 1)

    def test_each_operation_parses_the_directory_once_before_materializing_clean_members(self):
        # Same-buffer clean descriptors may use
        # the materialization core; the public wrapper would reparse per file.
        data, _ = zip_bytes([('a.js', b'eval(a)'), ('b.ts', b'eval(b)'), ('package.json', b'{"name":"app"}')])
        with scanner():
            for operation in ('files', 'package', 'hints'):
                with self.subTest(operation=operation), patch.object(apk, 'members', wraps=apk.members) as parsed:
                    self.assertTrue(run(operation, data))
                    self.assertEqual(parsed.call_count, 1)


class PackageTests(unittest.TestCase):
    def test_selection_uses_path_depth_then_central_order_and_escaped_selectors(self):
        data, _ = zip_bytes([('deep/lib/package.json', b'{"name":"deep"}'),
                             ('z/package.json', b'{"name":"first"}'),
                             ('a/package.json', b'{"name":"second"}'),
                             ('café/package.json', b'{"name":"unicode"}')])
        self.assertEqual([r.value['value'] for r in run('package', data)], ['first'])
        row, = run('package', data, file='caf\\xe9/package.json')
        self.assertEqual((row.value['file'], row.value['value']), ('caf\\xe9/package.json', 'unicode'))
        self.assertEqual(materialize(data, row.artifact), b'{"name":"unicode"}')
        root, _ = zip_bytes([('deep/package.json', b'{"name":"deep"}'), ('package.json', b'{"name":"root"}')])
        self.assertEqual(run('package', root)[0].value['value'], 'root')

    def test_fields_document_order_pointers_and_value_byte_anchors(self):
        data = (b'{ "scripts":{"postinstall":"node setup.js","a~b/c":"echo x"},'
                b'"name":"demo","repository":{"type":"git","url":"https://repo.test"},'
                b'"browser":{"ignored":"not a direct string"},"unknown":"ignored",'
                b'"bin":{"tool":["./one.js",{"nested":"./two.js"}]},'
                b'"bundleDependencies":["bundled-a","bundled-b"],"description":"a\\n\\u00e9"}')
        rows = run('package', data)
        expected = [('/scripts/postinstall', 'node setup.js', b'"node setup.js"'),
                    ('/scripts/a~0b~1c', 'echo x', b'"echo x"'), ('/name', 'demo', b'"demo"'),
                    ('/repository/url', 'https://repo.test', b'"https://repo.test"'),
                    ('/bin/tool/0', './one.js', b'"./one.js"'), ('/bin/tool/1/nested', './two.js', b'"./two.js"'),
                    ('/bundleDependencies/0', 'bundled-a', b'"bundled-a"'),
                    ('/bundleDependencies/1', 'bundled-b', b'"bundled-b"'),
                    ('/description', 'a\\x0a\\xe9', b'"a\\n\\u00e9"')]
        self.assertEqual([(r.value['path'], r.value['value']) for r in rows], [(p, v) for p, v, _ in expected])
        for index, (row, (_, _, raw)) in enumerate(zip(rows, expected)):
            self.assertEqual(row.location, Location(data.index(raw), len(raw)))
            self.assertEqual((row.value['index'], row.value['total'], row.value['truncated']), (index, len(expected), False))
        self.assertEqual(run('package', data, start=3, limit=2), rows[3:5])

    def test_all_named_fields_and_exports_depth_four(self):
        fields = ['name', 'version', 'description', 'main', 'module', 'browser', 'types', 'type', 'license', 'homepage',
                  'repository', 'bin', 'scripts', 'engines', 'dependencies', 'devDependencies', 'peerDependencies',
                  'optionalDependencies', 'bundledDependencies', 'bundleDependencies']
        maps = fields[12:18]
        bundled = fields[18:]
        doc = {name: {"item": name + '-value'} if name in maps else
                     [name + '-value'] if name in bundled else name + '-value' for name in fields}
        rows = run('package', json.dumps(doc).encode())
        self.assertEqual([r.value['path'] for r in rows], ['/' + name + ('/item' if name in maps else
                                                        '/0' if name in bundled else '') for name in fields])
        data = b'{"exports":{"a":"one","b":{"c":{"d":{"e":"four","f":{"g":"five"}}}}}}'
        self.assertEqual([(r.value['path'], r.value['value']) for r in run('package', data)],
                         [('/exports/a', 'one'), ('/exports/b/c/d/e', 'four')])

    def test_collections_distinguish_direct_values_descendants_and_bundled_entries(self):
        data = json.dumps({'scripts': 'ignored', 'engines': 'ignored', 'dependencies': 'ignored',
            'devDependencies': {'group': ['yes']}, 'bundledDependencies': ['bundled', {'nested': 'ignored'}, ['ignored']],
            'bundleDependencies': 'ignored', 'bin': './bin.js', 'exports': './main.js'}).encode()
        self.assertEqual([(r.value['path'], r.value['value']) for r in run('package', data)],
                         [('/devDependencies/group/0', 'yes'), ('/bundledDependencies/0', 'bundled'),
                          ('/bin', './bin.js'), ('/exports', './main.js')])

    def test_escaped_values_cut_at_256_and_anchor_quotes_before_the_excerpt_cap(self):
        for text in ('x' * 256, 'x' * 257, '🧪' * 30, '\\' * 100, '', 'x' * 6000):
            with self.subTest(text=text[:20]):
                raw = json.dumps(text, ensure_ascii=False).encode()
                data = b'{"description":' + raw + b'}'
                row, = run('package', data)
                escaped = apk.escape(text, maximum=10000)
                self.assertEqual((row.value['value'], row.value['truncated']), (escaped[:256], len(escaped) > 256))
                self.assertEqual(row.location, Location(len(b'{"description":'), min(len(raw), 4096)))
        data = json.dumps({'scripts': {'é/~\\': 'yes'}}).encode()
        self.assertEqual(run('package', data)[0].value['path'], '/scripts/\\xe9~1~0\\x5c')

    def test_json_and_pointer_bounds_fail_the_operation_instead_of_cutting_totals(self):
        for data in (b'{"name":"a","name":"b"}', b'{"unknown":{"k":0,"k":1}}', b'{"name":"a",}',
                     b'\xef\xbb\xbf{}', b'{"name":"\\ud800"}',
                     b'{"unknown":' + b'[' * 65 + b'0' + b']' * 65 + b'}', b'{' + b' ' * (1024 * 1024) + b'}'):
            with self.subTest(data=data[:50]), self.assertRaises(ContractError):
                run('package', data)
        for key in ('k' * 247, 'k' * 248):
            data = json.dumps({'scripts': {key: 'x'}}).encode()
            if len('/scripts/' + key) > 255:
                with self.assertRaisesRegex(ContractError, 'JavaScript JSON pointer exceeds its limit'):
                    run('package', data, start=100)
            else:
                self.assertEqual(len(run('package', data)[0].value['path']), 255)

    def test_single_bundle_has_no_package_and_object_inputs_remain_strict(self):
        # Only object-like single-file JSON is selected.
        for data in (shared.bundle_js()[0], b'', b'[]', b'null', b'"value"', b' \t\r\nconst x = 1;',
                     b'\xef\xbb\xbf' + shared.bundle_js()[0], b'\xef\xbb\xbf \tconst x = 1;'):
            with self.subTest(data=data[:30]):
                try:
                    rows = run('package', data)
                except ContractError as error:
                    self.fail(f'Non-package single file was refused: {error}')
                self.assertEqual(rows, [])
        data, layout = shared.package_only()
        rows = run('package', b' \t\r\n' + data)
        self.assertEqual([r.value['value'] for r in rows], [r['row']['value'] for r in layout['package']['rows']])
        self.assertEqual(rows[0].location.offset, layout['package']['rows'][0]['offset'] + 4)
        for data in (b'{not json', b'{"name":"x","name":"y"}', b' \t{bad', b'\xef\xbb\xbf{}', b'\xef\xbb\xbf \t{}'):
            with self.subTest(invalid=data), self.assertRaises(ContractError):
                run('package', data)
        for data in (b'[]', b'null', b'"value"', b'const x = 1;'):
            archive, _ = shared.package_zip(data)
            with self.subTest(archive=data), self.assertRaises(ContractError):
                run('package', archive)

    def test_shared_application_and_single_file_known_answers_match_every_value_and_anchor(self):
        for builder in (shared.app_zip, shared.bundle_js, shared.package_only):
            data, layout = builder()
            rows = run('files', data)
            self.assertEqual(len(rows), len(layout['files']))
            for index, (row, expected) in enumerate(zip(rows, layout['files'])):
                self.assertEqual(row.value, dict(kind='js_file', index=index, total=len(rows), **expected['row']))
                self.assertEqual(row.location, Location(**expected['anchor']))
                self.assertEqual(row.artifact, expected['artifact'])
            if layout['package']:
                expected = layout['package']['rows']
                rows = run('package', data)
                self.assertEqual(len(rows), len(expected))
                for index, (row, want) in enumerate(zip(rows, expected)):
                    self.assertEqual(row.value, dict(kind='package_field', index=index, total=len(rows), **want['row']))
                    self.assertEqual(row.location, Location(want['offset'], want['length']))
        for text in shared.INVALID_JSON.values():
            data, _ = shared.package_zip(text)
            with self.assertRaises(ContractError):
                run('package', data)

    def test_member_selectors_and_invalid_zip_mode_follow_the_contract(self):
        # Selection is closed and refuses a bad local ZIP header.
        data, _ = zip_bytes([('config.js', b'{"name":"wrong"}'), ('package.json', b'{"name":"right"}')])
        self.assertEqual(run('package', data, file='config.js'), [])
        self.assertEqual(run('package', data, file='missing.json'), [])
        self.assertEqual(run('package', b'{"name":"single"}', file='package.json'), [])
        with scanner():
            self.assertEqual(run('hints', data, file='package.json'), [])
            self.assertEqual(run('hints', b'eval(x)', file='index.js'), [])
            for operation in ('files', 'package', 'hints'):
                with self.subTest(operation=operation), self.assertRaisesRegex(ContractError, 'Invalid JavaScript ZIP container'):
                    run(operation, b'PK\x03\x04broken eval(x)')
            self.assertEqual(run('hints', b'PK-not-a-local-header eval(x)')[0].value['file'], '')


class HintsTests(unittest.TestCase):
    def test_files_offset_order_categories_overlaps_and_complete_paging_totals(self):
        data, _ = zip_bytes([('first.js', b'eval(x); https://example.test'),
                             ('package.json', b'{"description":"eval("}'),
                             ('second.ts', b'https://example.test; eval(y)')])
        with scanner():
            all_rows = run('hints', data)
            self.assertEqual([(r.value['file'], r.location.offset) for r in all_rows],
                             [('first.js', 0), ('first.js', 9), ('second.ts', 0), ('second.ts', 22)])
            self.assertEqual(run('hints', data, start=1, limit=2), all_rows[1:3])
            self.assertEqual([r.value['total'] for r in all_rows], [4] * 4)
            selected = run('hints', data, category='endpoint')
            self.assertEqual([(r.value['index'], r.value['total']) for r in selected], [(0, 2), (1, 2)])
            self.assertEqual([r.value['file'] for r in run('hints', data, file='second.ts')], ['second.ts'] * 2)
            self.assertEqual(run('hints', data, start=4), [])
            for row in all_rows:
                child = materialize(data, row.artifact)
                self.assertEqual(child[row.location.offset:row.location.offset + row.location.length].decode(), row.value['text'])
        def overlap(child):
            return iter(((0, 5, 'dynamic_code', 'eval'), (0, 4, 'network', 'also_here')))
        with scanner(overlap):
            rows = run('hints', b'eval(x)')
            self.assertEqual([r.value['hint'] for r in rows], ['eval', 'also_here'])

    def test_long_text_and_a_page_beyond_4096_matches_are_not_silent_cuts(self):
        with scanner():
            rows = run('hints', b'eval(' * 5000, start=4095, limit=3)
            self.assertEqual([r.value['index'] for r in rows], [4095, 4096, 4097])
            self.assertEqual([r.value['total'] for r in rows], [5000] * 3)
        def whole(child):
            return iter(((0, len(child), 'credential', 'test_literal'),))
        for data in (b'"' * 300, b'\xff' * 100, b'abc\n\t\\'):
            with scanner(whole):
                row, = run('hints', data)
                expected = apk.escape(data.decode('latin-1'), maximum=10000)
                self.assertEqual((row.value['text'], row.value['truncated']), (expected[:256], len(expected) > 256))
                self.assertEqual(row.location, Location(0, len(data)))

    def test_gateway_artifacts_and_claims_are_supported_for_each_operation(self):
        data, _ = zip_bytes([('index.js', b'eval(x)'), ('package.json', b'{"name":"app"}')])
        ref = InputRef(sha256_hex(data), len(data), 'app.zip')
        with scanner():
            for operation, key in (('js.files', 'javascript.files'), ('js.package', 'javascript.package'),
                                   ('js.hints', 'javascript.hints')):
                task = AnalysisTask(content_id('tk', {'operation': operation}), 'code', ref,
                                    (OperationRequest(operation),), Budget())
                result = Gateway((js.TOOL,), Budget()).run(task, data)
                self.assertEqual(result.status, 'ok', result.errors)
                kind = result.evidence[0].observation['kind']
                columns = claims.PAGES[kind][0]
                finding = make_finding('code', 'Application bytes.', key,
                    {'start': 0, 'total': len(result.evidence),
                     'rows': [[e.observation[c] for c in columns] for e in result.evidence]},
                    [e.id for e in result.evidence], 'observed')
                concluded = AnalysisResult(task.id, 'code', 'ok', result.evidence, (finding,))
                self.assertEqual([v.status for v in review(data, ref, [concluded], {'js': js.TOOL})], ['supported'])


if __name__ == '__main__':
    unittest.main()
