"""Host-only JavaScript parser probes; synthetic bytes, never sample execution."""

import copy
import json
import os
import tempfile
from pathlib import Path
import unittest
from unittest.mock import MagicMock, patch

from reverseai import contained
from reverseai.contract import (
    AnalysisResult, AnalysisTask, Budget, ContractError, InputRef, Location, OperationRequest,
    MAX_WORKER_REPLY_BYTES, WORKER_PROTOCOL, WorkerError, canonical_json, content_id,
    make_finding, materialize, sha256_hex,
)
from reverseai.gateway import Gateway
from reverseai.review import review
from reverseai.tools import apk, jsparser_tool, jshints
from reverseai.tools import jsparser_verify as verify
from tests.test_apk_parsing import zip_bytes

LOCK = {'image_id': 'sha256:' + 'a' * 64, 'platform': 'linux/arm64', 'adapter_version': '8.0.4-r2',
        **contained.JSPARSER_PINS, 'driver_sha256': '1' * 64, 'worker_sha256': '2' * 64}
BOM = b'\xef\xbb\xbf'
A = BOM + '// 😀\nimport x from "\\u{1f600}/m";\nobj.eval(code);\n'.encode()
B = b'require(`alpha\\${literal}`);\nexport {x} from "./next";\n'


def item(data, kind, spelling):
    text = data.removeprefix(BOM).decode()
    at = text.index(spelling)
    start = len(text[:at].encode('utf-16-le')) // 2
    return {'kind': kind, 'start': start, 'end': start + len(spelling.encode('utf-16-le')) // 2}


CATALOG = {
    A: {'modules': [item(A, 'import', '"\\u{1f600}/m"')], 'calls': [item(A, 'call', 'obj.eval')]},
    B: {'modules': [item(B, 'require', '`alpha\\${literal}`'), item(B, 'export_from', '"./next"')],
        'calls': []},
}


def packet(data, rows):
    return canonical_json({'protocol': WORKER_PROTOCOL, 'status': 'ok',
                           'snapshot_sha256': sha256_hex(data), 'observations': rows}).encode()


def reply(data, request, catalog=CATALOG):
    """Known-answer worker stand-in: slice a declared flat page, then group by file."""
    rows, flat = [], []
    for index, file in enumerate(request['files']):
        child = data if file['artifact'] is None else materialize(data, file['artifact'])
        declared = catalog.get(child, {})
        items = declared.get(request['kind'], [])
        rows.append({'file': index, 'status': declared.get('status', 'ok'), 'errors': declared.get('errors', 0),
                     'count': len(items), 'items': []})
        flat.extend((index, entry) for entry in items)
    for index, entry in flat[request['start']:request['start'] + request['limit']]:
        rows[index]['items'].append(copy.deepcopy(entry))
    return rows


class Executor:
    def __init__(self, change=None, catalog=CATALOG, raw=None):
        self.lock, self.change, self.catalog, self.raw, self.calls = LOCK, change, catalog, raw, []

    def run(self, operation, request, data, digest):
        self.calls.append(copy.deepcopy(request))
        assert operation == 'jsparser.syntax' and digest == sha256_hex(data)
        contained.build_argv(LOCK['image_id'], 'reverseai-jsfixture', '/private/tmp/js-fixture', operation, request)
        rows = reply(data, request, self.catalog)
        if self.change:
            rows = self.change(rows)
        return self.raw(data) if self.raw else packet(data, rows)


def arguments(**kwargs):
    return jsparser_tool.make_tool(Executor()).operations['jsparser.syntax'].validate_args(kwargs)


def invoke(data, args=None, **kwargs):
    executor = Executor(**kwargs)
    spec = jsparser_tool.make_tool(executor).operations['jsparser.syntax']
    return spec.handler(data, spec.validate_args(args or {})), executor


class CoordinateTests(unittest.TestCase):
    def test_utf16_units_map_to_exact_original_utf8_boundaries(self):
        text = 'aé中😀z'
        data = text.encode()
        expected = {0: 0, 1: 1, 2: 3, 3: 6, 5: 10, 6: 11}
        self.assertEqual(verify._offsets(data, set(expected)), expected)
        self.assertEqual(verify._offsets(b'\xef\xbb\xbf' + data, set(expected)),
                         {unit: byte + 3 for unit, byte in expected.items()})
        for invalid in (-1, 4, 7, 999):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(ContractError, verify.REFUSED):
                verify._offsets(data, {invalid})
        self.assertEqual(verify._offsets(b'\xef\xbb\xbf', {0}), {0: 3})

    def test_only_requested_boundaries_are_retained(self):
        data = b'x' * verify.MAX_FILE_BYTES
        self.assertEqual(verify._offsets(data, {1, len(data)}), {1: 1, len(data): len(data)})
        self.assertEqual(verify._offsets(data, set()), {})

    def test_invalid_utf8_cannot_supply_a_text_coordinate(self):
        for data in (b'\xff', b'\xed\xa0\x80', b'\xf0\x9f', b'\xef\xbb\xbf\xff'):
            with self.subTest(data=data), self.assertRaises(UnicodeError):
                verify._offsets(data, {0})


class LiteralTests(unittest.TestCase):
    def test_complete_literals_are_decoded_without_running_the_text(self):
        cases = [(b"'plain'", 'plain'), (b'""', ''), (b'`plain`', 'plain'),
                 (br'"a\n\r\t\b\f\v\0z"', 'a\n\r\t\b\f\v\0z'),
                 (br"'\x41\u0042\u{1f600}'", 'AB😀'), (br'"\ud83d\ude00"', '😀'),
                 (br'"\ud800"', '\ud800'), (br"'a\\b\'c'", "a\\b'c"),
                 (b'"a\\\r\nb"', 'ab'), (b'"a\\\nb"', 'ab'),
                 (b'`a\r\nb\rc\nd`', 'a\nb\nc\nd'), (br'`\${literal}`', '${literal}'),
                 (br'"\z\/"', 'z/'), ('"café中"'.encode(), 'café中')]
        cases += [(br'"\1\07\377\400\8\9"', '\x01\x07ÿ 089'), (br'"\08"', '\0' + '8'),
                  (br'"\u{000000000000041}"', 'A'), (br'`\0`', '\0'),
                  ('"a\u2028b\u2029c"'.encode(), 'a\u2028b\u2029c')]
        for raw, expected in cases:
            with self.subTest(raw=raw):
                self.assertEqual(verify._literal(raw), expected)

    def test_non_literals_partial_literals_and_templates_with_substitutions_fail(self):
        for raw in (b'name', b'"x" + "y"', b'"x', b'"a\nb"', b'"a\rb"', b'"a\\"',
                    br'"\x0g"', br'"\u123"', br'"\u{}"', br'"\u{110000}"',
                    b'`x${name}`', b'`a`b`', br'`\01`', br'`\8`', br'`\9`', br'`\08`'):
            with self.subTest(raw=raw), self.assertRaisesRegex(ContractError, verify.REFUSED):
                verify._literal(raw)


class PreparationTests(unittest.TestCase):
    def test_selected_clean_files_keep_order_dialects_and_exact_artifacts(self):
        data, _ = zip_bytes([('a.TSX', A), ('../bad.js', A), ('package.json', b'{}'),
                             ('é/b.JSX', B), ('empty.ts', b''), ('ignored.bin', A), ('last.mjs', b'x')])
        with patch.object(apk, 'members', wraps=apk.members) as parsed:
            request, files = verify.prepare(data, arguments())
        self.assertEqual(parsed.call_count, 1)
        self.assertEqual([(f.name, f.dialect) for f in files], [('a.TSX', 'tsx'), ('\\xe9/b.JSX', 'jsx'), ('last.mjs', 'js')])
        self.assertEqual([f.data for f in files], [A, B, b'x'])
        self.assertEqual(request['callees'], sorted(jshints.CALLEES))
        self.assertEqual((request['kind'], request['start'], request['limit']), ('modules', 0, 128))
        for sent, file in zip(request['files'], files):
            self.assertEqual(materialize(data, sent['artifact']), file.data)
            self.assertEqual(sent['artifact'], file.artifact)
            self.assertIsNot(sent['artifact'], file.artifact)
        request, files = verify.prepare(data, arguments(file='\\xe9/b.JSX'))
        self.assertEqual([f.name for f in files], ['\\xe9/b.JSX'])

    def test_empty_flagged_absent_and_package_members_never_reach_the_worker(self):
        for data, args in ((b'', {}), (A, {'file': 'named.js'}),
                           (zip_bytes([('empty.js', b''), ('../bad.js', A), ('package.json', b'{}')])[0], {}),
                           (zip_bytes([('a.js', A)])[0], {'file': 'absent.js'})):
            with self.subTest(args=args):
                rows, executor = invoke(data, args)
                self.assertEqual((rows, executor.calls), ((), []))
        request, files = verify.prepare(A, arguments())
        self.assertEqual(request['files'], [{'artifact': None, 'dialect': 'js'}])
        self.assertEqual(files[0].name, '')
        with self.assertRaisesRegex(ContractError, verify.REFUSED):
            invoke(b'PK\x03\x04broken')

    def test_limits_are_checked_before_inflation_and_empty_files_still_count(self):
        self.assertEqual((verify.MAX_FILES, verify.MAX_FILE_BYTES, verify.MAX_TOTAL_BYTES),
                         (64, 4 * 1024 * 1024, 32 * 1024 * 1024))
        for size in (64, 65):
            data, _ = zip_bytes([(f'{i}.js', b'') for i in range(size)])
            if size == 64:
                self.assertEqual(invoke(data)[0], ())
            else:
                with self.assertRaisesRegex(ContractError, verify.REFUSED):
                    invoke(data)
        with self.assertRaisesRegex(ContractError, verify.REFUSED):
            invoke(b'x' * (verify.MAX_FILE_BYTES + 1))
        data, _ = zip_bytes([('a.js', b'123456'), ('b.js', b'abcdef')])
        with patch.object(verify, 'MAX_TOTAL_BYTES', 11), \
                patch.object(apk, '_materialize', side_effect=AssertionError('over-budget payload read')):
            with self.assertRaisesRegex(ContractError, verify.REFUSED):
                invoke(data)
        with patch.object(verify, 'MAX_FILE_BYTES', 5), \
                patch.object(apk, '_materialize', side_effect=AssertionError('over-budget payload read')):
            with self.assertRaisesRegex(ContractError, verify.REFUSED):
                invoke(data)


class HostReplyTests(unittest.TestCase):
    def setUp(self):
        self.data, _ = zip_bytes([('a.js', A), ('b.ts', B)])

    def test_honest_modules_calls_and_parse_have_exact_host_text_and_anchors(self):
        modules, executor = invoke(self.data)
        self.assertEqual([(o.value['index'], o.value['total'], o.value['file'], o.value['form'], o.value['source'])
                          for o in modules], [(0, 3, 'a.js', 'import', '\\U0001f600/m'),
                                              (1, 3, 'b.ts', 'require', 'alpha${literal}'),
                                              (2, 3, 'b.ts', 'export_from', './next')])
        self.assertEqual([materialize(self.data, o.artifact)[o.location.offset:o.location.offset + o.location.length]
                          for o in modules], [br'"\u{1f600}/m"', br'`alpha\${literal}`', b'"./next"'])
        calls, _ = invoke(self.data, {'kind': 'calls'})
        self.assertEqual([o.value['callee'] for o in calls], ['obj.eval'])
        parsed, _ = invoke(self.data, {'kind': 'parse'})
        self.assertEqual([o.value for o in parsed], [
            {'kind': 'js_parse', 'file': 'a.js', 'status': 'ok', 'errors': 0, 'index': 0, 'total': 2},
            {'kind': 'js_parse', 'file': 'b.ts', 'status': 'ok', 'errors': 0, 'index': 1, 'total': 2}])
        self.assertEqual([o.location for o in parsed], [Location(0, len(A)), Location(0, len(B))])

    def test_pages_cross_files_and_keep_full_totals_without_a_65536_cut(self):
        for start, limit, expected in ((0, 1, ['\\U0001f600/m']), (1, 1, ['alpha${literal}']),
                                       (1, 2, ['alpha${literal}', './next']), (2, 2, ['./next']), (3, 1, [])):
            with self.subTest(start=start):
                rows, _ = invoke(self.data, {'start': start, 'limit': limit})
                self.assertEqual([o.value['source'] for o in rows], expected)
                self.assertEqual([o.value['index'] for o in rows], list(range(start, start + len(expected))))
                self.assertTrue(all(o.value['total'] == 3 for o in rows))
        rows, _ = invoke(self.data, {'kind': 'parse', 'start': 1, 'limit': 1})
        self.assertEqual([(o.value['index'], o.value['total'], o.value['file']) for o in rows], [(1, 2, 'b.ts')])
        # A tiny reply can describe a far page: its total is a derived parser count, never a host scan cap.
        rows, _ = invoke(A, {'start': 70000, 'limit': 1}, change=lambda r: [
            {**r[0], 'count': 70001, 'items': [CATALOG[A]['modules'][0]]}])
        self.assertEqual((rows[0].value['index'], rows[0].value['total']), (70000, 70001))

    def test_reply_file_identity_missing_extra_duplicate_and_reordered_files_fail(self):
        changes = [lambda r: [], lambda r: r[:1], lambda r: r + r[:1], lambda r: list(reversed(r)),
                   lambda r: [r[0], r[0]], lambda r: [{**r[0], 'file': True}, r[1]],
                   lambda r: [{**r[0], 'file': 99}, r[1]], lambda r: [{**r[0], 'name': 'lie'}, r[1]]]
        for change in changes:
            with self.subTest(change=change), self.assertRaisesRegex(ContractError, verify.REFUSED):
                invoke(self.data, change=change)

    def test_counts_page_cardinality_item_shapes_and_order_fail_closed(self):
        changes = [lambda r: [{**r[0], 'items': []}, r[1]],
                   lambda r: [r[0], {**r[1], 'items': list(reversed(r[1]['items']))}],
                   lambda r: [r[0], {**r[1], 'items': [r[1]['items'][0]] * 2}],
                   lambda r: [{**r[0], 'items': [{**r[0]['items'][0], 'source': 'forged'}]}, r[1]]]
        for key, value in (('count', -1), ('count', True), ('count', 2**32), ('count', 0),
                           ('errors', True), ('status', 'unknown'), ('status', 'syntax_error'), ('status', 'too_large')):
            changes.append(lambda r, key=key, value=value: [{**r[0], key: value}, r[1]])
        for field, value in (('start', True), ('end', -1), ('end', 9999), ('start', 12), ('end', 12),
                             ('kind', 'unknown'), ('kind', 'call')):
            changes.append(lambda r, field=field, value=value: [
                {**r[0], 'items': [{**r[0]['items'][0], field: value}]}, r[1]])
        for change in changes:
            with self.subTest(change=change), self.assertRaisesRegex(ContractError, verify.REFUSED):
                invoke(self.data, change=change)

    def test_non_bmp_boundary_splits_are_refused_and_bom_is_counted_once(self):
        text = '😀"x"'
        data = BOM + text.encode()
        honest = {'file': 0, 'status': 'ok', 'errors': 0, 'count': 1,
                  'items': [{'kind': 'import', 'start': 2, 'end': 5}]}
        rows, _ = invoke(data, change=lambda _: [honest])
        self.assertEqual(rows[0].location, Location(7, 3))
        for field, value in (('start', 1), ('end', 1), ('start', 0)):
            changed = {**honest, 'items': [{**honest['items'][0], field: value}]}
            with self.subTest(field=field), self.assertRaisesRegex(ContractError, verify.REFUSED):
                invoke(data, change=lambda _: [changed])

    def test_comment_roles_remain_derived_and_exact_bytes_are_still_required(self):
        # The host checks bytes, not whether the parser chose code or comment text.
        data = b'// eval(x) and "a"\n'
        modules, _ = invoke(data, change=lambda _: [{'file': 0, 'status': 'ok', 'errors': 0, 'count': 1,
                                'items': [item(data, 'import', '"a"')]}])
        self.assertEqual(modules[0].value['source'], 'a')
        calls, _ = invoke(data, {'kind': 'calls'}, change=lambda _: [{'file': 0, 'status': 'ok', 'errors': 0, 'count': 1,
                                'items': [item(data, 'call', 'eval')]}])
        self.assertEqual(calls[0].value['callee'], 'eval')
        with self.assertRaisesRegex(ContractError, verify.REFUSED):
            invoke(data, {'kind': 'calls'}, change=lambda _: [{'file': 0, 'status': 'ok', 'errors': 0, 'count': 1,
                                 'items': [item(data, 'call', 'eval(x)')]}])

    def test_callee_catalog_ascii_chain_length_and_parts_are_enforced(self):
        for spelling, valid in (('eval', True), ('$a._b.c.eval', True), ('a.b.c.d.eval', False),
                                 ('unknown', False), ('a .eval', False), ('a["eval"]', False),
                                 ('é.eval', False), ('a' * 251 + '.eval', False), ('a' * 250 + '.eval', True)):
            data = spelling.encode()
            changed = lambda _: [{'file': 0, 'status': 'ok', 'errors': 0, 'count': 1,
                                  'items': [item(data, 'call', spelling)]}]
            with self.subTest(spelling=spelling):
                if valid:
                    self.assertEqual(invoke(data, {'kind': 'calls'}, change=changed)[0][0].value['callee'], spelling)
                else:
                    with self.assertRaisesRegex(ContractError, verify.REFUSED):
                        invoke(data, {'kind': 'calls'}, change=changed)

    def test_qualified_callees_match_only_complete_trailing_parts(self):
        # Common method names need their catalog receiver.
        for spelling, valid in (('get', False), ('map.get', False), ('http.get', True), ('my.http.get', True),
                                 ('myhttp.get', False), ('Buffer.from', True), ('Other.from', False),
                                 ('buffer.from', False), ('fs.write', True), ('log.write', False),
                                 ('write', False), ('writeFileSync', True), ('dgram.createSocket', True),
                                 ('net.createSocket', False), ('net.connect', True), ('tls.connect', True),
                                 ('foo.connect', False)):
            data = spelling.encode()
            change = lambda _: [{'file': 0, 'status': 'ok', 'errors': 0, 'count': 1,
                                 'items': [item(data, 'call', spelling)]}]
            with self.subTest(spelling=spelling):
                if valid:
                    self.assertEqual(invoke(data, {'kind': 'calls'}, change=change)[0][0].value['callee'], spelling)
                else:
                    with self.assertRaisesRegex(ContractError, verify.REFUSED):
                        invoke(data, {'kind': 'calls'}, change=change)

    def test_parse_error_policy_checks_utf8_and_requires_zero_error_items(self):
        invalid = b'bad\xff'
        catalog = {invalid: {'status': 'decode_error'}}
        rows, _ = invoke(invalid, {'kind': 'parse'}, catalog=catalog)
        self.assertEqual((rows[0].value['status'], rows[0].value['errors']), ('decode_error', 0))
        for status in ('ok', 'syntax_error', 'too_large'):
            with self.subTest(status=status), self.assertRaisesRegex(ContractError, verify.REFUSED):
                invoke(invalid, {'kind': 'parse'}, catalog={invalid: {'status': status, 'errors': int(status == 'syntax_error')}})
        with self.assertRaisesRegex(ContractError, verify.REFUSED):
            invoke(A, {'kind': 'parse'}, catalog={A: {'status': 'decode_error'}})
        rows, _ = invoke(A, catalog={A: {**CATALOG[A], 'status': 'syntax_error', 'errors': 2}})
        self.assertEqual(rows[0].value['source'], '\\U0001f600/m')
        for change in (lambda r: [{**r[0], 'count': 1}], lambda r: [{**r[0], 'items': [{}]}]):
            with self.assertRaisesRegex(ContractError, verify.REFUSED):
                invoke(A, {'kind': 'parse'}, change=change)

    def test_long_literal_is_fully_decoded_but_excerpt_and_value_remain_bounded(self):
        data = b'"' + b'x' * 5000 + b'"'
        rows, _ = invoke(data, change=lambda _: [{'file': 0, 'status': 'ok', 'errors': 0, 'count': 1,
                               'items': [{'kind': 'import', 'start': 0, 'end': len(data)}]}])
        self.assertEqual((rows[0].location, rows[0].value['source'], rows[0].value['truncated']),
                         (Location(0, 4096), 'x' * 256, True))
        malformed = data[:-1] + b'x'
        with self.assertRaisesRegex(ContractError, verify.REFUSED):
            invoke(malformed, change=lambda _: [{'file': 0, 'status': 'ok', 'errors': 0, 'count': 1,
                                 'items': [{'kind': 'import', 'start': 0, 'end': len(data)}]}])

    def test_worker_envelope_is_bounded_exact_duplicate_free_and_hash_bound(self):
        valid = json.loads(packet(A, reply(A, verify.prepare(A, arguments())[0])))
        encoded = canonical_json(valid).encode()
        bad = [b'\xff', b'{}', b'[]', b'{' + b' ' * MAX_WORKER_REPLY_BYTES,
               b'{"protocol":"x","protocol":"x"}', b'{"x":NaN}', b'[' * 10000,
               encoded + b' ' * (MAX_WORKER_REPLY_BYTES + 1 - len(encoded)),
               encoded.replace(b'"status":"ok"', b'"status":"ok","status":"ok"', 1),
               encoded.replace(b'"file":0', b'"file":0,"file":0', 1),
               encoded.replace(b'"count":1', b'"count":NaN', 1)]
        for field, value in (('protocol', 'other'), ('snapshot_sha256', '0' * 64), ('status', 'unknown'),
                             ('observations', {}), ('observations', [{}] * 65), ('extra', True)):
            bad.append(canonical_json({**valid, field: value}).encode())
        for raw in bad:
            with self.subTest(raw=raw[:50]), self.assertRaisesRegex(ContractError, verify.REFUSED):
                verify.parse_reply(raw, sha256_hex(A))
        for error in ('input', 'memory', 'timeout'):
            raw = canonical_json({'protocol': WORKER_PROTOCOL, 'status': 'error', 'snapshot_sha256': sha256_hex(A),
                                  'error': error}).encode()
            with self.assertRaises(WorkerError):
                verify.parse_reply(raw, sha256_hex(A))

    def test_equal_ranges_use_form_order_and_never_duplicate_the_same_item(self):
        data = b'"same"'
        same = {'start': 0, 'end': len(data)}
        items = [{'kind': 'import', **same}, {'kind': 'require', **same}]
        rows = [{'file': 0, 'status': 'ok', 'errors': 0, 'count': 2, 'items': items}]
        found, _ = invoke(data, change=lambda _: rows)
        self.assertEqual([o.value['form'] for o in found], ['import', 'require'])
        for bad in (list(reversed(items)), [items[0], items[0]]):
            with self.assertRaisesRegex(ContractError, verify.REFUSED):
                invoke(data, change=lambda _: [{**rows[0], 'items': bad}])


class BoundaryTests(unittest.TestCase):
    def test_executor_stages_exact_bytes_with_the_fixed_jsparser_profile(self):
        calls = []

        def runner(argv, **limits):
            calls.append((argv, limits))
            mount = argv[argv.index('--mount') + 1]
            folder = Path(mount.split('source=', 1)[1].split(',target=', 1)[0])
            self.assertEqual((folder / 'input').read_bytes(), A)
            self.assertEqual(os.stat(folder / 'input').st_mode & 0o777, 0o444)
            return b'{}'

        request, _ = verify.prepare(A, arguments())
        with tempfile.TemporaryDirectory() as root:
            executor = contained.DockerExecutor(LOCK, runner, adapter_version='8.0.4-r2',
                                               inspect=lambda image: image, staging_root=root)
            self.assertEqual(executor.run('jsparser.syntax', request, A, sha256_hex(A)), b'{}')
            self.assertEqual(list(Path(root).iterdir()), [])
            argv, limits = calls[0]
            self.assertEqual(limits, {'timeout': 120, 'max_output': MAX_WORKER_REPLY_BYTES})
            for flag, value in (('--pids-limit', '64'), ('--memory', '2g'), ('--memory-swap', '2g'),
                                ('--cpus', '2'), ('--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=64m')):
                self.assertEqual(argv[argv.index(flag) + 1], value)
            self.assertEqual(argv[-3:-1], [LOCK['image_id'], 'jsparser.syntax'])
            self.assertEqual(json.loads(argv[-1]), request)
            for operation, args in (('lief.headers', {}), ('jsparser.syntax', {**request, 'callees': []})):
                with self.assertRaises(contained.ContainedError):
                    executor.run(operation, args, A, sha256_hex(A))
            for data in (b'', b'x' * (4 * 1024 * 1024 + 1)):
                with self.assertRaises(contained.ContainedError):
                    executor.run('jsparser.syntax', request, data, sha256_hex(data))
            self.assertEqual(len(calls), 1)
        with patch.object(contained, 'run_bounded', return_value=b'{}') as bounded:
            executor = contained.DockerExecutor(LOCK, adapter_version='8.0.4-r2')
            executor.runner(['trusted'], timeout=120, max_output=20)
            bounded.assert_called_once_with(['trusted'], profile='jsparser', timeout=120, max_output=20)

    def test_jsparser_runner_cannot_widen_the_fixed_wall_limit(self):
        process, selector = MagicMock(), MagicMock()
        process.poll.return_value = None
        selector.select.return_value = []
        selector.get_map.return_value = {1: True}
        manager = MagicMock()
        manager.__enter__.return_value = selector
        with patch.object(contained.subprocess, 'Popen', return_value=process), \
                patch.object(contained.selectors, 'DefaultSelector', return_value=manager), \
                patch.object(contained.time, 'monotonic', side_effect=[0.0, 60.0]):
            with self.assertRaises(contained.ContainedTimeout):
                contained.run_bounded(['trusted'], profile='jsparser', timeout=9999)
        selector.select.assert_called_once_with(60.0)
        process.kill.assert_called_once()

    def test_gateway_keeps_each_syntax_claim_derived_and_bound_to_its_child(self):
        data, _ = zip_bytes([('a.js', A), ('b.js', B)])
        tool = jsparser_tool.make_tool(Executor())
        ref = InputRef(sha256_hex(data), len(data), 'synthetic.zip')
        for kind, claim in (('modules', 'javascript.modules'), ('calls', 'javascript.calls'), ('parse', 'javascript.parse')):
            task = AnalysisTask(content_id('tk', {'kind': kind}), 'code', ref,
                                (OperationRequest('jsparser.syntax', {'kind': kind}),), Budget())
            result = Gateway((tool,), Budget()).run(task, data)
            self.assertEqual(result.status, 'ok', result.errors)
            from reverseai import claims
            fields = claims.PAGES[{'modules': 'js_module', 'calls': 'js_call', 'parse': 'js_parse'}[kind]][0]
            finding = make_finding('code', 'Syntax reading.', claim,
                                  {'start': 0, 'total': len(result.evidence),
                                   'rows': [[e.observation[field] for field in fields] for e in result.evidence]},
                                  [e.id for e in result.evidence], 'inferred')
            final = AnalysisResult(task.id, 'code', 'ok', result.evidence, (finding,))
            self.assertEqual([v.status for v in review(data, ref, [final], {'jsparser': tool})], ['derived'])

    def test_request_is_closed_catalog_fixed_and_dialects_follow_member_suffixes(self):
        data, _ = zip_bytes([('a.ts', A)])
        request, _ = verify.prepare(data, arguments())
        self.assertEqual(contained.validate_jsparser_request(request), request)
        bad = [{**request, 'extra': True}, {**request, 'callees': ['eval']}, {**request, 'limit': True},
               {**request, 'kind': 'evaluate'}, {**request, 'files': []},
               {**request, 'files': [{'artifact': None, 'dialect': 'ts'}]},
               {**request, 'files': request['files'] * 2},
               {**request, 'files': [{**request['files'][0], 'dialect': 'js'}]},
               {**request, 'files': [{**request['files'][0], 'path': '/etc/passwd'}]}]
        for value in bad:
            with self.subTest(value=value), self.assertRaises(contained.ContainedError):
                contained.validate_jsparser_request(value)
        tool = jsparser_tool.make_tool(Executor())
        spec = tool.operations['jsparser.syntax']
        self.assertTrue(tool.contained and spec.derived)
        self.assertEqual(spec.max_observations, 256)
        for args in ({'file': '../a.js\n'}, {'file': 'x' * 256}, {'limit': 257}, {'start': -1},
                     {'kind': 'eval'}, {'node_options': '--eval'}):
            with self.assertRaises(ContractError):
                spec.validate_args(args)

    def test_image_lock_requires_every_pin_and_availability_never_runs_a_worker(self):
        self.assertEqual(contained.load_lock(LOCK, adapter_version='8.0.4-r2'), LOCK)
        for key in LOCK:
            bad = {**LOCK, key: 'bad'}
            with self.subTest(key=key), self.assertRaises(contained.ContainedError):
                jsparser_tool.make_tool(type('E', (), {'lock': bad})())
        self.assertTrue(jsparser_tool.available(LOCK, inspect=lambda image: image))
        self.assertFalse(jsparser_tool.available(LOCK, inspect=lambda image: 'other'))
        self.assertFalse(jsparser_tool.available('/missing/jsparser.lock'))
        with self.assertRaises(TypeError):
            contained.resource_profile('jsparser.syntax')['memory'] = 'unbounded'


if __name__ == '__main__':
    unittest.main()
