"""Syntax queries and CLI: inert fixtures, an explicit parser stand-in, no Docker."""

import contextlib
from dataclasses import replace
import importlib
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from reverseai import cli, pipeline, queries
from reverseai.analysts import query
from reverseai.contained import ContainedError
from reverseai.contract import (
    AnalysisTask, ArgSpec, ContractError, InputRef, Location, Observation, OperationRequest,
    OperationSpec, ToolRef, ToolSpec, content_id, make_evidence, sha256_hex,
)
from reverseai.gateway import Gateway

NAME = 'analyze_javascript_application'
DATA = b'/* inert Python-built fixture; never evaluated */\n' * 32
INPUT = InputRef(sha256_hex(DATA), len(DATA), 'fixture.js')
REF = ToolRef('jsparser', '8.0.4-r2')
SCHEMA = {
    'file': ArgSpec('identity', 0, 255, default=''),
    'kind': ArgSpec('enum', choices=('modules', 'calls', 'parse'), default='modules'),
    'start': ArgSpec('int', 0, 1048575, default=0),
    'limit': ArgSpec('int', 1, 256, default=128),
}
SHAPES = {
    'modules': ('js_module', {'file': 'app.js', 'form': 'import', 'source': 'library', 'truncated': False}),
    'calls': ('js_call', {'file': 'app.js', 'callee': 'globalThis.fetch'}),
    'parse': ('js_parse', {'file': 'app.js', 'status': 'ok', 'errors': 0}),
}
SECRET = '/private/sensitive/parser.log SAMPLE_TEXT_DO_NOT_LEAK'


def fake_parser(calls, *, count=1, failure=None):
    def handler(data, args):
        calls.append(dict(args))
        if failure is not None:
            raise failure
        kind, row = SHAPES[args['kind']]
        return [Observation(Location(i, 1), {'kind': kind, 'index': i, 'total': count, **row})
                for i in range(args['start'], min(count, args['start'] + args['limit']))]
    op = OperationSpec('jsparser.syntax', SCHEMA, handler, max_observations=256, derived=True)
    return ToolSpec(REF, {op.name: op}, contained=True,
                    runtime={'image': 'sha256:' + 'a' * 64, 'platform': 'linux/arm64'})


class JavaScriptSyntaxQueryTests(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.tool = fake_parser(self.calls)

    def run_query(self, args, *, tools=None):
        try:
            return pipeline.query_bytes(DATA, INPUT, NAME, args, tools=(self.tool,) if tools is None else tools)
        except ContractError as error:
            self.fail('Contracted syntax query was refused: ' + str(error))

    def test_each_detail_routes_only_its_selected_kind_and_preserves_the_page(self):
        for detail in SHAPES:
            with self.subTest(detail=detail):
                self.calls.clear()
                args = {'detail': detail, 'file': r'lib/caf\xe9.js', 'start': 7, 'limit': 129}
                self.run_query(args)
                self.assertEqual(self.calls, [{'file': args['file'], 'kind': detail, 'start': 7, 'limit': 129}])
                spec, checked = queries.resolve(NAME, args)
                self.assertEqual(spec.role, 'structural')
                self.assertEqual([(r.operation, r.args) for r in spec.requests(checked)],
                                 [('jsparser.syntax', self.calls[0])])

    def test_new_details_require_an_exact_registered_pin_before_the_gateway(self):
        for detail in SHAPES:
            for tools, reason in (((), 'Query operation unavailable'),
                                  ((replace(self.tool, ref=ToolRef('jsparser', '8.0.4-r1')),),
                                   'Query JavaScript parser version unavailable')):
                with self.subTest(detail=detail, tools=bool(tools)), \
                        patch.object(Gateway, 'run', side_effect=AssertionError('operation ran')) as run:
                    with self.assertRaisesRegex(ContractError, '^' + reason + '$'):
                        pipeline.query_bytes(DATA, INPUT, NAME, {'detail': detail}, tools=tools)
                    run.assert_not_called()
        self.assertEqual(self.calls, [])

    def test_argument_bounds_and_unused_category_are_refused(self):
        for detail in SHAPES:
            for extra in ({'start': -1}, {'start': 1048576}, {'start': True}, {'limit': 0}, {'limit': 257},
                          {'limit': True}, {'file': 'x' * 256}, {'file': 'a\nb.js'}, {'category': 'network'},
                          {'kind': 'calls'}, {'plugin': 'typescript'}):
                with self.subTest(detail=detail, extra=extra), self.assertRaises(ContractError):
                    queries.resolve(NAME, {'detail': detail, **extra})
            checked = queries.parse_args(NAME, ['detail=' + detail, 'start=0xfffff', 'limit=256', 'file=' + 'x' * 255])
            self.assertEqual((checked['start'], checked['limit'], len(checked['file'])), (1048575, 256, 255))

    def test_syntax_file_selectors_refuse_non_ascii_before_any_operation(self):
        self.assertEqual(queries.TABLE[NAME].args['file'].kind, 'literal')
        _, checked = queries.resolve(NAME, {'detail': 'hints', 'file': 'café.js'})
        self.assertEqual(checked['file'], 'café.js')
        for detail in SHAPES:
            for name in ('café.js', '中.js'):
                with self.subTest(detail=detail, name=name), \
                        patch.object(Gateway, 'run', side_effect=AssertionError('operation ran')) as run:
                    with self.assertRaisesRegex(ContractError, 'printable ASCII'):
                        pipeline.query_bytes(DATA, INPUT, NAME, {'detail': detail, 'file': name}, tools=(self.tool,))
                    run.assert_not_called()
            _, checked = queries.resolve(NAME, {'detail': detail, 'file': r'caf\xe9.js'})
            self.assertEqual(checked['file'], r'caf\xe9.js')
        self.assertEqual(self.calls, [])

    def test_pages_chunk_at_64_with_inferred_confidence_and_derived_verdicts(self):
        tool = fake_parser(self.calls, count=300)
        for detail in SHAPES:
            with self.subTest(detail=detail):
                analysis = self.run_query({'detail': detail, 'start': 7, 'limit': 129}, tools=(tool,))
                result, = analysis.results
                self.assertEqual(result.status, 'ok')
                self.assertEqual(len(result.evidence), 129)
                self.assertEqual([(f.claim_key, f.value['start'], len(f.value['rows']), f.value['total'])
                                  for f in result.findings],
                                 [('javascript.' + detail, 7, 64, 300), ('javascript.' + detail, 71, 64, 300),
                                  ('javascript.' + detail, 135, 1, 300)])
                self.assertTrue(all(f.confidence == 'inferred' and len(f.evidence_ids) <= 64 for f in result.findings))
                cited = [eid for f in result.findings for eid in f.evidence_ids]
                self.assertCountEqual(cited, [item.id for item in result.evidence])
                for i, finding in enumerate(result.findings):
                    self.assertEqual(finding.evidence_ids,
                                     tuple(sorted(item.id for item in result.evidence[i * 64:(i + 1) * 64])))
                self.assertEqual([v.status for v in analysis.verdicts], ['derived'] * 3)

    def test_parse_statuses_are_derived_readings_without_claiming_execution(self):
        for status, errors in (('ok', 0), ('syntax_error', 2), ('decode_error', 0), ('too_large', 0)):
            value = {'kind': 'js_parse', 'index': 0, 'total': 1, 'file': '', 'status': status, 'errors': errors}
            op = replace(self.tool.operations['jsparser.syntax'],
                         handler=lambda data, args: [Observation(Location(0, 1), value)])
            tool = replace(self.tool, operations={'jsparser.syntax': op})
            with self.subTest(status=status):
                analysis = self.run_query({'detail': 'parse'}, tools=(tool,))
                self.assertEqual(analysis.results[0].status, 'ok')
                finding, = analysis.results[0].findings
                self.assertEqual((finding.confidence, analysis.verdicts[0].status), ('inferred', 'derived'))
                self.assertEqual(finding.value['rows'], [['', status, errors]])

    def test_old_details_do_not_invoke_a_registered_parser(self):
        for detail in ('summary', 'files', 'package', 'hints'):
            with self.subTest(detail=detail):
                analysis = self.run_query({'detail': detail}, tools=pipeline.TOOLS + (self.tool,))
                self.assertTrue(all(e.operation.startswith('js.') for r in analysis.results for e in r.evidence))
                self.assertTrue(all(f.confidence == 'observed' for r in analysis.results for f in r.findings))
        self.assertEqual(self.calls, [])
        self.assertNotIn(self.tool, pipeline.TOOLS)

    def test_task_and_gateway_keep_the_fixed_150_second_pair(self):
        seen = {}
        def gateway(tools, budget):
            seen['gateway'] = budget.max_wall_seconds
            instance = Gateway(tools, budget)
            original = instance.run
            def run(task, data):
                seen['task'] = task.budget.max_wall_seconds
                return original(task, data)
            instance.run = run
            return instance
        with patch.object(pipeline, 'Gateway', side_effect=gateway):
            self.run_query({'detail': 'calls'})
        self.assertEqual(seen, {'task': 150, 'gateway': 150})

    def test_conclude_binds_input_pin_operation_and_requested_kind(self):
        task = AnalysisTask(content_id('tk', {'fixture': 'syntax'}), 'structural', INPUT,
                            (OperationRequest('jsparser.syntax', {'kind': 'calls'}),))
        value = {'kind': 'js_call', 'index': 0, 'total': 1, **SHAPES['calls'][1]}
        good = make_evidence(DATA, REF, 'jsparser.syntax', Observation(Location(0, 1), value))
        self.assertEqual(len(query.conclude(task, (good,))), 1)
        module = {'kind': 'js_module', 'index': 0, 'total': 1, **SHAPES['modules'][1]}
        for item in (make_evidence(b'x' * len(DATA), REF, 'jsparser.syntax', Observation(Location(0, 1), value)),
                     make_evidence(DATA, ToolRef('jsparser', '8.0.4-r1'), 'jsparser.syntax', Observation(Location(0, 1), value)),
                     make_evidence(DATA, REF, 'jsparser.other', Observation(Location(0, 1), value)),
                     make_evidence(DATA, REF, 'jsparser.syntax', Observation(Location(0, 1), module)),
                     make_evidence(DATA, REF, 'jsparser.syntax', Observation(Location(0, 1), {**value, 'index': True}))):
            with self.subTest(item=item.id):
                self.assertEqual(query.conclude(task, (item,)), ())


class JavaScriptSyntaxCliTests(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.tool = fake_parser(self.calls)
        self.module = SimpleNamespace(available=lambda: True, make_tool=lambda: self.tool)

    def invoke(self, detail, *, flag=True, module=None, file=None):
        self.stdout, self.stderr, self.written = io.StringIO(), io.StringIO(), {}
        self.imports = []
        original_import = importlib.import_module
        def imported(name, *args):
            if name == 'reverseai.tools.jsparser_tool':
                self.imports.append(name)
                value = self.module if module is None else module
                if isinstance(value, Exception):
                    raise value
                return value
            return original_import(name, *args)
        with tempfile.TemporaryDirectory() as directory:
            argv = ['query', str(Path(directory) / 'inert.js'), '--query', NAME, '--arg', 'detail=' + detail,
                    '--out', str(Path(directory) / 'reports')]
            if flag:
                argv.append('--with-jsparser')
            if file is not None:
                argv += ['--arg', 'file=' + file]
            with patch('importlib.import_module', side_effect=imported), \
                    patch.object(cli.intake, 'snapshot', return_value=(DATA, INPUT)) as snapshot, \
                    patch.object(cli, 'open_output', return_value=123), patch.object(cli.os, 'close'), \
                    patch.object(cli, 'write_new', side_effect=lambda fd, name, text: self.written.update({name: text})), \
                    contextlib.redirect_stdout(self.stdout), contextlib.redirect_stderr(self.stderr):
                try:
                    code = cli.main(argv)
                except SystemExit as error:
                    code = error.code
        return code, snapshot.call_count

    def test_flag_enables_each_parser_detail_and_writes_both_reports(self):
        for detail in SHAPES:
            with self.subTest(detail=detail):
                self.assertEqual(self.invoke(detail), (0, 1))
                self.assertEqual(set(self.written), {'report.json', 'report.md'})
                document = json.loads(self.written['report.json'])
                self.assertEqual(document['results'][0]['findings'][0]['verdict'], 'derived')
                self.assertIn("### JavaScript syntax (parser's reading)", self.written['report.md'])

    def test_missing_flag_refuses_before_input_or_output(self):
        for detail in SHAPES:
            with self.subTest(detail=detail):
                self.assertEqual(self.invoke(detail, flag=False), (1, 0))
                self.assertIn('requires --with-jsparser', self.stderr.getvalue())
                self.assertEqual(self.written, {})
                self.assertEqual(self.imports, [])

    def test_non_ascii_selector_is_refused_before_worker_input_or_output(self):
        for detail in SHAPES:
            with self.subTest(detail=detail):
                self.assertEqual(self.invoke(detail, file='café.js'), (1, 0))
                self.assertIn('query refused: ContractError', self.stderr.getvalue())
                self.assertEqual(self.written, {})
                self.assertEqual(self.imports, [])

    def test_old_query_is_lazy_and_the_flag_is_query_only(self):
        self.assertEqual(self.invoke('files', flag=False), (0, 1))
        self.assertEqual(self.imports, [])
        self.assertIn('## JavaScript application', self.written['report.md'])
        self.assertNotIn("### JavaScript syntax (parser's reading)", self.written['report.md'])
        errors = io.StringIO()
        with patch.object(cli.intake, 'snapshot', side_effect=AssertionError('input read')), \
                contextlib.redirect_stderr(errors), self.assertRaises(SystemExit) as raised:
            cli.main(['analyze', 'inert.js', '--out', 'reports', '--with-jsparser'])
        self.assertEqual(raised.exception.code, 2)
        self.assertIn('unrecognized arguments: --with-jsparser', errors.getvalue())

    def test_unavailable_workers_and_factory_failures_have_inert_errors(self):
        for module in (ImportError(SECRET), SimpleNamespace(available=lambda: False),
                       SimpleNamespace(available=lambda: True, make_tool=lambda: (_ for _ in ()).throw(ContainedError(SECRET)))):
            with self.subTest(module=type(module).__name__):
                self.assertEqual(self.invoke('parse', module=module), (1, 0))
                self.assertIn('JavaScript parser worker is unavailable', self.stderr.getvalue())
                self.assertNotIn(SECRET, self.stderr.getvalue())
                self.assertNotIn('Traceback', self.stderr.getvalue())
                self.assertEqual(self.written, {})

    def test_wrong_pin_and_failed_parser_write_no_reports(self):
        bad = replace(self.tool, ref=ToolRef('jsparser', '8.0.4-r1'))
        failed = fake_parser([], failure=ContractError(SECRET))
        for tool in (bad, failed):
            with self.subTest(version=tool.ref.version):
                self.module = SimpleNamespace(available=lambda: True, make_tool=lambda: tool)
                self.assertEqual(self.invoke('modules')[0], 1)
                self.assertEqual(self.written, {})
                self.assertNotIn(SECRET, self.stderr.getvalue())
                self.assertNotIn('Traceback', self.stderr.getvalue())


if __name__ == '__main__':
    unittest.main()
