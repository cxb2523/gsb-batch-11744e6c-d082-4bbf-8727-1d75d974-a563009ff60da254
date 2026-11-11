"""npm tarballs through the real host/gateway/reviewer; syntax uses an inert executor stand-in."""

import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from reverseai import cli, contained, report, review
from reverseai.contract import WORKER_PROTOCOL, canonical_json, materialize, sha256_hex
from reverseai.tools import js, jsparser_tool
from tests import fixtures_tgz as F
from tests.test_js_queries import files_page, pages, run


def page(rows, columns, *, start=0, limit=None):
    stop = None if limit is None else start + limit
    return {'start': start, 'total': len(rows), 'rows': [[item['row'][key] for key in columns]
                                                       for item in rows[start:stop]]}


class ParserExecutor:
    """Return offsets from fixture declarations, without parsing or evaluating JavaScript."""
    def __init__(self, layout, *, change=None):
        self.layout, self.change, self.calls = layout, change, []
        self.lock = {'image_id': 'sha256:' + 'a' * 64, 'platform': 'linux/arm64',
                     'adapter_version': jsparser_tool.REF.version, **contained.JSPARSER_PINS,
                     'driver_sha256': '1' * 64, 'worker_sha256': '2' * 64}

    def run(self, operation, request, data, digest):
        assert operation == 'jsparser.syntax' and digest == sha256_hex(data)
        contained.validate_jsparser_request(request)
        self.calls.append(copy.deepcopy(request))
        rows, flat, streams = [], [], {}
        declarations = self.layout['calls'] if request['kind'] == 'calls' else self.layout['modules']
        for index, selected in enumerate(request['files']):
            artifact = selected['artifact']
            child = materialize(data, artifact, streams=streams) if artifact is not None else data
            name = artifact['member'] if artifact is not None else ''
            items = []
            if request['kind'] != 'parse':
                for span in declarations:
                    if span['row']['file'] != name:
                        continue
                    at, end = span['offset'], span['offset'] + span['length']
                    items.append({'kind': 'call' if request['kind'] == 'calls' else span['row']['form'],
                                  'start': len(child[:at].decode('utf-8').encode('utf-16-le')) // 2,
                                  'end': len(child[:end].decode('utf-8').encode('utf-16-le')) // 2})
            rows.append({'file': index, 'status': 'ok', 'errors': 0, 'count': len(items), 'items': []})
            flat.extend((index, item) for item in items)
        for index, item in flat[request['start']:request['start'] + request['limit']]:
            rows[index]['items'].append(item)
        packet = {'protocol': WORKER_PROTOCOL, 'status': 'ok', 'snapshot_sha256': digest, 'observations': rows}
        if self.change is not None:
            self.change(packet)
        return canonical_json(packet).encode()


class TarballHostQueries(unittest.TestCase):
    def test_summary_has_exact_supported_files_package_and_hint_pages(self):
        built = F.npm_tgz()
        analysis = run(built, name='approved.tgz')
        self.assertEqual(analysis.results[0].status, 'ok')
        self.assertEqual(pages(analysis), {
            'javascript.files': [('supported', files_page(built[1]))],
            'javascript.package': [('supported', page(built[1]['package']['rows'],
                                                     ('file', 'path', 'value', 'truncated')))],
            'javascript.hints': [('supported', page(built[1]['hints'],
                                                   ('file', 'category', 'hint', 'text', 'truncated')))],
        })
        self.assertTrue(all(item.input_sha256 == sha256_hex(built[0])
                            and item.artifact['method'] == 1 for item in analysis.results[0].evidence))

    def test_files_page_has_exact_child_artifacts_and_keeps_the_package_prefix(self):
        built = F.npm_tgz()
        analysis = run(built, {'detail': 'files', 'start': 1, 'limit': 3}, name='approved.tgz')
        self.assertEqual(pages(analysis)['javascript.files'], [('supported', files_page(built[1], 1, 4))])
        for evidence, declared in zip(analysis.results[0].evidence, built[1]['files'][1:4]):
            self.assertEqual(evidence.artifact, declared['artifact'])
            self.assertEqual((evidence.location.offset, evidence.location.length),
                             (declared['location']['offset'], declared['location']['length']))
            self.assertEqual(materialize(built[0], evidence.artifact), declared['data'])
        pax = run(built, {'detail': 'files', 'start': 4, 'limit': 1}, name='approved.tgz')
        self.assertEqual(pax.results[0].evidence[0].observation['file'], F.PAX_PATH)

    def test_empty_file_cites_its_tar_header_and_still_reports_the_empty_file_hash(self):
        built = F.npm_tgz()
        analysis = run(built, {'detail': 'files', 'start': 5, 'limit': 1})
        self.assertEqual(pages(analysis)['javascript.files'], [('supported', files_page(built[1], 5))])
        item, = analysis.results[0].evidence
        self.assertEqual(item.artifact, built[1]['files'][-1]['artifact'])
        self.assertEqual((item.artifact['size'], item.location.offset, item.location.length), (512, 0, 512))
        self.assertEqual(item.observation['sha256'], sha256_hex(b''))
        self.assertEqual(len(materialize(built[0], item.artifact)), 512)

    def test_package_pages_use_child_json_offsets_and_exact_displayed_selectors(self):
        built = F.npm_tgz()
        args = {'detail': 'package', 'file': 'package/package.json', 'start': 4, 'limit': 3}
        analysis = run(built, args)
        expected = page(built[1]['package']['rows'], ('file', 'path', 'value', 'truncated'), start=4, limit=3)
        self.assertEqual(pages(analysis)['javascript.package'], [('supported', expected)])
        for item, declared in zip(analysis.results[0].evidence, built[1]['package']['rows'][4:7]):
            self.assertEqual((item.location.offset, item.location.length), (declared['offset'], declared['length']))
            child = materialize(built[0], item.artifact)
            self.assertEqual(json.loads(child[item.location.offset:item.location.offset + item.location.length]),
                             item.observation['value'])
        missing = run(built, {'detail': 'package', 'file': 'package.json'})
        self.assertEqual((missing.results[0].status, pages(missing)), ('ok', {}))

    def test_hint_filter_and_selector_preserve_exact_bytes_and_rows(self):
        built = F.npm_tgz()
        wanted = [item for item in built[1]['hints'] if item['row']['category'] == 'network']
        analysis = run(built, {'detail': 'hints', 'category': 'network'})
        self.assertEqual(pages(analysis)['javascript.hints'],
                         [('supported', page(wanted, ('file', 'category', 'hint', 'text', 'truncated')))])
        for item in analysis.results[0].evidence:
            child = materialize(built[0], item.artifact)
            self.assertEqual(child[item.location.offset:item.location.offset + item.location.length].decode('latin-1'),
                             item.observation['text'])
        empty = run(built, {'detail': 'hints', 'file': F.PAX_PATH})
        self.assertEqual((empty.results[0].status, pages(empty)), ('ok', {}))

    def test_flagged_entries_are_supported_header_rows_and_supply_no_hints(self):
        for kind in ('symlink', 'hardlink', 'traversal', 'duplicate', 'long_name'):
            built = F.tgz_hostile(kind)
            with self.subTest(kind=kind):
                analysis = run(built, {'detail': 'files'})
                self.assertEqual(analysis.results[0].status, 'ok')
                self.assertEqual(pages(analysis)['javascript.files'], [('supported', files_page(built[1]))])
                for item, declared in zip(analysis.results[0].evidence, built[1]['files']):
                    self.assertTrue(item.observation['flags'])
                    self.assertEqual(item.artifact, declared['artifact'])
                    self.assertEqual((item.location.offset, item.location.length), (0, 512))
                hints = run(built, {'detail': 'hints'})
                self.assertEqual((hints.results[0].status, pages(hints)), ('ok', {}))

    def test_refused_tarballs_never_become_partial_file_lists_or_raw_bundle_hints(self):
        listed = {'symlink', 'hardlink', 'traversal', 'duplicate', 'long_name'}
        for kind in F.HOSTILE_KINDS:
            if kind in listed:
                continue
            built = F.tgz_hostile(kind)
            details = ('files',) if kind == 'too_many_entries' else ('files', 'hints')
            for detail in details:
                with self.subTest(kind=kind, detail=detail):
                    analysis = run(built, {'detail': detail})
                    self.assertEqual(analysis.results[0].status, 'error')
                    self.assertEqual((analysis.results[0].evidence, analysis.results[0].findings), ((), ()))

    def test_reviewer_rebuilds_all_tarball_evidence_with_one_stream_inflation(self):
        built = F.npm_tgz()
        analysis = run(built)
        with patch.object(review, 'inflate_stream', wraps=review.inflate_stream) as inflate:
            verdicts = review.review(built[0], analysis.input, analysis.results, {'js': js.TOOL})
        self.assertEqual(inflate.call_count, 1)
        self.assertEqual([v.status for v in verdicts], ['supported'] * 3)


class TarballSyntaxQueries(unittest.TestCase):
    def setUp(self):
        self.built = F.npm_tgz()
        self.executor = ParserExecutor(self.built[1])
        self.tool = jsparser_tool.make_tool(self.executor)

    def test_modules_calls_and_parse_stay_derived_with_method_one_citations(self):
        data, layout = self.built
        for detail, columns in [('modules', ('file', 'form', 'source', 'truncated')), ('calls', ('file', 'callee'))]:
            with self.subTest(detail=detail):
                analysis = run(self.built, {'detail': detail}, tools=(self.tool,))
                self.assertEqual(analysis.results[0].status, 'ok')
                self.assertEqual(pages(analysis)['javascript.' + detail], [('derived', page(layout[detail], columns))])
                self.assertTrue(all(f.confidence == 'inferred' for f in analysis.results[0].findings))
                self.assertTrue(all(item.artifact['method'] == 1 for item in analysis.results[0].evidence))
        analysis = run(self.built, {'detail': 'parse'}, tools=(self.tool,))
        expected = [[file['name'], 'ok', 0] for file in layout['files']
                    if file['data'] and not file['name'].endswith('/package.json')]
        self.assertEqual(pages(analysis)['javascript.parse'],
                         [('derived', {'start': 0, 'total': len(expected), 'rows': expected})])
        self.assertTrue(all(item.artifact['compressed_size'] == len(data) for item in analysis.results[0].evidence))

    def test_call_page_crosses_files_and_rebinds_utf16_offsets_after_non_ascii_text(self):
        analysis = run(self.built, {'detail': 'calls', 'start': 1, 'limit': 2}, tools=(self.tool,))
        self.assertEqual(pages(analysis)['javascript.calls'],
                         [('derived', page(self.built[1]['calls'], ('file', 'callee'), start=1, limit=2))])
        selected = run(self.built, {'detail': 'calls', 'file': 'package/index.js'}, tools=(self.tool,))
        self.assertEqual([item.observation['callee'] for item in selected.results[0].evidence], ['cp.exec', 'fetch'])
        self.assertEqual(len(self.executor.calls[-1]['files']), 1)

    def test_bad_streams_are_refused_before_invoking_the_parser_executor(self):
        for kind in ('gzip_crc', 'gzip_isize', 'gzip_trailing_data', 'gzip_concatenated',
                     'bad_tar_checksum', 'truncated_tar', 'not_gzip', 'ratio'):
            with self.subTest(kind=kind):
                self.executor.calls.clear()
                analysis = run(F.tgz_hostile(kind), {'detail': 'modules'}, tools=(self.tool,))
                self.assertEqual(analysis.results[0].status, 'error')
                self.assertEqual(self.executor.calls, [])

    def test_wrong_root_digest_and_non_literal_offsets_fail_without_findings(self):
        def move_quote(packet):
            next(row for row in packet['observations'] if row['items'])['items'][0]['start'] += 1
        for change in (lambda packet: packet.update(snapshot_sha256='0' * 64), move_quote):
            with self.subTest(change=change):
                executor = ParserExecutor(self.built[1], change=change)
                analysis = run(self.built, {'detail': 'modules'}, tools=(jsparser_tool.make_tool(executor),))
                self.assertEqual(analysis.results[0].status, 'error')
                self.assertEqual((analysis.results[0].evidence, analysis.results[0].findings), ((), ()))
                self.assertEqual(len(executor.calls), 1)


class TarballReports(unittest.TestCase):
    def test_json_keeps_header_and_file_provenance_and_markdown_marks_install_scripts(self):
        built = F.npm_tgz()
        analysis = run(built, name='approved.tgz')
        document = json.loads(report.to_json(analysis))
        self.assertEqual(document['input']['sha256'], sha256_hex(built[0]))
        self.assertEqual(document['summary']['supported'], 3)
        for item in document['results'][0]['evidence']:
            self.assertEqual(item['artifact']['method'], 1)
            self.assertEqual(item['artifact']['compressed_size'], len(built[0]))
            self.assertIn('inner_offset', item['artifact'])
        markdown = report.to_markdown(analysis)
        self.assertIn('`package/index.js` @ 0x0+', markdown)
        self.assertIn('package/empty.js', markdown)
        for path, ending in [('/scripts/preinstall', '| yes |'), ('/scripts/postinstall', '| yes |'),
                             ('/scripts/test', '| - |')]:
            line, = [line for line in markdown.splitlines() if line.startswith('| ') and '`' + path + '`' in line]
            self.assertTrue(line.endswith(ending), line)

    def test_cli_uses_magic_instead_of_suffix_and_creates_only_the_two_reports(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, output = root / 'approved.bin', root / 'reports'
            source.write_bytes(F.npm_tgz()[0])
            with contextlib.redirect_stdout(io.StringIO()), patch('subprocess.Popen') as popen:
                self.assertEqual(cli.main(['query', str(source), '--query', 'analyze_javascript_application',
                                           '--arg', 'detail=summary', '--out', str(output)]), 0)
            popen.assert_not_called()
            self.assertEqual(sorted(path.name for path in root.iterdir()), ['approved.bin', 'reports'])
            self.assertEqual(sorted(path.name for path in output.iterdir()), ['report.json', 'report.md'])
            self.assertEqual(json.loads((output / 'report.json').read_text())['summary']['supported'], 3)
