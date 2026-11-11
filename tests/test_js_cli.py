"""Run the actual JavaScript query CLI against synthetic bundle and ZIP inputs."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from reverseai.contract import sha256_hex
from tests import fixtures_js as shared


class JavaScriptCliTests(unittest.TestCase):
    def test_bundle_and_zip_write_both_reports_for_every_detail(self):
        name = 'analyze_javascript_application'
        with tempfile.TemporaryDirectory() as scratch:
            folder = Path(scratch)
            bundle, _ = shared.bundle_js()
            archive, _ = shared.app_zip()
            for filename, data, has_package in (('bundle.js', bundle, False), ('app.zip', archive, True),
                                                ('bom-bundle.js', b'\xef\xbb\xbf' + bundle, False)):
                sample = folder / filename
                sample.write_bytes(data)
                for detail in ('summary', 'files', 'package', 'hints'):
                    with self.subTest(input=filename, detail=detail):
                        output = folder / (filename + '-' + detail)
                        result = subprocess.run([sys.executable, '-B', '-m', 'reverseai', 'query', str(sample),
                            '--query', name, '--arg', 'detail=' + detail, '--out', str(output)],
                            cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, timeout=30)
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                        self.assertEqual({p.name for p in output.iterdir()}, {'report.md', 'report.json'})
                        document = json.loads((output / 'report.json').read_text())
                        markdown = (output / 'report.md').read_text()
                        self.assertEqual(document['input']['sha256'], sha256_hex(data))
                        self.assertEqual(document['query']['name'], name)
                        self.assertEqual(document['query']['args']['detail'], detail)
                        self.assertTrue(document['results'])
                        self.assertTrue(all(r['status'] == 'ok' for r in document['results']))
                        findings = [f for r in document['results'] for f in r['findings']]
                        self.assertTrue(all(f['verdict'] == 'supported' for f in findings))
                        expected = {'javascript.' + detail}
                        if detail == 'summary':
                            expected = {'javascript.files', 'javascript.hints'}
                            if has_package:
                                expected.add('javascript.package')
                        elif detail == 'package' and not has_package:
                            expected = set()
                        self.assertEqual({f['claim_key'] for f in findings}, expected)
                        self.assertIn(name, markdown)
                        self.assertIn(sha256_hex(data), result.stdout)


if __name__ == '__main__':
    unittest.main()
