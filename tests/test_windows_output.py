"""Real Windows report handles; no DLL stand-ins, Docker, network or sample execution.

The manual Windows proof runs this module separately. A Windows runner must be
able to create test symlinks/junctions; lack of that capability is a test failure,
not a skipped security check. Other operating systems skip the entire class.
"""

import contextlib
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest

from reverseai import cli, intake, pipeline, queries, report, winout
from tests.fixtures_structure import elf_imports


@unittest.skipUnless(os.name == "nt", "real Windows output handles require Windows")
class WindowsOutputTests(unittest.TestCase):
    def setUp(self):
        self.assertEqual(sys.implementation.name, "cpython")
        self.assertGreaterEqual(sys.version_info, (3, 12, 4))
        self.temporary = tempfile.TemporaryDirectory(prefix="reverseai-win-output-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.sample = self.root / "inert.elf"
        self.sample.write_bytes(elf_imports()[0])

    def run_cli(self, *args):
        output, error = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            try:
                code = cli.main(list(args))
            except SystemExit as exit:
                code = exit.code
        return code, output.getvalue(), error.getvalue()

    def assert_refused(self, path):
        code, _, error = self.run_cli("analyze", str(self.sample), "--out", str(path))
        self.assertEqual(code, 1)
        self.assertTrue(error.startswith(("reverseai: output refused:",
                                          "reverseai: --out must be a new or empty directory")), error)
        self.assertNotIn("Traceback", error)
        self.assertNotIn(str(self.root), error)

    def test_analyze_and_query_write_exact_utf8_lf_report_bytes(self):
        data, ref = intake.snapshot(self.sample)
        query = queries.parse_args("list_segments", ["limit=16"])
        for command, expected, args in (
                ("analyze", pipeline.analyze_bytes(data, ref), []),
                ("query", pipeline.query_bytes(data, ref, "list_segments", query),
                 ["--query", "list_segments", "--arg", "limit=16"])):
            with self.subTest(command=command):
                out = self.root / (command + "-r\u00e9sultats")
                code, _, error = self.run_cli(command, str(self.sample), *args, "--out", str(out))
                self.assertEqual((code, error), (0, ""))
                self.assertEqual(sorted(p.name for p in out.iterdir()), ["report.json", "report.md"])
                for name, render in (("report.json", report.to_json), ("report.md", report.to_markdown)):
                    actual = (out / name).read_bytes()
                    self.assertEqual(actual, render(expected).encode("utf-8", "backslashreplace"))
                    self.assertNotIn(b"\r\n", actual)

    def test_an_existing_empty_directory_is_refused(self):
        out = self.root / "existing"
        out.mkdir()
        self.assert_refused(out)
        self.assertEqual(list(out.iterdir()), [])

    def test_an_existing_nonempty_directory_is_unchanged(self):
        out = self.root / "existing"
        out.mkdir()
        marker = out / "report.json"
        marker.write_bytes(b"do not replace")
        self.assert_refused(out)
        self.assertEqual(marker.read_bytes(), b"do not replace")
        self.assertEqual(sorted(p.name for p in out.iterdir()), ["report.json"])

    def test_an_existing_file_is_unchanged(self):
        out = self.root / "existing"
        out.write_bytes(b"do not replace")
        self.assert_refused(out)
        self.assertEqual(out.read_bytes(), b"do not replace")

    def test_a_junction_at_out_is_refused_without_writing_to_the_target(self):
        import _winapi
        target = self.root / "target"
        target.mkdir()
        link = self.root / "junction"
        _winapi.CreateJunction(str(target), str(link))
        try:
            self.assert_refused(link)
            self.assertEqual(list(target.iterdir()), [])
        finally:
            link.rmdir()

    def test_a_directory_symlink_at_out_is_refused_without_writing_to_the_target(self):
        target = self.root / "target"
        target.mkdir()
        link = self.root / "symlink"
        link.symlink_to(target, target_is_directory=True)
        try:
            self.assert_refused(link)
            self.assertEqual(list(target.iterdir()), [])
        finally:
            link.unlink()

    def test_the_bound_directory_cannot_be_renamed_until_its_handle_is_closed(self):
        out, moved = self.root / "bound", self.root / "moved"
        directory = cli.open_output(out)
        try:
            with self.assertRaises(OSError):
                os.rename(out, moved)
            cli.write_new(directory, "report.json", "bound\n")
        finally:
            directory.close()
        os.rename(out, moved)
        self.assertFalse(out.exists())
        self.assertEqual((moved / "report.json").read_bytes(), b"bound\n")

    def test_a_symlinked_input_is_refused_before_output_is_created(self):
        link, out = self.root / "linked-input", self.root / "new-output"
        link.symlink_to(self.sample)
        code, _, error = self.run_cli("analyze", str(link), "--out", str(out))
        self.assertEqual(code, 1)
        self.assertTrue(error.startswith("reverseai: input refused:"), error)
        self.assertNotIn("Traceback", error)
        self.assertNotIn(str(self.root), error)
        self.assertFalse(out.exists())

    def test_an_existing_report_is_not_opened_or_truncated(self):
        out = self.root / "bound"
        directory = cli.open_output(out)
        try:
            cli.write_new(directory, "report.md", "first\n")
            with self.assertRaises(OSError):
                cli.write_new(directory, "report.md", "replacement\n")
        finally:
            directory.close()
        self.assertEqual((out / "report.md").read_bytes(), b"first\n")


if __name__ == "__main__":
    unittest.main()
