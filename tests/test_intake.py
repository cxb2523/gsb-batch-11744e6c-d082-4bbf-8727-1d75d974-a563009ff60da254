import json
import os
from pathlib import Path
import stat
import tempfile
import threading
import unittest
from unittest.mock import patch

from reverseai import intake
from reverseai.contract import ContractError, InputRef, sha256_hex


class Changed:
    """An fstat result whose selected fields differ from the real one."""

    def __init__(self, value, **changes):
        self.value, self.changes = value, changes

    def __getattr__(self, name):
        return self.changes.get(name, getattr(self.value, name))


class IntakeTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.sample = self.root / "sample.bin"
        self.sample.write_bytes(b"\x7fELF frozen bytes")

    def refused(self, path, message):
        with self.assertRaises(intake.IntakeError) as caught:
            intake.snapshot(path)
        self.assertIsInstance(caught.exception, ContractError)
        self.assertEqual(str(caught.exception), message)
        self.assertNotIn(str(self.root), str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)  # no OSError text with the path is chained

    def test_a_regular_file_is_frozen_with_its_basename(self):
        data, ref = intake.snapshot(self.sample)
        self.assertEqual(data, b"\x7fELF frozen bytes")
        self.assertEqual(ref, InputRef(sha256=sha256_hex(data), size=len(data), name="sample.bin"))
        self.assertEqual(intake.snapshot(str(self.sample)), (data, ref))

    def test_links_and_non_regular_files_are_refused(self):
        link = self.root / "link.bin"
        link.symlink_to(self.sample)
        self.refused(link, "Symlinks and reparse points cannot be input files")
        self.refused(self.root, "Only a regular file can be an input")
        hard = self.root / "hard.bin"
        os.link(self.sample, hard)
        self.refused(self.sample, "Hard-linked input files need a separate copy")
        self.refused(hard, "Hard-linked input files need a separate copy")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFOs need a POSIX host")
    def test_a_fifo_is_refused_without_blocking(self):
        fifo = self.root / "pipe"
        os.mkfifo(fifo)
        self.refused(fifo, "Only a regular file can be an input")

    def test_a_missing_file_is_refused_without_its_path(self):
        self.refused(self.root / "missing.bin", "Input file could not be inspected")

    def test_the_size_limit_is_enforced(self):
        with patch.object(intake, "MAX_INPUT_BYTES", 4):
            self.refused(self.sample, "Input file exceeds the byte limit")
        with patch.object(intake, "MAX_INPUT_BYTES", len(self.sample.read_bytes())):
            self.assertEqual(intake.snapshot(self.sample)[1].size, len(self.sample.read_bytes()))

    def test_a_file_replaced_or_changed_during_the_read_is_refused(self):
        real = os.fstat
        def replaced(descriptor):
            return Changed(real(descriptor), st_ino=real(descriptor).st_ino + 1)
        with patch.object(intake.os, "fstat", side_effect=replaced):
            self.refused(self.sample, "Input file changed identity while opening")
        calls = []
        def grown(descriptor):
            calls.append(descriptor)
            value = real(descriptor)
            return Changed(value, st_size=value.st_size + 1) if len(calls) > 1 else value
        with patch.object(intake.os, "fstat", side_effect=grown):
            self.refused(self.sample, "Input changed while reading")
        calls.clear()
        def touched(descriptor):
            calls.append(descriptor)
            value = real(descriptor)
            return Changed(value, st_mtime_ns=value.st_mtime_ns + 1) if len(calls) > 1 else value
        with patch.object(intake.os, "fstat", side_effect=touched):
            self.refused(self.sample, "Input changed while reading")

    def test_an_empty_file_is_frozen(self):
        empty = self.root / "empty.bin"
        empty.write_bytes(b"")
        self.assertEqual(intake.snapshot(empty), (b"", InputRef(sha256=sha256_hex(b""), size=0, name="empty.bin")))

    def test_a_nul_in_the_path_is_an_intake_error(self):
        self.refused(str(self.root) + "/a\x00b", "Input file could not be inspected")

    def test_non_utf8_names_become_escapes_that_reports_can_encode(self):
        name = intake.display_name(Path(os.fsdecode(b"/any/bad\xffname.bin")))
        self.assertEqual(name, "bad\\xffname.bin")
        json.dumps(name).encode("utf-8")
        self.assertEqual(len(intake.display_name(Path("n" * 300))), 255)

    def test_a_literal_backslash_never_looks_like_an_escaped_byte(self):
        text = intake.display_name(Path(os.fsdecode(b"/any/a\\xffb.bin")))  # the four characters \ x f f
        byte = intake.display_name(Path(os.fsdecode(b"/any/a\xffb.bin")))  # the single byte 0xFF
        self.assertEqual((text, byte), ("a\\x5cxffb.bin", "a\\xffb.bin"))
        self.assertEqual(intake.display_name(Path("caf\u00e9 \u6587\u4ef6.bin")), "caf\u00e9 \u6587\u4ef6.bin")

    def test_truncation_keeps_whole_escapes(self):
        cases = (
            (b"n" * 251 + b"\xff", "n" * 251 + "\\xff"),  # exactly 255 characters: unchanged
            (b"n" * 252 + b"\xff\xfe", "n" * 252 + "\u2026"),  # the escape would cross 254: dropped whole
            (b"n" * 250 + b"\\" + b"n" * 10, "n" * 250 + "\\x5c" + "\u2026"),
            (b"\xff" * 100, "\\xff" * 63 + "\u2026"),
        )
        for raw, expected in cases:
            with self.subTest(raw=raw[-12:]):
                shown = intake.display_name(Path(os.fsdecode(b"/any/" + raw)))
                self.assertEqual(shown, expected)
                self.assertLessEqual(len(shown), 255)

    def test_a_final_ellipsis_always_means_truncation(self):
        whole = intake.display_name(Path("n" * 240 + "\u2026"))  # 252 characters once escaped: not truncated
        self.assertEqual(whole, "n" * 240 + "\\xe2\\x80\\xa6")
        self.assertEqual(intake.display_name(Path("n" * 300)), "n" * 254 + "\u2026")
        self.assertEqual(intake.display_name(Path("n" * 250 + "\u2026")), "n" * 250 + "\\xe2\u2026")  # whole escapes kept

    def test_escapes_start_at_byte_0x80(self):
        self.assertEqual(intake.display_name(Path(os.fsdecode(b"/any/a\x7fb\x80c\xffd"))), "a\x7fb\\x80c\\xffd")

    def test_the_input_ref_uses_the_display_name(self):
        with patch.object(intake, "display_name", return_value="shown.bin") as shown:
            self.assertEqual(intake.snapshot(self.sample)[1].name, "shown.bin")
        shown.assert_called_once()

    def test_a_real_non_utf8_file_name_reaches_the_input_ref_escaped(self):
        try:
            raw = os.fsencode(self.root) + b"/bad\xffname.bin"
            with open(raw, "wb") as handle:
                handle.write(b"x")
        except OSError:
            self.skipTest("this file system refuses non-UTF-8 names")  # macOS APFS does
        self.assertEqual(intake.snapshot(os.fsdecode(raw))[1].name, "bad\\xffname.bin")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFOs need a POSIX host")
    def test_a_fifo_swapped_in_after_inspection_is_refused_without_blocking(self):
        real = intake._regular_stat
        def swap(path):
            value = real(path)
            path.unlink()
            os.mkfifo(path)
            return value
        outcome = []
        def attempt():
            try:
                intake.snapshot(self.sample)
            except intake.IntakeError as error:
                outcome.append(str(error))
        with patch.object(intake, "_regular_stat", side_effect=swap):
            worker = threading.Thread(target=attempt, daemon=True)
            worker.start()
            worker.join(timeout=10)
        if worker.is_alive():  # unblock the reader before failing
            os.close(os.open(self.sample, os.O_WRONLY | os.O_NONBLOCK))
            self.fail("opening a FIFO blocked: O_NONBLOCK is missing")
        self.assertEqual(outcome, ["Input file changed identity while opening"])

    def test_the_open_handle_is_checked_again(self):
        real = os.fstat
        for label, changes, message in (
                ("second hard link", {"st_nlink": 2}, "Input file changed identity while opening"),
                ("not a regular file", {"st_mode": stat.S_IFIFO | 0o644}, "Input file changed identity while opening")):
            with self.subTest(label), patch.object(intake.os, "fstat", side_effect=lambda fd, c=changes: Changed(real(fd), **c)):
                self.refused(self.sample, message)
        calls = []
        def ctime_changed(descriptor):
            calls.append(descriptor)
            value = real(descriptor)
            return Changed(value, st_ctime_ns=value.st_ctime_ns + 1) if len(calls) > 1 else value
        with patch.object(intake.os, "fstat", side_effect=ctime_changed):
            self.refused(self.sample, "Input changed while reading")

    def test_a_link_swapped_in_after_inspection_is_not_followed(self):
        if not getattr(os, "O_NOFOLLOW", 0):
            self.skipTest("O_NOFOLLOW is not available on this host")
        target = self.root / "target.bin"
        target.write_bytes(b"other bytes")
        real = intake._regular_stat
        def swap(path):
            value = real(path)
            path.unlink()
            path.symlink_to(target)
            return value
        with patch.object(intake, "_regular_stat", side_effect=swap):
            self.refused(self.sample, "Input file could not be opened")


if __name__ == "__main__":
    unittest.main()
