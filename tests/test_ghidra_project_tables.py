"""Indexed project-table boundaries, with synthetic JSONL and uint64 indexes only."""

import importlib.util
import json
import math
from pathlib import Path
import re
import struct
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "ghidra_project_tables_under_test", ROOT / "containers" / "ghidra" / "project_cache.py"
)
cache = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cache)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


class SeekGuard:
    """Make a body seek visible even if a reader would subsequently reject the row."""
    def __init__(self, body):
        self.body = body
        self.seeks = []

    def seek(self, offset, *args):
        self.seeks.append(offset)
        raise AssertionError("body seek before checking both uint64 endpoints")

    def close(self):
        self.body.close()


class ProjectTableTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.parent = Path(self.temporary.name)

    def folder(self):
        return Path(tempfile.mkdtemp(dir=self.parent))

    def raw_table(self, body, offsets, *, index=None):
        folder = self.folder()
        (folder / "functions.jsonl").write_bytes(body)
        (folder / "functions.idx").write_bytes(
            b"".join(struct.pack("<Q", offset) for offset in offsets) if index is None else index)
        return folder

    def reader(self, folder, count):
        reader = cache.TableReader(folder, "functions", count)
        self.addCleanup(reader.close)
        return reader

    def reject_raw(self, body):
        folder = self.raw_table(body, [0])
        with self.assertRaises(cache.InvalidCachedProject):
            reader = self.reader(folder, 1)
            reader.row(0)

    def test_roundtrip_uses_byte_offsets_and_supports_random_row_access(self):
        folder = self.folder()
        values = [{"index": 0, "text": "caffè 🍵", "data": [True, None, 7]},
                  {"index": 1, "text": "line\ninside\tstring"}, {"index": 2, "text": "last"}]
        writer = cache.TableWriter(folder, "functions")
        try:
            for value in values:
                writer.add(value)
            self.assertEqual(writer.count, 3)
        finally:
            writer.close()
        lines = [encoded(value) + b"\n" for value in values]
        self.assertEqual((folder / "functions.jsonl").read_bytes(), b"".join(lines))
        self.assertEqual((folder / "functions.idx").read_bytes(),
                         struct.pack("<QQQ", 0, len(lines[0]), len(lines[0]) + len(lines[1])))
        reader = self.reader(folder, 3)
        self.assertEqual(reader.row(2), values[2])
        self.assertEqual(reader.row(0), values[0])
        self.assertEqual(list(reader.rows()), values)

    def test_empty_table_requires_both_files_to_be_exactly_empty(self):
        folder = self.folder()
        writer = cache.TableWriter(folder, "functions")
        writer.close()
        self.assertEqual((folder / "functions.jsonl").read_bytes(), b"")
        self.assertEqual((folder / "functions.idx").read_bytes(), b"")
        reader = self.reader(folder, 0)
        self.assertEqual(list(reader.rows()), [])
        with self.assertRaises(cache.InvalidCachedProject):
            reader.row(0)
        for body, index in ((b"\n", b""), (b"", bytes(8))):
            with self.subTest(body=body, index=index):
                invalid = self.raw_table(body, [], index=index)
                with self.assertRaises(cache.InvalidCachedProject):
                    self.reader(invalid, 0)

    def test_row_limit_is_4096_canonical_utf8_bytes_excluding_newline(self):
        self.assertEqual(cache.MAX_ROW_BYTES, 4096)
        # Include a multibyte scalar, so a character-count implementation also fails the boundary test.
        overhead = len(encoded({"text": ""}))
        exact = {"text": "é" + "x" * (4096 - overhead - 2)}
        self.assertEqual(len(encoded(exact)), 4096)
        folder = self.folder()
        writer = cache.TableWriter(folder, "functions")
        try:
            writer.add(exact)
            with self.assertRaises(cache.InvalidCachedProject):
                writer.add({"text": exact["text"] + "x"})
            self.assertEqual(writer.count, 1)
        finally:
            writer.close()
        self.assertEqual((folder / "functions.jsonl").read_bytes(), encoded(exact) + b"\n")
        self.assertEqual((folder / "functions.idx").read_bytes(), bytes(8))
        self.assertEqual(self.reader(folder, 1).row(0), exact)

    def test_oversized_row_is_refused_without_calling_json_decoder(self):
        folder = self.raw_table(encoded({"text": "x" * 4096}) + b"\n", [0])
        with patch.object(cache.json, "loads", side_effect=AssertionError("unbounded JSON decode")) as decoder:
            with self.assertRaises(cache.InvalidCachedProject):
                self.reader(folder, 1)
            decoder.assert_not_called()

    def test_exact_count_cap_and_cap_plus_one_for_every_table(self):
        for name in ("functions", "calls", "references", "strings"):
            with self.subTest(table=name), patch.dict(cache.CAPS, {name: 2}):
                folder = self.folder()
                writer = cache.TableWriter(folder, name)
                try:
                    writer.add({"index": 0})
                    writer.add({"index": 1})
                    with self.assertRaises(cache.ProjectTooLarge):
                        writer.add({"index": 2})
                    self.assertEqual(writer.count, 2)
                finally:
                    writer.close()
                reader = cache.TableReader(folder, name, 2)
                try:
                    self.assertEqual(list(reader.rows()), [{"index": 0}, {"index": 1}])
                finally:
                    reader.close()
                with self.assertRaises(cache.InvalidCachedProject):
                    cache.TableReader(folder, name, 3)

    def test_shared_budget_counts_both_table_indexes_and_newlines_before_append(self):
        folder = self.folder()
        first, second = {"v": 1}, {"v": "é"}
        budget = {"bytes": 0}
        # Each row consumes its UTF-8 body, one LF and one eight-byte uint64 index entry.
        exact = len(encoded(first)) + len(encoded(second)) + 18
        writers = [cache.TableWriter(folder, "functions", budget=budget),
                   cache.TableWriter(folder, "calls", budget=budget)]
        try:
            with patch.object(cache, "MAX_UNPACKED_BYTES", exact):
                writers[0].add(first)
                writers[1].add(second)
                self.assertEqual(budget, {"bytes": exact})
                for writer in writers:
                    with self.assertRaises(cache.ProjectTooLarge):
                        writer.add({"extra": True})
                    self.assertEqual(writer.count, 1)
                self.assertEqual(budget, {"bytes": exact})
        finally:
            for writer in writers:
                writer.close()
        for name, value in (("functions", first), ("calls", second)):
            self.assertEqual((folder / (name + ".jsonl")).read_bytes(), encoded(value) + b"\n")
            self.assertEqual((folder / (name + ".idx")).read_bytes(), bytes(8))

    def test_bool_and_noninteger_counts_fail_before_opening_any_file(self):
        for count in (True, False, -1, 1.0, "1", None, 65537):
            with self.subTest(count=count), patch("builtins.open", side_effect=AssertionError("invalid count opened files")) as opened:
                with self.assertRaises(cache.InvalidCachedProject):
                    cache.TableReader(self.parent, "functions", count)
                opened.assert_not_called()

    def test_bad_row_positions_fail_before_body_seek(self):
        folder = self.raw_table(b"{}\n", [0])
        reader = self.reader(folder, 1)
        guard = SeekGuard(reader.body)
        reader.body = guard
        for position in (True, False, -1, 1, 0.0, "0", None):
            with self.subTest(position=position), self.assertRaises(cache.InvalidCachedProject):
                reader.row(position)
        self.assertEqual(guard.seeks, [])

    def test_short_extra_and_truncated_index_files_are_rejected(self):
        for index in (b"", bytes(7), bytes(9), bytes(15), bytes(24)):
            with self.subTest(index_bytes=len(index)):
                folder = self.raw_table(b"{}\n{}\n", [], index=index)
                with self.assertRaises(cache.InvalidCachedProject):
                    self.reader(folder, 2)

    def test_first_offset_must_be_zero_even_when_remaining_span_would_parse(self):
        for first in (1, 3, 2**63, 2**64 - 1):
            with self.subTest(first=first):
                folder = self.raw_table(b"x{}\n", [first])
                with self.assertRaises(cache.InvalidCachedProject):
                    self.reader(folder, 1)

    def test_both_offsets_and_last_body_endpoint_are_checked_before_any_seek(self):
        body = b"{}\n{}\n"
        # row 0 has a valid start but corrupt end; row 1 exposes corrupt starts and reversed spans.
        cases = [([0, 0], 0), ([0, 1], 0), ([0, len(body) + 1], 0), ([0, 2**63], 0),
                 ([0, 2**64 - 1], 0), ([0, len(body)], 1), ([0, len(body) + 1], 1),
                 ([0, 2**64 - 1], 1)]
        for offsets, position in cases:
            with self.subTest(offsets=offsets, position=position):
                reader = self.reader(self.raw_table(body, offsets), 2)
                guard = SeekGuard(reader.body)
                reader.body = guard
                with patch.object(cache.json, "loads", side_effect=AssertionError("decode before span validation")) as decoder:
                    with self.assertRaises(cache.InvalidCachedProject):
                        reader.row(position)
                    decoder.assert_not_called()
                self.assertEqual(guard.seeks, [])

    def test_oversized_indexed_span_is_checked_even_when_total_body_fits_count_budget(self):
        body = b"x" * 4098 + b"{}\n"
        reader = self.reader(self.raw_table(body, [0, 4098]), 2)
        guard = SeekGuard(reader.body)
        reader.body = guard
        with patch.object(cache.json, "loads", side_effect=AssertionError("oversized JSON decode")) as decoder:
            with self.assertRaises(cache.InvalidCachedProject):
                reader.row(0)
            decoder.assert_not_called()
        self.assertEqual(guard.seeks, [])

    def test_truncated_body_and_missing_or_extra_newlines_are_rejected(self):
        for body in (b"{", b"{}", b"{}\n{}\n", b"{}\n\n", b"{\n}\n"):
            with self.subTest(body=body):
                self.reject_raw(body)

    def test_noncanonical_duplicate_nonfinite_and_hostile_json_are_rejected(self):
        cases = [b'{"x":1,"x":2}\n', b'{"x":{"a":1,"a":2}}\n', b'{"x":NaN}\n',
                 b'{"x":Infinity}\n', b'{"x":-Infinity}\n', b'{"x":1e999}\n', b'{"x": 1}\n',
                 b'{"z":1,"a":2}\n', b'{"x":"\\u0061"}\n', b'{"x":"\\/"}\n', b'{"x":-0}\n',
                 b'{"x":"\xff"}\n', b'"\xed\xa0\x80"\n', b'\xef\xbb\xbf{}\n', b'{}\x00\n',
                 b'{"x":01}\n', b'{"x":true,}\n', b'not json\n', b'[' * 1500 + b'0' + b']' * 1499 + b'\n']
        for body in cases:
            with self.subTest(body=body[:70]):
                self.reject_raw(body)

    def test_escaped_lone_surrogates_are_a_fixed_invalid_cache_error(self):
        for body in (b'{"x":"\\ud800"}\n', b'{"x":"\\udfff"}\n', b'{"\\ud800":1}\n'):
            with self.subTest(body=body):
                self.reject_raw(body)

    def test_writer_rejects_nonfinite_numbers_and_surrogates_without_appending(self):
        for value in ({"x": math.nan}, {"x": math.inf}, {"x": -math.inf}, {"x": "\ud800"}, {"\udfff": 1}):
            with self.subTest(value=repr(value)):
                folder = self.folder()
                writer = cache.TableWriter(folder, "functions")
                try:
                    writer.add({"index": 0})
                    with self.assertRaises(cache.InvalidCachedProject):
                        writer.add(value)
                    self.assertEqual(writer.count, 1)
                finally:
                    writer.close()
                self.assertEqual((folder / "functions.jsonl").read_bytes(), b'{"index":0}\n')
                self.assertEqual((folder / "functions.idx").read_bytes(), bytes(8))

    def test_declared_producer_and_consumer_limits_match_the_contract(self):
        self.assertEqual(cache.CAPS, {"functions": 65536, "calls": 262144, "references": 262144, "strings": 65536})
        java = (ROOT / "containers/ghidra/ghidra_scripts/ReverseAIPrepare.java").read_text()
        worker = (ROOT / "containers/ghidra/worker.py").read_text()
        for name, expected in (("MAX_FUNCTIONS", 65536), ("MAX_CALLS", 262144), ("MAX_REFERENCES", 262144),
                               ("MAX_FUNCTION_VISITS", 1000000), ("MAX_INSTRUCTION_VISITS", 8388608)):
            with self.subTest(java_constant=name):
                match = re.search(r"\b" + name + r"\s*=\s*([0-9_]+)\s*;", java)
                self.assertIsNotNone(match)
                self.assertEqual(int(match.group(1).replace("_", "")), expected)
        for name, expected in (("MAX_FUNCTION_INSTRUCTIONS", 1000000), ("MAX_INSTRUCTION_VISITS", 8388608)):
            with self.subTest(worker_constant=name):
                match = re.search(r"^" + name + r"\s*=\s*([0-9_]+)\s*(?:#.*)?$", worker, re.MULTILINE)
                self.assertIsNotNone(match)
                self.assertEqual(int(match.group(1).replace("_", "")), expected)


if __name__ == "__main__":
    unittest.main()
