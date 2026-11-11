"""Closed, bounded USTAR project transfers; all archive bytes are synthetic.

These tests run without Ghidra, containers, stored samples or third-party modules.
The fixture writer deliberately does not use the production archive writer.
"""

import hashlib
import importlib.util
import io
import os
from pathlib import Path
import stat
import tarfile
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "ghidra_project_cache_under_test", ROOT / "containers" / "ghidra" / "project_cache.py"
)
cache = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cache)

BLOCK = 512
REPO = "cache/project/reverseai.rep"
TABLES = ("functions", "calls", "references", "strings")
REQUIRED = {"cache/project/reverseai.gpr", REPO, "cache/tables/meta.json"} | {
    f"cache/tables/{table}.{suffix}" for table in TABLES for suffix in ("jsonl", "idx")
}


def checksum(header):
    result = bytearray(header)
    result[148:156] = b" " * 8
    result[148:156] = f"{sum(result):06o}\0 ".encode("ascii")
    return bytes(result)


def member(name, body=b"", *, kind=b"0", mode=0o600, prefix="", fields=()):
    """An independently encoded POSIX USTAR header, body and zero block padding."""
    name = name.encode("ascii") if isinstance(name, str) else name
    prefix = prefix.encode("ascii") if isinstance(prefix, str) else prefix
    if len(name) > 100 or len(prefix) > 155:
        raise ValueError("fixture name requires a USTAR prefix")
    header = bytearray(BLOCK)
    header[:len(name)] = name
    header[100:108] = f"{mode:07o}\0".encode("ascii")
    header[108:116] = b"0000000\0"
    header[116:124] = b"0000000\0"
    header[124:136] = f"{len(body):011o}\0".encode("ascii")
    header[136:148] = b"00000000000\0"
    header[156:157] = kind
    header[257:265] = b"ustar\0" + b"00"
    header[329:337] = b"0000000\0"
    header[337:345] = b"0000000\0"
    header[345:345 + len(prefix)] = prefix
    for start, data in fields:
        header[start:start + len(data)] = data
    if len(header) != BLOCK:
        raise ValueError("fixture header field has the wrong width")
    return checksum(header) + body + bytes((-len(body)) % BLOCK)


def entries():
    result = [
        ("cache", None),
        ("cache/project", None),
        ("cache/project/reverseai.gpr", b"synthetic project\0\xff\n"),
        (REPO, None),
        (REPO + "/db", None),
        (REPO + "/db/project.dat", bytes(range(256)) * 3),
        ("cache/tables", None),
        ("cache/tables/meta.json", b'{"format":1}\n'),
    ]
    for table in TABLES:
        result.extend([(f"cache/tables/{table}.jsonl", b"{}\n"),
                       (f"cache/tables/{table}.idx", bytes(8))])
    return result


def archive(items=None, *, extra=(), end=bytes(1024)):
    items = entries() if items is None else items
    blocks = [member(name, body or b"", kind=b"5" if body is None else b"0") for name, body in items]
    return b"".join([*blocks, *extra]) + end


def tree(root, items=None):
    for name, body in entries() if items is None else items:
        target = root / name
        if body is None:
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(body)


class ShortSink:
    def __init__(self, limit=7):
        self.limit = limit
        self.data = bytearray()

    def write(self, data):
        count = min(self.limit, len(data))
        self.data.extend(data[:count])
        return count


class ProjectArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.parent = Path(self.temporary.name)

    def reject(self, data, *, expected_hash=None, error=None):
        """A late bad member must fail before even creating the restore root."""
        destination = self.parent / "restore"
        digest = hashlib.sha256(data).hexdigest() if expected_hash is None else expected_hash
        with patch.object(Path, "mkdir", side_effect=AssertionError("mkdir before validation")) as mkdir, \
                patch.object(os, "open", side_effect=AssertionError("open before validation")) as opened:
            with self.assertRaises(error or cache.InvalidCachedProject):
                cache.unpack_project(io.BytesIO(data), digest, destination)
            mkdir.assert_not_called()
            opened.assert_not_called()
        self.assertFalse(destination.exists())
        self.assertEqual(list(self.parent.iterdir()), [])

    def assert_tree(self, root, items=None):
        expected = dict(entries() if items is None else items)
        actual = {path.relative_to(root).as_posix(): path for path in root.rglob("*")}
        self.assertEqual(set(actual), set(expected))
        self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
        for name, body in expected.items():
            with self.subTest(name=name):
                path = actual[name]
                self.assertFalse(path.is_symlink())
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700 if body is None else 0o600)
                self.assertEqual(path.is_dir(), body is None)
                if body is not None:
                    self.assertEqual(path.read_bytes(), body)

    def test_closed_ustar_roundtrip_preserves_only_declared_bytes_and_private_modes(self):
        data = archive()
        restored = self.parent / "restore"
        self.assertEqual(cache.unpack_project(io.BytesIO(data), hashlib.sha256(data).hexdigest(), restored),
                         restored / "cache")
        self.assert_tree(restored)
        output = io.BytesIO()
        size, digest = cache.pack_project(restored, output)
        packed = output.getvalue()
        self.assertEqual((size, digest), (len(packed), hashlib.sha256(packed).hexdigest()))
        with tarfile.open(fileobj=io.BytesIO(packed), mode="r:") as reader:
            members = reader.getmembers()
            self.assertEqual({item.name.rstrip("/") for item in members}, set(dict(entries())))
            for item in members:
                self.assertTrue(item.isdir() or item.isfile())
                self.assertEqual(item.mode, 0o700 if item.isdir() else 0o600)
        second = self.parent / "second"
        cache.unpack_project(io.BytesIO(packed), digest, second)
        self.assert_tree(second)

    def test_valid_prefix_null_regular_type_and_zero_end_padding(self):
        extra_name = "a" * 64 + "/" + "b" * 64
        extra = member("b" * 64, b"prefix body", prefix=REPO + "/" + "a" * 64, kind=b"\0")
        data = archive(extra=[extra], end=bytes(4096))
        root = self.parent / "restore"
        cache.unpack_project(io.BytesIO(data), hashlib.sha256(data).hexdigest(), root)
        self.assert_tree(root, entries() + [(REPO + "/" + "a" * 64, None),
                                          (REPO + "/" + extra_name, b"prefix body")])

    def test_hash_mismatch_or_malformed_digest_never_creates_root(self):
        data = archive()
        for digest in ("0" * 64, "F" * 64, "1" * 63, "../digest", 1, None):
            with self.subTest(digest=digest):
                # None normally selects the fixture hash in reject().
                if digest is None:
                    with patch.object(Path, "mkdir", side_effect=AssertionError("premature write")) as mkdir:
                        with self.assertRaises(cache.InvalidCachedProject):
                            cache.unpack_project(io.BytesIO(data), digest, self.parent / "restore")
                        mkdir.assert_not_called()
                else:
                    self.reject(data, expected_hash=digest)

    def test_bad_checksum_is_rejected_after_an_otherwise_complete_tree(self):
        broken = bytearray(member(REPO + "/late", b"data"))
        broken[0] ^= 1
        self.reject(archive(extra=[bytes(broken)]))

    def test_only_posix_ustar_magic_and_version_are_accepted(self):
        for start, value in ((257, b"ustar "), (257, bytes(6)), (263, b" \0"), (263, b"01")):
            with self.subTest(start=start, value=value):
                self.reject(archive(extra=[member(REPO + "/late", fields=[(start, value)])]))

    def test_links_extensions_devices_and_other_types_are_rejected(self):
        for kind in (b"1", b"2", b"3", b"4", b"6", b"7", b"x", b"g", b"L", b"K", b"S", b"9"):
            with self.subTest(kind=kind):
                self.reject(archive(extra=[member(REPO + "/late", kind=kind)]))

    def test_regular_files_and_directories_cannot_hide_a_link_target(self):
        for kind in (b"0", b"5"):
            with self.subTest(kind=kind):
                self.reject(archive(extra=[member(REPO + "/late", kind=kind,
                                                  fields=[(157, b"../../outside")])]))

    def test_names_cannot_escape_or_expand_the_closed_namespace(self):
        names = ["/" + REPO + "/bad", REPO + "/./bad", REPO + "/../bad", REPO + "//bad",
                 REPO + "/bad/", REPO + "/space name", REPO + "/bad\\name", "", "../outside",
                 "cache/other", "cache/project/other", "cache/tables/other.json", "cache/project/reverseai.gpr/child",
                 REPO + "/" + "a" * 65, b"cache/project/reverseai.rep/\xff"]
        for name in names:
            with self.subTest(name=name):
                self.reject(archive(extra=[member(name)]))

    def test_name_depth_and_total_length_limits(self):
        names = [REPO + "/" + "/".join(["a"] * 14),
                 REPO + "/" + "/".join(["a" * 60] * 3 + ["a" * 32])]
        for name in names:
            with self.subTest(name=name):
                # Both USTAR name fields fit even though the restored path is invalid.
                split = next(index for index, char in enumerate(name)
                             if char == "/" and index <= 155 and len(name) - index - 1 <= 100)
                prefix, leaf = name[:split], name[split + 1:]
                self.reject(archive(extra=[member(leaf, prefix=prefix)]))

    def test_nonzero_bytes_after_a_name_terminator_are_rejected(self):
        self.reject(archive(extra=[member(REPO + "/late", fields=[(90, b"\0hidden")])]))
        self.reject(archive(extra=[member("late", prefix=REPO, fields=[(400, b"\0hidden")])]))

    def test_duplicates_and_directory_slash_aliases_are_rejected(self):
        extra_sets = [
            [member(REPO + "/duplicate"), member(REPO + "/duplicate")],
            [member(REPO + "/dir", kind=b"5"), member(REPO + "/dir/", kind=b"5")],
            [member("cache/tables/meta.json")],
        ]
        for extra in extra_sets:
            with self.subTest(extra=extra):
                self.reject(archive(extra=extra))

    def test_case_collisions_include_implicit_parent_directories(self):
        for first, second in (("same", "SAME"), ("branch/a", "BRANCH/b"), ("Branch/a", "branch")):
            with self.subTest(first=first, second=second):
                self.reject(archive(extra=[member(REPO + "/" + first), member(REPO + "/" + second)]))

    def test_a_file_cannot_be_a_parent_in_either_header_order(self):
        parent, child = member(REPO + "/node"), member(REPO + "/node/child")
        self.reject(archive(extra=[parent, child]))
        self.reject(archive(extra=[child, parent]))

    def test_base256_is_rejected_in_every_numeric_field(self):
        for start, width in ((100, 8), (108, 8), (116, 8), (124, 12), (136, 12), (329, 8), (337, 8)):
            with self.subTest(start=start):
                self.reject(archive(extra=[member(REPO + "/late", fields=[(start, b"\x80" + bytes(width - 1))])]))
        broken = bytearray(member(REPO + "/late"))
        broken[148:156] = b"\x80" + bytes(7)
        self.reject(archive(extra=[bytes(broken)]))

    def test_non_octal_sizes_and_modes_are_rejected(self):
        for start, value in ((124, b"00000000009\0"), (124, b"-0000000001\0"),
                             (124, bytes(12)), (100, b"0000009\0")):
            with self.subTest(start=start, value=value):
                self.reject(archive(extra=[member(REPO + "/late", fields=[(start, value)])]))

    def test_setid_and_sticky_bits_are_rejected(self):
        for mode in (0o4600, 0o2600, 0o1600, 0o7700):
            with self.subTest(mode=mode):
                self.reject(archive(extra=[member(REPO + "/late", mode=mode)]))

    def test_directory_body_and_nonzero_file_padding_are_rejected(self):
        self.reject(archive(extra=[member(REPO + "/dir", b"x", kind=b"5")]))
        padded = bytearray(member(REPO + "/late", b"x"))
        padded[-1] = 1
        self.reject(archive(extra=[bytes(padded)]))

    def test_two_zero_end_blocks_are_required_and_trailing_junk_is_rejected(self):
        for end in (b"", bytes(512), bytes(512) + b"x" + bytes(511), bytes(1024) + b"x" + bytes(511)):
            with self.subTest(end_length=len(end), nonzero=bool(end.strip(b"\0"))):
                self.reject(archive(end=end))

    def test_truncated_headers_body_and_end_blocks_are_rejected(self):
        complete = archive()
        for data in (b"", complete[:-1], complete[:-513], complete[:-1025], complete[:100],
                     archive(extra=[member(REPO + "/late", fields=[(124, b"00000100000\0")])])):
            with self.subTest(size=len(data)):
                self.reject(data)

    def test_each_required_member_is_checked_before_any_restore_write(self):
        for missing in sorted(REQUIRED):
            with self.subTest(missing=missing):
                self.reject(archive([(name, body) for name, body in entries() if name != missing]))

    def test_all_restore_caps_are_enforced_before_writes_at_small_limits(self):
        data = archive()
        caps = {"MAX_FILES": len(entries()) - 1, "MAX_TAR_BYTES": len(data) - 1,
                "MAX_UNPACKED_BYTES": sum(len(body) for _, body in entries() if body is not None) - 1}
        for name, value in caps.items():
            with self.subTest(cap=name), patch.object(cache, name, value):
                self.reject(data, error=cache.ProjectTooLarge)

    def test_restore_accepts_exact_caps(self):
        data = archive()
        with patch.object(cache, "MAX_FILES", len(entries())), patch.object(cache, "MAX_TAR_BYTES", len(data)), \
                patch.object(cache, "MAX_UNPACKED_BYTES", sum(len(body) for _, body in entries() if body is not None)):
            cache.unpack_project(io.BytesIO(data), hashlib.sha256(data).hexdigest(), self.parent / "restore")
        self.assert_tree(self.parent / "restore")

    def test_restore_refuses_existing_directory_file_and_symlink_without_modifying_them(self):
        data = archive()
        destination = self.parent / "restore"
        destination.mkdir()
        (destination / "sentinel").write_bytes(b"keep directory")
        file = self.parent / "file"
        file.write_bytes(b"keep file")
        link = self.parent / "link"
        link.symlink_to(destination, target_is_directory=True)
        for target in (destination, file, link):
            with self.subTest(target=target.name), self.assertRaises((FileExistsError, cache.InvalidCachedProject)):
                cache.unpack_project(io.BytesIO(data), hashlib.sha256(data).hexdigest(), target)
        self.assertEqual((destination / "sentinel").read_bytes(), b"keep directory")
        self.assertEqual(list(destination.iterdir()), [destination / "sentinel"])
        self.assertEqual(file.read_bytes(), b"keep file")
        self.assertTrue(link.is_symlink())

    def test_pack_rejects_file_count_and_body_caps_before_emitting_bytes(self):
        tree(self.parent)
        for name, value in (("MAX_FILES", len(entries()) - 1), ("MAX_UNPACKED_BYTES", 1)):
            sink = io.BytesIO()
            with self.subTest(cap=name), patch.object(cache, name, value), self.assertRaises(cache.ProjectTooLarge):
                cache.pack_project(self.parent, sink)
            self.assertEqual(sink.getvalue(), b"")

    def test_streaming_output_never_exceeds_cap_including_tar_padding(self):
        tree(self.parent, entries() + [(REPO + "/large", b"x" * 40960)])
        sink = io.BytesIO()
        cap = 16384
        with patch.object(cache, "MAX_TAR_BYTES", cap), self.assertRaises(cache.ProjectTooLarge):
            cache.pack_project(self.parent, sink)
        self.assertGreater(len(sink.getvalue()), 0)
        self.assertLessEqual(len(sink.getvalue()), cap)
        small = self.parent / "small"
        tree(small)
        # The final record padding also counts even when all member bytes fit.
        with patch.object(cache, "MAX_TAR_BYTES", len(archive())), self.assertRaises(cache.ProjectTooLarge):
            cache.pack_project(small, io.BytesIO())

    def test_shortwrite_sink_receives_every_byte_and_the_reported_digest(self):
        tree(self.parent)
        ordinary = io.BytesIO()
        expected_result = cache.pack_project(self.parent, ordinary)
        short = ShortSink()
        result = cache.pack_project(self.parent, short)
        self.assertEqual(bytes(short.data), ordinary.getvalue())
        self.assertEqual(result, expected_result)
        self.assertEqual(result, (len(short.data), hashlib.sha256(short.data).hexdigest()))

    def test_sink_no_progress_or_invalid_counts_fail_instead_of_looping(self):
        tree(self.parent)
        for result in (0, -1, None, True, "1", 1000000):
            class BadSink:
                def write(self, data):
                    return result

            with self.subTest(result=result), self.assertRaises(cache.InvalidCachedProject):
                cache.pack_project(self.parent, BadSink())


if __name__ == "__main__":
    unittest.main()
