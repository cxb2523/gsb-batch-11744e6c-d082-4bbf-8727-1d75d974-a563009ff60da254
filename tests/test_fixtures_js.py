"""The JavaScript fixtures checked against their own declared layouts with readers written here, zipfile and json,
so the JavaScript tests can trust the layouts as expectations."""

import hashlib
import io
import json
from pathlib import Path
import re
import unittest
import zipfile

from reverseai.contract import ContractError
from reverseai.tools import apk
from tests import fixtures_js as J

# Pinned so a change of host zlib or Python cannot change the fixture bytes unnoticed.
APP_SHA256 = "fdab5ef30f0a57bb4f201b76e0f14fc69cf0f32458fbc89c944d743207fedfb2"
BUNDLE_SHA256 = "22d65a14ccb720fc7147e4723cc174dab1fc5407903b60d987fa4fa4ec40542b"
APP_FILES = ("node_modules/left-pad/package.json", "node_modules/left-pad/index.js", "package.json", "lib/index.js",
             "lib/loader.mjs", "src/config.ts", "dist/app.min.js", "lib/util.cjs", "lib/Legacy.JS")


def strict_json(data):
    """RFC 8259 as the contract's reader: UTF-8 without a byte order mark, one object, no duplicate key, no NaN or
    Infinity, no lone surrogate."""
    def pairs(items):
        keys = [key for key, _ in items]
        if len(set(keys)) != len(keys):
            raise ValueError("duplicate key")
        return dict(items)

    def constant(name):
        raise ValueError(name)

    value = json.loads(data.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    json.dumps(value, ensure_ascii=False).encode("utf-8")  # a lone surrogate cannot be encoded
    if data.startswith(b"\xef\xbb\xbf") or not isinstance(value, dict):
        raise ValueError("not one JSON object")
    return value


def pointer(document, path):
    for segment in path.split("/")[1:]:
        segment = segment.replace("~1", "/").replace("~0", "~")
        document = document[int(segment)] if isinstance(document, list) else document[segment]
    return document


def metrics(data):
    """lines and max_line counted byte by byte."""
    lines = longest = run = 0
    for byte in data:
        if byte == 0x0A:
            lines, longest, run = lines + 1, max(longest, run), 0
        else:
            run += 1
    return lines + (run > 0), max(longest, run)


def depth(data):
    deepest = level = 0
    for byte in data:
        level += (byte in b"[{") - (byte in b"]}")
        deepest = max(deepest, level)
    return deepest


class ApplicationFixtureTests(unittest.TestCase):
    def setUp(self):
        self.data, self.layout = J.app_zip()

    def test_the_bytes_are_pinned_and_zipfile_reads_every_member_back(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), APP_SHA256)
        self.assertEqual(self.layout["sha256"], APP_SHA256)
        with zipfile.ZipFile(io.BytesIO(self.data)) as archive:
            self.assertIsNone(archive.testzip())
            infos = archive.infolist()
            self.assertEqual([info.filename for info in infos], [*APP_FILES, "README.md"])
            self.assertEqual([info.compress_type for info in infos], [8, 8, 8, 8, 0, 8, 8, 8, 8, 8])
            for row in self.layout["files"]:
                self.assertEqual(archive.read(row["name"]), row["data"])
        self.assertEqual([m.flags for m in apk.members(self.data)], [()] * 10)

    def test_the_files_are_the_javascript_members_with_their_rows(self):
        self.assertEqual([row["name"] for row in self.layout["files"]], list(APP_FILES))
        for index, row in enumerate(self.layout["files"]):
            data = row["data"]
            self.assertEqual(row["member"], index if index < 9 else None)
            self.assertEqual(row["row"], {"file": row["name"], "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                                          "lines": metrics(data)[0], "max_line": metrics(data)[1], "flags": []})
            self.assertEqual(row["anchor"], {"offset": 0, "length": min(len(data), 4096)})
            self.assertEqual(row["artifact"]["sha256"], hashlib.sha256(data).hexdigest())
        rows = {row["name"]: row["row"] for row in self.layout["files"]}
        self.assertEqual((rows["dist/app.min.js"]["lines"], rows["dist/app.min.js"]["max_line"]),
                         (1, rows["dist/app.min.js"]["size"]))  # one line, no final line feed
        config = next(row["data"] for row in self.layout["files"] if row["name"] == "src/config.ts")
        self.assertEqual(config.count(b"\r\n"), 7)
        self.assertEqual(rows["src/config.ts"]["max_line"], max(len(line) for line in config.split(b"\r\n")) + 1)

    def test_the_default_package_rows_follow_the_contract_field_list_in_document_order(self):
        package = self.layout["package"]
        self.assertEqual((package["name"], package["member"]), ("package.json", 2))
        child = self.layout["files"][2]["data"]
        document = strict_json(child)
        self.assertEqual(document, J.APP_PACKAGE)
        self.assertEqual([row["row"]["path"] for row in package["rows"]], list(J.APP_PACKAGE_PATHS))
        for row in package["rows"]:
            token = child[row["offset"]:row["offset"] + row["length"]]
            decoded = json.loads(token)
            self.assertEqual(decoded, pointer(document, row["row"]["path"]))
            self.assertEqual(row["row"]["file"], "package.json")
            self.assertEqual(row["row"]["truncated"], False)
        description = next(row for row in package["rows"] if row["row"]["path"] == "/description")
        self.assertEqual(description["row"]["value"],
                         'Fixture application: caf\\xe9 \\U0001f600, "quoted", C:\\x5ctmp')
        self.assertEqual(child[description["offset"]:description["offset"] + 11], b'"Fixture ap')
        offsets = [row["offset"] for row in package["rows"]]
        self.assertEqual(offsets, sorted(offsets))
        # every string of the document is recorded, listed or not
        self.assertEqual(len(package["strings"]), 35)
        for item in package["strings"]:
            self.assertEqual(json.loads(child[item["offset"]:item["offset"] + item["length"]]), item["value"])
            self.assertEqual(pointer(document, item["pointer"]), item["value"])
        unlisted = {item["pointer"] for item in package["strings"]} - set(J.APP_PACKAGE_PATHS)
        self.assertEqual(unlisted, {"/repository/type", "/exports/.~1five/a/b/c/d", "/keywords/0", "/keywords/1",
                                    "/config/port"})

    def test_marks_name_their_exact_bytes(self):
        data = {row["name"]: row["data"] for row in self.layout["files"]}
        labels = set()
        for name, marks in self.layout["marks"].items():
            for mark in marks:
                labels.add(mark["label"])
                self.assertEqual(data[name][mark["offset"]:mark["offset"] + mark["length"]], mark["text"].encode())
        self.assertLessEqual({"require_child_process", "url_https", "exec_call", "fetch_call", "eval_call", "new_function",
                              "aws_key_id", "private_key", "buffer_from", "base64_encoding", "atob_call"}, labels)
        self.assertRegex(J.FAKE_AWS_KEY_ID, r"^AKIA[0-9A-Z]{16}$")
        self.assertIn(J.PRIVATE_KEY_BEGIN.encode(), data["src/config.ts"])
        # The source itself holds no secret-looking literal
        text = Path(J.__file__).read_text(encoding="ascii")
        self.assertIsNone(re.search(r"AKIA[0-9A-Z]{16}|BEGIN PRIVATE KEY", text))
        # README.md is not a JavaScript file although it names eval( and a URL
        self.assertNotIn("README.md", self.layout["marks"])

    def test_escaping_matches_the_import_name_escaping(self):
        for text in ("a\\b", "caf\u00e9", "\U0001F600", "\x00\x7f\x1b", "tab\t", "plain", '"q"', "\u2028"):
            self.assertEqual(J.escaped(text), apk.escape(text, 10_000), text)
        self.assertEqual(J.cut("\u00e9" * 100), ("\\xe9" * 64, True))
        self.assertEqual(J.cut("d" * 256), ("d" * 256, False))


class SingleFileTests(unittest.TestCase):
    def test_the_bundle_is_one_file_that_is_not_a_zip(self):
        data, layout = J.bundle_js()
        self.assertEqual(hashlib.sha256(data).hexdigest(), BUNDLE_SHA256)
        with self.assertRaises(ContractError):
            apk.members(data)
        row, = layout["files"]
        self.assertEqual(row["row"], {"file": "", "size": len(data), "sha256": BUNDLE_SHA256, "lines": 3,
                                  "max_line": metrics(data)[1], "flags": []})
        self.assertGreater(row["row"]["max_line"], 400)
        for mark in layout["marks"][""]:
            self.assertEqual(data[mark["offset"]:mark["offset"] + mark["length"]], mark["text"].encode())

    def test_the_package_alone_has_the_application_rows_named_empty(self):
        data, layout = J.package_only()
        _, app = J.app_zip()
        self.assertEqual(data, app["files"][2]["data"])
        with self.assertRaises(ContractError):
            apk.members(data)
        self.assertEqual([(row["row"]["file"], row["row"]["path"], row["offset"]) for row in layout["package"]["rows"]],
                         [("", row["row"]["path"], row["offset"]) for row in app["package"]["rows"]])


class EdgeAndHostileTests(unittest.TestCase):
    def test_edge_cases(self):
        data, layout = J.js_edge("long_value")
        row = next(row for row in layout["package"]["rows"] if row["row"]["path"] == "/description")
        self.assertEqual((row["row"]["value"], row["row"]["truncated"], row["length"]), ("d" * 256, True, 4096))
        self.assertEqual(layout["files"][0]["data"][row["offset"]:row["offset"] + 2], b'"d')
        data, layout = J.js_edge("package_tie")
        self.assertEqual(layout["default_package"], "b/package.json")
        self.assertEqual([row["row"]["value"] for row in layout["package"]["rows"]], ["second-by-name"])
        data, layout = J.js_edge("empty_file")
        empty = layout["files"][0]
        self.assertEqual(empty["row"], {"file": "lib/empty.js", "size": 0, "sha256": hashlib.sha256(b"").hexdigest(),
                                    "lines": 0, "max_line": 0, "flags": []})
        central = layout["zip"]["members"][0]
        self.assertEqual((empty["anchor"], empty["artifact"]),
                         ({"offset": central["central_offset"], "length": central["central_length"]}, None))
        self.assertEqual(data[empty["anchor"]["offset"]:empty["anchor"]["offset"] + 4], b"PK\x01\x02")
        self.assertIsNotNone(layout["files"][1]["artifact"])
        data, layout = J.js_edge("empty_input")
        self.assertEqual((data, layout["files"], layout["expect"]["js.files"]), (b"", [], "no rows"))
        with self.assertRaises(ValueError):
            J.js_edge("unknown")

    def test_every_invalid_json_text_is_refused_by_a_strict_reader(self):
        for name, text in J.INVALID_JSON.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                strict_json(text)
        for kind in ("duplicate_key", "duplicate_nested_key", "invalid_json", "non_utf8", "long_pointer"):
            data, layout = J.js_hostile(kind)
            package = next(row["data"] for row in layout["files"] if row["name"] == "package.json")
            if kind == "long_pointer":  # valid JSON whose pointer /dependencies/k... is 314 characters
                self.assertEqual(len("/dependencies/" + next(iter(strict_json(package)["dependencies"]))), 314)
            else:
                with self.subTest(kind=kind), self.assertRaises(ValueError):
                    strict_json(package)
            self.assertEqual(layout["expect"]["js.package"], "refused")
            self.assertEqual([m.flags for m in apk.members(data)], [()] * len(layout["files"]))

    def test_depth_and_size_limits(self):
        self.assertEqual(J.nested_json(1), b"{}")
        for wanted in (2, 64, 65):
            self.assertEqual(depth(J.nested_json(wanted)), wanted)
            strict_json(J.nested_json(wanted))
        data, layout = J.js_hostile("deep_nesting")
        package = layout["files"][0]["data"]
        self.assertEqual(depth(package), 100_000)
        self.assertEqual(layout["zip"]["members"][0]["method"], 0)
        data, layout = J.js_hostile("huge_string")
        package = layout["files"][0]["data"]
        self.assertEqual(len(package), J.MAX_JSON_BYTES + 1)
        self.assertEqual(strict_json(package)["name"], "huge")  # valid JSON: only its size is refused

    def test_non_utf8_bytes_and_their_marks(self):
        data, layout = J.js_hostile("non_utf8")
        latin1 = next(row["data"] for row in layout["files"] if row["name"] == "lib/latin1.js")
        with self.assertRaises(UnicodeDecodeError):
            latin1.decode("utf-8")
        raw, url = layout["marks"]["lib/latin1.js"]
        self.assertEqual(latin1[raw["offset"]:raw["offset"] + raw["length"]], b"\xe9")
        self.assertEqual(latin1[url["offset"]:url["offset"] + url["length"]], url["text"].encode())
        self.assertEqual(layout["expect"], {"js.files": "ok", "js.package": "refused", "js.hints": "ok"})

    def test_flagged_members_and_declared_sizes(self):
        data, layout = J.js_hostile("flagged_members")
        members = apk.members(data)
        self.assertEqual([list(m.flags) for m in members], layout["flags"])
        self.assertEqual([row["name"] for row in layout["files"]], [member.name for member in members])
        for file, member in zip(layout['files'], members):
            self.assertEqual(file['row']['flags'], list(member.flags))
            if member.flags:
                self.assertEqual(file['row'], {'file': J.escaped(member.name)[:255], 'size': member.size,
                                               'sha256': None, 'lines': None, 'max_line': None,
                                               'flags': list(member.flags)})
                self.assertIsNone(file['artifact'])
                self.assertEqual(file['anchor'], {'offset': member.central_offset,
                                                  'length': min(member.central_length, 4096)})
        data, layout = J.js_hostile("declared_over_128mib")
        self.assertEqual([list(m.flags) for m in apk.members(data)], layout["flags"])
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            self.assertEqual(sum(info.file_size for info in archive.infolist()), 150 * 1024 * 1024)
        self.assertEqual([file['row']['size'] for file in layout['files']], [30 * 1024 * 1024] * 5)
        self.assertTrue(all(file['row']['sha256'] is None and file['artifact'] is None for file in layout['files']))
        data, layout = J.js_hostile("zip_refused")
        self.assertTrue(data.startswith(b"PK\x03\x04"))
        with self.assertRaisesRegex(ContractError, "ZIP64"):
            apk.members(data)
        self.assertEqual(set(layout["expect"].values()), {"refused"})
        with self.assertRaises(ValueError):
            J.js_hostile("unknown")


if __name__ == "__main__":
    unittest.main()
