"""The MCP catalog uses the existing query bounds and confines paths without reading input bytes."""

import contextlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from reverseai import cli, mcp_tools, queries
from reverseai.contract import MAX_STRING_ARG_CHARS


class ArgumentSchemaTests(unittest.TestCase):
    def test_every_query_argument_keeps_its_declared_type_limits_choices_and_default(self):
        kinds = set()
        tools = {tool["name"]: tool for tool in mcp_tools.catalog(frozenset(mcp_tools.ENABLE))}
        for name, query in queries.TABLE.items():
            schema = tools[name]["inputSchema"]
            self.assertFalse(schema["additionalProperties"])
            self.assertEqual(schema["type"], "object")
            self.assertEqual(set(schema["properties"]), {"file", "view", *(
                "member_file" if key == "file" else key for key in query.args)})
            self.assertEqual(schema["required"], ["file", *(
                "member_file" if key == "file" else key for key, spec in query.args.items() if spec.default is None)])
            for key, spec in query.args.items():
                with self.subTest(query=name, argument=key):
                    kinds.add(spec.kind)
                    field = schema["properties"]["member_file" if key == "file" else key]
                    if spec.kind == "int":
                        self.assertEqual(field, {"type": "integer", "minimum": spec.minimum,
                                                "maximum": spec.maximum, **(
                                                    {"default": spec.default} if spec.default is not None else {})})
                    else:
                        self.assertEqual(field["type"], "string")
                        if spec.kind == "enum":
                            self.assertEqual(field["enum"], list(spec.choices))
                        else:
                            self.assertEqual(field["minLength"], spec.minimum if spec.kind != "str" else 0)
                            self.assertEqual(field["maxLength"], spec.maximum if spec.kind != "str"
                                             else MAX_STRING_ARG_CHARS)
                        self.assertEqual(field.get("default"), spec.default)
                        self.assertEqual("default" in field, spec.default is not None)
        self.assertEqual(kinds, {"int", "str", "enum", "literal", "identity"})

    def test_catalog_order_worker_filtering_annotations_and_no_argument_inventory(self):
        host_names = ["binary_overview", "list_segments", "inspect_native_load_image", "list_names", "read_bytes",
                      "list_strings", "search_strings", "inspect_android_package", "search_android_classes",
                      "inspect_android_class", "inspect_android_method", "trace_android_references",
                      "analyze_javascript_application"]
        host = mcp_tools.catalog(frozenset())
        self.assertEqual([tool["name"] for tool in host], ["list_files", "analyze_file", *host_names])
        full = mcp_tools.catalog(frozenset(mcp_tools.ENABLE))
        self.assertEqual([tool["name"] for tool in full], ["list_files", "analyze_file", "prepare_file", *queries.TABLE])
        self.assertEqual(host[0]["inputSchema"], {"type": "object", "properties": {}, "required": [],
                                                "additionalProperties": False})
        for tool in full:
            self.assertTrue(tool["title"] and tool["description"])
            self.assertEqual(tool["annotations"], {"readOnlyHint": tool["name"] != "prepare_file", "destructiveHint": False,
                                                   "idempotentHint": True, "openWorldHint": False})
        for enabled in (frozenset(), frozenset({"jadx"}), frozenset({"jsparser"}), frozenset({"ghidra"})):
            with self.subTest(enabled=enabled):
                tools = {tool["name"]: tool for tool in mcp_tools.catalog(enabled)}
                self.assertEqual("procedure_info" in tools, "ghidra" in enabled)
                details = tools["analyze_javascript_application"]["inputSchema"]["properties"]["detail"]["enum"]
                self.assertEqual(details, ["summary", "files", "package", "hints", "modules", "calls", "parse"]
                                 if "jsparser" in enabled else ["summary", "files", "package", "hints"])

    def test_prepare_annotations_disclose_the_private_cache_write(self):
        tools = {tool["name"]: tool for tool in mcp_tools.catalog(frozenset({"ghidra"}))}
        self.assertEqual(tools["prepare_file"]["annotations"],
                         {"readOnlyHint": False, "destructiveHint": False,
                          "idempotentHint": True, "openWorldHint": False})
        self.assertTrue(all(tool["annotations"]["readOnlyHint"] for name, tool in tools.items()
                            if name != "prepare_file"))

    def test_catalog_calls_are_independent_and_do_not_probe_workers(self):
        with patch("subprocess.run", side_effect=AssertionError("no process")), \
                patch("subprocess.Popen", side_effect=AssertionError("no process")):
            first = mcp_tools.catalog(frozenset(mcp_tools.ENABLE))
            first[0]["annotations"]["readOnlyHint"] = False
            first[-1]["inputSchema"]["properties"]["detail"]["enum"].append("injected")
            first[1]["inputSchema"]["properties"]["file"]["maxLength"] = 999999
            fresh = mcp_tools.catalog(frozenset(mcp_tools.ENABLE))
        self.assertTrue(fresh[0]["annotations"]["readOnlyHint"])
        self.assertNotIn("injected", fresh[-1]["inputSchema"]["properties"]["detail"]["enum"])
        self.assertEqual(fresh[1]["inputSchema"]["properties"]["file"]["maxLength"], 1024)
        for flags in (None, "ghidra", ["ghidra"], {"ghidra"}, frozenset({"unknown"})):
            with self.subTest(flags=flags), self.assertRaises(mcp_tools.ToolInputError):
                mcp_tools.catalog(flags)

    def test_member_selector_description_explains_the_details_that_use_it(self):
        for enabled in (frozenset(), frozenset({"jsparser"})):
            tools = {tool["name"]: tool for tool in mcp_tools.catalog(enabled)}
            field = tools["analyze_javascript_application"]["inputSchema"]["properties"]["member_file"]
            self.assertEqual(field["description"], "Printable archive member selector used with detail hints, "
                             "package, modules, calls or parse; leave empty for summary or files.")


class RelativeNameTests(unittest.TestCase):
    def test_relative_posix_segments_and_utf8_byte_bound(self):
        self.assertEqual(mcp_tools._relative_parts("folder/inert.bin"), ["folder", "inert.bin"])
        self.assertEqual(mcp_tools._relative_parts("café.bin"), ["café.bin"])
        self.assertEqual(mcp_tools._relative_parts("x" * 1024), ["x" * 1024])
        self.assertEqual(mcp_tools._relative_parts("é" * 512), ["é" * 512])
        for bad in ("", ".", "..", "../x", "a/../x", "a/./x", "a//x", "a/", "/x", "//x",
                    "a\x00b", "x" * 1025, "é" * 513, "bad\udcff", "C:/x", "C:x", "a:stream", "a\\b",
                    "a\nb", "a\x1bb", "a\x85b", "a\u202eb", None, 1, b"bytes", []):
            with self.subTest(name=repr(bad)):
                with self.assertRaisesRegex(mcp_tools.ToolInputError, "^file must be a relative POSIX path"):
                    mcp_tools._relative_parts(bad)


class FileTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="reverseai-mcp-tools-")
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name).resolve()
        self.root = self.work / "inputs"
        self.root.mkdir()
        self.out = self.work / "new-report"

    def make_file(self, name="inert.bin", data=b"neutral fixture string\x00"):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def command(self, name="analyze_file", arguments=None, enabled=frozenset()):
        return mcp_tools.command(name, {"file": "inert.bin"} if arguments is None else arguments,
                                 root=str(self.root), out=str(self.out), enabled=enabled)

    def symlink(self, target, link):
        try:
            link.symlink_to(target, target_is_directory=target.is_dir())
        except OSError:
            if os.name == "nt":
                self.skipTest("Windows account cannot create test links")
            raise

    def test_empty_inventory_and_sorted_lstat_sizes_without_input_reads(self):
        self.assertEqual(mcp_tools.list_files(str(self.root)), {"files": [], "truncated": False})
        self.make_file("z.bin", b"123")
        self.make_file("folder/a.bin", b"12345")
        self.make_file("café.bin", b"")
        with patch.object(Path, "open", side_effect=AssertionError("no input bytes")):
            self.assertEqual(mcp_tools.list_files(str(self.root)), {"files": [
                {"name": "café.bin", "size": 0}, {"name": "folder/a.bin", "size": 5},
                {"name": "z.bin", "size": 3}], "truncated": False})

    def test_links_to_files_and_directories_are_never_followed(self):
        self.make_file("ordinary.bin", b"one")
        outside = self.work / "outside"
        outside.mkdir()
        (outside / "hidden.bin").write_bytes(b"secret")
        self.symlink(self.root / "ordinary.bin", self.root / "alias.bin")
        self.symlink(outside, self.root / "linked")
        self.assertEqual(mcp_tools.list_files(str(self.root)), {
            "files": [{"name": "ordinary.bin", "size": 3}], "truncated": False})

    def test_inventory_skips_reparse_entries_before_listing_or_descending(self):
        outside = SimpleNamespace(name="outside.bin", path=str(self.work / "outside.bin"),
                                  stat=lambda **kwargs: SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_size=7))
        for mode in (stat.S_IFDIR, stat.S_IFREG):
            with self.subTest(mode=mode):
                entry = SimpleNamespace(name="reparse", path=str(self.root / "reparse"),
                                        stat=lambda **kwargs: SimpleNamespace(
                                            st_mode=mode | 0o700, st_file_attributes=0x400, st_size=7))

                def scan(path):
                    return contextlib.nullcontext(iter([entry] if path == str(self.root) else [outside]))

                with patch.object(mcp_tools.os, "scandir", side_effect=scan) as scanned:
                    self.assertEqual(mcp_tools.list_files(str(self.root)), {"files": [], "truncated": False})
                scanned.assert_called_once_with(str(self.root))

    def test_unaddressable_names_are_omitted_with_an_honest_partial_listing(self):
        self.make_file()
        if os.name != "nt":
            for name in ("bad\\name", "bad:stream", "line\nbreak", "bidi\u202e.bin"):
                self.make_file(name)
        else:
            self.make_file("bidi\u202e.bin")
        self.assertEqual(mcp_tools.list_files(str(self.root)), {
            "files": [{"name": "inert.bin", "size": 23}], "truncated": True})
        # Some filesystems refuse non-UTF-8 names at creation time.
        with patch.object(mcp_tools.os, "scandir", return_value=contextlib.nullcontext(iter([
                SimpleNamespace(name="bad-\udcff.bin")]))):
            self.assertEqual(mcp_tools.list_files(str(self.root)), {"files": [], "truncated": True})

    def test_file_count_is_capped_at_one_thousand(self):
        for index in range(1001):
            self.make_file(f"f{index:04}.bin", b"")
        listed = mcp_tools.list_files(str(self.root))
        self.assertTrue(listed["truncated"])
        self.assertEqual(listed["files"], [{"name": f"f{index:04}.bin", "size": 0} for index in range(1000)])

    def test_file_depth_eight_is_included_and_nine_is_truncated(self):
        parent = "/".join("d" + str(i) for i in range(1, 8))
        self.make_file(parent + "/at_depth_eight.bin", b"ok")
        self.make_file(parent + "/d8/hidden.bin", b"hidden")
        self.assertEqual(mcp_tools.list_files(str(self.root)), {
            "files": [{"name": parent + "/at_depth_eight.bin", "size": 2}], "truncated": True})

    def test_directory_only_trees_have_a_ten_thousand_entry_scan_cap(self):
        seen, calls = [], []

        @contextlib.contextmanager
        def scan(path):
            calls.append(path)

            def entries():
                for index in range(10001):
                    seen.append(index)
                    yield SimpleNamespace(name=f"d{index:05}", path=str(self.root / f"d{index:05}"),
                                          stat=lambda **kwargs: SimpleNamespace(st_mode=stat.S_IFDIR | 0o700))
            yield entries()

        with patch.object(mcp_tools.os, "scandir", side_effect=scan):
            self.assertEqual(mcp_tools.list_files(str(self.root)), {"files": [], "truncated": True})
        self.assertEqual(len(seen), 10000)
        self.assertEqual(calls, [str(self.root)])

    def test_listing_errors_do_not_expose_absolute_paths(self):
        with patch.object(mcp_tools.os, "scandir", side_effect=PermissionError(str(self.work / "private"))):
            with self.assertRaises(mcp_tools.ToolInputError) as caught:
                mcp_tools.list_files(str(self.root))
        self.assertEqual(str(caught.exception), "The input directory could not be listed; check its accessibility and retry.")

    def test_command_rejects_traversal_external_and_internal_links_and_linked_parents(self):
        source = self.make_file()
        inside = self.make_file("sub/inside.bin")
        external = self.work / "private.bin"
        external.write_bytes(b"private")
        self.symlink(external, self.root / "external.bin")
        self.symlink(source, self.root / "internal.bin")
        self.symlink(inside.parent, self.root / "parent")
        for name in ("../private.bin", str(external), "external.bin", "internal.bin", "parent/inside.bin",
                     "sub/../inert.bin", "sub//inside.bin", "sub/./inside.bin", "sub", "absent.bin"):
            with self.subTest(name=name), self.assertRaises(mcp_tools.ToolInputError) as caught:
                self.command(arguments={"file": name})
            self.assertNotIn(str(self.work), str(caught.exception))

    def test_reparse_points_are_refused_even_when_their_stat_type_is_a_directory(self):
        self.make_file("junction/inside.bin")
        original = os.lstat

        def inspected(path, *args, **kwargs):
            if os.fspath(path) == str(self.root / "junction"):
                return SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_file_attributes=0x400)
            return original(path, *args, **kwargs)

        with patch.object(mcp_tools.os, "lstat", side_effect=inspected):
            with self.assertRaises(mcp_tools.ToolInputError):
                self.command(arguments={"file": "junction/inside.bin"})

    def test_hard_link_refusal_reuses_intake_and_command_never_reads_the_sample(self):
        source = self.make_file()
        with patch.object(Path, "open", side_effect=AssertionError("no sample reads")):
            self.assertEqual(self.command(), ["analyze", str(source), "--out", str(self.out)])
        os.link(source, self.root / "second.bin")
        with self.assertRaisesRegex(mcp_tools.ToolInputError, "^Hard-linked input files need a separate copy$"):
            self.command()

    def test_every_query_maps_to_the_existing_cli_with_validated_defaults(self):
        self.make_file()
        enabled = frozenset(mcp_tools.ENABLE)
        for name, spec in queries.TABLE.items():
            values = {key: (arg.minimum if arg.kind == "int" else "Lexample/App;")
                      for key, arg in spec.args.items() if arg.default is None}
            with self.subTest(name=name):
                argv = self.command(name, {"file": "inert.bin", **values}, enabled=enabled)
                self.assertEqual(argv[:6], ["query", str(self.root / "inert.bin"), "--out", str(self.out), "--query", name])
                forwarded = [argv[i + 1] for i, value in enumerate(argv) if value == "--arg"]
                self.assertEqual(queries.parse_args(name, forwarded), spec.validate(values))

    def test_enabled_workers_are_passed_only_to_applicable_commands(self):
        self.make_file()
        enabled = frozenset(mcp_tools.ENABLE)
        self.assertEqual(self.command(enabled=enabled)[4:], ["--with-lief", "--with-yarax", "--with-ghidra"])
        cases = (("list_strings", {}, []), ("procedure_info", {}, ["--with-ghidra"]),
                 ("inspect_android_method", {"class": "Lexample/App;", "method": "run"}, ["--with-jadx"]),
                 ("analyze_javascript_application", {}, []),
                 ("analyze_javascript_application", {"detail": "parse"}, ["--with-jsparser"]))
        for name, values, flags in cases:
            with self.subTest(name=name, values=values):
                argv = self.command(name, {"file": "inert.bin", **values}, enabled=enabled)
                self.assertEqual([value for value in argv if value.startswith("--with-")], flags)

    def test_outer_file_and_javascript_member_selector_stay_separate(self):
        self.make_file()
        argv = self.command("analyze_javascript_application", {
            "file": "inert.bin", "detail": "package", "member_file": "package/package.json"})
        self.assertEqual(argv[1], str(self.root / "inert.bin"))
        self.assertIn("file=package/package.json", argv)
        self.assertFalse(any(value.startswith("member_file=") for value in argv))

    def test_wrong_types_bounds_enums_missing_values_and_unknown_arguments_are_fixed_errors(self):
        self.make_file()
        cases = (("analyze_file", None), ("analyze_file", []), ("analyze_file", {}),
                 ("analyze_file", {"file": "inert.bin", "out": "/tmp/forbidden"}),
                 ("list_strings", {"encoding": "latin1"}), ("read_bytes", {"length": True}),
                 ("read_bytes", {"length": "12"}), ("read_bytes", {"length": 2001}),
                 ("read_bytes", {"at": -1}), ("read_bytes", {"at": 2**64}),
                 ("read_bytes", {"mode": "shell"}), ("list_strings", {"limit": 0}),
                 ("search_strings", {}), ("search_strings", {"query": "line\nbreak"}),
                 ("inspect_android_class", {"class": "x" * 256}),
                 ("analyze_javascript_application", {"member_file": "ignored.js"}),
                 ("analyze_javascript_application", {"detail": "files", "category": "network"}),
                 ("analyze_javascript_application", {"detail": "package", "start": 65536}),
                 ("list_strings", {"member_file": "injected"}),
                 ("list_strings", {"with_ghidra": True}), ("list_strings", {"root": "/"}))
        for name, values in cases:
            arguments = {"file": "inert.bin", **values} if isinstance(values, dict) and name != "analyze_file" else values
            with self.subTest(name=name, values=values), self.assertRaises(mcp_tools.ToolInputError):
                mcp_tools.command(name, arguments, root=str(self.root), out=str(self.out), enabled=frozenset())
        with self.assertRaisesRegex(mcp_tools.ToolInputError, "enable --with-jsparser"):
            self.command("analyze_javascript_application", {"file": "inert.bin", "detail": "calls"})
        for query in ("/outside", "a\\b", "-option", "x" * 257):
            with self.subTest(query=query), self.assertRaises(mcp_tools.ToolInputError):
                self.command("search_procedures", {"file": "inert.bin", "query": query}, frozenset({"ghidra"}))

    def test_unknown_or_disabled_tools_are_distinct_from_invalid_tool_arguments(self):
        for name in ("doctor", "unknown", "list_files", "--privileged", [], None, "procedure_info"):
            with self.subTest(name=name), self.assertRaises(mcp_tools.UnknownTool):
                self.command(name, {"file": "absent.bin"})

    def test_shell_metacharacters_remain_literal_argv_values(self):
        self.make_file()
        text = "--flag; $(touch should-never-exist) / path"
        argv = self.command("search_strings", {"file": "inert.bin", "query": text})
        self.assertIn("query=" + text, argv)
        self.assertEqual(queries.parse_args("search_strings", [argv[i + 1] for i, value in enumerate(argv)
                                                              if value == "--arg"])["query"], text)
        self.assertFalse((self.work / "should-never-exist").exists())

    def test_real_host_cli_report_uses_the_confined_file_and_query(self):
        self.make_file(data=b"known neutral phrase\x00")
        argv = self.command("list_strings", {"file": "inert.bin", "encoding": "ascii", "min_length": 4})
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(argv), 0)
        result = json.loads((self.out / "report.json").read_text())
        self.assertEqual(result["input"]["name"], "inert.bin")
        self.assertEqual(result["query"]["name"], "list_strings")
        self.assertGreater(result["summary"]["supported"], 0)
        self.assertTrue((self.out / "report.md").is_file())


if __name__ == "__main__":
    unittest.main()
