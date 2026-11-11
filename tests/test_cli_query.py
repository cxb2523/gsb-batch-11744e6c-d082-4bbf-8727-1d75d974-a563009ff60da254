"""Targeted command using inert in-process stand-ins."""
import contextlib
from dataclasses import replace
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from reverseai import cli, intake, pipeline
from reverseai.contract import ArgSpec, ContractError, Location, Observation, OperationSpec, ToolRef, ToolSpec


def byte_tool():
    def read(data, args):
        start = args["at"]
        raw = data[start:start + args["length"]]
        return [Observation(Location(start, len(raw)), {"kind": "bytes", "offset": start, "address": None,
                                                       "hex": raw.hex()})] if raw else []
    operation = OperationSpec("structure.read_bytes", {
        "mode": ArgSpec("enum", choices=("offset", "address"), default="offset"),
        "at": ArgSpec("int", 0, 2**64 - 1, default=0), "length": ArgSpec("int", 1, 2000, default=256)}, read)
    return ToolSpec(ToolRef("structure", "0.1.0"), {operation.name: operation})


class QueryCliTests(unittest.TestCase):
    def invoke(self, *argv):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            try:
                code = cli.main(list(argv))
            except SystemExit as error:
                code = error.code
        return code, stdout.getvalue(), stderr.getvalue()

    def test_read_bytes_query_writes_verified_reports_without_host_paths(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(pipeline, "TOOLS", (byte_tool(),)):
            sample, out = Path(folder, "sample.bin"), Path(folder, "report")
            sample.write_bytes(bytes(range(64)))
            code, stdout, stderr = self.invoke("query", str(sample), "--query", "read_bytes", "--arg", "at=0x10",
                                              "--arg", "length=004", "--out", str(out))
            self.assertEqual(code, 0, stderr)
            parsed = json.loads((out / "report.json").read_text())
            self.assertEqual(parsed["query"], {"name": "read_bytes", "args": {"mode": "offset", "at": 16, "length": 4}})
            finding, = parsed["results"][0]["findings"]
            self.assertEqual((finding["verdict"], finding["value"]),
                             ("supported", {"offset": 16, "address": None, "hex": "10111213"}))
            self.assertIn("supported", stdout)
            for name in ("report.json", "report.md"):
                self.assertNotIn(folder, (out / name).read_text())
                self.assertEqual((out / name).stat().st_mode & 0o777, 0o600)
            self.assertEqual(out.stat().st_mode & 0o777, 0o700)

    def test_failed_query_operation_exits_one_without_writing_reports(self):
        def fail(data, args):
            raise ContractError("synthetic operation failure")

        tool = byte_tool()
        spec = replace(tool.operations["structure.read_bytes"], handler=fail)
        tool = replace(tool, operations={spec.name: spec})
        with tempfile.TemporaryDirectory() as folder, patch.object(pipeline, "TOOLS", (tool,)):
            sample, out = Path(folder, "sample"), Path(folder, "report")
            sample.write_bytes(b"inert input")
            code, stdout, stderr = self.invoke("query", str(sample), "--query", "read_bytes", "--out", str(out))
            self.assertEqual(code, 1)
            self.assertEqual(stdout, "")
            self.assertEqual(stderr, "reverseai: analysis failed: ValueError\n")
            self.assertEqual(list(out.iterdir()), [])

    def test_invalid_query_arguments_are_refused_before_snapshot_or_output(self):
        for name, args in (("read_bytes", ["length=2001"]), ("read_bytes", ["path=/secret"]),
                           ("read_bytes", ["at=-1"]), ("read_bytes", ["at=1", "at=2"]),
                           ("read_bytes", ["at=0x"]), ("not_a_query", []), ("xrefs", []),
                           ("search_strings", ["query="])):
            with self.subTest(name=name, args=args), tempfile.TemporaryDirectory() as folder, \
                    patch.object(intake, "snapshot") as snapshot:
                out = Path(folder, "report")
                argv = ["query", "/missing/sample", "--query", name, "--out", str(out)]
                for arg in args:
                    argv += ["--arg", arg]
                code, _, error = self.invoke(*argv)
                self.assertEqual(code, 1, error)
                snapshot.assert_not_called()
                self.assertFalse(out.exists())
                self.assertNotIn("/missing", error)
                self.assertNotIn("Traceback", error)

    def test_ghidra_queries_require_the_flag_and_available_worker_before_input(self):
        from reverseai.tools import ghidra_tool
        for flag in (False, True):
            with self.subTest(flag=flag), tempfile.TemporaryDirectory() as folder, \
                    patch.object(ghidra_tool, "available", return_value=False), patch.object(intake, "snapshot") as snapshot:
                code, _, error = self.invoke("query", "/missing", "--query", "procedure_info", "--out", str(Path(folder, "r")),
                                             *(["--with-ghidra"] if flag else []))
                self.assertEqual(code, 1, error)
                snapshot.assert_not_called()
                self.assertNotIn("Traceback", error)
                self.assertIn("unavailable" if flag else "requires --with-ghidra", error)

    def test_query_output_handle_survives_directory_swap(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(pipeline, "TOOLS", (byte_tool(),)):
            sample, out = Path(folder, "sample"), Path(folder, "out")
            moved, elsewhere = Path(folder, "moved"), Path(folder, "elsewhere")
            sample.write_bytes(b"inert")
            elsewhere.mkdir()
            original = pipeline.query_bytes
            def swap(*args, **kwargs):
                out.rename(moved)
                out.symlink_to(elsewhere)
                return original(*args, **kwargs)
            with patch.object(pipeline, "query_bytes", side_effect=swap):
                code, _, error = self.invoke("query", str(sample), "--query", "read_bytes", "--out", str(out))
            self.assertEqual(code, 0, error)
            self.assertEqual(list(elsewhere.iterdir()), [])
            self.assertEqual(sorted(path.name for path in moved.iterdir()), ["report.json", "report.md"])

    def test_query_refuses_symlinked_input_and_used_or_symlinked_output(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(pipeline, "TOOLS", (byte_tool(),)):
            sample, link = Path(folder, "sample"), Path(folder, "link")
            sample.write_bytes(b"inert")
            link.symlink_to(sample)
            self.assertEqual(self.invoke("query", str(link), "--query", "read_bytes", "--out", str(Path(folder, "r")))[0], 1)
            used, other = Path(folder, "used"), Path(folder, "other")
            used.mkdir(); (used / "keep").write_text("keep")
            other.symlink_to(used)
            for out in (used, other):
                self.assertEqual(self.invoke("query", str(sample), "--query", "read_bytes", "--out", str(out))[0], 1)
            self.assertEqual((used / "keep").read_text(), "keep")
