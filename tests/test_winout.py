"""Exercise the native call contract through inert Win32/NT stand-ins on any OS."""

import contextlib
import ctypes as C
import io
import os
from pathlib import Path
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from reverseai import cli, winout as W
from tests.fixtures_structure import elf


class Function:
    def __init__(self, call):
        self.call = call

    def __call__(self, *args):
        return self.call(*args)


def entries(names):
    rows = []
    for i, name in enumerate(names):
        encoded = name.encode("utf-16-le")
        size = (68 + len(encoded) + 7) // 8 * 8
        row = bytearray(size)
        struct.pack_into("<I", row, 0, size if i + 1 < len(names) else 0)
        struct.pack_into("<I", row, 60, len(encoded))
        row[68:68 + len(encoded)] = encoded
        rows.append(row)
    return b"".join(rows)


class Fake:
    """No DLLs: inspect actual ctypes arguments, and lend real scratch fds to fdopen."""
    def __init__(self, folder):
        self.folder = Path(folder)
        self.events, self.handles, self.descriptors = [], {}, []
        self.error = 18
        self.directory_attributes = 0x10
        self.pages = [entries([".", ".."]), None]
        self.directory_handle = 1000
        self.status = 0
        self.created = 2
        self.fail = None
        self.kernel = SimpleNamespace(CreateFileW=Function(self.create_directory),
                                      GetFileInformationByHandleEx=Function(self.information),
                                      CloseHandle=Function(self.close_handle))
        self.ntdll = SimpleNamespace(NtCreateFile=Function(self.create_file),
                                     RtlNtStatusToDosError=Function(self.nt_error))
        self.api = W._API(self.kernel, self.ntdll, self.to_fd, lambda: self.error)

    def mkdir(self, path, mode):
        self.events.append(("mkdir", path, mode))
        if self.fail == "mkdir-existing":
            raise FileExistsError("private-path")
        if self.fail == "mkdir":
            raise PermissionError("private-path")

    def create_directory(self, *args):
        self.events.append(("CreateFileW", *args))
        if self.fail == "open":
            return W.INVALID_HANDLE_VALUE
        return self.directory_handle

    def information(self, handle, kind, buffer, size):
        self.events.append(("GetFileInformationByHandleEx", handle, kind, size))
        if kind == 9:
            if self.fail == "attributes":
                return 0
            C.cast(buffer, C.POINTER(W.FILE_ATTRIBUTE_TAG_INFO)).contents.FileAttributes = self.directory_attributes
            return 1
        if self.fail == "enumeration":
            self.error = 5
            return 0
        if not self.pages:
            raise AssertionError("Unexpected directory enumeration")
        page = self.pages.pop(0)
        if page is None:
            return 0
        C.memmove(buffer, page, len(page))
        return 1

    def create_file(self, output, access, attributes, status, allocation, file_attributes,
                    share, disposition, options, ea, ea_size):
        attributes = C.cast(attributes, C.POINTER(W.OBJECT_ATTRIBUTES)).contents
        name = attributes.ObjectName.contents
        text = C.string_at(name.Buffer, name.Length).decode("utf-16-le")
        self.events.append(("NtCreateFile", access, attributes.Length, attributes.RootDirectory,
                            text, name.Length, name.MaximumLength, attributes.Attributes,
                            attributes.SecurityDescriptor, attributes.SecurityQualityOfService,
                            allocation, file_attributes, share, disposition, options, ea, ea_size))
        if text not in ("report.json", "report.md"):
            raise AssertionError("An unsafe report name reached the native API")
        if self.fail == "null-report":
            C.cast(status, C.POINTER(W.IO_STATUS_BLOCK)).contents.Information = 2
            return 0
        if self.status and self.fail != "late-nt":
            return self.status
        descriptor = os.open(self.folder / text, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0), 0o600)
        native = 2000 + descriptor
        self.handles[native] = descriptor
        C.cast(output, C.POINTER(W.HANDLE)).contents.value = native
        C.cast(status, C.POINTER(W.IO_STATUS_BLOCK)).contents.Information = self.created
        return self.status

    def nt_error(self, status):
        self.events.append(("RtlNtStatusToDosError", status))
        return 5

    def to_fd(self, native, flags):
        self.events.append(("open_osfhandle", native, flags))
        if self.fail == "transfer":
            raise OSError("private-path")
        if self.fail == "negative-fd":
            return -1
        descriptor = self.handles.pop(native)
        self.descriptors.append(descriptor)
        return descriptor

    def close_handle(self, handle):
        self.events.append(("CloseHandle", handle))
        if handle in self.handles:
            os.close(self.handles.pop(handle))
        if self.fail == "close":
            return 0
        return 1


class WindowsOutputTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.fake = Fake(self.temporary.name)
        self.mkdir = patch.object(W, "mkdir", self.fake.mkdir)
        self.mkdir.start()
        self.addCleanup(self.mkdir.stop)

    def bind(self):
        return W.open_output("new-output", api=self.fake.api)

    def test_import_loads_no_windows_libraries_on_other_platforms(self):
        with patch.object(W.C, "WinDLL", create=True) as loader, patch.object(W, "os", SimpleNamespace(name="posix")):
            with self.assertRaises(W.OutputRefused):
                W._load_api()
            loader.assert_not_called()

    def test_windows_loader_is_lazy_and_assigns_the_same_explicit_abi(self):
        libraries = {"kernel32": self.fake.kernel, "ntdll": self.fake.ntdll}
        with patch.object(W, "os", SimpleNamespace(name="nt")), \
                patch.dict(sys.modules, {"msvcrt": SimpleNamespace(open_osfhandle=self.fake.to_fd)}), \
                patch.object(W.C, "WinDLL", create=True, side_effect=lambda name, **kw: libraries[name]) as loader, \
                patch.object(W.C, "get_last_error", create=True, return_value=18):
            api = W._load_api()
        self.assertEqual(loader.call_args_list, [unittest.mock.call("kernel32", use_last_error=True),
                                                unittest.mock.call("ntdll", use_last_error=True)])
        self.assertIs(api.NtCreateFile, self.fake.ntdll.NtCreateFile)

    def test_abi_widths_and_offsets_are_independent_of_host_c_ulong_and_wchar(self):
        self.assertEqual((C.sizeof(W.ULONG), C.sizeof(W.NTSTATUS), C.sizeof(W.USHORT)), (4, 4, 2))
        self.assertIs(W.NTSTATUS, C.c_int32)
        pointer = C.sizeof(C.c_void_p)
        self.assertEqual(W.UNICODE_STRING.Buffer.offset, pointer)
        self.assertEqual(W.OBJECT_ATTRIBUTES.RootDirectory.offset, pointer)
        self.assertEqual(C.sizeof(W.OBJECT_ATTRIBUTES), 48 if pointer == 8 else 24)
        self.assertEqual(C.sizeof(W.IO_STATUS_BLOCK), 2 * pointer)
        self.assertEqual(C.sizeof(W.FILE_ATTRIBUTE_TAG_INFO), 8)

    def test_every_native_function_has_explicit_argument_and_result_types(self):
        for function, count, restype in ((self.fake.api.CreateFileW, 7, C.c_void_p),
                                        (self.fake.api.GetFileInformationByHandleEx, 4, C.c_int32),
                                        (self.fake.api.CloseHandle, 1, C.c_int32),
                                        (self.fake.api.NtCreateFile, 11, C.c_int32),
                                        (self.fake.api.RtlNtStatusToDosError, 1, C.c_uint32)):
            self.assertEqual(len(function.argtypes), count)
            self.assertIs(function.restype, restype)

    def test_new_private_directory_is_checked_and_listed_only_through_its_bound_handle(self):
        directory = self.bind()
        self.assertEqual(self.fake.events, [
            ("mkdir", "new-output", 0o700),
            ("CreateFileW", "new-output", 0x1000A1, 3, None, 3, 0x02200000, None),
            ("GetFileInformationByHandleEx", 1000, 9, 8),
            ("GetFileInformationByHandleEx", 1000, 15, 65536),
            ("GetFileInformationByHandleEx", 1000, 14, 65536),
        ])
        directory.close()
        directory.close()
        self.assertEqual(self.fake.events[-1], ("CloseHandle", 1000))
        self.assertEqual(self.fake.events.count(("CloseHandle", 1000)), 1)

    def test_older_or_non_cpython_refuses_before_any_filesystem_or_native_call(self):
        for implementation, version in (("cpython", (3, 12, 3)), ("cpython", (3, 11, 9)), ("pypy", (3, 13, 0))):
            self.fake.events.clear()
            self.fake.pages = [entries([".", ".."]), None]
            with self.subTest(implementation=implementation, version=version), \
                    patch.object(W.sys, "version_info", version), \
                    patch.object(W.sys, "implementation", SimpleNamespace(name=implementation)):
                with self.assertRaisesRegex(W.OutputRefused, "CPython 3.12.4"):
                    self.bind()
                self.assertEqual(self.fake.events, [])

    def test_minimum_supported_cpython_is_allowed(self):
        with patch.object(W.sys, "version_info", (3, 12, 4)):
            self.bind().close()

    def test_cpython_313_prereleases_need_the_private_mkdir_acl_fix(self):
        for version, allowed in (((3, 13, 0, "alpha", 1), False), ((3, 13, 0, "beta", 1), False),
                                 ((3, 13, 0, "beta", 2), True), ((3, 13, 0, "final", 0), True)):
            self.fake.events.clear()
            self.fake.pages = [entries([".", ".."]), None]
            with self.subTest(version=version), patch.object(W.sys, "version_info", version):
                if allowed:
                    self.bind().close()
                    self.assertEqual(self.fake.events[0], ("mkdir", "new-output", 0o700))
                    self.assertEqual(self.fake.events[-1], ("CloseHandle", 1000))
                else:
                    with self.assertRaises(W.OutputRefused):
                        self.bind()
                    self.assertEqual(self.fake.events, [])

    def test_existing_or_uncreatable_directory_never_reaches_createfile(self):
        for failure in ("mkdir-existing", "mkdir"):
            with self.subTest(failure=failure):
                self.fake.events.clear()
                self.fake.fail = failure
                with self.assertRaises(W.OutputRefused) as error:
                    self.bind()
                self.assertNotIn("private-path", str(error.exception))
                self.assertEqual([e[0] for e in self.fake.events], ["mkdir"])

    def test_invalid_createfile_handle_is_not_closed_or_inspected(self):
        self.fake.fail = "open"
        with self.assertRaises(W.OutputRefused):
            self.bind()
        self.assertEqual([e[0] for e in self.fake.events], ["mkdir", "CreateFileW"])

    def test_non_directory_and_reparse_points_are_refused_and_closed_before_listing(self):
        for attributes in (0x80, 0x410, 0x400):
            with self.subTest(attributes=attributes):
                self.fake.events.clear()
                self.fake.directory_attributes = attributes
                with self.assertRaises(W.OutputRefused):
                    self.bind()
                self.assertEqual(self.fake.events[-1], ("CloseHandle", 1000))
                self.assertEqual(len([e for e in self.fake.events if e[0] == "GetFileInformationByHandleEx"]), 1)

    def test_attribute_and_listing_errors_close_the_directory(self):
        for failure in ("attributes", "enumeration"):
            with self.subTest(failure=failure):
                self.fake.fail = failure
                with self.assertRaises(OSError):
                    self.bind()
                self.assertEqual(self.fake.events[-1], ("CloseHandle", 1000))

    def test_a_new_but_nonempty_directory_is_refused(self):
        self.fake.pages = [entries([".", "..", "already-present"])]
        with self.assertRaises(W.OutputRefused):
            self.bind()
        self.assertEqual(self.fake.events[-1], ("CloseHandle", 1000))

    def test_no_entries_is_an_empty_directory(self):
        self.fake.pages = [None]
        self.bind().close()

    def test_malformed_enumeration_never_looks_empty_and_is_bounded(self):
        bad_length = bytearray(entries(["."]))
        struct.pack_into("<I", bad_length, 60, 65535)
        bad_offset = bytearray(entries(["."]))
        struct.pack_into("<I", bad_offset, 0, 1)
        for pages in ([bytes(72)], [bytes(bad_length)], [bytes(bad_offset)],
                      [entries(["."]), entries(["."]), entries(["."])]):
            with self.subTest(pages=[len(p) for p in pages]):
                self.fake.pages = list(pages)
                with self.assertRaises(W.OutputRefused):
                    self.bind()
                self.assertEqual(self.fake.events[-1], ("CloseHandle", 1000))

    def test_create_is_relative_exclusive_synchronous_and_has_no_delete_sharing(self):
        directory = self.bind()
        try:
            W.write_new(directory, "report.json", "caf\u00e9\nnext\n\ud800")
            creation = next(e for e in self.fake.events if e[0] == "NtCreateFile")
            self.assertEqual(creation, ("NtCreateFile", 0x40100000, C.sizeof(W.OBJECT_ATTRIBUTES), 1000,
                                        "report.json", 22, 24, 0x40, None, None, None, 0x80, 0, 2,
                                        0x00200060, None, 0))
            self.assertEqual(self.fake.events[-1][0], "open_osfhandle")
            self.assertEqual(self.fake.events[-1][2], 0x8081)
            self.assertEqual((Path(self.temporary.name) / "report.json").read_bytes(), b"caf\xc3\xa9\nnext\n\\ud800")
            for descriptor in self.fake.descriptors:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)
            self.assertFalse(any(e[0] == "CloseHandle" for e in self.fake.events))
        finally:
            directory.close()

    def test_report_collisions_do_not_replace_existing_bytes(self):
        directory = self.bind()
        try:
            W.write_new(directory, "report.md", "first")
            with self.assertRaises(FileExistsError):
                W.write_new(directory, "report.md", "replacement")
            self.assertEqual((Path(self.temporary.name) / "report.md").read_bytes(), b"first")
        finally:
            directory.close()

    def test_names_cannot_contain_paths_streams_or_another_basename(self):
        directory = self.bind()
        before = len(self.fake.events)
        try:
            for name in ("../report.json", "a\\report.json", "report.json:secret", "other.json", "", None):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    W.write_new(directory, name, "x")
            self.assertEqual(len(self.fake.events), before)
        finally:
            directory.close()

    def test_closed_directory_never_reaches_ntcreatefile(self):
        directory = self.bind()
        directory.close()
        with self.assertRaises(ValueError):
            W.write_new(directory, "report.json", "x")
        self.assertFalse(any(e[0] == "NtCreateFile" for e in self.fake.events))

    def test_nt_failure_is_mapped_and_never_transferred_to_crt(self):
        directory = self.bind()
        try:
            self.fake.status = -1073741790
            with self.assertRaises(OSError):
                W.write_new(directory, "report.json", "x")
            self.assertEqual(self.fake.events[-1], ("RtlNtStatusToDosError", -1073741790))
            self.assertFalse(any(e[0] == "open_osfhandle" for e in self.fake.events))
        finally:
            directory.close()

    def test_nt_failure_with_a_returned_handle_still_closes_it(self):
        directory = self.bind()
        try:
            self.fake.status, self.fake.fail = -1073741790, "late-nt"
            with self.assertRaises(OSError):
                W.write_new(directory, "report.json", "x")
            self.assertEqual(self.fake.handles, {})
            self.assertEqual(self.fake.events[-2][0], "CloseHandle")
            self.assertEqual(self.fake.events[-1][0], "RtlNtStatusToDosError")
        finally:
            directory.close()

    def test_success_with_a_null_report_handle_is_refused_before_transfer(self):
        directory = self.bind()
        try:
            self.fake.fail = "null-report"
            with self.assertRaises(OSError):
                W.write_new(directory, "report.json", "x")
            self.assertFalse(any(e[0] in ("CloseHandle", "open_osfhandle") for e in self.fake.events))
        finally:
            directory.close()

    def test_success_that_did_not_create_a_file_closes_the_returned_handle(self):
        directory = self.bind()
        try:
            self.fake.created = 1
            with self.assertRaises(OSError):
                W.write_new(directory, "report.json", "x")
            self.assertEqual(self.fake.events[-1][0], "CloseHandle")
            self.assertEqual(self.fake.handles, {})
        finally:
            directory.close()

    def test_failed_handle_transfer_closes_native_handle_once(self):
        for failure, name in (("transfer", "report.json"), ("negative-fd", "report.md")):
            with self.subTest(failure=failure):
                self.fake.pages = [None]
                directory = self.bind()
                self.fake.fail = failure
                try:
                    with self.assertRaises(OSError):
                        W.write_new(directory, name, "x")
                    self.assertEqual(self.fake.handles, {})
                    self.assertEqual(self.fake.events[-1][0], "CloseHandle")
                finally:
                    directory.close()

    def test_fdopen_failure_closes_only_the_transferred_descriptor(self):
        directory = self.bind()
        try:
            with patch.object(W.os, "fdopen", side_effect=OSError("private-path")):
                with self.assertRaises(OSError):
                    W.write_new(directory, "report.json", "x")
            self.assertEqual(self.fake.handles, {})
            self.assertFalse(any(e[0] == "CloseHandle" for e in self.fake.events))
            with self.assertRaises(OSError):
                os.fstat(self.fake.descriptors[-1])
        finally:
            directory.close()

    def test_write_failure_closes_the_stream_and_transferred_descriptor(self):
        directory = self.bind()
        real_fdopen = os.fdopen

        def failing_stream(descriptor, *args, **kwargs):
            stream = real_fdopen(descriptor, *args, **kwargs)
            wrapper = Mock(wraps=stream)
            wrapper.__enter__ = Mock(return_value=wrapper)
            wrapper.__exit__ = Mock(side_effect=lambda *args: stream.close())
            wrapper.write.side_effect = OSError("private-path")
            return wrapper

        try:
            with patch.object(W.os, "fdopen", side_effect=failing_stream), self.assertRaises(OSError):
                W.write_new(directory, "report.json", "x")
            with self.assertRaises(OSError):
                os.fstat(self.fake.descriptors[-1])
            self.assertFalse(any(e[0] == "CloseHandle" for e in self.fake.events))
        finally:
            directory.close()

    def test_close_errors_are_checked_and_primary_refusals_are_preserved(self):
        directory = self.bind()
        self.fake.fail = "close"
        with self.assertRaises(OSError):
            directory.close()
        directory.close()
        self.fake.pages = [None]
        self.fake.directory_attributes = 0x400
        with self.assertRaises(W.OutputRefused):
            self.bind()


class WindowsCliDispatchTests(unittest.TestCase):
    def test_open_and_write_dispatch_to_windows_with_sanitized_errors(self):
        proxy = SimpleNamespace(name="nt")
        with patch.object(cli, "os", proxy), patch.object(W, "open_output", return_value="bound") as opened:
            self.assertEqual(cli.open_output(Path("new")), "bound")
            opened.assert_called_once_with(Path("new"))
        for failure in (W.OutputRefused("fixed refusal"), OSError("private-path"), ValueError("private-path")):
            with self.subTest(failure=type(failure).__name__), patch.object(cli, "os", proxy), \
                    patch.object(W, "open_output", side_effect=failure), self.assertRaises(cli.OutputRefused) as error:
                cli.open_output(Path("new"))
            self.assertNotIn("private-path", str(error.exception))
        with patch.object(cli, "os", proxy), patch.object(W, "write_new") as write:
            cli.write_new("bound", "report.json", "text")
            write.assert_called_once_with("bound", "report.json", "text")

    def test_cli_closes_windows_handle_and_sanitizes_a_close_error(self):
        with tempfile.TemporaryDirectory() as folder:
            sample = Path(folder) / "input"
            sample.write_bytes(elf()[0])
            directory = SimpleNamespace(close=Mock(side_effect=OSError("private-path")))
            error = io.StringIO()
            with patch.object(cli, "os", SimpleNamespace(name="nt")), \
                    patch.object(W, "open_output", return_value=directory), patch.object(W, "write_new"), \
                    contextlib.redirect_stderr(error), self.assertRaises(SystemExit) as exit:
                cli.main(["analyze", str(sample), "--out", str(Path(folder) / "output")])
            self.assertEqual(exit.exception.code, 1)
            directory.close.assert_called_once_with()
            self.assertEqual(error.getvalue(), "reverseai: output failed: OSError; written: report.json, report.md\n")

    def test_a_close_error_does_not_replace_the_primary_analysis_error(self):
        with tempfile.TemporaryDirectory() as folder:
            sample = Path(folder) / "input"
            sample.write_bytes(elf()[0])
            directory = SimpleNamespace(close=Mock(side_effect=OSError("private-path")))
            error = io.StringIO()
            with patch.object(cli, "os", SimpleNamespace(name="nt")), \
                    patch.object(W, "open_output", return_value=directory), \
                    patch.object(cli.pipeline, "analyze_bytes", side_effect=ValueError("private-path")), \
                    contextlib.redirect_stderr(error), self.assertRaises(SystemExit) as exit:
                cli.main(["analyze", str(sample), "--out", str(Path(folder) / "output")])
            self.assertEqual(exit.exception.code, 1)
            self.assertEqual(error.getvalue(), "reverseai: analysis failed: ValueError\n")
            directory.close.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
