"""Windows reports created relative to a bound directory, never by their path.

Native DLLs and msvcrt are loaded only when Windows output is requested. The
fixed-width ABI types also let the same calls run against an inert test API.
"""

import ctypes as C
import os
import struct
import sys


ULONG = C.c_uint32
USHORT = C.c_uint16
HANDLE = C.c_void_p
NTSTATUS = C.c_int32
INVALID_HANDLE_VALUE = C.c_void_p(-1).value
FILE_LIST_DIRECTORY = 0x0001
FILE_TRAVERSE = 0x0020
FILE_READ_ATTRIBUTES = 0x0080
SYNCHRONIZE = 0x00100000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 1
FILE_SHARE_WRITE = 2
OPEN_EXISTING = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
FILE_ATTRIBUTE_DIRECTORY = 0x10
FILE_ATTRIBUTE_NORMAL = 0x80
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
FILE_CREATE = 2
FILE_CREATED = 2
FILE_NON_DIRECTORY_FILE = 0x40
FILE_OPEN_REPARSE_POINT = 0x00200000
FILE_SYNCHRONOUS_IO_NONALERT = 0x20
OBJ_CASE_INSENSITIVE = 0x40
FILE_ATTRIBUTE_TAG_INFO_CLASS = 9
FILE_FULL_DIRECTORY_INFO = 14
FILE_FULL_DIRECTORY_RESTART_INFO = 15
ERROR_NO_MORE_FILES = 18
DIRECTORY_BUFFER_BYTES = 65536
CRT_FLAGS = 0x0001 | 0x8000 | 0x0080  # _O_WRONLY | _O_BINARY | _O_NOINHERIT
REPORT_NAMES = ("report.json", "report.md")
mkdir = os.mkdir


class OutputRefused(Exception):
    """A constant, path-free explanation of an unsafe Windows output."""


class UNICODE_STRING(C.Structure):
    _fields_ = [("Length", USHORT), ("MaximumLength", USHORT), ("Buffer", C.c_void_p)]


class OBJECT_ATTRIBUTES(C.Structure):
    _fields_ = [("Length", ULONG), ("RootDirectory", HANDLE),
                ("ObjectName", C.POINTER(UNICODE_STRING)), ("Attributes", ULONG),
                ("SecurityDescriptor", C.c_void_p), ("SecurityQualityOfService", C.c_void_p)]


class _IO_STATUS(C.Union):
    _fields_ = [("Status", NTSTATUS), ("Pointer", C.c_void_p)]


class IO_STATUS_BLOCK(C.Structure):
    _anonymous_ = ("result",)
    _fields_ = [("result", _IO_STATUS), ("Information", C.c_size_t)]


class FILE_ATTRIBUTE_TAG_INFO(C.Structure):
    _fields_ = [("FileAttributes", ULONG), ("ReparseTag", ULONG)]


class _API:
    def __init__(self, kernel, ntdll, open_osfhandle, last_error):
        self.CreateFileW = kernel.CreateFileW
        self.CreateFileW.argtypes = [C.c_wchar_p, ULONG, ULONG, C.c_void_p, ULONG, ULONG, HANDLE]
        self.CreateFileW.restype = HANDLE
        self.GetFileInformationByHandleEx = kernel.GetFileInformationByHandleEx
        self.GetFileInformationByHandleEx.argtypes = [HANDLE, C.c_int, C.c_void_p, ULONG]
        self.GetFileInformationByHandleEx.restype = C.c_int32
        self.CloseHandle = kernel.CloseHandle
        self.CloseHandle.argtypes = [HANDLE]
        self.CloseHandle.restype = C.c_int32
        self.NtCreateFile = ntdll.NtCreateFile
        self.NtCreateFile.argtypes = [C.POINTER(HANDLE), ULONG, C.POINTER(OBJECT_ATTRIBUTES),
                                     C.POINTER(IO_STATUS_BLOCK), C.POINTER(C.c_int64),
                                     ULONG, ULONG, ULONG, ULONG, C.c_void_p, ULONG]
        self.NtCreateFile.restype = NTSTATUS
        self.RtlNtStatusToDosError = ntdll.RtlNtStatusToDosError
        self.RtlNtStatusToDosError.argtypes = [NTSTATUS]
        self.RtlNtStatusToDosError.restype = ULONG
        self.open_osfhandle = open_osfhandle
        self.last_error = last_error

    def close(self, handle):
        if not self.CloseHandle(handle):
            raise OSError(self.last_error(), "Windows output handle could not be closed")


def _load_api():
    if os.name != "nt":
        raise OutputRefused("Windows output APIs are unavailable")
    import msvcrt
    return _API(C.WinDLL("kernel32", use_last_error=True), C.WinDLL("ntdll", use_last_error=True),
                msvcrt.open_osfhandle, C.get_last_error)


def _valid_handle(handle):
    return handle not in (None, 0, -1, INVALID_HANDLE_VALUE)


def _close_after_error(api, handle):
    # Preserve the primary refusal while still attempting to close its handle.
    try:
        api.close(handle)
    except OSError:
        pass


def _empty(api, handle):
    """Only dot entries may precede NO_MORE_FILES; enumerate through this handle."""
    seen = 0
    for information in (FILE_FULL_DIRECTORY_RESTART_INFO, FILE_FULL_DIRECTORY_INFO,
                        FILE_FULL_DIRECTORY_INFO):
        buffer = C.create_string_buffer(DIRECTORY_BUFFER_BYTES)
        if not api.GetFileInformationByHandleEx(handle, information, buffer, len(buffer)):
            if api.last_error() == ERROR_NO_MORE_FILES:
                return True
            raise OSError(api.last_error(), "Windows output directory could not be listed")
        data, offset = buffer.raw, 0
        while True:
            if offset + 68 > len(data):
                raise OutputRefused("--out directory information is invalid")
            following = struct.unpack_from("<I", data, offset)[0]
            length = struct.unpack_from("<I", data, offset + 60)[0]
            end = offset + 68 + length
            if length == 0 or length % 2 or end > len(data):
                raise OutputRefused("--out directory information is invalid")
            if data[offset + 68:end] not in (b".\0", b".\0.\0"):
                return False
            seen += 1
            if seen > 2:
                raise OutputRefused("--out directory information is invalid")
            if following == 0:
                break
            if following % 8 or following < 68 + length or offset + following >= len(data):
                raise OutputRefused("--out directory information is invalid")
            offset += following
    raise OutputRefused("--out directory information is incomplete")


class Directory:
    def __init__(self, handle, api):
        self.handle = handle
        self.api = api

    def close(self):
        if self.handle is not None:
            handle, self.handle = self.handle, None
            self.api.close(handle)


def open_output(path, *, api=None):
    if sys.implementation.name != "cpython" or sys.version_info < (3, 12, 4) \
            or (sys.version_info[:2] == (3, 13) and sys.version_info < (3, 13, 0, "beta", 2)):
        raise OutputRefused("Windows output requires CPython 3.12.4 or later")
    api = _load_api() if api is None else api
    try:
        mkdir(path, 0o700)
    except FileExistsError:
        raise OutputRefused("--out must be a new directory on Windows") from None
    except (OSError, ValueError):
        raise OutputRefused("--out cannot be created") from None
    handle = api.CreateFileW(os.fspath(path), FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                             FILE_SHARE_READ | FILE_SHARE_WRITE, None, OPEN_EXISTING,
                             FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, None)
    if not _valid_handle(handle):
        raise OutputRefused("--out cannot be bound safely on Windows")
    try:
        attributes = FILE_ATTRIBUTE_TAG_INFO()
        if not api.GetFileInformationByHandleEx(handle, FILE_ATTRIBUTE_TAG_INFO_CLASS,
                                              C.byref(attributes), C.sizeof(attributes)):
            raise OSError(api.last_error(), "Windows output directory attributes are unavailable")
        if not attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY \
                or attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT or not _empty(api, handle):
            raise OutputRefused("--out must be a new empty directory without a reparse point")
    except BaseException:
        _close_after_error(api, handle)
        raise
    return Directory(handle, api)


def write_new(directory, name, text):
    if name not in REPORT_NAMES:
        raise ValueError("Unsupported report name")
    if directory.handle is None:
        raise ValueError("Windows output directory is closed")
    api, handle = directory.api, HANDLE()
    encoded = name.encode("utf-16-le")
    buffer = C.create_string_buffer(encoded + b"\0\0")
    string = UNICODE_STRING(len(encoded), len(encoded) + 2, C.cast(buffer, C.c_void_p))
    attributes = OBJECT_ATTRIBUTES(C.sizeof(OBJECT_ATTRIBUTES), directory.handle, C.pointer(string),
                                   OBJ_CASE_INSENSITIVE, None, None)
    io = IO_STATUS_BLOCK()
    status = api.NtCreateFile(C.byref(handle), GENERIC_WRITE | SYNCHRONIZE, C.byref(attributes),
                              C.byref(io), None, FILE_ATTRIBUTE_NORMAL, 0, FILE_CREATE,
                              FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                              None, 0)
    if status != 0 or not _valid_handle(handle.value) or io.Information != FILE_CREATED:
        if _valid_handle(handle.value):
            _close_after_error(api, handle.value)
        code = api.RtlNtStatusToDosError(status) if status != 0 else 0
        raise OSError(code, "Windows report could not be created")
    try:
        descriptor = api.open_osfhandle(handle.value, CRT_FLAGS)
        if descriptor < 0:
            raise OSError("Windows report descriptor could not be created")
    except BaseException:
        _close_after_error(api, handle.value)
        raise
    # open_osfhandle transferred ownership: only the CRT descriptor closes it now.
    try:
        stream = os.fdopen(descriptor, "w", encoding="utf-8", errors="backslashreplace", newline="\n")
    except BaseException:
        os.close(descriptor)
        raise
    with stream:
        stream.write(text)
