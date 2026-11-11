"""ReverseAI Ghidra worker: bounded query JSON, or one raw USTAR prepared artifact, on stdout.

Entrypoint (docs/contract.md, "Contained Ghidra worker (M3a)"):
    python3 -I -B /opt/reverseai/worker.py ghidra.analyze <canonical JSON of validated args>

The worker accepts ELF, PE and thin little-endian Mach-O only and runs one headless Ghidra import of
the snapshot into a project under /tmp, with a fixed loader per format (libraries never loaded), the
reviewed scripts baked into
the image (ReverseAIOptions turns off the analyzers that could look outside the input; ReverseAIQuery
writes functions, calls, other references, pseudocode and instruction listings as JSON), a fixed heap
and timeouts below the 240 s wall limit. Requests choose only the eight bounded counts: never a script,
loader or option.

Ghidra's addresses may be rebased, so every anchor is mapped again here with this file's own
section table (stdlib decoding; only file-mapped bytes count: ELF SHF_ALLOC sections, PE
min(SizeOfRawData, VirtualSize), decision m3a-function-span; Mach-O LC_SEGMENT(_64) sections with
file bytes inside their segment's file range, executable by the segment's initprot or an instruction
attribute, as the host's macho_sections, decision m3b-macho-zerofill): an observation's address is the
file's virtual address of its anchor, and an anchor is kept only inside an executable section. The
entry point that leads the pseudocode is the one the host checks (Mach-O: structure.macho_entry's rule,
decision m3b-macho-entry).
Each anchor is cross-checked: Ghidra's bytes there equal the snapshot's, Ghidra's memory block maps
its address back to the same file offset, and every anchor has the same Ghidra-to-file address
delta; anything else is InconsistentAnchor. What stays Ghidra's reading, reported as derived and
never as verified: names, a function's size (its span from the entry to the last body byte), call
and reference targets, reference types, instruction texts and pseudocode. Observations follow the M3a
seams: functions in address order, pseudocode for the entry-point function and then the largest (cut
to fit the 4,096-byte observation limit, decision m3c-pseudocode-fit), calls from emitted functions
only, inside their span. Then the M3c kinds (decision m3c-contract), each added only while the encoded
reply stays within its limit: instruction listings in the pseudocode order, each instruction's bytes
confirmed; non-call references with their contract type; and the strings the referenced bytes hold,
decoded here from the snapshot by the contract rule. Errors are class names only. Nothing but the
one JSON object is written, to stdout only.
"""

import hashlib
import importlib.util
import contextlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import struct
import subprocess
import sys

PROTOCOL = "reverseai.worker/1"
ADAPTER_VERSION = "12.1.4-r7"
SNAPSHOT = "/snapshot/input"
MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_REPLY_BYTES = 262_144
MAX_QUERY_BYTES = 32 * 1024 * 1024
MAX_LOCATION = 4096
MAX_OBSERVATION_BYTES = 4096  # an observation value's canonical JSON, as the host's Observation bounds it
MAX_NAME = 128
MAX_INSTRUCTION_TEXT = 64
MAX_STRING_CHARS = 128
MAX_STRING_FROM = 8
ARGS = {"max_functions": (1, 128, 64), "decompile": (0, 16, 8), "max_chars": (64, 2048, 1024), "max_calls": (0, 256, 128),
        "assembly": (0, 8, 4), "max_instructions": (1, 64, 32), "max_refs": (0, 128, 64), "max_strings": (0, 64, 32)}
MAX_ADDRESS = 2**64 - 1
# Every operation's arguments with the host's ArgSpec bounds (decision m3d-contract): ("int", min, max, default),
# ("enum", choices, default) or ("str", default); a None default means required.
OPERATIONS = {
    "ghidra.analyze": {name: ("int", *bounds) for name, bounds in ARGS.items()},
    "ghidra.functions": {"query": ("str", ""), "start": ("int", 0, 65535, 0), "limit": ("int", 1, 128, 64)},
    "ghidra.function": {"select": ("enum", ("entry", "name"), "entry"), "entry": ("int", 0, MAX_ADDRESS, 0), "name": ("str", ""),
                        "parts": ("enum", ("info", "pseudocode", "assembly", "callees", "callers", "all"), "all"),
                        "start": ("int", 0, 65535, 0), "limit": ("int", 1, 256, 64), "max_chars": ("int", 64, 2048, 1024),
                        "max_calls": ("int", 0, 256, 64), "max_refs": ("int", 0, 128, 64)},
    "ghidra.xrefs": {"address": ("int", 0, MAX_ADDRESS, None), "start": ("int", 0, 65535, 0), "limit": ("int", 1, 256, 64)},
}
OPERATIONS.update({
    "ghidra.prepare": {},
    "ghidra.pseudocode": {"select": ("enum", ("entry", "name"), "entry"),
                          "entry": ("int", 0, MAX_ADDRESS, 0), "name": ("str", ""),
                          "text_start": ("int", 0, 1048576, 0), "max_chars": ("int", 64, 2048, 1024)},
    "ghidra.export_function": {"select": ("enum", ("entry", "name"), "entry"),
        "entry": ("int", 0, MAX_ADDRESS, 0), "name": ("str", ""),
        "part": ("enum", ("info", "pseudocode", "assembly", "callees", "callers", "references", "strings"), "info"),
        "start": ("int", 0, 1048575, 0), "limit": ("int", 1, 128, 32),
        "text_start": ("int", 0, 1048576, 0), "max_chars": ("int", 64, 2048, 1024)},
    "ghidra.export_program": {"part": ("enum", ("functions", "calls", "references", "strings"), "functions"),
                               "start": ("int", 0, 1048575, 0), "limit": ("int", 1, 128, 32)},
})
MAX_OBSERVATIONS = {"ghidra.analyze": 600, "ghidra.functions": 128, "ghidra.function": 643, "ghidra.xrefs": 256}
MAX_ROWS = 65536  # functions, callers, callees or references to an address one query run may count (m3d-seams-w, m3d-fix-round)
MAX_FUNCTION_INSTRUCTIONS = 1_000_000  # instructions one function may count (m3d-fix-round)
MAX_STRING_ARG = 256
GHIDRA = Path("/opt/ghidra")
SCRIPTS = Path(__file__).resolve().parent / "ghidra_scripts"
WORK = Path("/tmp/reverseai-ghidra")
HEAP = "1G"
ANALYSIS_SECONDS = 120  # Ghidra's own per-file analysis timeout
DECOMPILE_SECONDS = 40  # all decompilation together
GHIDRA_SECONDS = 210  # the whole headless run, below the 240 s wall limit
LOADERS = {"elf": "ElfLoader", "pe": "PeLoader", "macho": "MachoLoader"}
MACHO_MAGICS = {b"\xce\xfa\xed\xfe": 32, b"\xcf\xfa\xed\xfe": 64}  # thin little-endian only
MACHO_ZEROFILL = (0x1, 0xC, 0x12)  # S_ZEROFILL, S_GB_ZEROFILL, S_THREAD_LOCAL_ZEROFILL: no file bytes
MACHO_THREADS = {0x1000007: (4, 42, 128), 0x100000C: (6, 68, 256)}  # cputype: (flavor, count, pc offset) x86_64 rip, arm64 pc


class WorkerFailure(Exception):
    """An expected refusal; its class name is the reply's error."""


class InvalidRequest(WorkerFailure):
    pass


class InputTooLarge(WorkerFailure):
    pass


class SnapshotUnreadable(WorkerFailure):
    pass


class UnsupportedFormat(WorkerFailure):
    pass


class TruncatedStructure(WorkerFailure):
    pass


class GhidraTimeout(WorkerFailure):
    pass


class GhidraFailed(WorkerFailure):
    """Ghidra exited without the query's output."""


class InvalidQueryOutput(WorkerFailure):
    """The query's JSON is missing, too large or not the expected shape."""


class AnalysisOptionOn(WorkerFailure):
    """An option ReverseAIOptions turns off (PDB, DWARF, Swift) was still on after analysis."""


class InconsistentAnchor(WorkerFailure):
    """Ghidra's address, bytes or memory block disagree with the snapshot at an anchor."""


class ReplyTooLarge(WorkerFailure):
    pass


class TooManyRows(WorkerFailure):
    """More than MAX_ROWS functions, callers, callees or references, or more than MAX_FUNCTION_INSTRUCTIONS instructions,
    to count: the run fails instead of reporting a total cut short."""


# ---- The file's own sections: offset <-> virtual address -----------------------------------------

def need(data, offset, length):
    if offset < 0 or length < 0 or offset + length > len(data):
        raise TruncatedStructure()


def kind(data):
    if data[:4] == b"\x7fELF":
        return "elf"
    if len(data) >= 0x40 and data[:2] == b"MZ":
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 4 <= len(data) and data[e_lfanew:e_lfanew + 4] == b"PE\0\0":
            return "pe"
    if data[:4] in MACHO_MAGICS:
        return "macho"
    raise UnsupportedFormat()


def elf_map(data):
    """(entry VA, [(file start, file end, VA start, executable)]) from the ELF section headers."""
    need(data, 0, 0x34)
    width, order = {1: 32, 2: 64}.get(data[4]), {1: "<", 2: ">"}.get(data[5])
    if width is None or order is None:
        raise UnsupportedFormat()
    if width == 64:
        need(data, 0, 64)
        entry, shoff = struct.unpack_from(order + "QQ", data, 24)[0], struct.unpack_from(order + "Q", data, 40)[0]
        shentsize, shnum = struct.unpack_from(order + "HH", data, 58)
        row, size = order + "IIQQQQIIQQ", 64
    else:
        entry, shoff = struct.unpack_from(order + "I", data, 24)[0], struct.unpack_from(order + "I", data, 32)[0]
        shentsize, shnum = struct.unpack_from(order + "HH", data, 46)
        row, size = order + "IIIIIIIIII", 40
    sections = []
    if shnum:
        if shentsize != size:
            raise UnsupportedFormat()
        need(data, shoff, size * shnum)
        for index in range(shnum):
            _, kind_, flags, address, offset, length = struct.unpack_from(row, data, shoff + size * index)[:6]
            if kind_ != 8 and flags & 0x2 and length:  # allocated and in the file (not NOBITS)
                need(data, offset, length)
                sections.append((offset, offset + length, address, bool(flags & 0x4)))
    return entry, sections


def pe_map(data):
    """(entry VA, [(file start, file end, VA start, executable)]) from the PE section table."""
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    coff = e_lfanew + 4
    need(data, coff, 20)
    count, optional_size = struct.unpack_from("<H", data, coff + 2)[0], struct.unpack_from("<H", data, coff + 16)[0]
    optional = coff + 20
    need(data, optional, optional_size)
    if optional_size < 32:
        raise UnsupportedFormat()
    magic, entry_rva = struct.unpack_from("<H", data, optional)[0], struct.unpack_from("<I", data, optional + 16)[0]
    if magic == 0x20B and optional_size >= 32:
        image_base = struct.unpack_from("<Q", data, optional + 24)[0]
    elif magic == 0x10B and optional_size >= 32:
        image_base = struct.unpack_from("<I", data, optional + 28)[0]
    else:
        raise UnsupportedFormat()
    table = optional + optional_size
    need(data, table, 40 * count)
    sections = []
    for index in range(count):
        virtual_size, rva, raw_size, raw = struct.unpack_from("<IIII", data, table + 40 * index + 8)
        characteristics = struct.unpack_from("<I", data, table + 40 * index + 36)[0]
        length = min(raw_size, virtual_size) if virtual_size else raw_size
        if length:
            need(data, raw, length)
            sections.append((raw, raw + length, image_base + rva, bool(characteristics & 0x20000000)))
    return image_base + entry_rva, sections


def _thread_pcs(data, start, end, expected):
    """Program counters of the expected (flavor, count, pc offset) states in one LC_UNIXTHREAD, None if malformed."""
    pcs = []
    while start < end:
        if start + 8 > end:
            return None
        flavor, count = struct.unpack_from("<II", data, start)
        state = start + 8
        if count > (end - state) // 4:
            return None
        if expected and flavor == expected[0]:
            if count != expected[1]:
                return None
            pcs.append(struct.unpack_from("<Q", data, state + expected[2])[0])
        start = state + count * 4
    return pcs


def macho_map(data):
    """(entry VA or 0, [(file start, file end, VA start, executable)]) from the LC_SEGMENT(_64) sections of a thin
    little-endian Mach-O. A section counts only with file bytes inside its segment's file range; executable is the
    segment's initprot execute bit or a section instruction attribute. The entry follows the host's macho_entry: one
    LC_MAIN through the one segment whose file bytes hold entryoff, else one x86_64 or arm64 LC_UNIXTHREAD pc, else 0."""
    width = MACHO_MAGICS[data[:4]]
    header = 32 if width == 64 else 28
    need(data, 0, header)
    cputype = struct.unpack_from("<I", data, 4)[0]
    ncmds, sizeofcmds = struct.unpack_from("<II", data, 16)
    need(data, header, sizeofcmds)
    segment_cmd, segment_size, section_size = (0x19, 72, 80) if width == 64 else (0x1, 56, 68)
    segment_row, section_row = ("<16sQQQQiiII", "<16s16sQQIIIIIIII") if width == 64 else ("<16sIIIIiiII", "<16s16sIIIIIIIII")
    at, end, sections, segments, mains, threads, valid = header, header + sizeofcmds, [], [], [], [], True
    for _ in range(ncmds):
        if at + 8 > end:
            raise TruncatedStructure()
        cmd, cmdsize = struct.unpack_from("<II", data, at)
        if cmdsize < 8 or at + cmdsize > end:
            raise TruncatedStructure()
        if cmd == segment_cmd:
            if cmdsize < segment_size:
                raise TruncatedStructure()
            _, vmaddr, vmsize, fileoff, filesize, _, initprot, nsects, _ = struct.unpack_from(segment_row, data, at + 8)
            if segment_size + nsects * section_size > cmdsize:
                raise TruncatedStructure()
            segments.append((fileoff, filesize, vmaddr, vmsize))
            for index in range(nsects):
                row = struct.unpack_from(section_row, data, at + segment_size + index * section_size)
                address, size, offset, flags = row[2], row[3], row[4], row[8]
                inside = fileoff <= offset and offset + size <= fileoff + filesize
                if size and offset and inside and (flags & 0xFF) not in MACHO_ZEROFILL:
                    need(data, offset, size)
                    sections.append((offset, offset + size, address, bool(initprot & 0x4) or bool(flags & 0x80000400)))
        elif cmd == 0x80000028:  # LC_MAIN: entryoff is a file offset inside __TEXT
            valid = valid and cmdsize >= 24
            if cmdsize >= 24:
                mains.append(struct.unpack_from("<Q", data, at + 8)[0])
        elif cmd == 0x5:  # LC_UNIXTHREAD: (flavor, count, state) records
            pcs = _thread_pcs(data, at + 8, at + cmdsize, MACHO_THREADS.get(cputype))
            valid = valid and pcs is not None
            threads += pcs or []
        at += cmdsize
    if not valid or len(mains) > 1:
        return 0, sections
    if mains:
        found = [vmaddr + mains[0] - fileoff for fileoff, filesize, vmaddr, vmsize in segments
                 if fileoff + filesize <= len(data) and 0 <= mains[0] - fileoff < min(filesize, vmsize)
                 and vmaddr + vmsize <= 2**width]
        return (found[0] if len(found) == 1 else 0), sections
    return (threads[0] if len(threads) == 1 else 0), sections


FILE_MAPS = {"elf": elf_map, "pe": pe_map, "macho": macho_map}


def section_at(sections, offset, length=1):
    found = [s for s in sections if s[0] <= offset and offset + length <= s[1]]
    return found[0] if len(found) == 1 else None


def offset_of(sections, address):
    found = [s for s in sections if s[2] <= address < s[2] + (s[1] - s[0])]
    return found[0][0] + (address - found[0][2]) if len(found) == 1 else None


# ---- Request -----------------------------------------------------------------------------------

def parse_request(argv):
    if len(argv) != 2:
        raise InvalidRequest()
    operation, text = argv
    try:
        args = json.loads(text, object_pairs_hook=lambda pairs: dict(pairs) if len({k for k, _ in pairs}) == len(pairs) else None)
    except ValueError:
        raise InvalidRequest() from None
    specs = OPERATIONS.get(operation)
    if specs is None or not isinstance(args, dict) or not set(args) <= set(specs):
        raise InvalidRequest()
    checked = {}
    for name, spec in specs.items():
        value = args.get(name, spec[-1])
        if value is None or not _allowed(spec, value):
            raise InvalidRequest()
        checked[name] = value
    if operation in ("ghidra.pseudocode", "ghidra.export_function"):
        if checked["select"] == "entry" and checked["name"] or checked["select"] == "name" and checked["entry"]:
            raise InvalidRequest()
    if operation == "ghidra.export_function":
        part = checked["part"]
        if (part == "info" and (checked["start"] or checked["limit"] != 32)
                or part == "pseudocode" and (checked["start"] or checked["limit"] != 32)
                or part not in ("pseudocode",) and (checked["text_start"] or checked["max_chars"] != 1024)):
            raise InvalidRequest()
    return operation, checked


def _allowed(spec, value):
    """The host's ArgSpec.check: int in range, enum choice, or a short str with no NUL, slash, backslash or leading dash."""
    if spec[0] == "int":
        return type(value) is int and spec[1] <= value <= spec[2]
    if spec[0] == "enum":
        return isinstance(value, str) and value in spec[1]
    return (isinstance(value, str) and len(value) <= MAX_STRING_ARG and "\x00" not in value and "/" not in value
            and "\\" not in value and not value.startswith("-"))


# ---- Ghidra ------------------------------------------------------------------------------------

def ghidra_argv(format_, out, script):
    """The one fixed headless command; the request contributes only the query's mode and its bounded arguments."""
    loader = LOADERS[format_]
    return ["/bin/bash", str(GHIDRA / "support" / "analyzeHeadless"), str(WORK / "project"), "reverseai",
            "-import", SNAPSHOT, "-readOnly", "-deleteProject", "-max-cpu", "2",
            "-analysisTimeoutPerFile", str(ANALYSIS_SECONDS),
            "-loader", loader, "-loader-loadLibraries", "false", "-loader-linkExistingProjectLibraries", "false",
            "-scriptPath", str(SCRIPTS), "-preScript", "ReverseAIOptions.java",
            "-postScript", "ReverseAIQuery.java", str(out), *script,
            "-log", str(WORK / "ghidra.log"), "-scriptlog", str(WORK / "script.log")]


def script_args(operation, args, data):
    """ReverseAIQuery's arguments after the output path: the mode, then its fixed arguments in a fixed order. Strings go
    as "x" + UTF-8 hex; file positions come from this file's own section table."""
    entry_va, sections = FILE_MAPS[kind(data)](data)

    def offset(address):
        found = offset_of(sections, address)
        return str(-1 if found is None else found)

    if operation == "ghidra.analyze":
        return ["analyze", str(args["max_functions"]), str(args["decompile"]), offset(entry_va), str(DECOMPILE_SECONDS),
                str(args["assembly"]), str(args["max_instructions"])]
    if operation == "ghidra.functions":
        return ["functions", "x" + args["query"].encode().hex(), str(args["start"]), str(args["limit"])]
    if operation == "ghidra.function":
        return ["function", args["select"], offset(args["entry"]) if args["select"] == "entry" else "-1",
                "x" + args["name"].encode().hex(), args["parts"], str(args["start"]), str(args["limit"]), str(DECOMPILE_SECONDS)]
    base = sections[0] if sections else (-1, -1, 0)
    return ["xrefs", offset(args["address"]), str(args["address"]), str(base[0]), str(base[2])]


def ghidra_env():
    home = WORK / "home"
    # Every JVM (Ghidra's launch support too) needs a writable home: user 65534's passwd home does not exist.
    return {"PATH": "/usr/bin:/bin", "HOME": str(home), "LANG": "C.UTF-8", "JAVA_HOME": "/opt/jdk",
            "GHIDRA_HEADLESS_MAXMEM": HEAP, "JAVA_TOOL_OPTIONS": f"-Duser.home={home} -Djava.io.tmpdir={WORK}"}


def run_ghidra(format_, args, script):
    """Run the fixed headless analysis with the query's mode and arguments and return the query's parsed JSON."""
    shutil.rmtree(WORK, ignore_errors=True)
    for folder in ("home", "project"):
        (WORK / folder).mkdir(parents=True, mode=0o700)
    out = WORK / "query.json"
    with open(WORK / "headless.out", "wb") as log:
        process = subprocess.Popen(ghidra_argv(format_, out, script), env=ghidra_env(), cwd=WORK,
                                   stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            process.wait(timeout=GHIDRA_SECONDS)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise GhidraTimeout() from None
    try:
        with open(out, "rb") as stream:
            raw = stream.read(MAX_QUERY_BYTES + 1)
    except OSError:
        raise GhidraFailed() from None
    if len(raw) > MAX_QUERY_BYTES:
        raise InvalidQueryOutput()
    try:
        return json.loads(raw)
    except ValueError:
        raise InvalidQueryOutput() from None


# ---- Observations ------------------------------------------------------------------------------

def _int(value, minimum=0):
    if type(value) is not int or value < minimum:
        raise InvalidQueryOutput()
    return value


def _hex(value, limit):
    if not isinstance(value, str) or len(value) > 2 * limit or not re.fullmatch(r"(?:[0-9a-f]{2})*", value):
        raise InvalidQueryOutput()
    return bytes.fromhex(value)


def printable_name(value):
    if not isinstance(value, str):
        raise InvalidQueryOutput()
    return "".join(c if " " <= c <= "~" else "?" for c in value)[:MAX_NAME]


def printable_text(value):
    if not isinstance(value, str):
        raise InvalidQueryOutput()
    return "".join(c if c.isprintable() or c in "\n\t" else "?" for c in value)


def _size(value):
    """Bytes of value's JSON as encode() and the host's canonical_json write it (UTF-8, sorted keys, no spaces)."""
    return len(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))


class Anchors:
    """Maps Ghidra addresses to this file's offsets and VAs, and checks every anchor against the bytes."""

    def __init__(self, data, sections, blocks):
        self.data, self.sections, self.delta = data, sections, None
        self.blocks = []
        for block in blocks:
            if not isinstance(block, dict):
                raise InvalidQueryOutput()
            self.blocks.append((_int(block.get("start")), _int(block.get("size"), 1), block.get("file_offset")))

    def block_offset(self, address):
        found = [b for b in self.blocks if b[0] <= address < b[0] + b[1]]
        if len(found) != 1 or type(found[0][2]) is not int or found[0][2] < 0:
            return None
        return found[0][2] + (address - found[0][0])

    def anchor(self, address, offset, raw, length):
        """The file VA of a Ghidra address whose first `length` bytes Ghidra reported as `raw` at file `offset`."""
        section = section_at(self.sections, offset, length)
        if section is None or not section[3]:
            return None  # not inside one executable section: not admitted
        if self.block_offset(address) != offset or len(raw) < length or raw[:length] != self.data[offset:offset + length]:
            raise InconsistentAnchor()
        va = section[2] + (offset - section[0])
        if self.delta is None:
            self.delta = address - va
        elif address - va != self.delta:
            raise InconsistentAnchor()
        return va, section


def _prelude(data, query, mode=None):
    """(entry VA, sections, anchors) for a query output of the expected mode; analysis options are checked first."""
    entry_va, sections = FILE_MAPS[kind(data)](data)
    if not isinstance(query, dict) or not isinstance(query.get("blocks"), list) or (mode and query.get("mode") != mode):
        raise InvalidQueryOutput()
    options = query.get("options_off")
    if not isinstance(options, dict) or not all(isinstance(v, str) for v in options.values()):
        raise InvalidQueryOutput()
    if any(value.lower() == "true" for value in options.values()):
        raise AnalysisOptionOn()
    return entry_va, sections, Anchors(data, sections, query["blocks"])


def _function(anchors, sections, item):
    """A query function as {address, va, offset, length, size, name, raw_name, calls, refs}, or None when the query did
    not anchor it or its first bytes are not inside one executable section of this file."""
    if not isinstance(item, dict):
        raise InvalidQueryOutput()
    address, size, offset = _int(item.get("entry")), _int(item.get("size"), 1), item.get("file_offset")
    if item.get("anchored") is not True or type(offset) is not int or offset < 0:
        return None  # the query anchors only file-backed executable functions
    section = section_at(sections, offset)
    if section is None:
        return None
    length = min(size, MAX_LOCATION, section[1] - offset)
    mapped = anchors.anchor(address, offset, _hex(item.get("bytes"), MAX_LOCATION), length)
    if mapped is None:
        return None
    return {"address": address, "va": mapped[0], "offset": offset, "length": length, "size": size,
            "name": printable_name(item.get("name")), "raw_name": item.get("name"), "calls": item.get("calls", []),
            "refs": item.get("refs", [])}


def observations(data, query, args):
    """The reply's observations from the query output, after every check; pure and testable without Ghidra."""
    entry_va, sections, anchors = _prelude(data, query)
    if not isinstance(query.get("functions"), list):
        raise InvalidQueryOutput()
    functions = []
    for item in sorted(query["functions"], key=lambda item: _int(item.get("entry") if isinstance(item, dict) else None)):
        function = _function(anchors, sections, item) if len(functions) < args["max_functions"] else None
        if function is not None:  # the first max_functions anchored ones
            functions.append(function)
    functions.sort(key=lambda f: f["va"])
    result = []
    for index, function in enumerate(functions):
        function["index"] = index
        result.append({"location": {"offset": function["offset"], "length": function["length"]},
                       "value": {"kind": "function", "index": index, "name": function["name"], "entry": function["va"],
                                 "size": function["size"]}})
    result += pseudocode(query.get("pseudocode", []), functions, entry_va, args)
    result += calls(functions, anchors, args)
    reply = Fit(result)
    for item in assembly(query.get("assembly", []), functions, entry_va, anchors, args):
        reply.add(item)
    for item in references(functions, anchors, args):
        reply.add(item)
    for item in strings(data, sections, [o["value"] for o in reply.items if o["value"]["kind"] == "ref"], args):
        reply.add(item)
    return reply.items


class Fit:
    """Observations added in order only while the encoded reply stays within MAX_REPLY_BYTES and the operation's
    observation cap; one is never cut. add() says whether the item went in."""

    def __init__(self, items, limit=MAX_OBSERVATIONS["ghidra.analyze"]):
        self.items, self.limit = list(items), limit
        envelope = len(encode({"protocol": PROTOCOL, "status": "ok", "snapshot_sha256": "0" * 64, "observations": []}))
        self.size = envelope + sum(map(_size, self.items)) + max(0, len(self.items) - 1)

    def add(self, item):
        grown = self.size + _size(item) + (1 if self.items else 0)
        if grown > MAX_REPLY_BYTES or len(self.items) >= self.limit:
            return False
        self.items.append(item)
        self.size = grown
        return True


def ranked(functions, entry_va):
    """The pseudocode order: the entry-point function first if emitted, then the largest (ties: lower entry)."""
    first = [f for f in functions if f["va"] == entry_va]
    return first + sorted((f for f in functions if f["va"] != entry_va), key=lambda f: (-f["size"], f["va"]))


def pseudocode(items, functions, entry_va, args):
    """Texts in the ranked order, at most `decompile`; each cut at max_chars and, if its observation value would pass
    MAX_OBSERVATION_BYTES, to the longest prefix that fits (decision m3c-pseudocode-fit)."""
    if not isinstance(items, list):
        raise InvalidQueryOutput()
    texts = {}
    for item in items:
        if not isinstance(item, dict):
            raise InvalidQueryOutput()
        texts[_int(item.get("entry"))] = printable_text(item.get("text"))  # texts of functions not emitted are ignored
    result = []
    for function in ranked(functions, entry_va)[:args["decompile"]]:
        text = texts.get(function["address"])
        if text is None:
            continue  # a failed decompilation is omitted
        value = {"kind": "pseudocode", "index": function["index"], "entry": function["va"],
                 "text": text[:args["max_chars"]], "truncated": len(text) > args["max_chars"]}
        if _size(value) > MAX_OBSERVATION_BYTES:
            whole, low, high = value["text"], 0, len(value["text"])
            value["truncated"] = True
            while low < high:  # the longest prefix that fits; the size grows with the prefix
                value["text"] = whole[:(low + high + 1) // 2]
                low, high = (len(value["text"]), high) if _size(value) <= MAX_OBSERVATION_BYTES else (low, len(value["text"]) - 1)
            value["text"] = whole[:low]
        result.append({"location": {"offset": function["offset"], "length": function["length"]}, "value": value})
    return result


def _instruction(anchors, function, item):
    """(file VA, file offset, length) of a query instruction whose whole bytes lie inside the function's span."""
    if not isinstance(item, dict):
        raise InvalidQueryOutput()
    address, length, offset = _int(item.get("address")), _int(item.get("length"), 1), item.get("file_offset")
    if length > 16 or type(offset) is not int or offset < 0:
        return None
    mapped = anchors.anchor(address, offset, _hex(item.get("bytes"), 16), length)
    if mapped is None or mapped[0] < function["va"] or mapped[0] + length > function["va"] + function["size"]:
        return None
    return mapped[0], offset, length


def _target(anchors, item, key="to"):
    """A call or reference target (or another address the query gives with its file offset) as a file VA: through its
    file offset when one section holds it, else Ghidra's address less the rebase delta; None below zero."""
    target, target_offset = _int(item.get(key)), item.get(key + "_file_offset")
    if type(target_offset) is int and target_offset >= 0:
        section = section_at(anchors.sections, target_offset)
        if section:
            return section[2] + (target_offset - section[0])
    return target - anchors.delta if target >= anchors.delta else None


def calls(functions, anchors, args):
    """Calls from emitted functions whose whole instruction lies inside that function's [entry, entry + size)."""
    found = set()
    for function in functions:
        if not isinstance(function["calls"], list):
            raise InvalidQueryOutput()
        for item in function["calls"]:
            mapped = _instruction(anchors, function, item)
            to = _target(anchors, item) if mapped else None
            if to is not None:
                found.add((mapped[0], mapped[1], mapped[2], function["va"], to, printable_name(item.get("to_name", ""))))
    return [{"location": {"offset": offset, "length": length},
             "value": {"kind": "call", "from": start, "to": to, "to_name": name}}
            for _, offset, length, start, to, name in sorted(found)[:args["max_calls"]]]


def assembly(items, functions, entry_va, anchors, args):
    """Instruction listings for the first `assembly` functions in the ranked order, each at the function's anchor:
    [delta, length, text] rows in address order, non-overlapping and wholly inside the anchor, each one's bytes
    confirmed; at most max_instructions rows and 4,096 bytes of value; truncated when any instruction of the function
    is not listed. A function with no listable instruction is omitted."""
    if not isinstance(items, list):
        raise InvalidQueryOutput()
    listings = {}
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("instructions"), list):
            raise InvalidQueryOutput()
        if _int(item.get("count")) < len(item["instructions"]):
            raise InvalidQueryOutput()
        listings[_int(item.get("entry"))] = item
    result = []
    for function in ranked(functions, entry_va)[:args["assembly"]]:
        item = listings.get(function["address"])
        if item is None:
            continue  # a failed listing is omitted
        value = {"kind": "assembly", "index": function["index"], "entry": function["va"], "instructions": [], "truncated": False}
        end, after = function["offset"] + function["length"], function["offset"]
        for row in item["instructions"][:args["max_instructions"]]:
            mapped = _instruction(anchors, function, row)
            if mapped is None or mapped[1] < after or mapped[1] + mapped[2] > end:
                break  # outside the anchor, before the previous row's end, or not in an executable section
            text = printable_name(row.get("text"))[:MAX_INSTRUCTION_TEXT] or "?"
            value["instructions"].append([mapped[1] - function["offset"], mapped[2], text])
            if _size(value) > MAX_OBSERVATION_BYTES:
                value["instructions"].pop()
                break
            after = mapped[1] + mapped[2]
        if value["instructions"]:
            value["truncated"] = len(value["instructions"]) < item["count"]
            result.append({"location": {"offset": function["offset"], "length": function["length"]}, "value": value})
    return result


def ref_type(item):
    """The contract type of one query reference from Ghidra's flags, None when it is not reported."""
    flags = [item.get(name) for name in ("flow", "jump", "read", "write", "data", "inside")]
    if not all(type(flag) is bool for flag in flags):
        raise InvalidQueryOutput()
    flow, jump, read, write, data, inside = flags
    if flow:
        return "jump" if jump and not inside else None  # flow inside the body is not reported
    if read and write:
        return "read_write"
    return "read" if read else "write" if write else "data" if data else None


def references(functions, anchors, args):
    """Non-call references from emitted functions' instructions inside their span; one row per contract key (instruction
    file offset, to, type), the lowest when the query repeats a key with other details; sorted by that key, at most
    max_refs."""
    found = {}
    for function in functions:
        if not isinstance(function["refs"], list):
            raise InvalidQueryOutput()
        for item in function["refs"]:
            kind = ref_type(item) if isinstance(item, dict) else None
            mapped = _instruction(anchors, function, item) if kind else None
            to = _target(anchors, item) if mapped else None
            if to is not None:
                row = (mapped[1], to, kind, mapped[2], function["va"], printable_name(item.get("to_name", "")))
                found[row[:3]] = min(found.get(row[:3], row), row)
    return [{"location": {"offset": offset, "length": length},
             "value": {"kind": "ref", "from": start, "to": to, "type": kind, "to_name": name}}
            for offset, to, kind, length, start, name in sorted(found.values())[:args["max_refs"]]]


def decode_string(data, sections, address):
    """(file offset, encoded length, encoding, text, truncated) of the string at address under the contract rule, or
    None: ascii when 2..128 bytes in 0x20..0x7e start there, then a zero byte; else utf-16le with XX 00 units and a
    00 00 terminator; a run that reaches 128 characters with the next one still matching is truncated instead. The text
    and its terminator (or that next unit) lie inside one section, and no other section maps any of those addresses or
    file bytes: an ambiguous string is omitted, never refused (the host maps the whole span both ways)."""
    found = [s for s in sections if s[2] <= address < s[2] + (s[1] - s[0])]
    if len(found) != 1:
        return None
    start, end = found[0][0] + (address - found[0][2]), found[0][1]

    def run(step, matches):
        count = 0
        while count <= MAX_STRING_CHARS and start + (count + 1) * step <= end and matches(start + count * step):
            count += 1
        return count

    for encoding, step in (("ascii", 1), ("utf-16le", 2)):
        count = run(step, lambda at: 0x20 <= data[at] <= 0x7E and (step == 1 or data[at + 1] == 0))
        truncated = count > MAX_STRING_CHARS
        count = min(count, MAX_STRING_CHARS)
        terminated = start + (count + 1) * step <= end and not any(data[start + count * step:start + (count + 1) * step])
        if count >= 2 and (truncated or terminated):
            span = (count + 1) * step
            virtual = [s for s in sections if s[2] < address + span and address < s[2] + (s[1] - s[0])]
            backed = [s for s in sections if s[0] < start + span and start < s[1]]
            if virtual != found or backed != found:
                return None
            return start, count * step, encoding, data[start:start + count * step].decode(encoding), truncated
    return None


def strings(data, sections, refs, args):
    """Strings at the distinct `to` of the reply's references, by address, at most max_strings; `from` the sorted
    referencing functions, the lowest MAX_STRING_FROM."""
    sources = {}
    for ref in refs:
        sources.setdefault(ref["to"], set()).add(ref["from"])
    result = []
    for address in sorted(sources):
        decoded = decode_string(data, sections, address) if len(result) < args["max_strings"] else None
        if decoded is None:
            continue
        offset, length, encoding, text, truncated = decoded
        result.append({"location": {"offset": offset, "length": length},
                       "value": {"kind": "string", "address": address, "encoding": encoding, "text": text,
                                 "truncated": truncated, "from": sorted(sources[address])[:MAX_STRING_FROM]}})
    return result


# ---- M3d targeted queries (decisions m3d-contract, m3d-seams-w) -------------------------------------

def xref_type(row):
    """The contract type of a reference to an address: call (tail calls included), jump, read_write, read, write, data;
    None for other flow."""
    flags = [row.get(name) for name in ("call", "flow", "jump", "read", "write", "data")]
    if not all(type(flag) is bool for flag in flags):
        raise InvalidQueryOutput()
    call, flow, jump, read, write, data = flags
    if call or flow:
        return "call" if call else "jump" if jump else None
    if read and write:
        return "read_write"
    return "read" if read else "write" if write else "data" if data else None


def references_to(anchors, block, to, calls_only):
    """The query's references to `to` (a file VA) from instructions in executable sections of this file, as
    (at, type, file offset, length, from) rows: unique by (at, type), in address order. More than 65,536 fails the run."""
    if not isinstance(block, dict) or not isinstance(block.get("rows"), list) or type(block.get("overflow")) is not bool:
        raise InvalidQueryOutput()
    if block["overflow"] or len(block["rows"]) > MAX_ROWS:
        raise TooManyRows()
    found = {}
    for row in block["rows"]:
        if not isinstance(row, dict):
            raise InvalidQueryOutput()
        kind_ = xref_type(row)
        address, length, offset = _int(row.get("address")), _int(row.get("length"), 1), row.get("file_offset")
        if kind_ is None or (calls_only and kind_ != "call") or length > 16 or type(offset) is not int or offset < 0:
            continue
        mapped = anchors.anchor(address, offset, _hex(row.get("bytes"), 16), length)
        if mapped is None:
            continue
        if _int(row.get("to")) - anchors.delta != to:
            raise InconsistentAnchor()
        source = None if row.get("from") is None else _target(anchors, row, "from")
        found[mapped[0], kind_] = min(found.get((mapped[0], kind_), (mapped[0], kind_, offset, length, source)),
                                      (mapped[0], kind_, offset, length, source), key=lambda r: (r[2], r[3], -1 if r[4] is None else r[4]))
    return [found[key] for key in sorted(found)]


def _rows(query, key):
    items = query.get(key)
    if not isinstance(items, list):
        raise InvalidQueryOutput()
    return items


def function_rows(data, query, args):
    """ghidra.functions: the page start.. of anchored functions whose name contains query, index and total from the
    query's full count; the page stops at the first row this file cannot anchor or that does not fit."""
    _, sections, anchors = _prelude(data, query, "functions")
    items, total = _rows(query, "functions"), _int(query.get("total"))
    if type(query.get("overflow")) is not bool:
        raise InvalidQueryOutput()
    if query["overflow"] or total > MAX_ROWS:
        raise TooManyRows()
    reply = Fit([], MAX_OBSERVATIONS["ghidra.functions"])
    for position, item in enumerate(items[:args["limit"]]):
        index = args["start"] + position
        if not isinstance(item, dict) or item.get("index") != index or index >= total:
            raise InvalidQueryOutput()
        function = _function(anchors, sections, item)
        if function is not None and (not isinstance(function["raw_name"], str) or args["query"] not in function["raw_name"]):
            raise InvalidQueryOutput()
        if function is None or not reply.add({"location": {"offset": function["offset"], "length": function["length"]},
                                              "value": {"kind": "function_row", "index": index, "total": total,
                                                        "name": function["name"], "entry": function["va"], "size": function["size"]}}):
            break
    return reply.items


def instruction_page(anchors, function, page, args):
    """The instructions observation: rows start.. (indexed from the entry) inside the function's span, each one's bytes
    confirmed, at the bytes from the first row to the end of the last (at most 4,096); None when nothing is listed."""
    if not isinstance(page, dict) or not isinstance(page.get("rows"), list):
        raise InvalidQueryOutput()
    total, start, rows = _int(page.get("total")), args["start"], page["rows"]
    if _int(page.get("start")) != start or len(rows) > args["limit"] or (rows and start + len(rows) > total):
        raise InvalidQueryOutput()
    if type(page.get("overflow")) is not bool:
        raise InvalidQueryOutput()
    if page["overflow"] or total > MAX_FUNCTION_INSTRUCTIONS:
        raise TooManyRows()
    value = {"kind": "instructions", "entry": function["va"], "start": start, "total": total, "rows": [], "truncated": False}
    first = after = None
    for position, row in enumerate(rows):
        if not isinstance(row, dict) or row.get("index") != start + position:
            raise InvalidQueryOutput()
        mapped = _instruction(anchors, function, row)
        if mapped is None or (after is not None and mapped[1] < after) or mapped[1] + mapped[2] - (first or mapped[1]) > MAX_LOCATION:
            break
        value["rows"].append([mapped[0] - function["va"], mapped[2], printable_name(row.get("text"))[:MAX_INSTRUCTION_TEXT] or "?"])
        if _size(value) > MAX_OBSERVATION_BYTES:
            value["rows"].pop()
            break
        first, after = mapped[1] if first is None else first, mapped[1] + mapped[2]
    if not value["rows"]:
        return None
    value["truncated"] = len(value["rows"]) < min(args["limit"], total - start)
    return {"location": {"offset": first, "length": after - first}, "value": value}


def function_parts(data, query, args):
    """ghidra.function: the target (by entry, or the lowest entry with that exact name) with its counts, then the parts
    asked for, each added only while the reply fits; nothing when there is no target."""
    _, sections, anchors = _prelude(data, query, "function")
    if query.get("target") is None:
        return []
    matches = _int(query.get("matches"), 1)
    function = _function(anchors, sections, query["target"])
    if function is None:
        return []
    if (function["va"] != args["entry"] or matches != 1) if args["select"] == "entry" else function["raw_name"] != args["name"]:
        raise InvalidQueryOutput()  # the query answered another question
    function["index"] = 0
    if not isinstance(function["calls"], list) or type(query["target"].get("calls_overflow")) is not bool:
        raise InvalidQueryOutput()
    if query["target"]["calls_overflow"] or len(function["calls"]) > MAX_ROWS:
        raise TooManyRows()  # callees_total counts every call instruction, never analyze's 1,024-row prefix
    callers = references_to(anchors, query.get("callers"), function["va"], True)
    callees = calls([function], anchors, {"max_calls": len(function["calls"])})
    anchor = {"offset": function["offset"], "length": function["length"]}
    reply = Fit([{"location": anchor, "value": {"kind": "target", "name": function["name"], "entry": function["va"],
                                               "size": function["size"], "matches": matches,
                                               "callers_total": len(callers), "callees_total": len(callees)}}],
                MAX_OBSERVATIONS["ghidra.function"])
    parts = args["parts"]
    text = query.get("pseudocode")
    if parts in ("pseudocode", "all") and text is not None:
        for item in pseudocode([{"entry": function["address"], "text": text}], [function], function["va"],
                               {"decompile": 1, "max_chars": args["max_chars"]}):
            reply.add(item)
    if parts in ("assembly", "all") and query.get("instructions") is not None:
        page = instruction_page(anchors, function, query["instructions"], args)
        if page is not None:
            reply.add(page)
    rows = []
    if parts in ("callees", "all"):
        rows += callees[:args["max_calls"]]
    if parts in ("callers", "all"):
        rows += [{"location": {"offset": offset, "length": length},
                  "value": {"kind": "caller", "at": at, "from": source, "to": function["va"]}}
                 for at, _, offset, length, source in callers[:args["max_calls"]]]
    if parts == "all":
        rows += references([function], anchors, args)
    for item in rows:
        if not reply.add(item):
            break
    return reply.items


def xref_rows(data, query, args):
    """ghidra.xrefs: the page start.. of every reference to address from instructions in executable sections, in
    address order, index and total over all of them."""
    _, _, anchors = _prelude(data, query, "xrefs")
    rows = references_to(anchors, query.get("xrefs"), args["address"], False)
    reply = Fit([], MAX_OBSERVATIONS["ghidra.xrefs"])
    for index in range(args["start"], min(len(rows), args["start"] + args["limit"])):
        at, kind_, offset, length, source = rows[index]
        if not reply.add({"location": {"offset": offset, "length": length},
                          "value": {"kind": "xref", "index": index, "total": len(rows), "at": at, "from": source,
                                    "to": args["address"], "type": kind_}}):
            break
    return reply.items


HANDLERS = {"ghidra.analyze": observations, "ghidra.functions": function_rows, "ghidra.function": function_parts,
            "ghidra.xrefs": xref_rows}


def run(operation, args, data, query_of=None):
    """Observations for one operation; query_of(format, args, script arguments) defaults to the headless Ghidra run."""
    if operation in ("ghidra.pseudocode", "ghidra.export_function", "ghidra.export_program"):
        return export_rows(operation, args, data, query_of=query_of)
    if query_of is None and (Path(SNAPSHOT).parent / "cache.json").exists():
        cache_root = restore_project(data)
        query = run_cached(kind(data), args, script_args(operation, args, data), cache_root)
    else:
        query = (query_of or run_ghidra)(kind(data), args, script_args(operation, args, data))
    return HANDLERS[operation](data, query, args)


# ---- Prepared projects and paged exports ---------------------------------------------------------

PREPARE_SECONDS = 840
PREPARE_ANALYSIS_SECONDS = 720
MAX_PSEUDOCODE = 1048576
MAX_INSTRUCTION_VISITS = 8388608
HOST_ID_BYTES = 81
BUNDLE_FILES = ("worker.py", "project_cache.py", "ghidra_scripts/ReverseAIOptions.java",
                "ghidra_scripts/ReverseAIQuery.java", "ghidra_scripts/ReverseAIPrepare.java")


class InvalidCachedProject(WorkerFailure):
    pass


class IncompleteAnalysis(WorkerFailure):
    pass


class PseudocodeTooLarge(WorkerFailure):
    pass


def cache_module():
    # The entrypoint uses -I, which intentionally excludes its directory from sys.path.
    spec = importlib.util.spec_from_file_location("reverseai_project_cache", Path(__file__).with_name("project_cache.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def bundle_hash():
    root = Path(__file__).resolve().parent
    hashes = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in BUNDLE_FILES}
    return hashlib.sha256(encode(hashes).rstrip(b"\n")).hexdigest()


def _headless(argv, timeout):
    with open(WORK / "headless.out", "wb") as log:
        process = subprocess.Popen(argv, env=ghidra_env(), cwd=WORK, stdin=subprocess.DEVNULL,
                                   stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise GhidraTimeout() from None
        if process.returncode != 0:
            raise GhidraFailed()


def _query_file(path):
    try:
        with open(path, "rb") as source:
            raw = source.read(MAX_QUERY_BYTES + 1)
        if len(raw) > MAX_QUERY_BYTES:
            raise InvalidQueryOutput()
        return cache_module()._json(raw)
    except (OSError, ValueError, RecursionError):
        raise InvalidQueryOutput() from None


def restore_project(data):
    module, folder = cache_module(), Path(SNAPSHOT).parent
    try:
        with open(folder / "cache.json", "rb") as source:
            raw = source.read(module.MAX_METADATA_BYTES + 1)
        if len(raw) > module.MAX_METADATA_BYTES:
            raise InvalidCachedProject()
        manifest = module._json(raw)
        fields = {"format", "input_sha256", "image_id", "bundle_sha256", "size", "artifact_sha256"}
        if (not isinstance(manifest, dict) or set(manifest) != fields or type(manifest["format"]) is not int
                or manifest["format"] != 1 or manifest["input_sha256"] != hashlib.sha256(data).hexdigest()
                or manifest["bundle_sha256"] != bundle_hash()
                or not isinstance(manifest["image_id"], str)
                or not re.fullmatch(r"sha256:[0-9a-f]{64}", manifest["image_id"])
                or type(manifest["size"]) is not int or not 0 < manifest["size"] <= module.MAX_TAR_BYTES):
            raise InvalidCachedProject()
        shutil.rmtree(WORK, ignore_errors=True)
        WORK.mkdir(mode=0o700)
        (WORK / "home").mkdir(mode=0o700)
        with open(folder / "project.tar", "rb") as source:
            if os.fstat(source.fileno()).st_size != manifest["size"]:
                raise InvalidCachedProject()
            root = module.unpack_project(source, manifest["artifact_sha256"], WORK / "restored")
        metadata = load_metadata(root, data)
        # Validate index sizes even for a query that does not read one of the tables.
        for name, count in metadata["counts"].items():
            reader = module.TableReader(root / "tables", name, count)
            reader.close()
        return root
    except (OSError, ValueError, KeyError, TypeError, struct.error):
        raise InvalidCachedProject() from None


def load_metadata(root, data):
    module = cache_module()
    with open(Path(root) / "tables" / "meta.json", "rb") as source:
        raw = source.read(module.MAX_METADATA_BYTES + 1)
    if len(raw) > module.MAX_METADATA_BYTES:
        raise InvalidCachedProject()
    metadata = module._json(raw)
    if (not isinstance(metadata, dict) or set(metadata) != {"format", "input_sha256", "counts", "complete"}
            or type(metadata["format"]) is not int or metadata["format"] != 1
            or metadata["input_sha256"] != hashlib.sha256(data).hexdigest() or metadata["complete"] is not True
            or not isinstance(metadata["counts"], dict) or set(metadata["counts"]) != set(module.TABLES)
            or any(type(n) is not int or not 0 <= n <= module.CAPS[name] for name, n in metadata["counts"].items())):
        raise InvalidCachedProject()
    return metadata


def run_cached(format_, args, script, root):
    out = WORK / "query.json"
    argv = ["/bin/bash", str(GHIDRA / "support" / "analyzeHeadless"), str(Path(root) / "project"), "reverseai",
            "-process", "input", "-noanalysis", "-readOnly", "-max-cpu", "2", "-scriptPath", str(SCRIPTS),
            "-postScript", "ReverseAIQuery.java", str(out), *script,
            "-log", str(WORK / "ghidra.log"), "-scriptlog", str(WORK / "script.log")]
    _headless(argv, GHIDRA_SECONDS)
    return _query_file(out)


def prepare_argv(format_, raw_folder):
    return ["/bin/bash", str(GHIDRA / "support" / "analyzeHeadless"), str(WORK / "cache" / "project"), "reverseai",
            "-import", SNAPSHOT, "-max-cpu", "2", "-analysisTimeoutPerFile", str(PREPARE_ANALYSIS_SECONDS),
            "-loader", LOADERS[format_], "-loader-loadLibraries", "false", "-loader-linkExistingProjectLibraries", "false",
            "-scriptPath", str(SCRIPTS), "-preScript", "ReverseAIOptions.java",
            "-postScript", "ReverseAIPrepare.java", str(raw_folder),
            "-log", str(WORK / "ghidra.log"), "-scriptlog", str(WORK / "script.log")]


def _raw_rows(path, cap):
    module = cache_module()
    with open(path, "rb") as source:
        count = 0
        while raw := source.readline(16385):
            if len(raw) > 16384 or not raw.endswith(b"\n") or count == cap:
                raise TooManyRows()
            value = module._json(raw)
            if not isinstance(value, dict):
                raise InvalidQueryOutput()
            count += 1
            yield value


def _export_item(location, value):
    # Reserve the host-added analysis_id in every value, including metadata and pseudocode.
    if _size(value) + HOST_ID_BYTES > MAX_OBSERVATION_BYTES:
        raise ReplyTooLarge()
    return {"location": location, "value": value}


def _signature(raw):
    if raw is None:
        return None, False
    if not isinstance(raw, str):
        raise InvalidQueryOutput()
    text = "".join(c if c.isprintable() else "?" for c in raw)
    return text[:512], len(text) > 512


def build_tables(data, raw_folder, tables):
    """Stream the fixed prepare output into bounded indexed tables; no full-program JSON blob."""
    module = cache_module()
    header = _query_file(Path(raw_folder) / "header.json")
    if header.get("complete") is not True:
        raise IncompleteAnalysis()
    _, sections, anchors = _prelude(data, header)
    functions, instruction_visits = {}, 0
    counts = {}
    with contextlib.ExitStack() as stack:
        writers, budget = {}, {"bytes": 0}
        for name in module.TABLES:
            writers[name] = module.TableWriter(tables, name, budget=budget)
            stack.callback(writers[name].close)
        previous = -1
        for item in _raw_rows(Path(raw_folder) / "functions.jsonl", module.CAPS["functions"]):
            function = _function(anchors, sections, item)
            if function is None or function["va"] <= previous or function["size"] > MAX_ADDRESS - function["va"]:
                raise InconsistentAnchor()
            previous = function["va"]
            signature, cut = _signature(item.get("signature"))
            assembly_total = _int(item.get("assembly_total"))
            if assembly_total > MAX_FUNCTION_INSTRUCTIONS:
                raise TooManyRows()
            instruction_visits += assembly_total
            if instruction_visits > MAX_INSTRUCTION_VISITS:
                raise TooManyRows()
            index = writers["functions"].count
            value = {"kind": "function_export", "index": index, "name": function["name"],
                     "entry": function["va"], "size": function["size"], "signature": signature,
                     "signature_truncated": cut, "library_hint": None}
            record = _export_item({"offset": function["offset"], "length": function["length"]}, value)
            record["raw_name"] = function["raw_name"]
            record["assembly_total"] = assembly_total
            writers["functions"].add(record)
            functions[function["address"]] = function
        last_string = None
        for name in ("calls", "references"):
            previous_key = None
            for item in _raw_rows(Path(raw_folder) / (name + ".jsonl"), module.CAPS[name]):
                function = functions.get(item.get("from"))
                if function is None:
                    raise InconsistentAnchor()
                mapped = _instruction(anchors, function, item)
                to = _target(anchors, item) if mapped else None
                if mapped is None or to is None or to > MAX_ADDRESS:
                    raise InconsistentAnchor()
                at, offset, length = mapped
                value = {"kind": "call_export" if name == "calls" else "reference_export", "index": writers[name].count,
                         "from": function["va"], "from_size": function["size"], "at": at, "to": to,
                         "to_name": printable_name(item.get("to_name", ""))}
                if name == "references":
                    value["type"] = ref_type(item)
                    if value["type"] is None:
                        continue
                key = (function["va"], at, to, value.get("type", ""))
                if previous_key is not None and key <= previous_key:
                    raise InvalidQueryOutput()
                previous_key = key
                writers[name].add(_export_item({"offset": offset, "length": length}, value))
                if name == "references":
                    decoded = decode_string(data, sections, to)
                    if decoded is not None:
                        start, size, encoding, text, truncated = decoded
                        string = {"kind": "string_export", "index": writers["strings"].count,
                                  "from": function["va"], "from_size": function["size"], "at": at,
                                  "instruction_length": length, "address": to, "encoding": encoding,
                                  "text": text, "truncated": truncated}
                        # A repeated reference type does not repeat the same string relationship.
                        string_key = (function["va"], at, to, encoding)
                        if string_key != last_string:
                            writers["strings"].add(_export_item({"offset": start, "length": size}, string))
                            last_string = string_key
        counts = {name: writer.count for name, writer in writers.items()}
    metadata = {"format": 1, "input_sha256": hashlib.sha256(data).hexdigest(), "counts": counts, "complete": True}
    (Path(tables) / "meta.json").write_bytes(module.canonical(metadata))
    return metadata


def _table_rows(folder, name, count, *, flush=None):
    if flush is not None:
        flush.body.flush()
        flush.index.flush()
    reader = cache_module().TableReader(folder, name, count)
    try:
        yield from reader.rows()
    finally:
        reader.close()


def prepare(data, sink):
    format_ = kind(data)
    shutil.rmtree(WORK, ignore_errors=True)
    for name in ("home", "raw", "cache/project", "cache/tables"):
        (WORK / name).mkdir(mode=0o700, parents=True, exist_ok=True)
    _headless(prepare_argv(format_, WORK / "raw"), PREPARE_SECONDS)
    build_tables(data, WORK / "raw", WORK / "cache" / "tables")
    # Headless has closed the project before it is packed. No query can write this artifact back.
    return cache_module().pack_project(WORK, sink)


def _page(data, scope, part, entry, total=0, start=0, rows=(), status="ok", count=None):
    rows = list(rows)
    start = min(start, total)
    row_units = count is None
    count = len(rows) if row_units else count
    if status != "ok":
        start = total = count = 0
        rows = []
    if count == 0 and start < total:
        raise InvalidQueryOutput()
    next_start = start + count if start + count < total else None
    value = {"kind": "export_page", "scope": scope, "part": part, "entry": entry, "status": status,
             "start": start, "total": total, "count": count, "next_start": next_start}
    while True:
        result = [_export_item({"offset": 0, "length": min(64, len(data))}, value), *rows]
        envelope = {"protocol": PROTOCOL, "status": "ok", "snapshot_sha256": "0" * 64, "observations": result}
        if len(result) <= 129 and len(encode(envelope)) + HOST_ID_BYTES * len(result) <= MAX_REPLY_BYTES:
            return result
        if not row_units or not rows:
            raise ReplyTooLarge()
        rows.pop()
        if not rows and start < total:
            raise ReplyTooLarge()
        value.update(count=len(rows), next_start=start + len(rows) if start + len(rows) < total else None)


def pseudocode_page(data, function, text, args):
    normalized = printable_text(text)
    # Python len/slicing counts Unicode scalar values after control/surrogate normalization.
    if len(normalized) > MAX_PSEUDOCODE:
        raise PseudocodeTooLarge()
    total, start = len(normalized), min(args.get("text_start", 0), len(normalized))
    whole = normalized[start:start + args["max_chars"]]
    value = {"kind": "pseudocode_page", "entry": function["entry"], "size": function["size"],
             "text_sha256": hashlib.sha256(normalized.encode("utf-8")).hexdigest(), "start": start,
             "total": total, "text": whole, "next_start": None, "status": "ok"}
    low, high = 0, len(whole)
    while low < high:
        middle = (low + high + 1) // 2
        value.update(text=whole[:middle], next_start=start + middle if start + middle < total else None)
        if _size(value) + HOST_ID_BYTES <= MAX_OBSERVATION_BYTES:
            low = middle
        else:
            high = middle - 1
    value.update(text=whole[:low], next_start=start + low if start + low < total else None)
    if not low and start < total:
        raise ReplyTooLarge()
    return _export_item(function["location"], value)


def export_rows(operation, args, data, *, query_of=None, root=None):
    root = root or restore_project(data)
    metadata = load_metadata(root, data)
    tables = Path(root) / "tables"
    part = "pseudocode" if operation == "ghidra.pseudocode" else args["part"]
    if operation == "ghidra.export_program":
        reader = cache_module().TableReader(tables, part, metadata["counts"][part])
        try:
            start = min(args["start"], reader.count)
            rows = [public_record(reader.row(i), i) for i in range(start, min(start + args["limit"], reader.count))]
            return _page(data, "program", part, None, reader.count, start, rows)
        finally:
            reader.close()
    matches, selected = 0, None
    for record in _table_rows(tables, "functions", metadata["counts"]["functions"]):
        value = record["value"]
        if (args["select"] == "entry" and value["entry"] == args["entry"]
                or args["select"] == "name" and record.get("raw_name") == args["name"]):
            matches += 1
            if selected is None:
                selected = record
    if selected is None:
        return _page(data, "function", part, None, status="not_found")
    function = dict(selected["value"], location=selected["location"])
    entry = function["entry"]
    if part == "info":
        totals = {"assembly": selected["assembly_total"], "callees": 0, "callers": 0, "references": 0, "strings": 0}
        for table in ("calls", "references", "strings"):
            for record in _table_rows(tables, table, metadata["counts"][table]):
                value = record["value"]
                if value["from"] == entry:
                    totals["callees" if table == "calls" else table] += 1
                if table == "calls" and value["to"] == entry:
                    totals["callers"] += 1
        value = {"kind": "function_info", "name": function["name"], "entry": entry, "size": function["size"],
                 "matches": matches, "signature": function["signature"], "signature_truncated": function["signature_truncated"],
                 "library_hint": None, "totals": totals, "pseudocode_status": "not_requested"}
        return _page(data, "function", part, entry, 1, 0, [_export_item(selected["location"], value)])
    if part in ("pseudocode", "assembly"):
        _, sections = FILE_MAPS[kind(data)](data)
        offset = offset_of(sections, entry)
        script = ["export", "entry", str(offset if offset is not None else -1), "x", part,
                  str(args.get("start", 0)), str(args.get("limit", 32))]
        query = ((query_of(kind(data), args, script)) if query_of else run_cached(kind(data), args, script, root))
        _, sections, anchors = _prelude(data, query, "export")
        found = _function(anchors, sections, query.get("function"))
        if found is None or found["va"] != entry or found["size"] != function["size"]:
            raise InconsistentAnchor()
        if part == "pseudocode":
            text = query.get("pseudocode")
            if text is None:
                return _page(data, "function", part, entry, status="decompile_failed")
            observation = pseudocode_page(data, function, text, args)
            value = observation["value"]
            return _page(data, "function", part, entry, value["total"], value["start"], [observation], count=len(value["text"]))
        listing = query.get("instructions")
        if not isinstance(listing, dict) or listing.get("overflow") is not False:
            raise TooManyRows()
        total = _int(listing.get("total"))
        start = min(args["start"], total)
        if total != selected["assembly_total"] or listing.get("start") != start:
            raise InvalidQueryOutput()
        rows, after = [], -1
        for index, row in enumerate(listing.get("rows", []), start):
            mapped = _instruction(anchors, found, row)
            if mapped is None or row.get("index") != index or index >= total or len(rows) >= args["limit"]:
                raise InconsistentAnchor()
            at, offset, length = mapped
            if at < after:
                raise InvalidQueryOutput()
            after = at + length
            value = {"kind": "instruction_export", "index": index, "from": entry, "from_size": function["size"],
                     "at": at, "length": length, "text": printable_name(row.get("text"))[:64] or "?"}
            rows.append(_export_item({"offset": offset, "length": length}, value))
        return _page(data, "function", part, entry, total, start, rows)
    table = "calls" if part in ("callees", "callers") else part
    total, rows = 0, []
    for record in _table_rows(tables, table, metadata["counts"][table]):
        value = record["value"]
        if value["to" if part == "callers" else "from"] == entry:
            if args["start"] <= total < args["start"] + args["limit"]:
                rows.append(public_record(record, total))
            total += 1
    return _page(data, "function", part, entry, total, args["start"], rows)


def public_record(record, index):
    if not isinstance(record, dict) or not isinstance(record.get("location"), dict) or not isinstance(record.get("value"), dict):
        raise InvalidCachedProject()
    value = dict(record["value"], index=index)
    return _export_item(record["location"], value)


# ---- Reply --------------------------------------------------------------------------------------

def error_name(exc):
    name = type(exc).__name__
    return name if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", name) else "WorkerError"


def encode(message):
    return (json.dumps(message, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def reply(argv, data, query_of=None, digest=None):
    """One reply; data None means the snapshot could not be read, digest defaults to the SHA-256 of data."""
    digest = digest or hashlib.sha256(data or b"").hexdigest()
    try:
        if data is None:
            raise SnapshotUnreadable()
        operation, args = parse_request(argv)
        if len(data) > MAX_INPUT_BYTES:
            raise InputTooLarge()
        message = {"protocol": PROTOCOL, "status": "ok", "snapshot_sha256": digest,
                   "observations": run(operation, args, data, query_of)}
        if len(encode(message)) > MAX_REPLY_BYTES:
            raise ReplyTooLarge()
        return message
    except Exception as exc:  # every failure is one short, inert error reply
        return {"protocol": PROTOCOL, "status": "error", "snapshot_sha256": digest, "error": error_name(exc)}


def read_snapshot(path):
    """At most MAX_INPUT_BYTES + 1 bytes, and the SHA-256 of the whole file: the digest the host compares."""
    digest, kept = hashlib.sha256(), bytearray()
    with open(path, "rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
            kept += chunk[:MAX_INPUT_BYTES + 1 - len(kept)]
    return bytes(kept), digest.hexdigest()


def main(argv=None, snapshot=SNAPSHOT):
    try:
        data, digest = read_snapshot(snapshot)
    except OSError:
        data, digest = None, None
    arguments = sys.argv[1:] if argv is None else argv
    if arguments and arguments[0] == "ghidra.prepare":
        try:
            operation, checked = parse_request(arguments)
            if data is None:
                raise SnapshotUnreadable()
            if len(data) > MAX_INPUT_BYTES:
                raise InputTooLarge()
            prepare(data, sys.stdout.buffer)
            sys.stdout.flush()
            return 0
        except Exception as exc:
            sys.stderr.write(error_name(exc) + "\n")
            return 1
    sys.stdout.buffer.write(encode(reply(arguments, data, digest=digest)))
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
