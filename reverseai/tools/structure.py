"""Bounded structural parsing of ELF, PE and Mach-O (tool "structure").

Handlers only read the frozen bytes they are given. Every offset and count
from the input is checked against the input size before it is used, loops
are bounded by input extents and fixed scan limits, and no size field is an allocation request.
Malformed input raises StructureError, a ValueError with a short message.
"""

from __future__ import annotations

import struct
from bisect import bisect_left, bisect_right

from reverseai.contract import (
    MAX_OBSERVATION_BYTES, ArgSpec, ContractError, Location, Observation, OperationSpec, ToolRef, ToolSpec, canonical_json,
)

REF = ToolRef("structure", "0.1.0")
MAX_SECTIONS = 256
MAX_NAME_BYTES = 64
UNKNOWN_PREFIX = 16
MAX_IMPORTS = 256
MAX_IMPORT_NAME = 128
MAX_TABLE_ENTRIES = 65536
MAX_ELF_MAPPING_WORK = 65536

ELF_MAGIC = b"\x7fELF"
ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06")
MACHO_MAGICS = (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe")
FAT_MAGICS = {b"\xca\xfe\xba\xbe": (">", 20), b"\xca\xfe\xba\xbf": (">", 32)}
MACHO_MACHINES = {7: "x86", 0x1000007: "x86_64", 12: "arm", 0x100000C: "aarch64",
                  18: "powerpc", 0x1000012: "powerpc64"}

ELF_TYPES = {0: "none", 1: "relocatable", 2: "executable", 3: "shared", 4: "core"}
ELF_MACHINES = {3: "x86", 8: "mips", 20: "powerpc", 21: "powerpc64", 40: "arm", 62: "x86_64", 183: "aarch64", 243: "riscv"}
PE_MACHINES = {0x14C: "x86", 0x1C4: "arm", 0x8664: "x86_64", 0xAA64: "aarch64"}
PE_OPTIONAL = {0x10B: "pe32", 0x20B: "pe32+"}
SHF_WRITE, SHF_EXECINSTR = 0x1, 0x4
SHN_XINDEX = 0xFFFF
SCN_MEM_EXECUTE, SCN_MEM_WRITE = 0x20000000, 0x80000000


class StructureError(ContractError):
    """The input claims a format whose structure is truncated or inconsistent."""


class MachoSegmentWidthMismatch(StructureError):
    """A segment list cannot be complete across incompatible command widths."""


def _need(data, offset, length, what):
    if offset < 0 or length < 0 or offset + length > len(data):
        raise StructureError(f"{what} lies outside the input")


def _name(raw: bytes) -> str:
    """Printable ASCII for an untrusted name; other bytes and the backslash itself become \\xNN escapes."""
    return "".join(chr(b) if 0x20 <= b < 0x7F and b != 0x5C else "\\x{:02x}".format(b) for b in raw[:MAX_NAME_BYTES])


def _pe_offset(data):
    """Offset of the "PE\\0\\0" signature, or None when the input is not a PE image."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    offset = struct.unpack_from("<I", data, 0x3C)[0]
    if offset + 4 > len(data) or data[offset:offset + 4] != b"PE\0\0":
        return None
    return offset


def _format(data):
    if data[:4] == ELF_MAGIC:
        return "elf", 0, 4
    pe = _pe_offset(data)
    if pe is not None:
        return "pe", pe, 4
    if data[:4] in MACHO_MAGICS:
        return "macho", 0, 4
    if data[:4] in FAT_MAGICS and len(data) >= 8:
        order, entry_size = FAT_MAGICS[data[:4]]
        count = struct.unpack_from(order + "I", data, 4)[0]
        if 1 <= count <= 20 and 8 + count * entry_size <= len(data):
            return "macho-universal", 0, 4
    if data[:4] in ZIP_MAGICS:
        return "zip", 0, 4
    return "unknown", 0, min(UNKNOWN_PREFIX, len(data))


def identify(data, args):
    kind, offset, length = _format(data)
    if not length:
        return []  # an empty input has no bytes to cite
    excerpt = data[offset:offset + length]
    value = {"format": kind, "magic": excerpt.hex()}
    if kind == "macho-universal":
        order, entry_size = FAT_MAGICS[data[:4]]
        count = struct.unpack_from(order + "I", data, 4)[0] if len(data) >= 8 else 0
        count = min(count, 8, max(0, (len(data) - 8) // entry_size))
        value["architectures"] = [MACHO_MACHINES.get(struct.unpack_from(order + "I", data, 8 + entry_size * i)[0], "unknown")
                                  for i in range(count)]
    return [Observation(Location(offset, length), value)]


def _macho_layout(data):
    if data[:4] not in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return None
    width = 64 if data[:4] == b"\xcf\xfa\xed\xfe" else 32
    size = 32 if width == 64 else 28
    _need(data, 0, size, "Mach-O header")
    _, machine, _, filetype, ncmds, sizeofcmds, _ = struct.unpack_from("<7I", data)
    return width, size, machine, filetype, ncmds, sizeofcmds


def _macho_commands(data, h):
    _, position, _, _, count, size = h
    _need(data, position, size, "Mach-O load commands")
    end = position + size
    if count > min(size // 8, MAX_TABLE_ENTRIES):
        raise StructureError("Mach-O command count exceeds its table")
    for _ in range(count):
        if position + 8 > end:
            raise StructureError("Truncated Mach-O load command")
        command, length = struct.unpack_from("<II", data, position)
        if length < 8 or length % (8 if h[0] == 64 else 4) or position + length > end:
            raise StructureError("Invalid Mach-O load command size")
        yield command, position, length
        position += length


def _macho_section_rows(data, h):
    index = 0
    for command, position, length in _macho_commands(data, h):
        if command not in (1, 0x19):
            continue
        width = 64 if command == 0x19 else 32
        if width != h[0]:
            raise StructureError("Mach-O segment width disagrees with its header")
        segment_size, section_size = (72, 80) if width == 64 else (56, 68)
        if length < segment_size:
            raise StructureError("Truncated Mach-O segment")
        prot_offset = 60 if width == 64 else 44
        initprot, count = struct.unpack_from("<II", data, position + prot_offset)
        fileoff, filesize = struct.unpack_from("<QQ" if width == 64 else "<II", data, position + (40 if width == 64 else 32))
        if count > (length - segment_size) // section_size:
            raise StructureError("Mach-O sections exceed their load command")
        for ordinal in range(count):
            start = position + segment_size + section_size * ordinal
            sectname, segname = struct.unpack_from("<16s16s", data, start)
            address, size, offset = struct.unpack_from("<QQI" if width == 64 else "<III", data, start + 32)
            flags = struct.unpack_from("<I", data, start + (64 if width == 64 else 56))[0]
            row = {"index": index, "name": _name(segname.split(b"\0", 1)[0]) + "," + _name(sectname.split(b"\0", 1)[0]),
                   "addr": address, "offset": offset, "size": size,
                   "writable": bool(initprot & 2), "executable": bool(initprot & 4 or flags & 0x80000400)}
            backed = (flags & 0xFF not in (1, 0xC, 0x12) and fileoff <= offset
                      and offset + size <= min(len(data), fileoff + filesize))
            yield Location(start, section_size), row, backed
            index += 1


def macho_sections(data):
    """File-backed thin LE Mach-O sections for host address mapping; original indices are retained."""
    h = _macho_layout(data)
    if h is None:
        return []
    rows = []
    for _, row, backed in _macho_section_rows(data, h):
        if row["index"] >= MAX_SECTIONS:
            break
        if backed:
            rows.append(row)
    return rows


def macho_entry(data):
    """Entry VA from LC_MAIN or a supported LC_UNIXTHREAD state; malformed/ambiguous inputs yield None."""
    try:
        h = _macho_layout(data)
        if h is None:
            return None
        commands = list(_macho_commands(data, h))
        mains, thread_entries, segments = [], [], []
        for command, position, size in commands:
            if command == 0x80000028:
                if size < 24:
                    return None
                mains.append(struct.unpack_from("<Q", data, position + 8)[0])
            elif command in (1, 0x19):
                width = 64 if command == 0x19 else 32
                if width != h[0] or size < (72 if width == 64 else 56):
                    return None
                section_count = struct.unpack_from("<I", data, position + (64 if width == 64 else 48))[0]
                if section_count > (size - (72 if width == 64 else 56)) // (80 if width == 64 else 68):
                    return None
                segments.append(struct.unpack_from("<QQQQ" if width == 64 else "<IIII", data, position + 24))
            elif command == 5:
                start, end = position + 8, position + size
                while start < end:
                    if start + 8 > end:
                        return None
                    flavor, count = struct.unpack_from("<II", data, start)
                    state = start + 8
                    if count > (end - state) // 4:
                        return None
                    expected = (4, 42, 128) if h[2] == 0x1000007 else (6, 68, 256) if h[2] == 0x100000C else None
                    if expected and flavor == expected[0]:
                        if count != expected[1]:
                            return None
                        thread_entries.append(struct.unpack_from("<Q", data, state + expected[2])[0])
                    start = state + count * 4
        if mains:
            if len(mains) != 1:
                return None
            entries = []
            for address, virtual_size, offset, size in segments:
                delta = mains[0] - offset
                if (offset + size <= len(data) and 0 <= delta < min(size, virtual_size)
                        and address + virtual_size <= 2**h[0]):
                    entries.append(address + delta)
            return entries[0] if len(entries) == 1 else None
        return thread_entries[0] if len(thread_entries) == 1 else None
    except StructureError:
        return None


def _elf_layout(data):
    _need(data, 0, 16, "ELF identification")
    width = {1: 32, 2: 64}.get(data[4])
    order = {1: "<", 2: ">"}.get(data[5])
    if width is None or order is None:
        raise StructureError("Unsupported ELF class or byte order")
    size = 52 if width == 32 else 64
    _need(data, 0, size, "ELF header")
    word = "I" if width == 32 else "Q"
    fields = struct.unpack_from(order + "HHI" + word * 3 + "IHHHHHH", data, 16)
    names = ("type", "machine", "version", "entry", "phoff", "shoff", "flags", "ehsize", "phentsize", "phnum",
             "shentsize", "shnum", "shstrndx")
    return width, order, size, dict(zip(names, fields))


def _pe_layout(data, pe):
    coff = pe + 4
    _need(data, coff, 20, "COFF header")
    machine, sections, timestamp, _, _, optional_size, characteristics = struct.unpack_from("<HHIIIHH", data, coff)
    if optional_size < 20:
        raise StructureError("PE optional header is smaller than the fields read")
    optional = coff + 20
    _need(data, optional, 20, "Optional header")
    magic = struct.unpack_from("<H", data, optional)[0]
    entry = struct.unpack_from("<I", data, optional + 16)[0]
    return {"machine": machine, "sections": sections, "timestamp": timestamp, "optional_size": optional_size,
            "characteristics": characteristics, "magic": magic, "entry": entry, "optional": optional}


def headers(data, args):
    kind, offset, _ = _format(data)
    if kind == "elf":
        width, order, size, h = _elf_layout(data)
        return [Observation(Location(0, size), {
            "format": "elf", "class": width, "endianness": "little" if order == "<" else "big",
            "type": h["type"], "type_name": ELF_TYPES.get(h["type"], "unknown"),
            "machine": h["machine"], "machine_name": ELF_MACHINES.get(h["machine"], "unknown"),
            "entry": h["entry"], "shnum": h["shnum"], "shoff": h["shoff"],
        })]
    if kind == "pe":
        h = _pe_layout(data, offset)
        # Signature, COFF header and the optional header up to AddressOfEntryPoint.
        return [Observation(Location(offset, h["optional"] + 20 - offset), {
            "format": "pe", "machine": h["machine"], "machine_name": PE_MACHINES.get(h["machine"], "unknown"),
            "number_of_sections": h["sections"], "timestamp": h["timestamp"], "characteristics": h["characteristics"],
            "optional_magic": PE_OPTIONAL.get(h["magic"], "unknown"), "entry_rva": h["entry"],
        })]
    if kind == "macho":
        h = _macho_layout(data)
        if h is not None:
            count = sum(1 for _ in _macho_section_rows(data, h))
            return [Observation(Location(0, h[1]), {
                "structure": "macho", "format": "macho", "machine_name": MACHO_MACHINES.get(h[2], "unknown"),
                "filetype": h[3], "ncmds": h[4], "number_of_sections": count,
            })]
    return []


def _elf_sections(data, limit):
    width, order, _, h = _elf_layout(data)
    entry = 40 if width == 32 else 64
    if h["shnum"] == 0 and h["shoff"] == 0:
        return []  # no section header table
    if h["shentsize"] != entry:
        raise StructureError("Unexpected ELF section header size")
    layout = order + ("IIIIIIIIII" if width == 32 else "IIQQQQIIQQ")
    shnum, shstrndx = h["shnum"], h["shstrndx"]
    if shnum == 0 or shstrndx == SHN_XINDEX:
        # Extended numbering: section 0 holds the real count (sh_size) and name table index (sh_link).
        _need(data, h["shoff"], entry, "ELF section header 0")
        first = struct.unpack_from(layout, data, h["shoff"])
        shnum = shnum or first[5]
        shstrndx = first[6] if shstrndx == SHN_XINDEX else shstrndx
    if shnum == 0:
        return []
    count = min(shnum, limit)
    _need(data, h["shoff"], entry * count, "ELF section header table")
    strtab = None
    if 0 < shstrndx < shnum:  # SHN_UNDEF (0) means no name table
        index_offset = h["shoff"] + entry * shstrndx
        _need(data, index_offset, entry, "ELF section name table header")
        values = struct.unpack_from(layout, data, index_offset)
        _need(data, values[4], values[5], "ELF section name table")
        strtab = (values[4], values[5])
    found = []
    for index in range(count):
        offset = h["shoff"] + entry * index
        name, kind, flags, _, start, size = struct.unpack_from(layout, data, offset)[:6]
        label = ""
        if strtab is not None and name < strtab[1]:
            begin = strtab[0] + name
            end = min(strtab[0] + strtab[1], begin + MAX_NAME_BYTES)
            terminator = data.find(b"\0", begin, end)
            label = _name(data[begin:end if terminator < 0 else terminator])
        found.append(Observation(Location(offset, entry), {
            "index": index, "name": label, "type": kind, "flags": flags, "offset": start, "size": size,
            "executable": bool(flags & SHF_EXECINSTR), "writable": bool(flags & SHF_WRITE),
        }))
    return found


def _pe_sections(data, pe, limit):
    h = _pe_layout(data, pe)
    table = h["optional"] + h["optional_size"]
    count = min(h["sections"], limit)
    _need(data, table, 40 * count, "PE section table")
    found = []
    for index in range(count):
        offset = table + 40 * index
        raw_name, virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from("<8sIIII", data, offset)
        characteristics = struct.unpack_from("<I", data, offset + 36)[0]
        found.append(Observation(Location(offset, 40), {
            "index": index, "name": _name(raw_name.split(b"\0", 1)[0]), "virtual_address": virtual_address,
            "virtual_size": virtual_size, "offset": raw_offset, "size": raw_size, "characteristics": characteristics,
            "executable": bool(characteristics & SCN_MEM_EXECUTE), "writable": bool(characteristics & SCN_MEM_WRITE),
        }))
    return found


def sections(data, args):
    limit = args["max_sections"]
    kind, offset, _ = _format(data)
    if kind == "elf":
        return _elf_sections(data, limit)
    if kind == "pe":
        return _pe_sections(data, offset, limit)
    if kind == "macho":
        h = _macho_layout(data)
        if h is not None:
            found = []
            for location, row, _ in _macho_section_rows(data, h):
                value = {key: value for key, value in row.items() if key != "addr"}
                found.append(Observation(location, value))
                if len(found) >= limit:
                    break
            return found
    return []


def _import_name(data, start, end):
    """A bounded, nonempty C string; its citation covers exactly the rendered prefix's source bytes."""
    end = min(end, len(data))
    if not 0 <= start < end:
        return None
    stop = data.find(b"\0", start, min(end, start + MAX_IMPORT_NAME + 1))
    if stop < 0:
        if end - start <= MAX_IMPORT_NAME:
            return None
        stop = start + MAX_IMPORT_NAME
    rendered, consumed = "", 0
    for byte in data[start:stop]:
        part = chr(byte) if 0x20 <= byte < 0x7F and byte != 0x5C else "\\x{:02x}".format(byte)
        if len(rendered) + len(part) > MAX_IMPORT_NAME:
            break
        rendered += part
        consumed += 1
    return (rendered, Location(start, consumed)) if consumed else None


def _elf_import_records(data):
    width, order, _, h = _elf_layout(data)
    entry = 40 if width == 32 else 64
    if h["shoff"] == 0:
        yield from _elf_dynamic_import_records(data, width, order, h)
        return
    if h["shentsize"] != entry:
        return
    layout = order + ("IIIIIIIIII" if width == 32 else "IIQQQQIIQQ")
    _need(data, h["shoff"], entry, "ELF section header 0")
    count = h["shnum"] or struct.unpack_from(layout, data, h["shoff"])[5]
    count = min(count, (len(data) - h["shoff"]) // entry, MAX_TABLE_ENTRIES)
    remaining = MAX_TABLE_ENTRIES
    for index in range(count):
        values = struct.unpack_from(layout, data, h["shoff"] + entry * index)
        kind, offset, size, link, entsize = values[1], values[4], values[5], values[6], values[9]
        if kind not in (6, 11) or link >= count:
            continue
        strings = struct.unpack_from(layout, data, h["shoff"] + entry * link)
        if strings[1] != 3:
            continue
        strings_start, strings_size = strings[4], strings[5]
        if not 0 <= offset < len(data) or not 0 <= strings_start < len(data):
            continue
        expected = (8 if width == 32 else 16) if kind == 6 else (16 if width == 32 else 24)
        if entsize != expected:
            continue
        entries = min(size // entsize, (len(data) - offset) // entsize, remaining)
        remaining -= entries
        for i in range(entries):
            position = offset + i * entsize
            if kind == 6:
                tag, name = struct.unpack_from(order + ("II" if width == 32 else "QQ"), data, position)
                if tag == 0:
                    break
                if tag != 1:
                    continue
            else:
                name = struct.unpack_from(order + "I", data, position)[0]
                section = struct.unpack_from(order + "H", data, position + (14 if width == 32 else 6))[0]
                if section != 0:
                    continue
            if name == 0 or name >= strings_size:
                continue
            value = _import_name(data, strings_start + name, strings_start + strings_size)
            if value:
                yield ("library" if kind == 6 else "symbols"), None, value


def _elf_dynamic_import_records(data, width, order, h):
    """Sectionless executables use PT_DYNAMIC and file-backed PT_LOAD address mappings."""
    entry = 56 if width == 64 else 32
    if h["phentsize"] != entry:
        return
    count = min(h["phnum"], max(0, (len(data) - h["phoff"]) // entry), MAX_TABLE_ENTRIES)
    loads, dynamics = [], {}
    for index in range(count):
        values = struct.unpack_from(order + ("IIQQQQQQ" if width == 64 else "8I"), data, h["phoff"] + index * entry)
        kind = values[0]
        offset, address, size = (values[2], values[3], values[5]) if width == 64 else (values[1], values[2], values[4])
        if offset + size > len(data):
            continue
        if kind == 1:
            loads.append((address, offset, size))
        elif kind == 2:
            dynamics[offset, size] = None

    mapping_left = MAX_ELF_MAPPING_WORK
    def mapped(address, length):
        nonlocal mapping_left
        span = None
        for base, offset, size in loads:
            if mapping_left == 0:
                raise StructureError("ELF import mapping work limit exceeded")
            mapping_left -= 1
            if base <= address and address + length <= base + size and address + length <= 2**width:
                if span is not None:
                    return None
                span = (offset + address - base, offset + size)
        return span

    remaining = MAX_TABLE_ENTRIES
    for offset, size in dynamics:
        dynamic_size = 16 if width == 64 else 8
        tags, needed = {}, []
        count = min(size // dynamic_size, remaining)
        remaining -= count
        for index in range(count):
            tag, value = struct.unpack_from(order + ("QQ" if width == 64 else "II"), data, offset + index * dynamic_size)
            if tag == 0:
                break
            if tag == 1:
                needed.append(value)
            elif tag in (4, 5, 6, 10, 11, 0x6FFFFEF5):
                if tag in tags:
                    return  # Conflicting address/size declarations have no unique interpretation.
                tags[tag] = value
        strings = mapped(tags.get(5, 0), tags.get(10, 0)) if tags.get(10) else None
        if strings is None:
            continue
        for name in needed:
            value = _import_name(data, strings[0] + name, strings[0] + tags[10]) if name < tags[10] else None
            if value:
                yield "library", None, value
        symbol_size = 24 if width == 64 else 16
        if tags.get(11) != symbol_size or not tags.get(6):
            continue
        symbol_count = 0
        hashed = mapped(tags[4], 8) if tags.get(4) else None
        if hashed:
            buckets, symbol_count = struct.unpack_from(order + "II", data, hashed[0])
            if not mapped(tags[4], 4 * (2 + buckets + symbol_count)):
                continue
        elif tags.get(0x6FFFFEF5):
            hashed = mapped(tags[0x6FFFFEF5], 16)
            if hashed is None:
                continue
            buckets, first, bloom, _ = struct.unpack_from(order + "4I", data, hashed[0])
            bucket_offset = 16 + bloom * (width // 8)
            table = mapped(tags[0x6FFFFEF5], bucket_offset + buckets * 4)
            if table is None or buckets > MAX_TABLE_ENTRIES or first > MAX_TABLE_ENTRIES:
                continue
            if buckets > remaining:
                return
            remaining -= buckets
            starts = [struct.unpack_from(order + "I", data, table[0] + bucket_offset + 4 * i)[0] for i in range(buckets)]
            last = max(starts, default=0)
            symbol_count = first
            if last:
                if not first <= last < MAX_TABLE_ENTRIES:
                    continue
                chains = table[0] + bucket_offset + buckets * 4
                while last < MAX_TABLE_ENTRIES and chains + (last - first + 1) * 4 <= table[1]:
                    if remaining == 0:
                        return
                    remaining -= 1
                    value = struct.unpack_from(order + "I", data, chains + (last - first) * 4)[0]
                    last += 1
                    if value & 1:
                        symbol_count = last
                        break
        symbols = mapped(tags[6], symbol_count * symbol_size) if symbol_count else None
        if symbols is None:
            continue
        count = min(symbol_count, remaining)
        remaining -= count
        for index in range(count):
            position = symbols[0] + index * symbol_size
            name = struct.unpack_from(order + "I", data, position)[0]
            section = struct.unpack_from(order + "H", data, position + (6 if width == 64 else 14))[0]
            if section == 0 and 0 < name < tags[10]:
                value = _import_name(data, strings[0] + name, strings[0] + tags[10])
                if value:
                    yield "symbols", None, value


def _pe_import_records(data, pe):
    h = _pe_layout(data, pe)
    if h["sections"] > MAX_SECTIONS:
        return
    optional, plus = h["optional"], h["magic"] == 0x20B
    if h["magic"] not in (0x10B, 0x20B):
        return
    directories = 112 if plus else 96
    if h["optional_size"] < directories + 16:
        return
    _need(data, optional, h["optional_size"], "PE optional header")
    if struct.unpack_from("<I", data, optional + directories - 4)[0] < 2:
        return
    rva, size = struct.unpack_from("<II", data, optional + directories + 8)
    if not rva or not size:
        return
    rows = [o.value for o in _pe_sections(data, pe, MAX_SECTIONS)]
    header_size = struct.unpack_from("<I", data, optional + 60)[0]

    def mapped(address, length=1):
        spans = []
        if 0 <= address and address + length <= min(header_size, len(data)):
            spans.append((address, min(header_size, len(data))))
        for row in rows:
            extent = min(row["size"], row["virtual_size"]) if row["virtual_size"] else row["size"]
            delta = address - row["virtual_address"]
            if 0 <= delta and delta + length <= extent:
                start = row["offset"] + delta
                end = min(len(data), row["offset"] + extent)
                if start + length <= end:
                    spans.append((start, end))
        return spans[0] if len(spans) == 1 and address + length <= 2**32 else None

    for index in range(min(size // 20, MAX_TABLE_ENTRIES)):
        descriptor = mapped(rva + index * 20, 20)
        if descriptor is None:
            break
        original, stamp, chain, name_rva, first = struct.unpack_from("<5I", data, descriptor[0])
        if not any((original, stamp, chain, name_rva, first)):
            break
        name_span = mapped(name_rva) if name_rva else None
        library = _import_name(data, *name_span) if name_span else None
        if library is None:
            break
        yield "library", None, library
        word = 8 if plus else 4
        thunk_rva = original or first
        for ordinal in range(MAX_TABLE_ENTRIES):
            thunk = mapped(thunk_rva + word * ordinal, word) if thunk_rva else None
            if thunk is None:
                break
            value = struct.unpack_from("<Q" if plus else "<I", data, thunk[0])[0]
            if value == 0:
                break
            if value & (1 << (word * 8 - 1)):
                if value & ~((1 << (word * 8 - 1)) | 0xFFFF):
                    break
                name = ("#" + str(value & 0xFFFF), Location(thunk[0], word))
            else:
                span = mapped(value, 3)
                name = _import_name(data, span[0] + 2, span[1]) if span else None
            if name is None:
                break
            yield "symbols", library[0], name


def _macho_import_records(data):
    h = _macho_layout(data)
    if h is None:
        return
    symbols = []
    for command, position, size in _macho_commands(data, h):
        if command in (0xC, 0x80000018, 0x8000001f, 0x20, 0x80000023):
            if size < 24:
                break
            start = struct.unpack_from("<I", data, position + 8)[0]
            value = _import_name(data, position + start, position + size) if 24 <= start < size else None
            if value:
                yield "library", None, value
        elif command == 2:
            if size < 24:
                break
            symbols.append(struct.unpack_from("<4I", data, position + 8))
    remaining = MAX_TABLE_ENTRIES
    for offset, count, strings, strings_size in symbols:
        entry = 16 if h[0] == 64 else 12
        if offset >= len(data) or strings >= len(data):
            continue
        count = min(count, (len(data) - offset) // entry, remaining)
        remaining -= count
        for index in range(count):
            position = offset + entry * index
            name, kind, section, _, value = struct.unpack_from("<IBBHQ" if h[0] == 64 else "<IBBHI", data, position)
            if kind & 0xE0 or not kind & 1 or kind & 0x0E or section or value or not name or name >= strings_size:
                continue
            imported = _import_name(data, strings + name, strings + strings_size)
            if imported:
                yield "symbols", None, imported


def imports(data, args):
    """Import declarations, cut at malformed tables, bounded by observation count and JSON size."""
    kind, offset, _ = _format(data)
    records = (_elf_import_records(data) if kind == "elf" else _pe_import_records(data, offset) if kind == "pe"
               else _macho_import_records(data) if kind == "macho" else ())
    found, names, library, anchor = [], [], None, None

    def flush():
        if names:
            found.append(Observation(anchor, {"kind": "symbols", "library": library, "names": list(names)}))
            names.clear()

    try:
        for kind, current_library, (name, location) in records:
            if kind == "library":
                flush()
                if len(found) >= args["max_imports"]:
                    break
                found.append(Observation(location, {"kind": "library", "name": name}))
            else:
                value = {"kind": "symbols", "library": current_library, "names": names + [name]}
                if names and (library != current_library or len(names) == 32
                              or len(canonical_json(value).encode()) > MAX_OBSERVATION_BYTES):
                    flush()
                if len(found) >= args["max_imports"]:
                    break
                if not names:
                    library, anchor = current_library, location
                names.append(name)
            if len(found) >= args["max_imports"]:
                break
    except StructureError:
        pass  # Retain the valid prefix, including any pending symbol group.
    if len(found) < args["max_imports"]:
        flush()
    return found


class _QueryLimit(StructureError):
    pass


def _charge(budget, count):
    if count > budget[0]:
        raise _QueryLimit("Query tables exceed the walk limit")
    budget[0] -= count


def _query_count(data, offset, count, stride, budget):
    count = min(count, max(0, (len(data) - offset) // stride)) if 0 <= offset <= len(data) else 0
    _charge(budget, count)
    return count


def _query_elf_table(data, budget):
    width, order, _, h = _elf_layout(data)
    stride = 40 if width == 32 else 64
    rows = []
    if h["shoff"] and h["shentsize"] == stride:
        layout = order + ("10I" if width == 32 else "IIQQQQIIQQ")
        if h["shoff"] + stride <= len(data):
            count = h["shnum"] or struct.unpack_from(layout, data, h["shoff"])[5]
            rows = [struct.unpack_from(layout, data, h["shoff"] + index * stride)
                    for index in range(_query_count(data, h["shoff"], count, stride, budget))]
    return width, order, h, rows


def _query_pe(data, pe, budget):
    h = _pe_layout(data, pe)
    width = {0x10B: 32, 0x20B: 64}.get(h["magic"])
    if width is None or h["optional_size"] < 32:
        return h, None, []
    _need(data, h["optional"], h["optional_size"], "PE optional header")
    base = struct.unpack_from("<I" if width == 32 else "<Q", data, h["optional"] + (28 if width == 32 else 24))[0]
    table = h["optional"] + h["optional_size"]
    count = _query_count(data, table, h["sections"], 40, budget)
    return h, base, _pe_sections(data, pe, count) if count else []


def _query_name(data, start, end):
    value = _import_name(data, start, end)
    return value[0] if value else ""


def file_sections(data):
    """File-backed sections in table order, with bounded names and extents wholly inside the input."""
    return _file_sections(data, [MAX_TABLE_ENTRIES])


def _file_sections(data, budget):
    kind, pe, _ = _format(data)
    found = []
    try:
        if kind == "elf":
            width, _, h, rows = _query_elf_table(data, budget)
            index = rows[0][6] if rows and h["shstrndx"] == SHN_XINDEX else h["shstrndx"]
            names = rows[index] if 0 < index < len(rows) else None
            for row in rows:
                name, type_, flags, address, offset, size = row[:6]
                if type_ != 8 and flags & 2 and size and offset + size <= len(data) and address + size <= 2**width:
                    label = _query_name(data, names[4] + name, names[4] + names[5]) if names and name < names[5] else ""
                    found.append(dict(name=label, address=address, offset=offset, size=size, executable=bool(flags & 4)))
        elif kind == "pe":
            _, base, rows = _query_pe(data, pe, budget)
            for item in rows:
                row = item.value
                size = min(row["size"], row["virtual_size"]) if row["virtual_size"] else row["size"]
                address, offset = base + row["virtual_address"], row["offset"]
                if size and offset + size <= len(data) and address + size <= 2**64:
                    found.append(dict(name=row["name"], address=address, offset=offset, size=size,
                                      executable=row["executable"]))
        elif kind == "macho":
            h = _macho_layout(data)
            if h is not None:
                _charge(budget, h[4])
                for _, row, backed in _macho_section_rows(data, h):
                    _charge(budget, 1)
                    if backed and row["size"] and row["addr"] + row["size"] <= 2**h[0]:
                        found.append(dict(name=row["name"], address=row["addr"], offset=row["offset"], size=row["size"],
                                          executable=row["executable"]))
    except _QueryLimit:
        raise
    except StructureError:
        pass
    return found


class _SectionMap:
    """An interval index: overlapping/aliased ranges map to nothing, without a table scan per lookup."""
    def __init__(self, rows, axis):
        self.axis = axis
        self.rows = sorted((r for r in rows if r["size"]), key=lambda r: r[axis])
        self.starts = [r[axis] for r in self.rows]
        self.ends = sorted(r[axis] + r["size"] for r in self.rows)
        self.covering = []
        longest = None
        for row in self.rows:
            if longest is None or row[axis] + row["size"] > longest[axis] + longest["size"]:
                longest = row
            self.covering.append(longest)

    def row(self, at, length=1):
        right = bisect_left(self.starts, at + length)
        if right - bisect_right(self.ends, at) != 1:
            return None
        row = self.covering[right - 1]
        return row if row[self.axis] <= at and at + length <= row[self.axis] + row["size"] else None


def _query_page(records, args, kind):
    page, total = [], 0
    for location, value in records:
        if args.get("query", "") not in value.get("name", ""):
            continue
        if args["start"] <= total < args["start"] + args["limit"]:
            page.append((location, value, total))
        total += 1
    return [Observation(location, {"kind": kind, "index": index, "total": total, **value})
            for location, value, index in page]


def _segment_records(data):
    kind, pe, _ = _format(data)
    budget = [MAX_TABLE_ENTRIES]
    try:
        if kind == "elf":
            width, order, _, h = _elf_layout(data)
            stride = 32 if width == 32 else 56
            if not h["phoff"] or h["phentsize"] != stride:
                return
            count = h["phnum"]
            if count == 0xFFFF:
                _, _, _, rows = _query_elf_table(data, budget)
                count = rows[0][7] if rows else 0
            names = {1: "LOAD", 2: "DYNAMIC", 3: "INTERP", 4: "NOTE", 6: "PHDR", 7: "TLS",
                     0x6474E550: "GNU_EH_FRAME", 0x6474E551: "GNU_STACK", 0x6474E552: "GNU_RELRO"}
            for i in range(_query_count(data, h["phoff"], count, stride, budget)):
                at = h["phoff"] + i * stride
                row = struct.unpack_from(order + ("8I" if width == 32 else "II6Q"), data, at)
                type_, offset, address, filesz, memsz, flags = ((row[0], row[1], row[2], row[4], row[5], row[6])
                    if width == 32 else (row[0], row[2], row[3], row[5], row[6], row[1]))
                yield Location(at, stride), dict(name=names.get(type_, f"0x{type_:x}"), offset=offset, filesz=filesz,
                    address=address, memsz=memsz, readable=bool(flags & 4), writable=bool(flags & 2), executable=bool(flags & 1))
        elif kind == "pe":
            _, base, rows = _query_pe(data, pe, budget)
            for item in rows:
                row = item.value
                address = base + row["virtual_address"]
                if address >= 2**64:
                    break
                yield item.location, dict(name=row["name"], offset=row["offset"], filesz=row["size"], address=address,
                    memsz=row["virtual_size"], readable=bool(row["characteristics"] & 0x40000000),
                    writable=row["writable"], executable=row["executable"])
        elif kind == "macho":
            h = _macho_layout(data)
            if h is None:
                return
            _charge(budget, h[4])
            for command, at, size in _macho_commands(data, h):
                if command not in (1, 0x19):
                    continue
                width = 64 if command == 0x19 else 32
                stride = 72 if width == 64 else 56
                if width != h[0]:
                    raise MachoSegmentWidthMismatch("Mach-O segment width disagrees with its header")
                if size < stride:
                    break
                name = _name(data[at + 8:at + 24].split(b"\0", 1)[0])
                address, memsz, offset, filesz = struct.unpack_from("<4Q" if width == 64 else "<4I", data, at + 24)
                flags = struct.unpack_from("<I", data, at + (60 if width == 64 else 44))[0]
                yield Location(at, stride), dict(name=name, offset=offset, filesz=filesz, address=address, memsz=memsz,
                    readable=bool(flags & 1), writable=bool(flags & 2), executable=bool(flags & 4))
    except (_QueryLimit, MachoSegmentWidthMismatch):
        raise
    except StructureError:
        return


def segments(data, args):
    return _query_page(_segment_records(data), args, "segment")


def _entry_field(data, budget):
    kind, pe, _ = _format(data)
    if kind == "elf":
        width, _, _, h = _elf_layout(data)
        return (h["entry"], Location(24, width // 8)) if h["entry"] else None
    if kind == "pe":
        h, base, _ = _query_pe(data, pe, budget)
        if base is not None and h["entry"] and base + h["entry"] < 2**64:
            return base + h["entry"], Location(h["optional"] + 16, 4)
    if kind == "macho":
        h = _macho_layout(data)
        if h is None:
            return None
        _charge(budget, h[4])
        threads, mains, segments = [], [], []
        for command, at, size in _macho_commands(data, h):
            if command == 0x80000028:
                if size < 24:
                    return None
                mains.append((struct.unpack_from("<Q", data, at + 8)[0], Location(at + 8, 8)))
            elif command in (1, 0x19):
                width = 64 if command == 0x19 else 32
                prefix, stride = (72, 80) if width == 64 else (56, 68)
                if width != h[0] or size < prefix:
                    return None
                count = struct.unpack_from("<I", data, at + (64 if width == 64 else 48))[0]
                if count > (size - prefix) // stride:
                    return None
                segments.append(struct.unpack_from("<4Q" if width == 64 else "<4I", data, at + 24))
            elif command == 5:
                cursor, end = at + 8, at + size
                while cursor < end:
                    _charge(budget, 1)
                    if cursor + 8 > end:
                        return None
                    flavor, count = struct.unpack_from("<II", data, cursor)
                    if count > (end - cursor - 8) // 4:
                        return None
                    expected = (4, 42, 128) if h[2] == 0x1000007 else (6, 68, 256) if h[2] == 0x100000C else None
                    if expected and flavor == expected[0]:
                        if count != expected[1]:
                            return None
                        location = Location(cursor + 8 + expected[2], 8)
                        threads.append((struct.unpack_from("<Q", data, location.offset)[0], location))
                    cursor += 8 + count * 4
        if mains:
            if len(mains) != 1:
                return None
            _charge(budget, len(segments))
            entryoff, location = mains[0]
            values = [address + entryoff - offset for address, memsz, offset, filesz in segments
                      if offset + filesz <= len(data) and 0 <= entryoff - offset < min(filesz, memsz)
                      and address + memsz <= 2**h[0]]
            return (values[0], location) if len(values) == 1 else None
        return threads[0] if len(threads) == 1 else None
    return None


def entry(data, args):
    budget = [MAX_TABLE_ENTRIES]
    try:
        declared = _entry_field(data, budget)
    except _QueryLimit:
        raise
    except StructureError:
        return []
    if declared is None:
        return []
    address, location = declared
    row = _SectionMap(_file_sections(data, budget), "address").row(address)
    return [Observation(location, dict(kind="entry", address=address,
                                      offset=row["offset"] + address - row["address"] if row else None))]


def read_bytes(data, args):
    rows, at = file_sections(data), args["at"]
    physical, virtual = _SectionMap(rows, "offset"), _SectionMap(rows, "address")
    end = len(data)
    if args["mode"] == "address":
        row = virtual.row(at)
        if row is None:
            return []
        at, end = row["offset"] + at - row["address"], row["offset"] + row["size"]
    length = min(args["length"], end - at)
    if length <= 0:
        return []
    row = physical.row(at)
    return [Observation(Location(at, length), dict(kind="bytes", offset=at,
        address=row["address"] + at - row["offset"] if row else None, hex=data[at:at + length].hex()))]


def _symbol_records(data):
    kind, pe, _ = _format(data)
    budget = [MAX_TABLE_ENTRIES]
    try:
        if kind == "elf":
            width, order, _, rows = _query_elf_table(data, budget)
            selected = 2 if any(r[1] == 2 for r in rows) else 11
            stride = 16 if width == 32 else 24
            types = {0: "notype", 1: "object", 2: "func", 5: "common", 6: "tls", 10: "ifunc"}
            for row in rows:
                if row[1] != selected or row[9] != stride or row[6] >= len(rows):
                    continue
                strings = rows[row[6]]
                if strings[1] != 3:
                    continue
                count = _query_count(data, row[4], row[5] // stride, stride, budget)
                for index in range(1, count):
                    at = row[4] + stride * index
                    record = struct.unpack_from(order + ("IIIBBH" if width == 32 else "IBBHQQ"), data, at)
                    name, address, info, section = ((record[0], record[1], record[3], record[5]) if width == 32
                                                   else (record[0], record[4], record[1], record[3]))
                    if info & 15 in (3, 4) or name == 0 or name >= strings[5]:
                        continue
                    named = _import_name(data, strings[4] + name, strings[4] + strings[5])
                    if named:
                        label, location = named
                        yield location, dict(name=label, address=address, type=types.get(info & 15, "other"),
                            binding={0: "local", 1: "global", 2: "weak"}.get(info >> 4, "other"), defined=section != 0)
        elif kind == "macho":
            h = _macho_layout(data)
            if h is None:
                return
            _charge(budget, h[4])
            stride = 16 if h[0] == 64 else 12
            for command, at, size in _macho_commands(data, h):
                if command != 2:
                    continue
                if size < 24:
                    break
                offset, count, strings, strings_size = struct.unpack_from("<4I", data, at + 8)
                for index in range(_query_count(data, offset, count, stride, budget)):
                    name, type_, _, flags, address = struct.unpack_from("<IBBHQ" if h[0] == 64 else "<IBBHI",
                                                                      data, offset + stride * index)
                    if type_ & 0xE0 or not 0 < name < strings_size:
                        continue
                    named = _import_name(data, strings + name, strings + strings_size)
                    if named:
                        label, location = named
                        yield location, dict(name=label, address=address, type="symbol",
                            binding="weak" if flags & 0xC0 else "global" if type_ & 1 else "local",
                            defined=type_ & 0xE not in (0, 0xC))
        elif kind == "pe":
            h, base, sections = _query_pe(data, pe, budget)
            directories = 112 if h["magic"] == 0x20B else 96
            if base is None or h["optional_size"] < directories + 8:
                return
            if not struct.unpack_from("<I", data, h["optional"] + directories - 4)[0]:
                return
            rva, size = struct.unpack_from("<II", data, h["optional"] + directories)
            if not rva or size < 40:
                return
            rows = []
            header_size = struct.unpack_from("<I", data, h["optional"] + 60)[0]
            if header_size:
                rows.append(dict(address=0, offset=0, size=min(header_size, len(data))))
            for item in sections:
                row = item.value
                extent = min(row["size"], row["virtual_size"]) if row["virtual_size"] else row["size"]
                extent = min(extent, max(0, len(data) - row["offset"]))
                if extent and row["virtual_address"] + extent <= 2**32:
                    rows.append(dict(address=row["virtual_address"], offset=row["offset"], size=extent))
            mapping = _SectionMap(rows, "address")

            def mapped(address, length=1):
                row = mapping.row(address, length)
                return (row["offset"] + address - row["address"], row["offset"] + row["size"]) if row else None

            directory = mapped(rva, 40)
            if directory is None:
                return
            functions, count, entries, names, ordinals = struct.unpack_from("<5I", data, directory[0] + 20)
            table = mapped(names, 4) if names else None
            if table is None:
                return
            count = _query_count(data, table[0], min(count, (table[1] - table[0]) // 4), 4, budget)
            for index in range(count):
                _charge(budget, 2)
                ordinal = mapped(ordinals + index * 2, 2) if ordinals else None
                if ordinal is None:
                    break
                number = struct.unpack_from("<H", data, ordinal[0])[0]
                if number >= functions:
                    break
                function = mapped(entries + number * 4, 4) if entries else None
                name = mapped(struct.unpack_from("<I", data, table[0] + index * 4)[0])
                if function is None or name is None:
                    break
                named = _import_name(data, *name)
                address = base + struct.unpack_from("<I", data, function[0])[0]
                if address >= 2**64:
                    break
                if named:
                    label, location = named
                    yield location, dict(name=label, address=address, type="export", binding="global",
                                         defined=address != base)
    except _QueryLimit:
        raise
    except StructureError:
        return


def symbols(data, args):
    return _query_page(_symbol_records(data), args, "symbol")


TOOL = ToolSpec(REF, {
    "structure.identify": OperationSpec("structure.identify", {}, identify, max_observations=1),
    "structure.headers": OperationSpec("structure.headers", {}, headers, max_observations=1),
    "structure.sections": OperationSpec("structure.sections",
                                        {"max_sections": ArgSpec("int", minimum=1, maximum=MAX_SECTIONS, default=64)},
                                        sections, max_observations=MAX_SECTIONS),
    "structure.imports": OperationSpec("structure.imports",
                                       {"max_imports": ArgSpec("int", minimum=1, maximum=MAX_IMPORTS, default=128)},
                                       imports, max_observations=MAX_IMPORTS),
    "structure.segments": OperationSpec("structure.segments", {
        "start": ArgSpec("int", 0, 65535, default=0), "limit": ArgSpec("int", 1, 256, default=64),
    }, segments, max_observations=256),
    "structure.entry": OperationSpec("structure.entry", {}, entry, max_observations=1),
    "structure.read_bytes": OperationSpec("structure.read_bytes", {
        "mode": ArgSpec("enum", choices=("offset", "address"), default="offset"),
        "at": ArgSpec("int", 0, 2**64 - 1, default=0), "length": ArgSpec("int", 1, 2000, default=256),
    }, read_bytes, max_observations=1),
    "structure.symbols": OperationSpec("structure.symbols", {
        "query": ArgSpec("literal", 0, 128, default=""),
        "start": ArgSpec("int", 0, 1048575, default=0), "limit": ArgSpec("int", 1, 256, default=128),
    }, symbols, max_observations=256),
})
