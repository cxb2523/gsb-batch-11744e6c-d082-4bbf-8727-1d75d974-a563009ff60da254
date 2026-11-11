"""Deterministic ELF64 and PE32+ x86-64 fixtures with real instructions, for Ghidra tests; no binary files.

The same four hand-assembled functions are placed in each container:

    entry        calls add_numbers, then compute, then exits (mov eax, 60; xor edi, edi; syscall; ret)
    add_numbers  push rbp; mov rbp, rsp; mov eax, edi; add eax, esi; pop rbp; ret
    compute      push rbx; add_numbers(2, 3); mov ebx, eax; constant(); add eax, ebx; pop rbx; ret
    constant     mov eax, 42; ret

with four direct `call rel32` instructions (5 bytes each) and int3 padding between functions. The
ELF has a .symtab naming them (entry is `_start`); the PE has no symbols; the thin x86_64 Mach-O
names them in its LC_SYMTAB and enters at `_start` through LC_MAIN. elf_data_only() is a clean
control with no executable section and no entry point. Each builder returns (data, layout): the
bytes and the declared addresses, file offsets and sizes, so tests can state exact expectations.

elf_refs(), pe_refs() and macho_refs() add a data section and a fifth function, called by
_start after compute:

    describe     lea rax, [rip+greeting]; lea rdx, [rip+wide_greeting]; mov ecx, [rip+counter];
                 mov [rip+result], ecx; add dword [rip+counter], 1; jmp constant

greeting is an ascii string, wide_greeting a utf-16le one, counter and result are dwords; the jmp is
a tail jump out of describe's body. Their layouts also declare every function's instructions as
[delta, length] rows, each non-call reference (instruction, target, the x86 access kind) and the two
strings (address, file offset, encoding, text, encoded length, referencing functions).
"""

from __future__ import annotations

import struct

PAD = 0xCC  # int3 between functions
# Function name, offset inside .text; their bytes are assembled by _code below.
FUNCTIONS = (("_start", 0x00), ("add_numbers", 0x20), ("compute", 0x30), ("constant", 0x50))
TEXT_SIZE = 0x56


def _rel32(at, length, target):
    return struct.pack("<i", target - (at + length))


def _code():
    """(.text bytes, functions [(name, offset, size)], calls [(from offset, call offset, target offset)])."""
    starts = dict(FUNCTIONS)
    text = bytearray([PAD]) * TEXT_SIZE
    calls = []

    def put(offset, *parts):
        at = offset
        for part in parts:
            if isinstance(part, tuple):  # ("call", target name)
                target = starts[part[1]]
                calls.append((offset, at, target))
                part = b"\xe8" + _rel32(at, 5, target)
            text[at:at + len(part)] = part
            at += len(part)
        return at - offset

    sizes = {
        "_start": put(0x00, ("call", "add_numbers"), ("call", "compute"), b"\xb8\x3c\x00\x00\x00", b"\x31\xff",
                      b"\x0f\x05", b"\xc3"),
        "add_numbers": put(0x20, b"\x55", b"\x48\x89\xe5", b"\x89\xf8", b"\x01\xf0", b"\x5d", b"\xc3"),
        "compute": put(0x30, b"\x53", b"\xbf\x02\x00\x00\x00", b"\xbe\x03\x00\x00\x00", ("call", "add_numbers"),
                       b"\x89\xc3", ("call", "constant"), b"\x01\xd8", b"\x5b", b"\xc3"),
        "constant": put(0x50, b"\xb8\x2a\x00\x00\x00", b"\xc3"),
    }
    functions = [(name, offset, sizes[name]) for name, offset in FUNCTIONS]
    assert functions[-1][1] + functions[-1][2] == TEXT_SIZE
    return bytes(text), functions, calls


def _layout(text_offset, text_address, functions, calls, *, named):
    """Declared addresses and file offsets; names are None when the container has no symbols (the tool names them)."""
    by_offset = {offset: name if named else None for name, offset, _ in functions}
    return {
        "entry": text_address + dict((n, o) for n, o, _ in functions)["_start"],
        "text": {"offset": text_offset, "address": text_address, "size": TEXT_SIZE},
        "functions": [{"name": by_offset[offset], "entry": text_address + offset, "offset": text_offset + offset, "size": size}
                      for name, offset, size in functions],
        "calls": [{"from": text_address + start, "address": text_address + at, "offset": text_offset + at, "length": 5,
                   "to": text_address + target, "to_name": by_offset[target]} for start, at, target in calls],
    }


def _strtab(names):
    table, offsets = b"\0", {}
    for name in names:
        offsets[name] = len(table)
        table += name + b"\0"
    return table, offsets


def elf_code():
    """ET_EXEC x86-64: one R+X PT_LOAD over headers and .text, then .symtab, .strtab, .shstrtab and the section table."""
    text, functions, calls = _code()
    base, text_offset = 0x400000, 0x100
    text_address = base + text_offset
    strtab, names = _strtab([name.encode() for name, _, _ in functions])
    symtab = bytes(24) + b"".join(
        struct.pack("<IBBHQQ", names[name.encode()], 0x12, 0, 1, text_address + offset, size)  # GLOBAL FUNC in section 1
        for name, offset, size in functions)
    shstrtab, shnames = _strtab([b".text", b".symtab", b".strtab", b".shstrtab"])
    symtab_offset = text_offset + TEXT_SIZE + (-(text_offset + TEXT_SIZE) % 8)
    strtab_offset = symtab_offset + len(symtab)
    shstrtab_offset = strtab_offset + len(strtab)
    shoff = shstrtab_offset + len(shstrtab) + (-(shstrtab_offset + len(shstrtab)) % 8)
    sections = [bytes(64),
                struct.pack("<IIQQQQIIQQ", shnames[b".text"], 1, 0x6, text_address, text_offset, TEXT_SIZE, 0, 0, 16, 0),
                struct.pack("<IIQQQQIIQQ", shnames[b".symtab"], 2, 0, 0, symtab_offset, len(symtab), 3, 1, 8, 24),
                struct.pack("<IIQQQQIIQQ", shnames[b".strtab"], 3, 0, 0, strtab_offset, len(strtab), 0, 0, 1, 0),
                struct.pack("<IIQQQQIIQQ", shnames[b".shstrtab"], 3, 0, 0, shstrtab_offset, len(shstrtab), 0, 0, 1, 0)]
    layout = _layout(text_offset, text_address, functions, calls, named=True)
    header = (b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
              + struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, layout["entry"], 64, shoff, 0, 64, 56, 1, 64, len(sections), 4))
    load = struct.pack("<IIQQQQQQ", 1, 0x5, 0, base, base, text_offset + TEXT_SIZE, text_offset + TEXT_SIZE, 0x1000)
    data = bytearray(header + load)
    data += bytes(text_offset - len(data)) + text
    data += bytes(symtab_offset - len(data)) + symtab + strtab + shstrtab
    data += bytes(shoff - len(data)) + b"".join(sections)
    layout.update(format="elf", image_base=base, shoff=shoff, section_names=[".text", ".symtab", ".strtab", ".shstrtab"])
    return bytes(data), layout


def pe_code():
    """PE32+ x86-64 console executable: .text (code, RX) and .data (RW), no symbols, no imports."""
    text, functions, calls = _code()
    image_base, lfanew, file_alignment = 0x140000000, 0x40, 0x200
    text_rva, data_rva, text_offset, data_offset = 0x1000, 0x2000, 0x200, 0x400
    sections = (struct.pack("<8sIIIIIIHHI", b".text", TEXT_SIZE, text_rva, file_alignment, text_offset, 0, 0, 0, 0, 0x60000020)
                + struct.pack("<8sIIIIIIHHI", b".data", 0x10, data_rva, file_alignment, data_offset, 0, 0, 0, 0, 0xC0000040))
    coff = struct.pack("<HHIIIHH", 0x8664, 2, 0x5F5E1000, 0, 0, 240, 0x22)
    optional = struct.pack("<HBBIIIIIQIIHHHHHHIIIIHHQQQQII", 0x20B, 14, 0, file_alignment, file_alignment, 0,
                           text_rva, text_rva, image_base, 0x1000, file_alignment, 6, 0, 0, 0, 6, 0, 0,
                           0x3000, 0x200, 0, 3, 0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16) + bytes(16 * 8)
    assert len(optional) == 240
    data = bytearray(b"MZ" + bytes(0x3A) + struct.pack("<I", lfanew))
    data += b"PE\0\0" + coff + optional + sections
    data += bytes(text_offset - len(data)) + text + bytes(file_alignment - TEXT_SIZE)
    data += b"ReverseAI data\0\0" + bytes(file_alignment - 16)
    layout = _layout(text_offset, image_base + text_rva, functions, calls, named=False)
    layout.update(format="pe", image_base=image_base, section_names=[".text", ".data"],
                  text_raw_size=file_alignment, data={"offset": data_offset, "address": image_base + data_rva, "size": 0x10})
    return bytes(data), layout


def elf_data_only():
    """A clean control: ET_EXEC with one R+W PT_LOAD and a .data section, no executable section and entry 0."""
    payload = b"ReverseAI clean data-only control\0" + bytes(range(32))
    base, data_offset = 0x400000, 0x100
    shstrtab, shnames = _strtab([b".data", b".shstrtab"])
    shstrtab_offset = data_offset + len(payload)
    shoff = shstrtab_offset + len(shstrtab) + (-(shstrtab_offset + len(shstrtab)) % 8)
    sections = [bytes(64),
                struct.pack("<IIQQQQIIQQ", shnames[b".data"], 1, 0x3, base + data_offset, data_offset, len(payload), 0, 0, 8, 0),
                struct.pack("<IIQQQQIIQQ", shnames[b".shstrtab"], 3, 0, 0, shstrtab_offset, len(shstrtab), 0, 0, 1, 0)]
    header = (b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
              + struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0, 64, shoff, 0, 64, 56, 1, 64, len(sections), 2))
    load = struct.pack("<IIQQQQQQ", 1, 0x6, data_offset, base + data_offset, base + data_offset, len(payload), len(payload), 0x1000)
    data = bytearray(header + load)
    data += bytes(data_offset - len(data)) + payload + shstrtab
    data += bytes(shoff - len(data)) + b"".join(sections)
    return bytes(data), {"format": "elf", "entry": 0, "functions": [], "calls": [], "shoff": shoff,
                         "data": {"offset": data_offset, "address": base + data_offset, "size": len(payload)}}


def macho_code():
    """Thin little-endian x86_64 MH_EXECUTE: __PAGEZERO, __TEXT (r-x) with one __text section holding the code,
    __LINKEDIT with LC_SYMTAB (the four functions, N_SECT | N_EXT in section 1) and LC_DYSYMTAB, and LC_MAIN."""
    text, functions, calls = _code()
    base, text_offset = 0x100000000, 0x200
    text_address = base + text_offset

    def segment(name, vmaddr, vmsize, fileoff, filesize, prot, sections=b"", count=0):
        return struct.pack("<II16sQQQQiiII", 0x19, 72 + len(sections), name, vmaddr, vmsize, fileoff, filesize,
                           prot, prot, count, 0) + sections

    names = [name.encode() for name, _, _ in functions]
    strtab, offsets = _strtab(names)
    symbols = b"".join(struct.pack("<IBBHQ", offsets[name.encode()], 0x0F, 1, 0, text_address + offset)
                       for name, offset, _ in functions)
    linkedit = text_offset + TEXT_SIZE + (-(text_offset + TEXT_SIZE) % 8)
    section = struct.pack("<16s16sQQIIIIIIII", b"__text", b"__TEXT", text_address, TEXT_SIZE, text_offset, 4, 0, 0,
                          0x80000400, 0, 0, 0)  # S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS
    commands = [
        segment(b"__PAGEZERO", 0, base, 0, 0, 0),
        segment(b"__TEXT", base, 0x1000, 0, text_offset + TEXT_SIZE, 0x5, section, 1),
        segment(b"__LINKEDIT", base + 0x1000, 0x1000, linkedit, len(symbols) + len(strtab), 0x1),
        struct.pack("<IIIIII", 0x2, 24, linkedit, len(functions), linkedit + len(symbols), len(strtab)),  # LC_SYMTAB
        struct.pack("<II18I", 0xB, 80, 0, 0, 0, len(functions), len(functions), 0, *([0] * 12)),  # LC_DYSYMTAB
        struct.pack("<IIQQ", 0x80000028, 24, text_offset, 0),  # LC_MAIN: entry at __TEXT file offset text_offset
    ]
    header = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x01000007, 3, 2, len(commands), sum(map(len, commands)), 0x1, 0)
    data = bytearray(header + b"".join(commands))
    assert len(data) <= text_offset
    data += bytes(text_offset - len(data)) + text
    data += bytes(linkedit - len(data)) + symbols + strtab
    layout = _layout(text_offset, text_address, functions, calls, named=True)
    layout.update(format="macho", image_base=base, section_names=["__TEXT,__text"], linkedit=linkedit)
    return bytes(data), layout


# The same four functions plus describe, with references into a data section.
REFS_FUNCTIONS = (("_start", 0x00), ("add_numbers", 0x20), ("compute", 0x30), ("constant", 0x50), ("describe", 0x60))
REFS_TEXT_SIZE = 0x86
DATA_SIZE = 0x50
GREETING, WIDE_GREETING = "ReverseAI ascii string", "ReverseAI wide"
# Name, offset inside the data section, size.
DATA_OBJECTS = (("greeting", 0x00, len(GREETING) + 1), ("wide_greeting", 0x20, 2 * len(WIDE_GREETING) + 2),
                ("counter", 0x40, 4), ("result", 0x48, 4))


def _data():
    data = bytearray(DATA_SIZE)
    data[0x00:0x00 + len(GREETING) + 1] = GREETING.encode("ascii") + b"\0"
    wide = WIDE_GREETING.encode("utf-16le") + b"\0\0"
    data[0x20:0x20 + len(wide)] = wide
    struct.pack_into("<I", data, 0x40, 7)
    return bytes(data)


def _refs_code(data_delta):
    """(.text, functions [(name, offset, size)], instructions {name: [(delta, length)]}, calls, refs) for the five
    functions; data_delta is the data section's address minus .text's (the RIP-relative displacements depend on it).
    calls are (from offset, call offset, target offset); refs are (from offset, offset, length, target offset from
    .text's address, access)."""
    starts, objects = dict(REFS_FUNCTIONS), {name: offset for name, offset, _ in DATA_OBJECTS}
    text = bytearray([PAD]) * REFS_TEXT_SIZE
    instructions, calls, refs = {}, [], []

    def put(name, *parts):
        offset = at = starts[name]
        rows = []
        for part in parts:
            if isinstance(part, bytes):
                encoded = part
            elif part[0] in ("call", "jmp"):  # ("call" or "jmp", target function)
                target = starts[part[1]]
                encoded = (b"\xe8" if part[0] == "call" else b"\xe9") + _rel32(at, 5, target)
                if part[0] == "call":
                    calls.append((offset, at, target))
                else:
                    refs.append((offset, at, 5, target, "jump"))
            else:  # (access, opcode, data object, immediate): a RIP-relative operand
                access, opcode, label, immediate = part
                length = len(opcode) + 4 + len(immediate)
                encoded = opcode + _rel32(at, length, data_delta + objects[label]) + immediate
                refs.append((offset, at, length, data_delta + objects[label], access))
            text[at:at + len(encoded)] = encoded
            rows.append((at - offset, len(encoded)))
            at += len(encoded)
        instructions[name] = rows
        return at - offset

    sizes = {
        "_start": put("_start", ("call", "add_numbers"), ("call", "compute"), ("call", "describe"), b"\xb8\x3c\x00\x00\x00",
                      b"\x31\xff", b"\x0f\x05", b"\xc3"),
        "add_numbers": put("add_numbers", b"\x55", b"\x48\x89\xe5", b"\x89\xf8", b"\x01\xf0", b"\x5d", b"\xc3"),
        "compute": put("compute", b"\x53", b"\xbf\x02\x00\x00\x00", b"\xbe\x03\x00\x00\x00", ("call", "add_numbers"),
                       b"\x89\xc3", ("call", "constant"), b"\x01\xd8", b"\x5b", b"\xc3"),
        "constant": put("constant", b"\xb8\x2a\x00\x00\x00", b"\xc3"),
        "describe": put("describe", ("data", b"\x48\x8d\x05", "greeting", b""), ("data", b"\x48\x8d\x15", "wide_greeting", b""),
                        ("read", b"\x8b\x0d", "counter", b""), ("write", b"\x89\x0d", "result", b""),
                        ("read_write", b"\x83\x05", "counter", b"\x01"), ("jmp", "constant")),
    }
    functions = [(name, offset, sizes[name]) for name, offset in REFS_FUNCTIONS]
    assert functions[-1][1] + functions[-1][2] == REFS_TEXT_SIZE
    return bytes(text), functions, instructions, calls, refs


def _refs_layout(text_offset, text_address, data_offset, data_address, functions, instructions, calls, refs, *, named):
    layout = _layout(text_offset, text_address, functions, calls, named=named)
    layout["text"]["size"] = REFS_TEXT_SIZE
    for row, (name, _, _) in zip(layout["functions"], functions):
        row["instructions"] = [list(item) for item in instructions[name]]
    starts = {offset: name for name, offset, _ in functions}
    objects = {data_address - text_address + offset: name for name, offset, _ in DATA_OBJECTS}
    layout["data"] = {"offset": data_offset, "address": data_address, "size": DATA_SIZE}
    layout["refs"] = [{"from": text_address + start, "address": text_address + at, "offset": text_offset + at, "length": length,
                       "to": text_address + target, "type": access,
                       "to_name": (starts.get(target) or objects[target]) if named else None}
                      for start, at, length, target, access in sorted(refs, key=lambda ref: ref[1])]
    describe = text_address + dict((name, offset) for name, offset, _ in functions)["describe"]
    layout["strings"] = [{"address": data_address + offset, "offset": data_offset + offset, "encoding": encoding, "text": text,
                          "length": len(text.encode(encoding)), "truncated": False, "from": [describe]}
                         for offset, encoding, text in ((0x00, "ascii", GREETING), (0x20, "utf-16le", WIDE_GREETING))]
    return layout


def elf_refs():
    """elf_code's layout plus .data: an R+X PT_LOAD over headers and .text, an R+W PT_LOAD over .data, and .symtab
    naming the five functions (FUNC, section 1) and the four data objects (OBJECT, section 2)."""
    base, text_offset, data_offset = 0x400000, 0x100, 0x200
    text_address, data_address = base + text_offset, base + 0x1000 + data_offset
    text, functions, instructions, calls, refs = _refs_code(data_address - text_address)
    names = [name.encode() for name, _, _ in functions] + [name.encode() for name, _, _ in DATA_OBJECTS]
    strtab, offsets = _strtab(names)
    symtab = bytes(24) + b"".join(
        struct.pack("<IBBHQQ", offsets[name.encode()], 0x12, 0, 1, text_address + offset, size) for name, offset, size in functions
    ) + b"".join(
        struct.pack("<IBBHQQ", offsets[name.encode()], 0x11, 0, 2, data_address + offset, size) for name, offset, size in DATA_OBJECTS)
    shstrtab, shnames = _strtab([b".text", b".data", b".symtab", b".strtab", b".shstrtab"])
    symtab_offset = data_offset + DATA_SIZE
    strtab_offset = symtab_offset + len(symtab)
    shstrtab_offset = strtab_offset + len(strtab)
    shoff = shstrtab_offset + len(shstrtab) + (-(shstrtab_offset + len(shstrtab)) % 8)
    sections = [bytes(64),
                struct.pack("<IIQQQQIIQQ", shnames[b".text"], 1, 0x6, text_address, text_offset, REFS_TEXT_SIZE, 0, 0, 16, 0),
                struct.pack("<IIQQQQIIQQ", shnames[b".data"], 1, 0x3, data_address, data_offset, DATA_SIZE, 0, 0, 8, 0),
                struct.pack("<IIQQQQIIQQ", shnames[b".symtab"], 2, 0, 0, symtab_offset, len(symtab), 4, 1, 8, 24),
                struct.pack("<IIQQQQIIQQ", shnames[b".strtab"], 3, 0, 0, strtab_offset, len(strtab), 0, 0, 1, 0),
                struct.pack("<IIQQQQIIQQ", shnames[b".shstrtab"], 3, 0, 0, shstrtab_offset, len(shstrtab), 0, 0, 1, 0)]
    layout = _refs_layout(text_offset, text_address, data_offset, data_address, functions, instructions, calls, refs, named=True)
    header = (b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
              + struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, layout["entry"], 64, shoff, 0, 64, 56, 2, 64, len(sections), 5))
    loads = (struct.pack("<IIQQQQQQ", 1, 0x5, 0, base, base, text_offset + REFS_TEXT_SIZE, text_offset + REFS_TEXT_SIZE, 0x1000)
             + struct.pack("<IIQQQQQQ", 1, 0x6, data_offset, data_address, data_address, DATA_SIZE, DATA_SIZE, 0x1000))
    data = bytearray(header + loads)
    data += bytes(text_offset - len(data)) + text
    data += bytes(data_offset - len(data)) + _data() + symtab + strtab + shstrtab
    data += bytes(shoff - len(data)) + b"".join(sections)
    layout.update(format="elf", image_base=base, shoff=shoff, section_names=[".text", ".data", ".symtab", ".strtab", ".shstrtab"])
    return bytes(data), layout


def pe_refs():
    """pe_code's layout with the five functions in .text and the strings and dwords in .data; no symbols, no imports."""
    image_base, lfanew, file_alignment = 0x140000000, 0x40, 0x200
    text_rva, data_rva, text_offset, data_offset = 0x1000, 0x2000, 0x200, 0x400
    text, functions, instructions, calls, refs = _refs_code(data_rva - text_rva)
    sections = (struct.pack("<8sIIIIIIHHI", b".text", REFS_TEXT_SIZE, text_rva, file_alignment, text_offset, 0, 0, 0, 0, 0x60000020)
                + struct.pack("<8sIIIIIIHHI", b".data", DATA_SIZE, data_rva, file_alignment, data_offset, 0, 0, 0, 0, 0xC0000040))
    coff = struct.pack("<HHIIIHH", 0x8664, 2, 0x5F5E1000, 0, 0, 240, 0x22)
    optional = struct.pack("<HBBIIIIIQIIHHHHHHIIIIHHQQQQII", 0x20B, 14, 0, file_alignment, file_alignment, 0,
                           text_rva, text_rva, image_base, 0x1000, file_alignment, 6, 0, 0, 0, 6, 0, 0,
                           0x3000, 0x200, 0, 3, 0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16) + bytes(16 * 8)
    assert len(optional) == 240
    data = bytearray(b"MZ" + bytes(0x3A) + struct.pack("<I", lfanew))
    data += b"PE\0\0" + coff + optional + sections
    data += bytes(text_offset - len(data)) + text + bytes(file_alignment - REFS_TEXT_SIZE)
    data += _data() + bytes(file_alignment - DATA_SIZE)
    layout = _refs_layout(text_offset, image_base + text_rva, data_offset, image_base + data_rva, functions, instructions, calls, refs,
                          named=False)
    layout.update(format="pe", image_base=image_base, section_names=[".text", ".data"], text_raw_size=file_alignment)
    return bytes(data), layout


def macho_refs():
    """macho_code's layout with the five functions in __TEXT,__text and the strings and dwords in __DATA,__data (rw-);
    LC_SYMTAB names the functions (section 1) and the data objects (section 2)."""
    base, text_offset, data_offset = 0x100000000, 0x300, 0x400
    text_address, data_address = base + text_offset, base + 0x1000
    text, functions, instructions, calls, refs = _refs_code(data_address - text_address)

    def segment(name, vmaddr, vmsize, fileoff, filesize, prot, sections=b"", count=0):
        return struct.pack("<II16sQQQQiiII", 0x19, 72 + len(sections), name, vmaddr, vmsize, fileoff, filesize,
                           prot, prot, count, 0) + sections

    names = [name.encode() for name, _, _ in functions] + [name.encode() for name, _, _ in DATA_OBJECTS]
    strtab, offsets = _strtab(names)
    symbols = b"".join(struct.pack("<IBBHQ", offsets[name.encode()], 0x0F, 1, 0, text_address + offset)
                       for name, offset, _ in functions)
    symbols += b"".join(struct.pack("<IBBHQ", offsets[name.encode()], 0x0F, 2, 0, data_address + offset)
                        for name, offset, _ in DATA_OBJECTS)
    linkedit = data_offset + DATA_SIZE
    text_section = struct.pack("<16s16sQQIIIIIIII", b"__text", b"__TEXT", text_address, REFS_TEXT_SIZE, text_offset, 4, 0, 0,
                               0x80000400, 0, 0, 0)  # S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS
    data_section = struct.pack("<16s16sQQIIIIIIII", b"__data", b"__DATA", data_address, DATA_SIZE, data_offset, 3, 0, 0, 0, 0, 0, 0)
    count = len(functions) + len(DATA_OBJECTS)
    commands = [
        segment(b"__PAGEZERO", 0, base, 0, 0, 0),
        segment(b"__TEXT", base, 0x1000, 0, text_offset + REFS_TEXT_SIZE, 0x5, text_section, 1),
        segment(b"__DATA", data_address, 0x1000, data_offset, DATA_SIZE, 0x3, data_section, 1),
        segment(b"__LINKEDIT", base + 0x2000, 0x1000, linkedit, len(symbols) + len(strtab), 0x1),
        struct.pack("<IIIIII", 0x2, 24, linkedit, count, linkedit + len(symbols), len(strtab)),  # LC_SYMTAB
        struct.pack("<II18I", 0xB, 80, 0, 0, 0, count, count, 0, *([0] * 12)),  # LC_DYSYMTAB
        struct.pack("<IIQQ", 0x80000028, 24, text_offset, 0),  # LC_MAIN: entry at __TEXT file offset text_offset
    ]
    header = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x01000007, 3, 2, len(commands), sum(map(len, commands)), 0x1, 0)
    data = bytearray(header + b"".join(commands))
    assert len(data) <= text_offset
    data += bytes(text_offset - len(data)) + text
    data += bytes(data_offset - len(data)) + _data()
    data += symbols + strtab
    layout = _refs_layout(text_offset, text_address, data_offset, data_address, functions, instructions, calls, refs, named=True)
    layout.update(format="macho", image_base=base, section_names=["__TEXT,__text", "__DATA,__data"], linkedit=linkedit)
    return bytes(data), layout
