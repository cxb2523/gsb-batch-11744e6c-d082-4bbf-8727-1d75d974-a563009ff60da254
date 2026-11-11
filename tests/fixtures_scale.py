"""Code-built, never executed ELF with exactly 10,000 named x86-64 functions."""

import struct


def elf_scale(count=10_000):
    if type(count) is not int or not 1 <= count <= 65_537:
        raise ValueError("Invalid scale fixture count")
    base, offset, stride = 0x400000, 0x100, 16
    text = b"".join(b"\xb8" + struct.pack("<I", index) + b"\xc3" + b"\xcc" * 10 for index in range(count))
    names = ["_start", *(f"function_{index:05d}" for index in range(1, count))]
    strings = bytearray(b"\0")
    symbols = bytearray(24)
    functions = []
    for index, name in enumerate(names):
        name_at = len(strings)
        strings.extend(name.encode("ascii") + b"\0")
        entry = base + offset + index * stride
        symbols.extend(struct.pack("<IBBHQQ", name_at, 0x12, 0, 1, entry, 6))
        functions.append({"name": name, "entry": entry, "offset": offset + index * stride, "size": 6})
    section_names = b"\0.text\0.symtab\0.strtab\0.shstrtab\0"
    sym_at = offset + len(text)
    str_at = sym_at + len(symbols)
    names_at = str_at + len(strings)
    section_at = (names_at + len(section_names) + 7) & ~7
    sections = [bytes(64),
                struct.pack("<IIQQQQIIQQ", 1, 1, 6, base + offset, offset, len(text), 0, 0, 16, 0),
                struct.pack("<IIQQQQIIQQ", 7, 2, 0, 0, sym_at, len(symbols), 3, 1, 8, 24),
                struct.pack("<IIQQQQIIQQ", 15, 3, 0, 0, str_at, len(strings), 0, 0, 1, 0),
                struct.pack("<IIQQQQIIQQ", 23, 3, 0, 0, names_at, len(section_names), 0, 0, 1, 0)]
    header = (b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
              + struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, base + offset, 64, section_at, 0,
                            64, 56, 1, 64, len(sections), 4))
    load = struct.pack("<IIQQQQQQ", 1, 5, 0, base, base, offset + len(text), offset + len(text), 0x1000)
    data = bytearray(header + load)
    data.extend(bytes(offset - len(data)) + text + symbols + strings + section_names)
    data.extend(bytes(section_at - len(data)) + b"".join(sections))
    return bytes(data), {"format": "elf", "functions": functions, "calls": [], "references": [], "strings": [],
                         "text": {"offset": offset, "address": base + offset, "size": len(text)}}
