"""Host re-derivation of every value a contained LIEF worker reports (contract rule 1, contained variant).

A worker reply is untrusted beyond its schema. For each observation the host names
the physical structure it claims to describe (ELF header, DOS header, signature and
COFF header, optional header, section header entry), decodes that structure from
the controller's own bytes with the stdlib code of the structure tool, and requires
the same Location and exactly the same value. A different, extra or missing field,
a shifted location, an operation that cannot report that structure, or anything
the host cannot decode refuses the whole reply: a compromised worker can withhold
evidence, never invent it.
"""

from __future__ import annotations

import struct

from reverseai.contract import ContractError, Location, canonical_json
from reverseai.tools.structure import (
    ELF_MACHINES, PE_MACHINES, PE_OPTIONAL, SCN_MEM_EXECUTE, SCN_MEM_WRITE, SHF_EXECINSTR, SHF_WRITE,
    _elf_layout, _format, _need, _pe_offset,
)

REFUSED = "Worker value not confirmed by the bytes"
PE_HEADERS = ("dos", "coff", "optional")


def _elf_header(data):
    width, order, size, h = _elf_layout(data)
    return Location(0, size), {
        "structure": "elf", "format": "elf", "class": width, "endianness": "little" if order == "<" else "big",
        "type": h["type"], "machine": h["machine"], "machine_name": ELF_MACHINES.get(h["machine"], "unknown"),
        "entry": h["entry"], "shnum": h["shnum"], "shoff": h["shoff"]}


def _elf_section(data, at):
    """The section header entry at byte offset at; its index is its position in the declared table."""
    width, order, _, h = _elf_layout(data)
    entry = 40 if width == 32 else 64
    index, remainder = divmod(at - h["shoff"], entry)
    if h["shentsize"] != entry or remainder or not 0 <= index < h["shnum"]:
        raise ContractError(REFUSED)  # not an entry of the declared table (extended numbering declares shnum 0)
    _need(data, at, entry, "ELF section header")
    _, _, flags, _, start, size = struct.unpack_from(order + ("IIIIIIIIII" if width == 32 else "IIQQQQIIQQ"), data, at)[:6]
    return Location(at, entry), {
        "structure": "section", "index": index, "offset": start, "size": size, "flags": flags,
        "writable": bool(flags & SHF_WRITE), "executable": bool(flags & SHF_EXECINSTR)}


def _pe_layout(data):
    """DOS, signature+COFF and optional-header bounds; the optional header may be shorter than 20 bytes."""
    e_lfanew = _pe_offset(data)
    coff = e_lfanew + 4
    _need(data, coff, 20, "COFF header")
    machine, sections, timestamp, _, _, optional_size, characteristics = struct.unpack_from("<HHIIIHH", data, coff)
    return {"e_lfanew": e_lfanew, "machine": machine, "number_of_sections": sections, "timestamp": timestamp,
            "characteristics": characteristics, "sizeof_optional_header": optional_size, "optional": coff + 20}


def _pe_header(data, structure):
    h = _pe_layout(data)
    if structure == "dos":
        return Location(0, 0x40), {"structure": "dos", "e_lfanew": h["e_lfanew"]}
    if structure == "coff":
        return Location(h["e_lfanew"], 24), {
            "structure": "coff", "format": "pe", "machine": h["machine"],
            "machine_name": PE_MACHINES.get(h["machine"], "unknown"), "number_of_sections": h["number_of_sections"],
            "timestamp": h["timestamp"], "characteristics": h["characteristics"],
            "sizeof_optional_header": h["sizeof_optional_header"]}
    start, size = h["optional"], h["sizeof_optional_header"]
    _need(data, start, size, "Optional header")
    value = {"structure": "optional"}
    if size >= 2:
        value["optional_magic"] = PE_OPTIONAL.get(struct.unpack_from("<H", data, start)[0], "unknown")
    if size >= 20:
        value["entry_rva"] = struct.unpack_from("<I", data, start + 16)[0]
    return Location(start, size), value


def _pe_section(data, at):
    h = _pe_layout(data)
    index, remainder = divmod(at - h["optional"] - h["sizeof_optional_header"], 40)
    if remainder or not 0 <= index < h["number_of_sections"]:
        raise ContractError(REFUSED)
    _need(data, at, 40, "PE section header")
    _, _, _, size, start = struct.unpack_from("<8sIIII", data, at)
    characteristics = struct.unpack_from("<I", data, at + 36)[0]
    return Location(at, 40), {
        "structure": "section", "index": index, "offset": start, "size": size, "characteristics": characteristics,
        "writable": bool(characteristics & SCN_MEM_WRITE), "executable": bool(characteristics & SCN_MEM_EXECUTE)}


def _expected(operation, data, observation):
    kind, structure = _format(data)[0], observation.value.get("structure")
    if operation == "lief.headers" and kind == "elf" and structure == "elf":
        return _elf_header(data)
    if operation == "lief.headers" and kind == "pe" and structure in PE_HEADERS:
        return _pe_header(data, structure)
    if operation == "lief.sections" and structure == "section" and kind in ("elf", "pe"):
        return (_elf_section if kind == "elf" else _pe_section)(data, observation.location.offset)
    raise ContractError(REFUSED)


def verify(operation, data, observation):
    """Refuse a worker observation unless the host decodes the same structure, location and value from data."""
    try:
        location, value = _expected(operation, data, observation)
    except (ContractError, struct.error):  # StructureError and Location's own checks are ContractErrors
        raise ContractError(REFUSED) from None
    if observation.location != location or canonical_json(observation.value) != canonical_json(value):
        raise ContractError(REFUSED)
