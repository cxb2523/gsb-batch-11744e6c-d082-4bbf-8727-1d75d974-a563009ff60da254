"""ReverseAI LIEF worker: one operation on /snapshot/input, one reverseai.worker/1 JSON object on stdout.

Entrypoint (docs/contract.md, "Contained worker interface (M2a)"):
    python3 -I -B /opt/reverseai/worker.py <operation> <canonical JSON of validated args>

LIEF 1.0.0 is lenient with malformed input: it returns partial or guessed headers,
and it picks ELF byte order from the machine field rather than EI_DATA. So every
value this worker reports is decoded twice, by LIEF and by the small decoder below,
and must agree; disagreement, truncation or an unsupported layout is an error reply,
never a partial answer. The ELF class and byte order are the exception: LIEF only
echoes the same e_ident bytes, so they come from the decoder alone, and a byte order
LIEF does not follow shows up in the multi-byte fields it does check. LIEF runs with
fixed parser options: every optional parse is off, leaving headers and section
tables. Observations follow M1's field names, one per physical structure, each
Location inside that structure and at most 4,096 bytes. Section names are deferred.
Nothing but the one JSON object is written, to stdout only. The functions take bytes
and plain dicts, so they are testable without LIEF.
"""

import hashlib
import json
import re
import struct
import sys

PROTOCOL = "reverseai.worker/1"
ADAPTER_VERSION = "1.0.0-r2"
SNAPSHOT = "/snapshot/input"
MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_LOCATION = 4096
HEADERS_CAP = 3
SECTIONS = (1, 64, 32)  # max_sections: minimum, maximum, default

# The same names as reverseai/tools/structure.py, so LIEF and M1 claims can agree.
ELF_MACHINES = {3: "x86", 8: "mips", 20: "powerpc", 21: "powerpc64", 40: "arm", 62: "x86_64", 183: "aarch64", 243: "riscv"}
PE_MACHINES = {0x14C: "x86", 0x1C4: "arm", 0x8664: "x86_64", 0xAA64: "aarch64"}
PE_OPTIONAL = {0x10B: "pe32", 0x20B: "pe32+"}
SHF_WRITE, SHF_EXECINSTR = 0x1, 0x4
SCN_MEM_EXECUTE, SCN_MEM_WRITE = 0x20000000, 0x80000000
# Every parse_* option of LIEF 1.0.0's ParserConfig (lief/ELF.pyi, lief/PE/__init__.pyi in the pinned wheel); all are set off.
ELF_PARSER_OFF = ("parse_dyn_symbols", "parse_notes", "parse_overlay", "parse_relocations", "parse_symbol_versions",
                  "parse_symtab_symbols")
PE_PARSER_OFF = ("parse_arm64x_binary", "parse_exceptions", "parse_exports", "parse_imports", "parse_reloc", "parse_rsrc",
                 "parse_signature")


class WorkerFailure(Exception):
    """An expected refusal; its class name is the reply's error."""


class InvalidRequest(WorkerFailure):
    pass


class InputTooLarge(WorkerFailure):
    pass


class UnsupportedFormat(WorkerFailure):
    pass


class UnsupportedLayout(WorkerFailure):
    pass


class TruncatedStructure(WorkerFailure):
    pass


class StructureTooLarge(WorkerFailure):
    pass


class ParserRefused(WorkerFailure):
    pass


class InconsistentParse(WorkerFailure):
    """LIEF and the byte decoder disagree about a reported field."""


class ParserOptionsChanged(WorkerFailure):
    """This LIEF's parser options are not exactly the ones the worker turns off."""


class SnapshotUnreadable(WorkerFailure):
    pass


def location(offset, length, size):
    if length > MAX_LOCATION:
        raise StructureTooLarge()
    if offset < 0 or length <= 0 or offset + length > size:
        raise TruncatedStructure()
    return {"offset": offset, "length": length}


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
    raise UnsupportedFormat()


# ---- ELF -------------------------------------------------------------------

def elf_raw(data):
    """The ELF header fields this worker reports, decoded with EI_CLASS and EI_DATA."""
    need(data, 0, 16)
    width, order = {1: 32, 2: 64}.get(data[4]), {1: "<", 2: ">"}.get(data[5])
    if width is None or order is None:
        raise UnsupportedLayout()
    header_size = 52 if width == 32 else 64
    need(data, 0, header_size)
    word = "I" if width == 32 else "Q"
    kind_, machine, _, entry, _, shoff, _, _, _, _, shentsize, shnum, shstrndx = struct.unpack_from(
        order + "HHI" + word * 3 + "IHHHHHH", data, 16)
    return {"class": width, "endianness": "little" if order == "<" else "big", "header_size": header_size, "type": kind_,
            "machine": machine, "entry": entry, "shoff": shoff, "shentsize": shentsize, "shnum": shnum, "shstrndx": shstrndx}


ELF_CHECKED = ("type", "machine", "entry", "shoff", "shentsize", "shnum")


def elf_header_observations(raw, size):
    return [{"location": location(0, raw["header_size"], size), "value": {
        "structure": "elf", "format": "elf", "class": raw["class"], "endianness": raw["endianness"], "type": raw["type"],
        "machine": raw["machine"], "machine_name": ELF_MACHINES.get(raw["machine"], "unknown"), "entry": raw["entry"],
        "shnum": raw["shnum"], "shoff": raw["shoff"]}}]


def elf_section_rows(data, raw, limit):
    """Physical section header entries: the whole declared table must lie inside the input."""
    if raw["shnum"] == 0:
        if raw["shoff"]:
            raise UnsupportedLayout()  # extended numbering: LIEF 1.0.0 lists no sections for it
        return []
    entry = 40 if raw["class"] == 32 else 64
    if raw["shentsize"] != entry:
        raise UnsupportedLayout()
    need(data, raw["shoff"], entry * raw["shnum"])
    order = "<" if raw["endianness"] == "little" else ">"
    layout = order + ("IIIIIIIIII" if raw["class"] == 32 else "IIQQQQIIQQ")
    rows = []
    for index in range(min(raw["shnum"], limit)):
        offset = raw["shoff"] + entry * index
        _, _, flags, _, start, length = struct.unpack_from(layout, data, offset)[:6]
        rows.append({"index": index, "offset": start, "size": length, "flags": flags, "writable": bool(flags & SHF_WRITE),
                     "executable": bool(flags & SHF_EXECINSTR), "at": offset, "entry": entry})
    return rows


# ---- PE --------------------------------------------------------------------

def pe_raw(data):
    """DOS, signature+COFF and optional-header fields, each read only inside its declared region."""
    need(data, 0, 0x40)
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    coff = e_lfanew + 4
    need(data, coff, 20)
    machine, sections, timestamp, _, _, optional_size, characteristics = struct.unpack_from("<HHIIIHH", data, coff)
    optional = coff + 20
    if optional_size > MAX_LOCATION:
        raise StructureTooLarge()
    need(data, optional, optional_size)
    raw = {"e_lfanew": e_lfanew, "machine": machine, "number_of_sections": sections, "timestamp": timestamp,
           "characteristics": characteristics, "sizeof_optional_header": optional_size, "optional": optional}
    if optional_size >= 2:
        raw["optional_magic"] = struct.unpack_from("<H", data, optional)[0]
    if optional_size >= 20:
        raw["entry_rva"] = struct.unpack_from("<I", data, optional + 16)[0]
    return raw


PE_CHECKED = ("e_lfanew", "machine", "number_of_sections", "timestamp", "characteristics", "sizeof_optional_header")


def pe_header_observations(raw, size):
    observations = [
        {"location": location(0, 0x40, size), "value": {"structure": "dos", "e_lfanew": raw["e_lfanew"]}},
        {"location": location(raw["e_lfanew"], 24, size), "value": {
            "structure": "coff", "format": "pe", "machine": raw["machine"],
            "machine_name": PE_MACHINES.get(raw["machine"], "unknown"), "number_of_sections": raw["number_of_sections"],
            "timestamp": raw["timestamp"], "characteristics": raw["characteristics"],
            "sizeof_optional_header": raw["sizeof_optional_header"]}},
    ]
    if raw["sizeof_optional_header"]:
        value = {"structure": "optional"}
        if "optional_magic" in raw:
            value["optional_magic"] = PE_OPTIONAL.get(raw["optional_magic"], "unknown")
        if "entry_rva" in raw:
            value["entry_rva"] = raw["entry_rva"]
        observations.append({"location": location(raw["optional"], raw["sizeof_optional_header"], size), "value": value})
    return observations


def pe_section_rows(data, raw, limit):
    table = raw["optional"] + raw["sizeof_optional_header"]
    need(data, table, 40 * raw["number_of_sections"])
    rows = []
    for index in range(min(raw["number_of_sections"], limit)):
        offset = table + 40 * index
        _, _, _, length, start = struct.unpack_from("<8sIIII", data, offset)
        characteristics = struct.unpack_from("<I", data, offset + 36)[0]
        rows.append({"index": index, "offset": start, "size": length, "characteristics": characteristics,
                     "writable": bool(characteristics & SCN_MEM_WRITE), "executable": bool(characteristics & SCN_MEM_EXECUTE),
                     "at": offset, "entry": 40})
    return rows


# ---- Cross-check, observations and request ---------------------------------

def agree(raw, facts, fields):
    """Every reported field must be the same in LIEF's parse and in the byte decode."""
    for name in fields:
        if name in raw and facts.get(name) != raw[name]:
            raise InconsistentParse()


def agree_sections(rows, facts, declared, flag_field):
    """LIEF must list exactly the declared sections, and each reported row must match its entry."""
    listed = facts.get("sections")
    if not isinstance(listed, list) or len(listed) != declared:
        raise InconsistentParse()
    for row in rows:
        if tuple(listed[row["index"]]) != (row["offset"], row["size"], row[flag_field]):
            raise InconsistentParse()


def section_observations(rows, size, flag_field):
    return [{"location": location(row["at"], row["entry"], size), "value": {
        "structure": "section", "index": row["index"], "offset": row["offset"], "size": row["size"],
        flag_field: row[flag_field], "writable": row["writable"], "executable": row["executable"]}} for row in rows]


def parse_request(argv):
    if len(argv) != 2:
        raise InvalidRequest()
    operation, text = argv
    try:
        args = json.loads(text, object_pairs_hook=lambda pairs: dict(pairs) if len({k for k, _ in pairs}) == len(pairs) else None)
    except ValueError:
        raise InvalidRequest() from None
    if not isinstance(args, dict):
        raise InvalidRequest()
    if operation == "lief.headers" and not args:
        return operation, {}
    if operation == "lief.sections" and set(args) <= {"max_sections"}:
        minimum, maximum, default = SECTIONS
        value = args.get("max_sections", default)
        if type(value) is int and minimum <= value <= maximum:
            return operation, {"max_sections": value}
    raise InvalidRequest()


def parser_config(config_class, off):
    """A config whose parse_* options are exactly off, all set False; a missing or new option is an error, never ignored."""
    config = config_class()
    if sorted(name for name in dir(config) if name.startswith("parse_")) != sorted(off):
        raise ParserOptionsChanged()
    for name in off:
        setattr(config, name, False)
        if getattr(config, name) is not False:
            raise ParserOptionsChanged()
    return config


def parser_configs():
    """The fixed LIEF parser configs; the image build runs this once, so a LIEF with other options fails the build."""
    import lief

    return {"elf": parser_config(lief.ELF.ParserConfig, ELF_PARSER_OFF), "pe": parser_config(lief.PE.ParserConfig, PE_PARSER_OFF)}


def lief_facts(data, format_):
    """The same fields as read by LIEF; the only function that parses with it (inside the image)."""
    import warnings

    import lief

    warnings.simplefilter("ignore")  # unknown enum values otherwise warn on stderr
    lief.logging.disable()
    config = parser_configs()[format_]
    binary = lief.ELF.parse(data, config) if format_ == "elf" else lief.PE.parse(data, config)
    if binary is None:
        raise ParserRefused()
    header = binary.header
    if format_ == "elf":
        return {"type": int(header.file_type),
                "machine": int(header.machine_type), "entry": header.entrypoint, "shoff": header.section_header_offset,
                "shentsize": header.section_header_size, "shnum": header.numberof_sections,
                "sections": [(s.offset, s.size, int(s.flags)) for s in binary.sections]}
    optional = binary.optional_header
    return {"e_lfanew": binary.dos_header.addressof_new_exeheader, "machine": int(header.machine),
            "number_of_sections": header.numberof_sections, "timestamp": header.time_date_stamps,
            "characteristics": int(header.characteristics), "sizeof_optional_header": header.sizeof_optional_header,
            "optional_magic": int(optional.magic), "entry_rva": optional.addressof_entrypoint,
            "sections": [(s.offset, s.size, int(s.characteristics)) for s in binary.sections]}


def run(operation, args, data, facts_of=None):
    """Observations for one operation; facts_of(data, format) defaults to LIEF."""
    facts_of = facts_of or lief_facts
    format_ = kind(data)
    raw = elf_raw(data) if format_ == "elf" else pe_raw(data)
    if operation == "lief.headers":
        observations = (elf_header_observations if format_ == "elf" else pe_header_observations)(raw, len(data))
        checked = ELF_CHECKED if format_ == "elf" else (*PE_CHECKED, "optional_magic", "entry_rva")
        agree(raw, facts_of(data, format_), checked)
        return observations[:HEADERS_CAP]
    rows_of, declared, flag = ((elf_section_rows, "shnum", "flags") if format_ == "elf"
                               else (pe_section_rows, "number_of_sections", "characteristics"))
    rows = rows_of(data, raw, args["max_sections"])
    facts = facts_of(data, format_)
    agree(raw, facts, ELF_CHECKED if format_ == "elf" else PE_CHECKED)
    agree_sections(rows, facts, raw[declared], flag)
    return section_observations(rows, len(data), flag)


def error_name(exc):
    name = type(exc).__name__
    return name if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", name) else "WorkerError"


def reply(argv, data, facts_of=None, digest=None):
    """One reply; data None means the snapshot could not be read, digest defaults to the SHA-256 of data."""
    digest = digest or hashlib.sha256(data or b"").hexdigest()
    try:
        if data is None:
            raise SnapshotUnreadable()
        operation, args = parse_request(argv)
        if len(data) > MAX_INPUT_BYTES:
            raise InputTooLarge()
        return {"protocol": PROTOCOL, "status": "ok", "snapshot_sha256": digest,
                "observations": run(operation, args, data, facts_of)}
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
    message = reply(sys.argv[1:] if argv is None else argv, data, digest=digest)
    sys.stdout.write(json.dumps(message, sort_keys=True, separators=(",", ":")) + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
