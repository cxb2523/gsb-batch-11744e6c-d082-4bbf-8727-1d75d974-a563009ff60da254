"""Re-derive Ghidra byte anchors and referenced strings, not code semantics."""

from array import array
from bisect import bisect_left, bisect_right
from collections import namedtuple
import struct

from reverseai.contract import ContractError, Location, Observation
from reverseai.tools import structure
from reverseai.tools.structure import (
    SHF_EXECINSTR, SCN_MEM_EXECUTE, _elf_layout, _format, _need, _pe_layout,
)

REFUSED = "Worker code anchor not confirmed by the bytes"
SHF_ALLOC = 0x2
_Section = namedtuple("_Section", "va offset size span executable")
_FIELDS = {
    "function": {"kind", "index", "name", "entry", "size"},
    "pseudocode": {"kind", "index", "entry", "text", "truncated"},
    "call": {"kind", "from", "to", "to_name"},
    "assembly": {"kind", "index", "entry", "instructions", "truncated"},
    "ref": {"kind", "from", "to", "type", "to_name"},
    "string": {"kind", "address", "encoding", "text", "truncated", "from"},
}


def _check(condition):
    if not condition:
        raise ContractError(REFUSED)


def _uint(value, minimum=0):
    return type(value) is int and minimum <= value < 2**64


def _name(value):
    return isinstance(value, str) and len(value) <= 128 and all(char.isprintable() for char in value)


def _sections(data):
    kind, pe, _ = _format(data)
    sections = []
    if kind == "macho":
        _check(data[:4] in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"))
        mapped = structure.macho_sections(data)
        _check(bool(mapped))
        width = 64 if data[:4] == b"\xcf\xfa\xed\xfe" else 32
        _check(all(row["addr"] + row["size"] <= 2**width for row in mapped))
        sections = [_Section(row["addr"], row["offset"], row["size"], row["size"], row["executable"])
                    for row in mapped]
        return sections, structure.macho_entry(data)
    if kind == "elf":
        width, order, _, header = _elf_layout(data)
        entry, layout = (40, "IIIIIIIIII") if width == 32 else (64, "IIQQQQIIQQ")
        if header["shnum"] == header["shoff"] == 0:
            return sections, header["entry"]
        _check(header["shentsize"] == entry and header["shoff"] > 0)
        count = header["shnum"]
        if count == 0:
            _need(data, header["shoff"], entry, "ELF section header zero")
            count = struct.unpack_from(order + layout, data, header["shoff"])[5]
        _need(data, header["shoff"], count * entry, "ELF section table")
        for index in range(count):
            _, kind, flags, va, offset, size = struct.unpack_from(order + layout, data, header["shoff"] + index * entry)[:6]
            backed = size if kind not in (0, 8) else 0
            if backed:
                _need(data, offset, backed, "ELF section contents")
            if flags & SHF_ALLOC:
                _check(va + size <= 2**width)
                sections.append(_Section(va, offset, backed, size if kind else 0, bool(flags & SHF_EXECINSTR)))
        return sections, header["entry"]
    _check(kind == "pe")
    header = _pe_layout(data, pe)
    optional = header["optional"]
    _check(header["magic"] in (0x10B, 0x20B) and header["optional_size"] >= 32)
    _need(data, optional, header["optional_size"], "PE optional header")
    base = struct.unpack_from("<Q" if header["magic"] == 0x20B else "<I", data,
                              optional + (24 if header["magic"] == 0x20B else 28))[0]
    width = 64 if header["magic"] == 0x20B else 32
    _check(base + header["entry"] < 2**width)
    table = optional + header["optional_size"]
    _need(data, table, header["sections"] * 40, "PE section table")
    for index in range(header["sections"]):
        at = table + index * 40
        _, virtual_size, rva, size, offset = struct.unpack_from("<8sIIII", data, at)
        flags = struct.unpack_from("<I", data, at + 36)[0]
        span = max(size, virtual_size)
        _check(rva + span <= 2**32 and base + rva + span <= 2**width)
        if size:
            _need(data, offset, size, "PE section contents")
        backed = min(size, virtual_size or size)
        sections.append(_Section(base + rva, offset, backed, backed, bool(flags & SCN_MEM_EXECUTE)))
    return sections, base + header["entry"]


class _Intervals:
    """Count overlaps in O(log n), including aliases away from the query's start."""

    def __init__(self, sections, *, virtual, backed=False):
        self.sections = sections
        bounds = ((section.va if virtual else section.offset,
                   section.size if backed or not virtual else section.span, index)
                  for index, section in enumerate(sections))
        self.starts, self.start_ids = self._prefix(sorted((start, index) for start, length, index in bounds if length))
        bounds = ((section.va if virtual else section.offset,
                   section.size if backed or not virtual else section.span, index)
                  for index, section in enumerate(sections))
        self.ends, self.end_ids = self._prefix(sorted((start + length, index) for start, length, index in bounds if length))

    @staticmethod
    def _prefix(rows):
        points, ids = [], array("Q", [0])
        for point, index in rows:
            points.append(point)
            ids.append(ids[-1] ^ index)
        return points, ids

    def single(self, start, length):
        _check(length > 0)
        began = bisect_left(self.starts, start + length)
        ended = bisect_right(self.ends, start)
        _check(began - ended == 1)
        # Ended intervals are a subset of started ones; their IDs cancel in the XOR.
        return self.sections[self.start_ids[began] ^ self.end_ids[ended]]


class _SectionIndex:
    def __init__(self, sections):
        self.virtual = _Intervals(sections, virtual=True)
        self.file = _Intervals(sections, virtual=False)
        self.backed_virtual = (self.virtual if all(section.span == section.size for section in sections)
                               else _Intervals(sections, virtual=True, backed=True))


def _map(sections, start, length, *, virtual):
    section = (sections.virtual if virtual else sections.file).single(start, length)
    delta = start - (section.va if virtual else section.offset)
    _check(section.executable and 0 <= delta and delta + length <= section.size)
    return (section.offset if virtual else section.va) + delta, section


def _function_anchor(sections, entry, size):
    offset, section = _map(sections, entry, 1, virtual=True)
    length = min(size, 4096, section.size - (entry - section.va))
    _map(sections, entry, length, virtual=True)
    _map(sections, offset, length, virtual=False)
    return Location(offset, length)


def _file_map(sections, start, length, *, virtual):
    """String mapping admits only file-backed bytes, independent of execute permission."""
    section = (sections.backed_virtual if virtual else sections.file).single(start, length)
    delta = start - (section.va if virtual else section.offset)
    _check(0 <= delta and delta + length <= section.size)
    return (section.offset if virtual else section.va) + delta, section


def _string_bytes(data, offset, end):
    for encoding, width in (("ascii", 1), ("utf-16le", 2)):
        chars = []
        while len(chars) < 128 and offset + (len(chars) + 1) * width <= end:
            unit = data[offset + len(chars) * width:offset + (len(chars) + 1) * width]
            if not 0x20 <= unit[0] <= 0x7e or (width == 2 and unit[1] != 0):
                break
            chars.append(chr(unit[0]))
        following = data[offset + len(chars) * width:min(end, offset + (len(chars) + 1) * width)]
        truncated = (len(chars) == 128 and len(following) == width
                     and 0x20 <= following[0] <= 0x7e and (width == 1 or following[1] == 0))
        if len(chars) >= 2 and (truncated or following == bytes(width)):
            return encoding, "".join(chars), truncated
    raise ContractError(REFUSED)


def verify(data, observations, args, operation="ghidra.analyze"):
    """Validate the whole reply before admitting any derived observation."""
    try:
        if operation in ("ghidra.pseudocode", "ghidra.export_function", "ghidra.export_program"):
            from reverseai.tools.ghidra_export import admit
            return admit(data, observations, args, operation)
        if operation == "ghidra.analyze":
            _verify(data, observations, args)
        else:
            _verify_query(data, observations, args, operation)
    except (ContractError, struct.error, TypeError, KeyError, ValueError, IndexError):
        raise ContractError(REFUSED) from None


def _verify(data, observations, args):
    args = {"assembly": 4, "max_instructions": 32, "max_refs": 64, "max_strings": 32, **args}
    _check(isinstance(data, bytes) and isinstance(observations, (list, tuple)) and len(observations) <= 600)
    decoded, binary_entry = _sections(data)
    sections = _SectionIndex(decoded)
    groups = {kind: [] for kind in _FIELDS}
    order = {kind: index for index, kind in enumerate(_FIELDS)}
    previous_kind = 0
    for item in observations:
        _check(isinstance(item, Observation) and item.location.within(len(data)))
        value = item.value
        kind = value.get("kind")
        _check(isinstance(kind, str) and kind in _FIELDS and set(value) == _FIELDS[kind])
        _check(order[kind] >= previous_kind)
        previous_kind = order[kind]
        functions = groups["function"]
        if kind == "function":
            _check(type(value["index"]) is int and value["index"] == len(functions) and _name(value["name"]))
            _check(_uint(value["entry"]) and _uint(value["size"], 1) and value["entry"] + value["size"] <= 2**64)
            _check(not functions or value["entry"] > functions[-1].value["entry"])
            _check(item.location == _function_anchor(sections, value["entry"], value["size"]))
        elif kind in ("pseudocode", "assembly"):
            _check(type(value["index"]) is int and _uint(value["entry"]) and type(value["truncated"]) is bool)
            if kind == "pseudocode":
                _check(isinstance(value["text"], str) and len(value["text"]) <= args["max_chars"])
            else:
                _check(isinstance(value["instructions"], list) and 1 <= len(value["instructions"]) <= args["max_instructions"])
                end = 0
                for row in value["instructions"]:
                    _check(isinstance(row, list) and len(row) == 3)
                    delta, length, text = row
                    _check(_uint(delta) and type(length) is int and 1 <= length <= 16
                           and end <= delta and delta + length <= item.location.length)
                    _check(isinstance(text, str) and 1 <= len(text) <= 64 and all(0x20 <= ord(c) <= 0x7e for c in text))
                    end = delta + length
        elif kind in ("call", "ref"):
            _check(_uint(value["from"]) and _uint(value["to"]) and _name(value["to_name"]))
            _check(1 <= item.location.length <= 16)
            if kind == "ref":
                _check(value["type"] in ("read", "write", "read_write", "data", "jump"))
        else:
            _check(_uint(value["address"]) and type(value["truncated"]) is bool)
            _check(isinstance(value["from"], list) and 1 <= len(value["from"]) <= 8
                   and all(_uint(entry) for entry in value["from"]))
        groups[kind].append(item)
    for kind, limit in (("function", "max_functions"), ("pseudocode", "decompile"), ("call", "max_calls"),
                        ("assembly", "assembly"), ("ref", "max_refs"), ("string", "max_strings")):
        _check(len(groups[kind]) <= args[limit])
    functions = groups["function"]
    by_entry = {item.value["entry"]: item for item in functions}
    selection = sorted(functions, key=lambda item: (item.value["entry"] != binary_entry,
                                                   -item.value["size"], item.value["entry"]))
    ranks = {item.value["index"]: index for index, item in enumerate(selection)}
    for kind in ("pseudocode", "assembly"):
        previous = -1
        for item in groups[kind]:
            value = item.value
            _check(0 <= value["index"] < len(functions))
            function = functions[value["index"]]
            _check(value["entry"] == function.value["entry"] and item.location == function.location)
            _check(ranks[value["index"]] > previous)
            previous = ranks[value["index"]]
    for item in groups["call"] + groups["ref"]:
        value = item.value
        _check(value["from"] in by_entry)
        function = by_entry[value["from"]].value
        va, _ = _map(sections, item.location.offset, item.location.length, virtual=False)
        _map(sections, va, item.location.length, virtual=True)
        _check(value["from"] <= va and va + item.location.length <= value["from"] + function["size"])
    previous = None
    origins = {}
    for item in groups["ref"]:
        value = item.value
        key = (item.location.offset, value["to"], value["type"])
        _check(previous is None or key > previous)
        previous = key
        origins.setdefault(value["to"], set()).add(value["from"])
    previous = -1
    for item in groups["string"]:
        value = item.value
        address = value["address"]
        _check(address > previous and address in origins)
        previous = address
        _check(value["from"] == sorted(origins[address])[:8])
        offset, section = _file_map(sections, address, 1, virtual=True)
        encoding, text, truncated = _string_bytes(data, offset, section.offset + section.size)
        _check((value["encoding"], value["text"], value["truncated"]) == (encoding, text, truncated))
        length = len(text.encode(encoding))
        _check(item.location == Location(offset, length))
        checked_length = length + (1 if encoding == "ascii" else 2)
        _file_map(sections, address, checked_length, virtual=True)
        _file_map(sections, offset, checked_length, virtual=False)


_QUERY_FIELDS = {
    "function_row": {"kind", "index", "total", "name", "entry", "size"},
    "target": {"kind", "name", "entry", "size", "matches", "callers_total", "callees_total"},
    "instructions": {"kind", "entry", "start", "total", "rows", "truncated"},
    "caller": {"kind", "at", "from", "to"},
    "xref": {"kind", "index", "total", "at", "from", "to", "type"},
    **{kind: _FIELDS[kind] for kind in ("pseudocode", "call", "ref")},
}
_REFERENCE_TYPES = ("read", "write", "read_write", "data", "jump")


def _index(value, minimum=0):
    return type(value) is int and minimum <= value < 2**32


def _instruction_anchor(sections, item):
    _check(1 <= item.location.length <= 16)
    address, _ = _map(sections, item.location.offset, item.location.length, virtual=False)
    offset, _ = _map(sections, address, item.location.length, virtual=True)
    _check(offset == item.location.offset)
    return address


def _instruction_rows(rows, maximum, size):
    _check(isinstance(rows, list) and 1 <= len(rows) <= maximum)
    end = 0
    for row in rows:
        _check(isinstance(row, list) and len(row) == 3)
        delta, length, text = row
        _check(_uint(delta) and type(length) is int and 1 <= length <= 16
               and end <= delta and delta + length <= size)
        _check(isinstance(text, str) and 1 <= len(text) <= 64 and all(" " <= c <= "~" for c in text))
        end = delta + length


def _page_rows(items, args):
    total = None
    for index, item in enumerate(items, args["start"]):
        value = item.value
        _check(type(value["index"]) is int and value["index"] == index)
        _check(_index(value["total"]) and index < value["total"] <= 65536)
        _check(total is None or total == value["total"])
        total = value["total"]


def _verify_query(data, observations, args, operation):
    _check(operation in ("ghidra.functions", "ghidra.function", "ghidra.xrefs"))
    _check(isinstance(data, bytes) and isinstance(observations, (list, tuple))
           and len(observations) <= (643 if operation == "ghidra.function" else 256))
    _check(isinstance(args, dict))
    defaults = {
        "ghidra.functions": {"query": "", "start": 0, "limit": 64},
        "ghidra.function": {"select": "entry", "entry": 0, "name": "", "parts": "all", "start": 0,
                             "limit": 64, "max_chars": 1024, "max_calls": 64, "max_refs": 64},
        "ghidra.xrefs": {"start": 0, "limit": 64},
    }[operation]
    _check(set(args) <= set(defaults) | ({"address"} if operation == "ghidra.xrefs" else set()))
    args = {**defaults, **args}
    _check(type(args["start"]) is int and 0 <= args["start"] <= 65535)
    maximum = 128 if operation == "ghidra.functions" else 256
    _check(type(args["limit"]) is int and 1 <= args["limit"] <= maximum)
    decoded, _ = _sections(data)
    sections = _SectionIndex(decoded)
    allowed = ({"function_row"} if operation == "ghidra.functions" else {"xref"}
               if operation == "ghidra.xrefs" else {"target", "pseudocode", "instructions", "call", "caller", "ref"})
    for item in observations:
        _check(isinstance(item, Observation) and item.location.within(len(data)))
        value = item.value
        kind = value.get("kind")
        _check(isinstance(kind, str) and kind in allowed and set(value) == _QUERY_FIELDS[kind])
    if operation == "ghidra.function":
        _verify_function(sections, observations, args)
        return
    _check(len(observations) <= args["limit"])
    _page_rows(observations, args)
    previous = -1
    if operation == "ghidra.functions":
        _check(isinstance(args["query"], str))
        for item in observations:
            value = item.value
            _check(_name(value["name"]) and args["query"] in value["name"])
            _check(_uint(value["entry"]) and value["entry"] > previous and _uint(value["size"], 1)
                   and value["entry"] + value["size"] <= 2**64)
            previous = value["entry"]
            _check(item.location == _function_anchor(sections, value["entry"], value["size"]))
    else:
        _check(_uint(args["address"]))
        previous = None
        for item in observations:
            value = item.value
            address = _instruction_anchor(sections, item)
            _check(_uint(value["at"]) and value["at"] == address)
            _check(_uint(value["to"]) and value["to"] == args["address"])
            _check(value["type"] in ("call", *_REFERENCE_TYPES))
            _check(value["from"] is None or _uint(value["from"]))
            key = (value["at"], value["type"])
            _check(previous is None or key > previous)
            previous = key



def _verify_function(sections, observations, args):
    _check(args["select"] in ("entry", "name") and _uint(args["entry"]) and isinstance(args["name"], str))
    parts = args["parts"]
    _check(parts in ("info", "pseudocode", "assembly", "callees", "callers", "all"))
    for key, minimum, maximum in (("max_chars", 64, 2048), ("max_calls", 0, 256), ("max_refs", 0, 128)):
        _check(type(args[key]) is int and minimum <= args[key] <= maximum)
    if not observations:
        return
    target_item = observations[0]
    target = target_item.value
    _check(target["kind"] == "target" and _name(target["name"]))
    _check(_uint(target["entry"]) and _uint(target["size"], 1)
           and target["entry"] + target["size"] <= 2**64)
    _check(_index(target["matches"], 1) and target["matches"] <= 65536
           and _index(target["callers_total"]) and target["callers_total"] <= 65536
           and _index(target["callees_total"]))
    _check((target["entry"] == args["entry"] and target["matches"] == 1) if args["select"] == "entry"
           else target["name"] == args["name"])
    _check(target_item.location == _function_anchor(sections, target["entry"], target["size"]))
    kinds = ("target", "pseudocode", "instructions", "call", "caller", "ref")
    limits = {"target": 1, "pseudocode": 1, "instructions": 1, "call": args["max_calls"],
              "caller": args["max_calls"], "ref": args["max_refs"]}
    selected = {"info": (), "pseudocode": ("pseudocode",), "assembly": ("instructions",),
                "callees": ("call",), "callers": ("caller",), "all": kinds[1:]}[parts]
    previous_kind = 0
    counts = dict.fromkeys(kinds, 0)
    previous_caller = -1
    previous_ref = None
    call_sites = set()
    for item in observations:
        value = item.value
        kind = value["kind"]
        rank = kinds.index(kind)
        _check(rank >= previous_kind and (kind == "target" or kind in selected))
        previous_kind = rank
        counts[kind] += 1
        _check(counts[kind] <= limits[kind])
        if kind == "target":
            continue
        if kind == "pseudocode":
            _check(type(value["index"]) is int and value["index"] == 0 and _uint(value["entry"])
                   and value["entry"] == target["entry"] and item.location == target_item.location)
            _check(isinstance(value["text"], str) and len(value["text"]) <= args["max_chars"]
                   and type(value["truncated"]) is bool)
        elif kind == "instructions":
            _check(_uint(value["entry"]) and value["entry"] == target["entry"])
            _check(type(value["start"]) is int and value["start"] == args["start"] and _index(value["total"]))
            rows = value["rows"]
            _instruction_rows(rows, args["limit"], target["size"])
            _check(value["start"] + len(rows) <= value["total"] and type(value["truncated"]) is bool)
            _check(value["truncated"] == (len(rows) < args["limit"] and value["start"] + len(rows) < value["total"]))
            address = target["entry"] + rows[0][0]
            length = rows[-1][0] + rows[-1][1] - rows[0][0]
            offset, _ = _map(sections, address, length, virtual=True)
            reverse, _ = _map(sections, offset, length, virtual=False)
            _check(reverse == address and item.location == Location(offset, length))
        elif kind == "caller":
            address = _instruction_anchor(sections, item)
            _check(_uint(value["at"]) and value["at"] == address and address > previous_caller)
            _check(_uint(value["to"]) and value["to"] == target["entry"])
            _check(value["from"] is None or _uint(value["from"]))
            previous_caller = address
        else:
            _check(_uint(value["from"]) and value["from"] == target["entry"]
                   and _uint(value["to"]) and _name(value["to_name"]))
            address = _instruction_anchor(sections, item)
            _check(target["entry"] <= address and address + item.location.length <= target["entry"] + target["size"])
            if kind == "call":
                _check(address not in call_sites)
                call_sites.add(address)
            if kind == "ref":
                _check(value["type"] in _REFERENCE_TYPES)
                key = (item.location.offset, value["to"], value["type"])
                _check(previous_ref is None or key > previous_ref)
                previous_ref = key
    _check(counts["caller"] <= target["callers_total"] and counts["call"] <= target["callees_total"])
