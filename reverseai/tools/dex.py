"""Bounded, read-only DEX structures; offsets always address the supplied child bytes.

This is a structural decoder, not a runtime verifier or a decompiler. Strings are
resolved lazily; a string may contain isolated UTF-16 surrogates permitted by DEX.
Sources: https://source.android.com/docs/core/runtime/dex-format and
https://source.android.com/docs/core/runtime/dalvik-bytecode
"""

from __future__ import annotations

from collections import OrderedDict
import hashlib
import re
import struct
import zlib

from reverseai.contract import (
    ArgSpec, ContractError, Location, MAX_OBSERVATION_BYTES, Observation, OperationSpec, ToolRef, ToolSpec,
    canonical_json,
)

MAX_CHILD_BYTES = 32 * 1024 * 1024
MAX_CHILDREN_BYTES = 128 * 1024 * 1024
MAX_ENTRIES = 65536
MAX_STRING_IDS = 1048576
MAX_STRING_BYTES = 65536
MAX_DECODED_BYTES = 128 * 1024 * 1024
MAX_MEMBER_ENTRIES = 262144
VERSIONS = (35, 37, 38, 39)
NO_INDEX = 0xFFFFFFFF
_TABLES = (("string_ids", 1, 4), ("type_ids", 2, 4), ("proto_ids", 3, 12),
           ("field_ids", 4, 8), ("method_ids", 5, 8), ("class_defs", 6, 32))
_FIXED = {0: 112, 1: 4, 2: 4, 3: 12, 4: 8, 5: 8, 6: 32, 7: 4, 8: 8}
_DATA_TYPES = {0x1000, 0x1001, 0x1002, 0x1003, 0x2000, 0x2001, 0x2002,
               0x2003, 0x2004, 0x2005, 0x2006, 0xF000}


class DexError(ContractError):
    """The bytes are unsupported, inconsistent, truncated, or exceed a parsing limit."""


def _check(condition):
    if not condition:
        raise DexError("Invalid DEX structure")


def _need(data, offset, length):
    _check(type(offset) is int and type(length) is int and offset >= 0 and length >= 0
           and offset + length <= len(data))


def _read(data, offset, format_):
    _need(data, offset, struct.calcsize(format_))
    return struct.unpack_from(format_, data, offset)


def uleb128(data, offset, end=None):
    """(unsigned 32-bit value, next offset); at most five bytes, no wraparound."""
    end = len(data) if end is None else end
    _check(type(end) is int and 0 <= end <= len(data))
    value = 0
    for i in range(5):
        _check(0 <= offset < end)
        byte = data[offset]
        offset += 1
        _check(i < 4 or byte <= 0x0F)
        value |= (byte & 0x7F) << (7 * i)
        if not byte & 0x80:
            return value, offset
    raise DexError("Invalid DEX structure")


def _sleb128(data, offset, end):
    value = 0
    for i in range(5):
        _check(0 <= offset < end)
        byte = data[offset]
        offset += 1
        _check(i < 4 or byte <= 7 or 0x78 <= byte <= 0x7F)
        value |= (byte & 0x7F) << (7 * i)
        if not byte & 0x80:
            if byte & 0x40:
                value -= 1 << (7 * (i + 1))
            return value, offset
    raise DexError("Invalid DEX structure")


def mutf8(data, offset, end=None):
    """A string_data_item as (text, utf16_size, next offset), with a bounded scan."""
    end = len(data) if end is None else end
    units, start = uleb128(data, offset, end)
    _check(units <= MAX_STRING_BYTES)
    stop = data.find(b"\0", start, min(end, start + MAX_STRING_BYTES))
    _check(stop >= 0)
    raw = data[start:stop]
    _check(re.search(b"[\xf0-\xff]", raw) is None)
    try:
        text = raw.replace(b"\xc0\x80", b"\0").decode("utf-8", "surrogatepass")
        encoded = text.encode("utf-16-le", "surrogatepass")
        _check(len(encoded) // 2 == units)
        text = encoded.decode("utf-16-le", "surrogatepass")
    except UnicodeError:
        raise DexError("Invalid DEX structure") from None
    return text, units, stop + 1


def header(data):
    _check(isinstance(data, bytes) and 112 <= len(data) <= MAX_CHILD_BYTES)
    _check(data[:4] == b"dex\n" and data[7] == 0 and data[4:7] in (b"035", b"037", b"038", b"039"))
    names = ("file_size", "header_size", "endian_tag", "link_size", "link_off", "map_off",
             "string_ids_size", "string_ids_off", "type_ids_size", "type_ids_off", "proto_ids_size", "proto_ids_off",
             "field_ids_size", "field_ids_off", "method_ids_size", "method_ids_off", "class_defs_size", "class_defs_off",
             "data_size", "data_off")
    result = dict(zip(names, _read(data, 32, "<20I")))
    _check(result["file_size"] == len(data) and result["header_size"] == 112 and result["endian_tag"] == 0x12345678)
    checksum, = _read(data, 8, "<I")
    _check(checksum == zlib.adler32(memoryview(data)[12:]) & 0xFFFFFFFF)
    _check(data[12:32] == hashlib.sha1(memoryview(data)[32:], usedforsecurity=False).digest())
    data_off, data_size = result["data_off"], result["data_size"]
    _need(data, data_off, data_size)
    _check(data_size > 0 and data_size % 4 == 0 and data_off >= 112 and data_off % 4 == 0)
    spans = [(0, 112), (data_off, data_off + data_size)]
    for name, _, width in _TABLES:
        count, offset = result[name + "_size"], result[name + "_off"]
        _check(count <= (MAX_STRING_IDS if name == "string_ids" else MAX_ENTRIES))
        _check((count == 0) == (offset == 0))
        if count:
            _need(data, offset, count * width)
            _check(offset >= 112 and offset % 4 == 0)
            spans.append((offset, offset + count * width))
    count, offset = result["link_size"], result["link_off"]
    _check((count == 0) == (offset == 0))
    if count:
        _need(data, offset, count)
        spans.append((offset, offset + count))
    spans.sort()
    _check(all(a[1] <= b[0] for a, b in zip(spans, spans[1:])))
    result.update(version=int(data[4:7]), checksum=checksum, signature=data[12:32].hex(), offset=0, length=112)
    return result


class _Parser:
    def __init__(self, data, string_budget=None):
        self.data, self.header = data, header(data)
        self.string_budget = [0] if string_budget is None else string_budget
        self.members = 0
        self.type_lists = {}
        self.codes = {}
        self.code_bytes = 0
        self.map = self._map()
        self.sections = {}
        for i, row in enumerate(self.map):
            end = self.map[i + 1]["item_offset"] if i + 1 < len(self.map) else len(data)
            self.sections[row["type"]] = (row["item_offset"], end, row["size"])

    def charge(self, count):
        self.members += count
        _check(self.members <= MAX_MEMBER_ENTRIES)

    def span(self, kind, offset, length, alignment=1):
        section = self.sections.get(kind)
        _check(section is not None and offset % alignment == 0)
        start, end, _ = section
        end = min(end, self.header["data_off"] + self.header["data_size"])
        _check(start <= offset and offset + length <= end)
        _need(self.data, offset, length)
        return end

    def _map(self):
        offset = self.header["map_off"]
        start, end = self.header["data_off"], self.header["data_off"] + self.header["data_size"]
        _check(start <= offset < end and offset % 4 == 0)
        count, = _read(self.data, offset, "<I")
        _check(1 <= count <= MAX_ENTRIES and offset + 4 + count * 12 <= end)
        rows, kinds, previous = [], set(), -1
        for i in range(count):
            at = offset + 4 + i * 12
            kind, unused, size, item = _read(self.data, at, "<HHII")
            _check(not unused and kind not in kinds and kind in _FIXED.keys() | _DATA_TYPES
                   and 0 < size <= (MAX_STRING_IDS if kind in (1, 0x2002) else MAX_ENTRIES)
                   and previous < item < len(self.data))
            _check(self.header["version"] >= 38 or kind not in (7, 8))
            if rows:
                old = rows[-1]
                _check(old["item_offset"] + old["size"] * _FIXED.get(old["type"], 1) <= item)
            if kind in _FIXED:
                _need(self.data, item, size * _FIXED[kind])
                _check(item % 4 == 0)
            else:
                _check(start <= item < end)
            if kind == 0x1000:
                _check(item == offset and size == 1)
            rows.append({"index": i, "offset": at, "length": 12, "type": kind, "size": size, "item_offset": item})
            kinds.add(kind)
            previous = item
        lookup = {r["type"]: r for r in rows}
        _check(0 in lookup and lookup[0]["item_offset"] == 0 and lookup[0]["size"] == 1 and 0x1000 in lookup)
        for name, kind, _ in _TABLES:
            count = self.header[name + "_size"]
            _check((kind in lookup) == bool(count))
            if count:
                _check((lookup[kind]["size"], lookup[kind]["item_offset"]) == (count, self.header[name + "_off"]))
        return rows

    def table(self, name, format_):
        width = struct.calcsize(format_)
        for i in range(self.header[name + "_size"]):
            offset = self.header[name + "_off"] + i * width
            yield {"index": i, "offset": offset, "length": width}, _read(self.data, offset, format_)

    def type_list(self, offset, types):
        if not offset:
            return ()
        if offset not in self.type_lists:
            self.span(0x1001, offset, 4, 4)
            count, = _read(self.data, offset, "<I")
            _check(count <= MAX_ENTRIES)
            self.span(0x1001, offset, 4 + count * 2, 4)
            values = _read(self.data, offset + 4, "<" + str(count) + "H")
            _check(all(v < len(types) and types[v]["descriptor"] != "V" for v in values))
            self.type_lists[offset] = values
        self.charge(len(self.type_lists[offset]))
        return self.type_lists[offset]

    def class_data(self, offset, class_index, fields, methods):
        end = self.span(0x2000, offset, 4)
        position, counts = offset, []
        for _ in range(4):
            n, position = uleb128(self.data, position, end)
            _check(n <= MAX_ENTRIES)
            counts.append(n)
        self.charge(sum(counts))
        result = {"offset": offset}
        used_fields, used_methods = set(), set()
        for label, count in zip(("static_fields", "instance_fields", "direct_methods", "virtual_methods"), counts):
            rows, index = [], 0
            is_method = label.endswith("methods")
            table, used = (methods, used_methods) if is_method else (fields, used_fields)
            for n in range(count):
                at = position
                delta, position = uleb128(self.data, position, end)
                access, position = uleb128(self.data, position, end)
                _check(n == 0 or delta > 0)
                index += delta
                _check(index < len(table) and index not in used and table[index]["class_idx"] == class_index)
                used.add(index)
                row = {"index": index, "offset": at, "access_flags": access}
                if is_method:
                    code, position = uleb128(self.data, position, end)
                    _check(bool(code) != bool(access & (0x100 | 0x400)))
                    row["code_off"] = code
                    if code:
                        if code not in self.codes:
                            self.span(0x2001, code, 16, 4)
                            parsed = code_item(self.data, code)
                            self.span(0x2001, code, parsed["length"], 4)
                            self.code_bytes += parsed["length"]
                            _check(self.code_bytes <= len(self.data))
                            _check(all(i < self.header["type_ids_size"] for i in parsed["handler_type_indices"]))
                            if parsed["debug_info_off"]:
                                self.span(0x2003, parsed["debug_info_off"], 1)
                            self.codes[code] = parsed
                        row["code"] = self.codes[code]
                row["length"] = position - at
                rows.append(row)
            result[label] = rows
        result["length"] = position - offset
        return result


class StringTable:
    """Lazy string rows with a bounded cache; returned dictionaries never expose cached mutable state."""

    def __init__(self, parser):
        self._parser = parser
        self._count = parser.header["string_ids_size"]
        self._offset = parser.header["string_ids_off"]
        self._cache = OrderedDict()

    def __len__(self):
        return self._count

    def __iter__(self):
        for i in range(len(self)):
            yield self[i]

    def _value(self, index):
        at = self._offset + index * 4
        offset, = _read(self._parser.data, at, "<I")
        if offset in self._cache:
            self._cache.move_to_end(offset)
            return self._cache[offset]
        end = self._parser.span(0x2002, offset, 2)
        text, units, after = mutf8(self._parser.data, offset, end)
        self._parser.string_budget[0] += after - offset
        _check(self._parser.string_budget[0] <= MAX_DECODED_BYTES)
        value = offset, after - offset, units, text
        self._cache[offset] = value
        if len(self._cache) > 256:
            self._cache.popitem(last=False)
        return value

    def __getitem__(self, index):
        _check(type(index) is int and 0 <= index < len(self))
        offset, length, units, text = self._value(index)
        return {"index": index, "offset": self._offset + index * 4, "length": 4,
                "data_offset": offset, "data_length": length, "utf16_size": units, "text": text}


def _at(table, index):
    _check(type(index) is int and 0 <= index < len(table))
    return table[index]


def _descriptor(value):
    dimensions = len(value) - len(value.lstrip("["))
    core = value[dimensions:]
    _check(dimensions <= 255 and bool(core))
    _check((len(core) == 1 and core in "ZBSCIJFD") or (not dimensions and core == "V")
           or (core.startswith("L") and core.endswith(";") and len(core) > 2
               and all(part and not any(c in part for c in ".;[\0") for part in core[1:-1].split("/"))))


def _shorty(descriptor):
    return "L" if descriptor.startswith(("L", "[")) else descriptor


def code_item(data, offset):
    """The full code_item span including try/catch tables; does not allocate the instruction array."""
    _check(isinstance(data, bytes) and len(data) <= MAX_CHILD_BYTES and type(offset) is int and offset >= 0 and offset % 4 == 0)
    registers, incoming, outgoing, tries, debug, size = _read(data, offset, "<4H2I")
    _check(incoming <= registers)
    instructions = offset + 16
    _need(data, instructions, size * 2)
    position = instructions + size * 2
    if tries and size % 2:
        padding, = _read(data, position, "<H")
        _check(padding == 0)
        position += 2
    try_start = position
    _need(data, position, tries * 8)
    position += tries * 8
    handler_types = []
    if tries:
        base = position
        count, position = uleb128(data, position)
        _check(count <= MAX_ENTRIES)
        starts, entries = set(), 0
        for _ in range(count):
            starts.add(position - base)
            amount, position = _sleb128(data, position, len(data))
            entries += abs(amount) + (amount <= 0)
            _check(entries <= MAX_MEMBER_ENTRIES)
            for _ in range(abs(amount)):
                type_index, position = uleb128(data, position)
                handler_types.append(type_index)
                address, position = uleb128(data, position)
                _check(address < size)
            if amount <= 0:
                address, position = uleb128(data, position)
                _check(address < size)
        previous = 0
        for i in range(tries):
            start, length, handler = _read(data, try_start + i * 8, "<IHH")
            _check(length > 0 and previous <= start and start + length <= size and handler in starts)
            previous = start + length
    if debug:
        _need(data, debug, 1)
    return {"offset": offset, "length": position - offset, "registers_size": registers, "ins_size": incoming,
            "outs_size": outgoing, "tries_size": tries, "debug_info_off": debug,
            "insns_offset": instructions, "insns_size": size, "handler_type_indices": tuple(handler_types)}


def _acyclic(classes):
    graph = {r["class_idx"]: tuple(i for i in (r["superclass_idx"], *r["interface_type_indices"]) if i != NO_INDEX)
             for r in classes}
    done = set()
    for root in graph:
        if root in done:
            continue
        active, stack = {root}, [(root, iter(graph[root]))]
        while stack:
            node, edges = stack[-1]
            target = next(edges, None)
            if target is None:
                done.add(node)
                active.remove(node)
                stack.pop()
            elif target in graph and target not in done:
                _check(target not in active)
                active.add(target)
                stack.append((target, iter(graph[target])))


def parse(data, *, _string_budget=None):
    """Decode bounded tables. Unused strings stay lazy; no code executes and no filesystem is accessed."""
    parser = _Parser(data, _string_budget)
    strings, types, protos, fields, methods, classes = StringTable(parser), [], [], [], [], []
    previous = -1
    for row, (descriptor,) in parser.table("type_ids", "<I"):
        text = _at(strings, descriptor)["text"]
        _descriptor(text)
        _check(descriptor > previous)
        previous = descriptor
        row.update(descriptor_idx=descriptor, descriptor=text)
        types.append(row)
    previous_proto = None
    for row, (shorty, result, parameters) in parser.table("proto_ids", "<III"):
        result_text = _at(types, result)["descriptor"]
        indices = parser.type_list(parameters, types)
        key = result, indices
        _check(previous_proto is None or previous_proto < key)
        previous_proto = key
        values = tuple(types[i]["descriptor"] for i in indices)
        short_text = _at(strings, shorty)["text"]
        _check(short_text == _shorty(result_text) + "".join(_shorty(v) for v in values))
        row.update(shorty_idx=shorty, shorty=short_text, return_type_idx=result, return_type=result_text,
                   parameters_off=parameters, parameter_type_indices=indices, parameters=values)
        protos.append(row)
    for name, target in (("field_ids", fields), ("method_ids", methods)):
        previous_key = None
        for row, (owner, type_or_proto, name_index) in parser.table(name, "<HHI"):
            owner_text = _at(types, owner)["descriptor"]
            _check(owner_text.startswith("L") if name == "field_ids" else owner_text.startswith(("L", "[")))
            text = _at(strings, name_index)["text"]
            key = owner, name_index, type_or_proto
            _check(previous_key is None or previous_key < key)
            previous_key = key
            row.update(class_idx=owner, class_descriptor=owner_text, name_idx=name_index, name=text)
            if name == "field_ids":
                descriptor = _at(types, type_or_proto)["descriptor"]
                _check(descriptor != "V")
                row.update(type_idx=type_or_proto, type_descriptor=descriptor)
            else:
                row.update(proto_idx=type_or_proto, prototype=_at(protos, type_or_proto))
            target.append(row)
    seen = set()
    for row, values in parser.table("class_defs", "<8I"):
        owner, access, superclass, interfaces, source, annotations, class_data, static_values = values
        owner_text = _at(types, owner)["descriptor"]
        _check(owner not in seen and owner_text.startswith("L"))
        seen.add(owner)
        superclass_text = None if superclass == NO_INDEX else _at(types, superclass)["descriptor"]
        _check(superclass_text is None or superclass_text.startswith("L"))
        interface_indices = parser.type_list(interfaces, types)
        _check(len(set(interface_indices)) == len(interface_indices)
               and all(types[i]["descriptor"].startswith("L") for i in interface_indices))
        if annotations:
            parser.span(0x2006, annotations, 16, 4)
        if static_values:
            parser.span(0x2005, static_values, 1)
        row.update(class_idx=owner, class_descriptor=owner_text, access_flags=access, superclass_idx=superclass,
                   superclass=superclass_text, interfaces_off=interfaces, interface_type_indices=interface_indices,
                   source_file_idx=source, source_file=None if source == NO_INDEX else _at(strings, source)["text"],
                   annotations_off=annotations, class_data_off=class_data, static_values_off=static_values)
        row["class_data"] = parser.class_data(class_data, owner, fields, methods) if class_data else None
        classes.append(row)
    _acyclic(classes)
    return {"header": parser.header, "map": parser.map, "strings": strings, "types": types,
            "protos": protos, "fields": fields, "methods": methods, "classes": classes}

# https://source.android.com/docs/core/runtime/dalvik-bytecode
# https://source.android.com/docs/core/runtime/instruction-formats
_DALVIK_WIDTHS = tuple(int(value) for value in (
    "1123123123111111"  # 00-0f
    "1112322352232112"  # 10-1f
    "2122333112333222"  # 20-2f
    "2222222222222200"  # 30-3f
    "0000222222222222"  # 40-4f
    "2222222222222222"  # 50-5f
    "2222222222222233"  # 60-6f
    "3330333330011111"  # 70-7f
    "1111111111111111"  # 80-8f
    "2222222222222222"  # 90-9f
    "2222222222222222"  # a0-af
    "1111111111111111"  # b0-bf
    "1111111111111111"  # c0-cf
    "2222222222222222"  # d0-df
    "2220000000000000"  # e0-ef
    "0000000000443322"  # f0-ff
))
_DALVIK_PAYLOADS = {1: "packed-switch", 2: "sparse-switch", 3: "fill-array-data"}
_DALVIK_PAYLOAD_OPS = {0x26: "fill-array-data", 0x2B: "packed-switch", 0x2C: "sparse-switch"}


def _dalvik_uint(data, offset, width, *, signed=False):
    return int.from_bytes(data[offset:offset + width], "little", signed=signed)


def _dalvik_instructions(data, offset, end, version):
    at = offset
    while at < end:
        word = _dalvik_uint(data, at, 2)
        opcode = word & 0xFF
        payload = None
        width = _DALVIK_WIDTHS[opcode] * 2
        if opcode == 0 and word:
            payload = _DALVIK_PAYLOADS.get(word >> 8)
            if payload is None or at % 4:
                raise DexError("invalid instruction payload")
            header_size = 4 if payload == "sparse-switch" else 8
            if header_size > end - at:
                raise DexError("truncated instruction payload")
            count = _dalvik_uint(data, at + 2, 2)
            if payload == "packed-switch":
                width = 8 + count * 4
            elif payload == "sparse-switch":
                width = 4 + count * 8
            else:
                if count not in (1, 2, 4, 8):
                    raise DexError("invalid array element width")
                elements = _dalvik_uint(data, at + 4, 4)
                width = 8 + ((count * elements + 1) // 2) * 2
            if width > end - at:
                raise DexError("truncated instruction payload")
            if payload == "sparse-switch":
                previous = None
                for pos in range(count):
                    key = _dalvik_uint(data, at + 4 + pos * 4, 4, signed=True)
                    if previous is not None and key <= previous:
                        raise DexError("invalid sparse switch keys")
                    previous = key
            elif payload == "packed-switch" and count:
                first = _dalvik_uint(data, at + 4, 4, signed=True)
                if first + count - 1 > 0x7FFFFFFF:
                    raise DexError("invalid packed switch keys")
        else:
            if width == 0:
                raise DexError("unused DEX opcode")
            if opcode >= 0xFA and version < (39 if opcode >= 0xFE else 38):
                raise DexError("opcode requires newer DEX version")
            if width > end - at:
                raise DexError("truncated DEX instruction")
            if opcode in (0x03, 0x06, 0x09, 0x0E, 0x29, 0x2A) and word >> 8:
                raise DexError("invalid instruction padding")
            if opcode in (0x24, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0xFA, 0xFC) and word >> 12 > 5:
                raise DexError("invalid invoke register count")
        yield at, width, opcode, payload
        at += width


def decode_instructions(data: bytes, offset: int, insns_size: int, *, version: int = 39):
    """Yield pool references with absolute child byte offsets and instruction lengths.

    Full width/payload validation precedes the first reference. The caller resolves
    pool indexes. This structural decoder does not verify runtime type or control flow.
    No sample is executed and no list of instruction descriptors is retained.
    """
    if type(offset) is not int or offset < 0 or offset % 2:
        raise DexError("invalid instruction offset")
    if type(insns_size) is not int or not 1 <= insns_size <= 0xFFFFFFFF:
        raise DexError("invalid instruction count")
    if type(version) is not int or version not in (35, 37, 38, 39):
        raise DexError("unsupported DEX version")
    _check(isinstance(data, bytes) and len(data) <= MAX_CHILD_BYTES)
    _need(data, offset, insns_size * 2)
    end = offset + insns_size * 2
    mask_size = (insns_size + 7) // 8
    payloads = None
    targets = None
    for at, width, opcode, payload in _dalvik_instructions(data, offset, end, version):
        if payload is not None:
            if payloads is None:
                payloads = bytearray(mask_size)
            index = (at - offset) // 2
            payloads[index // 8] |= 1 << (index % 8)
        elif opcode in _DALVIK_PAYLOAD_OPS:
            displacement = _dalvik_uint(data, at + 2, 4, signed=True)
            target = at + displacement * 2
            ident = {0x26: 0x0300, 0x2B: 0x0100, 0x2C: 0x0200}[opcode]
            if target < offset or target > end - 2 or target % 4 or _dalvik_uint(data, target, 2) != ident:
                raise DexError("invalid instruction payload target")
            if targets is None:
                targets = bytearray(mask_size)
            index = (target - offset) // 2
            targets[index // 8] |= 1 << (index % 8)
    if targets is not None:
        if payloads is None or any(required & ~actual for required, actual in zip(targets, payloads)):
            raise DexError("invalid instruction payload target")
    # Both bitsets are bounded by one bit per declared code unit. NOP-only methods
    # allocate neither. For a 32 MiB child, their combined maximum is 4 MiB.
    del targets, payloads
    for at, width, opcode, payload in _dalvik_instructions(data, offset, end, version):
        if payload is not None:
            continue
        kind = None
        if opcode in (0x1A, 0x1B):
            kind = "string"
        elif opcode in (0x1C, 0x1F, 0x20, 0x22, 0x23, 0x24, 0x25):
            kind = "type"
        elif 0x52 <= opcode <= 0x6D:
            kind = "field"
        elif 0x6E <= opcode <= 0x72 or 0x74 <= opcode <= 0x78 or opcode in (0xFA, 0xFB):
            kind = "method"
        elif opcode in (0xFC, 0xFD):
            kind = "call_site"
        elif opcode == 0xFE:
            kind = "method_handle"
        elif opcode == 0xFF:
            kind = "proto"
        if kind is not None:
            size = 4 if opcode == 0x1B else 2
            yield {"offset": at, "length": width, "opcode": opcode,
                   "kind": kind, "index": _dalvik_uint(data, at + 2, size)}
        if opcode in (0xFA, 0xFB):
            yield {"offset": at, "length": width, "opcode": opcode,
                   "kind": "proto", "index": _dalvik_uint(data, at + 6, 2)}


def _render(parts, maximum=256):
    """Bound printable output without first joining possibly large DEX prototypes."""
    result, length = [], 0
    for text in parts:
        for char in text:
            point = ord(char)
            part = (char if " " <= char <= "~" and char != "\\" else
                    ("\\x%02x" if point <= 255 else "\\u%04x" if point <= 65535 else "\\U%08x") % point)
            if length + len(part) > maximum:
                result.append(part[:maximum - length])
                return "".join(result), True
            result.append(part)
            length += len(part)
    return "".join(result), False


def _identity(parts, maximum=255):
    value, truncated = _render(parts, maximum)
    _check(not truncated)
    return value


def _prototype_parts(prototype):
    yield "("
    yield from prototype["parameters"]
    yield ")"
    yield prototype["return_type"]


def _matches(parts, text):
    displayed, truncated = _render(parts, 255)
    return not truncated and displayed == text


def _prototype_matches(prototype, text):
    return _matches(_prototype_parts(prototype), text)


def _dex_files(data, selected):
    # APK parsing owns archive names and inflation; nothing is ever extracted to disk.
    from reverseai.tools import apk
    total = 0
    string_budget = [0]
    for member in apk.members(data):
        if ((selected and not _matches((member.name,), selected))
                or (not selected and re.fullmatch(r"classes[^/]*\.dex", member.name) is None)):
            continue
        _check(not member.flags)
        total += member.size
        _check(total <= MAX_CHILDREN_BYTES)
        # Clean descriptor from this same-buffer directory walk; do not reparse per child.
        child, _ = apk._materialize(data, member)
        yield member.name, child, parse(child, _string_budget=string_budget), apk.artifact(member, child)


def _collect(rows, args):
    page, total = [], 0
    for location, value, artifact in rows:
        if args["start"] <= total < args["start"] + args["limit"]:
            page.append((location, {**value, "index": total}, artifact))
        total += 1
    try:
        result = []
        for row, value, artifact in page:
            value = {**value, "total": total}
            if value["kind"] == "class":
                # Index and total are included: retain the longest declared prefix that fits.
                while value["interfaces"] and len(canonical_json(value).encode()) > MAX_OBSERVATION_BYTES:
                    value["interfaces"].pop()
            result.append(Observation(Location(row["offset"], row["length"]), value, artifact))
        return result
    except ContractError:
        raise DexError("Invalid DEX structure") from None


def _class_rows(data, args):
    if args["class"] and args["query"]:
        raise ContractError("Conflicting class and query arguments")
    for name, _, parsed, artifact in _dex_files(data, args["member"]):
        for row in parsed["classes"]:
            if args["class"] and not _matches((row["class_descriptor"],), args["class"]):
                continue
            displayed = _identity((row["class_descriptor"],))
            if args["query"] not in displayed:
                continue
            _check(len(row["interface_type_indices"]) <= 64)
            yield row, dict(kind="class", dex=_identity((name,), 255),
                            name=displayed, access=row["access_flags"],
                            superclass=None if row["superclass"] is None else _identity((row["superclass"],)),
                            interfaces=[_identity((parsed["types"][i]["descriptor"],))
                                        for i in row["interface_type_indices"]],
                            interfaces_total=len(row["interface_type_indices"]),
                            source_file=None if row["source_file"] is None else _identity((row["source_file"],))), artifact


def _defined_methods(parsed):
    for cls in parsed["classes"]:
        if cls["class_data"]:
            for group in ("direct_methods", "virtual_methods"):
                for declaration in cls["class_data"][group]:
                    yield declaration, parsed["methods"][declaration["index"]]


def _methods(data, args):
    def rows():
        for name, _, parsed, artifact in _dex_files(data, args["member"]):
            for declaration, method in _defined_methods(parsed):
                if not _matches((method["class_descriptor"],), args["class"]):
                    continue
                code = declaration.get("code")
                value = {"kind": "method", "dex": _identity((name,), 255),
                         "class": _identity((method["class_descriptor"],)), "name": _identity((method["name"],)),
                         "prototype": _identity(_prototype_parts(method["prototype"])),
                         "access": declaration["access_flags"], "code_offset": declaration["code_off"] if code else None,
                         "code_units": code["insns_size"] if code else None}
                yield method, value, artifact
    return _collect(rows(), args)


def _selected_method(method, args):
    return (_matches((method["class_descriptor"],), args["class"]) and _matches((method["name"],), args["method"])
            and (not args["prototype"] or _prototype_matches(method["prototype"], args["prototype"])))


def _pool_reference(parsed, reference):
    kind, index = reference["kind"], reference["index"]
    if kind in ("call_site", "method_handle"):
        section = next((r for r in parsed["map"] if r["type"] == (7 if kind == "call_site" else 8)), None)
        _check(section is not None and index < section["size"])
        return None
    table = {"string": "strings", "type": "types", "field": "fields", "method": "methods", "proto": "protos"}[kind]
    return _at(parsed[table], index)


def _target(kind, row):
    if kind == "string":
        return _render((row["text"],))
    if kind == "type":
        return _identity((row["descriptor"],)), False
    _identity((row["class_descriptor"],))
    _identity((row["name"],))
    if kind == "field":
        _identity((row["type_descriptor"],))
        return _identity((row["class_descriptor"], "->", row["name"], ":", row["type_descriptor"]), 512), False
    _identity(_prototype_parts(row["prototype"]))
    def parts():
        yield row["class_descriptor"]
        yield "->"
        yield row["name"]
        yield from _prototype_parts(row["prototype"])
    return _identity(parts(), 512), False


def _reference_rows(data, args):
    for name, child, parsed, artifact in _dex_files(data, args["member"]):
        selected = {m["index"] for m in parsed["methods"] if _selected_method(m, args)}
        sources = [(declaration, method) for declaration, method in _defined_methods(parsed)
                   if declaration.get("code") and (args["direction"] == "to" or method["index"] in selected)]
        _check(sum(d["code"]["insns_size"] * 2 for d, _ in sources) <= len(child))
        sources.sort(key=lambda pair: (pair[0]["code_off"], pair[1]["index"]))
        for declaration, method in sources:
            code = declaration["code"]
            for reference in decode_instructions(child, code["insns_offset"], code["insns_size"],
                                                 version=parsed["header"]["version"]):
                target = _pool_reference(parsed, reference)
                kind = reference["kind"]
                if kind not in ("method", "field", "string", "type"):
                    continue
                if args["direction"] == "to" and (kind != "method" or reference["index"] not in selected):
                    continue
                rendered, truncated = _target(kind, target)
                value = dict(kind="dex_ref", dex=_identity((name,), 255),
                             from_class=_identity((method["class_descriptor"],)), from_method=_identity((method["name"],)),
                             from_prototype=_identity(_prototype_parts(method["prototype"])),
                             at=reference["offset"], ref_kind=kind, target=rendered, target_truncated=truncated)
                yield reference, value, artifact


TOOL = ToolSpec(ToolRef("dex", "0.1.0"), {
    "dex.classes": OperationSpec("dex.classes", {
        "member": ArgSpec("literal", 0, 255, default=""), "query": ArgSpec("literal", 0, 128, default=""),
        "class": ArgSpec("literal", 0, 255, default=""),
        "start": ArgSpec("int", 0, 1048575, default=0), "limit": ArgSpec("int", 1, 256, default=128),
    }, lambda data, args: _collect(_class_rows(data, args), args), max_observations=256),
    "dex.methods": OperationSpec("dex.methods", {
        "member": ArgSpec("literal", 0, 255, default=""), "class": ArgSpec("literal", 1, 255),
        "start": ArgSpec("int", 0, 65535, default=0), "limit": ArgSpec("int", 1, 256, default=128),
    }, _methods, max_observations=256),
    "dex.references": OperationSpec("dex.references", {
        "member": ArgSpec("literal", 0, 255, default=""), "class": ArgSpec("literal", 1, 255),
        "method": ArgSpec("literal", 1, 255), "prototype": ArgSpec("literal", 0, 255, default=""),
        "direction": ArgSpec("enum", choices=("from", "to"), default="from"),
        "start": ArgSpec("int", 0, 65535, default=0), "limit": ArgSpec("int", 1, 256, default=128),
    }, lambda data, args: _collect(_reference_rows(data, args), args), max_observations=256),
})
