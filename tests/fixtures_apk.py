"""Deterministic APK, binary Android manifest and DEX fixtures; no binary files.

apk_basic() builds a small Android package from declared values only, members in this order:

    AndroidManifest.xml   deflated binary XML: string pool, resource map, namespace and element chunks
    classes.dex           deflated; MainActivity, Marker and Helper
    classes2.dex          stored, data 4-aligned by zipalign's 0xd935 extra field; Worker
    resources.arsc        stored and 4-aligned; an empty resource table (header and string pool only)
    META-INF/MANIFEST.MF  deflated text

The manifest declares package org.reverseai.fixture, versionCode 7, versionName 1.0, uses-sdk 21 and 34,
the INTERNET and READ_CONTACTS permissions, an application labelled by the unresolved reference
@0x7f010000, activity .MainActivity exported and service .SyncService not exported. The DEX classes,
in smali terms (registers v0.., the parameters last):

    MainActivity extends Landroid/app/Activity; (source file MainActivity.java)
        <init>()V                       invoke-direct Activity.<init>()V
        helper(I)I                      invoke-static Helper.compute(II)I; sget, add, sput Marker.count:I
        helper(Ljava/lang/String;)I     invoke-virtual String.length()I
        onCreate(Landroid/os/Bundle;)V  invoke-super Activity.onCreate; const-string "ReverseAI marker";
                                        new-instance Marker; invoke-direct Marker.<init>(String);
                                        invoke-virtual helper(String), then helper(I)
    Marker                              static int count; final String label; <init>(String) iput-object label
    Helper                              static compute(II)I: add-int/2addr; return
    Worker implements Runnable          (classes2.dex) <init>()V; run()V invoke-static Helper.compute(2, 3)

Each builder returns (data, layout): the bytes and their declared structure (member offsets, sizes, CRCs
and child hashes; DEX tables, code items and instruction offsets inside the child; manifest chunks and
attribute records inside the child), so tests can state exact expectations. Deflated members use this
module's own fixed-Huffman encoder, so the bytes never depend on the host's zlib.

apk_hostile(kind) adds one problem to apk_basic() (HOSTILE_KINDS, with the member flags or the whole-
archive refusal the contract expects); dex_hostile(kind) breaks classes2.dex in one way
(DEX_HOSTILE_KINDS); apk_signing_block() is a clean variant with an APK signing block before the
central directory.
"""

from __future__ import annotations

import hashlib
import struct
import zlib

# ---- raw deflate: one fixed-Huffman block (RFC 1951 3.2.6) ----

_LENGTH_BASE = (3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195,
                227, 258)
_LENGTH_EXTRA = (0,) * 8 + (1,) * 4 + (2,) * 4 + (3,) * 4 + (4,) * 4 + (5,) * 4 + (0,)
_DISTANCE_BASE = (1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049,
                  3073, 4097, 6145, 8193, 12289, 16385, 24577)
_DISTANCE_EXTRA = (0, 0, 0, 0) + tuple(n for n in range(1, 14) for _ in (0, 1))


class _Bits:
    def __init__(self):
        self.out, self.value, self.count = bytearray(), 0, 0

    def put(self, value, count):
        """count bits of value, least significant first."""
        self.value |= value << self.count
        self.count += count
        while self.count >= 8:
            self.out.append(self.value & 0xFF)
            self.value >>= 8
            self.count -= 8

    def code(self, code, length):
        """A Huffman code, most significant bit first."""
        self.put(int(format(code, f"0{length}b")[::-1], 2), length)

    def symbol(self, symbol):
        """A literal/length symbol in the fixed code."""
        if symbol < 144:
            self.code(0x30 + symbol, 8)
        elif symbol < 256:
            self.code(0x190 + symbol - 144, 9)
        elif symbol < 280:
            self.code(symbol - 256, 7)
        else:
            self.code(0xC0 + symbol - 280, 8)

    def done(self):
        return bytes(self.out + (bytes([self.value]) if self.count else b""))


def _last(table, value):
    return max(index for index, base in enumerate(table) if base <= value)


def deflate(data) -> bytes:
    """Raw deflate in one fixed-Huffman block: greedy matches of 3..258 bytes at most 32 KiB back."""
    bits = _Bits()
    bits.put(0b011, 3)  # BFINAL 1, BTYPE 01
    heads = {}
    i, n = 0, len(data)
    while i < n:
        length = distance = 0
        for j in reversed(heads.get(data[i:i + 3], [])[-8:]):
            if i - j > 32768:
                break
            k = 0
            while k < 258 and i + k < n and data[j + k] == data[i + k]:
                k += 1
            if k > length:
                length, distance = k, i - j
        step = length if length >= 3 else 1
        if step == 1:
            bits.symbol(data[i])
        else:
            code = _last(_LENGTH_BASE, length)
            bits.symbol(257 + code)
            bits.put(length - _LENGTH_BASE[code], _LENGTH_EXTRA[code])
            code = _last(_DISTANCE_BASE, distance)
            bits.code(code, 5)
            bits.put(distance - _DISTANCE_BASE[code], _DISTANCE_EXTRA[code])
        for k in range(i, i + step):
            heads.setdefault(data[k:k + 3], []).append(k)
        i += step
    bits.symbol(256)
    return bits.done()


# ---- ZIP ----

LOCAL_HEADER, CENTRAL_HEADER, END_OF_CENTRAL, DATA_DESCRIPTOR = 0x04034B50, 0x02014B50, 0x06054B50, 0x08074B50
ZIP64_END, ZIP64_LOCATOR = 0x06064B50, 0x07064B50
DOS_TIME, DOS_DATE = 0x0000, 0x0221  # 1981-01-01 00:00:00, as reproducible Android builds
ALIGNMENT_EXTRA = 0xD935  # zipalign: u16 alignment, then zero padding
MADE_BY_DOS, MADE_BY_UNIX = 20, 0x0314
ENCRYPTED, HAS_DESCRIPTOR = 0x0001, 0x0008


def member(name, data, method=8, **options):
    """A zip_archive member: options crc32 (declared), flags, descriptor (overrides), align, made_by, external_attr."""
    return {"name": name, "data": bytes(data), "method": method, **options}


def zip_archive(members, *, prefix=b"", before_central=b"", disk=0, zip64=False, echo_end=False, cut_central=0):
    """(data, layout) of an archive of the members in order; the keywords build the whole-archive variants.

    method 8 deflates the child; any other method stores the child bytes under that method number. A member with
    `descriptor` has bit 3 set, zero CRC and sizes in its local header and a signed data descriptor after its data.
    cut_central drops that many bytes from the end of the central directory, the end record keeping the full size
    and count; echo_end makes the archive comment a second end record (comment length 0).
    """
    out = bytearray(prefix)
    rows = []
    for index, spec in enumerate(members):
        name, child, method = spec["name"].encode("utf-8"), spec["data"], spec["method"]
        payload = deflate(child) if method == 8 else child
        flags = spec.get("flags", 0) | (HAS_DESCRIPTOR if "descriptor" in spec else 0)
        sizes = (spec.get("crc32", zlib.crc32(child)), len(payload), len(child))
        needed = {0: 10, 8: 20}.get(method, 46)
        start = len(out)
        extra = b""
        if spec.get("align"):
            pad = -(start + 30 + len(name) + 6) % spec["align"]
            extra = struct.pack("<HHH", ALIGNMENT_EXTRA, 2 + pad, spec["align"]) + bytes(pad)
        out += struct.pack("<IHHHHHIIIHH", LOCAL_HEADER, needed, flags, method, DOS_TIME, DOS_DATE,
                           *((0, 0, 0) if flags & HAS_DESCRIPTOR else sizes), len(name), len(extra)) + name + extra
        row = {"index": index, "name": spec["name"], "method": method, "flags": flags, "crc32": sizes[0],
               "compressed_size": sizes[1], "size": sizes[2], "local_header_offset": start,
               "extra_length": len(extra), "data_offset": len(out), "child_crc32": zlib.crc32(child),
               "sha256": hashlib.sha256(child).hexdigest(), "descriptor": None}
        out += payload
        if flags & HAS_DESCRIPTOR:
            described = dict(zip(("crc32", "compressed_size", "size"), sizes), **spec["descriptor"])
            row["descriptor"] = {"offset": len(out), **described}
            out += struct.pack("<IIII", DATA_DESCRIPTOR, described["crc32"], described["compressed_size"],
                               described["size"])
        row["artifact"] = None if method not in (0, 8) else {
            "member": row["name"], "method": method, "data_offset": row["data_offset"],
            "compressed_size": sizes[1], "size": sizes[2], "crc32": sizes[0], "sha256": row["sha256"]}
        rows.append((row, spec, needed, name, sizes))
    out += before_central
    central = len(out)
    for row, spec, needed, name, sizes in rows:
        row["central_offset"] = len(out)
        out += struct.pack("<IHHHHHHIIIHHHHHII", CENTRAL_HEADER, spec.get("made_by", MADE_BY_DOS), needed, row["flags"],
                           row["method"], DOS_TIME, DOS_DATE, *sizes, len(name), 0, 0, 0, 0,
                           spec.get("external_attr", 0), row["local_header_offset"]) + name
        row["central_length"] = len(out) - row["central_offset"]
    size, count = len(out) - central, len(rows)
    del out[len(out) - cut_central:]
    zip64_end = None
    if zip64:
        zip64_end = len(out)
        out += struct.pack("<IQHHIIQQQQ", ZIP64_END, 44, 45, 45, 0, 0, count, count, size, central)
        out += struct.pack("<IIQI", ZIP64_LOCATOR, 0, zip64_end, 1)
    fields = (0xFFFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFF) if zip64 else (count, count, size, central)
    end = len(out)
    comment = struct.pack("<IHHHHIIH", END_OF_CENTRAL, disk, 0, *fields, 0) if echo_end else b""
    out += struct.pack("<IHHHHIIH", END_OF_CENTRAL, disk, 0, *fields, len(comment)) + comment
    data = bytes(out)
    return data, {
        "size": len(data), "sha256": hashlib.sha256(data).hexdigest(), "members": [row for row, *_ in rows],
        "central_directory": {"offset": central, "size": size, "entries": count, "present": size - cut_central},
        "end_of_central_directory": end, "zip64_end": zip64_end, "comment_length": len(comment),
    }


# ---- binary Android XML (frameworks/base ResourceTypes.h) ----

XML, STRING_POOL, TABLE = 0x0003, 0x0001, 0x0002
XML_START_NAMESPACE, XML_END_NAMESPACE, XML_START_ELEMENT, XML_END_ELEMENT = 0x0100, 0x0101, 0x0102, 0x0103
XML_RESOURCE_MAP = 0x0180
TYPE_REFERENCE, TYPE_STRING, TYPE_INT_DEC, TYPE_INT_BOOLEAN = 0x01, 0x03, 0x10, 0x12
UTF8_FLAG, NO_ENTRY = 0x100, 0xFFFFFFFF
ANDROID_NS = "http://schemas.android.com/apk/res/android"
ATTRIBUTE_IDS = {"label": 0x01010001, "name": 0x01010003, "exported": 0x01010010, "minSdkVersion": 0x0101020C,
                 "versionCode": 0x0101021B, "versionName": 0x0101021C, "targetSdkVersion": 0x01010270}
PACKAGE = "org.reverseai.fixture"
LABEL_REFERENCE = 0x7F010000
PERMISSIONS = ("android.permission.INTERNET", "android.permission.READ_CONTACTS")
# (tag, start line, end line, attributes (android namespace?, name, value), children); a tuple value is a reference
MANIFEST = ("manifest", 2, 10, ((True, "versionCode", 7), (True, "versionName", "1.0"), (False, "package", PACKAGE)), (
    ("uses-sdk", 3, 3, ((True, "minSdkVersion", 21), (True, "targetSdkVersion", 34)), ()),
    ("uses-permission", 4, 4, ((True, "name", PERMISSIONS[0]),), ()),
    ("uses-permission", 5, 5, ((True, "name", PERMISSIONS[1]),), ()),
    ("application", 6, 9, ((True, "label", ("reference", LABEL_REFERENCE)),), (
        ("activity", 7, 7, ((True, "name", ".MainActivity"), (True, "exported", True)), ()),
        ("service", 8, 8, ((True, "name", ".SyncService"), (True, "exported", False)), ()),
    )),
))


def _walk(element):
    yield element
    for child in element[4]:
        yield from _walk(child)


def _manifest_strings(manifest):
    """Attribute names with resource IDs first, in ID order (they index the resource map), then first use."""
    names = {name for element in _walk(manifest) for android, name, _ in element[3] if android}
    strings = sorted(names, key=ATTRIBUTE_IDS.__getitem__) + ["android", ANDROID_NS]
    for tag, _, _, attributes, _ in _walk(manifest):
        for text in [tag] + [text for _, name, value in attributes for text in (name, value) if isinstance(text, str)]:
            if text not in strings:
                strings.append(text)
    return strings


def _length8(n):
    return bytes([n]) if n < 0x80 else bytes([0x80 | n >> 8, n & 0xFF])


def _length16(n):
    return struct.pack("<H", n) if n < 0x8000 else struct.pack("<HH", 0x8000 | n >> 16, n & 0xFFFF)


def string_pool(strings, utf8=False):
    """(ResStringPool chunk, each string's offset inside the chunk); UTF-16LE unless utf8."""
    data, offsets = bytearray(), []
    for text in strings:
        offsets.append(len(data))
        if utf8:
            raw = text.encode("utf-8")
            data += _length8(len(text.encode("utf-16-le")) // 2) + _length8(len(raw)) + raw + b"\0"
        else:
            raw = text.encode("utf-16-le")
            data += _length16(len(raw) // 2) + raw + b"\0\0"
    data += bytes(-len(data) % 4)
    start = 28 + 4 * len(strings)
    header = struct.pack("<HHIIIIII", STRING_POOL, 28, start + len(data), len(strings), 0, UTF8_FLAG if utf8 else 0,
                         start, 0)
    return header + struct.pack(f"<{len(strings)}I", *offsets) + data, [start + offset for offset in offsets]


def _typed(value, index):
    """(raw value, data type, data, contract type, contract value)."""
    if isinstance(value, bool):
        return NO_ENTRY, TYPE_INT_BOOLEAN, 0xFFFFFFFF if value else 0, "bool", value
    if isinstance(value, int):
        return NO_ENTRY, TYPE_INT_DEC, value, "int", value
    if isinstance(value, tuple):
        return NO_ENTRY, TYPE_REFERENCE, value[1], "reference", f"@0x{value[1]:08x}"
    return index[value], TYPE_STRING, index[value], "string", value


def manifest_axml(utf8=False, manifest=MANIFEST):
    """(data, layout) of AndroidManifest.xml as aapt2 lays it out; the string pool is UTF-16LE unless utf8.

    manifest is a tree shaped like MANIFEST; its attribute names must be in ATTRIBUTE_IDS when android ones.
    """
    strings = _manifest_strings(manifest)
    index = {text: i for i, text in enumerate(strings)}
    pool, string_offsets = string_pool(strings, utf8)
    ids = [ATTRIBUTE_IDS[text] for text in strings if text in ATTRIBUTE_IDS]  # a prefix of the pool
    resource_map = struct.pack(f"<HHI{len(ids)}I", XML_RESOURCE_MAP, 8, 8 + 4 * len(ids), *ids)
    base = 8 + len(pool) + len(resource_map)
    body, chunks, elements, attributes = bytearray(), [], [], []

    def node(kind, line, payload):
        chunks.append({"type": kind, "offset": base + len(body), "size": 16 + len(payload), "line": line})
        body.extend(struct.pack("<HHIII", kind, 16, 16 + len(payload), line, NO_ENTRY) + payload)

    def element(spec, depth):
        tag, line, end_line, specs, children = spec
        record = {"index": len(elements), "name": tag, "depth": depth, "line": line, "offset": base + len(body),
                  "attributes": []}
        elements.append(record)
        payload = struct.pack("<IIHHHHHH", NO_ENTRY, index[tag], 20, 20, len(specs), 0, 0, 0)
        for position, (android, name, value) in enumerate(specs):
            raw, data_type, data, kind, shown = _typed(value, index)
            namespace = index[ANDROID_NS] if android else NO_ENTRY
            payload += struct.pack("<IIIHBBI", namespace, index[name], raw, 8, 0, data_type, data)
            attribute = {"index": len(attributes), "element_index": record["index"], "element": tag,
                         "attribute": f"android:{name}" if android else name, "type": kind, "value": shown,
                         "offset": record["offset"] + 36 + 20 * position, "length": 20, "namespace": namespace,
                         "name": index[name], "raw_value": raw, "data_type": data_type, "data": data}
            attributes.append(attribute)
            record["attributes"].append(attribute)
        node(XML_START_ELEMENT, line, payload)
        for child in children:
            element(child, depth + 1)
        record["end_offset"] = base + len(body)
        node(XML_END_ELEMENT, end_line, struct.pack("<II", NO_ENTRY, index[tag]))

    node(XML_START_NAMESPACE, manifest[1], struct.pack("<II", index["android"], index[ANDROID_NS]))
    element(manifest, 0)
    node(XML_END_NAMESPACE, manifest[2], struct.pack("<II", index["android"], index[ANDROID_NS]))
    data = struct.pack("<HHI", XML, 8, base + len(body)) + pool + resource_map + bytes(body)

    def by_tag(tag):
        return [e for e in elements if e["name"] == tag]

    def value(e, name):
        return next(a["value"] for a in e["attributes"] if a["attribute"] == name)
    return data, {
        "size": len(data), "sha256": hashlib.sha256(data).hexdigest(), "utf8": utf8,
        "string_pool": {"offset": 8, "size": len(pool), "count": len(strings), "strings_start": 28 + 4 * len(strings),
                        "strings": [{"index": i, "value": text, "offset": 8 + offset}
                                    for i, (text, offset) in enumerate(zip(strings, string_offsets))]},
        "resource_map": {"offset": 8 + len(pool), "size": len(resource_map), "ids": ids},
        "chunks": chunks, "elements": elements, "attributes": attributes,
        "package": value(elements[0], "package"), "version_code": value(elements[0], "android:versionCode"),
        "version_name": value(elements[0], "android:versionName"),
        "min_sdk": value(by_tag("uses-sdk")[0], "android:minSdkVersion"),
        "target_sdk": value(by_tag("uses-sdk")[0], "android:targetSdkVersion"),
        "permissions": sorted(value(e, "android:name") for e in by_tag("uses-permission")),
        "components": [{"element": e["name"], "name": value(e, "android:name"), "exported": value(e, "android:exported")}
                       for e in by_tag("activity") + by_tag("service")],
    }


# ---- DEX (source.android.com/docs/core/runtime/dex-format) ----

ENDIAN_CONSTANT, NO_INDEX = 0x12345678, 0xFFFFFFFF
ACC_PUBLIC, ACC_PROTECTED, ACC_STATIC, ACC_FINAL, ACC_CONSTRUCTOR = 0x1, 0x4, 0x8, 0x10, 0x10000
MAP_TYPES = {"header": 0x0000, "string_ids": 0x0001, "type_ids": 0x0002, "proto_ids": 0x0003, "field_ids": 0x0004,
             "method_ids": 0x0005, "class_defs": 0x0006, "map_list": 0x1000, "type_list": 0x1001,
             "class_data": 0x2000, "code": 0x2001, "string_data": 0x2002}
# The Dalvik instructions the fixtures use: name -> (opcode, format)
OPCODES = {"move-result": (0x0A, "11x"), "return-void": (0x0E, "10x"), "return": (0x0F, "11x"),
           "const/4": (0x12, "11n"), "const-string": (0x1A, "21c"), "new-instance": (0x22, "21c"),
           "iput-object": (0x5B, "22c"), "sget": (0x60, "21c"), "sput": (0x67, "21c"),
           "invoke-virtual": (0x6E, "35c"), "invoke-super": (0x6F, "35c"), "invoke-direct": (0x70, "35c"),
           "invoke-static": (0x71, "35c"), "add-int/2addr": (0xB0, "12x")}
REF_KINDS = ("method", "field", "string", "type")

MAIN, MARKER, HELPER, WORKER = (f"Lorg/reverseai/fixture/{name};" for name in ("MainActivity", "Marker", "Helper", "Worker"))
ACTIVITY, OBJECT, STRING = "Landroid/app/Activity;", "Ljava/lang/Object;", "Ljava/lang/String;"
BUNDLE, RUNNABLE = "Landroid/os/Bundle;", "Ljava/lang/Runnable;"
MARKER_TEXT = "ReverseAI marker"
COMPUTE = ("method", HELPER, "compute", "I", ("I", "I"))
COUNT, LABEL = ("field", MARKER, "count", "I"), ("field", MARKER, "label", STRING)


def _method(name, ret, params, access, registers, ins, outs, *code):
    return {"name": name, "ret": ret, "params": tuple(params), "access": access, "registers": registers, "ins": ins,
            "outs": outs, "code": code}


def _init(base):
    return _method("<init>", "V", (), ACC_PUBLIC | ACC_CONSTRUCTOR, 1, 1, 1,
                   ("invoke-direct", (0,), ("method", base, "<init>", "V", ())), ("return-void",))


CLASSES = (
    {"name": MAIN, "super": ACTIVITY, "access": ACC_PUBLIC, "source_file": "MainActivity.java",
     "direct": (_init(ACTIVITY),),
     "virtual": (
         _method("helper", "I", ("I",), ACC_PUBLIC, 4, 2, 2,
                 ("invoke-static", (3, 3), COMPUTE), ("move-result", 0), ("sget", 1, COUNT), ("add-int/2addr", 0, 1),
                 ("sput", 0, COUNT), ("return", 0)),
         _method("helper", "I", (STRING,), ACC_PUBLIC, 3, 2, 1,
                 ("invoke-virtual", (2,), ("method", STRING, "length", "I", ())), ("move-result", 0), ("return", 0)),
         _method("onCreate", "V", (BUNDLE,), ACC_PROTECTED, 4, 2, 2,
                 ("invoke-super", (2, 3), ("method", ACTIVITY, "onCreate", "V", (BUNDLE,))),
                 ("const-string", 0, ("string", MARKER_TEXT)),
                 ("new-instance", 1, ("type", MARKER)),
                 ("invoke-direct", (1, 0), ("method", MARKER, "<init>", "V", (STRING,))),
                 ("invoke-virtual", (2, 0), ("method", MAIN, "helper", "I", (STRING,))),
                 ("move-result", 0),
                 ("invoke-virtual", (2, 0), ("method", MAIN, "helper", "I", ("I",))),
                 ("return-void",)),
     )},
    {"name": MARKER, "super": OBJECT, "access": ACC_PUBLIC,
     "static_fields": (("count", "I", ACC_PUBLIC | ACC_STATIC),),
     "instance_fields": (("label", STRING, ACC_PUBLIC | ACC_FINAL),),
     "direct": (_method("<init>", "V", (STRING,), ACC_PUBLIC | ACC_CONSTRUCTOR, 2, 2, 1,
                        ("invoke-direct", (0,), ("method", OBJECT, "<init>", "V", ())), ("iput-object", 1, 0, LABEL),
                        ("return-void",)),)},
    {"name": HELPER, "super": OBJECT, "access": ACC_PUBLIC,
     "direct": (_method("compute", "I", ("I", "I"), ACC_PUBLIC | ACC_STATIC, 2, 2, 0,
                        ("add-int/2addr", 0, 1), ("return", 0)),)},
)
WORKER_CLASSES = (
    {"name": WORKER, "super": OBJECT, "access": ACC_PUBLIC, "interfaces": (RUNNABLE,),
     "direct": (_init(OBJECT),),
     "virtual": (_method("run", "V", (), ACC_PUBLIC, 3, 1, 2,
                         ("const/4", 0, 2), ("const/4", 1, 3), ("invoke-static", (0, 1), COMPUTE), ("move-result", 0),
                         ("return-void",)),)},
)


def uleb128(value):
    out = bytearray()
    while True:
        byte, value = value & 0x7F, value >> 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def mutf8(text):
    """(UTF-16 code units, MUTF-8 bytes): NUL as C0 80, supplementary characters as two 3-byte surrogates."""
    units = struct.unpack(f"<{len(text.encode('utf-16-le')) // 2}H", text.encode("utf-16-le"))
    out = bytearray()
    for unit in units:
        if 0 < unit < 0x80:
            out.append(unit)
        elif unit < 0x800:
            out += bytes((0xC0 | unit >> 6, 0x80 | unit & 0x3F))
        else:
            out += bytes((0xE0 | unit >> 12, 0x80 | unit >> 6 & 0x3F, 0x80 | unit & 0x3F))
    return len(units), bytes(out)


def _shorty(ret, params):
    return "".join(d[0] if d[0] in "VZBSCIJFD" else "L" for d in (ret, *params))


def prototype(ret, params):
    return f"({''.join(params)}){ret}"


def target(ref):
    """The contract's dex_ref target text of a reference."""
    if ref[0] == "method":
        return f"{ref[1]}->{ref[2]}{prototype(ref[3], ref[4])}"
    if ref[0] == "field":
        return f"{ref[1]}->{ref[2]}:{ref[3]}"
    return ref[1]


def _reference(instruction):
    last = instruction[-1]
    return last if isinstance(last, tuple) and last and last[0] in REF_KINDS else None


def _encode(instruction, index):
    op, form = OPCODES[instruction[0]]
    a = instruction[1] if len(instruction) > 1 else 0
    if form == "10x":
        return [op]
    if form == "11x":
        return [op | a << 8]
    if form == "11n":
        return [op | a << 8 | (instruction[2] & 0xF) << 12]
    if form == "12x":
        return [op | a << 8 | instruction[2] << 12]
    if form == "21c":
        return [op | a << 8, index(instruction[2])]
    if form == "22c":
        return [op | a << 8 | instruction[2] << 12, index(instruction[3])]
    c, d, e, f, g = (*a, 0, 0, 0, 0, 0)[:5]  # 35c: A|G|op, BBBB, F|E|D|C
    return [op | g << 8 | len(a) << 12, index(instruction[2]), c | d << 4 | e << 8 | f << 12]


def _seal(buffer):
    """Write the SHA-1 signature (bytes 32..) and then the Adler-32 checksum (bytes 12..) into a DEX buffer."""
    buffer[12:32] = hashlib.sha1(buffer[32:]).digest()
    struct.pack_into("<I", buffer, 8, zlib.adler32(buffer[12:]))


def dex_file(classes, version="035"):
    """(data, layout) of a DEX defining the class specs in order, with sorted id tables as the format requires."""
    strings, types, protos, fields, methods = set(), set(), set(), set(), set()

    def use(ref):
        if ref[0] == "string":
            strings.add(ref[1])
        elif ref[0] == "type":
            types.add(ref[1])
        elif ref[0] == "field":
            types.update((ref[1], ref[3]))
            strings.add(ref[2])
            fields.add(ref[1:])
        else:
            owner, name, ret, params = ref[1:]
            types.update((owner, ret, *params))
            strings.update((name, _shorty(ret, params)))
            protos.add((ret, params))
            methods.add(ref[1:])

    for spec in classes:
        types.update((spec["name"], spec["super"], *spec.get("interfaces", ())))
        if spec.get("source_file"):
            strings.add(spec["source_file"])
        for name, type_, _ in spec.get("static_fields", ()) + spec.get("instance_fields", ()):
            use(("field", spec["name"], name, type_))
        for method in spec.get("direct", ()) + spec.get("virtual", ()):
            use(("method", spec["name"], method["name"], method["ret"], method["params"]))
            for instruction in method["code"]:
                if _reference(instruction):
                    use(_reference(instruction))
    strings.update(types)

    string_list = sorted(strings, key=lambda text: text.encode("utf-16-be"))
    sidx = {text: i for i, text in enumerate(string_list)}
    type_list = sorted(types, key=sidx.__getitem__)
    tidx = {descriptor: i for i, descriptor in enumerate(type_list)}
    proto_list = sorted(protos, key=lambda p: (tidx[p[0]], [tidx[t] for t in p[1]]))
    pidx = {p: i for i, p in enumerate(proto_list)}
    field_list = sorted(fields, key=lambda f: (tidx[f[0]], sidx[f[1]], tidx[f[2]]))
    fidx = {f: i for i, f in enumerate(field_list)}
    method_list = sorted(methods, key=lambda m: (tidx[m[0]], sidx[m[1]], pidx[(m[2], m[3])]))
    midx = {m: i for i, m in enumerate(method_list)}

    def index(ref):
        return {"string": lambda: sidx[ref[1]], "type": lambda: tidx[ref[1]], "field": lambda: fidx[ref[1:]],
                "method": lambda: midx[ref[1:]]}[ref[0]]()

    counts = {"string_ids": len(string_list), "type_ids": len(type_list), "proto_ids": len(proto_list),
              "field_ids": len(field_list), "method_ids": len(method_list), "class_defs": len(classes)}
    widths = {"string_ids": 4, "type_ids": 4, "proto_ids": 12, "field_ids": 8, "method_ids": 8, "class_defs": 32}
    sections, at = {}, 0x70
    for name, count in counts.items():
        sections[name] = [count, at if count else 0]
        at += widths[name] * count
    data = bytearray(at)
    data_off = at

    def align():
        data.extend(bytes(-len(data) % 4))

    # code items, in class_data order: each class's direct then virtual methods by method index
    ordered, references, code_items = {}, [], []
    for spec in classes:
        rows = []
        for direct, group in ((True, spec.get("direct", ())), (False, spec.get("virtual", ()))):
            rows += sorted(((midx[(spec["name"], m["name"], m["ret"], m["params"])], direct, m) for m in group),
                           key=lambda row: row[0])
        ordered[spec["name"]] = rows
        for method_index, _, method in rows:
            if not method["code"]:  # abstract or native: code_off 0
                continue
            align()
            offset, units = len(data), []
            for instruction in method["code"]:
                ref = _reference(instruction)
                encoded = _encode(instruction, index)
                if ref:
                    references.append({"class": spec["name"], "method": method["name"],
                                       "prototype": prototype(method["ret"], method["params"]),
                                       "at": offset + 16 + 2 * len(units), "length": 2 * len(encoded),
                                       "opcode": instruction[0], "ref_kind": ref[0], "target": target(ref),
                                       "target_truncated": False, "pool_index": index(ref)})
                units += encoded
            data += struct.pack(f"<HHHHII{len(units)}H", method["registers"], method["ins"], method["outs"], 0, 0,
                                len(units), *units)
            code_items.append({"class": spec["name"], "method_index": method_index, "offset": offset,
                               "insns_offset": offset + 16, "code_units": len(units)})
    code_offsets = {item["method_index"]: item for item in code_items}

    lists = sorted({tuple(tidx[t] for t in p[1]) for p in proto_list if p[1]}
                   | {tuple(tidx[t] for t in spec["interfaces"]) for spec in classes if spec.get("interfaces")})
    list_offsets = {}
    for entries in lists:
        align()
        list_offsets[entries] = len(data)
        data += struct.pack(f"<I{len(entries)}H", len(entries), *entries)

    string_data = []
    for text in string_list:
        string_data.append(len(data))
        units, raw = mutf8(text)
        data += uleb128(units) + raw + b"\0"

    class_data = []  # offset per class, 0 for a class with no fields and no methods
    for spec in classes:
        statics = sorted((fidx[(spec["name"], n, t)], a) for n, t, a in spec.get("static_fields", ()))
        instances = sorted((fidx[(spec["name"], n, t)], a) for n, t, a in spec.get("instance_fields", ()))
        directs = [(i, m) for i, d, m in ordered[spec["name"]] if d]
        virtuals = [(i, m) for i, d, m in ordered[spec["name"]] if not d]
        class_data.append(len(data) if statics or instances or directs or virtuals else 0)
        if not class_data[-1]:
            continue
        data += b"".join(uleb128(len(group)) for group in (statics, instances, directs, virtuals))
        for group in (statics, instances):
            previous = 0
            for field_index, access in group:
                data += uleb128(field_index - previous) + uleb128(access)
                previous = field_index
        for group in (directs, virtuals):
            previous = 0
            for method_index, method in group:
                code = code_offsets.get(method_index)
                data += (uleb128(method_index - previous) + uleb128(method["access"])
                         + uleb128(code["offset"] if code else 0))
                previous = method_index

    align()
    map_off = len(data)
    items = [(MAP_TYPES["header"], 1, 0)] + [(MAP_TYPES[name], count, sections[name][1])
                                              for name, count in counts.items() if count]
    if code_items:
        items.append((MAP_TYPES["code"], len(code_items), code_items[0]["offset"]))
    if lists:
        items.append((MAP_TYPES["type_list"], len(lists), list_offsets[lists[0]]))
    items.append((MAP_TYPES["string_data"], len(string_data), string_data[0]))
    with_data = [offset for offset in class_data if offset]
    if with_data:
        items.append((MAP_TYPES["class_data"], len(with_data), with_data[0]))
    items.append((MAP_TYPES["map_list"], 1, map_off))
    data += struct.pack("<I", len(items)) + b"".join(struct.pack("<HHII", kind, 0, count, offset)
                                                     for kind, count, offset in items)

    for i, offset in enumerate(string_data):
        struct.pack_into("<I", data, sections["string_ids"][1] + 4 * i, offset)
    for i, descriptor in enumerate(type_list):
        struct.pack_into("<I", data, sections["type_ids"][1] + 4 * i, sidx[descriptor])
    for i, (ret, params) in enumerate(proto_list):
        struct.pack_into("<III", data, sections["proto_ids"][1] + 12 * i, sidx[_shorty(ret, params)], tidx[ret],
                         list_offsets[tuple(tidx[t] for t in params)] if params else 0)
    for i, (owner, name, type_) in enumerate(field_list):
        struct.pack_into("<HHI", data, sections["field_ids"][1] + 8 * i, tidx[owner], tidx[type_], sidx[name])
    for i, (owner, name, ret, params) in enumerate(method_list):
        struct.pack_into("<HHI", data, sections["method_ids"][1] + 8 * i, tidx[owner], pidx[(ret, params)], sidx[name])
    for i, spec in enumerate(classes):
        interfaces = tuple(tidx[t] for t in spec.get("interfaces", ()))
        struct.pack_into("<8I", data, sections["class_defs"][1] + 32 * i, tidx[spec["name"]], spec["access"],
                         tidx[spec["super"]], list_offsets[interfaces] if interfaces else 0,
                         sidx[spec["source_file"]] if spec.get("source_file") else NO_INDEX, 0, class_data[i], 0)
    header = [len(data), 0x70, ENDIAN_CONSTANT, 0, 0, map_off]
    for name in counts:
        header += sections[name]
    struct.pack_into("<8sI20s20I", data, 0, b"dex\n" + version.encode() + b"\0", 0, b"", *header,
                     len(data) - data_off, data_off)
    _seal(data)
    data = bytes(data)

    method_rows = {m: {"index": midx[m], "offset": sections["method_ids"][1] + 8 * midx[m], "class": m[0],
                       "name": m[1], "prototype": prototype(m[2], m[3])} for m in method_list}
    return data, {
        "version": version, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
        "checksum": struct.unpack_from("<I", data, 8)[0], "signature": data[12:32].hex(),
        "sections": {name: {"size": count, "offset": offset} for name, (count, offset) in sections.items()}
                    | {"data": {"size": len(data) - data_off, "offset": data_off}, "map": {"offset": map_off}},
        "map": [{"type": kind, "size": count, "offset": offset} for kind, count, offset in items],
        "strings": [{"index": i, "value": text, "id_offset": sections["string_ids"][1] + 4 * i,
                     "data_offset": string_data[i]} for i, text in enumerate(string_list)],
        "types": [{"index": i, "descriptor": d, "offset": sections["type_ids"][1] + 4 * i} for i, d in enumerate(type_list)],
        "protos": [{"index": i, "shorty": _shorty(r, p), "return": r, "parameters": list(p),
                    "offset": sections["proto_ids"][1] + 12 * i,
                    "parameters_offset": list_offsets[tuple(tidx[t] for t in p)] if p else 0}
                   for i, (r, p) in enumerate(proto_list)],
        "fields": [{"index": i, "class": o, "name": n, "type": t, "offset": sections["field_ids"][1] + 8 * i}
                   for i, (o, n, t) in enumerate(field_list)],
        "methods": [method_rows[m] for m in method_list],
        "classes": [{"index": i, "name": spec["name"], "offset": sections["class_defs"][1] + 32 * i,
                     "access": spec["access"], "superclass": spec["super"],
                     "interfaces": list(spec.get("interfaces", ())), "source_file": spec.get("source_file"),
                     "class_data_offset": class_data[i],
                     "fields": [{"name": n, "type": t, "access": a, "static": static,
                                 "field_index": fidx[(spec["name"], n, t)]}
                                for static, key in ((True, "static_fields"), (False, "instance_fields"))
                                for n, t, a in spec.get(key, ())],
                     "methods": [{**method_rows[(spec["name"], m["name"], m["ret"], m["params"])], "direct": direct,
                                  "access": m["access"], "registers": m["registers"], "ins": m["ins"], "outs": m["outs"],
                                  "code_offset": code_offsets[i_]["offset"] if i_ in code_offsets else None,
                                  "code_units": code_offsets[i_]["code_units"] if i_ in code_offsets else None}
                                 for i_, direct, m in ordered[spec["name"]]]}
                    for i, spec in enumerate(classes)],
        "code_items": code_items, "references": references,
    }


def classes_dex(version="035"):
    return dex_file(CLASSES, version)


def classes2_dex(version="035"):
    return dex_file(WORKER_CLASSES, version)


DEX_HOSTILE_KINDS = ("checksum", "version_040", "string_ids")


def dex_hostile(kind):
    """classes2.dex with one defect: a wrong checksum (signature right); version 040 (sealed); string_ids that run 4
    bytes past the end of the file, in the header and the map list (sealed)."""
    data, layout = classes2_dex()
    buffer = bytearray(data)
    anomaly = {"kind": kind}
    if kind == "checksum":
        struct.pack_into("<I", buffer, 8, layout["checksum"] ^ 1)
        anomaly["computed_checksum"] = layout["checksum"]
    elif kind == "version_040":
        buffer[4:7] = b"040"
        _seal(buffer)
    elif kind == "string_ids":  # header and map list agree on the larger count
        offset = layout["sections"]["string_ids"]["offset"]
        count = (len(buffer) - offset) // 4 + 1
        struct.pack_into("<I", buffer, 0x38, count)
        item = [row["type"] for row in layout["map"]].index(MAP_TYPES["string_ids"])
        struct.pack_into("<I", buffer, layout["sections"]["map"]["offset"] + 4 + 12 * item + 4, count)
        _seal(buffer)
        anomaly.update(string_ids_size=count, string_ids_end=offset + 4 * count, file_size=len(buffer))
    else:
        raise ValueError(kind)
    data = bytes(buffer)
    return data, {**layout, "version": data[4:7].decode(), "sha256": hashlib.sha256(data).hexdigest(),
                  "checksum": struct.unpack_from("<I", data, 8)[0], "signature": data[12:32].hex(), "anomaly": anomaly}


# ---- APK ----

JAR_MANIFEST = b"Manifest-Version: 1.0\r\nCreated-By: ReverseAI fixtures\r\n\r\n"
RESOURCES = (struct.pack("<HHII", TABLE, 12, 40, 0)
             + struct.pack("<HHIIIIII", STRING_POOL, 28, 28, 0, 0, UTF8_FLAG, 0, 0))
MAX_CHILD = 32 * 1024 * 1024
HOSTILE_TEXT = b"ReverseAI hostile fixture member\n" * 8
RATIO_ZEROS = 65536


def _noise(count):
    """count bytes that do not compress: a SHA-256 counter stream."""
    return b"".join(hashlib.sha256(i.to_bytes(4, "little")).digest() for i in range((count + 31) // 32))[:count]


HIGH_RATIO = bytes(RATIO_ZEROS) + _noise(256)  # deflates to a little under 100:1
PAST_RATIO = bytes(RATIO_ZEROS)  # about 157:1

# kind -> (flags the contract gives the anomalous member, whole archive refused)
HOSTILE_KINDS = {
    "crc": (["crc"], False), "unsupported_method": (["unsupported_method"], False),
    "duplicate_name": (["duplicate_name"], False), "traversing_name": (["traversing_name"], False),
    "encrypted": (["encrypted"], False), "descriptor_mismatch": (["header_mismatch"], False),
    "high_ratio": ([], False), "ratio": (["ratio"], False), "too_large": (["too_large"], False),
    "symlink": (["symlink"], False), "truncated_central": ([], False),
    "zip64": ([], True), "multi_disk": ([], True), "ambiguous_end": ([], True), "prefix": ([], True),
    "dex_checksum": ([], False), "dex_version_040": ([], False), "dex_string_ids": ([], False),
}
_EXTRA_MEMBER = {
    "crc": lambda: member("assets/hostile.txt", HOSTILE_TEXT, crc32=zlib.crc32(HOSTILE_TEXT) ^ 1),
    "unsupported_method": lambda: member("assets/hostile.txt", HOSTILE_TEXT, 12),
    "duplicate_name": lambda: member("classes.dex", classes2_dex()[0]),
    "traversing_name": lambda: member("../x", HOSTILE_TEXT),
    "encrypted": lambda: member("assets/hostile.txt", HOSTILE_TEXT, flags=ENCRYPTED),
    "descriptor_mismatch": lambda: member("assets/hostile.txt", HOSTILE_TEXT, descriptor={"size": len(HOSTILE_TEXT) + 1}),
    "high_ratio": lambda: member("assets/high_ratio.bin", HIGH_RATIO),
    "ratio": lambda: member("assets/past_ratio.bin", PAST_RATIO),
    "too_large": lambda: member("assets/large.bin", bytes(MAX_CHILD + 1), 0),
    "symlink": lambda: member("assets/link", b"classes.dex", 0, made_by=MADE_BY_UNIX, external_attr=0o120777 << 16),
}
_ARCHIVE = {"truncated_central": {"cut_central": 46}, "zip64": {"zip64": True}, "multi_disk": {"disk": 1},
            "ambiguous_end": {"echo_end": True},
            "prefix": {"prefix": b"ReverseAI: bytes before the first local header\n"}}


def _members(utf8=False, classes2=None):
    manifest, manifest_layout = manifest_axml(utf8)
    dex, dex_layout = classes_dex()
    dex2, dex2_layout = classes2 or classes2_dex()
    members = [member("AndroidManifest.xml", manifest), member("classes.dex", dex),
               member("classes2.dex", dex2, 0, align=4), member("resources.arsc", RESOURCES, 0, align=4),
               member("META-INF/MANIFEST.MF", JAR_MANIFEST)]
    return members, {"manifest": manifest_layout, "dex": {"classes.dex": dex_layout, "classes2.dex": dex2_layout}}


def apk_basic(utf8_manifest=False):
    """(data, layout) of the basic package: the ZIP layout plus "manifest" and "dex" (by member name) child layouts."""
    members, children = _members(utf8_manifest)
    data, layout = zip_archive(members)
    return data, {**layout, **children}


def apk_hostile(kind):
    """apk_basic() with one problem; layout["anomaly"] names the member and the contract's expected outcome.

    Member kinds append one member (index 5; duplicate_name repeats classes.dex with classes2.dex's bytes);
    truncated_central keeps 20 bytes of the last central entry; dex_* kinds replace classes2.dex by dex_hostile().
    """
    flags, refused = HOSTILE_KINDS[kind]
    members, children = _members(classes2=dex_hostile(kind[4:]) if kind.startswith("dex_") else None)
    if kind in _EXTRA_MEMBER:
        members.append(_EXTRA_MEMBER[kind]())
    data, layout = zip_archive(members, **_ARCHIVE.get(kind, {}))
    index = 5 if kind in _EXTRA_MEMBER else 2 if kind.startswith("dex_") else None
    anomaly = {"kind": kind, "member": index, "flags": flags, "refused": refused}
    if kind == "duplicate_name":
        anomaly["members"] = [1, 5]
    if kind == "truncated_central":
        anomaly["complete_entries"] = 4
    if kind in ("high_ratio", "ratio"):
        anomaly["ratio"] = layout["members"][5]["size"] / layout["members"][5]["compressed_size"]
    return data, {**layout, **children, "anomaly": anomaly}


def apk_signing_block():
    """apk_basic() with an APK signing block (one verity-padding pair, no signature) before the central directory."""
    members, children = _members()
    pairs = struct.pack("<QI", 4 + 8, 0x42726577) + bytes(8)
    size = len(pairs) + 8 + 16
    block = struct.pack("<Q", size) + pairs + struct.pack("<Q", size) + b"APK Sig Block 42"
    data, layout = zip_archive(members, before_central=block)
    offset = layout["central_directory"]["offset"] - len(block)
    return data, {**layout, **children, "signing_block": {"offset": offset, "size": len(block)}}
