"""The APK, manifest and DEX fixtures checked against their own declared layouts with readers written here,
zipfile and zlib, so the APK and DEX parsers can trust the layouts as expectations."""

import hashlib
import io
import random
import struct
import unittest
import zipfile
import zlib

from reverseai.contract import ContractError, materialize
from tests import fixtures_apk as F

# Pinned so a change of host zlib or Python cannot change the fixture bytes unnoticed.
BASIC_SHA256 = "cdf7349ac8ad5fcb98d232b76668d941d7cde7c5197fe93ff6dd8bcf88bf5c2f"


def u16(data, at):
    return struct.unpack_from("<H", data, at)[0]


def u32(data, at):
    return struct.unpack_from("<I", data, at)[0]


def uleb(data, at):
    value = shift = 0
    while True:
        byte = data[at]
        at += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if byte < 0x80:
            return value, at


def central_entries(data):
    """(end record, [(offset, fields, name)]) read from the single end record and the central directory it names."""
    end = data.rindex(struct.pack("<I", F.END_OF_CENTRAL))
    disk, cd_disk, on_disk, count, size, offset, comment = struct.unpack_from("<HHHHIIH", data, end + 4)
    entries, at = [], offset
    for _ in range(count):
        fields = struct.unpack_from("<IHHHHHHIIIHHHHHII", data, at)
        name = data[at + 46:at + 46 + fields[10]].decode()
        entries.append((at, fields, name))
        at += 46 + fields[10] + fields[11] + fields[12]
    assert at == offset + size
    return (end, disk, count, size, offset, comment), entries


class Dex:
    """A small independent DEX reader: header, id tables, class_data and code items."""

    NAMES = ("string_ids", "type_ids", "proto_ids", "field_ids", "method_ids", "class_defs", "data")

    def __init__(self, data):
        self.data = data
        fields = struct.unpack_from("<8sI20s20I", data, 0)
        self.magic, self.checksum, self.signature, self.file_size, self.header_size, self.endian = fields[:6]
        self.map_off = fields[8]
        self.sections = {name: (fields[9 + 2 * i], fields[10 + 2 * i]) for i, name in enumerate(self.NAMES)}

    def string(self, i):
        at = u32(self.data, self.sections["string_ids"][1] + 4 * i)
        units, at = uleb(self.data, at)
        end = self.data.index(b"\0", at)
        decoded, j = [], at
        while j < end:
            byte = self.data[j]
            if byte < 0x80:
                decoded.append(byte)
                j += 1
            elif byte >> 5 == 0b110:
                decoded.append((byte & 0x1F) << 6 | self.data[j + 1] & 0x3F)
                j += 2
            else:
                decoded.append((byte & 0x0F) << 12 | (self.data[j + 1] & 0x3F) << 6 | self.data[j + 2] & 0x3F)
                j += 3
        assert len(decoded) == units
        return struct.pack(f"<{units}H", *decoded).decode("utf-16-le", "surrogatepass")

    def type(self, i):
        return self.string(u32(self.data, self.sections["type_ids"][1] + 4 * i))

    def type_list(self, at):
        return [self.type(u16(self.data, at + 4 + 2 * k)) for k in range(u32(self.data, at))] if at else []

    def proto(self, i):
        shorty, ret, params = struct.unpack_from("<III", self.data, self.sections["proto_ids"][1] + 12 * i)
        return self.string(shorty), self.type(ret), self.type_list(params)

    def field(self, i):
        owner, type_, name = struct.unpack_from("<HHI", self.data, self.sections["field_ids"][1] + 8 * i)
        return f"{self.type(owner)}->{self.string(name)}:{self.type(type_)}"

    def method(self, i):
        owner, proto, name = struct.unpack_from("<HHI", self.data, self.sections["method_ids"][1] + 8 * i)
        _, ret, params = self.proto(proto)
        return self.type(owner), self.string(name), f"({''.join(params)}){ret}"

    def class_data(self, at):
        sizes = []
        for _ in range(4):
            value, at = uleb(self.data, at)
            sizes.append(value)
        groups = []
        for group, size in enumerate(sizes):
            rows, index = [], 0
            for _ in range(size):
                diff, at = uleb(self.data, at)
                access, at = uleb(self.data, at)
                index += diff
                code = None
                if group >= 2:
                    code, at = uleb(self.data, at)
                rows.append((index, access, code))
            groups.append(rows)
        return groups


# opcode -> (name, code units, reference kind), written independently of the builder's table
DALVIK = {0x0A: ("move-result", 1, None), 0x0E: ("return-void", 1, None), 0x0F: ("return", 1, None),
          0x12: ("const/4", 1, None), 0x1A: ("const-string", 2, "string"), 0x22: ("new-instance", 2, "type"),
          0x5B: ("iput-object", 2, "field"), 0x60: ("sget", 2, "field"), 0x67: ("sput", 2, "field"),
          0x6E: ("invoke-virtual", 3, "method"), 0x6F: ("invoke-super", 3, "method"),
          0x70: ("invoke-direct", 3, "method"), 0x71: ("invoke-static", 3, "method"), 0xB0: ("add-int/2addr", 1, None)}


def axml(data):
    """(strings, resource ids, elements) of a binary XML document read chunk by chunk."""
    kind, header, size = struct.unpack_from("<HHI", data, 0)
    assert (kind, header, size) == (F.XML, 8, len(data))
    pool_kind, pool_header, pool_size, count, styles, flags, start, styles_start = struct.unpack_from("<HHIIIIII", data, 8)
    assert (pool_kind, pool_header, styles, styles_start) == (F.STRING_POOL, 28, 0, 0)
    strings = []
    for k in range(count):
        at = 8 + start + u32(data, 36 + 4 * k)
        if flags & F.UTF8_FLAG:
            at += 1 if data[at] < 0x80 else 2
            length = data[at] if data[at] < 0x80 else (data[at] & 0x7F) << 8 | data[at + 1]
            at += 1 if data[at] < 0x80 else 2
            strings.append(data[at:at + length].decode("utf-8"))
            assert data[at + length] == 0
        else:
            length = u16(data, at)
            strings.append(data[at + 2:at + 2 + 2 * length].decode("utf-16-le"))
            assert u16(data, at + 2 + 2 * length) == 0
    at = 8 + pool_size
    map_kind, _, map_size = struct.unpack_from("<HHI", data, at)
    assert map_kind == F.XML_RESOURCE_MAP
    ids = list(struct.unpack_from(f"<{(map_size - 8) // 4}I", data, at + 8))
    at += map_size
    elements, stack, namespaces = [], [], []
    while at < len(data):
        kind, header, size, line, comment = struct.unpack_from("<HHIII", data, at)
        assert header == 16 and comment == F.NO_ENTRY
        if kind == F.XML_START_NAMESPACE:
            namespaces.append(struct.unpack_from("<II", data, at + 16))
        elif kind == F.XML_END_NAMESPACE:
            assert namespaces.pop() == struct.unpack_from("<II", data, at + 16)
        elif kind == F.XML_START_ELEMENT:
            ns, name, attr_start, attr_size, attr_count = struct.unpack_from("<IIHHH", data, at + 16)
            attributes = []
            for k in range(attr_count):
                offset = at + 16 + attr_start + k * attr_size
                a_ns, a_name, raw, value_size, res0, data_type, value = struct.unpack_from("<IIIHBBI", data, offset)
                assert (value_size, res0) == (8, 0)
                attributes.append({"offset": offset, "namespace": None if a_ns == F.NO_ENTRY else strings[a_ns],
                                   "name": strings[a_name], "raw": None if raw == F.NO_ENTRY else strings[raw],
                                   "data_type": data_type, "data": value})
            elements.append({"name": strings[name], "offset": at, "line": line, "depth": len(stack),
                             "attributes": attributes})
            stack.append(strings[name])
        elif kind == F.XML_END_ELEMENT:
            assert stack.pop() == strings[u32(data, at + 20)]
        else:
            raise AssertionError(kind)
        at += size
    assert at == len(data) and not stack and not namespaces
    return strings, ids, elements


class DeflateTests(unittest.TestCase):
    def test_zlib_inflates_the_encoder_output_exactly(self):
        rng = random.Random(7)
        cases = [b"", b"a", b"ab", b"abc" * 1000, bytes(70000), F.HIGH_RATIO, F.JAR_MANIFEST,
                 bytes(rng.randrange(256) for _ in range(5000)),
                 bytes(rng.randrange(4) for _ in range(40000))]
        chunk = bytes(rng.randrange(256) for _ in range(300))
        cases += [chunk + bytes(32768 - 300) + chunk, chunk + bytes(32769 - 300) + chunk]  # 32 KiB window edge
        for data in cases:
            with self.subTest(size=len(data)):
                inflater = zlib.decompressobj(-15)
                self.assertEqual(inflater.decompress(F.deflate(data)), data)
                self.assertTrue(inflater.eof)
                self.assertEqual(inflater.unused_data, b"")

    def test_ratio_members_sit_on_each_side_of_the_limit(self):
        high, past = len(F.deflate(F.HIGH_RATIO)), len(F.deflate(F.PAST_RATIO))
        self.assertTrue(90 * high < len(F.HIGH_RATIO) <= 100 * high)
        self.assertGreater(len(F.PAST_RATIO), 150 * past)


class ApkBasicTests(unittest.TestCase):
    def setUp(self):
        self.data, self.layout = F.apk_basic()

    def test_deterministic_and_pinned(self):
        self.assertEqual(F.apk_basic(), (self.data, self.layout))
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), self.layout["sha256"])
        self.assertEqual(self.layout["sha256"], BASIC_SHA256)

    def test_zipfile_agrees_with_the_layout(self):
        archive = zipfile.ZipFile(io.BytesIO(self.data))
        self.assertIsNone(archive.testzip())
        infos = archive.infolist()
        self.assertEqual([i.filename for i in infos], ["AndroidManifest.xml", "classes.dex", "classes2.dex",
                                                       "resources.arsc", "META-INF/MANIFEST.MF"])
        children = {"AndroidManifest.xml": F.manifest_axml()[0], "classes.dex": F.classes_dex()[0],
                    "classes2.dex": F.classes2_dex()[0], "resources.arsc": F.RESOURCES,
                    "META-INF/MANIFEST.MF": F.JAR_MANIFEST}
        for info, row in zip(infos, self.layout["members"]):
            with self.subTest(member=row["name"]):
                child = archive.read(info)
                self.assertEqual(child, children[row["name"]])
                self.assertEqual((info.compress_type, info.CRC, info.compress_size, info.file_size, info.header_offset),
                                 (row["method"], row["crc32"], row["compressed_size"], row["size"],
                                  row["local_header_offset"]))
                self.assertEqual((row["child_crc32"], row["sha256"]), (zlib.crc32(child), hashlib.sha256(child).hexdigest()))
                self.assertEqual(materialize(self.data, row["artifact"]), child)
        self.assertEqual([row["method"] for row in self.layout["members"]], [8, 8, 0, 0, 8])

    def test_headers_agree_with_the_layout_and_stay_inside_the_limits(self):
        (end, disk, count, size, offset, comment), entries = central_entries(self.data)
        self.assertEqual((end, disk, count, size, offset, comment, end + 22),
                         (self.layout["end_of_central_directory"], 0, 5, self.layout["central_directory"]["size"],
                          self.layout["central_directory"]["offset"], 0, len(self.data)))
        previous_end = 0
        for (at, fields, name), row in zip(entries, self.layout["members"]):
            with self.subTest(member=name):
                self.assertEqual((at, 46 + len(name), name), (row["central_offset"], row["central_length"], row["name"]))
                self.assertEqual(fields[3:10], (0, row["method"], F.DOS_TIME, F.DOS_DATE, row["crc32"],
                                                row["compressed_size"], row["size"]))
                self.assertEqual(fields[16], row["local_header_offset"])
                local = struct.unpack_from("<IHHHHHIIIHH", self.data, row["local_header_offset"])
                self.assertEqual(local[0], F.LOCAL_HEADER)
                self.assertEqual(local[2:9], fields[3:10])
                start = row["local_header_offset"] + 30
                self.assertEqual(self.data[start:start + local[9]].decode(), name)
                self.assertEqual((local[10], start + local[9] + local[10]), (row["extra_length"], row["data_offset"]))
                self.assertEqual(row["local_header_offset"], previous_end)  # contiguous, no gaps or overlaps
                previous_end = row["data_offset"] + row["compressed_size"]
                if row["method"] == 0:
                    self.assertEqual(row["data_offset"] % 4, 0)
                    self.assertEqual(struct.unpack_from("<HHH", self.data, start + local[9])[::2], (F.ALIGNMENT_EXTRA, 4))
                self.assertLessEqual(row["size"], F.MAX_CHILD)
                self.assertLessEqual(row["size"], 100 * max(row["compressed_size"], 1))
        self.assertEqual(previous_end, offset)

    def test_utf8_manifest_variant_differs_only_in_the_manifest(self):
        data, layout = F.apk_basic(utf8_manifest=True)
        self.assertTrue(layout["manifest"]["utf8"])
        self.assertEqual([r["sha256"] for r in layout["members"]][1:], [r["sha256"] for r in self.layout["members"]][1:])
        self.assertEqual(zipfile.ZipFile(io.BytesIO(data)).read("AndroidManifest.xml"), F.manifest_axml(True)[0])


class ManifestTests(unittest.TestCase):
    def test_both_encodings_decode_to_the_declared_layout(self):
        for utf8 in (False, True):
            data, layout = F.manifest_axml(utf8)
            with self.subTest(utf8=utf8):
                self.assertEqual((layout["size"], layout["sha256"]), (len(data), hashlib.sha256(data).hexdigest()))
                strings, ids, elements = axml(data)
                self.assertEqual(strings, [s["value"] for s in layout["string_pool"]["strings"]])
                self.assertEqual(u32(data, 8 + 16) & F.UTF8_FLAG, F.UTF8_FLAG if utf8 else 0)
                self.assertEqual(ids, layout["resource_map"]["ids"])
                self.assertEqual(ids, [F.ATTRIBUTE_IDS[s] for s in strings[:len(ids)]])  # names with IDs come first
                self.assertEqual([(e["name"], e["offset"], e["line"], e["depth"]) for e in elements],
                                 [(e["name"], e["offset"], e["line"], e["depth"]) for e in layout["elements"]])
                flat = [(i, e["name"], a) for i, e in enumerate(elements) for a in e["attributes"]]
                self.assertEqual(len(flat), len(layout["attributes"]))
                for (i, tag, read), declared in zip(flat, layout["attributes"]):
                    self.assertEqual((i, tag, read["offset"], read["data_type"], read["data"]),
                                     (declared["element_index"], declared["element"], declared["offset"],
                                      declared["data_type"], declared["data"]))
                    android = read["namespace"] == F.ANDROID_NS
                    self.assertEqual(("android:" if android else "") + read["name"], declared["attribute"])
                    if read["data_type"] == F.TYPE_STRING:
                        self.assertEqual((declared["type"], read["raw"], strings[read["data"]]),
                                         ("string", declared["value"], declared["value"]))
                    else:
                        self.assertIsNone(read["raw"])
                        shown = {F.TYPE_INT_DEC: ("int", read["data"]),
                                 F.TYPE_INT_BOOLEAN: ("bool", read["data"] == 0xFFFFFFFF),
                                 F.TYPE_REFERENCE: ("reference", f"@0x{read['data']:08x}")}[read["data_type"]]
                        self.assertEqual((declared["type"], declared["value"]), shown)
                    self.assertEqual(data[declared["offset"]:declared["offset"] + 20],
                                     struct.pack("<IIIHBBI", declared["namespace"], declared["name"],
                                                 declared["raw_value"], 8, 0, declared["data_type"], declared["data"]))

    def test_declared_semantics(self):
        data, layout = F.manifest_axml()
        _, _, elements = axml(data)

        def attribute(element, name):
            return next(a for a in element["attributes"] if a["name"] == name)

        manifest = elements[0]
        self.assertEqual((attribute(manifest, "package")["raw"], attribute(manifest, "versionCode")["data"],
                          attribute(manifest, "versionName")["raw"]), ("org.reverseai.fixture", 7, "1.0"))
        sdk = next(e for e in elements if e["name"] == "uses-sdk")
        self.assertEqual((attribute(sdk, "minSdkVersion")["data"], attribute(sdk, "targetSdkVersion")["data"]), (21, 34))
        self.assertEqual(sorted(attribute(e, "name")["raw"] for e in elements if e["name"] == "uses-permission"),
                         layout["permissions"])
        self.assertEqual(layout["permissions"], ["android.permission.INTERNET", "android.permission.READ_CONTACTS"])
        self.assertEqual([(e["name"], attribute(e, "name")["raw"], attribute(e, "exported")["data"])
                          for e in elements if e["name"] in ("activity", "service")],
                         [("activity", ".MainActivity", 0xFFFFFFFF), ("service", ".SyncService", 0)])
        self.assertEqual(layout["components"], [{"element": "activity", "name": ".MainActivity", "exported": True},
                                                {"element": "service", "name": ".SyncService", "exported": False}])
        self.assertEqual((layout["package"], layout["version_code"], layout["version_name"], layout["min_sdk"],
                          layout["target_sdk"]), ("org.reverseai.fixture", 7, "1.0", 21, 34))
        self.assertEqual([c["type"] for c in layout["chunks"]][:1] + [c["type"] for c in layout["chunks"]][-1:],
                         [F.XML_START_NAMESPACE, F.XML_END_NAMESPACE])
        self.assertEqual(sum(c["size"] for c in layout["chunks"]) + layout["string_pool"]["size"]
                         + layout["resource_map"]["size"] + 8, len(data))


class DexTests(unittest.TestCase):
    def check(self, data, layout):
        dex = Dex(data)
        self.assertEqual(dex.magic, b"dex\n" + layout["version"].encode() + b"\0")
        self.assertEqual((dex.checksum, dex.signature.hex()), (layout["checksum"], layout["signature"]))
        self.assertEqual(dex.checksum, zlib.adler32(data[12:]))
        self.assertEqual(dex.signature, hashlib.sha1(data[32:]).digest())
        self.assertEqual((dex.file_size, dex.header_size, dex.endian, dex.file_size % 4), (len(data), 0x70, F.ENDIAN_CONSTANT, 0))
        for name, (size, offset) in dex.sections.items():
            self.assertEqual((size, offset), (layout["sections"][name]["size"], layout["sections"][name]["offset"]))
        data_size, data_off = dex.sections["data"]
        self.assertEqual(data_off + data_size, len(data))
        # map list: sorted by offset, one item per section, counts equal the header's
        count = u32(data, dex.map_off)
        items = [struct.unpack_from("<HHII", data, dex.map_off + 4 + 12 * k) for k in range(count)]
        self.assertEqual([(t, n, o) for t, _, n, o in items], [(m["type"], m["size"], m["offset"]) for m in layout["map"]])
        self.assertEqual([o for *_, o in items], sorted(o for *_, o in items))
        by_type = {t: (n, o) for t, _, n, o in items}
        for name in Dex.NAMES[:-1]:
            if dex.sections[name][0]:
                self.assertEqual(by_type[F.MAP_TYPES[name]], dex.sections[name])
        self.assertEqual(by_type[F.MAP_TYPES["map_list"]], (1, dex.map_off))
        for kind, offsets in (("class_data", [c["class_data_offset"] for c in layout["classes"] if c["class_data_offset"]]),
                              ("code", [item["offset"] for item in layout["code_items"]])):
            self.assertEqual(by_type.get(F.MAP_TYPES[kind]), (len(offsets), min(offsets)) if offsets else None)
        # id tables: decoded equal to the layout and in the order the format requires
        strings = [dex.string(i) for i in range(dex.sections["string_ids"][0])]
        self.assertEqual(strings, [s["value"] for s in layout["strings"]])
        self.assertEqual(strings, sorted(strings, key=lambda s: s.encode("utf-16-be")))
        for row in layout["strings"]:
            self.assertEqual(u32(data, row["id_offset"]), row["data_offset"])
        types = [dex.type(i) for i in range(dex.sections["type_ids"][0])]
        self.assertEqual(types, [t["descriptor"] for t in layout["types"]])
        type_index = [strings.index(t) for t in types]
        self.assertEqual(type_index, sorted(type_index))
        protos = [dex.proto(i) for i in range(dex.sections["proto_ids"][0])]
        self.assertEqual(protos, [(p["shorty"], p["return"], p["parameters"]) for p in layout["protos"]])
        keys = [(types.index(r), [types.index(t) for t in ps]) for _, r, ps in protos]
        self.assertEqual(keys, sorted(keys))
        fields = [dex.field(i) for i in range(dex.sections["field_ids"][0])]
        self.assertEqual(fields, [f"{f['class']}->{f['name']}:{f['type']}" for f in layout["fields"]])
        methods = [dex.method(i) for i in range(dex.sections["method_ids"][0])]
        self.assertEqual(methods, [(m["class"], m["name"], m["prototype"]) for m in layout["methods"]])
        method_keys = [struct.unpack_from("<HHI", data, m["offset"]) for m in layout["methods"]]
        self.assertEqual([(c, n, p) for c, p, n in method_keys], sorted((c, n, p) for c, p, n in method_keys))
        # classes: class_def items, class_data and code items; every reference found by walking the code
        found = []
        for row in layout["classes"]:
            fields_ = struct.unpack_from("<8I", data, row["offset"])
            self.assertEqual(types[fields_[0]], row["name"])
            self.assertEqual((fields_[1], types[fields_[2]], dex.type_list(fields_[3])), (row["access"], row["superclass"], row["interfaces"]))
            self.assertEqual(None if fields_[4] == F.NO_INDEX else strings[fields_[4]], row["source_file"])
            self.assertEqual((fields_[5], fields_[6], fields_[7]), (0, row["class_data_offset"], 0))
            statics, instances, directs, virtuals = (dex.class_data(row["class_data_offset"])
                                                     if row["class_data_offset"] else ([], [], [], []))
            self.assertEqual([(i, a) for i, a, _ in statics + instances],
                             [(f["field_index"], f["access"]) for f in row["fields"]])
            listed = [(i, a, c, d) for d, group in ((True, directs), (False, virtuals)) for i, a, c in group]
            self.assertEqual(listed, [(m["index"], m["access"], m["code_offset"] or 0, m["direct"]) for m in row["methods"]])
            for method in row["methods"]:
                if method["code_offset"] is None:  # abstract or native
                    self.assertEqual((method["code_units"], method["access"] & 0x500 != 0), (None, True))
                    continue
                registers, ins, outs, tries, debug, units = struct.unpack_from("<HHHHII", data, method["code_offset"])
                self.assertEqual((registers, ins, outs, tries, debug, units, method["code_offset"] % 4),
                                 (method["registers"], method["ins"], method["outs"], 0, 0, method["code_units"], 0))
                at, end = method["code_offset"] + 16, method["code_offset"] + 16 + 2 * units
                while at < end:
                    name, width, kind = DALVIK[data[at]]
                    if kind:
                        index = u16(data, at + 2)
                        text = {"string": lambda: strings[index], "type": lambda: types[index],
                                "field": lambda: fields[index],
                                "method": lambda: "{}->{}{}".format(*methods[index])}[kind]()
                        found.append({"class": row["name"], "method": method["name"], "prototype": method["prototype"],
                                      "at": at, "length": 2 * width, "opcode": name, "ref_kind": kind,
                                      "target": text, "target_truncated": False, "pool_index": index})
                    at += 2 * width
                self.assertEqual(at, end)
        self.assertEqual(found, layout["references"])
        return dex

    def test_both_dex_files_read_back_exactly(self):
        for build in (F.classes_dex, F.classes2_dex):
            for version in ("035", "037", "038", "039"):
                data, layout = build(version)
                with self.subTest(build=build.__name__, version=version):
                    self.assertEqual((layout["size"], layout["sha256"]), (len(data), hashlib.sha256(data).hexdigest()))
                    self.check(data, layout)

    def test_classes_dex_declares_the_scoped_program(self):
        _, layout = F.classes_dex()
        self.assertEqual([c["name"] for c in layout["classes"]], [F.MAIN, F.MARKER, F.HELPER])
        main = layout["classes"][0]
        self.assertEqual([(m["name"], m["prototype"], m["direct"]) for m in main["methods"]],
                         [("<init>", "()V", True), ("helper", "(I)I", False),
                          ("helper", "(Ljava/lang/String;)I", False), ("onCreate", "(Landroid/os/Bundle;)V", False)])
        refs = [(r["method"], r["prototype"], r["opcode"], r["target"]) for r in layout["references"]]
        self.assertIn(("helper", "(I)I", "invoke-static", "Lorg/reverseai/fixture/Helper;->compute(II)I"), refs)
        self.assertIn(("helper", "(I)I", "sget", "Lorg/reverseai/fixture/Marker;->count:I"), refs)
        self.assertIn(("helper", "(I)I", "sput", "Lorg/reverseai/fixture/Marker;->count:I"), refs)
        self.assertIn(("onCreate", "(Landroid/os/Bundle;)V", "const-string", "ReverseAI marker"), refs)
        self.assertIn(("onCreate", "(Landroid/os/Bundle;)V", "invoke-virtual",
                       "Lorg/reverseai/fixture/MainActivity;->helper(Ljava/lang/String;)I"), refs)
        self.assertIn(("onCreate", "(Landroid/os/Bundle;)V", "new-instance", F.MARKER), refs)
        self.assertEqual({r["ref_kind"] for r in layout["references"]}, {"method", "field", "string", "type"})
        _, layout2 = F.classes2_dex()
        self.assertEqual([(c["name"], c["interfaces"]) for c in layout2["classes"]], [(F.WORKER, [F.RUNNABLE])])
        self.assertEqual([(r["method"], r["target"]) for r in layout2["references"] if r["opcode"] == "invoke-static"],
                         [("run", "Lorg/reverseai/fixture/Helper;->compute(II)I")])

    def test_a_dex_without_code_items_or_class_data(self):
        # dex_file builds a valid DEX when no method has code (an interface with an abstract method, a class
        # with a static field only, and an empty class with no class_data).
        from reverseai.tools import dex as tool
        classes = ({"name": "La/Api;", "super": F.OBJECT, "access": 0x601,
                    "virtual": (F._method("call", "I", (F.STRING,), 0x401, 0, 0, 0),)},
                   {"name": "La/Constants;", "super": F.OBJECT, "access": 0x11,
                    "static_fields": (("LIMIT", "I", 0x19),)},
                   {"name": "La/Empty;", "super": F.OBJECT, "access": 0x1})
        data, layout = F.dex_file(classes)
        self.check(data, layout)
        self.assertNotIn(F.MAP_TYPES["code"], [row["type"] for row in layout["map"]])
        self.assertEqual([c["class_data_offset"] == 0 for c in layout["classes"]], [False, False, True])
        self.assertEqual(layout["classes"][0]["methods"][0]["code_offset"], None)
        parsed = tool.parse(data)
        self.assertEqual([c["class_descriptor"] for c in parsed["classes"]], ["La/Api;", "La/Constants;", "La/Empty;"])
        self.assertEqual(parsed["classes"][0]["class_data"]["virtual_methods"][0]["code_off"], 0)
        self.assertIsNone(parsed["classes"][2]["class_data"])
        data, layout = F.dex_file(classes[1:])  # no method at all (formerly an IndexError)
        self.check(data, layout)
        self.assertEqual(len(tool.parse(data)["methods"]), 0)

    def test_mutf8_and_uleb128(self):
        self.assertEqual(F.mutf8("a\0\u00e9\u20ac\U0001F600"),
                         (6, b"a\xc0\x80\xc3\xa9\xe2\x82\xac\xed\xa0\xbd\xed\xb8\x80"))
        for value in (0, 1, 127, 128, 16383, 16384, 2 ** 32 - 1):
            self.assertEqual(uleb(F.uleb128(value), 0), (value, len(F.uleb128(value))))

    def test_hostile_dex_files_have_exactly_one_defect(self):
        clean, clean_layout = F.classes2_dex()
        for kind in F.DEX_HOSTILE_KINDS:
            data, layout = F.dex_hostile(kind)
            with self.subTest(kind=kind):
                dex = Dex(data)
                self.assertEqual(layout["anomaly"]["kind"], kind)
                self.assertEqual(len(data), len(clean))
                self.assertEqual(dex.signature, hashlib.sha1(data[32:]).digest())
                checksum_right = dex.checksum == zlib.adler32(data[12:])
                self.assertEqual(checksum_right, kind != "checksum")
                self.assertEqual(dex.magic[4:7], b"040" if kind == "version_040" else b"035")
                size, offset = dex.sections["string_ids"]
                self.assertEqual(offset + 4 * size > len(data), kind == "string_ids")
                if kind == "string_ids":
                    self.assertEqual((size, offset + 4 * size - len(data)), (layout["anomaly"]["string_ids_size"], 4))
                    self.assertIn((F.MAP_TYPES["string_ids"], 0, size, offset),
                                  [struct.unpack_from("<HHII", data, dex.map_off + 4 + 12 * k)
                                   for k in range(u32(data, dex.map_off))])
                changed = [i for i in range(len(data)) if data[i] != clean[i]]
                allowed = set(range(4, 7)) | set(range(8, 32)) | set(range(0x38, 0x3C))
                if kind == "string_ids":
                    allowed |= set(range(dex.map_off + 4, dex.map_off + 4 + 12 * u32(data, dex.map_off)))
                self.assertTrue(set(changed) <= allowed)


class HostileApkTests(unittest.TestCase):
    def test_every_kind_differs_from_basic_by_its_one_problem(self):
        basic, basic_layout = F.apk_basic()
        for kind, (flags, refused) in F.HOSTILE_KINDS.items():
            data, layout = F.apk_hostile(kind)
            anomaly = layout["anomaly"]
            with self.subTest(kind=kind):
                self.assertEqual((anomaly["kind"], anomaly["flags"], anomaly["refused"]), (kind, flags, refused))
                self.assertEqual(layout["sha256"], hashlib.sha256(data).hexdigest())
                rows = layout["members"]
                if anomaly["member"] == 5:
                    self.assertEqual(len(rows), 6)
                    self.assertEqual([r["sha256"] for r in rows[:5]], [r["sha256"] for r in basic_layout["members"]])
                    self.assertEqual(data[:rows[5]["local_header_offset"]], basic[:basic_layout["central_directory"]["offset"]])

    def entry(self, kind, index=5):
        data, layout = F.apk_hostile(kind)
        row = layout["members"][index]
        local = struct.unpack_from("<IHHHHHIIIHH", data, row["local_header_offset"])
        central = struct.unpack_from("<IHHHHHHIIIHHHHHII", data, row["central_offset"])
        return data, layout, row, local, central

    def test_member_problems_are_in_the_bytes(self):
        data, layout, row, local, central = self.entry("crc")
        self.assertEqual(local[6], central[7])
        self.assertNotEqual(central[7], zlib.crc32(F.HOSTILE_TEXT))
        with self.assertRaises(zipfile.BadZipFile):
            zipfile.ZipFile(io.BytesIO(data)).read("assets/hostile.txt")
        with self.assertRaisesRegex(ContractError, "does not match"):
            materialize(data, row["artifact"])

        data, layout, row, local, central = self.entry("unsupported_method")
        self.assertEqual((local[3], central[4], row["artifact"]), (12, 12, None))
        self.assertEqual(data[row["data_offset"]:row["data_offset"] + row["compressed_size"]], F.HOSTILE_TEXT)

        data, layout, row, local, central = self.entry("duplicate_name")
        names = zipfile.ZipFile(io.BytesIO(data)).namelist()
        self.assertEqual([i for i, n in enumerate(names) if n == "classes.dex"], layout["anomaly"]["members"])
        self.assertNotEqual(layout["members"][1]["sha256"], row["sha256"])

        data, layout, row, local, central = self.entry("traversing_name")
        self.assertEqual(zipfile.ZipFile(io.BytesIO(data)).namelist()[5], "../x")

        data, layout, row, local, central = self.entry("encrypted")
        self.assertEqual((local[2] & 1, central[3] & 1), (1, 1))
        with self.assertRaises(RuntimeError):
            zipfile.ZipFile(io.BytesIO(data)).read("assets/hostile.txt")

        data, layout, row, local, central = self.entry("descriptor_mismatch")
        self.assertEqual((local[2] & 8, local[6:9]), (8, (0, 0, 0)))
        descriptor = struct.unpack_from("<IIII", data, row["descriptor"]["offset"])
        self.assertEqual(descriptor, (F.DATA_DESCRIPTOR, central[7], central[8], central[9] + 1))
        self.assertEqual(row["descriptor"]["offset"], row["data_offset"] + row["compressed_size"])

        data, layout, row, local, central = self.entry("high_ratio")
        self.assertEqual(materialize(data, row["artifact"]), F.HIGH_RATIO)
        self.assertLessEqual(layout["anomaly"]["ratio"], 100)
        data, layout, row, local, central = self.entry("ratio")
        self.assertEqual(zipfile.ZipFile(io.BytesIO(data)).read("assets/past_ratio.bin"), F.PAST_RATIO)
        self.assertGreater(layout["anomaly"]["ratio"], 100)
        with self.assertRaisesRegex(ContractError, "ratio"):
            materialize(data, row["artifact"])

        data, layout, row, local, central = self.entry("too_large")
        self.assertEqual((row["method"], row["size"], row["compressed_size"]), (0, F.MAX_CHILD + 1, F.MAX_CHILD + 1))

        data, layout, row, local, central = self.entry("symlink")
        self.assertEqual((central[1] >> 8, central[15] >> 16 & 0o170000), (3, 0o120000))
        self.assertEqual(zipfile.ZipFile(io.BytesIO(data)).read("assets/link"), b"classes.dex")

    def test_archive_problems_are_in_the_bytes(self):
        data, layout = F.apk_hostile("truncated_central")
        end = layout["end_of_central_directory"]
        cd = layout["central_directory"]
        self.assertEqual((u16(data, end + 10), u32(data, end + 12), u32(data, end + 16)), (5, cd["size"], cd["offset"]))
        self.assertEqual((cd["offset"] + cd["present"], cd["size"] - cd["present"]), (end, 46))
        at, complete = cd["offset"], 0
        while at + 46 <= end and u32(data, at) == F.CENTRAL_HEADER:
            at += 46 + u16(data, at + 28)
            complete += 1
        self.assertEqual((complete, end - at), (layout["anomaly"]["complete_entries"], 20))
        with self.assertRaises(zipfile.BadZipFile):
            zipfile.ZipFile(io.BytesIO(data))

        data, layout = F.apk_hostile("zip64")
        end, record = layout["end_of_central_directory"], layout["zip64_end"]
        self.assertEqual(struct.unpack_from("<HHHHII", data, end + 4), (0, 0, 0xFFFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFF))
        self.assertEqual(struct.unpack_from("<IIQI", data, end - 20), (F.ZIP64_LOCATOR, 0, record, 1))
        self.assertEqual(struct.unpack_from("<IQ", data, record)[0], F.ZIP64_END)
        self.assertIsNone(zipfile.ZipFile(io.BytesIO(data)).testzip())

        data, layout = F.apk_hostile("multi_disk")
        self.assertEqual(u16(data, layout["end_of_central_directory"] + 4), 1)

        data, layout = F.apk_hostile("ambiguous_end")
        ends = [i for i in range(len(data) - 3) if data[i:i + 4] == struct.pack("<I", F.END_OF_CENTRAL)]
        self.assertEqual(len(ends), 2)
        for at in ends:  # each is a whole record whose comment ends the file, naming the same central directory
            self.assertEqual(at + 22 + u16(data, at + 20), len(data))
            self.assertEqual(data[at + 8:at + 20], data[ends[0] + 8:ends[0] + 20])

        data, layout = F.apk_hostile("prefix")
        self.assertGreater(layout["members"][0]["local_header_offset"], 0)
        self.assertEqual(data[:layout["members"][0]["local_header_offset"]],
                         b"ReverseAI: bytes before the first local header\n")
        self.assertIsNone(zipfile.ZipFile(io.BytesIO(data)).testzip())

    def test_dex_kinds_replace_classes2(self):
        for kind in F.DEX_HOSTILE_KINDS:
            data, layout = F.apk_hostile("dex_" + kind)
            with self.subTest(kind=kind):
                self.assertEqual(zipfile.ZipFile(io.BytesIO(data)).read("classes2.dex"), F.dex_hostile(kind)[0])
                self.assertEqual(layout["dex"]["classes2.dex"]["anomaly"]["kind"], kind)
                self.assertEqual(layout["anomaly"]["member"], 2)

    def test_signing_block_sits_before_the_central_directory(self):
        data, layout = F.apk_signing_block()
        block = layout["signing_block"]
        self.assertEqual(block["offset"] + block["size"], layout["central_directory"]["offset"])
        self.assertEqual(block["offset"], layout["members"][-1]["data_offset"] + layout["members"][-1]["compressed_size"])
        size = struct.unpack_from("<Q", data, block["offset"])[0]
        self.assertEqual((size + 8, struct.unpack_from("<Q", data, block["offset"] + block["size"] - 24)[0]),
                         (block["size"], size))
        self.assertEqual(data[block["offset"] + block["size"] - 16:block["offset"] + block["size"]], b"APK Sig Block 42")
        self.assertIsNone(zipfile.ZipFile(io.BytesIO(data)).testzip())


if __name__ == "__main__":
    unittest.main()
