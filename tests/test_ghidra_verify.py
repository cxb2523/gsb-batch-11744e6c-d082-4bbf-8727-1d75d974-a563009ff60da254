"""Anchor tests use declared synthetic layouts and never invoke a native parser."""

import copy
import struct
import unittest
from unittest.mock import patch

from reverseai.contract import ContractError, Location, Observation
from reverseai.tools import ghidra_verify, structure
from tests.fixtures_code import elf_code, pe_code, elf_data_only, macho_code, elf_refs, pe_refs, macho_refs
from tests.fixtures_structure import elf, pe, macho

ARGS = {"max_functions": 64, "decompile": 8, "max_chars": 1024, "max_calls": 128,
        "assembly": 4, "max_instructions": 32, "max_refs": 64, "max_strings": 32}


def records(layout):
    functions = [{"location": {"offset": value["offset"], "length": value["size"]},
                  "value": {"kind": "function", "index": index, "name": value["name"] or f"function_{index}",
                            "entry": value["entry"], "size": value["size"]}}
                 for index, value in enumerate(layout["functions"])]
    ordered = sorted(functions, key=lambda item: (item["value"]["entry"] != layout["entry"],
                                                 -item["value"]["size"], item["value"]["entry"]))
    pseudocode = [{"location": copy.deepcopy(item["location"]),
                   "value": {"kind": "pseudocode", "index": item["value"]["index"], "entry": item["value"]["entry"],
                             "text": "return 42;\n", "truncated": False}} for item in ordered]
    calls = [{"location": {"offset": value["offset"], "length": value["length"]},
              "value": {"kind": "call", "from": value["from"], "to": value["to"],
                        "to_name": value["to_name"] or "target"}} for value in layout["calls"]]
    return functions + pseudocode + calls


def observations(items):
    return tuple(Observation(Location(**item["location"]), item["value"]) for item in items)


def reference_records(layout):
    items = records(layout)
    ranked = sorted(enumerate(layout["functions"]), key=lambda item: (
        item[1]["entry"] != layout["entry"], -item[1]["size"], item[1]["entry"]))[:4]
    for index, function in ranked:
        items.append({"location": {"offset": function["offset"], "length": function["size"]}, "value": {
            "kind": "assembly", "index": index, "entry": function["entry"],
            "instructions": [[*row, "derived instruction"] for row in function["instructions"]], "truncated": False}})
    for ref in layout["refs"]:
        items.append({"location": {"offset": ref["offset"], "length": ref["length"]}, "value": {
            "kind": "ref", **{key: ref[key] for key in ("from", "to", "type")}, "to_name": ref["to_name"] or ""}})
    for string in layout["strings"]:
        items.append({"location": {"offset": string["offset"], "length": string["length"]}, "value": {
            "kind": "string", **{key: string[key] for key in ("address", "encoding", "text", "truncated", "from")}}})
    return items


class MachOAnchorTests(unittest.TestCase):
    def setUp(self):
        self.data, self.layout = macho_code()
        self.items = records(self.layout)

    def accepts(self, items=None, *, data=None):
        try:
            ghidra_verify.verify(self.data if data is None else data,
                                 observations(self.items if items is None else items), ARGS)
            return True
        except ContractError:
            return False

    def test_macho_functions_calls_and_pseudocode_have_exact_executable_anchors(self):
        self.assertTrue(self.accepts())
        self.assertTrue(self.accepts([]))
        for index in (0, 4, 8):
            changed = copy.deepcopy(self.items)
            changed[index]["location"]["offset"] += 20 if index == 8 else 1
            with self.subTest(index=index):
                self.assertFalse(self.accepts(changed))

    def test_macho_thin_little_endian_anchors_work_at_both_widths(self):
        for width in (32, 64):
            data, layout = macho(width=width, sections=((b"__text", b"__TEXT", 0x80000000, 5, 32),))
            item = {"location": {"offset": layout["content_start"], "length": 16},
                    "value": {"kind": "function", "index": 0, "name": "declared", "size": 16,
                              "entry": layout["addresses"][0]}}
            with self.subTest(width=width):
                self.assertTrue(self.accepts([item], data=data))
                item["location"]["offset"] += 1
                self.assertFalse(self.accepts([item], data=data))

    def test_macho_section_virtual_extent_cannot_wrap_its_address_width(self):
        for width in (32, 64):
            data, layout = macho(width=width, sections=((b"__text", b"__TEXT", 0x80000400, 5, 32),))
            for gap in (32, 16):
                address = 2**width - gap
                changed = bytearray(data)
                word = "<Q" if width == 64 else "<I"
                struct.pack_into(word, changed, layout["header_size"] + 24, address)
                struct.pack_into(word, changed, layout["section_offsets"][0] + 32, address)
                item = {"location": {"offset": layout["content_start"], "length": 8},
                        "value": {"kind": "function", "index": 0, "name": "declared", "size": 8, "entry": address}}
                # The function fits either way; only the enclosing section wraps when gap is 16.
                for items in ([item], []):
                    with self.subTest(width=width, gap=gap, empty=not items):
                        self.assertEqual(self.accepts(items, data=bytes(changed)), gap == 32)

    def test_macho_32_bit_function_and_call_cannot_cross_the_address_limit(self):
        data, layout = macho(width=32, sections=((b"__text", b"__TEXT", 0x80000400, 5, 32),))
        for gap in (32, 16):
            address = 2**32 - gap
            changed = bytearray(data)
            struct.pack_into("<I", changed, layout["header_size"] + 24, address)
            struct.pack_into("<I", changed, layout["section_offsets"][0] + 32, address)
            items = [{"location": {"offset": layout["content_start"], "length": 32},
                      "value": {"kind": "function", "index": 0, "name": "declared", "size": 32, "entry": address}},
                     {"location": {"offset": layout["content_start"] + 24, "length": 5},
                      "value": {"kind": "call", "from": address, "to": address, "to_name": "declared"}}]
            with self.subTest(gap=gap):
                self.assertEqual(self.accepts(items, data=bytes(changed)), gap == 32)

    def test_macho_non_executable_and_zero_fill_sections_cannot_anchor_code(self):
        self.assertTrue(self.accepts(self.items[:1]))
        text_segment = 32 + 72  # __PAGEZERO, followed by __TEXT in the declared fixture
        text_section = text_segment + 72
        changed = bytearray(self.data)
        struct.pack_into("<I", changed, text_segment + 60, 1)
        struct.pack_into("<I", changed, text_section + 64, 0)
        self.assertFalse(self.accepts(self.items[:1], data=bytes(changed)))
        for section_type in (1, 0xC, 0x12):
            changed = bytearray(self.data)
            struct.pack_into("<I", changed, text_section + 64, 0x80000400 | section_type)
            with self.subTest(section_type=section_type):
                self.assertFalse(self.accepts(self.items[:1], data=bytes(changed)))
                self.assertFalse(self.accepts([], data=bytes(changed)))

    def test_macho_function_only_anchors_require_unique_file_and_virtual_maps(self):
        self.assertTrue(self.accepts(self.items[:1]))
        row = {"index": 0, "name": "__TEXT,__text", "addr": self.layout["text"]["address"],
               "offset": self.layout["text"]["offset"], "size": self.layout["text"]["size"],
               "executable": True, "writable": False}
        for alias in ({**row, "addr": row["addr"] + 10, "offset": row["offset"] + 100},
                      {**row, "addr": row["addr"] + 100, "offset": row["offset"] + 10}):
            with self.subTest(alias=alias), patch.object(structure, "macho_sections", return_value=[row, alias]):
                self.assertFalse(self.accepts(self.items[:1]))

    def test_macho_anchors_cannot_start_in_headers_or_extend_past_the_section(self):
        self.assertTrue(self.accepts(self.items[:1]))
        row = copy.deepcopy(self.items[0])
        row["value"].update(entry=self.layout["image_base"], size=1)
        row["location"] = {"offset": 0, "length": 1}
        self.assertFalse(self.accepts([row]))
        row = copy.deepcopy(self.items[0])
        row["value"]["size"] = 1024
        row["location"]["length"] = self.layout["text"]["size"]
        self.assertTrue(self.accepts([row]))
        row["location"]["length"] += 1
        self.assertFalse(self.accepts([row]))

    def test_macho_entry_point_controls_pseudocode_priority_and_none_uses_size(self):
        at = 32
        for _ in range(struct.unpack_from("<I", self.data, 16)[0]):
            command, size = struct.unpack_from("<II", self.data, at)
            if command == 0x80000028:
                break
            at += size
        self.assertEqual(command, 0x80000028)
        changed = bytearray(self.data)
        struct.pack_into("<Q", changed, at + 8, self.layout["functions"][3]["offset"])
        functions = self.items[:4]
        pseudos = {row["value"]["index"]: row for row in self.items if row["value"]["kind"] == "pseudocode"}
        self.assertTrue(self.accepts(functions + [pseudos[i] for i in (3, 2, 0, 1)], data=bytes(changed)))
        self.assertFalse(self.accepts(functions + [pseudos[i] for i in (0, 2, 1, 3)], data=bytes(changed)))
        struct.pack_into("<I", changed, at, 0x80000029)  # an unrelated command, so no declared entry
        self.assertTrue(self.accepts(functions + [pseudos[i] for i in (2, 0, 1, 3)], data=bytes(changed)))
        self.assertFalse(self.accepts(functions + [pseudos[i] for i in (0, 2, 1, 3)], data=bytes(changed)))

    def test_macho_truncated_sections_refuse_even_an_empty_reply(self):
        for size in (4, 28, 103, 175, 255):
            with self.subTest(size=size):
                self.assertFalse(self.accepts([], data=self.data[:size]))


def m3c_records():
    data, layout = elf(entry=0x1000, sections=((b".text", 1, 6, 256), (b".rodata", 1, 2, 512), (b".bss", 8, 3, 16)))
    data = bytearray(data)
    for index, address in enumerate((0x1000, 0x3000, 0x5000), 1):
        struct.pack_into("<Q", data, layout["shoff"] + index * 64 + 16, address)
    text, rodata = layout["offsets"][:2]
    for offset, value in ((0, b"hello\0"), (32, "wide".encode("utf-16le") + b"\0\0"), (64, b"A" * 129)):
        data[rodata + offset:rodata + offset + len(value)] = value
    functions = [{"location": {"offset": text + 32 * index, "length": size},
                  "value": {"kind": "function", "index": index, "entry": 0x1000 + 32 * index,
                            "name": f"f{index}", "size": size}} for index, size in enumerate((16, 32, 24))]
    assembly = [{"location": dict(item["location"]), "value": {
        "kind": "assembly", "index": item["value"]["index"], "entry": item["value"]["entry"],
        "instructions": [[0, 1, "PUSH RBP"], [4, 5, "LEA RAX,[data]"]], "truncated": False}} for item in functions]
    refs = [{"location": {"offset": text + delta, "length": 5}, "value": {
        "kind": "ref", "from": origin, "to": target, "type": kind, "to_name": ""}}
        for delta, origin, target, kind in ((2, 0x1000, 0x3000, "read"), (7, 0x1000, 0x3020, "data"),
                                          (34, 0x1020, 0x3000, "write"), (66, 0x1040, 0x3040, "read_write"))]
    strings = [{"location": {"offset": rodata + delta, "length": len(text.encode(encoding))}, "value": {
        "kind": "string", "address": 0x3000 + delta, "encoding": encoding, "text": text,
        "truncated": truncated, "from": origins}}
        for delta, encoding, text, truncated, origins in ((0, "ascii", "hello", False, [0x1000, 0x1020]),
            (32, "utf-16le", "wide", False, [0x1000]), (64, "ascii", "A" * 128, True, [0x1040]))]
    return bytes(data), layout, functions + assembly + refs + strings


class M3cAnchorTests(unittest.TestCase):
    def setUp(self):
        self.data, self.layout, self.items = m3c_records()

    def check(self, items=None, *, data=None, args=None):
        return ghidra_verify.verify(self.data if data is None else data,
            observations(self.items if items is None else items), ARGS if args is None else args)

    def refuse(self, items=None, **kwargs):
        with self.assertRaisesRegex(ContractError, "^" + ghidra_verify.REFUSED + "$"):
            self.check(items, **kwargs)

    def test_all_kinds_admit_data_strings_without_relaxing_code_permissions(self):
        self.check()
        self.check(self.items[:3])
        for index in (0, 3, 6):
            items = copy.deepcopy(self.items)
            items[index]["location"] = dict(items[-3]["location"])
            self.refuse(items)

    def test_shared_elf_pe_macho_reference_fixtures_map_code_and_data(self):
        for generator in (elf_refs, pe_refs, macho_refs):
            data, layout = generator()
            items = reference_records(layout)
            with self.subTest(format=layout["format"]):
                self.check(items, data=data)
                items[-1]["value"]["text"] += "!"
                self.refuse(items, data=data)

    def test_ascii_and_utf16_rule_minimum_terminator_priority_and_truncation(self):
        for encoding in ("ascii", "utf-16le"):
            for count in (1, 2, 127, 128, 129):
                for terminated in (False, True):
                    raw = ("Z" * count).encode(encoding) + (bytes(1 if encoding == "ascii" else 2) if terminated else b"\x01")
                    expected = count >= 2 and (terminated or count >= 129)
                    with self.subTest(encoding=encoding, count=count, terminated=terminated):
                        # End the section before any bytes beyond this test's payload.
                        if expected:
                            got = ghidra_verify._string_bytes(raw, 0, len(raw))
                            self.assertEqual(got, (encoding, "Z" * min(count, 128), count >= 129))
                        else:
                            with self.assertRaises(ContractError): ghidra_verify._string_bytes(raw, 0, len(raw))
        self.assertEqual(ghidra_verify._string_bytes(b"AB\0C\0\0", 0, 6), ("ascii", "AB", False))
        for raw in (b"A\0", b"\x1fB\0", b"AB\x7f\0", b"A\0B\x01\0\0", b"A\0B\0\0"):
            with self.subTest(raw=raw), self.assertRaises(ContractError):
                ghidra_verify._string_bytes(raw, 0, len(raw))

    def test_string_origins_are_the_lowest_eight_distinct_emitted_ref_origins(self):
        text = self.layout["offsets"][0]
        functions, refs = [], []
        for index in range(10):
            entry = 0x1000 + index * 16
            functions.append({"location": {"offset": text + index * 16, "length": 8}, "value": {
                "kind": "function", "index": index, "name": "f", "entry": entry, "size": 8}})
            refs.append({"location": {"offset": text + index * 16, "length": 1}, "value": {
                "kind": "ref", "from": entry, "to": 0x3000, "type": "data", "to_name": ""}})
        string = copy.deepcopy(self.items[10]); string["value"]["from"] = [0x1000 + index * 16 for index in range(8)]
        self.check(functions + refs + [string])
        string["value"]["from"][-1] += 16
        self.refuse(functions + refs + [string])

    def test_each_new_kind_requires_exact_fields_and_global_emission_order(self):
        for index in (3, 6, 10):
            for field in (*self.items[index]["value"], "extra"):
                items = copy.deepcopy(self.items)
                if field == "extra":
                    items[index]["value"][field] = 0
                else:
                    del items[index]["value"][field]
                with self.subTest(index=index, field=field):
                    self.refuse(items)
        for left, right in ((0, 3), (3, 6), (6, 10)):
            items = copy.deepcopy(self.items)
            items[left], items[right] = items[right], items[left]
            self.refuse(items)

    def test_kind_block_order_is_independent_of_each_kinds_internal_order(self):
        self.check()
        self.refuse(self.items[:3] + self.items[6:10] + self.items[3:6] + self.items[10:])
        self.refuse(self.items[:10] + self.items[12:] + self.items[10:12])

    def test_ref_instruction_span_is_checked_without_a_sorting_or_string_failure(self):
        ref = copy.deepcopy(self.items[6])
        self.check(self.items[:3] + [ref])
        ref["location"] = {"offset": self.layout["offsets"][0] + 15, "length": 2}
        self.refuse(self.items[:3] + [ref])

    def test_assembly_requires_emitted_function_anchor_rank_and_unique_index(self):
        for key, value in (("index", True), ("index", -1), ("index", 3), ("entry", 0x1001), ("truncated", 1)):
            items = copy.deepcopy(self.items); items[3]["value"][key] = value
            self.refuse(items)
        for pair in ((4, 3), (3, 3)):
            self.refuse(self.items[:3] + [self.items[i] for i in pair])
        self.check(self.items[:3] + [self.items[4]])  # A failed/over-budget listing may be omitted.
        items = copy.deepcopy(self.items); items[3]["location"]["length"] -= 1
        self.refuse(items)
        self.refuse(self.items[3:])

    def test_instruction_types_order_lengths_ascii_and_anchor_bounds(self):
        bad_rows = ([], [[0, 1]], [[True, 1, "x"]], [[-1, 1, "x"]], [[0, True, "x"]],
                    [[0, 0, "x"]], [[0, 17, "x"]], [[0, 1, ""]], [[0, 1, "x" * 65]],
                    [[0, 1, "é"]], [[0, 1, "x\n"]], [[0, 1, "\x7f"]], [[0, 1, "x\u202e"]],
                    [[0, 4, "x"], [3, 1, "y"]], [[4, 1, "x"], [0, 1, "y"]], [[15, 2, "x"]])
        for rows in bad_rows:
            items = copy.deepcopy(self.items); items[3]["value"]["instructions"] = rows
            with self.subTest(rows=rows): self.refuse(items)
        items = copy.deepcopy(self.items); items[3]["value"]["instructions"] = [[0, 16, "x" * 64]]
        self.check(items)

    def test_instruction_length_bounds_are_independent_of_the_function_anchor(self):
        # A 17-byte row fits this 32-byte anchor, so only the row-length guard rejects it.
        for length in (0, 17):
            items = copy.deepcopy(self.items[:3] + [self.items[4]])
            items[3]["value"]["instructions"] = [[0, length, "x"]]
            with self.subTest(length=length):
                self.refuse(items)
        for length in (1, 16):
            items = copy.deepcopy(self.items[:3] + [self.items[4]])
            items[3]["value"]["instructions"] = [[0, length, "x"]]
            with self.subTest(length=length):
                self.check(items)

    def test_reference_types_instruction_span_order_uniqueness_and_emitted_origin(self):
        for key, value in (("from", True), ("from", 0x9999), ("to", -1),
                           ("type", "call"), ("type", []), ("to_name", "x\x1b"), ("to_name", "x" * 129)):
            items = copy.deepcopy(self.items); items[6]["value"][key] = value
            self.refuse(items)
        for delta, length in ((0, 17), (15, 2), (32, 1)):
            items = copy.deepcopy(self.items); items[6]["location"] = {"offset": self.layout["offsets"][0] + delta, "length": length}
            self.refuse(items)
        for refs in ([self.items[7], self.items[6]], [self.items[6], self.items[6]]):
            self.refuse(self.items[:3] + refs)
        for kind in ("read", "write", "read_write", "data", "jump"):
            ref = copy.deepcopy(self.items[6]); ref["value"].update(type=kind, to=2**64-1)
            self.check(self.items[:3] + [ref])

    def test_reference_order_ties_use_target_then_type_and_ignore_target_name(self):
        refs = []
        for target, kind in ((0x3000, "data"), (0x3000, "read"), (0x3001, "data")):
            row = copy.deepcopy(self.items[6]); row["value"].update(to=target, type=kind)
            refs.append(row)
        self.check(self.items[:3] + refs)
        for pair in ((0, 1), (1, 2)):
            changed = copy.deepcopy(refs)
            left, right = pair; changed[left], changed[right] = changed[right], changed[left]
            self.refuse(self.items[:3] + changed)
        duplicate = copy.deepcopy(refs[0]); duplicate["value"]["to_name"] = "another name"
        self.refuse(self.items[:3] + [refs[0], duplicate])

    def test_pe_string_terminator_cannot_use_raw_padding_beyond_virtual_extent(self):
        data, layout = pe_refs()
        self.check(reference_records(layout), data=data)
        changed = bytearray(data)
        pe_offset = struct.unpack_from("<I", changed, 0x3c)[0]
        optional_size = struct.unpack_from("<H", changed, pe_offset + 20)[0]
        data_header = pe_offset + 24 + optional_size + 40
        struct.pack_into("<I", changed, data_header + 8, layout["strings"][0]["length"])
        self.refuse(reference_records(layout), data=bytes(changed))

    def test_string_value_anchor_and_origin_list_are_rederived(self):
        for key, value in (("address", True), ("address", 0x3001), ("encoding", "utf-8"),
                           ("encoding", "utf-16le"), ("text", "HELLO"), ("truncated", True),
                           ("truncated", 0), ("from", []), ("from", [0x1020, 0x1000]),
                           ("from", [0x1000]), ("from", [0x1000, 0x1000]), ("from", [True]),
                           ("from", [0x1000, 0x1020, 0x1040])):
            items = copy.deepcopy(self.items); items[10]["value"][key] = value
            with self.subTest(key=key, value=value): self.refuse(items)
        for key in ("offset", "length"):
            items = copy.deepcopy(self.items); items[10]["location"][key] += 1
            self.refuse(items)
        self.refuse(self.items[:6] + self.items[10:])
        self.refuse(self.items[:10] + [self.items[11], self.items[10]])
        self.refuse(self.items + [self.items[-1]])

    def test_string_terminator_and_129th_unit_must_be_inside_the_same_file_section(self):
        rodata = self.layout["offsets"][1]
        for offset, replacement in ((5, b"!"), (40, b"x\0"), (64 + 128, b"\0")):
            data = bytearray(self.data); data[rodata + offset:rodata + offset + len(replacement)] = replacement
            self.refuse(data=bytes(data))
        for size in (5, 6, 64 + 128, 64 + 129):
            data = bytearray(self.data)
            struct.pack_into("<Q", data, self.layout["shoff"] + 2 * 64 + 32, size)
            if size == 6:
                self.check(self.items[:10] + self.items[10:11], data=bytes(data))
            elif size == 64 + 129:
                self.check(data=bytes(data))
            else:
                self.refuse(data=bytes(data))

    def test_string_mapping_refuses_nonallocated_nobits_and_ambiguous_file_or_virtual_ranges(self):
        for field, fmt, value in ((8, "<Q", 0), (4, "<I", 8)):
            data = bytearray(self.data); struct.pack_into(fmt, data, self.layout["shoff"] + 2 * 64 + field, value)
            self.refuse(data=bytes(data))
        for address, offset in ((0x3000, self.layout["offsets"][2]), (0x6000, self.layout["offsets"][1])):
            data = bytearray(self.data); at = self.layout["shoff"] + 3 * 64
            struct.pack_into("<I", data, at + 4, 1)
            struct.pack_into("<Q", data, at + 16, address)
            struct.pack_into("<Q", data, at + 24, offset)
            self.refuse(data=bytes(data))

    def test_individual_new_caps_are_enforced_and_zero_disables_the_kind(self):
        for key, value in (("assembly", 2), ("max_instructions", 1), ("max_refs", 3), ("max_strings", 2)):
            self.refuse(args=dict(ARGS, **{key: value}))
        self.check(self.items[:3], args=dict(ARGS, assembly=0, max_refs=0, max_strings=0))


class AnchorTests(unittest.TestCase):
    def setUp(self):
        self.data, self.layout = elf_code()
        self.items = records(self.layout)

    def check(self, items=None, *, data=None, args=None):
        return ghidra_verify.verify(self.data if data is None else data,
                                    observations(self.items if items is None else items), ARGS if args is None else args)

    def refuse(self, items=None, **kwargs):
        with self.assertRaisesRegex(ContractError, "^" + ghidra_verify.REFUSED + "$"):
            self.check(items, **kwargs)

    def accepts(self, items, **kwargs):
        try:
            self.check(items, **kwargs)
            return True
        except ContractError:
            return False

    def test_shared_elf_pe_and_data_only_fixtures_have_valid_exact_anchors(self):
        for generator in (elf_code, pe_code, elf_data_only):
            data, layout = generator()
            with self.subTest(format=layout["format"], functions=len(layout["functions"])):
                self.assertIsNone(self.check(records(layout), data=data))
                self.assertIsNone(self.check([], data=data))

    def test_function_interpretation_is_derived_but_its_exact_byte_anchor_is_checked(self):
        item = copy.deepcopy(self.items[0])
        item["value"].update(name="a_tool_interpretation", size=3)
        item["location"]["length"] = 3
        self.check([item])
        item["location"]["offset"] += 1
        self.refuse([item])
        item = copy.deepcopy(self.items[0])
        item["value"]["entry"] += 1
        self.refuse([item])

    def test_each_kind_requires_its_exact_fields(self):
        for index in (0, 4, 8):
            for field in self.items[index]["value"]:
                items = copy.deepcopy(self.items)
                del items[index]["value"][field]
                with self.subTest(index=index, missing=field):
                    self.refuse(items)
            items = copy.deepcopy(self.items)
            items[index]["value"]["extra"] = 1
            self.refuse(items)
        for kind in ("unknown", None, ["function"]):
            items = copy.deepcopy(self.items)
            items[0]["value"]["kind"] = kind
            self.refuse(items)

    def test_function_field_types_bounds_and_contiguous_address_order(self):
        for key, value in (("index", True), ("index", 1), ("index", -1), ("entry", True), ("entry", -1),
                           ("entry", "4194560"), ("size", 0), ("size", True), ("size", -1),
                           ("name", "x" * 129), ("name", "hidden\x1b[31m"), ("name", "bidi\u202e"), ("name", [])):
            items = copy.deepcopy(self.items)
            items[0]["value"][key] = value
            with self.subTest(key=key, value=value):
                self.refuse(items)
                self.refuse([items[0]])
        for changed in ([self.items[1], self.items[0]], [self.items[0], self.items[0]], self.items[1:]):
            self.refuse(changed)
        for changed in (copy.deepcopy(list(reversed(self.items[:2]))), copy.deepcopy([self.items[0], self.items[0]])):
            for index, item in enumerate(changed):
                item["value"]["index"] = index
            self.refuse(changed)
        items = copy.deepcopy(self.items[:1])
        items[0]["value"].update(entry=2**64 - 1, size=2)
        self.refuse(items)
        items = copy.deepcopy(self.items[:1])
        items[0]["value"]["size"] = 2**64 - 1
        items[0]["location"]["length"] = self.layout["text"]["size"]
        self.refuse(items)

    def test_non_executable_sections_cannot_anchor_code(self):
        for generator in (elf_code, pe_code):
            data, layout = generator()
            data = bytearray(data)
            if layout["format"] == "elf":
                struct.pack_into("<Q", data, layout["shoff"] + 64 + 8, 0x2)
            else:
                struct.pack_into("<I", data, 0x40 + 24 + 240 + 36, 0x40000020)
            with self.subTest(format=layout["format"]):
                self.refuse(records(layout), data=bytes(data))
        data, layout = elf_data_only()
        item = {"location": {"offset": layout["data"]["offset"], "length": 1},
                "value": {"kind": "function", "index": 0, "name": "invented", "entry": layout["data"]["address"], "size": 1}}
        self.refuse([item], data=data)

    def test_overlapping_virtual_sections_or_file_aliases_are_ambiguous(self):
        for field, value in ((16, self.layout["text"]["address"]), (24, self.layout["text"]["offset"]),
                             (16, self.layout["text"]["address"] + 10), (24, self.layout["text"]["offset"] + 10)):
            data = bytearray(self.data)
            struct.pack_into("<Q", data, self.layout["shoff"] + 2 * 64 + 8, 0x2)
            struct.pack_into("<Q", data, self.layout["shoff"] + 2 * 64 + field, value)
            with self.subTest(elf_field=field):
                self.refuse(data=bytes(data))
        data, layout = pe_code()
        for field, value in ((12, 0x1000), (20, 0x200)):
            changed = bytearray(data)
            struct.pack_into("<I", changed, 0x40 + 24 + 240 + 40 + field, value)
            with self.subTest(pe_field=field):
                self.refuse(records(layout), data=bytes(changed))

    def test_pie_code_ignores_non_allocated_virtual_and_file_aliases(self):
        data, layout = elf(kind=3, entry=0x10,
                           sections=((b".text", 1, 6, 32), (b".debug", 1, 0, 128)))
        data = bytearray(data)
        struct.pack_into("<Q", data, layout["shoff"] + 64 + 16, 0x10)
        item = {"location": {"offset": layout["offsets"][0], "length": 16},
                "value": {"kind": "function", "index": 0, "name": "pie_entry", "entry": 0x10, "size": 16}}
        for flags in (0, 4):
            changed = bytearray(data)
            struct.pack_into("<Q", changed, layout["shoff"] + 2 * 64 + 8, flags)
            with self.subTest(non_allocated_flags=flags):
                self.assertTrue(self.accepts([item], data=bytes(changed)))
                struct.pack_into("<Q", changed, layout["shoff"] + 2 * 64 + 24, layout["offsets"][0])
                self.assertTrue(self.accepts([item], data=bytes(changed)))

    def test_executable_but_non_allocated_elf_section_cannot_anchor_code(self):
        data = bytearray(self.data)
        struct.pack_into("<Q", data, self.layout["shoff"] + 64 + 8, 0x4)
        self.refuse(self.items[:1], data=bytes(data))

    def test_pe_raw_padding_is_not_mapped_and_zero_virtual_size_uses_raw_size(self):
        data, layout = pe_code()
        item = records(layout)[0]
        for relative, admitted in ((layout["text"]["size"] - 1, True), (layout["text"]["size"], False),
                                   (layout["text_raw_size"] - 1, False)):
            item["value"].update(entry=layout["text"]["address"] + relative, size=1)
            item["location"] = {"offset": layout["text"]["offset"] + relative, "length": 1}
            with self.subTest(relative=relative):
                self.assertEqual(self.accepts([item], data=data), admitted)
        changed = bytearray(data)
        struct.pack_into("<I", changed, 0x40 + 24 + 240 + 8, 0)
        self.assertTrue(self.accepts([item], data=bytes(changed)))

    def test_function_only_reply_rejects_file_aliases_without_call_records(self):
        for generator in (elf_code, pe_code):
            data, layout = generator()
            item = records(layout)[0]
            self.assertTrue(self.accepts([item], data=data))
            changed = bytearray(data)
            if layout["format"] == "elf":
                at = layout["shoff"] + 2 * 64
                struct.pack_into("<Q", changed, at + 8, 0x2)
                struct.pack_into("<Q", changed, at + 16, 0x600000)
                struct.pack_into("<Q", changed, at + 24, layout["text"]["offset"] + 10)
            else:
                struct.pack_into("<I", changed, 0x40 + 24 + 240 + 40 + 20, layout["text"]["offset"] + 10)
            with self.subTest(format=layout["format"]):
                self.refuse([item], data=bytes(changed))

    def test_function_only_reply_rejects_virtual_overlap_away_from_its_entry(self):
        for generator in (elf_code, pe_code):
            data, layout = generator()
            item = records(layout)[0]
            self.assertTrue(self.accepts([item], data=data))
            changed = bytearray(data)
            if layout["format"] == "elf":
                at = layout["shoff"] + 2 * 64
                struct.pack_into("<Q", changed, at + 8, 0x2)
                struct.pack_into("<Q", changed, at + 16, layout["text"]["address"] + 10)
            else:
                struct.pack_into("<I", changed, 0x40 + 24 + 240 + 40 + 12, 0x1000 + 10)
            with self.subTest(format=layout["format"]):
                self.refuse([item], data=bytes(changed))

    def test_virtual_only_nobits_and_pe_tail_bytes_cannot_be_file_anchors(self):
        data = bytearray(self.data)
        struct.pack_into("<I", data, self.layout["shoff"] + 64 + 4, 8)
        self.refuse(data=bytes(data))
        data, layout = pe_code()
        changed = bytearray(data)
        struct.pack_into("<I", changed, 0x40 + 24 + 240 + 8, 0x300)
        item = records(layout)[0]
        item["value"].update(entry=layout["text"]["address"] + 0x200, size=1)
        item["location"] = {"offset": 0x400, "length": 1}
        self.refuse([item], data=bytes(changed))

    def test_pseudocode_must_match_function_index_entry_anchor_and_selection_order(self):
        for key, value in (("index", True), ("index", -1), ("index", 4), ("entry", -1),
                           ("entry", self.layout["functions"][1]["entry"]), ("text", []),
                           ("text", "x" * 1025), ("truncated", 1)):
            items = copy.deepcopy(self.items)
            items[4]["value"][key] = value
            with self.subTest(key=key, value=value):
                self.refuse(items)
        for location in ({"offset": 0, "length": 1}, {"offset": 0x100, "length": 1}):
            items = copy.deepcopy(self.items)
            items[4]["location"] = location
            self.refuse(items)
        self.refuse(self.items[:4] + list(reversed(self.items[4:8])))
        self.refuse(self.items[:5] + self.items[4:5])
        self.check(self.items[:4] + self.items[6:7], args=dict(ARGS, decompile=1))
        self.refuse(self.items, args=dict(ARGS, decompile=0))
        items = copy.deepcopy(self.items)
        items[4]["value"].update(text="x" * 1024, truncated=True)
        items[0]["value"]["name"] = "n" * 128
        self.check(items)

    def test_calls_require_emitted_from_function_and_full_instruction_inside_it(self):
        for key, value in (("from", True), ("from", -1), ("from", self.layout["entry"] + 1),
                           ("to", True), ("to", -1), ("to_name", "x" * 129), ("to_name", "escape\x1b")):
            items = copy.deepcopy(self.items)
            items[8]["value"][key] = value
            with self.subTest(key=key, value=value):
                self.refuse(items)
        for offset, length in ((0x100, 17), (0x100 + 20, 1), (0x100 + 18, 5), (0x100 + 0x54, 5)):
            items = copy.deepcopy(self.items)
            items[8]["location"] = {"offset": offset, "length": length}
            self.refuse(items)
        self.refuse(self.items[8:])
        items = copy.deepcopy(self.items)
        items[8]["value"].update(to=2**64 - 1, to_name="external_target")
        self.check(items)

    def test_call_cannot_precede_its_from_function_even_when_the_upper_bound_passes(self):
        function = copy.deepcopy(self.items[1])
        function["value"]["index"] = 0
        call = copy.deepcopy(self.items[8])
        call["value"]["from"] = function["value"]["entry"]
        call["location"] = {"offset": function["location"]["offset"], "length": 1}
        self.check([function, call])
        call["location"]["offset"] -= 1
        self.refuse([function, call])

    def test_function_span_keeps_a_later_call_in_a_sparse_body(self):
        data, layout = elf(entry=0x1000, sections=((b".text", 1, 6, 0x80),))
        data = bytearray(data)
        struct.pack_into("<Q", data, layout["shoff"] + 64 + 16, 0x1000)
        function = {"location": {"offset": layout["offsets"][0], "length": 0x65},
                    "value": {"kind": "function", "index": 0, "name": "sparse", "entry": 0x1000, "size": 0x65}}
        call = {"location": {"offset": layout["offsets"][0] + 0x60, "length": 5},
                "value": {"kind": "call", "from": 0x1000, "to": 0, "to_name": "external"}}
        self.check([function, call], data=bytes(data))
        call["location"]["offset"] += 1
        self.refuse([function, call], data=bytes(data))

    def test_call_after_the_4096_byte_function_anchor_still_requires_a_unique_virtual_map(self):
        data, layout = elf(entry=0x1000, sections=((b".text", 1, 6, 8192), (b".data", 1, 3, 16)))
        data = bytearray(data)
        struct.pack_into("<Q", data, layout["shoff"] + 64 + 16, 0x1000)
        function = {"location": {"offset": layout["offsets"][0], "length": 4096},
                    "value": {"kind": "function", "index": 0, "name": "large", "entry": 0x1000, "size": 7000}}
        call = {"location": {"offset": layout["offsets"][0] + 5000, "length": 5},
                "value": {"kind": "call", "from": 0x1000, "to": 0, "to_name": "external"}}
        self.check([function, call], data=bytes(data))
        struct.pack_into("<Q", data, layout["shoff"] + 2 * 64 + 16, 0x1000 + 5000)
        self.refuse([function, call], data=bytes(data))

    def test_function_only_entries_are_strictly_increasing_with_valid_reindexed_records(self):
        items = copy.deepcopy(self.items[:2])
        self.check(items)
        for reordered in (list(reversed(items)), [items[0], copy.deepcopy(items[0])]):
            changed = copy.deepcopy(reordered)
            for index, item in enumerate(changed):
                item["value"]["index"] = index
            self.refuse(changed)

    def test_individual_request_limits_and_overall_observation_cap_are_enforced(self):
        for args in (dict(ARGS, max_functions=3), dict(ARGS, decompile=3), dict(ARGS, max_calls=3)):
            self.refuse(args=args)
        self.refuse([self.items[0]] * 401)
        self.check(self.items[:4], args=dict(ARGS, decompile=0, max_calls=0))

    def test_elf_width_endianness_extended_count_and_pe32_image_base(self):
        for width in (32, 64):
            for order in ("<", ">"):
                for extended in (False, True):
                    data, layout = elf(width=width, order=order, entry=0x1000, extended=extended)
                    data = bytearray(data)
                    for index in (1, 2, 3):
                        struct.pack_into(order + ("I" if width == 32 else "Q"), data,
                                         layout["shoff"] + layout["entry_size"] * index + (12 if width == 32 else 16), index * 0x1000)
                    item = {"location": {"offset": layout["offsets"][0], "length": 16},
                            "value": {"kind": "function", "index": 0, "name": "function", "entry": 0x1000, "size": 16}}
                    with self.subTest(width=width, order=order, extended=extended):
                        self.check([item], data=bytes(data))
        data, layout = pe(plus=False)
        data = bytearray(data)
        struct.pack_into("<I", data, layout["lfanew"] + 24 + 28, 0x400000)
        item["location"]["offset"] = layout["raw_offsets"][0]
        item["value"]["entry"] = 0x401000
        self.check([item], data=bytes(data))
        struct.pack_into("<I", data, layout["lfanew"] + 24 + 28, 0xFFFFFFF0)
        self.refuse([], data=bytes(data))

    def test_anchor_length_is_minimum_of_size_4096_and_file_bytes_left_in_section(self):
        data, layout = elf(entry=0x1000, sections=((b".text", 1, 6, 7000),))
        data = bytearray(data)
        struct.pack_into("<Q", data, layout["shoff"] + 64 + 16, 0x1000)
        item = {"location": {"offset": layout["offsets"][0], "length": 4096},
                "value": {"kind": "function", "index": 0, "name": "large", "entry": 0x1000, "size": 7000}}
        self.check([item], data=bytes(data))
        item["location"]["length"] = 4095
        self.refuse([item], data=bytes(data))
        item["value"].update(entry=0x1000 + 6998, size=50)
        item["location"] = {"offset": layout["offsets"][0] + 6998, "length": 2}
        self.check([item], data=bytes(data))
        for length in (1, 3):
            item["location"]["length"] = length
            self.refuse([item], data=bytes(data))

    def test_unknown_macho_truncated_or_inconsistent_tables_fail_even_with_no_observations(self):
        variants = [b"", b"unknown", b"\xcf\xfa\xed\xfe" + bytes(64), self.data[:40], self.data[:-1]]
        for offset, fmt, value in ((40, "<Q", len(self.data)), (58, "<H", 40), (60, "<H", 65535)):
            data = bytearray(self.data)
            struct.pack_into(fmt, data, offset, value)
            variants.append(bytes(data))
        data, _ = pe_code()
        variants.extend([data[:30], data[:0x40 + 24 + 240 + 70]])
        for data in variants:
            with self.subTest(bytes=len(data)):
                self.refuse([], data=data)

    def test_section_file_ranges_are_checked_even_when_the_worker_returns_no_code(self):
        data = bytearray(self.data)
        struct.pack_into("<Q", data, self.layout["shoff"] + 64 + 24, len(data) - 1)
        self.refuse([], data=bytes(data))
        data, _ = pe_code()
        changed = bytearray(data)
        struct.pack_into("<I", changed, 0x40 + 24 + 240 + 20, len(data) - 1)
        self.refuse([], data=bytes(changed))


def query_function_records(layout, index=1):
    function = layout["functions"][index]
    target = {"location": {"offset": function["offset"], "length": function["size"]}, "value": {
        "kind": "target", "name": function["name"] or "selected", "entry": function["entry"],
        "size": function["size"], "matches": 1, "callers_total": 2, "callees_total": 2}}
    return target


class TargetedAnchorTests(unittest.TestCase):
    def setUp(self):
        self.data, self.layout = elf_refs()

    def check(self, items, operation="ghidra.function", args=None, data=None):
        return ghidra_verify.verify(self.data if data is None else data, observations(items),
                                   {} if args is None else args, operation=operation)

    def refuse(self, items, **kwargs):
        with self.assertRaisesRegex(ContractError, "^" + ghidra_verify.REFUSED + "$"):
            self.check(items, **kwargs)

    def target(self, index=1):
        return query_function_records(self.layout, index)

    def function_rows(self, start=0, stop=3):
        rows = []
        for index in range(start, stop):
            function = self.layout["functions"][index]
            rows.append({"location": {"offset": function["offset"], "length": function["size"]}, "value": {
                "kind": "function_row", "index": index, "total": len(self.layout["functions"]),
                "name": function["name"], "entry": function["entry"], "size": function["size"]}})
        return rows

    def instruction_page(self, target, *, start=0, limit=2, total=4):
        value = target["value"]
        return {"location": {"offset": target["location"]["offset"] + 1, "length": 4}, "value": {
            "kind": "instructions", "entry": value["entry"], "start": start, "total": total,
            "rows": [[1, 1, "PUSH RBP"], [3, 2, "MOV RBP,RSP"]], "truncated": False}}

    def caller_rows(self):
        target = self.target()
        rows = []
        for call in self.layout["calls"]:
            if call["to"] == target["value"]["entry"]:
                rows.append({"location": {"offset": call["offset"], "length": call["length"]}, "value": {
                    "kind": "caller", "at": call["address"], "from": call["from"], "to": call["to"]}})
        return target, rows

    def xref_rows(self):
        refs = [ref for ref in self.layout["refs"] if ref["to_name"] == "counter"]
        self.assertEqual(len(refs), 2)
        rows = [{"location": {"offset": ref["offset"], "length": ref["length"]}, "value": {
            "kind": "xref", "index": index, "total": 2, "at": ref["address"], "from": ref["from"],
            "to": ref["to"], "type": ref["type"]}} for index, ref in enumerate(refs)]
        return rows[0]["value"]["to"], rows

    def test_functions_pages_check_indexes_total_filter_order_and_exact_anchors(self):
        rows = self.function_rows(1, 3)
        args = {"start": 1, "limit": 2}
        self.check(rows, "ghidra.functions", args)
        self.check([], "ghidra.functions", {"start": 65535})
        self.check(rows[:1], "ghidra.functions", {"start": 1, "query": "add"})
        for row_index, key, value in ((0, "index", True), (0, "index", 0), (1, "index", 3),
                (1, "total", 6), (1, "total", 2), (0, "total", True), (0, "name", "bad\nname"),
                (0, "name", "X" * 129), (0, "entry", True), (0, "size", 0), (0, "size", 2**64 - 1)):
            changed = copy.deepcopy(rows)
            changed[row_index]["value"][key] = value
            with self.subTest(row=row_index, key=key, value=value):
                self.refuse(changed, operation="ghidra.functions", args=args)
        self.refuse(rows, operation="ghidra.functions", args={"start": 1, "limit": 1})
        self.refuse(rows, operation="ghidra.functions", args={"start": 1, "query": "absent"})
        changed = copy.deepcopy(rows)
        changed[1]["value"].update(entry=rows[0]["value"]["entry"], size=rows[0]["value"]["size"])
        changed[1]["location"] = dict(rows[0]["location"])
        self.refuse(changed, operation="ghidra.functions", args=args)
        changed = copy.deepcopy(rows)
        changed[1]["location"]["offset"] += 1
        self.refuse(changed, operation="ghidra.functions", args=args)

    def test_target_selection_exact_fields_order_counts_and_atomic_refusal(self):
        target = self.target()
        args = {"entry": target["value"]["entry"], "parts": "info"}
        self.check([target], args=args)
        self.check([target], args={"select": "name", "name": target["value"]["name"], "parts": "info"})
        self.check([], args=args)
        for key, value in (("name", "x" * 129), ("entry", True), ("size", 0), ("matches", 0),
                           ("matches", 2), ("callers_total", True), ("callees_total", -1), ("size", 2**64 - 1)):
            changed = copy.deepcopy(target)
            changed["value"][key] = value
            with self.subTest(key=key, value=value): self.refuse([changed], args=args)
        changed = copy.deepcopy(target)
        changed["value"]["matches"] = 3
        self.check([changed], args={"select": "name", "name": target["value"]["name"], "parts": "info"})
        self.refuse([target], args={"entry": target["value"]["entry"] + 1})
        self.refuse([target], args={"select": "name", "name": "another"})
        self.refuse([target, target], args=args)
        for kind, keys in ghidra_verify._QUERY_FIELDS.items():
            source = target if kind == "target" else None
            if source:
                for missing in keys:
                    changed = copy.deepcopy(source)
                    del changed["value"][missing]
                    with self.subTest(missing=missing): self.refuse([changed], args=args)
        changed = copy.deepcopy(target)
        changed["value"]["extra"] = "hidden"
        self.refuse([changed], args=args)
        changed = copy.deepcopy(target)
        changed["location"]["offset"] += 1
        self.refuse([changed], args=args)

    def test_target_pseudocode_has_index_zero_same_anchor_and_selected_part(self):
        target = self.target()
        pseudo = {"location": dict(target["location"]), "value": {"kind": "pseudocode", "index": 0,
                  "entry": target["value"]["entry"], "text": "return a + b;\n", "truncated": False}}
        args = {"entry": target["value"]["entry"], "parts": "pseudocode"}
        self.check([target, pseudo], args=args)
        for key, value in (("index", True), ("index", 1), ("entry", 0), ("text", []),
                           ("text", "x" * 1025), ("truncated", 1)):
            changed = copy.deepcopy(pseudo)
            changed["value"][key] = value
            with self.subTest(key=key): self.refuse([target, changed], args=args)
        for parts in ("info", "assembly", "callers", "callees"):
            self.refuse([target, pseudo], args={**args, "parts": parts})
        self.refuse([pseudo, target], args=args)
        self.refuse([target, pseudo, pseudo], args=args)
        changed = copy.deepcopy(pseudo)
        changed["location"]["length"] -= 1
        self.refuse([target, changed], args=args)

    def test_function_parts_require_global_order_even_when_each_part_is_valid(self):
        target = self.target()
        pseudo = {"location": dict(target["location"]), "value": {"kind": "pseudocode", "index": 0,
                  "entry": target["value"]["entry"], "text": "return a + b;", "truncated": False}}
        page = self.instruction_page(target)
        args = {"entry": target["value"]["entry"], "parts": "all", "limit": 2}
        self.check([target, pseudo, page], args=args)
        self.refuse([target, page, pseudo], args=args)

    def test_instruction_page_checks_virtual_start_exact_span_and_function_extent(self):
        target = self.target()
        page = self.instruction_page(target)
        args = {"entry": target["value"]["entry"], "parts": "assembly", "limit": 2}
        self.check([target, page], args=args)
        for key, value in (("entry", 0), ("start", True), ("start", 1), ("total", 1),
                           ("total", True), ("rows", []), ("rows", [[True, 1, "NOP"]]),
                           ("rows", [[1, True, "NOP"]]), ("rows", [[1, 17, "NOP"]]),
                           ("rows", [[1, 1, "bad\n"]]), ("rows", [[1, 1, ""]]),
                           ("rows", [[1, 4, "A"], [3, 1, "B"]]), ("truncated", 1)):
            changed = copy.deepcopy(page)
            changed["value"][key] = value
            with self.subTest(key=key, value=value): self.refuse([target, changed], args=args)
        for location in ({"offset": page["location"]["offset"] - 1, "length": 4},
                         {"offset": page["location"]["offset"], "length": 5}):
            changed = copy.deepcopy(page)
            changed["location"] = location
            self.refuse([target, changed], args=args)
        changed = copy.deepcopy(page)
        changed["value"]["rows"][-1][0] = target["value"]["size"]
        self.refuse([target, changed], args=args)
        self.refuse([target, page], args={**args, "limit": 1})
        self.refuse([target, page, page], args=args)
        changed = copy.deepcopy(page)
        changed["value"]["start"] = 2
        self.check([target, changed], args={**args, "start": 2})

    def test_incoming_reference_origins_are_derived_uint64_or_null_without_mapping(self):
        target, callers = self.caller_rows()
        address, xrefs = self.xref_rows()
        args = {"entry": target["value"]["entry"], "parts": "callers"}
        for origin in (None, 0, 1, 2**64 - 1):
            changed = copy.deepcopy(callers)
            changed[0]["value"]["from"] = origin
            self.check([target, *changed], args=args)
            changed = copy.deepcopy(xrefs)
            changed[0]["value"]["from"] = origin
            self.check(changed, "ghidra.xrefs", {"address": address})
        for origin in (True, False, -1, "0", []):
            changed = copy.deepcopy(callers)
            changed[0]["value"]["from"] = origin
            self.refuse([target, *changed], args=args)
            changed = copy.deepcopy(xrefs)
            changed[0]["value"]["from"] = origin
            self.refuse(changed, operation="ghidra.xrefs", args={"address": address})

    def test_callers_bind_instruction_address_target_and_optional_origin(self):
        target, callers = self.caller_rows()
        args = {"entry": target["value"]["entry"], "parts": "callers"}
        self.assertEqual(len(callers), 2)
        self.check([target, *callers], args=args)
        changed = copy.deepcopy(callers)
        changed[0]["value"]["from"] = None
        self.check([target, *changed], args=args)
        for key, value in (("at", True), ("at", callers[0]["value"]["at"] + 1),
                           ("to", 0), ("from", True), ("from", -1)):
            changed = copy.deepcopy(callers)
            changed[0]["value"][key] = value
            with self.subTest(key=key, value=value): self.refuse([target, *changed], args=args)
        self.refuse([target, *reversed(callers)], args=args)
        self.refuse([target, callers[0], callers[0]], args=args)
        self.refuse([target, *callers], args={**args, "max_calls": 1})
        self.refuse([target, *callers], args={**args, "parts": "info"})
        changed = copy.deepcopy(callers)
        changed[-1]["location"]["length"] = 17
        self.refuse([target, *changed], args=args)

    def test_callees_and_references_from_only_the_target_fit_its_span(self):
        target = self.target(2)
        calls = [row for row in records(self.layout) if row["value"]["kind"] == "call"
                 and row["value"]["from"] == target["value"]["entry"]]
        args = {"entry": target["value"]["entry"], "parts": "callees"}
        self.check([target, *calls], args=args)
        self.refuse([target, *calls], args={**args, "max_calls": 1})
        changed = copy.deepcopy(calls)
        changed[0]["value"]["from"] = self.layout["entry"]
        self.refuse([target, *changed], args=args)
        changed = copy.deepcopy(calls)
        changed[0]["location"]["offset"] = target["location"]["offset"] + target["value"]["size"] - 1
        self.refuse([target, *changed], args=args)
        changed = copy.deepcopy(calls)
        changed[0]["value"]["to_name"] = "x\n"
        self.refuse([target, *changed], args=args)
        target = self.target(4)
        refs = [row for row in reference_records(self.layout) if row["value"]["kind"] == "ref"]
        args = {"entry": target["value"]["entry"], "parts": "all"}
        self.check([target, *refs], args=args)
        self.refuse([target, *refs], args={**args, "max_refs": 1})
        self.refuse([target, *reversed(refs)], args=args)
        self.refuse([target, *refs], args={**args, "parts": "callees"})
        changed = copy.deepcopy(refs)
        changed[0]["value"]["type"] = "call"
        self.refuse([target, *changed], args=args)

    def test_xrefs_page_checks_indexes_targets_types_at_maps_and_page_counts(self):
        address, rows = self.xref_rows()
        args = {"address": address}
        self.check(rows, "ghidra.xrefs", args)
        self.check(rows[1:], "ghidra.xrefs", {**args, "start": 1})
        self.check([], "ghidra.xrefs", {**args, "start": 65535})
        for key, value in (("index", True), ("index", 1), ("total", 0), ("total", True),
                           ("at", rows[0]["value"]["at"] + 1), ("at", True), ("to", address + 1),
                           ("to", True), ("from", []), ("from", True), ("type", "execute")):
            changed = copy.deepcopy(rows)
            changed[0]["value"][key] = value
            with self.subTest(key=key, value=value): self.refuse(changed, operation="ghidra.xrefs", args=args)
        changed = copy.deepcopy(rows)
        changed[1]["value"]["total"] += 1
        self.refuse(changed, operation="ghidra.xrefs", args=args)
        self.refuse(rows, operation="ghidra.xrefs", args={**args, "limit": 1})
        changed = list(reversed(copy.deepcopy(rows)))
        for index, row in enumerate(changed): row["value"]["index"] = index
        self.refuse(changed, operation="ghidra.xrefs", args=args)
        for kind in ("function", "ref", ["xref"]):
            changed = copy.deepcopy(rows)
            changed[0]["value"]["kind"] = kind
            self.refuse(changed, operation="ghidra.xrefs", args=args)

    def test_each_mode_refuses_foreign_kinds_and_unknown_operation(self):
        target = self.target()
        rows = self.function_rows()
        address, xrefs = self.xref_rows()
        self.refuse(rows, args={"entry": target["value"]["entry"]})
        self.refuse([target], operation="ghidra.functions")
        self.refuse(xrefs, operation="ghidra.functions")
        self.refuse(rows, operation="ghidra.xrefs", args={"address": address})
        self.refuse([], operation="ghidra.unknown")
        self.refuse([], operation="ghidra.xrefs", args={})
        self.refuse([], operation="ghidra.functions", args={"limit": True})
        self.refuse([], args={"parts": "outside"})

    def test_new_modes_share_execute_permission_nobits_and_both_direction_alias_refusals(self):
        target = self.target()
        args = {"entry": target["value"]["entry"]}
        row = self.function_rows(1, 2)
        for field, value in ((4, 8), (8, 2)):
            changed = bytearray(self.data)
            struct.pack_into("<I" if field == 4 else "<Q", changed, self.layout["shoff"] + 64 + field, value)
            self.refuse([target], args=args, data=bytes(changed))
            self.refuse(row, operation="ghidra.functions", args={"start": 1}, data=bytes(changed))
        for field, value in ((16, target["value"]["entry"] + 1),
                             (24, target["location"]["offset"] + 1)):
            changed = bytearray(self.data)
            at = self.layout["shoff"] + 2 * 64
            struct.pack_into("<Q", changed, at + 8, 2)
            struct.pack_into("<Q", changed, at + field, value)
            self.refuse([target], args=args, data=bytes(changed))
            self.refuse(row, operation="ghidra.functions", args={"start": 1}, data=bytes(changed))

    def test_indexed_mapping_matches_linear_overlap_oracle_including_nested_and_zero_spans(self):
        import random
        rng = random.Random(314159)
        rows = [ghidra_verify._Section(rng.randrange(60), rng.randrange(60), rng.randrange(9), rng.randrange(12),
                                      bool(rng.randrange(2))) for _ in range(80)]
        # The virtual interval may include memory-only bytes; file lookup must never do so.
        index = ghidra_verify._SectionIndex(rows)
        for virtual, backed in ((True, False), (False, False), (True, True)):
            lookup = index.backed_virtual if backed else index.virtual if virtual else index.file
            for start in range(75):
                for length in (1, 2, 7, 13):
                    matches = [row for row in rows
                               if (row.size if backed or not virtual else row.span) > 0
                               and start < (row.va if virtual else row.offset) + (row.size if backed or not virtual else row.span)
                               and start + length > (row.va if virtual else row.offset)]
                    with self.subTest(virtual=virtual, backed=backed, start=start, length=length):
                        if len(matches) == 1:
                            self.assertIs(lookup.single(start, length), matches[0])
                        else:
                            with self.assertRaises(ContractError): lookup.single(start, length)


    def test_query_modes_accept_valid_declared_readings(self):
        target = self.target()
        address, xrefs = self.xref_rows()
        cases = (("ghidra.functions", self.function_rows(), {}),
                 ("ghidra.function", [target], {"entry": target["value"]["entry"]}),
                 ("ghidra.xrefs", xrefs, {"address": address}))
        for operation, items, args in cases:
            try:
                self.check(items, operation, args)
                accepted = True
            except (ContractError, TypeError):
                accepted = False
            with self.subTest(operation=operation):
                self.assertTrue(accepted, "The declared query mode must admit its valid anchored reading")

    def test_xref_ties_are_unique_and_ascii_sorted_by_instruction_then_type(self):
        address, rows = self.xref_rows()
        first = copy.deepcopy(rows[0])
        first["value"].update(type="data", total=2)
        second = copy.deepcopy(first)
        second["value"].update(index=1, type="read")
        args = {"address": address}
        self.check([first, second], "ghidra.xrefs", args)
        reversed_types = [copy.deepcopy(second), copy.deepcopy(first)]
        for index, row in enumerate(reversed_types): row["value"]["index"] = index
        self.refuse(reversed_types, operation="ghidra.xrefs", args=args)
        second["value"]["type"] = first["value"]["type"]
        self.refuse([first, second], operation="ghidra.xrefs", args=args)
        second["value"]["from"] = None
        self.refuse([first, second], operation="ghidra.xrefs", args=args)
        # The destination does not need to be mapped: unresolved and memory-only targets are readings too.
        for row in (first, second): row["value"]["to"] = 2**64 - 1
        second["value"]["type"] = "write"
        self.check([first, second], "ghidra.xrefs", {"address": 2**64 - 1})

    def test_instruction_truncation_is_exact_and_empty_pages_have_no_observation(self):
        target = self.target()
        page = self.instruction_page(target)
        args = {"entry": target["value"]["entry"], "parts": "assembly", "limit": 3}
        changed = copy.deepcopy(page)
        changed["value"]["truncated"] = True
        self.check([target, changed], args=args)
        self.refuse([target, page], args=args)
        self.refuse([target, changed], args={**args, "limit": 2})
        changed["value"]["total"] = 2
        self.refuse([target, changed], args=args)
        changed["value"]["truncated"] = False
        self.check([target, changed], args=args)
        self.check([target], args={**args, "start": 65535})
        changed["value"]["start"] = 2
        self.refuse([target, changed], args={**args, "start": 2})

    def test_declared_totals_bound_reported_call_instructions_and_query_walk_counts(self):
        target, callers = self.caller_rows()
        args = {"entry": target["value"]["entry"], "parts": "callers"}
        for total in (0, 1, 65537):
            changed = copy.deepcopy(target)
            changed["value"]["callers_total"] = total
            self.refuse([changed, *callers], args=args)
        target = self.target(2)
        calls = [row for row in records(self.layout) if row["value"]["kind"] == "call"
                 and row["value"]["from"] == target["value"]["entry"]]
        args = {"entry": target["value"]["entry"], "parts": "callees"}
        self.refuse([target, calls[0], calls[0]], args=args)
        target["value"]["callees_total"] = 1
        self.refuse([target, *calls], args=args)
        rows = self.function_rows()
        for row in rows: row["value"]["total"] = 65537
        self.refuse(rows, operation="ghidra.functions")
        address, xrefs = self.xref_rows()
        for row in xrefs: row["value"]["total"] = 65537
        self.refuse(xrefs, operation="ghidra.xrefs", args={"address": address})

    def test_all_mode_admits_643_observations_with_every_part_at_its_maximum(self):
        data, layout = elf(entry=0x1000, sections=((b".text", 1, 6, 4096),))
        data = bytearray(data)
        struct.pack_into("<Q", data, layout["shoff"] + 64 + 16, 0x1000)
        offset = layout["offsets"][0]
        anchor = {"offset": offset, "length": 4096}
        target = {"location": anchor, "value": {"kind": "target", "name": "large", "entry": 0x1000,
                  "size": 4096, "matches": 1, "callers_total": 256, "callees_total": 256}}
        pseudo = {"location": anchor, "value": {"kind": "pseudocode", "index": 0, "entry": 0x1000,
                  "text": "return;", "truncated": False}}
        page = {"location": {"offset": offset, "length": 256}, "value": {"kind": "instructions", "entry": 0x1000,
                "start": 0, "total": 256, "rows": [[i, 1, "N"] for i in range(256)], "truncated": False}}
        calls = [{"location": {"offset": offset + i, "length": 1}, "value": {
                 "kind": "call", "from": 0x1000, "to": 0x1000, "to_name": "large"}} for i in range(256)]
        callers = [{"location": {"offset": offset + i, "length": 1}, "value": {
                   "kind": "caller", "at": 0x1000 + i, "from": 0x1000, "to": 0x1000}} for i in range(256)]
        refs = [{"location": {"offset": offset + i, "length": 1}, "value": {
                "kind": "ref", "from": 0x1000, "to": 0x5000 + i, "type": "data", "to_name": ""}} for i in range(128)]
        items = [target, pseudo, page, *calls, *callers, *refs]
        self.assertEqual(len(items), 643)
        args = {"entry": 0x1000, "limit": 256, "max_calls": 256, "max_refs": 128}
        self.check(items, args=args, data=bytes(data))
        self.refuse(items + [refs[-1]], args=args, data=bytes(data))

    def test_query_modes_preserve_elf_pe_macho_function_and_instruction_mapping(self):
        for builder in (elf_code, pe_code, macho_code):
            data, layout = builder()
            target = query_function_records(layout)
            args = {"entry": target["value"]["entry"], "parts": "info"}
            with self.subTest(format=layout["format"]):
                self.check([target], args=args, data=data)
                changed = copy.deepcopy(target)
                changed["location"]["offset"] += 1
                self.refuse([changed], args=args, data=data)

    def test_each_query_kind_requires_all_and_only_its_declared_fields(self):
        target, callers = self.caller_rows()
        page = self.instruction_page(target)
        pseudo = {"location": dict(target["location"]), "value": {
            "kind": "pseudocode", "index": 0, "entry": target["value"]["entry"], "text": "return;", "truncated": False}}
        address, xrefs = self.xref_rows()
        cases = [("ghidra.functions", self.function_rows(0, 1), {}, 0),
                 ("ghidra.function", [target], {"entry": target["value"]["entry"]}, 0),
                 ("ghidra.function", [target, pseudo], {"entry": target["value"]["entry"]}, 1),
                 ("ghidra.function", [target, page], {"entry": target["value"]["entry"], "limit": 2}, 1),
                 ("ghidra.function", [target, *callers], {"entry": target["value"]["entry"]}, 1),
                 ("ghidra.xrefs", xrefs, {"address": address}, 0)]
        for operation, items, args, index in cases:
            for field in (*items[index]["value"], "extra"):
                changed = copy.deepcopy(items)
                if field == "extra": changed[index]["value"][field] = 1
                else: del changed[index]["value"][field]
                with self.subTest(operation=operation, kind=items[index]["value"]["kind"], field=field):
                    self.refuse(changed, operation=operation, args=args)

    def test_interval_index_keeps_virtual_only_ambiguity_and_half_open_boundaries(self):
        rows = [ghidra_verify._Section(10, 100, 20, 20, True),
                ghidra_verify._Section(15, 200, 2, 2, False),
                ghidra_verify._Section(17, 300, 0, 4, True)]
        index = ghidra_verify._SectionIndex(rows)
        self.assertEqual(ghidra_verify._map(index, 10, 5, virtual=True)[0], 100)
        for start, length in ((9, 2), (14, 2), (17, 1), (20, 2), (29, 2), (30, 1)):
            with self.subTest(start=start, length=length), self.assertRaises(ContractError):
                ghidra_verify._map(index, start, length, virtual=True)
        self.assertEqual(ghidra_verify._file_map(index, 17, 1, virtual=True)[0], 107)
        self.assertEqual(ghidra_verify._map(index, 21, 9, virtual=True)[0], 111)
        self.assertEqual(ghidra_verify._map(index, 107, 1, virtual=False)[0], 17)
        extreme = ghidra_verify._SectionIndex([ghidra_verify._Section(2**64 - 4, 0, 4, 4, True)])
        self.assertEqual(ghidra_verify._map(extreme, 2**64 - 1, 1, virtual=True)[0], 3)


    def test_incoming_references_may_belong_to_a_body_chunk_before_its_function_entry(self):
        target, callers = self.caller_rows()
        args = {"entry": target["value"]["entry"], "parts": "callers"}
        changed = copy.deepcopy(callers)
        changed[0]["value"]["from"] = self.layout["functions"][2]["entry"]
        self.assertGreater(changed[0]["value"]["from"], changed[0]["value"]["at"])
        self.check([target, *changed], args=args)
        address, xrefs = self.xref_rows()
        for row in xrefs: row["value"]["from"] = row["value"]["at"] + 1
        self.check(xrefs, "ghidra.xrefs", {"address": address})
        for row in xrefs: row["value"]["from"] = None
        self.check(xrefs, "ghidra.xrefs", {"address": address})


    def test_gapped_instruction_page_anchor_accepts_4096_but_refuses_a_4097_byte_span(self):
        data, layout = elf(entry=0x1000, sections=((b".text", 1, 6, 8192),))
        data = bytearray(data)
        struct.pack_into("<Q", data, layout["shoff"] + 64 + 16, 0x1000)
        offset = layout["offsets"][0]
        anchor = {"offset": offset, "length": 4096}
        target = {"location": anchor, "value": {"kind": "target", "name": "sparse", "entry": 0x1000,
                  "size": 8192, "matches": 1, "callers_total": 0, "callees_total": 0}}
        page = {"location": anchor, "value": {"kind": "instructions", "entry": 0x1000,
                "start": 0, "total": 2, "rows": [[0, 1, "NOP"], [4095, 1, "RET"]], "truncated": False}}
        args = {"entry": 0x1000, "parts": "assembly", "limit": 2}
        self.check([target, page], args=args, data=bytes(data))
        page["value"]["rows"][-1][0] = 4096
        self.refuse([target, page], args=args, data=bytes(data))
