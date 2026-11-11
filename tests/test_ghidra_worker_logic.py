"""The Ghidra worker's pure logic, without Ghidra: requests, the file's own sections, anchor cross-checks, the function
selection rules and the reply.

Query outputs are built here from tests/fixtures_code.py's declared layout (addresses, offsets, sizes and calls fixed
by the fixture's own assembler), never from the worker or from Ghidra, and the expected observations come from the
same declared layout; an optional rebase delta stands for Ghidra loading the program at another base.
"""

import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import signal
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from reverseai.contract import Location, Observation, WorkerError, parse_worker_reply, sha256_hex
from reverseai.tools import ghidra_verify, structure
from reverseai.contract import MAX_WORKER_REPLY_BYTES, canonical_json
from tests.fixtures_code import (
    DATA_SIZE, REFS_TEXT_SIZE, TEXT_SIZE, elf_code, elf_data_only, elf_refs, macho_code, macho_refs, pe_code, pe_refs,
)

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "containers" / "ghidra"
SPEC = importlib.util.spec_from_file_location("ghidra_worker", SOURCE / "worker.py")
worker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(worker)
DEFAULTS = {"max_functions": 64, "decompile": 8, "max_chars": 1024, "max_calls": 128,
            "assembly": 4, "max_instructions": 32, "max_refs": 64, "max_strings": 32}
MINIMA = {"max_functions": 1, "decompile": 0, "max_chars": 64, "max_calls": 0, "assembly": 0, "max_instructions": 1, "max_refs": 0,
          "max_strings": 0}
MAXIMA = {"max_functions": 128, "decompile": 16, "max_chars": 2048, "max_calls": 256, "assembly": 8, "max_instructions": 64,
          "max_refs": 128, "max_strings": 64}
PE_NAMES = ("entry", "FUN_140001020", "FUN_140001030", "FUN_140001050")


def query(data, layout, *, delta=0, names=None, texts=None, options=None):
    """What a correct ReverseAIQuery writes for a fixture, from its declared layout; Ghidra addresses = VA + delta."""
    text = layout["text"]
    names = names or [f["name"] for f in layout["functions"]]
    block_size = layout.get("text_raw_size", TEXT_SIZE)
    blocks = [{"name": ".text", "start": text["address"] + delta, "size": block_size, "execute": True,
               "initialized": True, "file_offset": text["offset"]}]
    if "data" in layout:
        blocks.append({"name": ".data", "start": layout["data"]["address"] + delta, "size": 0x200, "execute": False,
                       "initialized": True, "file_offset": layout["data"]["offset"]})
    by_entry = {f["entry"]: name for f, name in zip(layout["functions"], names)}
    functions = []
    for function, name in zip(layout["functions"], names):
        calls = [{"address": c["address"] + delta, "length": c["length"], "file_offset": c["offset"],
                  "bytes": data[c["offset"]:c["offset"] + c["length"]].hex(), "to": c["to"] + delta,
                  "to_file_offset": c["to"] - text["address"] + text["offset"], "to_name": by_entry[c["to"]]}
                 for c in layout["calls"] if c["from"] == function["entry"]]
        functions.append({"name": name, "entry": function["entry"] + delta, "size": function["size"],
                          "file_offset": function["offset"], "anchored": True,
                          "bytes": data[function["offset"]:function["offset"] + function["size"]].hex(), "calls": calls})
    texts = texts if texts is not None else {f["entry"]: f"int f_{f['offset']:x}(void)\n{{\n}}\n" for f in layout["functions"]}
    return {"format": "x", "options_off": options or {}, "blocks": blocks, "functions": functions,
            "pseudocode": [{"entry": entry + delta, "text": t} for entry, t in texts.items()]}


def expected(layout, names=None, *, args=DEFAULTS, texts=None):
    """The function, pseudocode and call observations for the declared layout and request."""
    names = names or [f["name"] for f in layout["functions"]]
    functions = [dict(f, name=n, index=i) for i, (f, n) in enumerate(zip(layout["functions"], names))][:args["max_functions"]]
    end = layout["text"]["offset"] + TEXT_SIZE
    result = [{"location": {"offset": f["offset"], "length": min(f["size"], 4096, end - f["offset"])},
               "value": {"kind": "function", "index": f["index"], "name": f["name"], "entry": f["entry"], "size": f["size"]}}
              for f in functions]
    texts = texts if texts is not None else {f["entry"]: f"int f_{f['offset']:x}(void)\n{{\n}}\n" for f in layout["functions"]}
    order = [f for f in functions if f["entry"] == layout["entry"]]
    order += sorted((f for f in functions if f["entry"] != layout["entry"]), key=lambda f: (-f["size"], f["entry"]))
    for f in order[:args["decompile"]]:
        text = texts.get(f["entry"])
        if text is not None:
            result.append({"location": result[f["index"]]["location"],
                           "value": {"kind": "pseudocode", "index": f["index"], "entry": f["entry"],
                                     "text": text[:args["max_chars"]], "truncated": len(text) > args["max_chars"]}})
    entries = {f["entry"] for f in functions}
    by_entry = {f["entry"]: f["name"] for f in functions} | {f["entry"]: n for f, n in zip(layout["functions"], names)}
    calls = sorted((c for c in layout["calls"] if c["from"] in entries), key=lambda c: c["address"])[:args["max_calls"]]
    result += [{"location": {"offset": c["offset"], "length": 5},
                "value": {"kind": "call", "from": c["from"], "to": c["to"], "to_name": by_entry[c["to"]]}} for c in calls]
    return result


def observe(data, q, **args):
    return worker.observations(data, q, dict(DEFAULTS, **args))


def macho_commands(data):
    """The load commands of a thin 64-bit Mach-O, as (cmd, bytes)."""
    count, at, found = struct.unpack_from("<I", data, 16)[0], 32, []
    for _ in range(count):
        command, size = struct.unpack_from("<II", data, at)
        found.append((command, data[at:at + size]))
        at += size
    return found


def macho_rebuilt(data, commands, cputype=None):
    """macho_code with other load commands; the code at 0x200 and __LINKEDIT stay where they are."""
    header = bytearray(data[:32])
    struct.pack_into("<II", header, 16, len(commands), sum(map(len, commands)))
    if cputype is not None:
        struct.pack_into("<I", header, 4, cputype)
    rebuilt = bytes(header) + b"".join(commands)
    assert len(rebuilt) <= 0x200
    return rebuilt + bytes(0x200 - len(rebuilt)) + data[0x200:]


def unixthread(flavor, count, pc, pc_offset, extra=b""):
    """LC_UNIXTHREAD with one (flavor, count) state holding pc at pc_offset, then extra bytes."""
    state = bytearray(count * 4)
    if pc_offset + 8 <= len(state):
        struct.pack_into("<Q", state, pc_offset, pc)
    body = struct.pack("<II", flavor, count) + bytes(state) + extra
    return struct.pack("<II", 0x5, 8 + len(body)) + body


def macho_text_and_main(data):
    commands = macho_commands(data)
    return (next(body for command, body in commands if command == 0x19 and body[8:14] == b"__TEXT"),
            next(body for command, body in commands if command == 0x80000028))


# What a correct ReverseAIQuery writes for the refs fixtures; Ghidra's reference-type flags per x86 access.
FLAGS = {"data": (False, False, False, False, True), "read": (False, False, True, False, True), "write": (False, False, False, True, True),
         "read_write": (False, False, True, True, True), "jump": (True, True, False, False, False)}


def ranked(layout):
    first = [f for f in layout["functions"] if f["entry"] == layout["entry"]]
    return first + sorted((f for f in layout["functions"] if f["entry"] != layout["entry"]), key=lambda f: (-f["size"], f["entry"]))


def file_offset(layout, address):
    for block in (layout["text"], layout["data"]):
        if block["address"] <= address < block["address"] + block["size"]:
            return block["offset"] + address - block["address"]
    return -1


def refs_query(data, layout, *, delta=0, names=None, flags=None, listing=None):
    """query() for a refs fixture plus its data block, each function's references and every function's listing;
    instruction texts are INSN_<delta>, unless listing(function, rows) returns other rows."""
    names = names or [f["name"] or f"FUN_{f['entry']:x}" for f in layout["functions"]]
    q = query(data, layout, delta=delta, names=names)
    q["blocks"][0]["size"] = layout.get("text_raw_size", REFS_TEXT_SIZE)
    q["blocks"].append({"name": ".data", "start": layout["data"]["address"] + delta, "size": DATA_SIZE, "execute": False,
                        "initialized": True, "file_offset": layout["data"]["offset"]})
    by_entry = {f["entry"]: name for f, name in zip(layout["functions"], names)}
    for function, item in zip(layout["functions"], q["functions"]):
        item["refs"] = []
        for ref in (r for r in layout["refs"] if r["from"] == function["entry"]):
            flow, jump, read, write, is_data = (flags or FLAGS)[ref["type"]]
            item["refs"].append({"address": ref["address"] + delta, "length": ref["length"], "file_offset": ref["offset"],
                                 "bytes": data[ref["offset"]:ref["offset"] + ref["length"]].hex(), "to": ref["to"] + delta,
                                 "to_file_offset": file_offset(layout, ref["to"]), "to_name": ref["to_name"] or by_entry.get(ref["to"], ""),
                                 "type": ref["type"].upper(), "flow": flow, "jump": jump, "read": read, "write": write, "data": is_data,
                                 "inside": False})
    q["assembly"] = []
    for function in layout["functions"]:
        rows = [{"address": function["entry"] + d + delta, "length": n, "file_offset": function["offset"] + d,
                 "bytes": data[function["offset"] + d:function["offset"] + d + n].hex(), "text": f"INSN_{d:x}"}
                for d, n in function["instructions"]]
        rows = listing(function, rows) if listing else rows
        q["assembly"].append({"entry": function["entry"] + delta, "instructions": rows, "count": len(function["instructions"])})
    return q


def expected_m3c(layout, names=None, *, args=DEFAULTS):
    """Expected listings, six references and two strings for a refs fixture, in ranked order."""
    names = names or [f["name"] or f"FUN_{f['entry']:x}" for f in layout["functions"]]
    index = {f["entry"]: i for i, f in enumerate(layout["functions"])}
    by_entry = {f["entry"]: name for f, name in zip(layout["functions"], names)}
    end = layout["text"]["offset"] + REFS_TEXT_SIZE
    result = []
    for f in ranked(layout)[:args["assembly"]]:
        rows = [[d, n, f"INSN_{d:x}"] for d, n in f["instructions"]][:args["max_instructions"]]
        result.append({"location": {"offset": f["offset"], "length": min(f["size"], 4096, end - f["offset"])},
                       "value": {"kind": "assembly", "index": index[f["entry"]], "entry": f["entry"], "instructions": rows,
                                 "truncated": len(rows) < len(f["instructions"])}})
    refs = sorted(layout["refs"], key=lambda r: (r["offset"], r["to"], r["type"]))[:args["max_refs"]]
    result += [{"location": {"offset": r["offset"], "length": r["length"]},
                "value": {"kind": "ref", "from": r["from"], "to": r["to"], "type": r["type"], "to_name": r["to_name"] or by_entry.get(r["to"], "")}}
               for r in refs]
    targets = {r["to"] for r in refs}
    result += [{"location": {"offset": s["offset"], "length": s["length"]},
                "value": {"kind": "string", "address": s["address"], "encoding": s["encoding"], "text": s["text"],
                          "truncated": s["truncated"], "from": s["from"]}}
               for s in layout["strings"] if s["address"] in targets][:args["max_strings"]]
    return result


def code_elf(text, rodata, *, entry_offset=0):
    """A minimal ELF64 x86-64 with an AX .text at 0x400100 and an A .rodata right after it; no program headers."""
    text_offset, base = 0x100, 0x400000
    rodata_offset = text_offset + len(text)
    shstrtab, shnames = b"\0.text\0.rodata\0.shstrtab\0", (1, 7, 15)
    shoff = (rodata_offset + len(rodata) + len(shstrtab) + 7) & ~7
    sections = (bytes(64)
                + struct.pack("<IIQQQQIIQQ", shnames[0], 1, 0x6, base + text_offset, text_offset, len(text), 0, 0, 16, 0)
                + struct.pack("<IIQQQQIIQQ", shnames[1], 1, 0x2, base + rodata_offset, rodata_offset, len(rodata), 0, 0, 1, 0)
                + struct.pack("<IIQQQQIIQQ", shnames[2], 3, 0, 0, rodata_offset + len(rodata), len(shstrtab), 0, 0, 1, 0))
    header = (b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
              + struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, base + text_offset + entry_offset, 0, shoff, 0, 64, 0, 0, 64, 4, 3))
    data = header + bytes(text_offset - len(header)) + text + rodata + shstrtab
    return data + bytes(shoff - len(data)) + sections, {"text": (text_offset, base + text_offset), "rodata": (rodata_offset, base + rodata_offset)}


class KnownAnswerTests(unittest.TestCase):
    def test_elf_and_pe_observations_equal_the_declared_layout(self):
        for label, (data, layout), names in (("elf", elf_code(), None), ("pe", pe_code(), PE_NAMES), ("macho", macho_code(), None)):
            with self.subTest(label):
                self.assertEqual(observe(data, query(data, layout, names=names)), expected(layout, names))

    def test_a_rebased_program_still_reports_the_files_own_addresses(self):
        for build, delta in ((elf_code, 0x100000), (elf_code, -0x400000 + 0x1000), (macho_code, -0x100000000 + 0x4000)):
            data, layout = build()
            with self.subTest(build.__name__, delta=hex(delta)):
                self.assertEqual(observe(data, query(data, layout, delta=delta)), expected(layout))

    def test_known_values(self):
        data, layout = elf_code()
        result = observe(data, query(data, layout))
        self.assertEqual([o["value"]["name"] for o in result if o["value"]["kind"] == "function"],
                         ["_start", "add_numbers", "compute", "constant"])
        self.assertEqual([(o["location"]["offset"], o["location"]["length"]) for o in result if o["value"]["kind"] == "function"],
                         [(0x100, 20), (0x120, 10), (0x130, 27), (0x150, 6)])
        self.assertEqual([o["value"]["entry"] for o in result if o["value"]["kind"] == "pseudocode"],
                         [0x400100, 0x400130, 0x400120, 0x400150])  # entry point, then by size
        self.assertEqual([(o["location"]["offset"], o["value"]["from"], o["value"]["to"], o["value"]["to_name"])
                          for o in result if o["value"]["kind"] == "call"],
                         [(0x100, 0x400100, 0x400120, "add_numbers"), (0x105, 0x400100, 0x400130, "compute"),
                          (0x13B, 0x400130, 0x400120, "add_numbers"), (0x142, 0x400130, 0x400150, "constant")])

    def test_the_data_only_control_has_no_observations(self):
        data, layout = elf_data_only()
        q = {"options_off": {}, "blocks": [{"start": layout["data"]["address"], "size": layout["data"]["size"],
                                            "file_offset": layout["data"]["offset"]}], "functions": [], "pseudocode": []}
        self.assertEqual(observe(data, q), [])

    def test_observation_values_have_exactly_the_seam_fields(self):
        data, layout = pe_code()
        fields = {"function": {"kind", "index", "name", "entry", "size"}, "pseudocode": {"kind", "index", "entry", "text", "truncated"},
                  "call": {"kind", "from", "to", "to_name"}}
        for item in observe(data, query(data, layout, names=PE_NAMES)):
            self.assertEqual(set(item["value"]), fields[item["value"]["kind"]])
            self.assertTrue(1 <= item["location"]["length"] <= 4096)


class SelectionTests(unittest.TestCase):
    def test_caps_and_the_emitted_function_rule(self):
        data, layout = elf_code()
        for args in ({"max_functions": 1}, {"max_functions": 2}, {"max_functions": 3, "decompile": 2},
                     {"decompile": 0}, {"decompile": 1}, {"max_calls": 0}, {"max_calls": 3}, {"max_chars": 64},
                     {"max_functions": 2, "decompile": 1, "max_chars": 64, "max_calls": 1}):
            with self.subTest(args=args):
                self.assertEqual(observe(data, query(data, layout), **args), expected(layout, args=dict(DEFAULTS, **args)))

    def test_the_first_functions_are_chosen_by_address_whatever_the_query_order(self):
        data, layout = elf_code()
        q = query(data, layout)
        q["functions"].reverse()
        self.assertEqual(observe(data, q, max_functions=2), expected(layout, args=dict(DEFAULTS, max_functions=2)))

    def test_max_functions_2_keeps_calls_and_pseudocode_of_emitted_functions_only(self):
        data, layout = elf_code()
        result = observe(data, query(data, layout), max_functions=2)
        self.assertEqual([o["value"]["entry"] for o in result if o["value"]["kind"] == "pseudocode"], [0x400100, 0x400120])
        self.assertEqual([o["value"]["from"] for o in result if o["value"]["kind"] == "call"], [0x400100, 0x400100])

    def test_largest_ties_go_to_the_lower_entry(self):
        data, layout = elf_code()
        q = query(data, layout)
        for function in q["functions"][1:]:
            function["size"] = 6
            function["bytes"] = function["bytes"][:12]
        result = observe(data, q)
        self.assertEqual([o["value"]["entry"] for o in result if o["value"]["kind"] == "pseudocode"],
                         [0x400100, 0x400120, 0x400130, 0x400150])

    def test_text_is_cut_at_max_chars_and_marked_truncated(self):
        data, layout = elf_code()
        long = "x" * 100
        texts = {f["entry"]: long for f in layout["functions"]}
        result = observe(data, query(data, layout, texts=texts), max_chars=64)
        pseudo = [o["value"] for o in result if o["value"]["kind"] == "pseudocode"]
        self.assertTrue(all(p["text"] == "x" * 64 and p["truncated"] for p in pseudo))
        exact = observe(data, query(data, layout, texts={f["entry"]: "y" * 64 for f in layout["functions"]}), max_chars=64)
        self.assertTrue(all(o["value"]["truncated"] is False for o in exact if o["value"]["kind"] == "pseudocode"))

    def test_pseudocode_of_a_function_that_is_not_emitted_is_ignored(self):
        data, layout = elf_code()
        q = query(data, layout)
        q["pseudocode"].append({"entry": 0x401000, "text": "int stray(void)\n"})
        self.assertEqual(observe(data, q), expected(layout))

    def test_a_failed_decompilation_is_omitted(self):
        data, layout = elf_code()
        texts = {layout["functions"][2]["entry"]: "int compute(void)\n"}
        result = observe(data, query(data, layout, texts=texts))
        self.assertEqual([o["value"]["entry"] for o in result if o["value"]["kind"] == "pseudocode"], [0x400130])

    def test_functions_the_query_did_not_anchor_or_outside_an_executable_section_are_not_emitted(self):
        data, layout = pe_code()
        q = query(data, layout, names=PE_NAMES)
        q["functions"][1]["anchored"] = False
        data_function = dict(q["functions"][0], entry=layout["data"]["address"], file_offset=layout["data"]["offset"], size=4,
                             bytes=data[layout["data"]["offset"]:layout["data"]["offset"] + 4].hex(), calls=[])
        q["functions"].append(data_function)
        q["blocks"][1]["execute"] = True  # even if Ghidra marks it executable, the file's .data is not
        names = [o["value"]["name"] for o in observe(data, q) if o["value"]["kind"] == "function"]
        self.assertEqual(names, ["entry", "FUN_140001030", "FUN_140001050"])

    def test_calls_outside_their_function_or_longer_than_16_bytes_are_dropped(self):
        data, layout = elf_code()
        q = query(data, layout)
        q["functions"][1]["calls"].append(dict(q["functions"][0]["calls"][0]))  # before add_numbers: entry's call
        q["functions"][1]["calls"].append(dict(q["functions"][2]["calls"][1]))  # after add_numbers ends: compute's call
        long = dict(q["functions"][2]["calls"][0], length=17)
        q["functions"][2]["calls"][0] = long
        result = observe(data, q)
        self.assertEqual([(o["value"]["from"], o["location"]["offset"]) for o in result if o["value"]["kind"] == "call"],
                         [(0x400100, 0x100), (0x400100, 0x105), (0x400130, 0x142)])

    def test_a_call_to_an_unmapped_target_keeps_the_rebased_address(self):
        data, layout = elf_code()
        q = query(data, layout, delta=0x100000)
        q["functions"][0]["calls"][0].update(to=0x900000 + 0x100000, to_file_offset=-1, to_name="external")
        call = [o for o in observe(data, q) if o["value"]["kind"] == "call"][0]
        self.assertEqual((call["value"]["to"], call["value"]["to_name"]), (0x900000, "external"))


class BoundTests(unittest.TestCase):
    def test_an_anchor_stops_at_the_section_end_and_at_max_location(self):
        data, layout = elf_code()
        q = query(data, layout)
        last = q["functions"][3]  # constant: 6 bytes left in .text
        last.update(size=40, bytes=data[last["file_offset"]:last["file_offset"] + 40].hex())
        result = {o["value"]["name"]: (o["location"]["length"], o["value"]["size"]) for o in observe(data, q)
                  if o["value"]["kind"] == "function"}
        self.assertEqual(result["constant"], (6, 40))
        small = query(data, layout)
        for function in small["functions"]:
            function["bytes"] = function["bytes"][:16]  # the query sends at most MAX_LOCATION bytes
        with patch.object(worker, "MAX_LOCATION", 8):
            lengths = [o["location"]["length"] for o in observe(data, small) if o["value"]["kind"] == "function"]
        self.assertEqual(lengths, [8, 8, 8, 6])

    def test_a_sparse_body_keeps_the_calls_in_its_span(self):
        """Size is entry to last body byte, so a call after a gap is still inside."""
        data, layout = elf_code()
        q = query(data, layout)
        start = q["functions"][0]
        start["size"] = 0x56  # _start's span reaching the end of .text, as if its body continued there
        start["bytes"] = data[start["file_offset"]:start["file_offset"] + 0x56].hex()
        late = dict(q["functions"][2]["calls"][1])  # compute's call at 0x142, now also inside _start's span
        start["calls"].append(late)
        froms = [(o["value"]["from"], o["location"]["offset"]) for o in observe(data, q) if o["value"]["kind"] == "call"]
        self.assertIn((0x400100, 0x142), froms)

    def test_the_native_sparse_body_shape_is_accepted_with_its_span(self):
        """The shape Ghidra reported for the native sparse case: _start's body is [0x00, 0x17) and [0x2a, 0x30)."""
        data, layout = elf_code()
        patched, text = bytearray(data), layout["text"]["offset"]
        code = (b"\xe8" + (0x20 - 0x05).to_bytes(4, "little") + b"\x85\xc0" + b"\x0f\x84" + (0x2a - 0x0d).to_bytes(4, "little")
                + b"\xb8\x3c\x00\x00\x00\x31\xff\x0f\x05\xc3")
        patched[text:text + 0x20] = code + b"\xcc" * (0x20 - len(code))
        patched[text + 0x2a:text + 0x30] = b"\xe8" + (0x30 - 0x2f).to_bytes(4, "little") + b"\xc3"
        data = bytes(patched)
        q = query(data, layout)
        start = q["functions"][0]
        late = {"address": 0x40012a, "length": 5, "file_offset": text + 0x2a, "bytes": data[text + 0x2a:text + 0x2f].hex(),
                "to": 0x400130, "to_file_offset": text + 0x30, "to_name": "compute"}
        start.update(size=0x30, bytes=data[text:text + 0x30].hex(), calls=[start["calls"][0], late])
        result = observe(data, q)
        self.assertEqual([(o["location"]["offset"], o["location"]["length"], o["value"]["size"]) for o in result
                          if o["value"]["kind"] == "function"][0], (text, 0x30, 0x30))
        self.assertEqual([(o["value"]["from"], o["location"]["offset"]) for o in result if o["value"]["kind"] == "call"][:2],
                         [(0x400100, text), (0x400100, text + 0x2a)])
        start["size"] = 29  # the old byte count: the call after the gap falls outside and is dropped
        start["bytes"] = start["bytes"][:58]
        froms = [o["location"]["offset"] for o in observe(data, q) if o["value"]["kind"] == "call" and o["value"]["from"] == 0x400100]
        self.assertEqual(froms, [text])

    def test_a_call_whose_target_maps_below_zero_is_dropped(self):
        data, layout = elf_code()
        q = query(data, layout, delta=0x100000)
        q["functions"][0]["calls"][0].update(to=0x1000, to_file_offset=-1)  # 0x1000 - delta < 0
        calls = [o["location"]["offset"] for o in observe(data, q) if o["value"]["kind"] == "call"]
        self.assertEqual(calls, [0x105, 0x13B, 0x142])

    def test_a_too_large_input_is_refused_and_the_digest_covers_the_whole_file(self):
        data, layout = elf_code()
        with patch.object(worker, "MAX_INPUT_BYTES", len(data) - 1):
            self.assertEqual(worker.reply(["ghidra.analyze", "{}"], data, lambda f, a, o: query(data, layout))["error"], "InputTooLarge")
        with tempfile.TemporaryDirectory() as folder, patch.object(worker, "MAX_INPUT_BYTES", 16):
            path = Path(folder, "input")
            path.write_bytes(data)
            kept, digest = worker.read_snapshot(path)
        self.assertEqual((len(kept), digest), (17, hashlib.sha256(data).hexdigest()))


class CrossCheckTests(unittest.TestCase):
    def refused(self, data, q, error=worker.InconsistentAnchor):
        with self.assertRaises(error):
            observe(data, q)

    def test_bytes_blocks_and_rebase_must_agree_at_every_anchor(self):
        data, layout = elf_code()
        cases = {
            "function bytes": lambda q: q["functions"][1].update(bytes="00" + q["functions"][1]["bytes"][2:]),
            "function bytes too short": lambda q: q["functions"][1].update(bytes=q["functions"][1]["bytes"][:4]),
            "file offset of another function": lambda q: q["functions"][1].update(file_offset=layout["functions"][2]["offset"]),
            "block offset": lambda q: q["blocks"][0].update(file_offset=q["blocks"][0]["file_offset"] + 1),
            "a second delta": lambda q: q["functions"][3].update(entry=q["functions"][3]["entry"] + 0x1000),
            "call bytes": lambda q: q["functions"][0]["calls"][0].update(bytes="e800000000"),
            "call address": lambda q: q["functions"][0]["calls"][0].update(address=q["functions"][0]["calls"][0]["address"] + 1),
            "a second rebase through a second block": lambda q: (
                q["blocks"].append(dict(q["blocks"][0], start=q["blocks"][0]["start"] + 0x1000)),
                q["functions"][3].update(entry=q["functions"][3]["entry"] + 0x1000)),
        }
        for label, change in cases.items():
            with self.subTest(label):
                q = query(data, layout)
                change(q)
                self.refused(data, q)

    def test_options_ghidra_should_have_turned_off_must_be_off(self):
        data, layout = pe_code()
        self.assertTrue(observe(data, query(data, layout, names=PE_NAMES, options={"PDB Universal": "false", "x.Path": ""})))
        for options in ({"PDB Universal": "true"}, {"DWARF": "TRUE"}, {"PDB Universal.Search untrusted symbol servers": "true"}):
            with self.subTest(options=options):
                self.refused(data, query(data, layout, names=PE_NAMES, options=options), worker.AnalysisOptionOn)

    def test_malformed_query_output_is_refused(self):
        data, layout = elf_code()
        cases = {
            "not an object": lambda q: [],
            "no options": lambda q: {k: v for k, v in q.items() if k != "options_off"},
            "option not text": lambda q: dict(q, options_off={"PDB": False}),
            "functions not a list": lambda q: dict(q, functions={}),
            "function not an object": lambda q: dict(q, functions=["f"]),
            "entry not an int": lambda q: (q["functions"][0].update(entry="0x400100"), q)[1],
            "negative size": lambda q: (q["functions"][0].update(size=-1), q)[1],
            "bytes not hex": lambda q: (q["functions"][0].update(bytes="zz"), q)[1],
            "name not text": lambda q: (q["functions"][0].update(name=7), q)[1],
            "pseudocode not an object": lambda q: (q["pseudocode"].append("text"), q)[1],
            "pseudocode entry not an int": lambda q: (q["pseudocode"][0].update(entry=None), q)[1],
            "pseudocode text not text": lambda q: (q["pseudocode"][0].update(text=None), q)[1],
            "call not an object": lambda q: (q["functions"][0]["calls"].append("call"), q)[1],
            "block without size": lambda q: (q["blocks"][0].pop("size"), q)[1],
        }
        for label, change in cases.items():
            with self.subTest(label), self.assertRaises(worker.InvalidQueryOutput):
                observe(data, change(query(data, layout)))

    def test_names_are_printable_ascii_of_at_most_128_and_text_keeps_lines(self):
        data, layout = elf_code()
        names = ["caf\u00e9\x07name", "x" * 200, "ok", "tab\tname"]
        texts = {layout["functions"][0]["entry"]: "a\x00b\nc\td\u2028e"}
        result = observe(data, query(data, layout, names=names, texts=texts))
        self.assertEqual([o["value"]["name"] for o in result if o["value"]["kind"] == "function"],
                         ["caf??name", "x" * 128, "ok", "tab?name"])
        self.assertEqual([o["value"]["text"] for o in result if o["value"]["kind"] == "pseudocode"], ["a?b\nc\td?e"])


class FileMapTests(unittest.TestCase):
    def test_the_workers_section_map_matches_the_fixtures(self):
        for build, sections in ((elf_code, [(0x100, 0x156, 0x400100, True)]),
                                (pe_code, [(0x200, 0x256, 0x140001000, True), (0x400, 0x410, 0x140002000, False)])):
            data, layout = build()
            with self.subTest(build.__name__):
                self.assertEqual((build is elf_code and worker.elf_map or worker.pe_map)(data), (layout["entry"], sections))
                self.assertEqual(worker.offset_of(sections, layout["entry"]), layout["text"]["offset"])

    def test_sections_without_file_bytes_or_not_allocated_are_not_mapped(self):
        data, layout = elf_code()
        symtab = layout["shoff"] + 2 * 64
        nobits = bytearray(data)
        nobits[symtab + 4:symtab + 16] = (8).to_bytes(4, "little") + (0x2).to_bytes(8, "little")  # SHT_NOBITS, SHF_ALLOC
        alloc = bytearray(data)
        alloc[symtab + 8:symtab + 16] = (0x2).to_bytes(8, "little")  # an allocated .symtab is mapped
        self.assertEqual(worker.elf_map(bytes(nobits))[1], [(0x100, 0x156, 0x400100, True)])
        self.assertEqual(worker.elf_map(bytes(alloc))[1], [(0x100, 0x156, 0x400100, True), (0x158, 0x158 + 120, 0, False)])

    def test_pe_sections_count_their_raw_bytes_when_virtual_size_is_zero(self):
        """PE extent is min(SizeOfRawData, VirtualSize), SizeOfRawData when VirtualSize is 0."""
        data, layout = pe_code()
        text_header = 0x40 + 4 + 20 + 240
        patched = bytearray(data)
        patched[text_header + 8:text_header + 12] = (0).to_bytes(4, "little")  # .text VirtualSize 0
        self.assertEqual(worker.pe_map(bytes(patched))[1][0], (0x200, 0x400, 0x140001000, True))
        patched[text_header + 8:text_header + 12] = (0x300).to_bytes(4, "little")  # larger than SizeOfRawData
        self.assertEqual(worker.pe_map(bytes(patched))[1][0], (0x200, 0x400, 0x140001000, True))

    def test_the_macho_map_follows_its_segments_sections_and_lc_main(self):
        data, layout = macho_code()
        self.assertEqual(worker.macho_map(data), (0x100000200, [(0x200, 0x256, 0x100000200, True)]))
        text = 32 + 72 + 72  # mach header, __PAGEZERO, then __TEXT's first section header
        section_flags, initprot = text + 64, 32 + 72 + 8 + 52
        plain = bytearray(data)
        plain[section_flags:section_flags + 4] = (0).to_bytes(4, "little")  # no instruction attribute ...
        self.assertEqual(worker.macho_map(bytes(plain))[1], [(0x200, 0x256, 0x100000200, True)])  # ... __TEXT is r-x
        plain[initprot:initprot + 4] = (0x1).to_bytes(4, "little")  # ... and r-- only
        self.assertEqual(worker.macho_map(bytes(plain))[1], [(0x200, 0x256, 0x100000200, False)])
        zerofill = bytearray(data)
        zerofill[section_flags:section_flags + 4] = (0x80000401).to_bytes(4, "little")  # S_ZEROFILL: no file bytes
        self.assertEqual(worker.macho_map(bytes(zerofill))[1], [])
        no_main = bytearray(data)
        main = data.index((0x80000028).to_bytes(4, "little") + (24).to_bytes(4, "little"))
        no_main[main:main + 4] = (0x7FFFFFFF).to_bytes(4, "little")  # an unknown command instead of LC_MAIN
        self.assertEqual(worker.macho_map(bytes(no_main))[0], 0)
        for label, cut in (("header", data[:20]), ("commands", data[:100])):
            with self.subTest(label), self.assertRaises(worker.TruncatedStructure):
                worker.macho_map(cut)
        overrun = bytearray(data)
        overrun[16:20] = (40).to_bytes(4, "little")  # ncmds past sizeofcmds
        with self.assertRaises(worker.TruncatedStructure):
            worker.macho_map(bytes(overrun))

    def test_macho_instruction_attributes_bounds_and_32_bit_headers(self):
        data, layout = macho_code()
        text = 32 + 72 + 72  # mach header, __PAGEZERO, then __TEXT's first section header
        section_flags, section_size, initprot, nsects = text + 64, text + 40, 32 + 72 + 60, 32 + 72 + 64
        for flags in (0x80000400, 0x80000000, 0x400):
            attributes = bytearray(data)
            attributes[initprot:initprot + 4] = (0x1).to_bytes(4, "little")  # r-- ...
            attributes[section_flags:section_flags + 4] = flags.to_bytes(4, "little")  # ... with an instruction attribute
            with self.subTest(flags=hex(flags)):
                self.assertEqual(worker.macho_map(bytes(attributes))[1], [(0x200, 0x256, 0x100000200, True)])
        main = data.index((0x80000028).to_bytes(4, "little") + (24).to_bytes(4, "little"))
        filesize = 32 + 72 + 48  # __TEXT's filesize: a section past it is not mapped, a segment past the input is refused
        cases = {"the last command past sizeofcmds": ((main + 4, 32),), "more sections than the command holds": ((nsects, 2),),
                 "section bytes past the end": ((section_size, 0x1000), (filesize, 0x2000))}
        for label, patches in cases.items():
            broken = bytearray(data)
            for at, value in patches:
                broken[at:at + 4] = value.to_bytes(4, "little")
            with self.subTest(label), self.assertRaises(worker.TruncatedStructure):
                worker.macho_map(bytes(broken))
        vmaddr = 0x1000  # a 32-bit header: LC_SEGMENT with its 56-byte command and 68-byte sections
        section = struct.pack("<16s16sIIIIIIIII", b"__text", b"__TEXT", vmaddr + 0x100, 0x10, 0x100, 4, 0, 0, 0x80000400, 0, 0)
        segment = struct.pack("<II16sIIIIiiII", 0x1, 56 + 68, b"__TEXT", vmaddr, 0x1000, 0, 0x110, 0x5, 0x5, 1, 0) + section
        lc_main = struct.pack("<IIQQ", 0x80000028, 24, 0x100, 0)
        thin32 = struct.pack("<IiiIIII", 0xFEEDFACE, 7, 3, 2, 2, len(segment) + len(lc_main), 0) + segment + lc_main
        thin32 += bytes(0x100 - len(thin32)) + bytes(0x10)
        self.assertEqual(worker.kind(thin32), "macho")
        self.assertEqual(worker.macho_map(thin32), (vmaddr + 0x100, [(0x100, 0x110, vmaddr + 0x100, True)]))

    def test_the_macho_entry_follows_the_hosts_lc_main_and_lc_unixthread_rule(self):
        """The entry that leads the pseudocode is the one the host verifier checks."""
        data, layout = macho_code()
        text, main = macho_text_and_main(data)
        def text_with(field, value):  # __TEXT with one of vmaddr (24), vmsize (32), filesize (48) changed
            changed = bytearray(text)
            struct.pack_into("<Q", changed, field, value)
            return bytes(changed)
        alias = struct.pack("<II16sQQQQiiII", 0x19, 72, b"__ALIAS", 0x200000000, 0x1000, 0, 0x256, 5, 5, 0, 0)
        x86 = unixthread(4, 42, 0x100000200, 128)
        malformed = unixthread(4, 42, 0x100000200, 128, struct.pack("<II", 9, 4))
        cases = {
            "LC_MAIN": (data, 0x100000200),
            "x86_64 rip": (macho_rebuilt(data, [text, x86]), 0x100000200),
            "arm64 pc": (macho_rebuilt(data, [text, unixthread(6, 68, 0x100000220, 256)], cputype=0x100000C), 0x100000220),
            "LC_MAIN before a thread": (macho_rebuilt(data, [text, main, unixthread(4, 42, 0x100000250, 128)]), 0x100000200),
            "arm64 state in an x86_64 file": (macho_rebuilt(data, [text, unixthread(6, 68, 0x100000220, 256)]), 0),
            "wrong state count": (macho_rebuilt(data, [text, unixthread(4, 41, 0x100000200, 128)]), 0),
            "a record past its command": (macho_rebuilt(data, [text, malformed]), 0),
            "LC_MAIN with a malformed thread": (macho_rebuilt(data, [text, main, malformed]), 0),
            "a 4-byte thread tail": (macho_rebuilt(data, [text, unixthread(4, 42, 0x100000200, 128, bytes(4))]), 0),
            "two threads": (macho_rebuilt(data, [x86, x86]), 0),
            "two LC_MAIN": (macho_rebuilt(data, [text, main, main]), 0),
            "short LC_MAIN": (macho_rebuilt(data, [text, struct.pack("<IIQ", 0x80000028, 16, 0x200), x86]), 0),
            "entryoff past vmsize": (macho_rebuilt(data, [text_with(32, 0x100), main]), 0),
            "segment past the input": (macho_rebuilt(data, [text_with(48, 0x2000), main]), 0),
            "segment past the address space": (macho_rebuilt(data, [text_with(32, 2**64 - 0x100000000 + 1), main]), 0),
            "two segments hold entryoff": (macho_rebuilt(data, [text, alias, main]), 0),
            "no entry command": (macho_rebuilt(data, [text]), 0),
        }
        for label, (sample, entry) in cases.items():
            with self.subTest(label):
                self.assertEqual(worker.macho_map(sample)[0], entry)
                self.assertEqual(worker.macho_map(sample)[0], structure.macho_entry(sample) or 0)

    def test_macho_sections_outside_their_segments_file_bytes_are_not_mapped(self):
        """The worker maps exactly the code sections the host's macho_sections keeps."""
        data, _ = macho_code()
        text_segment = 32 + 72
        for label, at, value, mapped in (("declared", None, None, True), ("segment ends inside the section", text_segment + 48, 0x250, False),
                                         ("segment starts after the section", text_segment + 40, 0x201, False)):
            sample = bytearray(data)
            if at is not None:
                struct.pack_into("<Q", sample, at, value)  # __TEXT filesize, then fileoff
            sample = bytes(sample)
            host = [(row["offset"], row["offset"] + row["size"], row["addr"], row["executable"])
                    for row in structure.macho_sections(sample) if row["size"] and row["offset"]]
            with self.subTest(label):
                self.assertEqual(worker.macho_map(sample)[1], host)
                self.assertEqual(bool(host), mapped)

    def test_an_lc_unixthread_macho_reply_passes_the_host_verifier(self):
        """The same Mach-O through the worker (Ghidra's query in ReverseAIQuery's order) and the host verifier."""
        data, layout = macho_code()
        text, _ = macho_text_and_main(data)
        threaded = macho_rebuilt(data, [text, unixthread(4, 42, layout["entry"], 128)])
        spans = {f["entry"]: f["size"] for f in layout["functions"]}
        offsets = {f["entry"]: f["offset"] for f in layout["functions"]}
        for sample in (data, threaded):
            def ghidra(format_, args, script, sample=sample):
                q = query(sample, layout, names=["entry", "add_numbers", "compute", "constant"])
                entry_offset = int(script[3])  # analyze: mode, max_functions, decompile, entry file offset, ...
                q["pseudocode"].sort(key=lambda p: (offsets[p["entry"]] != entry_offset, -spans[p["entry"]], p["entry"]))
                return q
            records = worker.run("ghidra.analyze", DEFAULTS, sample, query_of=ghidra)
            with self.subTest(threaded=sample is threaded):
                self.assertEqual([r["value"]["entry"] for r in records if r["value"]["kind"] == "pseudocode"][0], layout["entry"])
                ghidra_verify.verify(sample, [Observation(Location(**r["location"]), r["value"]) for r in records], DEFAULTS)

    def test_only_elf_pe_and_thin_little_endian_macho_are_accepted(self):
        for data in (b"", b"\xca\xfe\xba\xbe" + bytes(60), b"\xfe\xed\xfa\xcf" + bytes(60), b"PK\x03\x04" + bytes(60),
                     b"MZ" + bytes(100), bytes(64)):
            with self.subTest(data=data[:4]), self.assertRaises(worker.UnsupportedFormat):
                worker.kind(data)
        self.assertEqual((worker.kind(elf_code()[0]), worker.kind(pe_code()[0]), worker.kind(macho_code()[0]), worker.kind(b"\xce\xfa\xed\xfe")),
                         ("elf", "pe", "macho", "macho"))

    def test_truncated_tables_are_refused(self):
        data, layout = elf_code()
        with self.assertRaises(worker.TruncatedStructure):
            worker.elf_map(data[:layout["shoff"] + 10])
        pe = pe_code()[0]
        with self.assertRaises(worker.TruncatedStructure):
            worker.pe_map(pe[:0x100])


class M3cTests(unittest.TestCase):
    """Assembly, reference and string observations alongside functions, pseudocode and calls."""

    def m3c(self, data, q, **args):
        return [o for o in observe(data, q, **args) if o["value"]["kind"] in ("assembly", "ref", "string")]

    def test_refs_fixtures_give_listings_references_and_strings_exactly(self):
        for build in (elf_refs, pe_refs, macho_refs):
            data, layout = build()
            with self.subTest(build.__name__):
                self.assertEqual(self.m3c(data, refs_query(data, layout)), expected_m3c(layout))
                self.assertEqual([o["value"]["type"] for o in self.m3c(data, refs_query(data, layout)) if o["value"]["kind"] == "ref"],
                                 ["data", "data", "read", "write", "read_write", "jump"])
                for delta in (0x10000, -0x1000):  # rebased by Ghidra: values stay the file's addresses
                    self.assertEqual(self.m3c(data, refs_query(data, layout, delta=delta)), expected_m3c(layout))
        data, layout = elf_refs()
        for args in (dict(assembly=0, max_refs=0, max_strings=0), dict(assembly=1, max_instructions=1), dict(max_refs=2, max_strings=1),
                     dict(MAXIMA)):
            with self.subTest(args=args):
                self.assertEqual(self.m3c(data, refs_query(data, layout), **args), expected_m3c(layout, args=dict(DEFAULTS, **args)))
        self.assertEqual([o["value"]["kind"] for o in observe(data, refs_query(data, layout))][-12:],
                         ["assembly"] * 4 + ["ref"] * 6 + ["string"] * 2)

    def test_listings_follow_the_ranked_order_and_skip_what_is_missing(self):
        data, layout = elf_refs()
        q = refs_query(data, layout)
        order = [f["entry"] for f in ranked(layout)]
        self.assertEqual([o["value"]["entry"] for o in self.m3c(data, q) if o["value"]["kind"] == "assembly"], order[:4])
        q["assembly"] = [item for item in q["assembly"] if item["entry"] != order[1]]  # a failed listing
        self.assertEqual([o["value"]["entry"] for o in self.m3c(data, q) if o["value"]["kind"] == "assembly"], [order[0], *order[2:4]])
        q["assembly"][0]["instructions"] = []  # nothing listable: omitted, never empty
        self.assertNotIn(order[0], [o["value"]["entry"] for o in self.m3c(data, q) if o["value"]["kind"] == "assembly"])
        for broken in ({"entry": 1}, {"entry": 1, "instructions": {}, "count": 0}, {"entry": 1, "instructions": [], "count": -1},
                       {"entry": 1, "instructions": [{}], "count": 0}, "listing"):
            q = refs_query(data, layout)
            q["assembly"].append(broken)
            with self.subTest(broken=broken), self.assertRaises(worker.InvalidQueryOutput):
                self.m3c(data, q)

    def test_listing_rows_stay_inside_the_anchor_in_order_and_confirmed(self):
        data, layout = elf_refs()
        describe = next(f for f in layout["functions"] if f["name"] == "describe")

        def listed(listing=None, **args):
            q = refs_query(data, layout, listing=lambda f, rows: listing(rows) if listing and f is describe else rows)
            return next(o for o in self.m3c(data, q, **args) if o["value"]["entry"] == describe["entry"] and o["value"]["kind"] == "assembly")

        self.assertEqual(listed()["value"]["instructions"], [[d, n, f"INSN_{d:x}"] for d, n in describe["instructions"]])
        self.assertFalse(listed()["value"]["truncated"])
        cut = listed(max_instructions=2)["value"]
        self.assertEqual((len(cut["instructions"]), cut["truncated"]), (2, True))
        overlapping = listed(lambda rows: [rows[0], dict(rows[1], address=rows[1]["address"] - 1, file_offset=rows[1]["file_offset"] - 1,
                                                          bytes=data[rows[1]["file_offset"] - 1:rows[1]["file_offset"] + 6].hex())] + rows[2:])
        self.assertEqual((len(overlapping["value"]["instructions"]), overlapping["value"]["truncated"]), (1, True))
        texts = listed(lambda rows: [dict(row, text=text) for row, text in zip(rows, ["\u00e9" + "x" * 80, "", "a\tb"] + ["ok"] * 3)])
        self.assertEqual([row[2] for row in texts["value"]["instructions"]], ["?" + "x" * 63, "?", "a?b", "ok", "ok", "ok"])
        with self.assertRaises(worker.InconsistentAnchor):  # Ghidra's bytes must be the snapshot's
            listed(lambda rows: [dict(rows[0], bytes="90" * rows[0]["length"])] + rows[1:])
        for change in (dict(length=17), dict(file_offset=-1), dict(file_offset=None)):
            with self.subTest(change=change):
                self.assertEqual(len(listed(lambda rows: [rows[0], dict(rows[1], **change)] + rows[2:])["value"]["instructions"]), 1)
        for change in (dict(length=0), dict(address=-1), dict(bytes="zz")):
            with self.subTest(change=change), self.assertRaises(worker.InvalidQueryOutput):
                listed(lambda rows: [rows[0], dict(rows[1], **change)] + rows[2:])

    def test_a_listing_past_its_anchor_or_its_value_limit_is_cut_and_truncated(self):
        data, layout = elf_refs()
        describe = next(f for f in layout["functions"] if f["name"] == "describe")
        q = refs_query(data, layout)
        next(item for item in q["functions"] if item["entry"] == describe["entry"])["size"] = 20  # the anchor ends inside row 4
        value = next(o["value"] for o in self.m3c(data, q) if o["value"]["kind"] == "assembly" and o["value"]["entry"] == describe["entry"])
        self.assertEqual(([row[:2] for row in value["instructions"]], value["truncated"]), ([[0, 7], [7, 7], [14, 6]], True))
        text = "\"" * 64
        rows = [{"address": layout["text"]["address"] + i, "length": 1, "file_offset": layout["text"]["offset"] + i,
                 "bytes": data[layout["text"]["offset"] + i:layout["text"]["offset"] + i + 1].hex(), "text": text} for i in range(64)]
        q = refs_query(data, layout)
        q["assembly"][0] = {"entry": layout["functions"][0]["entry"], "instructions": rows, "count": 64}
        q["functions"][0].update(size=REFS_TEXT_SIZE, bytes=data[layout["text"]["offset"]:layout["text"]["offset"] + REFS_TEXT_SIZE].hex())
        value = next(o["value"] for o in self.m3c(data, q, max_instructions=64) if o["value"]["kind"] == "assembly")
        self.assertLessEqual(len(canonical_json(value).encode()), 4096)
        self.assertTrue(value["truncated"])
        self.assertGreater(len(canonical_json(dict(value, instructions=value["instructions"] + [[64, 1, text]])).encode()), 4096)
        self.assertLess(len(value["instructions"]), 64)

    def test_a_listing_stops_at_the_4096_byte_anchor_of_a_longer_function(self):
        data, places = code_elf(bytes(0x90 for _ in range(5000)), b"")
        offset, va = places["text"]
        rows = [{"address": va + d, "length": n, "file_offset": offset + d, "bytes": data[offset + d:offset + d + n].hex(), "text": "NOP"}
                for d, n in ((0, 1), (4094, 4), (4098, 1))]
        q = {"format": "x", "options_off": {}, "pseudocode": [], "assembly": [{"entry": va, "instructions": rows, "count": 3}],
             "blocks": [{"name": ".text", "start": va, "size": 5000, "execute": True, "initialized": True, "file_offset": offset}],
             "functions": [{"name": "long", "entry": va, "size": 5000, "file_offset": offset, "anchored": True,
                            "bytes": data[offset:offset + 4096].hex(), "calls": [], "refs": []}]}
        value = next(o for o in observe(data, q) if o["value"]["kind"] == "assembly")
        self.assertEqual((value["location"], value["value"]["instructions"], value["value"]["truncated"]),
                         ({"offset": offset, "length": 4096}, [[0, 1, "NOP"]], True))

    def test_reference_types_come_from_ghidras_flags_and_inner_flow_is_not_reported(self):
        cases = {(False, False, False, False, True): "data", (False, False, True, False, True): "read", (False, False, False, True, True): "write",
                 (False, False, True, True, True): "read_write", (False, False, True, True, False): "read_write",
                 (True, True, False, False, False): "jump", (True, False, False, False, False): None, (False, False, False, False, False): None}
        for (flow, jump, read, write, is_data), kind in cases.items():
            item = {"flow": flow, "jump": jump, "read": read, "write": write, "data": is_data, "inside": False}
            with self.subTest(item=item):
                self.assertEqual(worker.ref_type(item), kind)
        self.assertIsNone(worker.ref_type({"flow": True, "jump": True, "read": False, "write": False, "data": False, "inside": True}))
        for bad in ({"flow": 1, "jump": True, "read": False, "write": False, "data": False, "inside": False}, {"flow": False}):
            with self.subTest(bad=bad), self.assertRaises(worker.InvalidQueryOutput):
                worker.ref_type(bad)

    def test_references_are_anchored_unique_sorted_capped_and_strings_follow_them(self):
        data, layout = elf_refs()
        q = refs_query(data, layout)
        describe = next(item for item in q["functions"] if item["name"] == "describe")
        describe["refs"] += describe["refs"][:2]  # duplicates collapse
        self.assertEqual(self.m3c(data, q), expected_m3c(layout))
        outside = dict(describe["refs"][0], address=q["functions"][0]["entry"], file_offset=q["functions"][0]["file_offset"],
                       bytes=data[q["functions"][0]["file_offset"]:q["functions"][0]["file_offset"] + 7].hex())
        describe["refs"].append(outside)  # an instruction before describe's entry is not inside its span
        self.assertEqual(self.m3c(data, q), expected_m3c(layout))
        q = refs_query(data, layout)
        for item in q["functions"]:
            item["refs"].reverse()
        self.assertEqual(self.m3c(data, q), expected_m3c(layout))
        values = [o["value"] for o in self.m3c(data, refs_query(data, layout), max_refs=1)]
        self.assertEqual([v["kind"] for v in values][-2:], ["ref", "string"])
        self.assertEqual(values[-1]["text"], "ReverseAI ascii string")  # only strings referenced by the reply's refs
        self.assertNotIn("string", [o["value"]["kind"] for o in self.m3c(data, refs_query(data, layout), max_refs=1, max_strings=0)])
        q = refs_query(data, layout)
        for item in q["functions"]:
            for ref in item["refs"]:
                ref["to_file_offset"] = -1  # no file offset from Ghidra: its address less the rebase delta
        self.assertEqual(self.m3c(data, q), expected_m3c(layout))
        with self.assertRaises(worker.InvalidQueryOutput):
            self.m3c(data, dict(q, functions=[dict(q["functions"][0], refs={})] + q["functions"][1:]))

    def test_string_rule_ascii_first_utf16le_then_terminator_or_truncation_inside_the_section(self):
        def decode(raw, at=0, section_end=None):
            data = bytes(raw)
            return worker.decode_string(data, [(0, len(data) if section_end is None else section_end, 0x1000, False)], 0x1000 + at)

        self.assertEqual(decode(b"ab\0"), (0, 2, "ascii", "ab", False))
        self.assertEqual(decode(b"a\0"), None)  # one character is not a string
        self.assertEqual(decode("hi".encode("utf-16le") + b"\0\0"), (0, 4, "utf-16le", "hi", False))
        self.assertEqual(decode(b"ab"), None)  # no terminator inside the section
        self.assertEqual(decode(b"ab\0", section_end=2), None)
        self.assertEqual(decode(b"ab\x01"), None)
        self.assertEqual(decode(b"A" * 128 + b"\0"), (0, 128, "ascii", "A" * 128, False))
        self.assertEqual(decode(b"A" * 129), (0, 128, "ascii", "A" * 128, True))  # the 129th still matches inside the section
        self.assertEqual(decode(b"A" * 128), None)  # 128, then neither a terminator nor a match
        self.assertEqual(decode(b"A" * 129 + b"\0", section_end=128), None)
        wide = "W".encode("utf-16le") * 129
        self.assertEqual(decode(wide), (0, 256, "utf-16le", "W" * 128, True))
        self.assertEqual(decode(wide[:256] + b"\0\0"), (0, 256, "utf-16le", "W" * 128, False))
        self.assertEqual(decode(b"ab\0", at=1), None)
        self.assertEqual(decode(b"xab\0", at=1), (1, 2, "ascii", "ab", False))
        self.assertEqual(decode("~ ".encode("utf-16le") + b"\0\0"), (0, 4, "utf-16le", "~ ", False))
        self.assertEqual(decode(b"\x7f\x00a\x00\0\0"), None)
        data = b"ab\0"
        self.assertIsNone(worker.decode_string(data, [(0, 3, 0x1000, False), (0, 3, 0x1000, True)], 0x1000))  # two sections map it
        self.assertIsNone(worker.decode_string(data, [(0, 3, 0x1000, False)], 0x2000))

    def test_a_string_needs_one_mapping_for_its_whole_span_both_ways(self):
        """Another section that maps any of the string's addresses or file bytes, terminator
        or next unit included, makes the string ambiguous; it is omitted and the rest of the reply stays admissible."""
        data, layout = elf_refs()
        symtab = layout["shoff"] + 3 * 64  # .symtab's header becomes an allocated PROGBITS section

        def aliased(address, offset, size):
            changed = bytearray(data)
            struct.pack_into("<IIQQQQ", changed, symtab, struct.unpack_from("<I", data, symtab)[0], 1, 0x2, address, offset, size)
            return bytes(changed)

        ascii, wide = layout["strings"]
        cases = {"the data bytes mapped again elsewhere": (aliased(0x600000, layout["data"]["offset"], 80), []),
                 "addresses inside the ascii text": (aliased(layout["data"]["address"] + 2, symtab - 64, 16), [wide["address"]]),
                 "only the ascii terminator": (aliased(ascii["address"] + ascii["length"], symtab - 64, 1), [wide["address"]]),
                 "only the wide terminator's bytes": (aliased(0x600000, wide["offset"] + wide["length"] + 1, 1), [ascii["address"]]),
                 "next to the strings, no overlap": (aliased(ascii["address"] + ascii["length"] + 1, symtab - 64, 8),
                                                    [ascii["address"], wide["address"]])}
        for label, (sample, kept) in cases.items():
            observations = observe(sample, refs_query(sample, layout))
            with self.subTest(label):
                self.assertEqual([o["value"]["address"] for o in observations if o["value"]["kind"] == "string"], kept)
                self.assertEqual(len([o for o in observations if o["value"]["kind"] == "ref"]), 6)
                ghidra_verify.verify(sample, [Observation(Location(**o["location"]), o["value"]) for o in observations], DEFAULTS)
        sections = [(0, 8, 0x1000, False), (8, 16, 0x1003, False)]  # the second maps 0x1003.. as well
        self.assertIsNone(worker.decode_string(b"abc\0" + bytes(12), sections, 0x1000))
        self.assertEqual(worker.decode_string(b"ab\0" + bytes(13), sections, 0x1000), (0, 2, "ascii", "ab", False))

    def test_references_are_unique_by_the_contract_key(self):
        """A repeated (offset, to, type) with another name gives one row, the lowest."""
        data, layout = elf_refs()
        q = refs_query(data, layout)
        describe = next(item for item in q["functions"] if item["name"] == "describe")
        describe["refs"].insert(0, dict(describe["refs"][0], to_name="another printable name"))
        observations = observe(data, q)
        refs = [o["value"] for o in observations if o["value"]["kind"] == "ref"]
        self.assertEqual(len(refs), 6)
        self.assertEqual(refs[0]["to_name"], min("another printable name", "greeting"))
        ghidra_verify.verify(data, [Observation(Location(**o["location"]), o["value"]) for o in observations], DEFAULTS)
        describe["refs"].reverse()  # the same row whatever the query order
        self.assertEqual([o["value"] for o in observe(data, q) if o["value"]["kind"] == "ref"], refs)

    def test_string_sources_are_sorted_unique_and_capped_at_eight(self):
        data, layout = elf_refs()
        greeting = layout["strings"][0]
        refs = [{"to": greeting["address"], "from": 0x400000 + n} for n in (9, 3, 3, 7, 1, 8, 2, 6, 5, 4)]
        found = worker.strings(data, worker.elf_map(data)[1], refs, DEFAULTS)
        self.assertEqual(found[0]["value"]["from"], [0x400001, 0x400002, 0x400003, 0x400004, 0x400005, 0x400006, 0x400007, 0x400008])
        self.assertEqual(found[0]["location"], {"offset": greeting["offset"], "length": greeting["length"]})
        many = [{"to": layout["strings"][1]["address"], "from": 1}, {"to": greeting["address"], "from": 1}, {"to": layout["data"]["address"] + 0x40, "from": 1}]
        self.assertEqual([o["value"]["address"] for o in worker.strings(data, worker.elf_map(data)[1], many, DEFAULTS)],
                         [s["address"] for s in layout["strings"]])
        self.assertEqual(len(worker.strings(data, worker.elf_map(data)[1], many, dict(DEFAULTS, max_strings=1))), 1)

    def test_pseudocode_is_cut_to_fit_the_observation_limit(self):
        """Bound by max_chars first, then the longest prefix whose value fits 4,096 bytes."""
        data, layout = elf_code()
        for max_chars in (2048, 1024):
            for label, char in (("quote", "\""), ("backslash", "\\"), ("newline", "\n"), ("cjk", "\u4e00"), ("astral", "\U0001f600"),
                                ("ascii", "a")):
                text = char * 3000
                q = query(data, layout, texts={f["entry"]: text for f in layout["functions"]})
                values = [o["value"] for o in observe(data, q, max_chars=max_chars) if o["value"]["kind"] == "pseudocode"]
                with self.subTest(max_chars=max_chars, label=label):
                    self.assertEqual(len(values), 4)
                    for value in values:
                        size = len(canonical_json(value).encode())
                        self.assertLessEqual(size, 4096)
                        self.assertTrue(value["truncated"])
                        self.assertLessEqual(len(value["text"]), max_chars)
                        self.assertTrue(len(value["text"]) == max_chars or
                                        len(canonical_json(dict(value, text=text[:len(value["text"]) + 1])).encode()) > 4096)
        q = query(data, layout, texts={f["entry"]: "a" * 100 for f in layout["functions"]})
        self.assertEqual({o["value"]["truncated"] for o in observe(data, q) if o["value"]["kind"] == "pseudocode"}, {False})
        q = query(data, layout, texts={f["entry"]: "\U0001f600" * 2000 for f in layout["functions"]})  # within max_chars, over 4,096 bytes
        values = [o["value"] for o in observe(data, q, max_chars=2048) if o["value"]["kind"] == "pseudocode"]
        self.assertEqual({(v["truncated"], len(v["text"]) < 2000) for v in values}, {(True, True)})

    def test_the_reply_at_every_maximum_is_never_refused_for_its_size(self):
        """128 functions, 16 pseudocode texts, 256 calls, 8 listings of 64 rows, 128 references and 64 strings, with every
        name and text at the size that costs most in JSON: functions, pseudocode and calls always fit;
        listings, references and strings are added only while the reply fits, none is cut, and the reply parses on the host."""
        quote = "\"" * 128
        text = bytearray(0x90 for _ in range(128 * 32))
        strings = b"".join(b"\"" * 129 + b"\0" for _ in range(64))
        data, places = code_elf(bytes(text), strings)
        (text_offset, text_va), (strings_offset, strings_va) = places["text"], places["rodata"]

        def hexed(offset, length):
            return data[offset:offset + length].hex()

        functions = []
        for i in range(128):
            offset, va = text_offset + 32 * i, text_va + 32 * i
            calls = [{"address": va + 5 * c, "length": 5, "file_offset": offset + 5 * c, "bytes": hexed(offset + 5 * c, 5),
                      "to": 2**63 + i, "to_file_offset": -1, "to_name": quote} for c in (0, 1)]
            refs = [{"address": va + 10, "length": 5, "file_offset": offset + 10, "bytes": hexed(offset + 10, 5),
                     "to": strings_va + 130 * (i % 64), "to_file_offset": strings_offset + 130 * (i % 64), "to_name": quote, "type": "DATA",
                     "flow": False, "jump": False, "read": False, "write": False, "data": True, "inside": False}]
            functions.append({"name": quote, "entry": va, "size": 2**64 - va - 1 - i, "file_offset": offset, "anchored": True,
                              "bytes": hexed(offset, min(4096, len(text) - 32 * i)), "calls": calls, "refs": refs})
        listings = [{"entry": text_va + 32 * i, "count": 65,
                     "instructions": [{"address": text_va + 32 * i + r, "length": 1, "file_offset": text_offset + 32 * i + r,
                                       "bytes": hexed(text_offset + 32 * i + r, 1), "text": "\"" * 64} for r in range(64)]}
                    for i in range(8)]
        q = {"format": "x", "options_off": {}, "functions": functions, "assembly": listings,
             "blocks": [{"name": ".text", "start": text_va, "size": len(text), "execute": True, "initialized": True, "file_offset": text_offset},
                        {"name": ".rodata", "start": strings_va, "size": len(strings), "execute": False, "initialized": True,
                         "file_offset": strings_offset}],
             "pseudocode": [{"entry": text_va + 32 * i, "text": "\U0001f600" * 2048} for i in range(128)]}
        message = worker.reply(["ghidra.analyze", json.dumps(MAXIMA)], data, query_of=lambda *a: q)
        self.assertEqual(message["status"], "ok")
        raw = worker.encode(message)
        self.assertLessEqual(len(raw), MAX_WORKER_REPLY_BYTES)
        self.assertEqual(MAX_WORKER_REPLY_BYTES, worker.MAX_REPLY_BYTES)
        parsed = parse_worker_reply(raw, input_sha256=sha256_hex(data), max_observations=600)
        kinds = [o.value["kind"] for o in parsed]
        self.assertEqual((kinds.count("function"), kinds.count("pseudocode"), kinds.count("call")), (128, 16, 256))
        self.assertEqual(kinds, sorted(kinds, key=["function", "pseudocode", "call", "assembly", "ref", "string"].index))
        self.assertGreater(kinds.count("assembly"), 0)
        self.assertLess(kinds.count("ref") + kinds.count("string"), 128 + 64)  # the rest did not fit and was left out
        fit = worker.Fit([])
        for item in message["observations"]:
            fit.add(item)
        self.assertEqual(fit.size, len(raw))  # the running size is the encoded reply's
        for item in message["observations"]:
            self.assertLessEqual(len(canonical_json(item["value"]).encode()), 4096)


class RequestAndCommandTests(unittest.TestCase):
    def test_requests_are_exact(self):
        self.assertEqual(worker.parse_request(["ghidra.analyze", "{}"]), ("ghidra.analyze", DEFAULTS))
        for bounds in (MINIMA, MAXIMA):
            self.assertEqual(worker.parse_request(["ghidra.analyze", json.dumps(bounds)])[1], bounds)
        self.assertEqual(worker.parse_request(["ghidra.analyze", '{"max_calls": 0}'])[1], dict(DEFAULTS, max_calls=0))
        for argv in (["ghidra.analyze"], ["ghidra.analyze", "{}", "x"], ["yarax.matches", "{}"], ["ghidra.script", "{}"],
                     ["ghidra.analyze", '{"max_functions": 0}'], ["ghidra.analyze", '{"max_functions": 129}'],
                     ["ghidra.analyze", '{"decompile": 17}'], ["ghidra.analyze", '{"max_chars": 63}'], ["ghidra.analyze", '{"max_chars": 2049}'],
                     ["ghidra.analyze", '{"max_calls": -1}'], ["ghidra.analyze", '{"max_calls": 257}'], ["ghidra.analyze", '{"decompile": true}'],
                     ["ghidra.analyze", '{"decompile": 1.0}'], ["ghidra.analyze", '{"script": "Evil.java"}'], ["ghidra.analyze", '{"loader": "BinaryLoader"}'],
                     ["ghidra.analyze", '{"decompile": 1, "decompile": 2}'], ["ghidra.analyze", "[]"], ["ghidra.analyze", "{"],
                     *(["ghidra.analyze", json.dumps({name: value})] for name in ("assembly", "max_instructions", "max_refs", "max_strings")
                       for value in (MINIMA[name] - 1, MAXIMA[name] + 1, True, "1"))):
            with self.subTest(argv=argv), self.assertRaises(worker.InvalidRequest):
                worker.parse_request(argv)

    def test_the_headless_command_is_fixed_and_takes_only_bounded_numbers(self):
        data = elf_code()[0]
        script = worker.script_args("ghidra.analyze", dict(DEFAULTS, max_functions=7, decompile=3), data)
        argv = worker.ghidra_argv("elf", "/tmp/reverseai-ghidra/query.json", script)
        self.assertEqual(argv[:2], ["/bin/bash", "/opt/ghidra/support/analyzeHeadless"])
        self.assertEqual(argv[argv.index("-import") + 1], "/snapshot/input")
        for flag in ("-readOnly", "-deleteProject"):
            self.assertIn(flag, argv)
        self.assertEqual(argv[argv.index("-loader") + 1:argv.index("-loader") + 6],
                         ["ElfLoader", "-loader-loadLibraries", "false", "-loader-linkExistingProjectLibraries", "false"])
        self.assertEqual(worker.ghidra_argv("pe", "q", script)[argv.index("-loader") + 1], "PeLoader")
        self.assertEqual(worker.ghidra_argv("macho", "q", script)[argv.index("-loader") + 1], "MachoLoader")
        self.assertEqual(argv[argv.index("-preScript") + 1], "ReverseAIOptions.java")
        post = argv.index("-postScript")
        self.assertEqual(argv[post + 1:post + 10],
                         ["ReverseAIQuery.java", "/tmp/reverseai-ghidra/query.json", "analyze", "7", "3", "256", "40", "4", "32"])
        widened = worker.script_args("ghidra.analyze", dict(DEFAULTS, assembly=8, max_instructions=64), data)
        self.assertEqual(widened[-2:], ["8", "64"])
        self.assertEqual(argv[post + 10:post + 12], ["-log", "/tmp/reverseai-ghidra/ghidra.log"])
        self.assertEqual(argv[argv.index("-scriptPath") + 1], str(worker.SCRIPTS))
        self.assertEqual(argv[argv.index("-max-cpu") + 1], "2")
        self.assertEqual(argv[argv.index("-analysisTimeoutPerFile") + 1], "120")
        self.assertLess(worker.ANALYSIS_SECONDS + worker.DECOMPILE_SECONDS, worker.GHIDRA_SECONDS)
        self.assertLess(worker.GHIDRA_SECONDS, 240)

    def test_the_environment_is_fixed_and_inherits_nothing(self):
        with patch.dict("os.environ", {"GHIDRA_JAVA_OPTIONS": "-agentlib:jdwp", "JAVA_TOOL_OPTIONS": "-Dx=y", "LD_PRELOAD": "/x"}):
            env = worker.ghidra_env()
        self.assertEqual(env, {"PATH": "/usr/bin:/bin", "HOME": "/tmp/reverseai-ghidra/home", "LANG": "C.UTF-8",
                               "JAVA_HOME": "/opt/jdk", "GHIDRA_HEADLESS_MAXMEM": "1G",
                               "JAVA_TOOL_OPTIONS": "-Duser.home=/tmp/reverseai-ghidra/home -Djava.io.tmpdir=/tmp/reverseai-ghidra"})


class FakeProcess:
    def __init__(self, write=None, hang=False):
        self.write, self.hang, self.pid, self.killed = write, hang, 4242, False

    def __call__(self, argv, **kwargs):
        self.argv, self.kwargs = argv, kwargs
        if self.write is not None:
            Path(argv[argv.index("-postScript") + 2]).write_bytes(self.write)
        return self

    def wait(self, timeout=None):
        if self.hang and not self.killed:
            raise subprocess.TimeoutExpired("analyzeHeadless", timeout)
        return 0


class RunGhidraTests(unittest.TestCase):
    def run_with(self, process):
        with tempfile.TemporaryDirectory() as folder, patch.object(worker, "WORK", Path(folder) / "work"), \
                patch.object(worker.subprocess, "Popen", process), \
                patch.object(worker.os, "killpg", side_effect=lambda pid, sig: setattr(process, "killed", (pid, sig))):
            process.expected_env = worker.ghidra_env()
            script = worker.script_args("ghidra.analyze", DEFAULTS, elf_code()[0])
            process.expected_argv = worker.ghidra_argv("elf", worker.WORK / "query.json", script)
            return worker.run_ghidra("elf", DEFAULTS, script)

    def test_the_query_output_is_read_back(self):
        process = FakeProcess(json.dumps({"functions": []}).encode())
        self.assertEqual(self.run_with(process), {"functions": []})
        self.assertTrue(process.kwargs["start_new_session"])
        self.assertIs(process.kwargs["stdin"], subprocess.DEVNULL)
        self.assertEqual(process.kwargs["env"], process.expected_env)
        self.assertEqual(process.argv, process.expected_argv)

    def test_failures_have_their_own_errors(self):
        for label, process, error in (("no output", FakeProcess(), worker.GhidraFailed),
                                      ("not JSON", FakeProcess(b"{"), worker.InvalidQueryOutput),
                                      ("too large", FakeProcess(b"{}" + b" " * 64), worker.InvalidQueryOutput)):
            with self.subTest(label), self.assertRaises(error), patch.object(worker, "MAX_QUERY_BYTES", 16):
                self.run_with(process)

    def test_a_hung_analysis_kills_its_whole_process_group(self):
        process = FakeProcess(hang=True)
        with self.assertRaises(worker.GhidraTimeout):
            self.run_with(process)
        self.assertEqual(process.killed, (4242, signal.SIGKILL))


class ReplyTests(unittest.TestCase):
    def test_replies_pass_the_hosts_parser(self):
        data, layout = elf_code()
        message = worker.reply(["ghidra.analyze", "{}"], data, lambda f, a, o: query(data, layout))
        observations = parse_worker_reply(worker.encode(message), input_sha256=sha256_hex(data), max_observations=400)
        self.assertEqual(len(observations), 12)
        error = worker.reply(["ghidra.analyze", '{"decompile": 17}'], data)
        with self.assertRaisesRegex(WorkerError, "^InvalidRequest$"):
            parse_worker_reply(worker.encode(error), input_sha256=sha256_hex(data), max_observations=400)

    def test_the_query_receives_the_format_the_args_and_the_entry_file_offset(self):
        seen = []
        for build in (elf_code, pe_code, macho_code):
            data, layout = build()
            worker.reply(["ghidra.analyze", '{"decompile": 2}'], data, lambda f, a, s: seen.append((f, a["decompile"], s)) or {})
        self.assertEqual(seen, [(f, 2, ["analyze", "64", "2", offset, "40", "4", "32"])
                                for f, offset in (("elf", "256"), ("pe", "512"), ("macho", "512"))])

    def test_unexpected_failures_become_short_error_names_and_large_replies_are_refused(self):
        def broken(f, a, o):
            raise RuntimeError("/private/path secret")

        data, layout = elf_code()
        self.assertEqual(worker.reply(["ghidra.analyze", "{}"], data, broken)["error"], "RuntimeError")
        with patch.object(worker, "MAX_REPLY_BYTES", 500):
            self.assertEqual(worker.reply(["ghidra.analyze", "{}"], data, lambda f, a, o: query(data, layout))["error"], "ReplyTooLarge")

    def test_main_prints_one_json_object_and_reports_an_unreadable_snapshot(self):
        with tempfile.TemporaryDirectory() as folder:
            out = io.StringIO()
            with contextlib.redirect_stdout(out), patch.object(worker.sys, "stdout", type("S", (), {"buffer": io.BytesIO(), "flush": lambda self: None})()) as stdout:
                worker.main(["ghidra.analyze", "{}"], snapshot=Path(folder, "missing"))
                text = stdout.buffer.getvalue().decode()
        self.assertTrue(text.endswith("\n") and text.count("\n") == 1)
        self.assertEqual(json.loads(text), {"protocol": "reverseai.worker/1", "status": "error",
                                            "snapshot_sha256": hashlib.sha256(b"").hexdigest(), "error": "SnapshotUnreadable"})


class BuildInputTests(unittest.TestCase):
    def test_scripts_lock_and_dockerfile_are_pinned_consistently(self):
        lock = json.loads((SOURCE / "image.lock.json").read_text(encoding="utf-8"))
        base_keys = {"adapter_version", "base_digest", "ghidra_sha256", "image_id", "jdk_sha256", "platform"}
        if lock["adapter_version"] == "12.1.4-r6":
            self.assertEqual(set(lock), base_keys)
            self.assertEqual(lock["image_id"], "sha256:ac77fda75da8580e0479087580f83b6e5495fb16df97b9696a2bdf3ae100f452")
        else:
            self.assertEqual(lock["adapter_version"], "12.1.4-r7")
            self.assertEqual(set(lock), base_keys | {"parent_image_id", "bundle_sha256", "cache_format"})
            from tools.build_ghidra_image import bundle_digest, bundle_hashes
            self.assertEqual(lock["bundle_sha256"], bundle_digest(bundle_hashes(SOURCE)))
            self.assertEqual(lock["cache_format"], 1)
        self.assertEqual((lock["platform"], worker.ADAPTER_VERSION), ("linux/arm64", "12.1.4-r7"))
        self.assertEqual(lock["ghidra_sha256"], "ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db")
        self.assertEqual(lock["jdk_sha256"], "23e37e026f12f3e706f18938ff611db3032d075b09d0879a25d06718c773e223")
        self.assertEqual(lock["base_digest"], json.loads((ROOT / "containers" / "lief" / "image.lock.json").read_text())["base_digest"])
        self.assertRegex(lock["image_id"], r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(sorted(p.name for p in (SOURCE / "ghidra_scripts").iterdir()), ["ReverseAIOptions.java", "ReverseAIPrepare.java", "ReverseAIQuery.java"])
        query_source = (SOURCE / "ghidra_scripts" / "ReverseAIQuery.java").read_text()
        # Size is the span; reverting to the body's address count must fail here.
        self.assertIn("long size = span(function);", query_source)
        self.assertIn("int bySize = Long.compare(span(b), span(a));", query_source)
        self.assertIn("Address last = function.getBody().getMaxAddress();", query_source)
        self.assertIn("last.subtract(entry) + 1", query_source)
        self.assertNotIn("getNumAddresses", query_source)
        self.assertIn('"Mac OS X Mach-O"', (SOURCE / "ghidra_scripts" / "ReverseAIOptions.java").read_text())
        rule = re.compile(r'Pattern\.compile\("\(\?i\)\.\*\(pdb\|dwarf\|swift\)\.\*"\)')
        for name in ("ReverseAIOptions.java", "ReverseAIQuery.java"):
            self.assertRegex((SOURCE / "ghidra_scripts" / name).read_text(), rule)
        # Each mode takes a fixed number of arguments after the output path and the mode itself.
        self.assertIn('int expected = mode.equals("analyze") ? 8 : mode.equals("functions") ? 5 : mode.equals("function") ? 9',
                      query_source)
        self.assertIn('mode.equals("export") ? 8', query_source)
        self.assertIn('if (args.length != expected) {', query_source)
        # References leave calls (their own kind) and non-memory targets out; listings start at the entry and count
        # the whole body, so the worker can tell a cut listing; the listed functions follow the pseudocode order.
        for pin in ("if (refs == MAX_REFS_PER_FUNCTION || !target.isMemoryAddress() || type.isCall()) {",
                    '.append(",\\"inside\\":").append(function.getBody().contains(target))',
                    "if (listed == maxInstructions || instruction.getAddress().compareTo(entry) < 0) {",
                    'out.append("],\\"count\\":").append(count).append("}");',
                    "for (Function function : order.subList(0, Math.min(Math.max(assembly, 0), order.size()))) {"):
            self.assertIn(pin, query_source)
        dockerfile = (SOURCE / "Dockerfile").read_text(encoding="utf-8")
        self.assertEqual(re.findall(r"^USER .*$", dockerfile, re.M | re.I), ["USER 65534:65534"])
        self.assertIn("g++=4:14.2.0-1 make=4.4.1-2", dockerfile)
        self.assertTrue(dockerfile.rstrip().endswith('ENTRYPOINT ["python3", "-I", "-B", "/opt/reverseai/worker.py"]'))
        self.assertEqual(worker.SNAPSHOT, "/snapshot/input")


if __name__ == "__main__":
    unittest.main()
