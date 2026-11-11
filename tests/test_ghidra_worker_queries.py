"""Ghidra worker query modes: ghidra.functions, ghidra.function and ghidra.xrefs from canned query output
built from the refs fixtures; no Ghidra, no container."""

import copy
import json
from pathlib import Path
import struct
import unittest
from unittest.mock import patch

from reverseai.contract import canonical_json, parse_worker_reply, sha256_hex
from tests.fixtures_code import elf_refs, macho_refs, pe_refs
from tests.test_ghidra_worker_logic import refs_query, worker

FUNCTIONS = {"query": "", "start": 0, "limit": 64}
FUNCTION = {"select": "entry", "entry": 0, "name": "", "parts": "all", "start": 0, "limit": 64, "max_chars": 1024,
            "max_calls": 64, "max_refs": 64}
XREFS = {"address": 0, "start": 0, "limit": 64}
# Ghidra's flags on a reference to an address, per type as the fixture declares it (the tail jmp is a call terminator).
FLAGS = {"call": (True, True, False, False, False, False), "jump": (True, True, True, False, False, False),
         "data": (False, False, False, False, False, True), "read": (False, False, False, True, False, True),
         "write": (False, False, False, False, True, True), "read_write": (False, False, False, True, True, True)}


def names(layout):
    return [f["name"] or f"FUN_{f['entry']:x}" for f in layout["functions"]]


LOGICAL = ("_start", "add_numbers", "compute", "constant", "describe")  # the refs fixtures' functions, in address order


def by_name(layout, name):
    return layout["functions"][LOGICAL.index(name)]


def containing(layout, address):
    return next((f for f in layout["functions"] if f["entry"] <= address < f["entry"] + f["size"]), None)


def mode_query(data, layout, mode, delta=0):
    """The header every mode writes (format, options, blocks) and the function items of refs_query."""
    q = refs_query(data, layout, delta=delta, names=names(layout))
    return {"format": "x", "options_off": {}, "blocks": q["blocks"], "mode": mode}, q["functions"]


def reference_rows(data, layout, to, delta=0):
    """What the query lists as references to `to`: calls (the tail jmp too), then the declared data references."""
    rows = []
    for call in layout["calls"] + [r for r in layout["refs"] if r["type"] == "jump"]:
        if call["to"] == to:
            rows.append((call, "call" if call in layout["calls"] else "jump"))
    rows += [(ref, ref["type"]) for ref in layout["refs"] if ref["to"] == to and ref["type"] != "jump"]
    result = []
    for row, kind in rows:
        source = containing(layout, row["address"])
        call, flow, jump, read, write, is_data = FLAGS[kind]
        result.append({"address": row["address"] + delta, "length": row["length"], "file_offset": row["offset"],
                       "bytes": data[row["offset"]:row["offset"] + row["length"]].hex(), "to": to + delta,
                       "from": None if source is None else source["entry"] + delta,
                       "from_file_offset": -1 if source is None else source["offset"],
                       "call": call, "flow": flow, "jump": jump, "read": read, "write": write, "data": is_data})
    return result


def functions_query(data, layout, *, query="", start=0, limit=64, delta=0):
    q, items = mode_query(data, layout, "functions", delta)
    matching = [item for item in items if query in item["name"]]
    q["functions"] = [dict(item, index=i) for i, item in enumerate(matching) if start <= i < start + limit]
    q.update(total=len(matching), overflow=False)
    return q


def function_query(data, layout, name, *, start=0, limit=64, delta=0, parts="all", matches=1, text="int f(void)\n{\n}\n"):
    q, items = mode_query(data, layout, "function", delta)
    target = by_name(layout, name)
    item = items[LOGICAL.index(name)]
    rows = [{"index": i, "address": target["entry"] + d + delta, "length": n, "file_offset": target["offset"] + d,
             "bytes": data[target["offset"] + d:target["offset"] + d + n].hex(), "text": f"INSN_{d:x}"}
            for i, (d, n) in enumerate(target["instructions"])]
    q.update(matches=matches, target=dict(item, index=0, calls_overflow=False),
             callers={"rows": [r for r in reference_rows(data, layout, target["entry"], delta) if r["call"]], "overflow": False},
             pseudocode=text if parts in ("pseudocode", "all") else None,
             instructions={"start": start, "rows": rows[start:start + limit], "total": len(rows), "overflow": False}
             if parts in ("assembly", "all") else None)
    return q


def xrefs_query(data, layout, address, *, delta=0):
    q, _ = mode_query(data, layout, "xrefs", delta)
    q.update(to=address + delta, xrefs={"rows": reference_rows(data, layout, address, delta), "overflow": False})
    return q


def values(data, operation, q, **args):
    defaults = {"ghidra.functions": FUNCTIONS, "ghidra.function": FUNCTION, "ghidra.xrefs": XREFS}[operation]
    return [o["value"] for o in worker.run(operation, dict(defaults, **args), data, query_of=lambda *a: q)]


class RequestTests(unittest.TestCase):
    def test_each_operation_takes_exactly_the_hosts_argument_bounds(self):
        for operation, defaults in (("ghidra.functions", FUNCTIONS), ("ghidra.function", FUNCTION)):
            self.assertEqual(worker.parse_request([operation, "{}"]), (operation, defaults))
        self.assertEqual(worker.parse_request(["ghidra.xrefs", '{"address": 4096}']), ("ghidra.xrefs", dict(XREFS, address=4096)))
        maxima = {"ghidra.functions": {"query": "q" * 256, "start": 65535, "limit": 128},
                  "ghidra.function": {"select": "name", "entry": 2**64 - 1, "name": "n" * 256, "parts": "callers", "start": 65535,
                                      "limit": 256, "max_chars": 2048, "max_calls": 256, "max_refs": 128},
                  "ghidra.xrefs": {"address": 2**64 - 1, "start": 65535, "limit": 256}}
        for operation, args in maxima.items():
            self.assertEqual(worker.parse_request([operation, json.dumps(args)])[1], args)
        refused = [("ghidra.xrefs", {}), ("ghidra.xrefs", {"address": -1}), ("ghidra.xrefs", {"address": 2**64}),
                   ("ghidra.xrefs", {"address": 1, "limit": 0}), ("ghidra.xrefs", {"address": 1, "limit": 257}),
                   ("ghidra.functions", {"limit": 129}), ("ghidra.functions", {"start": 65536}),
                   ("ghidra.functions", {"query": "q" * 257}), ("ghidra.functions", {"query": "a/b"}),
                   ("ghidra.functions", {"query": "a\\b"}), ("ghidra.functions", {"query": "-x"}),
                   ("ghidra.functions", {"query": "a\x00"}), ("ghidra.functions", {"query": 1}),
                   ("ghidra.function", {"select": "address"}), ("ghidra.function", {"parts": "bytes"}),
                   ("ghidra.function", {"max_calls": 257}), ("ghidra.function", {"max_refs": 129}),
                   ("ghidra.function", {"max_chars": 63}), ("ghidra.function", {"limit": 0}), ("ghidra.function", {"entry": True}),
                   ("ghidra.function", {"name": None}), ("ghidra.function", {"address": 1}), ("ghidra.functions", {"max_calls": 1}),
                   ("ghidra.script", {}), ("ghidra.xref", {"address": 1})]
        for operation, args in refused:
            with self.subTest(operation=operation, args=args), self.assertRaises(worker.InvalidRequest):
                worker.parse_request([operation, json.dumps(args)])
        self.assertEqual(worker.MAX_OBSERVATIONS, {"ghidra.analyze": 600, "ghidra.functions": 128, "ghidra.function": 643,
                                                   "ghidra.xrefs": 256})

    def test_the_query_gets_its_mode_and_fixed_arguments_with_strings_hex_encoded(self):
        data, layout = elf_refs()
        describe, counter = by_name(layout, "describe"), layout["data"]["address"] + 0x40
        self.assertEqual(worker.script_args("ghidra.functions", dict(FUNCTIONS, query="desc", start=3, limit=7), data),
                         ["functions", "x" + b"desc".hex(), "3", "7"])
        self.assertEqual(worker.script_args("ghidra.functions", FUNCTIONS, data), ["functions", "x", "0", "64"])
        self.assertEqual(worker.script_args("ghidra.function", dict(FUNCTION, entry=describe["entry"], parts="callers"), data),
                         ["function", "entry", str(describe["offset"]), "x", "callers", "0", "64", "40"])
        self.assertEqual(worker.script_args("ghidra.function", dict(FUNCTION, select="name", name="add numbers", entry=4), data),
                         ["function", "name", "-1", "x" + b"add numbers".hex(), "all", "0", "64", "40"])
        self.assertEqual(worker.script_args("ghidra.function", dict(FUNCTION, entry=0x10), data)[2], "-1")  # not in the file
        sections = worker.elf_map(data)[1]
        self.assertEqual(worker.script_args("ghidra.xrefs", dict(XREFS, address=counter), data),
                         ["xrefs", str(layout["data"]["offset"] + 0x40), str(counter), str(sections[0][0]), str(sections[0][2])])
        self.assertEqual(worker.script_args("ghidra.xrefs", dict(XREFS, address=0x900000), data)[1:3], ["-1", str(0x900000)])


class FunctionsTests(unittest.TestCase):
    def test_pages_of_functions_with_index_and_total(self):
        for build in (elf_refs, pe_refs, macho_refs):
            data, layout = build()
            rows = [[f["entry"], f["size"]] for f in layout["functions"]]
            with self.subTest(build.__name__):
                got = values(data, "ghidra.functions", functions_query(data, layout))
                self.assertEqual([[v["entry"], v["size"]] for v in got], rows)
                self.assertEqual([(v["kind"], v["index"], v["total"]) for v in got], [("function_row", i, 5) for i in range(5)])
                self.assertEqual([v["name"] for v in got], names(layout))
                page = values(data, "ghidra.functions", functions_query(data, layout, start=3, limit=2), start=3, limit=2)
                self.assertEqual([(v["index"], v["entry"]) for v in page], [(3, rows[3][0]), (4, rows[4][0])])
                self.assertEqual(values(data, "ghidra.functions", functions_query(data, layout, start=5), start=5), [])
                rebased = values(data, "ghidra.functions", functions_query(data, layout, delta=0x7000), )
                self.assertEqual(rebased, got)
        data, layout = elf_refs()
        found = values(data, "ghidra.functions", functions_query(data, layout, query="o"), query="o")
        self.assertEqual([(v["name"], v["index"], v["total"]) for v in found], [("compute", 0, 2), ("constant", 1, 2)])

    def test_rows_must_match_the_question_and_the_count_stays_bounded(self):
        data, layout = elf_refs()
        q = functions_query(data, layout)
        for change in ({"total": 4}, {"overflow": None}, {"functions": {}}, {"mode": "function"}):
            with self.subTest(change=change), self.assertRaises(worker.InvalidQueryOutput):
                values(data, "ghidra.functions", dict(q, **change))
        shifted = copy.deepcopy(q)
        shifted["functions"][1]["index"] = 2
        with self.assertRaises(worker.InvalidQueryOutput):
            values(data, "ghidra.functions", shifted)
        with self.assertRaises(worker.InvalidQueryOutput):  # a row whose name does not contain the query
            values(data, "ghidra.functions", q, query="desc")
        with self.assertRaises(worker.TooManyRows):
            values(data, "ghidra.functions", dict(q, overflow=True))
        message = worker.reply(["ghidra.functions", "{}"], data, query_of=lambda *a: dict(q, overflow=True))
        self.assertEqual(message["error"], "TooManyRows")
        unanchored = copy.deepcopy(q)
        unanchored["functions"][2]["anchored"] = False  # the page stops at the first row this file cannot anchor
        self.assertEqual([v["index"] for v in values(data, "ghidra.functions", unanchored)], [0, 1])


class FunctionTests(unittest.TestCase):
    def test_every_part_of_describe_by_entry(self):
        for build in (elf_refs, pe_refs, macho_refs):
            data, layout = build()
            describe, start = by_name(layout, "describe"), by_name(layout, "_start")
            got = values(data, "ghidra.function", function_query(data, layout, "describe"), entry=describe["entry"])
            with self.subTest(build.__name__):
                # In this canned reading the tail jmp is a jump reference, not a call: no callee.
                self.assertEqual([v["kind"] for v in got], ["target", "pseudocode", "instructions", "caller"] + ["ref"] * 6)
                self.assertEqual(got[0], {"kind": "target", "name": names(layout)[4], "entry": describe["entry"],
                                          "size": describe["size"], "matches": 1, "callers_total": 1, "callees_total": 0})
                self.assertEqual(got[1], {"kind": "pseudocode", "index": 0, "entry": describe["entry"],
                                          "text": "int f(void)\n{\n}\n", "truncated": False})
                self.assertEqual(got[2], {"kind": "instructions", "entry": describe["entry"], "start": 0, "total": 6,
                                          "rows": [[d, n, f"INSN_{d:x}"] for d, n in describe["instructions"]], "truncated": False})
                self.assertEqual(got[3], {"kind": "caller", "at": start["entry"] + 10, "from": start["entry"],
                                          "to": describe["entry"]})
                self.assertEqual([(v["to"], v["type"]) for v in got[4:]], [(r["to"], r["type"]) for r in layout["refs"]])

    def test_parts_select_what_follows_the_target(self):
        data, layout = elf_refs()
        compute = by_name(layout, "compute")
        expected = {"info": ["target"], "pseudocode": ["target", "pseudocode"], "assembly": ["target", "instructions"],
                    "callees": ["target", "call", "call"], "callers": ["target", "caller"],
                    "all": ["target", "pseudocode", "instructions", "call", "call", "caller"]}
        for parts, kinds in expected.items():
            q = function_query(data, layout, "compute", parts=parts)
            got = values(data, "ghidra.function", q, entry=compute["entry"], parts=parts)
            with self.subTest(parts=parts):
                self.assertEqual([v["kind"] for v in got], kinds)
                self.assertEqual((got[0]["callers_total"], got[0]["callees_total"]), (1, 2))
        one = values(data, "ghidra.function", function_query(data, layout, "compute"), entry=compute["entry"], parts="callees",
                     max_calls=1)
        self.assertEqual(([v["kind"] for v in one], one[0]["callees_total"]), (["target", "call"], 2))
        describe = by_name(layout, "describe")
        for parts in ("info", "pseudocode", "assembly", "callees", "callers"):  # references come with all only
            got = values(data, "ghidra.function", function_query(data, layout, "describe", parts=parts), entry=describe["entry"],
                         parts=parts)
            with self.subTest(parts=parts):
                self.assertNotIn("ref", [v["kind"] for v in got])

    def test_callers_count_every_call_instruction_tail_calls_included(self):
        data, layout = elf_refs()
        for name, callers in (("add_numbers", ["_start", "compute"]), ("constant", ["compute", "describe"]),
                              ("_start", []), ("describe", ["_start"])):
            target = by_name(layout, name)
            got = values(data, "ghidra.function", function_query(data, layout, name), entry=target["entry"], parts="callers")
            with self.subTest(name=name):
                self.assertEqual(got[0]["callers_total"], len(callers))
                self.assertEqual([v["from"] for v in got[1:]], [by_name(layout, c)["entry"] for c in callers])
                self.assertEqual([v["at"] for v in got[1:]], sorted(v["at"] for v in got[1:]))
        constant = by_name(layout, "constant")
        one = values(data, "ghidra.function", function_query(data, layout, "constant"), entry=constant["entry"], parts="callers",
                     max_calls=1)
        self.assertEqual((one[0]["callers_total"], len(one) - 1), (2, 1))
        q = function_query(data, layout, "constant")
        q["callers"]["rows"].append(copy.deepcopy(q["callers"]["rows"][0]))  # an instruction is counted once
        self.assertEqual(values(data, "ghidra.function", q, entry=constant["entry"])[0]["callers_total"], 2)
        q["callers"]["rows"][0]["to"] += 1
        with self.assertRaises(worker.InconsistentAnchor):  # every caller row must call the target
            values(data, "ghidra.function", q, entry=constant["entry"])
        with self.assertRaises(worker.TooManyRows):
            values(data, "ghidra.function", dict(q, callers={"rows": [], "overflow": True}), entry=constant["entry"])
        q = function_query(data, layout, "constant")
        q["callers"]["rows"][0].update(call=False, flow=False, read=True, data=True)  # a read of the entry is not a caller
        got = values(data, "ghidra.function", q, entry=constant["entry"], parts="callers")
        self.assertEqual((got[0]["callers_total"], len(got)), (1, 2))

    def test_a_target_by_name_is_the_lowest_entry_and_counts_its_namesakes(self):
        data, layout = elf_refs()
        compute = by_name(layout, "compute")
        q = function_query(data, layout, "compute", matches=2)
        got = values(data, "ghidra.function", q, select="name", name="compute", parts="info")
        self.assertEqual((got[0]["entry"], got[0]["matches"]), (compute["entry"], 2))
        for args in (dict(select="name", name="constant"), dict(select="entry", entry=compute["entry"] + 1),
                     dict(select="entry", entry=compute["entry"], parts="info")):
            with self.subTest(args=args), self.assertRaises(worker.InvalidQueryOutput):
                values(data, "ghidra.function", q, **args)  # another answer than the question, or matches 2 by entry
        self.assertEqual(values(data, "ghidra.function", dict(q, target=None, matches=0), select="name", name="nothing"), [])

    def test_instruction_pages_from_the_entry_with_contract_truncation(self):
        data, layout = elf_refs()
        compute = by_name(layout, "compute")
        rows = [[d, n, f"INSN_{d:x}"] for d, n in compute["instructions"]]

        def page(start, limit, **change):
            q = function_query(data, layout, "compute", start=start, limit=limit, parts="assembly")
            q["target"].update(change)
            found = [v for v in values(data, "ghidra.function", q, entry=compute["entry"], parts="assembly", start=start,
                                       limit=limit) if v["kind"] == "instructions"]
            return found[0] if found else None

        self.assertEqual(page(2, 3), {"kind": "instructions", "entry": compute["entry"], "start": 2, "total": 9,
                                      "rows": rows[2:5], "truncated": False})
        self.assertEqual(page(7, 5)["rows"], rows[7:])  # the last page: fewer rows than limit, not truncated
        self.assertFalse(page(7, 5)["truncated"])
        self.assertIsNone(page(9, 5))  # start at total: no observation
        cut = page(0, 9, size=12)  # the span ends inside row 3: the page stops there
        self.assertEqual((cut["rows"], cut["truncated"]), (rows[:3], True))
        q = function_query(data, layout, "compute", start=0, limit=9, parts="assembly")
        observed = worker.run("ghidra.function", dict(FUNCTION, entry=compute["entry"], parts="assembly", limit=9), data,
                              query_of=lambda *a: q)
        location = next(o["location"] for o in observed if o["value"]["kind"] == "instructions")
        self.assertEqual(location, {"offset": compute["offset"], "length": compute["size"]})
        later = worker.run("ghidra.function", dict(FUNCTION, entry=compute["entry"], parts="assembly", start=2, limit=2), data,
                           query_of=lambda *a: function_query(data, layout, "compute", start=2, limit=2, parts="assembly"))
        self.assertEqual(next(o["location"] for o in later if o["value"]["kind"] == "instructions"),
                         {"offset": compute["offset"] + 6, "length": 10})  # first row's offset to the last row's end
        overlapping = function_query(data, layout, "compute", start=0, limit=9, parts="assembly")
        row = overlapping["instructions"]["rows"][2]
        row.update(address=row["address"] - 1, file_offset=row["file_offset"] - 1,
                   bytes=data[row["file_offset"] - 1:row["file_offset"] + 4].hex())  # starts inside row 1
        got = [v for v in values(data, "ghidra.function", overlapping, entry=compute["entry"], parts="assembly", limit=9)
               if v["kind"] == "instructions"][0]
        self.assertEqual((got["rows"], got["truncated"]), (rows[:2], True))
        broken = function_query(data, layout, "compute", start=2, limit=2, parts="assembly")
        for change in ({"start": 1}, {"total": 3}, {"rows": {}}):
            q = copy.deepcopy(broken)
            q["instructions"].update(change)
            with self.subTest(change=change), self.assertRaises(worker.InvalidQueryOutput):
                values(data, "ghidra.function", q, entry=compute["entry"], parts="assembly", start=2, limit=2)

    def test_the_reply_respects_the_count_cap_and_the_byte_limit(self):
        data, layout = elf_refs()
        describe = by_name(layout, "describe")
        q = function_query(data, layout, "describe")
        with patch.dict(worker.MAX_OBSERVATIONS, {"ghidra.function": 4}):
            got = values(data, "ghidra.function", q, entry=describe["entry"])
        self.assertEqual([v["kind"] for v in got], ["target", "pseudocode", "instructions", "caller"])
        message = worker.reply(["ghidra.function", json.dumps({"entry": describe["entry"]})], data, query_of=lambda *a: q)
        observations = parse_worker_reply(worker.encode(message), input_sha256=sha256_hex(data), max_observations=643)
        self.assertEqual(len(observations), 10)
        long_text = "\U0001f600" * 3000
        q = function_query(data, layout, "describe", text=long_text)
        pseudo = next(v for v in values(data, "ghidra.function", q, entry=describe["entry"], max_chars=2048) if v["kind"] == "pseudocode")
        self.assertTrue(pseudo["truncated"])
        self.assertLessEqual(len(canonical_json(pseudo).encode()), 4096)


class LongFunctionTests(unittest.TestCase):
    def test_an_instruction_page_spans_at_most_4096_bytes(self):
        from tests.test_ghidra_worker_logic import code_elf
        data, places = code_elf(bytes(0x90 for _ in range(6000)), b"")
        offset, va = places["text"]
        q = {"format": "x", "options_off": {}, "mode": "function", "matches": 1,
             "blocks": [{"name": ".text", "start": va, "size": 6000, "execute": True, "initialized": True, "file_offset": offset}],
             "target": {"index": 0, "name": "long", "entry": va, "size": 6000, "file_offset": offset, "anchored": True,
                        "bytes": data[offset:offset + 4096].hex(), "calls": [], "calls_overflow": False, "refs": []},
             "callers": {"rows": [], "overflow": False}, "pseudocode": None,
             "instructions": {"start": 0, "total": 3, "overflow": False, "rows": [
                 {"index": i, "address": va + d, "length": 1, "file_offset": offset + d, "bytes": "90", "text": "NOP"}
                 for i, d in enumerate((0, 4095, 4096))]}}
        got = next(o for o in worker.run("ghidra.function", dict(FUNCTION, entry=va, parts="assembly"), data, query_of=lambda *a: q)
                   if o["value"]["kind"] == "instructions")
        self.assertEqual((got["location"], got["value"]["rows"], got["value"]["truncated"]),
                         ({"offset": offset, "length": 4096}, [[0, 1, "NOP"], [4095, 1, "NOP"]], True))



class CountLimitTests(unittest.TestCase):
    """Totals are complete counts; past MAX_ROWS rows or
    MAX_FUNCTION_INSTRUCTIONS instructions, or on the query's overflow marker, the run fails with TooManyRows."""

    def test_the_contract_ceilings(self):
        self.assertEqual((worker.MAX_ROWS, worker.MAX_FUNCTION_INSTRUCTIONS), (65536, 1_000_000))
        source = (Path(worker.__file__).parent / "ghidra_scripts" / "ReverseAIQuery.java").read_text()
        for pin in ("private static final int MAX_ROWS = 65536;", "private static final int MAX_BODY_INSTRUCTIONS = 1000000;",
                    "private static final int MAX_CALLS_PER_FUNCTION = 1024;",
                    "appendCalls(out, function, MAX_CALLS_PER_FUNCTION);  // analyze: at most 1,024 rows, unchanged",
                    "boolean more = appendCalls(out, function, MAX_ROWS);",
                    'out.append("],\\"calls_overflow\\":").append(more)',
                    "\t\t\tif (calls == cap) {\n\t\t\t\treturn true;\n\t\t\t}\n\t\t\tcalls++;",
                    "\t\t\tif (index == MAX_BODY_INSTRUCTIONS) {\n\t\t\t\toverflow = true;\n\t\t\t\tbreak;",
                    'out.append("],\\"total\\":").append(index).append(",\\"overflow\\":").append(overflow)',
                    "\t\t\tif (rows == MAX_ROWS) {\n\t\t\t\tout.append(\"],\\\"overflow\\\":true}\");",
                    "\t\t\tif (total == MAX_ROWS) {\n\t\t\t\tout.append(\"],\\\"overflow\\\":true,\\\"total\\\":\").append(total);"):
            with self.subTest(pin=pin):
                self.assertIn(pin, source)

    def test_a_callee_total_counts_every_call_past_analyzes_1024(self):
        from tests.test_ghidra_worker_logic import code_elf
        calls = 1025
        text = bytearray()
        for i in range(calls):
            text += b"\xe8" + struct.pack("<i", 5 * calls - 5 * (i + 1))  # call the ret after the last call
        text += b"\xc3"
        data, places = code_elf(bytes(text), b"")
        offset, va = places["text"]
        rows = [{"address": va + 5 * i, "length": 5, "file_offset": offset + 5 * i, "bytes": data[offset + 5 * i:offset + 5 * i + 5].hex(),
                 "to": va + 5 * calls, "to_file_offset": offset + 5 * calls, "to_name": "g"} for i in range(calls)]
        q = {"format": "x", "options_off": {}, "mode": "function", "matches": 1,
             "blocks": [{"name": ".text", "start": va, "size": len(text), "execute": True, "initialized": True, "file_offset": offset}],
             "target": {"index": 0, "name": "f", "entry": va, "size": len(text), "file_offset": offset, "anchored": True,
                        "bytes": data[offset:offset + 4096].hex(), "calls": rows, "calls_overflow": False, "refs": []},
             "callers": {"rows": [], "overflow": False}, "pseudocode": None, "instructions": None}
        got = values(data, "ghidra.function", q, entry=va, parts="callees")
        self.assertEqual((got[0]["callees_total"], len(got) - 1), (1025, 64))
        with patch.object(worker, "MAX_ROWS", 1025):
            self.assertEqual(values(data, "ghidra.function", q, entry=va, parts="info")[0]["callees_total"], 1025)
        with patch.object(worker, "MAX_ROWS", 1024), self.assertRaises(worker.TooManyRows):
            values(data, "ghidra.function", q, entry=va, parts="info")  # the limit plus one, even without the marker
        for change, error in (({"calls_overflow": True}, worker.TooManyRows), ({"calls_overflow": None}, worker.InvalidQueryOutput)):
            with self.subTest(change=change), self.assertRaises(error):
                values(data, "ghidra.function", dict(q, target=dict(q["target"], **change)), entry=va, parts="info")

    def test_rows_past_the_ceiling_fail_the_run_in_every_mode(self):
        data, layout = elf_refs()
        constant, counter = by_name(layout, "constant"), layout["data"]["address"] + 0x40
        with patch.object(worker, "MAX_ROWS", 2):
            self.assertEqual(len(values(data, "ghidra.function", function_query(data, layout, "constant"), entry=constant["entry"],
                                        parts="callers")), 3)
            self.assertEqual(len(values(data, "ghidra.xrefs", xrefs_query(data, layout, counter), address=counter)), 2)
            self.assertEqual(len(values(data, "ghidra.functions", functions_query(data, layout, query="o"), query="o")), 2)
        with patch.object(worker, "MAX_ROWS", 1):
            for operation, q, args in (("ghidra.function", function_query(data, layout, "constant"), {"entry": constant["entry"]}),
                                       ("ghidra.xrefs", xrefs_query(data, layout, counter), {"address": counter}),
                                       ("ghidra.functions", functions_query(data, layout, query="o"), {"query": "o"})):
                with self.subTest(operation=operation), self.assertRaises(worker.TooManyRows):
                    values(data, operation, q, **args)
        q = xrefs_query(data, layout, counter)
        message = worker.reply(["ghidra.xrefs", json.dumps({"address": counter})], data,
                               query_of=lambda *a: dict(q, xrefs={"rows": q["xrefs"]["rows"], "overflow": True}))
        self.assertEqual(message, {"protocol": "reverseai.worker/1", "status": "error", "snapshot_sha256": sha256_hex(data),
                                   "error": "TooManyRows"})

    def test_an_instruction_total_past_the_ceiling_fails_the_run(self):
        data, layout = elf_refs()
        compute = by_name(layout, "compute")

        def page(**change):
            q = function_query(data, layout, "compute", parts="assembly")
            q["instructions"].update(change)
            return values(data, "ghidra.function", q, entry=compute["entry"], parts="assembly")

        self.assertEqual(page()[1]["total"], 9)
        with patch.object(worker, "MAX_FUNCTION_INSTRUCTIONS", 9):
            self.assertEqual(page()[1]["total"], 9)
        with patch.object(worker, "MAX_FUNCTION_INSTRUCTIONS", 8), self.assertRaises(worker.TooManyRows):
            page()  # a total past the ceiling is never published
        for change, error in (({"overflow": True}, worker.TooManyRows), ({"overflow": "no"}, worker.InvalidQueryOutput),
                              ({"total": 1_000_001}, worker.TooManyRows)):
            with self.subTest(change=change), self.assertRaises(error):
                page(**change)


class XrefsTests(unittest.TestCase):
    def test_references_to_a_function_a_global_and_a_string(self):
        for build in (elf_refs, pe_refs, macho_refs):
            data, layout = build()
            start, compute, constant, describe = (by_name(layout, n) for n in ("_start", "compute", "constant", "describe"))
            counter, greeting = layout["data"]["address"] + 0x40, layout["strings"][0]["address"]
            cases = {constant["entry"]: [(compute["entry"] + 18, compute["entry"], "call"), (describe["entry"] + 33, describe["entry"], "call")],
                     counter: [(describe["entry"] + 14, describe["entry"], "read"), (describe["entry"] + 26, describe["entry"], "read_write")],
                     greeting: [(describe["entry"], describe["entry"], "data")],
                     by_name(layout, "add_numbers")["entry"]: [(start["entry"], start["entry"], "call"),
                                                               (compute["entry"] + 11, compute["entry"], "call")]}
            for address, rows in cases.items():
                got = values(data, "ghidra.xrefs", xrefs_query(data, layout, address), address=address)
                with self.subTest(build.__name__, address=hex(address)):
                    self.assertEqual([(v["at"], v["from"], v["type"]) for v in got], rows)
                    self.assertEqual({(v["kind"], v["to"], v["total"]) for v in got}, {("xref", address, len(rows))})
                    self.assertEqual([v["index"] for v in got], list(range(len(rows))))
                    rebased = values(data, "ghidra.xrefs", xrefs_query(data, layout, address, delta=0x10000), address=address)
                    self.assertEqual(rebased, got)

    def test_order_paging_ties_and_bounds(self):
        data, layout = elf_refs()
        counter = layout["data"]["address"] + 0x40
        q = xrefs_query(data, layout, counter)
        both = copy.deepcopy(q["xrefs"]["rows"][1])
        q["xrefs"]["rows"].insert(0, dict(both, read=False))  # the read_write instruction also gives a write
        q["xrefs"]["rows"].append(copy.deepcopy(q["xrefs"]["rows"][0]))  # never two rows with the same (at, type)
        got = values(data, "ghidra.xrefs", q, address=counter)
        at = by_name(layout, "describe")["entry"]
        self.assertEqual([(v["at"] - at, v["type"], v["index"], v["total"]) for v in got],
                         [(14, "read", 0, 3), (26, "read_write", 1, 3), (26, "write", 2, 3)])
        page = values(data, "ghidra.xrefs", q, address=counter, start=1, limit=1)
        self.assertEqual([(v["index"], v["type"], v["total"]) for v in page], [(1, "read_write", 3)])
        self.assertEqual(values(data, "ghidra.xrefs", q, address=counter, start=3), [])
        read = next(i for i, row in enumerate(q["xrefs"]["rows"]) if row["read"] and not row["write"])
        outside = copy.deepcopy(q)
        outside["xrefs"]["rows"][read].update(file_offset=layout["data"]["offset"],
                                              bytes=data[layout["data"]["offset"]:layout["data"]["offset"] + 6].hex())
        self.assertEqual([v["type"] for v in values(data, "ghidra.xrefs", outside, address=counter)],
                         ["read_write", "write"])  # not in executable code: no row
        inner = copy.deepcopy(q)
        inner["xrefs"]["rows"][read].update(call=False, flow=True, jump=False)  # other flow is not a reference row
        self.assertEqual([v["type"] for v in values(data, "ghidra.xrefs", inner, address=counter)], ["read_write", "write"])
        for change in ({"to": counter + 1}, ):
            wrong = copy.deepcopy(q)
            wrong["xrefs"]["rows"][0].update(change)
            with self.subTest(change=change), self.assertRaises(worker.InconsistentAnchor):
                values(data, "ghidra.xrefs", wrong, address=counter)
        for change in ({"read": 1}, {"call": None}):
            wrong = copy.deepcopy(q)
            wrong["xrefs"]["rows"][0].update(change)
            with self.subTest(change=change), self.assertRaises(worker.InvalidQueryOutput):
                values(data, "ghidra.xrefs", wrong, address=counter)
        with self.assertRaises(worker.TooManyRows):
            values(data, "ghidra.xrefs", dict(q, xrefs={"rows": [], "overflow": True}), address=counter)

    def test_an_address_without_file_bytes_and_a_caller_outside_any_function(self):
        data, layout = elf_refs()
        describe = by_name(layout, "describe")
        bss = 0x900000
        q = xrefs_query(data, layout, layout["data"]["address"] + 0x48)
        for row in q["xrefs"]["rows"]:
            row.update(to=bss, **{"from": None, "from_file_offset": -1})
        got = values(data, "ghidra.xrefs", q, address=bss)
        self.assertEqual([(v["at"], v["from"], v["to"], v["type"]) for v in got], [(describe["entry"] + 20, None, bss, "write")])


if __name__ == "__main__":
    unittest.main()
