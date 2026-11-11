"""The LIEF worker's pure logic, without LIEF: byte decoding, observations, cross-checks and the reply protocol."""

import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

from reverseai.contract import WorkerError, parse_worker_reply, sha256_hex
from reverseai.tools import structure
from tests.fixtures_structure import elf, malformed, patched, pe

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("lief_worker", ROOT / "containers" / "lief" / "worker.py")
worker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(worker)


def faithful(data, format_):
    """What a correct LIEF parse reports, read at the ELF and PE specifications' fixed offsets, not with the worker's decoder.

    Sections are (offset, size, flags) for every declared entry when the whole table is inside the input, and None
    otherwise: a header-only answer, as LIEF gives for a broken table.
    """
    if format_ == "elf":
        word, order = (8 if data[4] == 2 else 4), ("little" if data[5] == 1 else "big")

        def at(offset, size):
            return int.from_bytes(data[offset:offset + size], order)
        facts = {"type": at(16, 2), "machine": at(18, 2), "entry": at(24, word), "shoff": at(24 + 2 * word, word),
                 "shentsize": at(34 + 3 * word, 2), "shnum": at(36 + 3 * word, 2)}
        table, entry, count = facts["shoff"], 16 + 6 * word, facts["shnum"]  # sh_flags at 8, sh_offset at 8+2w, sh_size at 8+3w
        row = lambda start: (at(start + 8 + 2 * word, word), at(start + 8 + 3 * word, word), at(start + 8, word))
    else:
        def at(offset, size):
            return int.from_bytes(data[offset:offset + size], "little")
        coff = at(0x3C, 4) + 4
        facts = {"e_lfanew": coff - 4, "machine": at(coff, 2), "number_of_sections": at(coff + 2, 2),
                 "timestamp": at(coff + 4, 4), "sizeof_optional_header": at(coff + 16, 2), "characteristics": at(coff + 18, 2),
                 "optional_magic": at(coff + 20, 2), "entry_rva": at(coff + 36, 4)}
        table, entry, count = coff + 20 + facts["sizeof_optional_header"], 40, facts["number_of_sections"]
        row = lambda start: (at(start + 20, 4), at(start + 16, 4), at(start + 36, 4))  # PointerToRawData, SizeOfRawData
    inside = table + entry * count <= len(data)
    facts["sections"] = [row(table + entry * index) for index in range(count)] if inside else None
    return facts


def changed(update):
    """faithful facts after update(facts): one LIEF value that disagrees with the bytes."""
    def facts_of(data, format_):
        facts = faithful(data, format_)
        update(facts)
        return facts
    return facts_of


def far_pe(e_lfanew=0x2000):
    """The generated PE with its headers moved after a gap: e_lfanew beyond the 4,096-byte location cap."""
    data, _ = pe()
    head = bytearray(data[:0x40]) + bytearray(e_lfanew - 0x40)
    head[0x3C:0x40] = e_lfanew.to_bytes(4, "little")
    return bytes(head) + data[0x80:]


def run(operation, data, facts_of=faithful, **args):
    request = [operation, json.dumps(args)]
    return worker.reply(request, data, facts_of)


def values(reply):
    return [item["value"] for item in reply["observations"]]


class HeaderTests(unittest.TestCase):
    def test_elf_header_matches_the_m1_structure_tool(self):
        for label, data in (("elf64 le", elf()[0]), ("elf32 be mips", elf(width=32, order=">", kind=3, machine=8)[0]),
                            ("elf64 be ppc64", elf(order=">", machine=21)[0])):
            with self.subTest(label):
                reply = run("lief.headers", data)
                (observation,) = reply["observations"]
                m1 = structure.headers(data, {})[0]
                self.assertEqual(observation["location"], {"offset": m1.location.offset, "length": m1.location.length})
                for field in ("format", "class", "endianness", "type", "machine", "machine_name", "entry", "shnum", "shoff"):
                    self.assertEqual(observation["value"][field], m1.value[field], field)

    def test_pe_headers_are_three_physical_observations(self):
        data, layout = pe(entry_rva=0x1234)
        reply = run("lief.headers", data)
        self.assertEqual([item["location"] for item in reply["observations"]],
                         [{"offset": 0, "length": 64}, {"offset": 0x80, "length": 24}, {"offset": 0x98, "length": 240}])
        dos, coff, optional = values(reply)
        self.assertEqual(dos, {"structure": "dos", "e_lfanew": 0x80})
        m1 = structure.headers(data, {})[0].value
        for field in ("format", "machine", "machine_name", "number_of_sections", "timestamp", "characteristics"):
            self.assertEqual(coff[field], m1[field], field)
        self.assertEqual(optional, {"structure": "optional", "optional_magic": "pe32+", "entry_rva": 0x1234})
        self.assertNotIn("format", dos)
        self.assertNotIn("format", optional)  # each field only in the structure that holds it

    def test_a_distant_pe_header_is_never_spanned_by_one_location(self):
        reply = run("lief.headers", far_pe())
        self.assertEqual([item["location"] for item in reply["observations"]],
                         [{"offset": 0, "length": 64}, {"offset": 0x2000, "length": 24}, {"offset": 0x2018, "length": 240}])

    def test_optional_header_fields_only_inside_the_declared_size(self):
        data, layout = pe()
        coff = layout["lfanew"] + 4
        cases = ((pe(optional_size=20)[0], {"structure": "optional", "optional_magic": "pe32+", "entry_rva": 0x1000}),
                 (patched(data, coff + 16, "<H", 19), {"structure": "optional", "optional_magic": "pe32+"}),
                 (patched(data, coff + 16, "<H", 18), {"structure": "optional", "optional_magic": "pe32+"}),
                 (patched(data, coff + 16, "<H", 8), {"structure": "optional", "optional_magic": "pe32+"}),
                 (patched(data, coff + 16, "<H", 2), {"structure": "optional", "optional_magic": "pe32+"}),
                 (patched(data, coff + 16, "<H", 1), {"structure": "optional"}),
                 (patched(data, coff + 16, "<H", 0), None))
        for data_, expected in cases:
            with self.subTest(expected=expected):
                found = [v for v in values(run("lief.headers", data_)) if v["structure"] == "optional"]
                self.assertEqual(found, [expected] if expected else [])
        self.assertEqual(run("lief.headers", patched(data, coff + 16, "<H", 5000))["error"], "StructureTooLarge")

    def test_an_unknown_machine_is_named_unknown(self):
        for data in (elf(machine=0x3E00)[0], pe(machine=0x3E00)[0]):
            with self.subTest(format=data[:2]):
                (value,) = [v for v in values(run("lief.headers", data)) if "machine" in v]
                self.assertEqual((value["machine"], value["machine_name"]), (0x3E00, "unknown"))

    def test_a_location_is_at_most_4096_bytes(self):
        data, _ = pe(optional_size=4096)
        optional = run("lief.headers", data)["observations"][2]["location"]
        self.assertEqual(optional, {"offset": 0x98, "length": 4096})
        self.assertEqual(run("lief.sections", data)["status"], "ok")
        too_large, _ = pe(optional_size=4097)
        for operation in ("lief.headers", "lief.sections"):
            self.assertEqual(run(operation, too_large)["error"], "StructureTooLarge")
        self.assertEqual(worker.location(0, 4096, 4096), {"offset": 0, "length": 4096})
        with self.assertRaises(worker.TruncatedStructure):
            worker.location(1, 4096, 4096)  # one byte past the input
        with self.assertRaises(worker.StructureTooLarge):
            worker.location(0, 4097, 5000)

    def test_machine_names_are_m1_names(self):
        self.assertEqual(worker.ELF_MACHINES, structure.ELF_MACHINES)
        self.assertEqual(worker.PE_MACHINES, structure.PE_MACHINES)
        self.assertEqual(worker.PE_OPTIONAL, structure.PE_OPTIONAL)


class SectionTests(unittest.TestCase):
    def test_elf_sections_are_physical_entries_without_names(self):
        data, layout = elf()
        reply = run("lief.sections", data)
        self.assertEqual([item["location"] for item in reply["observations"]],
                         [{"offset": layout["shoff"] + 64 * i, "length": 64} for i in range(5)])
        self.assertEqual(values(reply)[3], {"structure": "section", "index": 3, "offset": layout["offsets"][2], "size": 8,
                                            "flags": 7, "writable": True, "executable": True})
        self.assertTrue(all("name" not in value for value in values(reply)))
        m1 = [o.value for o in structure.sections(data, {"max_sections": 64})]
        for mine, theirs in zip(values(reply), m1):
            for field in ("index", "offset", "size", "flags", "writable", "executable"):
                self.assertEqual(mine[field], theirs[field], field)

    def test_elf_rows_equal_m1_and_known_answers_for_every_width_and_byte_order(self):
        for label, (data, layout) in (("elf64 le", elf()), ("elf32 le", elf(width=32)),
                                      ("elf32 be", elf(width=32, order=">", kind=3, machine=8)), ("elf64 be", elf(order=">", machine=21))):
            with self.subTest(label):
                reply = run("lief.sections", data)
                m1 = structure.sections(data, {"max_sections": 64})
                self.assertEqual([item["location"] for item in reply["observations"]],
                                 [{"offset": o.location.offset, "length": o.location.length} for o in m1])
                for mine, theirs in zip(values(reply), m1):
                    self.assertEqual({k: mine[k] for k in ("index", "offset", "size", "flags", "writable", "executable")},
                                     {k: theirs.value[k] for k in ("index", "offset", "size", "flags", "writable", "executable")})
                self.assertEqual([(v["offset"], v["size"], v["flags"]) for v in values(reply)[1:4]],
                                 [(layout["offsets"][0], 32, 0x6), (layout["offsets"][1], 16, 0x3), (layout["offsets"][2], 8, 0x7)])

    def test_pe_rows_report_the_raw_size_not_the_virtual_size(self):
        data, layout = pe()
        for index in range(3):
            data = patched(data, layout["table_offset"] + 40 * index + 8, "<I", 0x123 + index)  # VirtualSize
        rows, m1 = values(run("lief.sections", data)), [o.value for o in structure.sections(data, {"max_sections": 64})]
        self.assertEqual([v["virtual_size"] for v in m1], [0x123, 0x124, 0x125])
        self.assertEqual([(r["offset"], r["size"]) for r in rows], [(offset, 0x200) for offset in layout["raw_offsets"]])
        self.assertEqual([(r["offset"], r["size"], r["characteristics"]) for r in rows],
                         [(v["offset"], v["size"], v["characteristics"]) for v in m1])

    def test_a_20_byte_optional_header_moves_the_section_table(self):
        data, layout = pe(optional_size=20)
        self.assertEqual(layout["table_offset"], 0x80 + 24 + 20)
        self.assertEqual(run("lief.headers", data)["observations"][2],
                         {"location": {"offset": 0x98, "length": 20},
                          "value": {"structure": "optional", "optional_magic": "pe32+", "entry_rva": 0x1000}})
        reply = run("lief.sections", data)
        self.assertEqual([item["location"] for item in reply["observations"]],
                         [{"offset": 0xAC + 40 * i, "length": 40} for i in range(3)])
        m1 = [o.value for o in structure.sections(data, {"max_sections": 64})]
        self.assertEqual([(v["offset"], v["size"], v["characteristics"]) for v in values(reply)],
                         [(v["offset"], v["size"], v["characteristics"]) for v in m1])

    def test_pe_sections(self):
        data, layout = pe()
        reply = run("lief.sections", data)
        self.assertEqual([item["location"] for item in reply["observations"]],
                         [{"offset": layout["table_offset"] + 40 * i, "length": 40} for i in range(3)])
        self.assertEqual([v["index"] for v in values(reply) if v["writable"] and v["executable"]], [2])
        self.assertEqual(values(reply)[0], {"structure": "section", "index": 0, "offset": layout["raw_offsets"][0], "size": 0x200,
                                            "characteristics": 0x60000020, "writable": False, "executable": True})

    def test_max_sections_caps_the_entries(self):
        self.assertEqual(len(run("lief.sections", elf()[0], max_sections=2)["observations"]), 2)
        self.assertEqual(len(run("lief.sections", elf()[0])["observations"]), 5)
        self.assertEqual([v["index"] for v in values(run("lief.sections", pe()[0], max_sections=2))], [0, 1])
        self.assertEqual(len(run("lief.sections", pe()[0])["observations"]), 3)

    def test_elf_extended_numbering_is_refused_not_listed_empty(self):
        data, _ = elf(extended=True)
        self.assertEqual(run("lief.sections", data)["error"], "UnsupportedLayout")
        self.assertEqual(values(run("lief.headers", data))[0]["shnum"], 0)  # with shoff set: no count claim can follow


class RefusalTests(unittest.TestCase):
    # Expected (headers, sections) outcome per malformed host input. The worker differs from the host by design where names
    # are deferred (a bad name table does not matter) and where the PE optional header is read only inside its
    # declared size, the section table then starting where the COFF header says, as the Windows loader does.
    MALFORMED = {
        "elf truncated identification": ("TruncatedStructure", "TruncatedStructure"),
        "elf truncated header": ("TruncatedStructure", "TruncatedStructure"),
        "elf bad class": ("UnsupportedLayout", "UnsupportedLayout"),
        "elf bad byte order": ("UnsupportedLayout", "UnsupportedLayout"),
        "elf section table past end": ("ok", "TruncatedStructure"),
        "elf huge section count": ("ok", "TruncatedStructure"),
        "elf wrong section entry size": ("ok", "UnsupportedLayout"),
        "elf name table past end": ("ok", "ok"),
        "elf truncated section table": ("ok", "TruncatedStructure"),
        "pe truncated coff": ("TruncatedStructure", "TruncatedStructure"),
        "pe truncated optional": ("TruncatedStructure", "TruncatedStructure"),
        "pe huge section count": ("ok", "TruncatedStructure"),
        "pe huge optional size": ("StructureTooLarge", "StructureTooLarge"),
        "pe zero optional size": ("ok", "ok"),
        "pe optional size below its fields": ("ok", "ok"),
        "pe truncated section table": ("ok", "TruncatedStructure"),
    }

    def test_malformed_inputs_have_exact_outcomes_and_in_range_locations(self):
        cases = malformed()
        self.assertEqual(set(cases), set(self.MALFORMED))
        for name, (data, _) in cases.items():
            for operation, expected in zip(("lief.headers", "lief.sections"), self.MALFORMED[name]):
                with self.subTest(name=name, operation=operation):
                    reply = run(operation, data)
                    self.assertEqual(reply.get("error", reply["status"]), expected)
                    for item in reply.get("observations", ()):
                        location = item["location"]
                        self.assertTrue(0 < location["length"] <= 4096 and location["offset"] + location["length"] <= len(data))

    def test_only_elf_and_pe_are_accepted(self):
        for data in (b"", b"PK\x03\x04" + bytes(40), b"\xcf\xfa\xed\xfe" + bytes(40), b"MZ" + bytes(100)):
            with self.subTest(data=data[:4]):
                self.assertEqual(run("lief.headers", data)["error"], "UnsupportedFormat")
        # A 64-byte DOS header is the smallest PE candidate: here the signature fits, the COFF header does not.
        smallest = patched(b"MZ" + bytes(0x2E) + b"PE\0\0" + bytes(0x0C), 0x3C, "<I", 0x30)
        self.assertEqual(run("lief.headers", smallest)["error"], "TruncatedStructure")
        self.assertEqual(run("lief.headers", smallest[:0x3F])["error"], "UnsupportedFormat")

    # Every field LIEF must confirm, listed here rather than read from the worker, so a dropped check fails.
    ELF_FIELDS = ("type", "machine", "entry", "shoff", "shentsize", "shnum")
    PE_FIELDS = ("e_lfanew", "machine", "number_of_sections", "timestamp", "characteristics", "sizeof_optional_header")

    def test_every_checked_header_field_must_agree_with_lief(self):
        cases = [(operation, data, field) for operation in ("lief.headers", "lief.sections")
                 for data, fields in ((elf()[0], self.ELF_FIELDS), (elf(width=32, order=">")[0], self.ELF_FIELDS),
                                      (pe()[0], self.PE_FIELDS))
                 for field in fields]
        cases += [("lief.headers", pe()[0], field) for field in ("optional_magic", "entry_rva")]
        for operation, data, field in cases:
            with self.subTest(operation=operation, field=field, size=len(data)):
                self.assertEqual(run(operation, data)["status"], "ok")
                bumped = changed(lambda facts: facts.update({field: facts[field] + 1}))
                self.assertEqual(run(operation, data, facts_of=bumped)["error"], "InconsistentParse")

    def test_every_reported_section_row_must_agree_with_lief(self):
        for label, data in (("elf64", elf()[0]), ("elf32 be", elf(width=32, order=">")[0]), ("pe", pe()[0])):
            declared = len(faithful(data, "elf" if label.startswith("elf") else "pe")["sections"])
            for index in range(declared):
                for position, name in enumerate(("offset", "size", "flags")):
                    def bump(facts):
                        row = list(facts["sections"][index])
                        row[position] += 1
                        facts["sections"][index] = tuple(row)
                    with self.subTest(label, index=index, field=name):
                        self.assertEqual(run("lief.sections", data, facts_of=changed(bump))["error"], "InconsistentParse")

    def test_class_and_byte_order_come_from_the_bytes_alone(self):
        # LIEF only echoes e_ident; a byte order it does not follow shows up in the multi-byte fields it confirms.
        self.assertNotIn("class", worker.ELF_CHECKED)
        self.assertNotIn("endianness", worker.ELF_CHECKED)
        little_reading = changed(lambda facts: facts.update(machine=int.from_bytes(facts["machine"].to_bytes(2, "big"), "little")))
        self.assertEqual(run("lief.headers", elf(order=">", machine=21)[0], facts_of=little_reading)["error"], "InconsistentParse")

    def test_lief_must_list_exactly_the_declared_sections(self):
        def listing(change):
            def facts_of(data, format_):
                facts = faithful(data, format_)
                facts["sections"] = change(facts["sections"])
                return facts
            return facts_of
        for label, change in (("one more", lambda listed: listed + [(0, 0, 0)]), ("one fewer", lambda listed: listed[:-1])):
            with self.subTest(label):
                self.assertEqual(run("lief.sections", elf()[0], facts_of=listing(change), max_sections=2)["error"], "InconsistentParse")

    def test_the_whole_declared_table_must_be_inside_the_input_even_when_fewer_entries_are_read(self):
        data, layout = elf()
        cut = data[:layout["shoff"] + 2 * 64]  # entries 0 and 1 fit, the declared five do not
        self.assertEqual(run("lief.sections", cut, max_sections=1)["error"], "TruncatedStructure")
        table = pe()[1]["table_offset"]
        self.assertEqual(run("lief.sections", pe()[0][:table + 40], max_sections=1)["error"], "TruncatedStructure")

    def test_requests_are_exact(self):
        data = elf()[0]
        for request in ([], ["lief.headers"], ["lief.headers", "{}", "x"], ["lief.imports", "{}"], ["lief.headers", '{"x": 1}'],
                        ["lief.sections", '{"max_sections": 0}'], ["lief.sections", '{"max_sections": 65}'],
                        ["lief.sections", '{"max_sections": true}'], ["lief.sections", '{"max_sections": "8"}'],
                        ["lief.sections", '{"max_sections": 8, "max_sections": 9}'], ["lief.sections", "[]"],
                        ["lief.sections", "not json"]):
            with self.subTest(request=request):
                self.assertEqual(worker.reply(request, data, faithful)["error"], "InvalidRequest")

    def test_unexpected_failures_become_short_error_names(self):
        def broken(data, format_):
            raise RuntimeError("detail with /host/path and bytes")
        reply = run("lief.headers", elf()[0], facts_of=broken)
        self.assertEqual(reply, {"protocol": worker.PROTOCOL, "status": "error", "snapshot_sha256": sha256_hex(elf()[0]),
                                 "error": "RuntimeError"})


def config_class(names, ignored=()):
    """A stand-in ParserConfig: each named option defaults to True; setting an ignored one silently does nothing."""
    class Config:
        def __setattr__(self, name, value):
            if name not in ignored:
                object.__setattr__(self, name, value)
    for name in names:
        setattr(Config, name, True)
    return Config


class ParserConfigTests(unittest.TestCase):
    def test_every_option_is_turned_off(self):
        for names in (worker.ELF_PARSER_OFF, worker.PE_PARSER_OFF):
            config = worker.parser_config(config_class((*names, "page_size", "rebase")), names)
            self.assertEqual({name: getattr(config, name) for name in names}, dict.fromkeys(names, False))

    def test_the_options_are_lief_1_0_0s(self):
        """Copied from lief/ELF.pyi and lief/PE/__init__.pyi of the pinned wheel: offline, without the image build."""
        self.assertEqual(worker.ELF_PARSER_OFF, ("parse_dyn_symbols", "parse_notes", "parse_overlay", "parse_relocations",
                                                 "parse_symbol_versions", "parse_symtab_symbols"))
        self.assertEqual(worker.PE_PARSER_OFF, ("parse_arm64x_binary", "parse_exceptions", "parse_exports", "parse_imports",
                                                "parse_reloc", "parse_rsrc", "parse_signature"))

    def test_a_missing_new_or_ignored_option_is_an_error(self):
        names = worker.ELF_PARSER_OFF
        for label, config in (("missing", config_class(names[1:])), ("new", config_class((*names, "parse_new_table"))),
                              ("ignored", config_class(names, ignored=(names[0],)))):
            with self.subTest(label), self.assertRaises(worker.ParserOptionsChanged):
                worker.parser_config(config, names)

    def test_lief_parses_with_the_fixed_configs(self):
        parsed = []

        def parse(data, config):
            parsed.append(config)

        fake = types.SimpleNamespace(logging=types.SimpleNamespace(disable=lambda: None),
                                     ELF=types.SimpleNamespace(ParserConfig=config_class(worker.ELF_PARSER_OFF), parse=parse),
                                     PE=types.SimpleNamespace(ParserConfig=config_class(worker.PE_PARSER_OFF), parse=parse))
        with patch.dict(sys.modules, {"lief": fake}):
            for data, format_, names in ((elf()[0], "elf", worker.ELF_PARSER_OFF), (pe()[0], "pe", worker.PE_PARSER_OFF)):
                with self.subTest(format_), self.assertRaises(worker.ParserRefused):  # the stand-in parse returns None
                    worker.lief_facts(data, format_)
                self.assertTrue(all(getattr(parsed[-1], name) is False for name in names))


class SnapshotTests(unittest.TestCase):
    def main(self, snapshot, request=("lief.headers", "{}")):
        out = io.StringIO()
        with patch.object(worker, "lief_facts", faithful), contextlib.redirect_stdout(out):
            self.assertEqual(worker.main(list(request), snapshot=str(snapshot)), 0)
        return json.loads(out.getvalue())

    def test_an_unreadable_snapshot_has_its_own_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            for path in (Path(temporary, "missing"), Path(temporary)):
                with self.subTest(path=path.name):
                    self.assertEqual(self.main(path)["error"], "SnapshotUnreadable")

    def test_a_too_large_snapshot_reports_the_digest_of_the_whole_file(self):
        data = bytes(range(256)) * 12_000  # about 3 MiB: several read chunks
        with tempfile.TemporaryDirectory() as temporary, patch.object(worker, "MAX_INPUT_BYTES", 1_500_000):
            snapshot = Path(temporary, "input")
            snapshot.write_bytes(data)
            self.assertEqual(worker.read_snapshot(snapshot), (data[:1_500_001], hashlib.sha256(data).hexdigest()))
            reply = self.main(snapshot)
        self.assertEqual((reply["error"], reply["snapshot_sha256"]), ("InputTooLarge", hashlib.sha256(data).hexdigest()))


class ProtocolTests(unittest.TestCase):
    def test_replies_pass_the_hosts_parser(self):
        for operation, data in (("lief.headers", elf()[0]), ("lief.headers", pe()[0]), ("lief.sections", pe()[0])):
            with self.subTest(operation=operation):
                raw = (json.dumps(run(operation, data), sort_keys=True, separators=(",", ":")) + "\n").encode()
                observations = parse_worker_reply(raw, input_sha256=sha256_hex(data), max_observations=64)
                self.assertEqual(len(observations), len(run(operation, data)["observations"]))
        error = (json.dumps(run("lief.sections", elf(extended=True)[0])) + "\n").encode()
        with self.assertRaises(WorkerError):
            parse_worker_reply(error, input_sha256=sha256_hex(elf(extended=True)[0]), max_observations=64)

    def test_main_reads_the_snapshot_and_prints_one_json_object(self):
        data = pe()[0]
        with tempfile.TemporaryDirectory() as temporary:
            snapshot = Path(temporary, "input")
            snapshot.write_bytes(data)
            out = io.StringIO()
            with patch.object(worker, "lief_facts", faithful), contextlib.redirect_stdout(out):
                self.assertEqual(worker.main(["lief.headers", "{}"], snapshot=str(snapshot)), 0)
        text = out.getvalue()
        self.assertTrue(text.endswith("\n") and text.count("\n") == 1)
        self.assertEqual(json.loads(text)["snapshot_sha256"], sha256_hex(data))

    def test_build_inputs_are_pinned_consistently(self):
        build = (ROOT / "tools" / "build_lief_image.py").read_text()
        dockerfile = (ROOT / "containers" / "lief" / "Dockerfile").read_text()
        requirements = (ROOT / "containers" / "lief" / "requirements.txt").read_text()
        digest = re.search(r'BASE_DIGEST = "(sha256:[0-9a-f]{64})"', build).group(1)
        self.assertIn("FROM python:3.12-slim@" + digest + "\n", dockerfile)
        self.assertIn('ADAPTER_VERSION = "' + worker.ADAPTER_VERSION + '"', build)
        self.assertEqual(re.findall(r"--hash=sha256:([0-9a-f]{64})", requirements),
                         ["a9e4b9e165bde0163624e159c8c7a096e3d6f671371c70d008baac7ac1f04f0d"])
        self.assertIn('ENTRYPOINT ["python3", "-I", "-B", "/opt/reverseai/worker.py"]', dockerfile)
        self.assertIn("USER 65534:65534", dockerfile)
        lock = ROOT / "containers" / "lief" / "image.lock.json"
        if lock.exists():
            value = json.loads(lock.read_text())
            self.assertEqual(set(value), {"image_id", "platform", "base_digest", "wheel_sha256", "adapter_version"})
            self.assertEqual((value["base_digest"], value["platform"], value["adapter_version"]),
                             (digest, "linux/arm64", worker.ADAPTER_VERSION))


if __name__ == "__main__":
    unittest.main()
