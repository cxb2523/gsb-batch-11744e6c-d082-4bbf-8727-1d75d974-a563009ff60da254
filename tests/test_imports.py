import random
import unittest

from reverseai.contract import MAX_OBSERVATION_BYTES, ContractError, Location, Observation, canonical_json, make_evidence
from reverseai.tools import structure
from tests.fixtures_structure import elf_dynamic_imports, elf_imports, macho, patched, pe_imports
from tests.test_structure import run


class ImportTests(unittest.TestCase):
    def test_sectionless_elf_uses_dynamic_program_header_and_both_hash_formats(self):
        for width in (32, 64):
            for order in ("<", ">"):
                for gnu in (True, False):
                    data, layout = elf_dynamic_imports(width=width, order=order, gnu_hash=gnu)
                    with self.subTest(width=width, order=order, gnu=gnu):
                        self.assertEqual(run("structure.imports", data), [
                            Observation(Location(layout["library_names"][0], 11), {"kind": "library", "name": "libalpha.so"}),
                            Observation(Location(layout["symbol_names"][0], 5), {"kind": "symbols", "library": None, "names": ["alpha", "beta"]})])

    def test_elf_libraries_and_only_undefined_dynamic_symbols_in_both_widths_and_orders(self):
        for width in (32, 64):
            for order in ("<", ">"):
                data, layout = elf_imports(width=width, order=order)
                with self.subTest(width=width, order=order):
                    self.assertEqual(run("structure.imports", data), [
                        Observation(Location(layout["library_names"][0], 11), {"kind": "library", "name": "libalpha.so"}),
                        Observation(Location(layout["library_names"][1], 10), {"kind": "library", "name": "libbeta.so"}),
                        Observation(Location(layout["symbol_names"][0], 5), {"kind": "symbols", "library": None, "names": ["alpha", "beta"]})])

    def test_pe_dll_names_hints_ordinals_and_first_thunk_fallback(self):
        for plus in (True, False):
            for original in (True, False):
                data, layout = pe_imports(plus=plus, original=original)
                with self.subTest(plus=plus, original=original):
                    self.assertEqual(run("structure.imports", data), [
                        Observation(Location(layout["library_names"][0], 12), {"kind": "library", "name": "KERNEL32.dll"}),
                        Observation(Location(layout["symbol_names"][0][0], 11), {"kind": "symbols", "library": "KERNEL32.dll", "names": ["ExitProcess", "#7"]}),
                        Observation(Location(layout["library_names"][1], 10), {"kind": "library", "name": "USER32.dll"}),
                        Observation(Location(layout["symbol_names"][1][0], 11), {"kind": "symbols", "library": "USER32.dll", "names": ["MessageBoxA"]})])
                ordinal_data, ordinal_layout = pe_imports(plus=plus, libraries=((b"lib.dll", (42, 43)),))
                self.assertEqual(run("structure.imports", ordinal_data)[1], Observation(
                    Location(ordinal_layout["thunks"][0], 8 if plus else 4), {"kind": "symbols", "library": "lib.dll", "names": ["#42", "#43"]}))

    def test_macho_reexport_lazy_and_upward_dylibs_use_the_bounded_name_layout(self):
        for width in (32, 64):
            data, layout = macho(width=width, libraries=(b"/usr/lib/libother.dylib",))
            position = layout["dylib_names"][0] - 24
            expected = run("structure.imports", data)
            self.assertEqual(expected[0].value, {"kind": "library", "name": "/usr/lib/libother.dylib"})
            for command in (0xC, 0x80000018, 0x8000001f, 0x20, 0x80000023):
                changed = patched(data, position, "<I", command)
                with self.subTest(width=width, command=command):
                    self.assertEqual(run("structure.imports", changed), expected)
                    self.assertEqual(run("structure.imports", patched(changed, position + 8, "<I", 23)), [])
                    self.assertEqual(run("structure.imports", patched(changed, position + 8, "<I", 2**32 - 1)), [])

    def test_macho_load_and_weak_dylibs_and_only_undefined_external_symbols(self):
        for width in (32, 64):
            data, layout = macho(width=width, libraries=(b"/usr/lib/a.dylib", b"/usr/lib/b.dylib"), symbols=(b"_alpha", b"_beta"))
            with self.subTest(width=width):
                self.assertEqual(run("structure.imports", data), [
                    Observation(Location(layout["dylib_names"][0], 16), {"kind": "library", "name": "/usr/lib/a.dylib"}),
                    Observation(Location(layout["dylib_names"][1], 16), {"kind": "library", "name": "/usr/lib/b.dylib"}),
                    Observation(Location(layout["symbol_names"][0], 6), {"kind": "symbols", "library": None, "names": ["_alpha", "_beta"]})])
                # Debug entries and common symbols (undefined type with a nonzero value) are not imports.
                start, size = layout["symbols_offset"] + (16 if width == 64 else 12), 16 if width == 64 else 12
                debug = patched(data, start + 4, "B", 0xE1)
                common = patched(data, start + 8, "<Q" if width == 64 else "<I", 12)
                defined_type = patched(data, start + 4, "B", 0xF)
                defined_section = patched(data, start + 5, "B", 1)
                for control in (debug, common, defined_type, defined_section):
                    self.assertEqual(run("structure.imports", control)[-1].value["names"], ["_beta"])

    def test_groups_cut_at_32_and_observation_cap_including_json_escaping(self):
        for names in (tuple(f"symbol{i:03d}".encode() for i in range(70)), (b'"' * 128,) * 40, (b"\xff" * 128,) * 40):
            for builder in (lambda: elf_imports(libraries=(), symbols=names), lambda: macho(symbols=names),
                            lambda: pe_imports(libraries=((b"a" * 128, names),))):
                data, _ = builder()
                found = run("structure.imports", data)
                groups = [o for o in found if o.value["kind"] == "symbols"]
                self.assertEqual(sum(len(o.value["names"]) for o in groups), len(names))
                for o in groups:
                    self.assertLessEqual(len(o.value["names"]), 32)
                    self.assertLessEqual(len(canonical_json(o.value).encode()), MAX_OBSERVATION_BYTES)
                    self.assertTrue(all(0 < len(name) <= 128 and name.isascii() and name.isprintable() for name in o.value["names"]))

    def test_names_and_locations_use_the_same_escaped_bounded_prefix(self):
        names = (b"a\\\x1b\xffb", b"n" * 300, b"\xff" * 100)
        for data, _ in (elf_imports(libraries=names, symbols=names), macho(libraries=names, symbols=names)):
            found = run("structure.imports", data)
            self.assertEqual([o.value["name"] for o in found if o.value["kind"] == "library"],
                             ["a\\x5c\\x1b\\xffb", "n" * 128, "\\xff" * 32])
            self.assertEqual([o.location.length for o in found if o.value["kind"] == "library"], [5, 128, 32])
            for observation in found:
                self.assertTrue(make_evidence(data, structure.REF, "structure.imports", observation).location.within(len(data)))

    def test_max_imports_caps_observations_and_has_closed_argument_schema(self):
        data, _ = elf_imports(libraries=tuple(f"lib{i}".encode() for i in range(300)))
        self.assertEqual(len(run("structure.imports", data)), 128)
        self.assertEqual(len(run("structure.imports", data, max_imports=256)), 256)
        self.assertEqual(len(run("structure.imports", data, max_imports=1)), 1)
        spec = structure.TOOL.operations["structure.imports"]
        self.assertFalse(spec.derived)
        self.assertEqual(spec.max_observations, 256)
        for args in ({"max_imports": 0}, {"max_imports": 257}, {"max_imports": True}, {"max_imports": "1"}, {"path": "x"}):
            with self.assertRaises(ContractError):
                spec.validate_args(args)

    def test_bad_elf_link_entry_size_and_name_offsets_never_become_imports(self):
        data, layout = elf_imports()
        for control in (patched(data, layout["shoff"] + 64 + 40, "<I", 2**32 - 1),
                        patched(data, layout["shoff"] + 64 + 56, "<Q", 0),
                        patched(data, layout["dynamic"] + 8, "<Q", 2**64 - 1)):
            self.assertNotIn("libalpha.so", [o.value.get("name") for o in run("structure.imports", control)])
        out_of_range = patched(data, layout["dynsym"] + 24, "<I", layout["strings_size"])
        self.assertEqual(run("structure.imports", out_of_range)[-1].value["names"], ["beta"])

    def test_malformed_pe_directory_dll_thunk_and_ordinal_cut_at_valid_prefix(self):
        data, layout = pe_imports()
        for control in (patched(data, layout["directory"], "<I", 0xFFFFFFFF),
                        patched(data, layout["descriptor"] + 12, "<I", 0xFFFFFFFF),
                        patched(data, layout["table_offset"] + 12, "<I", 0xFFFFFFFF)):
            self.assertEqual(run("structure.imports", control), [])
        invalid_thunk = patched(data, layout["thunks"][0], "<Q", 0x100000001)
        self.assertEqual(run("structure.imports", invalid_thunk)[0].value["name"], "KERNEL32.dll")
        self.assertFalse(any("ExitProcess" in o.value.get("names", []) for o in run("structure.imports", invalid_thunk)))
        invalid_ordinal = patched(data, layout["thunks"][0] + 8, "<Q", (1 << 63) | (1 << 30) | 7)
        self.assertEqual(run("structure.imports", invalid_ordinal)[1].value["names"], ["ExitProcess"])
        # Two section headers mapping the same RVA cannot select a unique import table.
        ambiguous = bytearray(patched(data, layout["lfanew"] + 6, "<H", 2))
        table = layout["table_offset"]
        ambiguous[table + 40:table + 80] = ambiguous[table:table + 40]
        self.assertEqual(run("structure.imports", bytes(ambiguous)), [])
        padding = patched(data, table + 8, "<I", 21)
        self.assertEqual(run("structure.imports", padding), [])

    def test_every_truncation_and_seeded_corruption_produces_only_bounded_observations(self):
        generator = random.Random(7317)
        for data, _ in (elf_imports(), elf_imports(width=32, order=">"), elf_dynamic_imports(), elf_dynamic_imports(gnu_hash=True),
                        pe_imports(), pe_imports(plus=False),
                        macho(libraries=(b"lib",), symbols=(b"func",))):
            corruptions = [data[:i] for i in range(len(data) + 1)]
            corruptions += [patched(data, generator.randrange(len(data)), "B", generator.randrange(256)) for _ in range(200)]
            for item in corruptions:
                found = run("structure.imports", item)
                self.assertLessEqual(len(found), 128)
                for observation in found:
                    self.assertTrue(observation.location.within(len(item)))
                    make_evidence(item, structure.REF, "structure.imports", observation)


if __name__ == "__main__":
    unittest.main()
