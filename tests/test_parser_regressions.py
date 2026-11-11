import struct
import unittest
from unittest.mock import patch

from reverseai import pipeline
from reverseai.analysts import capability
from reverseai.contract import InputRef, sha256_hex
from reverseai.tools import structure
from tests.fixtures_structure import (
    elf_dynamic_hash_product, elf_dynamic_imports, elf_dynamic_mapping_product, elf_imports, macho, macho_fat, patched, pe_imports,
)
from tests.test_structure import run


class ParserRegressionTests(unittest.TestCase):
    def test_sectionless_elf_mapping_work_is_bounded_across_all_tables(self):
        original = struct.unpack_from
        for distinct in (False, True):
            data = elf_dynamic_mapping_product(distinct=distinct)
            comparisons = 0

            class CountedAddress(int):
                def __le__(self, other):
                    nonlocal comparisons
                    comparisons += 1
                    if comparisons > 65536:
                        raise AssertionError("ELF mapping exceeded its aggregate comparison bound")
                    return super().__le__(other)

            def unpack(fmt, data, offset=0):
                values = original(fmt, data, offset)
                if fmt == "<IIQQQQQQ" and values[0] == 1:
                    values = (*values[:3], CountedAddress(values[3]), *values[4:])
                return values

            with self.subTest(distinct=distinct), patch.object(structure.struct, "unpack_from", side_effect=unpack):
                self.assertEqual(run("structure.imports", data), [])
            self.assertGreater(comparisons, 0)
            self.assertLessEqual(comparisons, 65536)
            if not distinct:
                self.assertEqual(comparisons, 2)  # One deduplicated table; stop at the second alias.

    def test_gnu_hash_work_is_shared_across_distinct_dynamic_tables(self):
        original = struct.unpack_from
        for chains in (False, True):
            data, layout = elf_dynamic_hash_product(chains=chains)
            reads = 0

            def unpack(fmt, data, offset=0):
                nonlocal reads
                if fmt == "<I" and layout["counted_start"] <= offset < layout["counted_end"]:
                    reads += 1
                    if reads > 65536:
                        raise AssertionError("GNU hash exceeded its aggregate element bound")
                return original(fmt, data, offset)

            with self.subTest(chains=chains), patch.object(structure.struct, "unpack_from", side_effect=unpack):
                self.assertEqual(run("structure.imports", data), [])
            self.assertGreater(reads, 0)
            self.assertLessEqual(reads, 65536)

    def test_only_external_undefined_macho_symbols_reach_supported_findings(self):
        for width in (32, 64):
            data, layout = macho(width=width, symbols=(b"_local", b"_external"))
            symbol = layout["symbols_offset"] + (16 if width == 64 else 12)
            for kind in (0, 0x10):  # Local undefined, with and without N_PEXT.
                altered = patched(data, symbol + 4, "B", kind)
                with self.subTest(width=width, kind=kind):
                    self.assertEqual(run("structure.imports", altered)[0].value["names"], ["_external"])
                    analysis = pipeline.analyze_bytes(altered, InputRef(sha256_hex(altered), len(altered), "synthetic"))
                    result = next(r for r in analysis.results if r.role == "capability")
                    finding = next(f for f in result.findings if f.claim_key == "imports.symbols")
                    self.assertEqual(finding.value, ["_external"])
                    self.assertEqual(next(v.status for v in analysis.verdicts if v.finding_id == finding.id), "supported")
            private_external = patched(data, symbol + 4, "B", 0x11)
            self.assertEqual(run("structure.imports", private_external)[0].value["names"], ["_local", "_external"])

    def test_java_classes_and_invalid_architecture_counts_are_not_universal_macho(self):
        java = bytes.fromhex("cafebabe00000034") + bytes(1200)
        self.assertEqual(run("structure.identify", java)[0].value["format"], "unknown")
        for width in (32, 64):
            for order in ("<", ">"):
                valid = macho_fat(width=width, order=order, machines=(7,) * 20)
                # Only big-endian fat wrappers are identified.
                self.assertEqual(run("structure.identify", valid)[0].value["format"],
                                 "macho-universal" if order == ">" else "unknown")
                for count in (0, 21, 52):
                    invalid = macho_fat(width=width, order=order, machines=(7,) * count)
                    self.assertEqual(run("structure.identify", invalid)[0].value["format"], "unknown")
                self.assertEqual(run("structure.identify", valid[:-1])[0].value["format"], "unknown")

    def test_universal_macho_finding_statement_matches_its_value(self):
        data = macho_fat()
        analysis = pipeline.analyze_bytes(data, InputRef(sha256_hex(data), len(data), "synthetic"))
        finding = next(f for r in analysis.results for f in r.findings if f.claim_key == "format.container")
        self.assertEqual(finding.value, "macho-universal")
        self.assertEqual(finding.claim, "The input is a universal Mach-O file.")

    def test_import_finding_cut_uses_file_order_instead_of_hash_order(self):
        data, _ = elf_imports(libraries=tuple(f"lib{i:03d}".encode() for i in range(80)), symbols=())
        ref = InputRef(sha256_hex(data), len(data), "synthetic")
        task = capability.plan(ref)
        from reverseai.contract import make_evidence
        evidence = tuple(make_evidence(data, structure.REF, "structure.imports", o) for o in run("structure.imports", data))
        for items in (evidence, tuple(reversed(evidence))):
            finding = next(f for f in capability.conclude(task, items) if f.claim_key == "imports.libraries")
            self.assertEqual(finding.value, [f"lib{i:03d}" for i in range(64)])

    def test_macho_command_alignment_and_sizeofcmds_are_independent_bounds(self):
        base, _ = macho(sections=(), entry=None)
        for size, declared in ((12, 12), (16, 8)):
            data = patched(patched(base, 16, "<I", 1), 20, "<I", declared) + struct.pack("<II", 0x42, size) + bytes(size - 8)
            with self.subTest(size=size, declared=declared), self.assertRaises(structure.StructureError):
                run("structure.headers", data)

    def test_macho_segment_width_must_match_header_even_without_sections(self):
        for width in (32, 64):
            base, _ = macho(width=width, sections=(), entry=None)
            if width == 32:
                segment = struct.pack("<II16sQQQQIIII", 0x19, 72, b"S", 0, 0, 0, 0, 0, 0, 0, 0)
            else:
                segment = struct.pack("<II16s8I", 1, 56, b"S", 0, 0, 0, 0, 0, 0, 0, 0)
            data = patched(patched(base, 16, "<I", 1), 20, "<I", len(segment)) + segment
            with self.subTest(width=width), self.assertRaises(structure.StructureError):
                run("structure.headers", data)

    def test_macho_entry_refuses_duplicate_main_and_virtual_only_or_wrapping_spans(self):
        for width in (32, 64):
            data, layout = macho(width=width, sections=((b"text", b"S", 0, 5, 32),))
            self.assertEqual(structure.macho_entry(data), layout["entry"])
            main, header = layout["entry_command"], layout["header_size"]
            old_size = struct.unpack_from("<I", data, 20)[0]
            duplicate = bytearray(patched(patched(data, 16, "<I", 3), 20, "<I", old_size + 24))
            duplicate[main + 24:main + 48] = duplicate[main:main + 24]
            self.assertIsNone(structure.macho_entry(bytes(duplicate)))
            word = "<Q" if width == 64 else "<I"
            virtual = patched(patched(data, header + (32 if width == 64 else 28), word, 8), main + 8, "<Q", layout["content_start"] + 16)
            self.assertIsNone(structure.macho_entry(virtual))
            wrapping = patched(data, header + 24, word, 2**width - 16)
            self.assertIsNone(structure.macho_entry(wrapping))

    def test_macho_thread_state_count_must_be_exact_even_when_pc_fits(self):
        for entry, machine, count in (("x86_thread", 0x1000007, 40), ("arm_thread", 0x100000C, 66)):
            data, layout = macho(entry=entry, machine=machine)
            command = layout["entry_command"]
            altered = patched(patched(data, command + 12, "<I", count), command + 4, "<I", 16 + count * 4)
            self.assertIsNone(structure.macho_entry(altered))

    def test_short_unterminated_import_name_and_non_string_link_are_refused(self):
        data, layout = elf_imports(libraries=(b"alpha",), symbols=())
        strings_header = layout["shoff"] + 2 * 64
        unterminated = patched(data, strings_header + 32, "<Q", 6)
        self.assertEqual(run("structure.imports", unterminated), [])
        not_strings = patched(data, strings_header + 4, "<I", 1)
        self.assertEqual(run("structure.imports", not_strings), [])

    def test_soname_rpath_and_runpath_are_not_needed_libraries(self):
        for width in (32, 64):
            data, layout = elf_imports(width=width, libraries=(b"needed", b"self", b"rpath", b"runpath"), symbols=())
            word, entry = ("<Q", 16) if width == 64 else ("<I", 8)
            for index, tag in enumerate((14, 15, 29), start=1):
                data = patched(data, layout["dynamic"] + entry * index, word, tag)
            self.assertEqual([o.value["name"] for o in run("structure.imports", data) if o.value["kind"] == "library"], ["needed"])

    def test_duplicate_dynamic_address_tags_and_ambiguous_load_maps_are_refused(self):
        data, layout = elf_dynamic_imports()
        duplicate_tag = patched(patched(data, layout["dynamic"] + 4 * 16, "<Q", 5),
                                layout["dynamic"] + 4 * 16 + 8, "<Q", 0x400300)
        self.assertEqual(run("structure.imports", duplicate_tag), [])
        alias = bytearray(patched(data, 56, "<H", 3))
        alias[64 + 2 * 56:64 + 3 * 56] = alias[64:64 + 56]
        self.assertEqual(run("structure.imports", bytes(alias)), [])

    def test_sysv_hash_extent_and_gnu_last_symbol_boundary_are_checked(self):
        data, layout = elf_dynamic_imports()
        overrun = patched(data, layout["hash"], "<I", 2**32 - 1)
        self.assertEqual([o.value["kind"] for o in run("structure.imports", overrun)], ["library"])
        data, _ = elf_dynamic_imports(gnu_hash=True)
        data = bytearray(patched(data, 0x200 + 3 * 24 + 6, "<H", 0))
        struct.pack_into("<IBBHQQ", data, 0x200 + 4 * 24, 1, 0x12, 0, 0, 0, 0)
        names = [o.value["names"] for o in run("structure.imports", bytes(data)) if o.value["kind"] == "symbols"]
        self.assertEqual(names, [["alpha", "beta", "defined"]])

    def test_pe_directory_count_and_macho_dylib_header_offsets_are_refused(self):
        for plus in (False, True):
            data, layout = pe_imports(plus=plus)
            self.assertEqual(run("structure.imports", patched(data, layout["directory"] - 12, "<I", 1)), [])
        data, layout = macho(libraries=(b"lib",))
        command = layout["dylib_names"][0] - 24
        self.assertEqual(run("structure.imports", patched(data, command + 8, "<I", 0)), [])


if __name__ == "__main__":
    unittest.main()
