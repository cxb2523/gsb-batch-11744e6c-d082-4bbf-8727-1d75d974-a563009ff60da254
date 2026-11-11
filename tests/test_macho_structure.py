import random
import struct
import unittest

from reverseai.contract import Location, Observation
from reverseai.tools import structure
from tests.fixtures_code import macho_code
from tests.fixtures_structure import MACHO_SECTIONS, macho, macho_fat, patched
from tests.test_structure import run


class MachoStructureTests(unittest.TestCase):
    def test_exact_thin_headers_and_sections_for_both_widths(self):
        for width in (32, 64):
            data, layout = macho(width=width)
            with self.subTest(width=width):
                self.assertEqual(run("structure.headers", data), [Observation(Location(0, layout["header_size"]), {
                    "structure": "macho", "format": "macho", "machine_name": "x86_64" if width == 64 else "x86",
                    "filetype": 2, "ncmds": 4, "number_of_sections": 3})])
                expected, raw = [], layout["content_start"]
                for i, (name, segment, flags, prot, size) in enumerate(MACHO_SECTIONS):
                    expected.append(Observation(Location(layout["section_offsets"][i], layout["section_size"]), {
                        "index": i, "name": segment.decode() + "," + name.decode(), "offset": raw, "size": size,
                        "writable": bool(prot & 2), "executable": bool(prot & 4 or flags & 0x80000400)}))
                    raw += size
                self.assertEqual(run("structure.sections", data), expected)
                mapped = structure.macho_sections(data)
                self.assertEqual(mapped, [dict(o.value, addr=layout["addresses"][i]) for i, o in enumerate(expected)])
                self.assertEqual(run("structure.sections", data, max_sections=1), expected[:1])

    def test_permissions_follow_segment_initprot_and_either_instruction_attribute(self):
        rows = ((b"a", b"S", 0, 4, 1), (b"b", b"S", 0x80000000, 0, 1),
                (b"c", b"S", 0x400, 0, 1), (b"d", b"S", 0, 2, 1), (b"e", b"S", 0, 0, 1))
        values = [o.value for o in run("structure.sections", macho(sections=rows)[0])]
        self.assertEqual([v["executable"] for v in values], [True, True, True, False, False])
        self.assertEqual([v["writable"] for v in values], [False, False, False, True, False])

    def test_big_endian_thin_and_fat_only_identified(self):
        for width in (32, 64):
            thin, _ = macho(width=width, order=">")
            self.assertEqual(run("structure.identify", thin)[0].value["format"], "macho")
            for operation in ("structure.headers", "structure.sections", "structure.imports"):
                self.assertEqual(run(operation, thin), [])
            self.assertEqual(structure.macho_sections(thin), [])
            self.assertIsNone(structure.macho_entry(thin))
            for order in (">",):
                fat = macho_fat(width=width, order=order, machines=(7, 0x1000007, 0x100000C, 999) * 3)
                self.assertEqual(run("structure.identify", fat)[0].value, {
                    "format": "macho-universal", "magic": fat[:4].hex(),
                    "architectures": ["x86", "x86_64", "aarch64", "unknown"] * 2})
                for operation in ("structure.headers", "structure.sections", "structure.imports"):
                    self.assertEqual(run(operation, fat), [])
                self.assertEqual(run("structure.identify", fat[:7])[0].value["format"], "unknown")

    def test_little_endian_fat_magics_are_not_universal(self):
        for width in (32, 64):
            data = macho_fat(width=width, order="<")
            self.assertEqual(run("structure.identify", data)[0].value["format"], "unknown")

    def test_names_escape_controls_backslashes_and_non_ascii(self):
        data, _ = macho(sections=((b"a\x1b\xff\\", b"S\x00ignored", 0, 0, 1),))
        self.assertEqual(run("structure.sections", data)[0].value["name"], "S,a\\x1b\\xff\\x5c")

    def test_mapping_refuses_zero_fill_and_out_of_segment_or_input_ranges(self):
        for width in (32, 64):
            for flag in (1, 0xC, 0x12):
                data, _ = macho(width=width, sections=((b"bss", b"RWX", flag, 7, 16),))
                self.assertTrue(run("structure.sections", data)[0].value["executable"])
                self.assertEqual(structure.macho_sections(data), [])
            data, layout = macho(width=width)
            s = layout["section_offsets"][0]
            offset_field = s + (48 if width == 64 else 40)
            # Both byte 0 and the next segment are real input, but neither belongs to this segment.
            for offset in (0, layout["content_start"] + 16, len(data)):
                self.assertEqual([r["index"] for r in structure.macho_sections(patched(data, offset_field, "<I", offset))], [1, 2])
            self.assertEqual(structure.macho_sections(data[:-1])[-1]["index"], 1)

    def test_helper_is_bounded_and_keeps_original_indices_when_filtering(self):
        rows = ((b"z", b"S", 1, 7, 1),) + ((b"a", b"S", 0, 5, 1),) * 299
        data, _ = macho(sections=rows, entry=None)
        self.assertEqual(len(run("structure.sections", data, max_sections=256)), 256)
        mapped = structure.macho_sections(data)
        self.assertEqual([r["index"] for r in mapped], list(range(1, 256)))
        self.assertEqual(run("structure.headers", data)[0].value["number_of_sections"], 300)

    def test_shared_code_fixture_exact_mapping_and_main_entry(self):
        data, layout = macho_code()
        self.assertEqual(structure.macho_sections(data), [{"index": 0, "name": "__TEXT,__text",
                         "addr": layout["text"]["address"], "offset": layout["text"]["offset"],
                         "size": layout["text"]["size"], "executable": True, "writable": False}])
        self.assertEqual(structure.macho_entry(data), layout["entry"])

    def test_main_entry_maps_nonzero_fileoff_and_rejects_ambiguous_or_out_of_bounds(self):
        for width in (32, 64):
            data, layout = macho(width=width)
            self.assertEqual(structure.macho_entry(data), layout["entry"])
            main = layout["entry_command"]
            for offset in (0, len(data), 2**64 - 1):
                self.assertIsNone(structure.macho_entry(patched(data, main + 8, "<Q", offset)))
            no_command = patched(data, main, "<I", 0x1234)
            self.assertIsNone(structure.macho_entry(no_command))
            self.assertIsNone(structure.macho_entry(patched(data, main + 4, "<I", 8)))
            # The whole segment must be in the input.
            segment_filesize = layout["header_size"] + (48 if width == 64 else 36)
            self.assertIsNone(structure.macho_entry(patched(data, segment_filesize, "<Q" if width == 64 else "<I", len(data))))
            # A second segment claiming the same file range makes LC_MAIN ambiguous.
            second = layout["section_offsets"][1] - (72 if width == 64 else 56)
            fileoff = second + (40 if width == 64 else 32)
            ambiguous = patched(data, fileoff, "<Q" if width == 64 else "<I", layout["content_start"])
            self.assertIsNone(structure.macho_entry(ambiguous))

    def test_unixthread_x86_64_and_arm64_states_and_bad_flavors_counts(self):
        for kind, machine in (("x86_thread", 0x1000007), ("arm_thread", 0x100000C)):
            data, layout = macho(entry=kind, machine=machine)
            start = layout["entry_command"]
            self.assertEqual(structure.macho_entry(data), layout["entry"])
            for field, value in ((8, 99), (12, 0), (12, 2**32 - 1)):
                self.assertIsNone(structure.macho_entry(patched(data, start + field, "<I", value)))
        for data in (b"", b"unrecognized", macho(entry=None)[0], macho(machine=1234, entry="x86_thread")[0]):
            self.assertIsNone(structure.macho_entry(data))

    def test_malformed_commands_stay_inside_the_input(self):
        data, layout = macho(libraries=(b"liba",), symbols=(b"func",))
        bad = [patched(data, 16, "<I", 2**32 - 1), patched(data, 20, "<I", 2**32 - 1),
               patched(data, 36, "<I", 0), patched(data, 36, "<I", 7), patched(data, 36, "<I", len(data)),
               patched(data, 32 + 64, "<I", 2**32 - 1)]
        for item in bad:
            for operation in ("structure.headers", "structure.sections"):
                with self.subTest(operation=operation), self.assertRaises(ValueError):
                    run(operation, item)
            self.assertIsNone(structure.macho_entry(item))
        generator = random.Random(7301)
        for item in [data[:i] for i in range(len(data))] + [patched(data, generator.randrange(len(data)), "B", generator.randrange(256)) for _ in range(300)]:
            for operation in ("structure.identify", "structure.headers", "structure.sections", "structure.imports"):
                try:
                    found = run(operation, item)
                except ValueError:
                    continue
                self.assertLessEqual(len(found), structure.TOOL.operations[operation].max_observations)
                self.assertTrue(all(o.location.within(len(item)) for o in found))
            structure.macho_entry(item)


if __name__ == "__main__":
    unittest.main()
