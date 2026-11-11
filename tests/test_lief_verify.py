"""Host re-derivation of contained LIEF values: honest worker replies pass, every forged value is refused.

The honest replies come from the worker's own logic with faithful LIEF facts (tests/test_lief_worker_logic.py),
so the host must confirm everything a correct worker can send; no Docker and no LIEF.
"""

import json
import struct
import unittest

from reverseai import pipeline
from reverseai.contract import ContractError, InputRef, Location, Observation, parse_worker_reply, sha256_hex
from reverseai.tools import lief_tool
from reverseai.tools.lief_verify import verify
from tests.fixtures_structure import elf, patched, pe
from tests.test_contained import lock
from tests.test_lief_worker_logic import far_pe, run as worker_run

REFUSED = "^Worker value not confirmed by the bytes$"
DROP = object()


class WorkerExecutor:
    """The real worker logic behind the contained interface; forge(operation, reply) may alter its reply first."""

    def __init__(self, forge=None):
        self.lock = lock()
        self.forge = forge

    def run(self, operation, args, data, digest):
        reply = worker_run(operation, data, **args)
        if self.forge:
            self.forge(operation, reply)
        return json.dumps(reply).encode("utf-8")


def honest(operation, data):
    """The observations a correct worker sends for data, parsed as the host parses them."""
    args = {"max_sections": 64} if operation == "lief.sections" else {}
    raw = json.dumps(worker_run(operation, data, **args)).encode("utf-8")
    return parse_worker_reply(raw, input_sha256=sha256_hex(data), max_observations=64)


def forged(observation, offset=0, length=0, **changes):
    value = dict(observation.value)
    for key, new in changes.items():
        if new is DROP:
            del value[key]
        else:
            value[key] = new
    return Observation(Location(observation.location.offset + offset, observation.location.length + length), value)


def decoded_at(data, at, index):
    """A section observation decoded truthfully from whatever bytes lie at at (ELF64 LE or PE): only alignment can refuse it."""
    if data[:4] == b"\x7fELF":
        _, _, flags, _, start, size = struct.unpack_from("<IIQQQQIIQQ", data, at)[:6]
        return Observation(Location(at, 64), {"structure": "section", "index": index, "offset": start, "size": size,
                                              "flags": flags, "writable": bool(flags & 1), "executable": bool(flags & 4)})
    _, _, _, size, start = struct.unpack_from("<8sIIII", data, at)
    characteristics = struct.unpack_from("<I", data, at + 36)[0]
    return Observation(Location(at, 40), {"structure": "section", "index": index, "offset": start, "size": size,
                                          "characteristics": characteristics, "writable": bool(characteristics & 0x80000000),
                                          "executable": bool(characteristics & 0x20000000)})


def g1_forge(operation, reply):
    """Section 1 (.text, flags 0x6) reported as writable and executable."""
    if operation == "lief.sections":
        reply["observations"][1]["value"].update(flags=0x7, writable=True, executable=True)


FIXTURES = {
    "elf64 le": elf()[0],
    "elf32 be": elf(width=32, order=">", kind=3, machine=8)[0],
    "elf64 be": elf(order=">", machine=21)[0],
    "pe32+": pe()[0],
    "pe32": pe(plus=False, machine=0x14C)[0],
    "pe32+ e_lfanew 0x2000": far_pe(),
    "pe32+ 20-byte optional header": pe(optional_size=20)[0],
    "pe without optional header": patched(pe()[0], 0x80 + 4 + 16, "<H", 0),
    "elf64 le unknown machine 0x3E00": elf(machine=0x3E00)[0],
    "pe32+ unknown machine 0x3E00": pe(machine=0x3E00)[0],
    **{f"pe32+ {size}-byte optional header": pe(optional_size=size)[0] for size in (1, 2, 18, 19)},
}


class HonestReplyTests(unittest.TestCase):
    def test_everything_a_correct_worker_sends_is_confirmed(self):
        for label, data in FIXTURES.items():
            for operation in ("lief.headers", "lief.sections"):
                with self.subTest(label, operation=operation):
                    observations = honest(operation, data)
                    self.assertTrue(observations)
                    for observation in observations:
                        self.assertIsNone(verify(operation, data, observation))
                    handler = lief_tool.make_tool(WorkerExecutor()).operations[operation].handler
                    self.assertEqual(handler(data, {"max_sections": 64} if operation == "lief.sections" else {}),
                                     observations)

    def test_known_answers_elf64_le(self):
        data, layout = elf()
        shoff = layout["shoff"]
        header = Observation(Location(0, 64), {
            "structure": "elf", "format": "elf", "class": 64, "endianness": "little", "type": 2, "machine": 62,
            "machine_name": "x86_64", "entry": 0x401000, "shnum": 5, "shoff": shoff})
        text = Observation(Location(shoff + 64, 64), {
            "structure": "section", "index": 1, "offset": layout["offsets"][0], "size": 32, "flags": 0x6,
            "writable": False, "executable": True})
        rwx = Observation(Location(shoff + 3 * 64, 64), {
            "structure": "section", "index": 3, "offset": layout["offsets"][2], "size": 8, "flags": 0x7,
            "writable": True, "executable": True})
        self.assertEqual(honest("lief.headers", data), (header,))
        self.assertEqual(honest("lief.sections", data)[1], text)
        self.assertEqual(honest("lief.sections", data)[3], rwx)
        for operation, observation in (("lief.headers", header), ("lief.sections", text), ("lief.sections", rwx)):
            self.assertIsNone(verify(operation, data, observation))

    def test_known_answers_elf32_be(self):
        data, layout = elf(width=32, order=">", kind=3, machine=8)
        header = Observation(Location(0, 52), {
            "structure": "elf", "format": "elf", "class": 32, "endianness": "big", "type": 3, "machine": 8,
            "machine_name": "mips", "entry": 0x401000, "shnum": 5, "shoff": layout["shoff"]})
        data_section = Observation(Location(layout["shoff"] + 2 * 40, 40), {
            "structure": "section", "index": 2, "offset": layout["offsets"][1], "size": 16, "flags": 0x3,
            "writable": True, "executable": False})
        self.assertEqual(honest("lief.headers", data), (header,))
        self.assertEqual(honest("lief.sections", data)[2], data_section)
        self.assertIsNone(verify("lief.headers", data, header))
        self.assertIsNone(verify("lief.sections", data, data_section))

    def test_known_answers_pe32_plus_with_e_lfanew_0x2000(self):
        data = far_pe()
        table = 0x2000 + 24 + 240
        expected_headers = (
            Observation(Location(0, 64), {"structure": "dos", "e_lfanew": 0x2000}),
            Observation(Location(0x2000, 24), {
                "structure": "coff", "format": "pe", "machine": 0x8664, "machine_name": "x86_64", "number_of_sections": 3,
                "timestamp": 0x5F5E1000, "characteristics": 0x22, "sizeof_optional_header": 240}),
            Observation(Location(0x2018, 240), {"structure": "optional", "optional_magic": "pe32+", "entry_rva": 0x1000}),
        )
        text = Observation(Location(table, 40), {
            "structure": "section", "index": 0, "offset": 0x200, "size": 0x200, "characteristics": 0x60000020,
            "writable": False, "executable": True})
        self.assertEqual(honest("lief.headers", data), expected_headers)
        self.assertEqual(honest("lief.sections", data)[0], text)
        for observation in expected_headers:
            self.assertIsNone(verify("lief.headers", data, observation))
        self.assertIsNone(verify("lief.sections", data, text))


class ForgedValueTests(unittest.TestCase):
    def assert_refused(self, cases):
        for label, operation, data, observation in cases:
            with self.subTest(label), self.assertRaisesRegex(ContractError, REFUSED):
                verify(operation, data, observation)

    def test_every_forged_elf_value_is_refused(self):
        data, layout = elf()
        (header,), sections = honest("lief.headers", data), honest("lief.sections", data)
        text, data_section, rwx = sections[1], sections[2], sections[3]
        self.assert_refused([
            ("writable flipped", "lief.sections", data, forged(text, writable=True)),
            ("writable and flag bits forged together", "lief.sections", data, forged(text, writable=True, flags=0x7)),
            ("executable flipped", "lief.sections", data, forged(data_section, executable=True)),
            ("index shifted", "lief.sections", data, forged(text, index=2)),
            ("offset changed", "lief.sections", data, forged(text, offset=text.value["offset"] + 1)),
            ("size changed", "lief.sections", data, forged(text, size=33)),
            ("flag sent as an integer", "lief.sections", data, forged(rwx, writable=1)),
            ("location shifted by one byte", "lief.sections", data, forged(text, offset=1)),
            ("location one byte longer", "lief.sections", data, forged(text, length=1)),
            ("values moved to the next entry", "lief.sections", data, forged(text, offset=64)),
            ("extra field", "lief.sections", data, forged(text, name=".text")),
            ("missing field", "lief.sections", data, forged(text, flags=DROP)),
            ("missing structure", "lief.sections", data, forged(text, structure=DROP)),
            ("section under lief.headers", "lief.headers", data, text),
            ("machine_name changed", "lief.headers", data, forged(header, machine_name="aarch64")),
            ("machine and machine_name changed", "lief.headers", data, forged(header, machine=183, machine_name="aarch64")),
            ("format changed", "lief.headers", data, forged(header, format="pe")),
            ("section count changed", "lief.headers", data, forged(header, shnum=4)),
            ("table offset changed", "lief.headers", data, forged(header, shoff=0)),
            ("class changed", "lief.headers", data, forged(header, **{"class": 32})),
            ("byte order changed", "lief.headers", data, forged(header, endianness="big")),
            ("entry changed", "lief.headers", data, forged(header, entry=0)),
            ("header location shifted by one byte", "lief.headers", data, forged(header, offset=1)),
            ("header location one byte shorter", "lief.headers", data, forged(header, length=-1)),
            ("header extra field", "lief.headers", data, forged(header, type_name="executable")),
            ("header relabelled as a section", "lief.sections", data, forged(header, structure="section")),
            ("header under lief.sections", "lief.sections", data, header),
            ("ELF header relabelled as DOS", "lief.headers", data, Observation(Location(0, 64), {
                "structure": "dos", "e_lfanew": int.from_bytes(data[0x3C:0x40], "little")})),
        ])

    def test_entries_outside_the_declared_table_are_refused(self):
        data, layout = elf()
        last = honest("lief.sections", data)[4]
        fewer = patched(data, 60, "<H", 4)  # e_shnum 4: entry 4 still exists in the bytes
        extended, extended_layout = elf(extended=True)
        entry = extended_layout["shoff"] + 64
        _, _, flags, _, start, size = struct.unpack_from("<IIQQQQIIQQ", extended, entry)[:6]
        self.assert_refused([
            ("entry past e_shnum", "lief.sections", fewer, last),
            ("extended numbering declares no table", "lief.sections", extended, Observation(Location(entry, 64), {
                "structure": "section", "index": 1, "offset": start, "size": size, "flags": flags,
                "writable": bool(flags & 1), "executable": bool(flags & 4)})),
            ("entry size other than the class's", "lief.sections", patched(data, 58, "<H", 40), honest("lief.sections", data)[1]),
            ("misaligned entry decoded from its bytes", "lief.sections", data, decoded_at(data, layout["shoff"] + 64 + 8, 1)),
            ("truncated header", "lief.headers", data[:40], honest("lief.headers", data)[0]),
        ])

    def test_every_forged_pe_value_is_refused(self):
        data = far_pe()
        dos, coff, optional = honest("lief.headers", data)
        text, data_section, _ = honest("lief.sections", data)
        past_count = Observation(Location(text.location.offset + 3 * 40, 40), {
            "structure": "section", "index": 3, "offset": 0, "size": 0, "characteristics": 0,
            "writable": False, "executable": False})
        self.assertEqual(data[past_count.location.offset:past_count.location.offset + 40], bytes(40))
        self.assert_refused([
            ("e_lfanew changed", "lief.headers", data, forged(dos, e_lfanew=0x80)),
            ("machine_name changed", "lief.headers", data, forged(coff, machine_name="x86")),
            ("format changed", "lief.headers", data, forged(coff, format="elf")),
            ("section count changed", "lief.headers", data, forged(coff, number_of_sections=4)),
            ("optional header size changed", "lief.headers", data, forged(coff, sizeof_optional_header=224)),
            ("COFF location shifted by one byte", "lief.headers", data, forged(coff, offset=1)),
            ("COFF relabelled as DOS", "lief.headers", data, forged(coff, structure="dos")),
            ("optional magic changed", "lief.headers", data, forged(optional, optional_magic="pe32")),
            ("entry changed", "lief.headers", data, forged(optional, entry_rva=0x2000)),
            ("optional header one byte shorter", "lief.headers", data, forged(optional, length=-1)),
            ("optional field missing", "lief.headers", data, forged(optional, entry_rva=DROP)),
            ("writable flipped", "lief.sections", data, forged(text, writable=True)),
            ("executable flipped", "lief.sections", data, forged(data_section, executable=True)),
            ("characteristics changed", "lief.sections", data, forged(text, characteristics=0xE0000020)),
            ("index shifted", "lief.sections", data, forged(text, index=1)),
            ("offset changed", "lief.sections", data, forged(text, offset=0x400)),
            ("size changed", "lief.sections", data, forged(text, size=0x100)),
            ("location shifted by one byte", "lief.sections", data, forged(text, offset=1)),
            ("extra field", "lief.sections", data, forged(text, name=".text")),
            ("entry past NumberOfSections", "lief.sections", data, past_count),
            ("misaligned entry decoded from its bytes", "lief.sections", data, decoded_at(data, text.location.offset + 44, 1)),
            ("DOS header of an ELF", "lief.headers", elf()[0], dos),
            ("DOS header under lief.sections", "lief.sections", data, dos),
            ("COFF header under lief.sections", "lief.sections", data, coff),
            ("optional header under lief.sections", "lief.sections", data, optional),
        ])

    def test_an_unknown_machine_cannot_be_given_a_known_name(self):
        elf_data, pe_data = elf(machine=0x3E00)[0], pe(machine=0x3E00)[0]
        (header,), (_, coff, _) = honest("lief.headers", elf_data), honest("lief.headers", pe_data)
        self.assertEqual((header.value["machine_name"], coff.value["machine_name"]), ("unknown", "unknown"))
        self.assert_refused([
            ("ELF 0x3E00 named x86_64", "lief.headers", elf_data, forged(header, machine_name="x86_64")),
            ("PE 0x3E00 named x86_64", "lief.headers", pe_data, forged(coff, machine_name="x86_64")),
        ])

    def test_optional_header_fields_past_its_declared_size_are_refused(self):
        """Each value below is what the bytes hold where the field would be; the declared size leaves it out."""
        cases = []
        for size in (1, 18, 19):
            data = pe(optional_size=size)[0]
            optional = honest("lief.headers", data)[2]
            start = optional.location.offset
            if size == 1:
                magic = {0x10B: "pe32", 0x20B: "pe32+"}.get(int.from_bytes(data[start:start + 2], "little"), "unknown")
                cases.append(("optional_magic at size 1", "lief.headers", data, forged(optional, optional_magic=magic)))
            else:
                entry = int.from_bytes(data[start + 16:start + 20], "little")
                cases.append((f"entry_rva at size {size}", "lief.headers", data, forged(optional, entry_rva=entry)))
        self.assert_refused(cases)


class HandlerTests(unittest.TestCase):
    def test_one_forged_value_fails_the_whole_operation(self):
        data, _ = elf()

        def forge_machine(operation, reply):
            reply["observations"][0]["value"]["machine_name"] = "aarch64"

        tool = lief_tool.make_tool(WorkerExecutor(g1_forge))
        with self.assertRaisesRegex(ContractError, REFUSED):
            tool.operations["lief.sections"].handler(data, {})
        with self.assertRaisesRegex(ContractError, REFUSED):
            lief_tool.make_tool(WorkerExecutor(forge_machine)).operations["lief.headers"].handler(data, {})

    def test_more_section_observations_than_max_sections_are_refused(self):
        """Every row is honest, but the worker ignored the request's max_sections: the host enforces it."""
        class Uncapped(WorkerExecutor):
            def run(self, operation, args, data, digest):
                return super().run(operation, {"max_sections": 64}, data, digest)

        for data, declared in ((elf()[0], 5), (pe()[0], 3)):
            handler = lief_tool.make_tool(Uncapped()).operations["lief.sections"].handler
            self.assertEqual(len(handler(data, {"max_sections": declared})), declared)
            for count in (1, declared - 1):
                with self.subTest(declared=declared, max_sections=count), \
                        self.assertRaisesRegex(ContractError, "over the cap"):
                    handler(data, {"max_sections": count})

    def test_the_old_unconfirmed_dummy_observations_are_refused(self):
        """Forged worker values must be refused by the host."""
        from tests.test_lief_tool import FakeExecutor, item, reply
        for data in (b"\x7fELF" + bytes(128), elf()[0]):
            for operation, value in (("lief.headers", {"format": "elf", "machine_name": "aarch64", "shnum": 4}),
                                     ("lief.sections", {"index": 2, "writable": True, "executable": True})):
                with self.subTest(operation=operation, size=len(data)), self.assertRaisesRegex(ContractError, REFUSED):
                    executor = FakeExecutor(reply(data, [item(**value)]))
                    lief_tool.make_tool(executor).operations[operation].handler(data, {})

    def test_g1_probe_end_to_end_leaves_no_supported_false_claim(self):
        data, _ = elf()
        ref = InputRef(sha256_hex(data), len(data), "sample.bin")

        def analyze(forge):
            tools = pipeline.TOOLS + (lief_tool.make_tool(WorkerExecutor(forge)),)
            analysis = pipeline.analyze_bytes(data, ref, tools=tools)
            result = next(r for r in analysis.results if r.role == "structural")
            judged = {v.finding_id: v.status for v in analysis.verdicts}
            return result, {f.claim_key: (f.value, judged[f.id]) for f in result.findings}

        result, claims = analyze(None)
        self.assertEqual(result.status, "ok")
        self.assertEqual(claims["sections.writable_executable_indices"], ([3], "supported"))

        result, claims = analyze(g1_forge)
        self.assertEqual(result.status, "error")
        self.assertIn("lief.sections: ContractError", result.errors)
        self.assertNotIn("lief.sections", {item.operation for item in result.evidence})
        self.assertNotIn("sections.writable_executable_indices", claims)
        self.assertEqual(claims["sections.writable_executable"], ([".rwx"], "supported"))
        self.assertEqual(claims["format.machine"], ("x86_64", "supported"))


if __name__ == "__main__":
    unittest.main()
