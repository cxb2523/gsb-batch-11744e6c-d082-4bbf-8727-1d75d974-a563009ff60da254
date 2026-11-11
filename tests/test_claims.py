import unittest
from unittest import mock

from reverseai import claims
from reverseai.contract import Location, Observation, ToolRef, make_evidence, make_finding

DATA = bytes(range(256)) * 4
STRUCTURE, STRINGS = ToolRef("structure", "0.1.0"), ToolRef("strings", "0.1.0")


def evidence(tool, operation, offset=0, **value):
    return make_evidence(DATA, tool, operation, Observation(Location(offset, 4), value))


def finding(claim_key, value, cited, role="structural", confidence=None):
    confidence = confidence or claims.RULES.get(claim_key, ("observed",))[0]
    return make_finding(role, "A claim.", claim_key, value, [item.id for item in cited], confidence)


class ClaimRuleTests(unittest.TestCase):
    def test_structural_claims_must_match_their_observations(self):
        pe = evidence(STRUCTURE, "structure.identify", format="pe")
        self.assertEqual(claims.check(finding("format.container", "pe", [pe]), [pe]), ())
        self.assertEqual(claims.check(finding("format.container", "elf", [pe]), [pe]), ("cited evidence does not yield the claimed value",))
        headers = evidence(STRUCTURE, "structure.headers", 8, machine_name="x86_64", number_of_sections=3)
        self.assertEqual(claims.check(finding("format.machine", "x86_64", [headers]), [headers]), ())
        self.assertEqual(claims.check(finding("format.section_count", 3, [headers]), [headers]), ())
        self.assertNotEqual(claims.check(finding("format.section_count", 4, [headers]), [headers]), ())

    def test_extended_numbering_never_supports_a_zero_section_count(self):
        extended = evidence(STRUCTURE, "structure.headers", 8, machine_name="x86_64", shnum=0, shoff=64)
        self.assertNotEqual(claims.check(finding("format.section_count", 0, [extended]), [extended]), ())
        empty = evidence(STRUCTURE, "structure.headers", 12, machine_name="x86_64", shnum=0, shoff=0)
        self.assertEqual(claims.check(finding("format.section_count", 0, [empty]), [empty]), ())

    def test_claims_may_only_cite_their_operation(self):
        headers = evidence(STRUCTURE, "structure.headers", format="pe", machine_name="x86_64")
        reasons = claims.check(finding("format.container", "pe", [headers]), [headers])
        self.assertEqual(reasons, ("format.container may only cite lief.headers, structure.identify evidence",))

    def test_disagreeing_citations_yield_nothing(self):
        a = evidence(STRUCTURE, "structure.identify", 0, format="pe")
        b = evidence(STRUCTURE, "structure.identify", 4, format="elf")
        self.assertNotEqual(claims.check(finding("format.container", "pe", [a, b]), [a, b]), ())

    def test_writable_executable_sections(self):
        rwx = evidence(STRUCTURE, "structure.sections", 0, name=".rwx", writable=True, executable=True)
        rx = evidence(STRUCTURE, "structure.sections", 4, name=".text", writable=False, executable=True)
        self.assertEqual(claims.check(finding("sections.writable_executable", [".rwx"], [rwx]), [rwx]), ())
        self.assertNotEqual(claims.check(finding("sections.writable_executable", [".rwx", ".text"], [rwx, rx]), [rwx, rx]), ())

    def test_capability_and_url_claims(self):
        inject = evidence(STRINGS, "strings.indicators", 0, rule="virtual_alloc_ex", category="process_injection", match="VirtualAllocEx")
        url = evidence(STRINGS, "strings.indicators", 4, rule="url", category="network", match="https://example.invalid/x")
        ok = finding("capability.process_injection", ["virtual_alloc_ex"], [inject], "capability")
        self.assertEqual(claims.check(ok, [inject]), ())
        wrong_category = finding("capability.persistence", ["virtual_alloc_ex"], [inject], "capability")
        self.assertNotEqual(claims.check(wrong_category, [inject]), ())
        self.assertEqual(claims.check(finding("strings.urls", ["https://example.invalid/x"], [url], "capability"), [url]), ())
        self.assertNotEqual(claims.check(finding("strings.urls", ["https://evil.invalid/"], [url], "capability"), [url]), ())

    def test_confidence_is_fixed_by_the_rule(self):
        rwx = evidence(STRUCTURE, "structure.sections", 0, name=".rwx", writable=True, executable=True)
        overstated = finding("sections.writable_executable", [".rwx"], [rwx], confidence="observed")
        self.assertEqual(claims.check(overstated, [rwx]), ("sections.writable_executable must be inferred",))

    def test_import_claims_name_exactly_the_cited_libraries_and_symbols(self):
        libc = evidence(STRUCTURE, "structure.imports", 0, kind="library", name="libc.so.6")
        libm = evidence(STRUCTURE, "structure.imports", 8, kind="library", name="libm.so.6")
        group = evidence(STRUCTURE, "structure.imports", 16, kind="symbols", library=None, names=["printf", "exit", "printf"])
        self.assertEqual(claims.check(finding("imports.libraries", ["libc.so.6", "libm.so.6"], [libc, libm]), [libc, libm]), ())
        self.assertNotEqual(claims.check(finding("imports.libraries", ["libc.so.6"], [libc, libm]), [libc, libm]), ())
        self.assertEqual(claims.check(finding("imports.symbols", ["exit", "printf"], [group]), [group]), ())
        self.assertNotEqual(claims.check(finding("imports.symbols", ["exit", "printf"], [group, libc]), [group, libc]), ())
        empty = evidence(STRUCTURE, "structure.imports", 24, kind="symbols", library=None, names=[])
        self.assertNotEqual(claims.check(finding("imports.symbols", [], [empty]), [empty]), ())
        for bad in ("printf", {"printf": 1}, 7, None, ["printf", 7]):
            odd = evidence(STRUCTURE, "structure.imports", 32, kind="symbols", library=None, names=bad)
            self.assertNotEqual(claims.check(finding("imports.symbols", ["printf"], [odd]), [odd]), ())
        lief = evidence(ToolRef("lief", "1.0.0-r2"), "lief.headers", 0, kind="library", name="libc.so.6")
        self.assertNotEqual(claims.check(finding("imports.libraries", ["libc.so.6"], [lief]), [lief]), ())

    def test_import_claims_keep_the_host_tools_name_bounds(self):
        # At most 32 names per group, each 1..128 printable characters.
        names = [f"f{index}" for index in range(32)]
        full = evidence(STRUCTURE, "structure.imports", 0, kind="symbols", library=None, names=names)
        self.assertEqual(claims.check(finding("imports.symbols", sorted(names), [full]), [full]), ())
        over = evidence(STRUCTURE, "structure.imports", 0, kind="symbols", library=None, names=names + ["f32"])
        self.assertNotEqual(claims.check(finding("imports.symbols", sorted(names + ["f32"]), [over]), [over]), ())
        self.assertEqual(claims.check(finding("imports.symbols", ["x" * 128], [ok := evidence(
            STRUCTURE, "structure.imports", 0, kind="symbols", library=None, names=["x" * 128])]), [ok]), ())
        for bad in ("x" * 129, "bad\nname", "tab\tname", "nul\x00", "del\x7f", ""):
            for kind, value in (("symbols", {"library": None, "names": [bad]}), ("library", {"name": bad})):
                odd = evidence(STRUCTURE, "structure.imports", 0, kind=kind, **value)
                key = "imports.symbols" if kind == "symbols" else "imports.libraries"
                self.assertNotEqual(claims.check(finding(key, [bad], [odd]), [odd]), (), (kind, bad))

    def test_signature_claims_name_exactly_the_matched_reviewed_rules(self):
        yarax = ToolRef("yarax", "1.21.0-r2")
        upx = evidence(yarax, "yarax.matches", 0, ruleset="m2_fixture_v1", rule="upx_packed", pattern="$a")
        upx_again = evidence(yarax, "yarax.matches", 8, ruleset="m2_fixture_v1", rule="upx_packed", pattern="$b")
        b64 = evidence(yarax, "yarax.matches", 4, ruleset="m2_fixture_v1", rule="base64_decode_api", pattern="$w")
        cited = [upx, upx_again, b64]
        self.assertEqual(claims.check(finding("signatures.rule_matches", ["base64_decode_api", "upx_packed"], cited), cited), ())
        self.assertNotEqual(claims.check(finding("signatures.rule_matches", ["upx_packed"], cited), cited), ())
        self.assertNotEqual(claims.check(finding("signatures.rule_matches", ["base64_decode_api", "upx_packed"], cited,
                                                 confidence="inferred"), cited), ())
        nameless = evidence(yarax, "yarax.matches", 12, ruleset="m2_fixture_v1", pattern="$a")
        self.assertNotEqual(claims.check(finding("signatures.rule_matches", ["upx_packed"], [upx, nameless]), [upx, nameless]), ())
        strings = evidence(STRINGS, "strings.indicators", 0, rule="url", match="http://x.invalid/")
        self.assertNotEqual(claims.check(finding("signatures.rule_matches", ["url"], [strings]), [strings]), ())

    def test_observations_without_the_field_do_not_count_against_the_claim(self):
        lief = ToolRef("lief", "1.0.0-r2")
        dos = evidence(lief, "lief.headers", 0, structure="dos", e_lfanew=64)
        coff = evidence(lief, "lief.headers", 64, structure="coff", format="pe", machine_name="x86_64")
        self.assertEqual(claims.check(finding("format.container", "pe", [dos, coff]), [dos, coff]), ())
        self.assertEqual(claims.check(finding("format.machine", "x86_64", [dos, coff]), [dos, coff]), ())

    def test_every_cited_operation_group_must_yield_the_value(self):
        lief = ToolRef("lief", "1.0.0")
        two_operations = ("observed", {
            "structure.identify": lambda obs: claims._one(o.get("format") for o in obs),
            "lief.headers": lambda obs: claims._one(o.get("format") for o in obs),
        })
        for wrong in ("structure.identify", "lief.headers"):
            with self.subTest(disagreeing=wrong), mock.patch.dict(claims.RULES, {"format.container": two_operations}):
                stdlib = evidence(STRUCTURE, "structure.identify", 0, format="elf" if wrong == "structure.identify" else "pe")
                worker = evidence(lief, "lief.headers", 4, format="elf" if wrong == "lief.headers" else "pe")
                self.assertEqual(claims.check(finding("format.container", "pe", [stdlib, worker]), [stdlib, worker]),
                                 ("cited evidence does not yield the claimed value",))

    def test_a_claim_may_cite_every_operation_its_rule_allows_if_they_agree(self):
        lief = ToolRef("lief", "1.0.0")
        two_operations = ("observed", {
            "structure.identify": lambda obs: claims._one(o.get("format") for o in obs),
            "lief.headers": lambda obs: claims._one(o.get("format") for o in obs),
        })
        stdlib = evidence(STRUCTURE, "structure.identify", 0, format="pe")
        agrees = evidence(lief, "lief.headers", 4, format="pe")
        disagrees = evidence(lief, "lief.headers", 8, format="elf")
        with mock.patch.dict(claims.RULES, {"format.container": two_operations}):
            self.assertEqual(claims.check(finding("format.container", "pe", [stdlib, agrees]), [stdlib, agrees]), ())
            self.assertEqual(claims.check(finding("format.container", "pe", [stdlib, disagrees]), [stdlib, disagrees]),
                             ("cited evidence does not yield the claimed value",))
            self.assertEqual(claims.check(finding("format.container", "pe", [stdlib, evidence(STRUCTURE, "structure.headers", 12, format="pe")]),
                                          [stdlib, evidence(STRUCTURE, "structure.headers", 12, format="pe")]),
                             ("format.container may only cite lief.headers, structure.identify evidence",))

    def test_lief_headers_support_format_claims_per_physical_header(self):
        lief = ToolRef("lief", "1.0.0-r2")
        dos = evidence(lief, "lief.headers", 0, structure="dos", e_lfanew=128)
        coff = evidence(lief, "lief.headers", 128, structure="coff", format="pe", machine_name="x86_64", number_of_sections=3)
        identify = evidence(STRUCTURE, "structure.identify", 4, format="pe")
        self.assertEqual(claims.check(finding("format.container", "pe", [identify, coff]), [identify, coff]), ())
        self.assertEqual(claims.check(finding("format.machine", "x86_64", [coff]), [coff]), ())
        self.assertEqual(claims.check(finding("format.section_count", 3, [coff]), [coff]), ())
        self.assertNotEqual(claims.check(finding("format.container", "pe", [dos]), [dos]), ())  # the DOS header carries no format
        self.assertNotEqual(claims.check(finding("format.container", "elf", [identify, coff]), [identify, coff]), ())

    def test_writable_executable_section_indices(self):
        lief = ToolRef("lief", "1.0.0-r2")
        rwx = evidence(lief, "lief.sections", 0, index=2, writable=True, executable=True)
        rx = evidence(lief, "lief.sections", 4, index=0, writable=False, executable=True)
        self.assertEqual(claims.check(finding("sections.writable_executable_indices", [2], [rwx]), [rwx]), ())
        self.assertNotEqual(claims.check(finding("sections.writable_executable_indices", [0, 2], [rwx, rx]), [rwx, rx]), ())
        self.assertNotEqual(claims.check(finding("sections.writable_executable", [".rwx"], [rwx]), [rwx]), ())
        self.assertEqual(claims.statement("sections.writable_executable_indices"), "Section indices that are both writable and executable")

    def test_unknown_claims_and_empty_citations_are_never_supported(self):
        pe = evidence(STRUCTURE, "structure.identify", format="pe")
        self.assertEqual(claims.check(finding("capability.ransomware", ["x"], [pe]), [pe]), ("no claim rule for this claim_key",))
        self.assertEqual(claims.check(finding("format.container", "pe", []), []), ("finding cites no evidence",))


if __name__ == "__main__":
    unittest.main()
