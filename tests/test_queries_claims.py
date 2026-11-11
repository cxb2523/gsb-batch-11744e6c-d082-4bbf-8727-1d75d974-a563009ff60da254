"""Query pages and single readings, verified on the host or derived from Ghidra."""

import unittest

from reverseai import claims
from reverseai.contract import (
    AnalysisResult, InputRef, Location, Observation, OperationSpec, ToolRef, ToolSpec, content_id, make_evidence,
    make_finding, sha256_hex,
)
from reverseai.review import review

DATA = b"MZ" + bytes(range(256)) * 3 + b"hello world\x00" + "wide".encode("utf-16-le") + b"\x00\x00" + bytes(64)
INPUT = InputRef(sha256_hex(DATA), len(DATA), "sample.bin")
STRUCTURE, STRINGS, GHIDRA = ToolRef("structure", "0.1.0"), ToolRef("strings", "0.1.0"), ToolRef("ghidra", "12.1.4-r7")
OPERATIONS = {STRUCTURE: ("structure.segments", "structure.entry", "structure.symbols", "structure.read_bytes"),
              STRINGS: ("strings.list", "strings.search"),
              GHIDRA: ("ghidra.functions", "ghidra.function", "ghidra.xrefs")}
HELLO = DATA.index(b"hello")
WIDE = DATA.index("wide".encode("utf-16-le"))


def tools(derived=True):
    def spec(ref):
        ops = {name: OperationSpec(name, {}, lambda data, args: [], derived=derived and ref is GHIDRA)
               for name in OPERATIONS[ref]}
        return ToolSpec(ref, ops)
    return {ref.name: spec(ref) for ref in OPERATIONS}


def observed(ref, operation, where, size=4, /, **value):
    return make_evidence(DATA, ref, operation, Observation(Location(where, size), value))


def judge(key, value, cited, confidence=None, registry=None):
    confidence = confidence or claims.RULES[key][0]
    finding = make_finding("code" if key.startswith("code.") else "structural", "A claim.", key, value,
                           [item.id for item in cited], confidence)
    result = AnalysisResult(content_id("tk", {"t": key}), finding.role, "ok", tuple(cited), (finding,))
    return review(DATA, INPUT, [result], registry or tools())[0].status


def segment(index, total=3, /, **change):
    row = dict(kind="segment", index=index, total=total, name="LOAD", offset=index * 64, filesz=64,
               address=0x400000 + index * 0x1000, memsz=64, readable=True, writable=False, executable=index == 0)
    row.update(change)
    return observed(STRUCTURE, "structure.segments", (64 + index * 56) % 800, 56, **row)


def text_row(operation, index, total, offset, encoding, text, truncated=False, length=None):
    width = 1 if encoding == "ascii" else 2
    return observed(STRINGS, operation, offset, length or len(text) * width, kind="string", index=index, total=total,
                    offset=offset, encoding=encoding, text=text, truncated=truncated)


class QueryClaimTests(unittest.TestCase):
    def test_a_page_is_contiguous_rows_of_one_total(self):
        rows = [segment(1), segment(2)]
        value = {"start": 1, "total": 3, "rows": [["LOAD", 64, 64, 0x401000, 64, True, False, False],
                                                   ["LOAD", 128, 64, 0x402000, 64, True, False, False]]}
        self.assertEqual(judge("segments.list", value, rows), "supported")
        self.assertEqual(judge("segments.list", value, rows[::-1]), "supported")  # cited order does not matter
        gap = [segment(0), segment(2)]
        gap_rows = [[r.observation[k] for k in ("name", "offset", "filesz", "address", "memsz", "readable", "writable",
                                                "executable")] for r in gap]
        # The claimed rows are the cited ones, so only the missing index 1 can reject them.
        self.assertEqual(judge("segments.list", {"start": 0, "total": 3, "rows": gap_rows}, gap), "unsupported")
        mixed = [segment(1), segment(2, total=4)]
        self.assertEqual(judge("segments.list", value, mixed), "unsupported")
        past = [segment(1, total=2), segment(2, total=2)]
        self.assertEqual(judge("segments.list", {**value, "total": 2}, past), "unsupported")
        for bad in ({"readable": 1}, {"offset": -1}, {"name": "a\nb"}, {"index": True}, {"extra": 0}):
            item = segment(0, **bad)
            row = {k: item.observation.get(k) for k in ("name", "offset", "filesz", "address", "memsz", "readable",
                                                        "writable", "executable")}
            self.assertEqual(judge("segments.list", {"start": 0, "total": 3, "rows": [list(row.values())]}, [item]),
                             "unsupported", bad)
        self.assertEqual(judge("segments.list", value, rows, confidence="inferred"), "unsupported")

    def test_single_readings(self):
        entry = observed(STRUCTURE, "structure.entry", 24, 8, kind="entry", address=0x401000, offset=None)
        self.assertEqual(judge("load.entry", {"address": 0x401000, "offset": None}, [entry]), "supported")
        twice = observed(STRUCTURE, "structure.entry", 32, 8, kind="entry", address=0x401000, offset=None)
        self.assertEqual(judge("load.entry", {"address": 0x401000, "offset": None}, [entry, twice]), "unsupported")
        odd = observed(STRUCTURE, "structure.entry", 24, 8, kind="entry", address="0x401000", offset=None)
        self.assertEqual(judge("load.entry", {"address": "0x401000", "offset": None}, [odd]), "unsupported")

    def test_read_bytes_must_be_exactly_the_cited_bytes(self):
        raw = DATA[10:26]
        good = observed(STRUCTURE, "structure.read_bytes", 10, 16, kind="bytes", offset=10, address=None, hex=raw.hex())
        self.assertEqual(judge("bytes.read", {"offset": 10, "address": None, "hex": raw.hex()}, [good]), "supported")
        lie = (raw[:-1] + b"\xff").hex()
        bad = observed(STRUCTURE, "structure.read_bytes", 10, 16, kind="bytes", offset=10, address=None, hex=lie)
        self.assertEqual(judge("bytes.read", {"offset": 10, "address": None, "hex": lie}, [bad]), "unsupported")
        short = observed(STRUCTURE, "structure.read_bytes", 10, 16, kind="bytes", offset=10, address=None,
                         hex=raw[:8].hex())
        self.assertEqual(judge("bytes.read", {"offset": 10, "address": None, "hex": raw[:8].hex()}, [short]),
                         "unsupported")
        for hex_text in ("ABCD", "abc", "zz", ""):
            item = observed(STRUCTURE, "structure.read_bytes", 10, 2, kind="bytes", offset=10, address=None, hex=hex_text)
            self.assertEqual(judge("bytes.read", {"offset": 10, "address": None, "hex": hex_text}, [item]),
                             "unsupported", hex_text)

    def test_string_rows_are_checked_against_their_bytes(self):
        ascii_row = text_row("strings.search", 0, 2, HELLO, "ascii", "hello world")
        wide_row = text_row("strings.search", 1, 2, WIDE, "utf-16le", "wide")
        value = {"start": 0, "total": 2, "rows": [[HELLO, "ascii", "hello world", False],
                                                   [WIDE, "utf-16le", "wide", False]]}
        self.assertEqual(judge("strings.matches", value, [ascii_row, wide_row]), "supported")
        lie = text_row("strings.search", 0, 1, HELLO, "ascii", "hellO world")
        self.assertEqual(judge("strings.matches", {"start": 0, "total": 1, "rows": [[HELLO, "ascii", "hellO world", False]]},
                               [lie]), "unsupported")
        cut = text_row("strings.list", 0, 1, HELLO, "ascii", "hello", truncated=True, length=11)
        self.assertEqual(judge("strings.listed", {"start": 0, "total": 1, "rows": [[HELLO, "ascii", "hello", True]]},
                               [cut]), "supported")  # a truncated row's text is a prefix: no whole-bytes check
        other_op = text_row("strings.list", 0, 2, HELLO, "ascii", "hello world")
        self.assertEqual(judge("strings.matches", {"start": 0, "total": 2, "rows": [[HELLO, "ascii", "hello world", False]]},
                               [other_op]), "unsupported")

    def test_symbol_pages(self):
        row = observed(STRUCTURE, "structure.symbols", 300, 4, kind="symbol", index=0, total=1, name="main",
                       address=0x401000, type="func", binding="global", defined=True)
        value = {"start": 0, "total": 1, "rows": [["main", 0x401000, "func", "global", True]]}
        self.assertEqual(judge("symbols.list", value, [row]), "supported")
        for change in ({"type": "function"}, {"binding": "GLOBAL"}, {"defined": "yes"}, {"name": ""}, {"name": "x" * 129}):
            item = observed(STRUCTURE, "structure.symbols", 300, 4, **{**row.observation, **change})
            rows = [[item.observation[k] for k in ("name", "address", "type", "binding", "defined")]]
            self.assertEqual(judge("symbols.list", {"start": 0, "total": 1, "rows": rows}, [item]), "unsupported", change)

    def test_ghidra_query_claims_are_derived(self):
        function = observed(GHIDRA, "ghidra.functions", 0, 32, kind="function_row", index=0, total=1, name="entry",
                            entry=0x1000, size=32)
        self.assertEqual(judge("code.function_list", {"start": 0, "total": 1, "rows": [["entry", 0x1000, 32]]},
                               [function]), "derived")
        target = observed(GHIDRA, "ghidra.function", 0, 32, kind="target", name="entry", entry=0x1000, size=32,
                          matches=1, callers_total=2, callees_total=1)
        info = {"name": "entry", "entry": 0x1000, "size": 32, "matches": 1, "callers_total": 2, "callees_total": 1}
        self.assertEqual(judge("code.function_info", info, [target]), "derived")
        self.assertEqual(judge("code.function_info", info, [target], registry=tools(derived=False)), "derived")
        callers = [observed(GHIDRA, "ghidra.function", 40, 5, kind="caller", at=0x1100, **{"from": 0x1080}, to=0x1000),
                   observed(GHIDRA, "ghidra.function", 60, 5, kind="caller", at=0x1200, **{"from": None}, to=0x1000)]
        self.assertEqual(judge("code.callers", {"to": 0x1000, "rows": [[0x1100, 0x1080], [0x1200, None]]}, callers),
                         "derived")
        split = callers[:1] + [observed(GHIDRA, "ghidra.function", 60, 5, kind="caller", at=0x1200, **{"from": None},
                                        to=0x2000)]
        self.assertEqual(judge("code.callers", {"to": 0x1000, "rows": [[0x1100, 0x1080], [0x1200, None]]}, split),
                         "unsupported")
        xref = observed(GHIDRA, "ghidra.xrefs", 40, 5, kind="xref", index=3, total=4, at=0x1100, **{"from": 0x1080},
                        to=0x2000, type="read")
        self.assertEqual(judge("code.xrefs", {"to": 0x2000, "start": 3, "total": 4, "rows": [[0x1100, 0x1080, "read"]]},
                               [xref]), "derived")
        wrong = observed(GHIDRA, "ghidra.xrefs", 40, 5, **{**xref.observation, "type": "flow"})
        self.assertEqual(judge("code.xrefs", {"to": 0x2000, "start": 3, "total": 4, "rows": [[0x1100, 0x1080, "flow"]]},
                               [wrong]), "unsupported")

    def test_an_instruction_page_spans_exactly_its_cited_bytes(self):
        rows = [[8, 1, "PUSH RBP"], [9, 3, "MOV RBP,RSP"]]
        page = dict(kind="instructions", entry=0x1000, start=2, total=9, rows=rows, truncated=False)
        good = observed(GHIDRA, "ghidra.function", 8, 4, **page)
        value = {k: page[k] for k in ("entry", "start", "total", "rows", "truncated")}
        self.assertEqual(judge("code.instructions", value, [good]), "derived")
        wide = observed(GHIDRA, "ghidra.function", 8, 16, **page)
        self.assertEqual(judge("code.instructions", value, [wide]), "unsupported")
        over = observed(GHIDRA, "ghidra.function", 8, 4, **{**page, "total": 2})
        self.assertEqual(judge("code.instructions", {**value, "total": 2}, [over]), "unsupported")

    def test_assembly_rows_must_end_inside_the_cited_anchor(self):
        # The reviewer itself checks rows against the cited location.
        rows = [[0, 1, "PUSH RBP"], [1, 3, "MOV RBP,RSP"]]
        listing = dict(kind="assembly", index=0, entry=0x1000, instructions=rows, truncated=False)
        value = {"entry": 0x1000, "instructions": rows, "truncated": False}
        inside = make_evidence(DATA, GHIDRA, "ghidra.analyze", Observation(Location(0, 4), listing))
        outside = make_evidence(DATA, GHIDRA, "ghidra.analyze", Observation(Location(0, 3), listing))
        registry = {"ghidra": ToolSpec(GHIDRA, {"ghidra.analyze": OperationSpec("ghidra.analyze", {}, lambda d, a: [],
                                                                                derived=True)})}
        self.assertEqual(judge("code.assembly", value, [inside], registry=registry), "derived")
        self.assertEqual(judge("code.assembly", value, [outside], registry=registry), "unsupported")

    def test_m3a_code_rules_refuse_malformed_readings_without_failing(self):
        registry = {"ghidra": ToolSpec(GHIDRA, {"ghidra.analyze": OperationSpec("ghidra.analyze", {}, lambda d, a: [],
                                                                                derived=True)})}
        cases = [("code.functions", ["x"], dict(kind="function", index=0, name="x", entry=1)),
                 ("code.functions", [None], dict(kind="function", index="0", name=None, entry=1, size=1)),
                 ("code.pseudocode", {"entry": 1, "text": None, "truncated": False},
                  dict(kind="pseudocode", index=0, entry=1, text=None, truncated=False)),
                 ("code.calls", [[1, None]], dict(kind="call", to=2, to_name=None, **{"from": 1})),
                 ("code.calls", [["a", "b"]], dict(kind="call", to=2, to_name="b", **{"from": "a"}))]
        for key, value, observation in cases:
            item = make_evidence(DATA, GHIDRA, "ghidra.analyze", Observation(Location(0, 4), observation))
            self.assertEqual(judge(key, value, [item], registry=registry), "unsupported", (key, observation))

    def test_every_query_claim_has_a_statement(self):
        for key in ("segments.list", "load.entry", "symbols.list", "bytes.read", "strings.listed", "strings.matches",
                    "code.function_list", "code.function_info", "code.instructions", "code.callers", "code.xrefs"):
            self.assertNotEqual(claims.statement(key), "No claim rule", key)
        self.assertEqual({k for k in claims.RULES if claims.RULES[k][0] == "observed"} & claims.DERIVED_CLAIMS, set())


if __name__ == "__main__":
    unittest.main()


class ReviewerHardeningTests(unittest.TestCase):
    """Malformed rows refused without failing, offsets bound, queries kept apart."""

    def test_a_non_ascii_text_row_is_refused_not_raised(self):
        for operation, key in (("strings.list", "strings.listed"), ("strings.search", "strings.matches")):
            for encoding in ("ascii", "utf-16le"):
                row = text_row(operation, 0, 1, HELLO, encoding, "caf\u00e9", length=11)
                value = {"start": 0, "total": 1, "rows": [[HELLO, encoding, "caf\u00e9", False]]}
                self.assertEqual(judge(key, value, [row]), "unsupported", (key, encoding))

    def test_bytes_and_string_rows_must_sit_at_their_cited_offset(self):
        raw = DATA[10:26]
        moved = observed(STRUCTURE, "structure.read_bytes", 10, 16, kind="bytes", offset=999999, address=None, hex=raw.hex())
        self.assertEqual(judge("bytes.read", {"offset": 999999, "address": None, "hex": raw.hex()}, [moved]), "unsupported")
        row = observed(STRINGS, "strings.search", HELLO, 11, kind="string", index=0, total=1, offset=999999,
                       encoding="ascii", text="hello world", truncated=False)
        value = {"start": 0, "total": 1, "rows": [[999999, "ascii", "hello world", False]]}
        self.assertEqual(judge("strings.matches", value, [row]), "unsupported")
        cut = observed(STRINGS, "strings.list", HELLO, 11, kind="string", index=0, total=1, offset=HELLO + 1,
                       encoding="ascii", text="hello", truncated=True)
        self.assertEqual(judge("strings.listed", {"start": 0, "total": 1, "rows": [[HELLO + 1, "ascii", "hello", True]]},
                               [cut]), "unsupported")

    def test_different_queries_reviewed_together_do_not_contradict(self):
        def result(task, key, value, cited):
            finding = make_finding("structural", "A claim.", key, value, [item.id for item in cited], "observed")
            return finding, AnalysisResult(content_id("tk", {"t": task}), "structural", "ok", tuple(cited), (finding,))

        first = text_row("strings.search", 0, 1, HELLO, "ascii", "hello world")
        second = text_row("strings.search", 0, 1, WIDE, "utf-16le", "wide")
        a, ra = result("alpha", "strings.matches", {"start": 0, "total": 1, "rows": [[HELLO, "ascii", "hello world", False]]},
                       [first])
        b, rb = result("beta", "strings.matches", {"start": 0, "total": 1, "rows": [[WIDE, "utf-16le", "wide", False]]},
                       [second])
        reads = []
        for task, start in (("read-0", 0), ("read-6", 6)):
            raw = DATA[start:start + 8]
            item = observed(STRUCTURE, "structure.read_bytes", start, 8, kind="bytes", offset=start, address=None,
                            hex=raw.hex())
            reads.append(result(task, "bytes.read", {"offset": start, "address": None, "hex": raw.hex()}, [item]))
        judged = {v.finding_id: v.status for v in review(DATA, INPUT, [ra, rb, reads[0][1], reads[1][1]], tools())}
        self.assertEqual({judged[f.id] for f in (a, b, reads[0][0], reads[1][0])}, {"supported"})
        # Within one task, two readings of one index still contradict (PageReviewTests).


class PageReviewTests(unittest.TestCase):
    """Pages of one verified list are compatible; a different total or row at one index contradicts."""

    def verdicts(self, pages):
        findings, evidence = [], []
        for rows in pages:
            value = {"start": rows[0].observation["index"], "total": rows[0].observation["total"],
                     "rows": [[r.observation[k] for k in ("name", "offset", "filesz", "address", "memsz", "readable",
                                                         "writable", "executable")] for r in rows]}
            findings.append(make_finding("structural", "Segments.", "segments.list", value, [r.id for r in rows], "observed"))
            evidence.extend(rows)
        result = AnalysisResult(content_id("tk", {"t": "pages"}), "structural", "ok", tuple({item.id: item for item in evidence}.values()),
                                tuple(findings))
        judged = {v.finding_id: v.status for v in review(DATA, INPUT, [result], tools())}
        return [judged[f.id] for f in findings]

    def test_contiguous_chunks_of_one_list_are_all_supported(self):
        rows = [segment(i, 130) for i in range(130)]
        self.assertEqual(self.verdicts([rows[:64], rows[64:128], rows[128:]]), ["supported"] * 3)
        self.assertEqual(self.verdicts([rows[:64], rows[10:20]]), ["supported"] * 2)  # overlapping, same rows

    def test_a_different_row_or_total_contradicts(self):
        first = [segment(0, 3), segment(1, 3)]
        other = [segment(1, 3, name="TEXT")]
        self.assertEqual(self.verdicts([first, other]), ["contradicted"] * 2)
        longer = [segment(2, 4)]
        self.assertEqual(self.verdicts([first, longer]), ["contradicted"] * 2)
