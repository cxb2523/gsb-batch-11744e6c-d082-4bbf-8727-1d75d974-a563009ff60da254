"""Prepared export oracles are declared by inert ELF, PE and Mach-O builders."""

import copy
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from reverseai import ghidra_args, ghidra_cache
from reverseai import pipeline, report
from reverseai import cli, mcp_tools
from reverseai.contract import ContractError, Location, Observation, sha256_hex
from reverseai.tools import ghidra_verify, ghidra_tool
from tests.fixtures_code import elf_refs, pe_refs, macho_refs
from tests.test_contained import ghidra_lock


def record(value, offset, length):
    return Observation(Location(offset, length), value)


def function_row(function, index=0, info=False):
    value = {"kind": "function_info" if info else "function_export", "name": function["name"] or "unnamed",
             "entry": function["entry"], "size": function["size"], "signature": "int f(void)",
             "signature_truncated": False, "library_hint": None}
    if info:
        value.update(matches=1, totals=dict.fromkeys(("assembly", "callees", "callers", "references", "strings"), 0),
                     pseudocode_status="not_requested")
    else:
        value["index"] = index
    return record(value, function["offset"], function["size"])


def header(data, part, *, scope="program", entry=None, start=0, total=0, count=0, status="ok"):
    return record({"kind": "export_page", "scope": scope, "part": part, "entry": entry, "status": status,
                   "start": start, "total": total, "count": count,
                   "next_start": start + count if start + count < total else None}, 0, min(64, len(data)))


def program(data, layout, part="functions"):
    functions = {f["entry"]: f for f in layout["functions"]}
    rows = []
    if part == "functions":
        rows = [function_row(f, i) for i, f in enumerate(layout["functions"])]
    if part in ("calls", "references"):
        source = layout["calls"] if part == "calls" else layout["refs"]
        for i, row in enumerate(source):
            value = {"kind": "call_export" if part == "calls" else "reference_export", "index": i,
                     "from": row["from"], "from_size": functions[row["from"]]["size"], "at": row["address"],
                     "to": row["to"], "to_name": row.get("to_name") or ""}
            if part == "references":
                value["type"] = row["type"]
            rows.append(record(value, row["offset"], row["length"]))
    if part == "strings":
        for i, row in enumerate(layout["strings"]):
            reference = next(r for r in layout["refs"] if r["to"] == row["address"])
            value = {"kind": "string_export", "index": i, "from": reference["from"],
                     "from_size": functions[reference["from"]]["size"], "at": reference["address"],
                     "instruction_length": reference["length"], "address": row["address"],
                     "encoding": row["encoding"], "text": row["text"], "truncated": row["truncated"]}
            rows.append(record(value, row["offset"], row["length"]))
    return (header(data, part, total=len(rows), count=len(rows)), *rows)


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.data, self.layout = elf_refs()

    def admit(self, items, args=None, operation="ghidra.export_program", data=None):
        return ghidra_verify.verify(self.data if data is None else data, items, args or {}, operation=operation)

    def test_all_program_parts_match_the_declared_three_format_anchors(self):
        for builder in (elf_refs, pe_refs, macho_refs):
            data, layout = builder()
            for part in ("functions", "calls", "references", "strings"):
                with self.subTest(builder=builder.__name__, part=part):
                    items = program(data, layout, part)
                    got = self.admit(items, {"part": part}, data=data)
                    self.assertEqual(got[:len(items)], items)
                    if part == "strings":
                        self.assertEqual(len(got), 1 + 2 * len(layout["strings"]))
                        for anchor, reference in zip(got[len(items):], layout["refs"][:2]):
                            self.assertEqual(anchor.location, Location(reference["offset"], reference["length"]))
                            self.assertEqual(anchor.value["kind"], "string_reference_anchor")
                    else:
                        self.assertEqual(got, items)

    def test_missing_and_past_end_pages_keep_explicit_metadata(self):
        empty = (header(self.data, "functions", start=5, total=5),)
        self.assertEqual(self.admit(empty, {"start": 100}), empty)
        failed = (header(self.data, "info", scope="function", status="not_found"),)
        self.assertEqual(self.admit(failed, operation="ghidra.export_function"), failed)
        malformed = copy.deepcopy(failed)
        malformed[0].value["count"] = True
        with self.assertRaises(ContractError):
            self.admit(malformed, operation="ghidra.export_function")

    def test_info_is_one_manifest_and_does_not_request_decompilation(self):
        target = self.layout["functions"][0]
        items = (header(self.data, "info", scope="function", entry=target["entry"], total=1, count=1), function_row(target, info=True))
        self.assertEqual(self.admit(items, {"entry": target["entry"]}, "ghidra.export_function"), items)
        for field, value in (("signature", None), ("library_hint", "libc"), ("matches", True)):
            bad = copy.deepcopy(items)
            bad[1].value[field] = value
            if field == "signature":
                bad[1].value["signature_truncated"] = True
            with self.subTest(field=field), self.assertRaises(ContractError):
                self.admit(bad, {"entry": target["entry"]}, "ghidra.export_function")

    def test_header_and_final_row_mutants_refuse_the_whole_page(self):
        baseline = program(self.data, self.layout)
        changes = ((0, "start", 1), (0, "total", True), (0, "count", 4), (0, "next_start", 3),
                   (0, "scope", "function"), (0, "entry", 10), (0, "part", "calls"),
                   (-1, "index", 3), (-1, "entry", 0), (-1, "size", True),
                   (-1, "kind", "call_export"), (-1, "analysis_id", "0" * 64))
        for row, key, value in changes:
            bad = copy.deepcopy(baseline)
            bad[row].value[key] = value
            with self.subTest(row=row, key=key), self.assertRaises(ContractError):
                self.admit(bad)

    def test_a_real_string_elsewhere_is_not_a_valid_reference_instruction(self):
        baseline = program(self.data, self.layout, "strings")
        for key, value in (("at", 0), ("from", 0), ("from_size", 1), ("instruction_length", 17),
                           ("text", "different"), ("address", self.layout["data"]["address"] + 1),
                           ("truncated", True), ("encoding", "ascii")):
            bad = copy.deepcopy(baseline)
            bad[-1].value[key] = value
            with self.subTest(key=key), self.assertRaises(ContractError):
                self.admit(bad, {"part": "strings"})

    def pseudocode(self, text, start, maximum):
        target = self.layout["functions"][0]
        shown = text[start:start + maximum]
        meta = header(self.data, "pseudocode", scope="function", entry=target["entry"],
                      start=min(start, len(text)), total=len(text), count=len(shown))
        value = {"kind": "pseudocode_page", "entry": target["entry"], "size": target["size"],
                 "text_sha256": hashlib.sha256(text.encode()).hexdigest(), "start": min(start, len(text)),
                 "total": len(text), "text": shown, "next_start": meta.value["next_start"], "status": "ok"}
        return (meta, record(value, target["offset"], target["size"]))

    def test_text_cursors_use_scalars_and_preserve_text_past_the_old_cut(self):
        text = ("x" * 65535) + "😀" + ("z" * 100)
        items = self.pseudocode(text, 65534, 64)
        args = {"entry": self.layout["entry"], "text_start": 65534, "max_chars": 64}
        self.assertEqual(self.admit(items, args, "ghidra.pseudocode"), items)
        self.assertEqual(items[1].value["text"][1], "😀")
        self.assertEqual(items[0].value["next_start"], 65598)
        self.assertEqual(items[1].value["total"], len(text))
        end = self.pseudocode(text, len(text) + 1, 64)
        self.assertEqual(self.admit(end, dict(args, text_start=len(text) + 1), "ghidra.pseudocode"), end)

    def test_complete_text_hash_failure_and_invalid_characters_are_refused(self):
        args = {"entry": self.layout["entry"]}
        for key, value in (("text_sha256", "0" * 64), ("text", "\x1b"), ("start", True), ("size", 0)):
            items = copy.deepcopy(self.pseudocode("return 1;", 0, 1024))
            items[-1].value[key] = value
            with self.subTest(key=key), self.assertRaises(ContractError):
                self.admit(items, args, "ghidra.pseudocode")

    def test_forged_pseudocode_reply_refuses_noninteger_next_cursor(self):
        from reverseai.contract import parse_worker_reply
        args = {"entry": self.layout["entry"]}
        baseline = self.pseudocode("ab", 0, 1)
        self.assertEqual(self.admit(baseline, args, "ghidra.pseudocode"), baseline)
        for invalid in (True, 1.0):
            items = copy.deepcopy(baseline)
            items[-1].value["next_start"] = invalid
            raw = json.dumps({"protocol": "reverseai.worker/1", "status": "ok",
                              "snapshot_sha256": sha256_hex(self.data),
                              "observations": [{"location": {"offset": o.location.offset, "length": o.location.length},
                                                "value": o.value} for o in items]}).encode()
            with self.subTest(cursor=invalid), self.assertRaises(ContractError):
                decoded = parse_worker_reply(raw, input_sha256=sha256_hex(self.data), max_observations=129)
                self.admit(decoded, args, "ghidra.pseudocode")

    def test_independent_pseudocode_rule_refuses_noninteger_next_cursor(self):
        from reverseai import export_claims
        baseline = [{**o.value, "analysis_id": "a" * 64} for o in self.pseudocode("ab", 0, 1)]
        self.assertIsNotNone(export_claims.pseudocode(baseline))
        for invalid in (True, 1.0):
            forged = copy.deepcopy(baseline)
            forged[-1]["next_start"] = invalid
            with self.subTest(cursor=invalid):
                self.assertIsNone(export_claims.pseudocode(forged))

    def test_function_parts_are_independent_bounded_pages(self):
        for part in ("callees", "callers", "references", "strings", "assembly"):
            target = self.layout["functions"][1 if part == "callers" else 2 if part == "callees" else -1]
            if part == "assembly":
                rows = [record({"kind": "instruction_export", "index": i, "from": target["entry"], "from_size": target["size"],
                                "at": target["entry"] + delta, "length": length, "text": "derived instruction"},
                               target["offset"] + delta, length) for i, (delta, length) in enumerate(target["instructions"])]
            else:
                source = program(self.data, self.layout, "calls" if part in ("callees", "callers") else part)[1:]
                rows = [copy.deepcopy(row) for row in source if row.value["to" if part == "callers" else "from"] == target["entry"]]
                for i, row in enumerate(rows):
                    row.value["index"] = i
            items = (header(self.data, part, scope="function", entry=target["entry"], total=len(rows), count=len(rows)), *rows)
            with self.subTest(part=part):
                admitted = self.admit(items, {"part": part, "entry": target["entry"]}, "ghidra.export_function")
                self.assertEqual(admitted[:len(items)], items)

    def test_export_argument_limits_and_unused_arguments_fail_closed(self):
        from reverseai import queries
        allowed = (("export_program", {"start": 1048575, "limit": 128}),
                   ("export_function", {"part": "assembly", "entry": 2**64 - 1, "start": 1048575, "limit": 128}),
                   ("procedure_pseudo_code", {"mode": "paged", "text_start": 1048576, "max_chars": 2048}))
        for name, args in allowed:
            queries.resolve(name, args)
            for key, value in args.items():
                if type(value) is int:
                    for invalid in (True, -1, str(value), value + 1):
                        with self.subTest(name=name, key=key, invalid=invalid), self.assertRaises(ContractError):
                            queries.resolve(name, dict(args, **{key: invalid}))
        for name, args in (("export_function", {"part": "info", "limit": 1}),
                           ("export_function", {"part": "pseudocode", "start": 1}),
                           ("export_function", {"part": "assembly", "text_start": 1}),
                           ("export_function", {"select": "entry", "name": "ignored"}),
                           ("procedure_pseudo_code", {"text_start": 1}),
                           ("export_program", {"part": "all"}), ("export_program", {"cache": "path"})):
            with self.subTest(name=name, args=args), self.assertRaises(ContractError):
                queries.resolve(name, args)


@unittest.skipIf(ghidra_cache.fcntl is None, "prepared tool requires POSIX cache")
class PreparedToolTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = ghidra_cache.CacheStore(Path(self.temp.name).resolve() / "cache")
        self.data, self.layout = elf_refs()
        self.calls = []
        owner = self
        class Executor:
            lock = ghidra_lock()
            def prepare(self, data, digest, sink):
                owner.calls.append(("prepare", digest))
                sink.write(b"opaque project")
            def run(self, operation, args, data, digest, *, project=None):
                owner.calls.append((operation, args, project.analysis_id))
                items = getattr(owner, "reply_items", None)
                if items is None:
                    items = program(data, owner.layout, args.get("part", "functions"))
                return json.dumps({"protocol": "reverseai.worker/1", "status": "ok", "snapshot_sha256": digest,
                                   "observations": [{"location": {"offset": o.location.offset, "length": o.location.length},
                                                     "value": o.value} for o in items]}).encode()
        self.executor = Executor()

    def test_miss_is_actionable_and_preparation_reuses_before_export(self):
        tool = ghidra_tool.make_tool(self.executor, store=self.store)
        handler = tool.operations["ghidra.export_program"].handler
        with self.assertRaisesRegex(ghidra_cache.CacheError, "^" + ghidra_cache.MISSING + "$"):
            handler(self.data, {})
        first = ghidra_tool.prepare(self.data, executor=self.executor, store=self.store)
        second = ghidra_tool.prepare(self.data, executor=self.executor, store=self.store)
        self.assertEqual((first["state"], second["state"]), ("created", "reused"))
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(set(first), {"schema", "input", "analysis_id", "state", "runtime", "cache_format", "artifact_size", "elapsed_seconds"})
        got = handler(self.data, {})
        self.assertEqual(len(got), 1 + len(self.layout["functions"]))
        self.assertTrue(all(o.value["analysis_id"] == first["analysis_id"] for o in got))
        self.assertEqual(self.calls[-1][0], "ghidra.export_program")

    def test_legacy_query_after_prepare_receives_the_prepared_project(self):
        receipt = ghidra_tool.prepare(self.data, executor=self.executor, store=self.store)
        projects = []
        def run(operation, args, data, digest, *, project=None):
            self.assertEqual(operation, "ghidra.functions")
            projects.append(project)
            return json.dumps({"protocol": "reverseai.worker/1", "status": "ok",
                               "snapshot_sha256": digest, "observations": []}).encode()
        self.executor.run = run
        tool = ghidra_tool.make_tool(self.executor, store=self.store)
        self.assertEqual(tool.operations["ghidra.functions"].handler(self.data, {"query": "absent"}), ())
        self.assertEqual(len(projects), 1)
        self.assertIsNotNone(projects[0])
        self.assertEqual(projects[0].analysis_id, receipt["analysis_id"])
        self.assertEqual(projects[0].manifest["input_sha256"], sha256_hex(self.data))
        self.assertIsNone(projects[0].fd)

    def test_real_gateway_reviewer_and_report_keep_false_semantics_derived(self):
        from reverseai.contract import InputRef
        ghidra_tool.prepare(self.data, executor=self.executor, store=self.store)
        tool = ghidra_tool.make_tool(self.executor, store=self.store)
        ref = InputRef(sha256_hex(self.data), len(self.data), "inert fixture")
        analysis = pipeline.query_bytes(self.data, ref, "export_program", {}, tools=(tool,))
        self.assertEqual(analysis.results[0].status, "ok")
        self.assertEqual({verdict.status for verdict in analysis.verdicts}, {"derived"})
        value = report.to_dict(analysis)
        findings = value["results"][0]["findings"]
        self.assertEqual({f["claim_key"] for f in findings}, {"code.export_page", "code.export_functions"})
        rows = next(f["value"]["rows"] for f in findings if f["claim_key"] == "code.export_functions")
        self.assertEqual([r["entry"] for r in rows], [f["entry"] for f in self.layout["functions"]])
        self.assertTrue(all(r["signature"] == "int f(void)" for r in rows))
        markdown = report.to_markdown(analysis)
        self.assertIn("rows 0..4 of 5", markdown)
        self.assertIn("Exported functions (derived)", markdown)
        self.assertIn("inert fixture", markdown)

    def test_gateway_miss_keeps_only_the_fixed_actionable_message(self):
        from reverseai.contract import InputRef
        tool = ghidra_tool.make_tool(self.executor, store=self.store)
        ref = InputRef(sha256_hex(self.data), len(self.data), "inert")
        analysis = pipeline.query_bytes(self.data, ref, "export_program", {}, tools=(tool,))
        self.assertEqual(analysis.results[0].status, "error")
        self.assertEqual(analysis.results[0].evidence, ())
        self.assertEqual(analysis.results[0].errors, ("ghidra.export_program: " + ghidra_cache.MISSING,))

    def test_referenced_strings_need_both_citations_in_the_independent_review(self):
        from dataclasses import replace
        from reverseai import review
        from reverseai.contract import InputRef, make_finding
        ghidra_tool.prepare(self.data, executor=self.executor, store=self.store)
        tool = ghidra_tool.make_tool(self.executor, store=self.store)
        ref = InputRef(sha256_hex(self.data), len(self.data), "inert")
        analysis = pipeline.query_bytes(self.data, ref, "export_program", {"part": "strings"}, tools=(tool,))
        self.assertEqual({v.status for v in analysis.verdicts}, {"derived"})
        result = analysis.results[0]
        finding = next(f for f in result.findings if f.claim_key == "code.export_strings")
        anchors = {e.id for e in result.evidence if e.observation["kind"] == "string_reference_anchor"}
        self.assertEqual(len(anchors), 2)
        self.assertTrue(anchors.issubset(set(finding.evidence_ids)))
        forged = make_finding(result.role, finding.claim, finding.claim_key, finding.value,
                              [i for i in finding.evidence_ids if i not in anchors], "inferred")
        verdicts = review.review(self.data, ref, (replace(result, findings=(forged,)),), {"ghidra": tool})
        self.assertEqual([v.status for v in verdicts], ["unsupported"])

    def test_cli_prepare_and_missing_export_have_small_path_free_results(self):
        sample = Path(self.temp.name) / "inert.elf"
        sample.write_bytes(self.data)
        tool = ghidra_tool.make_tool(self.executor, store=self.store)
        out, err = io.StringIO(), io.StringIO()
        with patch.object(ghidra_tool, "available", return_value=True), patch.object(ghidra_tool, "make_tool", return_value=tool), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as caught:
            cli.main(["query", str(sample), "--query", "export_program", "--with-ghidra", "--out", str(Path(self.temp.name) / "missing")])
        self.assertEqual(caught.exception.code, 1)
        self.assertIn(ghidra_cache.MISSING, err.getvalue())
        self.assertNotIn(self.temp.name, err.getvalue())
        out, err = io.StringIO(), io.StringIO()
        with patch.object(ghidra_tool, "DockerExecutor", return_value=self.executor), \
                patch.object(ghidra_tool.ghidra_cache, "CacheStore", return_value=self.store), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(cli.main(["prepare", str(sample), "--with-ghidra", "--json"]), 0)
        receipt = json.loads(out.getvalue())
        self.assertEqual(receipt["state"], "created")
        self.assertEqual(receipt["input"], {"sha256": sha256_hex(self.data), "size": len(self.data)})
        self.assertLess(len(out.getvalue().encode()), 4096)
        self.assertNotIn(self.temp.name, out.getvalue() + err.getvalue())

    def test_mcp_prepare_argv_is_confined_and_never_accepts_output_or_cache_paths(self):
        sample = Path(self.temp.name) / "inert.elf"
        sample.write_bytes(self.data)
        enabled = frozenset({"ghidra"})
        argv = mcp_tools.command("prepare_file", {"file": sample.name}, root=self.temp.name, out="unused", enabled=enabled)
        self.assertEqual(argv, ["prepare", str(sample.resolve()), "--with-ghidra", "--json"])
        for extra in ({"out": "/tmp"}, {"cache": "anything"}, {"view": "full"}):
            with self.subTest(extra=extra), self.assertRaises(mcp_tools.ToolInputError):
                mcp_tools.command("prepare_file", {"file": sample.name, **extra}, root=self.temp.name, out="unused", enabled=enabled)
        full = mcp_tools.command("export_program", {"file": sample.name, "view": "full"}, root=self.temp.name, out="unused", enabled=enabled)
        self.assertNotIn("view=full", full)

    def test_a_malformed_final_row_leaves_no_partial_gateway_evidence(self):
        from reverseai.contract import InputRef
        ghidra_tool.prepare(self.data, executor=self.executor, store=self.store)
        self.reply_items = copy.deepcopy(program(self.data, self.layout))
        self.reply_items[-1].value["entry"] = 0
        tool = ghidra_tool.make_tool(self.executor, store=self.store)
        analysis = pipeline.query_bytes(self.data, InputRef(sha256_hex(self.data), len(self.data), "inert"),
                                        "export_program", {}, tools=(tool,))
        self.assertEqual(analysis.results[0].status, "error")
        self.assertEqual(analysis.results[0].evidence, ())
        self.assertEqual(analysis.results[0].findings, ())

    def test_128_string_rows_synthesize_257_observations_and_chunk_citations(self):
        from tests.fixtures_structure import elf
        from reverseai.contract import InputRef
        data, layout = elf(entry=0x1000, sections=((b".text", 1, 6, 8192),))
        import struct
        data = bytearray(data)
        struct.pack_into("<Q", data, layout["shoff"] + 64 + 16, 0x1000)
        raw = layout["offsets"][0]
        data[raw + 512:raw + 515] = b"ok\0"
        self.data = bytes(data)
        rows = [record({"kind": "string_export", "index": i, "from": 0x1000, "from_size": 8192,
                        "at": 0x1000 + i, "instruction_length": 1, "address": 0x1200, "encoding": "ascii",
                        "text": "ok", "truncated": False}, raw + 512, 2) for i in range(128)]
        self.reply_items = (header(self.data, "strings", total=128, count=128), *rows)
        ghidra_tool.prepare(self.data, executor=self.executor, store=self.store)
        tool = ghidra_tool.make_tool(self.executor, store=self.store)
        ref = InputRef(sha256_hex(self.data), len(self.data), "inert")
        analysis = pipeline.query_bytes(self.data, ref, "export_program", {"part": "strings", "limit": 128}, tools=(tool,))
        result = analysis.results[0]
        self.assertEqual(result.status, "ok")
        self.assertEqual(len(result.evidence), 257)
        self.assertEqual({v.status for v in analysis.verdicts}, {"derived"})
        pages = [f for f in result.findings if f.claim_key == "code.export_strings"]
        self.assertEqual([len(f.value["rows"]) for f in pages], [31, 31, 31, 31, 4])
        self.assertTrue(all(len(f.evidence_ids) <= 64 for f in pages))


if __name__ == "__main__":
    unittest.main()
