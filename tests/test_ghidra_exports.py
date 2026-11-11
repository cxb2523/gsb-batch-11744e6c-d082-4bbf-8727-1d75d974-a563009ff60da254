"""Prepared worker pages from declared fixture bytes; no JVM, Docker or sample execution."""

import copy
import hashlib
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from tests.fixtures_code import elf_refs, pe_refs, macho_refs
from tests.test_ghidra_worker_logic import refs_query, worker


def prepared(root, data, layout):
    q = refs_query(data, layout, names=[f["name"] or f"FUN_{f['entry']:x}" for f in layout["functions"]])
    raw, tables = root / "raw", root / "cache" / "tables"
    raw.mkdir()
    tables.mkdir(parents=True)
    (root / "cache" / "project").mkdir()
    (raw / "header.json").write_text(json.dumps({k: v for k, v in dict(q, complete=True).items()
                                                 if k in ("format", "options_off", "blocks", "complete")}))
    functions, calls, refs = [], [], []
    for source, declared in zip(q["functions"], layout["functions"]):
        functions.append(dict(source, signature=f"int {source['name']}(void)", assembly_total=len(declared["instructions"])))
        calls.extend(dict(row, **{"from": source["entry"]}) for row in source["calls"])
        refs.extend(dict(row, **{"from": source["entry"]}) for row in source.get("refs", []))
    # Producer order is function, instruction, target, contract reference type.
    for name, rows in (("functions", functions), ("calls", calls), ("references", refs)):
        if name != "functions":
            rows.sort(key=lambda r: (r["from"], r["address"], r["to"], worker.ref_type(r) if name == "references" else ""))
        (raw / (name + ".jsonl")).write_text("".join(json.dumps(row) + "\n" for row in rows))
    metadata = worker.build_tables(data, raw, tables)
    return root / "cache", q, metadata


def arguments(operation, **changes):
    return worker.parse_request([operation, json.dumps(changes)])[1]


class TablesAndPagesTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="reverseai-export-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.data, self.layout = elf_refs()
        self.cache, self.query, self.metadata = prepared(self.root, self.data, self.layout)

    def run_page(self, operation="ghidra.export_program", **kwargs):
        return worker.export_rows(operation, arguments(operation, **kwargs), self.data, root=self.cache)

    def test_program_pages_cover_declared_rows_exactly_once_with_no_jvm(self):
        expected = {"functions": len(self.layout["functions"]), "calls": len(self.layout["calls"]),
                    "references": len(self.layout["refs"]), "strings": len(self.layout["strings"])}
        for part, total in expected.items():
            with self.subTest(part=part), patch.object(worker, "run_cached", side_effect=AssertionError("no JVM")):
                seen, start = [], 0
                while True:
                    result = self.run_page(part=part, start=start, limit=2)
                    meta, rows = result[0]["value"], result[1:]
                    self.assertEqual((meta["total"], meta["start"], meta["count"]), (total, start, len(rows)))
                    self.assertEqual(result[0]["location"], {"offset": 0, "length": 64})
                    seen.extend(rows)
                    if meta["next_start"] is None:
                        break
                    start = meta["next_start"]
                self.assertEqual([r["value"]["index"] for r in seen], list(range(total)))
                self.assertTrue(all("analysis_id" not in r["value"] for r in result))
                if part == "functions":
                    self.assertEqual([(r["value"]["entry"], r["value"]["size"]) for r in seen],
                                     [(f["entry"], f["size"]) for f in self.layout["functions"]])
                elif part == "calls":
                    self.assertEqual([(r["value"]["from"], r["value"]["at"], r["value"]["to"]) for r in seen],
                                     [(c["from"], c["address"], c["to"]) for c in self.layout["calls"]])

    def test_info_and_filtered_pages_agree_with_declared_edges(self):
        function = self.layout["functions"][2]
        entry = function["entry"]
        info = self.run_page("ghidra.export_function", entry=entry)[1]["value"]
        self.assertEqual(info["totals"]["assembly"], len(function["instructions"]))
        self.assertEqual(info["totals"]["callees"], sum(c["from"] == entry for c in self.layout["calls"]))
        self.assertEqual(info["totals"]["callers"], sum(c["to"] == entry for c in self.layout["calls"]))
        for part in ("callees", "callers", "references", "strings"):
            result = self.run_page("ghidra.export_function", entry=entry, part=part)
            self.assertEqual(result[0]["value"]["total"], info["totals"][part])
            self.assertEqual(result[0]["value"]["entry"], entry)
        by_name = self.run_page("ghidra.export_function", select="name", name=info["name"])
        self.assertEqual(by_name[1]["value"], info)
        self.assertEqual(info["library_hint"], None)

    def test_past_end_and_not_found_are_explicit_metadata(self):
        result = self.run_page(start=1048575)
        self.assertEqual(len(result), 1)
        meta = result[0]["value"]
        self.assertEqual((meta["start"], meta["total"], meta["count"], meta["next_start"]), (5, 5, 0, None))
        missing = self.run_page("ghidra.export_function", entry=1)[0]["value"]
        self.assertEqual((missing["status"], missing["start"], missing["total"], missing["count"]), ("not_found", 0, 0, 0))

    def test_prepare_refuses_incomplete_and_cap_plus_one_without_clipping(self):
        header = self.root / "raw" / "header.json"
        original = json.loads(header.read_text())
        for key, value in (("complete", False), ("options_off", {"PDB": "true"})):
            header.write_text(json.dumps(dict(original, **{key: value})))
            folder = self.root / key
            folder.mkdir()
            with self.assertRaises((worker.IncompleteAnalysis, worker.AnalysisOptionOn)):
                worker.build_tables(self.data, self.root / "raw", folder)
        header.write_text(json.dumps(original))
        with patch.object(worker, "MAX_FUNCTION_INSTRUCTIONS", 1):
            target = self.root / "cap"
            target.mkdir()
            with self.assertRaises(worker.TooManyRows):
                worker.build_tables(self.data, self.root / "raw", target)

    def test_instruction_bytes_and_source_span_are_rechecked_before_caching(self):
        path = self.root / "raw" / "calls.jsonl"
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        for field, bad in (("bytes", "00" * 5), ("address", self.layout["entry"] + 5000), ("from", 1)):
            changed = copy.deepcopy(rows)
            changed[0][field] = bad
            path.write_text("".join(json.dumps(row) + "\n" for row in changed))
            folder = self.root / field
            folder.mkdir()
            with self.assertRaises(worker.InconsistentAnchor):
                worker.build_tables(self.data, self.root / "raw", folder)

    def test_idx_offsets_and_row_json_are_bounded_before_decode(self):
        table = self.cache / "tables"
        path = table / "functions.idx"
        original = path.read_bytes()
        for data in (original[:-1], struct.pack("<Q", 1) + original[8:], original[:8] + struct.pack("<Q", 2**64 - 1) + original[16:]):
            path.write_bytes(data)
            with self.assertRaises(ValueError):
                self.run_page()
        path.write_bytes(original)
        body = table / "functions.jsonl"
        raw = body.read_bytes()
        body.write_bytes(b"x" + raw[1:])
        with self.assertRaises(ValueError):
            self.run_page()

    def test_function_export_assembly_and_pseudocode_use_the_selected_cached_function(self):
        function = self.layout["functions"][-1]
        item = self.query["functions"][-1]
        def java(format_, args, script):
            self.assertEqual(script[:5], ["export", "entry", str(function["offset"]), "x", args.get("part", "pseudocode")])
            start = min(args.get("start", 0), len(function["instructions"]))
            listing = [{"index": i, "address": function["entry"] + delta, "length": size,
                        "file_offset": function["offset"] + delta,
                        "bytes": self.data[function["offset"] + delta:function["offset"] + delta + size].hex(), "text": "INSN"}
                       for i, (delta, size) in enumerate(function["instructions"])]
            return {"format": "x", "mode": "export", "options_off": {}, "blocks": self.query["blocks"],
                    "function": item, "pseudocode": "text 😀\n" * 10000,
                    "instructions": {"start": start, "total": len(listing), "overflow": False,
                                     "rows": listing[start:start + args.get("limit", 32)]}}
        args = arguments("ghidra.export_function", entry=function["entry"], part="assembly", start=1, limit=2)
        rows = worker.export_rows("ghidra.export_function", args, self.data, root=self.cache, query_of=java)
        self.assertEqual((rows[0]["value"]["start"], rows[0]["value"]["count"]), (1, 2))
        for index, row in enumerate(rows[1:], 1):
            delta, length = function["instructions"][index]
            self.assertEqual(row["location"], {"offset": function["offset"] + delta, "length": length})
            self.assertEqual((row["value"]["from"], row["value"]["from_size"]), (function["entry"], function["size"]))
        args = arguments("ghidra.pseudocode", entry=function["entry"], text_start=65536, max_chars=128)
        rows = worker.export_rows("ghidra.pseudocode", args, self.data, root=self.cache, query_of=java)
        self.assertEqual(len(rows), 2)
        meta, value = [row["value"] for row in rows]
        self.assertEqual((meta["count"], meta["start"], meta["total"], meta["next_start"]),
                         (len(value["text"]), value["start"], value["total"], value["next_start"]))
        self.assertEqual(value["size"], function["size"])
        self.assertEqual(value["text"], ("text 😀\n" * 10000)[65536:65664])

    def test_decompile_failure_is_metadata_alone_and_wrong_function_anchor_is_refused(self):
        item = self.query["functions"][0]
        q = {"format": "x", "mode": "export", "options_off": {}, "blocks": self.query["blocks"],
             "function": item, "pseudocode": None, "instructions": None}
        args = arguments("ghidra.pseudocode", entry=self.layout["functions"][0]["entry"])
        rows = worker.export_rows("ghidra.pseudocode", args, self.data, root=self.cache, query_of=lambda *a: q)
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]["value"]["status"], rows[0]["value"]["count"]), ("decompile_failed", 0))
        q["function"] = dict(item, size=item["size"] + 1)
        with self.assertRaises(worker.InconsistentAnchor):
            worker.export_rows("ghidra.pseudocode", args, self.data, root=self.cache, query_of=lambda *a: q)

    def test_prepared_tables_work_for_each_original_format(self):
        for builder in (pe_refs, macho_refs):
            with self.subTest(format=builder.__name__):
                root = self.root / builder.__name__
                root.mkdir()
                data, layout = builder()
                cache, _, metadata = prepared(root, data, layout)
                result = worker.export_rows("ghidra.export_program", arguments("ghidra.export_program"), data, root=cache)
                self.assertEqual(result[0]["value"]["total"], len(layout["functions"]))
                self.assertEqual(metadata["counts"]["calls"], len(layout["calls"]))


class PseudocodePagingTests(unittest.TestCase):
    def setUp(self):
        self.data, layout = elf_refs()
        function = layout["functions"][0]
        self.function = {"entry": function["entry"], "size": function["size"],
                         "location": {"offset": function["offset"], "length": function["size"]}}

    def test_unicode_scalars_normalize_before_counting_and_never_split(self):
        text = ("A😀\u0301\ud800\n\t" * 1000) + "last"
        normalized = worker.printable_text(text)
        start, parts, digest = 0, [], None
        while True:
            value = worker.pseudocode_page(self.data, self.function, text, {"text_start": start, "max_chars": 2048})["value"]
            self.assertEqual(value["total"], len(normalized))
            self.assertLessEqual(worker._size(value) + 81, 4096)
            self.assertEqual(value["start"], start)
            digest = value["text_sha256"]
            parts.append(value["text"])
            if value["next_start"] is None:
                break
            self.assertGreater(value["next_start"], start)
            start = value["next_start"]
        self.assertEqual("".join(parts), normalized)
        self.assertEqual(digest, hashlib.sha256(normalized.encode()).hexdigest())

    def test_full_total_is_not_the_old_65536_cut_and_cap_is_a_failure(self):
        text = "x" * 70000
        value = worker.pseudocode_page(self.data, self.function, text, {"text_start": 65536, "max_chars": 64})["value"]
        self.assertEqual((value["total"], value["start"], len(value["text"])), (70000, 65536, 64))
        with patch.object(worker, "MAX_PSEUDOCODE", 100), self.assertRaises(worker.PseudocodeTooLarge):
            worker.pseudocode_page(self.data, self.function, "x" * 101, {"max_chars": 64})

    def test_unused_part_arguments_and_unknown_keys_are_refused(self):
        for args in ({"part": "info", "start": 1}, {"part": "info", "limit": 1},
                     {"part": "assembly", "text_start": 1}, {"part": "strings", "max_chars": 64},
                     {"part": "pseudocode", "start": 1}, {"part": "pseudocode", "limit": 128},
                     {"analysis_id": "x"}, {"entry": True}, {"select": "name", "entry": 1}, {"name": "x"}):
            with self.subTest(args=args), self.assertRaises(worker.InvalidRequest):
                arguments("ghidra.export_function", **args)


class RestoreAndInvocationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="reverseai-restore-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.data, self.layout = elf_refs()
        source = self.root / "source"
        source.mkdir()
        self.cache, _, _ = prepared(source, self.data, self.layout)
        (self.cache / "project" / "reverseai.gpr").write_bytes(b"fixture marker")
        (self.cache / "project" / "reverseai.rep").mkdir()
        (self.cache / "project" / "reverseai.rep" / "db").write_bytes(b"fixture db")
        sink = io.BytesIO()
        size, digest = worker.cache_module().pack_project(source, sink)
        self.snapshot = self.root / "snapshot"
        self.snapshot.mkdir()
        (self.snapshot / "input").write_bytes(self.data)
        (self.snapshot / "project.tar").write_bytes(sink.getvalue())
        self.manifest = {"format": 1, "input_sha256": hashlib.sha256(self.data).hexdigest(),
                         "image_id": "sha256:" + "a" * 64, "bundle_sha256": worker.bundle_hash(),
                         "size": size, "artifact_sha256": digest}
        self.stage_manifest(self.manifest)
        self.patches = [patch.object(worker, "WORK", self.root / "work"),
                        patch.object(worker, "SNAPSHOT", str(self.snapshot / "input"))]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)

    def stage_manifest(self, value):
        (self.snapshot / "cache.json").write_text(json.dumps(value))

    def test_restore_binds_body_input_bundle_and_closed_manifest_before_opening_project(self):
        root = worker.restore_project(self.data)
        self.assertEqual((root / "project" / "reverseai.gpr").read_bytes(), b"fixture marker")
        result = worker.export_rows("ghidra.export_program", arguments("ghidra.export_program"), self.data, root=root)
        self.assertEqual(result[0]["value"]["total"], 5)
        for change in ({"input_sha256": "b" * 64}, {"bundle_sha256": "b" * 64}, {"size": self.manifest["size"] - 512},
                       {"artifact_sha256": "b" * 64}, {"format": True}, {"analysis_id": "b" * 64}):
            with self.subTest(change=change):
                self.stage_manifest(dict(self.manifest, **change))
                with self.assertRaises(worker.InvalidCachedProject):
                    worker.restore_project(self.data)

    def test_cached_legacy_queries_reopen_readonly_with_no_analysis_and_never_import(self):
        root = worker.restore_project(self.data)
        argv = []
        def fake(argv_, timeout):
            argv.extend(argv_)
            (worker.WORK / "query.json").write_text('{"fixture":true}')
        with patch.object(worker, "_headless", side_effect=fake):
            self.assertEqual(worker.run_cached("elf", {}, ["functions", "x", "0", "1"], root), {"fixture": True})
        index = argv.index("-process")
        self.assertEqual(argv[index:index + 4], ["-process", "input", "-noanalysis", "-readOnly"])
        self.assertNotIn("-import", argv)
        self.assertNotIn("-deleteProject", argv)
        self.assertIn(str(root / "project"), argv)

    def test_prepare_argv_keeps_save_and_fixed_720_second_analysis_and_840_headless_wall(self):
        argv = worker.prepare_argv("elf", Path("/fixed/raw"))
        self.assertIn("-import", argv)
        self.assertNotIn("-readOnly", argv)
        self.assertNotIn("-deleteProject", argv)
        self.assertEqual(argv[argv.index("-analysisTimeoutPerFile") + 1], "720")
        self.assertEqual(argv[argv.index("-postScript") + 1:argv.index("-postScript") + 3],
                         ["ReverseAIPrepare.java", "/fixed/raw"])
        self.assertEqual(worker.PREPARE_SECONDS, 840)
        self.assertEqual(worker.HEAP, "1G")

    def test_header_and_body_must_both_be_bounded_and_hash_valid_before_restore(self):
        original = (self.snapshot / "project.tar").read_bytes()
        (self.snapshot / "cache.json").write_bytes(b" " * 4097)
        with self.assertRaises(worker.InvalidCachedProject):
            worker.restore_project(self.data)
        self.stage_manifest(self.manifest)
        (self.snapshot / "project.tar").write_bytes(b"X" + original[1:])
        with self.assertRaises(worker.InvalidCachedProject):
            worker.restore_project(self.data)

    def test_prepare_failure_has_no_json_success_stdout_and_nonzero_exit(self):
        output, error = io.BytesIO(), io.StringIO()
        stream = type("Out", (), {"buffer": output, "flush": lambda _: None})()
        with patch.object(worker.sys, "stdout", stream), patch.object(worker.sys, "stderr", error), \
                patch.object(worker, "prepare", side_effect=worker.IncompleteAnalysis()):
            code = worker.main(["ghidra.prepare", "{}"], snapshot=self.snapshot / "input")
        self.assertEqual(code, 1)
        self.assertEqual(output.getvalue(), b"")
        self.assertEqual(error.getvalue(), "IncompleteAnalysis\n")

    def test_budget_fit_shortens_a_row_page_with_an_honest_next_cursor(self):
        signature = "😀" * 512
        rows = [{"location": {"offset": 256, "length": 1},
                 "value": {"kind": "function_export", "index": i, "signature": signature}} for i in range(128)]
        result = worker._page(self.data, "program", "functions", None, 128, 0, rows)
        meta = result[0]["value"]
        self.assertGreater(meta["count"], 0)
        self.assertLess(meta["count"], 128)
        self.assertEqual(meta["next_start"], meta["count"])
        self.assertLessEqual(len(worker.encode({"protocol": worker.PROTOCOL, "status": "ok", "snapshot_sha256": "a" * 64,
                                               "observations": result})) + 81 * len(result), 262144)


if __name__ == "__main__":
    unittest.main()
