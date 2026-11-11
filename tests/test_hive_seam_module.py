"""Build/repair/review a module through production adapters; model CLI events are fixtures."""
import argparse
import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hive import bees, codex_bees, languages, queen
from tests.hive_compiler import confined
from tests.test_hive_queen import FakeEngine, FI


class FixtureBuild(queen.Build):
    """Declared fallback for hosts without confined Clang; it never executes a program."""
    @property
    def cc(self):
        return "fixture-compiler"

    @property
    def compiler_sha256(self):
        return "f" * 64

    def ensure_confinement(self):
        pass

    def syntax(self, header):
        return True, ""

    def compile(self, module_id, source, contract):
        obj = self.folder / "obj" / f"{module_id}.o"
        obj.unlink(missing_ok=True)
        if "BROKEN" in source.read_text():
            return {"ok": False, "errors": "fixture syntax error", "warnings": ""}
        obj.write_bytes(source.read_bytes())
        return {"ok": True, "errors": "", "warnings": "", "source_sha256": queen.sha256(source),
                "contract_sha256": queen.sha256(contract), "object_sha256": queen.sha256(obj),
                "compiler_sha256": self.compiler_sha256}

    def link(self, module_ids, name):
        binary = self.folder / "bin" / name
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_bytes(b"fixture binary: never executed")
        return {"ok": True, "log": "", "binary": str(binary)}


class ModuleSeamTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hive-module-seam-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.inputs = self.root / "inputs"
        self.inputs.mkdir()
        (self.inputs / "greet").write_bytes(b"inert input; never executed")
        self.real_compiler = confined("c")
        self.calls = []

    def router(self, policy):
        parser = argparse.ArgumentParser()
        codex_bees.add_arguments(parser)
        args = parser.parse_args(["--bee-policy", policy, "--codex", "fixture-codex"])
        claude = bees.ClaudeBees(engine=self.root, inputs=self.inputs, claude="fixture-claude",
                                config_dir=self.out / "claude")
        return codex_bees.build_router(args, claude, engine=self.root, inputs=self.inputs,
                                       config_dir=self.out / "codex")

    def cli(self, argv, **kwargs):
        self.assertIn(argv[0], ("fixture-claude", "fixture-codex"))
        codex = argv[0] == "fixture-codex"
        folder = Path(kwargs["cwd"])
        self.assertIn(self.out / ".hive/attempts", folder.parents)
        if codex:
            schema = json.loads(Path(argv[argv.index("--output-schema") + 1]).read_bytes())
            name = Path(argv[argv.index("-o") + 1]).name.removesuffix(".output.json")
        else:
            schema = json.loads(argv[argv.index("--json-schema") + 1])
            name = Path(argv[argv.index("--mcp-config") + 1]).stem
        self.calls.append((name, "codex" if codex else "claude", folder))
        events = []
        if name.startswith("network-probe-"):
            output = {"exit_code": 7}
            events.append({"type": "item.completed", "item": {"type": "command_execution",
                "command": codex_bees.NETWORK_COMMAND, "exit_code": 7}})
        elif name.startswith("planner-g"):
            output = {"modules": [{"id": "entry", "title": "Main", "functions": ["0x1000"]}],
                "skipped": [{"entry": entry, "reason": "fixture library", "evidence": [entry]}
                            for entry in ("0x1040", "0x1080")], "unknowns": [], "declarations": [{
                    "entity_id": "function:0x1000", "kind": "function", "entry": "0x1000",
                    "owner_entry": None, "linkage": None, "text": "int main(void); /* 0x1000 */",
                    "requires": [], "evidence": ["0x1000"]}]}
        elif name == "m01-build" or name.startswith("m01-repair-"):
            self.assertTrue((folder / "BRIEF.md").is_file())
            self.assertTrue((folder / "contract.h").is_file())
            self.assertFalse((folder / "attempt-only.txt").exists())
            if name == "m01-build":
                source = '#include "contract.h"\nint main(void) { BROKEN }\n'
            elif name == "m01-repair-b1":
                self.assertIn("BROKEN", (folder / "m01.c").read_text())
                source = '#include "contract.h"\nint main(void) { return 1; }\n'
            else:
                self.assertEqual(name, "m01-repair-c1")
                self.assertIn("return 1;", (folder / "m01.c").read_text())
                source = '#include "contract.h"\nint main(void) { return 0; }\n'
            (folder / "m01.c").write_text(source)
            (folder / "attempt-only.txt").write_text("must not be promoted")
            (folder / "claims.json").write_text(json.dumps({"file": "greet", "claims": [{"id": "c1",
                "text": "Fixture claim", "citations": [{"tool": "export_function", "args": {"entry": 4096}, "id": FI}]}]}))
            output = {"status": "done", "functions": [{"entry": "0x1000", "status": "rebuilt", "name": "main", "notes": "fixture"}],
                      "contract_requests": [], "unknowns": []}
        else:
            self.assertRegex(name, r"m01-council-r[12]-(control|io|data)")
            source = next(folder.glob("unit-*.c")).read_text()
            self.assertIn("return 1;" if "-r1-" in name else "return 0;", source)
            refute = name == "m01-council-r1-io"
            output = {"verdict": "refute" if refute else "accept", "defects": [{"function": "main",
                "problem": "wrong exit", "evidence": "0x1000 xor w0,w0", "fix": "return 0"}] if refute else [],
                      "summary": "fixture independent reading"}
        self.assertTrue(bees.matches_schema(output, schema), (name, output, schema))
        if codex:
            Path(argv[argv.index("-o") + 1]).write_text(json.dumps(output))
            events.append({"type": "turn.completed"})
        else:
            events.append({"type": "result", "structured_output": output})
        return subprocess.CompletedProcess(argv, 0, "\n".join(json.dumps(event) for event in events), "")

    def run_module(self, policy, *, use_real_compiler):
        self.out = self.root / (policy + ("-clang" if use_real_compiler else "-fixture"))
        self.calls = []
        build = (queen.Build if use_real_compiler else FixtureBuild)(self.out / "build", language=languages.C)
        def check(claims, out):
            rows = json.loads(Path(claims).read_bytes())["claims"]
            self.assertEqual(len(rows), 1)
            return {"claims": 1, "confirmed": 1, "rejected": 0, "questions": 1,
                    "input_sha256": ["cd" * 32]}, []
        q = queen.Queen(engine=FakeEngine(self.inputs), out=self.out, bees=self.router(policy),
                        build=build, check=check, attempt_not_started=bees.AttemptNotStarted)
        with patch("hive.bees.run_cli", side_effect=self.cli), contextlib.redirect_stdout(io.StringIO()):
            result = q.run()
        self.assertEqual(result["verdict"], "accepted without behaviour proof", result["reason"])
        self.assertEqual(result["modules"], {"m01": "accepted"})
        self.assertFalse(result["conformance"]["ran"])
        self.assertTrue((self.out / "build/obj/m01.o").is_file())
        self.assertTrue((self.out / "build/bin/greet").is_file())
        self.assertEqual((self.out / "modules/m01/m01.c").read_text(),
                         '#include "contract.h"\nint main(void) { return 0; }\n')
        self.assertFalse((self.out / "modules/m01/attempt-only.txt").exists())
        status = json.loads((self.out / ".hive/status/m01.json").read_bytes())
        self.assertEqual([c["ok"] for c in status["compiles"]], [False, True, True])
        self.assertEqual(len(status["rounds"]), 2)
        self.assertEqual(len(status["rounds"][0]["defects"]), 1)
        self.assertEqual(status["rounds"][1]["defects"], [])
        self.assertEqual(set(status["rounds"][1]["seats"]), {"control", "io", "data"})
        self.assertTrue(all(r["complete"] for r in status["rounds"]))
        authors, readers = status["author_attempts"], status["reviewer_attempts"]
        self.assertEqual(len(authors), 3)
        self.assertEqual(len(readers), 3)
        self.assertFalse(set(authors) & set(readers))
        attempts = q.state.data["attempts"]
        self.assertEqual([attempts[aid]["role"] for aid in authors], ["worker", "repair", "repair"])
        for aid in authors + readers:
            attempt = attempts[aid]
            self.assertEqual(attempt["status"], "finished")
            self.assertEqual(attempt["result"]["provenance"]["attempt_id"], aid)
            self.assertEqual(attempt["kind"], "bee")
        all_reader_ids = [seat["attempt_id"] for r in status["rounds"] for seat in r["seats"].values()]
        self.assertEqual(len(set(all_reader_ids)), 6)
        self.assertTrue(all(attempts[aid]["role"] == "councillor" for aid in all_reader_ids))
        self.assertFalse(set(authors) & set(all_reader_ids))
        contexts = [attempts[aid]["result"]["provenance"]["context_id"] for aid in authors + all_reader_ids]
        self.assertEqual(len(set(contexts)), 9)
        self.assertEqual(status["reviewed"]["source_sha256"], queen.sha256(self.out / "modules/m01/m01.c"))
        self.assertTrue(q.approved(status, self.out / "src/contract.h"))
        writers = [(name, folder) for name, _, folder in self.calls if name == "m01-build" or "-repair-" in name]
        self.assertEqual([name for name, _ in writers], ["m01-build", "m01-repair-b1", "m01-repair-c1"])
        self.assertTrue(all((folder / "attempt-only.txt").is_file() for _, folder in writers))
        self.assertEqual(len({folder for _, folder in writers}), 3)
        ordinary = [a for a in attempts.values() if a["kind"] == "bee"]
        self.assertEqual(len(ordinary), 10)
        self.assertEqual(q.spent["bees"], len(self.calls))
        self.assertEqual(len({a["context_id"] for a in attempts.values()}), len(attempts))
        clients = {a["client"] for a in ordinary}
        self.assertEqual(clients, {"claude", "codex"} if policy == "mixed" else {policy})
        before = len(self.calls)
        resumed = queen.Queen(engine=FakeEngine(self.inputs), out=self.out, bees=self.router(policy),
                              build=build, check=check, attempt_not_started=bees.AttemptNotStarted)
        with patch("hive.bees.run_cli", side_effect=self.cli), contextlib.redirect_stdout(io.StringIO()):
            resumed_result = resumed.run()
        self.assertEqual(resumed_result["modules"], {"m01": "accepted"})
        self.assertEqual(len(self.calls), before)
        self.assertEqual(resumed.spent["bees"], q.spent["bees"])

    def test_module_build_compile_repair_and_non_author_council_through_real_adapters(self):
        for policy in ("claude", "mixed", "codex"):
            with self.subTest(policy=policy, compiler="confined Clang" if self.real_compiler else "declared fixture"):
                self.run_module(policy, use_real_compiler=self.real_compiler)

    def test_declared_compiler_fixture_keeps_seam_coverage_without_clang(self):
        self.run_module("mixed", use_real_compiler=False)


if __name__ == "__main__":
    unittest.main()
