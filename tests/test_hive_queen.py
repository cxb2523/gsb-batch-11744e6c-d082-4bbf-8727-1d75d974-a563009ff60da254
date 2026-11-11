import json
import copy
import contextlib
import io
import shutil
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch
from pathlib import Path

from tests.hive_compiler import confined
from hive import bees, queen

CC = shutil.which("cc")

ORIGINAL = r'''
#include <stdio.h>
static int greet_line(const char *name) { return printf("hello %s\n", name); }
int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: greet NAME\n"); return 2; }
    greet_line(argv[1]);
    return 0;
}
'''
CONTRACT = '''#include <stdio.h>
int greet_line(const char *name); /* 0x1040 */
int main(int argc, char **argv); /* 0x1000 */
'''
GOOD = {
    "m01": '#include "contract.h"\nint greet_line(const char *name) { return printf("hello %s\\n", name); }\n',
    "m02": '#include "contract.h"\nint main(int argc, char **argv) {\n'
           '    if (argc < 2) { fprintf(stderr, "usage: greet NAME\\n"); return 2; }\n'
           '    greet_line(argv[1]);\n    return 0;\n}\n',
}
WRONG_EXIT = GOOD["m02"].replace("return 2;", "return 1;")
FI = "fi-" + "a" * 16


def page(claim_key, rows, total):
    return {"input": {"sha256": "cd" * 32},
            "results": [{"findings": [{"claim_key": claim_key, "verdict": "derived",
                                       "value": {"rows": rows, "total": total}}]}]}


class FakeEngine:
    file = "greet"

    def __init__(self, inputs):
        self.path = Path(inputs) / self.file
        self.questions = []

    def prepare(self):
        return {"status": "prepared"}

    def query(self, name, args, out):
        self.questions.append((name, dict(args)))
        functions = [{"index": 0, "entry": 0x1000, "name": "FUN_1000", "size": 64, "signature": None},
                     {"index": 1, "entry": 0x1040, "name": "FUN_1040", "size": 32, "signature": None},
                     {"index": 2, "entry": 0x1080, "name": "_printf", "size": 12, "signature": None}]
        tables = {"functions": ("code.export_functions", functions),
                  "calls": ("code.export_calls", [{"index": 0, "from": 0x1000, "to": 0x1040, "to_name": "FUN_1040"},
                                                  {"index": 1, "from": 0x1040, "to": 0x9000, "to_name": "_printf"}]),
                  "strings": ("code.export_strings", [{"index": 0, "from": 0x1000, "address": 0x2000,
                                                       "text": "usage: greet NAME\n"}])}
        key, rows = tables[args["part"]]
        start = args["start"]
        return page(key, rows[start:start + 2], len(rows))  # two rows per page, to exercise paging


class FakeRunner:
    """Adapt existing canned agents to the physical-attempt protocol; never start a CLI."""

    def __init__(self, provider, descriptor):
        self.provider, self.descriptor = provider, descriptor

    def __call__(self, role, name, task, folder, *, schema=None, before_start=None):
        aid = before_start("bee")
        result = dict(self.provider(role, name, task, folder))
        result.setdefault("outcome", "provider_refusal" if result.get("refused") else "ok" if result.get("ok") else "failure")
        result["provenance"] = {**self.descriptor, **result.get("provenance", {}), "attempt_id": aid}
        before_start.finished(aid, result)
        return result


class FakeRouter:
    def __init__(self, provider, *, fallback=None, scope="run", roles=(), names=()):
        self.provider, self.local_provider = provider, fallback
        self.settings = {"fallback": None if fallback is None else {
            "scope": scope, "roles": sorted(roles), "bees": sorted(names)}}

    def policy(self):
        return copy.deepcopy(self.settings)

    def describe(self, role, name, *, local=False):
        return {"client": "fixture", "server_kind": "local" if local else "cloud",
                "server": "http://127.0.0.1:11434" if local else "fixture://primary",
                "requested_model": "fixture-model", "observed_model": "fixture-model", "model_digest": None,
                "probe_key": None, "probe_required": False}

    def primary(self, role, name):
        return FakeRunner(self.provider, self.describe(role, name))

    def fallback(self, role, name):
        policy = self.settings["fallback"]
        allowed = policy and (policy["scope"] == "run" or
                              policy["scope"] == "role" and role in policy["roles"] or
                              policy["scope"] == "bee" and name in policy["bees"])
        return FakeRunner(self.local_provider, self.describe(role, name, local=True)) if allowed else None


class FakePlanningError(ValueError):
    def __init__(self, code, result=None, details=None):
        super().__init__(code)
        self.code, self.bee_result, self.details = code, result, details or {}


class FakePlanning:
    """A deterministic fixture bundle producer; the real phase-B implementation is another lane."""

    PlanningError = FakePlanningError

    def __init__(self, header=CONTRACT):
        self.header, self.calls = header, 0

    @staticmethod
    def validate_saved(out, saved):
        if saved is not None and not (
                type(saved) is dict and set(saved) == {"schema", "bindings", "groups", "resolutions"}
                and saved["schema"] == "hive.planning-progress/1"
                and all(type(saved[key]) is dict for key in ("bindings", "groups", "resolutions"))
                and saved == json.loads((Path(out) / "plan/progress.json").read_bytes())):
            raise FakePlanningError("resume_mismatch")

    def plan(self, program_map, partitioned, *, out, invoke, language, max_functions,
             max_prompt_bytes, interface_rounds, saved):
        self.validate_saved(out, saved)
        self.calls += 1
        folder = Path(out) / "plan"
        folder.mkdir(parents=True, exist_ok=True)
        answer = invoke("planner", "planner", "Plan the owned fixture in " + language + "; write "
                        + ("contract.h" if language == "c" else "contract.hpp"), folder)
        if not answer["ok"]:
            raise FakePlanningError(answer["outcome"], answer)
        modules, skipped = queen.normalise_plan(answer["output"], program_map, max_functions)
        for module in modules:
            module["globals"] = []
        header = folder / ("contract.h" if language == "c" else "contract.hpp")
        queen.write_file(header, self.header.encode())
        interfaces = folder / "interfaces.json"
        queen.write_file(interfaces, queen.canonical({"schema": "hive.interfaces/1", "declarations": [],
                                                     "owners": {}, "cut_edges": []}))
        bundle = {"schema": "hive.plan/1", "input_sha256": program_map["input_sha256"],
                  "map_sha256": queen.digest(program_map), "partition_sha256": queen.digest(partitioned),
                  "planning_policy_sha256": queen.digest({"fixture": 1, "max_functions": max_functions}),
                  "language": language, "modules": modules,
                  "skipped": [{"entry": entry, "reason": reason, "evidence": [entry]} for entry, reason in skipped.items()],
                  "contract_path": str(header.relative_to(out)), "contract_sha256": queen.sha256(header),
                  "interfaces_path": str(interfaces.relative_to(out)), "interfaces_sha256": queen.sha256(interfaces),
                  "planner_attempts": [*answer["provenance"]["prior_attempt_ids"], answer["provenance"]["attempt_id"]]}
        bundle["plan_id"] = queen.digest({k: v for k, v in bundle.items()
                                          if k not in ("contract_path", "interfaces_path", "planner_attempts")})
        queen.write_file(folder / "manifest.json", queen.canonical(bundle))
        return bundle

    def validate_bundle(self, bundle, program_map, *, out, language, max_functions):
        expected = queen.digest({k: v for k, v in bundle.items()
                                 if k not in ("plan_id", "contract_path", "interfaces_path", "planner_attempts")})
        if bundle["plan_id"] != expected:
            raise FakePlanningError("fixture plan changed")


def make_queen(**kwargs):
    kwargs["bees"] = kwargs["bees"] if isinstance(kwargs["bees"], FakeRouter) else FakeRouter(kwargs["bees"])
    kwargs.setdefault("planning", FakePlanning())
    return queen.Queen(**kwargs)


class FakeBees:
    """Writes canned module sources; council and repair behaviour is set per scenario."""

    def __init__(self, sources, *, refute_first=(), repaired=None, cases=None):
        self.sources, self.refute_first = dict(sources), set(refute_first)
        self.repaired, self.cases, self.calls = dict(repaired or {}), cases or [], []

    def __call__(self, role, name, task, folder):
        folder = Path(folder)
        self.calls.append((role, name))
        if role == "planner":
            (folder / "contract.h").write_text(CONTRACT)
            return {"ok": True, "seconds": 1, "output": {
                "modules": [{"id": "x", "title": "greeting", "functions": ["0x1040"]},
                            {"id": "y", "title": "main", "functions": ["0x1000", "0x1000", "0xdead"]}],
                "skipped": [{"entry": "0x1080", "reason": "import stub"}]}}
        if role in ("worker", "repair"):
            mid = folder.name
            if role == "worker":
                (folder / f"{mid}.c").write_text(self.sources[mid])
            elif mid in self.repaired:
                (folder / f"{mid}.c").write_text(self.repaired[mid])
            elif folder.parent.name == "fixes":
                for name_, text in self.repaired.items():
                    (folder / f"{name_}.c").write_text(text)
            (folder / "claims.json").write_text(json.dumps({"file": "greet", "claims": [
                {"id": "c1", "text": "t", "citations": [{"tool": "export_function", "args": {"entry": 1}, "id": FI}]}]}))
            entries = {"m01": ["0x1040"], "m02": ["0x1000"]}
            mids = list(self.repaired) if folder.parent.name == "fixes" else [mid]
            return {"ok": True, "seconds": 1, "output": {"status": "done", "functions": [
                {"entry": entry, "status": "rebuilt"} for unit in mids for entry in entries.get(unit, [])]}}
        if role == "councillor":
            mid = name.split("-")[0]
            if mid in self.refute_first and "-r1-" in name and name.endswith("-io"):
                return {"ok": True, "seconds": 1, "output": {"verdict": "refute", "defects": [
                    {"function": "main", "problem": "wrong exit code", "evidence": "0x1010 mov w0, #2"},
                    {"function": "main", "problem": "unevidenced opinion", "evidence": "trust me"}]}}
            return {"ok": True, "seconds": 1, "output": {"verdict": "accept", "defects": []}}
        if role == "tester":
            return {"ok": True, "seconds": 1, "output": {"cases": self.cases}}
        raise AssertionError(role)


CASES = [{"id": "no-args", "steps": [{"args": []}]},
         {"id": "name", "steps": [{"args": ["ada"]}]},
         {"id": "file-escape", "files": [{"name": "../outside", "text": "x"}], "steps": [{"args": ["x"]}]}]


@unittest.skipUnless(confined("c"), "needs a Clang compiler the hive can confine")
class QueenRunTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.inputs = self.tmp / "inputs"
        self.inputs.mkdir()
        source = self.tmp / "greet.c"
        source.write_text(ORIGINAL)
        subprocess.run([CC, str(source), "-o", str(self.inputs / "greet")], check=True)

    def queen(self, fake, *, rejected=0, **kwargs):
        def check(claims, out):
            count = len(json.loads(Path(claims).read_text())["claims"])
            return {"claims": count, "confirmed": count - rejected, "rejected": rejected, "questions": 1,
                    "input_sha256": ["cd" * 32]}, []
        return make_queen(engine=FakeEngine(self.inputs), out=self.tmp / "run", bees=fake, slots=2,
                           check=check, **kwargs)

    def test_accepted_only_when_every_check_passes(self):
        fake = FakeBees(GOOD, cases=CASES)
        result = self.queen(fake, run_original=True).run()
        self.assertEqual(result["verdict"], "accepted", result["reason"])
        self.assertEqual(result["modules"], {"m01": "accepted", "m02": "accepted"})
        self.assertEqual(result["conformance"]["identical"], 3)
        self.assertFalse((self.tmp / "outside").exists())
        self.assertEqual(result["skipped"], 1)
        self.assertTrue((self.tmp / "run" / "REPORT.md").is_file())
        frozen = self.tmp / "run" / "src" / "contract.h"
        self.assertEqual(frozen.stat().st_mode & 0o777, 0o444)
        self.assertEqual(sum(1 for role, _ in fake.calls if role == "councillor"), 6)  # 3 lenses x 2 modules

    def test_without_permission_the_original_never_runs(self):
        result = self.queen(FakeBees(GOOD, cases=CASES)).run()
        self.assertEqual(result["verdict"], "accepted without behaviour proof")
        self.assertFalse(result["conformance"]["ran"])
        self.assertFalse((self.tmp / "run" / "tests").exists())

    def test_council_defect_with_evidence_goes_back_for_repair(self):
        fake = FakeBees({"m01": GOOD["m01"], "m02": WRONG_EXIT}, refute_first={"m02"}, repaired={"m02": GOOD["m02"]})
        result = self.queen(fake).run()
        self.assertEqual(result["modules"]["m02"], "accepted")
        status = json.loads((self.tmp / "run" / "modules" / "m02" / "status.json").read_text())
        self.assertEqual([d["problem"] for d in status["rounds"][0]["defects"]], ["wrong exit code"])
        self.assertIn(("repair", "m02-repair-c1"), fake.calls)
        council_seats = list((self.tmp / "run" / "council").iterdir())
        self.assertTrue(all(not list(seat.glob("m0*.c")) for seat in council_seats))  # authorship hidden
        self.assertTrue(all(not (seat / "NOTES.md").exists() for seat in council_seats))

    def test_compile_errors_are_repaired_and_cheats_fail(self):
        fake = FakeBees({"m01": "#include \"contract.h\"\nint greet_line(const char *name) { return nope; }\n",
                         "m02": GOOD["m02"].replace("return 0;", "__asm__(\"nop\"); return 0;")},
                        repaired={"m01": GOOD["m01"]})
        result = self.queen(fake).run()
        self.assertEqual(result["modules"], {"m01": "accepted", "m02": "failed"})
        self.assertEqual(result["verdict"], "not accepted")
        status = json.loads((self.tmp / "run" / "modules" / "m02" / "status.json").read_text())
        self.assertIn("forbidden constructs", status["errors"])

    def test_checker_rejection_cannot_be_overridden(self):
        result = self.queen(FakeBees(GOOD), rejected=1).run()
        self.assertEqual(result["verdict"], "not accepted")
        self.assertIn("rejected by the evidence checker", result["reason"])

    def test_behaviour_difference_triggers_a_fix_round(self):
        unfixed = FakeBees({"m01": GOOD["m01"], "m02": WRONG_EXIT}, cases=CASES)
        result = self.queen(unfixed, run_original=True).run()
        self.assertEqual(result["conformance"]["different"], ["no-args"])
        self.assertEqual(result["verdict"], "not accepted")
        shutil.rmtree(self.tmp / "run")
        fixed = FakeBees({"m01": GOOD["m01"], "m02": WRONG_EXIT}, cases=CASES, repaired={"m02": GOOD["m02"]})
        result = self.queen(fixed, run_original=True).run()
        self.assertIn(("repair", "behaviour-fix-1"), fixed.calls)
        self.assertEqual(result["conformance"]["identical"], 3)
        self.assertEqual(result["verdict"], "accepted")

    def test_bee_budget_is_enforced_and_logged(self):
        fake = FakeBees(GOOD)
        result = self.queen(fake, max_bees=1).run()
        self.assertEqual(result["verdict"], "not accepted")
        self.assertEqual(result["stop_reason"], "budget_insufficient")
        self.assertEqual(fake.calls, [("planner", "planner")])
        self.assertEqual(result["spent"]["bees"], 1)
        self.assertIn("budget_insufficient", (self.tmp / "run" / "hive.log").read_text())


class PlanAndLinkTests(unittest.TestCase):
    MAP = {"functions": [{"hex": hex(e), "entry": e} for e in (0x10, 0x20, 0x30, 0x40, 0x50)]}

    def test_every_function_lands_in_exactly_one_bounded_module(self):
        plan = {"modules": [{"title": "a", "functions": ["0x10", "0x20", "0x30", "0x10", "0x999"]},
                            {"title": "b", "functions": ["0x20"]}],
                "skipped": [{"entry": "0x50", "reason": "stub"}, {"entry": "0x777", "reason": "?"}]}
        modules, skipped = queen.normalise_plan(plan, self.MAP, max_functions=2)
        assigned = [e for m in modules for e in m["functions"]]
        self.assertEqual(sorted(assigned), ["0x10", "0x20", "0x30", "0x40"])
        self.assertEqual(len(assigned), len(set(assigned)))
        self.assertTrue(all(len(m["functions"]) <= 2 for m in modules))
        self.assertEqual(skipped, {"0x50": "stub"})
        self.assertEqual([m["id"] for m in modules], ["m01", "m02", "m03"])

    def test_link_errors_are_routed_to_their_modules(self):
        mac = ('Undefined symbols for architecture arm64:\n  "_greet_line", referenced from:\n      _main in m02.o\n'
               "duplicate symbol '_helper' in:\n    build/obj/m01.o\n    build/obj/m03.o\n")
        blamed = queen.link_blame(mac, {"greet_line": "m01", "helper": "m01"}, ["m01", "m02", "m03"])
        self.assertIn("undefined symbol greet_line", blamed["m01"][0])
        self.assertIn("duplicate symbol helper", blamed["m03"][0])
        gnu = "m02.o: in function `main':\nx.c:(.text+0x1): undefined reference to `greet_line'\n"
        self.assertIn("m01", queen.link_blame(gnu, {"greet_line": "m01"}, ["m01", "m02"]))

    def test_contract_names_read_the_entry_comments(self):
        self.assertEqual(queen.contract_names(CONTRACT), {0x1040: "greet_line", 0x1000: "main"})


class BeeCommandTests(unittest.TestCase):
    def test_main_passes_tool_rejection_limit_to_primary_and_fallback_runners(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "greet").write_bytes(b"inert fixture")
            flags = ["run", "--inputs", folder, "--file", "greet", "--out", str(root / "out"),
                     "--bee-policy", "mixed", "--fallback-model-server", "http://127.0.0.1:11434",
                     "--fallback-model", "local-claude", "--fallback-codex-model", "local-codex", "--fallback-scope", "run"]
            for extra, expected in (([], 8), (["--max-tool-rejections", "3"], 3)):
                with patch.object(queen, "Engine"), patch.object(bees, "environment_ok", return_value=True), \
                     patch.object(queen, "Queen") as make:
                    make.return_value.run.return_value = {"verdict": "accepted"}
                    self.assertEqual(queen.main(flags + extra), 0)
                    router = make.call_args.kwargs["bees"]
                    for name in ("m01-build", "m02-build"):
                        self.assertEqual(router.primary("worker", name).max_tool_rejections, expected)
                        self.assertEqual(router.fallback("worker", name).max_tool_rejections, expected)
            for value in ("0", "-1"):
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                    queen.main(flags + ["--max-tool-rejections", value])
                self.assertEqual(error.exception.code, 2)

    def test_no_role_gets_a_shell_or_the_web_and_each_bee_has_its_own_server(self):
        tmp = Path(tempfile.mkdtemp())
        runner = bees.ClaudeBees(engine="/engine", inputs="/inputs", config_dir=tmp)
        for role in bees.TOOLSETS:
            argv = runner.argv(role, f"bee-{role}")
            tools = argv[argv.index("--tools") + 1].split(",")
            self.assertFalse({"Bash", "WebFetch", "WebSearch", "Agent"} & set(tools))
            self.assertIn("--strict-mcp-config", argv)
            allowed = argv[argv.index("--allowedTools") + 1:]
            self.assertEqual(allowed[0], "mcp__reverseai__*")
            self.assertEqual(allowed[1:], [f"{tool}(./**)" for tool in tools])  # file tools fenced to the bee's folder
            if "Write" in tools:
                self.assertIn("Edit(./**)", allowed)  # Claude Code checks file writes against Edit rules
            self.assertEqual(argv[argv.index("--permission-mode") + 1], "dontAsk")
            config = json.loads(Path(argv[argv.index("--mcp-config") + 1]).read_text())
            server = config["mcpServers"]["reverseai"]
            self.assertEqual(server["args"][:5], ["-B", "-m", "reverseai", "mcp", "--inputs"])
            self.assertEqual(server["env"]["PYTHONPATH"], "/engine")
        self.assertEqual(runner.argv("councillor", "c")[runner.argv("councillor", "c").index("--tools") + 1], "Read")
        self.assertEqual(len(list(tmp.glob("*.json"))), len(bees.TOOLSETS) + 1)

    def test_every_role_has_a_card_and_a_schema(self):
        for role in bees.TOOLSETS:
            text = bees.brief(role, "TASK")
            self.assertTrue(text.startswith("# ReverseAI hive: rules for every bee"))
            self.assertTrue(text.rstrip().endswith("TASK"))
            self.assertEqual(bees.SCHEMAS[role]["type"], "object")


class DurableAttemptTests(unittest.TestCase):
    """Exercise crash, concurrency and fallback boundaries with inert local fixtures only."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hive-durable-attempts-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.inputs = self.root / "inputs"
        self.inputs.mkdir()
        (self.inputs / "greet").write_bytes(b"owned inert fixture")
        self.out = self.root / "run"
        self.folder = self.out / "modules/m01"
        self.folder.mkdir(parents=True)

    def make(self, provider=None, **kwargs):
        return make_queen(engine=FakeEngine(self.inputs), out=self.out,
                          bees=provider or (lambda *args: {"ok": True, "output": {}}), **kwargs)

    def call(self, q, name="m01-build", role="worker"):
        return q.bee(role, name, "owned fixture task", self.folder)

    def test_parallel_starts_never_exceed_cap_and_denied_calls_cost_nothing(self):
        calls = []
        q = self.make(lambda *args: calls.append(args[1]) or {"ok": True, "output": {}}, max_bees=3, slots=8)
        results = []
        def call(n):
            # Parallel modules own separate folders, as in Queen.module; share only the budget.
            folder = self.out / "modules" / f"m{n + 1:02d}"
            folder.mkdir(exist_ok=True)
            results.append(q.bee("worker", f"job-{n}", "owned fixture task", folder))
        workers = [threading.Thread(target=call, args=(n,)) for n in range(12)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(10)
            self.assertFalse(worker.is_alive())
        self.assertEqual(len(results), 12)
        self.assertEqual(len(calls), 3)
        self.assertEqual(q.spent["bees"], 3)
        self.assertEqual(sum(r["ok"] for r in results), 3)
        self.assertEqual(sum(r["outcome"] == "not_started" for r in results), 9)

    def test_fallback_has_explicit_scope_and_keeps_ordered_attempt_provenance(self):
        calls = []
        def primary(*args):
            calls.append("primary")
            return {"ok": False, "refused": True, "error": "provider refused"}
        def local(*args):
            calls.append("local")
            return {"ok": True, "output": {}}
        q = self.make(FakeRouter(primary, fallback=local, scope="role", roles=("worker",)))
        first, second = self.call(q), self.call(q, "next-worker")
        self.assertTrue(first["ok"] and second["ok"])
        self.assertEqual(calls, ["primary", "local", "local"])
        self.assertEqual(q.spent["bees"], 3)
        self.assertEqual(len(first["provenance"]["prior_attempt_ids"]), 1)
        self.assertNotEqual(first["provenance"]["attempt_id"], first["provenance"]["prior_attempt_ids"][0])
        self.assertNotIn("attempt_id", first)
        self.assertEqual(len(q.refusals), 1)
        self.assertEqual(q.state.data["unresolved_refusals"], {})
        self.assertEqual(q.state.data["activated"], ["role:worker"])

    def test_without_consent_and_for_unselected_bees_there_is_no_second_provider(self):
        calls = []
        refused = lambda *args: {"ok": False, "refused": True}
        local = lambda *args: calls.append("local") or {"ok": True, "output": {}}
        q = self.make(FakeRouter(refused, fallback=local, scope="bee", names=("selected",)))
        self.assertEqual(self.call(q, "unselected")["outcome"], "provider_refusal")
        self.assertEqual(calls, [])
        self.assertEqual(q.spent["bees"], 1)

    def test_report_declares_missing_native_tool_monitor(self):
        q = self.make(lambda *args: {"ok": True, "output": {}, "tool_rejections": None})
        self.call(q)
        q._stopped_result("fixture stop")
        report = (self.out / "REPORT.md").read_text()
        self.assertIn("MCP rejection monitor unavailable", report)
        self.assertIsNone(next(iter(q.state.data["attempts"].values()))["result"]["tool_rejections"])

    def test_timeout_does_not_activate_local_routing(self):
        calls = []
        q = self.make(FakeRouter(lambda *a: {"ok": False, "outcome": "timeout"},
                                 fallback=lambda *a: calls.append("local")))
        self.assertEqual(self.call(q)["outcome"], "timeout")
        self.assertEqual(calls, [])
        self.assertEqual(q.state.data["activated"], [])

    def test_tool_schema_failure_is_recorded_without_fallback_or_refusal_threshold(self):
        calls = []
        failure = {"ok": False, "outcome": "tool_schema_failure", "tool_rejections": 9,
                   "consecutive_tool_rejections": 8, "tool_name": "mcp__reverseai__export_function",
                   "error": "Stopped after 8 consecutive MCP argument/schema rejections"}
        q = self.make(FakeRouter(lambda *a: failure, fallback=lambda *a: calls.append("local")), refusal_limit=1)
        answer = self.call(q)
        self.assertEqual(answer["outcome"], "tool_schema_failure")
        self.assertFalse(answer["refused"])
        self.assertEqual(answer["tool_name"], failure["tool_name"])
        self.assertEqual(calls, [])
        self.assertEqual(q.refusals, [])
        self.assertEqual(q.state.data["unresolved_refusals"], {})
        self.assertEqual(q.state.data["activated"], [])
        self.assertIsNone(q.stopped)
        self.assertEqual(q.spent["bees"], 1)
        q._stopped_result("fixture failure")
        report = (self.out / "REPORT.md").read_text()
        self.assertIn("8 consecutive MCP argument/schema rejections", report)
        self.assertIn("mcp__reverseai__export_function", report)
        self.assertIn("total observed 9", report)

    def test_refused_attempt_cannot_contaminate_local_attempt_files(self):
        source = self.folder / "m01.c"
        source.write_text("known baseline")
        def primary(role, name, task, folder):
            (Path(folder) / "m01.c").write_text("untrusted partial write")
            return {"ok": False, "refused": True}
        def local(role, name, task, folder):
            self.assertEqual((Path(folder) / "m01.c").read_text(), "known baseline")
            (Path(folder) / "m01.c").write_text("local replacement")
            return {"ok": True, "output": {}}
        q = self.make(FakeRouter(primary, fallback=local))
        answer = self.call(q)
        self.assertTrue(answer["ok"])
        self.assertEqual(source.read_text(), "local replacement")
        self.assertEqual(q.state.data["authors"]["m01"], [answer["provenance"]["attempt_id"]])

    def test_changed_protected_inputs_prevent_all_file_promotion(self):
        (self.folder / "BRIEF.md").write_text("frozen brief")
        source = self.folder / "m01.c"
        source.write_text("baseline")
        def malicious(role, name, task, folder):
            (Path(folder) / "BRIEF.md").write_text("changed")
            (Path(folder) / "m01.c").write_text("poison")
            return {"ok": True, "output": {}}
        q = self.make(malicious)
        result = self.call(q)
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "unsafe_attempt_files")
        self.assertEqual(source.read_text(), "baseline")
        self.assertEqual((self.folder / "BRIEF.md").read_text(), "frozen brief")

    def test_interrupted_start_stays_consumed_after_a_fresh_queen(self):
        class Crash(BaseException):
            pass
        def interrupted(*args):
            raise Crash()
        q = self.make(interrupted, max_bees=1)
        with self.assertRaises(Crash):
            self.call(q)
        restarted = self.make()
        answer = self.call(restarted)
        self.assertEqual(answer["outcome"], "not_started")
        self.assertEqual(restarted.spent["bees"], 1)
        self.assertEqual(restarted.max_bees, 1)
        self.assertEqual(next(iter(restarted.state.data["attempts"].values()))["status"], "interrupted")

    def test_editing_checkpoint_to_reset_budget_is_refused(self):
        q = self.make(max_bees=1)
        self.assertTrue(self.call(q)["ok"])
        path = self.out / ".hive/run.json"
        data = json.loads(path.read_text())
        data["spent"]["bees"] = 0
        path.write_text(json.dumps(data))
        with self.assertRaisesRegex(queen.HiveError, "checkpoint differs"):
            self.call(self.make())

    def test_refusal_recovery_requires_explicit_consent_and_preserves_history(self):
        refused = lambda *a: {"ok": False, "refused": True}
        q = self.make(refused, refusal_limit=1)
        first = self.call(q)
        self.assertEqual(q.stopped, "refusal_limit")
        blocked = self.make(refused, refusal_limit=1)
        self.assertEqual(self.call(blocked)["outcome"], "not_started")
        self.assertEqual(blocked.spent["bees"], 1)
        local = lambda *a: {"ok": True, "output": {}}
        recovered = self.make(FakeRouter(refused, fallback=local), resume_refused=True, refusal_limit=1)
        answer = self.call(recovered)
        self.assertTrue(answer["ok"], answer)
        self.assertEqual(recovered.spent["bees"], 2)
        self.assertEqual(len(recovered.refusals), 1)
        self.assertEqual(recovered.state.data["unresolved_refusals"], {})
        self.assertIsNone(recovered.stopped)
        self.assertEqual(answer["provenance"]["prior_attempt_ids"], [first["provenance"]["attempt_id"]])

    def test_adapter_attempt_not_started_is_converted_without_an_invented_start(self):
        class AdapterDenied(Exception):
            code = "budget_exhausted"
        class DeniedRouter(FakeRouter):
            def primary(self, role, name):
                def denied(*args, **kwargs):
                    raise AdapterDenied()
                return denied
        q = self.make(DeniedRouter(lambda *a: None), attempt_not_started=AdapterDenied)
        result = self.call(q)
        self.assertEqual(result["outcome"], "not_started")
        self.assertEqual(result["code"], "budget_exhausted")
        self.assertEqual(q.spent["bees"], 0)
        self.assertEqual(q.state.data["attempts"], {})

    def test_probe_and_worker_both_consume_budget_and_an_inadequate_cap_starts_neither(self):
        calls = []
        class ProbeRouter(FakeRouter):
            pending = True
            def describe(self, role, name, *, local=False):
                return dict(super().describe(role, name, local=local),
                            probe_key="fixture-probe", probe_required=self.pending)
            def primary(router, role, name):
                base = super().primary(role, name)
                def probed(role, name, task, folder, *, schema, before_start):
                    if router.pending:
                        aid = before_start("network_probe")
                        calls.append("probe")
                        before_start.finished(aid, {"ok": True, "outcome": "ok", "output": {}})
                        router.pending = False
                    calls.append("worker")
                    return base(role, name, task, folder, schema=schema, before_start=before_start)
                return probed
        router = ProbeRouter(lambda *a: {"ok": True, "output": {}})
        blocked = self.make(router, max_bees=1)
        self.assertEqual(self.call(blocked)["outcome"], "not_started")
        self.assertEqual(calls, [])
        q = self.make(router, max_bees=2)
        answer = self.call(q)
        self.assertTrue(answer["ok"], answer)
        self.assertEqual(q.spent["bees"], 2)
        self.assertEqual(calls, ["probe", "worker"])
        self.assertEqual([a["kind"] for a in q.state.data["attempts"].values()], ["network_probe", "bee"])


class FrozenPlanTests(unittest.TestCase):
    def setUp(self):
        from unittest.mock import patch
        self.temp = tempfile.TemporaryDirectory(prefix="hive-frozen-plan-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.inputs = self.root / "inputs"
        self.inputs.mkdir()
        (self.inputs / "greet").write_bytes(b"owned inert fixture")
        self.out = self.root / "run"
        for target, result in (("ensure_confinement", None), ("syntax", (True, ""))):
            stub = patch.object(queen.Build, target, return_value=result)
            stub.start()
            self.addCleanup(stub.stop)

    def provider(self, *args):
        return {"ok": True, "output": {"modules": [], "skipped": [
            {"entry": hex(entry), "reason": "fixture library"} for entry in (0x1000, 0x1040, 0x1080)]}}

    def make(self, provider=None, **kwargs):
        return make_queen(engine=FakeEngine(self.inputs), out=self.out, bees=provider or self.provider, **kwargs)

    def run_quietly(self, q):
        with contextlib.redirect_stdout(io.StringIO()):
            return q.run()

    def test_fresh_instance_reuses_frozen_plan_without_planner_or_budget_reset(self):
        first = self.make(max_bees=30)
        self.run_quietly(first)
        self.assertEqual(first.planning.calls, 1)
        def forbidden(*args):
            self.fail("resuming a frozen plan must not invoke a bee")
        second = self.make(forbidden)
        self.run_quietly(second)
        self.assertEqual(second.planning.calls, 0)
        self.assertEqual(second.plan_bundle["plan_id"], first.plan_bundle["plan_id"])
        self.assertEqual(second.spent["bees"], 1)
        self.assertEqual(second.max_bees, 30)

    def test_partial_planning_resume_passes_saved_content_and_skips_completed_group(self):
        class PartialPlanning(FakePlanning):
            def plan(backend, program_map, partitioned, *, out, invoke, saved, **kwargs):
                backend.validate_saved(out, saved)
                progress = saved or {"schema": "hive.planning-progress/1", "bindings": {
                    "map_sha256": queen.digest(program_map)}, "groups": {}, "resolutions": {}}
                path = Path(out) / "plan/progress.json"
                queen.write_file(path, queen.canonical(progress))
                for index, row in enumerate(program_map["functions"], 1):
                    gid = f"g{index:04d}"
                    if gid in progress["groups"]:
                        continue
                    answer = invoke("planner", "planner-" + gid, "Plan " + row["hex"],
                                    Path(out) / "plan/groups" / gid)
                    if not answer["ok"]:
                        raise FakePlanningError(answer["outcome"], answer,
                                                {"progress_path": "plan/progress.json"})
                    progress["groups"][gid] = answer
                    queen.write_file(path, queen.canonical(progress))
                answers = list(progress["groups"].values())
                aggregate = copy.deepcopy(answers[-1])
                aggregate["output"] = {"modules": [], "skipped": [
                    item for answer in answers for item in answer["output"]["skipped"]]}
                aggregate["provenance"]["prior_attempt_ids"] = [
                    answer["provenance"]["attempt_id"] for answer in answers[:-1]]
                return super().plan(program_map, partitioned, out=out, saved=saved,
                                    invoke=lambda *args, **kw: aggregate, **kwargs)

        calls = []
        def primary(role, name, task, folder):
            calls.append(("primary", name))
            if name == "planner-g0002":
                return {"ok": False, "refused": True, "error": "fixture refusal"}
            return {"ok": True, "output": {"modules": [], "skipped": [
                {"entry": task.split()[-1], "reason": "fixture library"}]}}
        def local(role, name, task, folder):
            calls.append(("local", name))
            return {"ok": True, "output": {"modules": [], "skipped": [
                {"entry": task.split()[-1], "reason": "fixture library"}]}}

        first = self.make(primary, planning=PartialPlanning())
        with self.assertRaises(queen.ProviderRefused):
            self.run_quietly(first)
        saved = json.loads((self.out / "plan/progress.json").read_bytes())
        self.assertEqual(list(saved["groups"]), ["g0001"])
        completed = copy.deepcopy(saved["groups"]["g0001"])
        second = self.make(FakeRouter(primary, fallback=local, scope="bee", names=["planner-g0002"]),
                           planning=PartialPlanning(), resume_refused=True)
        self.run_quietly(second)
        self.assertIsNotNone(second.plan_bundle)
        self.assertEqual(calls, [("primary", "planner-g0001"), ("primary", "planner-g0002"),
                                 ("local", "planner-g0002"), ("primary", "planner-g0003")])
        self.assertEqual(json.loads((self.out / "plan/progress.json").read_bytes())["groups"]["g0001"], completed)
        self.assertEqual(second.spent["bees"], 4)
        self.assertFalse(second.state.data["unresolved_refusals"])

    def test_planning_fake_rejects_a_path_wrapper_as_saved_content(self):
        with self.assertRaisesRegex(FakePlanningError, "resume_mismatch"):
            FakePlanning().plan({}, {}, out=self.out, invoke=None, language="c", max_functions=12,
                                max_prompt_bytes=65536, interface_rounds=2,
                                saved={"progress_path": "plan/progress.json"})

    def test_planning_resume_rejects_escaped_or_linked_progress_before_invoking(self):
        outside = self.root / "outside.json"
        outside.write_text('{}')
        for index, relative in enumerate(("../outside.json", "plan/../../outside.json",
                                           str(outside), "plan/progress.json")):
            with self.subTest(path=relative):
                self.out = self.root / f"run-{index}"
                (self.out / "plan").mkdir(parents=True)
                if relative == "plan/progress.json":
                    (self.out / relative).symlink_to(outside)
                q = self.make()
                q._ensure_state()
                q.state.append("planning_progress", {"progress_path": relative})
                with self.assertRaisesRegex(queen.HiveError, "plan path"):
                    self.run_quietly(q)
                self.assertEqual(q.planning.calls, 0)
                self.assertEqual(q.spent["bees"], 0)

    def test_changed_input_stops_before_any_new_attempt(self):
        self.run_quietly(self.make())
        (self.inputs / "greet").write_bytes(b"different owned input")
        second = self.make()
        with self.assertRaisesRegex(queen.HiveError, "input, map"):
            self.run_quietly(second)
        self.assertEqual(second.spent["bees"], 1)
        self.assertFalse(json.loads((self.out / "result.json").read_text())["verdict"].startswith("accepted"))

    def test_changed_plan_artifact_is_never_replanned_silently(self):
        self.run_quietly(self.make())
        (self.out / "plan/contract.h").write_text("changed contract")
        second = self.make()
        with self.assertRaisesRegex(queen.HiveError, "plan artifact hash"):
            self.run_quietly(second)
        self.assertEqual(second.planning.calls, 0)
        self.assertEqual(second.spent["bees"], 1)

    def test_inadequate_planning_budget_starts_no_bee_and_exposes_forecast(self):
        q = self.make(max_bees=0)
        result = self.run_quietly(q)
        self.assertEqual(result["verdict"], "not started")
        self.assertEqual(result["stop_reason"], "budget_insufficient")
        self.assertEqual(result["spent"]["bees"], 0)
        self.assertEqual(result["forecast"]["remaining_min"], 1)

    def test_second_workspace_writer_is_refused(self):
        with queen.workspace_lock(self.out / ".hive"):
            with self.assertRaisesRegex(queen.HiveError, "another queen"):
                self.run_quietly(self.make())

    def test_legacy_workspace_has_no_implicit_verified_migration(self):
        self.out.mkdir()
        (self.out / "result.json").write_text('{"verdict":"accepted"}')
        with self.assertRaisesRegex(queen.HiveError, "legacy workspace"):
            self.run_quietly(self.make())


if __name__ == "__main__":
    unittest.main()
