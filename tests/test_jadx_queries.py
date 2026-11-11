"""Query/CLI wiring against real APK bytes and a contained JADX stand-in."""

import contextlib
import copy
from dataclasses import replace
import importlib
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from reverseai import cli, pipeline, queries, report
from reverseai.analysts import query
from reverseai.contained import ContainedError
from reverseai.contract import (
    AnalysisTask, ArgSpec, ContractError, InputRef, Location, Observation, OperationRequest,
    OperationSpec, ToolRef, ToolSpec, make_evidence, sha256_hex,
)
from reverseai.gateway import Gateway
from tests import fixtures_apk


JADX_REF = ToolRef("jadx", "1.5.6-r1")
JADX_IMAGE = "sha256:" + "a" * 64
MISSING_JAVA = "Decompiled Java requires --with-jadx and the locally built pinned JADX image."
SECRET = "/private/sensitive/worker.log SAMPLE_CONTENT_DO_NOT_LEAK"
BASE_ARGS = {"member": "classes.dex", "class": fixtures_apk.HELPER,
             "method": "compute", "prototype": "(II)I"}
JADX_SCHEMA = {
    "member": ArgSpec("identity", 0, 255, default=""),
    "class": ArgSpec("identity", 1, 255),
    "method": ArgSpec("identity", 1, 255),
    "prototype": ArgSpec("identity", 0, 255, default=""),
    "start": ArgSpec("int", 0, 1048575, default=0),
    "max_chars": ArgSpec("int", 64, 2048, default=1024),
}


def fake_jadx(layout, calls, *, failure=None):
    """Real child artifacts and method instruction ranges; no worker import/run."""
    def handler(data, args):
        calls.append(dict(args))
        if failure is not None:
            raise failure
        rows = []
        for member in layout["members"]:
            name = member["name"]
            if name not in layout["dex"] or args["member"] not in ("", name):
                continue
            for cls in layout["dex"][name]["classes"]:
                if cls["name"] != args["class"]:
                    continue
                for method in cls["methods"]:
                    if method["name"] != args["method"] or args["prototype"] not in ("", method["prototype"]):
                        continue
                    if not method["code_offset"]:
                        continue
                    text = ("public static int " + method["name"] + "(int a, int b) {\n"
                            "\t// Stand-in decompiler text.\n\treturn a + b;\n}\n") * 3
                    value = {"kind": "java", "dex": name, "class": cls["name"], "name": method["name"],
                             "prototype": method["prototype"], "form": "java", "start": args["start"],
                             "total": len(text), "text": text[args["start"]:args["start"] + args["max_chars"]]}
                    rows.append(Observation(Location(method["code_offset"] + 16, method["code_units"] * 2),
                                            value, copy.deepcopy(member["artifact"])))
        return rows

    operation = OperationSpec("jadx.method", JADX_SCHEMA, handler, max_observations=16, derived=True)
    return ToolSpec(JADX_REF, {"jadx.method": operation}, contained=True,
                    runtime={"image": JADX_IMAGE, "platform": "linux/arm64"})


class JadxQuerySurfaceTests(unittest.TestCase):
    def setUp(self):
        self.data, self.layout = fixtures_apk.apk_basic()
        self.ref = InputRef(sha256_hex(self.data), len(self.data), "fixture.apk")
        self.calls = []
        self.jadx = fake_jadx(self.layout, self.calls)

    def query(self, args=None, *, tools=None):
        try:
            return pipeline.query_bytes(self.data, self.ref, "inspect_android_method",
                                        dict(BASE_ARGS if args is None else args),
                                        tools=pipeline.TOOLS + (self.jadx,) if tools is None else tools)
        except ContractError as error:
            self.fail("The Android method query refused its contracted arguments: " + str(error))

    def test_registered_jadx_routes_identity_selectors_and_default_java_page(self):
        analysis = self.query()
        self.assertEqual(self.calls, [{**BASE_ARGS, "start": 0, "max_chars": 1024}])
        self.assertEqual(analysis.results[0].role, "structural")
        self.assertEqual({e.operation for e in analysis.results[0].evidence},
                         {"dex.methods", "jadx.method"})
        self.assertNotIn(MISSING_JAVA, report.to_markdown(analysis))

    def test_wrong_jadx_version_is_refused_before_any_operation_runs(self):
        wrong = replace(self.jadx, ref=ToolRef('jadx', '1.5.6-r2'))
        with patch.object(Gateway, 'run', side_effect=AssertionError('operation ran')) as run:
            with self.assertRaisesRegex(ContractError, '^Query JADX version unavailable$'):
                pipeline.query_bytes(self.data, self.ref, 'inspect_android_method', BASE_ARGS,
                                     tools=pipeline.TOOLS + (wrong,))
            run.assert_not_called()

    def test_java_page_is_independent_of_the_dex_reference_page(self):
        analysis = self.query({**BASE_ARGS, "start": 1, "limit": 1, "java_start": 17, "max_chars": 64})
        self.assertEqual(self.calls, [{**BASE_ARGS, "start": 17, "max_chars": 64}])
        item, = [e for e in analysis.results[0].evidence if e.operation == "jadx.method"]
        self.assertEqual(item.observation["start"], 17)
        self.assertEqual(len(item.observation["text"]), 64)
        self.assertEqual(analysis.query["args"]["start"], 1)

    def test_java_bounds_are_closed_and_cli_integers_share_the_schema(self):
        good = {**BASE_ARGS, "java_start": 1048575, "max_chars": 2048}
        try:
            checked = queries.parse_args("inspect_android_method", [key + "=" + str(value) for key, value in good.items()])
        except ContractError as error:
            self.fail("The CLI schema refused the contracted Java page arguments: " + str(error))
        self.assertEqual((checked["java_start"], checked["max_chars"]), (1048575, 2048))
        for key, value in (("java_start", -1), ("java_start", 1048576), ("java_start", True),
                           ("max_chars", 63), ("max_chars", 2049), ("max_chars", True)):
            with self.subTest(key=key, value=value), self.assertRaises(ContractError):
                queries.resolve("inspect_android_method", {**BASE_ARGS, key: value})

    def test_each_java_observation_yields_only_its_own_inferred_derived_finding(self):
        analysis = self.query({"class": fixtures_apk.MAIN, "method": "helper"})
        result, = analysis.results
        self.assertEqual(result.status, "ok", result.errors)
        items = [e for e in result.evidence if e.operation == "jadx.method"]
        findings = [f for f in result.findings if f.claim_key == "android.java"]
        self.assertEqual(len(items), 2)
        self.assertEqual(len(findings), 2)
        by_id = {e.id: e for e in items}
        judged = {v.finding_id: v.status for v in analysis.verdicts}
        for finding in findings:
            self.assertEqual(len(finding.evidence_ids), 1)
            item = by_id[finding.evidence_ids[0]]
            self.assertEqual(finding.value, {key: value for key, value in item.observation.items() if key != "kind"})
            self.assertEqual((finding.role, finding.confidence, judged[finding.id]), ("structural", "inferred", "derived"))
        self.assertEqual({f.evidence_ids[0] for f in findings}, set(by_id))
        self.assertTrue([f for f in result.findings if f.claim_key == "android.methods"])
        for finding in result.findings:
            if finding.claim_key != "android.java":
                self.assertEqual(judged[finding.id], "supported")

    def test_analyst_ignores_non_java_kinds_from_jadx_method(self):
        result, = self.query().results
        good, = [item for item in result.evidence if item.operation == "jadx.method"]
        task = AnalysisTask(result.task_id, result.role, self.ref,
                            (OperationRequest("jadx.method", {}),))
        accepted = query.conclude(task, (good,))
        self.assertEqual(len(accepted), 1)
        self.assertEqual((accepted[0].claim_key, accepted[0].evidence_ids),
                         ("android.java", (good.id,)))
        for kind in ("not_java", None):
            with self.subTest(kind=kind):
                value = {**good.observation, "kind": kind}
                if kind is None:
                    del value["kind"]
                other = make_evidence(self.data, good.tool, good.operation,
                                      Observation(good.location, value, good.artifact))
                self.assertEqual(query.conclude(task, (other,)), ())
                self.assertEqual(query.conclude(task, (other, good)), accepted)

    def test_query_task_and_gateway_allow_the_fixed_120_second_worker(self):
        tasks = []
        real_run = Gateway.run

        def capture(gateway, task, data):
            tasks.append(task)
            return real_run(gateway, task, data)

        with patch.object(pipeline, "Gateway", wraps=Gateway) as factory, patch.object(Gateway, "run", capture):
            self.query()
        self.assertEqual(factory.call_args.args[1].max_wall_seconds, 180)
        self.assertEqual(len(tasks), 1)
        self.assertEqual(tasks[0].budget.max_wall_seconds, 150)
        self.assertEqual(tasks[0].role, "structural")

    def test_absent_tool_preserves_the_existing_dex_requests_and_findings(self):
        tasks = []
        real_run = Gateway.run

        def capture(gateway, task, data):
            tasks.append(task)
            return real_run(gateway, task, data)

        with patch.object(Gateway, "run", capture):
            analysis = self.query(tools=pipeline.TOOLS)
        self.assertEqual([r.operation for r in tasks[0].operations], ["dex.methods", "dex.references"])
        self.assertEqual(tasks[0].operations[0].args, {"member": "classes.dex", "class": fixtures_apk.HELPER})
        self.assertEqual(tasks[0].operations[1].args, {**BASE_ARGS, "start": 0, "limit": 128, "direction": "from"})
        self.assertEqual(analysis.results[0].role, "structural")
        self.assertEqual(self.calls, [])
        self.assertTrue(analysis.results[0].findings)
        self.assertEqual({v.status for v in analysis.verdicts}, {"supported"})

    def test_absent_tool_reports_the_java_enablement_note(self):
        analysis = self.query(tools=pipeline.TOOLS)
        self.assertIn(MISSING_JAVA, report.to_markdown(analysis))

    def test_worker_errors_are_sanitized_and_do_not_make_a_java_claim(self):
        broken = fake_jadx(self.layout, self.calls, failure=RuntimeError(SECRET))
        analysis = self.query(tools=pipeline.TOOLS + (broken,))
        result, = analysis.results
        self.assertEqual(result.status, "error")
        self.assertEqual(result.errors, ("jadx.method: RuntimeError",))
        self.assertFalse([f for f in result.findings if f.claim_key == "android.java"])
        self.assertNotIn(SECRET, report.to_json(analysis) + report.to_markdown(analysis))


class AndroidQueryIdentityTests(unittest.TestCase):
    CASES = (
        ("search_android_classes", {}, ("member",)),
        ("inspect_android_class", {"class": fixtures_apk.HELPER}, ("member", "class")),
        ("inspect_android_method", BASE_ARGS, ("member", "class", "method", "prototype")),
        ("trace_android_references", BASE_ARGS, ("member", "class", "method", "prototype")),
    )
    RAW = {"member": "classesé.dex", "class": "Ldemo/é;", "method": "méthod", "prototype": "(Ldemo/é;)V"}
    ESCAPED = {"member": r"classes\xe9.dex", "class": r"Ldemo/\xe9;", "method": r"m\xe9thod", "prototype": r"(Ldemo/\xe9;)V"}

    def test_every_android_identity_selector_accepts_escaped_ascii(self):
        for name, base, keys in self.CASES:
            for key in keys:
                with self.subTest(query=name, selector=key):
                    _, checked = queries.resolve(name, {**base, key: self.ESCAPED[key]})
                    self.assertEqual(checked[key], self.ESCAPED[key])

    def test_every_android_identity_selector_rejects_raw_unicode(self):
        for name, base, keys in self.CASES:
            for key in keys:
                with self.subTest(query=name, selector=key), self.assertRaises(ContractError):
                    queries.resolve(name, {**base, key: self.RAW[key]})


class JadxCliSurfaceTests(unittest.TestCase):
    def setUp(self):
        self.data, self.layout = fixtures_apk.apk_basic()
        self.calls = []
        self.tool = fake_jadx(self.layout, self.calls)

    def run_cli(self, *, enabled, module=None, import_error=None):
        real_import = importlib.import_module
        imports = []

        def load(name, *args, **kwargs):
            if name == "reverseai.tools.jadx_tool":
                imports.append(name)
                if import_error is not None:
                    raise import_error
                return module or SimpleNamespace(available=lambda: True, make_tool=lambda: self.tool)
            return real_import(name, *args, **kwargs)

        with tempfile.TemporaryDirectory() as temporary:
            sample, output = Path(temporary, "fixture.apk"), Path(temporary, "report")
            sample.write_bytes(self.data)
            argv = ["query", str(sample), "--query", "inspect_android_method", "--out", str(output)]
            for key, value in BASE_ARGS.items():
                argv += ["--arg", key + "=" + value]
            if enabled:
                argv += ["--with-jadx"]
            stdout, stderr = io.StringIO(), io.StringIO()
            with patch("importlib.import_module", side_effect=load), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                try:
                    status = cli.main(argv)
                except SystemExit as stopped:
                    status = stopped.code
            files = {path.name: path.read_text() for path in output.iterdir()} if output.is_dir() else {}
            return status, stdout.getvalue(), stderr.getvalue(), files, imports

    def test_no_flag_runs_without_importing_the_optional_jadx_module(self):
        status, _, stderr, files, imports = self.run_cli(enabled=False, import_error=ImportError(SECRET))
        self.assertEqual(status, 0, stderr)
        self.assertEqual(imports, [])
        self.assertEqual(self.calls, [])
        self.assertEqual(set(files), {"report.json", "report.md"})

    def test_with_jadx_registers_the_standin_and_writes_reviewed_java(self):
        status, _, stderr, files, imports = self.run_cli(enabled=True)
        self.assertEqual(status, 0, stderr)
        self.assertEqual(imports, ["reverseai.tools.jadx_tool"])
        self.assertEqual(len(self.calls), 1)
        parsed = json.loads(files["report.json"])
        java = [f for f in parsed["results"][0]["findings"] if f["claim_key"] == "android.java"]
        self.assertEqual(len(java), 1)
        self.assertEqual((java[0]["confidence"], java[0]["verdict"]), ("inferred", "derived"))
        self.assertIn("jadx 1.5.6-r1", files["report.md"])
        self.assertNotIn(MISSING_JAVA, files["report.md"])

    def test_unavailable_import_and_image_errors_are_sanitized_before_reports(self):
        cases = (
            {"module": SimpleNamespace(available=lambda: False)},
            {"import_error": ImportError(SECRET)},
            {"module": SimpleNamespace(available=lambda: True,
                                       make_tool=lambda: (_ for _ in ()).throw(ContainedError(SECRET)))},
        )
        for case in cases:
            with self.subTest(case=list(case)), \
                    patch.object(cli.intake, 'snapshot', side_effect=AssertionError('input read')) as snapshot:
                status, _, stderr, files, _ = self.run_cli(enabled=True, **case)
                self.assertEqual(status, 1, stderr)
                self.assertIn("JADX worker is unavailable", stderr)
                self.assertNotIn("Traceback", stderr)
                self.assertNotIn(SECRET, stderr)
                self.assertEqual(files, {})
                snapshot.assert_not_called()

    def test_worker_failure_is_an_analysis_error_and_writes_no_reports(self):
        self.tool = fake_jadx(self.layout, self.calls, failure=RuntimeError(SECRET))
        status, _, stderr, files, _ = self.run_cli(enabled=True)
        self.assertEqual(status, 1, stderr)
        self.assertIn("reverseai: analysis failed:", stderr)
        self.assertNotIn(SECRET, stderr)
        self.assertNotIn("Traceback", stderr)
        self.assertEqual(files, {})


if __name__ == "__main__":
    unittest.main()
