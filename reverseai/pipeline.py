"""Pipeline: snapshot -> plan -> gateway -> conclude -> review."""

from concurrent.futures import ThreadPoolExecutor
import copy
import inspect

from reverseai import intake, queries, review
from reverseai.analysts import capability, code, structural, query
from reverseai.contract import AnalysisResult, AnalysisTask, Budget, ContractError, content_id
from reverseai.gateway import Gateway
from reverseai.report import Analysis
from reverseai.tools import apk, dex, js, strings, structure

ANALYSTS = (structural, capability, code)
TOOLS = (structure.TOOL, strings.TOOL, apk.TOOL, dex.TOOL, js.TOOL)  # apk and dex read packages; js reads JavaScript applications
# LIEF and YARA-X start a container per operation (45 s limit each), so a run that includes one gets more time.
CONTAINED_BUDGET = Budget(max_wall_seconds=150)
# Ghidra's single import-and-analyse run may take its full 240 s profile; the code task allows 300 s.
GHIDRA_BUDGET = Budget(max_wall_seconds=330)
# JADX's fixed 120 s worker profile plus host work; the query task allows 150 s.
JADX_BUDGET = Budget(max_wall_seconds=180)
ANDROID_QUERY_BUDGET = Budget(max_wall_seconds=120)
# Every jshints pattern over up to 128 MiB of JavaScript (measured at 68 to 94 s)
JAVASCRIPT_QUERY_BUDGET = Budget(max_wall_seconds=150)


def _budget(tools):
    if any(spec.contained and spec.ref.name == "ghidra" for spec in tools):
        return GHIDRA_BUDGET
    return CONTAINED_BUDGET if any(spec.contained for spec in tools) else Budget()


def _plan(analyst, ref, tools):
    """Analysts that can use optional tools say so with a tools parameter; the others are called without it.

    An optional analyst returns None when its tool is absent and then takes no part in the run.
    """
    if "tools" in inspect.signature(analyst.plan).parameters:
        return analyst.plan(ref, tools=tools)
    return analyst.plan(ref)


def analyze_bytes(data, ref, *, budget=None, analysts=ANALYSTS, tools=TOOLS):
    """Analyse bytes that intake already froze; analysts never see a path."""
    budget = budget or _budget(tools)
    gateway = Gateway(tools, budget)
    planned = [(analyst, _plan(analyst, ref, tools)) for analyst in analysts]
    planned = [(analyst, task) for analyst, task in planned if task is not None]
    analysts, tasks = [analyst for analyst, _ in planned], [task for _, task in planned]
    with ThreadPoolExecutor(max_workers=budget.max_concurrency) as pool:
        gathered = list(pool.map(lambda task: gateway.run(task, data), tasks))
    results = []
    for analyst, task, partial in zip(analysts, tasks, gathered):
        # The reviewer, not the analyst, decides whether partial evidence is enough. Analysts get
        # copies: the result keeps the gateway's records, so an analyst cannot alter them.
        findings = analyst.conclude(task, copy.deepcopy(partial.evidence)) if partial.evidence else ()
        results.append(AnalysisResult(task.id, task.role, partial.status, partial.evidence, tuple(findings), partial.errors))
    specs = {spec.ref.name: spec for spec in tools}
    verdicts = review.review(data, ref, results, specs)
    ordered = sorted(specs.values(), key=lambda spec: spec.ref.name)
    runtimes = tuple((spec.ref.name, dict(spec.runtime)) for spec in ordered if spec.contained)
    return Analysis(ref, tuple(spec.ref for spec in ordered), tuple(results), tuple(verdicts), runtimes)


def analyze_path(path, *, budget=None, tools=TOOLS):
    data, ref = intake.snapshot(path)
    return analyze_bytes(data, ref, budget=budget, tools=tools)


def query_bytes(data, ref, name, args, tools=TOOLS):
    """One typed query on frozen bytes, through the same gateway and reviewer."""
    spec, checked = queries.resolve(name, args)
    tools = tuple(tools)
    registered = {operation: tool for tool in tools for operation in tool.operations}
    requests = spec.requests(checked, available=registered)
    if any(request.operation not in registered for request in requests):
        raise ContractError("Query operation unavailable")
    if spec.role == "code" and any(registered[request.operation].ref != query.REFS["ghidra"] for request in requests):
        raise ContractError("Query Ghidra version unavailable")
    with_jadx = any(request.operation == "jadx.method" for request in requests)
    if with_jadx and registered["jadx.method"].ref != query.REFS["jadx"]:
        raise ContractError("Query JADX version unavailable")
    with_jsparser = any(request.operation == "jsparser.syntax" for request in requests)
    if with_jsparser and registered["jsparser.syntax"].ref != query.REFS["jsparser"]:
        raise ContractError("Query JavaScript parser version unavailable")
    with_android = any(request.operation.startswith(("apk.", "dex.")) for request in requests)
    with_javascript = any(request.operation.startswith(("js.", "jsparser.")) for request in requests)
    budget = (GHIDRA_BUDGET if spec.role == "code" else JADX_BUDGET if with_jadx
              else ANDROID_QUERY_BUDGET if with_android else JAVASCRIPT_QUERY_BUDGET if with_javascript else Budget())
    task_seconds = 300 if spec.role == "code" else 150 if with_jadx else budget.max_wall_seconds
    task = AnalysisTask(content_id("tk", {"input": ref.sha256, "query": name, "args": checked}), spec.role, ref,
                        requests, Budget(max_concurrency=1, max_wall_seconds=task_seconds))
    partial = Gateway(tools, budget).run(task, data)
    findings = query.conclude(task, copy.deepcopy(partial.evidence)) if partial.evidence else ()
    result = AnalysisResult(task.id, task.role, partial.status, partial.evidence, tuple(findings), partial.errors)
    registry = {tool.ref.name: tool for tool in tools}
    verdicts = review.review(data, ref, (result,), registry)
    ordered = sorted(registry.values(), key=lambda tool: tool.ref.name)
    runtimes = tuple((tool.ref.name, dict(tool.runtime)) for tool in ordered if tool.contained)
    return Analysis(ref, tuple(tool.ref for tool in ordered), (result,), verdicts, runtimes,
                    {"name": name, "args": copy.deepcopy(checked)})
