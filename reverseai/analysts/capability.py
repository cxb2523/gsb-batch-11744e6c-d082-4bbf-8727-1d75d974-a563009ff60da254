"""A deterministic capability analyst: string hints and verified signature matches."""

from reverseai.contract import (
    MAX_EVIDENCE_PER_FINDING, AnalysisTask, Budget, InputRef, OperationRequest,
    content_id, make_finding,
)
from reverseai.tools.strings import RULE_CATEGORIES, TOOL
from reverseai.tools.structure import REF as STRUCTURE_REF
from reverseai.tools.yarax_tool import REF as YARAX_REF


def plan(input: InputRef, *, tools=()) -> AnalysisTask:
    operations = (OperationRequest("strings.extract"), OperationRequest("strings.indicators"),
                  OperationRequest("structure.imports"))
    identity = {"input": input.sha256, "role": "capability"}
    budget = Budget(max_operations=3, max_concurrency=1)
    if any(tool.ref == YARAX_REF for tool in tools):
        operations += (OperationRequest("yarax.matches", {"max_matches": 64}),)
        budget = Budget(max_operations=4, max_concurrency=1, max_wall_seconds=60)
    identity["operations"] = [request.operation for request in operations]
    return AnalysisTask(
        content_id("tk", identity),
        "capability", input,
        operations, budget,
    )


def conclude(task, evidence):
    if task.role != "capability":
        return ()
    categories, urls = {}, {}
    for item in sorted(evidence, key=lambda item: item.id):
        if (item.input_sha256 != task.input.sha256 or item.tool != TOOL.ref
                or item.operation != "strings.indicators" or not item.location.within(task.input.size)):
            continue
        rule = item.observation.get("rule")
        category = item.observation.get("category")
        matched = item.observation.get("match")
        if (not isinstance(rule, str) or RULE_CATEGORIES.get(rule) != category
                or not isinstance(matched, str) or not matched):
            continue
        # A representative per rule supports the rule set; repeated occurrences
        # do not consume the contract's bounded evidence list.
        categories.setdefault(category, {}).setdefault(rule, item.id)
        if rule == "url":
            urls.setdefault(matched, item.id)
    findings = []
    for category, rules in sorted(categories.items()):
        findings.append(make_finding(
            "capability", f"String indicators suggest {category.replace('_', ' ')} capabilities.",
            "capability." + category, sorted(rules), rules.values(), confidence="inferred",
        ))
    if urls:
        # Report only the URLs actually supported by this bounded set of citations.
        selected = sorted(urls)[:MAX_EVIDENCE_PER_FINDING]
        findings.append(make_finding(
            "capability", "URL strings observed in the input.", "strings.urls",
            selected, (urls[url] for url in selected), confidence="observed",
        ))
    matches = [item for item in evidence if item.input_sha256 == task.input.sha256 and item.tool == YARAX_REF
               and item.operation == "yarax.matches" and item.location.within(task.input.size)
               and isinstance(item.observation.get("rule"), str) and item.observation["rule"]]
    if matches:
        findings.append(make_finding(
            "capability", "Reviewed signature patterns observed in the input.", "signatures.rule_matches",
            sorted({item.observation["rule"] for item in matches}), (item.id for item in matches), confidence="observed",
        ))
    imported = {"library": [], "symbols": []}
    for item in sorted(evidence, key=lambda item: (item.location.offset, item.location.length, item.id)):
        if (item.input_sha256 != task.input.sha256 or item.tool != STRUCTURE_REF
                or item.operation != "structure.imports" or not item.location.within(task.input.size)):
            continue
        value = item.observation
        kind = value.get("kind")
        if kind == "library":
            names = [value.get("name")]
        elif kind == "symbols" and isinstance(value.get("names"), list) and 0 < len(value["names"]) <= 32:
            names = value["names"]
        else:
            continue
        if all(isinstance(name, str) and 0 < len(name) <= 128 and all(0x20 <= ord(c) < 0x7F for c in name) for name in names):
            imported[kind].append(item)
    for kind, key in (("library", "libraries"), ("symbols", "symbols")):
        selected = imported[kind][:MAX_EVIDENCE_PER_FINDING]
        if selected:
            names = [item.observation["name"] for item in selected] if kind == "library" else [
                name for item in selected for name in item.observation["names"]]
            findings.append(make_finding(
                "capability", f"The file declares imported {key}.", "imports." + key,
                sorted(set(names)), (item.id for item in selected), confidence="observed",
            ))
    return tuple(findings)
