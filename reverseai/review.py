"""Evidence reviewer: rule 6 of docs/contract.md, re-checked against the frozen bytes.

Analyst output is untrusted. Reasons name evidence IDs only, never input bytes.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from reverseai import claims
from reverseai.contract import (
    MAX_CHILD_RATIO, MAX_STREAM_BYTES, AnalysisResult, ContractError, InputRef, ReviewVerdict, ToolSpec, canonical_json,
    check_artifact, evidence_intact, finding_intact, inflate_stream, materialize, sha256_hex,
)

MAX_REVIEW_CHILD_BYTES = 128 * 1024 * 1024  # distinct child artifacts one review re-materializes


class _Children:
    """Child artifacts re-materialized from the input once per review, within a byte budget."""

    def __init__(self, data):
        self.data, self.cache, self.spent = data, {}, 0
        self.streams, self.stream_spent = {}, 0  # each gzip stream inflated once, its bound charged first

    def get(self, artifact):
        key = canonical_json(artifact)
        if key not in self.cache:
            try:
                check_artifact(artifact)
            except ContractError:
                self.cache[key] = None
            else:
                # Charged before inflating, so failed attempts spend the budget too.
                if self.spent + artifact["size"] > MAX_REVIEW_CHILD_BYTES:
                    return None, "child artifacts exceed the review budget"
                self.spent += artifact["size"]
                if artifact["method"] == 1:
                    stream = (artifact["data_offset"], artifact["compressed_size"])
                    if stream not in self.streams:
                        bound = min(MAX_STREAM_BYTES, MAX_CHILD_RATIO * stream[1])
                        if self.stream_spent + bound > MAX_STREAM_BYTES:
                            return None, "gzip streams exceed the review budget"
                        self.stream_spent += bound
                        try:
                            self.streams[stream] = inflate_stream(self.data, *stream)
                        except ContractError:
                            self.streams[stream] = None
                    if self.streams[stream] is None:
                        self.cache[key] = None
                        return None, "child artifact does not match the input"
                try:
                    self.cache[key] = materialize(self.data, artifact, streams=self.streams)
                except ContractError:
                    self.cache[key] = None
        child = self.cache[key]
        return (child, None) if child is not None else (None, "child artifact does not match the input")


def _evidence_problems(evidence, data, data_sha256, input, tools, children):
    if not evidence_intact(evidence):
        return ["record does not match its ID"]
    problems = []
    if len(data) != input.size:
        problems.append("input size mismatch")
    if evidence.input_sha256 != data_sha256 or evidence.input_sha256 != input.sha256:
        problems.append("input hash mismatch")
    spec = tools.get(evidence.tool.name)
    if not isinstance(spec, ToolSpec) or spec.ref != evidence.tool:
        problems.append("tool name or version not registered")
    elif evidence.operation not in spec.operations:
        problems.append("operation not registered")
    location, target = evidence.location, data
    if evidence.artifact is not None:
        target, problem = children.get(evidence.artifact)
        if problem:
            problems.append(problem)
            return problems
    if not location.within(len(target)):
        problems.append("location outside the input")
    elif sha256_hex(bytes(target[location.offset:location.offset + location.length])) != evidence.excerpt_sha256:
        problems.append("excerpt hash mismatch")
    return problems


def _content(finding):
    return (finding.role, finding.claim, finding.claim_key, canonical_json(finding.value), finding.evidence_ids, finding.confidence)


def review(data: bytes, input: InputRef, results: Iterable[AnalysisResult], tools: Mapping[str, ToolSpec]) -> tuple:
    """One verdict per finding ID, sorted; tools are ToolSpecs keyed by tool name."""
    data = bytes(data)
    data_sha256 = sha256_hex(data)
    findings, problems, derived, tasks = {}, {}, set(), {}
    children = _Children(data)
    for result in results:
        own = {}  # citations resolve only inside the finding's own result
        for item in result.evidence:
            own.setdefault(item.id, item)
        for finding in result.findings:
            first = findings.setdefault(finding.id, finding)
            tasks.setdefault(finding.id, set()).add(result.task_id)
            reasons = problems.setdefault(finding.id, [])
            if finding.claim_key in claims.DERIVED_CLAIMS:
                derived.add(finding.id)
            if not finding_intact(finding):
                reasons.append("finding does not match its ID")
                continue
            if first is not finding and finding_intact(first) and _content(finding) != _content(first):
                reasons.append("finding ID reused for different content")
            local, cited = [] if finding.evidence_ids else ["finding cites no evidence"], []
            for evidence_id in finding.evidence_ids:
                item = own.get(evidence_id)
                if item is None:
                    local.append(f"{evidence_id}: evidence missing")
                    continue
                local.extend(f"{evidence_id}: {problem}" for problem in _evidence_problems(item, data, data_sha256, input, tools, children))
                cited.append(item)
                spec = tools.get(item.tool.name)
                if isinstance(spec, ToolSpec) and getattr(spec.operations.get(item.operation), "derived", False):
                    derived.add(finding.id)
            # Provenance first; then the claim must follow from what it cites.
            reasons.extend(local or claims.check(finding, cited))
    # Only verified findings contradict each other: neither an unsupported nor a derived claim can cancel a verified one.
    # Pages of one list contradict only by a different total or a different row at the same index, within
    # the task (one query and its arguments) that produced them; different filters give different lists. A claim the
    # reviewer checks against its own cited bytes (bytes.read) cannot contradict another one.
    values, pages = {}, {}
    def families_of(finding_id, finding):
        # A finding produced by several tasks joins each task's list.
        return [(finding.claim_key, canonical_json(finding.value.get("to")), task) for task in sorted(tasks[finding_id])]
    for finding_id, finding in findings.items():
        if (problems[finding_id] or finding_id in derived or finding.claim_key in claims.SELF_CHECKED_CLAIMS
                or finding.claim_key in claims.SUBSET_CLAIMS):
            continue
        if finding.claim_key in claims.PAGE_CLAIMS:
            for key in families_of(finding_id, finding):
                family = pages.setdefault(key, ({}, set()))
                family[1].add(finding.value["total"])
                for index, row in enumerate(finding.value["rows"], finding.value["start"]):
                    family[0].setdefault(index, set()).add(canonical_json(row))
        else:
            values.setdefault(finding.claim_key, set()).add(canonical_json(finding.value))
    clashing = {key for key, (rows, totals) in pages.items() if len(totals) > 1 or any(len(r) > 1 for r in rows.values())}
    verdicts = []
    for finding_id in sorted(findings):
        finding, reasons = findings[finding_id], tuple(dict.fromkeys(problems[finding_id]))
        if reasons:
            verdicts.append(ReviewVerdict(finding_id, "unsupported", reasons))
        elif finding_id in derived:
            verdicts.append(ReviewVerdict(finding_id, "derived", ("cites a derived operation: the tool's reading, not verified against the bytes",)))
        elif finding.claim_key in claims.SELF_CHECKED_CLAIMS or finding.claim_key in claims.SUBSET_CLAIMS:
            verdicts.append(ReviewVerdict(finding_id, "supported"))
        elif finding.claim_key in claims.PAGE_CLAIMS:
            if any(key in clashing for key in families_of(finding_id, finding)):
                verdicts.append(ReviewVerdict(finding_id, "contradicted", (f"another page of {finding.claim_key} gives a different total or row",)))
            else:
                verdicts.append(ReviewVerdict(finding_id, "supported"))
        elif len(values[finding.claim_key]) > 1:
            verdicts.append(ReviewVerdict(finding_id, "contradicted", (f"another finding gives {finding.claim_key} a different value",)))
        else:
            verdicts.append(ReviewVerdict(finding_id, "supported"))
    return tuple(verdicts)
