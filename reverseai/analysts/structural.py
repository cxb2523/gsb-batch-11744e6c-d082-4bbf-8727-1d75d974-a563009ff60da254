"""Structural analyst: container format, machine and section layout from structure evidence."""

from __future__ import annotations

from reverseai.contract import (
    AnalysisTask, Budget, InputRef, OperationRequest, canonical_json, content_id, make_finding,
)

ROLE = "structural"
MAX_SECTIONS = 64
FORMAT_NAMES = {"elf": "an ELF", "pe": "a PE", "macho": "a Mach-O", "macho-universal": "a universal Mach-O",
                "zip": "a ZIP", "unknown": "an unrecognized"}


def plan(input: InputRef, *, tools=()) -> AnalysisTask:
    operations = (OperationRequest("structure.identify"), OperationRequest("structure.headers"),
                  OperationRequest("structure.sections", {"max_sections": MAX_SECTIONS}))
    identity = {"input": input.sha256, "role": ROLE}
    budget = Budget(max_concurrency=1)
    if any(tool.ref.name == "lief" for tool in tools):
        operations += (OperationRequest("lief.headers"), OperationRequest("lief.sections", {"max_sections": MAX_SECTIONS}))
        identity["operations"] = [op.operation for op in operations]
        budget = Budget(max_concurrency=1, max_wall_seconds=120)  # two contained runs, 45 s limit each
    return AnalysisTask(
        id=content_id("tk", identity),
        role=ROLE,
        input=input,
        operations=operations,
        budget=budget,
    )


def _label(value):
    """A format or machine label short enough for a claim; anything else is not a label."""
    return isinstance(value, str) and 0 < len(value) <= 32


def _grouped(items):
    """{canonical value: (value, [evidence IDs])}: one finding per distinct value, so disagreement stays visible."""
    groups = {}
    for value, evidence in items:
        groups.setdefault(canonical_json(value), (value, []))[1].append(evidence.id)
    return groups.values()


def conclude(task: AnalysisTask, evidence) -> tuple:
    own = [item for item in evidence if item.input_sha256 == task.input.sha256 and item.tool.name in ("structure", "lief")]
    by_operation = {}
    for item in own:
        by_operation.setdefault(item.operation, []).append(item)
    findings = []
    lief_headers = by_operation.get("lief.headers", ())
    formats = (*by_operation.get("structure.identify", ()), *lief_headers)
    for value, ids in _grouped((item.observation.get("format"), item) for item in formats
                                if _label(item.observation.get("format"))):
        findings.append(make_finding(ROLE, f"The input is {FORMAT_NAMES.get(value, 'an unrecognized')} file.",
                                     "format.container", value, ids))
    headers = (*by_operation.get("structure.headers", ()), *lief_headers)
    for value, ids in _grouped((item.observation.get("machine_name"), item) for item in headers
                                if _label(item.observation.get("machine_name")) and item.observation.get("machine_name") != "unknown"):
        findings.append(make_finding(ROLE, f"The header names the {value} machine.", "format.machine", value, ids))
    counts = []
    for item in headers:
        count = item.observation.get("shnum", item.observation.get("number_of_sections"))
        if count == 0 and item.observation.get("shoff"):
            continue  # ELF extended numbering: the header does not hold the count
        if type(count) is int:
            counts.append((count, item))
    for value, ids in _grouped(counts):
        findings.append(make_finding(ROLE, f"The header declares {value} sections.", "format.section_count", value, ids))
    risky = [item for item in by_operation.get("structure.sections", ())
             if item.observation.get("writable") is True and item.observation.get("executable") is True]
    if risky:
        names = sorted({str(item.observation.get("name", "")) for item in risky})
        findings.append(make_finding(ROLE, "Some sections are both writable and executable.",
                                     "sections.writable_executable", names, [item.id for item in risky], confidence="inferred"))
    risky_indices = [item for item in by_operation.get("lief.sections", ())
                     if item.observation.get("writable") is True and item.observation.get("executable") is True
                     and type(item.observation.get("index")) is int and item.observation["index"] >= 0]
    if risky_indices:
        indices = sorted({item.observation["index"] for item in risky_indices})
        findings.append(make_finding(ROLE, "Some sections are both writable and executable.",
                                     "sections.writable_executable_indices", indices, [item.id for item in risky_indices],
                                     confidence="inferred"))
    return tuple(sorted(findings, key=lambda finding: (finding.claim_key, finding.id)))
