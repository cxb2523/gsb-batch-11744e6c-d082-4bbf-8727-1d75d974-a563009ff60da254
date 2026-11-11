"""Code interpretations from the optional contained Ghidra tool; never verified facts."""

from reverseai.contract import (
    MAX_EVIDENCE_PER_FINDING, AnalysisTask, Budget, OperationRequest, ToolRef,
    content_id, evidence_intact, make_finding,
)

ROLE = "code"
REF = ToolRef("ghidra", "12.1.4-r7")
OPERATION = "ghidra.analyze"


def plan(input, *, tools=()):
    if not any(tool.ref == REF and OPERATION in tool.operations and tool.operations[OPERATION].derived for tool in tools):
        return None
    return AnalysisTask(
        content_id("tk", {"input": input.sha256, "role": ROLE}), ROLE, input,
        (OperationRequest(OPERATION),),
        Budget(max_operations=1, max_concurrency=1, max_wall_seconds=300),
    )


def _address(value):
    return type(value) is int and 0 <= value < 2**64


def _ascii(value, minimum, maximum):
    return isinstance(value, str) and minimum <= len(value) <= maximum and all(" " <= c <= "~" for c in value)


def _valid(item):
    value = item.observation
    kind = value.get("kind")
    fields = {
        "function": {"kind", "index", "name", "entry", "size"},
        "pseudocode": {"kind", "index", "entry", "text", "truncated"},
        "call": {"kind", "from", "to", "to_name"},
        "assembly": {"kind", "index", "entry", "instructions", "truncated"},
        "ref": {"kind", "from", "to", "type", "to_name"},
        "string": {"kind", "address", "encoding", "text", "truncated", "from"},
    }
    if not isinstance(kind, str) or kind not in fields or set(value) != fields[kind]:
        return False
    if kind in ("function", "pseudocode", "assembly"):
        if type(value["index"]) is not int or not 0 <= value["index"] < 128 or not _address(value["entry"]):
            return False
    if kind == "pseudocode":
        return isinstance(value["text"], str) and len(value["text"]) <= 2048 and type(value["truncated"]) is bool
    if kind == "assembly":
        if (not isinstance(value["instructions"], list) or not 1 <= len(value["instructions"]) <= 64
                or type(value["truncated"]) is not bool):
            return False
        end = 0
        for row in value["instructions"]:
            if not isinstance(row, list) or len(row) != 3:
                return False
            delta, length, text = row
            if (type(delta) is not int or delta < end or type(length) is not int or not 1 <= length <= 16
                    or delta + length > item.location.length or not _ascii(text, 1, 64)):
                return False
            end = delta + length
        return True
    if kind == "string":
        sources = value["from"]
        return (_address(value["address"]) and value["encoding"] in ("ascii", "utf-16le")
                and _ascii(value["text"], 2, 128) and type(value["truncated"]) is bool
                and (not value["truncated"] or len(value["text"]) == 128)
                and item.location.length == len(value["text"]) * (2 if value["encoding"] == "utf-16le" else 1)
                and isinstance(sources, list) and 1 <= len(sources) <= 8
                and all(_address(source) for source in sources) and sources == sorted(set(sources)))
    name = value["name"] if kind == "function" else value["to_name"]
    if not isinstance(name, str) or len(name) > 128 or not all(c.isprintable() for c in name):
        return False
    if kind == "function":
        return type(value["size"]) is int and item.location.length <= value["size"] < 2**64
    return (_address(value["from"]) and _address(value["to"]) and item.location.length <= 16
            and (kind == "call" or value["type"] in ("read", "write", "read_write", "data", "jump")))


def _chunks(items):
    for start in range(0, len(items), MAX_EVIDENCE_PER_FINDING):
        yield items[start:start + MAX_EVIDENCE_PER_FINDING]


def conclude(task, evidence):
    if task.role != ROLE or not any(request.operation == OPERATION for request in task.operations):
        return ()
    own = {item.id: item for item in evidence if evidence_intact(item)
           and item.input_sha256 == task.input.sha256 and item.tool == REF and item.operation == OPERATION
           and item.location.within(task.input.size) and _valid(item)}
    functions = sorted((item for item in own.values() if item.observation["kind"] == "function"),
                       key=lambda item: (item.observation["index"], item.id))
    pseudocode = sorted((item for item in own.values() if item.observation["kind"] == "pseudocode"),
                        key=lambda item: (item.observation["index"], item.id))
    calls = sorted((item for item in own.values() if item.observation["kind"] == "call"),
                   key=lambda item: (item.observation["from"], item.observation["to_name"], item.id))
    listings = sorted((item for item in own.values() if item.observation["kind"] == "assembly"),
                      key=lambda item: (item.observation["index"], item.id))
    refs = sorted((item for item in own.values() if item.observation["kind"] == "ref"),
                  key=lambda item: (item.observation["from"], item.observation["type"],
                                    item.observation["to"], item.observation["to_name"], item.id))
    strings, conflicts = {}, set()
    for item in sorted(own.values(), key=lambda item: item.id):
        if item.observation["kind"] == "string":
            address = item.observation["address"]
            previous = strings.setdefault(address, item)
            if previous.observation != item.observation:
                conflicts.add(address)
    findings = []
    for group in _chunks(functions):
        findings.append(make_finding(
            ROLE, "Functions identified by Ghidra.", "code.functions",
            [item.observation["name"] for item in group], (item.id for item in group), "inferred",
        ))
    for item in pseudocode:
        findings.append(make_finding(
            ROLE, "Pseudocode decompiled by Ghidra.", "code.pseudocode",
            {key: item.observation[key] for key in ("entry", "text", "truncated")}, [item.id], "inferred",
        ))
    for group in _chunks(calls):
        findings.append(make_finding(
            ROLE, "Calls identified by Ghidra.", "code.calls",
            [list(pair) for pair in sorted({(item.observation["from"], item.observation["to_name"]) for item in group})],
            (item.id for item in group), "inferred",
        ))
    for item in listings:
        findings.append(make_finding(
            ROLE, "Instructions disassembled by Ghidra.", "code.assembly",
            {key: item.observation[key] for key in ("entry", "instructions", "truncated")}, [item.id], "inferred",
        ))
    for group in _chunks(refs):
        findings.append(make_finding(
            ROLE, "References identified by Ghidra.", "code.references",
            [list(row) for row in sorted({tuple(item.observation[key] for key in ("from", "type", "to", "to_name"))
                                         for item in group})], (item.id for item in group), "inferred",
        ))
    for group in _chunks([strings[address] for address in sorted(strings) if address not in conflicts]):
        findings.append(make_finding(
            ROLE, "Strings referenced by code according to Ghidra.", "code.strings",
            [{key: item.observation[key] for key in ("address", "encoding", "text", "truncated", "from")}
             for item in group], (item.id for item in group), "inferred",
        ))
    return tuple(findings)
