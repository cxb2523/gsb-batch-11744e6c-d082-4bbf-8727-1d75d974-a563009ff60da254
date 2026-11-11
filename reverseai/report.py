"""Deterministic JSON and Markdown reports without timestamps or host paths.

Reports carry bounded text taken from the sample (strings, URLs, section names)
and from analysts. It stays untrusted: Markdown shows it inside code spans or
fenced blocks, where HTML, links, images and autolinks do not render.
"""

from dataclasses import dataclass
import re

from reverseai import __version__, claims
from reverseai.contract import CONTRACT_VERSION, VERDICT_STATUS, InputRef, canonical_json


@dataclass(frozen=True)
class Analysis:
    input: InputRef
    tools: tuple  # tuple[ToolRef, ...]
    results: tuple  # tuple[AnalysisResult, ...]
    verdicts: tuple  # tuple[ReviewVerdict, ...]
    runtimes: tuple = ()  # ((tool name, {"image": ..., "platform": ...}), ...) for contained tools
    query: object = None  # {"name": str, "args": dict} for targeted queries only


def to_dict(analysis):
    verdicts = {v.finding_id: v for v in analysis.verdicts}
    results = []
    for result in analysis.results:
        results.append({
            "task_id": result.task_id,
            "role": result.role,
            "status": result.status,
            "errors": list(result.errors),
            "evidence": [e.to_dict() for e in result.evidence],
            "findings": [{
                "id": f.id,
                "claim": f.claim,
                "statement": claims.statement(f.claim_key),
                "claim_key": f.claim_key,
                "value": f.value,
                "confidence": f.confidence,
                "evidence_ids": list(f.evidence_ids),
                "verdict": verdicts[f.id].status if f.id in verdicts else "unreviewed",
                "reasons": list(verdicts[f.id].reasons) if f.id in verdicts else [],
            } for f in result.findings],
        })
    summary = {status: 0 for status in (*VERDICT_STATUS, "unreviewed")}
    for result in results:
        for finding in result["findings"]:
            summary[finding["verdict"]] += 1
    return {
        "contract": CONTRACT_VERSION,
        "reverseai": __version__,
        "input": {"sha256": analysis.input.sha256, "size": analysis.input.size, "name": analysis.input.name},
        "tools": [{"name": t.name, "version": t.version, **({"runtime": dict(analysis.runtimes)[t.name]} if t.name in dict(analysis.runtimes) else {})}
                  for t in analysis.tools],
        "results": results,
        "summary": summary,
        **({"query": analysis.query} if analysis.query is not None else {}),
    }


def to_json(analysis):
    return canonical_json(to_dict(analysis)) + "\n"


def _cell(value, limit=200):
    """Untrusted text as one inert code span; "-" when empty."""
    text = value if isinstance(value, str) else canonical_json(value)
    text = "".join(c if c.isprintable() else "�" for c in text).replace("`", "'")
    if len(text) > limit:
        text = text[:limit - 1] + "…"
    return "`" + text.replace("|", "\\|") + "`" if text.strip() else "-"


def _address(value):
    return hex(value) if type(value) is int and value >= 0 else value


def _code_value(key, value):
    """Markdown-only address formatting; leave JSON values and byte offsets intact."""
    if key in ("code.assembly", "code.pseudocode", "code.instructions", "code.function_info") and isinstance(value, dict):
        return {k: _address(v) if k == "entry" else v for k, v in value.items()}
    if key in ("code.calls", "code.references") and isinstance(value, list):
        width = 2 if key == "code.calls" else 4
        return [[_address(v) if i == 0 or (width == 4 and i == 2) else v for i, v in enumerate(row)]
                if isinstance(row, list) and len(row) == width else row for row in value]
    if key == "code.strings" and isinstance(value, list):
        return [{k: _address(v) if k == "address" else [_address(a) for a in v]
                 if k == "from" and isinstance(v, list) else v for k, v in entry.items()}
                if isinstance(entry, dict) else entry for entry in value]
    if key in ("code.function_list", "code.xrefs", "code.callers") and isinstance(value, dict):
        positions = (1,) if key == "code.function_list" else (0, 1)
        return {k: _address(v) if k == "to" else [
            [_address(cell) if i in positions else cell for i, cell in enumerate(row)] for row in v]
                if k == "rows" else v for k, v in value.items()}
    if key in ("load.entry", "bytes.read") and isinstance(value, dict):
        return {k: _address(v) if k == "address" else v for k, v in value.items()}
    if key in ("segments.list", "symbols.list") and isinstance(value, dict):
        position = 3 if key == "segments.list" else 1
        return {k: [[_address(cell) if i == position else cell for i, cell in enumerate(row)] for row in v]
                if k == "rows" else v for k, v in value.items()}
    return value


# DEX access flags (dex-format access_flags), for readable Markdown only
CLASS_ACCESS = ((0x1, "public"), (0x2, "private"), (0x4, "protected"), (0x8, "static"), (0x10, "final"),
                (0x200, "interface"), (0x400, "abstract"), (0x1000, "synthetic"), (0x2000, "annotation"), (0x4000, "enum"))
METHOD_ACCESS = ((0x1, "public"), (0x2, "private"), (0x4, "protected"), (0x8, "static"), (0x10, "final"),
                 (0x20, "synchronized"), (0x40, "bridge"), (0x80, "varargs"), (0x100, "native"), (0x400, "abstract"),
                 (0x800, "strict"), (0x1000, "synthetic"), (0x10000, "constructor"), (0x20000, "declared-synchronized"))
METHODS = {0: "stored", 8: "deflate"}


def _access(value, names):
    if type(value) is not int or value < 0:
        return value
    return " ".join([hex(value)] + [name for bit, name in names if value & bit])


def _android_value(key, value):
    """Markdown-only views of Android page rows: methods, CRCs, access flags and offsets inside a child in hex."""
    if not isinstance(value, dict) or not isinstance(value.get("rows"), list):
        return value
    views = {"android.members": {1: lambda v: METHODS.get(v, v), 4: lambda v: f"0x{v:08x}" if type(v) is int else v,
                                 6: lambda v: (", ".join(v) or "-") if isinstance(v, list)
                                 and all(isinstance(flag, str) for flag in v) else v},
             "android.classes": {2: lambda v: _access(v, CLASS_ACCESS)},
             "android.methods": {4: lambda v: _access(v, METHOD_ACCESS), 5: _address},
             "android.references": {4: _address}}.get(key, {})
    return {**value, "rows": [[views[i](cell) if i in views else cell for i, cell in enumerate(row)]
                              if isinstance(row, list) else row for row in value["rows"]]}


def _query_details(rows):
    columns = {
        "segments.list": ("Name", "File offset", "File size", "Address", "Memory size", "Readable", "Writable", "Executable"),
        "symbols.list": ("Name", "Address", "Type", "Binding", "Defined"),
        "strings.listed": ("File offset", "Encoding", "Text", "Truncated"),
        "strings.matches": ("File offset", "Encoding", "Text", "Truncated"),
        "code.function_list": ("Name", "Entry", "Size"),
        "code.xrefs": ("At", "From function", "Type"),
        "android.members": ("Name", "Method", "Compressed size", "Size", "CRC-32", "SHA-256", "Flags"),
        "android.manifest": ("Element index", "Element", "Attribute", "Type", "Value"),
        "android.classes": ("DEX", "Class", "Access", "Superclass"),
        "android.methods": ("DEX", "Class", "Name", "Prototype", "Access", "Code offset", "Code units"),
        "android.references": ("DEX", "From class", "From method", "From prototype", "At", "Kind", "Target",
                               "Truncated"),
    }
    lines = []
    for _, finding in rows:
        key, raw = finding["claim_key"], finding["value"]
        if key == "android.permissions":
            lines += ["", f"### {claims.statement(key)}", ""]
            lines += [f"- {_cell(name, limit=512)}" for name in raw] if isinstance(raw, list) else []
            continue
        if key == "bytes.read":
            lines += ["", "### Bytes read from the input", "", "| File offset | Address | Bytes (hex) |", "|---|---|---|",
                      f"| {_cell(raw['offset'])} | {_cell(_address(raw['address']))} | {_cell(raw['hex'], limit=8192)} |"]
            continue
        if key == "code.function_info":
            lines += ["", "### Function (derived)", "", "| Field | Value |", "|---|---|"]
            lines += [f"| {field} | {_cell(value, limit=512)} |" for field, value in _code_value(key, raw).items()]
            continue
        if key == "code.pseudocode":
            lines += ["", "### Pseudocode (derived)", "", f"Entry: {_cell(_address(raw['entry']))}",
                      f"Truncated: {_cell(raw['truncated'])}", ""]
            for line in raw["text"].splitlines():
                lines += [_cell(line, limit=4096), ""]
            continue
        if key in ("code.callers", "code.calls"):
            value = _code_value(key, raw)
            values = value.get("rows", []) if key == "code.callers" else value
            lines += ["", f"### {claims.statement(key)}", "", "| At | From function |" if key == "code.callers"
                      else "| From function | Callee |", "|---|---|"]
            lines += ["| " + " | ".join(_cell(cell) for cell in row) + " |" for row in values]
            continue
        if key not in columns and key != "code.instructions":
            continue
        if not isinstance(raw, dict) or not all(field in raw for field in ("start", "total", "rows")) or not raw["rows"]:
            continue
        value = _android_value(key, _code_value(key, raw))
        start, end, total = raw["start"], raw["start"] + len(raw["rows"]) - 1, raw["total"]
        lines += ["", f"### {claims.statement(key)}", "", f"rows {start}..{end} of {total}"]
        if end + 1 < total:
            lines += [f"Next start: {end + 1}"]
        if key == "code.instructions":
            lines += [f"Truncated: {_cell(raw['truncated'])}", "", "| Index | Address | Length | Instruction |", "|---|---|---|---|"]
            for index, (delta, length, text) in enumerate(raw["rows"], start):
                lines.append(f"| {index} | {_cell(_address(raw['entry'] + delta))} | {_cell(length)} | {_cell(text)} |")
        else:
            lines += ["", "| Index | " + " | ".join(columns[key]) + " |", "|---|" + "---|" * len(columns[key])]
            for index, row in enumerate(value["rows"], start):
                lines.append(f"| {index} | " + " | ".join(_cell(cell, limit=512) for cell in row) + " |")
    return lines


def _export_details(rows):
    """Render reviewed export values once as complete, bounded pages."""
    lines = []
    for _, finding in rows:
        key, value = finding["claim_key"], finding["value"]
        if key == "code.export_page":
            lines += ["", "### Prepared analysis page (derived)", "",
                      f"Analysis: {_cell(value['analysis_id'], limit=64)}",
                      f"Part: {_cell(value['scope'])} / {_cell(value['part'])}; status: {_cell(value['status'])}"]
            if value["count"] == 0:
                lines += [f"No rows shown; cursor {value['start']} of {value['total']}."]
            continue
        if key == "code.pseudocode_page":
            start, count = value["start"], len(value["text"])
            shown = f"characters {start}..{start + count - 1} of {value['total']}" if count else f"No characters shown at {start} of {value['total']}"
            lines += ["", "### Pseudocode character page (derived)", "", shown,
                      f"Entry: {_cell(_address(value['entry']))}; text SHA-256: {_cell(value['text_sha256'], limit=64)}"]
            if value["next_start"] is not None:
                lines += [f"Next text_start: {value['next_start']}"]
            lines += [""]
            for line in value["text"].splitlines():
                lines += [_cell(line.replace("\t", "    "), limit=16384), ""]
            continue
        if not key.startswith("code.export_") or not value.get("rows"):
            continue
        start, count = value["start"], len(value["rows"])
        lines += ["", f"### Exported {value['part']} (derived)", "", f"rows {start}..{start + count - 1} of {value['total']}"]
        if value["next_start"] is not None:
            lines += [f"Next start: {value['next_start']}"]
        fields = [name for name in value["rows"][0] if name != "index"]
        lines += ["", "| Index | " + " | ".join(fields) + " |", "|---|" + "---|" * len(fields)]
        for index, row in enumerate(value["rows"], start):
            cells = [_cell(_address(row[name]) if name in ("entry", "from", "at", "to", "address") else row[name], limit=4096)
                     for name in fields]
            lines += [f"| {index} | " + " | ".join(cells) + " |"]
    return lines


def _code_details(rows):
    """Readable views of derived values; instruction bytes are not carried by Analysis."""
    lines = []
    listings = [(r, f) for r, f in rows if f["claim_key"] == "code.assembly" and isinstance(f["value"], dict)]
    if listings:
        lines += ["", "### Assembly (derived)"]
        for result, finding in listings:
            value = finding["value"]
            own = {item["id"]: item for item in result["evidence"]}
            anchor = next((own[i]["location"]["offset"] for i in finding["evidence_ids"] if i in own
                           and own[i]["observation"] == {"kind": "assembly", "index": own[i]["observation"].get("index"), **value}), None)
            lines += ["", f"#### Function at {_cell(_address(value.get('entry')))}", "",
                      f"Truncated: {_cell(value.get('truncated'))}", "",
                      "| File offset | Length | Instruction |", "|---|---|---|"]
            for row in value.get("instructions", []) if isinstance(value.get("instructions"), list) else []:
                if isinstance(row, list) and len(row) == 3:
                    delta, length, text = row
                    offset = anchor + delta if anchor is not None and type(delta) is int else ""
                    lines.append(f"| {_cell(offset)} | {_cell(length)} | {_cell(text)} |")
    refs = [f for _, f in rows if f["claim_key"] == "code.references" and isinstance(f["value"], list)]
    if refs:
        lines += ["", "### References (derived)", "", "| From function | Type | To address | Symbol |", "|---|---|---|---|"]
        for finding in refs:
            for row in _code_value("code.references", finding["value"]):
                if isinstance(row, list) and len(row) == 4:
                    lines.append("| " + " | ".join(_cell(value) for value in row) + " |")
    strings = [f for _, f in rows if f["claim_key"] == "code.strings" and isinstance(f["value"], list)]
    if strings:
        lines += ["", "### Referenced strings (derived)", "", "| Address | Encoding | Text | Truncated | From functions |",
                  "|---|---|---|---|---|"]
        for finding in strings:
            for entry in _code_value("code.strings", finding["value"]):
                if isinstance(entry, dict):
                    lines.append("| " + " | ".join(_cell(entry.get(key)) for key in
                                                   ("address", "encoding", "text", "truncated", "from")) + " |")
    return lines


def _java_details(rows, tools):
    lines = []
    runtimes = {tool["name"]: tool.get("runtime", {}) for tool in tools}
    for result, finding in rows:
        if finding["claim_key"] != "android.java":
            continue
        value = finding["value"]
        own = {item["id"]: item for item in result["evidence"]}
        cited = [own[i] for i in finding["evidence_ids"] if i in own]
        tool = cited[0]["tool"] if cited else {"name": "jadx", "version": "not recorded"}
        image = runtimes.get(tool["name"], {}).get("image", "not recorded")
        start, stop, total = value["start"], value["start"] + len(value["text"]), value["total"]
        lines += ["", "### Java (derived)", "",
                  f"Method: {_cell(value['dex'], 255)} · {_cell(value['class'], 255)} · "
                  f"{_cell(value['name'], 255)} {_cell(value['prototype'], 255)}",
                  f"Tool: {_cell(tool['name'] + ' ' + tool['version'])}; Image: {_cell(image, 128)}",
                  f"Form: {_cell(value['form'])}"]
        if value["text"]:
            lines += [f"characters {start}..{stop - 1} of {total}"]
            if stop < total:
                lines += [f"Next start: {stop}"]
        else:
            lines += [f"no text (form {value['form']})"]
        # Controls stay visible as escapes; a fence longer than any run cannot be closed by the text.
        text = "".join(char if " " <= char <= "~" or char in "\n\t" else ascii(char)[1:-1]
                       for char in value["text"])
        fence = "`" * max(3, 1 + max((len(run) for run in re.findall(r"`+", text)), default=0))
        lines += ["", fence + "java", text, fence]
    return lines


INSTALL_SCRIPTS = ("preinstall", "install", "postinstall", "prepare")  # npm runs these on install
JAVASCRIPT_PAGES = {
    "javascript.files": ("File", "Size", "SHA-256", "Lines", "Longest line (bytes)", "Flags"),
    "javascript.package": ("File", "Path", "Value", "Truncated", "Runs on install"),
    "javascript.hints": ("File", "Category", "Hint", "Text", "Truncated"),
}
JAVASCRIPT_SYNTAX_PAGES = {
    "javascript.modules": ("File", "Form", "Source", "Truncated"),
    "javascript.calls": ("File", "Callee"),
    "javascript.parse": ("File", "Status", "Errors"),
}


def _runs(indexes):
    """Contiguous (first, last) runs of sorted row indexes."""
    runs = []
    for index in indexes:
        if runs and index == runs[-1][1] + 1:
            runs[-1][1] = index
        else:
            runs.append([index, index])
    return runs


def _javascript_details(rows, args=None, *, syntax=False):
    """Lexical or derived syntax pages, combining findings without spanning unshown rows."""
    columns_by_key = JAVASCRIPT_SYNTAX_PAGES if syntax else JAVASCRIPT_PAGES
    lines = (["", "### JavaScript syntax (parser's reading)", "",
              "Syntax roles are the pinned parser's reading (derived); their anchors cite host-checked bytes. "
              "The sample was not executed."] if syntax else
             ["", "## JavaScript application", "",
              "Hints are lexical: occurrences of fixed patterns in the bytes, comments and strings included, not evidence "
              "that the code runs. This reading uses no JavaScript syntax and runs nothing."])
    pages = {key: ({}, set()) for key in columns_by_key}
    for _, finding in rows:
        found, totals = pages.get(finding["claim_key"], (None, None))
        value = finding["value"]
        if found is None or not isinstance(value, dict) or type(value.get("start")) is not int \
                or not isinstance(value.get("rows"), list):
            continue
        width = len(columns_by_key[finding["claim_key"]]) - (finding["claim_key"] == "javascript.package")
        found.update((index, row) for index, row in enumerate(value["rows"], value["start"])
                     if isinstance(row, list) and len(row) == width)
        totals.add(value.get("total"))
    if not any(found for found, _ in pages.values()):
        return [] if syntax else lines + ["", "No JavaScript row was supported."]
    for key, (found, totals) in pages.items():
        if not found:
            continue
        runs = _runs(sorted(found))
        total = totals.pop() if len(totals) == 1 else "?"
        level = "####" if syntax else "###"
        lines += ["", f"{level} {claims.statement(key)}", "",
                  "rows " + ", ".join(f"{first}..{last}" for first, last in runs) + f" of {total}"]
        # The page asked for rows from its start (0 in a summary): the first one not shown is where to continue.
        start = (args or {}).get("start", 0) if (args or {}).get("detail") != "summary" else 0
        following = start if runs[0][0] > start else runs[0][1] + 1
        if type(total) is int and following < total:
            lines += [f"Next start: {following}"]
        if key == "javascript.package":
            lines += ["", "Runs on install marks the scripts npm runs when the package is installed (" +
                      ", ".join(INSTALL_SCRIPTS) + "); they are declarations, and nothing ran them."]
        groups = [(None, sorted(found))]
        if key == "javascript.hints":
            order = {name: i for i, name in enumerate(claims.JS_CATEGORIES)}
            categories = sorted({found[i][1] for i in found}, key=lambda c: (order.get(c, len(order)), str(c)))
            groups = [(category, [i for i in sorted(found) if found[i][1] == category]) for category in categories]
        columns = columns_by_key[key]
        for category, indexes in groups:
            if category is not None:
                lines += ["", f"#### {_cell(category)}"]
            lines += ["", "| Index | " + " | ".join(columns) + " |", "|---|" + "---|" * len(columns)]
            for index in indexes:
                row = list(found[index])
                if key == "javascript.files" and row[5]:
                    row[2:5] = ["not read"] * 3
                if key == "javascript.package":
                    row.append("yes" if row[1] in tuple("/scripts/" + name for name in INSTALL_SCRIPTS) else "")
                cells = ["(input)" if i == 0 and cell == "" else cell if i == 4 and key == "javascript.package"
                         else _cell(cell, limit=512) for i, cell in enumerate(row)]
                lines.append(f"| {index} | " + " | ".join(cell or "-" for cell in cells) + " |")
    return lines


def to_markdown(analysis):
    report = to_dict(analysis)
    evidence = {e["id"]: e for r in report["results"] for e in r["evidence"]}
    lines = [
        "# ReverseAI static analysis report",
        "",
        f"- Input: {_cell(report['input']['name'], limit=255)}, {report['input']['size']} bytes",
        f"- SHA-256: `{report['input']['sha256']}`",
        f"- Contract: {report['contract']}; ReverseAI {report['reverseai']}",
        "- Tools: " + ", ".join(f"{t['name']} {t['version']}" + (f" (contained, image {t['runtime'].get('image', '?')[:19]}, {t['runtime'].get('platform', '?')})"
                                 if "runtime" in t else "") for t in report["tools"]),
        "- The sample was not executed. Findings marked inferred are hints, not proof of behaviour.",
        "",
        "## Supported findings",
        "",
    ]
    if analysis.query is not None:
        args = analysis.query["args"]
        displayed = {k: _address(v) if k in ("entry", "address") or (k == "at" and args.get("mode") == "address")
                     else v for k, v in args.items()}
        lines[2:2] = [f"- Query: {_cell(analysis.query['name'])}; arguments: {_cell(displayed, limit=4096)}"]
        if analysis.query["name"] == "inspect_android_method" and not any(t["name"] == "jadx" for t in report["tools"]):
            lines[3:3] = ["- Decompiled Java requires --with-jadx and the locally built pinned JADX image."]
    supported = [(r, f) for r in report["results"] for f in r["findings"] if f["verdict"] == "supported"]
    derived = [(r, f) for r in report["results"] for f in r["findings"] if f["verdict"] == "derived"]
    rejected = [(r, f) for r in report["results"] for f in r["findings"] if f["verdict"] not in ("supported", "derived")]

    def cite(item):
        """operation @ offset+length in the input; inside a child artifact, its member and the offset in hex."""
        location = item["location"]
        if "artifact" in item:
            member = item["artifact"].get("member") if isinstance(item["artifact"], dict) else None
            return f"{item['operation']} in {_cell(member, limit=64)} @ {_address(location['offset'])}+{location['length']}"
        return f"{item['operation']} @ {location['offset']}+{location['length']}"

    def table(rows):
        out = ["| Analyst | Checked statement | Value | Confidence | Evidence (operation @ offset+length) |", "|---|---|---|---|---|"]
        for result, finding in rows:
            cited = "; ".join(cite(evidence[i]) for i in finding["evidence_ids"][:6] if i in evidence)
            more = len(finding["evidence_ids"]) - 6
            cited += f"; +{more} more" if more > 0 else ""
            value = _code_value(finding["claim_key"], finding["value"])
            out.append(f"| {result['role']} | {finding['statement']} | {_cell(value)} | {finding['confidence']} | {cited} |")
        return out

    lines += table(supported) if supported else ["No finding was supported by the evidence."]
    if derived:
        # the tool's reading, anchored in the input but not verified against it
        lines += ["", "## Derived by analysis tools (not verified against the bytes)", ""] + table(derived)
        lines += _code_details(derived)
        lines += _java_details(derived, report["tools"])
        lines += _javascript_details(derived, analysis.query["args"] if analysis.query is not None else None, syntax=True)
    if analysis.query is not None:
        lines += _export_details(derived)
        lines += _query_details(supported + derived)
        if analysis.query["name"] == "analyze_javascript_application" and analysis.query["args"].get("detail") in (
                "summary", "files", "package", "hints"):
            lines += _javascript_details(supported + derived, analysis.query["args"])
    lines += ["", "## Rejected or unreviewed claims", ""]
    if rejected:
        lines += ["| Analyst | Claim (analyst wording, unchecked) | Verdict | Reasons |", "|---|---|---|---|"]
        for result, finding in rejected:
            lines.append(f"| {result['role']} | {_cell(finding['claim'])} | {finding['verdict']} | {_cell('; '.join(finding['reasons']))} |")
    else:
        lines.append("None.")
    lines += ["", "## Analyst runs", "", "| Analyst | Status | Evidence items | Errors |", "|---|---|---|---|"]
    for result in report["results"]:
        lines.append(f"| {result['role']} | {result['status']} | {len(result['evidence'])} | {_cell('; '.join(result['errors']))} |")
    summary = report["summary"]
    lines += ["", "Summary: " + ", ".join(f"{summary[k]} {k}" for k in summary), ""]
    return "\n".join(lines)
