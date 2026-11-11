"""Independent claim derivation for admitted prepared Ghidra pages."""

import re

from reverseai.tools.ghidra_export import CAPS, FIELDS, KINDS

OPERATIONS = ("ghidra.pseudocode", "ghidra.export_function", "ghidra.export_program")
_HASH = re.compile(r"[0-9a-f]{64}\Z")


def _shape(observation, kind):
    return (isinstance(observation, dict) and observation.get("kind") == kind
            and set(observation) == FIELDS[kind] | {"analysis_id"}
            and isinstance(observation["analysis_id"], str) and _HASH.fullmatch(observation["analysis_id"]))


def _integer(value, maximum):
    return type(value) is int and 0 <= value <= maximum


def _row_valid(value, kind):
    if kind in ("function_export", "function_info"):
        if (not isinstance(value["name"], str) or len(value["name"]) > 128 or not all(c.isprintable() for c in value["name"])
                or not _integer(value["entry"], 2**64 - 1) or not _integer(value["size"], 2**64 - 1) or value["size"] == 0
                or value["entry"] + value["size"] > 2**64 or value["library_hint"] is not None
                or type(value["signature_truncated"]) is not bool):
            return False
        signature = value["signature"]
        if signature is None:
            if value["signature_truncated"]:
                return False
        elif not isinstance(signature, str) or len(signature) > 512 or not all(c.isprintable() for c in signature):
            return False
        if kind == "function_info":
            return (value["pseudocode_status"] == "not_requested" and _integer(value["matches"], 65536) and value["matches"] > 0
                    and isinstance(value["totals"], dict) and set(value["totals"]) == {"assembly", "callees", "callers", "references", "strings"}
                    and all(_integer(total, CAPS[key]) for key, total in value["totals"].items()))
        return True
    if not (all(_integer(value[k], 2**64 - 1) for k in ("from", "from_size", "at"))
            and value["from_size"] > 0 and value["from"] <= value["at"] < value["from"] + value["from_size"] <= 2**64):
        return False
    if kind == "instruction_export":
        return (type(value["length"]) is int and 1 <= value["length"] <= 16
                and value["at"] + value["length"] <= value["from"] + value["from_size"]
                and isinstance(value["text"], str) and 1 <= len(value["text"]) <= 64
                and all(" " <= c <= "~" for c in value["text"]))
    if kind == "string_export":
        return (_integer(value["address"], 2**64 - 1) and type(value["instruction_length"]) is int
                and 1 <= value["instruction_length"] <= 16 and value["at"] + value["instruction_length"] <= value["from"] + value["from_size"]
                and value["encoding"] in ("ascii", "utf-16le") and type(value["truncated"]) is bool
                and isinstance(value["text"], str) and 2 <= len(value["text"]) <= 128 and all(" " <= c <= "~" for c in value["text"])
                and (not value["truncated"] or len(value["text"]) == 128))
    return (_integer(value["to"], 2**64 - 1) and isinstance(value["to_name"], str) and len(value["to_name"]) <= 128
            and all(c.isprintable() for c in value["to_name"])
            and (kind != "reference_export" or value["type"] in ("read", "write", "read_write", "data", "jump")))


def _header(observations):
    selected = [o for o in observations if o.get("kind") == "export_page"]
    if len(selected) != 1 or not _shape(selected[0], "export_page"):
        return None
    value = selected[0]
    part = value["part"]
    if (part not in CAPS or value["scope"] not in ("function", "program")
            or value["scope"] == "program" and (part not in ("functions", "calls", "references", "strings") or value["entry"] is not None)
            or value["entry"] is not None and not _integer(value["entry"], 2**64 - 1)
            or value["status"] not in ("ok", "not_found", "decompile_failed")
            or not all(_integer(value[k], CAPS[part]) for k in ("start", "count", "total"))
            or value["start"] + value["count"] > value["total"]):
        return None
    if value["status"] != "ok":
        if any(value[k] != 0 for k in ("start", "count", "total")) or value["next_start"] is not None:
            return None
    else:
        following = value["start"] + value["count"]
        if following < value["total"]:
            if type(value["next_start"]) is not int or value["next_start"] != following or value["count"] == 0:
                return None
        elif value["next_start"] is not None:
            return None
    return value


def page(observations):
    header = _header(observations)
    return {k: v for k, v in header.items() if k != "kind"} if header and len(observations) == 1 else None


def pseudocode(observations):
    header = _header(observations)
    rows = [o for o in observations if o.get("kind") == "pseudocode_page"]
    if (header is None or header["part"] != "pseudocode" or header["status"] != "ok"
            or len(observations) != 2 or len(rows) != 1 or not _shape(rows[0], "pseudocode_page")):
        return None
    value = rows[0]
    if (value["analysis_id"] != header["analysis_id"] or value["entry"] != header["entry"]
            or not _integer(value["size"], 2**64 - 1) or value["size"] == 0
            or value["next_start"] is not None and type(value["next_start"]) is not int
            or any(value[k] != header[k] for k in ("start", "total", "next_start", "status"))
            or not isinstance(value["text"], str) or len(value["text"]) != header["count"]
            or len(value["text"]) > 2048 or not isinstance(value["text_sha256"], str)
            or not _HASH.fullmatch(value["text_sha256"])):
        return None
    return {k: v for k, v in value.items() if k != "kind"}


def rows_for(kinds):
    def derive(observations):
        header = _header(observations)
        if header is None or header["status"] != "ok" or KINDS[header["part"]] not in kinds:
            return None
        kind = KINDS[header["part"]]
        rows = [o for o in observations if o.get("kind") == kind]
        anchors = [o for o in observations if o.get("kind") == "string_reference_anchor"]
        if (not rows or len(rows) > 63 or len(observations) != 1 + len(rows) + len(anchors)
                or any(not _shape(o, kind) or not _row_valid(o, kind) or o["analysis_id"] != header["analysis_id"] for o in rows)):
            return None
        if kind != "function_info":
            if any(not _integer(o["index"], CAPS[header["part"]]) for o in rows):
                return None
            rows.sort(key=lambda o: o["index"])
        first = 0 if kind == "function_info" else rows[0]["index"]
        if (not _integer(first, CAPS[header["part"]]) or first < header["start"]
                or first + len(rows) > header["start"] + header["count"]):
            return None
        if kind != "function_info" and any(type(o["index"]) is not int or o["index"] != first + i for i, o in enumerate(rows)):
            return None
        if kind == "string_export":
            if len(anchors) != len(rows) or len(rows) > 31:
                return None
            by_index = {o.get("index"): o for o in anchors}
            if len(by_index) != len(rows):
                return None
            for row in rows:
                anchor = by_index.get(row["index"])
                if (anchor is None or not _shape(anchor, "string_reference_anchor")
                        or any(anchor[k] != row[k] for k in FIELDS["string_reference_anchor"] - {"kind"} | {"analysis_id"})):
                    return None
        elif anchors:
            return None
        result = {k: v for k, v in header.items() if k != "kind"}
        result.update(start=first, count=len(rows), rows=[{k: v for k, v in o.items() if k not in ("kind", "analysis_id")} for o in rows])
        result["next_start"] = first + len(rows) if first + len(rows) < header["total"] else None
        return result
    return derive


DERIVATIONS = {"code.export_page": page, "code.export_functions": rows_for(("function_export", "function_info")),
               "code.export_calls": rows_for(("call_export",)), "code.export_references": rows_for(("reference_export",)),
               "code.export_strings": rows_for(("string_export",)), "code.export_instructions": rows_for(("instruction_export",)),
               "code.pseudocode_page": pseudocode}
