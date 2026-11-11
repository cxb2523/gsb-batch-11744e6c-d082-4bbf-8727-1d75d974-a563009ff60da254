"""Admit prepared export pages against the original image, never the project blob."""

import hashlib
import re

from reverseai import ghidra_args
from reverseai.contract import Location, Observation, canonical_json
from reverseai.tools.ghidra_verify import (
    _SectionIndex, _sections, _check, _uint, _name, _function_anchor,
    _instruction_anchor, _file_map, _map, _string_bytes, _REFERENCE_TYPES,
)

FIELDS = {
    "export_page": {"kind", "scope", "part", "entry", "status", "start", "total", "count", "next_start"},
    "function_export": {"kind", "index", "name", "entry", "size", "signature", "signature_truncated", "library_hint"},
    "instruction_export": {"kind", "index", "from", "from_size", "at", "length", "text"},
    "call_export": {"kind", "index", "from", "from_size", "at", "to", "to_name"},
    "reference_export": {"kind", "index", "from", "from_size", "at", "to", "type", "to_name"},
    "string_export": {"kind", "index", "from", "from_size", "at", "instruction_length", "address", "encoding", "text", "truncated"},
    "function_info": {"kind", "name", "entry", "size", "matches", "signature", "signature_truncated", "library_hint", "totals", "pseudocode_status"},
    "pseudocode_page": {"kind", "entry", "size", "text_sha256", "start", "total", "text", "next_start", "status"},
    "string_reference_anchor": {"kind", "index", "from", "from_size", "at", "address", "instruction_length"},
}
KINDS = {"functions": "function_export", "assembly": "instruction_export", "calls": "call_export",
         "callees": "call_export", "callers": "call_export", "references": "reference_export",
         "strings": "string_export", "info": "function_info", "pseudocode": "pseudocode_page"}
CAPS = {"functions": 65536, "assembly": 1000000, "calls": 262144, "callees": 262144,
        "callers": 262144, "references": 262144, "strings": 65536, "info": 1, "pseudocode": 1048576}
ANALYSIS_ID_BYTES = 81


def _integer(value, maximum):
    return type(value) is int and 0 <= value <= maximum


def _function(value):
    _check(_name(value["name"]) and _uint(value["entry"]) and _uint(value["size"], 1)
           and value["entry"] + value["size"] <= 2**64)
    signature = value["signature"]
    _check(signature is None or isinstance(signature, str) and len(signature) <= 512
           and all(c.isprintable() for c in signature))
    _check(type(value["signature_truncated"]) is bool and value["library_hint"] is None
           and (signature is not None or not value["signature_truncated"]))


def _source(sections, item, value, length):
    _check(_uint(value["from"]) and _uint(value["from_size"], 1)
           and value["from"] + value["from_size"] <= 2**64 and _uint(value["at"]))
    _function_anchor(sections, value["from"], value["from_size"])
    _check(1 <= length <= 16 and value["from"] <= value["at"]
           and value["at"] + length <= value["from"] + value["from_size"])
    offset, _ = _map(sections, value["at"], length, virtual=True)
    reverse, _ = _map(sections, offset, length, virtual=False)
    _check(reverse == value["at"])
    return Location(offset, length)


def _page(value, args, part):
    maximum = CAPS[part]
    _check(all(_integer(value[field], maximum) for field in ("start", "total", "count")))
    request = args.get("text_start", 0) if part == "pseudocode" else args.get("start", 0)
    _check(value["start"] == min(request, value["total"]) and value["start"] + value["count"] <= value["total"])
    more = value["start"] + value["count"] < value["total"]
    _check(value["next_start"] == value["start"] + value["count"] if more else value["next_start"] is None)
    if more:
        _check(type(value["next_start"]) is int and value["count"] > 0)


def admit(data, observations, raw_args, operation):
    args = ghidra_args.check(operation, raw_args)
    scope = "program" if operation == "ghidra.export_program" else "function"
    part = "pseudocode" if operation == "ghidra.pseudocode" else args["part"]
    _check(isinstance(observations, (list, tuple)) and 1 <= len(observations) <= 129)
    for item in observations:
        _check(isinstance(item, Observation) and item.artifact is None and item.location.within(len(data)))
        value = item.value
        _check(value.get("kind") in FIELDS and value["kind"] != "string_reference_anchor"
               and set(value) == FIELDS[value["kind"]]
               and len(canonical_json(value).encode("utf-8")) + ANALYSIS_ID_BYTES <= 4096)
    header = observations[0]
    meta = header.value
    _check(meta["kind"] == "export_page" and header.location == Location(0, min(64, len(data)))
           and meta["scope"] == scope and meta["part"] == part
           and meta["status"] in ("ok", "not_found", "decompile_failed"))
    if scope == "program":
        _check(meta["entry"] is None and meta["status"] == "ok")
    else:
        _check(meta["entry"] is None or _uint(meta["entry"]))
        if meta["entry"] is not None and args["select"] == "entry":
            _check(meta["entry"] == args["entry"])
    if meta["status"] != "ok":
        _check(len(observations) == 1 and all(type(meta[k]) is int and meta[k] == 0 for k in ("start", "total", "count"))
               and meta["next_start"] is None
               and (meta["status"] != "decompile_failed" or part == "pseudocode"))
        return tuple(observations)
    _page(meta, args, part)
    rows = observations[1:]
    _check(all(item.value["kind"] == KINDS[part] for item in rows))
    if part == "pseudocode":
        _check(len(rows) == 1 and meta["entry"] is not None)
        item, value = rows[0], rows[0].value
        _check(_uint(value["entry"]) and value["entry"] == meta["entry"] and _uint(value["size"], 1)
               and value["entry"] + value["size"] <= 2**64)
        _check(item.location == _function_anchor(_SectionIndex(_sections(data)[0]), value["entry"], value["size"]))
        _check(value["status"] == "ok" and all(value[k] == meta[k] for k in ("start", "total", "next_start")))
        _check(all(_integer(value[k], 1048576) for k in ("start", "total")))
        _check(value["next_start"] is None or type(value["next_start"]) is int)
        text = value["text"]
        _check(isinstance(text, str) and len(text) <= args["max_chars"] and len(text) == meta["count"]
               and all(c.isprintable() or c in "\n\t" for c in text)
               and isinstance(value["text_sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", value["text_sha256"]))
        if value["start"] == 0 and len(text) == value["total"]:
            _check(hashlib.sha256(text.encode("utf-8")).hexdigest() == value["text_sha256"])
        return tuple(observations)
    _check(len(rows) == meta["count"] and len(rows) <= args["limit"])
    _check(part != "info" or len(rows) == 1)
    sections = _SectionIndex(_sections(data)[0])
    if scope == "function":
        _check(meta["entry"] is not None)
        _map(sections, meta["entry"], 1, virtual=True)
    extra, previous, sources, callsites = [], None, {}, set()
    instruction_end = -1
    for number, item in enumerate(rows, meta["start"]):
        value = item.value
        if part != "info":
            _check(type(value["index"]) is int and value["index"] == number)
        if part in ("info", "functions"):
            _function(value)
            _check(item.location == _function_anchor(sections, value["entry"], value["size"]))
            order = value["entry"]
            if part == "info":
                _check(meta["entry"] == value["entry"] and meta["start"] == 0 and meta["total"] == meta["count"] == 1
                       and _integer(value["matches"], 65536) and value["matches"] >= 1
                       and value["pseudocode_status"] == "not_requested"
                       and isinstance(value["totals"], dict)
                       and set(value["totals"]) == {"assembly", "callees", "callers", "references", "strings"}
                       and all(_integer(total, CAPS[name]) for name, total in value["totals"].items()))
                if args["select"] == "entry":
                    _check(value["entry"] == args["entry"] and value["matches"] == 1)
                else:
                    _check(value["name"] == args["name"])
        else:
            _check(_uint(value["at"]) and _uint(value["from"]) and _uint(value["from_size"], 1))
            _check(sources.setdefault(value["from"], value["from_size"]) == value["from_size"])
            if part == "strings":
                _check(type(value["instruction_length"]) is int)
                source = _source(sections, item, value, value["instruction_length"])
                _check(value["encoding"] in ("ascii", "utf-16le") and type(value["truncated"]) is bool
                       and isinstance(value["text"], str) and 2 <= len(value["text"]) <= 128
                       and all(" " <= c <= "~" for c in value["text"]) and _uint(value["address"]))
                width = 1 if value["encoding"] == "ascii" else 2
                _check(item.location.length == width * len(value["text"]))
                address, section = _file_map(sections, item.location.offset, item.location.length + width, virtual=False)
                _check(address == value["address"])
                offset, _ = _file_map(sections, address, item.location.length + width, virtual=True)
                _check(offset == item.location.offset)
                _check(_string_bytes(data, offset, section.offset + section.size)
                       == (value["encoding"], value["text"], value["truncated"]))
                extra.append(Observation(source, {"kind": "string_reference_anchor", **{
                    key: value[key] for key in ("index", "from", "from_size", "at", "address", "instruction_length")}}))
                order = (value["from"], value["at"], value["address"], value["encoding"])
            else:
                _check(item.location == _source(sections, item, value, item.location.length)
                       and _instruction_anchor(sections, item) == value["at"])
                if part == "assembly":
                    _check(type(value["length"]) is int and value["length"] == item.location.length
                           and value["at"] >= instruction_end
                           and isinstance(value["text"], str) and 1 <= len(value["text"]) <= 64
                           and all(" " <= c <= "~" for c in value["text"]))
                    order = value["at"]
                    instruction_end = value["at"] + value["length"]
                else:
                    _check(_uint(value["to"]) and _name(value["to_name"]))
                    order = (value["from"], value["at"], value["to"])
                    if part == "references":
                        _check(value["type"] in _REFERENCE_TYPES)
                        order += (value["type"],)
                    else:
                        site = (value["from"], value["at"])
                        _check(site not in callsites)
                        callsites.add(site)
            if scope == "function":
                _check(meta["entry"] is not None)
                _check(value["to"] == meta["entry"] if part == "callers" else value["from"] == meta["entry"])
        _check(previous is None or order > previous)
        previous = order
    _check(scope != "function" or meta["entry"] is not None)
    return (*observations, *extra)
