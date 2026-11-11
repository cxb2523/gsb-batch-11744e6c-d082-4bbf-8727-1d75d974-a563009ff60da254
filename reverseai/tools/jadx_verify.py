"""Resolve JADX targets from DEX bytes and attach only host-derived anchors."""

from dataclasses import dataclass
import json
import re

from reverseai.contract import (
    ContractError, Location, MAX_EXCERPT_BYTES, MAX_OBSERVATION_BYTES, MAX_WORKER_REPLY_BYTES,
    Observation, WORKER_PROTOCOL, WorkerError, canonical_json,
)
from reverseai.tools import dex

REFUSED = "JADX reply does not match the input"
_FIELDS = {"target", "status", "code_offset", "insns_count", "total", "text"}
_ERRORS = {"decompile_failed", "class_not_found", "method_not_found", "no_code"}


def _check(condition):
    if not condition:
        raise ContractError(REFUSED)


@dataclass(frozen=True)
class _Anchor:
    identity: dict
    location: Location
    artifact: dict
    code_offset: int
    insns_count: int


def prepare(data, args):
    """Resolve once, using the DEX tool's limits and exact escaped comparisons."""
    members, targets, anchors = [], [], []
    selected = not args["member"]
    try:
        for name, _, parsed, artifact in dex._dex_files(data, ""):
            _check(len(members) < 16)
            member_index = len(members)
            members.append(dict(artifact))
            if args["member"] and not dex._matches((name,), args["member"]):
                continue
            selected = True
            methods = sorted(dex._defined_methods(parsed), key=lambda pair: pair[1]["index"])
            for declaration, method in methods:
                code = declaration.get("code")
                if not code or not code["insns_size"] or not dex._selected_method(method, args):
                    continue
                _check(len(targets) < 16)
                identity = {"dex": dex._identity((name,)),
                            "class": dex._identity((method["class_descriptor"],)),
                            "name": dex._identity((method["name"],)),
                            "prototype": dex._identity(dex._prototype_parts(method["prototype"]))}
                raw_prototype = "".join(dex._prototype_parts(method["prototype"]))
                targets.append({"member": member_index,
                                "class": method["class_descriptor"].encode("utf-8").hex(),
                                "method": method["name"].encode("utf-8").hex(),
                                "prototype": raw_prototype.encode("utf-8").hex()})
                anchors.append(_Anchor(identity,
                    Location(code["insns_offset"], min(2 * code["insns_size"], MAX_EXCERPT_BYTES)),
                    dict(artifact), declaration["code_off"], code["insns_size"]))
    except (ContractError, UnicodeError):
        raise ContractError(REFUSED) from None
    if not selected:
        raise ContractError("JADX member is not a classes*.dex member of the input")
    return {"members": members, "targets": targets, "start": args["start"], "max_chars": args["max_chars"]}, tuple(anchors)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        _check(key not in result)
        result[key] = value
    return result


def parse_reply(raw, digest):
    _check(isinstance(raw, bytes) and len(raw) <= MAX_WORKER_REPLY_BYTES)
    try:
        reply = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique,
                           parse_constant=lambda value: _check(False))
    except (UnicodeError, ValueError, RecursionError):
        raise ContractError(REFUSED) from None
    _check(isinstance(reply, dict) and reply.get("protocol") == WORKER_PROTOCOL
           and reply.get("snapshot_sha256") == digest)
    if reply.get("status") == "error":
        _check(set(reply) == {"protocol", "status", "snapshot_sha256", "error"})
        _check(isinstance(reply["error"], str) and reply["error"] in ("memory", "timeout", "input"))
        raise WorkerError(reply["error"])
    _check(set(reply) == {"protocol", "status", "snapshot_sha256", "observations"}
           and reply.get("status") == "ok")
    rows = reply["observations"]
    _check(isinstance(rows, list) and len(rows) <= 16)
    return rows


def anchor(rows, args, anchors):
    """Only prepare's host-owned anchors may enter this core; no worker location is admitted."""
    _check(isinstance(rows, list) and len(rows) == len(anchors) <= 16)
    result = []
    for index, (row, expected) in enumerate(zip(rows, anchors)):
        _check(isinstance(row, dict) and set(row) == _FIELDS)
        _check(type(row["target"]) is int and row["target"] == index)
        status, total, text = row["status"], row["total"], row["text"]
        _check(isinstance(status, str) and status in {"ok", "fallback", "omitted", *_ERRORS})
        _check(type(total) is int and 0 <= total < 2**32 and isinstance(text, str)
               and len(text) <= args["max_chars"]
               and all(" " <= char <= "~" or char in "\n\t" for char in text))
        if status in ("ok", "fallback"):
            _check(total > 0 and type(row["code_offset"]) is int and row["code_offset"] == expected.code_offset
                   and type(row["insns_count"]) is int and row["insns_count"] == expected.insns_count)
            start = min(args["start"], total)
            _check(len(text) == min(args["max_chars"], total - start))
            form = "java" if status == "ok" else "fallback"
        else:
            _check(row["code_offset"] is None and row["insns_count"] is None and total == 0 and text == "")
            start, form = 0, "omitted" if status == "omitted" else "error"
        value = {"kind": "java", **expected.identity, "form": form, "start": start, "total": total, "text": text}
        if len(canonical_json(value).encode()) > MAX_OBSERVATION_BYTES:
            low, high = 0, len(text)
            while low < high:
                middle = (low + high + 1) // 2
                value["text"] = text[:middle]
                if len(canonical_json(value).encode()) <= MAX_OBSERVATION_BYTES:
                    low = middle
                else:
                    high = middle - 1
            for escape in re.finditer(r"\\u[0-9a-fA-F]{4}", text):
                if escape.start() < low < escape.end():
                    low = escape.start()
                    break
            value["text"] = text[:low]
        _check(len(canonical_json(value).encode()) <= MAX_OBSERVATION_BYTES)
        result.append(Observation(expected.location, value, dict(expected.artifact)))
    return tuple(result)


def verify(data, rows, args):
    """Standalone verification always derives anchors afresh from the input bytes."""
    _, anchors = prepare(data, args)
    return anchor(rows, args, anchors)
