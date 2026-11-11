"""Deterministic, model-free map partitioning for the first planning stage.

``partition`` returns bounded map views, complete side-file evidence, all directed
cut calls, and a bounded summary. Count/byte caps take precedence over affinity:
a connected component may be split. No function is classified or skipped;
library/runtime metadata survives.
Byte limits refer to ``encode(slice)`` (compact, sorted-key UTF-8 JSON). Oversized
singletons have bounded views and complete side-file payloads; write_side_files
materializes them. No program execution or model invocation is performed.
"""

import hashlib
import json
import re
from collections import defaultdict
from pathlib import Path


def encode(value):
    """Canonical serialization used for the slice and summary byte budgets."""
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"),
                          allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise ValueError(f"invalid UTF-8 JSON: {error}") from None


def _address(value):
    if isinstance(value, str):
        try:
            value = int(value, 0)
        except ValueError:
            raise ValueError(f"invalid address: {value!r}") from None
    if type(value) is not int or not 0 <= value < 2**64:
        raise ValueError(f"invalid address: {value!r}")
    return value


def _entry(value):
    return _address(value.get("entry", value.get("hex"))) if isinstance(value, dict) else _address(value)


def _validate(source):
    if not isinstance(source, dict):
        raise ValueError("program map must be a JSON object")
    if "functions" not in source:
        raise ValueError("map.functions is required")
    for key in ("functions", "calls", "strings", "references", "data_refs", "entry_points", "imports"):
        if key in source and not isinstance(source[key], list):
            raise ValueError(f"map.{key} must be a list")
    for key in ("functions", "calls", "strings", "references", "data_refs"):
        for index, row in enumerate(source.get(key, [])):
            label = f"{key}[{index}]"
            if not isinstance(row, dict):
                raise ValueError(f"{label} must be an object")
            fields = (("entry",) if "entry" in row else ("hex",)) if key == "functions" else (
                "from", "address" if key == "strings" else "to")
            for field in fields:
                try:
                    _address(row[field])
                except (KeyError, ValueError):
                    raise ValueError(f"{label}.{field} must contain a valid address") from None
            if key == "strings" and not isinstance(row.get("text"), str):
                raise ValueError(f"{label}.text must be a string")
            if key == "functions" and "name" in row and not isinstance(row["name"], str):
                raise ValueError(f"{label}.name must be a string")
            if key == "calls" and row.get("to_name") is not None and not isinstance(row["to_name"], str):
                raise ValueError(f"{label}.to_name must be a string or null")
    if any(not isinstance(name, str) for name in source.get("imports", [])):
        raise ValueError("map.imports must contain strings")
    for index, entry in enumerate(source.get("entry_points", [])):
        try:
            _entry(entry)
        except ValueError:
            raise ValueError(f"entry_points[{index}] must contain a valid address") from None


def write_side_files(result, folder):
    """Write current payloads and remove only stale JSON names this writer owns."""
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    prepared = {}
    for name, payload in result["side_files"].items():
        if Path(name).name != name or not name.endswith(".json"):
            raise ValueError("invalid side-file name")
        prepared[name] = encode(payload)
    for old in folder.iterdir():
        owned = old.name == "unattached.json" or re.fullmatch(
            r"g[0-9]{4,}-(incoming_calls|outgoing_calls|strings|references|data_refs)\.json", old.name)
        if owned and old.name not in prepared and (old.is_file() or old.is_symlink()):
            old.unlink()
    for name, data in prepared.items():
        (folder / name).write_bytes(data)


def _summary(groups, cuts, declared, hints, named_hints, unattached, budget):
    hint_order = sorted(hints - declared)
    lists = {
        "groups": [{"id": g["id"], "functions": len(g["functions"]), "bytes": g["bytes"],
                    **({"oversized": True} if g["oversized"] else {})} for g in groups],
        "cut_edges": [{k: c[k] for k in ("from", "to", "from_group", "to_group")} for c in cuts],
        "entry_points": [hex(e) for e in sorted(declared)],
        "entry_hints": [hex(e) for e in hint_order if e in named_hints]
                       + [hex(e) for e in hint_order if e not in named_hints],
    }
    result = {key: [] for key in lists}
    result["totals"] = {key: len(rows) for key, rows in lists.items()}
    result["totals"]["functions"] = sum(len(g["functions"]) for g in groups)
    result["omitted"] = {key: len(rows) for key, rows in lists.items()}
    result["unattached"] = {key: len(rows) for key, rows in unattached.items()}
    result["oversized"] = sum(g["oversized"] for g in groups)
    if len(encode(result)) > budget:
        raise ValueError("summary budget cannot hold its counts and omission labels")
    # Round-robin samples keep group sizes, entry points and cut edges represented.
    active = [key for key, rows in lists.items() if rows]
    while active:
        for key in active[:]:
            index = len(result[key])
            result[key].append(lists[key][index])
            result["omitted"][key] -= 1
            if len(encode(result)) > budget:
                result[key].pop()
                result["omitted"][key] += 1
                active.remove(key)
            elif len(result[key]) == len(lists[key]):
                active.remove(key)
    return result


def partition(program_map, *, max_functions=128, max_bytes=65536, summary_bytes=8192,
              incoming_limit=128, string_limit=128, outgoing_limit=128, reference_limit=128):
    """Group related functions within hard caps; return groups/cut_edges/summary.

    Function rows must have consistent unique numeric entry/hex addresses. Call
    slices include incoming and outgoing edges. Strings and data references stay
    with their source (and referenced functions, when present). ``references`` and
    ``data_refs`` use the export's from/to fields. Imports are the supplied names
    actually called by the group. Entry-point lists are restricted to the slice;
    other top-level metadata is preserved and counts toward the byte cap.

    Affinity combines calls, shared string addresses/text and shared data targets.
    Sorted adjacent users represent a shared resource in O(users) edges rather
    than a quadratic clique. Greedy unions prefer stronger affinity, with numeric
    address tie breaks. Remaining groups are packed in address order. This is a
    bounded deterministic heuristic, not a minimum-cut claim.

    Entry hints include entry/main/start names and functions without callers;
    these are not proven entry points. Oversized singletons stay isolated. Their
    bounded map view samples incoming/outgoing calls, references,
    data_refs and strings up to their limits (fewer if needed for bytes).
    reference_limit applies separately to references and data_refs. Outgoing
    samples prefer self calls. The manifest's by_group counts only deferred rows; side
    files keep complete rows and complete counts. Unknown call sources use
    unknown_caller; unknown reference sources/targets have their own buckets.
    Side files are independent JSON objects. Only views shorten, never evidence.
    Call write_side_files on the result to materialize the referenced JSON files.
    """
    for name, value in (("max_functions", max_functions), ("max_bytes", max_bytes),
                        ("summary_bytes", summary_bytes), ("incoming_limit", incoming_limit),
                        ("string_limit", string_limit), ("outgoing_limit", outgoing_limit),
                        ("reference_limit", reference_limit)):
        if type(value) is not int or value < 1:
            raise ValueError(f"{name} must be a positive integer")
    # Detach every output from the caller, while rejecting non-JSON/NaN inputs.
    source = json.loads(encode(program_map))
    _validate(source)
    functions = {}
    for row in source["functions"]:
        entry = _entry(row)
        if "hex" in row and _address(row["hex"]) != entry:
            raise ValueError(f"inconsistent function address at {hex(entry)}")
        if entry in functions:
            raise ValueError(f"duplicate function at {hex(entry)}")
        functions[entry] = row
    known = set(functions)
    declared = {_entry(e) for e in source.get("entry_points", [])}
    if source.get("entry_point") is not None:
        declared.add(_entry(source["entry_point"]))
    declared.update(e for e, f in functions.items() if f.get("is_entry") is True)
    hints = {e for e, f in functions.items() if f.get("name") in ("entry", "main", "_main", "start", "_start")}

    tables = {key: sorted(source[key], key=encode)
              for key in ("calls", "strings", "references", "data_refs") if key in source}
    attached = {e: set() for e in known}
    affinity, resources = defaultdict(int), defaultdict(set)

    def relate(a, b, weight):
        if a in known and b in known and a != b:
            affinity[tuple(sorted((a, b)))] += weight

    for key, rows in tables.items():
        for index, row in enumerate(rows):
            start = _address(row["from"])
            target = _address(row["address"] if key == "strings" else row["to"])
            if start in known:
                attached[start].add((key, index))
            if key != "strings" and target in known:
                attached[target].add((key, index))
            if key == "calls":
                relate(start, target, 4)
            elif start in known:
                resources[("address", target)].add(start)
                if key == "strings" and row.get("text"):
                    resources[("text", row["text"])].add(start)
    for (kind, _), users in sorted(resources.items()):
        ordered = sorted(users)
        for a, b in zip(ordered, ordered[1:]):
            relate(a, b, 2 if kind == "text" else 3)
    named_hints = set(hints)
    hints.update(known - {_address(row["to"]) for row in tables.get("calls", [])})
    assigned = set().union(*attached.values()) if attached else set()
    unattached = {key: [row for i, row in enumerate(values) if (key, i) not in assigned]
                  for key, values in tables.items()}

    def slice_map(entries, row_ids):
        result = dict(source)
        result["functions"] = [functions[e] for e in sorted(entries)]
        for key, rows in tables.items():
            result[key] = [rows[i] for table, i in sorted(row_ids) if table == key]
        if "imports" in source:
            called = {r.get("to_name") for r in result.get("calls", [])
                      if _address(r["from"]) in entries and _address(r["to"]) not in known}
            result["imports"] = sorted(name for name in source["imports"] if name in called)
        if "entry_points" in source:
            result["entry_points"] = sorted((e for e in source["entry_points"] if _entry(e) in entries), key=encode)
        return result

    def overflow_parts(e, row_ids):
        ordered = sorted(row_ids)
        return (("incoming_calls", incoming_limit,
                 [(key, i) for key, i in ordered if key == "calls" and _address(tables[key][i]["from"]) != e]),
                ("outgoing_calls", outgoing_limit,
                 sorted([(key, i) for key, i in ordered if key == "calls" and _address(tables[key][i]["from"]) == e],
                        key=lambda item: (_address(tables[item[0]][item[1]]["to"]) != e, item))),
                ("references", reference_limit, [item for item in ordered if item[0] == "references"]),
                ("data_refs", reference_limit, [item for item in ordered if item[0] == "data_refs"]),
                ("strings", string_limit, [item for item in ordered if item[0] == "strings"]))

    parent = {e: e for e in known}
    members = {e: {e} for e in known}
    rows = {e: attached[e] for e in known}
    oversized, full_rows, original_bytes = set(), {}, {}

    def root(e):
        while parent[e] != e:
            parent[e] = parent[parent[e]]
            e = parent[e]
        return e

    def merge(a, b):
        if a in oversized or b in oversized:
            return False
        entries = members[a] | members[b]
        if len(entries) > max_functions:
            return False
        together = rows[a] | rows[b]
        if len(encode(slice_map(entries, together))) > max_bytes:
            return False
        a, b = sorted((a, b))
        parent[b] = a
        members[a], rows[a] = entries, together
        del members[b], rows[b]
        return True

    offenders = []
    for e in sorted(known):
        needed = len(encode(slice_map({e}, rows[e])))
        if needed <= max_bytes:
            continue
        oversized.add(e)
        full_rows[e], original_bytes[e] = rows[e], needed
        parts = overflow_parts(e, rows[e])
        retained = rows[e] - {item for _, _, items in parts for item in items}
        core_bytes = len(encode(slice_map({e}, retained)))
        if core_bytes > max_bytes:
            offenders.append(f"{hex(e)} needs {core_bytes} core bytes (original {needed})")
            continue
        for _, limit, candidates in parts:
            lo, hi = 0, min(len(candidates), limit)
            while lo < hi:
                mid = (lo + hi + 1) // 2
                if len(encode(slice_map({e}, retained | set(candidates[:mid])))) <= max_bytes:
                    lo = mid
                else:
                    hi = mid - 1
            retained.update(candidates[:lo])
        rows[e] = retained
    if offenders:
        raise ValueError(f"irreducible slices exceed max_bytes={max_bytes}: " + "; ".join(offenders))
    for (a, b), weight in sorted(affinity.items(), key=lambda item: (-item[1], item[0])):
        a, b = root(a), root(b)
        if a != b:
            merge(a, b)
    current = None
    for e in sorted(members):
        if current is None or not merge(current, e):
            current = e

    groups, owners = [], {}
    for number, (e, entries) in enumerate(sorted(members.items()), 1):
        mid = f"g{number:04d}"
        # Separate slices may touch the same row; give each its own JSON objects.
        data = encode(slice_map(entries, rows[e]))
        groups.append({"id": mid, "functions": [hex(a) for a in sorted(entries)],
                       "map": json.loads(data), "bytes": len(data), "oversized": e in oversized})
        owners.update((a, mid) for a in entries)
    cuts = []
    for row in tables.get("calls", []):
        a, b = _address(row["from"]), _address(row["to"])
        if a in known and b in known and owners[a] != owners[b]:
            cuts.append({**row, "from_group": owners[a], "to_group": owners[b]})
    side_files = {}
    if any(unattached.values()):
        side_files["unattached.json"] = unattached

    def group_counts(items, kind, entry):
        counts = defaultdict(int)
        for table, i in items:
            row = tables[table][i]
            if kind == "strings":
                counterpart, unknown = entry, "unknown_source"
            elif _address(row["from"]) == entry:
                counterpart, unknown = _address(row["to"]), "unknown_target"
            else:
                counterpart = _address(row["from"])
                unknown = "unknown_caller" if table == "calls" else "unknown_source"
            counts[owners.get(counterpart, unknown)] += 1
        return dict(sorted(counts.items()))

    for group in groups:
        e = _address(group["functions"][0])
        if e not in oversized:
            continue
        group["original_bytes"], group["overflow"] = original_bytes[e], {}
        for kind, _, selected in overflow_parts(e, full_rows[e]):
            retained = sum(item in rows[e] for item in selected)
            if retained == len(selected):
                continue
            payload = {"rows": [tables[key][i] for key, i in selected],
                       "by_group": group_counts(selected, kind, e)}
            filename = f"{group['id']}-{kind}.json"
            side_files[filename] = payload
            group["overflow"][kind] = {"file": filename, "total": len(selected), "retained": retained,
                                       "deferred": len(selected) - retained,
                                       "by_group": group_counts([item for item in selected if item not in rows[e]], kind, e),
                                       "sha256": hashlib.sha256(encode(payload)).hexdigest()}
    summary = _summary(groups, cuts, declared, hints, named_hints, unattached, summary_bytes)
    return {"groups": groups, "cut_edges": cuts, "summary": summary, "summary_bytes": len(encode(summary)),
            "unattached": unattached, "side_files": json.loads(encode(side_files))}
