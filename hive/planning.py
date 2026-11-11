"""Bounded group planning and byte-bound interfaces; model calls belong to the queen."""

from collections import Counter, defaultdict
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tempfile

from hive.partition import encode


def _object(properties):
    return {"type": "object", "properties": properties, "required": list(properties), "additionalProperties": False}


def _array(items):
    return {"type": "array", "items": items}


_TEXT = {"type": "string", "minLength": 1}
_TEXTS = _array(_TEXT)
_NULLABLE = {"type": ["string", "null"]}
_MODULE = _object({"id": _TEXT, "title": _TEXT, "functions": _TEXTS})
_SKIP = _object({"entry": _TEXT, "reason": _TEXT, "evidence": _TEXTS})
_DECLARATION = _object({"entity_id": _TEXT, "kind": {"type": "string", "enum": ["include", "type", "function", "global"]},
                        "entry": _NULLABLE, "owner_entry": _NULLABLE, "linkage": _NULLABLE,
                        "text": _TEXT, "requires": _TEXTS, "evidence": _TEXTS})
GROUP_SCHEMA = _object({"modules": _array(_MODULE), "skipped": _array(_SKIP),
                        "declarations": _array(_DECLARATION), "unknowns": _TEXTS})
INTERFACE_SCHEMA = _object({"choices": _array(_object({"entity_id": _TEXT, "variant_sha256": _TEXT, "evidence": _TEXTS}))})
_BUNDLE = {"schema", "input_sha256", "map_sha256", "partition_sha256", "planning_policy_sha256", "language",
           "modules", "skipped", "contract_path", "contract_sha256", "interfaces_path", "interfaces_sha256",
           "planner_attempts", "plan_id"}
_TABLES = ("calls", "strings", "references", "data_refs")
_ADDRESS = re.compile(r"0x(?:0|[1-9a-f][0-9a-f]*)\Z")
_NAME = re.compile(r"[A-Za-z_][A-Za-z_0-9]*(?:::[A-Za-z_][A-Za-z_0-9]*)*\Z")


class PlanningError(ValueError):
    def __init__(self, code, details=None, bee_result=None):
        self.code, self.details, self.bee_result = code, details or {}, bee_result
        self.details.setdefault("progress_path", "plan/progress.json")
        super().__init__(f"{code}: {self.details}")


def _require(condition, code, **details):
    if not condition:
        raise PlanningError(code, details)


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _hash(value):
    return _sha(encode(value))


def _schema(value, schema):
    kind = schema["type"]
    kinds = kind if isinstance(kind, list) else [kind]
    actual = "null" if value is None else "object" if type(value) is dict else "array" if type(value) is list else "string" if type(value) is str else "other"
    _require(actual in kinds, "invalid_schema", expected=kinds)
    if actual == "object":
        _require(set(value) == set(schema["required"]), "invalid_schema", fields=sorted(value))
        for name, item in value.items():
            _schema(item, schema["properties"][name])
    elif actual == "array":
        for item in value:
            _schema(item, schema["items"])
    elif actual == "string":
        _require(len(value) >= schema.get("minLength", 0), "invalid_schema")
    if "enum" in schema:
        _require(value in schema["enum"], "invalid_schema")


def _address(value):
    if type(value) is int:
        number = value
    elif isinstance(value, str):
        try:
            number = int(value, 0)
        except ValueError:
            raise PlanningError("invalid_map", {"address": value}) from None
    else:
        raise PlanningError("invalid_map", {"address": value})
    _require(0 <= number < 2**64, "invalid_map", address=value)
    return hex(number)


def _entry(row):
    value = _address(row.get("entry", row.get("hex")))
    _require("hex" not in row or _address(row["hex"]) == value, "invalid_map", entry=value)
    return value


def _path(out, name):
    relative = PurePosixPath(name)
    _require(not relative.is_absolute() and relative.parts and relative.parts[0] == "plan"
             and ".." not in relative.parts and "\\" not in name and str(relative) == name,
             "unsafe_planning_path", path=name)
    target = out.joinpath(*relative.parts)
    for part in [out, *[out.joinpath(*relative.parts[:i]) for i in range(1, len(relative.parts) + 1)]]:
        _require(not part.is_symlink(), "unsafe_planning_path", path=name)
        if part.exists():
            info = part.stat()
            _require(stat.S_ISDIR(info.st_mode) or (part == target and stat.S_ISREG(info.st_mode) and info.st_nlink == 1),
                     "unsafe_planning_path", path=name)
    return target


def _read(out, name):
    target = _path(out, name)
    try:
        fd = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 64 * 1024 * 1024,
                     "unsafe_planning_path", path=name)
            return stream.read()
    except OSError as error:
        raise PlanningError("planning_file_missing", {"path": name, "error": type(error).__name__}) from None


def _json(out, name):
    def pairs(items):
        result = {}
        for key, value in items:
            _require(key not in result, "invalid_planning_file", path=name)
            result[key] = value
        return result
    def constant(value):
        raise ValueError("non-finite JSON constant")
    try:
        return json.loads(_read(out, name), object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeError) as error:
        if isinstance(error, PlanningError):
            raise
        raise PlanningError("invalid_planning_file", {"path": name}) from None


def _write(out, name, data):
    target = _path(out, name)
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _path(out, name)
    fd, temporary = tempfile.mkstemp(prefix=".planning-", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), 0o444)
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return {"path": name, "sha256": _sha(data)}


def _write_json(out, name, value):
    return _write(out, name, encode(value))


def _checked(out, reference):
    _require(type(reference) is dict and set(reference) == {"path", "sha256"}, "resume_mismatch")
    _require(_sha(_read(out, reference["path"])) == reference["sha256"], "resume_mismatch", path=reference["path"])
    return _json(out, reference["path"])


def _rows(rows):
    return Counter(encode(row) for row in rows)


def _validate_partition(program_map, partitioned):
    _require(type(program_map) is dict and type(partitioned) is dict, "invalid_partition")
    _require(re.fullmatch(r"[0-9a-f]{64}", program_map.get("input_sha256", "")) is not None, "invalid_map")
    source = program_map.get("functions")
    _require(type(source) is list and all(type(row) is dict for row in source), "invalid_map")
    known = {_entry(row): row for row in source}
    _require(len(known) == len(source), "invalid_map", reason="duplicate function")
    groups = partitioned.get("groups")
    _require(type(groups) is list, "invalid_partition")
    owners = {}
    for group in groups:
        _require(type(group) is dict and type(group.get("functions")) is list and group["functions"], "invalid_partition")
        _require(re.fullmatch(r"g[0-9]{4,}", group.get("id", "")) is not None, "invalid_partition")
        for entry in group["functions"]:
            _require(entry in known and entry not in owners, "invalid_partition", entry=entry)
            owners[entry] = group["id"]
    _require(set(owners) == set(known) and len({g["id"] for g in groups}) == len(groups), "invalid_partition", reason="coverage")
    ordered = sorted(groups, key=lambda g: min(int(e, 16) for e in g["functions"]))
    _require([g["id"] for g in ordered] == [f"g{i:04d}" for i in range(1, len(groups) + 1)], "invalid_partition", reason="group order")
    tables = {}
    for table in _TABLES:
        values = program_map.get(table, [])
        _require(type(values) is list and all(type(row) is dict for row in values), "invalid_map", table=table)
        for row in values:
            _address(row.get("from"))
            _address(row.get("address" if table == "strings" else "to"))
        tables[table] = values
    cuts = [{**row, "from_group": owners[_address(row["from"])], "to_group": owners[_address(row["to"])]}
            for row in tables["calls"] if _address(row["from"]) in owners and _address(row["to"]) in owners
            and owners[_address(row["from"])] != owners[_address(row["to"])]]
    _require(_rows(cuts) == _rows(partitioned.get("cut_edges", [])), "invalid_partition", reason="cut edges")
    side_files = partitioned.get("side_files", {})
    _require(type(side_files) is dict and all(Path(name).name == name and name.endswith(".json") for name in side_files), "invalid_partition")
    def counts(rows, kind, entry):
        result = Counter()
        for row in rows:
            if kind == "strings":
                counterpart, missing = entry, "unknown_source"
            elif _address(row["from"]) == entry:
                counterpart, missing = _address(row["to"]), "unknown_target"
            else:
                counterpart = _address(row["from"])
                missing = "unknown_caller" if kind.endswith("_calls") else "unknown_source"
            result[owners.get(counterpart, missing)] += 1
        return dict(sorted(result.items()))

    used = set()
    for group in ordered:
        view, entries = group.get("map"), set(group["functions"])
        _require(type(view) is dict and set(view) == set(program_map) and group.get("bytes") == len(encode(view)), "invalid_partition", group=group["id"])
        _require(_rows(view["functions"]) == _rows(known[e] for e in entries), "invalid_partition", reason="function bytes")
        for key in set(program_map) - set(_TABLES) - {"functions", "imports", "entry_points"}:
            _require(view[key] == program_map[key], "invalid_partition", field=key)
        if "imports" in view:
            called = {r.get("to_name") for r in view.get("calls", []) if _address(r["from"]) in entries and _address(r["to"]) not in known}
            _require(view["imports"] == sorted(name for name in program_map["imports"] if name in called), "invalid_partition", field="imports")
        if "entry_points" in view:
            expected = [e for e in program_map["entry_points"] if (_entry(e) if isinstance(e, dict) else _address(e)) in entries]
            _require(_rows(view["entry_points"]) == _rows(expected), "invalid_partition", field="entry_points")
        overflow = group.get("overflow", {})
        _require(not overflow or (group.get("oversized") is True and len(entries) == 1), "invalid_partition")
        _require(set(overflow) <= {"incoming_calls", "outgoing_calls", "references", "data_refs", "strings"}, "invalid_partition")
        for table, source_rows in tables.items():
            expected = [r for r in source_rows if _address(r["from"]) in entries or (table != "strings" and _address(r["to"]) in entries)]
            actual = view.get(table, [])
            _require(not (_rows(actual) - _rows(expected)), "invalid_partition", table=table)
            represented = _rows(actual)
            for kind, meta in overflow.items():
                if ("calls" if kind.endswith("_calls") else kind) != table:
                    continue
                full = [r for r in expected if not kind.endswith("_calls") or (_address(r["from"]) in entries) == (kind == "outgoing_calls")]
                retained = [r for r in actual if not kind.endswith("_calls") or (_address(r["from"]) in entries) == (kind == "outgoing_calls")]
                name = meta.get("file")
                _require(name in side_files and name not in used, "invalid_partition", reason="missing overflow")
                payload = side_files[name]
                _require(_sha(encode(payload)) == meta.get("sha256") and _rows(payload.get("rows", [])) == _rows(full)
                         and meta.get("total") == len(full) and meta.get("retained") == len(retained)
                         and meta.get("deferred") == len(full) - len(retained), "invalid_partition", overflow=name)
                deferred = _rows(full) - _rows(retained)
                deferred_rows = [json.loads(row) for row, count in deferred.items() for _ in range(count)]
                entry = next(iter(entries))
                _require(payload.get("by_group") == counts(full, kind, entry)
                         and meta.get("by_group") == counts(deferred_rows, kind, entry), "invalid_partition", reason="overflow counts")
                represented.update(deferred)
                used.add(name)
            _require(represented == _rows(expected), "invalid_partition", reason="lost evidence", table=table)
    unattached = {table: [r for r in values if _address(r["from"]) not in known
                         and (table == "strings" or _address(r["to"]) not in known)]
                  for table, values in tables.items() if table in program_map}
    _require(partitioned.get("unattached") == {k: sorted(v, key=encode) for k, v in unattached.items()}, "invalid_partition", reason="unattached")
    if any(unattached.values()):
        _require(side_files.get("unattached.json") == partitioned["unattached"], "invalid_partition")
        used.add("unattached.json")
    _require(set(side_files) == used, "invalid_partition", reason="unreferenced side files")
    summary = partitioned.get("summary")
    _require(type(summary) is dict and partitioned.get("summary_bytes") == len(encode(summary)), "invalid_partition", reason="summary bytes")
    declared = {_entry(e) if isinstance(e, dict) else _address(e) for e in program_map.get("entry_points", [])}
    if program_map.get("entry_point") is not None:
        value = program_map["entry_point"]
        declared.add(_entry(value) if isinstance(value, dict) else _address(value))
    declared.update(e for e, row in known.items() if row.get("is_entry") is True)
    hints = {e for e, row in known.items() if row.get("name") in ("entry", "main", "_main", "start", "_start")}
    hints.update(set(known) - {_address(row["to"]) for row in tables["calls"]})
    full_summary = {
        "groups": [{"id": g["id"], "functions": len(g["functions"]), "bytes": g["bytes"],
                    **({"oversized": True} if g["oversized"] else {})} for g in ordered],
        "cut_edges": [{k: c[k] for k in ("from", "to", "from_group", "to_group")} for c in cuts],
        "entry_points": sorted(declared), "entry_hints": sorted(hints - declared)}
    for kind, values in full_summary.items():
        sample = summary.get(kind)
        _require(type(sample) is list and not (_rows(sample) - _rows(values))
                 and summary["totals"][kind] == len(values)
                 and summary["omitted"][kind] == len(values) - len(sample), "invalid_partition", reason="summary counts", kind=kind)
    _require(summary["totals"]["functions"] == len(known)
             and summary["oversized"] == sum(g["oversized"] for g in ordered)
             and summary["unattached"] == {k: len(v) for k, v in unattached.items()}, "invalid_partition", reason="summary totals")
    return ordered, known, sorted(cuts, key=encode)


def _text(text):
    return "\n".join(line.rstrip(" \t") for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"))


def _evidence(items):
    return bool(items) and all(re.fullmatch(r"fi-[0-9a-f]{16}", item)
                              or (re.fullmatch(r"0x[0-9a-fA-F]+", item) and int(item, 16) < 2**64)
                              for item in items)


def _declaration(value, language, functions):
    _schema(value, _DECLARATION)
    value = json.loads(encode(value))
    value["text"] = _text(value["text"])
    kind, key, entry, text = (value[k] for k in ("kind", "entity_id", "entry", "text"))
    _require(_evidence(value["evidence"]) and len(value["requires"]) == len(set(value["requires"])), "interface_conflict", entity=key)
    _require(not any(ord(c) < 32 and c not in "\n\t" for c in text), "interface_conflict", entity=key)
    if kind in {"function", "global"}:
        _require(isinstance(entry, str) and _ADDRESS.fullmatch(entry) and _address(entry) == entry
                 and key == kind + ":" + entry, "interface_conflict", entity=key)
        _require((entry in functions) if kind == "function" else (entry not in functions),
                 "interface_conflict", entity=key, reason="declaration disagrees with function map")
    else:
        _require(entry is None and key.startswith(kind + ":"), "interface_conflict", entity=key)
    if kind == "include":
        header = key[len("include:"):]
        _require(re.fullmatch(r"[A-Za-z_0-9./+-]+", header) and ".." not in header.split("/") and not header.startswith("/")
                 and re.fullmatch(r"\s*#\s*include\s*<" + re.escape(header) + r">\s*", text), "interface_conflict", entity=key)
    else:
        _require("#" not in text, "interface_conflict", entity=key, reason="preprocessor declaration")
    if kind == "type":
        name = key[len("type:"):]
        _require(_NAME.fullmatch(name) and (language == "cpp" or "::" not in name), "interface_conflict", entity=key)
        short = name.rsplit("::", 1)[-1]
        declares = (re.search(r"\b(?:struct|class|union|enum)\s+" + re.escape(short) + r"\b", text)
                    or re.search(r"\btypedef\b[\s\S]*\b" + re.escape(short) + r"\s*;\s*$", text)
                    or (language == "cpp" and re.search(r"\busing\s+" + re.escape(short) + r"\s*=", text)))
        _require(bool(declares), "interface_conflict", entity=key, reason="type name")
        for namespace in name.split("::")[:-1]:
            _require(re.search(r"\bnamespace\s+" + re.escape(namespace) + r"\s*\{", text), "interface_conflict", entity=key)
    elif kind == "function":
        comments = re.findall(r"/\*\s*(0x[0-9a-f]+)\s*\*/", text)
        _require(comments == [entry] and "(" in text and ";" in text, "interface_conflict", entity=key, reason="function address")
    elif kind == "global":
        _require(re.match(r"\s*extern\s+", text) and ";" in text and "=" not in text, "interface_conflict", entity=key, reason="global declaration")
        _require(value["linkage"] in {"defined", "external"}, "interface_conflict", entity=key)
        if value["linkage"] == "defined":
            owner = value["owner_entry"]
            _require(isinstance(owner, str) and _ADDRESS.fullmatch(owner) and _address(owner) == owner, "interface_conflict", entity=key)
        else:
            _require(value["owner_entry"] is None, "interface_conflict", entity=key)
    if kind != "global":
        _require(value["owner_entry"] is None and value["linkage"] is None, "interface_conflict", entity=key)
    value["requires"] = sorted(value["requires"])
    value["evidence"] = sorted(set(value["evidence"]))
    return value


def _group_output(output, group, language, known):
    _schema(output, GROUP_SCHEMA)
    assigned, ids = [], set()
    for module in output["modules"]:
        _require(module["id"] not in ids and module["functions"], "planning_coverage", group=group["id"])
        ids.add(module["id"])
        assigned.extend(module["functions"])
    for skipped in output["skipped"]:
        _require(_evidence(skipped["evidence"]), "planning_coverage", reason="skip without evidence")
        assigned.append(skipped["entry"])
    _require(Counter(assigned) == Counter(group["functions"]), "planning_coverage", group=group["id"])
    for declaration in output["declarations"]:
        _declaration(declaration, language, known)
    return output


def _modules(proposals, known, max_functions):
    modules, skipped = [], []
    for proposal in proposals:
        for module in proposal["modules"]:
            entries = sorted(module["functions"], key=lambda e: int(e, 16))
            for start in range(0, len(entries), max_functions):
                modules.append({"title": module["title"], "functions": entries[start:start + max_functions], "globals": []})
        skipped.extend(proposal["skipped"])
    modules.sort(key=lambda m: int(m["functions"][0], 16))
    for index, module in enumerate(modules, 1):
        module["id"] = f"m{index:02d}"
    skipped.sort(key=lambda s: int(s["entry"], 16))
    assigned = [e for m in modules for e in m["functions"]] + [s["entry"] for s in skipped]
    _require(Counter(assigned) == Counter(known.keys()), "planning_coverage")
    return modules, skipped


def _opaque(declaration):
    return bool(re.fullmatch(r"\s*(?:typedef\s+)?(?:struct|class|union)\s+\w+\s*(?:\w+)?\s*;\s*", declaration["text"]))


def _pointer_only(text, name):
    for match in re.finditer(r"(?<![A-Za-z_0-9])" + re.escape(name) + r"(?![A-Za-z_0-9])", text):
        tail = re.sub(r"^(?:\s*(?:const|volatile)\b)*\s*", "", text[match.end():])
        if not tail.startswith(("*", "&")):
            return False
    return True


def _interfaces(declarations, modules, skipped, known, cuts, language):
    normalized = [_declaration(d, language, known) for d in declarations]
    by_key = {d["entity_id"]: d for d in normalized}
    _require(len(by_key) == len(normalized), "interface_conflict", reason="duplicate entity")
    function_owners = {entry: module["id"] for module in modules for entry in module["functions"]}
    _require(set(function_owners) | {s["entry"] for s in skipped} == set(known), "planning_coverage")
    _require(all("function:" + entry in by_key for entry in function_owners), "interface_conflict", reason="missing function interface")
    owners, dependencies = {}, {}
    for key, declaration in by_key.items():
        requires = set(declaration["requires"])
        _require(requires <= by_key.keys(), "interface_conflict", entity=key, reason="unresolved dependency")
        dependencies[key] = set(requires)
        if declaration["kind"] == "global" and declaration["linkage"] == "defined":
            owner = function_owners.get(declaration["owner_entry"])
            _require(owner is not None, "interface_conflict", entity=key, reason="global owner not built")
            owners[key] = owner
        for dependency in requires:
            required = by_key[dependency]
            if required["kind"] != "type":
                continue
            name = dependency[len("type:"):]
            text = declaration["text"]
            forward = r"\b(?:struct|class|union)\s+" + re.escape(name) + r"\s*;"
            without_forward = re.sub(forward, "", text)
            if _opaque(required):
                _require(_pointer_only(without_forward, name), "interface_conflict", entity=key, reason="opaque type by value")
            if re.search(forward, text) and _pointer_only(without_forward, name):
                dependencies[key].discard(dependency)
    order = []
    rank = {"include": 0, "type": 1, "global": 2, "function": 3}
    while dependencies:
        ready = sorted((key for key, deps in dependencies.items() if not deps), key=lambda key: (rank[by_key[key]["kind"]], key))
        _require(bool(ready), "interface_conflict", reason="dependency cycle", entities=sorted(dependencies))
        for key in ready:
            order.append(key)
            del dependencies[key]
        for deps in dependencies.values():
            deps.difference_update(ready)
    for module in modules:
        expected = sorted(key for key, owner in owners.items() if owner == module["id"])
        _require(module["globals"] == expected, "interface_conflict", module=module["id"], reason="global assignment")
    contract = "".join(by_key[key]["text"] + ("" if by_key[key]["text"].endswith("\n") else "\n") for key in order).encode("utf-8")
    return {"schema": "hive.interfaces/1", "declarations": [by_key[key] for key in sorted(by_key)],
            "owners": dict(sorted(owners.items())), "cut_edges": cuts}, contract


def _records(value):
    def walk(item, path):
        if isinstance(item, dict):
            if not item:
                yield {"path": path, "value": {}}
            for key, child in sorted(item.items()):
                yield from walk(child, [*path, key])
        elif isinstance(item, list):
            if not item:
                yield {"path": path, "value": []}
            for index, row in enumerate(item):
                yield {"path": [*path, index], "value": row}
        else:
            yield {"path": path, "value": item}
    return list(walk(value, []))


def _pages(out, folder, label, records, limit, protected):
    total, level = len(records), 0
    while True:
        pages, chunk = [], []
        for record in records:
            single = {"schema": "hive.planning-page/1", "rows": [record]}
            _require(len(encode(single)) <= limit, "planning_payload_too_large", kind=label)
            candidate = {"schema": "hive.planning-page/1", "rows": chunk + [record]}
            if chunk and len(encode(candidate)) > limit:
                pages.append(chunk)
                chunk = []
            chunk.append(record)
        if chunk or not pages:
            pages.append(chunk)
        index = []
        for number, rows in enumerate(pages, 1):
            name = f"{folder}/pages/{label}-{level}-{number:04d}.json"
            ref = _write_json(out, name, {"schema": "hive.planning-page/1", "rows": rows})
            protected.append(ref)
            index.append({"path": name[len(folder) + 1:], "sha256": ref["sha256"], "records": len(rows)})
        root = {"schema": "hive.planning-index/1", "paged": True, "records": total, "depth": level, "pages": index}
        if len(encode(root)) <= min(limit // 4, 4096):
            return root
        _require(len(index) < len(records), "planning_payload_too_large", kind=label, reason="index budget")
        records, level = index, level + 1


def _group_files(out, group, partitioned, task, limit):
    gid, protected = group["id"], []
    folder = f"plan/groups/{gid}"
    cuts = [edge for edge in partitioned["cut_edges"] if gid in (edge["from_group"], edge["to_group"])]
    overflow_rows = [{"file": meta["file"], "row": row} for meta in group.get("overflow", {}).values()
                     for row in partitioned["side_files"][meta["file"]]["rows"]]
    inputs = {"map.json": group["map"], "summary.json": partitioned["summary"],
              "interfaces.json": {"group": gid, "cut_edges": sorted(cuts, key=encode),
                                  "overflow": group.get("overflow", {}), "overflow_rows": overflow_rows,
                                  "unattached": partitioned["unattached"] if gid == "g0001" else {}}}
    inline = {name: value for name, value in inputs.items()}
    if len(task.encode("utf-8")) + sum(len(encode(v)) for v in inline.values()) > limit:
        inline = {name: _pages(out, folder, name[:-5], _records(value), limit, protected) for name, value in inputs.items()}
    used = len(task.encode("utf-8")) + sum(len(encode(v)) for v in inline.values())
    _require(used <= limit, "planning_payload_too_large", group=gid, bytes=used, limit=limit)
    for name, value in inline.items():
        protected.append(_write_json(out, folder + "/" + name, value))
    return _path(out, folder), protected


def _policy(language, max_functions, max_prompt_bytes, interface_rounds):
    _require(language in {"c", "cpp"} and type(max_functions) is int and max_functions > 0
             and type(max_prompt_bytes) is int and max_prompt_bytes > 0
             and type(interface_rounds) is int and 0 <= interface_rounds <= 2, "invalid_planning_policy")
    return {"schema": "hive.planning-policy/1", "language": language, "max_functions": max_functions,
            "max_prompt_bytes": max_prompt_bytes, "interface_rounds": interface_rounds,
            "group_schema_sha256": _hash(GROUP_SCHEMA), "interface_schema_sha256": _hash(INTERFACE_SCHEMA),
            "planner_role_sha256": _sha(Path(__file__).with_name("roles").joinpath("planner.md").read_bytes())}


def _identity(bundle):
    return _hash({key: value for key, value in bundle.items()
                  if key not in {"plan_id", "contract_path", "interfaces_path", "planner_attempts"}})


def _invoke(invoke, name, task, folder, schema):
    result = invoke("planner", name, task, folder, schema=schema)
    _require(type(result) is dict, "invalid_schema", bee=name)
    if result.get("outcome") != "ok" or result.get("ok") is not True:
        raise PlanningError(result.get("outcome") or "invalid_schema", {"bee": name}, result)
    _schema(result.get("output"), schema)
    provenance = result.get("provenance", {})
    attempt = provenance.get("attempt_id")
    prior = provenance.get("prior_attempt_ids", [])
    _require(isinstance(attempt, str) and attempt and type(prior) is list
             and all(isinstance(value, str) and value for value in prior), "invalid_schema", reason="planner provenance", bee=name)
    attempts = [*prior, attempt]
    _require(len(attempts) == len(set(attempts)), "invalid_schema", reason="duplicate attempt", bee=name)
    return result["output"], attempts


def _variants(proposals, language, known):
    variants = defaultdict(dict)
    for proposal in proposals:
        for raw in proposal["declarations"]:
            value = _declaration(raw, language, known)
            semantic = {key: item for key, item in value.items() if key != "evidence"}
            bucket = variants[value["entity_id"]]
            fingerprint = _hash(semantic)
            if fingerprint in bucket:
                value["evidence"] = sorted(set(value["evidence"]) | set(bucket[fingerprint]["evidence"]))
            bucket[fingerprint] = value
    return {key: sorted(values.values(), key=encode) for key, values in sorted(variants.items())}


def _plan(program_map, partitioned, *, out, invoke, language, max_functions=12,
          max_prompt_bytes=65536, interface_rounds=2, saved=None):
    _require(not Path(out).is_symlink(), "unsafe_planning_path")
    out = Path(out).resolve()
    out.mkdir(parents=True, exist_ok=True, mode=0o700)
    program_map, partitioned = json.loads(encode(program_map)), json.loads(encode(partitioned))
    groups, known, cuts = _validate_partition(program_map, partitioned)
    policy = _policy(language, max_functions, max_prompt_bytes, interface_rounds)
    bindings = {"input_sha256": program_map["input_sha256"], "map_sha256": _hash(program_map),
                "partition_sha256": _hash(partitioned), "planning_policy_sha256": _hash(policy)}
    if _path(out, "plan/manifest.json").exists():
        complete = _json(out, "plan/manifest.json")
        _require(all(complete.get(key) == value for key, value in bindings.items()), "resume_mismatch")
        validate_bundle(complete, program_map, out=out, language=language, max_functions=max_functions)
        return complete
    progress = {"schema": "hive.planning-progress/1", "bindings": bindings, "groups": {}, "resolutions": {}}
    if saved is not None:
        _require(type(saved) is dict and set(saved) == set(progress) and saved["schema"] == progress["schema"]
                 and saved["bindings"] == bindings and saved == _json(out, "plan/progress.json"), "resume_mismatch")
        _require(type(saved["groups"]) is dict and set(saved["groups"]) <= {g["id"] for g in groups}
                 and type(saved["resolutions"]) is dict, "resume_mismatch")
        progress = json.loads(encode(saved))
    _write_json(out, "plan/policy.json", policy)
    _write_json(out, "plan/partition.json", partitioned)
    for name, payload in partitioned["side_files"].items():
        _write_json(out, "plan/evidence/" + name, payload)
    _write_json(out, "plan/progress.json", progress)
    proposals, attempts = [], []
    for group in groups:
        gid = group["id"]
        record = progress["groups"].get(gid)
        if record is not None:
            _require(type(record) is dict and set(record) == {"proposal", "attempts"}, "resume_mismatch")
            output = _checked(out, record["proposal"])
            ids = record["attempts"]
            _require(type(ids) is list and ids and all(isinstance(i, str) and i for i in ids), "resume_mismatch")
        else:
            task = (f"Plan only group {gid} in {language}; max {max_functions} functions per module. "
                    "Read map.json, summary.json and interfaces.json. If paged=true, read one page at a time: "
                    "pages lists relative paths and SHA-256; index pages contain further page references. "
                    "Data rows carry path/value records. Follow every page, including overflow and cut edges; "
                    "do not infer missing rows from summary samples. MCP may query individual functions. "
                    "Assign each group function exactly once to modules or skipped with reason/evidence. "
                    "Return modules, skipped, declarations and unknowns matching the supplied schema. "
                    "Declare dependencies with entity_id, globals with linkage and owner_entry; use evidence. "
                    "A dependency in another group is never an assignment. Do not write the shared contract. "
                    "Unknown layouts stay unknown; opaque types cross interfaces only by pointer/reference.")
            folder, protected = _group_files(out, group, partitioned, task, max_prompt_bytes)
            output, ids = _invoke(invoke, "planner-" + gid, task, folder, GROUP_SCHEMA)
            for ref in protected:
                _require(_sha(_read(out, ref["path"])) == ref["sha256"], "planning_evidence_changed", path=ref["path"])
            _group_output(output, group, language, known)
            ref = _write_json(out, f"plan/proposals/{gid}.json", output)
            _require(not output["unknowns"], "interface_conflict", group=gid, unknowns=output["unknowns"])
            progress["groups"][gid] = {"proposal": ref, "attempts": ids}
            _write_json(out, "plan/progress.json", progress)
        _group_output(output, group, language, known)
        _require(not output["unknowns"], "interface_conflict", group=gid, unknowns=output["unknowns"])
        proposals.append(output)
        attempts.extend(ids)
    modules, skipped = _modules(proposals, known, max_functions)
    variants = _variants(proposals, language, known)
    declarations = []
    for key, values in variants.items():
        if len(values) == 1:
            declarations.append(values[0])
            continue
        choices = [{"variant_sha256": _hash(value), "declaration": value} for value in values]
        relevant = set().union(*(set(value["requires"]) for value in values))
        while True:
            expanded = relevant | {dependency for entity in relevant for variant in variants.get(entity, [])
                                   for dependency in variant["requires"]}
            if expanded == relevant:
                break
            relevant = expanded
        conflict = {"entity_id": key, "variants": choices,
                    "dependencies": {entity: variants[entity] for entity in sorted(relevant) if entity in variants},
                    "cut_edges": [edge for edge in cuts if any(value["entry"] in (_address(edge["from"]), _address(edge["to"])) for value in values)]}
        conflict_id = _hash({"entity_id": key, "variants": choices})[:12]
        record = progress["resolutions"].setdefault(conflict_id, {"rounds": []})
        _require(type(record) is dict and set(record) == {"rounds"} and type(record["rounds"]) is list
                 and len(record["rounds"]) <= interface_rounds, "resume_mismatch", entity=key)
        selection = None
        for index in range(interface_rounds):
            if index < len(record["rounds"]):
                reply = _checked(out, record["rounds"][index])
                answer, ids = reply["output"], reply["attempts"]
                _schema(answer, INTERFACE_SCHEMA)
                _require(type(ids) is list and ids and all(isinstance(i, str) and i for i in ids), "resume_mismatch")
            else:
                name = f"planner-interface-{conflict_id}-r{index + 1}"
                task = ("Resolve only the conflict in interfaces.json. Choose exactly one existing variant by "
                        "entity_id and variant_sha256 and cite evidence. Do not create declaration bytes. "
                        "If no existing variant is supported, return choices=[]; read one page at a time when paged=true.")
                folder = f"plan/interfaces/{conflict_id}/r{index + 1}"
                protected = []
                payload = conflict
                if len(encode(payload)) + len(task.encode()) > max_prompt_bytes:
                    payload = _pages(out, folder, "conflict", _records(conflict), max_prompt_bytes, protected)
                _require(len(encode(payload)) + len(task.encode()) <= max_prompt_bytes, "planning_payload_too_large", entity=key)
                protected.append(_write_json(out, folder + "/interfaces.json", payload))
                answer, ids = _invoke(invoke, name, task, _path(out, folder), INTERFACE_SCHEMA)
                for ref in protected:
                    _require(_sha(_read(out, ref["path"])) == ref["sha256"], "planning_evidence_changed")
                record["rounds"].append(_write_json(out, folder + "/answer.json", {"output": answer, "attempts": ids}))
                _write_json(out, "plan/progress.json", progress)
            attempts.extend(ids)
            if len(answer["choices"]) == 1:
                choice = answer["choices"][0]
                if choice["entity_id"] == key and _evidence(choice["evidence"]) and choice["variant_sha256"] in {c["variant_sha256"] for c in choices}:
                    selection = choice
                    break
        _require(selection is not None, "interface_conflict", entity=key)
        selected = [value for value in values if _hash(value) == selection["variant_sha256"]]
        _require(len(selected) == 1, "interface_conflict", entity=key, reason="invented variant")
        declarations.append(selected[0])
    function_owners = {entry: module for module in modules for entry in module["functions"]}
    for declaration in declarations:
        if declaration["kind"] == "global" and declaration["linkage"] == "defined":
            _require(declaration["owner_entry"] in function_owners, "interface_conflict", entity=declaration["entity_id"])
            function_owners[declaration["owner_entry"]]["globals"].append(declaration["entity_id"])
    for module in modules:
        module["globals"].sort()
    interfaces, contract = _interfaces(declarations, modules, skipped, known, cuts, language)
    contract_path = "plan/contract.h" if language == "c" else "plan/contract.hpp"
    _write(out, contract_path, contract)
    _write_json(out, "plan/interfaces.json", interfaces)
    bundle = {"schema": "hive.plan/1", **bindings, "language": language, "modules": modules, "skipped": skipped,
              "contract_path": contract_path, "contract_sha256": _sha(contract), "interfaces_path": "plan/interfaces.json",
              "interfaces_sha256": _hash(interfaces), "planner_attempts": list(dict.fromkeys(attempts))}
    bundle["plan_id"] = _identity(bundle)
    _write_json(out, "plan/manifest.json", bundle)
    validate_bundle(bundle, program_map, out=out, language=language, max_functions=max_functions)
    return bundle


def plan(program_map, partitioned, *, out, invoke, language, max_functions=12,
         max_prompt_bytes=65536, interface_rounds=2, saved=None):
    """Propose and verify interfaces; the caller still compiles and freezes the contract.

    Resume accepts the verified dict read from plan/progress.json. Page and proposal
    files are read-only queen inputs; invoke must stage every attempt separately.
    """
    try:
        return _plan(program_map, partitioned, out=out, invoke=invoke, language=language,
                     max_functions=max_functions, max_prompt_bytes=max_prompt_bytes,
                     interface_rounds=interface_rounds, saved=saved)
    except PlanningError:
        raise
    except (KeyError, TypeError, ValueError, UnicodeError) as error:
        raise PlanningError("invalid_planning_data", {"error": type(error).__name__}) from None


def validate_bundle(bundle, program_map, *, out, language, max_functions):
    """Recheck the manifest and its byte-bound inputs without invoking a model."""
    try:
        _validate_bundle(bundle, program_map, out=out, language=language, max_functions=max_functions)
    except PlanningError:
        raise
    except (KeyError, TypeError, ValueError, UnicodeError) as error:
        raise PlanningError("resume_mismatch", {"error": type(error).__name__}) from None


def _validate_bundle(bundle, program_map, *, out, language, max_functions):
    _require(type(bundle) is dict and set(bundle) == _BUNDLE and bundle["schema"] == "hive.plan/1", "resume_mismatch")
    _require(not Path(out).is_symlink(), "unsafe_planning_path")
    out = Path(out).resolve()
    _require(bundle == _json(out, "plan/manifest.json") and bundle["language"] == language
             and bundle["input_sha256"] == program_map["input_sha256"] and bundle["map_sha256"] == _hash(program_map), "resume_mismatch")
    policy = _json(out, "plan/policy.json")
    _require(policy == _policy(language, max_functions, policy["max_prompt_bytes"], policy["interface_rounds"])
             and _hash(policy) == bundle["planning_policy_sha256"], "resume_mismatch", reason="policy")
    partitioned = _json(out, "plan/partition.json")
    _, known, cuts = _validate_partition(program_map, partitioned)
    _require(_hash(partitioned) == bundle["partition_sha256"], "resume_mismatch")
    for name, value in partitioned["side_files"].items():
        _require(_read(out, "plan/evidence/" + name) == encode(value), "resume_mismatch", overflow=name)
    modules, skipped = bundle["modules"], bundle["skipped"]
    _require(type(modules) is list and type(skipped) is list, "resume_mismatch")
    for index, module in enumerate(modules, 1):
        _require(type(module) is dict and set(module) == {"id", "title", "functions", "globals"}
                 and module["id"] == f"m{index:02d}" and isinstance(module["title"], str) and module["title"]
                 and type(module["functions"]) is list and 0 < len(module["functions"]) <= max_functions
                 and module["functions"] == sorted(module["functions"], key=lambda entry: int(entry, 16))
                 and type(module["globals"]) is list, "resume_mismatch")
    ordered = sorted(modules, key=lambda m: int(m["functions"][0], 16))
    _require(modules == ordered, "resume_mismatch", reason="module order")
    for skip in skipped:
        _schema(skip, _SKIP)
        _require(_evidence(skip["evidence"]), "resume_mismatch")
    assigned = [entry for m in modules for entry in m["functions"]] + [s["entry"] for s in skipped]
    _require(Counter(assigned) == Counter(known.keys()), "resume_mismatch", reason="coverage")
    expected_path = "plan/contract.h" if language == "c" else "plan/contract.hpp"
    _require(bundle["contract_path"] == expected_path and bundle["interfaces_path"] == "plan/interfaces.json", "resume_mismatch")
    actual_interfaces = _json(out, bundle["interfaces_path"])
    expected_interfaces, contract = _interfaces(actual_interfaces["declarations"], modules, skipped, known, cuts, language)
    _require(actual_interfaces == expected_interfaces and _sha(_read(out, expected_path)) == bundle["contract_sha256"]
             and _read(out, expected_path) == contract and _hash(actual_interfaces) == bundle["interfaces_sha256"]
             and _identity(bundle) == bundle["plan_id"], "resume_mismatch", reason="interfaces or contract")
    _require(type(bundle["planner_attempts"]) is list and all(isinstance(i, str) and i for i in bundle["planner_attempts"])
             and len(bundle["planner_attempts"]) == len(set(bundle["planner_attempts"])), "resume_mismatch", reason="provenance")
