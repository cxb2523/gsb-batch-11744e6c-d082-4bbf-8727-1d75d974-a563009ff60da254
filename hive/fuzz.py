"""Deterministic file mutations and reports; execution stays in queen.run_cases."""

import base64
import copy
import hashlib
import json
from pathlib import Path
import random
import re

MAX_MUTANTS = 500
ATTEMPTS_PER_MUTANT = 20
MUTATORS = ("bitflip", "insert", "delete", "truncate", "boundary", "splice")
BOUNDARIES = (0x00, 0xff, 0x7f, 0x80)


def count(value):
    """Validate both the command-line count and the Python keyword."""
    if isinstance(value, str) and re.fullmatch(r"[0-9]+", value):
        value = int(value)
    if type(value) is not int or not 0 <= value <= MAX_MUTANTS:
        raise ValueError(f"fuzz count must be between 0 and {MAX_MUTANTS}")
    return value


def mutate(data, operation, rng, max_file_size, other=b""):
    """Apply one bounded byte operation; arguments and filenames are never involved."""
    data = data[:max_file_size]
    if operation == "bitflip":
        if not data:
            result = bytes([1 << rng.randrange(8)])
        else:
            at = rng.randrange(len(data))
            result = data[:at] + bytes([data[at] ^ (1 << rng.randrange(8))]) + data[at + 1:]
    elif operation == "insert":
        at = rng.randrange(len(data) + 1)
        result = data[:at] + bytes([rng.randrange(256)]) + data[at:]
    elif operation == "delete":
        at = rng.randrange(len(data)) if data else 0
        result = data[:at] + data[at + 1:]
    elif operation == "truncate":
        result = data[:rng.randrange(len(data))] if data else b""
    elif operation == "boundary":
        at = rng.randrange(len(data)) if data else 0
        choices = [value for value in BOUNDARIES if not data or value != data[at]]
        result = data[:at] + bytes([rng.choice(choices)]) + data[at + 1:]
    elif operation == "splice":
        other = other[:max_file_size]
        result = data[:rng.randrange(len(data) + 1)] + other[rng.randrange(len(other) + 1):]
    else:
        raise ValueError(f"unknown fuzz mutator: {operation}")
    return result[:max_file_size]


def _written_name(name):
    """A file's relative destination in the fresh case folder, or None when run_cases skips it."""
    path = Path(name)
    if path.is_absolute() or path.drive:
        return None
    parts = []
    for part in path.parts:
        if part == "..":
            if not parts:
                return None
            parts.pop()
        elif part != ".":
            parts.append(part)
    return str(Path(*parts)) if parts else None


def _input_key(case):
    # Later entries for the same destination overwrite earlier ones before any step runs.
    files = {_written_name(item["name"]): item["base64"] for item in case["files"]}
    steps = [{"args": step["args"], "stdin": step.get("stdin")} for step in case["steps"]]
    return hashlib.sha256(json.dumps([files, steps], sort_keys=True, separators=(",", ":")).encode()).digest()


def generate(cases, input_sha256, total, max_file_size):
    """At most total fresh case IDs, seeded by the input hash and each normalised source ID."""
    total = count(total)
    if not total:
        return []
    if not isinstance(input_sha256, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", input_sha256):
        raise ValueError("fuzzing needs the input SHA-256")
    if type(max_file_size) is not int or max_file_size < 1:
        raise ValueError("fuzz file cap must be positive")
    reserved, sources, seen = set(), [], set()
    for case in cases:
        if not isinstance(case.get("id"), str):
            raise ValueError("fuzz source cases need string IDs")
        name = re.sub(r"[^A-Za-z0-9_.-]", "_", case["id"])[:64]
        if not name or name in reserved:
            raise ValueError("fuzz source IDs must be unique after normalisation")
        reserved.add(name)
        source = copy.deepcopy(case)
        source["id"] = name
        kept, data, destinations = [], [], {}
        for item in case.get("files", []):
            destination = _written_name(item["name"])
            if destination is None:
                continue  # Match run_cases: an escaping entry is not decoded or written.
            destinations[destination] = len(kept)
            kept.append(item)
            data.append((base64.b64decode(item["base64"]) if item.get("base64")
                         else item.get("text", "").encode())[:max_file_size])
        source["files"] = [{"name": item["name"], "base64": base64.b64encode(content).decode("ascii")}
                           for item, content in zip(kept, data)]
        seen.add(_input_key(source))
        if data:
            seed = hashlib.sha256(f"hive-fuzz-v1\0{input_sha256.lower()}\0{name}".encode()).digest()
            sources.append((source, data, random.Random(int.from_bytes(seed, "big")), tuple(destinations.values())))
    sources.sort(key=lambda item: item[0]["id"])
    if not sources:
        return []
    operations = MUTATORS if len(sources) > 1 else MUTATORS[:-1]
    mutants, sequence = [], 1
    visits = list(range(len(sources)))
    for attempt in range(total * ATTEMPTS_PER_MUTANT):
        if len(mutants) == total:
            break
        index = attempt % len(sources)
        source, files, rng, written = sources[index]
        operation = operations[visits[index] % len(operations)]
        visits[index] += 1  # An independent cycle for each source, including rejected attempts.
        at, other = rng.choice(written), b""
        if operation == "splice":
            donors = [contents[index] for case, contents, _, active in sources
                      if case["id"] != source["id"] for index in active]
            other = rng.choice(donors)
        mutant = copy.deepcopy(source)
        changed = mutate(files[at], operation, rng, max_file_size, other)
        mutant["files"][at]["base64"] = base64.b64encode(changed).decode("ascii")
        identity = _input_key(mutant)
        if identity in seen:
            continue
        seen.add(identity)
        while True:
            suffix = f"-{sequence}"
            name = "fz-" + source["id"][:64 - 3 - len(suffix)] + suffix
            sequence += 1
            if name not in reserved:
                break
        reserved.add(name)
        mutant["id"] = name
        mutants.append(mutant)
    return mutants


def summarise(cases, original, rebuilt, seed, compare):
    """Compare every complete pair, keeping missing or timed-out mutants separate."""
    def complete(case, executions):
        row = executions.get(case["id"]) if isinstance(executions, dict) else None
        steps = row.get("steps") if isinstance(row, dict) else None
        return (bool(case.get("steps")) and isinstance(steps, list) and len(steps) == len(case["steps"])
                and all(isinstance(step, dict) and type(step.get("code")) is int for step in steps))
    unique = len({case["id"] for case in cases}) == len(cases)
    completed, incomplete = [], []
    for case in cases:
        target = completed if unique and complete(case, original) and complete(case, rebuilt) else incomplete
        target.append(case["id"])
    same, different = compare({key: original[key] for key in completed}, {key: rebuilt[key] for key in completed})
    result = {"cases": len(cases), "completed": len(completed), "identical": len(same), "different": different,
              "incomplete": incomplete, "seed": seed, "ran": bool(cases) and not incomplete}
    if incomplete:
        result["reason"] = f"{len(incomplete)} fuzz mutant(s) incomplete or timed out: " + ", ".join(incomplete)
    elif not cases:
        result["reason"] = "no distinct mutants (no case files or attempts exhausted)"
    return result


def write_report(path, summary, cases):
    """Keep bounded reproduction inputs for differing and incomplete mutants."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    retained = set(summary["different"]) | set(summary.get("incomplete", []))
    with path.open("w", encoding="utf-8") as handle:
        json.dump(dict(summary, inputs=[case for case in cases if case["id"] in retained]), handle,
                  indent=1, ensure_ascii=False)
        handle.write("\n")
