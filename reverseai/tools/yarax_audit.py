"""Audit a contained YARA-X match reply as pure data, without containers or the network.

`audit_matches` re-implements every check of `yarax_verify.verify` over a plain-data
snapshot (the scanned bytes, the request arguments, the local pattern table and the
worker's observations) and reports a structured, JSON-serializable verdict instead of
raising. It never starts a container, never touches DockerExecutor, never reaches the
network and never mutates its inputs.

For the same data, valid request arguments (as produced by the operation's
``validate_args``), pattern table and observations, ``audit_matches(...)["all_accepted"]``
is True exactly when `yarax_verify.verify` returns without raising ``ContractError``:
a reply is admitted only whole, so a single failed check rejects the observation it
belongs to and the reply as a whole. Malformed inputs (empty data, missing fields, a
non-dict value) degrade into readable failed checks instead of exceptions.
"""

import json
import math
from collections.abc import Mapping
from pathlib import Path

from reverseai.contained import ContainedError
from reverseai.contract import sha256_hex
from reverseai.tools import yarax_verify

RULESET = yarax_verify.RULESET
VALUE_KEYS = ("ruleset", "rule", "pattern")
MAX_OCCURRENCES = 4
MIN_MAX_MATCHES = 1
MAX_MAX_MATCHES = 64

_MISSING = object()


def default_ruleset_path():
    """The reviewed ruleset next to the installed image lock, or the source checkout's."""
    package = Path(__file__).resolve().parents[1]
    packaged = package / "_locks" / "m2_fixture_v1.json"
    return packaged if packaged.is_file() else package.parent / "containers" / "yarax" / "m2_fixture_v1.json"


def load_default_patterns(path=None):
    """Best-effort local pattern table for callers that do not pass one; never raises."""
    path = default_ruleset_path() if path is None else path
    try:
        digest = sha256_hex(Path(path).read_bytes())
        return dict(yarax_verify.load_patterns(path, digest)), None
    except (OSError, ContainedError):
        return {}, "local pattern table unavailable"


def _shown(value, limit=60):
    """A short readable rendering of an arbitrary input value, for reason strings."""
    if value is _MISSING:
        return "<missing>"
    text = value if isinstance(value, str) else repr(value)
    return text if len(text) <= limit else text[:limit] + "..."


def _json_safe(value):
    """Echo an arbitrary input value in a form `json.dumps` always accepts."""
    if value is _MISSING:
        return None
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else repr(value)
    return repr(value)[:120]


def _fields(item):
    """Pull (offset, length, value) out of a plain mapping or an Observation-like object."""
    if isinstance(item, Mapping):
        value = item.get("value", _MISSING)
        location = item.get("location")
        if isinstance(location, Mapping):
            return location.get("offset", _MISSING), location.get("length", _MISSING), value, True
        return item.get("offset", _MISSING), item.get("length", _MISSING), value, True
    if hasattr(item, "location") and hasattr(item, "value"):
        location = item.location
        return (getattr(location, "offset", _MISSING), getattr(location, "length", _MISSING),
                item.value, True)
    return _MISSING, _MISSING, _MISSING, False


def audit_matches(data, args, observations, patterns=None):
    """Audit one `yarax.matches` reply; the result is plain JSON-serializable data."""
    checks = []

    def record(name, passed, reason=None):
        checks.append({"name": name, "passed": bool(passed),
                       "reason": None if passed else str(reason)})
        return checks[-1]["passed"]

    if isinstance(data, (bytes, bytearray)):
        blob = bytes(data)
        record("data_is_bytes", True)
    else:
        blob = b""
        record("data_is_bytes", False, f"data is {type(data).__name__}, not bytes; audited as empty")

    if isinstance(args, Mapping):
        request = args
        record("args_is_mapping", True)
    else:
        request = {}
        record("args_is_mapping", False, f"args is {type(args).__name__}, not a mapping")
    requested_ruleset = request.get("ruleset", _MISSING)
    record("args_ruleset_is_m2_fixture_v1", requested_ruleset == RULESET,
           f"ruleset is {_shown(requested_ruleset)!r}, expected {RULESET!r}")
    max_matches = request.get("max_matches", _MISSING)
    max_ok = record("args_max_matches_int_1_to_64",
                    type(max_matches) is int and MIN_MAX_MATCHES <= max_matches <= MAX_MAX_MATCHES,
                    f"max_matches is {_shown(max_matches)!r}, expected an int between 1 and 64 (booleans refused)")

    if isinstance(observations, (list, tuple)):
        items = list(observations)
        record("observations_is_list", True)
    else:
        items = []
        record("observations_is_list", False,
               f"observations is {type(observations).__name__}, not a list; audited as empty")

    if max_ok:
        record("observation_count_within_max_matches", len(items) <= max_matches,
               f"{len(items)} observations exceed max_matches {max_matches}")
    else:
        record("observation_count_within_max_matches", False, "not evaluated: max_matches is invalid")

    patterns_error = None
    if patterns is None:
        table, patterns_error = load_default_patterns()
        record("patterns_loaded", patterns_error is None, patterns_error)
    elif isinstance(patterns, Mapping):
        table = patterns
        record("patterns_loaded", True)
    else:
        table = {}
        patterns_error = f"patterns is {type(patterns).__name__}, not a mapping"
        record("patterns_loaded", False, patterns_error)

    counts, previous, audited = {}, None, []
    for index, item in enumerate(items):
        local = []

        def orecord(name, passed, reason=None):
            entry = {"name": name, "passed": bool(passed),
                     "reason": None if passed else str(reason)}
            local.append(entry)
            checks.append({"name": f"observation[{index}].{name}",
                           "passed": entry["passed"], "reason": entry["reason"]})
            return entry["passed"]

        offset, length, value, shape_ok = _fields(item)
        if not shape_ok:
            orecord("observation_shape", False,
                    f"observation is {type(item).__name__}, not a mapping with offset/length/value")

        is_dict = orecord("value_is_dict", isinstance(value, dict),
                          "value is missing" if value is _MISSING
                          else f"value is {type(value).__name__}, not a dict")
        if is_dict:
            keys = set(value)
            orecord("value_keys_exact", keys == set(VALUE_KEYS),
                    f"value keys are {sorted(map(str, keys))}, expected exactly {sorted(VALUE_KEYS)}")
            actual_ruleset = value.get("ruleset", _MISSING)
            orecord("value_ruleset_matches_request", actual_ruleset == requested_ruleset,
                    f"value.ruleset is {_shown(actual_ruleset)!r}, request ruleset is "
                    f"{_shown(requested_ruleset)!r}")
        else:
            orecord("value_keys_exact", False, "not evaluated: value is not a dict")
            orecord("value_ruleset_matches_request", False, "not evaluated: value is not a dict")

        rule = value.get("rule", _MISSING) if is_dict else _MISSING
        pattern_id = value.get("pattern", _MISSING) if is_dict else _MISSING
        rule_ok = orecord("rule_is_string", isinstance(rule, str),
                          f"rule is {_shown(rule)!r}, expected a string")
        pattern_ok = orecord("pattern_is_string", isinstance(pattern_id, str),
                             f"pattern is {_shown(pattern_id)!r}, expected a string")
        offset_ok = orecord("offset_valid", type(offset) is int and offset >= 0,
                            f"offset is {_shown(offset)!r}, expected a non-negative int")
        length_ok = orecord("length_valid", type(length) is int and length > 0,
                            f"length is {_shown(length)!r}, expected a positive int")

        pattern_bytes = None
        if rule_ok and pattern_ok:
            candidate = table.get((rule, pattern_id))
            if candidate is not None and not isinstance(candidate, (bytes, bytearray)):
                orecord("pattern_in_local_table", False,
                        f"table entry for ({rule!r}, {pattern_id!r}) is not bytes")
            else:
                pattern_bytes = None if candidate is None else bytes(candidate)
                orecord("pattern_in_local_table", pattern_bytes is not None,
                        f"({_shown(rule)!r}, {_shown(pattern_id)!r}) is not in the local pattern table")
        else:
            orecord("pattern_in_local_table", False,
                    "not evaluated: rule and pattern must be strings")

        if pattern_bytes is not None and length_ok:
            orecord("length_matches_pattern", length == len(pattern_bytes),
                    f"length {length} differs from pattern length {len(pattern_bytes)}")
        else:
            orecord("length_matches_pattern", False,
                    "not evaluated: needs a known pattern and a valid length")

        if offset_ok and length_ok:
            orecord("range_within_data", offset + length <= len(blob),
                    f"[{offset}, {offset + length}) exceeds data length {len(blob)}")
        else:
            orecord("range_within_data", False, "not evaluated: offset and length must be valid")

        if pattern_bytes is not None and offset_ok and length_ok:
            orecord("bytes_match_pattern", blob[offset:offset + length] == pattern_bytes,
                    "declared bytes differ from the local pattern")
        else:
            orecord("bytes_match_pattern", False,
                    "not evaluated: needs a known pattern and a valid range")

        occurrence = None
        if rule_ok and pattern_ok:
            key = (rule, pattern_id)
            counts[key] = counts.get(key, 0) + 1
            occurrence = counts[key]
            orecord("occurrence_cap_at_most_4", occurrence <= MAX_OCCURRENCES,
                    f"({_shown(rule)!r}, {_shown(pattern_id)!r}) occurs {occurrence} times, "
                    f"at most {MAX_OCCURRENCES} allowed")
        else:
            orecord("occurrence_cap_at_most_4", False,
                    "not evaluated: rule and pattern must be strings")

        if index == 0:
            orecord("strictly_increasing", True)
        elif offset_ok and rule_ok and pattern_ok and previous is not None:
            current = (offset, rule, pattern_id)
            orecord("strictly_increasing", current > previous,
                    f"key {current!r} does not strictly follow {previous!r}")
        else:
            orecord("strictly_increasing", False,
                    "not evaluated: needs a valid offset, string rule/pattern and a previous key")
        if offset_ok and rule_ok and pattern_ok:
            previous = (offset, rule, pattern_id)

        accepted = all(entry["passed"] for entry in local)
        reasons = [f"{entry['name']}: {entry['reason']}" for entry in local if not entry["passed"]]
        audited.append({"index": index, "accepted": accepted, "occurrence_count": occurrence,
                        "reasons": reasons, "checks": local})

    rejected = [{"index": entry["index"], "reasons": entry["reasons"]}
                for entry in audited if not entry["accepted"]]
    arg_entries = [entry for entry in checks if entry["name"].startswith("args_")]
    return {
        "ruleset_expected": RULESET,
        "data_sha256": sha256_hex(blob),
        "data_length": len(blob),
        "args": {
            "valid": all(entry["passed"] for entry in arg_entries),
            "ruleset": _json_safe(requested_ruleset),
            "max_matches": _json_safe(max_matches),
            "errors": [entry["reason"] for entry in arg_entries if not entry["passed"]],
        },
        "patterns": {
            "source": "caller" if patterns is not None else "default",
            "count": len(table),
            "error": patterns_error,
        },
        "observation_count": len(items),
        "accepted_count": sum(1 for entry in audited if entry["accepted"]),
        "rejected_count": len(rejected),
        "all_accepted": all(entry["passed"] for entry in checks),
        "observations": audited,
        "rejected": rejected,
        "checks": checks,
    }
