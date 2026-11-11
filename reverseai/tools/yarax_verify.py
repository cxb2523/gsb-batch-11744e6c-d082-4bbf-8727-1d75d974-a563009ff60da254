"""Verify contained signature matches against the host's pinned literal patterns."""

import json
from pathlib import Path
import re
from types import MappingProxyType

from reverseai.contained import ContainedError
from reverseai.contract import ContractError, sha256_hex

RULESET = "m2_fixture_v1"
REFUSED = "Worker match not confirmed by the bytes"
KEYWORDS = frozenset((
    "all and any ascii at base64 base64wide condition contains defined endswith entrypoint false filesize for fullword "
    "global icontains iendswith iequals import in include istartswith matches meta none nocase not of or private rule "
    "startswith strings them true wide with xor").split())


def load_patterns(path, expected_sha256):
    """Freeze the reviewed ruleset before an executor can run; errors never include paths or file content."""
    try:
        with Path(path).open("rb") as stream:
            raw = stream.read(65_537)
        if len(raw) > 65_536 or sha256_hex(raw) != expected_sha256:
            raise ValueError
        value = json.loads(raw, object_pairs_hook=lambda pairs: dict(pairs) if len({k for k, _ in pairs}) == len(pairs) else None)
        if set(value) != {"ruleset", "rules"} or value["ruleset"] != RULESET or not value["rules"]:
            raise ValueError
        patterns, rules = {}, set()
        for rule in value["rules"]:
            if (set(rule) != {"id", "category", "patterns"} or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", rule["id"])
                    or rule["id"] in rules or rule["id"] in KEYWORDS or not rule["patterns"]
                    or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", rule["category"])):
                raise ValueError
            rules.add(rule["id"])
            for pattern in rule["patterns"]:
                if (set(pattern) != {"id", "hex"} or not re.fullmatch(r"\$[a-z0-9_]{1,32}", pattern["id"])
                        or not re.fullmatch(r"(?:[0-9a-f]{2}){4,256}", pattern["hex"])):
                    raise ValueError
                key = (rule["id"], pattern["id"])
                if key in patterns:
                    raise ValueError
                patterns[key] = bytes.fromhex(pattern["hex"])
        if len(patterns) * 4 > 64:
            raise ValueError
        return MappingProxyType(patterns)
    except (OSError, ValueError, TypeError, KeyError):
        raise ContainedError("InvalidRuleset") from None


def verify(data, observations, args, patterns):
    """Verify the entire reply before admitting any observation; omissions are allowed, inventions are not."""
    if args["ruleset"] != RULESET or len(observations) > args["max_matches"]:
        raise ContractError(REFUSED)
    previous, counts = None, {}
    for item in observations:
        value, location = item.value, item.location
        if (set(value) != {"ruleset", "rule", "pattern"} or value["ruleset"] != args["ruleset"]
                or not isinstance(value["rule"], str) or not isinstance(value["pattern"], str)):
            raise ContractError(REFUSED)
        pattern = patterns.get((value["rule"], value["pattern"]))
        key = (location.offset, value["rule"], value["pattern"])
        counts[key[1:]] = counts.get(key[1:], 0) + 1
        if (pattern is None or location.length != len(pattern) or not location.within(len(data))
                or data[location.offset:location.offset + location.length] != pattern
                or counts[key[1:]] > 4 or (previous is not None and key <= previous)):
            raise ContractError(REFUSED)
        previous = key
