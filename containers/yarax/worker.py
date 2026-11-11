"""ReverseAI YARA-X worker: one operation on /snapshot/input, one reverseai.worker/1 JSON object on stdout.

Entrypoint (docs/contract.md, "Contained YARA-X worker (M2b)"):
    python3 -I -B /opt/reverseai/worker.py yarax.matches <canonical JSON of validated args>

The only rule source is the reviewed ruleset file next to this worker in the image.
The worker checks its shape, generates YARA source from it (one hex string per
pattern, every rule with condition `any of them`) and compiles that source with
yara_x on every run: includes are off, no module may be imported, no external
variable is defined, and compiled or serialized rules are never loaded. The scan
has an explicit timeout below the 45 s wall limit, fast scan off (every match is
tracked) and a per-pattern match limit of 4 (decision m2b-per-pattern-cap): a ruleset
whose pattern count times 4 exceeds the largest max_matches is refused, so a flood of
one pattern can never hide another rule's match. A literal pattern's matches are found
in offset order, so each pattern reports its first 4.
Every match is checked against the bytes: its rule and pattern must be in the
ruleset, its length the pattern's length and the input at its offset the pattern's
bytes, else InconsistentMatch. Matches are reported once each, in ascending
(offset, rule, pattern) order, cut at max_matches. Errors are class names only.
Nothing but the one JSON object is written, to stdout only. The functions take
bytes and plain values, so they are testable without yara_x.
"""

import hashlib
import json
from pathlib import Path
import re
import sys

PROTOCOL = "reverseai.worker/1"
ADAPTER_VERSION = "1.21.0-r2"
SNAPSHOT = "/snapshot/input"
RULESETS = ("m2_fixture_v1",)  # each is <name>.json next to this file
MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_RULESET_BYTES = 64 * 1024
MATCHES = (1, 64, 32)  # max_matches: minimum, maximum, default
SCAN_TIMEOUT = 30  # seconds, below the executor's 45 s wall limit
MATCHES_PER_PATTERN = 4  # pattern count x 4 must stay within MATCHES[1]
PATTERN_BYTES = (4, 256)
ALLOWED_WARNING = "text_as_hex"
RULE_ID = re.compile(r"[a-z][a-z0-9_]{0,63}")
PATTERN_ID = re.compile(r"\$[a-z0-9_]{1,32}")
HEX = re.compile(r"(?:[0-9a-f]{2})+")
# YARA keywords that a lower-case rule id could collide with; the build-time compile would catch the rest.
KEYWORDS = frozenset({
    "all", "and", "any", "ascii", "at", "base64", "base64wide", "condition", "contains", "defined", "endswith", "entrypoint",
    "false", "filesize", "for", "fullword", "global", "icontains", "iendswith", "iequals", "import", "in", "include",
    "istartswith", "matches", "meta", "none", "nocase", "not", "of", "or", "private", "rule", "startswith", "strings", "them",
    "true", "wide", "with", "xor"})


class WorkerFailure(Exception):
    """An expected refusal; its class name is the reply's error."""


class InvalidRequest(WorkerFailure):
    pass


class InputTooLarge(WorkerFailure):
    pass


class SnapshotUnreadable(WorkerFailure):
    pass


class RulesetInvalid(WorkerFailure):
    """The ruleset file is missing, too large or not the reviewed shape, or its source does not compile cleanly."""


class ScanTimeout(WorkerFailure):
    pass


class ScanFailed(WorkerFailure):
    pass


class InconsistentMatch(WorkerFailure):
    """yara_x reported a match the bytes or the ruleset do not confirm."""


# ---- Ruleset and YARA source -------------------------------------------------

def check_ruleset(value, name):
    """The reviewed shape only: a dict per rule with an id, a category and literal hex patterns of 4 to 256 bytes."""
    if not isinstance(value, dict) or set(value) != {"ruleset", "rules"} or value["ruleset"] != name:
        raise RulesetInvalid()
    rules = value["rules"]
    if not isinstance(rules, list) or not rules:
        raise RulesetInvalid()
    checked, seen = [], set()
    for rule in rules:
        if not isinstance(rule, dict) or set(rule) != {"id", "category", "patterns"}:
            raise RulesetInvalid()
        rule_id, category, patterns = rule["id"], rule["category"], rule["patterns"]
        if (not isinstance(rule_id, str) or not RULE_ID.fullmatch(rule_id) or rule_id in KEYWORDS or rule_id in seen
                or not isinstance(category, str) or not RULE_ID.fullmatch(category)
                or not isinstance(patterns, list) or not patterns):
            raise RulesetInvalid()
        seen.add(rule_id)
        literal = {}
        for pattern in patterns:
            if not isinstance(pattern, dict) or set(pattern) != {"id", "hex"}:
                raise RulesetInvalid()
            pattern_id, text = pattern["id"], pattern["hex"]
            if (not isinstance(pattern_id, str) or not PATTERN_ID.fullmatch(pattern_id) or pattern_id in literal
                    or not isinstance(text, str) or not HEX.fullmatch(text)
                    or not PATTERN_BYTES[0] <= len(text) // 2 <= PATTERN_BYTES[1]):
                raise RulesetInvalid()
            literal[pattern_id] = bytes.fromhex(text)
        checked.append((rule_id, literal))
    if sum(len(literal) for _, literal in checked) * MATCHES_PER_PATTERN > MATCHES[1]:
        raise RulesetInvalid()  # max_matches 64 must hold every pattern's capped matches
    return checked


def load_ruleset(name, folder=None):
    """{rule id: {pattern id: bytes}} from <name>.json, the reviewed file built into the image."""
    if name not in RULESETS:
        raise RulesetInvalid()
    path = Path(folder or Path(__file__).resolve().parent) / (name + ".json")
    try:
        with open(path, "rb") as handle:
            raw = handle.read(MAX_RULESET_BYTES + 1)
        if len(raw) > MAX_RULESET_BYTES:
            raise RulesetInvalid()
        value = json.loads(raw, object_pairs_hook=lambda pairs: dict(pairs) if len({k for k, _ in pairs}) == len(pairs) else None)
    except (OSError, ValueError):
        raise RulesetInvalid() from None
    return dict(check_ruleset(value, name))


def yara_source(ruleset):
    """One rule per ruleset entry, one hex string per pattern, condition `any of them`; nothing else."""
    blocks = []
    for rule_id, patterns in ruleset.items():
        strings = "".join(f"    {pattern_id} = {{ {' '.join(f'{b:02x}' for b in data)} }}\n"
                          for pattern_id, data in patterns.items())
        blocks.append(f"rule {rule_id} {{\n  strings:\n{strings}  condition:\n    any of them\n}}\n")
    return "\n".join(blocks)


def compiled(name, folder=None, yara_x=None):
    """The ruleset and its rules compiled from generated source; the image build calls this once."""
    if yara_x is None:
        import yara_x
    ruleset = load_ruleset(name, folder)
    try:
        compiler = yara_x.Compiler(relaxed_re_syntax=False, error_on_slow_pattern=True, includes_enabled=False)
        compiler.add_source(yara_source(ruleset), origin=name)
        # The contract asks for hex strings, so the only accepted warning is that one could be written as text.
        if any(not isinstance(w, dict) or w.get("code") != ALLOWED_WARNING for w in compiler.warnings()):
            raise RulesetInvalid()
        rules = compiler.build()
    except yara_x.CompileError:
        raise RulesetInvalid() from None
    if list(rules.imports()):
        raise RulesetInvalid()
    return ruleset, rules


# ---- Scan, cross-check and observations --------------------------------------

def yara_matches(data, name, folder=None, yara_x=None):
    """(offset, length, rule id, pattern id) for every match yara_x reports, unchecked."""
    if yara_x is None:
        import yara_x
    ruleset, rules = compiled(name, folder, yara_x)
    scanner = yara_x.Scanner(rules)
    scanner.set_timeout(SCAN_TIMEOUT)
    scanner.max_matches_per_pattern(MATCHES_PER_PATTERN)
    scanner.fast_scan(False)
    try:
        results = scanner.scan(data)
    except yara_x.TimeoutError:
        raise ScanTimeout() from None
    except yara_x.ScanError:
        raise ScanFailed() from None
    found = []
    for rule in results.matching_rules:
        if rule.namespace != "default":
            raise InconsistentMatch()
        for pattern in rule.patterns:
            for match in pattern.matches:
                found.append((match.offset, match.length, rule.identifier, pattern.identifier))
    return ruleset, found


def confirmed(data, ruleset, found):
    """Each reported match must be a ruleset pattern whose exact bytes lie at its offset."""
    distinct = set()
    for offset, length, rule_id, pattern_id in found:
        pattern = ruleset.get(rule_id, {}).get(pattern_id)
        if (pattern is None or type(offset) is not int or type(length) is not int or length != len(pattern)
                or offset < 0 or data[offset:offset + length] != pattern):
            raise InconsistentMatch()
        distinct.add((offset, rule_id, pattern_id, length))
    return sorted(distinct)


def parse_request(argv):
    if len(argv) != 2:
        raise InvalidRequest()
    operation, text = argv
    try:
        args = json.loads(text, object_pairs_hook=lambda pairs: dict(pairs) if len({k for k, _ in pairs}) == len(pairs) else None)
    except ValueError:
        raise InvalidRequest() from None
    if operation != "yarax.matches" or not isinstance(args, dict) or not set(args) <= {"ruleset", "max_matches"}:
        raise InvalidRequest()
    name = args.get("ruleset", RULESETS[0])
    minimum, maximum, default = MATCHES
    limit = args.get("max_matches", default)
    if name not in RULESETS or type(limit) is not int or not minimum <= limit <= maximum:
        raise InvalidRequest()
    return operation, {"ruleset": name, "max_matches": limit}


def run(operation, args, data, matches_of=None):
    """Observations for yarax.matches; matches_of(data, ruleset name) defaults to yara_x."""
    ruleset, found = (matches_of or yara_matches)(data, args["ruleset"])
    rows = confirmed(data, ruleset, found)[:args["max_matches"]]
    return [{"location": {"offset": offset, "length": length},
             "value": {"ruleset": args["ruleset"], "rule": rule_id, "pattern": pattern_id}}
            for offset, rule_id, pattern_id, length in rows]


# ---- Reply --------------------------------------------------------------------

def error_name(exc):
    name = type(exc).__name__
    return name if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", name) else "WorkerError"


def reply(argv, data, matches_of=None, digest=None):
    """One reply; data None means the snapshot could not be read, digest defaults to the SHA-256 of data."""
    digest = digest or hashlib.sha256(data or b"").hexdigest()
    try:
        if data is None:
            raise SnapshotUnreadable()
        operation, args = parse_request(argv)
        if len(data) > MAX_INPUT_BYTES:
            raise InputTooLarge()
        return {"protocol": PROTOCOL, "status": "ok", "snapshot_sha256": digest,
                "observations": run(operation, args, data, matches_of)}
    except Exception as exc:  # every failure is one short, inert error reply
        return {"protocol": PROTOCOL, "status": "error", "snapshot_sha256": digest, "error": error_name(exc)}


def read_snapshot(path):
    """At most MAX_INPUT_BYTES + 1 bytes, and the SHA-256 of the whole file: the digest the host compares."""
    digest, kept = hashlib.sha256(), bytearray()
    with open(path, "rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
            kept += chunk[:MAX_INPUT_BYTES + 1 - len(kept)]
    return bytes(kept), digest.hexdigest()


def main(argv=None, snapshot=SNAPSHOT):
    try:
        data, digest = read_snapshot(snapshot)
    except OSError:
        data, digest = None, None
    message = reply(sys.argv[1:] if argv is None else argv, data, digest=digest)
    sys.stdout.write(json.dumps(message, sort_keys=True, separators=(",", ":")) + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
