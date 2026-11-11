"""Shared task, operation, evidence, finding and review contract.

Every component builds against these types. Tools return Observations; only the gateway
turns them into Evidence with make_evidence, so evidence IDs and excerpt hashes are
computed in one place and the reviewer can recompute them from the frozen bytes.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
import copy
import hashlib
import json
import re
import zlib

CONTRACT_VERSION = "reverseai.contract/3"

MAX_EXCERPT_BYTES = 4096
MAX_OBSERVATION_BYTES = 4096
MAX_CLAIM_CHARS = 280
MAX_EVIDENCE_PER_FINDING = 64
MAX_STRING_ARG_CHARS = 256
MAX_WORKER_REPLY_BYTES = 262_144
WORKER_PROTOCOL = "reverseai.worker/1"

ROLES = ("structural", "capability", "code")
FINDING_CONFIDENCE = ("observed", "inferred")
RESULT_STATUS = ("ok", "error", "budget_exceeded")
VERDICT_STATUS = ("supported", "derived", "unsupported", "contradicted")

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_NAME = re.compile(r"[a-z][a-z0-9_]{0,31}\Z")
_OPERATION = re.compile(r"[a-z][a-z0-9_]{0,31}\.[a-z][a-z0-9_]{0,31}\Z")
_CLAIM_KEY = re.compile(r"[a-z][a-z0-9_.]{0,63}\Z")
_VERSION = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+_-]{0,31}\Z")
_ID = re.compile(r"[a-z]{2,4}-[0-9a-f]{16}\Z")


class ContractError(ValueError):
    """A value does not satisfy the contract."""


def require(condition, message):
    if not condition:
        raise ContractError(message)


def canonical_json(value) -> str:
    """Deterministic JSON used for IDs, de-duplication keys and size limits."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def content_id(prefix: str, value) -> str:
    return f"{prefix}-{sha256_hex(canonical_json(value).encode())[:16]}"


def check_json_value(value, *, depth=0):
    """Observation and finding values: JSON scalars, lists and string-keyed dicts only."""
    require(depth <= 8, "JSON value nested too deeply")
    if value is None or isinstance(value, (bool, str)):
        return
    if isinstance(value, int):
        require(-(2**63) <= value < 2**64, "Integer out of range")
        return
    if isinstance(value, list):
        for item in value:
            check_json_value(item, depth=depth + 1)
        return
    require(isinstance(value, dict), f"Unsupported JSON type {type(value).__name__}")
    for key, item in value.items():
        require(isinstance(key, str), "JSON object keys must be strings")
        check_json_value(item, depth=depth + 1)


@dataclass(frozen=True)
class InputRef:
    sha256: str
    size: int
    name: str  # display only; never used as a path

    def __post_init__(self):
        require(isinstance(self.sha256, str) and _SHA256.match(self.sha256), "Invalid input sha256")
        require(type(self.size) is int and self.size >= 0, "Invalid input size")
        require(isinstance(self.name, str) and 0 < len(self.name) <= 255 and "\x00" not in self.name, "Invalid input name")


@dataclass(frozen=True)
class ToolRef:
    name: str
    version: str

    def __post_init__(self):
        require(isinstance(self.name, str) and _NAME.match(self.name), "Invalid tool name")
        require(isinstance(self.version, str) and _VERSION.match(self.version), "Invalid tool version")


@dataclass(frozen=True)
class Location:
    """Half-open byte range [offset, offset + length) inside the analysed input."""

    offset: int
    length: int

    def __post_init__(self):
        require(type(self.offset) is int and self.offset >= 0, "Invalid location offset")
        require(type(self.length) is int and 0 < self.length <= MAX_EXCERPT_BYTES, "Invalid location length")

    def within(self, size: int) -> bool:
        return self.offset + self.length <= size


@dataclass(frozen=True)
class Observation:
    """What a tool handler returns: a byte range and a bounded JSON description.

    With an artifact, the location is inside that child artifact (a member of the input, such as
    classes.dex in an APK), which the gateway and the reviewer re-materialize from the input bytes.
    """

    location: Location
    value: dict
    artifact: dict | None = None

    def __post_init__(self):
        require(isinstance(self.location, Location), "Observation location must be a Location")
        require(isinstance(self.value, dict), "Observation value must be a dict")
        check_json_value(self.value)
        require(len(canonical_json(self.value).encode()) <= MAX_OBSERVATION_BYTES, "Observation value too large")
        if self.artifact is not None:
            check_artifact(self.artifact)


# Child artifacts: bytes stored or deflated inside the input, bound by size, CRC-32 and SHA-256.
MAX_CHILD_BYTES = 32 * 1024 * 1024
MAX_CHILD_RATIO = 100
ARTIFACT_KEYS = frozenset({"member", "method", "data_offset", "compressed_size", "size", "crc32", "sha256"})
# Method 1 is a range of one whole gzip stream (RFC 1952) inside the input, after inflating it.
GZIP_ARTIFACT_KEYS = ARTIFACT_KEYS | {"inner_offset"}
MAX_STREAM_BYTES = 128 * 1024 * 1024


def check_artifact(artifact):
    require(isinstance(artifact, dict) and set(artifact) == (GZIP_ARTIFACT_KEYS if artifact.get("method") == 1
                                                             else ARTIFACT_KEYS), "Invalid child artifact")
    member = artifact["member"]
    require(isinstance(member, str) and 0 < len(member) <= 255 and member.isprintable(), "Invalid child artifact member")
    require(type(artifact["method"]) is int and artifact["method"] in (0, 1, 8), "Unsupported child artifact method")
    require(all(type(artifact[key]) is int and 0 <= artifact[key] < 2**64
                for key in ("data_offset", "compressed_size", "size", "crc32", "inner_offset") if key in artifact),
            "Invalid child artifact field")
    require(0 < artifact["size"] <= MAX_CHILD_BYTES and artifact["crc32"] < 2**32, "Invalid child artifact size")
    require(isinstance(artifact["sha256"], str) and _SHA256.match(artifact["sha256"]), "Invalid child artifact sha256")
    if artifact["method"] == 0:
        require(artifact["compressed_size"] == artifact["size"], "Stored child artifact sizes differ")
    elif artifact["method"] == 8:
        require(0 < artifact["compressed_size"] and artifact["size"] <= MAX_CHILD_RATIO * artifact["compressed_size"],
                "Child artifact expands past the ratio limit")
    else:
        end = artifact["inner_offset"] + artifact["size"]
        require(0 < artifact["compressed_size"] and end <= MAX_STREAM_BYTES
                and end <= MAX_CHILD_RATIO * artifact["compressed_size"], "Child artifact expands past the ratio limit")


def inflate_stream(data, start, length) -> bytes:
    """One whole gzip member (RFC 1952) at data[start:start + length]: header checked, inflated within
    min(MAX_STREAM_BYTES, 100 x length), trailer CRC-32 and size equal, nothing after it."""
    require(type(start) is int and type(length) is int and 0 <= start and 18 <= length
            and start + length <= len(data), "Gzip stream outside the input")
    raw = bytes(data[start:start + length])
    require(raw[:3] == b"\x1f\x8b\x08" and raw[3] & 0xE0 == 0, "Invalid gzip header")
    flags, at = raw[3], 10
    if flags & 4:
        require(at + 2 <= len(raw), "Invalid gzip header")
        at += 2 + int.from_bytes(raw[at:at + 2], "little")
    for flag in (8, 16):
        if flags & flag:
            end = raw.find(b"\x00", at, len(raw) - 8)
            require(end != -1, "Invalid gzip header")
            at = end + 1
    if flags & 2:
        require(at + 2 <= len(raw) and int.from_bytes(raw[at:at + 2], "little") == zlib.crc32(raw[:at]) & 0xFFFF,
                "Invalid gzip header")
        at += 2
    require(at <= len(raw) - 8, "Invalid gzip header")
    limit = min(MAX_STREAM_BYTES, MAX_CHILD_RATIO * length)
    inflater = zlib.decompressobj(-15)
    try:
        stream = inflater.decompress(raw[at:], limit + 1)
    except zlib.error:
        raise ContractError("Gzip stream does not inflate") from None
    require(len(stream) <= limit and inflater.eof and not inflater.unconsumed_tail and len(inflater.unused_data) == 8,
            "Gzip stream does not inflate within its limits")
    trailer = inflater.unused_data
    require(int.from_bytes(trailer[:4], "little") == zlib.crc32(stream)
            and int.from_bytes(trailer[4:], "little") == len(stream) & 0xFFFFFFFF, "Gzip stream trailer does not match")
    return stream


def materialize(data, artifact, *, streams=None) -> bytes:
    """The child's bytes, re-derived from the input: in range, fully inflated to exactly its size, CRC and hash equal.

    streams, when given, caches inflated gzip streams by (data_offset, compressed_size) for method 1 children.
    """
    check_artifact(artifact)
    start, length, size = artifact["data_offset"], artifact["compressed_size"], artifact["size"]
    require(start + length <= len(data), "Child artifact outside the input")
    if artifact["method"] == 1:
        key = (start, length)
        stream = streams.get(key) if streams is not None else None
        if stream is None:
            stream = inflate_stream(data, start, length)
            if streams is not None:
                streams[key] = stream
        inner = artifact["inner_offset"]
        require(inner + size <= len(stream), "Child artifact outside its gzip stream")
        child = stream[inner:inner + size]
        require(zlib.crc32(child) == artifact["crc32"] and sha256_hex(child) == artifact["sha256"],
                "Child artifact does not match its declared bytes")
        return child
    raw = bytes(data[start:start + length])
    if artifact["method"] == 0:
        child = raw
    else:
        inflater = zlib.decompressobj(-15)
        try:
            child = inflater.decompress(raw, size + 1)
        except zlib.error:
            raise ContractError("Child artifact does not inflate") from None
        require(len(child) == size and inflater.eof and not inflater.unused_data and not inflater.unconsumed_tail,
                "Child artifact does not inflate to its size")
    require(zlib.crc32(child) == artifact["crc32"] and sha256_hex(child) == artifact["sha256"],
            "Child artifact does not match its declared bytes")
    return child


@dataclass(frozen=True)
class Evidence:
    id: str
    input_sha256: str
    tool: ToolRef
    operation: str
    location: Location
    excerpt_sha256: str
    observation: dict
    artifact: dict | None = None  # the location and excerpt are inside this child artifact

    def __post_init__(self):
        require(isinstance(self.input_sha256, str) and _SHA256.match(self.input_sha256), "Invalid evidence input sha256")
        require(isinstance(self.tool, ToolRef), "Evidence tool must be a ToolRef")
        require(isinstance(self.operation, str) and _OPERATION.match(self.operation), "Invalid evidence operation")
        require(self.operation.split(".", 1)[0] == self.tool.name, "Evidence operation must belong to its tool")
        require(isinstance(self.location, Location), "Evidence location must be a Location")
        require(isinstance(self.excerpt_sha256, str) and _SHA256.match(self.excerpt_sha256), "Invalid excerpt sha256")
        Observation(self.location, self.observation, self.artifact)
        require(self.id == evidence_id(self.input_sha256, self.tool, self.operation, self.location, self.excerpt_sha256,
                                       self.observation, self.artifact), "Evidence ID does not match its content")

    def to_dict(self):
        record = {
            "id": self.id,
            "input_sha256": self.input_sha256,
            "tool": {"name": self.tool.name, "version": self.tool.version},
            "operation": self.operation,
            "location": {"offset": self.location.offset, "length": self.location.length},
            "excerpt_sha256": self.excerpt_sha256,
            "observation": self.observation,
        }
        if self.artifact is not None:
            record["artifact"] = self.artifact
        return record


def evidence_id(input_sha256, tool, operation, location, excerpt_sha256, observation, artifact=None) -> str:
    content = {
        "input_sha256": input_sha256,
        "tool": [tool.name, tool.version],
        "operation": operation,
        "location": [location.offset, location.length],
        "excerpt_sha256": excerpt_sha256,
        "observation": observation,
    }
    if artifact is not None:  # evidence without an artifact keeps its ID
        content["artifact"] = artifact
    return content_id("ev", content)


def make_evidence(data: bytes, tool: ToolRef, operation: str, observation: Observation, *, input_sha256=None,
                  child=None) -> Evidence:
    """The only constructor the gateway uses: binds an observation to the frozen bytes.

    A caller that already hashed the input once per run passes input_sha256; the
    reviewer recomputes it from the bytes either way. For an observation inside a child
    artifact, the gateway may pass the child it already materialized for this run; the
    reviewer re-materializes it from the input either way.
    """
    require(isinstance(data, (bytes, bytearray)), "Evidence needs the frozen input bytes")
    require(isinstance(observation, Observation), "Evidence needs an Observation")
    location = observation.location
    target = data
    if observation.artifact is not None:
        target = materialize(data, observation.artifact) if child is None else child
        require(len(target) == observation.artifact["size"], "Child artifact size mismatch")
    require(location.within(len(target)), "Observation location is outside the input")
    fields = {
        "input_sha256": input_sha256 or sha256_hex(bytes(data)),
        "tool": tool,
        "operation": operation,
        "location": location,
        "excerpt_sha256": sha256_hex(bytes(target[location.offset:location.offset + location.length])),
        "observation": observation.value,
        "artifact": copy.deepcopy(observation.artifact),
    }
    return Evidence(id=evidence_id(**fields), **fields)


def evidence_intact(evidence) -> bool:
    """True if the record still matches its content-bound ID: analysts may hold mutable views of it."""
    try:
        return isinstance(evidence, Evidence) and evidence_from_dict(evidence.to_dict()) == evidence
    except (ContractError, TypeError, ValueError):
        return False


def evidence_from_dict(raw) -> Evidence:
    fields = {"id", "input_sha256", "tool", "operation", "location", "excerpt_sha256", "observation"}
    require(isinstance(raw, dict) and set(raw) in (fields, fields | {"artifact"}), "Invalid evidence fields")
    require(isinstance(raw["tool"], dict) and set(raw["tool"]) == {"name", "version"}, "Invalid evidence tool")
    require(isinstance(raw["location"], dict) and set(raw["location"]) == {"offset", "length"}, "Invalid evidence location")
    return Evidence(
        id=raw["id"],
        input_sha256=raw["input_sha256"],
        tool=ToolRef(**raw["tool"]),
        operation=raw["operation"],
        location=Location(**raw["location"]),
        excerpt_sha256=raw["excerpt_sha256"],
        observation=raw["observation"],
        artifact=raw.get("artifact"),
    )


@dataclass(frozen=True)
class ArgSpec:
    """Bounded argument: an int range, a short string or a closed set. Never a path or a flag.

    "literal" is search text for in-process tools only: minimum..maximum printable characters, and it may
    contain "/" or start with "-"; a contained tool may not declare one (ToolSpec refuses it).
    "identity" is an escaped DEX identity as rows show it: minimum..maximum printable ASCII characters; a
    contained tool may declare it, and its worker compares it as text only, never as a path, option or program.
    """

    kind: str  # "int" | "str" | "enum" | "literal" | "identity"
    minimum: int = 0
    maximum: int = 0
    choices: tuple = ()
    default: object = None

    def __post_init__(self):
        require(self.kind in ("int", "str", "enum", "literal", "identity"), "Invalid argument kind")
        if self.kind == "enum":
            require(self.choices and all(isinstance(c, str) for c in self.choices), "Enum needs string choices")
        if self.kind == "int":
            require(self.minimum <= self.maximum, "Invalid int range")
        if self.kind in ("literal", "identity"):
            require(0 <= self.minimum <= self.maximum <= MAX_STRING_ARG_CHARS, "Invalid literal length range")
        if self.kind == "identity":
            require(self.maximum <= 255, "Invalid identity length range")  # escaped identities are at most 255

    def check(self, value):
        if self.kind == "int":
            require(type(value) is int and self.minimum <= value <= self.maximum, "Integer argument out of range")
        elif self.kind == "enum":
            require(value in self.choices, "Argument not in allowed choices")
        elif self.kind == "literal":
            require(isinstance(value, str) and self.minimum <= len(value) <= self.maximum and value.isprintable(),
                    "Literal argument is not allowed")
        elif self.kind == "identity":
            require(isinstance(value, str) and self.minimum <= len(value) <= self.maximum
                    and all(" " <= char <= "~" for char in value), "Identity argument is not allowed")
        else:
            require(isinstance(value, str) and len(value) <= MAX_STRING_ARG_CHARS and "\x00" not in value
                    and "/" not in value and "\\" not in value and not value.startswith("-"),
                    "String argument is not allowed")
        return value


Handler = Callable[[bytes, Mapping[str, object]], list]


@dataclass(frozen=True)
class OperationSpec:
    name: str  # "<tool>.<operation>"
    args: Mapping[str, ArgSpec]
    handler: Handler  # (frozen bytes, validated args) -> list[Observation]
    max_observations: int = 1024
    derived: bool = False  # values are the tool's interpretation; the host re-derives only the anchor

    def __post_init__(self):
        require(isinstance(self.name, str) and _OPERATION.match(self.name), "Invalid operation name")
        require(all(isinstance(k, str) and _NAME.match(k) and isinstance(v, ArgSpec) for k, v in self.args.items()), "Invalid argument specs")
        require(callable(self.handler), "Operation handler must be callable")
        require(type(self.derived) is bool, "OperationSpec derived must be a bool")

    def validate_args(self, raw) -> dict:
        """Unknown arguments are refused; missing ones take the declared default."""
        require(isinstance(raw, Mapping), "Operation arguments must be a mapping")
        unknown = set(raw) - set(self.args)
        require(not unknown, f"Unknown arguments: {sorted(unknown)}")
        out = {}
        for key, spec in sorted(self.args.items()):
            value = raw.get(key, spec.default)
            require(value is not None, f"Missing argument {key}")
            out[key] = spec.check(value)
        return out


@dataclass(frozen=True)
class ToolSpec:
    ref: ToolRef
    operations: Mapping[str, OperationSpec]
    contained: bool = False  # rule 1 contained variant: handlers reach a pinned worker only through reverseai.contained
    runtime: Mapping[str, str] = field(default_factory=dict)  # e.g. image digest and platform, shown in reports

    def __post_init__(self):
        require(isinstance(self.ref, ToolRef), "ToolSpec ref must be a ToolRef")
        for name, op in self.operations.items():
            require(name == op.name and name.split(".", 1)[0] == self.ref.name, "Operation must be keyed by name and belong to its tool")
        require(type(self.contained) is bool, "ToolSpec contained must be a bool")
        require(not self.contained or all(arg.kind != "literal" for op in self.operations.values() for arg in op.args.values()),
                "Contained tools cannot take literal arguments")
        require(isinstance(self.runtime, Mapping) and len(self.runtime) <= 8 and all(
            isinstance(k, str) and _NAME.match(k) and isinstance(v, str) and 0 < len(v) <= 128 and v.isprintable()
            for k, v in self.runtime.items()), "Invalid ToolSpec runtime")
        require(self.contained or not self.runtime, "Only contained tools carry runtime identity")


class WorkerError(ContractError):
    """A contained worker reported a failure; the message is the worker's exception class name only."""


def _unique_keys(pairs):
    keys = [key for key, _ in pairs]
    require(len(keys) == len(set(keys)), "Duplicate key in worker reply")
    return dict(pairs)


def parse_worker_reply(raw, *, input_sha256, max_observations):
    """The only shape the gateway accepts from a contained worker (rule 1, contained variant).

    stdout must be one UTF-8 JSON object: {"protocol": WORKER_PROTOCOL, "status": "ok", "snapshot_sha256": <hex>,
    "observations": [{"location": {"offset", "length"}, "value": {...}}]} or the same with "status": "error" and
    "error": <exception class name>. The worker never supplies evidence IDs or excerpt hashes: the gateway makes
    evidence from the controller's own bytes after this check.
    """
    require(isinstance(raw, (bytes, bytearray)) and len(raw) <= MAX_WORKER_REPLY_BYTES, "Worker reply too large")
    try:
        reply = json.loads(bytes(raw).decode("utf-8"), object_pairs_hook=_unique_keys,
                           parse_constant=lambda name: require(False, "Invalid number in worker reply"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ContractError("Worker reply is not UTF-8 JSON") from None
    require(isinstance(reply, dict) and reply.get("protocol") == WORKER_PROTOCOL, "Unknown worker protocol")
    require(reply.get("snapshot_sha256") == input_sha256, "Worker read a different snapshot")
    if reply.get("status") == "error":
        require(set(reply) == {"protocol", "status", "snapshot_sha256", "error"}, "Invalid worker error fields")
        error = reply["error"]
        require(isinstance(error, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", error), "Invalid worker error name")
        raise WorkerError(error)
    require(reply.get("status") == "ok" and set(reply) == {"protocol", "status", "snapshot_sha256", "observations"},
            "Invalid worker reply fields")
    items = reply["observations"]
    require(isinstance(items, list) and len(items) <= max_observations, "Worker observations missing or over the cap")
    observations = []
    for item in items:
        require(isinstance(item, dict) and set(item) == {"location", "value"}, "Invalid worker observation")
        location = item["location"]
        require(isinstance(location, dict) and set(location) == {"offset", "length"}, "Invalid worker location")
        observations.append(Observation(Location(location["offset"], location["length"]), item["value"]))
    return tuple(observations)


@dataclass(frozen=True)
class OperationRequest:
    operation: str
    args: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self):
        require(isinstance(self.operation, str) and _OPERATION.match(self.operation), "Invalid requested operation")
        require(isinstance(self.args, Mapping), "Requested arguments must be a mapping")


def operation_key(input_sha256: str, tool: ToolRef, operation: str, args: Mapping) -> str:
    """De-duplication key: the same validated operation on the same bytes and tool version runs once."""
    return content_id("op", {"input": input_sha256, "tool": [tool.name, tool.version], "operation": operation, "args": dict(args)})


@dataclass(frozen=True)
class Budget:
    max_concurrency: int = 2
    max_wall_seconds: float = 30.0
    max_output_bytes: int = 1_048_576  # canonical JSON of all evidence produced
    max_evidence: int = 4096
    max_operations: int = 64

    def __post_init__(self):
        require(type(self.max_concurrency) is int and 1 <= self.max_concurrency <= 16, "Invalid concurrency budget")
        require(isinstance(self.max_wall_seconds, (int, float)) and 0 < self.max_wall_seconds <= 3600, "Invalid time budget")
        require(type(self.max_output_bytes) is int and 0 < self.max_output_bytes <= 64 * 1_048_576, "Invalid output budget")
        require(type(self.max_evidence) is int and 0 < self.max_evidence <= 100_000, "Invalid evidence budget")
        require(type(self.max_operations) is int and 0 < self.max_operations <= 1024, "Invalid operation budget")


@dataclass(frozen=True)
class AnalysisTask:
    id: str
    role: str
    input: InputRef
    operations: tuple  # tuple[OperationRequest, ...]
    budget: Budget = Budget(max_concurrency=1)

    def __post_init__(self):
        require(isinstance(self.id, str) and _ID.match(self.id), "Invalid task ID")
        require(self.role in ROLES, "Unknown analyst role")
        require(isinstance(self.input, InputRef), "Task input must be an InputRef")
        require(isinstance(self.operations, tuple) and self.operations and all(isinstance(o, OperationRequest) for o in self.operations),
                "Task needs a tuple of OperationRequest")
        require(isinstance(self.budget, Budget), "Task budget must be a Budget")


@dataclass(frozen=True)
class Finding:
    id: str
    role: str
    claim: str
    claim_key: str  # stable key: two findings with the same key and different values contradict
    value: object
    evidence_ids: tuple
    confidence: str = "observed"

    def __post_init__(self):
        require(self.role in ROLES, "Unknown finding role")
        require(isinstance(self.claim, str) and 0 < len(self.claim) <= MAX_CLAIM_CHARS, "Invalid claim text")
        require(isinstance(self.claim_key, str) and _CLAIM_KEY.match(self.claim_key), "Invalid claim key")
        check_json_value(self.value)
        require(isinstance(self.evidence_ids, tuple) and len(self.evidence_ids) <= MAX_EVIDENCE_PER_FINDING
                and all(isinstance(e, str) and _ID.match(e) and e.startswith("ev-") for e in self.evidence_ids), "Invalid evidence IDs")
        require(self.confidence in FINDING_CONFIDENCE, "Invalid finding confidence")
        require(self.id == finding_id(self.role, self.claim, self.claim_key, self.value, self.evidence_ids, self.confidence),
                "Finding ID does not match its content")


def finding_id(role, claim, claim_key, value, evidence_ids, confidence) -> str:
    """Every field is bound, so one ID can never stand for two different claims."""
    return content_id("fi", {"role": role, "claim": claim, "claim_key": claim_key, "value": value,
                             "evidence": sorted(evidence_ids), "confidence": confidence})


def finding_intact(finding) -> bool:
    """True if the finding still matches its ID (its value may be a mutable list or dict)."""
    try:
        return isinstance(finding, Finding) and finding == Finding(finding.id, finding.role, finding.claim, finding.claim_key,
                                                                   finding.value, finding.evidence_ids, finding.confidence)
    except (ContractError, TypeError, ValueError):
        return False


def make_finding(role, claim, claim_key, value, evidence_ids, confidence="observed") -> Finding:
    ids = tuple(sorted(set(evidence_ids)))
    return Finding(finding_id(role, claim, claim_key, value, ids, confidence), role, claim, claim_key, value, ids, confidence)


@dataclass(frozen=True)
class AnalysisResult:
    task_id: str
    role: str
    status: str
    evidence: tuple  # tuple[Evidence, ...]
    findings: tuple  # tuple[Finding, ...]
    errors: tuple = ()  # tuple[str, ...], short and free of input bytes

    def __post_init__(self):
        require(self.role in ROLES and self.status in RESULT_STATUS, "Invalid result role or status")
        require(all(isinstance(e, Evidence) for e in self.evidence), "Result evidence must be Evidence")
        require(all(isinstance(f, Finding) and f.role == self.role for f in self.findings), "Result findings must match the role")
        require(all(isinstance(e, str) and len(e) <= 200 for e in self.errors), "Invalid result errors")


@dataclass(frozen=True)
class ReviewVerdict:
    finding_id: str
    status: str
    reasons: tuple = ()

    def __post_init__(self):
        require(isinstance(self.finding_id, str) and _ID.match(self.finding_id), "Invalid verdict finding ID")
        require(self.status in VERDICT_STATUS, "Invalid verdict status")
        require(all(isinstance(r, str) and len(r) <= 200 for r in self.reasons), "Invalid verdict reasons")
        require(self.status == "supported" or self.reasons, "A finding that is not supported needs a reason")
