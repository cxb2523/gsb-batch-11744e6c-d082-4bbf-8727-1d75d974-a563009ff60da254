# ReverseAI contract (reverseai.contract/3)

The types live in `reverseai/contract.py`. This page fixes how the M1 components
connect, so lanes can be built in parallel and joined without negotiation.
A lane that needs a change to this contract asks the coordinator; it does not edit
`contract.py`.

## Data flow

```text
approved file
  -> intake.snapshot()            frozen bytes + InputRef            (lane A)
  -> analyst.plan(InputRef)       AnalysisTask                        (lane A structural, lane B capability)
  -> Gateway.run(task, bytes)     AnalysisResult with evidence only   (lane B)
  -> analyst.conclude(task, ev)   tuple[Finding, ...]                 (lane A structural, lane B capability)
  -> review(...)                  tuple[ReviewVerdict, ...]           (lane A)
  -> report                       JSON + Markdown                     (coordinator integration)
```

## Module interfaces

| Module | Owner | Exports |
| --- | --- | --- |
| `reverseai/intake.py` | lane A | `snapshot(path) -> tuple[bytes, InputRef]` |
| `reverseai/tools/structure.py` | lane A | `TOOL: ToolSpec` named `structure` |
| `reverseai/analysts/structural.py` | lane A | `plan(InputRef) -> AnalysisTask`, `conclude(AnalysisTask, tuple[Evidence, ...]) -> tuple[Finding, ...]` |
| `reverseai/review.py` | lane A | `review(data: bytes, input: InputRef, results: Iterable[AnalysisResult], tools: Mapping[str, ToolSpec]) -> tuple[ReviewVerdict, ...]` (tools keyed by tool name) |
| `reverseai/tools/strings.py` | lane B | `TOOL: ToolSpec` named `strings` |
| `reverseai/analysts/capability.py` | lane B | `plan`, `conclude` as above |
| `reverseai/gateway.py` | lane B | `Gateway(tools: Iterable[ToolSpec], budget: Budget)` with `run(task, data) -> AnalysisResult` |
| `reverseai/claims.py` | coordinator (contract) | `RULES` (confidence and allowed operations per claim_key), `STATEMENTS`, `check(finding, cited_evidence) -> tuple[str, ...]` reasons |
| `reverseai/contained.py` | M2a | the only path from a contained handler to its worker: stages the snapshot, runs the pinned image with fixed limits, returns its bounded stdout |
| `reverseai/tools/lief_tool.py` | M2a | `TOOL: ToolSpec` named `lief`, `contained=True`: `lief.headers`, `lief.sections` |
| `containers/lief/` | M2a | worker image definition and in-container worker; never imported on the host |
| `reverseai/pipeline.py`, `reverseai/cli.py`, `reverseai/report.py` | coordinator | integration |

## Rules every component keeps

1. **Tools only observe.** A handler receives the frozen bytes and validated
   arguments and returns `Observation`s. It never opens files, runs processes,
   uses the network or reads the environment.
   *Contained variant* (amendment to contract/1, decision `owner-m2-choices`): a
   `ToolSpec` with `contained=True` has handlers that reach one fixed, pinned
   worker image only through `reverseai/contained.py`. The worker sees one
   read-only frozen snapshot of the input and a bounded private `/tmp`; it gets no
   host path, network, Docker socket, credentials or agent input, runs as a
   non-root user with every capability dropped on a read-only root, and is
   stopped at its time, memory, CPU, process and output limits. Its stdout must
   pass `parse_worker_reply` (protocol `reverseai.worker/1`): bounded
   observations plus the digest of the snapshot it read, which must equal the
   `InputRef` hash, or an error class name. The digest is checked first, so a
   worker that could not read its snapshot (it reports the digest of no bytes)
   is refused as a snapshot mismatch, not by its error name; it still fails
   closed. Worker replies are untrusted beyond
   their schema: before any evidence is made, the host re-derives every value of
   every observation from the controller's own bytes at that observation's
   Location, with in-process decoding, and refuses the whole reply when a value
   disagrees, is missing, is unknown or cannot be re-derived. A compromised
   worker can therefore withhold evidence but never invent it. The gateway then
   makes evidence from the controller's own bytes with `make_evidence`;
   worker-supplied evidence IDs or excerpt hashes are never accepted. The controller never parses with the
   tool natively, and the sample itself is never executed. `ToolSpec.runtime`
   records the image digest and platform; the `ToolRef` version changes whenever
   the adapter, image or hidden settings change.
2. **Only the gateway makes evidence**, with `make_evidence`, so the evidence ID,
   input hash and excerpt hash are always computed the same way.
3. **The gateway refuses** an operation that is not registered, arguments that
   `OperationSpec.validate_args` rejects, and any request beyond the task or global
   `Budget`. Hitting a budget returns status `budget_exceeded` with the evidence
   gathered so far; it never raises past the pipeline. A task's `max_evidence`
   bounds the evidence returned for that task; the global budget counts each
   unique evidence item the run produces once, including items a task did not
   receive because of its own limit.
4. **De-duplication.** One `Gateway` instance is shared by all tasks of a run. An
   operation whose `operation_key` was already executed returns the stored
   evidence without calling the handler again. An execution cut short by time
   may be retried after its worker stops. Fixed observation, global evidence and
   output cuts are cached and replayed as `budget_exceeded` without invoking the
   handler again. Retries do not charge the unique-operation budget twice.
5. **Findings cite evidence.** `conclude` sees only evidence of its own task, as
   copies: the pipeline keeps the gateway's records for the result. It returns
   findings made with `make_finding`, whose ID binds every field. A finding with no evidence is
   allowed to exist, so the reviewer can reject it.
6. **The reviewer re-checks bytes.** Analyst output is untrusted. The reviewer
   checks that `len(data)` and the input hash match the `InputRef`. It resolves a
   finding's evidence IDs only inside the finding's own `AnalysisResult`. For each
   cited item it checks that the record still matches its content-bound ID
   (`evidence_intact`), recomputes the input hash, checks the tool name and version
   and that the operation is registered for that tool, checks that the location is
   inside the input and that the excerpt hash matches the frozen bytes. A finding
   that no longer matches its own ID (`finding_intact`), or that shares its ID with
   different content, is `unsupported`. A finding is also `unsupported` if any cited
   item is missing or fails, if it cites none, or if `reverseai.claims.check` finds
   that its claim_key has no rule, that its confidence differs from the rule's,
   that it cites an operation the rule does not allow, or that the citations of
   any allowed operation do not yield exactly the claimed value (a rule may allow
   several operations, for example a stdlib parser and a contained tool; each
   must agree). The reviewer
   thereby checks that a claim follows from its evidence, not only that the
   evidence exists; `contradicted` if another finding whose cited
   evidence also all verifies has the same `claim_key` and a different `value`;
   otherwise `supported`. An unsupported finding never contradicts anything, so
   a claim without valid evidence cannot cancel a verified one.
7. **Errors are short and inert.** Error and reason strings never contain input
   bytes or host paths. Reports do contain bounded text taken from the sample
   (strings, URLs, section names); it stays untrusted, and the Markdown report
   escapes it so it cannot render as HTML, links or images.
   Reports are deterministic for a given input and budget unless a shared global
   budget is exhausted; then which concurrent task received the last slots may
   vary, and the result says `budget_exceeded`.
8. **No execution.** Nothing in M1 runs the sample, installs software, opens a
   network connection or calls a model.

## Contained worker interface (M2a)

Fixed by the coordinator so the worker image and the host executor can be built
in parallel. Nothing in this interface comes from a sample, an analyst or a peer.

- **Image**: built locally from a digest-pinned base and a hash-pinned wheel;
  `containers/lief/image.lock.json` records `image_id`, `platform`
  (`linux/arm64`), `base_digest`, `wheel_sha256` and `adapter_version`. The host
  refuses to run an image whose ID differs from the lock.
- **Entrypoint**: `python3 -I -B /opt/reverseai/worker.py`, user `65534:65534`,
  no shell needed. Arguments: `<operation> <canonical JSON of validated args>`.
- **Input**: one file `/snapshot/input` (mode 0444 in a 0555 directory) on a
  read-only bind mount of a private per-run folder under
  `/Users/Shared/rea-safe-staging-501`, removed after the run. No other mount.
- **Run flags** (exact, built by `reverseai/contained.py` as an argv list):
  `docker run --rm --init --pull never --name reverseai-<random> --platform linux/arm64
  --network none --read-only --cap-drop ALL --security-opt no-new-privileges
  --user 65534:65534 --pids-limit 64 --memory 512m --memory-swap 512m --cpus 1
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m --log-driver none
  --mount type=bind,source=<run folder>,target=/snapshot,readonly
  <image_id> <operation> <args>`.
- **Environment**: the container's environment must equal the image's; the
  verifier refuses any variable the engine injects (for example proxy settings).
- **Output**: one `reverseai.worker/1` JSON object on stdout, at most
  `MAX_WORKER_REPLY_BYTES`; stderr is discarded. Wall limit per run 45 s; on
  timeout the host kills the named container and reports `budget_exceeded`.
- **Observations**: field names follow M1 (`format`, `machine_name`, `shnum`
  with `shoff`, `number_of_sections`; section `index`, `offset`, `size`,
  `writable`, `executable`), one observation per physical structure, each
  Location inside that structure and at most 4,096 bytes.

## Contained YARA-X worker (M2b)

Same container interface, run flags, environment, reply protocol and limits as
M2a; only what differs is listed. Fixed by the coordinator before the lanes.

- **Image**: `containers/yarax/`, built locally from the same digest-pinned
  `python:3.12-slim` base and the hash-pinned wheel
  `yara_x-1.21.0-cp38-abi3-manylinux_2_28_aarch64.whl` (SHA-256
  `9bd9961b44b47dd747d526e61c703a2a8170426d003e789e7724bc7862de6d56`, owner
  decision `owner-m2b-download`). `containers/yarax/image.lock.json` records the
  M2a fields plus `ruleset_sha256`; adapter version `1.21.0-r2` (rebuilt for the 4-per-pattern cap); tool name `yarax`.
- **Ruleset**: `containers/yarax/m2_fixture_v1.json` is the only rule source:
  reviewed rules, each with an `id`, a `category` and literal byte patterns given
  as hex (4 to 256 bytes, no wildcards, jumps, regexes, modules, includes or
  external variables). The image copies this file; the worker generates YARA
  source from it, every rule with condition `any of them`, and compiles it at
  start. Compiled or serialized rules are never loaded. The host refuses to run
  when the SHA-256 of its own copy differs from the lock's `ruleset_sha256`.
- **Operation** `yarax.matches`: args `ruleset` enum `("m2_fixture_v1",)`,
  default `m2_fixture_v1`; `max_matches` int 1..64, default 32; at most 64
  observations. The worker sets a scan timeout below the 45 s wall limit and a
  per-pattern match limit of 4, and reports matches in ascending (offset, rule,
  pattern) order, cut at `max_matches`. Worker and host refuse a ruleset whose
  pattern count times 4 exceeds 64, so a `max_matches` of 64 never hides a
  matched rule (decision `m2b-per-pattern-cap`).
- **Observation**: one per match, value
  `{"ruleset": <name>, "rule": <rule id>, "pattern": <pattern id>}` at
  `Location(offset, len(pattern bytes))`.
- **Host re-derivation** (rule 1 applied to M2b): the host looks the rule and
  pattern up in its own copy of the ruleset and refuses the whole reply unless
  the value has exactly those three fields, the ruleset is the requested one,
  the Location length equals the pattern length and the input bytes at the
  Location equal the pattern bytes. Observations must be distinct and in the
  stated order. A compromised worker can hide matches but never add one.
- **Claim**: `signatures.rule_matches`, confidence `observed`, cites only
  `yarax.matches`; its value is the sorted unique rule IDs of the cited matches.
  The capability analyst plans it when the YARA-X tool is available.

## Derived evidence (contract/2, M3)

Owner decision `owner-m3-derived`. Some tools interpret code (functions,
pseudocode, calls) in ways the host cannot re-derive from the input bytes.
Contract/2 admits them as **derived** evidence, never as verified fact.

- **Declared per operation**: `OperationSpec.derived = True`. Rule 1 still
  applies to everything the host can check: for a derived operation the host
  re-derives the observation's **anchor** (its Location must be exactly the
  file range the observation names, mapped through the host's own section
  decoding, inside an executable section where the value says code) and checks
  the value's schema and bounds; the remaining fields are the tool's
  interpretation. A refusal fails the whole operation, as before.
- **Evidence records are unchanged**: the gateway still makes them with
  `make_evidence`, bound to the input bytes at the anchor, the tool, the
  operation and the exact observation value. A derived observation is always
  anchored in the input; output that cannot be anchored is not admitted.
- **Claims**: a claim rule whose operations are all derived must carry
  confidence `inferred`. A rule never mixes derived and non-derived operations.
- **Verdicts**: `VERDICT_STATUS` gains `derived`. A finding whose provenance
  and claim checks pass is `derived` (not `supported`) when any cited
  evidence comes from a derived operation; its reason says so. A derived
  finding never contradicts and is never contradicted: it is the tool's
  reading, shown with its source, not a fact that competes with verified ones.
- **Reports** list derived findings in their own section, "Derived by
  analysis tools (not verified against the bytes)", after the supported ones,
  with the tool, image and operation that produced them.
- **Roles**: `ROLES` gains `code` for the analyst that plans Ghidra operations.

## Contained Ghidra worker (M3a)

Same container interface and reply protocol as M2a; what differs:

- **Image**: `containers/ghidra/`, linux/arm64, built from the pinned
  `python:3.12-slim` base with the owner-approved downloads (`owner-m3-downloads`):
  Ghidra 12.1.4 (`ddac49f9...d4db`), Temurin JDK 21.0.12.1+1 aarch64
  (`23e37e02...e223`) and, in a build stage only, Debian `g++`/`make` to
  build the arm64 decompiler and demangler natives. Lock keys: the M2a keys plus
  `ghidra_sha256`, `jdk_sha256`; `wheel_sha256` is absent. Adapter `12.1.4-r2` (function span, decision `m3a-function-span`).
- **Resource profile** (per tool, fixed in `reverseai/contained.py`; LIEF and
  YARA-X keep theirs): `--memory 2g --memory-swap 2g --pids-limit 256
  --cpus 2 --tmpfs /tmp:rw,noexec,nosuid,nodev,size=512m`, wall limit 240 s.
  Every other run flag is the M2a flag. The native verifier proves this profile.
- **Analysis**: one headless import per run into a project under `/tmp`, fixed
  reviewed query code baked into the image, fixed analyzers: no servers, no
  debugger, no external debug-file lookup, Swift demangler off, analysis timeout
  below the wall limit. Requests cannot select scripts, loaders or options.
  M3a accepts ELF and PE; Mach-O comes with the host decoder in M3b.
- **Operation** `ghidra.analyze` (derived): args `max_functions` int 1..128
  default 64, `decompile` int 0..16 default 8, `max_chars` int 64..2048 default
  1024, `max_calls` int 0..256 default 128; at most 400 observations. One run
  returns three kinds, each anchored at its file range:
  - `{"kind": "function", "index", "name", "entry", "size"}` at the function's
    first bytes (at most 4,096), functions address-sorted, index from 0;
  - `{"kind": "pseudocode", "index", "entry", "text", "truncated"}` at the same
    anchor, for the entry-point function and then the largest functions
    (ties by lower entry), `decompile` in all, text cut at `max_chars`
    characters and, when needed, to the longest prefix whose observation value
    fits 4,096 bytes (`truncated` true when cut; decision `m3c-pseudocode-fit`);
  - `{"kind": "call", "from", "to", "to_name"}` at the call instruction's bytes.
  `name`/`to_name` are at most 128 printable characters. Values are virtual
  addresses; the host maps each anchor through its own section table and refuses
  an observation whose anchor is not inside an executable section.
  A function's `size` is its span: from `entry` to the last byte of its body,
  so a body with gaps keeps the calls in its later ranges; a call's instruction
  must lie inside the span of the function named by `from`. Section tables
  count only what is mapped from the file: ELF sections with `SHF_ALLOC`, and
  for PE the first `min(SizeOfRawData, VirtualSize)` bytes (`SizeOfRawData`
  when `VirtualSize` is 0). Decision `m3a-function-span`.
- **Claims** (all `inferred`, all derived): `code.functions` = names in index
  order; `code.pseudocode` = `{"entry", "text", "truncated"}` for one function
  (one finding per decompiled function); `code.calls` = sorted unique
  `[from, to_name]` pairs.

## Mach-O and imports on the host (M3b)

Host tools stay in-process and standard-library only; their observations are
verified evidence (not derived), as in M1.

- **Mach-O decoding** in `reverseai/tools/structure.py`: thin 32- and 64-bit
  little-endian Mach-O (`0xfeedface`, `0xfeedfacf`) is decoded; big-endian thin
  files and universal (fat) files (`0xcafebabe`, `0xcafebabf`) are identified
  only: `structure.identify` reports `format` `macho` or `macho-universal`, and
  for universal files an `architectures` list of at most 8 machine names.
  `structure.headers` gives `{"structure": "macho", "format": "macho",
  "machine_name", "filetype", "ncmds", "number_of_sections"}` at the Mach-O header
  (28 or 32 bytes); `structure.sections` gives one observation per section of
  every `LC_SEGMENT`/`LC_SEGMENT_64`, `{"index", "name" ("<segname>,<sectname>"),
  "offset", "size", "writable", "executable"}` at the section header (68 or 80
  bytes); `executable` is the segment's `initprot` execute bit or a section
  instruction attribute (`S_ATTR_PURE_INSTRUCTIONS`, `S_ATTR_SOME_INSTRUCTIONS`),
  `writable` the segment's `initprot` write bit. The existing format, machine,
  section-count and writable-executable claims apply unchanged. A public helper
  `macho_sections(data)` returns the same section rows plus `addr` for other host
  code (the Ghidra anchor check).
- **Imports**: new operation `structure.imports`, arg `max_imports` int 1..256
  default 128, at most 256 observations, for ELF (`DT_NEEDED` libraries and
  undefined dynamic symbols), PE (import directory: DLL names and imported names or
  ordinals as `#<n>`) and thin Mach-O (`LC_LOAD_DYLIB`/`LC_LOAD_WEAK_DYLIB` paths,
  and since M3c `LC_REEXPORT_DYLIB`, `LC_LAZY_LOAD_DYLIB` and `LC_LOAD_UPWARD_DYLIB`
  through the same dylib command layout, and undefined symbols from `LC_SYMTAB`).
  Little-endian fat magics are not universal (M3c). Observations:
  `{"kind": "library", "name"}` at the bytes of that name, and
  `{"kind": "symbols", "library": <name or null>, "names": [at most 32]}` at the
  bytes of the first name in the group. Names are at most 128 printable
  characters, escaped as section names are. Malformed tables are cut, never read
  past the input.
- **Claims** (observed, verified): `imports.libraries` = sorted unique library
  names of the cited `library` observations; `imports.symbols` = sorted unique
  names of the cited `symbols` observations. One finding each.
- **Ghidra on Mach-O (M3b)**: the worker accepts thin Mach-O; the host maps
  Ghidra anchors through `macho_sections` (an anchor must lie inside an executable
  section's file bytes). Adapter `12.1.4-r4` (decision `m3b-fix-round`).

## Assembly, references and referenced strings (M3c)

The same single `ghidra.analyze` run (one container, same resource profile and
wall limit) reports three more derived kinds. Adapter `12.1.4-r5`. Decision
`m3c-contract`.

- **New args** (all ints, defaults when absent): `assembly` 0..8 default 4,
  `max_instructions` 1..64 default 32, `max_refs` 0..128 default 64,
  `max_strings` 0..64 default 32. At most 600 observations (the sum of every
  kind's maximum). The reply limit stays 262,144 bytes: the M3a kinds are
  emitted as before, then `assembly`, `ref` and `string` observations in that
  order, each added only while the encoded reply stays within the limit; an
  observation is never cut, and a reply at every maximum is never refused for
  its size.
- `{"kind": "assembly", "index", "entry", "instructions", "truncated"}` at the
  same anchor as function `index` (equal location and entry), for `assembly`
  functions chosen in the pseudocode order (entry-point function first, then the
  largest, ties by lower entry): a subset of that selection in that order, each
  function at most once (a listing that fails or does not fit the reply is
  omitted, as pseudocode may be). `instructions` is a non-empty
  list of at most `max_instructions` `[delta, length, text]` rows in address
  order from the entry: `delta` the instruction's offset from the entry,
  `length` 1..16, rows non-overlapping (`delta + length` at most the next
  `delta`) and inside the anchor (`delta + length` at most the location
  length); `text` 1..64 printable ASCII characters, the instruction as Ghidra
  prints it. Only instructions wholly inside the anchor are listed; the worker
  confirms each one's bytes against the snapshot. `truncated` is true when the
  function has instructions that were not listed (cut by `max_instructions`, by
  the anchor's end or by the 4,096-byte observation limit).
- `{"kind": "ref", "from", "to", "type", "to_name"}` at the referencing
  instruction's bytes (1..16 bytes inside an executable section and inside the
  span of the function whose entry is `from`, as for `call`). `type` is one of
  `read`, `write`, `read_write`, `data` (any other data reference, such as an
  address taken) and `jump` (a jump to an address outside the function's body);
  calls stay `call`, including a jump Ghidra reads as a tail call (flow type
  call-terminator, decision `m3c-tail-call`), and flow inside the function's
  body is not reported. `to`
  is a virtual address that may lie outside the file (zero-fill, external,
  unresolved); `to_name` at most 128 printable characters, empty when Ghidra has
  no symbol there. Rows are unique, sorted by (instruction file offset, `to`,
  `type`), at most `max_refs`.
- `{"kind": "string", "address", "encoding", "text", "truncated", "from"}` at
  the string's own bytes, for distinct `to` addresses of the reply's `ref`
  observations whose target bytes hold a string under this fixed rule, which the
  host re-derives from the snapshot: `ascii` when 2..128 bytes in 0x20..0x7e
  start at the target, else `utf-16le` when 2..128 code units `XX 00` with `XX`
  in 0x20..0x7e do; `ascii` wins whenever its whole rule holds. `truncated` is
  true only when the run reaches 128 characters and the next character still
  matches inside the same section's file bytes (no terminator is then needed);
  otherwise a terminator (one zero byte, or two for `utf-16le`) must follow there. The location is exactly the encoded `text`
  (terminator excluded); it and its terminator lie inside one section's file
  bytes (executable or not: ELF `SHF_ALLOC` sections that are not `SHT_NOBITS`,
  PE raw data within the mapped extent, Mach-O sections that are not zero-fill),
  and that section maps the location to `address`. `from` is the sorted unique
  `from` values of the reply's `ref` observations whose `to` is `address`, the
  lowest 8 when there are more, never empty. Sorted by `address`, unique, at
  most `max_strings`.
- **Host check** (`reverseai/tools/ghidra_verify.py`): the rules above, every
  string re-derived from the bytes (text, encoding, terminator or truncation,
  section, address) and every `from` list recomputed from the reply's `ref`
  rows; any violation refuses the whole reply, as in M3a. Instruction texts,
  reference types, targets and names remain Ghidra's reading.
- **Claims** (all `inferred`, all derived, in `DERIVED_CLAIMS`):
  `code.assembly` = `{"entry", "instructions", "truncated"}` for one function
  (one finding per disassembled function); `code.references` = sorted unique
  `[from, type, to, to_name]` rows; `code.strings` = the cited string
  observations as `{"address", "encoding", "text", "truncated", "from"}`, one per
  address, in address order. A string's bytes are re-read by the host, yet the
  finding stays derived: that code references the string is Ghidra's reading.
- **Imports claim bounds** (decision `m3b-deferred-to-m3c`, R3-P): the
  `imports.*` rules refuse a symbols group of more than 32 names and any name that
  is empty, longer than 128 characters or not printable.

## Targeted queries (M3d)

M3d answers one question at a time, by name, address or text, with paging, next
to the whole-file `analyze` run. The query names follow the common vocabulary of
native reverse-engineering queries, so a benchmark can compare them one by one. Decision `m3d-contract`.

- **Command**: `python3 -m reverseai query FILE --query NAME [--arg KEY=VALUE ...]
  --out DIR [--with-ghidra]`. NAME is one of the closed table below
  (`reverseai/queries.py`); each `--arg` key must be one the query accepts and its
  value is checked by the operation's `ArgSpec` (integers in decimal or `0x` hex);
  anything else is refused before the input is read. A query runs its fixed
  operations through the same intake, gateway, budgets and reviewer as `analyze`
  and writes the same report files; the report adds `"query": {"name", "args"}`
  (JSON) and a line naming the query and its arguments (Markdown). A Ghidra query
  without `--with-ghidra`, or without the Ghidra image, exits 1 cleanly.
- **Paging**: list operations take `start` (0-based) and `limit`. Every row
  carries `index` (its place in the operation's full, deterministic order) and
  `total` (rows in that order). A page holds rows `start..start+n-1`; when
  `start+n < total` the report says so and gives the next `start`. A row missing
  from a page is never evidence that it does not exist. List claims have the
  value `{"start", "total", "rows"}`: indexes contiguous from `start`, one `total`,
  rows in index order; an empty page makes no finding. A long page is split into
  findings of at most 64 citations, each a contiguous page; the reviewer compares
  verified pages of one list row by row, within the task (one query and its
  arguments) that produced them, so they contradict only by a different `total`
  or a different row at the same index (decision `m3d-seams-paging`); results of
  different queries are never compared as one list. `bytes.read` is checked against
  its own cited bytes and offset, so two readings never contradict; string rows
  must sit at their cited offset and hold printable ASCII (decision `m3d-fix-round`).

| Query | Operations (fixed arguments) | Accepted `--arg` keys |
| --- | --- | --- |
| `binary_overview` | `structure.identify`, `.headers`, `.sections`, `.imports`, `.entry` | none |
| `list_segments` | `structure.segments` | `start`, `limit` |
| `inspect_native_load_image` | `structure.segments`, `structure.entry` | `start`, `limit` |
| `list_names` | `structure.symbols` | `query`, `start`, `limit` |
| `read_bytes` | `structure.read_bytes` | `mode`, `at`, `length` |
| `list_strings` | `strings.list` | `encoding`, `min_length`, `start`, `limit` |
| `search_strings` | `strings.search` | `query`, `encoding`, `start`, `limit` |
| `list_procedures` | `ghidra.functions` (`query` "") | `start`, `limit` |
| `search_procedures` | `ghidra.functions` | `query`, `start`, `limit` |
| `procedure_info` | `ghidra.function` (`parts` info) | `select`, `entry`, `name` |
| `procedure_pseudo_code` | `ghidra.function` (`parts` pseudocode) | `select`, `entry`, `name`, `max_chars` |
| `procedure_assembly` | `ghidra.function` (`parts` assembly) | `select`, `entry`, `name`, `start`, `limit` |
| `procedure_callees` | `ghidra.function` (`parts` callees) | `select`, `entry`, `name`, `max_calls` |
| `procedure_callers` | `ghidra.function` (`parts` callers) | `select`, `entry`, `name`, `max_calls` |
| `analyze_function` | `ghidra.function` (`parts` all) | every `ghidra.function` key except `parts` |
| `xrefs` | `ghidra.xrefs` | `address`, `start`, `limit` |

### Host operations (verified, in-process, stdlib)

Search text is the `ArgSpec` kind `literal`: a bounded number of printable
characters that may contain `/` or start with `-`. Only in-process tools may
declare it (a contained `ToolSpec` refuses one), so Ghidra's `query` and `name`
keep the `str` rule (no `/`, `\`, leading `-`, at most 256 characters).

Rows are re-derived by the host from the bytes, as in M1; names are escaped and
cut as section and import names are (at most 128 printable characters). A table
walk reads at most 65,536 entries in all; a file whose otherwise valid tables
need more is refused (`StructureError`, no observation), so `total` is never a
count cut short. Malformed or truncated tables keep their valid prefix.
`structure.file_sections(data)` is a public helper: the file-backed sections of
ELF (`SHF_ALLOC`, not `SHT_NOBITS`), PE (raw data within `min(SizeOfRawData,
VirtualSize)`, `SizeOfRawData` when `VirtualSize` is 0) and thin Mach-O (not
zero-fill) as `{"name", "address", "offset", "size", "executable"}` rows.

- `structure.segments`: args `start` 0..65535 default 0, `limit` 1..256 default
  64. One row per ELF program header, PE section header or Mach-O
  `LC_SEGMENT`/`LC_SEGMENT_64`, in file order: `{"kind": "segment", "index",
  "total", "name", "offset", "filesz", "address", "memsz", "readable", "writable",
  "executable"}` at the declaring header (32/56, 40 or 56/72 bytes). ELF `name` is
  the program header type (`LOAD`, `DYNAMIC`, `INTERP`, `NOTE`, `PHDR`, `TLS`,
  `GNU_STACK`, `GNU_RELRO`, `GNU_EH_FRAME`, else `0x` hex) and the permissions
  are `PF_R/W/X`; PE `address` is `ImageBase + VirtualAddress`, `memsz`
  `VirtualSize`, `offset`/`filesz` the raw data, permissions from
  `IMAGE_SCN_MEM_*`; Mach-O uses `segname`, `fileoff`, `filesize`, `vmaddr`,
  `vmsize`, `initprot`. Claim `segments.list` (observed) rows
  `[name, offset, filesz, address, memsz, readable, writable, executable]`.
- `structure.entry`: no args, at most 1 observation: `{"kind": "entry",
  "address", "offset"}` at the field that declares it (ELF `e_entry`, PE
  `AddressOfEntryPoint`, Mach-O `LC_MAIN` `entryoff` or the `LC_UNIXTHREAD` pc);
  `address` virtual (PE `ImageBase` + RVA; Mach-O `__TEXT` `vmaddr` + `entryoff`),
  `offset` the file offset it maps to through `file_sections`, else null. No
  observation when the file declares none (ELF `e_entry` 0). Claim `load.entry`
  (observed) = `{"address", "offset"}`.
- `structure.symbols`: args `query` literal 0..128 default "" (case-sensitive
  substring of the name; "" lists all), `start` 0..1048575 default 0, `limit` 1..256 default
  128. Rows in table order: ELF `.symtab`, or `.dynsym` when there is no
  `.symtab`, without index 0, `STT_SECTION` and `STT_FILE`; Mach-O `LC_SYMTAB`
  without stab entries; PE export names. Empty names are skipped. `{"kind":
  "symbol", "index", "total", "name", "address", "type", "binding", "defined"}` at
  the name's bytes; `type` ELF `func`, `object`, `notype`, `tls`, `common`,
  `ifunc` or `other`, Mach-O `symbol`, PE `export`; `binding` `local`, `global`,
  `weak` or `other` (Mach-O external is `global`, PE `global`); `defined` bool.
  Claim `symbols.list` (observed) rows `[name, address, type, binding, defined]`.
- `structure.read_bytes`: args `mode` enum `offset`|`address` default `offset`,
  `at` int 0..2^64-1 default 0, `length` 1..2000 default 256 (the hex must fit the
  4,096-byte observation limit); at most 1 observation. `offset`: bytes `[at, min(at + length, size))`, none when `at` is at
  or past the end. `address`: `at` must map into exactly one `file_sections` row;
  the range is cut at that row's file end; none otherwise. `{"kind": "bytes",
  "offset", "address", "hex"}` at exactly those bytes; `address` is the virtual
  address when the offset lies in exactly one file-backed section, else null;
  `hex` lowercase. Claim `bytes.read` (observed) = `{"offset", "address", "hex"}`;
  the reviewer also checks that `hex` decodes to bytes whose SHA-256 is the cited
  evidence's excerpt hash.
- `strings.list`: args `encoding` enum `any`|`ascii`|`utf16le` default `any`,
  `min_length` 4..64 default 6, `start` 0..1048575 default 0, `limit` 1..256
  default 128. The printable runs of `strings.extract` (ASCII, UTF-16LE), merged
  in offset order (ASCII first on ties): `{"kind": "string", "index", "total",
  "offset", "encoding", "text", "truncated"}` at the run's bytes (at most 4,096),
  `text` at most 256 characters, `truncated` when longer. Claim `strings.listed`
  (observed) rows `[offset, encoding, text, truncated]`; for an untruncated row
  the reviewer checks that the encoded text is exactly the cited bytes.
- `strings.search`: args `query` literal 1..128, `encoding` and `start` as
  `strings.list`, `limit` 1..256 default 64. The `strings.list` runs (minimum
  length 4) whose full text contains `query` (case-sensitive), same rows and
  order, `total` counting matches. Claim `strings.matches` (observed), same rows
  and checks as `strings.listed`.

### Ghidra operations (derived, contained)

Same image, resource profile and wall limit as M3a; adapter `12.1.4-r6`. The
query script takes a fixed mode argument; requests still cannot choose scripts
or options. Each operation is one container run (one import and analysis).
Rows are added only while the encoded reply fits 262,144 bytes; an observation
is never cut. Anchors follow the M3a rules (a function's first bytes, at most
4,096, inside an executable section; an instruction's 1..16 bytes).

- `ghidra.functions`: args `query` str default "", `start` 0..65535 default 0,
  `limit` 1..128 default 64; at most 128 observations. File-backed, executable,
  non-external functions in address order whose name contains `query`:
  `{"kind": "function_row", "index", "total", "name", "entry", "size"}` at the
  function's anchor. Claim `code.function_list` (derived) rows
  `[name, entry, size]`.
- `ghidra.function`: args `select` enum `entry`|`name` default `entry`, `entry`
  int 0..2^64-1 default 0, `name` str default "", `parts` enum
  `info`|`pseudocode`|`assembly`|`callees`|`callers`|`all` default `all`, `start`
  0..65535 default 0, `limit` 1..256 default 64, `max_chars` 64..2048 default
  1024, `max_calls` 0..256 default 64, `max_refs` 0..128 default 64; at most 643
  observations (1 + 1 + 1 + 256 + 256 + 128, every part at its maximum). The target is the function whose entry is `entry`, or the
  lowest-entry function named exactly `name`; no observation when there is none.
  - always `{"kind": "target", "name", "entry", "size", "matches", "callers_total",
    "callees_total"}` at the function's anchor (`matches`: functions with that name,
    1 for `select` entry); claim `code.function_info` (derived) = the value
    without `kind`;
  - `pseudocode` or `all`: one M3a `pseudocode` observation (index 0), claim
    `code.pseudocode`;
  - `assembly` or `all`: `{"kind": "instructions", "entry", "start", "total",
    "rows", "truncated"}` at the bytes from the first listed instruction to the
    end of the last (at most 4,096); `rows` at most `limit` M3c rows `[delta,
    length, text]`, `delta` from `entry`, inside the function's span; `total` the
    function's instruction count; `truncated` when the anchor or observation limit
    stopped the page before `limit`; claim `code.instructions` = the value without
    `kind`, and the reviewer checks the cited location starts at the first row and
    ends at the last row's end;
  - `callees` or `all`: M3a `call` rows from the target (`from` = target entry),
    at most `max_calls`, claim `code.calls`;
  - `callers` or `all`: `{"kind": "caller", "at", "from", "to"}` at each call
    instruction in file-backed executable code whose target is the target's entry,
    in address order, at most `max_calls`; `at` the instruction's virtual address,
    `from` the containing function's entry or null, `to` the target entry; claim
    `code.callers` = `{"to", "rows": [[at, from], ...]}` in `at` order;
  - `all` only: M3c `ref` rows from the target, at most `max_refs`, claim
    `code.references`.
- `ghidra.xrefs`: args `address` int 0..2^64-1 (required), `start` 0..65535
  default 0, `limit` 1..256 default 64; at most 256 observations. Every reference
  to `address` from an instruction in file-backed executable code, in instruction
  address order: `{"kind": "xref", "index", "total", "at", "from", "to", "type"}`
  at the instruction's bytes; `type` `call` (tail calls included), `jump`, `read`,
  `write`, `read_write` or `data`; `from` the containing function's entry or null;
  `to` equals `address` (also when `address` has no file bytes). Claim
  `code.xrefs` (derived) = `{"to", "start", "total", "rows": [[at, from, type], ...]}`.
- **Counts**: `total`, `callers_total` and `callees_total` count the rows that pass
  the worker's anchor checks. Instructions are indexed from the entry in address
  order (a body chunk before the entry is not listed). A run that would count more
  than 65,536 callers, callees, xrefs or functions, or more than 1,000,000
  instructions in one function, fails with a fixed error instead of reporting a
  total cut short; these query counts never reuse `ghidra.analyze`'s emission caps
  (decision `m3d-fix-round`). `callers_total` and `callees_total` count call
  instructions (each once), as the `caller` and `call` rows do. `ghidra.xrefs` rows
  are ordered by `at`, then `type` (ASCII order); one instruction may give several
  rows of different types, never two of the same type. An `instructions` page is
  `truncated` exactly when it holds fewer than `limit` rows and
  `start + len(rows) < total`; no `instructions` observation when `start` is at or
  past `total`.
- **Host check** (`ghidra_verify`): per mode, exact field sets and types, anchors
  as above (an instruction's `at` must be the virtual address its offset maps to;
  `to` the target entry or `address`), indexes contiguous from `start`, one
  `total`, counts within `limit`/`max_*`; any violation refuses the whole reply.
  `analyze` keeps `ghidra.analyze` unchanged.
- All `code.*` claims stay in `DERIVED_CLAIMS` (every claim whose operations are
  all `ghidra.*`).

## Child artifacts and Android packages (M4a, contract/3)

M4a reads Android packages on the host, stdlib only: the ZIP container, the binary
manifest and the DEX files, all verified evidence. Decompiled Java (JADX) is M4b
and needs an owner-approved download. Decision `m4a-contract`.

- **Child artifacts** (`reverseai.contract/3`): an observation may name an
  `artifact`, a member stored or deflated inside the input:
  `{"member", "method" (0 stored or 8 deflate), "data_offset", "compressed_size",
  "size", "crc32", "sha256"}`. Its location and excerpt hash are then inside the
  child's bytes. `contract.materialize(data, artifact)` re-derives the child from
  the input: the compressed range inside the input, raw deflate inflated to
  exactly `size` with nothing left over, CRC-32 and SHA-256 equal; at most 32 MiB
  per child and 100:1 expansion; stored members have equal sizes. The gateway
  materializes each child once per operation (at most 128 MiB of distinct
  children, else `budget_exceeded`); the reviewer re-materializes it independently
  once per review (same budget, each distinct child charged at its declared size
  before it is inflated, so a child that fails still spends it; decision
  `m4a-fix-round-2`) and refuses evidence whose child does not match the input. Evidence without an artifact keeps its contract/2 ID and meaning.
  Worker replies (contained tools) cannot name artifacts yet.
- **Tools** `apk` 0.1.0 and `dex` 0.1.0 (in-process): `reverseai/tools/apk.py` (ZIP,
  manifest; operations `apk.*`) and `reverseai/tools/dex.py` (DEX; operations
  `dex.*`). `apk` inflates members with its own bounded inflater (same limits,
  equivalence tested) and `dex` takes its children from `apk`; the gateway and
  the reviewer re-derive every child independently with `contract.materialize`. Limits: input at most 64 MiB (intake), at most
  2,048 members, methods 0 and 8 only; encrypted members, ZIP64, multi-disk
  archives, duplicate or traversing names, and local headers or data descriptors
  that disagree with the central directory are refused or flagged; DEX versions
  035, 037, 038 and 039 (036 was never released) in little-endian order with a
  right checksum and signature; at most 65,536 type, proto, field, method and
  class entries per DEX and 1,048,576 string entries (strings decoded only when
  used, each scan at most 65,536 bytes), at most 262,144 `class_data` and
  `type_list` entries in all per DEX; references decoded as a stream, never a
  list of every instruction; the code decoded for one DEX, aliased code items
  included, at most the DEX's size (decision `m4a-seams-x2`); at most 128 MiB of
  decoded strings per operation, re-decodes included (`m4a-seams-x3`); a DEX past these limits is refused with a fixed
  error, never cut to a total that looks complete. ZIP tables keep their valid
  prefix when malformed, never read past the buffer. Member names are escaped as import names (at most 255 printable
  characters); DEX strings are decoded from MUTF-8 and escaped the same way (at
  most 256 characters, `truncated` when longer). Every literal selector of a `dex.*`
  operation (`member`, `query`, `class`, `method`, `prototype`) is compared with
  the escaped text the rows show, never the raw decoded text, so a displayed
  identity can always be copied back (decision `m4a-fix-round-2`).
- `apk.inventory`: args `start` 0..65535 default 0, `limit` 1..256 default 128.
  Central directory entries in order: `{"kind": "member", "index", "total",
  "name", "method", "compressed_size", "size", "crc32", "sha256", "flags"}` at the
  central directory entry (at most 4,096 bytes, in the input itself); `sha256` is
  the materialized child's hash, or null when the member cannot be materialized;
  `flags` a sorted list of refusal reasons (`crc`, `duplicate_name`, `encrypted`,
  `header_mismatch`, `long_name`, `ratio`, `symlink`, `too_large`, `traversing_name`,
  `unsupported_method`), empty when clean; `long_name` marks an escaped name longer than 255
  characters, listed as its first 255 escaped characters and never materialized; `crc` covers every failed
  materialization (CRC, inflate, size or trailing data); a flagged member is listed but never
  materialized; an empty name is listed only with `traversing_name`. The whole archive is refused (no observation) for ZIP64, multiple
  disks, an ambiguous end of central directory or bytes before the first local
  header other than none; an APK signing block between the last member and the
  central directory is allowed. Manifest decoding is bounded too: XML depth 256,
  at most 65,536 chunks, attributes and string entries in all, and 32 MiB of
  decoded strings (decision `m4a-seams-z`). Claim `android.members` (observed) page rows
  `[name, method, compressed_size, size, crc32, sha256, flags]`.
- `apk.manifest`: args `start` 0..65535 default 0, `limit` 1..256 default 256.
  The attributes of `AndroidManifest.xml` in document order, each
  `{"kind": "manifest_attribute", "index", "total", "element_index", "element",
  "attribute", "type", "value"}` at its 20-byte attribute record inside the child
  (artifact = that member). `element_index` counts start tags from 0, `element`
  is the tag name, `attribute` the name with `android:` when in the Android
  namespace, `type` one of `string`, `int`, `bool`, `reference`, `other`, and
  `value` a string (`string`; `reference` as `@0x7f...`; `other` as `0x` hex), an
  int or a bool. Claims (observed): `android.manifest` page rows `[element_index,
  element, attribute, type, value]`; `android.permissions` = sorted unique values
  of the cited `uses-permission` (and `uses-permission-sdk-23`) `android:name`
  string attributes, whose `index` and `total` must be coherent (one total,
  distinct indexes below it); more than 64 are split into several findings, each a subset,
  which never contradict each other (decision `m4a-fix-round`).
- `dex.classes`: args `member` literal 0..255 default "" (one DEX member by name;
  "" for every `classes*.dex` member in central directory order), `query` literal
  0..128 default "" (substring of the class descriptor), `class` literal 0..255
  default "" (when set, exactly that descriptor and `query` must be ""; decision
  `m4a-fix-round`), `start` 0..1048575 default 0, `limit` 1..256 default 128. `{"kind": "class", "index", "total",
  "dex", "name", "access", "superclass", "interfaces", "interfaces_total",
  "source_file"}` at the
  32-byte `class_def_item` inside the DEX child; `dex` is the member name,
  `name` and `superclass` descriptors (`superclass` null for none), `interfaces`
  the leading declared interfaces while the observation stays within 4,096
  bytes, `interfaces_total` the declared count (at most 64, else the operation
  fails; decision `m4a-fix-round-2`), `source_file` or null ("" is a valid DEX
  value), `access` the flags as an int.
  Claim `android.classes` (observed) page rows `[dex, name, access, superclass]`.
- `dex.methods`: args `member` literal 0..255 default "" (as `dex.classes`: ""
  selects every `classes*.dex` member, and a class defined in several members
  lists each member's methods in member order; decision `m4a-seams-x4`),
  `class` literal 1..255 (exact descriptor), `start` 0..65535 default 0, `limit`
  1..256 default 128. The class's direct then virtual methods in `class_data`
  order: `{"kind": "method", "index", "total", "dex", "class", "name",
  "prototype", "access", "code_offset", "code_units"}` at the 8-byte
  `method_id_item`; `prototype` as `(params)return` descriptors, `code_offset`
  and `code_units` null without code. Claim `android.methods` (observed) page
  rows `[dex, class, name, prototype, access, code_offset, code_units]`.
- `dex.references`: args `member` literal 0..255 default "" (as `dex.classes`),
  `class` literal 1..255, `method` literal 1..255, `prototype` literal 0..255
  default "" (exact; "" for every overload), `direction` enum `from`|`to` default
  `from`, `start` 0..65535 default 0, `limit` 1..256 default 128. `from`: the
  references the method's code makes, in code order; `to`: every instruction in
  the selected DEX members that references the method, in member and code order.
  `{"kind": "dex_ref", "index", "total", "dex", "from_class", "from_method",
  "from_prototype", "at", "ref_kind", "target", "target_truncated"}` at the
  instruction's code units inside the DEX child; `at` the instruction's offset
  inside the child; `ref_kind` `method`, `field`, `string` or `type`; `target`
  `Lcls;->name(params)ret`, `Lcls;->name:Type`, the string or a type descriptor.
  Only a string literal is cut (escaped, at 256 characters, `target_truncated`
  true); an identity (descriptor, name, prototype, member) longer than 255
  escaped characters, or a composed target longer than 512, fails the operation
  with a fixed error rather than an ambiguous cut (decision `m4a-seams-x`). Only references decoded from complete, valid instructions count;
  a method whose code cannot be decoded gives no rows and the run fails with a
  fixed error rather than a total cut short. Claim `android.references`
  (observed) page rows `[dex, from_class, from_method, from_prototype, at,
  ref_kind, target, target_truncated]`.
- These are declarations in the bytes: a reference in code is not evidence that
  it runs, and a permission declared is not evidence that it is used.
- **Queries** (`reverseai/queries.py`), the Android names: `inspect_android_package`
  (`apk.inventory`, `apk.manifest`), `search_android_classes` (`dex.classes`),
  `inspect_android_class` (`dex.classes` with the exact `class`, `dex.methods`), `inspect_android_method` (`dex.methods`, `dex.references`
  `from`; decompiled Java comes with M4b), `trace_android_references`
  (`dex.references`; `direction` from the arguments).

## Decompiled Java through JADX (M4b, contract/3)

Decisions `owner-next-m4b`, `m4b-contract`. JADX reads the package as data; its
Java is the decompiler's reading, kept **derived** like Ghidra's pseudocode.

- **Image**: `containers/jadx/`, linux/arm64, built from the pinned
  `python:3.12-slim` base with JADX 1.5.6 (`jadx-1.5.6.zip`, `545ea2be...8974`,
  the one approved download) and the JDK bytes already approved for Ghidra
  (Temurin 21.0.12.1+1, `23e37e02...e223`); a fixed driver is compiled at build
  time against the bundled `jadx-1.5.6-all.jar` (`fe3e12c4...554b`, its Apache-2.0
  LICENSE kept with it). Lock keys: `adapter_version` `1.5.6-r1`, `platform`,
  `base_digest`, `jadx_zip_sha256`, `jadx_jar_sha256`, `jdk_sha256`,
  `driver_sha256`, `worker_sha256`, `image_id`.
- **Resource profile** (fixed in `reverseai/contained.py`, proven by the native
  verifier): `--memory 2g --memory-swap 2g --pids-limit 256 --cpus 2
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=512m`, wall 120 s, JVM heap 1,536 MiB,
  one JADX thread (decision `m4b-w-plan`; measured: about 4 s and a 207 MB heap
  peak for a 21.7 MB DEX of 60,001 methods).
- **Analysis**: the host resolves the escaped selectors with `dex.py` first.
  The worker request carries the artifact of every clean `classes*.dex` member
  (central directory order, at most 16 and 128 MiB, for type resolution), the
  selected methods as targets (member, and class, name and prototype as hex of
  their raw decoded text, so no escaping or injection question reaches Java),
  `start` and `max_chars`. The worker re-materializes each member from the
  read-only snapshot into `/tmp` and refuses unless size, CRC-32 and SHA-256 equal
  the artifact; JADX reads only those DEX files, never the ZIP, with only its DEX
  input plugin, no resource decoding, no deobfuscation or renames, comments at
  WARN (no paths), no export outside `/tmp`, no option chosen by a request. JADX's
  display names appear only inside the Java text.
- **Argument kind `identity`**: 0..255 printable ASCII characters, the escaped
  form rows show. Unlike `literal`, a contained tool may declare it; its worker
  compares it as text only, never as a path, option or program.
- **Operation** `jadx.method` (derived): args `member` identity 0..255 default ""
  ("" for every `classes*.dex` member; a name that is no `classes*.dex` member of
  the input fails the operation, since JADX needs that set), `class` identity
  1..255, `method` identity 1..255, `prototype` identity 0..255 default "" ("" for
  every overload), `start` int 0..1048575 default 0, `max_chars` int 64..2048
  default 1024. One observation per matched method with code, in member and
  `method_id` order, at most 16 (more fails the operation with a fixed error);
  methods without code (abstract, native) have none.
  `{"kind": "java", "dex", "class", "name", "prototype", "form", "start", "total",
  "text"}`: identities as `dex.methods` rows; `form` `java` (decompiled),
  `fallback` (JADX's fallback listing when it could not decompile), `omitted`
  (JADX by design prints no text for this method: a default constructor that
  only calls `super()`, a synthetic accessor, bridge or inlined lambda; decision
  `m4b-omitted`) or `error` (nothing produced); `omitted` and `error` have
  `text` "", `start` = `total` = 0; `total` the length in
  characters of the method's whole text; `text` its characters from `start`, at
  most `max_chars` (for `java` and `fallback` exactly min(`max_chars`, `total` -
  `start`) characters, else the operation fails; decision `next-carries`); after
  checking the worker's whole row the host cuts it to the
  longest prefix whose observation fits 4,096 bytes, never inside a `\uXXXX`
  escape (decision `m4b-fix-round`). The text is printable ASCII, newline and tab only: the driver
  writes every other UTF-16 unit as a Java `\uXXXX` escape, and `start` and
  `total` count characters of that escaped text. The class declaration line JADX
  prints before a class's first method is not part of the method's text. A
  selected method whose raw class, name or prototype holds an unpaired surrogate
  (MUTF-8 allows one) cannot be sent as UTF-8 and fails the operation.
- **Reply and anchors**: the worker answers each target, in order, with its
  status (`ok`, `fallback`, `omitted`, `decompile_failed`, `class_not_found`,
  `method_not_found`, `no_code`), JADX's `code_offset` and `insns_count` for the
  method, `total` and `text`; a whole-run failure (`memory`, `timeout`, `input`)
  is a fixed error and fails the operation. It names no location or artifact.
  The host builds each observation itself: identities escaped from its own
  `dex.py` rows, `form` `java` for `ok`, `fallback` for `fallback`, `omitted`
  for `omitted`, `error` otherwise; it requires JADX's `code_offset` and `insns_count` to equal the
  verified `code_offset` and `code_units` of that method (for `ok` and
  `fallback`), and anchors the observation at the method's instructions (the
  `insns` of its `code_item`, at most their first 4,096 bytes) inside the
  member's child artifact. A reply for other methods, in another order, or with
  other counts fails the operation. Other statuses carry null `code_offset` and
  `insns_count`, `total` 0 and `text` "" and become `form` `error`. A `start` at
  or past the end gives an empty page at `start` = `total`. A method whose code
  has no instructions counts as without code. Any flagged `classes*.dex` member
  refuses the whole operation, as for `dex.*` (decision `m4b-host-bounds`).
- **Claim** `android.java` (inferred, derived): the observation's fields but
  `kind`, one finding per method page. It never contradicts and is never
  contradicted.
- **Queries**: `inspect_android_method` adds `jadx.method` (same `member`,
  `class`, `method`, `prototype`; `java_start`, `max_chars`) when run with
  `--with-jadx` and the locally built pinned image; without it the Java part is
  absent and the report says so. The Android selector arguments of the queries
  are `identity`, since rows show escaped identities.
- **Report**: the derived section shows each method's Java in a fenced block
  with the tool, image and page (`characters a..b of N`, next `start`).

## JavaScript applications on the host (M5a, contract/3)

Decision `owner-next-m5a`: stdlib only, no download. M5a covers
`analyze_javascript_application` with what the host can verify from the bytes:
the files of an application, its `package.json` declarations and lexical hints
anchored at exact bytes. Abstract syntax, module graphs and deobfuscation need a
pinned parser (M5b, a separate owner question); nothing here executes, imports or
evaluates the sample.

- **Inputs**: one approved file, as today. When the input is a valid ZIP archive
  (the APK ZIP parser accepts it, with its limits and flags) the operations read
  its clean members as child artifacts; an input that starts with a ZIP local
  header signature but that the parser refuses fails the operation with a fixed
  error, so a refused archive is never read as one script; otherwise the input
  itself is one file, named "" in rows. Explicit `file` selectors name clean
  `package.json` members for `js.package` and clean JavaScript members for
  `js.hints`; a selector that names none gives no rows (decision
  `m5a-seams-p2`). Flagged members are listed by `apk.inventory` but never read.
  Tar, gzip and ASAR packages are out of M5a.
- **JavaScript files**: members whose name ends in `.js`, `.mjs`, `.cjs`, `.jsx`,
  `.ts` or `.tsx` (ASCII case-insensitive), plus `package.json`, in central
  directory order; the single-file input counts as one.
- **Tool** `js` 0.1.0 (in-process), `reverseai/tools/js.py`; JSON positions in
  `reverseai/tools/jsonpos.py`; lexical patterns in `reverseai/tools/jshints.py`.
  At most 128 MiB of JavaScript read per operation, else the operation fails with
  a fixed error (never a total that looks complete). Names and texts are escaped
  as import names; `file` and selector arguments compare with the escaped text
  rows show.
- `js.files`: args `start` 0..65535 default 0, `limit` 1..256 default 128.
  `{"kind": "js_file", "index", "total", "file", "size", "sha256", "lines",
  "max_line"}` anchored at the first min(size, 4,096) bytes of the file (inside
  its child artifact for an archive); `sha256` the file's hash (equal to the
  artifact's), `lines` the count of line feeds plus one when the last byte is
  not a line feed (0 for an empty file), `max_line` the longest line in bytes (a
  minified or packed file shows here). A JavaScript-named member that the ZIP
  parser flags is listed too, with `flags` (sorted reviewed flag names, `[]` for
  clean rows), `sha256`, `lines` and `max_line` null and `size` the declared size,
  anchored at its central directory entry and never read (decision
  `m5a-fix-round`); for a clean row `size` 0 means `lines` and `max_line` 0, else
  1 <= `lines` <= `size` and `max_line` <= `size`. An empty archive member is anchored at its
  central directory entry in the input instead (no artifact); an empty
  single-file input has no rows (decision `m5a-seams-p`). Claim `javascript.files` (observed) page
  rows `[file, size, sha256, lines, max_line, flags]`.
- `js.package`: args `file` literal 0..255 default "" ("" for the `package.json`
  with the fewest path segments, the first in central directory order on a tie;
  for a single-file input, the input when its first byte that is not JSON
  whitespace is `{`, else no rows; decision `m5a-bundle-summary`), `start` 0..65535, `limit` 1..256 default
  128. The file is parsed by a bounded JSON reader that records byte positions:
  at most 1 MiB, depth 64 and 65,536 tokens; invalid JSON or a duplicate key in
  one object fails the operation. Rows are the string values of these fields, in
  document order: `name`, `version`, `description`, `main`, `module`, `browser`,
  `types`, `type`, `license`, `homepage`, `repository` (or `repository/url`),
  every string under `bin`, `exports` (depth at most 4), `scripts`, `engines`,
  `dependencies`, `devDependencies`, `peerDependencies`, `optionalDependencies`
  and the entries of `bundledDependencies` (or `bundleDependencies`).
  `{"kind": "package_field", "index", "total", "file", "path", "value",
  "truncated"}` anchored at the value's bytes in the file, quotes included (the
  first 4,096 when longer); `path` an RFC 6901 JSON pointer of the decoded keys
  (`/dependencies/left-pad`, `~0` and `~1` escapes), escaped for display, and a
  pointer longer than 255 characters fails the operation; `exports` strings at
  most four object or array edges below `exports`, `repository` only as a string
  or its direct `url`, `browser` only as a string; a UTF-8 byte order mark is
  refused; the file must hold one JSON object;
  `value` the decoded string escaped, cut at 256 characters with `truncated`.
  Claim `javascript.package` (observed) page rows `[file, path, value,
  truncated]`. Scripts are declarations: `preinstall`, `install`, `postinstall`
  and `prepare` run on install, which the report says, but nothing runs them.
- `js.hints`: args `file` literal 0..255 default "" (every JavaScript file but
  `package.json`), `category` enum `all`, `endpoint`, `dynamic_code`, `shell`,
  `filesystem`, `network`, `credential`, `encoding` default `all`, `start`
  0..1048575, `limit` 1..256 default 128. Every occurrence of the fixed patterns
  of `jshints.PATTERNS` (each a name, a category and a bounded regular expression
  over bytes), in file then offset order, comments and strings included:
  `{"kind": "js_hint", "index", "total", "file", "category", "hint", "text",
  "truncated"}` anchored at the matched bytes (at most 4,096); `hint` the pattern
  name, `text` the matched text escaped, cut at 256 with `truncated`. Claim
  `javascript.hints` (observed) page rows `[file, category, hint, text,
  truncated]`: lexical occurrences, not evidence that the code runs. Known
  limits: a call split by a comment or by more than 64 bytes of whitespace, an
  indirect call or a non-literal `fs` receiver is missed; `process_call` matches
  `execSync`, `execFile`, `execFileSync`, `spawn`, `spawnSync` and `fork` bare or
  on any receiver, and `exec` only bare or on `child_process`, `childProcess` or
  `cp` (so a regular expression's `.exec(` is not a hint); `new Function(` gives
  one `new_function` hint, not also `function_constructor` (decision
  `m5a-fix-round`).
  `jshints.scan(data)` yields `(offset, length, category, hint)` for one file's
  bytes, in offset order, overlapping matches of different patterns allowed.
- **Query** `analyze_javascript_application`: args `detail` enum
  `summary`, `files`, `package`, `hints` default `summary`, `file`, `category`,
  `start`, `limit` as above; `summary` routes `js.files`, `js.package` and
  `js.hints` (first page each), the others one operation.
- **Report**: a JavaScript section with files (size, lines, longest line),
  package declarations (install-time scripts marked), and hints grouped by
  category; it says plainly that hints are lexical and that M5a reads no syntax.

## JavaScript syntax through a pinned parser (M5b, contract/3)

Decisions `owner-next-m5b`, `owner-m5b-downloads`, `m5b-contract`. A pinned
parser reads JavaScript text as data in a locked container; the host binds every
answer to bytes it reads itself. The syntactic role (an import, a call) is the
parser's reading and stays **derived**; the bytes at each anchor are verified.

- **Image**: `containers/jsparser/`, linux/arm64, from the pinned
  `python:3.12-slim` base with the five approved downloads: Node.js 24.22.1
  (`node-v24.22.1-linux-arm64.tar.xz`, `dbabf7a1...336e`) and the npm tarballs
  `@babel/parser` 8.0.4, `@babel/types` 8.0.4, `@babel/helper-string-parser`
  8.0.6, `@babel/helper-validator-identifier` 8.0.6 (registry sha512 integrities). No npm client and no install scripts: the build tool checks each
  tarball and unpacks it. A fixed driver imports `@babel/parser` only. Lock keys:
  `adapter_version` `8.0.4-r1` (`8.0.4-r2` since M5c, whose worker also reads gzip-stream children), `platform`, `base_digest`, `node_sha256`,
  `babel_parser_integrity`, `babel_types_integrity`,
  `helper_string_parser_integrity`, `helper_validator_identifier_integrity`,
  `driver_sha256`, `worker_sha256`, `image_id`.
- **Profile** (fixed in `reverseai/contained.py`, proven by the native
  verifier; decision `m5b-w-plan`): the JADX flag set with `--memory 2g
  --memory-swap 2g --cpus 2 --pids-limit 64 --tmpfs /tmp:...,size=64m`, wall
  120 s, Node heap 1,536 MiB (measured: 32 MiB of JavaScript in 72 s and 784 MiB
  on one loaded CPU).
- **Parsing**: each file's bytes are decoded as UTF-8 (a leading BOM skipped;
  invalid UTF-8 gives status `decode_error`), then parsed with `sourceType`
  `unambiguous`, `errorRecovery` on, plugins fixed by the file suffix (`jsx` for
  `.jsx`, `typescript` for `.ts`, `typescript` and `jsx` for `.tsx`, none
  otherwise); no plugin or option comes from a request. Nothing is evaluated,
  imported, required or transpiled.
- **Operation** `jsparser.syntax` (derived): args `file` identity 0..255
  default "" (as `js.hints`: "" for every JavaScript file but `package.json`),
  `kind` enum `modules`, `calls`, `parse` default `modules`, `start` int
  0..1048575 default 0, `limit` int 1..256 default 128. The host resolves the
  files with the `js` tool's rules (ZIP or single file, flags, budgets; at most
  64 files, each at most 4 MiB, 32 MiB in all, else a fixed error) and sends the
  worker their artifacts (or the snapshot for a single file) and their dialects;
  the worker re-materializes members like the JADX worker.
- **Request and paging** (decision `m5b-seams-w`): the host's closed request
  carries the files (artifacts or the snapshot, dialects), `kind`, `start`,
  `limit` and `callees`, the sorted `jshints.CALLEES` (always exactly that list;
  the image need not change when the list does). The worker finds every item of
  that kind in file then offset order, returns each file's item count and only
  the items of the page `start`..`start + limit`, each with its file index.
- **Reply** (decision `m5b-seams-h`): the worker/1 observations are one row per
  file in request order, `{"file": index, "status", "errors", "count", "items"}`:
  `status` `ok` (errors 0), `syntax_error` (errors > 0, items allowed),
  `decode_error` or `too_large` (errors, count 0, no items); `count` the file's
  items of the kind; `items` that file's part of the page, sorted by start, end
  and form, no duplicates. Offsets count UTF-16 units of the decoded text after
  one leading BOM is skipped; an offset inside a surrogate pair fails. The
  concatenated items must be exactly the page the counts define. Items: `{"kind": "import" | "export_from" | "require" | "dynamic_import",
  "start", "end"}` with the UTF-16 offsets of the module source string literal,
  and `{"kind": "call", "start", "end"}` with the offsets of a callee that is an
  identifier or a chain of at most four identifiers joined by dots (`new` calls
  included) whose trailing parts equal an entry of `jshints.CALLEES`: entries
  are one name for distinctive calls (`eval`, `execSync`, `fetch`) and a
  receiver plus name for common names (`Buffer.from`, `http.get`,
  `https.request`, `net.connect`, `fs.write`, and `exec` only as
  `child_process.exec`, `childProcess.exec` or `cp.exec`, so a regular
  expression's `exec` is not a call item; decision `m5b-fix-round`), so `map.get(k)` is not a call item
  (decision `m5b-callee-suffix`); `import(...)` is a `dynamic_import` module item,
  never a call. Offsets only: the worker
  never returns text, names or locations in bytes.
- **Anchors**: the host converts each UTF-16 offset to a UTF-8 byte offset of
  the file's own bytes, then re-derives the value from those bytes: for a module
  item the bytes must be one complete single- or double-quoted string literal
  (or a template literal without `${`), decoded with every ECMAScript escape
  (legacy octal and identity escapes included), whose decoded value becomes
  `source` (escaped, cut at 256 with `truncated`); for a call the bytes must be
  the identifier chain (ASCII identifiers `[$A-Za-z_][$A-Za-z0-9_]*` and dots, no
  other byte; the worker omits chains with other identifiers or escapes), which
  becomes `callee`. Anything else fails the operation. The host checks the
  bytes, not the syntactic role: that an anchor is code and not a comment is the
  parser's reading, which is why these pages are derived.
  `{"kind": "js_module", "index", "total", "file", "form", "source",
  "truncated"}`, `{"kind": "js_call", "index", "total", "file", "callee"}` and
  `{"kind": "js_parse", "index", "total", "file", "status", "errors"}` (anchored
  at the first 4,096 bytes of the file; empty files have no rows).
- **Claims** (inferred, derived pages): `javascript.modules` rows `[file, form,
  source, truncated]`, `javascript.calls` rows `[file, callee]`,
  `javascript.parse` rows `[file, status, errors]`. They never contradict and
  are never contradicted; the lexical hints of M5a stay observed.
- **Query**: `analyze_javascript_application` gains `detail` values `modules`,
  `calls` and `parse` (routing `jsparser.syntax` with that `kind`) with
  `--with-jsparser` and the locally built pinned image; without it those details
  are refused and the other details work as in M5a.

## Electron ASAR archives (M5b, contract/3)

Decision `m5b-asar`. An ASAR archive is an uncompressed concatenation of files
behind a JSON header, so its files are stored child artifacts (`method` 0) of the
input, verified by `contract.materialize` like stored ZIP members.

- **Format**: a 4-byte little-endian size field equal to 4, the 4-byte header
  pickle size, then the header pickle (payload size, string length, the JSON
  header bytes, padding to 4); file data starts right after the header pickle.
  The header is read with `jsonpos` at most 4 MiB, depth 64 and 262,144 tokens;
  entries are `{"files": {...}}` directories or file objects with `size` and a
  decimal-string `offset` relative to the data start; `unpacked`, `link`,
  `executable` and `integrity` fields are allowed.
- **Members**: names are the `/`-joined path, escaped as ZIP member names, in
  header order (depth first); each joined raw path at most 65,535 UTF-8 bytes and
  at most 32 MiB of joined raw path bytes per archive, checked before joining
  (decision `m5b-asar-names`); at most 65,536 entries and 128 MiB of file data
  read per operation; every stored member range lies inside the input after the
  header (flagged `asar_unpacked` and `asar_link` entries have no range and are
  never read).
  A member with `unpacked` true (its bytes are outside the archive) gets the flag
  `asar_unpacked`, a `link` entry the flag `asar_link`, a name failing the ZIP
  name rules `traversing_name`; flagged members are listed and never read.
  Overlapping ranges, a size or offset past the input, or a malformed header
  fail the operation (never a total that looks complete).
- **Use**: `js.files`, `js.package`, `js.hints` and `jsparser.syntax` treat a
  valid ASAR input like a ZIP archive (the JavaScript file rule, selectors and
  budgets unchanged); an input that starts with the ASAR size field but fails the
  ASAR rules fails the operation, as a refused ZIP does. Artifacts carry
  `method` 0, `compressed_size` = `size`, the CRC-32 and SHA-256 the host computes.
  `MEMBER_FLAGS` gains `asar_link` and `asar_unpacked`.

## npm tarballs (M5c, contract/3)

Decisions `owner-next-m5c`, `m5c-contract`. An npm package tarball is one gzip
stream (RFC 1952) holding a tar archive; its files are children inside the
inflated stream. Host only, stdlib only, no download.

- **Child artifacts, method 1** (still `reverseai.contract/3`: methods 0 and 8
  and every existing evidence ID keep their meaning): `{"member", "method": 1,
  "data_offset", "compressed_size", "inner_offset", "size", "crc32", "sha256"}`
  names the bytes `inner_offset`..`inner_offset + size` of the stream obtained by
  inflating the gzip member at `data_offset`..`data_offset + compressed_size` of
  the input. `contract.inflate_stream` accepts exactly one gzip member filling
  that range: magic `1f 8b`, method 8, reserved flag bits zero, FEXTRA, FNAME and
  FCOMMENT skipped inside the range, FHCRC checked when present; inflated within
  min(128 MiB, 100 x `compressed_size`); then the 8-byte trailer, whose CRC-32
  and ISIZE equal the inflated bytes, and nothing after it. `inner_offset +
  size` is at most 128 MiB and at most 100 x `compressed_size`; `size` stays at
  most 32 MiB as for every child. `contract.materialize(data, artifact,
  streams=cache)` inflates each distinct stream once per cache. The gateway
  keeps one cache per operation and charges each new stream min(128 MiB, 100 x
  `compressed_size`) before inflating it (at most 128 MiB of streams besides the
  128 MiB of distinct children, else `budget_exceeded`); the reviewer keeps one
  per review and charges each distinct stream min(128 MiB, 100 x
  `compressed_size`) before inflating it, so a stream that fails still spends
  its charge, and is remembered as failed: every child of it is refused (the
  rule of `m4a-fix-round-2`).
- **Tarball** (`reverseai/tools/tarball.py`, its own bounded inflater, tested
  equal to `contract.inflate_stream`): an input that starts with `1f 8b` is a
  tarball, and the whole input must be its one gzip member (`data_offset` 0,
  `compressed_size` the input size). A tarball is accepted only after the whole
  stream is inflated and verified and the tar is read to its end: there is no
  prefix reading. Tar headers are 512-byte blocks with a right checksum (the
  unsigned sum, or the signed sum old tools wrote), magic `ustar\0` with version
  `00` (POSIX, whose `prefix` field is joined with `/`) or `ustar  \0` (GNU),
  sizes in octal or base-256. The archive ends with two zero blocks followed by
  zero bytes only, up to the end of the stream. A missing end, a truncated
  header or data, a bad checksum or magic, or other bytes after the end fail the
  operation. At most 65,536 physical headers, extensions and directories
  included.
- **Extensions**: a pax `x` record and the GNU `L` (name) and `K` (link name)
  extensions apply to the next entry; at most 1 MiB per extension body and 4 MiB
  of extension bodies per archive; a name or link name at most 65,535 UTF-8
  bytes. Pax records are `<length> <key>=<value>\n` with an exact decimal
  length; the keys `path`, `linkpath` and `size` (decimal digits) apply, other
  keys are ignored. A malformed record, a key repeated in one record,
  `hdrcharset` other than the literal value `UTF-8`, any `GNU.sparse.` key, a pax `g` record with a
  key other than `comment`, an extension not followed by an entry, and GNU
  sparse (`S`), multivolume (`M`) or volume (`V`) headers fail the operation.
- **Entries**: names are decoded as UTF-8; a name that is not valid UTF-8 is
  listed with backslash escapes and flagged `header_mismatch`, as a ZIP name is.
  Regular files (`0`, NUL, `7`) are members in archive order; directories (`5`)
  are counted, not listed; symbolic links (`2`) are flagged `symlink`, hard links
  (`1`) `hardlink`, other types (`3`, `4`, `6` and unknown ones)
  `unsupported_type`. Links, directories and devices must declare size 0, else
  the operation fails; unknown types skip their declared data. The ZIP name
  rules apply unchanged: `traversing_name`, `long_name` (an escaped name longer
  than 255 characters, listed as its first 255), `duplicate_name` on every entry
  whose escaped name repeats, `too_large` past 32 MiB. Flagged entries are listed
  and never read; link targets are never followed or shown. `MEMBER_FLAGS` gains
  `hardlink` and `unsupported_type`.
- **Use**: `js.files`, `js.package`, `js.hints` and `jsparser.syntax` treat a
  valid tarball as they treat a ZIP or ASAR archive (the JavaScript file rule,
  selectors and budgets unchanged; names keep the `package/` prefix, so the
  shallowest `package.json` is `package/package.json`); a refused tarball fails
  the operation. A file that is read carries a method 1 artifact. A flagged
  entry's row, and an empty file's, is anchored at the entry's 512-byte header
  block: a method 1 artifact with `inner_offset` the header's offset, `size` 512
  and `member` the row's `file` (`tar header` when that is empty).
- **Worker**: the jsparser worker accepts method 1 artifacts and re-derives them
  as the host does (one bounded inflation per stream, then the range, size,
  CRC-32 and SHA-256) inside its fixed profile. Its image is rebuilt offline from
  the approved downloads already cached (`adapter_version` `8.0.4-r2`), and the
  native verifier gains a tarball case.

## Packaging, setup and platforms (M6, contract/3)

Decisions `owner-next-m6`, `m6-contract`. M6a makes ReverseAI installable and
checkable without a download, a paid call or a hosted CI run. Hosted CI, amd64
images and a Windows proof are M6b and wait for the owner. The analysis
contract above is unchanged.

- **Version**: `reverseai.__version__` is the single source, `0.6.0` for M6, `0.6.1` for M6b, `0.6.2` for the presentation release, `0.7.0` for the MCP server, `0.8.0` for the reconstruction export and `0.9.0` for the resumable hive;
  `pyproject.toml` declares the same static version and a test pins the two equal.
- **pyproject.toml** (PEP 621): name `reverseai`, the version, a one-line
  description, `readme = "README.md"`, `requires-python = ">=3.12"`, no
  dependencies, `[project.scripts] reverseai = "reverseai.cli:main"`. No license
  field until the owner chooses one. `[build-system] requires = []`,
  `build-backend = "reverseai_build"`, `backend-path = ["tools"]`: an in-tree
  PEP 517 backend, `tools/reverseai_build.py`, stdlib only, with `build_wheel`,
  `build_sdist` and `get_requires_for_build_wheel` / `_sdist` returning `[]`, so
  `pip wheel .` and `pip install .` need no download.
- **Wheel** `reverseai-0.6.0-py3-none-any.whl`, reproducible (the same clean tree
  gives the same bytes; untracked files under `reverseai/` would enter it: entries sorted, timestamp 1980-01-01 00:00:00, modes 0644):
  every `reverseai/**/*.py` (no `__pycache__`), the five locks copied to
  `reverseai/_locks/<tool>.json` from `containers/<tool>/image.lock.json` (`lief`,
  `yarax`, `ghidra`, `jadx`, `jsparser`) with the YARA-X ruleset as
  `reverseai/_locks/m2_fixture_v1.json` (decision `m6-seams-p`), and `reverseai-0.6.0.dist-info/` with
  `METADATA` (Name, Version, Summary, Requires-Python, the README as Markdown
  description), `WHEEL` (purelib, tag `py3-none-any`), `entry_points.txt`,
  `THIRD_PARTY_NOTICES.md` and a `RECORD` with SHA-256 and sizes. No tests,
  tools or container build contexts: images are built from a checkout.
- **sdist** `reverseai-0.6.0.tar.gz`, reproducible (sorted, mtime 0, uid and gid
  0, modes 0644 or 0755 as in Git, gzip level 9 fixed, so the bytes do not
  depend on the Python version's default; decision `m6-fix-round`): the Git-tracked files of `reverseai/`,
  `tools/`, `containers/`, `docs/`, `tests/`, `media/` and the top-level
  `README.md`, `THIRD_PARTY_NOTICES.md`, `pyproject.toml`, under one
  `reverseai-0.6.0/` root with a `PKG-INFO`.
- **Locks**: each contained tool resolves its default lock through
  `contained.default_lock(tool)`: the packaged `reverseai/_locks/<tool>.json`
  when it exists (an installed wheel), else `containers/<tool>/image.lock.json`
  in the checkout. A test pins the wheel copies equal to the checkout bytes.
- **CLI**: `reverseai --version` prints `reverseai 0.6.0`. `reverseai doctor`
  is read-only: it never pulls, builds or runs a container and reads no sample.
  It reports the Python version and platform, whether each lock loads, whether
  Docker answers a fixed `docker version` call within 10 s, and for each
  contained tool whether the locked image ID is present locally (inspect only).
  Exit 0 when the host features work (Python 3.12 or later), with each contained
  tool marked available or not; `--json` gives the same facts as JSON.
- **Platforms (M6a)**: the whole suite on the macOS arm64 host, and in a Linux
  arm64 container built from the pinned `python:3.12-slim` base already cached
  (the source copied in from `git archive` of the candidate, no host mount,
  network none, non-root, read-only root with a tmpfs), plus the wheel built,
  installed into a fresh venv offline and run there. Receipts
  `.coordination/m6/platform-<os>-<arch>.json` name the Python version, platform,
  commit, counts and base digest. Natives stay Linux arm64 Docker on the Mac.
- **Docs**: `docs/INSTALL.md` (requirements, install from the wheel or a
  checkout, running the five contained tools offline from locked images already
  built, building images from their approved downloads with each SHA-256: JADX and
  jsparser build offline, while the LIEF, YARA-X and Ghidra recipes still pull the
  pinned base and Ghidra installs build packages, so they need network; decision
  `m6-seams-builders`), the native verifier, `doctor`), `docs/SECURITY.md` (what is trusted,
  containment profile, verified versus derived, limits, how to report a
  problem), `CHANGELOG.md` (M1 to M6 with tags), and the README install section.

## License, manual CI, Windows reports and offline builders (M6b, contract/3)

Decisions `owner-license-mit`, `owner-ci-manual`, `m6b-contract`. M6b is version
`0.6.1`. The analysis contract and the evidence shapes above are unchanged.

- **License (lane P)**: the project is MIT. A top-level `LICENSE` holds the
  standard MIT text, `Copyright (c) 2026 Stefano D'Agostino`. `pyproject.toml`
  declares `license = "MIT"` and `license-files = ["LICENSE",
  "THIRD_PARTY_NOTICES.md"]` (PEP 639). The wheel's `METADATA` becomes
  Metadata-Version 2.4 with `License-Expression: MIT` and one `License-File`
  line per file; both files are copied to `reverseai-0.6.1.dist-info/licenses/`
  (no longer at the dist-info root) and listed in `RECORD`. The sdist adds
  `LICENSE` at its root and the same headers in `PKG-INFO`. `THIRD_PARTY_NOTICES.md`
  lists the external tools and their licenses. The backend refuses a pyproject
  whose license or license files differ from these values.
- **Editable install (lane P)**: the backend adds PEP 660 `build_editable` and
  `get_requires_for_build_editable` (returning `[]`): a wheel whose only payload
  is `reverseai_editable.pth` holding the absolute checkout root, with the same
  dist-info (METADATA, WHEEL, entry points, licenses, RECORD) as the normal wheel.
  `pip install --no-index --no-deps -e .` then needs no download; the checkout's
  locks are used through `contained.default_lock` because no `_locks` copy exists.
- **Manual CI (lane C)**: `.github/workflows/manual-proof.yml` is triggered only by
  `workflow_dispatch` with one choice input `target` (`linux`, `windows`, `both`;
  default `linux`). No `push`, `pull_request`, `pull_request_target`, `schedule`
  or `workflow_run` trigger. Top-level `permissions: contents: read`; no
  `secrets.` reference; no cache, artifact upload or deployment. Jobs:
  `linux` on `ubuntu-24.04` and `windows` on `windows-2025`, each with
  `timeout-minutes: 30`. The only actions are `actions/checkout` pinned to commit
  `3d3c42e5aac5ba805825da76410c181273ba90b1` (v7.0.1) with
  `persist-credentials: false`, and `actions/setup-python` pinned to commit
  `6d4fd22b20465ccc0f7354476588e8df7c9ca0e0` (v7.1.0) with Python `3.12`; the
  pins are full SHAs with the version as a trailing comment. Each job then runs
  only `python -B tools/host_proof.py --receipt <runner temp>/receipt.json`.
  A test pins all of the above by reading the workflow text, so the YAML stays
  in one plain block style without anchors or flow mappings. Running it is the
  owner's call each time (decision `owner-ci-manual`); a workflow on GitHub can be
  dispatched only once it is on the default branch.
- **Host proof (lane C)**: `tools/host_proof.py` runs on the current host, from a
  checkout, the steps of the Linux proof's `inside()` (refactored so both share
  one implementation): suite, wheel (`pip wheel --no-index --no-deps`), venv,
  offline install, `--version`, imported_from, `doctor --json`, the code-built
  fixture, `analyze --out`, plus a `query <fixture> --query list_segments --arg
  limit=16 --out` step. The venv layout follows the host (`bin/` or `Scripts\`).
  It writes the receipt JSON and prints it on one line after the marker
  `REVERSEAI-HOST-PROOF `, also appending it to `$GITHUB_STEP_SUMMARY` when set.
  Pass on POSIX: every step exit 0, the whole suite run with zero failures and
  errors, the counts parsed, version and imported_from inside the venv, the
  `doctor --json` output a JSON object with `host_ok` true and `reverseai` equal
  to the expected version, both reports present. Pass on Windows (`os.name == "nt"`): the same install,
  version, doctor, fixture, analyze and query checks plus a `windows_tests` step
  running `python -B -m unittest tests.test_windows_output -v` with zero
  failures, errors and skips and at least one test run (decision `m6b-fix-round`); the whole suite still runs and
  its counts are recorded, but it does not gate the Windows result. The receipt
  names the commit (`git rev-parse HEAD`), Python version, platform, machine and
  each step's exit and output tail. Receipts kept in the repository are
  `.coordination/m6b/platform-<os>-<arch>.json`.
- **Offline LIEF and YARA-X builders (lane C)**: `tools/build_lief_image.py` and
  `tools/build_yarax_image.py` no longer pull: like the JADX builder they inspect
  the pinned base and refuse when it is absent (`this tool never pulls`). The build
  keeps `--network none` and `--pull=false`; `--download` for the pinned wheel
  stays an explicit opt-in. Proof: one rebuild each from the approved local
  wheel to a scratch tag and a scratch lock path, then the native verifier with
  that scratch lock; the committed locks and images stay unchanged and the scratch
  images are removed. Docker only under the `docker-desktop` reservation. The
  Ghidra builder still needs network (its natives stage runs `apt-get`); making it
  offline needs approved Debian package downloads and is deferred.
- **Windows reports (lane W)**: on Windows (`os.name == "nt"`) `analyze` and
  `query` accept `--out` only for a directory that does not exist yet. It is
  created with `os.mkdir(path, 0o700)`, which on CPython 3.12.4 or later
  (gh-118486; for 3.13, 3.13.0b2 or later) gives the new directory a private ACL;
  older Windows Pythons, including earlier 3.13 prereleases, refuse `--out`. The new directory is opened with `CreateFileW` using
  `FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT`, share mode without
  `FILE_SHARE_DELETE` (so it cannot be renamed, deleted or replaced while bound),
  and checked through the handle to be a directory, not a reparse point, and
  empty. Each report is created relative to that handle with `NtCreateFile`
  (`OBJECT_ATTRIBUTES.RootDirectory` set to the handle, a bare file name,
  `FILE_CREATE`, `FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT |
  FILE_SYNCHRONOUS_IO_NONALERT`), never by path, then written through
  `msvcrt.open_osfhandle` with `\n` newlines. All Win32 and NT calls live in a
  new `reverseai/winout.py` with explicit `argtypes`, `restype` and error
  checks, loaded only on Windows. Existing POSIX behaviour and messages are
  unchanged. Tests on POSIX drive `winout` through a fake API to pin the call
  sequence and every refusal; `tests/test_windows_output.py` runs the real
  calls only on Windows (an existing directory, a junction and a symlink at
  `--out` refused, new reports with exact bytes, the bound directory not
  renameable while bound) and skips elsewhere. Input intake already refuses a
  link or a swapped file through its `lstat` and handle identity check; the
  Windows tests also pin that for a symlinked input.
- **Docs (lane P)**: README (license section, platforms, manual CI and how it
  is started, Windows reports), `docs/INSTALL.md` (Windows analysis with a new
  `--out` and Python 3.12.4 or later; editable install; offline LIEF and YARA-X
  builders; Ghidra still online), `docs/SECURITY.md` (Windows report binding,
  the CI's permissions and pinned actions, what a manual CI receipt proves),
  `CHANGELOG.md` under "Unreleased: M6b", and `media/how-it-works.svg`. Release
  status lines are written at the release gate from the receipts.
- **Platforms (M6b)**: the whole suite on macOS arm64 and in the Linux arm64
  container as in M6a, natives on rc1, and the manual CI receipts for Linux
  x86-64 (host suite and wheel, not containers) and Windows x86-64 once the owner
  starts a run. No AMD64 container image is built: that needs approved downloads.

## MCP server (0.7.0)

`reverseai mcp` serves ReverseAI's analysis to AI agents and other clients of the Model Context Protocol (MCP). It
adds no analysis of its own: every tool call runs the existing `analyze` or `query` command in-process, with the
same validation, budgets, gateway, reviewer and reports.

- **Command:** `reverseai mcp --inputs DIR [--with-lief] [--with-yarax] [--with-ghidra] [--with-jadx]
  [--with-jsparser]`. `DIR` must be an existing directory; it is resolved once at start with `os.path.realpath`.
  The flags are the operator's choice; no client request can enable a contained tool. The command is `stdio` only:
  it opens no network port.
- **Transport:** JSON-RPC 2.0, one UTF-8 JSON object per line on stdin and stdout. stdout carries protocol messages
  only; diagnostics go to stderr, bounded. A line longer than 1 MiB is answered with a parse error and discarded
  without being held in memory beyond the limit. JSON arrays (batches) are refused with "invalid request". Messages
  are handled one at a time, in order. End of input ends the server with exit 0.
- **Protocol versions (dual-era):** the server supports the modern revision `2026-07-28` and the handshake-based
  revisions `2025-11-25`, `2025-06-18` and `2025-03-26`, as the MCP specification's backward-compatibility rules
  allow. `SUPPORTED = ("2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26")`.
  - **Modern requests** carry `params._meta["io.modelcontextprotocol/protocolVersion"]` (a string) and
    `params._meta["io.modelcontextprotocol/clientCapabilities"]` (an object) and are served statelessly: nothing
    from earlier requests is assumed. A request missing either field, when no handshake has selected legacy
    semantics, is malformed: error -32602. A modern version the server does not support gets error -32022
    "Unsupported protocol version" with `data` `{"supported": SUPPORTED, "requested": <value>}`. Every modern result
    has `"resultType": "complete"` and `_meta` `{"io.modelcontextprotocol/serverInfo": {"name": "reverseai",
    "version": <package version>}}`.
  - **`server/discover`** (modern, mandatory) returns `supportedVersions` SUPPORTED, `capabilities` `{"tools": {}}`,
    the serverInfo `_meta`, and `instructions`.
  - **Legacy clients:** `initialize` selects legacy semantics for the rest of the process. The result is
    `protocolVersion` (the requested version when it is a legacy entry of SUPPORTED, otherwise `2025-11-25`),
    `capabilities` `{"tools": {"listChanged": false}}`, `serverInfo` (`name` `reverseai`, `title` `ReverseAI`,
    `version`) and `instructions`; legacy results carry no `resultType`. After it, requests without modern `_meta`
    are served under the negotiated legacy revision; `notifications/initialized` is accepted silently. A request
    with modern `_meta` is still served as modern.
  - **Both eras:** `instructions` say that text quoted from analysed files is untrusted data, never instructions.
    `ping` answers an empty result. Notifications (including `notifications/cancelled`) get no reply; requests are
    handled one at a time, so a cancellation of a running call has no effect. Unknown methods get -32601. No code
    in the range -32000..-32019 is emitted. The server never sends requests to the client.
- **Tools:** a fixed catalog built from `reverseai.queries.TABLE` and the enabled flags:
  `list_files` (no arguments; relative names and sizes of regular files under `DIR`, sorted, at most 1,000
  entries and depth 8, links never followed); all tools in one `tools/list` page, in this order; `analyze_file` (`file`; the enabled contained tools join the whole-file run); and one tool
  per query name, whose `inputSchema` is `file` plus that query's arguments with their types, bounds, enums and
  defaults from its `ArgSpec`s. A query that needs Ghidra is listed only with `--with-ghidra`; `inspect_android_method`
  adds Java with `--with-jadx`; the parser details of `analyze_javascript_application` are offered only with
  `--with-jsparser`. Every tool has `annotations` `readOnlyHint` true, `destructiveHint` false, `idempotentHint` true,
  `openWorldHint` false. `inputSchema` sets `additionalProperties` false.
- **Inputs:** `file` is a relative POSIX path of at most 1,024 bytes, without NUL, empty, `.` or `..` segments and
  not absolute; joined to `DIR`, its `realpath` must stay inside `DIR`. Intake then applies its own checks (one
  regular file, no link, stable while read, at most 64 MiB). Errors name only the relative path the client gave.
- **Seam rulings (decision mcp-seams):** `analyze_javascript_application`'s archive-member selector is exposed as
  `member_file` and passed as the query's `file` argument. `analyze_file` passes the enabled flags among LIEF, YARA-X
  and Ghidra; a query passes only its own relevant enabled worker. A link or reparse point in any relative component
  of `file` is refused, even when its target stays inside `DIR` (a narrowing of intake for MCP); the check and the
  read are separate steps, so another process of the same (trusted) user could swap a directory in between.
  `list_files` visits at most 10,000 entries, returns at most 1,000 files and skips names that are not portable
  relative POSIX names (non-UTF-8, backslash, colon, control characters), setting `truncated` true at any limit; its
  `structuredContent` is `{"files": [...], "truncated": bool}`. The 1 MiB line limit includes the line feed; the
  whole text item is at most 256 KiB; the structured size is the canonical JSON byte length. The server learns an
  exceeded budget or a failed analysis through a private keyword-only status callback of `reverseai.cli.main`.
- **Calls:** each call writes its reports into a new directory inside a fresh private temporary directory, reads
  them back and removes the temporary directory whatever the outcome. The command's own stdout and stderr are
  captured, never written to the protocol stream.
- **Results:** `content` holds one text item: a fixed line saying that quoted file text is untrusted data, then the
  Markdown report, cut at 256 KiB with a closing note when longer. `structuredContent` is `{"report": <report.json>}`
  when that object serialises to at most 1 MiB, otherwise `{"report": null, "omitted": "<reason>"}` with a hint to
  narrow or page the query. An unknown tool name is a protocol error (-32602, "Unknown tool: <name>"). Arguments that do not
  fit the tool's `inputSchema`, a refused input, a failed targeted query or an exceeded budget are tool results
  with `isError` true and a fixed message, never a traceback; a CLI refusal is forwarded only from an allow-list of
  fixed, path-free lines (decision mcp-fix-s-seams). `analyze_file` is an error only when the review has no
  supported or derived verdict or a budget was exceeded; when a contained tool does not apply to the format, the
  report is returned with a first line naming the incomplete operations (decision mcp-real-test-findings).

## Reconstruction export: prepared Ghidra analysis and paged exports (0.8.0)

Goal: let an agent rebuild larger programs from evidence. Ghidra analyses a file once; the analysis is kept as an
opaque artifact that only locked containers ever open; whole functions and the whole program are exported in pages.
The analysis path still never executes the input. Every observation is still admitted against the ORIGINAL input
bytes; the cached project is always untrusted (a matching digest proves storage identity, not honest analysis).

- **Offline image revision (r7).** `tools/build_ghidra_image.py revise` builds a new locked image from the approved
  local r6 parent `sha256:ac77fda75da8580e0479087580f83b6e5495fb16df97b9696a2bdf3ae100f452` without network: route A
  (a closed Dockerfile FROM that local parent, COPY of the reviewed worker files only, `--pull=false --network=none`,
  fail-closed engine preflight) and route B (create the parent with `--pull never`, never start it, copy the fixed
  files, commit, remove the container). The parent is inspected by ID first; a missing or different parent fails
  before any build. The result is verified (parent layer prefix, unchanged JDK and Ghidra, user, environment,
  entrypoint, exact file set). Lock keys r7: adapter_version, base_digest, ghidra_sha256, jdk_sha256,
  parent_image_id, bundle_sha256, cache_format, image_id, platform; `bundle_sha256` is the SHA-256 of the canonical
  JSON map relative path -> SHA-256 of every worker, helper, Java script and options file. An r6 lock is never
  admitted as r7. The full networked build copies the same bundle file set and writes an r7 lock with
  `parent_image_id: null` (revise writes the r6 ID); it is not run in 0.8.0. No frozen r6 copy is kept: the r6 bytes
  are reproducible from tag v0.7.0. `parent_image_id` is informational and not part of the cache key.
- **Prepare.** CLI `reverseai prepare FILE --with-ghidra [--json]` and the MCP tool `prepare_file(file)` (listed only
  with `--with-ghidra`) run the internal operation `ghidra.prepare` (args `{}`): import, fixed analysis, export tables,
  close, then write ONLY an uncompressed USTAR archive on stdout through a dedicated streaming sink (<= 64 MiB, never
  JSON or base64). Failure, timeout, overflow or incomplete analysis publishes nothing. The host never parses the tar;
  after exit 0 it builds the manifest `{format, input_sha256, image_id, bundle_sha256, size, artifact_sha256}`.
  Key `K = SHA-256(canonical {input_sha256, image_id, bundle_sha256, cache_format: 1})`; `analysis_id =
  SHA-256(canonical {key: K, artifact_sha256})`. Receipt `{schema: "reverseai.prepare/1", input: {sha256, size},
  analysis_id, state: created|reused, runtime: {image, platform, bundle_sha256}, cache_format: 1, artifact_size,
  elapsed_seconds}`; no cache path in any output. Prepare profile: 900 s host wall (840 s headless, 720 s
  auto-analysis), JVM heap 1 GiB, 2 GiB memory and swap, 2 CPUs, 256 PIDs, 512 MiB noexec tmpfs; controller
  deadline 1020 s including a 30 s lock wait. Queries keep their current profile (240 s, 262,144-byte replies,
  4,096-byte observations).
- **Store.** Private per user: macOS `~/Library/Caches/ReverseAI/ghidra/v1`, Linux `$XDG_CACHE_HOME/reverseai/ghidra/v1`
  when absolute and safe, else `~/.cache/reverseai/ghidra/v1`; Windows unsupported in 0.8.0. Directories 0700, files
  0600, owned by the user, link count 1, descriptor-relative no-follow access, nothing repaired or chmod-ed. Entry =
  `<K>.tar` + `<K>.json` (<= 8 KiB). At most 32 entries and 2 GiB including in-progress bytes; least-recently-used
  eviction, ties by K. One OS lock serialises cold prepares (a second waits <= 30 s, then "Ghidra cache busy; retry
  prepare."); a short index lock guards publication and eviction; hits never wait for prepare. Publish = fsync body
  and manifest, atomic rename, index last, fsync directory. A lookup re-hashes the whole body. `doctor` reports
  `ghidra_cache {state: absent|unsafe|ready|unsupported, entries, bytes, max_entries, max_bytes, artifact_max_bytes}`
  read-only.
- **Restore.** A cached call stages `input`, `project.tar` and a <= 4,096-byte host-built `cache.json` (exactly the manifest
  keys `{format: 1, input_sha256, image_id, bundle_sha256, size, artifact_sha256}`; no analysis_id or store data) in the same
  disposable read-only `/snapshot` (no new mount or flag). The worker re-hashes and strictly unpacks into fresh tmpfs:
  USTAR only, valid checksums and octal sizes, <= 4,096 headers, <= 64 MiB tar, <= 128 MiB unpacked, depth <= 16, names
  relative ASCII <= 240 bytes with components `[A-Za-z0-9_.~+-]{1,64}` (not `.` or `..`), only `cache/project/...` and
  `cache/tables/...`, regular files and directories only; no links, devices, pax/GNU, sparse or base-256 fields,
  duplicates or case collisions; two zero end blocks; files written exclusively, no-follow, 0600/0700. It opens the
  project with `-process input -noanalysis -readOnly`, binds it to the staged input, image and bundle, and never
  writes back. Tables `cache/tables/{functions,calls,references,strings}.{jsonl,idx}` and `meta.json` hold bounded
  rows (<= 4,096 bytes each, uint64 offsets checked before every seek); program pages are served from them without a
  JVM. Caps fixed at prepare: 65,536 functions, 262,144 calls, 262,144 references, 65,536 strings, 8,388,608
  instruction visits overall, 1,000,000 per function; exceeding any cap fails prepare (never a clipped total).
- **Queries.** Existing queries are unchanged without a prepared file; once a file is prepared, its existing Ghidra
  queries are answered from the prepared analysis (same wire shapes, still derived). New:
  `procedure_pseudo_code` gains `mode=preview|paged` (default preview; preview refuses a nonzero `text_start`) and
  `text_start` 0..1,048,576; `export_function(select, entry, name, part=info|pseudocode|assembly|callees|callers|
  references|strings, start 0..1,048,575, limit 1..128 default 32, text_start, max_chars 64..2048 default 1024)` pages
  one part; `export_program(part=functions|calls|references|strings, start, limit)` has no selector. Arguments unused
  by a part must keep their defaults. Paged pseudocode and both exports require a prepared file; a miss returns
  "Prepared Ghidra analysis is missing or invalid; run reverseai prepare FILE --with-ghidra." Program pages decompile
  nothing; function pages decompile at most the selected function. Exports cover the instructions Ghidra places in a
  function's body at a unique offset of the original file; others are not listed.
- **Fixed failure lines.** `prepare` prints exactly one of: "reverseai: analysis failed: Ghidra preparation failed or
  exceeded its limits", "reverseai: analysis failed: Prepared Ghidra analysis is missing or invalid; run reverseai
  prepare FILE --with-ghidra.", "reverseai: analysis failed: Ghidra cache busy; retry prepare.", "reverseai: analysis
  failed: Private Ghidra cache is unsafe or unavailable."; queries print the same three cache messages after the
  prefix "reverseai: query refused: ". Unknown cache error text is replaced by the unsafe line and never echoed; input
  refusals keep "reverseai: input refused: " with the error class only. A timeout, the 64 MiB artifact limit and a
  row cap all fail prepare with the preparation line; nothing is published.
- **Capacity.** The 64 MiB artifact holds the Ghidra database and the export tables together, so it binds before the
  row caps on real programs: a program whose prepared analysis exceeds it cannot be prepared. A function whose raw
  name exceeds about 3,900 characters also makes prepare fail (rows are at most 4,096 bytes).
- **Wire shapes (worker/1).** Every reply starts with a derived metadata value
  `{kind: "export_page", scope: function|program, part, entry: uint64|null, status: ok|not_found|decompile_failed,
  start, total, count, next_start: int|null}` anchored at the original `Location(0, min(64, size))`; `start =
  min(requested, total)`, rows contiguous, `next_start = start + count` while below total, else null; a non-ok page
  has zero counts. At most 129 observations per reply (metadata + 128 rows). Rows, each with its `kind`:
  - `{kind: "function_export", index, name, entry, size, signature|null, signature_truncated, library_hint|null}`
    at the function's anchor (the existing first-bytes rules); name and hint <= 128, signature <= 512 printable
    characters; `library_hint` is always null in 0.8.0;
  - `{kind: "instruction_export", index, from, from_size, at, length, text}` at the instruction bytes (`length`
    1..16, text <= 64 printable characters);
  - `{kind: "call_export", index, from, from_size, at, to, to_name}` at the call instruction bytes;
  - `{kind: "reference_export", index, from, from_size, at, to, type, to_name}` at the referencing instruction bytes,
    `type` from the existing `refs` enumeration;
  - `{kind: "string_export", index, from, from_size, at, instruction_length, address, encoding, text, truncated}` at
    the string bytes, with the instruction `[at, at + instruction_length)` mapped and cited separately, one row per
    `(from, at, address, encoding)` and the existing decoding rules; after admission the host adds its own
    `{kind: "string_reference_anchor", index, from, from_size, at, address, instruction_length}` at the instruction
    bytes, so the finding cites both (the worker's 129-observation cap is unchanged);
  - `{kind: "function_info", name, entry, size, matches, signature, signature_truncated, library_hint, totals:
    {assembly, callees, callers, references, strings}, pseudocode_status: "not_requested"}` at the function's anchor;
  - `{kind: "pseudocode_page", entry, size, text_sha256, start, total, text, next_start, status}` at the function's
    anchor (`size` lets the host re-derive that anchor).
  A pseudocode reply counts characters in its metadata too (`count` = length of `text`, equal start/total/next_start).
  The info reply has `start` 0, `total` = `count` = 1, `next_start` null and `entry` = the target. A non-ok reply is
  the metadata alone with zero counts and `next_start` null. Host-added citations are not counted. `signature_truncated`
  is false when `signature` is null.
  `(from, from_size)` is the containing function, so no row depends on an earlier page. Pseudocode units are Unicode
  scalars after `printable_text` normalization, never split; `total` is the complete normalized text (<= 1,048,576
  scalars, above that a fixed failure; the old 65,536-unit Java cut does not apply to paged modes); a page is the
  longest prefix fitting both `max_chars` and the 4,096-byte value. No row that is too large is silently dropped: a
  page that leaves rows remaining with `count` 0 is an error. Every instruction anchor maps uniquely from original
  executable bytes and lies inside its `(from, from_size)` span. Names, spans, targets, relationships and text stay
  derived.
- **Host admission and reports.** Exact field sets, strict types, bounds, order, duplicates, binding, totals and
  progress are checked before any row is admitted; the host then adds its own `analysis_id` to every new
  observation (81 bytes reserved), never one from the worker or the client. New claims `code.export_page`,
  `code.export_functions`, `code.export_calls`, `code.export_references`, `code.export_strings`,
  `code.export_instructions`, `code.pseudocode_page` are derived, at most 64 citations per finding. Reports show
  `rows a..b of N` or `characters a..b of N`, the next cursor, analysis_id and "derived"; all sample text is inert.
- **MCP compact view.** Analyse and query tools gain an MCP-only `view=compact|full` (default compact, removed before
  CLI validation): the same reviewed analysis without evidence bodies or duplicate values, structured <= 64 KiB, an
  explicit omission note when rows do not fit ("reduce limit or max_chars, or use view=full"). The text content is the
  untrusted-data notice followed by that same compact JSON, so a client that passes only text to its model receives
  every value; in the text every non-ASCII character is escaped (`\uXXXX`), so invisible, bidi or tag characters from a
  sample never reach it raw (decision `r1-compact-text-ascii`).
- **MCP prepare.** `prepare_file` runs the fixed argv `prepare FILE --with-ghidra --json` and writes no report files. The
  bounded captured stdout (<= 8,192 bytes) must be exactly one strict `reverseai.prepare/1` receipt with the contract's
  keys and no path; it is returned as `structuredContent` and as text after the notice. Failures return only the fixed
  failure lines above. Because it writes the private cache and may evict entries, its annotations are
  `readOnlyHint: false`, `destructiveHint: false`, `idempotentHint: true`, `openWorldHint: false`.
- **Proof.** Unit and hostile tests (archive grammar, store races and crashes, lying workers, cursor and Unicode
  edges, compact/full equality). Native: the revision route on Docker, prepare once per ELF/PE/Mach-O
  fixture and cached answers equal to fresh ones, restore negatives inside the container, flood +1 controls, and one
  scale receipt on a code-built (never executed) image with 10,000 minimal functions (no calls, references or
  strings) recording counts, timings and sizes; a cap or timeout is reported as a limit, not as success. That receipt
  proves paging at 10,000 functions, not that a real program of that size fits the 64 MiB artifact.

## Known-answer fixtures

Each lane writes a deterministic generator for its own synthetic fixtures under
`tests/` and asserts the exact expected evidence and findings. Fixtures are built
from declared values in code; no binary fixture files are committed and no real
malware or third-party binaries are used.

## Proof command

```sh
python3 -B -m unittest discover -s tests -t . -v
```

Run from the repository root with Python 3.12 or later and the standard library only.
