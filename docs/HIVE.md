# The hive: an AI analyst team on top of ReverseAI

The hive is an optional team of AI agents that analyses a native program with ReverseAI and
rebuilds it as C or C++ source. A **queen** splits the work, a **hive of bees** works in parallel, and
an **independent council** plus a deterministic **evidence checker** decide what is accepted.
The ReverseAI engine itself stays model-free: the hive is a separate layer in `hive/` that
talks to the engine only through its MCP server and command line.

Status: experimental. This guide describes the integrated 0.9.0 hive; it needs prepared Ghidra
exports (`reverseai prepare`).
The default path uses your Claude Code subscription, or your Codex login for Codex bees.
An explicitly configured self-hosted server is an alternative (see [Self-hosted models](#self-hosted-models-experimental));
the agent CLIs and the queen's checks still apply.

## Roles

| Role | Who | Does | Never does |
| --- | --- | --- | --- |
| Queen | Python code (`hive/queen.py`) | Exports the program map, freezes the plan, schedules bees, compiles and links, runs the checks, computes the verdict | Write code, review, vote, or override a check |
| Planner | One bee per bounded group, plus interface reconciliation when needed | Proposes modules, evidence-backed skips and declarations; the queen validates and freezes the interface | Rebuild or judge |
| Builder | One bee per module, in parallel | Rebuilds its module's functions as C from the evidence; writes claims citing finding IDs | Edit the contract or another module |
| Councillor | Three per module, one lens each | Tries to refute the module against the original's assembly: control flow and arithmetic, input/output, data and memory | Write anything; see the author's notes |
| Tester | One bee, only with `--run-original` | Designs conformance cases from strings and logic | Run anything |

## How a run works

1. **Survey.** The queen prepares the file once (Ghidra analyses it in its locked container and
   keeps the project in the private cache), then exports every function, call and string into
   `survey/map.json`.
2. **Pre-flight.** Before any bee is spent, the queen checks whether the program is packed or
   obfuscated (see [Pre-flight](#pre-flight)). A packed program stops the run with the reasons,
   unless you start it with `--allow-packed`. Then the queen chooses the language: C, or C++ when
   the map shows C++ (see [Languages](#languages)).
3. **Plan.** Phase A partitions the map deterministically. In phase B, planners propose modules
   and declarations from bounded groups; interface tasks reconcile conflicting declarations. The queen
   checks exact function coverage and evidence-backed skips, splits oversized modules, checks that
   the assembled contract compiles on its own, and freezes it read-only (see [Group planning](#group-planning-phases-a-and-b)).
   Configured self-hosted targets must pass their [capability checks](#automatic-capability-checks) first.
4. **Build.** Builders work in parallel, one folder each. Every module is compiled alone from a
   clean stage containing snapshots of its source and the frozen contract, with
   `-Wall -Wextra -fwrapv -fno-strict-aliasing`. This requires Clang with a closed virtual
   filesystem (`-ivfsoverlay`, no fallthrough): generated includes and include-existence queries
   can see only that stage and the compiler's system header directories. Other compilers are
   refused. Before the planner starts, a native positive/negative probe checks the selected
   compiler once: the outside-file query must fail and nonempty inline assembly must be disabled
   in the selected C or C++ mode. The compiler receives `-fno-gnu-inline-asm` and `-fno-asm-blocks`;
   the preprocessor VFS alone does not confine the assembler. Symlinked or hard-linked sources
   and contracts are refused. The queen scans the whole expanded output for file-loading
   constructs, without trusting source line markers, then compiles the original source in the
   same confinement so macro context is kept. Generated source-location overrides are refused.
   Each compiler command has a 60-second deadline and captured-output limits of 16 MiB stdout
   and 256 KiB stderr; crossing a limit stops the command (the owned process group on POSIX).
   Compiler messages go back to the builder, at most three times. A builder must report every
   assigned function rebuilt and status `done`; repair reports update the entries they touch
   while preserving the other functions' reported state.
5. **Council.** Three councillors, each with a fresh context, review a renamed copy of the module
   without the builder's notes. Only behavioural differences with evidence (an address in the
   original or a finding ID) count. The builder must fix them or disprove them with evidence; a
   fresh council reviews again. A module still refuted after two rounds is **disputed**, never
   silently accepted. Every configured seat must return a valid verdict; a missing or failed
   seat leaves the module **incomplete**, including a refused Codex seat in a mixed council.
6. **Link.** The queen links all modules and routes undefined or duplicate symbols to the module
   that owns them, at most three rounds. Each repaired module returns to council on its new
   source; a missing or refuting verdict prevents acceptance.
7. **Evidence check.** `tools/hive_check.py` re-runs every question that a claim cites, through
   ReverseAI itself, and keeps a claim only if each cited finding ID comes back with a
   `supported` or `derived` verdict. Finding IDs are bound to the file's hash and the result's
   content, so a made-up ID, an ID from another file or a stale ID is rejected. The queen binds
   every citation to the target file and requires the checker's input hash to match the survey.
   These checks run after the last repair, including behaviour repairs.
8. **Behaviour (optional).** With `--run-original`, the tester writes cases; the queen runs the
   original and the rebuild on each case in a fresh folder and compares the exit code, stdout and
   every file created (by hash), and stderr with the program's path masked (its first 2,000
   characters). At least **two nonempty cases**, with unique IDs after filename
   normalisation, must complete; empty suites, colliding IDs and timeouts cannot prove behaviour.
   Differences go to one fixer bee, at most two rounds; changed modules return to council.
   A failed relink removes the older binary, invalidates the link result and stops the behaviour
   proof; the queen never falls back to a binary built from earlier objects.
9. **Verdict.** Code computes it: **accepted** only if the program links, every module is
   accepted by its council, no function is a stub, the checker rejected no claim and every
   conformance case is identical. Without `--run-original` the best verdict is
   **accepted without behaviour proof**.

With `--run-original --fuzz N`, add up to 500 deterministic mutants after the ordinary behaviour
checks and repairs (`N` defaults to 0, off). They change only case-file bytes, including stdin files,
using bit flips, insertion, deletion, truncation, boundary bytes and splicing between cases; arguments
stay unchanged and each file stays within the 64 KiB case limit. The input SHA-256 and source case ID
seed each sequence. Mutants use the final rebuilt binary and extend the conformance totals; differences
are reported without another repair round. No-op and duplicate inputs are discarded with bounded
attempts; cases whose files the executor skips add no mutants. Complete mutant pairs are compared
even if others time out or are missing: the report keeps the plain result, differing cases and a
separate `incomplete` list. Any incomplete mutant prevents acceptance. `tests/fuzz.json` records the
seed and bounded base64 inputs of both differing and incomplete mutants for reproduction, and is
cleared at the start of each conformance attempt.

## Group planning: phases A and B

Phase A is implemented in `hive/partition.py`: it splits the map deterministically into
bounded groups while keeping every function exactly once. Functions that call each other,
share strings or touch the same data tend to stay together, but count and byte caps take
precedence. Calls across groups remain explicit. A singleton that is still too large keeps
an inline sample plus complete overflow side files with hashes and counts; unattached rows
are retained too. The global summary declares its omissions and cannot prove coverage.

The queen uses phase B in `hive/planning.py` to propose a plan from those groups. Each planner receives
only its own `map.json`, a bounded `summary.json` and an `interfaces.json` index. Large inputs
are paged inside that group's readable folder; every page has a count and SHA-256, and no
individual page exceeds `max_prompt_bytes`. The same limit bounds the combined task and
initial map/summary/index bytes. It does not measure the agent CLI's system prompt, tool
definitions or total token context. An indivisible record above the cap stops planning
with `planning_payload_too_large`, rather than being silently truncated.

Every group function must be assigned or skipped with a reason and evidence. The queen's
planning code checks exact coverage, shared declarations, dependencies and global owners.
Conflicting declarations get a bounded interface task that can select only an existing
variant. Unknown layouts or unresolved conflicts stop the plan; opaque types cross module
interfaces only through pointers/references. Final modules use `m01`, `m02`, etc., separately
from partition groups `g0001`, `g0002`, etc. A global definition belongs to the module that
contains its `owner_entry`, including after a large module is split.

The output is `plan/manifest.json`, `plan/interfaces.json` and `plan/contract.h` (or `.hpp`).
The manifest binds input, map, partition, planning policy, declarations and assignments by
hash. `validate_bundle` rechecks those bindings without a planner. Partial verified proposals
and interface decisions can be resumed from `plan/progress.json`; prior failed attempts
remain in the queen's history. The queen compiles and freezes the contract before builders
start. Planning alone does not accept a module or prove that the rebuild behaves like the original.

If a group fails or is refused before the plan is frozen, resume validates the saved progress
and retains completed groups and interface decisions. Only unfinished work is planned again;
[refusal recovery](#explicit-local-recovery-after-a-refusal) requires explicit local consent.
Once frozen, the verified plan is reused without another planner. The integrated tests use
simulated agent processes and servers; they do not demonstrate a complete curl reconstruction
or measure a whole run on a local model.

## Who has the final word

- A failed check cannot be overruled by any agent. The council can only add a veto.
- The queen is code. She cannot vote, and her plan is reviewed only through its results.
- A claim without a resolvable citation is dropped, whatever it says.

## Speed

- **One MCP server per bee.** ReverseAI's MCP server answers one request at a time, so the hive
  gives every bee its own server process: Ghidra questions from different bees run in parallel
  containers instead of queueing.
- **Analyse once.** Preparation runs Ghidra's auto-analysis once; later questions load the
  cached project.
- **Barriers only where needed.** Modules run as independent pipelines (build, compile, council,
  repair); the queen waits only after the plan, before linking and before the final checks.
- `--bees N` sets how many bees work at once (default 4). Each contained Ghidra question uses up
  to 2 CPUs and 2 GiB, so size N to your Docker VM. `--max-bees` caps the whole run.

## Pre-flight

Rebuilding a packed program from static evidence only rebuilds its unpacking stub, and
obfuscation (flattened control flow, virtual machines) defeats decompilation, so the queen checks
first, deterministically, in `hive/preflight.py`:

- packer section names (UPX, MPRESS, ASPack, PECompact, Themida, VMProtect, Enigma, NsPack, ...)
  and packer marker strings in the file;
- byte entropy of each executable segment and of the whole file, computed from the approved file
  over the segment ranges that ReverseAI verifies (compressed or encrypted bytes are close to
  8 bits per byte);
- imports that only load more code (`LoadLibrary`/`GetProcAddress`, `dlopen`/`dlsym`, ...);
- very few functions or strings for the code size, or one function holding most of the code.

Any strong signal gives **packed** (the run stops); two weak signals give **suspected** (the run
warns and continues). The result is in `survey/preflight/preflight.json` and in the report.
Nothing is unpacked or executed: unpacking stays your decision. A clean verdict does not prove
that a program is neither packed nor obfuscated.

## Languages

`--language auto` (the default) rebuilds in C, or in C++ when the map shows at least two signs of
C++: mangled names (`_Z...`), qualified names (`Class::method`), C++ runtime imports
(`__cxa_throw`, `__gxx_personality_v0`, ...) or `operator new`/`delete`. `--language c` and
`--language cpp` force a choice. C++ builders rebuild classes with the layout the assembly shows,
pinned with `static_assert`, and virtual methods in vtable order; the contract becomes
`contract.hpp` and the queen compiles with `c++ -std=gnu++17`. Other languages (Java for Android
apps, ports to Rust, Go or Python) are not handled yet.

## Bee models

`--bee-policy claude` (the default) runs every bee on Claude Code. `--bee-policy codex` runs every
bee on the Codex CLI (`codex exec`), and `--bee-policy mixed` alternates: odd-numbered modules are
built by Claude and even ones by Codex, repairs stay with the module's builder, and each council
gives two of its three seats to the other client. The planner, the tester and the behaviour
fixer stay on Claude. These flags select agent clients; each user chooses the models behind them.
Every council seat still needs a fresh context independent of the author. Running Claude and
Codex against the same local model does not establish model diversity.

Each attempt records `provenance.client`, the requested model, any observed model/digest, a
context ID and `origin` (`primary` or `fallback`). `provenance.server_kind` distinguishes
`cloud` (the default provider path), `local` (a configured loopback server) and `remote` (a
configured non-loopback server). These describe routing, not where a server ultimately performs
inference. Unknown observed identities stay null. The per-module `model_diversity` result is
true/false only when all relevant author/reviewer identities are observed; otherwise it is null.
Client names and requested model aliases alone do not prove diversity.

Codex bees are less fenced than Claude bees, and this was measured on 2026-10-31 with
codex-cli 0.165.0 on macOS: writes outside the bee's folder were denied, but a Codex bee could read
files elsewhere on the disk, run programs (including the input), and reach the network from inside
`codex exec` in both its read-only and workspace-write modes, although `codex sandbox` alone blocks
it. The hive therefore probes the Codex sandbox before its first Codex bee and refuses Codex bees
while the probe reaches the network. `--codex-allow-network` skips that refusal for operators who
accept the risk on software they would run anyway; never use Codex bees on malware.

## Configure your own model

Hive is independent of a particular model. Choose a model and server that support all three:

- **Tools:** a native tool call, its result, and a following answer through the selected agent CLI.
- **Structured output:** a JSON instance conforming to Hive's schema through Claude Code's
  `--json-schema` or Codex's `--output-schema` path. Returning the schema itself, a wrapper or
  prose containing JSON is insufficient.
- **Active context:** at least `--required-context` tokens (default **65536**). Allow space for
  the CLI's system prompt, tools, evidence, history and output. The planning byte cap is separate
  from token context, and this minimum does not guarantee completion of a particular program.

Install/configure the agent CLIs and prepare your chosen server and model before invoking Hive.
Configured fallback clients must also be installed before startup. Hive's routing flags do not
install a server, download a model or start a server process.

### Self-hosted models (experimental)

`--model-server URL` selects a primary server. Claude bees need Anthropic Messages support and
`--model NAME`; Codex bees need OpenAI Responses support and `--codex-model NAME`. Mixed policy
needs both names and both API paths. A Chat Completions endpoint alone is insufficient. Pass the
server root URL without `/v1`: Claude uses that base; Codex appends `/v1` for Responses.

The primary must be on loopback unless you add `--model-server-remote`, explicitly consenting to
send prompts and program evidence to another machine. This consent does not authorize a remote
fallback. Loopback addresses also do not prove that a server performs inference locally.

The bees retain their CLI, role tools and checks: Claude uses folder-scoped writes and `dontAsk`;
Codex keeps its sandbox and isolation probe. Self-hosted bees receive an allowlisted environment
(system basics, locale and certificate paths) and routing, with a placeholder token for Claude.
Subscription logins, cloud credentials and API/repository tokens are excluded.

### Server settings

Set these on the server process or its service, then verify the **active** configuration. Select
parallelism against available memory and measure latency before increasing Hive's `--bees`.
A longer context and more concurrent requests consume more memory; no machine-size or throughput
estimate is implied by these examples.

| Setting | Ollama | vLLM |
| --- | --- | --- |
| Listen locally | `OLLAMA_HOST=127.0.0.1:11434` | `--host 127.0.0.1 --port 8000` |
| Context | `OLLAMA_CONTEXT_LENGTH=65536`; inspect `ollama ps` and `/api/ps` for the chosen loaded model | `--max-model-len 65536` bounds prompt plus output; the model and available memory must support it |
| Parallelism | Start with `OLLAMA_NUM_PARALLEL=1`; coordinate it with Hive's `--bees` | `--max-num-seqs` bounds sequences per iteration; start small and coordinate it with Hive's `--bees` |
| Tools | Choose a model/API path supporting tool calls and tool results | Configure `--enable-auto-tool-choice`, a `--tool-call-parser` for the chosen model and a tool-compatible chat template; set `--chat-template` if needed |
| Structured output | Schema support must work through the selected Messages/Responses client, beyond native `/api/chat`'s `format` option | Structured outputs default to backend `auto`; `--structured-outputs-config.backend` selects it explicitly. Verify the required API/client path, not just Chat Completions |

For a manually managed Ollama server, an example in a separate terminal is:

```sh
OLLAMA_HOST=127.0.0.1:11434 OLLAMA_CONTEXT_LENGTH=65536 OLLAMA_NUM_PARALLEL=1 ollama serve
```

If Ollama already runs as an app or service, configure and restart that instance instead. Use
an already installed model name in the Hive command, from another terminal:

```sh
python3 -m hive run --inputs /path/to/approved-inputs --file program --out new-hive-run \
  --model-server http://127.0.0.1:11434 --model your-installed-model \
  --required-context 65536 --max-tool-rejections 8 --bees 1
```

Ollama settings and diagnostics: [context length](https://docs.ollama.com/context-length),
[server configuration and concurrency](https://docs.ollama.com/faq),
[structured outputs](https://docs.ollama.com/capabilities/structured-outputs),
[loaded-model metadata](https://docs.ollama.com/api/ps).
vLLM settings: [serve options](https://docs.vllm.ai/en/latest/cli/serve/),
[tool calling](https://docs.vllm.ai/en/latest/features/tool_calling/),
[structured outputs](https://docs.vllm.ai/en/latest/features/structured_outputs/).
Use the documentation and help matching your installed server version.

### Active context metadata

Hive reads the configured model's serving context from Ollama-compatible `/api/ps`
(`context_length`). When that API is absent or unrecognized, it tries vLLM-compatible
`/v1/models` (`max_model_len`). The model name or ID must match the configured name
exactly, and the reported length must be a positive integer. Recognized metadata with
a missing model or invalid length stays unknown; Hive does not borrow another model's
limit or replace a loaded context with a larger limit from another API.

If no recognized source provides usable metadata, `context` is `unsupported`:
**“Active context is not verifiable on this server”**, or *non verificabile su questo
server*. This differs from a measured context below `--required-context`, which is an
`error`. Connection, authentication and other metadata-query failures are also errors.
Expose the chosen model's serving metadata and verify the server's active settings.
The Python `selfhost.check_model` API can accept a `context_query(server, model)` reader
for another server API; the CLI has no flag to inject one.

### Automatic capability checks

Before planning or workers, Hive checks every configured self-hosted primary and authorized
fallback target, once per client, including fallback targets not yet activated. The default
cloud path, with no `--model-server`, keeps its existing behavior without these capability probes.
A configured local fallback is still checked when the primary uses cloud.

One short process through the actual selected CLI reads a random nonce with a tool,
calls ReverseAI's real MCP `export_function` on a function from the input survey, and
returns the nonce under a small output schema. It uses the same ReverseAI MCP server,
input directory and tool configuration as the bees. `mcp_tool` is `ok` only when native
CLI events show that the server accepted the call with arguments matching that surveyed
file and function; the model's story or final JSON cannot establish acceptance.
A surveyed function, configured MCP tools and an accepted native result are required.

Read, MCP and structured output share that one capability process, counted as
`network_probe` in the start budget. Codex may first need a separate isolation probe,
also counted. Hive separately compares the server's declared **active** context with
`--required-context`. These checks do not measure effective context retention, peak
memory, inference speed or whether a long reconstruction will succeed.

`.hive/model-checks.json` records `tool_roundtrip`, `mcp_tool`, `structured_output` and
`context`, each with status `ok`, `unsupported` or `error`, a message and a configuration
suggestion. All must be `ok`:

| Result | Meaning and action |
| --- | --- |
| `ok` | This small capability check passed; normal compiler, council, evidence and behavior checks remain required. |
| `unsupported` | A capability was not demonstrated. For `mcp_tool`, provide a surveyed function, the configured MCP tools and accepted native tool evidence. For `context`, *non verificabile su questo server* means serving metadata is unknown, not a measured small context; expose valid metadata for the exact configured model. |
| `error` | The probe or metadata query failed, or the declared context is below the required minimum. Read the message: configure tools/schema support, increase the server's active context, or fix the metadata connection as appropriate. |

An `unsupported` or `error` stops the run as `model_capability`. There is no CLI flag to skip
these checks for configured servers. After correcting the server, resume repeats them and
retains the already consumed budget. Raising `--required-context` raises the requirement; it
does not enlarge the server's context. Passing the checks is a minimum compatibility result.
It does not guarantee a successful reconstruction or measure curl performance.

### Read failed attempts

The attempt's `outcome` and `code`, saved in the report/state, distinguish causes:

| Outcome or code | Meaning | Activates local fallback? |
| --- | --- | --- |
| `provider_refusal` | The provider declined this logical call. | Only with explicit matching consent, for one additional local attempt. |
| `invalid_schema` | No completed schema-conforming response; this includes returning a schema instead of its JSON instance. | No; check schema/API/client compatibility. |
| `tool_schema_failure` | The agent was stopped after consecutive MCP argument-schema rejections reached `--max-tool-rejections`. This is not a provider refusal. | No; check tool calling, the tool arguments and active context. |
| `context_limit` | The prompt exceeded the available context. | No; fix active context or size the work appropriately. |
| `timeout`, `rate_limit`, `failure` | Process deadline, provider quota/rate limit, or another failure. | No; diagnose the reported cause. |
| `failure` with `network_isolation` | The Codex isolation probe failed. A cached negative probe starts no process and creates no new attempt ID. | No; `--resume-refused` does not bypass it. |
| `not_started` | No agent process was started, for example because the persisted budget or a run stop denied it. | No; resolve the stop/budget first. |

These outcomes differ from the capability report's per-check statuses. For example, a server
whose context cannot be verified is not a provider refusal. Diagnostics and observed rejected
MCP arguments (`tool_rejections`, null when no tool trace is available) help diagnose compatibility;
they do not establish the correctness of generated code.

### Stop repeated MCP argument errors

`--max-tool-rejections N` sets a positive consecutive-error limit, default **8**. The
agent process is interrupted when the native MCP results reach that schema-rejection
streak, rather than waiting for the ordinary process timeout. An MCP result without an
argument-schema error resets the streak; prose and non-MCP tools do not change it.
The outcome is `tool_schema_failure`, with `refused=false` and `output=null`. It does
not activate fallback or contribute to the provider-refusal stop limit.

`REPORT.md` shows the tool name, consecutive streak and total observed rejections;
the result retains `tool_name`, `consecutive_tool_rejections` and `tool_rejections`.
Check the selected model/API's tool-calling support and the server's active context.
Choose a model/API with more reliable tool calling or configure a larger supported
active context when appropriate. Preserve the failed workspace; after
correcting the configuration, a fresh `--out` starts a new run. `--resume-refused` is
for provider refusals and does not recover a tool-schema stop through local fallback.

When the CLI exposes no native MCP results, the report says the rejection monitor is
unavailable and `tool_rejections` is `null`. The consecutive-error monitor cannot
operate on hidden results; `null` is not an observed zero. A self-hosted startup check
also requires native accepted MCP evidence before `mcp_tool` can pass.

### Explicit local recovery after a refusal

Without fallback configuration, Hive records refusals without switching servers. A refused planner
stops planning; a refused worker leaves that module refused. To authorize a local alternative:

```sh
python3 -m hive run --inputs /path/to/approved-inputs --file program --out new-hive-run \
  --fallback-model-server http://127.0.0.1:11434 \
  --fallback-model your-installed-model --fallback-scope role --fallback-role planner
```

`--fallback-model-server` and an explicit `--fallback-scope` provide consent. Claude needs
`--fallback-model`; Codex needs `--fallback-codex-model`; mixed policy needs both. The server
must be loopback and its URL must be the root without `/v1`. The chosen fallback must differ
from the primary client/server/model destination; identical destinations provide no alternative.

| Scope | Selection and activation |
| --- | --- |
| `run` | After the first refusal, all newly starting calls use the local target. |
| `role` | Repeat `--fallback-role` for planner, worker, repair, councillor or tester. Each selected role switches after its own first refusal. |
| `bee` | Repeat `--fallback-bee` with exact logical names, such as `planner-g0001` or `m01-build`; each selected name switches after its refusal. Wildcards are not accepted. |

Only `provider_refusal` activates the switch, for one additional local attempt for that logical
call. Timeouts, rate limits, invalid schemas, context limits and isolation failures do not.
Already active calls finish on their original destination. Hive does not rewrite the prompt or
switch back to cloud after a local failure. Each attempt keeps its own files; the refused
attempt's partial writes are not used as the local retry's starting point. All attempts and
historical refusals remain visible; a successful replacement resolves only that logical work.
Independent council contexts and all acceptance checks remain required.

### Resume a frozen plan and retain the budget

Run the same command with the same `--out` to resume. A verified frozen plan and contract are
loaded without another planner call. Before freezing, validated partial group proposals and
interface decisions are retained. Accepted modules are kept only while their input, assignment,
source, contract, compiled object, compiler policy and review bindings still match. Changed
inputs/maps/planning policy or damaged plan artifacts stop resume; use a new output directory
to make a different plan. Old workspaces without authoritative 0.9.0 state are not silently
accepted as verified resumptions. Do not replace the frozen contract in an existing run.

After a refusal stop, add `--resume-refused` and explicitly configure the local fallback matching
the work to recover. For example, repeat the role-scoped fallback command above with
`--resume-refused` appended. This preserves refusal history and consumed starts. Keep the explicit
local configuration on subsequent resumptions: omitting it after local routing was activated
stops resume rather than restoring cloud routing. Failed isolation probes are not bypassed.

`--max-bees` caps physical agent CLI starts: planners, builders, councillors, repairs, local
alternatives and capability/isolation probes. It does not cap tokens, money or HTTP requests
inside an agent CLI. A new run defaults to **400**; a resume keeps the saved cap when the flag
is absent. Starts interrupted by a crash remain consumed. A budget stop requires an explicit,
sufficiently larger `--max-bees`; rerunning the command does not reset the counter.

Before capability checks, planning and module work, `hive.log` reports a call forecast: probes,
group planners, then
unfinished module builds/reviews, the optional tester and pending probes. Group count is not
module count; interface reconciliation and repairs can add calls. If the minimum exceeds the
remaining allowance, the phase does not start and completed work is retained. The recommended
total adds a **heuristic** reserve of `max(8, ceil(25% of remaining_min))` to spent calls plus
the minimum. That margin is not a completion or time guarantee. Size curl from its plan and
measure the chosen server/model; multiplying lz4's elapsed time is not a reliable forecast.

Keep `.hive/run.json`, `.hive/attempts.jsonl`, the frozen plan and the workspace together.
They retain routing activation, consumed starts, refusal history and provenance. Each bee result
carries `provenance.attempt_id`; `provenance.prior_attempt_ids` preserves earlier attempts of the
same call. If no process started, an attempt ID can be null; Hive does not invent one.
The plan's `planner_attempts` retains those IDs rather than deriving them from model or bee names.

## Safety

- Bees read text that comes from untrusted binaries. No Claude bee has a shell, the web or the
  ability to start other agents (Codex bees differ: see [Bee models](#bee-models)). Each bee runs with Claude Code's `dontAsk` permission mode and file rules
  limited to its own folder (`Read(./**)`, `Write(./**)`, `Edit(./**)`), so reads and writes
  anywhere else are denied; councillors can only read. ReverseAI's MCP tools are read-only and
  never execute the input.
- Each bee's MCP configuration, the frozen contract and the build stage live outside the bee's
  folder or are copied fresh by the queen, so a bee cannot change what the queen compiles or
  checks.
- The original program runs **only** with `--run-original`, in a temporary folder with a short
  timeout and a minimal environment. That is not a sandbox: use it only for software you would
  run anyway, and never for malware.
- Workspaces contain decompiled code and data from the input. Treat them as sensitive.
- Use the hive only on programs you are entitled to analyse and rebuild; see the README's
  responsible-use notice.

## Run it

From the integrated 0.9.0 checkout, with Docker running, the pinned Ghidra image present and
the selected agent CLI configured (subscription login for the default cloud path):

```sh
python3 -m hive run --inputs /path/to/approved-inputs --file program --out new-hive-run --bees 4
python3 -m hive run --inputs /path/to/approved-inputs --file program --out new-hive-run --run-original
```

Run the same command again with the same `--out` to [resume](#resume-a-frozen-plan-and-retain-the-budget).
The queen verifies the frozen plan and saved decisions outside bee folders; module `status.json`
files are informational copies. Inspect the available options with `python3 -m hive run --help`.

## Workspace

| Path | Contents |
| --- | --- |
| `survey/map.json` | Functions, calls, strings and imports exported from the prepared project |
| `plan/manifest.json`, `plan/interfaces.json`, `plan/contract.h` or `.hpp` | Verified plan bundle, declarations and assembled interface |
| `plan/groups/`, `plan/interfaces/` | Bounded planner inputs/pages and interface reconciliation work |
| `plan/progress.json`, `plan/policy.json`, `plan/partition.json` | Resumable planning work and the policy/partition bound by the manifest |
| `src/contract.h` or `.hpp` | The frozen interface, read-only |
| `.hive/run.json`, `.hive/attempts.jsonl` | Authoritative run state and attempt journal: counters, routing, refusals and provenance |
| `.hive/attempts/`, `.hive/status/` | Isolated attempt files and queen-owned module decisions |
| `.hive/model-checks.json` | Capability checks for configured self-hosted targets |
| `modules/mNN/` | One builder's folder: `BRIEF.md`, `mNN.c`, `claims.json`, `NOTES.md`, `status.json` |
| `council/` | One read-only seat per councillor and round |
| `build/` | Objects, the linked rebuild in `build/bin/` |
| `check/` | Merged claims and the checker's `verdicts.json` with every re-run report |
| `tests/` | Cases and results, only with `--run-original` |
| `REPORT.md`, `result.json`, `hive.log` | The verdict, its reasons and the timeline |

## Limits

- The bees run on Claude Code (and optionally Codex), so the provider's usage policies and safety
  classifiers apply: work on malware in particular may be refused. The hive recognises a refusal
  and records it in the log and report. Without a successful authorized replacement, a refused
  planner stops planning and a refused builder leaves its module refused. Three unresolved logical
  refusals (`refusal_limit`) stop new bees; historical refusals resolved by local recovery remain
  recorded without counting toward that threshold. Unresolved work prevents acceptance.
- C and C++ output only; Objective-C, Swift, Go and Rust programs are not handled specially.
- The pre-flight recognises common packers and strong signs of obfuscation; it does not unpack,
  and it can miss custom packers or light obfuscation.
- Rebuilt code follows Ghidra's and the agents' reading of the assembly. It is not the original
  source, and conformance cases show equal behaviour only on the cases run.
