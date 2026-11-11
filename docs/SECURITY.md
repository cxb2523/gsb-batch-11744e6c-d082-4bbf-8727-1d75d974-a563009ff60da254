# Security model

> To report a vulnerability, use GitHub's private form; see
> [Reporting a security problem privately](#reporting-a-security-problem-privately).

ReverseAI performs static analysis of an approved file. It does not execute,
import or evaluate sample code, install sample packages, run their scripts, or
resolve their dependencies. Contained tools parse and decompile bytes as data.
This reduces exposure; it does not make a vulnerable parser or container runtime
safe by definition.

## Trust boundaries

The trusted computing base includes the host controller and its Python standard
library, the gateway, host decoders, claim rules and reviewer, the checked-out or
installed code and locks, Docker and its daemon configuration, and the relevant
kernel and hypervisor. The operator controls the approved input, local images,
staging directory and report destination. Another process with the same host
account can alter these trusted components; same-account staging races are
outside the containment claim.

Sample bytes, archive names, tool replies, and analyst findings are untrusted.
Intake accepts one regular file of at most 64 MiB, rejects symlinks, reparse
points and hard-linked files, checks the opened file's identity and stable
size/timestamps, and hashes its frozen bytes. Parent directories may be links;
intake does not protect an untrusted choice of path or an adversarial parent
directory.

ELF, PE, Mach-O, APK, DEX, ZIP, ASAR, gzip/tar, JSON and lexical-string processing
also occur in the host process. Those parsers are part of the trusted controller,
not protected by the worker's container. An exploit there or a container escape
can cross the intended boundary. No model-provider connection or model-driven
analysis agent is included in the current analysis runtime.

## Report destinations

POSIX reports are created exclusively relative to a bound, empty directory
handle, without following a link or replacing an existing report. On Windows,
each `--out` must name a directory that does not exist. CPython 3.12.4 or later
creates it with a private ACL; older Windows Pythons refuse output.

The Windows binding is designed to prevent the output directory from being
renamed or replaced: it opens the new directory as a handle without delete
sharing, checks that it is empty rather than a reparse point, and keeps it bound
until writing finishes. Each report is created exclusively relative to that
handle with `NtCreateFile`, without reopening the directory by path or following
a report-name reparse point. Existing output directories, junctions and symlinks
are refused by design. These Windows properties await confirmation by the first
owner-started Windows proof receipt. The operator must still choose a trusted
parent directory; these controls do not make a compromised host account safe.

## Installation and manual CI

The package and its build backend are trusted code. An editable install adds
the absolute checkout root to Python's import path and uses that checkout's
locks; anyone who can change it can change the installed program. Never install
a sample project or run its build scripts. The MIT license and preserved
third-party notices describe redistribution terms, not a security attestation.

The hosted workflow is manually dispatched by the owner, with no automatic
push, pull-request or scheduled trigger. It grants only `contents: read`, uses
checkout without persisted credentials, and pins checkout and setup-python to
full commit SHAs. It references no secrets and has no cache, artifact-upload
or deployment step. Changing a pin requires reviewing the actual upstream code;
a SHA binds a version, not its trustworthiness. Hosted runner provisioning is
separate from the offline package-install commands.

Host proof receipts identify a commit, interpreter, OS/architecture and each
check's exit status. They use code-built fixtures, never submitted samples.
On POSIX, a passing receipt requires the whole suite and installed CLI checks.
On Windows, it requires the real Windows report tests and installed CLI checks;
the separate whole-suite result is still recorded but does not gate the
Windows receipt. A passing host receipt is not a successful all-tests Windows
claim or a proof of native tool containment. A workflow definition or an
unstarted manual job is not execution evidence; consult the recorded receipt.

## Contained tools

[`contained.py`](../reverseai/contained.py) builds a fixed command for each
validated operation. Each run uses the local image's immutable SHA-256 ID with
`--pull never`, `--init`, no network, a read-only root, UID/GID `65534:65534`,
all capabilities dropped and `no-new-privileges`. The only host bind mount is
the disposable snapshot directory, read-only at `/snapshot`. There is no Docker
socket, home-directory mount, credential forwarding or caller-supplied entrypoint.
Temporary storage is private tmpfs with `noexec,nosuid,nodev`.

Resources are selected by the operation, not by sample or analyst arguments:

| Tool and operation | PIDs | Memory / memory-swap setting | CPUs | `/tmp` size | Worker wall limit |
| --- | --- | --- | --- | --- | --- |
| LIEF: `lief.headers`, `lief.sections` | 64 | 512 MiB / 512 MiB | 1 | 64 MiB | 45 s |
| YARA-X: `yarax.matches` | 64 | 512 MiB / 512 MiB | 1 | 64 MiB | 45 s |
| Ghidra: `ghidra.analyze`, `ghidra.functions`, `ghidra.function`, `ghidra.xrefs` | 256 | 2 GiB / 2 GiB | 2 | 512 MiB | 240 s |
| JADX: `jadx.method` | 256 | 2 GiB / 2 GiB | 2 | 512 MiB | 120 s |
| JavaScript parser: `jsparser.syntax` | 64 | 2 GiB / 2 GiB | 2 | 64 MiB | 120 s |

Worker stdout is capped at 262,144 bytes. Protocol, input digest, schema,
ordering, bounds and tool-specific anchors must pass host admission before
observations become evidence. A failed run attempts to kill its own named
container and remove its staging directory. A kill error does not replace the
primary failure; staging cleanup failures are reported or attached to it. The
controller does not clean up unrelated containers.

These controls constrain the container. Docker Desktop's VM and its configured
host shares remain separate trust boundaries: a container-to-VM escape may
expose whatever the VM can access. ReverseAI does not change file sharing,
restart Docker or claim a separate dedicated VM around the controller.

## Verified facts and derived interpretations

| Result | What it means |
| --- | --- |
| `supported` | The cited bytes, provenance and registered claim rule support this precise value. It is not proof of execution, intent, safety or absence of malicious behaviour. |
| `derived` | The tool's interpretation is retained with checked citations. Ghidra's functions, decompilation, calls, assembly and references; JADX's Java; and the JavaScript parser's syntax roles remain derived. A byte anchor does not prove the interpretation. |
| `unsupported` | A citation, integrity check, tool registration or claim rule failed. |
| `contradicted` | Otherwise verifiable claims or pages disagree under the applicable comparison rules. Derived or unsupported findings cannot cancel a verified fact. |

The host re-derives LIEF values and YARA-X matches from its own bytes. It checks
Ghidra anchors and referenced strings, binds JADX output to a DEX method's
host-verified instruction span, and re-reads JavaScript literals and callee names
at converted byte offsets. These checks do not make decompilation or syntax
interpretations verified source code, nor prove that a worker found every item.

The reviewer independently recomputes input and excerpt hashes, content-bound
IDs, tool registration and versions, child-artifact bytes and claim-rule results.
Citations resolve within the finding's own result. Archive members are rebuilt
in memory from the approved input, never extracted to sample-selected paths.
For gzip-stream children, the gateway and reviewer precharge each distinct
stream's bound before inflation; failed reviewer inflation remains charged and
cached. Distinct-child and stream budgets are 128 MiB each; each stream is also
limited to 100 times its compressed size, and each child to 32 MiB.

Hashes bind records to bytes; they do not authenticate an upstream publisher or
prove a complete analysis. The reviewer uses trusted host code and is not a
second sandbox or an independent implementation of every parser.

## Verification and known limits

The native verifier, [`tests/verify_m2_runtime.py`](../tests/verify_m2_runtime.py),
inspects the containment configuration and runs fixed negative controls and
known-answer fixtures. Receipts identify image, lock, verifier/executor and
fixture bindings. A passing receipt applies to that platform, image and tested
profile; it is not a general guarantee against escapes or unknown vulnerabilities.
Current native evidence is for Linux ARM64 containers on Docker Desktop on the
Mac. Host unit tests, an offline installation check and a Linux host test do not
substitute for a native containment proof on another platform.

In-process handlers have soft time budgets; they do not have the contained
workers' hard process and memory limits. Bounded parsing can still consume
resources. Lexical hints can match comments or strings and miss indirect forms.
Unsupported formats, paging and observation limits restrict coverage. See the
[contract](contract.md) for each format's limits and the
[README](../README.md) for the user-facing limitations.

Reports contain bounded sample-derived text, including strings, declarations
and decompiled code. Store them as sensitive analysis artifacts; escaping their
Markdown display does not remove confidential content. Upstream artifacts are
pinned and checked by hash, but pinning is not a vulnerability audit.

## Reporting a security problem privately

Please report suspected containment, evidence-integrity or disclosure problems
privately to the repository owner, Stefano D'Agostino, with GitHub's private
vulnerability form: the **Report a vulnerability** button on the repository's
Security tab, or directly
[this link](https://github.com/dagoSte/reverseai/security/advisories/new). Only
the owner and you can read the report. Do not open a public issue about a
vulnerability. See [GitHub's private-reporting guide](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/report-privately).
Fixes go into the latest release. No security email or response-time commitment
is published here.

Provide the affected tag or commit, Python/OS/architecture, relevant image and
lock identifiers, expected versus observed behaviour, and a minimal synthetic
reproduction when possible. Remove credentials, personal paths and confidential
sample data. Do not post exploit details or upload the sample to a public issue
or external analysis service. Agree on any sample transfer and disclosure with
the owner first.
