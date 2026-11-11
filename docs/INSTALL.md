# Install and check ReverseAI

Version 0.9.0 installation examples for macOS ARM64 and Linux ARM64. Installing the
Python package enables host-only
analysis on supported POSIX systems. Contained tools additionally require their
exact local images and a separately verified Docker environment. Installation
and `doctor` do not prove containment.

## Requirements

- Python 3.12 or later, with `venv` and pip already available for installation.
  ReverseAI has no Python runtime dependencies; its standard-library PEP 517
  backend requires no downloaded build packages.
- Windows analysis and queries require **CPython 3.12.4 or later** and a new,
  nonexistent output directory for each call. Existing directories, junctions
  and symlinks are refused; older Windows Pythons cannot create the required
  private report directory and refuse output.
- An approved local wheel or a checkout of the desired revision. The wheel
  includes five image locks and the YARA-X ruleset. Image builders, tests and the
  native verifier require a checkout; they are not in the wheel.
- For contained tools: Docker Desktop and the locked Linux ARM64 images already
  present locally. Current native proof covers Linux ARM64 containers on Docker
  Desktop on the Mac. A `py3-none-any` wheel does not establish native-container
  proof on another architecture or OS.

No Node.js, JDK, Ghidra, JADX, LIEF or YARA-X installation is needed on the host.
Those runtimes belong inside worker images. No sample package is installed.

## Install offline

Use a new virtual environment. Run these commands from a trusted checkout or a
directory containing an approved wheel, not from sample contents. Do not add a
package index or upgrade pip as part of this offline path.

On macOS or Linux:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install --no-index --no-deps /approved/reverseai-0.9.0-py3-none-any.whl
.venv/bin/reverseai --version
.venv/bin/reverseai doctor
.venv/bin/reverseai doctor --json
```

Or, from the checkout root, install the source into that environment:

```sh
.venv/bin/python -m pip install --no-index --no-deps .
```

For development in a trusted checkout, use an editable install instead:

```sh
.venv/bin/python -m pip install --no-index --no-deps -e .
```

The editable wheel adds the absolute checkout root to Python's import path;
source changes and checkout image locks are used directly. Keep the checkout
at that path. Reinstall when metadata or entry points change. Never run this
command on a sample directory or an untrusted project: installing a Python
project can execute its build backend. The normal wheel carries fixed lock
copies and does not depend on keeping a checkout.

Use a dedicated virtual environment: the checkout's top-level packages, such as
`tests`, also become importable through the editable install.

On Windows, with CPython 3.12.4 or later installed:

```powershell
py -3.12 -m venv .venv
.venv\Scripts\python.exe -m pip install --no-index --no-deps C:\approved\reverseai-0.9.0-py3-none-any.whl
.venv\Scripts\reverseai.exe --version
.venv\Scripts\reverseai.exe doctor --json
.venv\Scripts\reverseai.exe analyze C:\approved\file.exe --out C:\reports\new-analysis
.venv\Scripts\reverseai.exe query C:\approved\file.exe --query list_segments --arg limit=16 --out C:\reports\new-query
```

The parent `C:\reports` must exist; `new-analysis` and `new-query` must not.
Windows output is bound to a directory handle until both reports are written,
so the directory cannot be renamed or replaced while bound. Use a different
new directory for every call. Windows handling remains experimental: consult
the receipt for the exact tested host and commit. Use your installed Python
launcher when a different supported version is selected.

The version command prints `reverseai 0.9.0`. `doctor` reports Python, OS and
architecture, lock validity, whether Docker answers its version probe within
10 seconds, and whether each locked image is present. It reads no sample and
never pulls, builds or runs a container. Exit 0 means the host Python requirement
is met; all contained tools can still be unavailable. Inspect the tool rows or
JSON `tools` array, not just the exit code. A present image is not a native proof.

On supported POSIX systems, a host-only query needs no Docker:

```sh
.venv/bin/reverseai query /approved/file --query list_segments --arg limit=16 --out new-query-report
```

Choose your approved input and a new report directory. Reports can contain
sensitive strings and derived text from that input.

## Build distribution artifacts

Build from a clean checkout root using Python 3.12 or later. Check that no local
changes or untracked Python files are present under `reverseai/`: the wheel
includes modules from the working tree, including untracked `.py` files.

```sh
python3 -B tools/reverseai_build.py wheel --out dist
python3 -B tools/reverseai_build.py sdist --out dist
```

This writes `reverseai-0.9.0-py3-none-any.whl` and `reverseai-0.9.0.tar.gz`.
The backend fixes archive ordering, timestamps and modes for reproducible output
from the same tree. Source distributions select tracked files; commit new files
before building a release sdist. Wheels contain application modules, locks,
ruleset and metadata, not image build contexts or tests. The project uses MIT;
the wheel's Metadata-Version 2.4 declares `License-Expression: MIT` and the two
license files, copied under `reverseai-0.9.0.dist-info/licenses/`. The sdist
includes `LICENSE`, `THIRD_PARTY_NOTICES.md` and the same license headers in
`PKG-INFO`. Third-party notices and licenses remain applicable.

## Use local contained images

Each tool loads its lock from `reverseai/_locks/<tool>.json` in an installed
wheel, or `containers/<tool>/image.lock.json` in a checkout. The image ID must
already exist in Docker; analysis uses `--pull never`. Tool flags are
`--with-lief`, `--with-yarax`, `--with-ghidra`, `--with-jadx` and
`--with-jsparser`, where the selected command/query supports them.

The current runtime's snapshot root is `/Users/Shared/rea-safe-staging-501`.
It must already be owned by the calling host user with mode `0700`, and
accessible to Docker Desktop. It is for disposable approved snapshots, not the
workspace or home directory. The installer and `doctor` do not create it, widen
Docker sharing or restart Docker.

Wheel locks are fixed at build time. If an authorized image rebuild updates a
checkout lock, rebuild/reinstall the wheel or reinstall that updated checkout
before expecting the installed command to use it:

```sh
.venv/bin/python -m pip install --no-index --no-deps --force-reinstall .
```

Do not substitute an arbitrary image tag for a pin. Re-run the corresponding
native proof after an image or relevant controller change.

## Approved image inputs and build recipes

Use only artifacts already obtained through the project's approval process.
Builders check pinned hashes before use. They do not run a sample's package
manager or scripts. The common base is
`python:3.12-slim@sha256:16bf2b5c59a08523519d3c8589deca849285dee1d62a3653e124c3dba340f15e`.

| Input | Expected hash in the checkout |
| --- | --- |
| `lief-1.0.0-cp312-abi3-manylinux_2_28_aarch64.whl` | [`containers/lief/image.lock.json`](../containers/lief/image.lock.json): `wheel_sha256`; also pinned in [`requirements.txt`](../containers/lief/requirements.txt). |
| `yara_x-1.21.0-cp38-abi3-manylinux_2_28_aarch64.whl` | [`containers/yarax/image.lock.json`](../containers/yarax/image.lock.json): `wheel_sha256`; also pinned in [`requirements.txt`](../containers/yarax/requirements.txt). |
| `ghidra_12.1.4_PUBLIC_20260921.zip` | [`containers/ghidra/image.lock.json`](../containers/ghidra/image.lock.json): `ghidra_sha256`. |
| `OpenJDK21U-jdk_aarch64_linux_hotspot_21.0.12.1_1.tar.gz` | Ghidra and [JADX locks](../containers/jadx/image.lock.json): `jdk_sha256`. |
| `jadx-1.5.6.zip` | [JADX lock](../containers/jadx/image.lock.json): `jadx_zip_sha256`; its JAR is also checked against `jadx_jar_sha256`. |
| `node-v24.22.1-linux-arm64.tar.xz` | [`containers/jsparser/image.lock.json`](../containers/jsparser/image.lock.json): `node_sha256`. |
| `parser-8.0.4.tgz`, `types-8.0.4.tgz`, `helper-string-parser-8.0.6.tgz`, `helper-validator-identifier-8.0.6.tgz` | [Parser lock](../containers/jsparser/image.lock.json): `babel_parser_integrity`, `babel_types_integrity`, `helper_string_parser_integrity`, `helper_validator_identifier_integrity`. These use SHA-512 SRI, not SHA-256. |

The build scripts contain the same approved input hashes. The locks are the
authoritative values; do not change them to accept a mismatched artifact.

JADX and the parser build offline when the pinned base is already cached and
the approved inputs are present. Replace the directories with your local
approved artifact directories:

```sh
python3 -B tools/build_jadx_image.py --download-dir /approved/jadx-and-jdk
python3 -B tools/build_jsparser_image.py --download-dir /approved/node-and-babel
```

JADX needs its ZIP and the JDK tarball; the parser needs the Node archive and
four Babel archives. These builders refuse a missing base instead of pulling
it, and use network-disabled build steps.

LIEF and YARA-X also build offline from the approved local wheel and cached
pinned base. They inspect that base and refuse if it is absent, never pull, and
use network-disabled build steps. Do not add the optional `--download` flag
under a no-download policy:

```sh
python3 -B tools/build_lief_image.py --wheel-dir /approved/lief-wheel
python3 -B tools/build_yarax_image.py --wheel-dir /approved/yarax-wheel
```

Ghidra's builder still pulls the pinned base and its native-build stage runs
`apt-get` for compiler/make packages. Even with its ZIP and JDK already present,
this recipe needs network:

```sh
python3 -B tools/build_ghidra_image.py --download-dir /approved/ghidra-and-jdk
```

Do not run the Ghidra recipe under a no-download policy. Use the already-built
locked image instead; an offline Ghidra build needs separately approved Debian
packages and is deferred. Installing the Python package, running existing
workers offline and rebuilding images are separate operations.

## Verification and platform scope

`doctor` inspects the environment. The native verifier deliberately creates and
runs trusted control containers to test the profile; it is a separate operation.
From a checkout, with the locked image already present:

```sh
python3 -B tests/verify_m2_runtime.py --tool lief --profile small --offline --lock containers/lief/image.lock.json --receipt new-lief-receipt.json
```

Repeat with `yarax`, `ghidra`, `jadx` or `jsparser`, its lock and a new receipt.
Controls exercise network/write/privilege refusal, PID, memory, wall and output
limits, known answers and cleanup. They parse synthetic fixtures without
executing sample code. See the [security model](SECURITY.md) for the trust limits.

The proven host scope is macOS ARM64 plus a Linux ARM64 container. On the
Mac, run the committed candidate's whole suite:

```sh
python3 -B -m unittest discover -s tests -t . -v
```

The Linux proof requires Docker and the already-cached pinned base. It copies
the selected commit with `git archive`, uses no host mount or network, runs the
suite, builds/installs the wheel offline in a fresh environment and exercises
the installed command on code-built fixture bytes:

```sh
python3 -B tools/linux_proof.py --commit HEAD --receipt new-linux-arm64-receipt.json
```

This host-suite proof is distinct from native worker proof. A receipt applies to
its recorded commit, Python version, architecture and base/image bindings.
Windows remains experimental. No Windows, AMD64 or all-OS containment claim
follows from a host receipt. Consult the receipts for the release you use,
not only an earlier milestone's green result.

## Owner-started host proof workflow

The [manual workflow](../.github/workflows/manual-proof.yml) runs only through
`workflow_dispatch`, after it is on the default branch. The owner selects it
in GitHub Actions, chooses **Run workflow**, and sets `target` to `linux`,
`windows` or `both` (default `linux`). It has no push, pull-request or scheduled
trigger. Do not dispatch it without the owner's instruction.

Each job runs `tools/host_proof.py` on Linux x86-64 or Windows x86-64. It records
the commit, Python/OS/architecture, suite counts, offline wheel installation,
installed version and module path, doctor, and analysis/query of code-built
fixture bytes. The JSON receipt appears after `REVERSEAI-HOST-PROOF ` in the
log and in the GitHub step summary; there is no artifact-upload step. The
package install uses no index, but provisioning a hosted runner and Python is
not an offline operation.

On POSIX, the whole suite gates the host result. On Windows, the real
`tests.test_windows_output` run and installed CLI checks gate it; the whole
suite also runs and its failures/skips are recorded, without being treated as
a successful all-tests Windows proof. A receipt proves only the recorded
checks on that host and commit, not native worker containment or an AMD64
container image. No hosted run is claimed by these instructions.
