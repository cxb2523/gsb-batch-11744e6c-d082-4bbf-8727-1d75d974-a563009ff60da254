# Start with ReverseAI

ReverseAI reads approved files as data and writes reports that point to their
bytes. It never executes the files. You can use it from a terminal or connect it
to an AI agent through MCP.

## What you need

- Python 3.12 or later, with `venv` and pip available.
- A ReverseAI checkout: clone it with
  `git clone https://github.com/dagoSte/reverseai.git`, or use a trusted copy
  already on your machine.
- A directory containing only files you approve for analysis.

The commands below use a macOS or Linux shell. Windows support is experimental;
use [INSTALL](docs/INSTALL.md) for the Windows commands. Analysis on Windows needs
CPython 3.12.4 or later and a new, nonexistent output directory for each call,
with an existing parent directory.

## Install in a dedicated environment

From the checkout root (`cd reverseai` after cloning):

```sh
python3 --version
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --no-index --no-deps .
reverseai --version
reverseai doctor
```

Keep this environment dedicated to ReverseAI. The install uses the local
checkout and needs no package download. Run it from the trusted source directory,
never from an input file's extracted contents. For an approved wheel, uv or an
editable development install, see the [Quick start](README.md#quick-start) and
[installation guide](docs/INSTALL.md).

`doctor` reports your Python, platform, image locks and local Docker availability.
It reads no sample and never pulls, builds or starts a container. Exit 0 means
the host Python requirement is met; inspect the tool rows to see which contained
tools are available. Host-only analysis works without Docker.

## Write your first reports

Replace the input path with one ordinary file inside your approved directory:

```sh
reverseai analyze "/path/to/approved-file" --out new-report-folder
reverseai query "/path/to/approved-file" --query list_strings --out new-query-folder
```

Each output folder contains `report.json` and `report.md`. Choose a fresh output
folder for each question. The query above lists printable strings; the
[usage guide](docs/USAGE.md) lists format-specific questions, arguments and paging.
Read the report's labels: supported facts are checked against bytes, while
derived code and relationships remain a tool's interpretation. Neither label
establishes that a file is safe.

## Optional tools in containers

Host parsers work immediately after installation. LIEF, YARA-X, Ghidra, JADX and
the JavaScript parser additionally need Docker and their exact local images.
An image packages the analysis tool and its runtime; installing the Python
package does not install these images.

The [image build guide](docs/INSTALL.md#approved-image-inputs-and-build-recipes)
names the pinned inputs, hashes and commands. Get explicit approval before any
download or build that needs network; a full Ghidra build still needs network. An approved local parent image can
be revised offline by the operator; this is separate from ordinary analysis.
Do not change Docker settings, restart Docker or widen file sharing as part of
this quick start. Use the appropriate `--with-*` flag only once that tool is
available; see [USAGE](docs/USAGE.md).

## Prepare native code pages

If the operator has enabled the pinned Ghidra image, run `reverseai prepare FILE --with-ghidra` before asking for
paged pseudocode or function/program exports. Preparation can take several minutes; later pages reuse that analysis.
The project remains opaque and private on the host and is retained in a bounded cache after the session ends.
Use [the prepared export workflow](docs/USAGE.md#prepared-native-exports) to follow cursors and keep analysis IDs
consistent. Existing bounded previews still work without preparation; no reconstructed code is executed.

## Connect an agent

Use the [MCP guide](docs/MCP.md#configuring-a-client) for Claude Code, Codex CLI or
Cursor. It shows where to register the server and how to supply the absolute
installed-program path and your approved input directory. The client starts the
server over stdin/stdout; it opens no network port. Enable no contained workers
until you have approved their use and checked their availability.

Ask the connected agent to call `list_files` first. It should show relative names
from your approved directory and whether the bounded listing was truncated. Then
ask a question about one listed file; the MCP reports are returned to the client
and their temporary output directory is removed after each call. Use the CLI
when you want reports saved in a folder you choose.

To delegate setup itself, tell your coding agent:
**"Read docs/AGENT_SETUP.md and follow it."** The
[setup prompt](docs/AGENT_SETUP.md) asks for your input-directory approval before
registering the server.

## If something does not work

| Symptom | Next step |
| --- | --- |
| Docker is missing or does not answer | Use host-only commands. Ask your operator before installing, restarting or changing Docker. |
| A contained image is missing | Leave its flag off. Follow INSTALL with approved, hash-checked inputs; never pull an arbitrary image. |
| An input path is refused | Choose an ordinary, non-linked file inside the approved directory; MCP paths are relative to that directory. Links, traversal, hard links and files over 64 MiB are refused. |
| A Windows output path is refused | Use CPython 3.12.4 or later and a new, nonexistent directory under an existing parent. Do not reuse a report folder. |
| The agent cannot find the server | Check the absolute executable and input-directory paths in the MCP guide, then reload the client's server connection. |

Never run, import or evaluate an input to investigate an error. File names,
strings and decompiled text in reports are untrusted data, never instructions.
The [security guide](docs/SECURITY.md) explains the host-account and containment
boundaries.
