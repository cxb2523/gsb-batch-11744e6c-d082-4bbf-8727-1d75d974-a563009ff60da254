# Using ReverseAI from an MCP client

`reverseai mcp` lets an AI agent, or any other client of the Model Context Protocol (MCP), ask ReverseAI the same
questions as the command line. Analysis calls run the existing `analyze` or `query` command, with the same checks,
budgets, reviewer and reports. `prepare_file` runs the explicit `prepare` command for cached Ghidra analysis. For the questions themselves see
[USAGE](USAGE.md); for installation see [INSTALL](INSTALL.md); for the trust model see [SECURITY](SECURITY.md).

```sh
reverseai mcp --inputs DIR [--with-lief] [--with-yarax] [--with-ghidra] [--with-jadx] [--with-jsparser]
```

`DIR` is a directory of files you have approved for analysis. The client starts this command itself and talks to it
over its standard input and output; you do not run it by hand.

## What the client can and cannot do

- **Local only.** The server speaks over stdin and stdout and opens no network port.
- **Only files under `DIR`.** Every tool except `list_files` takes a `file` argument: a relative path inside `DIR` (no absolute paths,
  no `..`, no empty parts). A link anywhere along that path is refused, even one that points inside `DIR`, and
  the usual intake checks still apply (one regular file, not a link, at most 64 MiB, unchanged while it is read).
  `list_files` lists regular files under `DIR` with their sizes and never follows links. The check and the read
  are separate steps: another process of the same user could swap a directory in between. As in
  [SECURITY](SECURITY.md), the host account itself is trusted; keep `DIR` writable only by you.
- **Your flags, not the client's.** The contained tools (LIEF, YARA-X, Ghidra, JADX, the JavaScript parser) run only
  when you start the server with their flags and their pinned images are present. No request can enable a tool,
  pass a Docker option, choose an output path or reach a shell.
- **Nothing is executed.** As with the command line, the files are read as data; no sample runs.
- **File text is untrusted.** Reports quote strings, names and decompiled code from the files. Each result begins
  with a line saying so, and the server's instructions tell the agent to treat that text as data, never as
  instructions. A file can still contain text written to mislead an agent, so keep a person in the loop for any
  action an agent proposes after reading a report.
- **Bounded results.** Analysis/query calls default to `view=compact`: reviewed findings and minimal citations,
  without repeated evidence bodies. The text includes the untrusted-data notice and the same compact JSON as
  `structuredContent`; the complete text and the structured content are each bounded to 64 KiB. The JSON is never
  cut, so text-only clients receive the data too; in the text every non-ASCII character is escaped (`\uXXXX`), so
  invisible or bidi characters from a file never reach a model unseen. Use `view=full` to request the
  bounded Markdown/JSON reports (256 KiB text, 1 MiB structured). An oversized report is explicitly omitted; reduce
  the page limit or `max_chars`. Temporary report folders are removed after each call; prepared projects persist
  in the private cache with a copy of the file's bytes until eviction or deletion. See
  [cache retention and deletion](#cache-retention-and-deletion).
- **Errors are messages.** A wrong argument, a refused file, a failed analysis or an exceeded budget comes back as a
  tool result marked as an error with a short, fixed explanation.

## Tools

Tools do not modify approved inputs. Preparation maintains a private cache; it never executes the input. The fixed
catalog is listed in one page:

| Tool | What it does | Needs |
| --- | --- | --- |
| `list_files` | Names and sizes of the regular files under `DIR` | - |
| `analyze_file` | The whole-file analysis of one file | LIEF, YARA-X and Ghidra join the run when enabled |
| `prepare_file` | Prepare or reuse a private Ghidra project; returns a small receipt, never the project | `--with-ghidra` |
| `binary_overview`, `list_segments`, `inspect_native_load_image`, `list_names`, `read_bytes`, `list_strings`, `search_strings` | Native file structure, names, bytes and strings, verified on the host | - |
| `list_procedures`, `search_procedures`, `procedure_info`, `procedure_pseudo_code`, `procedure_assembly`, `procedure_callees`, `procedure_callers`, `analyze_function`, `xrefs` | Functions, code and references as Ghidra reads them | `--with-ghidra` |
| `export_function`, `export_program` | One part/page of a prepared function or program | `--with-ghidra` and `prepare_file` first |
| `inspect_android_package`, `search_android_classes`, `inspect_android_class`, `inspect_android_method`, `trace_android_references` | APK and DEX structure verified on the host | `--with-jadx` adds Java to `inspect_android_method` |
| `analyze_javascript_application` | Files, package.json declarations and lexical hints of a JavaScript ZIP, ASAR, npm tarball or bundle | `--with-jsparser` adds the module, call and parse details |

Analysis and query tools also accept `view=compact|full` (default compact); this is an MCP display option, not a query
argument. `prepare_file` accepts only `file`. Each query tool takes `file` plus that query's own arguments, with the types, limits and defaults the command line
uses; the client sees them in the tool's input schema, and unknown arguments are refused. Large lists are paged
with `start` and `limit`, as on the command line. For `analyze_javascript_application` the archive is `file`, and
one file inside it is chosen with `member_file` (the command line's `--arg file=`). A query uses only its own
contained tool: Ghidra for the code queries, JADX for `inspect_android_method`, the parser for the JavaScript
syntax details.

`list_files` returns `structuredContent` `{"files": [{"name": ..., "size": ...}], "truncated": ...}` and a readable
listing. It visits at most 10,000 entries to a depth of 8 and returns at most 1,000 files; names that are not plain
portable relative names (not UTF-8, or with a backslash, a colon or a control character) are skipped. `truncated`
is true whenever a limit was reached or a name was skipped. Analysis/query tools return `structuredContent`
`{"report": ...}`. `prepare_file` returns the bare `reverseai.prepare/1` receipt as `structuredContent`, with
top-level `schema`, `input`, `analysis_id`, `state`, `runtime`, `cache_format`, `artifact_size` and `elapsed_seconds`.
The text includes the same receipt and the untrusted-data notice.

## Prepared native export workflow

With Ghidra enabled by the operator, call `prepare_file({"file":"program"})` once. It can take up to 1,020 seconds,
including lock wait and host work; if the client cannot wait that long, run `reverseai prepare FILE --with-ghidra`
in the terminal first. No analysis call silently starts this warm-up. Existing preview queries still work without it.
Once an input is prepared, its ordinary Ghidra queries also use the prepared analysis.

Then ask for bounded pages:

```json
{"file":"program","part":"functions","start":0,"limit":32}
```

Pass that object to `export_program`, then follow `next_start`. Use `part=calls`, `references` or `strings` for the
other tables. `export_function` selects an entry or exact name and one part (`info` by default); pseudocode uses
`text_start` and `max_chars`, while assembly/call/reference/string parts use `start` and `limit`.
`procedure_pseudo_code` keeps its bounded `mode=preview` default; set `mode=paged` after preparation.

Record the input hash and `analysis_id` with every page. Do not mix different analysis IDs; pseudocode pages must
also share `text_sha256`. A missing/invalid cache entry gives the explicit prepare command. The cache checks every
opaque project's size/hash, while observations still cite the original file bytes; signatures, functions and
relationships remain Ghidra's interpretation. No program export decompiles all functions, compiles code or executes
an input. See [the CLI workflow and limits](USAGE.md#prepared-native-exports).

## Cache retention and deletion

Prepared analyses include a copy of the file's bytes and survive CLI and MCP sessions until least-recently-used
eviction or manual deletion (up to 32 projects / 2 GiB). They remain sensitive even after the original file is removed.
The private folder is `~/Library/Caches/ReverseAI/ghidra/v1` on macOS. On Linux it is
`$XDG_CACHE_HOME/reverseai/ghidra/v1` when that base is absolute and safe, otherwise `~/.cache/reverseai/ghidra/v1`.

To erase the retained analyses, stop ReverseAI instances using the cache and delete that entire `ghidra/v1` folder.
This is also the recovery for a stray file such as `.DS_Store` or a damaged entry that triggers
`Private Ghidra cache is unsafe or unavailable.` Run prepare again to create a fresh private cache and analysis.
An unsafe parent directory still needs its ownership or permissions corrected.

## Configuring a client

The examples use an installed package at `/path/to/.venv` and approved files in `/path/to/approved-inputs`; use
your own absolute paths. On Windows the program is `C:\path\to\.venv\Scripts\reverseai.exe` (Windows support is
experimental; see [INSTALL](INSTALL.md)). To enable a contained tool, add its flag after `--inputs DIR`, for
example `"--with-ghidra"`.

### Claude Code

Add the server for yourself (the default `local` scope, or `--scope user` for every project):

```sh
claude mcp add --transport stdio reverseai -- /path/to/.venv/bin/reverseai mcp --inputs /path/to/approved-inputs
```

The configuration holds your absolute paths, so keep it in your own settings. A project scope (`--scope project`)
writes `.mcp.json` into the project and shares it with everyone who uses it; use it only for paths that are meant to
be shared, never inside the ReverseAI checkout, and keep it out of version control:

```json
{
  "mcpServers": {
    "reverseai": {
      "type": "stdio",
      "command": "/path/to/.venv/bin/reverseai",
      "args": ["mcp", "--inputs", "/path/to/approved-inputs"]
    }
  }
}
```

Claude Code asks before it first uses a project's servers from `.mcp.json`. It warns when one tool result passes 10,000 tokens and
stores results over its limit (25,000 tokens by default, or 50,000 characters of text) in a file instead of the
conversation; prefer paged queries, or raise `MAX_MCP_OUTPUT_TOKENS` before starting Claude Code.

### Codex CLI

```sh
codex mcp add reverseai -- /path/to/.venv/bin/reverseai mcp --inputs /path/to/approved-inputs
```

Or add it to your own `~/.codex/config.toml` (a project's `.codex/config.toml` is shared with the project; keep
private paths out of it):

```toml
[mcp_servers.reverseai]
command = "/path/to/.venv/bin/reverseai"
args = ["mcp", "--inputs", "/path/to/approved-inputs"]
tool_timeout_sec = 1200
```

The example allows 1,200 seconds for a tool call: Ghidra queries can take up to 240 seconds, while prepare has a
1,020-second overall deadline. Use this longer timeout when enabling `--with-ghidra`, or prepare through the CLI
first if your client cannot wait that long.

### Cursor

Put this in `~/.cursor/mcp.json` (your own settings, for every project). A project's `.cursor/mcp.json` is shared
with the project; keep private paths out of it:

```json
{
  "mcpServers": {
    "reverseai": {
      "type": "stdio",
      "command": "/path/to/.venv/bin/reverseai",
      "args": ["mcp", "--inputs", "${workspaceFolder}/approved-inputs"]
    }
  }
}
```

Cursor asks for approval before it uses an MCP tool unless your run mode allows it.

## Protocol

The server follows MCP revision `2026-07-28`: each request carries its protocol version and client capabilities in
`params._meta`, and `server/discover` describes the server. Clients that still open with `initialize` (revisions
`2025-11-25`, `2025-06-18` and `2025-03-26`) are served too. Messages are JSON-RPC 2.0, one per line; a line over
1 MiB is refused, and the server never sends requests to the client.

## Trying it without an agent

`tests/mcp_client.py` is a small client used by the end-to-end tests. It starts the server, sends requests and
reads each reply with a timeout and a size limit:

```python
from tests.mcp_client import Client

with Client.reverseai("/path/to/approved-inputs") as client:
    print(client.discover()["result"]["supportedVersions"])
    print(client.call_tool("list_files")["result"]["structuredContent"]["files"])
    reply = client.call_tool("binary_overview", {"file": "sample.bin"})
```

Run it from the repository root with Python 3.12 or later.
