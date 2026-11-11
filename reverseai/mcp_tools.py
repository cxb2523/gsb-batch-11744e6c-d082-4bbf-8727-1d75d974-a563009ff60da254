"""Fixed MCP tool descriptions and validation for the existing analysis commands."""

import os
from pathlib import Path
import stat
import unicodedata

from reverseai import intake, queries
from reverseai.contract import ContractError, MAX_STRING_ARG_CHARS


ENABLE = ("lief", "yarax", "ghidra", "jadx", "jsparser")
MAX_PATH_BYTES = 1024
MAX_FILES = 1000
MAX_ENTRIES = 10_000
MAX_DEPTH = 8
_BAD_FILE = "file must be a relative POSIX path within --inputs, up to 1024 UTF-8 bytes."
_BAD_ARGUMENTS = "Arguments must match this tool's input schema."


class UnknownTool(Exception):
    """The tool is absent from this server's operator-selected catalog."""


class ToolInputError(Exception):
    """A fixed, actionable client message without host paths or tool output."""


_QUERY_TEXT = {
    "binary_overview": ("Inspect a native file", "Read the format, headers, sections, imports and entry point."),
    "list_segments": ("List segments", "Page through declared segments and their permissions."),
    "inspect_native_load_image": ("Inspect the load image", "Read declared segments and the native entry point."),
    "list_names": ("List names", "Find declared symbols by literal name text and page through the results."),
    "read_bytes": ("Read bytes", "Read a bounded byte range at a file offset or mapped address."),
    "list_strings": ("List strings", "Page through printable ASCII and UTF-16LE runs in the file."),
    "search_strings": ("Search strings", "Find printable runs containing literal text."),
    "list_procedures": ("List functions", "Page through Ghidra's derived function list."),
    "search_procedures": ("Search functions", "Find functions by name in Ghidra's derived reading."),
    "procedure_info": ("Inspect a function", "Read Ghidra's derived metadata for a function by entry or exact name."),
    "procedure_pseudo_code": ("Decompile a function", "Read derived pseudocode for a function; it is not verified source."),
    "export_function": ("Export a function page", "Read one part of a prepared Ghidra function; results are derived."),
    "export_program": ("Export a program page", "Read a page of prepared functions, calls or references without decompiling all functions."),
    "procedure_assembly": ("Read assembly", "Page through a function's derived instruction listing."),
    "procedure_callees": ("List function callees", "Read Ghidra's derived calls from a selected function."),
    "procedure_callers": ("List function callers", "Read Ghidra's derived call sites targeting a selected function."),
    "analyze_function": ("Analyze a function", "Read derived function metadata, pseudocode, instructions, calls and references."),
    "xrefs": ("Find references", "Page through Ghidra's derived references to an address."),
    "inspect_android_package": ("Inspect an Android package", "Read APK members and binary manifest declarations."),
    "search_android_classes": ("Search Android classes", "Find declared DEX classes inside an APK by literal text."),
    "inspect_android_class": ("Inspect an Android class", "Read the exact displayed class descriptor and its declared methods."),
    "inspect_android_method": ("Inspect an Android method", "Read method declarations and code references; enabled JADX adds derived Java."),
    "trace_android_references": ("Trace Android references", "Read declared references from or to a method inside an APK."),
    "analyze_javascript_application": ("Inspect a JavaScript application", "Read files, package declarations and lexical hints; enabled parser details are derived syntax."),
}


def _schema(spec):
    if spec.kind == "int":
        field = {"type": "integer", "minimum": spec.minimum, "maximum": spec.maximum}
    elif spec.kind == "enum":
        field = {"type": "string", "enum": list(spec.choices)}
    else:
        bounded = spec.kind in ("literal", "identity")
        field = {"type": "string", "minLength": spec.minimum if bounded else 0,
                 "maxLength": spec.maximum if bounded else MAX_STRING_ARG_CHARS}
        field["description"] = {
            "str": "Text without slashes, backslashes, NUL or a leading hyphen.",
            "literal": "Printable literal text.",
            "identity": "Exact escaped identity displayed in the analysis rows (printable ASCII).",
        }[spec.kind]
    if spec.default is not None:
        field["default"] = spec.default
    return field


def _tool(name, title, description, properties, required):
    return {"name": name, "title": title, "description": description,
            "inputSchema": {"type": "object", "properties": properties,
                            "required": required, "additionalProperties": False},
            "annotations": {"readOnlyHint": True, "destructiveHint": False,
                            "idempotentHint": True, "openWorldHint": False}}


def _enabled(enabled):
    if not isinstance(enabled, frozenset) or not enabled.issubset(ENABLE):
        raise ToolInputError("Select only the supported server worker flags.")
    return enabled


def _query_names(enabled):
    return [name for name, spec in queries.TABLE.items() if spec.role != "code" or "ghidra" in enabled]


def _argument_name(key):
    return "member_file" if key == "file" else key


def catalog(enabled: frozenset) -> list[dict]:
    enabled = _enabled(enabled)
    file_schema = {"type": "string", "minLength": 1, "maxLength": MAX_PATH_BYTES,
                   "description": "Relative POSIX path under the configured input directory, at most 1024 UTF-8 bytes; no links."}
    tools = [
        _tool("list_files", "List input files", "List regular input files without following links; the listing is bounded.", {}, []),
        _tool("analyze_file", "Analyze a file", "Run static whole-file analysis without executing the input.",
              {"file": dict(file_schema)}, ["file"]),
    ]
    view = {"type": "string", "enum": ["compact", "full"], "default": "compact",
            "description": "Compact reviewed findings, or full bounded reports including evidence bodies."}
    tools[1]["inputSchema"]["properties"]["view"] = dict(view)
    if "ghidra" in enabled:
        tools.append(_tool("prepare_file", "Prepare a native file",
                           "Create or reuse a private pinned Ghidra analysis without executing the input. This can take up to 17 minutes.",
                           {"file": dict(file_schema)}, ["file"]))
        tools[-1]["annotations"]["readOnlyHint"] = False
    for name in _query_names(enabled):
        spec = queries.TABLE[name]
        properties = {"file": dict(file_schema),
                      "view": dict(view),
                      **{_argument_name(key): _schema(value) for key, value in spec.args.items()}}
        if name == "analyze_javascript_application":
            properties["member_file"]["description"] = ("Printable archive member selector used with detail hints, "
                                                        "package, modules, calls or parse; leave empty for summary or files.")
            if "jsparser" not in enabled:
                properties["detail"]["enum"] = [value for value in properties["detail"]["enum"]
                                                  if value not in queries.JS_SYNTAX_DETAILS]
        required = ["file", *(_argument_name(key) for key, value in spec.args.items() if value.default is None)]
        title, description = _QUERY_TEXT[name]
        tools.append(_tool(name, title, description, properties, required))
    return tools


def _relative_parts(name):
    if not isinstance(name, str):
        raise ToolInputError(_BAD_FILE)
    try:
        size = len(name.encode("utf-8"))
    except UnicodeError:
        raise ToolInputError(_BAD_FILE) from None
    parts = name.split("/")
    if (not 1 <= size <= MAX_PATH_BYTES or "\\" in name or ":" in name or name.startswith("/")
            or any(unicodedata.category(char) in ("Cc", "Cf") for char in name)
            or any(part in ("", ".", "..") for part in parts)):
        raise ToolInputError(_BAD_FILE)
    return parts


def _linked(info):
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & intake._REPARSE_POINT)


def _root_path(root):
    try:
        root = os.path.abspath(root)
        info = os.lstat(root)
        if _linked(info) or not stat.S_ISDIR(info.st_mode):
            raise ValueError
        return os.path.realpath(root)
    except (OSError, ValueError, TypeError):
        raise ToolInputError("The configured input directory is unavailable.") from None


def _input_path(root, name):
    parts = _relative_parts(name)
    root = _root_path(root)
    current = root
    try:
        for index, part in enumerate(parts):
            current = os.path.join(current, part)
            info = os.lstat(current)
            if _linked(info) or (index < len(parts) - 1 and not stat.S_ISDIR(info.st_mode)):
                raise ValueError
        resolved = os.path.realpath(current)
        if os.path.commonpath((root, resolved)) != root:
            raise ValueError
        intake._regular_stat(Path(resolved))
        return resolved
    except intake.IntakeError as error:
        raise ToolInputError(str(error)) from None
    except (OSError, ValueError):
        raise ToolInputError("Choose an existing regular, non-linked file within --inputs.") from None


def list_files(root: str) -> dict:
    pending = [(_root_path(root), "")]
    files, visited, truncated = [], 0, False
    try:
        while pending and visited < MAX_ENTRIES:
            directory, prefix = pending.pop()
            entries = []
            with os.scandir(directory) as iterator:
                for entry in iterator:
                    visited += 1
                    entries.append(entry)
                    if visited == MAX_ENTRIES:
                        truncated = True
                        break
            children = []
            for entry in sorted(entries, key=lambda item: item.name):
                name = prefix + entry.name
                try:
                    parts = _relative_parts(name)
                except ToolInputError:
                    truncated = True
                    continue
                info = entry.stat(follow_symlinks=False)
                if _linked(info):
                    continue
                if stat.S_ISREG(info.st_mode):
                    files.append({"name": name, "size": info.st_size})
                    if len(files) == MAX_FILES:
                        return {"files": sorted(files, key=lambda item: item["name"]), "truncated": True}
                elif stat.S_ISDIR(info.st_mode):
                    if len(parts) == MAX_DEPTH:
                        truncated = True
                    else:
                        children.append((entry.path, name + "/"))
            pending.extend(reversed(children))
    except (OSError, ValueError):
        raise ToolInputError("The input directory could not be listed; check its accessibility and retry.") from None
    return {"files": sorted(files, key=lambda item: item["name"]), "truncated": truncated}


def command(name, arguments, *, root: str, out: str, enabled: frozenset) -> list[str]:
    enabled = _enabled(enabled)
    if not isinstance(name, str) or (name != "analyze_file" and name not in _query_names(enabled)
                                   and not (name == "prepare_file" and "ghidra" in enabled)):
        raise UnknownTool
    if not isinstance(arguments, dict) or "file" not in arguments:
        raise ToolInputError(_BAD_ARGUMENTS)
    if name == "prepare_file":
        if set(arguments) != {"file"}:
            raise ToolInputError(_BAD_ARGUMENTS)
        return ["prepare", _input_path(root, arguments["file"]), "--with-ghidra", "--json"]
    arguments = dict(arguments)
    if arguments.pop("view", "compact") not in ("compact", "full"):
        raise ToolInputError(_BAD_ARGUMENTS)
    if name == "analyze_file":
        if set(arguments) != {"file"}:
            raise ToolInputError(_BAD_ARGUMENTS)
        checked = {}
        workers = [worker for worker in ("lief", "yarax", "ghidra") if worker in enabled]
    else:
        raw = {("file" if key == "member_file" else key): value
               for key, value in arguments.items() if key != "file"}
        if "member_file" in arguments and "file" not in queries.TABLE[name].args:
            raise ToolInputError(_BAD_ARGUMENTS)
        try:
            _, checked = queries.resolve(name, raw)
        except (ContractError, TypeError):
            raise ToolInputError(_BAD_ARGUMENTS) from None
        worker = ("ghidra" if queries.TABLE[name].role == "code" else
                  "jadx" if name == "inspect_android_method" else
                  "jsparser" if name == "analyze_javascript_application"
                  and checked["detail"] in queries.JS_SYNTAX_DETAILS else None)
        if worker == "jsparser" and worker not in enabled:
            raise ToolInputError("Ask the operator to enable --with-jsparser for syntax details.")
        workers = [worker] if worker in enabled else []
    path = _input_path(root, arguments["file"])
    argv = ["analyze" if name == "analyze_file" else "query", path, "--out", out]
    if name != "analyze_file":
        argv += ["--query", name]
        for key, value in checked.items():
            argv += ["--arg", f"{key}={value}"]
    return argv + ["--with-" + worker for worker in workers]
