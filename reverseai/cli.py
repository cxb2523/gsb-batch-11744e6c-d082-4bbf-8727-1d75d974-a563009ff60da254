"""Command line: python3 -m reverseai analyze FILE --out DIR"""

import argparse
import os
from pathlib import Path
import stat
import sys

import reverseai
from reverseai import doctor, intake, pipeline, queries, report

# Reports hold text taken from untrusted samples: private to the user.
DIRECTORY_MODE = 0o700
FILE_MODE = 0o600
REPORTS = ("report.json", "report.md")


class OutputRefused(Exception):
    """--out is not a new or empty real directory, or cannot be bound safely."""


def safe_directories():
    return os.open in os.supports_dir_fd and hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW")


def open_output(path):
    """Bind --out to a directory handle before the analysis, so a later swap of the path cannot redirect the reports."""
    if os.name == "nt":
        from reverseai import winout
        try:
            return winout.open_output(path)
        except winout.OutputRefused as error:
            raise OutputRefused(str(error)) from None
        except (OSError, ValueError):
            raise OutputRefused("--out cannot be bound safely on Windows") from None
    if not safe_directories():
        raise OutputRefused("this platform lacks safe directory handles")
    try:
        os.mkdir(path, DIRECTORY_MODE)
    except FileExistsError:
        pass
    except OSError:
        raise OutputRefused("--out cannot be created") from None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        raise OutputRefused("--out must be a new or empty directory") from None
    if not stat.S_ISDIR(os.fstat(descriptor).st_mode) or os.listdir(descriptor):
        os.close(descriptor)
        raise OutputRefused("--out must be a new or empty directory")
    return descriptor


def write_new(directory, name, text):
    """Create the file inside the bound directory or fail; never follow or replace an existing entry."""
    if os.name == "nt":
        from reverseai import winout
        return winout.write_new(directory, name, text)
    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, FILE_MODE, dir_fd=directory)
    with os.fdopen(descriptor, "w", encoding="utf-8", errors="backslashreplace", newline="\n") as handle:
        handle.write(text)


def main(argv=None, *, _on_status=None):
    parser = argparse.ArgumentParser(prog="reverseai", description="Static reverse engineering of untrusted files, with verifiable evidence.")
    parser.add_argument("--version", action="version", version="reverseai " + reverseai.__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("doctor", help="Report Python, Docker and the contained tools' locks and images, read-only")
    check.add_argument("--json", action="store_true", help="Print the same facts as JSON")
    prepare = commands.add_parser("prepare", help="Prepare a private Ghidra analysis for paged exports without executing the input")
    prepare.add_argument("file", type=Path)
    prepare.add_argument("--with-ghidra", action="store_true", required=True)
    prepare.add_argument("--json", action="store_true", help="Print a bounded preparation receipt")
    analyze = commands.add_parser("analyze", help="Analyse one approved file without executing it")
    analyze.add_argument("file", type=Path)
    analyze.add_argument("--out", type=Path, required=True, help="New or empty directory for report.json and report.md")
    analyze.add_argument("--with-lief", action="store_true", help="Also run the pinned LIEF worker in its locked container")
    analyze.add_argument("--with-yarax", action="store_true",
                         help="Also run the pinned YARA-X worker with the reviewed ruleset in its locked container")
    analyze.add_argument("--with-ghidra", action="store_true",
                         help="Also run pinned Ghidra headless in its locked container; its findings are derived, not verified")
    query = commands.add_parser("query", help="Ask one targeted static-analysis question")
    query.add_argument("file", type=Path)
    query.add_argument("--query", required=True, metavar="NAME", help="One of: " + ", ".join(queries.TABLE))
    query.add_argument("--arg", action="append", default=[], metavar="KEY=VALUE")
    query.add_argument("--out", type=Path, required=True, help="New or empty directory for report.json and report.md")
    query.add_argument("--with-ghidra", action="store_true", help="Enable the pinned contained Ghidra query worker")
    query.add_argument("--with-jadx", action="store_true",
                       help="Include derived Java for Android method queries using the pinned contained JADX worker")
    query.add_argument("--with-jsparser", action="store_true",
                       help="Enable derived JavaScript syntax queries using the pinned contained parser")
    mcp = commands.add_parser("mcp", help="Serve the analysis tools over MCP stdio")
    mcp.add_argument("--inputs", type=Path, required=True, help="Existing directory of operator-approved inputs")
    for tool in ("lief", "yarax", "ghidra", "jadx", "jsparser"):
        mcp.add_argument("--with-" + tool, action="store_true", help="Enable the contained " + tool + " tool")
    args = parser.parse_args(argv)

    if args.command == "mcp":
        root = os.path.realpath(args.inputs)
        if not os.path.isdir(root):
            parser.exit(1, "reverseai: MCP --inputs must be an existing directory\n")
        from reverseai.mcp import serve
        enabled = frozenset(tool for tool in ("lief", "yarax", "ghidra", "jadx", "jsparser")
                            if getattr(args, "with_" + tool))
        return serve(sys.stdin.buffer, sys.stdout.buffer, sys.stderr, root=root, enabled=enabled)
    if args.command == "doctor":
        return doctor.main(as_json=args.json)
    if args.command == "prepare":
        from reverseai.tools import ghidra_tool
        from reverseai.ghidra_cache import CacheError, ERRORS, UNSAFE
        from reverseai.contained import ContainedError
        try:
            data, _ = intake.snapshot(args.file)
        except (OSError, ValueError) as error:
            parser.exit(1, f"reverseai: input refused: {type(error).__name__}\n")
        try:
            receipt = ghidra_tool.prepare(data)
        except CacheError as error:
            message = str(error) if str(error) in ERRORS else UNSAFE
            parser.exit(1, f"reverseai: analysis failed: {message}\n")
        except (ContainedError, OSError, ValueError, TimeoutError):
            parser.exit(1, "reverseai: analysis failed: Ghidra preparation failed or exceeded its limits\n")
        if args.json:
            from reverseai.contract import canonical_json
            print(canonical_json(receipt))
        else:
            print(f"Ghidra analysis {receipt['state']}: {receipt['analysis_id']}")
        return 0
    if args.command == "query":
        try:
            checked = queries.parse_args(args.query, args.arg)
        except ValueError as error:
            parser.exit(1, f"reverseai: query refused: {type(error).__name__}\n")
        if queries.TABLE[args.query].role == "code" and not args.with_ghidra:
            parser.exit(1, "reverseai: this query requires --with-ghidra\n")
        if args.query == "analyze_javascript_application" and checked["detail"] in queries.JS_SYNTAX_DETAILS \
                and not args.with_jsparser:
            parser.exit(1, "reverseai: this detail requires --with-jsparser\n")

    try:
        unusable = args.out.is_symlink() or (args.out.exists() and (not args.out.is_dir() or any(args.out.iterdir())))
    except OSError:
        unusable = True
    if unusable:
        parser.exit(1, "reverseai: --out must be a new or empty directory\n")
    tools = pipeline.TOOLS
    for wanted, module, label in ((getattr(args, "with_lief", False), "lief_tool", "LIEF"),
                                  (getattr(args, "with_yarax", False), "yarax_tool", "YARA-X"),
                                  (args.with_ghidra, "ghidra_tool", "Ghidra"),
                                  (getattr(args, "with_jadx", False), "jadx_tool", "JADX"),
                                  (getattr(args, "with_jsparser", False), "jsparser_tool", "JavaScript parser")):
        if not wanted:
            continue
        from importlib import import_module
        from reverseai.contained import ContainedError
        try:
            contained = import_module(f"reverseai.tools.{module}")
            # The lock can change between the check and the build of the tool.
            worker = contained.make_tool() if contained.available() else None
        except (ContainedError, ImportError):
            worker = None
        if worker is None:
            parser.exit(1, f"reverseai: the {label} worker is unavailable (image lock, image or Docker missing)\n")
        tools = tools + (worker,)
    try:
        data, ref = intake.snapshot(args.file)
    except (OSError, ValueError) as error:  # ContractError is a ValueError
        parser.exit(1, f"reverseai: input refused: {type(error).__name__}\n")
    try:
        directory = open_output(args.out)
    except OutputRefused as error:
        parser.exit(1, f"reverseai: output refused: {error}\n")
    written = []
    try:
        try:
            analysis = (pipeline.query_bytes(data, ref, args.query, checked, tools=tools) if args.command == "query"
                        else pipeline.analyze_bytes(data, ref, tools=tools))
            if _on_status is not None:
                incomplete = tuple(dict.fromkeys(
                    (operation.partition(":")[0], result.status)
                    for result in analysis.results if result.status != "ok"
                    for operation in (result.errors or (result.role,))))
                _on_status(tuple(result.status for result in analysis.results),
                           usable=any(verdict.status in ("supported", "derived") for verdict in analysis.verdicts),
                           incomplete=incomplete)
            if args.command == "query" and any(result.status == "error" for result in analysis.results):
                from reverseai.ghidra_cache import ERRORS
                for result in analysis.results:
                    for error in result.errors:
                        message = error.partition(": ")[2]
                        if message in ERRORS:
                            parser.exit(1, "reverseai: query refused: " + message + "\n")
                raise ValueError("Query operation failed")
        except ValueError as error:
            parser.exit(1, f"reverseai: analysis failed: {type(error).__name__}\n")
        for name, render in zip(REPORTS, (report.to_json, report.to_markdown)):
            write_new(directory, name, render(analysis))
            written.append(name)
    except (OSError, ValueError) as error:
        parser.exit(1, f"reverseai: output failed: {type(error).__name__}; written: {', '.join(written) or 'nothing'}\n")
    finally:
        if os.name == "nt":
            pending = sys.exc_info()[0] is not None
            try:
                directory.close()
            except OSError as error:
                if not pending:
                    parser.exit(1, f"reverseai: output failed: {type(error).__name__}; written: {', '.join(written) or 'nothing'}\n")
        else:
            os.close(directory)
    summary = report.to_dict(analysis)["summary"]
    print(f"{analysis.input.sha256}  " + ", ".join(f"{summary[k]} {k}" for k in summary))
    return 0


if __name__ == "__main__":
    sys.exit(main())
