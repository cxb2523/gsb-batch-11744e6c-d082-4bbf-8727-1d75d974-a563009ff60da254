"""Pre-flight: is the program packed or obfuscated? Decided before any bee is spent.

A packed program keeps its real code compressed or encrypted until it runs, so static
analysis sees only the unpacking stub; an obfuscated one hides its logic behind flattened
control flow or a virtual machine. Rebuilding either from static evidence wastes the
whole run. The queen therefore checks first, deterministically, from:

- the segment and section names ReverseAI reports (UPX0, .MPRESS1, .vmp0, ...);
- packer marker strings in the file's own bytes;
- byte entropy of executable segments and of the whole file, computed here from the
  approved file over the ranges ReverseAI reports (compressed or encrypted bytes are
  close to 8 bits per byte; ordinary machine code is well below 7);
- imports that only load more code (LoadLibrary/GetProcAddress, dlopen/dlsym, ...);
- the program map: very few functions or strings for the code size, or one function
  holding most of the code (a dispatcher or VM loop).

Verdicts: "packed" (any strong signal: the queen stops unless the operator allows it),
"suspected" (two or more weak signals: the queen warns), "clean" otherwise. Nothing is
unpacked or executed; unpacking stays the operator's decision. Signals are heuristics:
a clean verdict does not prove the absence of packing or obfuscation.
"""

import json
import math
from pathlib import Path

from reverseai import intake, mcp_tools

PACKER_NAMES = {
    "UPX": ("upx0", "upx1", "upx2", "upx!", ".upx0", ".upx1", "__xhdr", "upx_data"),
    "MPRESS": (".mpress1", ".mpress2"),
    "ASPack": (".aspack", ".adata"),
    "PECompact": ("pec1", "pec2", "pecompact2"),
    "Petite": (".petite",),
    "Themida/WinLicense": (".themida", ".winlice"),
    "VMProtect": (".vmp0", ".vmp1", ".vmp2"),
    "Enigma": (".enigma1", ".enigma2"),
    "NsPack": (".nsp0", ".nsp1", ".nsp2"),
    "Obsidium": (".obsidium",),
    "kkrunchy": ("kkrunchy",),
}
SEGMENT_PACKERS = {name: packer for packer, names in PACKER_NAMES.items() for name in names}
MARKERS = (
    (b"$Info: This file is packed with the UPX", "UPX"),
    (b"UPX!", "UPX"),
    (b"MPRESS1", "MPRESS"),
    (b"kkrunchy", "kkrunchy"),
    (b"VMProtect begin", "VMProtect"),
)
LOADER_IMPORTS = {
    "loadlibrarya", "loadlibraryw", "loadlibraryexa", "loadlibraryexw", "getprocaddress", "virtualalloc",
    "virtualprotect", "virtualfree", "getmodulehandlea", "getmodulehandlew", "exitprocess",
    "dlopen", "dlsym", "dlclose", "mmap", "mprotect", "munmap", "exit", "_exit",
}
STRONG_SEGMENT_ENTROPY = 7.2
WEAK_SEGMENT_ENTROPY = 6.85
STRONG_FILE_ENTROPY = 7.4
MIN_ENTROPY_BYTES = 4096
LARGE_CODE = 64 * 1024


def entropy(data):
    """Shannon entropy in bits per byte (0..8)."""
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    return -sum(c / total * math.log2(c / total) for c in counts if c)


def _bare(name):
    name = name.lower().lstrip("_")
    return name.split("@")[0]


def assess(data, segments, imports, functions=None, strings=None):
    """Signals and verdict from bytes, ReverseAI's segment rows and imports, and the program map.

    segments: rows (name, offset, filesz, address, memsz, readable, writable, executable).
    imports: imported symbol names. functions: [{"size": ...}] or None. strings: count or None.
    """
    signals = []

    def signal(strength, kind, detail, **values):
        signals.append({"strength": strength, "signal": kind, "detail": detail, **values})

    for row in segments:
        packer = SEGMENT_PACKERS.get(str(row[0]).strip().lower())
        if packer:
            signal("strong", "packer section", f"segment or section named {row[0]!r} belongs to {packer}", packer=packer)
    head = data[:1 << 20]
    for marker, packer in MARKERS:
        if marker in head:
            signal("strong", "packer marker", f"the bytes contain {marker.decode(errors='replace')!r} ({packer})",
                   packer=packer)
    code_bytes = 0
    for name, offset, size, _address, _memsz, _r, _w, executable in segments:
        chunk = data[offset:offset + size] if executable and 0 <= offset < len(data) else b""
        if len(chunk) < MIN_ENTROPY_BYTES:  # judge the bytes actually present, not the declared size
            continue
        code_bytes += len(chunk)
        value = round(entropy(chunk), 3)
        if value >= STRONG_SEGMENT_ENTROPY:
            signal("strong", "executable entropy", f"executable segment {name!r} has {value} bits/byte "
                   "(compressed or encrypted)", entropy=value, threshold=STRONG_SEGMENT_ENTROPY)
        elif value >= WEAK_SEGMENT_ENTROPY:
            signal("weak", "executable entropy", f"executable segment {name!r} has {value} bits/byte",
                   entropy=value, threshold=WEAK_SEGMENT_ENTROPY)
    whole = round(entropy(data), 3)
    if len(data) >= MIN_ENTROPY_BYTES and whole >= STRONG_FILE_ENTROPY:
        signal("strong", "file entropy", f"the whole file has {whole} bits/byte", entropy=whole,
               threshold=STRONG_FILE_ENTROPY)
    names = {_bare(i) for i in imports}
    if names and names <= LOADER_IMPORTS:
        signal("weak", "loader-only imports", "every import only loads, maps or protects code: "
               + ", ".join(sorted(names)), imports=len(names))
    elif len(names) <= 3 and code_bytes >= LARGE_CODE:
        signal("weak", "few imports", f"{len(names)} imports for {code_bytes} bytes of executable code",
               imports=len(names))
    if functions is not None and code_bytes >= LARGE_CODE:
        per_64k = len(functions) * LARGE_CODE / code_bytes
        if per_64k < 2:
            signal("weak", "few functions", f"{len(functions)} functions in {code_bytes} bytes of executable code",
                   functions=len(functions))
        sizes = sorted((f.get("size") or 0 for f in functions), reverse=True)
        total = sum(sizes)
        if sizes and total and sizes[0] >= 32 * 1024 and sizes[0] / total >= 0.6:
            signal("weak", "one dominant function", f"one function holds {sizes[0]} of {total} function bytes "
                   "(a dispatcher, VM loop or flattened code)", size=sizes[0])
    if strings is not None and code_bytes >= LARGE_CODE and strings * LARGE_CODE / code_bytes < 1:
        signal("weak", "few strings", f"{strings} referenced strings in {code_bytes} bytes of executable code",
               strings=strings)
    strong = [s for s in signals if s["strength"] == "strong"]
    weak = [s for s in signals if s["strength"] == "weak"]
    verdict = "packed" if strong else "suspected" if len(weak) >= 2 else "clean"
    packers = sorted({s["packer"] for s in strong if s.get("packer")})
    return {"verdict": verdict, "packers": packers, "file_entropy": whole, "executable_bytes": code_bytes,
            "signals": signals,
            "advice": ("Unpack the program statically with the packer's own tool, or analyse the unpacked image, "
                       "then run the hive on that file." if verdict == "packed" else
                       "Rebuilding may fail or waste bees; review the signals before allowing the run."
                       if verdict == "suspected" else "No sign of packing or obfuscation was found.")}


def segment_rows(report):
    rows = []
    for result in report.get("results", []):
        for finding in result.get("findings", []):
            if finding.get("claim_key") == "segments.list" and finding.get("verdict") == "supported":
                rows += finding["value"]["rows"]
    return rows


def imported_symbols(report):
    for result in report.get("results", []):
        for finding in result.get("findings", []):
            if finding.get("claim_key") == "imports.symbols" and finding.get("verdict") == "supported":
                return list(finding["value"])
    return []


def approved_bytes(engine, expected_sha256):
    """Read the approved file the way ReverseAI does, and bind it to the hash the survey saw.

    The same path check as the MCP server (inside the inputs folder, no link anywhere on the way) and the engine's
    intake (one regular file, stable identity while read); a different file, a link or a changed file stops the run.
    """
    from hive.queen import HiveError  # queen imports this module; import at call time
    try:
        path = mcp_tools._input_path(str(engine.inputs), engine.file)
        data, ref = intake.snapshot(path)
    except Exception as error:  # the MCP layer's and intake's own refusals
        raise HiveError(f"pre-flight refused the input: {error}") from None
    if ref.sha256 != expected_sha256:
        raise HiveError("pre-flight refused the input: the approved file changed since the survey")
    return data


def run(engine, program_map, folder):
    """Ask ReverseAI for segments and imports, read the approved file, write preflight.json.

    Every report and the bytes assessed must carry the program map's input hash."""
    from hive.queen import HiveError
    expected = program_map.get("input_sha256")
    if not isinstance(expected, str):
        raise HiveError("pre-flight needs the survey's input hash")

    def bound(report):
        if (report.get("input") or {}).get("sha256") != expected:
            raise HiveError("pre-flight refused a report about a different input")
        return report

    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    rows, start = [], 0
    while True:
        report = bound(engine.query("list_segments", {"start": start, "limit": 64}, folder / f"segments-{start:04d}"))
        page = segment_rows(report)
        rows += page
        start += len(page)
        if len(page) < 64:
            break
    overview = bound(engine.query("binary_overview", {}, folder / "overview"))
    data = approved_bytes(engine, expected)
    result = assess(data, rows, imported_symbols(overview), program_map.get("functions"),
                    len(program_map.get("strings", [])))
    (folder / "preflight.json").write_text(json.dumps(result, indent=1), encoding="utf-8")
    return result
