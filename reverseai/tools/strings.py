"""Bounded printable ASCII strings, stored as ASCII or UTF-16LE, and hints.

Indicators are lexical clues, never proof that the input performs a behavior.
UTF-16LE scanning accepts printable ASCII code points at either byte alignment;
it does not attempt Unicode language detection. Tools only read the given bytes.
"""

import heapq
import re
from types import MappingProxyType

from reverseai.contract import (
    MAX_EXCERPT_BYTES, ArgSpec, Location, Observation, OperationSpec, ToolRef, ToolSpec,
)

# Bound regex backtracking storage even for a single input-sized wide string.
# Adjacent matches are joined as ranges, without copying their contents.
_ASCII = re.compile(rb"[\x20-\x7e]{1,8192}")
_WIDE = re.compile(rb"(?:[\x20-\x7e]\x00){1,2048}")
_CHUNK = 4096
_OVERLAP = 1024  # Longer than the maximum span of every rule below (under 600).
_MAX_INDICATORS = 4096


def _literal(text):
    return r"(?<![A-Za-z0-9_])" + re.escape(text) + r"(?:A|W)?(?![A-Za-z0-9_])"


_OCTET = r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
_RUN_PREFIX = r"(?:(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU)\\)?Software\\Microsoft\\Windows\\CurrentVersion\\"
_RULE_SOURCE = (
    ("url", "network", r"(?<![A-Za-z0-9_])https?://[A-Za-z0-9][A-Za-z0-9.-]{0,252}(?::[0-9]{1,5})?(?:[/?#][A-Za-z0-9._~%!$&*+,;=:@/?#-]{0,256})?"),
    ("ipv4", "network", r"(?<![A-Za-z0-9_.])" + _OCTET + r"(?:\." + _OCTET + r"){3}(?![A-Za-z0-9_.])"),
    ("open_process", "process_injection", _literal("OpenProcess")),
    ("virtual_alloc_ex", "process_injection", _literal("VirtualAllocEx")),
    ("write_process_memory", "process_injection", _literal("WriteProcessMemory")),
    ("create_remote_thread", "process_injection", _literal("CreateRemoteThread")),
    ("nt_map_view_of_section", "process_injection", _literal("NtMapViewOfSection")),
    ("queue_user_apc", "process_injection", _literal("QueueUserAPC")),
    ("registry_run", "persistence", _RUN_PREFIX + r"Run(?![A-Za-z0-9_])"),
    ("registry_run_once", "persistence", _RUN_PREFIX + r"RunOnce(?![A-Za-z0-9_])"),
    ("reg_set_value_ex", "persistence", _literal("RegSetValueEx")),
    ("create_service", "persistence", _literal("CreateService")),
    ("winhttp_open", "network", _literal("WinHttpOpen")),
    ("internet_open", "network", _literal("InternetOpen")),
    ("wsa_startup", "network", _literal("WSAStartup")),
    ("socket", "network", _literal("socket")),
    ("connect", "network", _literal("connect")),
    ("bcrypt_encrypt", "crypto", _literal("BCryptEncrypt")),
    ("crypt_encrypt", "crypto", _literal("CryptEncrypt")),
    ("crypt_acquire_context", "crypto", _literal("CryptAcquireContext")),
    ("is_debugger_present", "anti_debug", _literal("IsDebuggerPresent")),
    ("check_remote_debugger_present", "anti_debug", _literal("CheckRemoteDebuggerPresent")),
    ("nt_query_information_process", "anti_debug", _literal("NtQueryInformationProcess")),
)
_RULES = tuple((name, category, re.compile(pattern, re.IGNORECASE | re.ASCII))
               for name, category, pattern in _RULE_SOURCE)
RULE_CATEGORIES = MappingProxyType({name: category for name, category, _ in _RULES})


def _ranges(data, encoding):
    width, pattern = (1, _ASCII) if encoding == "ascii" else (2, _WIDE)
    start, end = 0, 0
    for match in pattern.finditer(data):
        if match.start() != end:
            if (end - start) // width >= 4:
                yield start, width, (end - start) // width
            start = match.start()
        end = match.end()
    if (end - start) // width >= 4:
        yield start, width, (end - start) // width


def _extract(data, args):
    encoding = args["encoding"]
    observations = []
    for offset, width, length in _ranges(data, encoding):
        if length < args["min_length"]:
            continue
        codec = "ascii" if width == 1 else "utf-16le"
        text = data[offset:offset + min(length, 256) * width].decode(codec)
        observations.append(Observation(
            Location(offset, min(length * width, MAX_EXCERPT_BYTES)),
            {"text": text, "encoding": encoding, "truncated": length > 256},
        ))
        if len(observations) >= args["max_strings"]:
            break
    return observations


def _indicators(data, args):
    observations = []
    regions = heapq.merge(_ranges(data, "ascii"), _ranges(data, "utf16le"))
    for offset, width, length in regions:
        encoding = "ascii" if width == 1 else "utf-16le"
        for start in range(0, length, _CHUNK):
            left = max(0, start - 1)
            right = min(length, start + _CHUNK + _OVERLAP)
            text = data[offset + left * width:offset + right * width].decode(encoding)
            for rule, category, pattern in _RULES:
                for match in pattern.finditer(text):
                    position = left + match.start()
                    if not start <= position < start + _CHUNK:
                        continue
                    observations.append(Observation(
                        Location(offset + position * width, len(match.group()) * width),
                        {"rule": rule, "category": category, "match": match.group()},
                    ))
                    if len(observations) > _MAX_INDICATORS:
                        # One extra item lets the gateway report budget_exceeded
                        # rather than silently describing a complete scan.
                        return sorted(observations, key=lambda item: (item.location.offset, item.value["rule"]))
    return sorted(observations, key=lambda item: (item.location.offset, item.value["rule"]))


def _page(data, args):
    encodings = ("ascii", "utf16le") if args["encoding"] == "any" else (args["encoding"],)
    regions = heapq.merge(*(_ranges(data, encoding) for encoding in encodings))
    minimum, query = args.get("min_length", 4), args.get("query")
    if query is not None and not query.isascii():
        return []  # Both scanners admit only printable ASCII code points.
    page, total = [], 0
    for offset, width, length in regions:
        if length < minimum:
            continue
        encoding = "ascii" if width == 1 else "utf-16le"
        if query is not None and data.find(query.encode(encoding), offset, offset + width * length) < 0:
            continue
        if args["start"] <= total < args["start"] + args["limit"]:
            value = dict(kind="string", index=total, offset=offset, encoding=encoding,
                         text=data[offset:offset + min(length, 256) * width].decode(encoding), truncated=length > 256)
            page.append((Location(offset, min(length * width, MAX_EXCERPT_BYTES)), value))
        total += 1
    return [Observation(location, {**value, "total": total}) for location, value in page]


TOOL = ToolSpec(ToolRef("strings", "0.1.0"), {
    "strings.extract": OperationSpec("strings.extract", {
        "min_length": ArgSpec("int", 4, 64, default=6),
        "encoding": ArgSpec("enum", choices=("ascii", "utf16le"), default="ascii"),
        "max_strings": ArgSpec("int", 1, 4096, default=1024),
    }, _extract, max_observations=4096),
    "strings.indicators": OperationSpec("strings.indicators", {
        "ruleset": ArgSpec("enum", choices=("default",), default="default"),
    }, _indicators, max_observations=_MAX_INDICATORS),
    "strings.list": OperationSpec("strings.list", {
        "encoding": ArgSpec("enum", choices=("any", "ascii", "utf16le"), default="any"),
        "min_length": ArgSpec("int", 4, 64, default=6),
        "start": ArgSpec("int", 0, 1048575, default=0), "limit": ArgSpec("int", 1, 256, default=128),
    }, _page, max_observations=256),
    "strings.search": OperationSpec("strings.search", {
        "query": ArgSpec("literal", 1, 128),
        "encoding": ArgSpec("enum", choices=("any", "ascii", "utf16le"), default="any"),
        "start": ArgSpec("int", 0, 1048575, default=0), "limit": ArgSpec("int", 1, 256, default=64),
    }, _page, max_observations=256),
})
