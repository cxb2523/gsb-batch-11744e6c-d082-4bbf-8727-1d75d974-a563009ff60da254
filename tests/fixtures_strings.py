"""Inert, generated known-answer strings. No executable or external samples."""

ASCII = (
    "OpenProcess VirtualAllocEx WriteProcessMemory CreateRemoteThread",
    "https://example.invalid/submit 203.0.113.7 WinHttpOpen BCryptEncrypt IsDebuggerPresent",
)
WIDE = (
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run RegSetValueExW CryptEncrypt CheckRemoteDebuggerPresent",
    "https://wide.example.invalid/path 198.51.100.42 WSAStartup",
)
KNOWN = (
    ("OpenProcess", "open_process", "process_injection"),
    ("VirtualAllocEx", "virtual_alloc_ex", "process_injection"),
    ("WriteProcessMemory", "write_process_memory", "process_injection"),
    ("CreateRemoteThread", "create_remote_thread", "process_injection"),
    ("https://example.invalid/submit", "url", "network"),
    ("203.0.113.7", "ipv4", "network"),
    ("WinHttpOpen", "winhttp_open", "network"),
    ("BCryptEncrypt", "bcrypt_encrypt", "crypto"),
    ("IsDebuggerPresent", "is_debugger_present", "anti_debug"),
    (r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "registry_run", "persistence"),
    ("RegSetValueExW", "reg_set_value_ex", "persistence"),
    ("CryptEncrypt", "crypt_encrypt", "crypto"),
    ("CheckRemoteDebuggerPresent", "check_remote_debugger_present", "anti_debug"),
    ("https://wide.example.invalid/path", "url", "network"),
    ("198.51.100.42", "ipv4", "network"),
    ("WSAStartup", "wsa_startup", "network"),
)


def known_strings():
    data = bytearray(b"\x01\xff\x00\x02\x03")
    extracts = {"ascii": [], "utf16le": []}
    indicators = []
    for encoding, strings in (("ascii", ASCII), ("utf16le", WIDE)):
        width = 1 if encoding == "ascii" else 2
        for text in strings:
            offset = len(data)
            data.extend(text.encode("ascii" if width == 1 else "utf-16le"))
            data.extend(b"\x00\xff\x00\x01")
            extracts[encoding].append((offset, len(text) * width, {
                "text": text, "encoding": encoding, "truncated": False,
            }))
            for match, rule, category in KNOWN:
                # Whole names: CryptEncrypt is also a substring of BCryptEncrypt.
                start = text.find(match)
                if start < 0 or (start and text[start - 1].isalnum()):
                    continue
                indicators.append((offset + start * width, len(match) * width, {
                    "rule": rule, "category": category, "match": match,
                }))
    return bytes(data), extracts, sorted(indicators, key=lambda item: (item[0], item[2]["rule"]))


def clean_control():
    return b"\x00\xffNeutral fixture with ordinary descriptive words.\x00"
