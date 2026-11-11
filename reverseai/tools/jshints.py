"""Bounded lexical JavaScript hints; comments and quoted text are included.

These rules describe occurrences, never execution or parsed JavaScript semantics.
Each regex has a fixed maximum span; scan merges its iterators without retaining
the file's matches. Within one pattern, occurrences do not overlap.
"""

import heapq
import re

from reverseai.contract import ContractError, MAX_EXCERPT_BYTES

MAX_BYTES = 128 * 1024 * 1024
CALLEES = frozenset((
    "eval", "Function", "child_process.exec", "childProcess.exec", "cp.exec",
    "execSync", "execFile", "execFileSync", "spawn", "spawnSync", "fork",
    "runInNewContext", "runInThisContext", "runInContext", "fetch", "XMLHttpRequest", "WebSocket",
    "atob", "btoa", "fromCharCode", "Buffer.from", "http.get", "https.get", "http.request", "https.request",
    "net.connect", "tls.connect", "net.createConnection", "dgram.createSocket",
    "fs.write", "fs.writeSync", "fs.writev", "fs.writevSync", "writeFile", "writeFileSync", "appendFile", "appendFileSync",
    "unlink", "unlinkSync", "rm", "rmSync", "rmdir", "rmdirSync", "chmod", "chmodSync", "fchmod", "fchmodSync",
    "lchmod", "lchmodSync",
))
_LEFT = rb"(?<![A-Za-z0-9_$])"
_RIGHT = rb"(?![A-Za-z0-9_$])"
_WS = rb"[ \t-\r]{0,64}"
_DOT = _WS + rb"\." + _WS
_OPEN = _WS + rb"\("
_OCTET = rb"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
_PORT = rb"(?:6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3}|0)"
_KEY = rb"(?:api[_-]?key|secret|token)"
_ASSIGN_KEY = rb"(?:" + _KEY + _RIGHT + b'|"' + _KEY + b'"' + b"|'" + _KEY + b"')"
_LITERAL = rb'''(?:"(?:[^"\\\r\n]|\\[^\r\n]){1,512}"|'(?:[^'\\\r\n]|\\[^\r\n]){1,512}')'''
# A closed, plain literal is the only loading argument excluded by this rule.
# Concatenations, interpolated templates and escaped spellings remain hints.
_PLAIN = rb'''(?:"[^"\\\r\n]{0,1024}"|'[^'\\\r\n]{0,1024}'|`(?:[^`\\$]|\$(?!\{)){0,1024}`)'''
_DYNAMIC = _WS + rb"(?!" + _PLAIN + _WS + rb"\))[^) \t-\r]"
_PREVIOUS_DOT = re.compile(rb"\.[ \t-\r]{0,64}\Z")
_PREVIOUS_NEW = re.compile(_LEFT + rb"new[ \t-\r]{1,64}\Z")


def _call(source):
    return _LEFT + source + _OPEN


PATTERNS = tuple((name, category, re.compile(source, flags)) for name, category, source, flags in (
    ("url", "endpoint", _LEFT + rb'''(?:https?|wss?|ftp)://[A-Za-z0-9\[][^\x00-\x20\x7f"'<>`\\]{0,4079}''', 0),
    ("ipv4_port", "endpoint", rb"(?<![A-Za-z0-9_$.])" + _OCTET + rb"(?:\." + _OCTET + rb"){3}:" + _PORT + rb"(?![A-Za-z0-9_$.])", 0),
    ("eval", "dynamic_code", _call(rb"eval"), 0),
    ("new_function", "dynamic_code", _call(rb"new" + rb"[ \t-\r]{1,64}" + rb"Function"), 0),
    ("function_constructor", "dynamic_code", _call(rb"Function"), 0),
    ("timer_string", "dynamic_code", _call(rb"set(?:Timeout|Interval)") + _WS + rb'''["'`]''', 0),
    ("vm_run", "dynamic_code", _call(rb"vm" + _DOT + rb"runIn[A-Za-z0-9_$]{1,64}"), 0),
    ("dynamic_import", "dynamic_code", _call(rb"import") + _DYNAMIC, 0),
    ("dynamic_require", "dynamic_code", _call(rb"require") + _DYNAMIC, 0),
    ("child_process", "shell", _LEFT + rb"child_process" + _RIGHT, 0),
    ("process_call", "shell", _call(rb"(?:(?:(?:child_process|childProcess|cp)" + _DOT + rb")?(?P<exec_method>exec)|exec(?:File)?Sync|execFile|spawn(?:Sync)?|fork)"), 0),
    ("fs_mutation", "filesystem", _call(rb"fs" + _DOT + rb"(?:promises" + _DOT + rb")?(?:write(?:File|v)?|appendFile|unlink|rm(?:dir)?|(?:f|l)?chmod)(?:Sync)?"), 0),
    ("process_env", "credential", _LEFT + rb"process" + _DOT + rb"env" + _RIGHT, 0),
    ("fetch", "network", _call(rb"fetch"), 0),
    ("xml_http_request", "network", _LEFT + rb"XMLHttpRequest" + _RIGHT, 0),
    ("web_socket", "network", _LEFT + rb"WebSocket" + _RIGHT, 0),
    ("http_request", "network", _call(rb"https?" + _DOT + rb"(?:request|get)"), 0),
    ("net_connect", "network", _call(rb"net" + _DOT + rb"(?:connect|createConnection)"), 0),
    ("dgram", "network", _LEFT + rb"dgram" + _RIGHT, 0),
    ("aws_access_key", "credential", _LEFT + rb"(?:AKIA|ASIA)[A-Z0-9]{16}" + _RIGHT, 0),
    ("private_key", "credential", rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----", 0),
    ("credential_assignment", "credential", _LEFT + _ASSIGN_KEY + _WS + rb"(?::|=(?![=>]))" + _WS + _LITERAL, re.IGNORECASE),
    ("jwt", "credential", rb"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{5,253}\.[A-Za-z0-9_-]{8,1024}\.[A-Za-z0-9_-]{8,1024}(?![A-Za-z0-9_-])", 0),
    ("atob", "encoding", _call(rb"atob"), 0),
    ("btoa", "encoding", _call(rb"btoa"), 0),
    ("buffer_decode", "encoding", _LEFT + rb"Buffer" + _DOT + rb"from" + _OPEN + rb'''[^,()\r\n]{1,1024},''' + _WS + rb'''(?:'(?:base64|hex)'|"(?:base64|hex)")''' + _WS + rb"\)", 0),
    ("from_char_code", "encoding", _call(rb"String" + _DOT + rb"fromCharCode"), 0),
    ("hex_escapes", "encoding", rb"(?:\\x[0-9A-Fa-f]{2}){8,1024}", 0),
    ("unicode_escapes", "encoding", rb"(?:\\u[0-9A-Fa-f]{4}){8,682}", 0),
))


def _matches(data, order, name, category, pattern):
    for match in pattern.finditer(data):
        start, end = match.span()
        if not 0 < end - start <= MAX_EXCERPT_BYTES:
            raise ContractError("Invalid JavaScript hint span")
        if name == "function_constructor" or (name == "process_call" and match.lastgroup == "exec_method"):
            # Three bytes for 'new', up to 64 whitespace bytes, and its boundary.
            prefix = data[max(0, start - 68):start]
            if name == "process_call" and _PREVIOUS_DOT.search(prefix):
                continue
            if name == "function_constructor" and _PREVIOUS_NEW.search(prefix):
                continue
        yield start, order, end - start, category, name


def scan(data):
    """Yield (offset, length, category, hint), ordered by byte then pattern."""
    if not isinstance(data, bytes) or len(data) > MAX_BYTES:
        raise ContractError("JavaScript input exceeds its limit")
    streams = (_matches(data, order, name, category, pattern)
               for order, (name, category, pattern) in enumerate(PATTERNS))
    for offset, _, length, category, name in heapq.merge(*streams):
        yield offset, length, category, name
