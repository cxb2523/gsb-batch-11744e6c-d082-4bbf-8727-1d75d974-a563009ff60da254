"""Closed query names, typed arguments and fixed operation requests for native, Android and JavaScript inputs."""

from dataclasses import dataclass
import re
from types import MappingProxyType

from reverseai.contract import ArgSpec, ContractError, OperationRequest, OperationSpec
from reverseai import ghidra_args


def _integer(low, high, default=None):
    return ArgSpec("int", low, high, default=default)


START = _integer(0, 65535, 0)
HOST_START = _integer(0, 1048575, 0)
LIMIT = _integer(1, 256, 64)
FUNCTION_ARGS = {
    "select": ArgSpec("enum", choices=("entry", "name"), default="entry"),
    "entry": _integer(0, 2**64 - 1, 0), "name": ArgSpec("str", default=""),
}


@dataclass(frozen=True)
class QuerySpec:
    operations: tuple
    args: object
    role: str = "structural"
    fixed: object = None
    routes: object = None  # operation -> ({operation argument: query argument}, {operation argument: fixed value})
    optional: tuple = ()  # included only when the tool's operation is registered
    details: object = None  # the "detail" argument's value -> routes of the operations it selects
    check: object = None  # (validated arguments) -> None, raising ContractError when they do not fit together
    dispatch: str = "detail"

    def validate(self, raw):
        args = OperationSpec("query.arguments", self.args, lambda data, args: ()).validate_args(raw)
        if self.check is not None:
            self.check(args)
        return args

    def requests(self, args, *, available=()):
        routes = self.details[args[self.dispatch]] if self.details else self.routes

        def arguments(name):
            if routes:
                taken, fixed = routes[name]
                return {**{key: args[source] for key, source in taken.items()}, **fixed}
            return {} if name == "structure.entry" else {**args, **(self.fixed or {})}
        return tuple(OperationRequest(name, arguments(name)) for name in (tuple(routes) if self.details else self.operations)
                     if name not in self.optional or name in available)


def _query(operation, args, *, fixed=None, check=None):
    return QuerySpec((operation,), MappingProxyType(args), "code" if operation.startswith("ghidra.") else "structural",
                     MappingProxyType(fixed or {}), check=check)


def _routes(routes):
    return MappingProxyType(
        {name: (MappingProxyType(dict(zip(taken, taken)) if isinstance(taken, tuple) else taken), MappingProxyType(fixed))
         for name, (taken, fixed) in routes.items()})


def _routed(args, routes, *, optional=()):
    """A query whose operations take different arguments: routes[operation] = ({argument: query argument}, fixed)."""
    return QuerySpec(tuple(routes), MappingProxyType(args), routes=_routes(routes), optional=optional)


def _detailed(args, details, check, *, dispatch="detail", role="structural"):
    """A query whose "detail" argument selects its operations: details[value] = routes as _routed takes them."""
    operations = tuple(dict.fromkeys(name for routes in details.values() for name in routes))
    return QuerySpec(operations, MappingProxyType(args), role=role, details=MappingProxyType(
        {detail: _routes(routes) for detail, routes in details.items()}), check=check, dispatch=dispatch)


# Android: one DEX member by name, or "" for every classes*.dex member;
# exact descriptors and names, in the escaped form displayed in the rows.
ANY_DEX = ArgSpec("identity", 0, 255, default="")
CLASS = ArgSpec("identity", 1, 255)
METHOD_ARGS = {"class": CLASS, "method": ArgSpec("identity", 1, 255), "prototype": ArgSpec("identity", 0, 255, default="")}
ANDROID_LIMIT = _integer(1, 256, 128)

# JavaScript applications: the clean members of a ZIP, or the input itself as file "".
JS_CATEGORIES = ("all", "endpoint", "dynamic_code", "shell", "filesystem", "network", "credential", "encoding")
JS_PAGES = {"files": ("js.files", ("start", "limit")), "package": ("js.package", ("file", "start", "limit")),
            "hints": ("js.hints", ("file", "category", "start", "limit"))}
JS_SYNTAX_DETAILS = ("modules", "calls", "parse")
JS_DEFAULTS = {"file": "", "category": "all", "start": 0}  # what summary reads: the first page of every operation


def _javascript(args):
    """An argument the detail does not pass on must keep its default, so no part of a question is silently dropped;
    js.files and js.package page up to 65535."""
    if args["detail"] in JS_SYNTAX_DETAILS:
        if not args["file"].isascii():
            raise ContractError("Syntax query file must be printable ASCII")
        taken = ("file", "start", "limit")
    else:
        taken = ("limit",) if args["detail"] == "summary" else JS_PAGES[args["detail"]][1]
    if any(args[name] != default for name, default in JS_DEFAULTS.items() if name not in taken):
        raise ContractError("Query argument unused by this detail")
    if args["detail"] in ("files", "package") and args["start"] > 65535:
        raise ContractError("Integer argument out of range")


def _pseudocode(args):
    if args["mode"] == "preview":
        if args["text_start"] != 0:
            raise ContractError("Query argument unused by preview")
    else:
        ghidra_args.check("ghidra.pseudocode", {key: args[key] for key in ghidra_args.OPERATIONS["ghidra.pseudocode"]})


TABLE = MappingProxyType({
    "binary_overview": QuerySpec(tuple("structure." + name for name in ("identify", "headers", "sections", "imports", "entry")),
                                 MappingProxyType({})),
    "list_segments": _query("structure.segments", {"start": START, "limit": LIMIT}),
    "inspect_native_load_image": QuerySpec(("structure.segments", "structure.entry"),
                                           MappingProxyType({"start": START, "limit": LIMIT})),
    "list_names": _query("structure.symbols", {"query": ArgSpec("literal", 0, 128, default=""),
                                               "start": HOST_START, "limit": _integer(1, 256, 128)}),
    "read_bytes": _query("structure.read_bytes", {"mode": ArgSpec("enum", choices=("offset", "address"), default="offset"),
                                                  "at": _integer(0, 2**64 - 1, 0), "length": _integer(1, 2000, 256)}),
    "list_strings": _query("strings.list", {"encoding": ArgSpec("enum", choices=("any", "ascii", "utf16le"), default="any"),
                                            "min_length": _integer(4, 64, 6), "start": HOST_START,
                                            "limit": _integer(1, 256, 128)}),
    "search_strings": _query("strings.search", {"query": ArgSpec("literal", 1, 128),
                                                "encoding": ArgSpec("enum", choices=("any", "ascii", "utf16le"), default="any"),
                                                "start": HOST_START, "limit": LIMIT}),
    "list_procedures": _query("ghidra.functions", {"start": START, "limit": _integer(1, 128, 64)}, fixed={"query": ""}),
    "search_procedures": _query("ghidra.functions", {"query": ArgSpec("str", default=""),
                                                    "start": START, "limit": _integer(1, 128, 64)}),
    **{name: _query("ghidra.function", {**FUNCTION_ARGS, **args}, fixed={"parts": part})
       for name, part, args in (
           ("procedure_info", "info", {}),
           ("procedure_assembly", "assembly", {"start": START, "limit": LIMIT}),
           ("procedure_callees", "callees", {"max_calls": _integer(0, 256, 64)}),
           ("procedure_callers", "callers", {"max_calls": _integer(0, 256, 64)}),
           ("analyze_function", "all", {"start": START, "limit": LIMIT, "max_chars": _integer(64, 2048, 1024),
                                         "max_calls": _integer(0, 256, 64), "max_refs": _integer(0, 128, 64)}))},
    "procedure_pseudo_code": _detailed(
        {**FUNCTION_ARGS, **ghidra_args.TEXT, "mode": ArgSpec("enum", choices=("preview", "paged"), default="preview")},
        {"preview": {"ghidra.function": (("select", "entry", "name", "max_chars"), {"parts": "pseudocode"})},
         "paged": {"ghidra.pseudocode": (("select", "entry", "name", "text_start", "max_chars"), {})}},
        _pseudocode, dispatch="mode", role="code"),
    **{name: _query(operation, ghidra_args.OPERATIONS[operation],
                   check=lambda args, operation=operation: ghidra_args.check(operation, args))
       for name, operation in (("export_function", "ghidra.export_function"), ("export_program", "ghidra.export_program"))},
    "xrefs": _query("ghidra.xrefs", {"address": _integer(0, 2**64 - 1), "start": START, "limit": LIMIT}),
    "inspect_android_package": _routed(
        {"member_start": START, "member_limit": ANDROID_LIMIT, "attribute_start": START,
         "attribute_limit": _integer(1, 256, 256)},
        {"apk.inventory": ({"start": "member_start", "limit": "member_limit"}, {}),
         "apk.manifest": ({"start": "attribute_start", "limit": "attribute_limit"}, {})}),
    "search_android_classes": _query("dex.classes", {"member": ANY_DEX, "query": ArgSpec("literal", 0, 128, default=""),
                                                     "start": HOST_START, "limit": ANDROID_LIMIT}),
    # Exact displayed descriptor for the class row and its methods; search remains a separate query.
    "inspect_android_class": _routed(
        {"member": ANY_DEX, "class": CLASS, "start": START, "limit": ANDROID_LIMIT},
        {"dex.classes": (("member", "class"), {}),
         "dex.methods": (("member", "class", "start", "limit"), {})}),
    "inspect_android_method": _routed(
        {"member": ANY_DEX, **METHOD_ARGS, "start": START, "limit": ANDROID_LIMIT,
         "java_start": HOST_START, "max_chars": _integer(64, 2048, 1024)},
        {"dex.methods": (("member", "class"), {}),
         "dex.references": (("member", "class", "method", "prototype", "start", "limit"), {"direction": "from"}),
         "jadx.method": ({"member": "member", "class": "class", "method": "method", "prototype": "prototype",
                          "start": "java_start", "max_chars": "max_chars"}, {})}, optional=("jadx.method",)),
    "trace_android_references": _query("dex.references", {
        "member": ANY_DEX, **METHOD_ARGS, "direction": ArgSpec("enum", choices=("from", "to"), default="from"),
        "start": START, "limit": ANDROID_LIMIT}),
    # The JavaScript name: summary reads the first page of files, package.json declarations and hints
    "analyze_javascript_application": _detailed(
        {"detail": ArgSpec("enum", choices=("summary", *JS_PAGES, *JS_SYNTAX_DETAILS), default="summary"),
         "file": ArgSpec("literal", 0, 255, default=""), "category": ArgSpec("enum", choices=JS_CATEGORIES, default="all"),
         "start": HOST_START, "limit": _integer(1, 256, 128)},
        {"summary": {operation: (("limit",), {name: JS_DEFAULTS[name] for name in taken if name != "limit"})
                     for operation, taken in JS_PAGES.values()},
         **{detail: {operation: (taken, {})} for detail, (operation, taken) in JS_PAGES.items()},
         **{detail: {"jsparser.syntax": (("file", "start", "limit"), {"kind": detail})}
            for detail in JS_SYNTAX_DETAILS}},
        _javascript),
})


def resolve(name, args):
    if not isinstance(name, str) or name not in TABLE:
        raise ContractError("Unknown query")
    spec = TABLE[name]
    return spec, spec.validate(args)


def parse_args(name, values):
    """CLI KEY=VALUE arguments, with decimal/hex integers and no duplicate keys."""
    if name not in TABLE:
        raise ContractError("Unknown query")
    schema, raw = TABLE[name].args, {}
    for item in values:
        key, separator, value = item.partition("=")
        if not separator or key not in schema or key in raw:
            raise ContractError("Invalid or duplicate query argument")
        if schema[key].kind == "int":
            if len(value) > 32 or not re.fullmatch(r"(?:0[xX][0-9a-fA-F]+|[0-9]+)", value):
                raise ContractError("Invalid query integer")
            value = int(value, 16 if value.lower().startswith("0x") else 10)
        raw[key] = value
    return resolve(name, raw)[1]
