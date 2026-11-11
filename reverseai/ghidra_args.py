"""Closed arguments shared by export queries, tool handlers and the Docker boundary."""

from reverseai.contract import ArgSpec, ContractError, OperationSpec

SELECTOR = {"select": ArgSpec("enum", choices=("entry", "name"), default="entry"),
            "entry": ArgSpec("int", 0, 2**64 - 1, default=0), "name": ArgSpec("str", default="")}
TEXT = {"text_start": ArgSpec("int", 0, 1048576, default=0),
        "max_chars": ArgSpec("int", 64, 2048, default=1024)}
PAGE = {"start": ArgSpec("int", 0, 1048575, default=0), "limit": ArgSpec("int", 1, 128, default=32)}
FUNCTION_PARTS = ("info", "pseudocode", "assembly", "callees", "callers", "references", "strings")
PROGRAM_PARTS = ("functions", "calls", "references", "strings")
OPERATIONS = {
    "ghidra.pseudocode": {**SELECTOR, **TEXT},
    "ghidra.export_function": {**SELECTOR, "part": ArgSpec("enum", choices=FUNCTION_PARTS, default="info"), **PAGE, **TEXT},
    "ghidra.export_program": {"part": ArgSpec("enum", choices=PROGRAM_PARTS, default="functions"), **PAGE},
}


def check(operation, args):
    schema = OPERATIONS[operation]
    checked = OperationSpec(operation, schema, lambda data, checked: ()).validate_args(args)
    if "select" in checked:
        if ((checked["select"] == "entry" and checked["name"] != "")
                or (checked["select"] == "name" and checked["entry"] != 0)):
            raise ContractError("Query argument unused by this selector")
    if operation == "ghidra.export_function":
        unused = (PAGE if checked["part"] == "pseudocode" else TEXT)
        if checked["part"] == "info":
            unused = {**PAGE, **TEXT}
        if any(checked[name] != spec.default for name, spec in unused.items()):
            raise ContractError("Query argument unused by this part")
    return checked
