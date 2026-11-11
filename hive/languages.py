"""Target languages for the hive: what the bees write and how the queen compiles it.

The hive rebuilds a native program in the language it was most likely written in: C, or
C++ when the program map shows C++ (mangled or qualified names, the C++ runtime's imports).
The operator can force either. Other languages (Java for Android apps, ports to Rust, Go
or Python) are not handled yet.
"""

import os
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Language:
    name: str
    label: str
    extension: str
    header: str
    compiler_env: str
    compiler: str
    standard: str
    syntax_kind: str
    guidance: str

    def cc(self):
        return os.environ.get(self.compiler_env, self.compiler)

    def source(self, module_id):
        return f"{module_id}{self.extension}"


C = Language(
    name="c", label="C", extension=".c", header="contract.h", compiler_env="CC", compiler="cc",
    standard="-std=gnu11", syntax_kind="c",
    guidance="Write C (C11 with GNU extensions allowed). Use plain structs and functions.")
CPP = Language(
    name="cpp", label="C++", extension=".cpp", header="contract.hpp", compiler_env="CXX", compiler="c++",
    standard="-std=gnu++17", syntax_kind="c++",
    guidance=("Write C++17. Rebuild classes with the member layout the assembly shows and pin it with "
              "static_assert(offsetof(...)) and static_assert(sizeof(...)); declare virtual methods in the "
              "vtable order the assembly uses; keep constructors, destructors, exceptions and the standard "
              "library types the binary links (std::string, std::vector, ...) only where the evidence shows them. "
              "Free functions and static members get the names the contract gives them."))
LANGUAGES = {"c": C, "cpp": CPP}

_MANGLED = re.compile(r"^_{1,2}Z[A-Za-z0-9_]")
_CPP_RUNTIME = ("__cxa_throw", "__cxa_begin_catch", "__cxa_allocate_exception", "__gxx_personality_v0",
                "_Unwind_Resume", "__cxa_atexit", "__cxa_guard_acquire", "__dynamic_cast")
_CPP_OPERATORS = ("_Znwm", "_Znam", "_ZdlPv", "_ZdaPv", "_Znwj", "_ZdlPvm")


def detect(program_map):
    """Return ("c" or "cpp", reasons) from the names and imports in the program map."""
    names = [f.get("name") or "" for f in program_map.get("functions", [])]
    imports = [i.lstrip("_") for i in program_map.get("imports", [])]
    reasons = []
    mangled = sum(1 for n in names + program_map.get("imports", []) if _MANGLED.match(n))
    if mangled:
        reasons.append(f"{mangled} mangled C++ names")
    qualified = sum(1 for n in names if "::" in n)
    if qualified:
        reasons.append(f"{qualified} qualified names (Class::method)")
    runtime = sorted({i for i in imports if any(i.endswith(r.lstrip("_")) for r in _CPP_RUNTIME)})
    if runtime:
        reasons.append("C++ runtime imports: " + ", ".join(runtime[:5]))
    operators = sorted({i for i in imports if i.lstrip("_") in {o.lstrip("_") for o in _CPP_OPERATORS}})
    if operators:
        reasons.append("operator new/delete imports: " + ", ".join(operators))
    score = (mangled >= 3) + (qualified >= 3) + bool(runtime) + bool(operators)
    return ("cpp", reasons) if score >= 2 else ("c", reasons or ["no C++ names or runtime imports"])


def choose(requested, program_map):
    """The language for a run: forced by the operator, or detected from the map with `auto`."""
    if requested in LANGUAGES:
        return LANGUAGES[requested], [f"chosen by the operator ({requested})"]
    if requested != "auto":
        raise ValueError(f"unknown language {requested!r}; choose auto, c or cpp")
    name, reasons = detect(program_map)
    return LANGUAGES[name], reasons
