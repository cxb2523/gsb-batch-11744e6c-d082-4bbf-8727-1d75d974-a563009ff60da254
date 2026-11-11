import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests.hive_compiler import confined
from tests.test_hive_queen import FakePlanning, make_queen
from hive import languages, queen

CXX = shutil.which("c++")

C_MAP = {"functions": [{"name": "FUN_100000a98"}, {"name": "_main"}], "imports": ["_printf", "_exit"]}
CPP_MAP = {"functions": [{"name": "__ZN7Greeter5greetEPKc"}, {"name": "__ZN7GreeterC1Ev"}, {"name": "__ZNK7Greeter4nameEv"},
                         {"name": "_main"}],
           "imports": ["__Znwm", "__ZdlPv", "___cxa_throw", "___gxx_personality_v0", "_printf"]}

ORIGINAL = r'''
#include <cstdio>
struct Greeter { const char *word; explicit Greeter(const char *w) : word(w) {} int greet(const char *n) const; };
int Greeter::greet(const char *n) const { return std::printf("%s %s\n", word, n); }
int main(int argc, char **argv) {
    if (argc < 2) { std::fprintf(stderr, "usage: greet NAME\n"); return 2; }
    Greeter g("hello");
    g.greet(argv[1]);
    return 0;
}
'''
CONTRACT = '''#include <cstdio>
#include <cstddef>
struct Greeter {
    const char *word;
    explicit Greeter(const char *w);
    int greet(const char *name) const; /* 0x1040 */
};
static_assert(sizeof(Greeter) == sizeof(const char *), "Greeter holds one pointer");
int main(int argc, char **argv); /* 0x1000 */
'''
SOURCES = {
    "m01": '#include "contract.hpp"\nGreeter::Greeter(const char *w) : word(w) {}\n'
           'int Greeter::greet(const char *n) const { return std::printf("%s %s\\n", word, n); }\n',
    "m02": '#include "contract.hpp"\nint main(int argc, char **argv) {\n'
           '    if (argc < 2) { std::fprintf(stderr, "usage: greet NAME\\n"); return 2; }\n'
           '    Greeter g("hello");\n    g.greet(argv[1]);\n    return 0;\n}\n',
}


class DetectTests(unittest.TestCase):
    def test_c_and_cpp_programs_are_told_apart(self):
        self.assertEqual(languages.detect(C_MAP)[0], "c")
        name, reasons = languages.detect(CPP_MAP)
        self.assertEqual(name, "cpp")
        self.assertTrue(any("mangled" in r for r in reasons))
        self.assertTrue(any("runtime" in r for r in reasons))

    def test_one_weak_sign_is_not_enough(self):
        self.assertEqual(languages.detect({"functions": [{"name": "_main"}], "imports": ["__Znwm"]})[0], "c")

    def test_the_operator_can_force_a_language(self):
        self.assertEqual(languages.choose("cpp", C_MAP)[0], languages.CPP)
        self.assertEqual(languages.choose("c", CPP_MAP)[0], languages.C)
        self.assertEqual(languages.choose("auto", CPP_MAP)[0], languages.CPP)
        with self.assertRaises(ValueError):
            languages.choose("rust", C_MAP)

    def test_language_files_and_compilers(self):
        self.assertEqual((languages.C.source("m01"), languages.C.header), ("m01.c", "contract.h"))
        self.assertEqual((languages.CPP.source("m01"), languages.CPP.header), ("m01.cpp", "contract.hpp"))
        build = queen.Build(tempfile.mkdtemp(), language=languages.CPP)
        self.assertEqual(build.cflags[0], "-std=gnu++17")
        self.assertIn("-Wall", build.cflags)


class CppEngine:
    file = "greet"

    def __init__(self, inputs):
        self.path = Path(inputs) / self.file

    def prepare(self):
        return {}

    def query(self, name, args, out):
        functions = [{"index": 0, "entry": 0x1000, "name": "_main", "size": 64},
                     {"index": 1, "entry": 0x1040, "name": "__ZNK7Greeter5greetEPKc", "size": 32},
                     {"index": 2, "entry": 0x1060, "name": "__ZN7GreeterC1EPKc", "size": 16},
                     {"index": 3, "entry": 0x1070, "name": "__ZN7GreeterC2EPKc", "size": 16}]
        calls = [{"index": 0, "from": 0x1000, "to": 0x1040, "to_name": "__ZNK7Greeter5greetEPKc"},
                 {"index": 1, "from": 0x1000, "to": 0x9000, "to_name": "___cxa_throw"},
                 {"index": 2, "from": 0x1000, "to": 0x9010, "to_name": "__Znwm"}]
        key, rows = {"functions": ("code.export_functions", functions), "calls": ("code.export_calls", calls),
                     "strings": ("code.export_strings", [])}[args["part"]]
        return {"input": {"sha256": "ef" * 32}, "results": [{"findings": [
            {"claim_key": key, "verdict": "derived", "value": {"rows": rows, "total": len(rows)}}]}]}


class CppBees:
    def __init__(self):
        self.calls = []

    def __call__(self, role, name, task, folder):
        folder = Path(folder)
        self.calls.append((role, name, task))
        if role == "planner":
            (folder / "contract.hpp").write_text(CONTRACT)
            return {"ok": True, "output": {"modules": [{"id": "a", "title": "greeter", "functions": ["0x1040", "0x1060"]},
                                                       {"id": "b", "title": "main", "functions": ["0x1000"]}],
                                           "skipped": [{"entry": "0x1070", "reason": "duplicate constructor"}]}}
        if role == "worker":
            (folder / f"{folder.name}.cpp").write_text(SOURCES[folder.name])
            entries = {"m01": ["0x1040", "0x1060"], "m02": ["0x1000"]}[folder.name]
            return {"ok": True, "output": {"status": "done", "functions": [
                {"entry": entry, "status": "rebuilt"} for entry in entries]}}
        if role == "councillor":
            return {"ok": True, "output": {"verdict": "accept", "defects": []}}
        if role == "tester":
            return {"ok": True, "output": {"cases": [{"id": "none", "steps": [{"args": []}]},
                                                     {"id": "ada", "steps": [{"args": ["ada"]}]}]}}
        raise AssertionError(role)


@unittest.skipUnless(confined("cpp"), "needs a Clang++ compiler the hive can confine")
class CppRunTests(unittest.TestCase):
    def test_a_cpp_program_is_rebuilt_as_cpp(self):
        tmp = Path(tempfile.mkdtemp())
        inputs = tmp / "inputs"
        inputs.mkdir()
        (tmp / "greet.cpp").write_text(ORIGINAL)
        subprocess.run([CXX, "-std=gnu++17", str(tmp / "greet.cpp"), "-o", str(inputs / "greet")], check=True)
        bees = CppBees()

        def check(claims, out):
            return {"claims": 1, "confirmed": 1, "rejected": 0, "questions": 1,
                    "input_sha256": ["ef" * 32]}, []

        hive = make_queen(engine=CppEngine(inputs), out=tmp / "run", bees=bees, slots=2, check=check, planning=FakePlanning(header=CONTRACT),
                           run_original=True, language="auto")
        (tmp / "run" / "modules" / "m01").mkdir(parents=True)
        (tmp / "run" / "modules" / "m01" / "claims.json").write_text(json.dumps({"claims": [
            {"id": "c", "text": "t", "citations": []}]}))
        result = hive.run()
        self.assertEqual(result["language"], "C++")
        self.assertEqual(result["verdict"], "accepted", result["reason"])
        self.assertEqual(result["conformance"]["identical"], 2)
        self.assertTrue((tmp / "run" / "src" / "contract.hpp").is_file())
        seats = list((tmp / "run" / "council").glob("*/unit-*"))
        self.assertTrue(seats and all(seat.suffix == ".cpp" for seat in seats))
        planner_task = next(task for role, _, task in bees.calls if role == "planner")
        self.assertIn("contract.hpp", planner_task)
        self.assertIn("C++", (tmp / "run" / "REPORT.md").read_text())


if __name__ == "__main__":
    unittest.main()
