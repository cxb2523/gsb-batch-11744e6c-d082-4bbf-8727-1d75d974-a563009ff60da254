"""reverseai --version and the read-only doctor, with stand-in Docker answers; no Docker is called."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import reverseai
from reverseai import cli, contained, doctor
from reverseai.tools import yarax_tool

# The only argv doctor may run, written out here rather than read from doctor, so a changed command fails.
VERSION_ARGV = ["docker", "version", "--format", "{{.Server.Version}}"]
INSPECT_PREFIX = ["docker", "image", "inspect", "--format", "{{.Id}}"]


class StandInDocker:
    """run_bounded stand-in: answers "docker version" and "docker image inspect" only, recording every argv."""
    def __init__(self, server=b"29.8.2\n", present=None):
        self.server, self.present, self.calls = server, present, []

    def __call__(self, argv, *, timeout, max_output, profile="default"):
        self.calls.append((list(argv), timeout))
        if list(argv) == VERSION_ARGV:
            if isinstance(self.server, Exception):
                raise self.server
            return self.server
        if argv[:5] == INSPECT_PREFIX and len(argv) == 6:
            return (argv[5] if self.present is None or argv[5] in self.present else "").encode() + b"\n"
        raise AssertionError(f"unexpected docker call {argv}")


def invoke(*argv, docker=None):
    stdout = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()), \
            patch.object(contained, "run_bounded", docker or StandInDocker()):
        try:
            code = cli.main(list(argv))
        except SystemExit as error:
            code = error.code
    return code, stdout.getvalue()


class VersionTests(unittest.TestCase):
    def test_version_prints_the_package_version_and_exits_zero(self):
        self.assertEqual(invoke("--version"), (0, f"reverseai {reverseai.__version__}\n"))


class DoctorTests(unittest.TestCase):
    def test_docker_gets_one_fixed_version_call_and_each_locked_image_one_inspect(self):
        docker = StandInDocker()
        with patch.object(contained, "run_bounded", docker):
            facts = doctor.collect()
        self.assertEqual(docker.calls[0], (VERSION_ARGV, 10))
        inspected = [argv[5] for argv, timeout in docker.calls[1:]]
        self.assertTrue(all(argv[:5] == INSPECT_PREFIX and timeout == 5 for argv, timeout in docker.calls[1:]))
        self.assertEqual(inspected, [tool["image_id"] for tool in facts["tools"]])
        self.assertEqual(facts["docker"], {"answered": True, "server_version": "29.8.2", "timeout_seconds": 10})
        self.assertEqual([tool["tool"] for tool in facts["tools"]], ["lief", "yarax", "ghidra", "jadx", "jsparser"])
        for tool in facts["tools"]:
            with self.subTest(tool=tool["tool"]):
                self.assertEqual((tool["lock_loads"], tool["image_present"], tool["available"]), (True, True, True))
                self.assertRegex(tool["image_id"], r"\Asha256:[0-9a-f]{64}\Z")
        self.assertEqual(facts["tools"][1]["version"], yarax_tool.REF.version)
        self.assertEqual((facts["reverseai"], facts["host_ok"], facts["python"]["supported"]),
                         (reverseai.__version__, True, True))

    def test_silent_docker_skips_every_image_lookup_and_still_reports_the_locks(self):
        for silence in (contained.ContainedTimeout("WorkerTimeout"), contained.ContainedError("WorkerProcessError")):
            docker = StandInDocker(server=silence)
            with self.subTest(silence=type(silence).__name__), patch.object(contained, "run_bounded", docker):
                facts = doctor.collect()
                self.assertEqual(docker.calls, [(VERSION_ARGV, 10)])
                self.assertEqual(facts["docker"]["answered"], False)
                self.assertTrue(all(tool["lock_loads"] and tool["image_present"] is None and not tool["available"]
                                    for tool in facts["tools"]))
                self.assertIn("docker: no answer within 10 s", doctor.to_text(facts))
                self.assertTrue(facts["host_ok"])

    def test_the_only_process_started_is_the_docker_version_call(self):
        with patch("subprocess.Popen", side_effect=FileNotFoundError("docker")) as popen:
            facts = doctor.collect()
        popen.assert_called_once()
        self.assertEqual(popen.call_args.args[0], VERSION_ARGV)
        self.assertIs(popen.call_args.kwargs["shell"], False)
        self.assertFalse(facts["docker"]["answered"])

    def test_a_changed_docker_command_is_refused_by_the_stand_in(self):
        for argv in (("docker", "pull", "reverseai-control"), ("docker", "build", "."), ("docker", "run", "x")):
            with self.subTest(argv=argv), patch.object(doctor, "DOCKER_VERSION_ARGV", argv), \
                    patch.object(contained, "run_bounded", StandInDocker()), self.assertRaises(AssertionError):
                doctor.collect()

    def test_missing_images_and_unloadable_locks_are_reported_per_tool(self):
        with tempfile.TemporaryDirectory() as folder:
            broken = Path(folder, "image.lock.json")
            broken.write_text("{not json", encoding="utf-8")
            docker = StandInDocker(present=())
            with patch("reverseai.tools.jadx_tool.DEFAULT_LOCK", broken), patch.object(contained, "run_bounded", docker):
                facts = doctor.collect()
        tools = {tool["tool"]: tool for tool in facts["tools"]}
        self.assertEqual((tools["jadx"]["lock_loads"], tools["jadx"]["image_id"], tools["jadx"]["image_present"]),
                         (False, None, None))
        self.assertEqual(tools["jadx"]["lock"], str(broken))
        self.assertTrue(all(tools[name]["lock_loads"] and tools[name]["image_present"] is False
                            and not tools[name]["available"] for name in ("lief", "yarax", "ghidra", "jsparser")))
        text = doctor.to_text(facts)
        self.assertIn("jadx 1.5.6-r1: unavailable: the image lock does not load", text)
        self.assertIn(f"lief 1.0.0-r2: unavailable: image {tools['lief']['image_id']} is not present locally", text)
        self.assertEqual(len(docker.calls), 5)  # the version call and the four loadable locks' images

    def test_an_unexpected_server_answer_is_kept_out_of_the_report(self):
        for raw in (b"29.8.2 extra words\n", b"\xff\xfe", b""):
            with self.subTest(raw=raw), patch.object(contained, "run_bounded", StandInDocker(server=raw)):
                self.assertEqual(doctor.collect()["docker"]["server_version"], "unknown")

    def test_python_before_3_12_exits_one(self):
        with contextlib.redirect_stdout(io.StringIO()) as stdout, \
                patch.object(contained, "run_bounded", StandInDocker()):
            self.assertEqual(doctor.main(version_info=(3, 11, 9)), 1)
        self.assertIn("python 3.11.9", stdout.getvalue())
        self.assertIn("unsupported, needs 3.12 or later", stdout.getvalue())
        self.assertTrue(stdout.getvalue().endswith("host features: not usable\n"))


class DoctorCliTests(unittest.TestCase):
    def test_text_and_json_give_the_same_facts(self):
        code, text = invoke("doctor")
        self.assertEqual(code, 0)
        self.assertEqual(text.splitlines()[0], f"reverseai {reverseai.__version__}")
        self.assertIn("docker: answered (server 29.8.2)", text)
        for name in ("lief", "yarax", "ghidra", "jadx", "jsparser"):
            self.assertRegex(text, rf"\n{name} [0-9][^:]*: available\n")
        code, raw = invoke("doctor", "--json")
        self.assertEqual(code, 0)
        facts = json.loads(raw)
        self.assertEqual(doctor.to_text(facts), text)
        self.assertEqual(sorted(facts), ["docker", "ghidra_cache", "host_ok", "platform", "python", "reverseai", "tools"])

    def test_doctor_takes_no_file_and_no_output_directory(self):
        for extra in (["sample.bin"], ["--out", "reports"]):
            with self.subTest(extra=extra):
                self.assertEqual(invoke("doctor", *extra)[0], 2)


if __name__ == "__main__":
    unittest.main()
