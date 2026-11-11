import copy
import builtins
import importlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from reverseai.contained import ContainedError
from reverseai.contract import ContractError, WorkerError, sha256_hex
from reverseai.tools import yarax_tool
from tests.fixtures_yarax import FakeExecutor, known_matches, match, pattern_table, reply, yarax_lock


class YaraxToolTests(unittest.TestCase):
    def setUp(self):
        self.data, self.matches = known_matches()

    def test_metadata_defaults_and_snapshot_are_bound_to_the_executor(self):
        executor = FakeExecutor(reply(self.data, self.matches))
        tool = yarax_tool.make_tool(executor)
        self.assertEqual((tool.ref.name, tool.ref.version), ("yarax", "1.21.0-r2"))
        self.assertTrue(tool.contained)
        self.assertEqual(tool.runtime, {"image": yarax_lock()["image_id"], "platform": "linux/arm64"})
        self.assertEqual(set(tool.operations), {"yarax.matches"})
        operation = tool.operations["yarax.matches"]
        self.assertEqual(operation.max_observations, 64)
        self.assertEqual(len(operation.handler(self.data, {})), 4)
        self.assertEqual(executor.calls, [("yarax.matches", {"ruleset": "m2_fixture_v1", "max_matches": 32},
                                           self.data, sha256_hex(self.data))])

    def test_invalid_arguments_are_refused_before_executor(self):
        executor = FakeExecutor(reply(self.data))
        operation = yarax_tool.make_tool(executor).operations["yarax.matches"]
        for args in ({"max_matches": 0}, {"max_matches": 65}, {"max_matches": True}, {"max_matches": "64"},
                     {"ruleset": "other"}, {"ruleset": ["m2_fixture_v1"]}, {"rules": "rule arbitrary"},
                     {"path": "/private/input"}, {"entrypoint": "sh"}):
            with self.subTest(args=args), self.assertRaises(ContractError):
                operation.handler(self.data, args)
        self.assertEqual(executor.calls, [])

    def test_counts_1_32_64_are_allowed_but_the_requested_cap_is_not_exceeded(self):
        raw, data, matches = pattern_table()
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "ruleset.json"
            path.write_bytes(raw)
            for count in (1, 32, 64):
                executor = FakeExecutor(reply(data, matches[:count]))
                executor.lock["ruleset_sha256"] = sha256_hex(raw)
                with patch.object(yarax_tool, "RULESET_PATH", path):
                    operation = yarax_tool.make_tool(executor).operations["yarax.matches"]
                self.assertEqual(len(operation.handler(data, {"max_matches": count})), count)
                extra = matches[count:count + 1] or [copy.deepcopy(matches[-1])]
                executor.response = reply(data, matches[:count] + extra)
                with self.subTest(count=count), self.assertRaises(ContractError):
                    operation.handler(data, {"max_matches": count})

    def test_fifth_occurrence_fails_the_whole_operation_after_four_valid_matches(self):
        data = b"UPX!" * 5
        executor = FakeExecutor(reply(data, [match(index * 4) for index in range(5)]))
        with self.assertRaisesRegex(ContractError, "^Worker match not confirmed by the bytes$"):
            yarax_tool.make_tool(executor).operations["yarax.matches"].handler(data, {"max_matches": 64})

    def test_bad_final_observation_refuses_the_entire_reply(self):
        matches = copy.deepcopy(self.matches)
        matches[-1]["value"]["rule"] = "invented"
        operation = yarax_tool.make_tool(FakeExecutor(reply(self.data, matches))).operations["yarax.matches"]
        with self.assertRaisesRegex(ContractError, "^Worker match not confirmed by the bytes$"):
            operation.handler(self.data, {})

    def test_worker_error_bad_digest_protocol_and_location_are_refused(self):
        error = dict(reply(self.data), status="error", error="ScanTimeout")
        del error["observations"]
        with self.assertRaisesRegex(WorkerError, "^ScanTimeout$"):
            yarax_tool.make_tool(FakeExecutor(error)).operations["yarax.matches"].handler(self.data, {})
        for response in (dict(reply(self.data), snapshot_sha256="0" * 64),
                         dict(reply(self.data), protocol="other"), reply(self.data, [match(len(self.data))])):
            with self.subTest(response=response), self.assertRaises(ContractError):
                yarax_tool.make_tool(FakeExecutor(response)).operations["yarax.matches"].handler(self.data, {})

    def test_mismatched_missing_or_changed_local_ruleset_refuses_factory_and_availability(self):
        executor = FakeExecutor(reply(self.data))
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "ruleset.json"
            with patch.object(yarax_tool, "RULESET_PATH", path):
                for raw in (None, b"{}", yarax_tool.RULESET_PATH.name.encode()):
                    if raw is not None:
                        path.write_bytes(raw)
                    with self.assertRaisesRegex(ContainedError, "^InvalidRuleset$"):
                        yarax_tool.make_tool(executor)
                    inspect = unittest.mock.Mock()
                    self.assertFalse(yarax_tool.available(yarax_lock(), inspect=inspect))
                    inspect.assert_not_called()
        self.assertEqual(executor.calls, [])


class AvailabilityTests(unittest.TestCase):
    def test_missing_or_wrong_version_lock_disables_tool_before_inspect(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "lock.json"
            inspect = unittest.mock.Mock()
            self.assertFalse(yarax_tool.available(path, inspect=inspect))
            for value in ({}, dict(yarax_lock(), adapter_version="1.0.0-r2"),
                          {k: v for k, v in yarax_lock().items() if k != "ruleset_sha256"}):
                path.write_text(json.dumps(value))
                self.assertFalse(yarax_tool.available(path, inspect=inspect))
            inspect.assert_not_called()

    def test_image_identity_and_daemon_failure_disable_tool(self):
        self.assertTrue(yarax_tool.available(yarax_lock(), inspect=lambda image: image))
        self.assertFalse(yarax_tool.available(yarax_lock(), inspect=lambda image: "sha256:" + "d" * 64))
        self.assertFalse(yarax_tool.available(yarax_lock(), inspect=unittest.mock.Mock(side_effect=OSError("/private/socket"))))

    def test_import_is_docker_free_and_default_factory_passes_its_own_pins(self):
        original_import = builtins.__import__

        def host_import(name, *args, **kwargs):
            self.assertNotEqual(name.split(".")[0], "yara_x", "native scanning library imported on host")
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=host_import), \
                patch("reverseai.contained.subprocess.Popen", side_effect=AssertionError("unexpected process")):
            importlib.reload(yarax_tool)
            with tempfile.TemporaryDirectory() as folder:
                path = Path(folder) / "lock.json"
                path.write_text(json.dumps(yarax_lock()))
                with patch.object(yarax_tool, "DEFAULT_LOCK", path):
                    tool = yarax_tool.TOOL
                    self.assertEqual(tool.runtime["image"], yarax_lock()["image_id"])
                    path.write_text(json.dumps(dict(yarax_lock(), image_id="sha256:" + "d" * 64)))
                    self.assertNotEqual(yarax_tool.TOOL.runtime["image"], tool.runtime["image"])
                    with patch.object(yarax_tool, "DockerExecutor", wraps=yarax_tool.DockerExecutor) as factory:
                        yarax_tool.make_tool()
                    self.assertEqual(factory.call_args.kwargs,
                                     {"adapter_version": "1.21.0-r2", "extra_keys": ("ruleset_sha256",)})
