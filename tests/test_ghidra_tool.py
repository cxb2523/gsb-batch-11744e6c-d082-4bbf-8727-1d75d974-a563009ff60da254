"""Ghidra tool tests use the shared inert fixtures and a canned executor."""

import copy
import importlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from reverseai.contained import ContainedTimeout
from reverseai.ghidra_args import OPERATIONS as EXPORT_OPERATIONS
from reverseai.contract import (
    AnalysisTask, Budget, ContractError, InputRef, MAX_WORKER_REPLY_BYTES, OperationRequest,
    WORKER_PROTOCOL, WorkerError, content_id, sha256_hex,
)
from reverseai.gateway import Gateway
from reverseai.tools import ghidra_tool, ghidra_verify
from tests.fixtures_code import elf_code, pe_code
from tests.fixtures_structure import elf
from tests.test_contained import ghidra_lock
from tests.test_ghidra_verify import ARGS, observations, records, m3c_records


def reply(data, items, **changes):
    value = {"protocol": WORKER_PROTOCOL, "status": "ok", "snapshot_sha256": sha256_hex(data), "observations": items}
    value.update(changes)
    return json.dumps(value).encode()


class FakeExecutor:
    def __init__(self, response):
        self.lock, self.response, self.calls = ghidra_lock(), response, []

    def run(self, operation, args, data, digest):
        self.calls.append((operation, args, data, digest))
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


class ToolTests(unittest.TestCase):
    def setUp(self):
        self.data, self.layout = elf_code()
        self.items = records(self.layout)
        self.executor = FakeExecutor(reply(self.data, self.items))
        self.tool = ghidra_tool.make_tool(self.executor)
        self.operation = self.tool.operations["ghidra.analyze"]

    def test_metadata_defaults_derived_declaration_and_snapshot_binding(self):
        self.assertEqual((self.tool.ref.name, self.tool.ref.version), ("ghidra", "12.1.4-r7"))
        self.assertTrue(self.tool.contained)
        self.assertTrue(self.operation.derived)
        self.assertEqual(self.operation.max_observations, 600)
        self.assertEqual(set(self.tool.operations), {"ghidra.analyze", "ghidra.functions", "ghidra.function", "ghidra.xrefs", *EXPORT_OPERATIONS})
        self.assertEqual(self.tool.runtime, {"image": ghidra_lock()["image_id"], "platform": "linux/arm64"})
        self.assertEqual(self.operation.handler(self.data, {}), observations(self.items))
        self.assertEqual(self.executor.calls, [("ghidra.analyze", ARGS, self.data, sha256_hex(self.data))])
        for generator in (elf_code, pe_code):
            data, layout = generator()
            tool = ghidra_tool.make_tool(FakeExecutor(reply(data, records(layout))))
            self.assertEqual(tool.operations["ghidra.analyze"].handler(data, {}), observations(records(layout)))

    def test_invalid_analyst_arguments_fail_before_the_executor(self):
        for key, low, high in (("max_functions", 1, 128), ("decompile", 0, 16),
                               ("max_chars", 64, 2048), ("max_calls", 0, 256), ("assembly", 0, 8),
                               ("max_instructions", 1, 64), ("max_refs", 0, 128), ("max_strings", 0, 64)):
            for value in (True, low - 1, high + 1, str(low)):
                with self.subTest(key=key, value=value), self.assertRaises(ContractError):
                    self.operation.handler(self.data, {key: value})
        for key in ("path", "script", "loader", "profile", "timeout"):
            with self.subTest(key=key), self.assertRaises(ContractError):
                self.operation.handler(self.data, {key: "untrusted"})
        self.assertEqual(self.executor.calls, [])

    def test_forged_last_anchor_refuses_the_whole_gateway_operation(self):
        items = copy.deepcopy(self.items)
        items[-1]["location"]["offset"] = 0
        self.executor.response = reply(self.data, items)
        task = AnalysisTask(content_id("tk", {"input": sha256_hex(self.data)}), "code", InputRef(sha256_hex(self.data), len(self.data), "inert"),
                            (OperationRequest("ghidra.analyze"),))
        result = Gateway((self.tool,), Budget()).run(task, self.data)
        self.assertEqual(result.status, "error")
        self.assertEqual(result.evidence, ())
        self.assertEqual(len(self.executor.calls), 1)

    def test_bad_replies_and_encoding_are_constant_refusals(self):
        bad_text = copy.deepcopy(self.items)
        bad_text[4]["value"]["text"] = "\ud800"
        bad = (b"\xff", b"{", None, b"x" * (MAX_WORKER_REPLY_BYTES + 1),
               reply(self.data, self.items, snapshot_sha256="0" * 64),
               reply(self.data, self.items, protocol="reverseai.worker/2"),
               reply(self.data, bad_text), reply(self.data, self.items[:1] * 401))
        for raw in bad:
            self.executor.response = raw
            with self.subTest(length=None if raw is None else len(raw)), \
                    self.assertRaisesRegex(ContractError, "^" + ghidra_verify.REFUSED + "$"):
                self.operation.handler(self.data, {})

    def test_worker_error_and_contained_timeout_preserve_their_types(self):
        self.executor.response = json.dumps({"protocol": WORKER_PROTOCOL, "status": "error",
            "snapshot_sha256": sha256_hex(self.data), "error": "AnalysisTimedOut"}).encode()
        with self.assertRaisesRegex(WorkerError, "^AnalysisTimedOut$"):
            self.operation.handler(self.data, {})
        failure = ContainedTimeout("WorkerTimeout")
        self.executor.response = failure
        with self.assertRaises(ContainedTimeout) as caught:
            self.operation.handler(self.data, {})
        self.assertIs(caught.exception, failure)

    def test_a_forged_final_string_refuses_all_code_evidence_atomically(self):
        data, _, items = m3c_records()
        executor = FakeExecutor(reply(data, items))
        tool = ghidra_tool.make_tool(executor)
        task = AnalysisTask(content_id("tk", {"input": sha256_hex(data)}), "code",
                            InputRef(sha256_hex(data), len(data), "inert"), (OperationRequest("ghidra.analyze"),))
        self.assertEqual(Gateway((tool,), Budget()).run(task, data).status, "ok")
        items[-1]["value"]["text"] = "forged"
        executor.response = reply(data, items)
        result = Gateway((tool,), Budget()).run(task, data)
        self.assertEqual(result.status, "error")
        self.assertEqual(result.evidence, ())

    def test_the_exact_maximum_of_400_observations_is_admitted_and_the_next_is_refused(self):
        data, layout = elf(entry=0x1000, sections=((b".text", 1, 6, 8192),))
        data = bytearray(data)
        struct.pack_into("<Q", data, layout["shoff"] + 64 + 16, 0x1000)
        data = bytes(data)
        functions, pseudocode, calls = [], [], []
        for index in range(128):
            entry, offset = 0x1000 + 32 * index, layout["offsets"][0] + 32 * index
            location = {"offset": offset, "length": 16}
            functions.append({"location": location, "value": {
                "kind": "function", "index": index, "entry": entry, "name": f"f{index}", "size": 16}})
            if index < 16:
                pseudocode.append({"location": dict(location), "value": {
                    "kind": "pseudocode", "index": index, "entry": entry, "text": "return;", "truncated": False}})
            for shift in (0, 5):
                calls.append({"location": {"offset": offset + shift, "length": 5}, "value": {
                    "kind": "call", "from": entry, "to": 0, "to_name": "external"}})
        items = functions + pseudocode + calls
        executor = FakeExecutor(reply(data, items))
        handler = ghidra_tool.make_tool(executor).operations["ghidra.analyze"].handler
        args = {"max_functions": 128, "decompile": 16, "max_chars": 64, "max_calls": 256}
        self.assertEqual(len(handler(data, args)), 400)
        executor.response = reply(data, items + calls[:1])
        with self.assertRaises(ContractError):
            handler(data, args)

    def test_import_is_lazy_and_default_factory_uses_the_agreed_adapter(self):
        with patch("reverseai.contained.DockerExecutor") as factory:
            importlib.reload(ghidra_tool)
            factory.assert_not_called()
        importlib.reload(ghidra_tool)
        with patch.object(ghidra_tool, "DockerExecutor", return_value=self.executor) as factory:
            tool = ghidra_tool.make_tool()
            factory.assert_called_once_with(ghidra_tool.DEFAULT_LOCK, adapter_version="12.1.4-r7")
            self.assertTrue(tool.operations["ghidra.analyze"].derived)

    def test_availability_requires_exact_lock_and_local_image_without_host_native_imports(self):
        inspected = []
        def inspect(image):
            inspected.append(image)
            return image
        self.assertTrue(ghidra_tool.available(ghidra_lock(), inspect=inspect))
        self.assertEqual(inspected, [ghidra_lock()["image_id"]])
        for version in ("12.1.4-r1", "12.1.4-r2", "12.1.4-r3", "12.1.4-r4", "12.1.4-r5", "12.1.4-r6"):
            with self.subTest(version=version):
                self.assertFalse(ghidra_tool.available(dict(ghidra_lock(), adapter_version=version), inspect=inspect))
        self.assertFalse(ghidra_tool.available(dict(ghidra_lock(), ghidra_sha256="0" * 64), inspect=inspect))
        self.assertEqual(len(inspected), 1)
        self.assertFalse(ghidra_tool.available(ghidra_lock(), inspect=lambda image: "other"))
        def unavailable(image):
            raise OSError("/private/socket")
        self.assertFalse(ghidra_tool.available(ghidra_lock(), inspect=unavailable))
        with tempfile.TemporaryDirectory() as folder:
            self.assertFalse(ghidra_tool.available(Path(folder) / "missing", inspect=inspect))
        self.assertEqual(len(inspected), 1)

    def test_all_600_observations_can_be_admitted_and_601_is_refused(self):
        data, layout = elf(entry=0x1000, sections=((b".text", 1, 6, 8192), (b".data", 1, 3, 512)))
        data = bytearray(data)
        for index, address in ((1, 0x1000), (2, 0x4000)):
            struct.pack_into("<Q", data, layout["shoff"] + index * 64 + 16, address)
        text, raw = layout["offsets"]
        functions, pseudocode, calls, assembly, refs, strings = [], [], [], [], [], []
        for index in range(128):
            entry, offset = 0x1000 + index * 32, text + index * 32
            location = {"offset": offset, "length": 16}
            functions.append({"location": location, "value": {
                "kind": "function", "index": index, "entry": entry, "name": f"f{index}", "size": 16}})
            if index < 16:
                pseudocode.append({"location": location, "value": {
                    "kind": "pseudocode", "index": index, "entry": entry, "text": "return;", "truncated": False}})
            if index < 8:
                assembly.append({"location": location, "value": {
                    "kind": "assembly", "index": index, "entry": entry,
                    "instructions": [[0, 1, "RET"]], "truncated": False}})
            for delta in (0, 5):
                calls.append({"location": {"offset": offset + delta, "length": 5}, "value": {
                    "kind": "call", "from": entry, "to": 0, "to_name": ""}})
            refs.append({"location": {"offset": offset + 10, "length": 1}, "value": {
                "kind": "ref", "from": entry, "to": 0x4000 + (index % 64) * 8, "type": "data", "to_name": ""}})
        for index in range(64):
            value = f"s{index:02}"
            data[raw + index * 8:raw + index * 8 + 4] = value.encode() + b"\0"
            strings.append({"location": {"offset": raw + index * 8, "length": 3}, "value": {
                "kind": "string", "address": 0x4000 + index * 8, "encoding": "ascii", "text": value,
                "truncated": False, "from": [0x1000 + index * 32, 0x1000 + (index + 64) * 32]}})
        data = bytes(data)
        items = functions + pseudocode + calls + assembly + refs + strings
        executor = FakeExecutor(reply(data, items))
        handler = ghidra_tool.make_tool(executor).operations["ghidra.analyze"].handler
        args = dict(ARGS, max_functions=128, decompile=16, max_calls=256, assembly=8, max_refs=128, max_strings=64)
        self.assertEqual(len(handler(data, args)), 600)
        executor.response = reply(data, items + strings[:1])
        with self.assertRaises(ContractError):
            handler(data, args)


class QueryToolTests(unittest.TestCase):
    DEFAULTS = {
        "ghidra.functions": {"query": "", "start": 0, "limit": 64},
        "ghidra.function": {"select": "entry", "entry": 0, "name": "", "parts": "all", "start": 0,
                            "limit": 64, "max_chars": 1024, "max_calls": 64, "max_refs": 64},
        "ghidra.xrefs": {"address": 0, "start": 0, "limit": 64},
    }

    def test_query_metadata_and_mode_dispatch_are_exact_and_derived(self):
        data, _ = elf_code()
        executor = FakeExecutor(reply(data, []))
        tool = ghidra_tool.make_tool(executor)
        self.assertEqual(set(tool.operations), {"ghidra.analyze", *self.DEFAULTS, *EXPORT_OPERATIONS})
        for operation, expected in self.DEFAULTS.items():
            with self.subTest(operation=operation):
                spec = tool.operations[operation]
                self.assertTrue(spec.derived)
                self.assertEqual(spec.max_observations, {"ghidra.functions": 128, "ghidra.function": 643,
                                                        "ghidra.xrefs": 256}[operation])
                self.assertEqual(set(spec.args), set(expected))
                self.assertTrue(all(arg.kind != "literal" for arg in spec.args.values()))
                raw_args = {"address": 0} if operation == "ghidra.xrefs" else {}
                self.assertEqual(spec.validate_args(raw_args), expected)
                with patch.object(ghidra_verify, "verify") as verify:
                    self.assertEqual(spec.handler(data, raw_args), ())
                    verify.assert_called_once_with(data, (), expected, operation=operation)
                self.assertEqual(executor.calls[-1], (operation, expected, data, sha256_hex(data)))

    def test_query_specs_pin_every_integer_bound_and_enum_choice(self):
        executor = FakeExecutor(reply(b"inert", []))
        tool = ghidra_tool.make_tool(executor)
        self.assertEqual(set(tool.operations), {"ghidra.analyze", *self.DEFAULTS, *EXPORT_OPERATIONS})
        ranges = {
            "ghidra.functions": {"start": (0, 65535), "limit": (1, 128)},
            "ghidra.function": {"entry": (0, 2 ** 64 - 1), "start": (0, 65535), "limit": (1, 256),
                                "max_chars": (64, 2048), "max_calls": (0, 256), "max_refs": (0, 128)},
            "ghidra.xrefs": {"address": (0, 2 ** 64 - 1), "start": (0, 65535), "limit": (1, 256)},
        }
        for operation, bounds in ranges.items():
            spec = tool.operations[operation]
            for key, (low, high) in bounds.items():
                with self.subTest(operation=operation, key=key):
                    self.assertEqual((spec.args[key].kind, spec.args[key].minimum, spec.args[key].maximum),
                                     ("int", low, high))
                for value in (low, high):
                    self.assertEqual(spec.validate_args(dict(self.DEFAULTS[operation], **{key: value}))[key], value)
                for value in (low - 1, high + 1, True, str(low), float(low)):
                    with self.subTest(operation=operation, key=key, value=value), self.assertRaises(ContractError):
                        spec.validate_args(dict(self.DEFAULTS[operation], **{key: value}))
        function_args = tool.operations["ghidra.function"].args
        self.assertEqual((function_args["select"].kind, function_args["select"].choices), ("enum", ("entry", "name")))
        self.assertEqual((function_args["parts"].kind, function_args["parts"].choices),
                         ("enum", ("info", "pseudocode", "assembly", "callees", "callers", "all")))
        self.assertEqual(tool.operations["ghidra.functions"].args["query"].kind, "str")
        self.assertEqual(function_args["name"].kind, "str")
        self.assertEqual(executor.calls, [])

    def test_query_arguments_fail_before_executor_and_xrefs_address_is_required(self):
        data, _ = elf_code()
        executor = FakeExecutor(reply(data, []))
        tool = ghidra_tool.make_tool(executor)
        self.assertEqual(set(tool.operations), {"ghidra.analyze", *self.DEFAULTS, *EXPORT_OPERATIONS})
        for operation, defaults in self.DEFAULTS.items():
            for args in ({"script": "run.py"}, {"profile": "ghidra"}, {"timeout": 999},
                         {"entrypoint": "other"}, {"limit": True}, {"start": -1}):
                with self.subTest(operation=operation, args=args), self.assertRaises(ContractError):
                    tool.operations[operation].handler(data, dict(defaults, **args))
        for operation, key in (("ghidra.functions", "query"), ("ghidra.function", "name")):
            for value in ("-flag", "/host/path", "name\\path", "a" * 257, None, 1):
                with self.subTest(operation=operation, key=key, value=value), self.assertRaises(ContractError):
                    tool.operations[operation].handler(data, {key: value})
        with self.assertRaises(ContractError):
            tool.operations["ghidra.xrefs"].handler(data, {})
        self.assertEqual(executor.calls, [])

    def test_query_parse_limits_and_verifier_failure_are_atomic(self):
        data, _ = elf_code()
        for operation, defaults in self.DEFAULTS.items():
            executor = FakeExecutor(reply(data, []))
            tool = ghidra_tool.make_tool(executor)
            self.assertIn(operation, tool.operations)
            spec = tool.operations[operation]
            with patch.object(ghidra_tool, "parse_worker_reply", return_value=[]) as parse, \
                    patch.object(ghidra_verify, "verify", side_effect=ContractError(ghidra_verify.REFUSED)):
                task = AnalysisTask(content_id("tk", {"operation": operation}), "code",
                                    InputRef(sha256_hex(data), len(data), "inert"),
                                    (OperationRequest(operation, defaults),))
                result = Gateway((tool,), Budget()).run(task, data)
                self.assertEqual(result.status, "error")
                self.assertEqual(result.evidence, ())
                parse.assert_called_once_with(executor.response, input_sha256=sha256_hex(data),
                                               max_observations=spec.max_observations)
