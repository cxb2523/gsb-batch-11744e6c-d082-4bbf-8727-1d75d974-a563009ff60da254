"""tests/mcp_client.py against a tiny fake stdio server written by the test; no ReverseAI server is needed."""
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest

from tests import mcp_client

# The fake server echoes each request's method and params as its result; "big", "silent", "noisy", "raw" and "flood"
# misbehave on purpose ("raw" writes params.text with {id} replaced, "flood" writes params.count extra replies). With
# --hang it ignores end of input. It reads only its own stdin and writes only its own streams.
FAKE_SERVER = r'''
import json, sys, time
for raw in sys.stdin.buffer:
    message = json.loads(raw)
    if "id" not in message:
        sys.stderr.write("notification " + message["method"] + "\n")
        sys.stderr.flush()
        continue
    method, params = message["method"], message.get("params") or {}
    if method == "silent":
        continue
    if method == "noisy":
        sys.stderr.write("x" * 1024 * 1024)
        sys.stderr.flush()
    if method == "big":
        head = '{"jsonrpc": "2.0", "id": %d, "result": {"pad": "' % message["id"]
        sys.stdout.buffer.write(head.encode() + b"x" * int(params["size"]) + b'"}}\n')
    elif method == "raw":
        sys.stdout.buffer.write(params["text"].replace("{id}", str(message["id"])).encode() + b"\n")
    elif method == "flood":
        line = json.dumps({"jsonrpc": "2.0", "id": 999, "result": {"pad": "y" * int(params.get("width", 10))}})
        sys.stdout.buffer.write((line + "\n").encode() * int(params["count"]))
    else:
        reply = {"jsonrpc": "2.0", "id": message["id"], "result": {"method": method, "params": message.get("params")}}
        sys.stdout.buffer.write(json.dumps(reply).encode() + b"\n")
    sys.stdout.flush()
if "--hang" in sys.argv:
    time.sleep(60)
'''


class ClientTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.script = Path(folder.name, "fake_server.py")
        self.script.write_text(FAKE_SERVER, encoding="utf-8")

    def client(self, *extra, **options):
        client = mcp_client.Client([sys.executable, "-I", str(self.script), *extra], **options)
        self.addCleanup(lambda: client.process.poll() is not None or client.close(timeout=1))
        return client

    def wait_for_failure(self, client):
        deadline = time.monotonic() + 10
        while getattr(client, "failure", None) is None and time.monotonic() < deadline:
            time.sleep(0.02)
        return getattr(client, "failure", None)

    def test_requests_carry_the_modern_meta_and_ids_match_replies(self):
        client = self.client()
        first = client.discover()
        self.assertEqual((first["id"], first["result"]["method"]), (1, "server/discover"))
        self.assertEqual(first["result"]["params"]["_meta"], mcp_client.META)
        self.assertEqual(mcp_client.META["io.modelcontextprotocol/protocolVersion"], "2026-07-28")
        call = client.call_tool("list_files")
        self.assertEqual((call["id"], call["result"]["method"]), (2, "tools/call"))
        self.assertEqual(call["result"]["params"]["name"], "list_files")
        self.assertEqual(call["result"]["params"]["arguments"], {})
        legacy = client.request("initialize", {"protocolVersion": "2025-11-25"}, modern=False)
        self.assertNotIn("_meta", legacy["result"]["params"])
        client.notify("notifications/initialized")
        self.assertEqual(client.request("ping")["id"], 4)  # the notification got no reply and took no id
        error = client.request("raw", {"text": '{"jsonrpc": "2.0", "id": {id}, "error": {"code": -32601, '
                                               '"message": "Method not found"}}'})
        self.assertEqual(error["error"]["code"], -32601)
        brackets = client.request("raw", {"text": '{"jsonrpc": "2.0", "id": {id}, "result": {"s": "' + "[{" * 500 + '"}}'})
        self.assertEqual(len(brackets["result"]["s"]), 1000)  # brackets inside a string are not nesting
        self.assertEqual(client.close(), 0)
        self.assertIn("notification notifications/initialized", client.stderr)

    def test_a_missing_reply_times_out_without_spoiling_the_session(self):
        client = self.client()
        with self.assertRaisesRegex(mcp_client.ClientError, "no reply"):
            client.request("silent", timeout=0.3)
        self.assertIsNone(client.failure)
        self.assertEqual(client.request("ping")["result"]["method"], "ping")
        self.assertEqual(client.close(), 0)

    def test_every_malformed_reply_is_refused_and_the_refusal_is_sticky(self):
        cases = {
            "not JSON": "not json",
            "NaN": '{"jsonrpc": "2.0", "id": {id}, "result": {"x": NaN}}',
            "Infinity": '{"jsonrpc": "2.0", "id": {id}, "result": {"x": -Infinity}}',
            "duplicate key": '{"jsonrpc": "2.0", "id": {id}, "id": {id}, "result": {}}',
            "deep nesting": '{"jsonrpc": "2.0", "id": {id}, "result": {"x": ' + "[" * 100_000 + "]" * 100_000 + "}}",
            "version 1.0": '{"jsonrpc": "1.0", "id": {id}, "result": {}}',
            "boolean id": '{"jsonrpc": "2.0", "id": true, "result": {}}',
            "string id": '{"jsonrpc": "2.0", "id": "{id}", "result": {}}',
            "other id": '{"jsonrpc": "2.0", "id": 7, "result": {}}',
            "result and error": '{"jsonrpc": "2.0", "id": {id}, "result": {}, "error": {"code": 1, "message": "m"}}',
            "neither": '{"jsonrpc": "2.0", "id": {id}}',
            "extra member": '{"jsonrpc": "2.0", "id": {id}, "result": {}, "more": 1}',
            "result not an object": '{"jsonrpc": "2.0", "id": {id}, "result": [1]}',
            "error without code": '{"jsonrpc": "2.0", "id": {id}, "error": {"message": "m"}}',
            "boolean error code": '{"jsonrpc": "2.0", "id": {id}, "error": {"code": true, "message": "m"}}',
            "array": "[{}]",
        }
        for label, text in cases.items():
            with self.subTest(label=label):
                client = self.client()
                with self.assertRaises(mcp_client.ClientError):
                    client.request("raw", {"text": text})
                with self.assertRaises(mcp_client.ClientError):
                    client.request("ping")  # sticky: nothing after a breach is trusted
                self.assertEqual(client.close(), 0)

    def test_replies_nobody_asked_for_are_bounded_in_count(self):
        client = self.client()
        client.send({"jsonrpc": "2.0", "id": 1, "method": "flood", "params": {"count": 2000}})
        self.assertRegex(str(self.wait_for_failure(client)), "more replies than were requested")
        self.assertLessEqual(client.lines.qsize(), mcp_client.MAX_QUEUED_LINES)
        with self.assertRaisesRegex(mcp_client.ClientError, "more replies"):
            client.request("ping")
        self.assertIsNotNone(client.close(timeout=1))

    def test_replies_nobody_asked_for_are_bounded_in_bytes(self):
        client = self.client(max_queued_bytes=10_000)
        client.send({"jsonrpc": "2.0", "id": 1, "method": "flood", "params": {"count": 20, "width": 3000}})
        self.assertRegex(str(self.wait_for_failure(client)), "more reply bytes")
        self.assertLessEqual(client.queued_bytes, 10_000)
        self.assertIsNotNone(client.close(timeout=1))

    def test_a_reply_over_the_size_bound_is_refused_whole_or_partial(self):
        client = self.client(max_line=4096)
        self.assertEqual(len(client.request("big", {"size": 1000})["result"]["pad"]), 1000)
        with self.assertRaisesRegex(mcp_client.ClientError, "longer than the client's limit"):
            client.request("big", {"size": 100_000})  # still unterminated when it passes the limit
        self.assertIsNotNone(client.close(timeout=2))
        client = self.client(max_line=1000)
        with self.assertRaisesRegex(mcp_client.ClientError, "longer than the client's limit"):
            client.request("big", {"size": 5000})  # one complete line in one read
        self.assertIsNotNone(client.close(timeout=2))

    def test_stderr_chatter_does_not_block_and_is_kept_bounded(self):
        client = self.client()
        self.assertEqual(client.request("noisy")["result"]["method"], "noisy")
        self.assertEqual(client.close(), 0)
        self.assertEqual(len(client.stderr), mcp_client.MAX_STDERR)

    def test_close_kills_only_its_own_child_when_it_ignores_end_of_input(self):
        client = self.client("--hang")
        self.assertEqual(client.request("ping")["result"]["method"], "ping")
        code = client.close(timeout=0.5)
        self.assertNotEqual(code, 0)
        self.assertIsNotNone(client.process.poll())

    def test_the_reverseai_command_line_is_fixed(self):
        captured = {}

        class Recorder(mcp_client.Client):
            def __init__(self, argv, **options):
                captured.update(argv=argv, options=options)

        Recorder.reverseai(Path("/inputs"), "--with-ghidra", timeout=5)
        self.assertEqual(captured["argv"], [sys.executable, "-B", "-m", "reverseai", "mcp", "--inputs", "/inputs",
                                            "--with-ghidra"])
        self.assertEqual(captured["options"], {"timeout": 5})


if __name__ == "__main__":
    unittest.main()
