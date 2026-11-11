"""A small stdio MCP client for end-to-end tests; standard library only.

It starts one server process (by default `python -B -m reverseai mcp --inputs DIR`), sends JSON-RPC requests one line
each with the modern per-request `_meta`, and reads one reply line per request with a timeout and a size bound. Two
reader threads drain stdout and stderr, so a chatty server never blocks and the client works where select() cannot
watch pipes. Unread replies are bounded in count and bytes; a reply must be one strict JSON-RPC 2.0 response to the
request (no NaN or Infinity, no duplicate keys, the same integer id, exactly one of result and error). Any breach
makes the client refuse every later read. close() ends stdin, waits with a timeout and kills only its own child.
"""

import json
import os
import queue
import subprocess
import sys
import threading

PROTOCOL_VERSION = "2026-07-28"
META = {"io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
        "io.modelcontextprotocol/clientCapabilities": {}}
MAX_LINE = 4 * 1024 * 1024  # above the server's 256 KiB report text plus 1 MiB of structured content
MAX_STDERR = 64 * 1024
MAX_QUEUED_LINES = 64  # replies the server sent ahead of the requests that asked for them
MAX_QUEUED_BYTES = 16 * 1024 * 1024
MAX_DEPTH = 64  # nested arrays and objects in one reply; json.loads itself may accept far more
CHUNK = 65536


class ClientError(Exception):
    """The server did not answer in time, answered too much, or answered something that is not one JSON reply."""


def _refuse_constant(name):
    raise ValueError("non-finite number " + name)


def _shallow(line, limit):
    """True when arrays and objects nest at most limit deep (brackets inside strings do not count)."""
    if line.count(b"[") + line.count(b"{") <= limit:
        return True
    depth, in_string, escaped = 0, False, False
    for byte in line:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:  # backslash
                escaped = True
            elif byte == 0x22:  # quote
                in_string = False
        elif byte == 0x22:
            in_string = True
        elif byte in (0x5B, 0x7B):
            depth += 1
            if depth > limit:
                return False
        elif byte in (0x5D, 0x7D):
            depth -= 1
    return True


def _unique_object(pairs):
    value = dict(pairs)
    if len(value) != len(pairs):
        raise ValueError("duplicate key")
    return value


class Client:
    def __init__(self, argv, *, cwd=None, env=None, timeout=60.0, max_line=MAX_LINE, max_queued=MAX_QUEUED_LINES,
                 max_queued_bytes=MAX_QUEUED_BYTES):
        self.timeout, self.max_line, self.next_id = timeout, max_line, 0
        self.lines, self.stderr_tail = queue.Queue(maxsize=max_queued), bytearray()
        self.max_queued_bytes, self.queued_bytes, self.counter = max_queued_bytes, 0, threading.Lock()
        self.failure = None  # the first breach; sticky
        self.process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        cwd=cwd, env=env, shell=False)
        self.readers = [threading.Thread(target=self._read_stdout, daemon=True),
                        threading.Thread(target=self._read_stderr, daemon=True)]
        for reader in self.readers:
            reader.start()

    @classmethod
    def reverseai(cls, inputs, *flags, python=sys.executable, **options):
        """The ReverseAI server over DIR, with the operator's --with-... flags."""
        return cls([python, "-B", "-m", "reverseai", "mcp", "--inputs", os.fspath(inputs), *flags], **options)

    def _fail(self, message):
        if self.failure is None:
            self.failure = ClientError(message)
        try:
            self.lines.put_nowait(None)  # wake a waiting read; a full queue wakes it anyway
        except queue.Full:
            pass

    def _queue(self, item, size=0):
        with self.counter:
            if self.queued_bytes + size > self.max_queued_bytes:
                self._fail("the server sent more reply bytes than the client holds")
                return False
            try:
                self.lines.put_nowait(item)
            except queue.Full:
                self._fail("the server sent more replies than were requested")
                return False
            self.queued_bytes += size
            return True

    def _read_stdout(self):
        # Stop reading at the first breach: the server then blocks on a full pipe until close() ends it.
        pending = bytearray()
        while chunk := self.process.stdout.read1(CHUNK):
            pending.extend(chunk)
            while (end := pending.find(b"\n")) >= 0:
                if end > self.max_line:
                    self._fail("reply line longer than the client's limit")
                    return
                if not self._queue(bytes(pending[:end]), end):
                    return
                del pending[:end + 1]
            if len(pending) > self.max_line:
                self._fail("reply line longer than the client's limit")
                return
        self._queue(None)  # end of output

    def _read_stderr(self):
        while chunk := self.process.stderr.read1(CHUNK):
            self.stderr_tail.extend(chunk)
            del self.stderr_tail[:-MAX_STDERR]

    def send(self, message):
        """Write one message as one line; bytes are sent as given (for malformed-input tests)."""
        raw = message if isinstance(message, bytes) else json.dumps(message, separators=(",", ":")).encode("utf-8")
        self.process.stdin.write(raw + b"\n")
        self.process.stdin.flush()

    def read_line(self, timeout=None):
        if self.failure is not None:
            raise self.failure
        try:
            line = self.lines.get(timeout=self.timeout if timeout is None else timeout)
        except queue.Empty:
            raise self.failure or ClientError("no reply within the timeout") from None
        if self.failure is not None:
            raise self.failure
        if line is None:
            raise self.failure or ClientError("the server closed its output")
        with self.counter:
            self.queued_bytes -= len(line)
        return line

    def response(self, line, request_id):
        """One strict JSON-RPC 2.0 response to request_id, else a sticky ClientError."""
        try:
            if not _shallow(line, MAX_DEPTH):
                raise ValueError("nested too deeply")
            reply = json.loads(line, parse_constant=_refuse_constant, object_pairs_hook=_unique_object)
        except (ValueError, RecursionError):
            self._fail("the reply is not strict JSON")
            raise self.failure from None
        error = reply.get("error") if isinstance(reply, dict) else None
        if not (isinstance(reply, dict) and reply.get("jsonrpc") == "2.0" and type(reply.get("id")) is int
                and reply["id"] == request_id and set(reply) in ({"jsonrpc", "id", "result"}, {"jsonrpc", "id", "error"})
                and (isinstance(reply.get("result"), dict) if "result" in reply else
                     isinstance(error, dict) and type(error.get("code")) is int and isinstance(error.get("message"), str))):
            self._fail("the reply is not a JSON-RPC 2.0 response to this request")
            raise self.failure
        return reply

    def request(self, method, params=None, *, modern=True, timeout=None):
        """Send one request and return its reply object (result or error)."""
        self.next_id += 1
        params = dict(params or {})
        if modern:
            params["_meta"] = {**META, **params.get("_meta", {})}
        self.send({"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params})
        return self.response(self.read_line(timeout), self.next_id)

    def notify(self, method, params=None):
        self.send({"jsonrpc": "2.0", "method": method, **({"params": params} if params is not None else {})})

    def discover(self):
        return self.request("server/discover")

    def list_tools(self):
        return self.request("tools/list")

    def call_tool(self, name, arguments=None, *, timeout=None):
        return self.request("tools/call", {"name": name, "arguments": arguments or {}}, timeout=timeout)

    @property
    def stderr(self):
        return bytes(self.stderr_tail).decode("utf-8", "replace")

    def close(self, timeout=10.0):
        """End stdin, wait for the server to exit, kill it (only this child) if it does not; return its exit code."""
        try:
            self.process.stdin.close()
        except OSError:
            pass
        try:
            code = self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.process.kill()
            code = self.process.wait()
        for reader in self.readers:
            reader.join(timeout=5)
        self.process.stdout.close()
        self.process.stderr.close()
        return code

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        if self.process.poll() is None or not self.process.stdin.closed:
            self.close()
