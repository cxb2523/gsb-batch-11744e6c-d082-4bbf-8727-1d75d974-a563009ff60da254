"""Bounded RFC 8259 JSON with source byte ranges; UTF-8 BOMs are refused.

Numbers use Decimal's finite range and exact precision, never binary floats.
Tokens include punctuation and keys; EOF and whitespace are not tokens.
"""

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
import json
import re

from reverseai.contract import ContractError

MAX_BYTES = 1024 * 1024
MAX_DEPTH = 64
MAX_TOKENS = 65536
_SPACE = re.compile(rb"[ \t\r\n]*")
_NUMBER = re.compile(rb"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
_HEX = frozenset(b"0123456789abcdefABCDEF")


def _check(condition):
    if not condition:
        raise ContractError("Invalid or over-budget JSON")


@dataclass(frozen=True)
class Token:
    kind: str
    value: object
    start: int
    end: int


@dataclass(frozen=True)
class Node:
    value: object
    start: int
    end: int
    # Array children are nodes; object children are (key token, value node).
    children: tuple = ()


@dataclass(frozen=True)
class Document:
    root: Node
    tokens: tuple


class _Reader:
    def __init__(self, data, max_tokens):
        self.data, self.position, self.tokens = data, 0, []
        self.max_tokens = max_tokens
        self.current = self.next()

    def next(self):
        data = self.data
        start = _SPACE.match(data, self.position).end()
        if start == len(data):
            self.position = start
            return None
        _check(len(self.tokens) < self.max_tokens)
        byte, end = data[start], start + 1
        if byte in b'{}[]:,':
            kind = value = chr(byte)
        elif byte == 34:
            while end < len(data) and data[end] != 34:
                _check(data[end] >= 32)
                if data[end] == 92:
                    end += 1
                    _check(end < len(data) and data[end] in b'"\\/bfnrtu')
                    if data[end] == 117:
                        _check(end + 4 < len(data) and all(c in _HEX for c in data[end + 1:end + 5]))
                        end += 4
                end += 1
            _check(end < len(data))
            end += 1
            value = json.loads(data[start:end])
            _check(not any(0xD800 <= ord(char) <= 0xDFFF for char in value))
            kind = "string"
        else:
            match = _NUMBER.match(data, start)
            if match:
                end, kind = match.end(), "number"
                value = Decimal(data[start:end].decode("ascii"))
            else:
                for spelling, value in ((b"true", True), (b"false", False), (b"null", None)):
                    if data.startswith(spelling, start):
                        end, kind = start + len(spelling), "literal"
                        break
                else:
                    _check(False)
        token = Token(kind, value, start, end)
        self.position = end
        self.tokens.append(token)
        return token

    def take(self, kind):
        token = self.current
        _check(token is not None and token.kind == kind)
        self.current = self.next()
        return token

    def node(self, depth=0):
        token = self.current
        _check(token is not None)
        if token.kind not in ("{", "["):
            _check(token.kind in ("string", "number", "literal"))
            self.take(token.kind)
            return Node(token.value, token.start, token.end)
        _check(depth < MAX_DEPTH)
        opening, closing = token.kind, "}" if token.kind == "{" else "]"
        self.take(opening)
        children, value = [], {} if opening == "{" else []
        if self.current is not None and self.current.kind != closing:
            while True:
                if opening == "{":
                    key = self.take("string")
                    _check(key.value not in value)
                    self.take(":")
                    child = self.node(depth + 1)
                    value[key.value] = child.value
                    children.append((key, child))
                else:
                    child = self.node(depth + 1)
                    value.append(child.value)
                    children.append(child)
                if self.current is None or self.current.kind != ",":
                    break
                self.take(",")
        end = self.take(closing).end
        return Node(value, token.start, end, tuple(children))


def parse(data, *, max_bytes=None, max_tokens=None):
    """Return Document(root, tokens); all spans address the original bytes.

    At most 64 nested containers are admitted. Strings and object keys decode
    JSON escapes; duplicate decoded keys and isolated UTF-16 surrogates fail.
    """
    max_bytes = MAX_BYTES if max_bytes is None else max_bytes
    max_tokens = MAX_TOKENS if max_tokens is None else max_tokens
    _check(type(max_bytes) is int and max_bytes >= 0 and type(max_tokens) is int and max_tokens >= 0)
    _check(isinstance(data, bytes) and len(data) <= max_bytes)
    _check(not data.startswith(b"\xef\xbb\xbf"))
    try:
        reader = _Reader(data, max_tokens)
        root = reader.node()
        _check(reader.current is None)
        return Document(root, tuple(reader.tokens))
    except (UnicodeError, ValueError, InvalidOperation, RecursionError):
        raise ContractError("Invalid or over-budget JSON") from None
