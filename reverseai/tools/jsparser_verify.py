"""Bind contained JavaScript parser offsets to the host's immutable input bytes."""

from dataclasses import dataclass
import json
import re

from reverseai.contract import (
    ContractError, Location, MAX_EXCERPT_BYTES, MAX_WORKER_REPLY_BYTES, Observation,
    WORKER_PROTOCOL, WorkerError,
)
from reverseai.tools import apk, js

REFUSED = "JavaScript parser reply does not match the input"
MAX_FILES = 64
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
_FORMS = ('import', 'export_from', 'require', 'dynamic_import', 'call')


def _check(condition):
    if not condition:
        raise ContractError(REFUSED)


@dataclass(frozen=True)
class _File:
    name: str
    data: bytes
    artifact: dict | None
    dialect: str


def prepare(data, args):
    """Resolve clean source files once; no worker-supplied path reaches the host."""
    from reverseai.tools.jshints import CALLEES

    _check(isinstance(data, bytes))
    try:
        members = js._members(data)
        if members is None:
            if args['file']:
                sources = ()
            else:
                _check(len(data) <= MAX_FILE_BYTES)
                sources = js._sources(data, None)
        else:
            selected = tuple(member for member in members if not js._package_name(member.name)
                             and (not args['file'] or apk.escape(member.name) == args['file']))
            _check(len(selected) <= MAX_FILES and all(member.size <= MAX_FILE_BYTES for member in selected)
                   and sum(member.size for member in selected) <= MAX_TOTAL_BYTES)
            sources = js._sources(data, tuple(member for member in selected if member.size))
        files = []
        for name, child, artifact, member in sources:
            if not child:
                continue
            lower = member.name.translate(js._ASCII_LOWER) if member is not None else ''
            dialect = next((suffix for suffix in ('tsx', 'jsx', 'ts') if lower.endswith('.' + suffix)), 'js')
            files.append(_File(name, child, artifact, dialect))
    except ContractError:
        raise ContractError(REFUSED) from None
    return {'files': [{'artifact': dict(file.artifact) if file.artifact is not None else None,
                      'dialect': file.dialect} for file in files],
            'kind': args['kind'], 'start': args['start'], 'limit': args['limit'],
            'callees': sorted(CALLEES)}, tuple(files)


def _unique(pairs):
    value = {}
    for key, item in pairs:
        _check(key not in value)
        value[key] = item
    return value


def parse_reply(raw, digest):
    _check(isinstance(raw, bytes) and len(raw) <= MAX_WORKER_REPLY_BYTES)
    try:
        reply = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique,
                           parse_constant=lambda value: _check(False))
    except (ValueError, UnicodeError, RecursionError):
        raise ContractError(REFUSED) from None
    _check(isinstance(reply, dict) and reply.get('protocol') == WORKER_PROTOCOL
           and reply.get('snapshot_sha256') == digest)
    if reply.get('status') == 'error':
        _check(set(reply) == {'protocol', 'status', 'snapshot_sha256', 'error'}
               and isinstance(reply['error'], str) and reply['error'] in ('memory', 'timeout', 'input'))
        raise WorkerError(reply['error'])
    _check(set(reply) == {'protocol', 'status', 'snapshot_sha256', 'observations'} and reply.get('status') == 'ok')
    rows = reply['observations']
    _check(isinstance(rows, list) and len(rows) <= MAX_FILES)
    return rows


def _offsets(data, wanted):
    """Only requested UTF-16 boundaries are retained; the middle of a pair is absent."""
    prefix = 3 if data.startswith(b'\xef\xbb\xbf') else 0
    text = data[prefix:].decode('utf-8')
    if not wanted:
        return {}
    units, byte = 0, prefix
    found = {}
    for char in text:
        if units in wanted:
            found[units] = byte
        point = ord(char)
        units += 2 if point > 0xffff else 1
        byte += 1 if point < 0x80 else 2 if point < 0x800 else 3 if point < 0x10000 else 4
    if units in wanted:
        found[units] = byte
    _check(set(found) == wanted)
    return found


def _literal(raw):
    """Decode a complete quoted source literal; no sample expression is evaluated."""
    text = raw.decode('utf-8')
    _check(len(text) >= 2 and text[0] in "\"'`" and text[-1] == text[0])
    quote, stop, at, out = text[0], len(text) - 1, 1, []
    escapes = {'b': '\b', 'f': '\f', 'n': '\n', 'r': '\r', 't': '\t', 'v': '\v'}
    while at < stop:
        char = text[at]
        at += 1
        _check(char != quote)
        if char != '\\':
            _check(quote == '`' or char not in '\r\n')
            _check(not (quote == '`' and char == '$' and at < stop and text[at] == '{'))
            if quote == '`' and char == '\r':
                at += int(at < stop and text[at] == '\n')
                char = '\n'
            out.append(char)
            continue
        _check(at < stop)
        char = text[at]
        at += 1
        if char in '\r\n\u2028\u2029':
            at += int(char == '\r' and at < stop and text[at] == '\n')
            continue
        if char in escapes:
            out.append(escapes[char])
        elif char in ('x', 'u'):
            count = 2 if char == 'x' else 4
            if char == 'u' and at < stop and text[at] == '{':
                end = text.find('}', at + 1, stop)
                _check(end != -1)
                digits = text[at + 1:end]
                _check(bool(re.fullmatch(r'[0-9a-fA-F]+', digits)))
                significant = digits.lstrip('0') or '0'
                _check(len(significant) <= 6)
                point = int(significant, 16)
                _check(point <= 0x10ffff)
                at = end + 1
            else:
                digits = text[at:at + count]
                _check(at + count <= stop and bool(re.fullmatch(r'[0-9a-fA-F]{' + str(count) + '}', digits)))
                point, at = int(digits, 16), at + count
            out.append(chr(point))
        elif char in '01234567':
            _check(quote != '`' or (char == '0' and (at == stop or text[at] not in '0123456789')))
            digits = char
            maximum = 3 if char in '0123' else 2
            while len(digits) < maximum and at < stop and text[at] in '01234567':
                digits += text[at]
                at += 1
            out.append(chr(int(digits, 8)))
        else:
            _check(quote != '`' or char not in '89')
            out.append(char)
    return ''.join(out).encode('utf-16-le', 'surrogatepass').decode('utf-16-le', 'surrogatepass')


def _uint(value):
    return type(value) is int and 0 <= value < 2**32


def anchor(rows, args, files):
    """Text and byte ranges are verified; the parser's syntactic roles stay derived."""
    from reverseai.tools.jshints import CALLEES

    try:
        _check(isinstance(rows, list) and len(rows) == len(files) <= MAX_FILES)
        pending, total = [], 0
        for index, (row, file) in enumerate(zip(rows, files)):
            _check(isinstance(row, dict) and set(row) == {'file', 'status', 'errors', 'count', 'items'}
                   and type(row['file']) is int and row['file'] == index)
            status, errors, count, items = (row[key] for key in ('status', 'errors', 'count', 'items'))
            _check(isinstance(status, str) and status in ('ok', 'syntax_error', 'decode_error', 'too_large')
                   and _uint(errors) and _uint(count) and isinstance(items, list)
                   and len(items) <= args['limit'] and (status == 'syntax_error') == (errors > 0))
            if status in ('decode_error', 'too_large'):
                _check(count == 0 and not items)
            try:
                _offsets(file.data, set())
                decoded = True
            except UnicodeError:
                decoded = False
            _check((status == 'decode_error') == (not decoded) and status != 'too_large')
            if args['kind'] == 'parse':
                _check(count == 0 and not items)
                pending.append((Location(0, min(len(file.data), MAX_EXCERPT_BYTES)),
                                dict(kind='js_parse', file=file.name, status=status, errors=errors), file.artifact))
                continue
            first = max(args['start'], total)
            last = min(args['start'] + args['limit'], total + count)
            _check(len(items) == max(0, last - first))
            previous, wanted = None, set()
            for item in items:
                _check(isinstance(item, dict) and set(item) == {'kind', 'start', 'end'}
                       and isinstance(item['kind'], str) and item['kind'] in _FORMS
                       and _uint(item['start']) and _uint(item['end'])
                       and item['start'] < item['end'] <= len(file.data))
                form = item['kind']
                _check((form == 'call') == (args['kind'] == 'calls'))
                order = (item['start'], item['end'], _FORMS.index(form))
                _check(previous is None or order > previous)
                previous = order
                wanted.update((item['start'], item['end']))
            offsets = _offsets(file.data, wanted) if items else {}
            for position, item in enumerate(items, first):
                start, end = offsets[item['start']], offsets[item['end']]
                raw = file.data[start:end]
                if args['kind'] == 'modules':
                    source, truncated = js._cut(_literal(raw))
                    value = dict(kind='js_module', file=file.name, form=item['kind'], source=source, truncated=truncated)
                else:
                    _check(len(raw) <= 255 and bool(re.fullmatch(rb'[$A-Za-z_][$A-Za-z0-9_]*(?:\.[$A-Za-z_][$A-Za-z0-9_]*){0,3}', raw)))
                    callee = raw.decode('ascii')
                    _check(any(callee == name or callee.endswith('.' + name) for name in CALLEES))
                    value = dict(kind='js_call', file=file.name, callee=callee)
                pending.append((Location(start, min(end - start, MAX_EXCERPT_BYTES)),
                                {**value, 'index': position}, file.artifact))
            total += count
            _check(total < 2**32)
        if args['kind'] == 'parse':
            total = len(pending)
            pending = [(location, {**value, 'index': index}, artifact)
                       for index, (location, value, artifact) in enumerate(pending)
                       if args['start'] <= index < args['start'] + args['limit']]
        return tuple(Observation(location, {**value, 'total': total}, dict(artifact) if artifact is not None else None)
                     for location, value, artifact in pending)
    except (ContractError, UnicodeError, ValueError, TypeError, KeyError):
        raise ContractError(REFUSED) from None


def verify(data, rows, args):
    _, files = prepare(data, args)
    return anchor(rows, args, files)
