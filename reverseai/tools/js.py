"""Read JavaScript application bytes and package declarations without executing them."""

from reverseai.contract import (
    ArgSpec, ContractError, Location, MAX_EXCERPT_BYTES, Observation, OperationSpec,
    ToolRef, ToolSpec, sha256_hex,
)
from reverseai.tools import apk, asar, jsonpos, tarball

MAX_READ_BYTES = 128 * 1024 * 1024
_SUFFIXES = ('.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx')
_ASCII_LOWER = str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')
_CATEGORIES = ('endpoint', 'dynamic_code', 'shell', 'filesystem', 'network', 'credential', 'encoding')
_FIELDS = frozenset(('name', 'version', 'description', 'main', 'module', 'browser', 'types',
                     'type', 'license', 'homepage'))
_COLLECTIONS = frozenset(('bin', 'exports', 'scripts', 'engines', 'dependencies', 'devDependencies',
                          'peerDependencies', 'optionalDependencies'))


def _package_name(name):
    return name.rsplit('/', 1)[-1].translate(_ASCII_LOWER) == 'package.json'


def _javascript_name(name):
    return name.translate(_ASCII_LOWER).endswith(_SUFFIXES) or _package_name(name)


def _members(data, *, include_flagged=False):
    if data.startswith(tarball.MAGIC):
        return tuple(member for member in tarball.members(data)
                     if _javascript_name(member.name) and (include_flagged or not member.flags))
    if data.startswith(asar.MAGIC):
        return tuple(member for member in asar.members(data)
                     if _javascript_name(member.name) and (include_flagged or not member.flags))
    try:
        return tuple(member for member in apk.members(data)
                     if _javascript_name(member.name) and (include_flagged or not member.flags))
    except apk.ApkError:
        if data.startswith(b'PK\x03\x04'):
            raise ContractError('Invalid JavaScript ZIP container') from None
        return None  # The input itself is the single file, named "".


def _sources(data, members):
    if members is None:
        if len(data) > MAX_READ_BYTES:
            raise ContractError('JavaScript read budget exceeded')
        yield '', data, None, None
        return
    total = 0
    for member in members:
        if member.flags:
            yield apk.escape(member.name), None, None, member
            continue
        total += member.size
        if total > MAX_READ_BYTES:
            raise ContractError('JavaScript read budget exceeded')
        # These clean descriptors came from one parse of these exact bytes.
        archive = (tarball if isinstance(member, tarball.TarMember)
                   else asar if isinstance(member, asar.AsarMember) else apk)
        child, _ = archive._materialize(data, member)
        artifact = None if archive is tarball and not child else archive.artifact(member, child)
        yield apk.escape(member.name), child, artifact, member


def _page(rows, args):
    page, total = [], 0
    for location, value, artifact in rows:
        if args['start'] <= total < args['start'] + args['limit']:
            page.append((location, {**value, 'index': total}, artifact))
        total += 1
    return [Observation(location, {**value, 'total': total}, artifact) for location, value, artifact in page]


def _line_stats(data):
    lines, longest, pending = 0, 0, 0
    for at in range(0, len(data), 65536):
        parts = data[at:at + 65536].split(b'\n')
        lines += len(parts) - 1
        if len(parts) == 1:
            pending += len(parts[0])
        else:
            longest = max(longest, pending + len(parts[0]), max(map(len, parts[1:-1]), default=0))
            pending = len(parts[-1])
    return lines + int(bool(data) and data[-1] != 10), max(longest, pending)


def _header_location(member):
    if isinstance(member, tarball.TarMember):
        return Location(0, tarball.BLOCK), tarball.header_artifact(member)
    return Location(member.central_offset, min(member.central_length, MAX_EXCERPT_BYTES)), None


def _files(data, args):
    def rows():
        for name, child, artifact, member in _sources(data, _members(data, include_flagged=True)):
            if member is not None and member.flags:
                location, artifact = _header_location(member)
                yield location, dict(
                    kind='js_file', file=name, size=member.size, sha256=None, lines=None, max_line=None,
                    flags=list(member.flags)), artifact
                continue
            if not child:
                if member is None:
                    continue  # There is no byte range to cite in an empty input.
                location, artifact = _header_location(member)
            else:
                location = Location(0, min(len(child), MAX_EXCERPT_BYTES))
            lines, longest = _line_stats(child)
            yield location, dict(kind='js_file', file=name, size=len(child), sha256=sha256_hex(child),
                                 lines=lines, max_line=longest, flags=[]), artifact
    return _page(rows(), args)


def _cut(text):
    escaped = apk.escape(text, maximum=266)
    return escaped[:256], len(escaped) > 256


def _pointer(parts):
    raw = '/' + '/'.join(part.replace('~', '~0').replace('/', '~1') for part in parts)
    escaped = apk.escape(raw, maximum=265)
    if len(escaped) > 255:
        raise ContractError('JavaScript JSON pointer exceeds its limit')
    return escaped


def _strings(node, path, depth=0, maximum=None):
    if maximum is not None and depth > maximum:
        return
    if isinstance(node.value, str):
        yield node, path
    elif isinstance(node.value, dict):
        for key, child in node.children:
            yield from _strings(child, (*path, key.value), depth + 1, maximum)
    elif isinstance(node.value, list):
        for index, child in enumerate(node.children):
            yield from _strings(child, (*path, str(index)), depth + 1, maximum)


def _declarations(data):
    root = jsonpos.parse(data).root
    if not isinstance(root.value, dict):
        raise ContractError('JavaScript package must be a JSON object')
    for key, node in root.children:
        name = key.value
        if name in _FIELDS and isinstance(node.value, str):
            yield node, (name,)
        elif name == 'repository':
            if isinstance(node.value, str):
                yield node, (name,)
            elif isinstance(node.value, dict):
                for child_key, child in node.children:
                    if child_key.value == 'url' and isinstance(child.value, str):
                        yield child, (name, 'url')
        elif name in ('bundledDependencies', 'bundleDependencies'):
            if isinstance(node.value, list):
                for index, child in enumerate(node.children):
                    if isinstance(child.value, str):
                        yield child, (name, str(index))
        elif name in _COLLECTIONS and (name in ('bin', 'exports') or isinstance(node.value, (dict, list))):
            yield from _strings(node, (name,), maximum=4 if name == 'exports' else None)


def _package(data, args):
    members = _members(data)
    if members is not None:
        members = tuple(m for m in members if _package_name(m.name)
                        and (not args['file'] or apk.escape(m.name) == args['file']))
        if not args['file'] and members:
            members = (min(members, key=lambda m: m.name.count('/')),)
    elif args['file']:
        return []

    def rows():
        for name, child, artifact, _ in _sources(data, members):
            if members is None and not child.removeprefix(b'\xef\xbb\xbf').lstrip(b' \t\r\n').startswith(b'{'):
                continue
            for node, path in _declarations(child):
                text, truncated = _cut(node.value)
                yield Location(node.start, min(node.end - node.start, MAX_EXCERPT_BYTES)), dict(
                    kind='package_field', file=name, path=_pointer(path), value=text, truncated=truncated), artifact
    return _page(rows(), args)


def _hints(data, args):
    from reverseai.tools import jshints

    members = _members(data)
    if members is not None:
        members = tuple(m for m in members if not _package_name(m.name)
                        and (not args['file'] or apk.escape(m.name) == args['file']))
    elif args['file']:
        return []

    def rows():
        for name, child, artifact, _ in _sources(data, members):
            for offset, length, category, hint in jshints.scan(child):
                if args['category'] != 'all' and args['category'] != category:
                    continue
                text, truncated = _cut(child[offset:offset + length].decode('latin-1'))
                yield Location(offset, min(length, MAX_EXCERPT_BYTES)), dict(
                    kind='js_hint', file=name, category=category, hint=hint, text=text, truncated=truncated), artifact
    return _page(rows(), args)


TOOL = ToolSpec(ToolRef('js', '0.1.0'), {
    'js.files': OperationSpec('js.files', {
        'start': ArgSpec('int', 0, 65535, default=0), 'limit': ArgSpec('int', 1, 256, default=128),
    }, _files, max_observations=256),
    'js.package': OperationSpec('js.package', {
        'file': ArgSpec('literal', 0, 255, default=''),
        'start': ArgSpec('int', 0, 65535, default=0), 'limit': ArgSpec('int', 1, 256, default=128),
    }, _package, max_observations=256),
    'js.hints': OperationSpec('js.hints', {
        'file': ArgSpec('literal', 0, 255, default=''),
        'category': ArgSpec('enum', choices=('all', *_CATEGORIES), default='all'),
        'start': ArgSpec('int', 0, 1048575, default=0), 'limit': ArgSpec('int', 1, 256, default=128),
    }, _hints, max_observations=256),
})
