"""Code-built npm tarballs; all JavaScript is inert data, never imported or run.

npm_tgz() and tgz_hostile(kind) return (gzip bytes, layout). Offsets in members,
files, package, hints, modules and calls refer to the decompressed tar or its
declared child as named. Accepted files carry method 1 artifacts;
flagged and empty rows cite their own 512-byte header as a child of the gzip.
"""

import hashlib
import struct
import zlib

from tests import fixtures_js as F

BLOCK = 512
PAX_PATH = 'package/lib/' + 'long-name-' * 12 + 'module.mjs'
PACKAGE = {
    'name': '@fixture/tgz-app', 'version': '1.0.0', 'main': 'index.js', 'type': 'module',
    'scripts': {'preinstall': 'node setup.js', 'postinstall': 'node index.js --install', 'test': 'node --test'},
    'dependencies': {'left-pad': '1.3.0', '@fixture/helper': '^2.0.0'},
}
HOSTILE_KINDS = (
    'symlink', 'hardlink', 'traversal', 'duplicate', 'long_name', 'truncated_tar', 'bad_tar_checksum',
    'gzip_trailing_data', 'gzip_concatenated', 'gzip_crc', 'gzip_isize', 'ratio', 'too_many_entries', 'not_gzip',
)


def gzip_bytes(data, *, level=6):
    """One fixed-header gzip member, without platform-dependent metadata."""
    compressor = zlib.compressobj(level, zlib.DEFLATED, -15)
    body = compressor.compress(data) + compressor.flush()
    return b'\x1f\x8b\x08\x00' + bytes(4) + b'\x00\xff' + body + struct.pack('<II', zlib.crc32(data), len(data))


def _header(name, size=0, kind=b'0', link=''):
    name, link = name.encode('utf-8'), link.encode('utf-8')
    if len(name) > 100 or len(link) > 100:
        raise ValueError('Fixture header field exceeds USTAR width')
    header = bytearray(BLOCK)
    for at, width, value in ((0, 100, name), (100, 8, b'0000644\0'), (108, 8, b'0000000\0'),
                             (116, 8, b'0000000\0'), (124, 12, f'{size:011o}\0'.encode()),
                             (136, 12, b'00000000000\0'), (148, 8, b'        '), (156, 1, kind),
                             (157, 100, link), (257, 6, b'ustar\0'), (263, 2, b'00')):
        header[at:at + width] = value.ljust(width, b'\0')
    header[148:156] = f'{sum(header):06o}\0 '.encode()
    return bytes(header)


def _pax(key, value):
    payload = key.encode() + b'=' + value.encode('utf-8') + b'\n'
    size = len(payload) + 2
    while size != len(str(size)) + 1 + len(payload):
        size = len(str(size)) + 1 + len(payload)
    return str(size).encode() + b' ' + payload


def tar_bytes(entries):
    """Entries are (name, bytes, typeflag, linkname); PAX path records are explicit in the layout."""
    out, members, physical = bytearray(), [], []

    def append(name, child, kind=b'0', link=''):
        at = len(out)
        out.extend(_header(name, len(child), kind, link))
        out.extend(child)
        out.extend(bytes(-len(child) % BLOCK))
        physical.append({'name': name, 'kind': kind.decode(), 'header_offset': at,
                         'data_offset': at + BLOCK, 'size': len(child)})
        return at

    for name, child, kind, link in entries:
        pax = append('PaxHeaders/path', _pax('path', name), b'x') if len(name.encode('utf-8')) > 100 else None
        header_at = append('PaxFile' if pax is not None else name, child, kind, link)
        members.append({'name': name, 'data': child, 'kind': kind.decode(), 'linkname': link,
                        'header_offset': header_at, 'data_offset': header_at + BLOCK,
                        'size': len(child), 'pax_offset': pax})
    out.extend(bytes(2 * BLOCK))
    return bytes(out), {'members': members, 'entries': physical, 'entry_count': len(physical)}


def _wrapped(tar, layout, *, level=6):
    data = gzip_bytes(tar, level=level)
    files = []
    names = [F.escaped(member['name'])[:255] for member in layout.get('members', ())]
    for member, name in zip(layout.get('members', ()), names):
        if member['kind'] == '5' or not F.is_javascript(member['name']):
            continue
        flags = set()
        if member['kind'] in ('1', '2'):
            flags.add('hardlink' if member['kind'] == '1' else 'symlink')
        if member['name'].startswith('../'):
            flags.add('traversing_name')
        if names.count(name) > 1:
            flags.add('duplicate_name')
        if len(F.escaped(member['name'])) > 255:
            flags.add('long_name')
        child = member['data']
        header = bool(flags) or not child
        at = member['header_offset'] if header else member['data_offset']
        payload = tar[at:at + BLOCK] if header else child
        artifact = {'member': name or 'tar header', 'method': 1, 'data_offset': 0,
                    'compressed_size': len(data), 'inner_offset': at, 'size': len(payload),
                    'crc32': zlib.crc32(payload), 'sha256': hashlib.sha256(payload).hexdigest()}
        lines, max_line = F.line_metrics(child)
        files.append({'name': member['name'], 'data': child, 'header_offset': member['header_offset'],
                      'data_offset': member['data_offset'], 'anchor_space': 'tar' if header else 'child',
                      'anchor': {'offset': at if header else 0, 'length': min(len(payload), 4096)},
                      'location': {'offset': 0, 'length': min(len(payload), 4096)},
                      'artifact': artifact,
                      'row': {'file': name, 'size': len(child),
                              'sha256': None if flags else hashlib.sha256(child).hexdigest(),
                              'lines': None if flags else lines, 'max_line': None if flags else max_line,
                              'flags': sorted(flags)}})
    return data, {**layout, 'files': files, 'tar_size': len(tar), 'tar_sha256': hashlib.sha256(tar).hexdigest(),
                  'gzip_size': len(data), 'gzip_sha256': hashlib.sha256(data).hexdigest()}


def npm_tgz():
    package, strings = F.json_text(PACKAGE)
    index, imarks = F.source(
        '// Inert fixture, caf\u00e9; never execute.',
        ('const cp = require(\'', ('child_process', 'child_process'), '\');'),
        ('const endpoint = \'', ('url', 'https://fixture.invalid/collect'), '\';'),
        (('process_call', 'cp.exec('), "'echo fixture');"),
        (('fetch', 'fetch('), 'endpoint);'),
    )
    net, nmarks = F.source(
        ('import { decode } from ', ('module', "'./decode.mjs'"), ';'),
        ('export const open = name => ', ('dynamic_import', 'import(n'), 'ame);'),
        ('export const socket = new ', ('web_socket', 'WebSocket'),
         "('", ('url', 'wss://fixture.invalid/live'), "');"),
    )
    types, tmarks = F.source('export const limit: number = 3;',
                            ('export const decoded = ', ('atob', 'atob('), "'Zml4dHVyZQ==');"))
    entries = [('package/', b'', b'5', ''), ('package/lib/', b'', b'5', ''), ('package/src/', b'', b'5', ''),
               ('package/package.json', package, b'0', ''), ('package/index.js', index, b'0', ''),
               ('package/lib/net.mjs', net, b'0', ''), ('package/src/types.ts', types, b'0', ''),
               (PAX_PATH, b'export const answer = 42;\n', b'0', ''), ('package/empty.js', b'', b'0', ''),
               ('package/README.md', b'Inert fixture; no installation or execution.\n', b'0', '')]
    tar, layout = tar_bytes(entries)
    marks = {'package/index.js': imarks, 'package/lib/net.mjs': nmarks, 'package/src/types.ts': tmarks}
    hints, modules, calls = [], [], []
    categories = {'child_process': 'shell', 'url': 'endpoint', 'process_call': 'shell', 'fetch': 'network',
                  'dynamic_import': 'dynamic_code', 'web_socket': 'network', 'atob': 'encoding'}
    for name, spans in marks.items():
        for span in spans:
            label, at, size = span['label'], span['offset'], span['length']
            if label in categories:
                hints.append({'offset': at, 'length': size, 'row': {'file': name, 'category': categories[label],
                              'hint': label, 'text': span['text'], 'truncated': False}})
            if label in ('process_call', 'fetch', 'web_socket', 'atob'):
                callee = span['text'].removesuffix('(')
                calls.append({'offset': at, 'length': len(callee), 'row': {'file': name, 'callee': callee}})
            if label in ('child_process', 'module'):
                source = span['text'] if label == 'child_process' else span['text'][1:-1]
                modules.append({'offset': at - 1 if label == 'child_process' else at,
                                'length': size + 2 if label == 'child_process' else size,
                                'row': {'file': name, 'form': 'require' if label == 'child_process' else 'import',
                                        'source': source, 'truncated': False}})
    layout.update(marks=marks, hints=hints, modules=modules, calls=calls,
                  package={'name': 'package/package.json', 'data': package, 'strings': strings,
                           'rows': F.package_rows(strings, 'package/package.json')})
    return _wrapped(tar, layout)


def tgz_hostile(kind):
    if kind not in HOSTILE_KINDS:
        raise ValueError('Unknown hostile tarball fixture')
    if kind == 'too_many_entries':
        count = 65537
        tar = b''.join(_header(f'package/f{i}.js') for i in range(count)) + bytes(2 * BLOCK)
        return _wrapped(tar, {'problem': kind, 'entry_count': count}, level=0)
    entries = [('package/index.js', b'eval(code);\n', b'0', '')]
    if kind in ('symlink', 'hardlink'):
        entries = [('package/link.js', b'', b'2' if kind == 'symlink' else b'1', 'outside.js')]
    elif kind == 'traversal':
        entries = [('../outside.js', b'eval(code);\n', b'0', '')]
    elif kind == 'duplicate':
        entries *= 2
    elif kind == 'long_name':
        entries = [('package/' + 'x' * 256 + '.js', b'eval(code);\n', b'0', '')]
    elif kind == 'ratio':
        entries = [('package/zeros.js', bytes(256 * 1024), b'0', '')]
    tar, layout = tar_bytes(entries)
    if kind == 'truncated_tar':
        tar = tar[:layout['members'][0]['data_offset'] + len(entries[0][1]) - 1]
    elif kind == 'bad_tar_checksum':
        tar = bytes([tar[0] ^ 1]) + tar[1:]
    data, layout = _wrapped(tar, {**layout, 'problem': kind})
    if kind == 'gzip_trailing_data':
        data += b'unapproved trailing data'
    elif kind == 'gzip_concatenated':
        data += gzip_bytes(tar)
    elif kind in ('gzip_crc', 'gzip_isize'):
        at = -8 if kind == 'gzip_crc' else -4
        changed = bytearray(data)
        changed[at] ^= 1
        data = bytes(changed)
    elif kind == 'not_gzip':
        data = b'\x1f\x8bnot a gzip stream'
    layout.update(gzip_size=len(data), gzip_sha256=hashlib.sha256(data).hexdigest())
    return data, layout
