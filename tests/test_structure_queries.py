"""Known answers and hostile bounds for the verified structure operations."""

import struct
import unittest
import random
from unittest.mock import patch

from reverseai import claims
from reverseai.contract import (AnalysisResult, AnalysisTask, Budget, InputRef, Location, OperationRequest, content_id, make_evidence, make_finding, sha256_hex)
from reverseai.review import review
from reverseai.gateway import Gateway
from reverseai.report import Analysis, to_markdown
from reverseai.tools import structure
from tests.fixtures_code import elf_code, pe_code, macho_code, elf_refs, macho_refs
from tests.fixtures_structure import elf, elf_symbols, pe, pe_exports, macho


def run(operation, data, **args):
    spec = structure.TOOL.operations['structure.' + operation]
    return spec.handler(data, spec.validate_args(args))


def supported(test, data, operation, key, rows, value):
    evidence = tuple(make_evidence(data, structure.REF, 'structure.' + operation, o) for o in rows)
    finding = make_finding('structural', claims.statement(key), key, value, [e.id for e in evidence], 'observed')
    result = AnalysisResult(content_id('tk', {'query': operation}), 'structural', 'ok', evidence, (finding,))
    verdict = review(data, InputRef(sha256_hex(data), len(data), 'fixture'), [result], {'structure': structure.TOOL})
    test.assertEqual(verdict[0].status, 'supported')


class StructureQueryTests(unittest.TestCase):
    def test_operations_are_registered_and_verified(self):
        expected = {'structure.segments', 'structure.entry', 'structure.symbols', 'structure.read_bytes'}
        self.assertTrue(expected <= set(structure.TOOL.operations))
        self.assertTrue(hasattr(structure, 'file_sections'))
        for name in expected:
            self.assertFalse(structure.TOOL.operations[name].derived)

    def test_file_sections_on_all_code_formats(self):
        for builder, name in ((elf_code, '.text'), (pe_code, '.text'), (macho_code, '__TEXT,__text')):
            data, layout = builder()
            with self.subTest(builder=builder.__name__):
                self.assertEqual(structure.file_sections(data)[0], dict(name=name, **layout['text'], executable=True))
                for row in structure.file_sections(data):
                    self.assertGreater(row['size'], 0)
                    self.assertLessEqual(row['offset'] + row['size'], len(data))
        self.assertEqual(structure.file_sections(b''), [])

    def test_file_sections_omit_nobits_zero_fill_and_nonallocated_elf(self):
        data, _ = elf(sections=((b'.bss', 8, 3, 10), (b'.debug', 1, 0, 12)))
        self.assertEqual(structure.file_sections(data), [])
        data, _ = macho(sections=((b'__bss', b'__DATA', 1, 3, 16),))
        self.assertEqual(structure.file_sections(data), [])

    def test_elf_program_header_and_permissions(self):
        data, layout = elf_code()
        rows = run('segments', data)
        value = dict(kind='segment', index=0, total=1, name='LOAD', offset=0, filesz=0x156, address=0x400000,
                     memsz=0x156, readable=True, writable=False, executable=True)
        self.assertEqual([(r.location, r.value) for r in rows], [(Location(64, 56), value)])
        supported(self, data, 'segments', 'segments.list', rows,
                  dict(start=0, total=1, rows=[['LOAD', 0, 0x156, 0x400000, 0x156, True, False, True]]))
        self.assertEqual(run('segments', data, start=1), [])

    def test_elf32_program_headers_in_both_byte_orders(self):
        for order in ('<', '>'):
            data, _ = elf(width=32, order=order, sections=())
            data = bytearray(data)
            at = len(data)
            struct.pack_into(order + 'I', data, 28, at)
            struct.pack_into(order + 'HH', data, 42, 32, 1)
            data += struct.pack(order + '8I', 7, 16, 0x2000, 0, 12, 24, 6, 4)
            rows = run('segments', bytes(data))
            self.assertEqual(rows[0].location, Location(at, 32))
            self.assertEqual(rows[0].value, dict(kind='segment', index=0, total=1, name='TLS', offset=16, filesz=12,
                                               address=0x2000, memsz=24, readable=True, writable=True, executable=False))

    def test_pe_and_macho_segments_are_paged_in_table_order(self):
        for builder, expected in ((pe_code, ['.text', '.data']), (macho_code, ['__PAGEZERO', '__TEXT', '__LINKEDIT'])):
            data, _ = builder()
            rows = run('segments', data)
            self.assertEqual([o.value['name'] for o in rows], expected)
            permissions = [(o.value['readable'], o.value['writable'], o.value['executable']) for o in rows]
            self.assertEqual(permissions, [(True, False, True), (True, True, False)] if builder is pe_code else
                             [(False, False, False), (True, False, True), (True, False, False)])
            page = run('segments', data, start=1, limit=1)
            self.assertEqual(page, rows[1:2])
            self.assertEqual(page[0].value['total'], len(expected))
            fields = ('name', 'offset', 'filesz', 'address', 'memsz', 'readable', 'writable', 'executable')
            supported(self, data, 'segments', 'segments.list', page,
                      dict(start=1, total=len(expected), rows=[[page[0].value[k] for k in fields]]))
        self.assertEqual(run('segments', b'unknown'), [])

    @staticmethod
    def mixed_width_segments(width, *, wrong=True):
        base, _ = macho(width=width, sections=(), entry=None)
        commands = []
        for index in range(3):
            current = 96 - width if wrong and index == 1 else width
            if current == 64:
                command = struct.pack('<II16s4Q4I', 0x19, 72, f'S{index}'.encode(), 0, 0, 0, 0, 0, 0, 0, 0)
            else:
                command = struct.pack('<II16s8I', 1, 56, f'S{index}'.encode(), 0, 0, 0, 0, 0, 0, 0, 0)
            commands.append(command)
        header = bytearray(base[:32 if width == 64 else 28])
        struct.pack_into('<II', header, 16, len(commands), sum(map(len, commands)))
        return bytes(header) + b''.join(commands)

    def test_macho_wrong_width_segment_never_returns_a_complete_prefix(self):
        # An incomplete table is refused instead of returning a silent prefix.
        for width in (32, 64):
            honest = self.mixed_width_segments(width, wrong=False)
            self.assertEqual([o.value['name'] for o in run('segments', honest)], ['S0', 'S1', 'S2'])
            hostile = self.mixed_width_segments(width)
            for start in (0, 1, 2):
                with self.subTest(width=width, start=start):
                    with self.assertRaises(structure.StructureError) as error:
                        run('segments', hostile, start=start, limit=1)
                    self.assertEqual(type(error.exception).__name__, 'MachoSegmentWidthMismatch')

    def test_macho_width_error_reaches_gateway_and_report_without_evidence(self):
        for width in (32, 64):
            with self.subTest(width=width):
                data = self.mixed_width_segments(width)
                ref = InputRef(sha256_hex(data), len(data), 'synthetic')
                task = AnalysisTask(content_id('tk', {'width': width}), 'structural', ref,
                                    (OperationRequest('structure.segments'),), Budget())
                result = Gateway([structure.TOOL], Budget()).run(task, data)
                self.assertEqual(result.status, 'error')
                self.assertEqual(result.evidence, ())
                self.assertEqual(result.errors, ('structure.segments: MachoSegmentWidthMismatch',))
                report = to_markdown(Analysis(ref, (structure.REF,), (result,), ()))
                self.assertIn('structure.segments: MachoSegmentWidthMismatch', report)

    def test_macho_short_segment_still_keeps_its_valid_prefix(self):
        for width in (32, 64):
            data = bytearray(self.mixed_width_segments(width, wrong=False))
            header, stride = (32, 72) if width == 64 else (28, 56)
            struct.pack_into('<I', data, header + stride + 4, 8)
            rows = run('segments', bytes(data))
            self.assertEqual([o.value['name'] for o in rows], ['S0'])
            self.assertEqual(rows[0].value['total'], 1)

    def test_entries_cite_the_declaring_field_on_every_format(self):
        for builder, field in ((elf_code, 24), (pe_code, 104), (macho_code, 440)):
            data, layout = builder()
            rows = run('entry', data)
            expected = dict(kind='entry', address=layout['entry'], offset=layout['text']['offset'])
            self.assertEqual(rows[0].value, expected)
            self.assertEqual(rows[0].location, Location(field, 4 if builder is pe_code else 8))
            supported(self, data, 'entry', 'load.entry', rows, {k: expected[k] for k in ('address', 'offset')})
        data, _ = elf(entry=0)
        self.assertEqual(run('entry', data), [])
        data, _ = elf(entry=0x999999)
        self.assertIsNone(run('entry', data)[0].value['offset'])

    def test_elf32_entry_anchor_and_mapping_in_both_byte_orders(self):
        address, delta = 0x8048000, 7
        for order in ('<', '>'):
            with self.subTest(order=order):
                data, layout = elf(width=32, order=order, machine=3, entry=address + delta,
                                   sections=((b'.text', 1, 0x6, 32),))
                data = bytearray(data)
                struct.pack_into(order + 'I', data, layout['shoff'] + layout['entry_size'] + 12, address)
                data = bytes(data)
                rows = run('entry', data)
                value = dict(address=address + delta, offset=layout['offsets'][0] + delta)
                self.assertEqual([(row.location, row.value) for row in rows],
                                 [(Location(24, 4), dict(kind='entry', **value))])
                supported(self, data, 'entry', 'load.entry', rows, value)

    def test_entry_thread_field_and_zero_pe_entry(self):
        for flavor, machine, delta in (('x86_thread', 0x1000007, 128), ('arm_thread', 0x100000C, 256)):
            data, layout = macho(entry=flavor, machine=machine)
            rows = run('entry', data)
            self.assertEqual(rows[0].value['address'], layout['entry'])
            self.assertEqual(rows[0].location, Location(layout['entry_command'] + 16 + delta, 8))
        data, _ = pe(entry_rva=0)
        self.assertEqual(run('entry', data), [])

    def test_elf_and_macho_symbols_cite_each_name(self):
        for builder, type_ in ((elf_code, 'func'), (macho_code, 'symbol')):
            data, layout = builder()
            rows = run('symbols', data)
            expected = [[f['name'], f['entry'], type_, 'global', True] for f in layout['functions']]
            self.assertEqual([[o.value[k] for k in ('name', 'address', 'type', 'binding', 'defined')] for o in rows], expected)
            for o in rows:
                self.assertEqual(data[o.location.offset:o.location.offset + o.location.length].decode(), o.value['name'])
            supported(self, data, 'symbols', 'symbols.list', rows, dict(start=0, total=4, rows=expected))
            self.assertEqual([o.value['name'] for o in run('symbols', data, query='num')], ['add_numbers'])
            self.assertEqual(run('symbols', data, query='NO_MATCH'), [])
            self.assertEqual(run('symbols', data, start=4), [])
            self.assertEqual(run('symbols', data, start=1, limit=2), rows[1:3])
        self.assertEqual(run('symbols', pe_code()[0]), [])

    def test_elf_symbol_types_bindings_and_dynsym_on_both_widths_and_orders(self):
        expected = [['main', 0x1000, 'func', 'global', True], ['object', 0x2000, 'object', 'local', True],
                    ['weak_import', 0, 'notype', 'weak', False]]
        for width in (32, 64):
            for order in ('<', '>'):
                for dynamic in (False, True):
                    data, _ = elf_symbols(width=width, order=order, dynamic=dynamic)
                    rows = run('symbols', data)
                    with self.subTest(width=width, order=order, dynamic=dynamic):
                        supported(self, data, 'symbols', 'symbols.list', rows, dict(start=0, total=3, rows=expected))

    def test_pe_exports_in_both_optional_header_widths(self):
        for plus in (False, True):
            data, layout = pe_exports(plus=plus)
            rows = run('symbols', data)
            expected = [[s['name'].decode(), s['address'], 'export', 'global', True] for s in layout['symbols']]
            self.assertEqual([o.location.offset for o in rows], [s['offset'] for s in layout['symbols']])
            supported(self, data, 'symbols', 'symbols.list', rows, dict(start=0, total=3, rows=expected))
            self.assertEqual([o.value['name'] for o in run('symbols', data, query='/')], ['slash/name'])

    def test_elf_symtab_precedes_dynsym_and_macho_stabs_are_omitted(self):
        data, layout = elf_symbols()
        changed = bytearray(data)
        symtab = layout['shoff'] + 64
        dynamic = layout['shoff'] + 3 * 64
        changed[dynamic:dynamic + 64] = changed[symtab:symtab + 64]
        struct.pack_into('<I', changed, dynamic + 4, 11)
        offset = len(changed)
        changed += bytes(24) + struct.pack('<IBBHQQ', 1, 0x22, 0, 1, 0x9000, 1)
        struct.pack_into('<QQ', changed, dynamic + 24, offset, 48)
        self.assertEqual([o.value['name'] for o in run('symbols', bytes(changed))], ['main', 'object', 'weak_import'])
        struct.pack_into('<I', changed, symtab + 4, 0)
        fallback = run('symbols', bytes(changed))
        self.assertEqual([(o.value['name'], o.value['address'], o.value['binding']) for o in fallback],
                         [('main', 0x9000, 'weak')])
        data, layout = macho_code(); changed = bytearray(data)
        changed[layout['linkedit'] + 4] = 0xE0
        self.assertEqual([o.value['name'] for o in run('symbols', bytes(changed))], ['add_numbers', 'compute', 'constant'])
        for width in (32, 64):
            data, layout = macho(width=width, symbols=(b'weak_import',), entry=None); changed = bytearray(data)
            stride = 16 if width == 64 else 12
            struct.pack_into('<H', changed, layout['symbols_offset'] + stride + 6, 0x40)
            self.assertEqual(run('symbols', bytes(changed))[0].value['binding'], 'weak')
            self.assertFalse(run('symbols', bytes(changed))[0].value['defined'])

    def test_symbol_names_are_escaped_bounded_and_source_anchored(self):
        data, layout = pe_exports(names=(b'a\x1b\\b', b'x' * 300))
        rows = run('symbols', data)
        self.assertEqual([o.value['name'] for o in rows], ['a\\x1b\\x5cb', 'x' * 128])
        self.assertEqual([o.location.length for o in rows], [4, 128])
        self.assertEqual(run('symbols', data, query='\\x1b')[0].value['name'], 'a\\x1b\\x5cb')

    def test_read_bytes_offset_address_and_section_end(self):
        for builder in (elf_refs, pe_code, macho_refs):
            data, layout = builder()
            at = layout['text']['offset']; address = layout['text']['address']
            rows = run('read_bytes', data, at=at, length=16)
            value = dict(offset=at, address=address, hex=data[at:at + 16].hex())
            self.assertEqual(rows[0].value, dict(kind='bytes', **value))
            supported(self, data, 'read_bytes', 'bytes.read', rows, value)
            self.assertEqual(run('read_bytes', data, mode='address', at=address, length=16), rows)
            tail = run('read_bytes', data, mode='address', at=address + layout['text']['size'] - 1, length=2000)
            self.assertEqual(tail[0].location.length, 1)
            self.assertEqual(run('read_bytes', data, mode='address', at=2**64-1), [])
        rows = run('read_bytes', b'abc', at=1, length=2000)
        self.assertEqual(rows[0].value, dict(kind='bytes', offset=1, address=None, hex='6263'))
        self.assertEqual(run('read_bytes', b'abc', at=3), [])
        self.assertEqual(run('read_bytes', b'', at=0), [])
        self.assertEqual(run('read_bytes', b'x' * 3000, length=2000)[0].location.length, 2000)

    def test_invalid_file_extents_are_not_addressable_sections(self):
        data, layout = elf_code(); changed = bytearray(data)
        struct.pack_into('<Q', changed, layout['shoff'] + 64 + 32, len(data) + 1)
        self.assertEqual(structure.file_sections(bytes(changed)), [])
        self.assertEqual(run('read_bytes', bytes(changed), mode='address', at=layout['entry']), [])
        data, layout = pe_code(); changed = bytearray(data)
        pe = structure._pe_offset(data); table = pe + 24 + struct.unpack_from('<H', data, pe + 20)[0]
        struct.pack_into('<I', changed, table + 20, len(data) + 1)
        self.assertEqual([s['name'] for s in structure.file_sections(bytes(changed))], ['.data'])
        data, layout = macho_code(); changed = bytearray(data)
        struct.pack_into('<I', changed, 104 + 72 + 48, layout['linkedit'])
        self.assertEqual(structure.file_sections(bytes(changed)), [])

    def test_ambiguous_mappings_and_nested_intervals(self):
        data, layout = elf_refs(); changed = bytearray(data)
        header = layout['shoff'] + 3 * 64
        struct.pack_into('<I', changed, header + 4, 1)
        struct.pack_into('<Q', changed, header + 8, 2)
        struct.pack_into('<Q', changed, header + 16, layout['text']['address'])
        struct.pack_into('<Q', changed, header + 24, layout['text']['offset'])
        struct.pack_into('<Q', changed, header + 32, 8)
        self.assertEqual(run('read_bytes', bytes(changed), mode='address', at=layout['entry']), [])
        self.assertIsNone(run('read_bytes', bytes(changed), at=layout['text']['offset'])[0].value['address'])
        self.assertIsNone(run('entry', bytes(changed))[0].value['offset'])
        rows = [dict(address=0, size=100), dict(address=10, size=1)]
        mapping = structure._SectionMap(rows, 'address')
        self.assertIsNone(mapping.row(10)); self.assertEqual(mapping.row(20), rows[0])

    def test_interval_index_agrees_with_an_independent_linear_overlap_check(self):
        rng = random.Random(31)
        for _ in range(40):
            rows = [dict(address=rng.randrange(80), size=rng.randrange(1, 20)) for _ in range(20)]
            mapping = structure._SectionMap(rows, 'address')
            for _ in range(30):
                at, length = rng.randrange(100), rng.randrange(1, 20)
                overlaps = [r for r in rows if r['address'] < at + length and at < r['address'] + r['size']]
                expected = overlaps[0] if len(overlaps) == 1 and overlaps[0]['address'] <= at and at + length <= overlaps[0]['address'] + overlaps[0]['size'] else None
                self.assertEqual(mapping.row(at, length), expected)

    def test_malformed_tables_keep_a_valid_prefix_and_walk_limits_refuse(self):
        data, layout = pe_exports(); changed = bytearray(data)
        struct.pack_into('<H', changed, layout['ordinals'] + 2, 0xFFFF)
        rows = run('symbols', bytes(changed))
        self.assertEqual([o.value['name'] for o in rows], ['hello'])
        self.assertEqual(rows[0].value['total'], 1)
        data, _ = elf_code()
        with patch.object(structure, 'MAX_TABLE_ENTRIES', 8), self.assertRaises(structure.StructureError):
            run('symbols', data)
        self.assertEqual(run('symbols', data[:100]), [])
        for data in (b'\x7fELF', b'MZ', b'\xcf\xfa\xed\xfe', bytes(range(128))):
            for operation in ('segments', 'entry', 'symbols', 'read_bytes'):
                if operation != 'read_bytes':
                    self.assertEqual(run(operation, data), [])

    def test_the_65536_entry_budget_is_aggregate_and_never_a_silent_total(self):
        data, layout = elf_symbols()
        for count, refused in ((65532, False), (65533, True)):
            changed = bytearray(data)
            offset = len(changed)
            changed += bytes(count * 24)
            struct.pack_into('<QQ', changed, layout['shoff'] + 64 + 24, offset, count * 24)
            if refused:
                with self.assertRaises(structure.StructureError):run('symbols', bytes(changed))
            else:
                self.assertEqual(run('symbols', bytes(changed)), [])

    def test_argument_bounds_unknown_keys_and_defaults(self):
        self.assertEqual(structure.TOOL.operations['structure.symbols'].validate_args({})['query'], '')
        for op, args in [('segments', {'limit':257}), ('segments', {'start':True}), ('symbols', {'query':'x\x1b'}),
                         ('symbols', {'query':'x'*129}), ('read_bytes', {'length':2001}), ('read_bytes', {'length':0}),
                         ('read_bytes', {'at':2**64}), ('read_bytes', {'mode':'file'}), ('entry', {'at':0})]:
            with self.subTest(op=op,args=args), self.assertRaises(ValueError):run(op,b'',**args)


if __name__ == '__main__':unittest.main()
