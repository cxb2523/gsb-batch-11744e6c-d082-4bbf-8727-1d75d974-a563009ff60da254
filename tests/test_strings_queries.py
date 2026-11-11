"""String pages: exact byte citations, full-run literal search and real reviewer checks."""

import unittest
import tracemalloc

from reverseai import claims
from reverseai.contract import (AnalysisResult, InputRef, Location, content_id, make_evidence, make_finding, sha256_hex)
from reverseai.review import review
from reverseai.tools import strings
from tests.fixtures_code import elf_refs, pe_refs, macho_refs


def run(operation, data, **args):
    spec = strings.TOOL.operations['strings.' + operation]
    return spec.handler(data, spec.validate_args(args))


def supported(test, data, operation, rows, expected):
    evidence = tuple(make_evidence(data, strings.TOOL.ref, 'strings.' + operation, o) for o in rows)
    key = 'strings.listed' if operation == 'list' else 'strings.matches'
    finding = make_finding('structural', claims.statement(key), key, expected, [e.id for e in evidence], 'observed')
    result = AnalysisResult(content_id('tk', {'query': operation}), 'structural', 'ok', evidence, (finding,))
    verdict = review(data, InputRef(sha256_hex(data), len(data), 'fixture'), [result], {'strings': strings.TOOL})
    test.assertEqual(verdict[0].status, 'supported')


class StringsQueryTests(unittest.TestCase):
    def test_operations_are_registered_and_verified(self):
        self.assertTrue({'strings.list', 'strings.search'} <= set(strings.TOOL.operations))
        for operation in ('list', 'search'):
            self.assertFalse(strings.TOOL.operations['strings.' + operation].derived)

    def test_exact_ascii_and_odd_aligned_wide_pages_through_reviewer(self):
        data = b'hello world\0X' + 'wide words'.encode('utf-16le') + b'\0\0'
        rows = run('list', data, min_length=4)
        expected = [[0, 'ascii', 'hello world', False], [13, 'utf-16le', 'wide words', False]]
        self.assertEqual([o.location for o in rows], [Location(0, 11), Location(13, 20)])
        self.assertEqual([[o.value[k] for k in ('offset','encoding','text','truncated')] for o in rows], expected)
        supported(self, data, 'list', rows, dict(start=0,total=2,rows=expected))
        page = run('list', data, min_length=4,start=1,limit=1)
        self.assertEqual(page, rows[1:])
        supported(self, data,'list',page,dict(start=1,total=2,rows=expected[1:]))
        self.assertEqual(run('list',data,start=2), [])
        self.assertEqual(run('list',data,start=1048575), [])

    def test_queries_on_elf_pe_macho_real_fixture_bytes(self):
        for builder in (elf_refs,pe_refs,macho_refs):
            data,layout=builder()
            rows=run('search',data,query='ReverseAI')
            expected=[[s['offset'],s['encoding'],s['text'],False] for s in layout['strings']]
            self.assertEqual([o.location for o in rows],[Location(s['offset'],s['length']) for s in layout['strings']])
            supported(self,data,'search',rows,dict(start=0,total=2,rows=expected))
            ascii_rows=run('search',data,query='ReverseAI',encoding='ascii')
            wide_rows=run('search',data,query='ReverseAI',encoding='utf16le')
            self.assertEqual([o.value['total'] for o in ascii_rows+wide_rows],[1,1])
            self.assertEqual(run('search',data,query='reverseai'),[])

    def test_list_on_each_binary_format_supports_its_known_rows(self):
        for builder in (elf_refs, pe_refs, macho_refs):
            original, _ = builder()
            data = original + b'\xff' + b'A' * 64 + b'\xff' + ('W' * 64).encode('utf-16le') + b'\xff'
            rows = run('list', data, min_length=64)
            expected = [[len(original) + 1, 'ascii', 'A' * 64, False],
                        [len(original) + 66, 'utf-16le', 'W' * 64, False]]
            self.assertEqual(len(rows), 2)
            supported(self, data, 'list', rows, dict(start=0, total=2, rows=expected))

    def test_full_run_is_searched_after_the_preview_and_excerpt(self):
        for encoding,codec in [('ascii','ascii'),('utf16le','utf-16le')]:
            data=('a'*5000+' needle/end -option').encode(codec)
            rows=run('search',data,query='needle/end -option',encoding=encoding)
            self.assertEqual(len(rows),1)
            self.assertEqual(rows[0].location,Location(0,4096))
            self.assertEqual(rows[0].value['text'],'a'*256)
            self.assertTrue(rows[0].value['truncated'])
            expected=[[0,'ascii' if encoding=='ascii' else 'utf-16le','a'*256,True]]
            supported(self,data,'search',rows,dict(start=0,total=1,rows=expected))

    def test_minimum_length_and_encodings(self):
        data=b'abcd\0abcdef\0\0'+'wide'.encode('utf-16le')+b'\0\0'
        self.assertEqual([o.value['text'] for o in run('list',data)],['abcdef'])
        self.assertEqual([o.value['text'] for o in run('list',data,min_length=4)],['abcd','abcdef','wide'])
        self.assertEqual([o.value['text'] for o in run('list',data,encoding='utf16le',min_length=4)],['wide'])
        self.assertEqual(run('search',data,query='é'),[])
        for data in (b'',b'abc',bytes(range(32)),b'\xff'*10):
            self.assertEqual(run('list',data),[])
            self.assertEqual(run('search',data,query='abc'),[])

    def test_merge_order_includes_overlapping_runs(self):
        data=b'abcd\0e\0f\0g\0'
        rows=run('list',data,min_length=4)
        self.assertEqual([(o.location.offset,o.value['text']) for o in rows],[(0,'abcd'),(3,'defg')])
        self.assertEqual([o.value['index'] for o in rows],[0,1])
        self.assertEqual([o.value['total'] for o in rows],[2,2])
        data = 'wide'.encode('utf-16le') + b'\xffafter\0'
        rows = run('list', data, min_length=4)
        self.assertEqual([(o.location.offset, o.value['encoding'], o.value['text']) for o in rows],
                         [(0, 'utf-16le', 'wide'), (9, 'ascii', 'after')])

    def test_long_run_boundaries_are_joined_before_paging(self):
        for encoding,codec in [('ascii','ascii'),('utf16le','utf-16le')]:
            data=('x'*9000+'joinmarker'+'x'*9000).encode(codec)+b'\0\0'+('lastrow').encode(codec)
            rows=run('list',data,encoding=encoding,start=1,limit=1)
            self.assertEqual(rows[0].value['text'],'lastrow')
            self.assertEqual(rows[0].value['total'],2)
            matches=run('search',data,query='joinmarker',encoding=encoding)
            self.assertEqual(len(matches),1)
            self.assertEqual(matches[0].value['total'],1)

    def test_preview_bound_and_literal_flags_slashes(self):
        for size in (256,257):
            row=run('list',b'a'*size)[0]
            self.assertEqual(row.value['truncated'],size>256)
            self.assertEqual(len(row.value['text']),min(size,256))
        rows=run('search',b'-switch/path literal\0another literal\0',query='-switch/path')
        self.assertEqual(rows[0].value['text'],'-switch/path literal')
        self.assertEqual(run('search',b'alpha beta\0',query='a.*b'),[])

    def test_page_total_counts_only_matching_runs(self):
        data=b'hit one\0miss\0hit two\0hit three\0'
        page=run('search',data,query='hit',start=1,limit=1)
        expected=dict(start=1,total=3,rows=[[13,'ascii','hit two',False]])
        self.assertEqual(page[0].location.offset,13)
        supported(self,data,'search',page,expected)
        self.assertEqual(run('search',data,query='hit',start=3),[])

    def test_dense_pages_count_all_runs_with_bounded_allocation(self):
        # Keep this routine check smaller than the 64 MiB performance measurements.
        count = 70000
        data = b'abcd\0' * count
        for operation in ('list', 'search'):
            args = dict(start=count - 1, limit=1)
            args.update(dict(min_length=4) if operation == 'list' else dict(query='abcd'))
            with self.subTest(operation=operation):
                tracemalloc.start()
                try:
                    rows = run(operation, data, **args)
                    _, peak = tracemalloc.get_traced_memory()
                finally:
                    tracemalloc.stop()
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0].value['index'], count - 1)
                self.assertEqual(rows[0].value['total'], count)
                self.assertEqual(rows[0].value['text'], 'abcd')
                self.assertEqual(rows[0].location, Location((count - 1) * 5, 4))
                self.assertLess(peak, 1024 * 1024)

    def test_huge_run_pages_keep_preview_and_excerpt_bounded(self):
        for codec in ('ascii', 'utf-16le'):
            data = ('A' * (256 * 1024) + 'needle').encode(codec)
            for operation in ('list', 'search'):
                args = {} if operation == 'list' else dict(query='needle')
                with self.subTest(codec=codec, operation=operation):
                    rows = run(operation, data, limit=1, **args)
                    self.assertEqual(len(rows), 1)
                    self.assertEqual(rows[0].value['total'], 1)
                    self.assertEqual(rows[0].value['text'], 'A' * 256)
                    self.assertTrue(rows[0].value['truncated'])
                    self.assertEqual(rows[0].location, Location(0, 4096))

    def test_argument_ranges_unknown_keys_and_search_requirement(self):
        for operation,args in [('list',{'min_length':3}),('list',{'min_length':65}),('list',{'limit':257}),
             ('list',{'start':-1}),('list',{'encoding':'utf-8'}),('list',{'query':'x'}),('search',{}),
             ('search',{'query':''}),('search',{'query':'x'*129}),('search',{'query':'a\x1b'}),
             ('search',{'query':'x','start':True}),('search',{'query':'x','min_length':6})]:
            with self.subTest(operation=operation,args=args),self.assertRaises(ValueError):run(operation,b'',**args)


if __name__=='__main__':unittest.main()
