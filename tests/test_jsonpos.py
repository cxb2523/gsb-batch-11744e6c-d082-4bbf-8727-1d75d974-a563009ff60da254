"""JSON known answers and exact byte/token/recursion boundaries."""

from decimal import Decimal
import json
import random
import unittest
from unittest.mock import patch

from reverseai.contract import ContractError
from reverseai.tools import jsonpos


class JsonPositionTests(unittest.TestCase):
    def test_decoded_values_and_every_token_keep_original_byte_spans(self):
        data = ' {"é": ["\\u0061", true, null, -12.50e+2], "face": "\\ud83d\\ude00"} \n'.encode()
        document = jsonpos.parse(data)
        self.assertEqual(document.root.value, {'é': ['a', True, None, Decimal('-1250')], 'face': '😀'})
        self.assertEqual(data[document.root.start:document.root.end], data.strip())
        expected = [b'{', '"é"'.encode(), b':', b'[', b'"\\u0061"', b',', b'true', b',', b'null',
                    b',', b'-12.50e+2', b']', b',', b'"face"', b':', b'"\\ud83d\\ude00"', b'}']
        self.assertEqual([data[t.start:t.end] for t in document.tokens], expected)
        self.assertTrue(all(a.end <= b.start for a, b in zip(document.tokens, document.tokens[1:])))
        (key, array), (face, value) = document.root.children
        self.assertEqual((key.value, face.value), ('é', 'face'))
        self.assertEqual([n.value for n in array.children], ['a', True, None, Decimal('-1250')])
        self.assertEqual(data[value.start:value.end], b'"\\ud83d\\ude00"')

    def test_strings_numbers_and_top_level_scalars_follow_json_syntax(self):
        cases = [(b'"\\\"\\\\\\/\\b\\f\\n\\r\\t\\u0000"', '"\\/\b\f\n\r\t\0'),
                 (b'""', ''), (b'0', Decimal(0)), (b'-0', Decimal('-0')),
                 (b'9007199254740993', Decimal('9007199254740993')),
                 (b'1e9999', Decimal('1e9999')), (b'true', True), (b'false', False), (b'null', None),
                 (b'[]', []), (b'{}', {})]
        for data, expected in cases:
            with self.subTest(data=data):
                root = jsonpos.parse(data).root
                self.assertEqual(root.value, expected)
                self.assertEqual((root.start, root.end), (0, len(data)))
        huge = b'9' * 5000
        self.assertEqual(str(jsonpos.parse(huge).root.value), huge.decode())

    def test_invalid_utf8_bom_surrogates_duplicates_and_malformed_json_fail(self):
        bad = [b'', b' ', b'\xef\xbb\xbf{}', b'\xff', b'"\xc0\x80"', b'"\xed\xa0\x80"',
               b'"\\ud800"', b'"\\udc00"', b'"\\ud800\\u0041"', b'"\\ud800\\ud800"',
               b'{"a":1,"\\u0061":2}', b'{"outer":{"a":1,"a":2}}', b'{"x":1,}',
               b'[1,]', b'[,1]', b'{1:2}', b'{"a" 1}', b'{"a":}', b'[] []', b'nullx',
               b'NaN', b'Infinity', b'-Infinity', b'01', b'-01', b'+1', b'1.', b'.1', b'1e',
               b'1e+', b'--1', b'"a\nb"', b'"a\x00b"', b'"\\q"', b'"\\u123"', b'"\\u12zz"',
               b'"unterminated', b'"backslash\\', b'\x0c{}', b'\x0b[]']
        for data in bad:
            with self.subTest(data=data), self.assertRaises(ContractError):
                jsonpos.parse(data)
        self.assertEqual(jsonpos.parse(b'{"a":1,"nested":{"a":2}}').root.value,
                         {'a': Decimal(1), 'nested': {'a': Decimal(2)}})

    def test_the_byte_depth_and_token_limits_admit_the_boundary_then_refuse_more(self):
        data = b'"' + b'x' * (jsonpos.MAX_BYTES - 2) + b'"'
        self.assertEqual(jsonpos.parse(data).root.end, jsonpos.MAX_BYTES)
        with self.assertRaises(ContractError):
            jsonpos.parse(data + b' ')
        nested = b'[' * 64 + b'0' + b']' * 64
        self.assertEqual(jsonpos.parse(nested).root.end, len(nested))
        for data in (b'[' + nested + b']', b'{"a":' * 65 + b'0' + b'}' * 65):
            with self.assertRaises(ContractError):
                jsonpos.parse(data)
        # A valid JSON document has an odd number of these tokens: 65,535
        # fits, the next possible count (65,537) exceeds the 65,536 cap.
        data = b'[' + b'0,' * 32766 + b'0]'
        self.assertEqual(len(jsonpos.parse(data).tokens), 65535)
        with self.assertRaises(ContractError):
            jsonpos.parse(b'[' + b'0,' * 32767 + b'0]')
        with patch.object(jsonpos, 'MAX_TOKENS', 5):
            self.assertEqual(len(jsonpos.parse(b'{"a":0}').tokens), 5)
            with self.assertRaises(ContractError):
                jsonpos.parse(b'[0,0,0]')

    def test_generated_documents_agree_with_the_standard_decoder(self):
        rng = random.Random(576)
        atoms = [None, True, False, '', 'é😀', '~a/b\\c\n\t', 12345, -3.25]
        for _ in range(150):
            value = {str(i): [rng.choice(atoms) for _ in range(rng.randrange(5))] for i in range(rng.randrange(8))}
            data = json.dumps(value, ensure_ascii=rng.choice((True, False))).encode()
            self.assertEqual(jsonpos.parse(data).root.value,
                             json.loads(data, parse_int=Decimal, parse_float=Decimal))
        for _ in range(500):
            data = rng.randbytes(rng.randrange(128))
            try:
                jsonpos.parse(data)
            except ContractError:
                pass
            else:
                json.loads(data)


if __name__ == '__main__':
    unittest.main()
