import unittest

from reverseai.contract import MAX_EXCERPT_BYTES, ContractError, ToolRef
from reverseai.tools.strings import TOOL
from tests.fixtures_strings import clean_control, known_strings


def observe(operation, data, **args):
    spec = TOOL.operations["strings." + operation]
    return spec.handler(data, spec.validate_args(args))


def records(observations):
    return [(item.location.offset, item.location.length, item.value) for item in observations]


class StringsTests(unittest.TestCase):
    def test_tool_identity_and_argument_defaults(self):
        self.assertEqual(TOOL.ref, ToolRef("strings", "0.1.0"))
        self.assertEqual(TOOL.operations["strings.extract"].validate_args({}), {
            "encoding": "ascii", "max_strings": 1024, "min_length": 6,
        })
        self.assertEqual(TOOL.operations["strings.indicators"].validate_args({}), {"ruleset": "default"})

    def test_exact_ascii_extraction_at_declared_offsets(self):
        data, expected, _ = known_strings()
        self.assertEqual(records(observe("extract", data)), expected["ascii"])

    def test_exact_utf16le_extraction_at_declared_offsets(self):
        data, expected, _ = known_strings()
        self.assertEqual(records(observe("extract", data, encoding="utf16le")), expected["utf16le"])

    def test_exact_indicator_rules_matches_and_byte_ranges(self):
        data, _, expected = known_strings()
        actual = records(observe("indicators", data))
        self.assertEqual(actual, expected)
        self.assertEqual(len(actual), 16)

    def test_wide_strings_can_start_at_odd_byte_offsets(self):
        text = "VirtualAllocEx https://odd.example.invalid"
        data = b"\xff" + text.encode("utf-16le") + b"\xff"
        extracted = records(observe("extract", data, encoding="utf16le"))
        self.assertEqual(extracted, [(1, len(text) * 2, {
            "text": text, "encoding": "utf16le", "truncated": False,
        })])
        actual = records(observe("indicators", data))
        self.assertEqual(actual[0], (1, 28, {
            "rule": "virtual_alloc_ex", "category": "process_injection", "match": "VirtualAllocEx",
        }))
        self.assertEqual(actual[1][0], 31)

    def test_minimum_length_and_maximum_count(self):
        data = b"four\x00short\x00sixsix\x00seventh\x00"
        self.assertEqual([o.value["text"] for o in observe("extract", data)], ["sixsix", "seventh"])
        self.assertEqual([o.value["text"] for o in observe("extract", data, min_length=4, max_strings=2)], ["four", "short"])

    def test_long_ascii_and_wide_strings_have_bounded_text_and_excerpt(self):
        for encoding, codec in (("ascii", "ascii"), ("utf16le", "utf-16le")):
            with self.subTest(encoding=encoding):
                data = b"\xff" + ("a" * 5000).encode(codec) + b"\xff"
                observations = observe("extract", data, encoding=encoding)
                self.assertEqual(len(observations), 1)
                self.assertEqual(records(observations), [(1, MAX_EXCERPT_BYTES, {
                    "text": "a" * 256, "encoding": encoding, "truncated": True,
                })])

    def test_exact_text_limit_is_not_marked_truncated(self):
        self.assertEqual(observe("extract", b"a" * 256)[0].value["truncated"], False)
        self.assertEqual(observe("extract", b"a" * 257)[0].value["truncated"], True)

    def test_clean_control_has_strings_and_no_indicators(self):
        self.assertTrue(observe("extract", clean_control()))
        self.assertEqual(observe("indicators", clean_control()), [])

    def test_empty_short_and_non_printable_inputs(self):
        for data in (b"", b"abc", bytes(range(32)), b"\xff\x80\x00"):
            with self.subTest(data=data):
                self.assertEqual(observe("extract", data), [])
                self.assertEqual(observe("extract", data, encoding="utf16le"), [])
                self.assertEqual(observe("indicators", data), [])

    def test_unknown_or_out_of_bounds_arguments_refused(self):
        for args in ({"min_length": 3}, {"min_length": 65}, {"min_length": True},
                     {"max_strings": 0}, {"max_strings": 4097}, {"encoding": "utf8"},
                     {"path": "/tmp/x"}):
            with self.subTest(args=args), self.assertRaises(ContractError):
                observe("extract", b"inert", **args)
        with self.assertRaises(ContractError):
            observe("indicators", b"inert", ruleset="download")

    def test_api_boundaries_and_invalid_ipv4_control(self):
        data = (b"ReOpenProcess CreateRemoteThreaded sockets reconnect "
                b"256.1.2.3 1.2.3.999 01.2.3.4 x1.2.3.4 1.2.3.4.5")
        self.assertEqual(observe("indicators", data), [])

    def test_valid_ipv4_edges(self):
        data = b"0.0.0.0 255.255.255.255"
        self.assertEqual(records(observe("indicators", data)), [
            (0, 7, {"rule": "ipv4", "category": "network", "match": "0.0.0.0"}),
            (8, 15, {"rule": "ipv4", "category": "network", "match": "255.255.255.255"}),
        ])

    def test_remaining_rule_table_positive_controls(self):
        cases = (
            ("NtMapViewOfSection", "nt_map_view_of_section", "process_injection"),
            ("QueueUserAPC", "queue_user_apc", "process_injection"),
            (r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "registry_run_once", "persistence"),
            ("CreateServiceW", "create_service", "persistence"),
            ("InternetOpenA", "internet_open", "network"),
            ("socket", "socket", "network"),
            ("connect", "connect", "network"),
            ("CryptAcquireContextW", "crypt_acquire_context", "crypto"),
            ("NtQueryInformationProcess", "nt_query_information_process", "anti_debug"),
        )
        for text, rule, category in cases:
            for encoding, width in (("ascii", 1), ("utf-16le", 2)):
                with self.subTest(rule=rule, encoding=encoding):
                    self.assertEqual(records(observe("indicators", text.encode(encoding))), [
                        (0, len(text) * width, {"rule": rule, "category": category, "match": text}),
                    ])

    def test_case_insensitive_match_keeps_exact_input_spelling(self):
        self.assertEqual(records(observe("indicators", b"virtualallocex")), [
            (0, 14, {"rule": "virtual_alloc_ex", "category": "process_injection", "match": "virtualallocex"}),
        ])

    def test_chunk_boundary_matches_once_with_exact_byte_offsets(self):
        for text in ("VirtualAllocEx", "https://boundary.example.invalid/path", "203.0.113.7"):
            for codec, width in (("ascii", 1), ("utf-16le", 2)):
                with self.subTest(text=text, codec=codec):
                    source = " " * 4091 + text + " " * 4100
                    actual = observe("indicators", source.encode(codec))
                    self.assertEqual(len(actual), 1)
                    self.assertEqual(actual[0].location.offset, 4091 * width)
                    self.assertEqual(actual[0].location.length, len(text) * width)
                    self.assertEqual(actual[0].value["match"], text)

    def test_chunk_boundary_does_not_create_false_word_boundary(self):
        source = b"x" * 4096 + b"OpenProcess" + b"x" * 4096
        self.assertEqual(observe("indicators", source), [])

    def test_long_runs_are_joined_across_bounded_scanner_blocks(self):
        for codec, label, width in (("ascii", "ascii", 1), ("utf-16le", "utf16le", 2)):
            with self.subTest(codec=codec):
                text = "x" * 20_000 + " VirtualAllocEx"
                data = b"\xff" + text.encode(codec) + b"\xff"
                self.assertEqual(len(observe("extract", data, encoding=label)), 1)
                self.assertEqual(records(observe("indicators", data)), [
                    (1 + 20_001 * width, 14 * width, {
                        "rule": "virtual_alloc_ex", "category": "process_injection", "match": "VirtualAllocEx",
                    }),
                ])

    def test_indicator_flood_has_bounded_handler_output_and_sentinel(self):
        observations = observe("indicators", b"OpenProcess " * 10_000)
        self.assertEqual(len(observations), 4097)
        self.assertEqual(TOOL.operations["strings.indicators"].max_observations, 4096)


if __name__ == "__main__":
    unittest.main()
