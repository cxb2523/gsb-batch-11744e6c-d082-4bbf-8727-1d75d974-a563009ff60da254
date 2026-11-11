"""Native LIEF/YARA-X/Ghidra/JADX/jsparser checks; ordinary unittest discovery never runs Docker.

Run from the repository root with --tool lief (or yarax/ghidra/jadx/jsparser), --profile small --offline,
--lock containers/<tool>/image.lock.json --receipt NEW_PRIVATE_FILE.
Unit tests establish validator behaviour; only a successful native run supplies
runtime evidence for its exact image, platform, executor and verifier hashes.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
from pathlib import Path
import re
import struct
import sys
import textwrap
import threading
import time
from types import SimpleNamespace

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from reverseai.contract import ContractError, Location, MAX_WORKER_REPLY_BYTES, Observation, canonical_json, parse_worker_reply, sha256_hex
from reverseai.tools import structure, ghidra_verify
from reverseai.tools.jshints import CALLEES as _JSHINTS_CALLEES
from tests.fixtures_structure import elf, pe
from tests.fixtures_code import elf_code, pe_code, elf_data_only, macho_code, elf_refs, pe_refs, macho_refs
from tests import fixtures_apk, fixtures_js


PLATFORM = "linux/arm64"
ENTRYPOINT = ["python3", "-I", "-B", "/opt/reverseai/worker.py"]
MEMORY = 512 * 1024**2
WALL_SECONDS = 45
PROBE_PROTOCOL = "reverseai.native-probe/1"
FIXTURE_NAMES = ("elf64le", "elf32be", "pe32plus", "pe32plus-distant")
CONTROL_NAMES = ("runtime_identity", "network", "write_root", "write_snapshot", "setuid",
                 "capability", "pids", "memory", "wall", "stdout")
REQUIRED_CHECKS = ("local_daemon", "image", "container", *CONTROL_NAMES,
                   *(f"{name}.{op}" for name in FIXTURE_NAMES for op in ("headers", "sections")))
NATIVE_RUNS = len(CONTROL_NAMES) + 2 * len(FIXTURE_NAMES)
YARAX_RULESET_NAME = "m2_fixture_v1"
YARAX_RULESET_PATH = Path(__file__).resolve().parents[1] / "containers/yarax/m2_fixture_v1.json"
YARAX_RULESET_SHA256 = "e2217ff703858af17fe8eee8ac0d4cc44dfefd632e096bb4b527b89b08a062a7"
YARAX_WHEEL_SHA256 = "9bd9961b44b47dd747d526e61c703a2a8170426d003e789e7724bc7862de6d56"
YARAX_BASE_DIGEST = "sha256:16bf2b5c59a08523519d3c8589deca849285dee1d62a3653e124c3dba340f15e"
YARAX_ADAPTER_VERSION = "1.21.0-r2"
YARAX_MATCHES_PER_PATTERN = 4
YARAX_FIXTURE_NAMES = ("upx_markers", "utf16_markers", "clean", "repeated_markers")
YARAX_REQUIRED_CHECKS = ("local_daemon", "image", "container", *CONTROL_NAMES,
                         *(f"{name}.matches" for name in YARAX_FIXTURE_NAMES))
YARAX_NATIVE_RUNS = len(CONTROL_NAMES) + len(YARAX_FIXTURE_NAMES)
GHIDRA_ADAPTER_VERSION = "12.1.4-r6"
GHIDRA_BASE_DIGEST = "sha256:16bf2b5c59a08523519d3c8589deca849285dee1d62a3653e124c3dba340f15e"
GHIDRA_SHA256 = "ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db"
GHIDRA_JDK_SHA256 = "23e37e026f12f3e706f18938ff611db3032d075b09d0879a25d06718c773e223"
GHIDRA_R7_VERSION = "12.1.4-r7"
GHIDRA_PARENT_IMAGE_ID = "sha256:ac77fda75da8580e0479087580f83b6e5495fb16df97b9696a2bdf3ae100f452"
GHIDRA_BUNDLE_FILES = ("worker.py", "project_cache.py", "ghidra_scripts/ReverseAIOptions.java",
                       "ghidra_scripts/ReverseAIQuery.java", "ghidra_scripts/ReverseAIPrepare.java")
GHIDRA_SOURCE = Path(__file__).resolve().parents[1] / "containers/ghidra"
GHIDRA_FIXTURE_NAMES = ("elf_code", "pe_code", "elf_data_only", "macho_code", "elf_refs", "pe_refs", "macho_refs")
GHIDRA_QUERY_FIXTURES = ("elf_refs", "pe_refs", "macho_refs")
GHIDRA_QUERY_CASES = ("functions_page", "function_add", "function_constant", "xrefs_counter")
GHIDRA_REQUIRED_CHECKS = ("local_daemon", "image", "container", *CONTROL_NAMES,
                          *(f"{name}.analyze" for name in GHIDRA_FIXTURE_NAMES),
                          *(f"{name}.{case}" for name in GHIDRA_QUERY_FIXTURES for case in GHIDRA_QUERY_CASES))
GHIDRA_NATIVE_RUNS = len(GHIDRA_REQUIRED_CHECKS) - 3
GHIDRA_OPERATIONS = ("ghidra.analyze", "ghidra.functions", "ghidra.function", "ghidra.xrefs")
JADX_ADAPTER_VERSION = "1.5.6-r1"
JADX_BASE_DIGEST = "sha256:16bf2b5c59a08523519d3c8589deca849285dee1d62a3653e124c3dba340f15e"
JADX_ZIP_SHA256 = "545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974"
JADX_JAR_SHA256 = "fe3e12c45acf75f92369685fd02d1d7a7323385dc725680a9b98a0dac0ea554b"
JADX_JDK_SHA256 = "23e37e026f12f3e706f18938ff611db3032d075b09d0879a25d06718c773e223"
JADX_DRIVER_PATH = Path(__file__).resolve().parents[1] / "containers/jadx/driver/ReverseAIJadx.java"
JADX_WORKER_PATH = Path(__file__).resolve().parents[1] / "containers/jadx/worker.py"
JADX_CASE_NAMES = ("main_init", "helper_int", "helper_string", "on_create", "marker_init",
                   "compute", "worker_init", "run", "helper_overloads", "past_end")
JADX_REQUIRED_CHECKS = ("local_daemon", "image", "container", *CONTROL_NAMES,
                        *(f"apk_basic.{name}" for name in JADX_CASE_NAMES),
                        "jadx.hostile_reply", "jadx.input_mismatch")
JADX_NATIVE_RUNS = len(JADX_REQUIRED_CHECKS) - 3
JSPARSER_ADAPTER_VERSION = "8.0.4-r2"
JSPARSER_PINS = {
    "base_digest": "sha256:16bf2b5c59a08523519d3c8589deca849285dee1d62a3653e124c3dba340f15e",
    "node_sha256": "dbabf7a1cbf947e6059ffad2c27b80041db97dea1e553b62afdee7f13fca336e",
    "babel_parser_integrity": "sha512-srpptsAkEbbNIC/q8nT7o+m6CQe8CJUTV/t7MYc9NnWlgYVtHOb7JH6SorxMhN0kuRJjVqXbKClG6xSbPtzz+g==",
    "babel_types_integrity": "sha512-eY+Yn3dCqTGmyiq2QRU66lA5FL8lqqqvecHt0fF3uHONIa7ToYsaCiWV8lOKqAs0Rb2SjixiKFROngnulPtt2g==",
    "helper_string_parser_integrity":
        "sha512-+6HYEBnsDRZHJtUTAEfMQd0zMDqdFHS7C+5vAsEZqBUr3vEMWOWlHJ0Jz1gS8jJIlCvLsuA6ivmeoqzH936YcA==",
    "helper_validator_identifier_integrity":
        "sha512-HYx0YmuchRxRSpnjvcNffnPS8DCauKNmnumIuHG3jnQAVewRA7kfJGwF13ayEpSZs7s4R/oBH4eppuXcAQd5JQ==",
}
JSPARSER_DRIVER_PATH = Path(__file__).resolve().parents[1] / "containers/jsparser/driver.mjs"
JSPARSER_WORKER_PATH = Path(__file__).resolve().parents[1] / "containers/jsparser/worker.py"
# The host's catalog is the only list reverseai.contained admits (validate_jsparser_request).
# Changes to jshints.CALLEES require renewing these known answers.
JSPARSER_CALLEES = tuple(sorted(_JSHINTS_CALLEES))
JSPARSER_CASE_NAMES = ("app_modules", "app_calls", "app_page", "app_parse", "bundle_modules", "bundle_calls",
                       "dialects_modules", "dialects_calls", "dialects_parse", "boundary_parse", "input_mismatch",
                       "tarball_calls", "tarball_tampered")
JSPARSER_REQUIRED_CHECKS = ("local_daemon", "image", "container", *CONTROL_NAMES,
                            *(f"jsparser.{name}" for name in JSPARSER_CASE_NAMES))
JSPARSER_NATIVE_RUNS = len(JSPARSER_REQUIRED_CHECKS) - 3
# Measured on r6 image sha256:d4c9076d0f6b0e4123704851f4300f08ab5d2f96ae6e4f37faadbcdf7d96492a.
# Native Ghidra query oracle, SHA-256 d8baabf89e32d3147ec08ea231415e9fd68dadf21fdfb3438e888d75f471674d.
GHIDRA_QUERY_EXPECTED = {'84a2fe7a4e67702df1bfa4434c1c57aa6fee8d21df4717ed47a1f3688d162e4f': {'function_add': [{'location': {'length': 10,
                                                                                                     'offset': 800},
                                                                                        'value': {'callees_total': 0,
                                                                                                  'callers_total': 2,
                                                                                                  'entry': 4294968096,
                                                                                                  'kind': 'target',
                                                                                                  'matches': 1,
                                                                                                  'name': 'add_numbers',
                                                                                                  'size': 10}},
                                                                                       {'location': {'length': 10,
                                                                                                     'offset': 800},
                                                                                        'value': {'entry': 4294968096,
                                                                                                  'index': 0,
                                                                                                  'kind': 'pseudocode',
                                                                                                  'text': '\n'
                                                                                                          'int '
                                                                                                          'add_numbers(int '
                                                                                                          'param_1,int '
                                                                                                          'param_2)\n'
                                                                                                          '\n'
                                                                                                          '{\n'
                                                                                                          '  '
                                                                                                          'return '
                                                                                                          'param_1 '
                                                                                                          '+ '
                                                                                                          'param_2;\n'
                                                                                                          '}\n'
                                                                                                          '\n',
                                                                                                  'truncated': False}},
                                                                                       {'location': {'length': 5,
                                                                                                     'offset': 801},
                                                                                        'value': {'entry': 4294968096,
                                                                                                  'kind': 'instructions',
                                                                                                  'rows': [[1,
                                                                                                            3,
                                                                                                            'MOV '
                                                                                                            'RBP,RSP'],
                                                                                                           [4,
                                                                                                            2,
                                                                                                            'MOV '
                                                                                                            'EAX,EDI']],
                                                                                                  'start': 1,
                                                                                                  'total': 6,
                                                                                                  'truncated': False}},
                                                                                       {'location': {'length': 5,
                                                                                                     'offset': 768},
                                                                                        'value': {'at': 4294968064,
                                                                                                  'from': 4294968064,
                                                                                                  'kind': 'caller',
                                                                                                  'to': 4294968096}},
                                                                                       {'location': {'length': 5,
                                                                                                     'offset': 827},
                                                                                        'value': {'at': 4294968123,
                                                                                                  'from': 4294968112,
                                                                                                  'kind': 'caller',
                                                                                                  'to': 4294968096}}],
                                                                      'function_constant': [{'location': {'length': 6,
                                                                                                          'offset': 848},
                                                                                             'value': {'callees_total': 0,
                                                                                                       'callers_total': 2,
                                                                                                       'entry': 4294968144,
                                                                                                       'kind': 'target',
                                                                                                       'matches': 1,
                                                                                                       'name': 'constant',
                                                                                                       'size': 6}},
                                                                                            {'location': {'length': 5,
                                                                                                          'offset': 834},
                                                                                             'value': {'at': 4294968130,
                                                                                                       'from': 4294968112,
                                                                                                       'kind': 'caller',
                                                                                                       'to': 4294968144}},
                                                                                            {'location': {'length': 5,
                                                                                                          'offset': 897},
                                                                                             'value': {'at': 4294968193,
                                                                                                       'from': 4294968160,
                                                                                                       'kind': 'caller',
                                                                                                       'to': 4294968144}}],
                                                                      'functions_page': [{'location': {'length': 10,
                                                                                                       'offset': 800},
                                                                                          'value': {'entry': 4294968096,
                                                                                                    'index': 1,
                                                                                                    'kind': 'function_row',
                                                                                                    'name': 'add_numbers',
                                                                                                    'size': 10,
                                                                                                    'total': 5}},
                                                                                         {'location': {'length': 27,
                                                                                                       'offset': 816},
                                                                                          'value': {'entry': 4294968112,
                                                                                                    'index': 2,
                                                                                                    'kind': 'function_row',
                                                                                                    'name': 'compute',
                                                                                                    'size': 27,
                                                                                                    'total': 5}}],
                                                                      'xrefs_counter': [{'location': {'length': 6,
                                                                                                      'offset': 878},
                                                                                         'value': {'at': 4294968174,
                                                                                                   'from': 4294968160,
                                                                                                   'index': 0,
                                                                                                   'kind': 'xref',
                                                                                                   'to': 4294971456,
                                                                                                   'total': 2,
                                                                                                   'type': 'read'}},
                                                                                        {'location': {'length': 7,
                                                                                                      'offset': 890},
                                                                                         'value': {'at': 4294968186,
                                                                                                   'from': 4294968160,
                                                                                                   'index': 1,
                                                                                                   'kind': 'xref',
                                                                                                   'to': 4294971456,
                                                                                                   'total': 2,
                                                                                                   'type': 'read_write'}}]},
 'a8c34c434308ca4f62f7e5f114e18582d15c7f7a5be9c2a8835d1f8961a1ec63': {'function_add': [{'location': {'length': 10,
                                                                                                     'offset': 288},
                                                                                        'value': {'callees_total': 0,
                                                                                                  'callers_total': 2,
                                                                                                  'entry': 4194592,
                                                                                                  'kind': 'target',
                                                                                                  'matches': 1,
                                                                                                  'name': 'add_numbers',
                                                                                                  'size': 10}},
                                                                                       {'location': {'length': 10,
                                                                                                     'offset': 288},
                                                                                        'value': {'entry': 4194592,
                                                                                                  'index': 0,
                                                                                                  'kind': 'pseudocode',
                                                                                                  'text': '\n'
                                                                                                          'int '
                                                                                                          'add_numbers(int '
                                                                                                          'param_1,int '
                                                                                                          'param_2)\n'
                                                                                                          '\n'
                                                                                                          '{\n'
                                                                                                          '  '
                                                                                                          'return '
                                                                                                          'param_1 '
                                                                                                          '+ '
                                                                                                          'param_2;\n'
                                                                                                          '}\n'
                                                                                                          '\n',
                                                                                                  'truncated': False}},
                                                                                       {'location': {'length': 5,
                                                                                                     'offset': 289},
                                                                                        'value': {'entry': 4194592,
                                                                                                  'kind': 'instructions',
                                                                                                  'rows': [[1,
                                                                                                            3,
                                                                                                            'MOV '
                                                                                                            'RBP,RSP'],
                                                                                                           [4,
                                                                                                            2,
                                                                                                            'MOV '
                                                                                                            'EAX,EDI']],
                                                                                                  'start': 1,
                                                                                                  'total': 6,
                                                                                                  'truncated': False}},
                                                                                       {'location': {'length': 5,
                                                                                                     'offset': 256},
                                                                                        'value': {'at': 4194560,
                                                                                                  'from': 4194560,
                                                                                                  'kind': 'caller',
                                                                                                  'to': 4194592}},
                                                                                       {'location': {'length': 5,
                                                                                                     'offset': 315},
                                                                                        'value': {'at': 4194619,
                                                                                                  'from': 4194608,
                                                                                                  'kind': 'caller',
                                                                                                  'to': 4194592}}],
                                                                      'function_constant': [{'location': {'length': 6,
                                                                                                          'offset': 336},
                                                                                             'value': {'callees_total': 0,
                                                                                                       'callers_total': 2,
                                                                                                       'entry': 4194640,
                                                                                                       'kind': 'target',
                                                                                                       'matches': 1,
                                                                                                       'name': 'constant',
                                                                                                       'size': 6}},
                                                                                            {'location': {'length': 5,
                                                                                                          'offset': 322},
                                                                                             'value': {'at': 4194626,
                                                                                                       'from': 4194608,
                                                                                                       'kind': 'caller',
                                                                                                       'to': 4194640}},
                                                                                            {'location': {'length': 5,
                                                                                                          'offset': 385},
                                                                                             'value': {'at': 4194689,
                                                                                                       'from': 4194656,
                                                                                                       'kind': 'caller',
                                                                                                       'to': 4194640}}],
                                                                      'functions_page': [{'location': {'length': 10,
                                                                                                       'offset': 288},
                                                                                          'value': {'entry': 4194592,
                                                                                                    'index': 1,
                                                                                                    'kind': 'function_row',
                                                                                                    'name': 'add_numbers',
                                                                                                    'size': 10,
                                                                                                    'total': 5}},
                                                                                         {'location': {'length': 27,
                                                                                                       'offset': 304},
                                                                                          'value': {'entry': 4194608,
                                                                                                    'index': 2,
                                                                                                    'kind': 'function_row',
                                                                                                    'name': 'compute',
                                                                                                    'size': 27,
                                                                                                    'total': 5}}],
                                                                      'xrefs_counter': [{'location': {'length': 6,
                                                                                                      'offset': 366},
                                                                                         'value': {'at': 4194670,
                                                                                                   'from': 4194656,
                                                                                                   'index': 0,
                                                                                                   'kind': 'xref',
                                                                                                   'to': 4198976,
                                                                                                   'total': 2,
                                                                                                   'type': 'read'}},
                                                                                        {'location': {'length': 7,
                                                                                                      'offset': 378},
                                                                                         'value': {'at': 4194682,
                                                                                                   'from': 4194656,
                                                                                                   'index': 1,
                                                                                                   'kind': 'xref',
                                                                                                   'to': 4198976,
                                                                                                   'total': 2,
                                                                                                   'type': 'read_write'}}]},
 'e15339c0da09e09400ecc16de618a492a49c2a7fb77eb616f424ed30a30130eb': {'function_add': [{'location': {'length': 10,
                                                                                                     'offset': 544},
                                                                                        'value': {'callees_total': 0,
                                                                                                  'callers_total': 2,
                                                                                                  'entry': 5368713248,
                                                                                                  'kind': 'target',
                                                                                                  'matches': 1,
                                                                                                  'name': 'FUN_140001020',
                                                                                                  'size': 10}},
                                                                                       {'location': {'length': 10,
                                                                                                     'offset': 544},
                                                                                        'value': {'entry': 5368713248,
                                                                                                  'index': 0,
                                                                                                  'kind': 'pseudocode',
                                                                                                  'text': '\n'
                                                                                                          'int '
                                                                                                          'FUN_140001020(void)\n'
                                                                                                          '\n'
                                                                                                          '{\n'
                                                                                                          '  int '
                                                                                                          'unaff_ESI;\n'
                                                                                                          '  int '
                                                                                                          'unaff_EDI;\n'
                                                                                                          '  \n'
                                                                                                          '  '
                                                                                                          'return '
                                                                                                          'unaff_EDI '
                                                                                                          '+ '
                                                                                                          'unaff_ESI;\n'
                                                                                                          '}\n'
                                                                                                          '\n',
                                                                                                  'truncated': False}},
                                                                                       {'location': {'length': 5,
                                                                                                     'offset': 545},
                                                                                        'value': {'entry': 5368713248,
                                                                                                  'kind': 'instructions',
                                                                                                  'rows': [[1,
                                                                                                            3,
                                                                                                            'MOV '
                                                                                                            'RBP,RSP'],
                                                                                                           [4,
                                                                                                            2,
                                                                                                            'MOV '
                                                                                                            'EAX,EDI']],
                                                                                                  'start': 1,
                                                                                                  'total': 6,
                                                                                                  'truncated': False}},
                                                                                       {'location': {'length': 5,
                                                                                                     'offset': 512},
                                                                                        'value': {'at': 5368713216,
                                                                                                  'from': 5368713216,
                                                                                                  'kind': 'caller',
                                                                                                  'to': 5368713248}},
                                                                                       {'location': {'length': 5,
                                                                                                     'offset': 571},
                                                                                        'value': {'at': 5368713275,
                                                                                                  'from': 5368713264,
                                                                                                  'kind': 'caller',
                                                                                                  'to': 5368713248}}],
                                                                      'function_constant': [{'location': {'length': 6,
                                                                                                          'offset': 592},
                                                                                             'value': {'callees_total': 0,
                                                                                                       'callers_total': 2,
                                                                                                       'entry': 5368713296,
                                                                                                       'kind': 'target',
                                                                                                       'matches': 1,
                                                                                                       'name': 'FUN_140001050',
                                                                                                       'size': 6}},
                                                                                            {'location': {'length': 5,
                                                                                                          'offset': 578},
                                                                                             'value': {'at': 5368713282,
                                                                                                       'from': 5368713264,
                                                                                                       'kind': 'caller',
                                                                                                       'to': 5368713296}},
                                                                                            {'location': {'length': 5,
                                                                                                          'offset': 641},
                                                                                             'value': {'at': 5368713345,
                                                                                                       'from': 5368713312,
                                                                                                       'kind': 'caller',
                                                                                                       'to': 5368713296}}],
                                                                      'functions_page': [{'location': {'length': 10,
                                                                                                       'offset': 544},
                                                                                          'value': {'entry': 5368713248,
                                                                                                    'index': 1,
                                                                                                    'kind': 'function_row',
                                                                                                    'name': 'FUN_140001020',
                                                                                                    'size': 10,
                                                                                                    'total': 5}},
                                                                                         {'location': {'length': 27,
                                                                                                       'offset': 560},
                                                                                          'value': {'entry': 5368713264,
                                                                                                    'index': 2,
                                                                                                    'kind': 'function_row',
                                                                                                    'name': 'FUN_140001030',
                                                                                                    'size': 27,
                                                                                                    'total': 5}}],
                                                                      'xrefs_counter': [{'location': {'length': 6,
                                                                                                      'offset': 622},
                                                                                         'value': {'at': 5368713326,
                                                                                                   'from': 5368713312,
                                                                                                   'index': 0,
                                                                                                   'kind': 'xref',
                                                                                                   'to': 5368717376,
                                                                                                   'total': 2,
                                                                                                   'type': 'read'}},
                                                                                        {'location': {'length': 7,
                                                                                                      'offset': 634},
                                                                                         'value': {'at': 5368713338,
                                                                                                   'from': 5368713312,
                                                                                                   'index': 1,
                                                                                                   'kind': 'xref',
                                                                                                   'to': 5368717376,
                                                                                                   'total': 2,
                                                                                                   'type': 'read_write'}}]}}


class VerificationError(ValueError):
    """Static reasons only: do not echo daemon output, paths or environment."""


def need(condition, reason):
    if not condition:
        raise VerificationError(reason)


def limits(tool):
    """Independent fixed expectations: pids, memory, nanocpus, tmpfs, wall."""
    need(tool in ("lief", "yarax", "ghidra", "jadx", "jsparser"), "VerifierTool")
    if tool == "jsparser":
        return (64, 2 * 1024**3, 2_000_000_000, "rw,noexec,nosuid,nodev,size=64m", 120)
    if tool in ("ghidra", "jadx"):
        return (256, 2 * 1024**3, 2_000_000_000, "rw,noexec,nosuid,nodev,size=512m",
                240 if tool == "ghidra" else 120)
    return (64, MEMORY, 1_000_000_000, "rw,noexec,nosuid,nodev,size=64m", WALL_SECONDS)


def required_checks(tool):
    need(tool in ("lief", "yarax", "ghidra", "jadx", "jsparser"), "VerifierTool")
    return {"lief": REQUIRED_CHECKS, "yarax": YARAX_REQUIRED_CHECKS, "ghidra": GHIDRA_REQUIRED_CHECKS,
            "jadx": JADX_REQUIRED_CHECKS, "jsparser": JSPARSER_REQUIRED_CHECKS}[tool]


def native_runs(tool):
    return len(required_checks(tool)) - 3


def lock_options(tool, lock=None):
    if tool == "jsparser":
        return {"adapter_version": JSPARSER_ADAPTER_VERSION}
    if tool == "jadx":
        return {"adapter_version": JADX_ADAPTER_VERSION}
    if tool == "ghidra":
        if lock is not None:
            verify_ghidra_lock(lock)
        return {"adapter_version": GHIDRA_ADAPTER_VERSION if lock is None else lock["adapter_version"]}
    return {} if tool == "lief" else {"adapter_version": YARAX_ADAPTER_VERSION,
                                       "extra_keys": ("ruleset_sha256",)}


def verify_ghidra_executor_profile(boundary):
    expected = {"pids": 256, "memory": "2g", "cpus": 2,
                "tmpfs": "/tmp:rw,noexec,nosuid,nodev,size=512m", "wall_seconds": 240}
    for operation in GHIDRA_OPERATIONS:
        profile = boundary.resource_profile(operation)
        need(dict(profile) == expected and all(type(profile[key]) is type(value) for key, value in expected.items()) and
             type(boundary.GHIDRA_WALL_SECONDS) is int and boundary.GHIDRA_WALL_SECONDS == 240,
             "ExecutorGhidraProfile")


def verify_jadx_executor_profile(boundary):
    expected = {"pids": 256, "memory": "2g", "cpus": 2,
                "tmpfs": "/tmp:rw,noexec,nosuid,nodev,size=512m", "wall_seconds": 120}
    profile = boundary.resource_profile("jadx.method")
    need(dict(profile) == expected and all(type(profile[key]) is type(value) for key, value in expected.items()) and
         type(boundary.JADX_WALL_SECONDS) is int and boundary.JADX_WALL_SECONDS == 120,
         "ExecutorJadxProfile")


def verify_jsparser_executor_profile(boundary):
    expected = {"pids": 64, "memory": "2g", "cpus": 2, "tmpfs": "/tmp:rw,noexec,nosuid,nodev,size=64m", "wall_seconds": 120}
    profile = boundary.resource_profile("jsparser.syntax")
    need(dict(profile) == expected and all(type(profile[key]) is type(value) for key, value in expected.items()) and
         type(boundary.JSPARSER_WALL_SECONDS) is int and boundary.JSPARSER_WALL_SECONDS == 120,
         "ExecutorJsparserProfile")


def _unique(pairs):
    need(len(pairs) == len({k for k, _ in pairs}), "DuplicateJSONKey")
    return dict(pairs)


def _empty_optional(value, kind):
    return value is None or (type(value) is kind and not value)


def decode(raw):
    try:
        return json.loads(raw, object_pairs_hook=_unique,
                          parse_constant=lambda _: need(False, "InvalidJSONNumber"))
    except (ValueError, UnicodeError, TypeError, RecursionError):
        raise VerificationError("InvalidJSON") from None


def verify_image(image, lock):
    need(isinstance(image, dict) and isinstance(lock, dict), "ImageShape")
    need(image.get("Id") == lock.get("image_id") and
         bool(re.fullmatch(r"sha256:[0-9a-f]{64}", str(lock.get("image_id", "")))), "ImageID")
    need(lock.get("platform") == PLATFORM and image.get("Os") == "linux" and
         image.get("Architecture") == "arm64", "ImagePlatform")
    config = image.get("Config")
    need(isinstance(config, dict), "ImageConfig")
    need(config.get("User") == "65534:65534", "ImageUser")
    need(config.get("Entrypoint") == ENTRYPOINT, "ImageEntrypoint")
    need(_empty_optional(config.get("Volumes"), dict), "ImageVolumes")
    need(isinstance(config.get("Env"), list) and all(isinstance(v, str) for v in config["Env"]), "ImageEnvironment")


def verify_snapshot_mount(data, snapshot):
    mounts = data.get("Mounts")
    need(isinstance(mounts, list) and len(mounts) == 1 and isinstance(mounts[0], dict), "ContainerMountCount")
    mount = mounts[0]
    need(mount.get("Type") == "bind" and mount.get("Destination") == "/snapshot" and
         mount.get("RW") is False and mount.get("Source") == os.fspath(snapshot), "ContainerSnapshotMount")


def verify_container(data, image, lock, snapshot, *, entrypoint=None, command=None, tool="lief"):
    pids, memory, cpus, tmpfs, _ = limits(tool)
    need(isinstance(data, dict), "ContainerShape")
    host, inner, state = data.get("HostConfig"), data.get("Config"), data.get("State")
    need(all(isinstance(v, dict) for v in (host, inner, state)), "ContainerConfig")
    need(data.get("Image") == lock.get("image_id"), "ContainerImage")
    need(state.get("Running") is False, "ContainerAlreadyRunning")
    need(inner.get("User") == "65534:65534", "ContainerUser")
    need(inner.get("Entrypoint") == (ENTRYPOINT if entrypoint is None else entrypoint), "ContainerEntrypoint")
    need(inner.get("Cmd") == (["lief.headers", "{}"] if command is None else command), "ContainerCommand")
    need(inner.get("Env") == image["Config"]["Env"], "ContainerEnvironment")
    need(_empty_optional(inner.get("Volumes"), dict), "ContainerVolumes")
    for field, expected in (("Privileged", False), ("ReadonlyRootfs", True), ("Init", True),
                            ("AutoRemove", True), ("NetworkMode", "none"), ("PidsLimit", pids),
                            ("Memory", memory), ("MemorySwap", memory), ("NanoCpus", cpus)):
        value = host.get(field)
        need(type(value) is type(expected) and value == expected, "Container" + field)
    need(host.get("CapDrop") == ["ALL"] and _empty_optional(host.get("CapAdd"), list), "ContainerCapabilities")
    need(host.get("SecurityOpt") in (["no-new-privileges"], ["no-new-privileges:true"]), "ContainerSecurityOpt")
    need(isinstance(host.get("LogConfig"), dict) and host["LogConfig"].get("Type") == "none", "ContainerLogging")
    need(host.get("Tmpfs") == {"/tmp": tmpfs}, "ContainerTmpfs")
    for field in ("Binds", "VolumesFrom", "Devices", "DeviceRequests", "DeviceCgroupRules", "GroupAdd", "ExtraHosts"):
        need(_empty_optional(host.get(field), list), "Container" + field)
    for field in ("PidMode", "UTSMode", "UsernsMode"):
        need(host.get(field) == "", "Container" + field)
    need(_empty_optional(host.get("PortBindings"), dict) and host.get("PublishAllPorts") is False, "ContainerPorts")
    need(host.get("IpcMode") in ("private", ""), "ContainerIpcMode")
    need(host.get("CgroupnsMode") in ("private", ""), "ContainerCgroupnsMode")
    verify_snapshot_mount(data, snapshot)


def validate_probe(name, value, *, tool="lief"):
    pids, memory, _, _, wall = limits(tool)
    need(isinstance(value, dict) and value.get("protocol") == PROBE_PROTOCOL and value.get("probe") == name,
         "ProbeProtocol")
    need(value.get("skipped", False) is False and value.get("status", "ok") == "ok", "ProbeSkippedOrFailed")
    if name == "runtime_identity":
        for key, expected in (("uid", 65534), ("gid", 65534), ("cap_eff", 0), ("cap_prm", 0),
                              ("cap_inh", 0), ("cap_amb", 0), ("no_new_privs", 1), ("seccomp", 2)):
            need(type(value.get(key)) is int and value[key] == expected, "RuntimeIdentity")
        return
    need(name in CONTROL_NAMES and value.get("attempted") is True and value.get("blocked") is True, "ProbeNotBlocked")
    # These errors prove refusal, not its cause: permission or routing can fail first.
    # Read-only/network policy is established separately by the stopped-container inspect.
    errno_values = {"network": (1, 13, 101, 113), "write_root": (1, 13, 30),
                    "write_snapshot": (1, 13, 30), "setuid": (1, 13), "capability": (1, 13)}
    if name in errno_values:
        need(type(value.get("errno")) is int and value["errno"] in errno_values[name], "ProbeWrongFailure")
    elif name == "pids":
        need(type(value.get("errno")) is int and value["errno"] == 11 and
             type(value.get("limit")) is int and value["limit"] == pids and
             type(value.get("spawned")) is int and 1 <= value["spawned"] < pids, "ProcessLimitNotObserved")
    elif name == "memory":
        need(type(value.get("limit")) is int and value["limit"] == memory and
             type(value.get("child_returncode")) is int and value["child_returncode"] == -9 and
             type(value.get("oom_kill_delta")) is int and value["oom_kill_delta"] > 0, "OOMNotObserved")
    elif name == "wall":
        elapsed = value.get("elapsed")
        need(value.get("error") == "WorkerTimeout" and value.get("running_observed") is True and
             type(value.get("timeout")) is int and value["timeout"] == wall and type(elapsed) in (int, float) and
             wall - 0.5 <= elapsed <= wall + 5, "WallLimitNotObserved")
    elif name == "stdout":
        need(value.get("error") == "WorkerOutputLimit" and type(value.get("max_output")) is int and
             value["max_output"] == MAX_WORKER_REPLY_BYTES,
             "OutputLimitNotObserved")


def fixtures():
    data, layout = pe()
    shift = 0x2000 - layout["lfanew"]
    distant = bytearray(data[:layout["lfanew"]] + bytes(shift) + data[layout["lfanew"]:])
    struct.pack_into("<I", distant, 0x3C, 0x2000)
    for index, offset in enumerate(layout["raw_offsets"]):
        struct.pack_into("<I", distant, layout["table_offset"] + shift + 40 * index + 20, offset + shift)
    return {"elf64le": elf()[0], "elf32be": elf(width=32, order=">", machine=8)[0],
            "pe32plus": data, "pe32plus-distant": bytes(distant)}


def load_yarax_ruleset(lock, path=None):
    try:
        with (YARAX_RULESET_PATH if path is None else Path(path)).open("rb") as stream:
            raw = stream.read(65_537)
    except OSError:
        raise VerificationError("YaraxRulesetUnavailable") from None
    need(len(raw) <= 65_536, "YaraxRulesetTooLarge")
    need(isinstance(lock, dict) and lock.get("ruleset_sha256") == sha256_hex(raw) == YARAX_RULESET_SHA256,
         "YaraxRulesetHash")
    value = decode(raw)
    need(isinstance(value, dict) and value.get("ruleset") == YARAX_RULESET_NAME and
         isinstance(value.get("rules"), list), "YaraxRulesetShape")
    return value


def verify_yarax_lock(lock):
    need(isinstance(lock, dict) and
         set(lock) == {"adapter_version", "base_digest", "image_id", "platform", "ruleset_sha256", "wheel_sha256"},
         "YaraxLockPins")
    need(lock["adapter_version"] == YARAX_ADAPTER_VERSION and lock["platform"] == PLATFORM and
         lock["base_digest"] == YARAX_BASE_DIGEST and lock["wheel_sha256"] == YARAX_WHEEL_SHA256 and
         lock["ruleset_sha256"] == YARAX_RULESET_SHA256 and
         bool(re.fullmatch(r"sha256:[0-9a-f]{64}", str(lock["image_id"]))), "YaraxLockPins")


def verify_ghidra_lock(lock):
    keys = {"adapter_version", "base_digest", "image_id", "platform", "ghidra_sha256", "jdk_sha256"}
    need(isinstance(lock, dict), "GhidraLockPins")
    revision = lock.get("adapter_version") == GHIDRA_R7_VERSION
    need(set(lock) == (keys | {"parent_image_id", "bundle_sha256", "cache_format"} if revision else keys),
         "GhidraLockPins")
    need(lock["adapter_version"] in (GHIDRA_ADAPTER_VERSION, GHIDRA_R7_VERSION) and lock["platform"] == PLATFORM and
         lock["base_digest"] == GHIDRA_BASE_DIGEST and lock["ghidra_sha256"] == GHIDRA_SHA256 and
         lock["jdk_sha256"] == GHIDRA_JDK_SHA256 and
         isinstance(lock["image_id"], str) and re.fullmatch(r"sha256:[0-9a-f]{64}", lock["image_id"]),
         "GhidraLockPins")
    if revision:
        need((lock["parent_image_id"] is None or isinstance(lock["parent_image_id"], str)
              and re.fullmatch(r"sha256:[0-9a-f]{64}", lock["parent_image_id"])) and type(lock["cache_format"]) is int
             and lock["cache_format"] == 1 and lock["bundle_sha256"] == ghidra_bundle_hash(), "GhidraRevisionPins")


def ghidra_bundle_hash():
    try:
        paths = {name: GHIDRA_SOURCE / name for name in GHIDRA_BUNDLE_FILES}
        need(all(path.is_file() and not path.is_symlink() for path in paths.values()), "GhidraSourcePins")
        return sha256_hex(canonical_json({name: sha256_hex(path.read_bytes()) for name, path in paths.items()}).encode())
    except OSError:
        raise VerificationError("GhidraSourcePins") from None


def verify_jadx_lock(lock):
    pins = {"adapter_version": JADX_ADAPTER_VERSION, "platform": PLATFORM, "base_digest": JADX_BASE_DIGEST,
            "jadx_zip_sha256": JADX_ZIP_SHA256, "jadx_jar_sha256": JADX_JAR_SHA256,
            "jdk_sha256": JADX_JDK_SHA256}
    need(isinstance(lock, dict) and set(lock) == {*pins, "driver_sha256", "worker_sha256", "image_id"},
         "JadxLockPins")
    need(all(type(lock[key]) is str and lock[key] == value for key, value in pins.items()) and
         isinstance(lock["image_id"], str) and re.fullmatch(r"sha256:[0-9a-f]{64}", lock["image_id"]),
         "JadxLockPins")
    try:
        need(lock["driver_sha256"] == sha256_hex(JADX_DRIVER_PATH.read_bytes()) and
             lock["worker_sha256"] == sha256_hex(JADX_WORKER_PATH.read_bytes()), "JadxSourcePins")
    except OSError:
        raise VerificationError("JadxSourcePins") from None


# Native method forms; the Java spelling remains derived.
JADX_FORMS = {"main_init": "omitted", "helper_int": "java", "helper_string": "java",
              "on_create": "java", "marker_init": "java", "compute": "java",
              "worker_init": "omitted", "run": "java", "helper_overloads": "java", "past_end": "java"}


def _jadx_fixture(data):
    sample, layout = fixtures_apk.apk_basic()
    need(type(data) is bytes and data == sample, "KnownAnswerFixture")
    return layout


def _jadx_targets():
    f = fixtures_apk
    return {
        "main_init": ("classes.dex", f.MAIN, "<init>", "()V"),
        "helper_int": ("classes.dex", f.MAIN, "helper", "(I)I"),
        "helper_string": ("classes.dex", f.MAIN, "helper", "(Ljava/lang/String;)I"),
        "on_create": ("classes.dex", f.MAIN, "onCreate", "(Landroid/os/Bundle;)V"),
        "marker_init": ("classes.dex", f.MARKER, "<init>", "(Ljava/lang/String;)V"),
        "compute": ("classes.dex", f.HELPER, "compute", "(II)I"),
        "worker_init": ("classes2.dex", f.WORKER, "<init>", "()V"),
        "run": ("classes2.dex", f.WORKER, "run", "()V"),
    }


def jadx_cases(data):
    """Fixed public jadx.method args, including both declared helper overloads."""
    _jadx_fixture(data)
    fields = ("member", "class", "method", "prototype")
    cases = {label: {**dict(zip(fields, identity)), "start": 0, "max_chars": 1024}
             for label, identity in _jadx_targets().items()}
    cases["helper_overloads"] = {**cases["helper_int"], "prototype": ""}
    cases["past_end"] = {**cases["helper_int"], "start": 1048575, "max_chars": 64}
    return cases


def _jadx_methods(layout, args):
    methods = sorted((m for c in layout["dex"][args["member"]]["classes"] if c["name"] == args["class"]
                      for m in c["methods"] if m["name"] == args["method"]
                      and args["prototype"] in ("", m["prototype"])), key=lambda m: m["index"])
    need(len(methods) == (2 if args["prototype"] == "" else 1)
         and all(m["code_offset"] is not None and m["code_units"] > 0 for m in methods), "JadxFixtureMethod")
    return methods


def jadx_prepared_request(data, args):
    """Independent fixed worker request, from the fixture declarations only."""
    layout = _jadx_fixture(data)
    need(isinstance(args, dict) and any(canonical_json(args) == canonical_json(case)
         for case in jadx_cases(data).values()), "JadxRequestChanged")
    members = [dict(row["artifact"]) for row in layout["members"] if row["name"] in layout["dex"]]
    member = next(i for i, artifact in enumerate(members) if artifact["member"] == args["member"])
    targets = [{"member": member, "class": args["class"].encode("utf-8").hex(),
                "method": args["method"].encode("utf-8").hex(), "prototype": method["prototype"].encode("utf-8").hex()}
               for method in _jadx_methods(layout, args)]
    return {"members": members, "targets": targets, "start": args["start"], "max_chars": args["max_chars"]}


def jadx_request_allowed(operation, args):
    if operation != "jadx.method" or not isinstance(args, dict):
        return False
    data = fixtures_apk.apk_basic()[0]
    return any(canonical_json(args) == canonical_json(jadx_prepared_request(data, checked))
               for checked in jadx_cases(data).values())


def compare_jadx_observations(data, args, observations):
    """Compare one public case against fixture declarations, without Java spelling pins.

    The expected form comes from the native-measured case table. A missing
    measurement refuses the case until its form is confirmed.
    """
    layout = _jadx_fixture(data)
    need(isinstance(args, dict) and set(args) == {"member", "class", "method", "prototype", "start", "max_chars"}
         and all(type(args[k]) is str for k in ("member", "class", "method", "prototype"))
         and type(args["start"]) is int and type(args["max_chars"]) is int, "JadxRequestChanged")
    matches = [case for case, wanted in jadx_cases(data).items() if wanted == args]
    need(len(matches) == 1, "JadxRequestChanged")
    expected_form = JADX_FORMS.get(matches[0])
    need(expected_form in ("java", "fallback", "omitted", "error"), "JadxOracleMissing")
    methods = _jadx_methods(layout, args)
    need(isinstance(observations, (list, tuple)) and len(observations) == len(methods)
         and all(isinstance(item, Observation) for item in observations), "KnownAnswerShape")
    artifact = next(row["artifact"] for row in layout["members"] if row["name"] == args["member"])
    for item, method in zip(observations, methods):
        need(item.location == Location(method["code_offset"] + 16, min(method["code_units"] * 2, 4096)),
             "JadxKnownAnswerAnchor")
        need(canonical_json(item.artifact) == canonical_json(artifact), "JadxKnownAnswerArtifact")
        value = item.value
        fields = {"kind", "dex", "class", "name", "prototype", "form", "start", "total", "text"}
        need(isinstance(value, dict) and set(value) == fields, "KnownAnswerShape")
        identity = {"kind": "java", "dex": args["member"], "class": args["class"],
                    "name": args["method"], "prototype": method["prototype"]}
        need(all(value[key] == expected for key, expected in identity.items()), "JadxKnownAnswerIdentity")
        forms = ("java", "fallback", "omitted", "error")
        need(value["form"] in forms and value["form"] == expected_form,
             "JadxKnownAnswerForm")
        need(type(value["start"]) is int and type(value["total"]) is int
             and 0 <= value["start"] <= value["total"] < 2**32 and type(value["text"]) is str
             and len(value["text"]) <= args["max_chars"]
             and all(" " <= c <= "~" or c in "\n\t" for c in value["text"])
             and len(canonical_json(value).encode()) <= 4096, "JadxKnownAnswerPage")
        if value["form"] in ("omitted", "error"):
            need(value["text"] == "" and value["start"] == value["total"] == 0, "JadxKnownAnswerPage")
        else:
            need(value["total"] > 0 and value["start"] == min(args["start"], value["total"])
                 and value["start"] + len(value["text"]) <= value["total"]
                 and bool(value["text"]) == (value["start"] < value["total"]), "JadxKnownAnswerPage")
        if matches[0] == "past_end":
            need(0 < value["total"] <= args["start"] and value["start"] == value["total"]
                 and value["text"] == "", "JadxKnownAnswerPage")


def verify_jsparser_lock(lock):
    pins = {"adapter_version": JSPARSER_ADAPTER_VERSION, "platform": PLATFORM, **JSPARSER_PINS}
    need(isinstance(lock, dict) and set(lock) == {*pins, "driver_sha256", "worker_sha256", "image_id"},
         "JsparserLockPins")
    need(all(type(lock[key]) is str and lock[key] == value for key, value in pins.items()) and
         isinstance(lock["image_id"], str) and re.fullmatch(r"sha256:[0-9a-f]{64}", lock["image_id"]),
         "JsparserLockPins")
    try:
        need(lock["driver_sha256"] == sha256_hex(JSPARSER_DRIVER_PATH.read_bytes()) and
             lock["worker_sha256"] == sha256_hex(JSPARSER_WORKER_PATH.read_bytes()), "JsparserSourcePins")
    except OSError:
        raise VerificationError("JsparserSourcePins") from None


# Code-built sources of the dialect archive: every status, dialect, module form and callee rule.
JSPARSER_DIALECT_SOURCES = (
    ("view.tsx", b'import React from "react";\nexport const C = (p: {n: string}) => '
                 b'<div onClick={() => fetch("/x")}>{p.n}</div>;\n'),
    ("plain.jsx", b'const v = <App/>;\nrequire("./x");\neval("1");\n'),
    ("types.ts", b'import fs = require("fs");\nimport type { T } from "./t";\nfs.writeFileSync(p, d);\n'
                 b'Buffer.from(s, "base64");\n'),
    ("latin1.js", b'var s = "caf\xe9";\nrequire("x");\n'),
    ("recover.js", b'const a = 1;\nconst a = 2;\nrequire("still-found");\nfetch(u);\n'),
    ("fatal.js", b'let a = ;\nrequire("lost");\n'),
    ("bom.js", b'\xef\xbb\xbfrequire("bom");\neval(x);\n'),
    ("astral.js", ('const s = "' + chr(0x1F600) * 2 + ' caf' + chr(0xE9) + '";\nrequire("after-astral");\n'
                   'child_process.exec(c);\n').encode()),
    ("forms.js", b'import x from "a";\nexport * from "b";\nexport { y } from \'c\';\nconst z = require(`d`);\n'
                 b'import("e");\nrequire(name);\nrequire(`f${g}`);\nrequire(`h\\08`);\nnew WebSocket("wss://x.example");\n'
                 b'a.b.c.exec();\na.b.c.d.exec();\nwindow["eval"]("x");\nobj?.fetch();\nmap.get(k);\nhttp.get(u);\n'
                 b'(0, eval)(s);\na . b.eval(1);\n\\u0065val(2);\n'),
)


def _jsparser_dialect(name):
    lowered = name.lower()
    return "tsx" if lowered.endswith(".tsx") else "ts" if lowered.endswith(".ts") else (
        "jsx" if lowered.endswith(".jsx") else "js")


def _jsparser_dialects():
    return fixtures_apk.zip_archive([fixtures_apk.member(name, data) for name, data in JSPARSER_DIALECT_SOURCES])


# An npm tarball built in code, its files read through method 1 artifacts.
JSPARSER_TARBALL_SOURCES = (
    ("package/package.json", b'{"name": "fixture", "main": "index.js"}\n'),
    ("package/index.js", b"const cp = require('child_process');\ncp.exec(cmd);\nfetch(url);\n"),
    ("package/lib/util.ts", b"export const run = (s: string) => eval(s);\nBuffer.from(s, 'base64');\n"),
)


def _jsparser_tarball():
    """(gzip bytes, [(name, method 1 artifact)]) of a reproducible tar of JSPARSER_TARBALL_SOURCES, built here."""
    import gzip
    import tarfile
    import zlib
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, body in JSPARSER_TARBALL_SOURCES:
            info = tarfile.TarInfo(name)
            info.size, info.mtime, info.mode, info.uid, info.gid = len(body), 0, 0o644, 0, 0
            archive.addfile(info, io.BytesIO(body))
    tar = buffer.getvalue()
    data = gzip.compress(tar, compresslevel=9, mtime=0)
    with tarfile.open(fileobj=io.BytesIO(tar)) as archive:
        rows = [(info.name, {"member": info.name, "method": 1, "data_offset": 0, "compressed_size": len(data),
                             "inner_offset": info.offset_data, "size": info.size,
                             "crc32": zlib.crc32(tar[info.offset_data:info.offset_data + info.size]),
                             "sha256": sha256_hex(tar[info.offset_data:info.offset_data + info.size])})
                for info in archive.getmembers()]
    return data, rows


def jsparser_fixtures():
    # js_boundary is exactly the 4 MiB a single file may have: the host refuses one byte more before any worker,
    # so the worker's too_large row is covered by its unit tests, not by a native case.
    tarball = _jsparser_tarball()[0]
    # js_tarball_bad flips one bit of the gzip trailer's CRC-32: the worker must refuse the stream ("input")
    return {"js_app": fixtures_js.app_zip()[0], "js_bundle": fixtures_js.bundle_js()[0],
            "js_dialects": _jsparser_dialects()[0], "js_boundary": b"var a = 1;\n" * 381300 + b"//xx",
            "js_tarball": tarball, "js_tarball_bad": tarball[:-8] + bytes([tarball[-8] ^ 1]) + tarball[-7:]}


def jsparser_cases(fixtures):
    """Fixed public jsparser.syntax requests (fixture name, args), built from the fixtures' own declarations."""
    need(isinstance(fixtures, dict) and set(fixtures) == {"js_app", "js_bundle", "js_dialects", "js_boundary",
                                                          "js_tarball", "js_tarball_bad"} and
         all(type(fixtures[name]) is bytes and fixtures[name] == value for name, value in jsparser_fixtures().items()),
         "KnownAnswerFixture")

    def entries(rows):
        return [{"artifact": dict(row["artifact"]), "dialect": _jsparser_dialect(row["name"])} for row in rows
                if row["name"].rsplit("/", 1)[-1] != "package.json"]

    def case(fixture, files, kind, start=0, limit=256):
        return fixture, {"files": files, "kind": kind, "start": start, "limit": limit, "callees": list(JSPARSER_CALLEES)}

    app = entries(fixtures_js.app_zip()[1]["files"])
    dialects = entries(_jsparser_dialects()[1]["members"])
    tarball = entries({"name": name, "artifact": artifact} for name, artifact in _jsparser_tarball()[1])
    single = [{"artifact": None, "dialect": "js"}]
    tampered = [dict(entry) for entry in app]
    tampered[1] = {**tampered[1], "artifact": {**tampered[1]["artifact"], "sha256": "0" * 64}}
    return {"app_modules": case("js_app", app, "modules"), "app_calls": case("js_app", app, "calls"),
            "app_page": case("js_app", app, "calls", 3, 4), "app_parse": case("js_app", app, "parse"),
            "bundle_modules": case("js_bundle", single, "modules"), "bundle_calls": case("js_bundle", single, "calls"),
            "dialects_modules": case("js_dialects", dialects, "modules"),
            "dialects_calls": case("js_dialects", dialects, "calls"),
            "dialects_parse": case("js_dialects", dialects, "parse"),
            "boundary_parse": case("js_boundary", single, "parse"), "input_mismatch": case("js_app", tampered, "modules"),
            "tarball_calls": case("js_tarball", tarball, "calls"),
            "tarball_tampered": case("js_tarball_bad", tarball, "modules")}


def _jsparser_rows(*rows):
    return [{"file": index, "status": status, "errors": errors, "count": count,
             "items": [{"kind": kind, "start": start, "end": end} for kind, start, end in items]}
            for index, (status, errors, count, items) in enumerate(rows)]


# Known answers, checked natively: one tuple per file, (status, errors, count, page items).
JSPARSER_EXPECTED = {
    "app_modules": _jsparser_rows(("ok", 0, 0, ()), ("ok", 0, 2, (("require", 119, 134), ("require", 156, 160))),
        ("ok", 0, 0, ()), ("ok", 0, 0, ()), ("ok", 0, 0, ()), ("ok", 0, 0, ()), ("ok", 0, 0, ())),
    "app_calls": _jsparser_rows(("ok", 0, 0, ()), ("ok", 0, 1, (("call", 337, 342),)), ("ok", 0, 4, (("call", 92, 97),
        ("call", 189, 193), ("call", 220, 228), ("call", 277, 286))), ("ok", 0, 2, (("call", 324, 335),
        ("call", 410, 414))), ("ok", 0, 1, (("call", 1322, 1336),)), ("ok", 0, 0, ()), ("ok", 0, 0, ())),
    "app_page": _jsparser_rows(("ok", 0, 0, ()), ("ok", 0, 1, ()), ("ok", 0, 4, (("call", 220, 228),
        ("call", 277, 286))), ("ok", 0, 2, (("call", 324, 335), ("call", 410, 414))), ("ok", 0, 1, ()),
        ("ok", 0, 0, ()), ("ok", 0, 0, ())),
    "app_parse": _jsparser_rows(("ok", 0, 0, ()), ("ok", 0, 0, ()), ("ok", 0, 0, ()), ("ok", 0, 0, ()),
        ("ok", 0, 0, ()), ("ok", 0, 0, ()), ("ok", 0, 0, ())),
    "bundle_modules": _jsparser_rows(("ok", 0, 1, (("require", 173, 188),))),
    "bundle_calls": _jsparser_rows(("ok", 0, 5, (("call", 105, 109), ("call", 136, 140), ("call", 190, 200),
        ("call", 211, 216), ("call", 494, 502)))),
    "dialects_modules": _jsparser_rows(("ok", 0, 1, (("import", 18, 25),)), ("ok", 0, 1, (("require", 26, 31),)),
        ("ok", 0, 2, (("require", 20, 24), ("import", 50, 55))), ("decode_error", 0, 0, ()),
        ("syntax_error", 1, 1, (("require", 34, 47),)), ("syntax_error", 1, 0, ()),
        ("ok", 0, 1, (("require", 8, 13),)), ("ok", 0, 1, (("require", 31, 45),)),
        ("syntax_error", 1, 5, (("import", 14, 17), ("export_from", 33, 36), ("export_from", 56, 59),
        ("require", 79, 82), ("dynamic_import", 92, 95)))),
    "dialects_calls": _jsparser_rows(("ok", 0, 1, (("call", 84, 89),)), ("ok", 0, 1, (("call", 34, 38),)),
        ("ok", 0, 2, (("call", 57, 73), ("call", 81, 92))), ("decode_error", 0, 0, ()),
        ("syntax_error", 1, 1, (("call", 50, 55),)), ("syntax_error", 1, 0, ()), ("ok", 0, 1, (("call", 16, 20),)),
        ("ok", 0, 1, (("call", 48, 66),)), ("syntax_error", 1, 2, (("call", 152, 161), ("call", 259, 267)))),
    "dialects_parse": _jsparser_rows(("ok", 0, 0, ()), ("ok", 0, 0, ()), ("ok", 0, 0, ()), ("decode_error", 0, 0, ()),
        ("syntax_error", 1, 0, ()), ("syntax_error", 1, 0, ()), ("ok", 0, 0, ()), ("ok", 0, 0, ()),
        ("syntax_error", 1, 0, ())),
    "boundary_parse": _jsparser_rows(("ok", 0, 0, ())),
    "input_mismatch": {"error": "input"},
    "tarball_calls": _jsparser_rows(("ok", 0, 2, (("call", 37, 44), ("call", 51, 56))),
        ("ok", 0, 2, (("call", 34, 38), ("call", 43, 54)))),
    "tarball_tampered": {"error": "input"},
}


def jsparser_request_allowed(operation, args):
    """Only the fixed case requests may reach the worker during a native run."""
    try:
        allowed = {canonical_json(request) for _, request in jsparser_cases(jsparser_fixtures()).values()}
        return operation == "jsparser.syntax" and canonical_json(args) in allowed
    except (VerificationError, TypeError, ValueError):
        return False


def compare_jsparser_reply(data, case, value):
    """The worker's reply equals the case's known answer exactly (rows, statuses, counts, page items), or its error."""
    need(case in JSPARSER_EXPECTED, "JsparserOracleMissing")
    expected = JSPARSER_EXPECTED[case]
    need(isinstance(value, dict) and value.get("protocol") == "reverseai.worker/1" and
         value.get("snapshot_sha256") == sha256_hex(data), "JsparserReplyIdentity")
    if isinstance(expected, dict):
        need(set(value) == {"protocol", "status", "snapshot_sha256", "error"} and value["status"] == "error" and
             value["error"] == expected["error"], "JsparserKnownAnswerError")
        return 0
    need(set(value) == {"protocol", "status", "snapshot_sha256", "observations"} and value["status"] == "ok" and
         canonical_json(value["observations"]) == canonical_json(expected), "JsparserKnownAnswer")
    return len(expected)


def ghidra_fixtures():
    return dict(zip(GHIDRA_FIXTURE_NAMES, (elf_code()[0], pe_code()[0], elf_data_only()[0], macho_code()[0],
                                         elf_refs()[0], pe_refs()[0], macho_refs()[0])))


def ghidra_args():
    return {"max_functions": 64, "decompile": 8, "max_chars": 1024, "max_calls": 128,
            "assembly": 4, "max_instructions": 32, "max_refs": 64, "max_strings": 32}


def ghidra_query_requests(data):
    """Fixed requests on the declared refs-fixture addresses; these do not assert Ghidra's readings."""
    layout = next((layout for sample, layout in (elf_refs(), pe_refs(), macho_refs()) if sample == data), None)
    need(layout is not None, "KnownAnswerFixture")
    base = layout["text"]["address"]
    function = {"select": "entry", "entry": base + 0x20, "name": "", "parts": "all", "start": 1,
                "limit": 2, "max_chars": 1024, "max_calls": 64, "max_refs": 64}
    return {
        "functions_page": ("ghidra.functions", {"query": "", "start": 1, "limit": 2}),
        "function_add": ("ghidra.function", function),
        "function_constant": ("ghidra.function", {**function, "entry": base + 0x50, "parts": "callers",
                                                  "start": 0, "limit": 64}),
        "xrefs_counter": ("ghidra.xrefs", {"address": layout["data"]["address"] + 0x40, "start": 0, "limit": 64}),
    }


def ghidra_request_allowed(operation, args):
    expected = [("ghidra.analyze", ghidra_args())]
    if operation != "ghidra.analyze":
        expected = [request for data in (elf_refs()[0], pe_refs()[0], macho_refs()[0])
                    for request in ghidra_query_requests(data).values()]
    return any(operation == name and canonical_json(args) == canonical_json(checked) for name, checked in expected)


def ghidra_query_case(data, operation, args):
    matches = [case for case, (name, checked) in ghidra_query_requests(data).items()
               if operation == name and canonical_json(args) == canonical_json(checked)]
    need(len(matches) == 1, "GhidraRequestChanged")
    return matches[0]


def compare_ghidra_query(data, operation, args, observations):
    """Exact ordered rows and byte anchors from the measured, fixed native request cases."""
    case = ghidra_query_case(data, operation, args)
    expected = GHIDRA_QUERY_EXPECTED.get(sha256_hex(data), {}).get(case)
    need(isinstance(expected, list) and bool(expected), "GhidraQueryOracleMissing")
    need(isinstance(observations, (list, tuple)) and all(isinstance(o, Observation) for o in observations),
         "KnownAnswerShape")
    actual = [{"location": {"offset": o.location.offset, "length": o.location.length}, "value": o.value}
              for o in observations]
    need(canonical_json(actual) == canonical_json(expected), "GhidraQueryKnownAnswer")


def compare_ghidra_observations(data, observations):
    """Check fixture entries/calls/symbols and require working decompilation."""
    need(type(data) is bytes and isinstance(observations, (list, tuple)), "KnownAnswerShape")
    layout = next((layout for sample, layout in (elf_code(), pe_code(), elf_data_only(), macho_code(),
                                                elf_refs(), pe_refs(), macho_refs()) if sample == data), None)
    need(layout is not None, "KnownAnswerFixture")
    groups = {"function": [], "pseudocode": [], "call": [], "assembly": [], "ref": [], "string": []}
    schemas = {"function": {"kind", "index", "name", "entry", "size"},
               "pseudocode": {"kind", "index", "entry", "text", "truncated"},
               "call": {"kind", "from", "to", "to_name"},
               "assembly": {"kind", "index", "entry", "instructions", "truncated"},
               "ref": {"kind", "from", "to", "type", "to_name"},
               "string": {"kind", "address", "encoding", "text", "truncated", "from"}}
    for item in observations:
        need(isinstance(item, Observation) and item.location.within(len(data)), "KnownAnswerLocation")
        value = item.value
        kind = value.get("kind")
        need(type(kind) is str and kind in groups and set(value) == schemas[kind], "KnownAnswerSchema")
        groups[kind].append(item)
    functions, calls = groups["function"], groups["call"]
    # The pinned Ghidra reads the refs fixtures' tail jump as CALL_TERMINATOR.
    entries = {row["entry"] for row in layout["functions"]}
    tail_calls = [row for row in layout.get("refs", []) if row["type"] == "jump" and row["to"] in entries]
    expected_calls = sorted(layout["calls"] + tail_calls,
                            key=lambda row: row["offset"])
    expected_refs = [row for row in layout.get("refs", []) if row not in tail_calls]
    need(len(functions) == len(layout["functions"]) and len(calls) == len(expected_calls), "KnownAnswerCount")
    need(not layout["functions"] or groups["pseudocode"], "KnownAnswerPseudocodeMissing")
    for index, (item, expected) in enumerate(zip(functions, layout["functions"])):
        value = item.value
        mapped_size = layout.get("text_raw_size", layout["text"]["size"])
        if layout["format"] == "pe":
            mapped_size = min(mapped_size, layout["text"]["size"] or mapped_size)
        remaining = mapped_size - (expected["offset"] - layout["text"]["offset"])
        need(type(value["index"]) is int and value["index"] == index and
             type(value["entry"]) is int and value["entry"] == expected["entry"] and
             type(value["size"]) is int and 1 <= value["size"] and value["entry"] + value["size"] <= 2**64,
             "KnownAnswerFunction")
        need(item.location.offset == expected["offset"] and
             item.location.length == min(value["size"], 4096, remaining), "KnownAnswerFunctionAnchor")
        need(type(value["name"]) is str and 1 <= len(value["name"]) <= 128 and
             value["name"].isprintable(), "KnownAnswerName")
        if layout["format"] in ("elf", "macho"):
            name = "entry" if layout["format"] == "macho" and expected["entry"] == layout["entry"] else expected["name"]
            need(value["name"] == name,
                 "KnownAnswerELFName" if layout["format"] == "elf" else "KnownAnswerMachOName")
    names = {item.value["entry"]: item.value["name"] for item in functions}
    for item, expected in zip(calls, expected_calls):
        value = item.value
        need(type(value["from"]) is int and type(value["to"]) is int and
             (value["from"], value["to"]) == (expected["from"], expected["to"]) and
             (item.location.offset, item.location.length) == (expected["offset"], expected["length"]),
             "KnownAnswerCall")
        need(type(value["to_name"]) is str and value["to_name"] == names[value["to"]], "KnownAnswerName")
    seen = set()
    for item in groups["pseudocode"]:
        value = item.value
        index = value["index"]
        need(type(index) is int and 0 <= index < len(functions) and index not in seen, "KnownAnswerPseudocode")
        function = functions[index]
        need(type(value["entry"]) is int and value["entry"] == function.value["entry"] and
             item.location == function.location and type(value["text"]) is str and len(value["text"]) <= 1024 and
             type(value["truncated"]) is bool, "KnownAnswerPseudocode")
        seen.add(index)
    selection = sorted(functions, key=lambda item: (item.value["entry"] != layout["entry"],
                                                   -item.value["size"], item.value["entry"]))[:4]
    assembly = groups["assembly"]
    if "refs" in layout:
        need(len(assembly) == len(selection), "KnownAnswerAssemblyMissing")
    for item, function in zip(assembly, selection):
        value = item.value
        need(type(value["index"]) is int and value["index"] == function.value["index"] and
             type(value["entry"]) is int and value["entry"] == function.value["entry"] and
             item.location == function.location and type(value["truncated"]) is bool,
             "KnownAnswerAssemblyAnchor")
        rows = value["instructions"]
        need(type(rows) is list and 1 <= len(rows) <= 32, "KnownAnswerInstructions")
        end = 0
        for row in rows:
            need(type(row) is list and len(row) == 3, "KnownAnswerInstruction")
            delta, length, text = row
            need(type(delta) is int and type(length) is int and end <= delta and 1 <= length <= 16
                 and delta + length <= item.location.length and type(text) is str and 1 <= len(text) <= 64
                 and all(0x20 <= ord(c) <= 0x7e for c in text), "KnownAnswerInstruction")
            end = delta + length
        expected = layout["functions"][function.value["index"]].get("instructions")
        if expected is not None:
            listed = [row for row in expected if sum(row) <= item.location.length][:32]
            need([row[:2] for row in rows] == listed and value["truncated"] == (len(listed) < len(expected)),
                 "KnownAnswerInstructions")
    need(len(assembly) <= len(selection), "KnownAnswerAssemblyCount")
    refs = groups["ref"]
    need(len(refs) == len(expected_refs), "KnownAnswerRefCount")
    for item, expected in zip(refs, expected_refs):
        value = item.value
        need(type(value["from"]) is int and type(value["to"]) is int and
             (value["from"], value["to"]) == (expected["from"], expected["to"]) and
             (item.location.offset, item.location.length) == (expected["offset"], expected["length"]) and
             value["type"] == expected["type"] and
             type(value["to_name"]) is str and len(value["to_name"]) <= 128 and
             all(c.isprintable() for c in value["to_name"]), "KnownAnswerRef")
    strings = groups["string"]
    need(len(strings) == len(layout.get("strings", [])), "KnownAnswerStringCount")
    for item, expected in zip(strings, layout.get("strings", [])):
        value = item.value
        need(type(value["address"]) is int and type(value["truncated"]) is bool and
             type(value["from"]) is list and all(type(entry) is int for entry in value["from"]) and
             value == {"kind": "string", **{key: expected[key] for key in ("address", "encoding", "text", "truncated", "from")}}
             and (item.location.offset, item.location.length) == (expected["offset"], expected["length"]),
             "KnownAnswerString")


def yarax_fixtures():
    return {
        "upx_markers": b"\x00UPX!----UPX0----UPX1\x00-EncodedCommand\x00FromBase64String\x00sekurlsa::",
        "utf16_markers": b"\x00\x00" + "-EncodedCommand\x00FromBase64String\x00sekurlsa::".encode("utf-16le"),
        "clean": b"deterministic clean fixture\x00",
        "repeated_markers": b"UPX!" * 80 + b"sekurlsa::",
    }


def compare_yarax_observations(data, observations, ruleset, max_matches=64):
    need(isinstance(data, bytes) and isinstance(observations, (list, tuple)) and
         type(max_matches) is int and 1 <= max_matches <= 64, "KnownAnswerShape")
    expected = []
    for rule in ruleset["rules"]:
        for pattern in rule["patterns"]:
            needle, start = bytes.fromhex(pattern["hex"]), 0
            for _ in range(min(YARAX_MATCHES_PER_PATTERN, max_matches)):
                offset = data.find(needle, start)
                if offset < 0:
                    break
                expected.append((offset, len(needle), YARAX_RULESET_NAME, rule["id"], pattern["id"]))
                start = offset + 1
    expected.sort(key=lambda row: (row[0], row[3], row[4]))
    expected = expected[:max_matches]
    actual = []
    for item in observations:
        need(isinstance(item, Observation) and item.location.within(len(data)), "KnownAnswerLocation")
        need(set(item.value) == {"ruleset", "rule", "pattern"} and
             all(type(item.value[key]) is str for key in ("ruleset", "rule", "pattern")), "KnownAnswerMatch")
        actual.append((item.location.offset, item.location.length,
                       item.value["ruleset"], item.value["rule"], item.value["pattern"]))
    need(actual == expected, "KnownAnswerMatches")


def compare_observations(data, operation, observations):
    need(operation in ("lief.headers", "lief.sections") and isinstance(observations, (list, tuple)), "KnownAnswerShape")
    for item in observations:
        need(isinstance(item, Observation) and item.location.within(len(data)), "KnownAnswerLocation")
    headers = structure.headers(data, {})
    expected = headers[0].value
    if operation == "lief.headers":
        kind = expected["format"]
        count = "shnum" if kind == "elf" else "number_of_sections"
        for key in ("format", "machine_name", count):
            values = [item.value[key] for item in observations if key in item.value]
            need(len(values) == 1 and type(values[0]) is type(expected[key]) and values[0] == expected[key],
                 "KnownAnswerHeader")
        if kind == "elf":
            need(len(observations) == 1 and observations[0].location == headers[0].location, "KnownAnswerPhysicalHeader")
        else:
            pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
            optional_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
            records = {item.value.get("structure"): item for item in observations}
            need(len(observations) == 3 and set(records) == {"dos", "coff", "optional"}, "KnownAnswerPEParts")
            need((records["dos"].location.offset, records["dos"].location.length) == (0, 64) and
                 records["dos"].value.get("e_lfanew") == pe_offset, "KnownAnswerDOS")
            need((records["coff"].location.offset, records["coff"].location.length) == (pe_offset, 24) and
                 all(key in records["coff"].value for key in ("format", "machine_name", count)), "KnownAnswerCOFF")
            optional = records["optional"].location
            need(optional.offset == pe_offset + 24 and 20 <= optional.length <= optional_size, "KnownAnswerOptional")
    else:
        expected_sections = structure.sections(data, {"max_sections": 64})
        need(len(observations) == len(expected_sections), "KnownAnswerSectionCount")
        for got, want in zip(observations, expected_sections):
            need(got.location == want.location and all(type(got.value.get(k)) is type(want.value[k]) and
                 got.value[k] == want.value[k] for k in ("index", "offset", "size", "writable", "executable")),
                 "KnownAnswerSection")


def receipt_passes(receipt):
    try:
        tool = receipt.get("tool")
        need(receipt.get("schema") == "reverseai.m2-runtime/1" and receipt.get("platform") == PLATFORM and
             tool in ("lief", "yarax", "ghidra", "jadx", "jsparser") and receipt.get("profile") == "small" and
             receipt.get("offline") is True,
             "ReceiptIdentity")
        for key in ("lock_sha256", "verifier_sha256", "executor_sha256"):
            need(bool(re.fullmatch(r"[0-9a-f]{64}", receipt.get(key, ""))), "ReceiptBinding")
        pins = receipt["lock"]
        need(pins["platform"] == PLATFORM and receipt["image_id"] == pins["image_id"] and
             bool(re.fullmatch(r"sha256:[0-9a-f]{64}", pins["image_id"])), "ReceiptImage")
        if tool in ("ghidra", "jadx", "jsparser"):
            {"ghidra": verify_ghidra_lock, "jadx": verify_jadx_lock, "jsparser": verify_jsparser_lock}[tool](pins)
            need("ruleset_sha256" not in receipt and "wheel_sha256" not in receipt,
                 {"ghidra": "ReceiptGhidraPins", "jadx": "ReceiptJadxPins", "jsparser": "ReceiptJsparserPins"}[tool])
        else:
            need(bool(re.fullmatch(r"sha256:[0-9a-f]{64}", pins["base_digest"])) and
                 bool(re.fullmatch(r"[0-9a-f]{64}", pins["wheel_sha256"])) and
                 pins["adapter_version"] == ("1.0.0-r2" if tool == "lief" else YARAX_ADAPTER_VERSION), "ReceiptLockPins")
            if tool == "yarax":
                verify_yarax_lock(pins)
                need(receipt.get("ruleset_sha256") == YARAX_RULESET_SHA256, "ReceiptYaraxPins")
        required, runs = required_checks(tool), native_runs(tool)
        rows = receipt["checks"]
        need(isinstance(rows, list) and len(rows) == len(required) and
             {r["id"] for r in rows} == set(required) and all(r["status"] == "passed" for r in rows),
             "ReceiptChecks")
        cleanup = receipt["cleanup"]
        need(len(cleanup) == runs and len({r["container_id"] for r in cleanup}) == runs and
             all(re.fullmatch(r"[0-9a-f]{64}", r["container_id"]) and r["verified"] is True and
                 r["staging_removed"] is True for r in cleanup), "ReceiptCleanup")
        return True
    except (VerificationError, KeyError, TypeError, AttributeError):
        return False


def probe_code(name, *, tool="lief"):
    """Fixed trusted probes only; none of this code is supplied by a sample."""
    pids, memory, _, _, wall = limits(tool)
    bodies = {
        "runtime_identity": """
            fields = dict(line.split(':', 1) for line in open('/proc/self/status') if ':' in line)
            r.update(uid=os.getuid(), gid=os.getgid(),
                     cap_eff=int(fields['CapEff'],16), cap_prm=int(fields['CapPrm'],16),
                     cap_inh=int(fields['CapInh'],16), cap_amb=int(fields['CapAmb'],16),
                     no_new_privs=int(fields['NoNewPrivs']), seccomp=int(fields['Seccomp']))
        """,
        "network": """
            try:
                with socket.socket() as connection:
                    connection.settimeout(1)
                    connection.connect(('198.51.100.1',443))
            except OSError as exc:
                r.update(blocked=True,errno=exc.errno)
        """,
        "write_root": """
            try:
                with open('/reverseai-negative-control','xb') as stream:
                    stream.write(b'x')
            except OSError as exc:
                r.update(blocked=True,errno=exc.errno)
        """,
        "write_snapshot": """
            try:
                with open('/snapshot/input','ab') as stream:
                    stream.write(b'x')
            except OSError as exc:
                r.update(blocked=True,errno=exc.errno)
        """,
        "setuid": """
            try:
                os.setuid(0)
            except OSError as exc:
                r.update(blocked=True,errno=exc.errno)
        """,
        "capability": """
            try:
                with socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP):
                    pass
            except OSError as exc:
                r.update(blocked=True,errno=exc.errno)
        """,
        "pids": f"""
            children=[]
            r['limit']=int(open('/sys/fs/cgroup/pids.max').read())
            try:
                for _ in range({pids + 16}):
                    try:
                        child=os.fork()
                    except OSError as exc:
                        r.update(blocked=True,errno=exc.errno)
                        break
                    if child==0:
                        time.sleep(8)
                        os._exit(0)
                    children.append(child)
                r['spawned']=len(children)
            finally:
                for child in children:
                    try:
                        os.kill(child,9)
                    except ProcessLookupError:
                        pass
                for child in children:
                    os.waitpid(child,0)
        """,
        "memory": f"""
            def oom_kills():
                return int(dict(line.split() for line in open('/sys/fs/cgroup/memory.events'))['oom_kill'])
            r['limit']=int(open('/sys/fs/cgroup/memory.max').read())
            before=oom_kills()
            child=subprocess.run([sys.executable,'-I','-B','-c','x=bytearray({memory // 1024**2 + 88}*1024*1024);x[0]=1'],
                                 stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
            r.update(child_returncode=child.returncode,oom_kill_delta=oom_kills()-before,
                     blocked=child.returncode==-9)
        """,
    }
    if name == "wall":
        return f"import time; time.sleep({wall + 15})"
    if name == "stdout":
        return f"import sys; sys.stdout.buffer.write(b'x'*{MAX_WORKER_REPLY_BYTES + 1}); sys.stdout.buffer.flush()"
    need(name in bodies, "UnknownProbe")
    header = ("import json,os,socket,subprocess,sys,time\n"
              + "r=" + repr({"protocol": PROBE_PROTOCOL, "probe": name, "attempted": True, "blocked": False}) + "\n")
    return header + textwrap.dedent(bodies[name]) + "\nprint(json.dumps(r,separators=(',',':')),flush=True)\n"


def derive_control_argv(argv, image_id, code=None):
    """Change only the lifecycle and, for controls, the fixed entrypoint/tail."""
    need(isinstance(argv, list) and all(isinstance(v, str) for v in argv) and
         argv[:2] == ["docker", "run"] and argv.count(image_id) == 1, "BuilderArgv")
    need(code is None or isinstance(code, str), "ControlCodeType")
    at = argv.index(image_id)
    options = argv[2:at]
    pulls = [index for index, value in enumerate(options) if value == "--pull"]
    need(len(pulls) == 1 and pulls[0] + 1 < len(options) and options[pulls[0] + 1] == "never" and
         not any(value.startswith("--pull=") for value in options), "BuilderPullPolicy")
    result = list(argv)
    result[1] = "create"
    if code is not None:
        result = result[:at] + ["--entrypoint", "python3", image_id, "-I", "-B", "-c", code]
    # Flags are copied verbatim; exact-output tests cover both transformations.
    return result


class NativeVerifier:
    """A native controller; constructors and all unit validators are Docker-free."""

    def __init__(self, boundary, lock, receipt, *, tool="lief", ruleset=None):
        need(tool in ("lief", "yarax", "ghidra", "jadx", "jsparser"), "VerifierTool")
        need(tool != "yarax" or isinstance(ruleset, dict), "YaraxRulesetShape")
        if tool == "yarax":
            verify_yarax_lock(lock)
        if tool == "ghidra":
            verify_ghidra_lock(lock)
            verify_ghidra_executor_profile(boundary)
        if tool == "jadx":
            verify_jadx_lock(lock)
            verify_jadx_executor_profile(boundary)
        if tool == "jsparser":
            verify_jsparser_lock(lock)
            verify_jsparser_executor_profile(boundary)
        self.boundary, self.lock, self.receipt = boundary, lock, receipt
        self.tool, self.ruleset = tool, ruleset
        self.native_runs = native_runs(tool)
        self.wall = limits(tool)[4]
        self.image = None
        self.active = None
        self.inspected = 0
        self.last = None

    def docker(self, args, *, cap=1_048_576):
        return self.boundary.run_bounded(["docker", *args], timeout=5, max_output=cap)

    def run_bounded(self, argv, *, timeout, max_output):
        options = {"profile": self.tool} if self.tool in ("ghidra", "jadx", "jsparser") else {}
        return self.boundary.run_bounded(argv, timeout=timeout, max_output=max_output, **options)

    def one_inspect(self, args):
        value = decode(self.docker(args))
        need(isinstance(value, list) and len(value) == 1 and isinstance(value[0], dict), "InspectShape")
        return value[0]

    def local_daemon(self):
        need(not os.environ.get("DOCKER_HOST") and not os.environ.get("DOCKER_CONTEXT"), "DockerEnvironmentOverride")
        context = self.one_inspect(["context", "inspect"])
        endpoint = context.get("Endpoints", {}).get("docker", {}).get("Host", "")
        need(isinstance(endpoint, str) and endpoint.startswith("unix:///"), "NonlocalDockerDaemon")
        server = decode(self.docker(["version", "--format", "{{json .Server}}"], cap=65_536))
        need(isinstance(server, dict) and server.get("Os") == "linux" and server.get("Arch") == "arm64", "DaemonPlatform")
        return {"os": server["Os"], "arch": server["Arch"], "version": server.get("Version")}

    def image_check(self):
        self.image = self.one_inspect(["image", "inspect", self.lock["image_id"]])
        verify_image(self.image, self.lock)
        self.receipt["image_id"] = self.image["Id"]
        return {"image_id": self.image["Id"], "platform": PLATFORM}

    def absent(self, container_id):
        try:
            output = self.docker(["ps", "--all", "--no-trunc", "--filter", "id=" + container_id,
                                  "--format", "{{.ID}}"], cap=256)
            return output.strip() == b""
        except Exception:
            return False

    def cleanup(self, row):
        try:
            self.docker(["rm", "--force", row["container_id"]], cap=256)
        except Exception:
            pass  # An auto-removed container is proved absent by a successful ps.
        row["verified"] = self.absent(row["container_id"])
        need(row["verified"], "ContainerCleanupUnverified")

    def reconcile_create(self, name, snapshot):
        row = {"container_id": None, "container_name": name, "uncertain_create": True,
               "verified": False, "staging_removed": False}
        self.receipt["cleanup"].append(row)
        self.last = (row, Path(snapshot))
        try:
            raw = self.docker(["ps", "--all", "--no-trunc", "--filter", "name=^/" + name + "$",
                               "--format", "{{.ID}}"], cap=256)
            ids = raw.decode("ascii").strip().splitlines()
            need(len(ids) <= 1 and all(re.fullmatch(r"[0-9a-f]{64}", cid) for cid in ids), "CreateLookupID")
            if ids:
                cid = ids[0]
                data = self.one_inspect(["inspect", cid])
                need(data.get("Id") == cid and data.get("Name") == "/" + name and
                     data.get("Image") == self.lock["image_id"], "CreateLookupOwnership")
                verify_snapshot_mount(data, snapshot)
                row["container_id"] = cid
                self.cleanup(row)
            else:
                row["verified"] = True  # Observed absent at this lookup; a late daemon create remains possible.
        except Exception:
            raise VerificationError("CreateCleanupUnverified") from None

    def runner(self, argv, *, timeout, max_output):
        if argv[:2] != ["docker", "run"]:
            return self.run_bounded(argv, timeout=timeout, max_output=max_output)
        need(type(timeout) is int and timeout == self.wall,
             "ExecutorLimitsChanged")
        name = argv[argv.index("--name") + 1]
        need(bool(re.fullmatch(r"reverseai-[a-z0-9-]{1,64}", name)), "BuilderContainerName")
        mount = next(csv.reader(io.StringIO(argv[argv.index("--mount") + 1])))
        sources = [item.removeprefix("source=") for item in mount if item.startswith("source=")]
        need(len(sources) == 1, "BuilderSnapshot")
        snapshot = sources[0]
        at = argv.index(self.lock["image_id"])
        operation, args = argv[at + 1], decode(argv[at + 2])
        if self.tool == "ghidra":
            need(self.ghidra_request_allowed(operation, args), "GhidraRequestChanged")
        need(type(max_output) is int and max_output == (64 * 1024**2 if operation == "ghidra.prepare"
                                                       else MAX_WORKER_REPLY_BYTES), "ExecutorLimitsChanged")
        if self.tool == "jadx":
            need(jadx_request_allowed(operation, args), "JadxRequestChanged")
        if self.tool == "jsparser":
            need(jsparser_request_allowed(operation, args), "JsparserRequestChanged")
        need(argv == self.boundary.build_argv(self.lock["image_id"], name, snapshot, operation, args), "BuilderMismatch")
        code = self.control_code() if self.active is not None else None
        created = derive_control_argv(argv, self.lock["image_id"], code)
        try:
            raw = self.boundary.run_bounded(created, timeout=5, max_output=128)
            need(isinstance(raw, bytes), "CreatedContainerID")
            cid = raw.decode("ascii", errors="replace").strip()
            need(bool(re.fullmatch(r"[0-9a-f]{64}", cid)), "CreatedContainerID")
        except BaseException:
            self.reconcile_create(name, snapshot)
            raise
        row = {"container_id": cid, "verified": False, "staging_removed": False}
        self.receipt["cleanup"].append(row)
        self.last = (row, Path(snapshot))
        stop, running = threading.Event(), threading.Event()
        watcher = None
        try:
            data = self.one_inspect(["inspect", cid])
            need(data.get("Id") == cid, "InspectContainerID")
            command = argv[at + 1:] if code is None else ["-I", "-B", "-c", code]
            entrypoint = ENTRYPOINT if code is None else ["python3"]
            verify_container(data, self.image, self.lock, snapshot, entrypoint=entrypoint, command=command,
                             tool=self.tool)
            self.inspected += 1
            if self.active == "wall":
                def observe_running():
                    while not stop.is_set():
                        try:
                            raw = self.boundary.run_bounded(["docker", "inspect", "--format", "{{.State.Running}}", cid],
                                                            timeout=2, max_output=16)
                            if raw.strip() == b"true":
                                running.set()
                                return
                        except Exception:
                            pass
                        stop.wait(0.1)
                watcher = threading.Thread(target=observe_running, daemon=True)
                watcher.start()
            started = time.monotonic()
            try:
                return self.run_bounded(["docker", "start", "--attach", cid],
                                        timeout=timeout, max_output=max_output)
            except self.boundary.ContainedTimeout as exc:
                need(self.active == "wall" and str(exc) == "WorkerTimeout", "UnexpectedTimeout")
                result = {"protocol": PROBE_PROTOCOL, "probe": "wall", "attempted": True, "blocked": True,
                          "error": "WorkerTimeout", "running_observed": running.is_set(),
                          "elapsed": time.monotonic() - started, "timeout": timeout}
                return json.dumps(result).encode()
            except self.boundary.ContainedError as exc:
                need(self.active == "stdout" and str(exc) == "WorkerOutputLimit", "UnexpectedWorkerFailure")
                return json.dumps({"protocol": PROBE_PROTOCOL, "probe": "stdout", "attempted": True, "blocked": True,
                                   "error": "WorkerOutputLimit", "max_output": max_output}).encode()
        finally:
            stop.set()
            try:
                self.cleanup(row)
            finally:
                if watcher is not None:
                    watcher.join(timeout=2.5)
                    need(not watcher.is_alive(), "MonitorCleanupUnverified")

    def invoke(self, data, operation, args, *, probe=None):
        self.active, self.last = probe, None
        executor = self.boundary.DockerExecutor(self.lock, runner=self.runner, **lock_options(self.tool, self.lock))
        try:
            return executor.run(operation, args, data, sha256_hex(data))
        finally:
            if self.last is not None:
                row, snapshot = self.last
                row["staging_removed"] = not snapshot.exists()
                need(row["staging_removed"], "SnapshotCleanupUnverified")
            self.active = None

    def ghidra_request_allowed(self, operation, args):
        return ghidra_request_allowed(operation, args)

    def control_code(self):
        return probe_code(self.active, tool=self.tool)

    def record(self, name, check):
        try:
            evidence = check()
            row = {"id": name, "status": "passed", "evidence": evidence}
        except Exception as exc:
            reason = str(exc) if isinstance(exc, VerificationError) else type(exc).__name__
            row = {"id": name, "status": "failed", "reason": reason}
        self.receipt["checks"].append(row)
        return row["status"] == "passed"

    def control(self, name, data):
        operation = "lief.headers" if self.tool == "lief" else "yarax.matches"
        args = {} if self.tool == "lief" else {"ruleset": YARAX_RULESET_NAME, "max_matches": 32}
        if self.tool == "ghidra":
            operation, args = "ghidra.analyze", ghidra_args()
        if self.tool == "jadx":
            operation, args = "jadx.method", jadx_prepared_request(data, jadx_cases(data)["compute"])
        if self.tool == "jsparser":
            operation, args = "jsparser.syntax", jsparser_cases(jsparser_fixtures())["app_calls"][1]
        value = decode(self.invoke(data, operation, args, probe=name))
        validate_probe(name, value, tool=self.tool)
        return value

    def known_answer(self, data, operation, args=None):
        if self.tool == "jsparser":
            case = operation
            fixture, request = jsparser_cases(jsparser_fixtures())[case]
            need(data == jsparser_fixtures()[fixture] and args is None, "JsparserRequestChanged")
            rows = compare_jsparser_reply(data, case, decode(self.invoke(data, "jsparser.syntax", request)))
            return {"input_sha256": sha256_hex(data), "input_bytes": len(data), "case": case, "rows": rows}
        if self.tool == "jadx":
            need(operation == "jadx.method", "JadxRequestChanged")
            return self.jadx_known_answer(data, args)
        if self.tool == "ghidra":
            if operation == "ghidra.analyze":
                need(args is None, "GhidraRequestChanged")
                checked, cap = ghidra_args(), 600
            else:
                ghidra_query_case(data, operation, args)
                checked, cap = args, {"ghidra.functions": 128, "ghidra.function": 643, "ghidra.xrefs": 256}[operation]
            raw = self.invoke(data, operation, checked)
            observations = parse_worker_reply(raw, input_sha256=sha256_hex(data), max_observations=cap)
            if operation == "ghidra.analyze":
                ghidra_verify.verify(data, observations, checked)
                compare_ghidra_observations(data, observations)
            else:
                ghidra_verify.verify(data, observations, checked, operation=operation)
                compare_ghidra_query(data, operation, checked, observations)
            evidence = {"input_sha256": sha256_hex(data), "input_bytes": len(data), "observations": len(observations)}
            return evidence if operation == "ghidra.analyze" else {**evidence, "operation": operation, "args": checked}
        if self.tool == "yarax":
            need(operation == "yarax.matches", "KnownAnswerShape")
            raw = self.invoke(data, operation, {"ruleset": YARAX_RULESET_NAME, "max_matches": 64})
            observations = parse_worker_reply(raw, input_sha256=sha256_hex(data), max_observations=64)
            compare_yarax_observations(data, observations, self.ruleset, max_matches=64)
            return {"input_sha256": sha256_hex(data), "input_bytes": len(data), "observations": len(observations)}
        raw = self.invoke(data, operation, {} if operation == "lief.headers" else {"max_sections": 64})
        observations = parse_worker_reply(raw, input_sha256=sha256_hex(data),
                                          max_observations=3 if operation == "lief.headers" else 64)
        compare_observations(data, operation, observations)
        return {"input_sha256": sha256_hex(data), "input_bytes": len(data), "observations": len(observations)}

    def jadx_known_answer(self, data, args, *, negative=None):
        from reverseai.tools import jadx_tool, jadx_verify
        need(negative in (None, "shape", "input"), "JadxNegativeChanged")
        expected = jadx_prepared_request(data, args)
        state = {"calls": 0, "healthy": False}

        def execute(operation, request, frozen, digest):
            need(operation == "jadx.method" and frozen == data and digest == sha256_hex(data)
                 and canonical_json(request) == canonical_json(expected), "JadxRequestChanged")
            state["calls"] += 1
            raw = self.invoke(data, operation, request)
            if negative is not None:
                # Establish a healthy real reply before testing host refusal of its corrupted copy.
                rows = jadx_verify.parse_reply(raw, digest)
                admitted = jadx_verify.verify(data, rows, args)
                compare_jadx_observations(data, args, admitted)
                value = decode(raw)
                if negative == "shape":
                    need(isinstance(value.get("observations"), list) and value["observations"], "JadxNegativeShape")
                    value["observations"][0]["unexpected"] = True
                else:
                    value["snapshot_sha256"] = "0" * 64
                state["healthy"] = True
                return canonical_json(value).encode()
            return raw

        tool = jadx_tool.make_tool(SimpleNamespace(lock=self.lock, run=execute))
        operation = tool.operations["jadx.method"]
        rejected = False
        try:
            observations = operation.handler(data, operation.validate_args(args))
        except ContractError:
            if negative is None:
                raise
            rejected = True
        need(state["calls"] == 1, "JadxInvocationCount")
        if negative is not None:
            need(state["healthy"] and rejected, "JadxNegativeNotRefused")
            return {"input_sha256": sha256_hex(data), "refused": negative}
        compare_jadx_observations(data, args, observations)
        return {"input_sha256": sha256_hex(data), "input_bytes": len(data), "observations": len(observations),
                "operation": "jadx.method", "args": args}

    def run(self):
        if not self.record("local_daemon", self.local_daemon) or not self.record("image", self.image_check):
            return
        values = (fixtures() if self.tool == "lief" else yarax_fixtures() if self.tool == "yarax"
                  else {"apk_basic": fixtures_apk.apk_basic()[0]} if self.tool == "jadx"
                  else jsparser_fixtures() if self.tool == "jsparser" else ghidra_fixtures())
        control_data = values[{"lief": "elf64le", "yarax": "upx_markers", "ghidra": "elf_code", "jadx": "apk_basic",
                               "jsparser": "js_app"}[self.tool]]
        for name in CONTROL_NAMES:
            self.record(name, lambda name=name: self.control(name, control_data))
        if self.tool == "jsparser":
            for case, (fixture, _) in jsparser_cases(values).items():
                self.record(f"jsparser.{case}", lambda case=case, data=values[fixture]: self.known_answer(data, case))
            values = {}
        for name, data in values.items():
            if self.tool == "jadx":
                for case, args in jadx_cases(data).items():
                    self.record(f"apk_basic.{case}", lambda args=args: self.known_answer(data, "jadx.method", args))
                for label, negative in (("jadx.hostile_reply", "shape"), ("jadx.input_mismatch", "input")):
                    self.record(label, lambda negative=negative:
                                self.jadx_known_answer(data, jadx_cases(data)["compute"], negative=negative))
                continue
            for op in (("headers", "sections") if self.tool == "lief" else
                       ("matches",) if self.tool == "yarax" else ("analyze",)):
                self.record(f"{name}.{op}", lambda data=data, op=op: self.known_answer(data, self.tool + "." + op))
        if self.tool == "ghidra":
            for name in GHIDRA_QUERY_FIXTURES:
                data = values[name]
                for case, (operation, args) in ghidra_query_requests(data).items():
                    self.record(f"{name}.{case}", lambda data=data, operation=operation, args=args:
                                self.known_answer(data, operation, args))
        self.record("container", lambda: need(self.inspected == self.native_runs, "ContainerInspectionMissing"))


def write_receipt(path, receipt):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(receipt, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write("\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tool", choices=("lief", "yarax", "ghidra", "jadx", "jsparser"), required=True)
    parser.add_argument("--profile", choices=("small",), required=True)
    parser.add_argument("--offline", action="store_true", required=True)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args(argv)
    receipt = {"schema": "reverseai.m2-runtime/1", "tool": args.tool, "profile": args.profile,
               "offline": args.offline, "platform": PLATFORM, "checks": [], "cleanup": []}
    interrupted = False
    try:
        receipt["verifier_sha256"] = sha256_hex(Path(__file__).read_bytes())
        from reverseai import contained
        need(contained.WALL_SECONDS == WALL_SECONDS, "ExecutorWallLimit")
        with args.lock.open("rb") as stream:
            raw = stream.read(16_385)
        need(len(raw) <= 16_384, "LockTooLarge")
        receipt["lock_sha256"] = sha256_hex(raw)
        candidate_lock = decode(raw)
        if args.tool == "yarax":
            verify_yarax_lock(candidate_lock)
        if args.tool == "ghidra":
            verify_ghidra_lock(candidate_lock)
            verify_ghidra_executor_profile(contained)
        if args.tool == "jadx":
            verify_jadx_lock(candidate_lock)
            verify_jadx_executor_profile(contained)
        if args.tool == "jsparser":
            verify_jsparser_lock(candidate_lock)
            verify_jsparser_executor_profile(contained)
        receipt["lock"] = contained.load_lock(candidate_lock, **lock_options(args.tool, candidate_lock))
        ruleset = None
        if args.tool == "yarax":
            ruleset = load_yarax_ruleset(receipt["lock"])
            receipt["ruleset_sha256"] = receipt["lock"]["ruleset_sha256"]
        executor_source = Path(contained.__file__)
        receipt["executor_sha256"] = sha256_hex(executor_source.read_bytes())
        if args.tool == "lief":
            NativeVerifier(contained, receipt["lock"], receipt).run()
        elif args.tool == "yarax":
            NativeVerifier(contained, receipt["lock"], receipt, tool="yarax", ruleset=ruleset).run()
            load_yarax_ruleset(receipt["lock"])
        else:
            NativeVerifier(contained, receipt["lock"], receipt, tool=args.tool).run()
        need(receipt["verifier_sha256"] == sha256_hex(Path(__file__).read_bytes()) and
             receipt["executor_sha256"] == sha256_hex(executor_source.read_bytes()), "SourceChangedDuringVerification")
    except KeyboardInterrupt:
        interrupted = True
        receipt["checks"].append({"id": "interrupted", "status": "failed"})
    except Exception as exc:
        receipt["checks"].append({"id": "controller", "status": "failed",
                                  "reason": str(exc) if isinstance(exc, VerificationError) else type(exc).__name__})
    recorded = {row["id"] for row in receipt["checks"]}
    required = required_checks(args.tool)
    receipt["checks"].extend({"id": name, "status": "not_run"} for name in required if name not in recorded)
    receipt["passed"] = receipt_passes(receipt)
    try:
        write_receipt(args.receipt, receipt)
    except (OSError, ValueError):
        print("Native verification receipt refused", file=sys.stderr)
        return 1
    print("Native containment " + ("passed" if receipt["passed"] else "failed"), file=sys.stderr)
    return 130 if interrupted else 0 if receipt["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
