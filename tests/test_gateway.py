from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import threading
import time
import unittest
from unittest.mock import patch

from reverseai.contract import (
    AnalysisTask, ArgSpec, Budget, InputRef, Location, Observation, OperationRequest,
    OperationSpec, ToolRef, ToolSpec, canonical_json, content_id, make_evidence, sha256_hex,
)
from reverseai.gateway import Gateway

DATA = b"inert test bytes for gateway observations"
REF = ToolRef("fake", "0.1.0")


def observation(offset=0, text="known"):
    return Observation(Location(offset, 1), {"text": text})


def tool(handler, *, other=None, cap=1024):
    operations = {"fake.observe": OperationSpec("fake.observe", {
        "n": ArgSpec("int", 0, 100, default=0),
    }, handler, max_observations=cap)}
    if other is not None:
        operations["fake.other"] = OperationSpec("fake.other", {}, other)
    return ToolSpec(REF, operations)


def task(*requests, budget=None, data=DATA):
    return AnalysisTask(content_id("tk", {"input": sha256_hex(data), "role": "capability"}),
                        "capability", InputRef(sha256_hex(data), len(data), "fixture.bin"),
                        requests or (OperationRequest("fake.observe"),), budget or Budget())


class GatewayTests(unittest.TestCase):
    def test_exact_bound_evidence_and_empty_findings(self):
        gateway = Gateway([tool(lambda data, args: [observation(2)])], Budget())
        result = gateway.run(task(), DATA)
        expected = make_evidence(DATA, REF, "fake.observe", observation(2))
        self.assertEqual(result.status, "ok")
        self.assertEqual(result.evidence, (expected,))
        self.assertEqual(result.errors, ())
        self.assertEqual(result.findings, ())

    def test_hash_and_size_mismatch_never_call_handler(self):
        calls = []
        gateway = Gateway([tool(lambda data, args: calls.append(1) or [])], Budget())
        for ref in (InputRef("0" * 64, len(DATA), "x"), InputRef(sha256_hex(DATA), len(DATA) + 1, "x")):
            with self.subTest(ref=ref):
                result = gateway.run(replace(task(), input=ref), DATA)
                self.assertEqual(result.status, "error")
                self.assertEqual(result.evidence, ())
        self.assertEqual(calls, [])

    def test_input_is_hashed_once_per_run_including_multiple_observations(self):
        gateway = Gateway([tool(lambda data, args: [observation(i) for i in range(4)])], Budget())
        request = task()
        full_input_hashes = []

        def hashing(value):
            if value == DATA:
                full_input_hashes.append(1)
            return sha256_hex(value)

        with patch("reverseai.gateway.sha256_hex", side_effect=hashing), \
                patch("reverseai.contract.sha256_hex", side_effect=hashing):
            first = gateway.run(request, DATA)
            replay = gateway.run(request, DATA)
        self.assertEqual(first.status, "ok")
        self.assertEqual(len(first.evidence), 4)
        self.assertEqual(replay.evidence, first.evidence)
        self.assertEqual(len(full_input_hashes), 2)

    def test_timed_out_operation_retries_once_for_concurrent_larger_tasks(self):
        release = threading.Event()
        calls = []

        def handler(data, args):
            calls.append(1)
            if len(calls) == 1:
                release.wait(timeout=3)
            return [observation()]

        gateway = Gateway([tool(handler)], Budget(max_operations=1, max_concurrency=2))
        first = gateway.run(task(budget=Budget(max_wall_seconds=0.03)), DATA)
        self.assertEqual(first.status, "budget_exceeded")
        self.assertEqual(first.evidence, ())
        started = time.monotonic()
        blocked_retry = gateway.run(task(budget=Budget(max_wall_seconds=0.02)), DATA)
        self.assertLess(time.monotonic() - started, 0.75)
        self.assertEqual(blocked_retry.status, "budget_exceeded")
        self.assertEqual(calls, [1])
        barrier = threading.Barrier(3)

        def retry():
            barrier.wait(timeout=2)
            return gateway.run(task(budget=Budget(max_wall_seconds=2)), DATA)

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(retry) for _ in range(2)]
            try:
                barrier.wait(timeout=2)
                self.assertEqual(calls, [1])
            finally:
                release.set()
            results = [future.result(timeout=3) for future in futures]
        self.assertEqual([result.status for result in results], ["ok", "ok"])
        self.assertEqual(calls, [1, 1])
        self.assertEqual(results[0].evidence, results[1].evidence)
        self.assertEqual(len(results[0].evidence), 1)
        self.assertEqual(first.evidence, ())
        refused = gateway.run(task(OperationRequest("fake.observe", {"n": 1})), DATA)
        self.assertEqual(refused.status, "budget_exceeded")
        self.assertEqual(calls, [1, 1])

    def test_unknown_operation_refused_and_run_continues(self):
        calls = []
        gateway = Gateway([tool(lambda data, args: calls.append(1) or [observation()])], Budget())
        result = gateway.run(task(OperationRequest("fake.unknown"), OperationRequest("fake.observe")), DATA)
        self.assertEqual(result.status, "error")
        self.assertEqual(len(result.evidence), 1)
        self.assertEqual(calls, [1])
        self.assertEqual(result.errors, ("fake.unknown: operation not allowed",))

    def test_refused_arguments_do_not_reach_handler_and_run_continues(self):
        calls = []
        gateway = Gateway([tool(lambda data, args: calls.append(dict(args)) or [observation()])], Budget())
        result = gateway.run(task(OperationRequest("fake.observe", {"path": "/private/secret"}),
                                 OperationRequest("fake.observe")), DATA)
        self.assertEqual(result.status, "error")
        self.assertEqual(calls, [{"n": 0}])
        self.assertEqual(len(result.evidence), 1)
        self.assertEqual(result.errors, ("fake.observe: ContractError",))

    def test_duplicate_operation_names_rejected_even_across_versions(self):
        first = tool(lambda data, args: [])
        second = ToolSpec(ToolRef("fake", "0.2.0"), first.operations)
        with self.assertRaisesRegex(ValueError, "Duplicate operation"):
            Gateway([first, second], Budget())

    def test_default_arguments_and_input_aliases_share_cache(self):
        calls = []
        gateway = Gateway([tool(lambda data, args: calls.append(dict(args)) or [observation()])], Budget())
        first = gateway.run(task(), DATA)
        alias = replace(task(OperationRequest("fake.observe", {"n": 0})),
                        input=InputRef(sha256_hex(DATA), len(DATA), "other-name"))
        self.assertEqual(gateway.run(alias, DATA).evidence, first.evidence)
        self.assertEqual(calls, [{"n": 0}])
        gateway.run(task(OperationRequest("fake.observe", {"n": 1})), DATA)
        self.assertEqual(calls, [{"n": 0}, {"n": 1}])

    def test_input_hash_is_part_of_cache_key(self):
        calls = []
        gateway = Gateway([tool(lambda data, args: calls.append(data) or [observation()])], Budget())
        first = gateway.run(task(), DATA)
        other = b"other inert bytes"
        second = gateway.run(task(data=other), other)
        self.assertEqual(calls, [DATA, other])
        self.assertNotEqual(first.evidence[0].id, second.evidence[0].id)

    def test_duplicate_requests_return_unique_evidence(self):
        calls = []
        gateway = Gateway([tool(lambda data, args: calls.append(1) or [observation()])], Budget())
        result = gateway.run(task(OperationRequest("fake.observe"), OperationRequest("fake.observe")), DATA)
        self.assertEqual(len(result.evidence), 1)
        self.assertEqual(calls, [1])

    def test_error_message_contains_class_only_and_next_operation_runs(self):
        def raising(data, args):
            raise RuntimeError("PRIVATE INPUT /Users/person/secret")
        gateway = Gateway([tool(raising, other=lambda data, args: [observation()])], Budget())
        result = gateway.run(task(OperationRequest("fake.observe"), OperationRequest("fake.other")), DATA)
        self.assertEqual(result.status, "error")
        self.assertEqual(result.errors, ("fake.observe: RuntimeError",))
        self.assertEqual(len(result.evidence), 1)

    def test_error_outcome_is_cached(self):
        calls = []
        def raising(data, args):
            calls.append(1)
            raise ValueError("private")
        gateway = Gateway([tool(raising)], Budget())
        for _ in range(2):
            self.assertEqual(gateway.run(task(), DATA).errors, ("fake.observe: ValueError",))
        self.assertEqual(calls, [1])

    def test_non_observation_is_error_and_prior_evidence_kept(self):
        gateway = Gateway([tool(lambda data, args: [observation(), {"forged": True}])], Budget())
        result = gateway.run(task(), DATA)
        self.assertEqual(result.status, "error")
        self.assertEqual(result.errors, ("fake.observe: TypeError",))
        self.assertEqual(len(result.evidence), 1)

    def test_invalid_byte_location_is_error(self):
        gateway = Gateway([tool(lambda data, args: [observation(len(data))])], Budget())
        result = gateway.run(task(), DATA)
        self.assertEqual(result.status, "error")
        self.assertEqual(result.errors, ("fake.observe: ContractError",))
        self.assertEqual(result.evidence, ())

    def test_invalid_handler_collection_is_error(self):
        gateway = Gateway([tool(lambda data, args: {"not": "observations"})], Budget())
        self.assertEqual(gateway.run(task(), DATA).errors, ("fake.observe: TypeError",))

    def test_fixed_cut_replay_preserves_prefix_without_charging_global_limits_twice(self):
        calls = []
        limit = sum(len(canonical_json(make_evidence(DATA, REF, "fake.observe", observation(i)).to_dict()).encode())
                    for i in range(2))
        gateway = Gateway([tool(lambda data, args: calls.append(1) or [observation(i) for i in range(3)], cap=2)],
                          Budget(max_operations=1, max_evidence=2, max_output_bytes=limit))
        for _ in range(2):
            result = gateway.run(task(), DATA)
            self.assertEqual(result.status, "budget_exceeded")
            self.assertEqual([e.location.offset for e in result.evidence], [0, 1])
        self.assertEqual(calls, [1])

    def test_task_evidence_cap_applies_also_to_replay(self):
        gateway = Gateway([tool(lambda data, args: [observation(i) for i in range(3)])], Budget())
        self.assertEqual(len(gateway.run(task(), DATA).evidence), 3)
        result = gateway.run(task(budget=Budget(max_evidence=2)), DATA)
        self.assertEqual(result.status, "budget_exceeded")
        self.assertEqual([e.location.offset for e in result.evidence], [0, 1])

    def test_global_evidence_cap_spans_operations_and_runs(self):
        gateway = Gateway([tool(lambda data, args: [observation()],
                                other=lambda data, args: [observation(1), observation(2)])], Budget(max_evidence=2))
        self.assertEqual(gateway.run(task(), DATA).status, "ok")
        second = gateway.run(task(OperationRequest("fake.other")), DATA)
        self.assertEqual(second.status, "budget_exceeded")
        self.assertEqual([e.location.offset for e in second.evidence], [1])
        self.assertEqual(gateway.run(task(), DATA).status, "ok")

    def test_task_output_cap_uses_utf8_canonical_json_and_keeps_prefix(self):
        first = make_evidence(DATA, REF, "fake.observe", observation(0, "\u00e8"))
        limit = len(canonical_json(first.to_dict()).encode("utf-8"))
        gateway = Gateway([tool(lambda data, args: [observation(0, "\u00e8"), observation(1)])], Budget())
        result = gateway.run(task(budget=Budget(max_output_bytes=limit)), DATA)
        self.assertEqual(result.status, "budget_exceeded")
        self.assertEqual(result.evidence, (first,))
        smaller = gateway.run(task(budget=Budget(max_output_bytes=limit - 1)), DATA)
        self.assertEqual(smaller.status, "budget_exceeded")
        self.assertEqual(smaller.evidence, ())

    def test_global_output_cap_spans_runs_and_cache_replay_is_free(self):
        first = make_evidence(DATA, REF, "fake.observe", observation())
        limit = len(canonical_json(first.to_dict()).encode())
        gateway = Gateway([tool(lambda data, args: [observation()],
                                other=lambda data, args: [observation(1)])], Budget(max_output_bytes=limit))
        self.assertEqual(gateway.run(task(), DATA).status, "ok")
        self.assertEqual(gateway.run(task(), DATA).status, "ok")
        result = gateway.run(task(OperationRequest("fake.other")), DATA)
        self.assertEqual(result.status, "budget_exceeded")
        self.assertEqual(result.evidence, ())

    def test_task_operation_cap_prevents_next_handler(self):
        calls = []
        gateway = Gateway([tool(lambda data, args: [observation()],
                                other=lambda data, args: calls.append(1) or [])], Budget())
        result = gateway.run(task(OperationRequest("fake.observe"), OperationRequest("fake.other"),
                                 budget=Budget(max_operations=1)), DATA)
        self.assertEqual(result.status, "budget_exceeded")
        self.assertEqual(len(result.evidence), 1)
        self.assertEqual(calls, [])

    def test_global_operation_cap_spans_runs_but_allows_cached_result(self):
        calls = []
        gateway = Gateway([tool(lambda data, args: [observation()],
                                other=lambda data, args: calls.append(1) or [])], Budget(max_operations=1))
        self.assertEqual(gateway.run(task(), DATA).status, "ok")
        self.assertEqual(gateway.run(task(), DATA).status, "ok")
        self.assertEqual(gateway.run(task(OperationRequest("fake.other")), DATA).status, "budget_exceeded")
        self.assertEqual(calls, [])

    def test_cache_and_previous_results_are_protected_from_mutation(self):
        source = observation()
        gateway = Gateway([tool(lambda data, args: [source])], Budget())
        first = gateway.run(task(), DATA)
        source.value["text"] = "changed by handler"
        first.evidence[0].observation["text"] = "changed by caller"
        second = gateway.run(task(), DATA)
        self.assertEqual(second.evidence[0].observation, {"text": "known"})

    def test_concurrent_same_key_calls_handler_once(self):
        calls = []
        barrier = threading.Barrier(8)
        def handler(data, args):
            calls.append(1)
            return [observation()]
        gateway = Gateway([tool(handler)], Budget())
        def run(_):
            barrier.wait(timeout=3)
            return gateway.run(task(), DATA)
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(run, range(8)))
        self.assertEqual(calls, [1])
        self.assertEqual([result.status for result in results], ["ok"] * 8)
        self.assertTrue(all(result.evidence == results[0].evidence for result in results))

    def test_global_semaphore_limits_different_keys(self):
        lock = threading.Lock()
        active, peak = 0, 0
        barrier = threading.Barrier(2)
        def handler(data, args):
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(active, peak)
            try:
                barrier.wait(timeout=3)
                return [observation(args["n"])]
            finally:
                with lock:
                    active -= 1
        gateway = Gateway([tool(handler)], Budget(max_concurrency=2))
        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(lambda n: gateway.run(task(OperationRequest("fake.observe", {"n": n})), DATA), range(6)))
        self.assertEqual([result.status for result in results], ["ok"] * 6)
        self.assertEqual(peak, 2)

    def test_global_evidence_budget_is_atomic_under_concurrency(self):
        barrier = threading.Barrier(2)
        def handler(data, args):
            barrier.wait(timeout=3)
            return [observation(args["n"])]
        gateway = Gateway([tool(handler)], Budget(max_evidence=1, max_concurrency=2))
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda n: gateway.run(task(OperationRequest("fake.observe", {"n": n})), DATA), range(2)))
        self.assertEqual(sum(len(result.evidence) for result in results), 1)
        self.assertCountEqual([result.status for result in results], ["ok", "budget_exceeded"])

    def test_wall_timeout_is_prompt_keeps_prior_evidence_and_rejects_late_output(self):
        release = threading.Event()
        finished = threading.Event()
        def slow(data, args):
            try:
                release.wait(timeout=2)
                return [observation(1)]
            finally:
                finished.set()
        gateway = Gateway([tool(lambda data, args: [observation()], other=slow)], Budget())
        request = task(OperationRequest("fake.observe"), OperationRequest("fake.other"),
                       budget=Budget(max_wall_seconds=0.06))
        started = time.monotonic()
        try:
            result = gateway.run(request, DATA)
            self.assertLess(time.monotonic() - started, 0.75)
            self.assertEqual(result.status, "budget_exceeded")
            self.assertEqual(len(result.evidence), 1)
        finally:
            release.set()
            self.assertTrue(finished.wait(timeout=2))
        retried = gateway.run(task(OperationRequest("fake.other")), DATA)
        self.assertEqual(retried.status, "ok")
        self.assertEqual(len(retried.evidence), 1)
        self.assertEqual(len(result.evidence), 1)

    def test_global_wall_deadline_overrides_long_task_deadline(self):
        release = threading.Event()
        finished = threading.Event()
        def slow(data, args):
            release.wait(timeout=2)
            finished.set()
            return []
        gateway = Gateway([tool(slow)], Budget(max_wall_seconds=0.05))
        started = time.monotonic()
        try:
            self.assertEqual(gateway.run(task(budget=Budget(max_wall_seconds=2)), DATA).status, "budget_exceeded")
            self.assertLess(time.monotonic() - started, 0.75)
        finally:
            release.set()
            self.assertTrue(finished.wait(timeout=2))
        self.assertEqual(gateway.run(task(), DATA).status, "budget_exceeded")

    def test_short_cache_waiter_does_not_cancel_original(self):
        entered = threading.Event()
        release = threading.Event()
        calls = []
        def handler(data, args):
            calls.append(1)
            entered.set()
            release.wait(timeout=2)
            return [observation()]
        gateway = Gateway([tool(handler)], Budget())
        with ThreadPoolExecutor(max_workers=1) as pool:
            original = pool.submit(gateway.run, task(), DATA)
            try:
                self.assertTrue(entered.wait(timeout=2))
                waiter = gateway.run(task(budget=Budget(max_wall_seconds=0.03)), DATA)
                self.assertEqual(waiter.status, "budget_exceeded")
            finally:
                release.set()
            self.assertEqual(original.result(timeout=2).status, "ok")
        self.assertEqual(calls, [1])

    def test_timed_out_handler_holds_semaphore_until_it_finishes(self):
        release = threading.Event()
        finished = threading.Event()
        calls = []
        def handler(data, args):
            calls.append(args["n"])
            if args["n"] == 0:
                release.wait(timeout=2)
                finished.set()
            return [observation()]
        gateway = Gateway([tool(handler)], Budget(max_concurrency=1))
        try:
            first = gateway.run(task(budget=Budget(max_wall_seconds=0.03)), DATA)
            self.assertEqual(first.status, "budget_exceeded")
            waiting = gateway.run(task(OperationRequest("fake.observe", {"n": 1}),
                                       budget=Budget(max_wall_seconds=0.03)), DATA)
            self.assertEqual(waiting.status, "budget_exceeded")
            self.assertEqual(calls, [0])
        finally:
            release.set()
            self.assertTrue(finished.wait(timeout=2))
        final = gateway.run(task(OperationRequest("fake.observe", {"n": 2})), DATA)
        self.assertEqual(final.status, "ok")
        self.assertEqual(calls, [0, 2])
