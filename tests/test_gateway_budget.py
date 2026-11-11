import threading
import unittest
from unittest.mock import patch

from reverseai.contract import Budget, OperationRequest, canonical_json, make_evidence
from reverseai.gateway import Gateway
from tests.test_gateway import DATA, REF, observation, task, tool


class OperationChargeTests(unittest.TestCase):
    def test_worker_detected_time_cuts_remain_retryable(self):
        for outcome in ("empty", "observation", "error"):
            with self.subTest(outcome=outcome):
                now, calls = [0.0], []

                def handler(data, args):
                    calls.append(1)
                    if len(calls) == 1:
                        now[0] = 1.0
                        if outcome == "error":
                            raise ValueError("inert")
                    return [] if outcome == "empty" else [observation()]

                gateway = Gateway([tool(handler)], Budget(max_operations=1))
                with patch("reverseai.gateway.time.monotonic", side_effect=lambda: now[0]):
                    first = gateway.run(task(budget=Budget(max_wall_seconds=0.5)), DATA)
                    self.assertEqual(first.status, "budget_exceeded")
                    self.assertEqual(first.evidence, ())
                    retried = gateway.run(task(), DATA)
                self.assertEqual(retried.status, "ok")
                self.assertEqual(len(retried.evidence), 0 if outcome == "empty" else 1)
                self.assertEqual(calls, [1, 1])

    def test_a_known_fixed_cut_is_cached_even_when_time_has_also_expired(self):
        now, calls = [0.0], []

        def handler(data, args):
            calls.append(1)
            now[0] = 1.0
            return [observation()]

        gateway = Gateway([tool(handler)], Budget(max_output_bytes=1))
        with patch("reverseai.gateway.time.monotonic", side_effect=lambda: now[0]):
            first = gateway.run(task(budget=Budget(max_wall_seconds=0.5)), DATA)
            second = gateway.run(task(), DATA)
        self.assertEqual(first.status, "budget_exceeded")
        self.assertEqual(second.status, "budget_exceeded")
        self.assertEqual(second.evidence, ())
        self.assertEqual(calls, [1])

    def test_observation_cap_is_cached_without_another_handler_call(self):
        for cap in (0, 2):
            with self.subTest(cap=cap):
                calls = []
                gateway = Gateway([tool(lambda data, args: calls.append(1) or
                                        [observation(i) for i in range(3)], cap=cap)], Budget())
                for _ in range(3):
                    result = gateway.run(task(), DATA)
                    self.assertEqual(result.status, "budget_exceeded")
                    self.assertEqual([e.location.offset for e in result.evidence], list(range(cap)))
                self.assertEqual(calls, [1])

    def test_global_evidence_cap_is_cached_without_another_handler_call(self):
        calls = []
        gateway = Gateway([tool(lambda data, args: calls.append(1) or
                                [observation(i) for i in range(3)])], Budget(max_evidence=2))
        for _ in range(3):
            result = gateway.run(task(), DATA)
            self.assertEqual(result.status, "budget_exceeded")
            self.assertEqual([e.location.offset for e in result.evidence], [0, 1])
        self.assertEqual(calls, [1])

    def test_global_output_cap_is_cached_without_another_handler_call(self):
        calls = []
        limit = sum(len(canonical_json(make_evidence(DATA, REF, "fake.observe", observation(i)).to_dict()).encode())
                    for i in range(2))
        gateway = Gateway([tool(lambda data, args: calls.append(1) or
                                [observation(i) for i in range(3)])], Budget(max_output_bytes=limit))
        for _ in range(3):
            result = gateway.run(task(), DATA)
            self.assertEqual(result.status, "budget_exceeded")
            self.assertEqual([e.location.offset for e in result.evidence], [0, 1])
        self.assertEqual(calls, [1])

    def test_a_time_retry_that_hits_a_fixed_cap_is_then_cached(self):
        release, calls = threading.Event(), []

        def handler(data, args):
            calls.append(1)
            if len(calls) == 1:
                release.wait(timeout=3)
            return [observation(i) for i in range(3)]

        gateway = Gateway([tool(handler, cap=2)], Budget(max_operations=1))
        try:
            first = gateway.run(task(budget=Budget(max_wall_seconds=0.03)), DATA)
            self.assertEqual(first.status, "budget_exceeded")
            self.assertEqual(first.evidence, ())
        finally:
            release.set()
        for _ in range(2):
            result = gateway.run(task(), DATA)
            self.assertEqual(result.status, "budget_exceeded")
            self.assertEqual([e.location.offset for e in result.evidence], [0, 1])
        self.assertEqual(calls, [1, 1])

    def test_a_slot_timeout_can_retry_without_another_global_operation_charge(self):
        release, calls = threading.Event(), []

        def handler(data, args):
            calls.append(args["n"])
            if args["n"] == 0:
                release.wait(timeout=3)
            return [observation()]

        gateway = Gateway([tool(handler)], Budget(max_operations=2, max_concurrency=1))
        try:
            first = gateway.run(task(budget=Budget(max_wall_seconds=0.03)), DATA)
            self.assertEqual(first.status, "budget_exceeded")
            request = OperationRequest("fake.observe", {"n": 1})
            waiting = gateway.run(task(request, budget=Budget(max_wall_seconds=0.03)), DATA)
            self.assertEqual(waiting.status, "budget_exceeded")
            self.assertEqual(calls, [0])
        finally:
            release.set()
        self.assertEqual(gateway.run(task(request), DATA).status, "ok")
        self.assertEqual(calls, [0, 1])

    def test_retrying_a_time_cut_operation_does_not_charge_the_global_budget_twice(self):
        release, calls = threading.Event(), []

        def slow(data, args):
            calls.append("observe")
            if len(calls) == 1:
                release.wait(timeout=3)
            return [observation()]

        def other(data, args):
            calls.append("other")
            return [observation(1, "other")]

        gateway = Gateway([tool(slow, other=other)], Budget(max_operations=2, max_concurrency=2))
        self.assertEqual(gateway.run(task(budget=Budget(max_wall_seconds=0.03)), DATA).status, "budget_exceeded")
        release.set()
        self.assertEqual(gateway.run(task(budget=Budget(max_wall_seconds=2)), DATA).status, "ok")
        second = gateway.run(task(OperationRequest("fake.other"), budget=Budget(max_wall_seconds=2)), DATA)
        self.assertEqual(second.status, "ok")
        self.assertEqual(calls, ["observe", "observe", "other"])


    def test_a_worker_timeout_is_a_retriable_time_cut(self):
        calls = []

        def worker(data, args):
            calls.append(1)
            if len(calls) == 1:
                raise TimeoutError("worker wall limit")
            return [observation()]

        gateway = Gateway([tool(worker)], Budget())
        first = gateway.run(task(), DATA)
        self.assertEqual((first.status, first.errors), ("budget_exceeded", ()))
        second = gateway.run(task(), DATA)
        self.assertEqual((second.status, len(second.evidence), calls), ("ok", 1, [1, 1]))


if __name__ == "__main__":
    unittest.main()
