"""Allowlisted observations with shared execution, output and concurrency limits.

Global counters charge each unique operation and its evidence once. A cache replay
still consumes the requesting run's task limits. The global wall clock starts on
the first run; every task additionally has its own wall-time deadline. Operations
within one run are serial, so they also respect every task concurrency limit.
"""

from __future__ import annotations

from collections.abc import Iterable
from copy import deepcopy
from dataclasses import dataclass, field
import threading
import time
from types import MappingProxyType

from reverseai.contract import (
    AnalysisResult, AnalysisTask, Budget, Evidence, Observation, ToolSpec,
    MAX_CHILD_RATIO, MAX_STREAM_BYTES, canonical_json, check_artifact, make_evidence, materialize, operation_key,
    sha256_hex,
)

MAX_RUN_CHILD_BYTES = 128 * 1024 * 1024  # distinct child artifacts one operation may materialize


@dataclass
class _Execution:
    deadline: float
    done: threading.Event = field(default_factory=threading.Event)
    stopped: threading.Event = field(default_factory=threading.Event)
    evidence: list[Evidence] = field(default_factory=list)
    status: str = "ok"
    errors: tuple[str, ...] = ()
    time_cut: bool = False


def _error(operation, exc):
    from reverseai.ghidra_cache import CacheError, ERRORS
    if isinstance(exc, CacheError) and str(exc) in ERRORS:
        return f"{operation}: {exc}"
    # Exception messages can contain input bytes or host paths.
    return f"{operation}: {type(exc).__name__}"[:200]


def _size(evidence):
    return len(canonical_json(evidence.to_dict()).encode("utf-8"))


class Gateway:
    def __init__(self, tools: Iterable[ToolSpec], budget: Budget):
        self.budget = budget
        self._operations = {}
        for tool in tools:
            for name, spec in tool.operations.items():
                if name in self._operations:
                    raise ValueError("Duplicate operation name")
                if type(spec.max_observations) is not int or spec.max_observations < 0:
                    raise ValueError("Invalid observation limit")
                self._operations[name] = (tool.ref, spec)
        self._lock = threading.Lock()
        self._slots = threading.BoundedSemaphore(budget.max_concurrency)
        self._cache: dict[str, _Execution] = {}
        self._started = None
        self._operation_count = 0
        self._evidence_ids = set()
        self._output_bytes = 0

    def _finish(self, execution, status, errors=(), *, time_cut=False):
        with self._lock:
            if not execution.done.is_set():
                execution.status = status
                execution.errors = errors
                execution.time_cut = time_cut
                execution.done.set()

    def _work(self, execution, data, digest, ref, spec, args):
        try:
            if time.monotonic() >= execution.deadline:
                self._finish(execution, "budget_exceeded", time_cut=True)
                return
            observations = spec.handler(data, MappingProxyType(args))
            if not isinstance(observations, (list, tuple)):
                raise TypeError("Expected observations")
            children, streams, charged = {}, {}, {}
            for index, observation in enumerate(observations):
                if index >= spec.max_observations:
                    self._finish(execution, "budget_exceeded")
                    return
                if not isinstance(observation, Observation):
                    raise TypeError("Expected an Observation")
                # Freeze nested JSON too: frozen dataclasses alone do not freeze dicts.
                observation = Observation(observation.location, deepcopy(observation.value), deepcopy(observation.artifact))
                child = None
                if observation.artifact is not None:  # materialize each child once per run, within a budget
                    key = canonical_json(observation.artifact)
                    if key not in children:
                        check_artifact(observation.artifact)
                        if sum(len(c) for c in children.values()) + observation.artifact["size"] > MAX_RUN_CHILD_BYTES:
                            self._finish(execution, "budget_exceeded")
                            return
                        if observation.artifact["method"] == 1:  # a new gzip stream's bound is charged before it inflates
                            stream = (observation.artifact["data_offset"], observation.artifact["compressed_size"])
                            if stream not in charged:
                                charged[stream] = min(MAX_STREAM_BYTES, MAX_CHILD_RATIO * stream[1])
                                if sum(charged.values()) > MAX_STREAM_BYTES:
                                    self._finish(execution, "budget_exceeded")
                                    return
                        children[key] = materialize(data, observation.artifact, streams=streams)
                        if sum(len(s) for s in streams.values()) > MAX_STREAM_BYTES:  # gzip streams per run
                            self._finish(execution, "budget_exceeded")
                            return
                    child = children[key]
                evidence = make_evidence(data, ref, spec.name, observation, input_sha256=digest, child=child)
                size = _size(evidence)
                with self._lock:
                    if execution.done.is_set():
                        return
                    new = evidence.id not in self._evidence_ids
                    fixed_cut = new and (len(self._evidence_ids) >= self.budget.max_evidence
                                         or self._output_bytes + size > self.budget.max_output_bytes)
                    time_cut = time.monotonic() >= execution.deadline
                    if time_cut or fixed_cut:
                        execution.status = "budget_exceeded"
                        execution.time_cut = time_cut and not fixed_cut
                        execution.done.set()
                        return
                    execution.evidence.append(evidence)
                    if new:
                        self._evidence_ids.add(evidence.id)
                        self._output_bytes += size
            status = "budget_exceeded" if time.monotonic() >= execution.deadline else "ok"
            self._finish(execution, status, time_cut=status == "budget_exceeded")
        except Exception as exc:
            # A contained worker that hit its own wall limit is a time cut, like the gateway's deadline.
            timed_out = isinstance(exc, TimeoutError) or time.monotonic() >= execution.deadline
            status = "budget_exceeded" if timed_out else "error"
            self._finish(execution, status, (_error(spec.name, exc),) if status == "error" else (),
                         time_cut=timed_out)
        finally:
            self._slots.release()
            execution.stopped.set()

    def _execute(self, key, data, digest, ref, spec, args, deadline):
        while True:
            with self._lock:
                previous = self._cache.get(key)
                owner = previous is None or (previous.done.is_set()
                        and previous.time_cut and previous.stopped.is_set())
                if owner:
                    if (time.monotonic() >= deadline
                            or (previous is None and self._operation_count >= self.budget.max_operations)):
                        return (), "budget_exceeded", ()
                    execution = _Execution(deadline)
                    self._cache[key] = execution
                    if previous is None:
                        self._operation_count += 1
                else:
                    execution = previous
            if owner:
                if not self._slots.acquire(timeout=max(0, deadline - time.monotonic())):
                    self._finish(execution, "budget_exceeded", time_cut=True)
                    execution.stopped.set()
                else:
                    # An overrun keeps its slot until exit. Its sealed result
                    # rejects late evidence; same-key retries wait for that exit.
                    worker = threading.Thread(target=self._work,
                                              args=(execution, data, digest, ref, spec, args), daemon=True)
                    try:
                        worker.start()
                    except Exception as exc:
                        self._slots.release()
                        self._finish(execution, "error", (_error(spec.name, exc),))
                        execution.stopped.set()
            completed = execution.done.wait(timeout=max(0, deadline - time.monotonic()))
            if not completed and owner:
                self._finish(execution, "budget_exceeded", time_cut=True)
            if completed and not owner and execution.time_cut:
                if execution.stopped.wait(timeout=max(0, deadline - time.monotonic())):
                    continue
                return (), "budget_exceeded", ()
            with self._lock:
                # A short-lived cache waiter cannot cancel the original execution.
                status = execution.status if completed else "budget_exceeded"
                return tuple(deepcopy(execution.evidence)), status, execution.errors if completed else ()

    def run(self, task: AnalysisTask, data: bytes) -> AnalysisResult:
        started = time.monotonic()
        with self._lock:
            if self._started is None:
                self._started = started
            deadline = min(started + task.budget.max_wall_seconds,
                           self._started + self.budget.max_wall_seconds)
        evidence, errors = [], []
        seen = set()
        output_bytes = 0
        status = "ok"

        def result(state):
            return AnalysisResult(task.id, task.role, state, tuple(evidence), (), tuple(errors))

        digest = sha256_hex(data) if isinstance(data, bytes) and len(data) == task.input.size else None
        if digest != task.input.sha256:
            errors.append("input: hash or size mismatch")
            return result("error")
        for index, request in enumerate(task.operations):
            if index >= task.budget.max_operations or time.monotonic() >= deadline:
                return result("budget_exceeded")
            registered = self._operations.get(request.operation)
            if registered is None:
                errors.append(f"{request.operation}: operation not allowed")
                status = "error"
                continue
            ref, spec = registered
            try:
                args = spec.validate_args(request.args)
                key = operation_key(task.input.sha256, ref, spec.name, args)
            except Exception as exc:
                errors.append(_error(spec.name, exc))
                status = "error"
                continue
            produced, operation_status, operation_errors = self._execute(key, data, digest, ref, spec, args, deadline)
            for item in produced:
                if item.id in seen:
                    continue
                size = _size(item)
                if len(evidence) >= task.budget.max_evidence or output_bytes + size > task.budget.max_output_bytes:
                    return result("budget_exceeded")
                evidence.append(item)
                seen.add(item.id)
                output_bytes += size
            errors.extend(operation_errors)
            if operation_status == "budget_exceeded" or time.monotonic() >= deadline:
                return result("budget_exceeded")
            if operation_status == "error":
                status = "error"
        return result(status)
