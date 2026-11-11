"""Derived Ghidra analysis through the contained worker; the host verifies its anchors."""

from reverseai.contained import ContainedError, DockerExecutor, default_lock, inspect_image, load_lock
from reverseai.contract import ArgSpec, ContractError, OperationSpec, ToolRef, ToolSpec, WorkerError, parse_worker_reply, sha256_hex
from reverseai.tools import ghidra_verify
from reverseai import ghidra_args, ghidra_cache
from reverseai.contract import Observation

REF = ToolRef("ghidra", "12.1.4-r7")
DEFAULT_LOCK = default_lock("ghidra")


def make_tool(executor=None, *, store=None):
    if executor is None:
        executor = DockerExecutor(DEFAULT_LOCK, adapter_version=REF.version)
        if store is None:
            store = ghidra_cache.CacheStore()
    lock = load_lock(executor.lock, adapter_version=REF.version)

    def invoke(operation, data, args):
        spec = operations[operation]
        checked = spec.validate_args(args)
        digest = sha256_hex(data)
        exported = operation in ghidra_args.OPERATIONS
        if exported:
            checked = ghidra_args.check(operation, checked)
        project = None
        if store is not None:
            try:
                project = store.lookup(ghidra_cache.identity(digest, lock))
            except ghidra_cache.CacheError:
                if exported:
                    raise
        if exported and project is None:
            raise ghidra_cache.CacheError(ghidra_cache.MISSING)
        try:
            raw = (executor.run(operation, checked, data, digest, project=project) if project is not None
                   else executor.run(operation, checked, data, digest))
            source_id = None if project is None else project.analysis_id
        finally:
            if project is not None:
                project.close()
        try:
            observations = parse_worker_reply(raw, input_sha256=digest,
                                              max_observations=129 if exported else spec.max_observations)
        except WorkerError:
            raise
        except (ContractError, UnicodeError):
            raise ContractError(ghidra_verify.REFUSED) from None
        if exported:
            admitted = ghidra_verify.verify(data, observations, checked, operation=operation)
            return tuple(Observation(item.location, {**item.value, "analysis_id": source_id}) for item in admitted)
        if operation == "ghidra.analyze":
            ghidra_verify.verify(data, observations, checked)
        else:
            ghidra_verify.verify(data, observations, checked, operation=operation)
        return observations

    def operation(name, args, max_observations):
        return OperationSpec(name, args, lambda data, checked: invoke(name, data, checked),
                             max_observations=max_observations, derived=True)

    operations = {
        "ghidra.analyze": operation("ghidra.analyze", {
            "max_functions": ArgSpec("int", 1, 128, default=64),
            "decompile": ArgSpec("int", 0, 16, default=8),
            "max_chars": ArgSpec("int", 64, 2048, default=1024),
            "max_calls": ArgSpec("int", 0, 256, default=128),
            "assembly": ArgSpec("int", 0, 8, default=4),
            "max_instructions": ArgSpec("int", 1, 64, default=32),
            "max_refs": ArgSpec("int", 0, 128, default=64),
            "max_strings": ArgSpec("int", 0, 64, default=32),
        }, 600),
        "ghidra.functions": operation("ghidra.functions", {
            "query": ArgSpec("str", default=""),
            "start": ArgSpec("int", 0, 65535, default=0),
            "limit": ArgSpec("int", 1, 128, default=64),
        }, 128),
        "ghidra.function": operation("ghidra.function", {
            "select": ArgSpec("enum", choices=("entry", "name"), default="entry"),
            "entry": ArgSpec("int", 0, 2 ** 64 - 1, default=0),
            "name": ArgSpec("str", default=""),
            "parts": ArgSpec("enum", choices=("info", "pseudocode", "assembly", "callees", "callers", "all"), default="all"),
            "start": ArgSpec("int", 0, 65535, default=0),
            "limit": ArgSpec("int", 1, 256, default=64),
            "max_chars": ArgSpec("int", 64, 2048, default=1024),
            "max_calls": ArgSpec("int", 0, 256, default=64),
            "max_refs": ArgSpec("int", 0, 128, default=64),
        }, 643),
        "ghidra.xrefs": operation("ghidra.xrefs", {
            "address": ArgSpec("int", 0, 2 ** 64 - 1),
            "start": ArgSpec("int", 0, 65535, default=0),
            "limit": ArgSpec("int", 1, 256, default=64),
        }, 256),
    }
    for name, args in ghidra_args.OPERATIONS.items():
        operations[name] = operation(name, args, 257)
    return ToolSpec(REF, operations, contained=True,
                    runtime={"image": lock["image_id"], "platform": lock["platform"]})


def prepare(data, *, executor=None, store=None):
    """Explicit trusted controller operation; a project is storage, never evidence."""
    executor = executor if executor is not None else DockerExecutor(DEFAULT_LOCK, adapter_version=REF.version)
    store = store if store is not None else ghidra_cache.CacheStore()
    lock = load_lock(executor.lock, adapter_version=REF.version)
    digest = sha256_hex(data)
    manifest, source_id, state, seconds = store.prepare(ghidra_cache.identity(digest, lock),
                                                        lambda sink: executor.prepare(data, digest, sink))
    return {"schema": "reverseai.prepare/1", "input": {"sha256": digest, "size": len(data)},
            "analysis_id": source_id, "state": state,
            "runtime": {"image": lock["image_id"], "platform": lock["platform"], "bundle_sha256": lock["bundle_sha256"]},
            "cache_format": 1, "artifact_size": manifest["size"], "elapsed_seconds": seconds}


def available(lock=None, *, inspect=None):
    try:
        executor = DockerExecutor(DEFAULT_LOCK if lock is None else lock, adapter_version=REF.version,
                                  inspect=inspect_image if inspect is None else inspect)
        return executor.available()
    except ContainedError:
        return False


def __getattr__(name):
    if name == "TOOL":
        return make_tool()
    raise AttributeError(name)
