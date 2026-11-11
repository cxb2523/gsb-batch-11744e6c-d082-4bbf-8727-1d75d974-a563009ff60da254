"""Allowlisted LIEF operations, reached only through the contained executor."""

from reverseai.contained import DockerExecutor, ContainedError, default_lock, inspect_image
from reverseai.contract import (
    ArgSpec, ContractError, OperationSpec, ToolRef, ToolSpec, parse_worker_reply, sha256_hex,
)
from reverseai.tools import lief_verify, structure

REF = ToolRef("lief", "1.0.0-r2")
DEFAULT_LOCK = default_lock("lief")


def make_tool(executor=None):
    """Bind handlers and reported runtime identity to one frozen executor lock."""
    if executor is None:
        executor = DockerExecutor(DEFAULT_LOCK, adapter_version=REF.version)
    operations = {}

    def handler(name, cap):
        def invoke(data, args):
            checked = operations[name].validate_args(args)
            identified = structure.identify(data, {})
            if not identified or identified[0].value["format"] not in ("elf", "pe"):
                return []  # the LIEF worker reads ELF and PE only; the host decides this, and no container starts
            digest = sha256_hex(data)
            raw = executor.run(name, checked, data, digest)
            # No more observations than the validated request allows (max_sections, or the headers cap).
            observations = parse_worker_reply(raw, input_sha256=digest, max_observations=checked.get("max_sections", cap))
            if any(not item.location.within(len(data)) for item in observations):
                raise ContractError("Worker location outside the snapshot")
            for item in observations:  # every worker value is re-derived from the controller's bytes
                lief_verify.verify(name, data, item)
            return observations
        return invoke

    operations["lief.headers"] = OperationSpec("lief.headers", {}, handler("lief.headers", 3), max_observations=3)
    operations["lief.sections"] = OperationSpec("lief.sections", {
        "max_sections": ArgSpec("int", 1, 64, default=32),
    }, handler("lief.sections", 64), max_observations=64)
    return ToolSpec(REF, operations, contained=True,
                    runtime={"image": executor.lock["image_id"], "platform": executor.lock["platform"]})


def available(lock=None, *, inspect=None):
    """A missing lock, image or Docker daemon leaves the optional tool disabled."""
    try:
        executor = DockerExecutor(DEFAULT_LOCK if lock is None else lock,
                                  adapter_version=REF.version,
                                  inspect=inspect_image if inspect is None else inspect)
        return executor.available()
    except ContainedError:
        return False


def __getattr__(name):
    # Direct callers get a fresh TOOL; merely importing this module never touches Docker.
    if name == "TOOL":
        return make_tool()
    raise AttributeError(name)
