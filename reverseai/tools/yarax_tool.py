"""Allowlisted YARA-X matches; parsing/scanning happens only in the contained worker."""

from reverseai.contained import ContainedError, DockerExecutor, default_lock, inspect_image
from reverseai.contract import ArgSpec, OperationSpec, ToolRef, ToolSpec, parse_worker_reply, sha256_hex
from reverseai.tools import yarax_verify

REF = ToolRef("yarax", "1.21.0-r2")
DEFAULT_LOCK = default_lock("yarax")
RULESET_PATH = DEFAULT_LOCK.with_name("m2_fixture_v1.json")
EXTRA_KEYS = ("ruleset_sha256",)


def make_tool(executor=None):
    """Freeze both image identity and the local pattern bytes used to verify its replies."""
    if executor is None:
        executor = DockerExecutor(DEFAULT_LOCK, adapter_version=REF.version, extra_keys=EXTRA_KEYS)
    try:
        digest = executor.lock["ruleset_sha256"]
    except KeyError:
        raise ContainedError("InvalidImageLock") from None
    patterns = yarax_verify.load_patterns(RULESET_PATH, digest)

    def invoke(data, args):
        checked = operation.validate_args(args)
        digest = sha256_hex(data)
        raw = executor.run("yarax.matches", checked, data, digest)
        observations = parse_worker_reply(raw, input_sha256=digest, max_observations=checked["max_matches"])
        yarax_verify.verify(data, observations, checked, patterns)
        return observations

    operation = OperationSpec("yarax.matches", {
        "ruleset": ArgSpec("enum", choices=(yarax_verify.RULESET,), default=yarax_verify.RULESET),
        "max_matches": ArgSpec("int", 1, 64, default=32),
    }, invoke, max_observations=64)
    return ToolSpec(REF, {operation.name: operation}, contained=True,
                    runtime={"image": executor.lock["image_id"], "platform": executor.lock["platform"]})


def available(lock=None, *, inspect=None):
    """Missing image, lock or a mismatched local ruleset disables the optional tool."""
    try:
        executor = DockerExecutor(DEFAULT_LOCK if lock is None else lock, adapter_version=REF.version,
                                  extra_keys=EXTRA_KEYS, inspect=inspect_image if inspect is None else inspect)
        make_tool(executor)
        return executor.available()
    except ContainedError:
        return False


def __getattr__(name):
    if name == "TOOL":
        return make_tool()
    raise AttributeError(name)
