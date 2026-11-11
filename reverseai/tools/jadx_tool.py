"""Contained JADX method pages; identities and byte anchors come from the host."""

from reverseai.contained import ContainedError, DockerExecutor, default_lock, inspect_image, load_lock
from reverseai.contract import ArgSpec, OperationSpec, ToolRef, ToolSpec, sha256_hex
from reverseai.tools import jadx_verify

REF = ToolRef("jadx", "1.5.6-r1")
DEFAULT_LOCK = default_lock("jadx")


def make_tool(executor=None):
    if executor is None:
        executor = DockerExecutor(DEFAULT_LOCK, adapter_version=REF.version)
    lock = load_lock(executor.lock, adapter_version=REF.version)

    def invoke(data, args):
        checked = operation.validate_args(args)
        request, anchors = jadx_verify.prepare(data, checked)
        if not anchors:
            return ()
        digest = sha256_hex(data)
        raw = executor.run("jadx.method", request, data, digest)
        return jadx_verify.anchor(jadx_verify.parse_reply(raw, digest), checked, anchors)

    operation = OperationSpec("jadx.method", {
        "member": ArgSpec("identity", 0, 255, default=""),
        "class": ArgSpec("identity", 1, 255), "method": ArgSpec("identity", 1, 255),
        "prototype": ArgSpec("identity", 0, 255, default=""),
        "start": ArgSpec("int", 0, 1048575, default=0),
        "max_chars": ArgSpec("int", 64, 2048, default=1024),
    }, invoke, max_observations=16, derived=True)
    return ToolSpec(REF, {"jadx.method": operation}, contained=True,
                    runtime={"image": lock["image_id"], "platform": lock["platform"]})


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
