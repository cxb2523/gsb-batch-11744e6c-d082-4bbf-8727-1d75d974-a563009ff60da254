"""Contained syntax readings with source text and byte anchors re-derived on the host."""

from reverseai.contained import ContainedError, DockerExecutor, default_lock, inspect_image, load_lock
from reverseai.contract import ArgSpec, OperationSpec, ToolRef, ToolSpec, sha256_hex
from reverseai.tools import jsparser_verify

REF = ToolRef('jsparser', '8.0.4-r2')
DEFAULT_LOCK = default_lock("jsparser")


def make_tool(executor=None):
    if executor is None:
        executor = DockerExecutor(DEFAULT_LOCK, adapter_version=REF.version)
    lock = load_lock(executor.lock, adapter_version=REF.version)

    def invoke(data, args):
        checked = operation.validate_args(args)
        request, files = jsparser_verify.prepare(data, checked)
        if not files:
            return ()
        digest = sha256_hex(data)
        raw = executor.run('jsparser.syntax', request, data, digest)
        return jsparser_verify.anchor(jsparser_verify.parse_reply(raw, digest), checked, files)

    operation = OperationSpec('jsparser.syntax', {
        'file': ArgSpec('identity', 0, 255, default=''),
        'kind': ArgSpec('enum', choices=('modules', 'calls', 'parse'), default='modules'),
        'start': ArgSpec('int', 0, 1048575, default=0),
        'limit': ArgSpec('int', 1, 256, default=128),
    }, invoke, max_observations=256, derived=True)
    return ToolSpec(REF, {'jsparser.syntax': operation}, contained=True,
                    runtime={'image': lock['image_id'], 'platform': lock['platform']})


def available(lock=None, *, inspect=None):
    try:
        executor = DockerExecutor(DEFAULT_LOCK if lock is None else lock, adapter_version=REF.version,
                                  inspect=inspect_image if inspect is None else inspect)
        return executor.available()
    except ContainedError:
        return False


def __getattr__(name):
    if name == 'TOOL':
        return make_tool()
    raise AttributeError(name)
