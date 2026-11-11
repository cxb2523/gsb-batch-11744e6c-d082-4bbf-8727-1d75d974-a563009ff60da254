"""reverseai doctor: read-only facts about this host; never pulls, builds or runs a container and reads no sample.

Docker is asked one fixed question, "docker version", within 10 s; each contained tool's lock is loaded as its
available() loads it, and only when Docker answered is its locked image ID looked up with "docker image inspect".
"""

from importlib import import_module
import json
import platform
import re
import sys

import reverseai
from reverseai import contained
from reverseai.ghidra_cache import CacheStore

MIN_PYTHON = (3, 12)
DOCKER_SECONDS = 10
DOCKER_VERSION_ARGV = ("docker", "version", "--format", "{{.Server.Version}}")
TOOLS = (("lief", "lief_tool"), ("yarax", "yarax_tool"), ("ghidra", "ghidra_tool"), ("jadx", "jadx_tool"),
         ("jsparser", "jsparser_tool"))
_SERVER_VERSION = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+~-]{0,63}\Z")


def docker_version():
    """The Docker server version, or None when Docker does not answer the fixed call within 10 s."""
    try:
        raw = contained.run_bounded(list(DOCKER_VERSION_ARGV), timeout=DOCKER_SECONDS, max_output=256)
    except contained.ContainedError:
        return None
    text = raw.decode("ascii", "replace").strip()
    return text if _SERVER_VERSION.match(text) else "unknown"


def tool_facts(name, module_name, inspect):
    module = import_module("reverseai.tools." + module_name)
    facts = {"tool": name, "version": module.REF.version, "lock": str(module.DEFAULT_LOCK), "lock_loads": False,
             "image_id": None, "image_present": None, "available": False}
    try:
        executor = contained.DockerExecutor(module.DEFAULT_LOCK, adapter_version=module.REF.version,
                                            extra_keys=getattr(module, "EXTRA_KEYS", ()), inspect=inspect)
    except contained.ContainedError:
        return facts
    facts.update(lock_loads=True, image_id=executor.lock["image_id"])
    if inspect is not None:
        facts["image_present"] = executor.available()
        facts["available"] = facts["image_present"] and module.available(inspect=inspect)
    return facts


def collect(*, version_info=None, ask_docker=docker_version, inspect=None):
    """inspect(image_id) -> local ID; injections let tests run without Docker."""
    version_info = sys.version_info if version_info is None else version_info
    server = ask_docker()
    if server is not None:
        seen = {}
        lookup = contained.inspect_image if inspect is None else inspect

        def inspect(image_id):
            if image_id not in seen:
                try:
                    seen[image_id] = lookup(image_id)
                except Exception:
                    seen[image_id] = None
            return seen[image_id]
    else:
        inspect = None
    supported = tuple(version_info[:2]) >= MIN_PYTHON
    return {
        "reverseai": reverseai.__version__,
        "python": {"version": ".".join(str(part) for part in version_info[:3]),
                   "implementation": platform.python_implementation(), "supported": supported},
        "platform": {"system": platform.system(), "machine": platform.machine(), "release": platform.release()},
        "docker": {"answered": server is not None, "server_version": server, "timeout_seconds": DOCKER_SECONDS},
        "tools": [tool_facts(name, module, inspect) for name, module in TOOLS],
        "ghidra_cache": CacheStore().facts(),
        "host_ok": supported,
    }


def to_text(facts):
    python, docker = facts["python"], facts["docker"]
    lines = [f"reverseai {facts['reverseai']}",
             f"python {python['version']} ({python['implementation']}, {facts['platform']['system']} "
             f"{facts['platform']['machine']}): " + ("ok" if python["supported"] else "unsupported, needs 3.12 or later"),
             "docker: " + (f"answered (server {docker['server_version']})" if docker["answered"]
                           else f"no answer within {docker['timeout_seconds']} s; contained tools unavailable")]
    for tool in facts["tools"]:
        if not tool["lock_loads"]:
            state = "unavailable: the image lock does not load"
        elif tool["image_present"] is None:
            state = f"lock loads ({tool['image_id']}); image not checked"
        elif not tool["image_present"]:
            state = f"unavailable: image {tool['image_id']} is not present locally"
        else:
            state = "available" if tool["available"] else "unavailable: the lock does not match its local files"
        lines.append(f"{tool['tool']} {tool['version']}: {state}")
    cache = facts["ghidra_cache"]
    lines.append(f"Ghidra cache: {cache['state']}; entries {cache['entries']}; bytes {cache['bytes']}")
    lines.append("host features: " + ("ok" if facts["host_ok"] else "not usable"))
    return "\n".join(lines) + "\n"


def main(as_json=False, **injections):
    facts = collect(**injections)
    sys.stdout.write(json.dumps(facts, indent=2, sort_keys=True) + "\n" if as_json else to_text(facts))
    return 0 if facts["host_ok"] else 1
