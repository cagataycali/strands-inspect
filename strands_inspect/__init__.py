"""
strands-inspect — See what your code does. Control what it can do.

    from strands_inspect import watch, lock

    @watch                          # see everything
    @watch(policy="sandbox")        # see + block
    @lock                           # kernel-level, nothing escapes

    from strands_inspect import inspect_tool
    agent = Agent(tools=[inspect_tool])
"""

from strands_inspect._tool import inspect_tool
from strands_inspect._decorator import (
    watch,
    replay,
    list_sessions,
    InspectSession,
    PolicyViolation,
)
from strands_inspect._sandbox import (
    KernelSandbox,
    SandboxResult,
    lock,
    PolicyViolation_Lock,
)
from strands_inspect._config import (
    load_config,
    get_watch_defaults,
    get_named_policy,
    get_lock_defaults,
)

try:
    from strands_inspect._version import version as __version__
except ImportError:
    __version__ = "0.0.0.dev0"

__all__ = [
    "watch",
    "lock",
    "inspect_tool",
    "replay",
    "list_sessions",
    "InspectSession",
    "KernelSandbox",
    "SandboxResult",
    "PolicyViolation",
    "PolicyViolation_Lock",
    "load_config",
    "get_watch_defaults",
    "get_named_policy",
    "get_lock_defaults",
    "__version__",
]
