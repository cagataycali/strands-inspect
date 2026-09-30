"""Static projection of a Dogwood policy onto the kernel sandbox dict of ``@lock``.

The kernel sandbox (Seatbelt / seccomp) knows seven coarse capabilities and cannot see
history, so the projection is deliberately conservative: a capability is allowed iff EVERY
hooked action behind it is covered by an unconditional ``permit`` (scope-only rule, no
``when``/``unless``) and NO ``forbid`` -- conditional or not -- covers any of them. A
``file.read`` permit whose only condition is ``context.input.path like "/prefix/*"`` projects
to a read path allow-list instead. Everything else denies.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from . import ast as A
from .authorizer import PolicySet
from .inspect_schema import ACTIONS, inspect_schema
from .values import EntityRef

# kernel capability -> the hooked actions it stands for
CAPABILITIES: Dict[str, List[str]] = {
    "network": ["network", "net.socket"],
    "file_read": ["file.read"],
    "file_write": [
        "file.write",
        "file.delete",
        "file.move",
        "file.chmod",
        "file.link",
        "file.mkdir",
        "file.special",
        "file.fd_io",
    ],
    "subprocess": ["subprocess", "os.system", "os.exec", "process.fork", "process.mp"],
    "ipc": ["process.kill"],
    "mmap_exec": ["meta.ctypes"],
    "sysctl": [],  # no hooked action stands for sysctl: always denied by a projected policy
}


def _covered(policy: A.Policy, ps: PolicySet) -> List[str]:
    """The Inspect categories a policy's action scope admits."""
    refs = ps.actions_covered(policy)
    if refs is None:
        return list(ACTIONS)
    return [r.id for r in refs if r.id in ACTIONS]


def _read_prefix(policy: A.Policy) -> Optional[str]:
    """``when { context.input.path like "P" }`` (exactly that) -> the glob P, else None."""
    if len(policy.conditions) != 1 or policy.conditions[0].kind != "when":
        return None
    body = policy.conditions[0].body
    if not isinstance(body, A.Like) or not isinstance(body.operand, A.GetAttr):
        return None
    ga = body.operand
    if ga.attr != "path" or not isinstance(ga.operand, A.GetAttr) or ga.operand.attr != "input":
        return None
    if not isinstance(ga.operand.operand, A.Var) or ga.operand.operand.name != "context":
        return None
    return body.pattern


def project_to_kernel(policy_set: PolicySet) -> Dict[str, Any]:
    """Project ``policy_set`` onto the ``@lock`` kernel dict (see the module docstring)."""
    if policy_set.schema is None:
        policy_set = PolicySet(policy_set.ast, policy_set.source_text, inspect_schema())
    unconditional: set = set()
    forbidden: set = set()
    read_globs: List[str] = []
    for p in policy_set.policies:
        cats = _covered(p, policy_set)
        if p.effect == "forbid":
            forbidden.update(cats)
        elif any(k == "ask" for k, _ in p.annotations):
            continue  # the kernel cannot prompt: an @ask permit grants nothing statically
        elif not p.conditions:
            unconditional.update(cats)
        elif cats == ["file.read"]:
            glob = _read_prefix(p)
            if glob is not None:
                read_globs.append(
                    glob.replace("\\*", "*").replace("*", "**") if glob.endswith("*") else glob
                )
    out: Dict[str, Any] = {}
    for cap, cats in CAPABILITIES.items():
        if not cats:
            out[cap] = False
            continue
        if any(c in forbidden for c in cats):
            out[cap] = False
        elif all(c in unconditional for c in cats):
            out[cap] = True
        elif cap == "file_read" and read_globs and "file.read" not in forbidden:
            out[cap] = sorted(set(read_globs))
        else:
            out[cap] = False
    return out
