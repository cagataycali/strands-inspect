"""The ``Inspect`` action schema: what a strands-inspect policy scopes over.

Principal = the watched ``Function``; resource = the ``Process``; one Cedar action per
hooked category (the 20 legacy categories, verbatim), grouped as ``file`` / ``net`` /
``os`` / ``process`` / ``meta``. Every action's ``context.input`` carries ``detail`` (the
legacy one-line string) and ``op`` (the hooked callable) plus typed fields; ``context.output``
is ``{ allowed: Bool }`` on the response event; ``context.system`` = ``{ now, session }``.

The same text ships as ``strands_inspect/dogwood/inspect.cedarschema`` (package data); a test
pins the two copies to each other.
"""

from __future__ import annotations

import os
import re
from functools import lru_cache
from typing import Dict, List, Optional

from .schema import Schema, parse_schema
from .values import EntityRef

NAMESPACE = "Inspect"
ACTION_TYPE = "Inspect::Action"
FUNCTION_TYPE = "Inspect::Function"
PROCESS_TYPE = "Inspect::Process"

# category -> (group or None, input fields beyond detail/op)
ACTIONS: Dict[str, tuple] = {
    "file.read": ("file", "path: String, mode: String, sensitive: Bool"),
    "file.write": ("file", "path: String, mode: String, sensitive: Bool"),
    "file.delete": ("file", "path: String"),
    "file.move": ("file", "src: String, dst: String"),
    "file.chmod": ("file", "path: String, mode: String"),
    "file.link": ("file", "src: String, dst: String"),
    "file.mkdir": ("file", "path: String"),
    "file.fd_io": ("file", "fd: Long, size: Long"),
    "file.special": ("file", "path: String"),
    "network": ("net", "host: String, port: Long, url: String, scheme: String, method: String"),
    "net.socket": ("net", "host: String, port: Long, size: Long"),
    "subprocess": ("os", "command: String, program: String, argv: Set<String>, shell: Bool"),
    "os.system": ("os", "command: String, program: String, argv: Set<String>, shell: Bool"),
    "os.exec": ("os", "command: String, program: String, argv: Set<String>, shell: Bool"),
    "process.fork": ("process", ""),
    "process.kill": ("process", "pid: Long, signal: Long"),
    "process.mp": ("process", "name: String, target: String"),
    "import": (None, "module: String, package: String"),
    "meta.ctypes": ("meta", "library: String"),
    "meta.code": ("meta", "source: String"),
}
GROUPS = ("file", "net", "os", "process", "meta")


def _type_name(category: str) -> str:
    return "".join(part.capitalize() for part in re.split(r"[._]", category)) + "Input"


def _render_schema() -> str:
    lines = [
        "// The Inspect action schema of strands-inspect (generated from inspect_schema.py; do not edit).",
        "namespace Inspect {",
        "  entity Function = { module: String, name: String };",
        "  entity Process = { pid: Long, cwd: String };",
        "  type Output = { allowed: Bool };",
        "  type SystemContext = { now: datetime, session: String };",
    ]
    for cat, (_, fields) in ACTIONS.items():
        extra = f", {fields}" if fields else ""
        lines.append(f"  type {_type_name(cat)} = {{ detail: String, op: String{extra} }};")
    for g in GROUPS:
        lines.append(f'  action "{g}";')
    for cat, (group, _) in ACTIONS.items():
        head = f'  action "{cat}"' + (f' in [Action::"{group}"]' if group else "")
        lines.append(
            f"{head} appliesTo {{ principal: [Function], resource: [Process], "
            f"context: {{ input: {_type_name(cat)}, output?: Output, system: SystemContext }} }};"
        )
    lines.append("}")
    return "\n".join(lines) + "\n"


INSPECT_SCHEMA_TEXT = _render_schema()
SCHEMA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "inspect.cedarschema")


@lru_cache(maxsize=1)
def inspect_schema() -> Schema:
    """The parsed Inspect schema (cached)."""
    return parse_schema(INSPECT_SCHEMA_TEXT, "inspect.cedarschema")


def action_ref(category: str) -> EntityRef:
    return EntityRef(ACTION_TYPE, category)


def group_of(category: str) -> Optional[str]:
    return ACTIONS[category][0] if category in ACTIONS else None


def categories_in(group: str) -> List[str]:
    return [c for c, (g, _) in ACTIONS.items() if g == group]


# --------------------------------------------------------------------------- sensitive paths
_SENSITIVE_DIRS = ("~/.ssh", "~/.aws", "~/.gnupg", "~/.config/gcloud", "~/.kube")
_SENSITIVE_FILES = ("/etc/shadow", "/etc/passwd")
_SENSITIVE_BASENAMES = re.compile(
    r"^(\.env.*|.*\.pem|.*\.key|id_.*|.*credentials.*|.*\.keychain.*)$", re.IGNORECASE
)


def classify_sensitive(path: str) -> bool:
    """True when ``path`` is a credential-shaped location (see the module docstring of bridge.py)."""
    if not path:
        return False
    p = os.path.expanduser(str(path))
    norm = os.path.normpath(p)
    home = os.path.expanduser("~")
    for d in _SENSITIVE_DIRS:
        full = os.path.normpath(d.replace("~", home, 1))
        if norm == full or norm.startswith(full + os.sep):
            return True
    if norm in _SENSITIVE_FILES:
        return True
    base = os.path.basename(norm)
    return bool(_SENSITIVE_BASENAMES.match(base))
