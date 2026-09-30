"""Bridge between the ``@watch`` syscall hooks and the Dogwood authorizer.

Every hook check becomes one ``request`` event for the watched function (principal) on the
process (resource) with ``context.input`` = the structured fields of the call; the
authorizer answers; a ``response`` event with ``output.allowed`` is fed back so temporal
rules can look at what already happened ("no network after a sensitive read").
"""

from __future__ import annotations

import os
import re
import shlex
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from . import ast as A
from .authorizer import Authorizer, Event, PolicySet, Response
from .cedar_eval import EntityData
from .errors import DogwoodError
from .event_schema import DEFAULT_EVENT_SCHEMA
from .inspect_schema import (
    ACTIONS,
    FUNCTION_TYPE,
    PROCESS_TYPE,
    action_ref,
    classify_sensitive,
    inspect_schema,
)
from .values import DateTime, EntityRef, Record, SetValue

PRESETS = ("allow_all", "deny_all", "deny_network", "deny_write", "sandbox", "strict")
PRESET_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "policies")


def preset_path(name: str) -> str:
    return os.path.join(PRESET_DIR, f"{name}.dw")


def looks_like_dogwood(text: str) -> bool:
    """Inline Dogwood source: mentions permit/forbid and has a parenthesis."""
    return bool(re.search(r"\b(permit|forbid)\b", text)) and "(" in text


class DogwoodPolicy:
    """A parsed Dogwood policy set bound to the Inspect schema.

    Build one with :meth:`parse` (inline source), :meth:`from_file` (a ``.dw`` path) or
    :meth:`preset` (``allow_all`` ... ``strict``); pass it to ``@watch(policy=...)`` or
    ``@lock(policy=...)``.
    """

    def __init__(self, policy_set: PolicySet, source: str, name: str = "<inline>"):
        self.policy_set = policy_set
        self.source = source
        self.name = name

    @classmethod
    def parse(cls, text: str, name: str = "<inline>") -> "DogwoodPolicy":
        ps = PolicySet.parse(text, schema=inspect_schema(), source=name, validate=True)
        return cls(ps, text, name)

    @classmethod
    def from_file(cls, path: Any) -> "DogwoodPolicy":
        p = os.fspath(path)
        with open(p, encoding="utf-8") as fh:
            return cls.parse(fh.read(), os.path.basename(p))

    @classmethod
    def preset(cls, name: str) -> "DogwoodPolicy":
        if name not in PRESETS:
            raise DogwoodError(f"unknown preset `{name}`; presets: {', '.join(PRESETS)}")
        return cls.from_file(preset_path(name))

    @property
    def rules(self) -> List[str]:
        return self.policy_set.labels

    @property
    def policies(self) -> List[A.Policy]:
        return self.policy_set.policies

    def asks(self, label: str) -> bool:
        """True when the rule ``label`` carries the ``@ask`` annotation."""
        for p in self.policies:
            if p.label == label:
                return any(k == "ask" for k, _ in p.annotations)
        return False

    def describe(self) -> Dict[str, Any]:
        return {
            "language": "dogwood",
            "name": self.name,
            "source": self.source,
            "rules": self.rules,
        }

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"DogwoodPolicy({self.name!r}, rules={self.rules})"


# --------------------------------------------------------------------------- detail parsing
_ARROW = "\u2192"


def fields_from_detail(action: str, detail: str) -> Dict[str, Any]:
    """Recover structured fields from a legacy detail string (best effort, tested per hook)."""
    d = detail.strip()
    f: Dict[str, Any] = {}
    if action in ("file.read", "file.write"):
        m = re.match(
            r"^(?:shutil\.\w+ )?(.*?)(?: \(mode=([^)]*)\))?(?: \(os\.open flags=(0x[0-9a-f]+)\))?$",
            d,
        )
        if m:
            path = m.group(1)
            if _ARROW in path:  # shutil.copy src -> dst : the written path is dst
                path = path.split(_ARROW)[-1].strip()
            f["path"] = path
            f["mode"] = m.group(2) or m.group(3) or ""
    elif action in ("file.delete", "file.mkdir", "file.special"):
        f["path"] = re.sub(r"^(rmtree|makedirs|mkfifo|mknod) ", "", d)
    elif action in ("file.move", "file.link"):
        parts = re.sub(r"^(shutil\.move|link|symlink) ", "", d).split(_ARROW)
        if len(parts) == 2:
            f["src"], f["dst"] = parts[0].strip(), parts[1].strip()
    elif action == "file.chmod":
        m = re.match(r"^(chmod|chown) (\S+) (.*)$", d)
        if m:
            f["mode"], f["path"] = m.group(2), m.group(3)
    elif action == "file.fd_io":
        m = re.search(r"fd=(\d+)", d)
        if m:
            f["fd"] = int(m.group(1))
        m = re.search(r"(?:n|len|count)=(\d+)|to (\d+)$", d)
        if m:
            f["size"] = int(m.group(1) or m.group(2))
    elif action == "network":
        target = d.split(_ARROW)[-1].strip() if _ARROW in d else d
        m = re.match(r"^(\w+) " + _ARROW, d)
        if m and m.group(1).isupper():
            f["method"] = m.group(1)
        f.update(_parse_target(target))
    elif action == "net.socket":
        m = re.search(r"(\d+) bytes", d)
        if m:
            f["size"] = int(m.group(1))
        if _ARROW in d:
            f.update(_parse_target(d.split(_ARROW)[-1].strip()))
    elif action in ("subprocess", "os.system", "os.exec"):
        cmd = re.sub(r"^(popen: |\w+: )", "", d)
        f["command"] = cmd
        f.update(_split_command(cmd))
    elif action == "process.kill":
        m = re.search(r"(?:pid|pgid)=(-?\d+) sig=(\d+)", d)
        if m:
            f["pid"], f["signal"] = int(m.group(1)), int(m.group(2))
    elif action == "process.mp":
        m = re.match(r"^Process\.start name=(.*) target=(.*)$", d)
        if m:
            f["name"], f["target"] = m.group(1), m.group(2)
    elif action == "import":
        f["module"] = d
        f["package"] = d.split(".")[0]
    elif action == "meta.ctypes":
        m = re.match(r"^\w+(?:\.\w+)?\((.*)\)$", d)
        f["library"] = m.group(1) if m else d
    elif action == "meta.code":
        m = re.match(r"^(eval|exec|compile)\((.*)\)$", d, re.DOTALL)
        f["source"] = m.group(2) if m else d
    return f


def _parse_target(target: str) -> Dict[str, Any]:
    """``host:port`` / ``('h', p)`` / ``scheme://host[:port]/...`` -> host, port, url, scheme."""
    out: Dict[str, Any] = {}
    t = target.strip()
    m = re.match(r"^\(?'?([^',:/ ]+)'?,?\s*(\d+)\)?$", t)  # ('host', port) or host:port
    if m and not t.startswith(("http", "ws", "ftp")):
        out["host"], out["port"] = m.group(1), int(m.group(2))
        return out
    m = re.match(r"^([a-z][a-z0-9+.-]*)://([^/:?#]+)(?::(\d+))?", t)
    if m:
        out["url"] = t
        out["scheme"] = m.group(1)
        out["host"] = m.group(2)
        out["port"] = (
            int(m.group(3))
            if m.group(3)
            else {"https": 443, "http": 80, "wss": 443, "ws": 80}.get(m.group(1), 0)
        )
        return out
    m = re.match(r"^([^:/ ]+):(\d+)$", t)
    if m:
        out["host"], out["port"] = m.group(1), int(m.group(2))
        return out
    out["host"] = t
    return out


def _split_command(cmd: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    text = cmd.strip()
    if text.startswith("[") and text.endswith("]"):
        try:
            import ast as _ast

            argv = [str(x) for x in _ast.literal_eval(text)]
        except (ValueError, SyntaxError):
            argv = [text]
        out["shell"] = False
    else:
        try:
            argv = shlex.split(text)
        except ValueError:
            argv = text.split()
        out["shell"] = True
    out["argv"] = argv
    out["program"] = os.path.basename(argv[0]) if argv else ""
    return out


_FIELD_TYPES: Dict[str, type] = {
    "port": int,
    "size": int,
    "fd": int,
    "pid": int,
    "signal": int,
    "shell": bool,
    "sensitive": bool,
}


def build_input(action: str, detail: str, fields: Dict[str, Any]) -> Record:
    """The typed ``context.input`` record for one hook check (schema-shaped, missing fields defaulted)."""
    declared = ACTIONS.get(action, (None, ""))[1]
    names = [part.split(":")[0].strip() for part in declared.split(",") if part.strip()]
    merged = dict(fields_from_detail(action, detail))
    merged.update({k: v for k, v in fields.items() if v is not None})
    rec: Dict[str, Any] = {"detail": detail, "op": str(merged.pop("op", "") or "")}
    for name in names:
        v = merged.get(name)
        if name == "argv":
            rec[name] = SetValue(str(x) for x in (v or []))
        elif name == "sensitive":
            rec[name] = (
                bool(v) if v is not None else classify_sensitive(str(merged.get("path", "")))
            )
        elif _FIELD_TYPES.get(name) is int:
            try:
                rec[name] = int(v) if v is not None else 0
            except (TypeError, ValueError):
                rec[name] = 0
        elif _FIELD_TYPES.get(name) is bool:
            rec[name] = bool(v)
        else:
            rec[name] = "" if v is None else str(v)
    return Record(rec)


@dataclass
class Verdict:
    decision: str  # allow | deny | ask
    rules: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


class DogwoodBridge:
    """One watched call: a stateful authorizer keyed on the watched function.

    ``check(action, detail, **fields)`` returns a :class:`Verdict`; the caller raises
    ``PolicyViolation`` on ``deny`` and prompts on ``ask``. :meth:`record` feeds the
    matching ``response`` event so later temporal rules see the outcome.
    """

    def __init__(
        self,
        policy: DogwoodPolicy,
        func_module: str = "__main__",
        func_name: str = "<function>",
        session: str = "",
        clock=time.time,
    ):
        self.policy = policy
        self.principal = EntityRef(FUNCTION_TYPE, f"{func_module}.{func_name}")
        self.resource = EntityRef(PROCESS_TYPE, str(os.getpid()))
        self.session = session
        self.clock = clock
        self.authorizer = Authorizer(policy.policy_set, inspect_schema(), DEFAULT_EVENT_SCHEMA)
        self.entities = {
            self.principal: EntityData(Record({"module": func_module, "name": func_name})),
            self.resource: EntityData(Record({"pid": os.getpid(), "cwd": os.getcwd()})),
        }
        self._n = 0
        self._pending: Optional[Tuple[EntityRef, Record, str]] = None

    def _event(
        self, kind: str, action: EntityRef, input_rec: Record, output: Optional[Record], rid: str
    ) -> Event:
        now_ms = int(self.clock() * 1000)
        system = Record({"now": DateTime(now_ms), "session": self.session})
        ctx: Dict[str, Any] = {"input": input_rec, "system": system}
        logged: Dict[str, Any] = {
            "input": input_rec,
            "callerPrincipal": self.principal,
            "callerResource": self.resource,
            "requestId": rid,
            "sessionId": self.session,
        }
        if output is not None:
            ctx["output"] = output
            logged["output"] = output
        return Event(
            ts=now_ms // 1000,
            action=action,
            kind=kind,
            principal=self.principal,
            resource=self.resource,
            request_context=Record(ctx),
            logged=Record(logged),
            entities=self.entities,
        )

    def check(self, action: str, detail: str, **fields: Any) -> Verdict:
        if action not in ACTIONS:
            return Verdict("deny", [], [f"unknown action `{action}`"])
        ref = action_ref(action)
        input_rec = build_input(action, detail, fields)
        self._n += 1
        rid = f"r{self._n}"
        resp: Optional[Response] = self.authorizer.is_authorized(
            self._event("request", ref, input_rec, None, rid)
        )
        self._pending = (ref, input_rec, rid)
        if resp is None or not resp.allowed:
            return Verdict(
                "deny", list(resp.rules) if resp else [], list(resp.errors) if resp else []
            )
        if any(self.policy.asks(label) for label in resp.rules):
            return Verdict("ask", list(resp.rules), list(resp.errors))
        return Verdict("allow", list(resp.rules), list(resp.errors))

    def record(self, allowed: bool) -> None:
        """Feed the ``response`` event for the last check (history only, no verdict)."""
        if self._pending is None:
            return
        ref, input_rec, rid = self._pending
        self._pending = None
        self.authorizer.observe(
            self._event("response", ref, input_rec, Record({"allowed": allowed}), rid)
        )

    @property
    def history_len(self) -> int:
        return len(self.authorizer.history)
