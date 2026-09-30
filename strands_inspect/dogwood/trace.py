"""The ``.log`` trace wire format (one event per line) and the corpus replay format.

Line shape (dogwood-language/src/interpreter/log_parse.rs)::

    @<ts> [scope(principal: <uid>, resource: <uid>)] [entities(<uid>: {..} [in [..]], ..)]
          [request_context(input: {..}, system: {..})] Ns::Action::"X"::kind(field: value, ..)

Values use Cedar surface forms: entity refs, strings, integers, decimals, true/false,
null, arrays and objects. There is no comment syntax.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from .authorizer import Event
from .cedar_eval import EntityData
from .errors import TraceError
from .lexer import unescape
from .values import Decimal, EntityRef, Record, SetValue


def _split_top_level(s: str, sep: str) -> List[str]:
    parts: List[str] = []
    depth = 0
    in_str = False
    esc = False
    start = 0
    for i, ch in enumerate(s):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == sep and depth == 0:
            parts.append(s[start:i])
            start = i + 1
    parts.append(s[start:])
    return parts


def _split_once(s: str, sep: str) -> Optional[Tuple[str, str]]:
    depth = 0
    in_str = False
    esc = False
    for i, ch in enumerate(s):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == sep and depth == 0:
            if sep == ":" and (s[i + 1 : i + 2] == ":" or s[i - 1 : i] == ":"):
                continue  # a `::` path separator is not a key/value colon
            return s[:i], s[i + 1 :]
    return None


def _matching_paren(s: str) -> int:
    """Index of the ``)`` closing an already-opened ``(`` at the start of ``s``; -1 if none."""
    depth = 1
    in_str = False
    esc = False
    for i, ch in enumerate(s):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
    return -1


def _find_unescaped_quote(s: str) -> int:
    esc = False
    for i, ch in enumerate(s):
        if esc:
            esc = False
        elif ch == "\\":
            esc = True
        elif ch == '"':
            return i
    return -1


def _unquote(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        s = s[1:-1]
    return unescape(s, 0, 0)


def _entity_quote_open(s: str) -> int:
    """Position of the ``::"`` that opens an entity id whose closing quote ends ``s``."""
    i = s.find('::"')
    while i >= 0:
        rest = s[i + 3 :]
        q = _find_unescaped_quote(rest)
        if q >= 0 and i + 3 + q == len(s) - 1:
            return i
        i = s.find('::"', i + 1)
    return -1


_MAX_DEPTH = 128


def parse_value(s: str, depth: int = 0) -> Any:
    """Parse one Cedar-surface value from a trace line. ``null`` becomes None."""
    if depth > _MAX_DEPTH:
        raise TraceError(f"logged value nested deeper than the limit of {_MAX_DEPTH}")
    s = s.strip()
    if s == "null":
        return None
    if s == "true":
        return True
    if s == "false":
        return False
    if s.startswith("[") and s.endswith("]"):
        items = [parse_value(p, depth + 1) for p in _split_top_level(s[1:-1], ",") if p.strip()]
        return SetValue(items)
    if s.startswith("{") and s.endswith("}"):
        obj: Dict[str, Any] = {}
        for part in _split_top_level(s[1:-1], ","):
            if not part.strip():
                continue
            kv = _split_once(part, ":")
            if kv is None:
                raise TraceError(f"object field `{part.strip()}` missing `:`")
            k = _unquote(kv[0])
            if k in obj:
                raise TraceError(f"record has a duplicate field `{k}`")
            obj[k] = parse_value(kv[1], depth + 1)
        return Record(obj)
    if "::" in s and s.endswith('"'):
        q = _entity_quote_open(s)
        if q >= 0:
            return EntityRef(s[:q], _unquote(s[q + 2 :]))
    if len(s) >= 2 and s.startswith('"') and s.endswith('"'):
        return _unquote(s)
    try:
        return int(s)
    except ValueError:
        pass
    if "." in s:
        try:
            float(s)
            return Decimal.parse(s if len(s.split(".")[1]) <= 4 else s[: s.index(".") + 5])
        except (ValueError, Exception):
            pass
    return s


def parse_args(src: str) -> Dict[str, Any]:
    fields: Dict[str, Any] = {}
    for part in _split_top_level(src, ","):
        part = part.strip()
        if not part:
            continue
        kv = _split_once(part, ":")
        if kv is None:
            raise TraceError(f"argument `{part}` missing `:`")
        key = kv[0].strip()
        if key in fields:
            raise TraceError(f"duplicate field `{key}`")
        fields[key] = parse_value(kv[1])
    return fields


def _parse_entities(src: str) -> Dict[EntityRef, EntityData]:
    out: Dict[EntityRef, EntityData] = {}
    for part in _split_top_level(src, ","):
        part = part.strip()
        if not part:
            continue
        kv = _split_once(part, ":")
        if kv is None:
            raise TraceError(f"entity entry `{part}` missing `:`")
        uid = parse_value(kv[0])
        if not isinstance(uid, EntityRef):
            raise TraceError(f"entity entry key `{kv[0].strip()}` is not an entity uid")
        rest = kv[1].strip()
        parents: set = set()
        if rest.endswith("]"):
            idx = rest.rfind(" in [")
            if idx >= 0:
                plist = parse_value(rest[idx + 4 :])
                rest = rest[:idx].strip()
                for p in plist if isinstance(plist, SetValue) else []:
                    if isinstance(p, EntityRef):
                        parents.add(p)
        attrs = parse_value(rest)
        if not isinstance(attrs, Record):
            raise TraceError(f"entity `{uid}` attributes must be a record")
        clean = Record({k: v for k, v in attrs.items() if v is not None})
        out[uid] = EntityData(attrs=clean, parents=parents)
    return out


def _parse_head(head: str) -> Tuple[EntityRef, str]:
    q = head.find('::"')
    if q < 0:
        raise TraceError(f"event head `{head}` is missing a quoted action id")
    id_start = q + 3
    q_end = _find_unescaped_quote(head[id_start:])
    if q_end < 0:
        raise TraceError(f"event head `{head}` has an unterminated action id")
    id_end = id_start + q_end
    ns = head[:q]
    action = unescape(head[id_start:id_end], 0, 0)
    after = head[id_end + 1 :].strip()
    if not after.startswith("::") or not after[2:].strip():
        raise TraceError(f"event head `{head}` is missing a `::kind` segment")
    return EntityRef(ns, action), after[2:].strip()


def parse_line(line: str) -> Event:
    if not line.startswith("@"):
        raise TraceError("timepoint must start with `@`")
    rest = line[1:]
    sp = 0
    while sp < len(rest) and not rest[sp].isspace():
        sp += 1
    if sp == len(rest):
        raise TraceError("expected whitespace after timestamp")
    ts_str, after = rest[:sp], rest[sp:].strip()
    try:
        ts = int(ts_str)
    except ValueError:
        raise TraceError(f"bad timestamp `{ts_str}`") from None
    principal = resource = None
    if after.startswith("scope("):
        close = after.find(")")
        if close < 0:
            raise TraceError("scope missing `)`")
        sc = parse_args(after[6:close])
        principal, resource = sc.get("principal"), sc.get("resource")
        after = after[close + 1 :].strip()
    entities: Dict[EntityRef, EntityData] = {}
    if after.startswith("entities("):
        body = after[len("entities(") :]
        close = _matching_paren(body)
        if close < 0:
            raise TraceError("entities missing `)`")
        entities = _parse_entities(body[:close])
        after = body[close + 1 :].strip()
    request_context: Dict[str, Any] = {}
    if after.startswith("request_context("):
        body = after[len("request_context(") :]
        close = _matching_paren(body)
        if close < 0:
            raise TraceError("request_context missing `)`")
        request_context = parse_args(body[:close])
        after = body[close + 1 :].strip()
    open_ = after.find("(")
    close = after.rfind(")")
    if open_ < 0 or close < 0:
        raise TraceError("event missing `(` or `)`")
    if open_ >= close:
        raise TraceError("event group `(` and `)` are out of order")
    action, kind = _parse_head(after[:open_].strip())
    logged = parse_args(after[open_ + 1 : close])
    return Event(
        ts=ts,
        action=action,
        kind=kind,
        principal=principal if isinstance(principal, EntityRef) else None,
        resource=resource if isinstance(resource, EntityRef) else None,
        request_context=Record(request_context),
        logged=Record(logged),
        entities=entities,
    )


def parse_trace(text: str) -> List[Event]:
    """Parse a whole ``.log`` trace; blank lines are skipped."""
    text = text.lstrip("\ufeff")
    events: List[Event] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        try:
            events.append(parse_line(line))
        except TraceError as exc:
            raise TraceError(f"line {lineno}: {exc.message}") from None
    return events
