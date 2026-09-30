"""Minimal ``.dwschema`` (event schema) reader.

Only what evaluation needs: which kinds are ``decision`` kinds, and the ``pin``
declarations per kind (``pin field: T = principal | resource | context.<path>``). A pin
declared on EVERY kind is *universal*; a universal pin whose value is symmetric switches
temporal evaluation to key-local semantics on that field. The default (``DEFAULT``) is the
reference's pinned request/response/error schema; ``UNPINNED`` is the corpus harness's.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .errors import SchemaError
from .lexer import EOF_KIND, IDENT, INT, OP, tokenize

Ref = Tuple[str, ...]  # ("principal",) | ("resource",) | ("context", "a", "b")

DEFAULT = """
decision event <A>::request { ...inputs(A), pin callerPrincipal: principalType(A) = principal, callerResource: resourceType(A), requestId: String, sessionId: String }
event <A>::response { ...inputs(A), ...outputs(A), pin callerPrincipal: principalType(A) = principal, callerResource: resourceType(A), requestId: String, sessionId: String }
event <A>::error { ...inputs(A), pin callerPrincipal: principalType(A) = principal, callerResource: resourceType(A), requestId: String, sessionId: String }
"""

UNPINNED = DEFAULT.replace(
    "pin callerPrincipal: principalType(A) = principal", "callerPrincipal: principalType(A)"
)


@dataclass
class EventSchema:
    decision_kinds: List[str] = field(default_factory=list)
    kinds: List[str] = field(default_factory=list)
    pins: Dict[str, List[Tuple[Tuple[str, ...], Ref]]] = field(
        default_factory=dict
    )  # kind -> [(field path, ref)]
    max_window: Optional[int] = None  # seconds

    @property
    def universal_pins(self) -> List[Tuple[Tuple[str, ...], Ref]]:
        """Pins declared (identically) on every kind -- the key-local partition key."""
        if not self.kinds:
            return []
        first = self.pins.get(self.kinds[0], [])
        return [p for p in first if all(p in self.pins.get(k, []) for k in self.kinds)]

    @property
    def key_local(self) -> bool:
        return bool(self.universal_pins)


def parse_event_schema(text: str, source: str = "") -> EventSchema:
    toks = tokenize(text.lstrip("\ufeff"), source)
    i = 0
    es = EventSchema()

    def tok(k: int = 0):
        return toks[min(i + k, len(toks) - 1)]

    def err(msg: str) -> SchemaError:
        return SchemaError(msg, tok().line, tok().col, source)

    def expect(kind: str, value: Optional[str] = None):
        nonlocal i
        t = tok()
        if t.kind != kind or (value is not None and t.value != value):
            raise err(f"expected `{value or kind}`, found `{t.value or 'end of input'}`")
        i += 1
        return t

    def parse_ref() -> Ref:
        nonlocal i
        base = expect(IDENT).value
        path = [base]
        while tok().is_op(".") and tok(1).kind == IDENT:
            i += 2
            path.append(toks[i - 1].value)
        if base not in ("principal", "resource", "context"):
            raise err("a pin value must be `principal`, `resource` or `context.<path>`")
        return tuple(path)

    def parse_fields(kind: str, prefix: Tuple[str, ...]) -> None:
        nonlocal i
        expect(OP, "{")
        while not tok().is_op("}"):
            if tok().is_op("."):  # ...inputs(A) / ...outputs(A)
                while tok().is_op("."):
                    i += 1
                expect(IDENT)
                expect(OP, "(")
                expect(IDENT)
                expect(OP, ")")
            else:
                pinned = False
                if tok().is_ident("pin") and tok(1).kind == IDENT and tok(2).is_op(":"):
                    pinned = True
                    i += 1
                name = expect(IDENT).value
                expect(OP, ":")
                if tok().is_op("{"):
                    parse_fields(kind, prefix + (name,))
                else:
                    while tok().kind == IDENT or tok().is_op("::"):
                        i += 1
                    if tok().is_op("("):
                        i += 1
                        expect(IDENT)
                        expect(OP, ")")
                if tok().is_op("="):
                    if not pinned:
                        raise err(f"field `{name}` has a `= ...` value but is not marked `pin`")
                    i += 1
                    es.pins.setdefault(kind, []).append((prefix + (name,), parse_ref()))
                elif pinned:
                    raise err(f"pinned field `{name}` is missing its pin value")
            if tok().is_op(","):
                i += 1
        expect(OP, "}")

    while tok().kind != EOF_KIND:
        if tok().is_ident("max_window"):
            i += 1
            expect(OP, "=")
            n = int(expect(INT).value)
            unit = expect(IDENT).value
            es.max_window = n * {"s": 1, "m": 60, "h": 3600, "d": 86400}.get(unit, 0)
            continue
        decision = False
        if tok().is_ident("decision"):
            decision = True
            i += 1
        expect(IDENT, "event")
        expect(OP, "<")
        expect(IDENT)
        expect(OP, ">")
        expect(OP, "::")
        kind = expect(IDENT).value
        es.kinds.append(kind)
        es.pins.setdefault(kind, [])
        if decision:
            es.decision_kinds.append(kind)
        parse_fields(kind, ())
    return es


DEFAULT_EVENT_SCHEMA = parse_event_schema(DEFAULT)
UNPINNED_EVENT_SCHEMA = parse_event_schema(UNPINNED)
