"""Light schema validation: every ``context.<path>`` a rule reads must exist for the actions
its scope covers, and every predicate field pattern must name a field of that action's event.

This is the check that catches ``context.input.hostname`` (a typo) at parse time instead of
letting the rule silently never apply at runtime.
"""

from __future__ import annotations

from typing import Any, Iterable, List, Optional, Tuple

from . import ast as A
from .errors import SchemaError
from .schema import Schema
from .values import EntityRef

_EVENT_FIELDS = ("callerPrincipal", "callerResource", "requestId", "sessionId")


def _context_paths(e: Any, out: List[Tuple[List[str], Any]]) -> None:
    """Collect ``context.a.b`` GetAttr chains (not the ones guarded by ``has``)."""
    if isinstance(e, A.GetAttr):
        path: List[str] = []
        cur: Any = e
        while isinstance(cur, A.GetAttr):
            path.append(cur.attr)
            cur = cur.operand
        if isinstance(cur, A.Var) and cur.name == "context":
            out.append((list(reversed(path)), e))
            return
        _context_paths(e.operand, out)
        return
    if isinstance(e, A.Has):
        return  # the guard exists precisely because the attribute may be absent
    if isinstance(e, A.TemporalBlock):
        _temporal_paths(e.cond, out)
        return
    for name in ("cond", "then", "orelse", "left", "right", "operand", "in_expr"):
        sub = getattr(e, name, None)
        if isinstance(sub, A.Expr):
            _context_paths(sub, out)
    for name in ("args", "items"):
        for sub in getattr(e, name, None) or []:
            if isinstance(sub, tuple):
                sub = sub[1]
            if isinstance(sub, A.Expr):
                _context_paths(sub, out)


def _temporal_paths(c: Any, out: List[Tuple[List[str], Any]]) -> None:
    if isinstance(c, A.TContextField):
        out.append((list(c.path), c))
    if isinstance(c, A.Pred):
        for path, term in c.args:
            _temporal_paths(term, out)
        return
    for name in ("body", "left", "right", "operand", "var", "sum_var"):
        sub = getattr(c, name, None)
        if isinstance(sub, (A.TCond, A.Term)):
            _temporal_paths(sub, out)
    for name in ("args", "items"):
        for sub in getattr(c, name, None) or []:
            if isinstance(sub, tuple):
                sub = sub[1]
            if isinstance(sub, (A.TCond, A.Term)):
                _temporal_paths(sub, out)


def _predicates(c: Any, out: List[A.Pred]) -> None:
    if isinstance(c, A.Pred):
        out.append(c)
        return
    for name in ("body", "left", "right", "operand", "cond"):
        sub = getattr(c, name, None)
        if isinstance(sub, (A.TCond, A.Term, A.Expr)):
            _predicates(sub, out)
    for name in ("args", "items"):
        for sub in getattr(c, name, None) or []:
            if isinstance(sub, tuple):
                sub = sub[1]
            if isinstance(sub, (A.TCond, A.Term, A.Expr)):
                _predicates(sub, out)


def _fields_of(schema: Schema, action: EntityRef, group: str) -> List[str]:
    t = schema.record_path(action, [group])
    return sorted(t[1]) if t and t[0] == "record" else []


def validate_against_schema(
    policies: Iterable[A.Policy], schema: Schema, actions_of, source: str = ""
) -> None:
    """Raise SchemaError for a ``context.<path>`` or predicate field that no covered action declares."""
    for p in policies:
        covered: Optional[List[EntityRef]] = actions_of(p)
        if covered is None:
            covered = list(schema.actions)
        covered = [a for a in covered if a in schema.actions and schema.context_type(a) is not None]
        if not covered:
            continue
        reads: List[Tuple[List[str], Any]] = []
        for cond in p.conditions:
            _context_paths(cond.body, reads)
        for path, node in reads:
            if path and path[0] == "output":
                continue  # optional on the request; a rule reads it behind `has`
            if not any(schema.record_path(a, path) is not None for a in covered):
                known = _fields_of(schema, covered[0], path[0]) if len(path) > 1 else []
                hint = f" (fields: {', '.join(known)})" if known else ""
                raise SchemaError(
                    f"policy `{p.label}` reads `context.{'.'.join(path)}`, which none of its actions declares{hint}",
                    getattr(node, "line", 0),
                    getattr(node, "col", 0),
                    source,
                )
        preds: List[A.Pred] = []
        for cond in p.conditions:
            _predicates(cond.body, preds)
        for pred in preds:
            ref = EntityRef("::".join(pred.namespace), pred.action)
            if ref not in schema.actions:
                raise SchemaError(
                    f"policy `{p.label}` names unknown action `{ref}` in a temporal predicate",
                    pred.line,
                    pred.col,
                    source,
                )
            for path, _ in pred.args:
                if len(path) == 1 and path[0] in _EVENT_FIELDS:
                    continue
                if (
                    path
                    and path[0] in ("input", "output")
                    and schema.record_path(ref, path) is not None
                ):
                    continue
                if len(path) == 1 and schema.record_path(ref, path) is not None:
                    continue
                known = (
                    _fields_of(schema, ref, path[0])
                    if path and path[0] in ("input", "output")
                    else []
                )
                hint = f" (fields: {', '.join(known)})" if known else ""
                raise SchemaError(
                    f"policy `{p.label}`: `{ref.id}::{pred.kind}` has no field `{'.'.join(path)}`{hint}",
                    pred.line,
                    pred.col,
                    source,
                )
