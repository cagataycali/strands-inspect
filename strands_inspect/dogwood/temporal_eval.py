"""Temporal engine: evaluates ``temporal { ... }`` blocks over the event history.

Semantics follow dogwood-docs/guide/04-temporal-expressions.md "Evaluation semantics":
a condition is evaluated relationally (a set of binding rows; true = non-empty) at the
decision timepoint over the history slice ``0..=i``. With the default event schema the
``callerPrincipal`` pin is universal and symmetric, so evaluation is KEY-LOCAL: the slice
holds only the events whose ``callerPrincipal`` equals the current request's principal.
Windows are closed; ``previous`` is the key's previous event; ``since`` needs an anchor in
the window with the left holding at every later step; ``==`` with one unbound variable
binds it; ordering needs two Longs; count/sum project onto the ``for`` domain and dedupe.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import ast as A
from .cedar_eval import EntityStore, Request
from .errors import EvalError
from .values import I64_MAX, I64_MIN, EntityRef, Record, hash_key, values_equal

Row = Dict[str, Any]
_UNRESOLVED = object()


def _clamp(n: int) -> int:
    return max(I64_MIN, min(I64_MAX, n))


def _dedupe(rows: List[Row]) -> List[Row]:
    seen = set()
    out: List[Row] = []
    for r in rows:
        key = tuple(sorted((k, hash_key(v)) for k, v in r.items()))
        if key not in seen:
            seen.add(key)
            out.append(r)
    return out


def event_key(ev: Any) -> Any:
    """The key-local partition key of an event: its ``callerPrincipal`` (falls back to the scope principal)."""
    cp = ev.logged.get("callerPrincipal") if isinstance(ev.logged, Record) else None
    if isinstance(cp, EntityRef):
        return cp
    return ev.principal


def field_lookup(record: Record, path: Sequence[str]) -> Any:
    cur: Any = record
    for seg in path:
        if not isinstance(cur, Record) or seg not in cur:
            return _UNRESOLVED
        cur = cur[seg]
    return cur


class TemporalEngine:
    """Owns the observed history and evaluates temporal blocks for the authorizer."""

    def __init__(self, policy_set: Any, schema: Any = None, key_local: bool = True):
        self.policy_set = policy_set
        self.schema = schema
        self.key_local = key_local
        self.history: List[Any] = []

    def observe(self, event: Any) -> None:
        self.history.append(event)

    # ------------------------------------------------------------ entry point
    def evaluate(
        self,
        policy: A.Policy,
        block: A.TemporalBlock,
        event: Any,
        request: Request,
        store: EntityStore,
    ) -> bool:
        slice_ = self._slice(event)
        ctx = _Ctx(slice_, request, store, self.history)
        rows = ctx.cond(block.cond, {}, len(slice_) - 1)
        return bool(rows)

    def _slice(self, event: Any) -> List[Any]:
        if not self.key_local:
            return list(self.history)
        key = event_key(event)
        return [ev for ev in self.history if event_key(ev) == key]


class _Ctx:
    """One evaluation: the slice, the current request, and the row-set semantics."""

    def __init__(self, slice_: List[Any], request: Request, store: EntityStore, history: List[Any]):
        self.events = slice_
        self.request = request
        self.store = store
        self.index_of = {id(ev): idx for idx, ev in enumerate(history)}  # global timepoint index

    def tp(self, j: int) -> int:
        return self.index_of[id(self.events[j])]

    def ts(self, j: int) -> int:
        return self.events[j].ts

    def in_window(self, j: int, k: int, window: Any) -> bool:
        if not isinstance(window, A.Interval):
            raise EvalError(
                "unexpanded window parameter in a temporal operator", getattr(window, "line", 0)
            )
        return 0 <= self.ts(j) - self.ts(k) <= window.seconds

    # ------------------------------------------------------------ terms
    def term(self, t: A.Term, env: Row, j: int) -> Any:
        """Resolve a term to a value, or _UNRESOLVED (unbound variable, wildcard, missing field)."""
        if isinstance(t, A.TLit):
            return t.value
        if isinstance(t, A.TVar):
            return env.get(t.name, _UNRESOLVED)
        if isinstance(t, A.TWildcard):
            return _UNRESOLVED
        if isinstance(t, A.TContextField):
            return field_lookup(self.request.context, t.path)
        if isinstance(t, A.TScopeField):
            ent = self.request.principal if t.base == "principal" else self.request.resource
            if not t.path:
                return ent
            if t.path == ["id"]:
                return ent.id
            if t.path == ["type"]:
                return ent.type
            return field_lookup(self.store.data(ent).attrs, t.path)
        if isinstance(t, A.TArray):
            items = [self.term(x, env, j) for x in t.items]
            if any(v is _UNRESOLVED for v in items):
                return _UNRESOLVED
            from .values import SetValue

            return SetValue(items)
        if isinstance(t, A.TAgg):
            return self.aggregate(t, env, j)
        if isinstance(t, (A.TParam, A.TBinder, A.TAggCall)):
            raise EvalError(
                "unexpanded macro construct reached the temporal evaluator", t.line, t.col
            )
        raise EvalError(f"cannot resolve term {type(t).__name__}", t.line, t.col)

    def aggregate(self, agg: A.TAgg, env: Row, j: int) -> int:
        names = [self._binder_name(v) for v, _ in agg.binders]
        inner = {k: v for k, v in env.items() if k not in names}  # `for` binders shadow
        rows = self.cond(agg.body, inner, j)
        projected: List[Tuple[Any, ...]] = []
        seen = set()
        for r in rows:
            if any(n not in r for n in names):
                continue
            tup = tuple(r[n] for n in names)
            key = tuple(hash_key(v) for v in tup)
            if key not in seen:
                seen.add(key)
                projected.append(tup)
        if agg.kind == "count":
            return _clamp(len(projected))
        col = names.index(self._binder_name(agg.sum_var))
        total = 0
        for tup in projected:
            v = tup[col]
            if isinstance(v, bool) or not isinstance(v, int):
                raise EvalError("`sum` over a non-Long column", agg.line, agg.col)
            total += v
        return _clamp(total)

    @staticmethod
    def _binder_name(t: Any) -> str:
        if isinstance(t, A.TVar):
            return t.name
        raise EvalError(
            "unexpanded macro binder reached the temporal evaluator", getattr(t, "line", 0)
        )

    # ------------------------------------------------------------ conditions
    def cond(self, c: A.TCond, env: Row, j: int) -> List[Row]:
        m = getattr(self, "_c_" + type(c).__name__, None)
        if m is None:
            raise EvalError(f"cannot evaluate temporal {type(c).__name__}", c.line, c.col)
        return m(c, env, j)

    def holds(self, c: A.TCond, env: Row, j: int) -> bool:
        return bool(self.cond(c, env, j))

    def _c_TAnd(self, c: A.TAnd, env: Row, j: int) -> List[Row]:
        out: List[Row] = []
        for r in self.cond(c.left, env, j):
            out.extend(self.cond(c.right, r, j))
        return _dedupe(out)

    def _c_TNot(self, c: A.TNot, env: Row, j: int) -> List[Row]:
        return [] if self.holds(c.operand, env, j) else [env]

    def _c_Formerly(self, c: A.Formerly, env: Row, j: int) -> List[Row]:
        out: List[Row] = []
        for k in range(j, -1, -1):
            if not self.in_window(j, k, c.window):
                break
            out.extend(self.cond(c.body, env, k))
        return _dedupe(out)

    def _c_Previous(self, c: A.Previous, env: Row, j: int) -> List[Row]:
        if j == 0 or not self.in_window(j, j - 1, c.window):
            return []
        return self.cond(c.body, env, j - 1)

    def _c_Since(self, c: A.Since, env: Row, j: int) -> List[Row]:
        out: List[Row] = []
        for k in range(j, -1, -1):
            if not self.in_window(j, k, c.window):
                break
            for r in self.cond(c.right, env, k):
                if all(self.holds(c.left, r, m) for m in range(k + 1, j + 1)):
                    out.append(r)
        return _dedupe(out)

    def _c_Exists(self, c: A.Exists, env: Row, j: int) -> List[Row]:
        name = self._binder_name(c.var)
        inner = {k: v for k, v in env.items() if k != name}
        rows = self.cond(c.body, inner, j)
        out = []
        for r in rows:
            r2 = {k: v for k, v in r.items() if k != name}
            if name in env:
                r2[name] = env[name]
            out.append(r2)
        return _dedupe(out)

    def _c_Tp(self, c: A.Tp, env: Row, j: int) -> List[Row]:
        name = self._binder_name(c.var)
        t = self.tp(j)
        if name in env:
            return [env] if env[name] == t else []
        return [{**env, name: t}]

    def _c_Comparison(self, c: A.Comparison, env: Row, j: int) -> List[Row]:
        lv = self.term(c.left, env, j)
        rv = self.term(c.right, env, j)
        if c.op == "==":
            lu = isinstance(c.left, A.TVar) and lv is _UNRESOLVED
            ru = isinstance(c.right, A.TVar) and rv is _UNRESOLVED
            if lu and not ru and rv is not _UNRESOLVED:
                return [{**env, c.left.name: rv}]
            if ru and not lu and lv is not _UNRESOLVED:
                return [{**env, c.right.name: lv}]
        if lv is _UNRESOLVED or rv is _UNRESOLVED:
            return []
        if c.op == "==":
            ok = values_equal(lv, rv)
        elif c.op == "!=":
            ok = not values_equal(lv, rv)
        else:
            if (
                isinstance(lv, bool)
                or isinstance(rv, bool)
                or not (isinstance(lv, int) and isinstance(rv, int))
            ):
                return []
            ok = {"<": lv < rv, "<=": lv <= rv, ">": lv > rv, ">=": lv >= rv}[c.op]
        return [env] if ok else []

    def _c_Pred(self, c: A.Pred, env: Row, j: int) -> List[Row]:
        ev = self.events[j]
        if (
            ev.kind != c.kind
            or ev.action.id != c.action
            or ev.action.type != "::".join(c.namespace)
        ):
            return []
        row = dict(env)
        for path, term in c.args:
            fv = field_lookup(ev.logged, path)
            if fv is _UNRESOLVED:
                return []
            if isinstance(term, A.TWildcard):
                continue
            if isinstance(term, A.TVar):
                if term.name in row:
                    if not values_equal(row[term.name], fv):
                        return []
                else:
                    row[term.name] = fv
                continue
            tv = self.term(term, row, j)
            if tv is _UNRESOLVED or not values_equal(tv, fv):
                return []
        return [row]

    def _c_Refined(self, c: A.Refined, env: Row, j: int) -> List[Row]:
        if not isinstance(c.base, A.Pred):
            raise EvalError("refinement of a non-predicate reached the evaluator", c.line, c.col)
        merged = A.Pred(
            c.base.namespace, c.base.action, c.base.kind, list(c.base.args), line=c.line, col=c.col
        )
        for block in c.blocks:
            merged.args.extend(block)
        return self._c_Pred(merged, env, j)

    def _c_TCall(self, c: A.TCall, env: Row, j: int) -> List[Row]:
        raise EvalError(
            f"unexpanded macro call `{c.name}` reached the temporal evaluator", c.line, c.col
        )

    def _c_TParamCond(self, c: A.TParamCond, env: Row, j: int) -> List[Row]:
        raise EvalError(
            f"unexpanded macro parameter `?{c.name}` reached the temporal evaluator", c.line, c.col
        )
