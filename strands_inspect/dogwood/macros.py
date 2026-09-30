"""Macro expansion: ``def cedar`` / ``def temporal`` templates, the default library, hygiene.

Definitions are collected first (the policy's own ``def`` wins over the default library),
then every call is replaced by the body with ``?p`` parameters substituted by the call's
arguments and each ``$t`` fresh binder renamed to ``t$<offset>`` (offset = the call site's
byte position, so two call sites never share a binder and builds are reproducible).
Kind, arity and argument-shape mismatches are :class:`MacroError`.
"""

from __future__ import annotations

import dataclasses
from typing import Any, Dict, List, Optional

from . import ast as A
from .errors import MacroError
from .parser import Parser

DEFAULT_MACROS = """
// Dogwood's default macro library (dogwood-language/configuration/default_macros.dw).
def temporal count_within(?w, ?s) {
    count for ($t: Timepoint). where (formerly within ?w (?s && tp($t)))
};
def temporal sum_within(?a, ?w, ?body) {
    sum ?a for (?a: Long), ($t: Timepoint). where (formerly within ?w (?body && tp($t)))
};
def temporal count_distinct_within(?k, ?w, ?s) {
    count for (?k: String). where (formerly within ?w ?s)
};
def temporal bind(?n, ?A, ?B) {
    exists (?n: Long). (?A == ?n && ?B)
};
"""

_RESERVED = {
    "decimal", "datetime", "duration", "ip", "formerly", "previous", "since", "within", "exists",
    "tp", "count", "sum", "for", "where", "if", "then", "else", "in", "has", "like", "is",
    "permit", "forbid", "when", "unless", "principal", "action", "resource", "context", "true", "false",
}  # fmt: skip


def _parse_macros(text: str, source: str) -> List[A.MacroDef]:
    ps = Parser(text, source).parse_policy_set()
    if ps.policies:
        raise MacroError("a macro library may only contain `def` items", source=source)
    return ps.macros


def _copy(node: Any, fn) -> Any:
    """Rebuild ``node`` bottom-up; ``fn(new_node)`` may replace any rebuilt node."""
    if isinstance(node, list):
        return [_copy(x, fn) for x in node]
    if isinstance(node, tuple):
        return tuple(_copy(x, fn) for x in node)
    if dataclasses.is_dataclass(node) and not isinstance(node, type):
        kwargs = {f.name: _copy(getattr(node, f.name), fn) for f in dataclasses.fields(node)}
        return fn(type(node)(**kwargs))
    return node


def _walk(node: Any, fn) -> None:
    if isinstance(node, (list, tuple)):
        for x in node:
            _walk(x, fn)
    elif dataclasses.is_dataclass(node) and not isinstance(node, type):
        fn(node)
        for f in dataclasses.fields(node):
            _walk(getattr(node, f.name), fn)


def _flavour(m: A.MacroDef) -> str:
    if m.kind == "cedar":
        return "cedar"
    return "aggregation" if isinstance(m.body, A.Term) else "condition"


class Expander:
    def __init__(self, defs: Dict[str, A.MacroDef], source: str = ""):
        self.defs = defs
        self.source = source

    def err(self, msg: str, node: Any) -> MacroError:
        return MacroError(msg, getattr(node, "line", 0), getattr(node, "col", 0), self.source)

    def lookup(self, name: str, node: Any) -> A.MacroDef:
        m = self.defs.get(name)
        if m is None:
            raise self.err(f"unknown macro `{name}`", node)
        return m

    def check_arity(self, m: A.MacroDef, args: List[Any], node: Any) -> None:
        if len(args) != len(m.params):
            raise self.err(
                f"macro `{m.name}` expects {len(m.params)} argument(s), got {len(args)}", node
            )

    # ------------------------------------------------------------ Cedar side
    def expr(self, e: A.Expr) -> A.Expr:
        def fn(n: Any) -> Any:
            if isinstance(n, A.Call) and n.name not in ("decimal", "datetime", "duration", "ip"):
                m = self.lookup(n.name, n)
                if m.kind != "cedar":
                    raise self.err(
                        f"macro `{m.name}` is a temporal macro and cannot be called in a cedar expression position",
                        n,
                    )
                self.check_arity(m, n.args, n)
                env = dict(
                    zip(m.params, n.args)
                )  # args were rebuilt (expanded) before reaching here
                return self.instantiate_cedar(m, env, n)
            if isinstance(n, A.TemporalBlock):
                return A.TemporalBlock(self.cond(n.cond), line=n.line, col=n.col)
            if isinstance(n, A.ParamRef):
                raise self.err(
                    f"`?{n.name}` is a macro parameter and is only valid inside a macro body", n
                )
            return n

        return _copy(e, fn)

    def instantiate_cedar(self, m: A.MacroDef, env: Dict[str, A.Expr], site: Any) -> A.Expr:
        def check(n: Any) -> None:
            if isinstance(n, A.Call) and n.name not in ("decimal", "datetime", "duration", "ip"):
                raise self.err(
                    f"macro `{m.name}` calls macro `{n.name}` inside its body; macros cannot call macros",
                    site,
                )

        _walk(m.body, check)

        def fn(n: Any) -> Any:
            if isinstance(n, A.ParamRef):
                if n.name not in env:
                    raise self.err(f"macro `{m.name}` uses undeclared parameter `?{n.name}`", n)
                return env[n.name]
            return n

        return _copy(m.body, fn)

    # ------------------------------------------------------------ temporal side
    def cond(self, c: A.TCond) -> A.TCond:
        out = self._expand_temporal(c)
        if not isinstance(out, A.TCond):
            raise self.err(
                "an aggregation macro must appear as a comparison operand, not as a condition", c
            )
        return out

    def _resolve_arg(self, arg: Any) -> Any:
        """Expand a call argument to Interval | TCond | Term (an aggregation call becomes a TAgg term)."""
        if isinstance(arg, A.Interval):
            return arg
        return self._expand_temporal(arg)

    def _expand_temporal(self, node: Any) -> Any:
        def fn(n: Any) -> Any:
            if isinstance(n, (A.TCall, A.TAggCall)):
                m = self.lookup(n.name, n)
                if m.kind == "cedar":
                    raise self.err(
                        f"macro `{m.name}` is a cedar macro and cannot be called in a temporal condition position",
                        n,
                    )
                self.check_arity(m, n.args, n)
                if isinstance(n, A.TAggCall) and _flavour(m) != "aggregation":
                    raise self.err(
                        f"macro `{m.name}` is a condition macro and cannot be used where an aggregation value is expected",
                        n,
                    )
                return self.instantiate_temporal(m, list(n.args), n)
            if isinstance(n, (A.TParam, A.TParamCond, A.IntervalParam)):
                raise self.err(
                    f"`?{n.name}` is a macro parameter and is only valid inside a macro body", n
                )
            if isinstance(n, A.TBinder):
                raise self.err(
                    f"`${n.name}` is a macro fresh binder and is only valid inside a macro body", n
                )
            if isinstance(n, A.Refined):
                return self._merge_refined(n)
            return n

        return _copy(node, fn)

    def _merge_refined(self, r: A.Refined) -> A.TCond:
        base = r.base
        if isinstance(base, A.Refined):
            base = self._merge_refined(base)
        if not isinstance(base, A.Pred):
            raise self.err("field injection `{ ... }` needs a single predicate to refine", r)
        args = list(base.args)
        for block in r.blocks:
            args.extend(block)
        return A.Pred(base.namespace, base.action, base.kind, args, line=base.line, col=base.col)

    def instantiate_temporal(self, m: A.MacroDef, raw_args: List[Any], site: Any) -> Any:
        args = [self._resolve_arg(a) for a in raw_args]
        env = dict(zip(m.params, args))
        offset = getattr(site, "pos", None)
        if offset is None:
            offset = site.line * 10000 + site.col
        fresh: Dict[str, str] = {}

        def check(n: Any) -> None:
            if isinstance(n, (A.TCall, A.TAggCall)):
                raise self.err(
                    f"macro `{m.name}` calls macro `{n.name}` inside its body; macros cannot call macros",
                    site,
                )

        _walk(m.body, check)

        def binder(t: Any, what: str) -> A.Term:
            """A binder slot: `?p` needs a bare identifier argument; `$t` gets a fresh name."""
            if isinstance(t, A.TParam):
                a = env.get(t.name)
                if a is None:
                    raise self.err(f"macro `{m.name}` uses undeclared parameter `?{t.name}`", t)
                if not isinstance(a, A.TVar):
                    raise self.err(
                        f"parameter `?{t.name}` is used in a binder position, so the call-site argument must be a single identifier",
                        site,
                    )
                return A.TVar(a.name, line=t.line, col=t.col)
            if isinstance(t, A.TBinder):
                name = fresh.setdefault(t.name, f"{t.name}${offset}")
                return A.TVar(name, line=t.line, col=t.col)
            return t

        def fn(n: Any) -> Any:
            if isinstance(n, A.IntervalParam):
                a = env.get(n.name)
                if not isinstance(a, A.Interval):
                    raise self.err(
                        f"parameter `?{n.name}` is a window and needs an interval argument such as `1h`",
                        site,
                    )
                return a
            if isinstance(n, A.TParamCond):
                a = env.get(n.name)
                if a is None:
                    raise self.err(f"macro `{m.name}` uses undeclared parameter `?{n.name}`", n)
                if not isinstance(a, A.TCond):
                    raise self.err(
                        f"parameter `?{n.name}` expects a temporal condition argument", site
                    )
                return a
            if isinstance(n, A.TParam):
                a = env.get(n.name)
                if a is None:
                    raise self.err(f"macro `{m.name}` uses undeclared parameter `?{n.name}`", n)
                if not isinstance(a, A.Term):
                    raise self.err(
                        f"parameter `?{n.name}` expects a term argument, not a condition or an interval",
                        site,
                    )
                return a
            if isinstance(n, A.TBinder):
                return A.TVar(
                    fresh.setdefault(n.name, f"{n.name}${offset}"), line=n.line, col=n.col
                )
            if isinstance(n, A.Exists):
                return A.Exists(binder(n.var, "exists"), n.type, n.body, line=n.line, col=n.col)
            if isinstance(n, A.Tp):
                return A.Tp(binder(n.var, "tp"), line=n.line, col=n.col)
            if isinstance(n, A.TAgg):
                sv = binder(n.sum_var, "sum") if n.sum_var is not None else None
                return A.TAgg(
                    n.kind,
                    sv,
                    [(binder(v, "for"), t) for v, t in n.binders],
                    n.body,
                    line=n.line,
                    col=n.col,
                )
            if isinstance(n, A.Refined):
                return self._merge_refined(n)
            return n

        body = _copy(m.body, fn)
        return body

    # ------------------------------------------------------------ whole policy set
    def policy_set(self, ps: A.PolicySetAst) -> A.PolicySetAst:
        policies = []
        for p in ps.policies:
            conds = [
                A.Condition(c.kind, self.expr(c.body), line=c.line, col=c.col) for c in p.conditions
            ]
            q = dataclasses.replace(p, conditions=conds)
            policies.append(q)
        return A.PolicySetAst(policies, [], line=ps.line, col=ps.col)


def collect_macros(
    ps: A.PolicySetAst, extra_macro_source: Optional[str] = None, source: str = ""
) -> Dict[str, A.MacroDef]:
    defs: Dict[str, A.MacroDef] = {}
    for m in _parse_macros(DEFAULT_MACROS, "default_macros.dw"):
        defs[m.name] = m
    if extra_macro_source:
        for m in _parse_macros(extra_macro_source, "macros.dw"):
            defs[m.name] = m
    for m in ps.macros:
        if m.name in _RESERVED:
            raise MacroError(
                f"macro name `{m.name}` shadows a built-in or keyword", m.line, m.col, source
            )
        if m.name in {d.name for d in ps.macros if d is not m}:
            raise MacroError(f"macro `{m.name}` is defined twice", m.line, m.col, source)
        defs[m.name] = m
    return defs


def expand_policy_set(
    ast: A.PolicySetAst, extra_macro_source: Optional[str] = None, source: str = ""
) -> A.PolicySetAst:
    """Expand every macro call in ``ast``; the result has no macro definitions, calls or sigils."""
    defs = collect_macros(ast, extra_macro_source, source)
    return Expander(defs, source).policy_set(ast)
