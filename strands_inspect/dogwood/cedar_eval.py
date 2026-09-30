"""Cedar expression evaluation.

Evaluates the Cedar tower of :mod:`ast` against a request (principal, action, resource,
context), an entity store (attributes, parents, tags) and the schema's action
hierarchy. A type error or a missing attribute raises :class:`EvalError`; the
authorizer turns that into "this policy does not apply" (fail-closed).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional, Set

from . import ast as A
from .errors import EvalError
from .schema import Schema
from .values import (
    DateTime,
    Decimal,
    Duration,
    EntityRef,
    IpAddr,
    Record,
    SetValue,
    check_long,
    render,
    type_name,
    values_equal,
)


@dataclass(frozen=True)
class Request:
    principal: EntityRef
    action: EntityRef
    resource: EntityRef
    context: Record = field(default_factory=Record)


@dataclass
class EntityData:
    attrs: Record = field(default_factory=Record)
    parents: Set[EntityRef] = field(default_factory=set)
    tags: Record = field(default_factory=Record)


class EntityStore:
    """Entities known to one authorization: caller-supplied data plus the schema's action groups."""

    def __init__(
        self,
        entities: Optional[Dict[EntityRef, EntityData]] = None,
        schema: Optional[Schema] = None,
    ):
        self.entities: Dict[EntityRef, EntityData] = dict(entities or {})
        self.schema = schema

    def data(self, ref: EntityRef) -> EntityData:
        return self.entities.get(ref) or EntityData()

    def ancestors(self, ref: EntityRef) -> Set[EntityRef]:
        seen: Set[EntityRef] = set()
        todo = [ref]
        while todo:
            cur = todo.pop()
            for p in self.data(cur).parents:
                if p not in seen:
                    seen.add(p)
                    todo.append(p)
        if self.schema is not None:
            seen |= self.schema.action_ancestors(ref)
        return seen

    def is_in(self, a: EntityRef, b: EntityRef) -> bool:
        return a == b or b in self.ancestors(a)


def like_regex(pattern: str) -> "re.Pattern[str]":
    """Compile a Cedar ``like`` pattern: ``*`` is a wildcard, ``\\*`` a literal star."""
    out = []
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\" and i + 1 < len(pattern) and pattern[i + 1] == "*":
            out.append(re.escape("*"))
            i += 2
            continue
        out.append(".*" if ch == "*" else re.escape(ch))
        i += 1
    return re.compile("".join(out), re.DOTALL)


def _bool(v: Any, what: str) -> bool:
    if not isinstance(v, bool):
        raise EvalError(f"{what} must be Bool, got {type_name(v)}")
    return v


def _long(v: Any, what: str) -> int:
    if isinstance(v, bool) or not isinstance(v, int):
        raise EvalError(f"{what} must be Long, got {type_name(v)}")
    return v


_EXT_CTORS: Dict[str, Callable[[str], Any]] = {
    "decimal": Decimal.parse,
    "datetime": DateTime.parse,
    "duration": Duration.parse,
    "ip": IpAddr.parse,
}


class Evaluator:
    """Evaluate Cedar expressions for one request.

    ``temporal`` is called for every ``temporal { ... }`` block; the authorizer supplies
    the temporal engine's verdict. Without one, a temporal block is an evaluation error.
    """

    def __init__(
        self,
        request: Request,
        store: Optional[EntityStore] = None,
        temporal: Optional[Callable[[A.TemporalBlock], bool]] = None,
    ):
        self.request = request
        self.store = store or EntityStore()
        self.temporal = temporal

    # ------------------------------------------------------------ dispatch
    def eval(self, e: A.Expr) -> Any:
        m = getattr(self, "_ev_" + type(e).__name__, None)
        if m is None:
            raise EvalError(f"cannot evaluate {type(e).__name__}", e.line, e.col)
        return m(e)

    def eval_bool(self, e: A.Expr, what: str = "condition") -> bool:
        return _bool(self.eval(e), what)

    # ------------------------------------------------------------ leaves
    def _ev_Lit(self, e: A.Lit) -> Any:
        return e.value

    def _ev_EntityLit(self, e: A.EntityLit) -> Any:
        return e.ref

    def _ev_Var(self, e: A.Var) -> Any:
        return getattr(self.request, e.name)

    def _ev_Slot(self, e: A.Slot) -> Any:
        raise EvalError(f"template slot `?{e.name}` is not linked", e.line, e.col)

    def _ev_ParamRef(self, e: A.ParamRef) -> Any:
        raise EvalError(f"macro parameter `?{e.name}` was not expanded", e.line, e.col)

    def _ev_TemporalBlock(self, e: A.TemporalBlock) -> Any:
        if self.temporal is None:
            raise EvalError(
                "temporal { ... } needs a temporal engine (an event history)", e.line, e.col
            )
        return self.temporal(e)

    # ------------------------------------------------------------ logic
    def _ev_If(self, e: A.If) -> Any:
        return (
            self.eval(e.then) if self.eval_bool(e.cond, "`if` condition") else self.eval(e.orelse)
        )

    def _ev_Or(self, e: A.Or) -> Any:
        if self.eval_bool(e.left, "`||` operand"):
            return True
        return self.eval_bool(e.right, "`||` operand")

    def _ev_And(self, e: A.And) -> Any:
        if not self.eval_bool(e.left, "`&&` operand"):
            return False
        return self.eval_bool(e.right, "`&&` operand")

    def _ev_Not(self, e: A.Not) -> Any:
        return not self.eval_bool(e.operand, "`!` operand")

    def _ev_Neg(self, e: A.Neg) -> Any:
        return check_long(-_long(self.eval(e.operand), "`-` operand"), "negation")

    # ------------------------------------------------------------ binary operators
    def _ev_BinOp(self, e: A.BinOp) -> Any:
        left = self.eval(e.left)
        right = self.eval(e.right)
        op = e.op
        if op == "==":
            return values_equal(left, right)
        if op == "!=":
            return not values_equal(left, right)
        if op == "in":
            return self._in(left, right, e)
        if op in ("+", "-", "*"):
            a, b = _long(left, f"`{op}` operand"), _long(right, f"`{op}` operand")
            r = a + b if op == "+" else a - b if op == "-" else a * b
            return check_long(r, f"`{op}`")
        # ordering
        if isinstance(left, bool) or isinstance(right, bool):
            raise EvalError(f"`{op}` is not defined on Bool", e.line, e.col)
        if isinstance(left, int) and isinstance(right, int):
            a, b = left, right
        elif isinstance(left, DateTime) and isinstance(right, DateTime):
            a, b = left.ms, right.ms
        elif isinstance(left, Duration) and isinstance(right, Duration):
            a, b = left.ms, right.ms
        else:
            raise EvalError(
                f"`{op}` needs two Longs (or two datetimes / durations), got {type_name(left)} and {type_name(right)}",
                e.line,
                e.col,
            )
        return {"<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}[op]

    def _in(self, left: Any, right: Any, e: A.Expr) -> bool:
        if not isinstance(left, EntityRef):
            raise EvalError(
                f"`in` needs an entity on its left, got {type_name(left)}", e.line, e.col
            )
        if isinstance(right, EntityRef):
            return self.store.is_in(left, right)
        if isinstance(right, SetValue):
            for item in right:
                if not isinstance(item, EntityRef):
                    raise EvalError(
                        f"`in` needs a set of entities, got {type_name(item)}", e.line, e.col
                    )
            return any(self.store.is_in(left, item) for item in right)
        raise EvalError(
            f"`in` needs an entity or a set of entities on its right, got {type_name(right)}",
            e.line,
            e.col,
        )

    # ------------------------------------------------------------ has / like / is
    def _ev_Has(self, e: A.Has) -> Any:
        cur = self.eval(e.operand)
        for i, attr in enumerate(e.attrs):
            if isinstance(cur, Record):
                if attr not in cur:
                    return False
                cur = cur[attr]
            elif isinstance(cur, EntityRef):
                attrs = self.store.data(cur).attrs
                if attr not in attrs:
                    return False
                cur = attrs[attr]
            else:
                if i == 0:
                    raise EvalError(
                        f"`has` needs a record or an entity, got {type_name(cur)}", e.line, e.col
                    )
                return False
        return True

    def _ev_Like(self, e: A.Like) -> Any:
        s = self.eval(e.operand)
        if not isinstance(s, str):
            raise EvalError(f"`like` needs a String, got {type_name(s)}", e.line, e.col)
        return like_regex(e.pattern).fullmatch(s) is not None

    def _ev_Is(self, e: A.Is) -> Any:
        v = self.eval(e.operand)
        if not isinstance(v, EntityRef):
            raise EvalError(f"`is` needs an entity, got {type_name(v)}", e.line, e.col)
        if v.type != e.entity_type:
            return False
        if e.in_expr is not None:
            return self._in(v, self.eval(e.in_expr), e)
        return True

    # ------------------------------------------------------------ access, calls, literals
    def _ev_GetAttr(self, e: A.GetAttr) -> Any:
        v = self.eval(e.operand)
        if isinstance(v, Record):
            if e.attr not in v:
                raise EvalError(f"record does not have attribute `{e.attr}`", e.line, e.col)
            return v[e.attr]
        if isinstance(v, EntityRef):
            attrs = self.store.data(v).attrs
            if e.attr not in attrs:
                raise EvalError(
                    f"entity `{render(v)}` does not have attribute `{e.attr}`", e.line, e.col
                )
            return attrs[e.attr]
        raise EvalError(
            f"attribute access `.{e.attr}` needs a record or an entity, got {type_name(v)}",
            e.line,
            e.col,
        )

    def _ev_Call(self, e: A.Call) -> Any:
        ctor = _EXT_CTORS.get(e.name)
        if ctor is None:
            raise EvalError(
                f"`{e.name}(...)` is not an extension function (unexpanded macro?)", e.line, e.col
            )
        if len(e.args) != 1:
            raise EvalError(f"`{e.name}` takes exactly one string argument", e.line, e.col)
        arg = self.eval(e.args[0])
        if not isinstance(arg, str):
            raise EvalError(
                f"`{e.name}` takes a String argument, got {type_name(arg)}", e.line, e.col
            )
        try:
            return ctor(arg)
        except EvalError as exc:
            raise EvalError(exc.message, e.line, e.col) from None

    def _ev_SetLit(self, e: A.SetLit) -> Any:
        return SetValue(self.eval(x) for x in e.items)

    def _ev_RecordLit(self, e: A.RecordLit) -> Any:
        return Record((k, self.eval(v)) for k, v in e.items)

    def _ev_MethodCall(self, e: A.MethodCall) -> Any:
        recv = self.eval(e.operand)
        args = [self.eval(a) for a in e.args]
        name = e.name

        def need(t: type, what: str) -> None:
            if not isinstance(recv, t):
                raise EvalError(f"`.{name}()` needs {what}, got {type_name(recv)}", e.line, e.col)

        def arg(t: type, what: str) -> Any:
            if not isinstance(args[0], t) or isinstance(args[0], bool) and t is int:
                raise EvalError(
                    f"`.{name}()` argument must be {what}, got {type_name(args[0])}", e.line, e.col
                )
            return args[0]

        if name == "isEmpty":
            need(SetValue, "a Set")
            return len(recv) == 0
        if name == "contains":
            need(SetValue, "a Set")
            return recv.contains(args[0])
        if name in ("containsAll", "containsAny"):
            need(SetValue, "a Set")
            other = arg(SetValue, "a Set")
            if name == "containsAll":
                return all(recv.contains(x) for x in other)
            return any(recv.contains(x) for x in other)
        if name in ("hasTag", "getTag"):
            need(EntityRef, "an entity")
            key = arg(str, "a String")
            tags = self.store.data(recv).tags
            if name == "hasTag":
                return key in tags
            if key not in tags:
                raise EvalError(f"entity `{render(recv)}` has no tag `{key}`", e.line, e.col)
            return tags[key]
        if name in ("isIpv4", "isIpv6", "isLoopback", "isMulticast", "isInRange"):
            need(IpAddr, "an ipaddr")
            if name == "isInRange":
                return recv.in_range(arg(IpAddr, "an ipaddr"))
            return {
                "isIpv4": recv.is_ipv4,
                "isIpv6": recv.is_ipv6,
                "isLoopback": recv.is_loopback,
                "isMulticast": recv.is_multicast,
            }[name]
        if name in ("toDate", "toTime", "offset", "durationSince"):
            need(DateTime, "a datetime")
            if name == "toDate":
                return recv.to_date()
            if name == "toTime":
                return recv.to_time()
            if name == "offset":
                return DateTime(
                    check_long(recv.ms + arg(Duration, "a duration").ms, "datetime offset")
                )
            return Duration(check_long(recv.ms - arg(DateTime, "a datetime").ms, "durationSince"))
        if name in ("toMilliseconds", "toSeconds", "toMinutes", "toHours", "toDays"):
            need(Duration, "a duration")
            div = {
                "toMilliseconds": 1,
                "toSeconds": 1000,
                "toMinutes": 60_000,
                "toHours": 3_600_000,
                "toDays": 86_400_000,
            }[name]
            return int(recv.ms / div)  # truncates toward zero like Cedar
        if name in ("lessThan", "lessThanOrEqual", "greaterThan", "greaterThanOrEqual"):
            need(Decimal, "a decimal")
            other = arg(Decimal, "a decimal")
            a, b = recv.value, other.value
            return {
                "lessThan": a < b,
                "lessThanOrEqual": a <= b,
                "greaterThan": a > b,
                "greaterThanOrEqual": a >= b,
            }[name]
        raise EvalError(f"unknown method `{name}`", e.line, e.col)
