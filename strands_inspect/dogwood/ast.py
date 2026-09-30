"""Abstract syntax of a Dogwood policy set.

Three families: the Cedar expression tower (``Expr`` subclasses), the temporal
sub-language (``TCond`` conditions and ``Term`` values) and the top-level items
(``Policy``, ``MacroDef``). Every node carries ``line``/``col`` for diagnostics.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List, Optional, Tuple

from .values import EntityRef


@dataclass
class Node:
    line: int = field(default=0, kw_only=True)
    col: int = field(default=0, kw_only=True)


# ============================================================ Cedar expressions
class Expr(Node):
    """Base of the Cedar expression tower."""


@dataclass
class Lit(Expr):
    value: Any  # bool | int | str


@dataclass
class EntityLit(Expr):
    ref: EntityRef


@dataclass
class Var(Expr):
    name: str  # principal | action | resource | context


@dataclass
class Slot(Expr):
    name: str  # principal | resource  (?principal / ?resource)


@dataclass
class ParamRef(Expr):
    """``?p`` inside a ``def cedar`` body; replaced at expansion."""

    name: str


@dataclass
class If(Expr):
    cond: Expr
    then: Expr
    orelse: Expr


@dataclass
class Or(Expr):
    left: Expr
    right: Expr


@dataclass
class And(Expr):
    left: Expr
    right: Expr


@dataclass
class Not(Expr):
    operand: Expr


@dataclass
class Neg(Expr):
    operand: Expr


@dataclass
class BinOp(Expr):
    op: str  # == != < <= > >= in + - *
    left: Expr
    right: Expr


@dataclass
class Has(Expr):
    operand: Expr
    attrs: List[str]  # dotted path, e.g. ["a", "b"]


@dataclass
class Like(Expr):
    operand: Expr
    pattern: str  # raw pattern body with `\*` kept escaped


@dataclass
class Is(Expr):
    operand: Expr
    entity_type: str
    in_expr: Optional[Expr] = None


@dataclass
class GetAttr(Expr):
    operand: Expr
    attr: str


@dataclass
class Call(Expr):
    """``name(args)``: an extension constructor (decimal/datetime/duration/ip) or a macro."""

    name: str
    args: List[Expr]


@dataclass
class MethodCall(Expr):
    operand: Expr
    name: str
    args: List[Expr]


@dataclass
class SetLit(Expr):
    items: List[Expr]


@dataclass
class RecordLit(Expr):
    items: List[Tuple[str, Expr]]


@dataclass
class TemporalBlock(Expr):
    """``temporal { ... }`` used as a primary or as a whole clause body."""

    cond: "TCond"


# ============================================================ temporal terms
class Term(Node):
    """Base of temporal terms (the values field patterns and comparisons range over)."""


@dataclass
class TLit(Term):
    value: Any  # int | str | bool | Decimal | EntityRef


@dataclass
class TContextField(Term):
    path: List[str]  # context.a.b -> ["a", "b"]


@dataclass
class TScopeField(Term):
    base: str  # principal | resource
    path: List[str]


@dataclass
class TVar(Term):
    name: str


@dataclass
class TWildcard(Term):
    pass


@dataclass
class TArray(Term):
    items: List[Term]


@dataclass
class TParam(Term):
    name: str  # ?p in a def temporal body


@dataclass
class TBinder(Term):
    name: str  # $t in a def temporal body


@dataclass
class TAgg(Term):
    kind: str  # count | sum
    sum_var: Optional[Term]  # TVar/TParam/TBinder for sum
    binders: List[Tuple[Term, str]]  # (variable, type)
    body: "TCond"


@dataclass
class TAggCall(Term):
    """A macro call in aggregation-value position (resolved at expansion)."""

    name: str
    args: List[Any]  # Interval | TCond | Term


# ============================================================ temporal conditions
@dataclass
class Interval(Node):
    seconds: int
    text: str = ""


@dataclass
class IntervalParam(Node):
    name: str  # within ?w


class TCond(Node):
    """Base of temporal conditions."""


@dataclass
class Pred(TCond):
    namespace: List[str]  # ["Drupe", "Action"]
    action: str
    kind: str
    args: List[Tuple[List[str], Term]]  # (field path, term)


@dataclass
class Refined(TCond):
    """``base{ a: 1 }{ b: 2 }`` -- injections merged onto a predicate at expansion."""

    base: TCond  # Pred or TParamCond
    blocks: List[List[Tuple[List[str], Term]]]


@dataclass
class TParamCond(TCond):
    name: str  # ?s used as a whole condition


@dataclass
class Comparison(TCond):
    op: str  # <= >= == < >
    left: Term
    right: Term


@dataclass
class Formerly(TCond):
    window: Any  # Interval | IntervalParam
    body: TCond


@dataclass
class Previous(TCond):
    window: Any
    body: TCond


@dataclass
class Since(TCond):
    left: TCond
    window: Any
    right: TCond


@dataclass
class TNot(TCond):
    operand: TCond


@dataclass
class TAnd(TCond):
    left: TCond
    right: TCond


@dataclass
class Exists(TCond):
    var: Term  # TVar/TParam/TBinder
    type: str
    body: TCond


@dataclass
class Tp(TCond):
    var: Term


@dataclass
class TCall(TCond):
    name: str
    args: List[Any]  # Interval | TCond | Term


# ============================================================ top-level items
@dataclass
class ScopeConstraint(Node):
    """One slot of the scope triple."""

    var: str  # principal | action | resource
    op: str = "any"  # any | eq | in | is | is_in
    entity: Optional[EntityRef] = None
    entities: Optional[List[EntityRef]] = None  # action in [..]
    slot: Optional[str] = None  # ?principal / ?resource
    entity_type: Optional[str] = None  # is Type


@dataclass
class Condition(Node):
    kind: str  # when | unless
    body: Expr


@dataclass
class Policy(Node):
    effect: str  # permit | forbid
    annotations: List[Tuple[str, Optional[str]]]
    principal: ScopeConstraint
    action: ScopeConstraint
    resource: ScopeConstraint
    conditions: List[Condition]
    index: int = 0

    @property
    def id(self) -> Optional[str]:
        for k, v in self.annotations:
            if k == "id":
                return v
        return None

    @property
    def label(self) -> str:
        return self.id if self.id is not None else f"policy{self.index}"


@dataclass
class MacroDef(Node):
    kind: str  # cedar | temporal
    name: str
    params: List[str]
    body: Any  # Expr | TCond | Term(TAgg)


@dataclass
class PolicySetAst(Node):
    policies: List[Policy]
    macros: List[MacroDef]
