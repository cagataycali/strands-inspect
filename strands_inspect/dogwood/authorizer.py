"""Policy sets, events and the stateful authorizer.

``Authorizer.is_authorized(event)`` observes every event (history grows) and returns a
``Response`` only for decision-kind events (``request`` by default). The decision is
deny-overrides with default deny; an evaluation error makes that policy not apply and
is reported in ``Response.errors`` (fail-closed, as the reference does).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from . import ast as A
from .cedar_eval import EntityData, EntityStore, Evaluator, Request
from .errors import DogwoodError, EvalError, ParseError
from .parser import parse_policy_set
from .schema import Schema
from .values import EntityRef, Record


@dataclass
class Event:
    """One trace event: a request/response/error (or custom kind) for one action."""

    ts: int
    action: EntityRef
    kind: str
    principal: Optional[EntityRef] = None
    resource: Optional[EntityRef] = None
    request_context: Record = field(default_factory=Record)
    logged: Record = field(default_factory=Record)
    entities: Dict[EntityRef, EntityData] = field(default_factory=dict)


@dataclass
class Response:
    decision: str  # "Allow" | "Deny"
    rules: List[str] = field(default_factory=list)  # labels (@id or policyN) of determining rules
    errors: List[str] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.decision == "Allow"

    def __str__(self) -> str:
        tail = f" [rules: {', '.join(self.rules)}]" if self.rules else ""
        return f"{self.decision}{tail}"


def _cedar_value(v: Any) -> Any:
    """Trace/JSON values -> Cedar context values (``None`` becomes the empty string, as in the reference)."""
    if v is None:
        return ""
    if isinstance(v, Record):
        return Record((k, _cedar_value(x)) for k, x in v.items())
    return v


class PolicySet:
    """A parsed, macro-expanded, slot-free Dogwood policy set ready to authorize."""

    def __init__(self, ast: A.PolicySetAst, source_text: str = "", schema: Optional[Schema] = None):
        self.ast = ast
        self.source_text = source_text
        self.schema = schema
        self.policies: List[A.Policy] = ast.policies

    @classmethod
    def parse(
        cls,
        text: str,
        schema: Optional[Schema] = None,
        source: str = "",
        macros: Optional[str] = None,
    ) -> "PolicySet":
        """Parse ``text``, expand macros (the default library plus ``macros``), reject templates."""
        from .macros import expand_policy_set

        ast = parse_policy_set(text, source)
        ast = expand_policy_set(ast, extra_macro_source=macros, source=source)
        for p in ast.policies:
            for sc in (p.principal, p.resource):
                if sc.slot is not None:
                    raise ParseError(
                        f"template slot `?{sc.slot}` is not supported: this implementation evaluates linked "
                        "policies only",
                        sc.line,
                        sc.col,
                        source,
                    )
        return cls(ast, text, schema)

    @property
    def labels(self) -> List[str]:
        return [p.label for p in self.policies]

    def temporal_blocks(self) -> List[Tuple[A.Policy, A.TemporalBlock]]:
        out: List[Tuple[A.Policy, A.TemporalBlock]] = []

        def walk(e: Any, p: A.Policy) -> None:
            if isinstance(e, A.TemporalBlock):
                out.append((p, e))
                return
            for name in ("cond", "then", "orelse", "left", "right", "operand", "in_expr"):
                sub = getattr(e, name, None)
                if isinstance(sub, A.Expr):
                    walk(sub, p)
            for name in ("args", "items"):
                for sub in getattr(e, name, None) or []:
                    if isinstance(sub, tuple):
                        sub = sub[1]
                    if isinstance(sub, A.Expr):
                        walk(sub, p)

        for p in self.policies:
            for c in p.conditions:
                walk(c.body, p)
        return out

    def actions_covered(self, policy: A.Policy) -> Optional[List[EntityRef]]:
        """The declared actions a policy's scope admits (None = every action; needs a schema for groups)."""
        sc = policy.action
        if sc.op == "any":
            return None if self.schema is None else list(self.schema.actions)
        if sc.op == "eq":
            return [sc.entity] if sc.entity else []
        refs = sc.entities or []
        if self.schema is None:
            return refs
        out: List[EntityRef] = []
        for r in refs:
            for a in self.schema.members_of(r) or [r]:
                if a not in out:
                    out.append(a)
        return out


TemporalFn = Callable[[A.Policy, A.TemporalBlock], bool]


def scope_matches(policy: A.Policy, request: Request, store: EntityStore) -> bool:
    """The coarse ``(principal, action, resource)`` filter."""
    for sc, value in ((policy.principal, request.principal), (policy.resource, request.resource)):
        if sc.op == "any":
            continue
        if sc.op == "eq":
            if value != sc.entity:
                return False
        elif sc.op == "in":
            if sc.entity is None or not store.is_in(value, sc.entity):
                return False
        elif sc.op in ("is", "is_in"):
            if value.type != sc.entity_type:
                return False
            if sc.op == "is_in" and (sc.entity is None or not store.is_in(value, sc.entity)):
                return False
    sc = policy.action
    if sc.op == "eq":
        return request.action == sc.entity
    if sc.op == "in":
        return any(store.is_in(request.action, r) for r in sc.entities or [])
    return True


def evaluate_policy(
    policy: A.Policy,
    request: Request,
    store: EntityStore,
    temporal: Optional[TemporalFn] = None,
) -> Tuple[bool, Optional[str]]:
    """Return ``(applies, error)``. An evaluation error means the policy does not apply."""
    if not scope_matches(policy, request, store):
        return False, None
    tfn = (lambda block: temporal(policy, block)) if temporal is not None else None
    ev = Evaluator(request, store, tfn)
    try:
        for cond in policy.conditions:
            held = ev.eval_bool(cond.body, f"`{cond.kind}` body")
            if cond.kind == "when" and not held:
                return False, None
            if cond.kind == "unless" and held:
                return False, None
    except EvalError as exc:
        return False, f"policy `{policy.label}`: {exc.message}"
    return True, None


def decide(
    policies: Sequence[A.Policy],
    request: Request,
    store: EntityStore,
    temporal: Optional[TemporalFn] = None,
) -> Response:
    """Deny-overrides, default deny. ``rules`` are the labels of the determining policies."""
    permits: List[str] = []
    forbids: List[str] = []
    errors: List[str] = []
    for p in policies:
        applies, err = evaluate_policy(p, request, store, temporal)
        if err:
            errors.append(err)
        if applies:
            (forbids if p.effect == "forbid" else permits).append(p.label)
    if forbids:
        return Response("Deny", forbids, errors)
    if permits:
        return Response("Allow", permits, errors)
    return Response("Deny", [], errors)


class Authorizer:
    """Stateful authorizer: feed events in order; decision-kind events yield a Response."""

    def __init__(
        self,
        policy_set: PolicySet,
        schema: Optional[Schema] = None,
        event_schema: Any = None,
        decision_kinds: Optional[Sequence[str]] = None,
    ):
        from .event_schema import DEFAULT_EVENT_SCHEMA

        self.policy_set = policy_set
        self.schema = schema if schema is not None else policy_set.schema
        self.event_schema = event_schema if event_schema is not None else DEFAULT_EVENT_SCHEMA
        self.decision_kinds = set(
            decision_kinds if decision_kinds is not None else self.event_schema.decision_kinds
        )
        self.history: List[Event] = []
        self._engine: Any = None
        if policy_set.temporal_blocks():
            from .temporal_eval import TemporalEngine

            self._engine = TemporalEngine(policy_set, self.schema, self.event_schema)

    def observe(self, event: Event) -> None:
        self.history.append(event)
        if self._engine is not None:
            self._engine.observe(event)

    def is_authorized(self, event: Event) -> Optional[Response]:
        self.observe(event)
        if event.kind not in self.decision_kinds:
            return None
        return self.decide(event)

    def decide(self, event: Event) -> Response:
        if event.principal is None:
            return Response("Deny", [], ["request has no principal"])
        if event.resource is None:
            return Response("Deny", [], ["request has no resource"])
        context = Record((k, _cedar_value(v)) for k, v in event.request_context.items())
        request = Request(event.principal, event.action, event.resource, context)
        store = EntityStore(event.entities, self.schema)
        temporal: Optional[TemporalFn] = None
        if self._engine is not None:
            engine = self._engine
            temporal = lambda policy, block: engine.evaluate(policy, block, event, request, store)
        return decide(self.policy_set.policies, request, store, temporal)

    def authorize(
        self, request: Request, entities: Optional[Dict[EntityRef, EntityData]] = None
    ) -> Response:
        """Stateless single decision (no history; temporal blocks are evaluation errors)."""
        return decide(self.policy_set.policies, request, EntityStore(entities, self.schema))


def replay(
    policy_text: str,
    trace_text: str,
    schema: Optional[Schema] = None,
    macros: Optional[str] = None,
    event_schema: Any = None,
) -> str:
    """Replay a ``.log`` trace; return the corpus verdict stream (``@ts (time point i): true|false``)."""
    from .trace import parse_trace

    ps = PolicySet.parse(policy_text, schema=schema, macros=macros)
    auth = Authorizer(ps, schema, event_schema)
    lines: List[str] = []
    for i, ev in enumerate(parse_trace(trace_text)):
        r = auth.is_authorized(ev)
        if r is not None:
            lines.append(f"@{ev.ts} (time point {i}): {'true' if r.allowed else 'false'}")
    return "\n".join(lines)
