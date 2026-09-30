"""Schema reader, Cedar evaluator and (non-temporal) authorizer tests."""

import pytest

from strands_inspect.dogwood.authorizer import Authorizer, Event, PolicySet, Response, replay
from strands_inspect.dogwood.cedar_eval import (
    EntityData,
    EntityStore,
    Evaluator,
    Request,
    like_regex,
)
from strands_inspect.dogwood.errors import EvalError, ParseError, SchemaError, TraceError
from strands_inspect.dogwood.parser import parse_expression
from strands_inspect.dogwood.schema import parse_schema
from strands_inspect.dogwood.trace import parse_trace, parse_value
from strands_inspect.dogwood.values import DateTime, Decimal, Duration, EntityRef, Record, SetValue

SCHEMA = """
namespace Drupe {
  type LoginInput = { user: String, tries?: Long };
  type SystemContext = { now: datetime };
  entity Gateway;
  entity OAuthUser = { id: String } tags String;
  entity Role enum ["reader", "admin"];
  entity Team in [Org];
  entity Org;
  action "Mcp";
  action "CallTool" in [Action::"Mcp"];
  action "Login", "Read" in [Action::"CallTool"] appliesTo {
    principal: [OAuthUser],
    resource: Gateway,
    context: { input: LoginInput, output?: { result: Bool }, system: SystemContext, tags: Set<String> }
  };
}
"""

U = EntityRef("Drupe::OAuthUser", "alice")
GW = EntityRef("Drupe::Gateway", "gw1")


def act(name):
    return EntityRef("Drupe::Action", name)


def test_schema_reader_groups_types_enums_and_paths():
    s = parse_schema(SCHEMA)
    assert s.action_in(act("Login"), act("Mcp")) and s.action_in(act("Read"), act("CallTool"))
    assert not s.action_in(act("Mcp"), act("Login"))
    assert sorted(a.id for a in s.members_of(act("CallTool"))) == ["CallTool", "Login", "Read"]
    assert s.has_entity_type("Drupe::OAuthUser") and s.enum_ids("Drupe::Role") == [
        "reader",
        "admin",
    ]
    assert s.entities["Drupe::Team"].parents == ["Drupe::Org"]
    assert s.entities["Drupe::OAuthUser"].tags == ("prim", "String")
    assert s.actions[act("Login")].principal_types == ["Drupe::OAuthUser"]
    assert s.record_path(act("Login"), ["input", "user"]) == ("prim", "String")
    assert s.record_path(act("Login"), ["input", "tries"]) == ("prim", "Long")
    assert s.record_path(act("Login"), ["system", "now"]) == ("ext", "datetime")
    assert s.record_path(act("Login"), ["tags"]) == ("set", ("prim", "String"))
    assert s.record_path(act("Login"), ["input", "nope"]) is None
    assert s.context_type(act("Mcp")) is None


def test_schema_reader_errors():
    with pytest.raises(SchemaError):
        parse_schema("entity A = String;")
    with pytest.raises(SchemaError):
        parse_schema("namespace X { bogus }")
    with pytest.raises(SchemaError):
        parse_schema("type A = B; type B = A;").resolve(("named", "A"))
    with pytest.raises(SchemaError):
        parse_schema("type A = Missing;").resolve(("named", "A"))


@pytest.fixture
def evaluator():
    ctx = Record(
        {
            "input": Record({"shares": 5, "stock": "AMZN", "tags": SetValue(["a"])}),
            "system": Record({"now": DateTime.parse("2025-06-01T00:00:00Z")}),
        }
    )
    store = EntityStore(
        {
            U: EntityData(
                Record({"dept": "eng"}), {EntityRef("Drupe::Team", "t")}, Record({"k": "v"})
            )
        },
        parse_schema(SCHEMA),
    )
    return Evaluator(Request(U, act("Read"), GW, ctx), store)


@pytest.mark.parametrize(
    "src, want",
    [
        ('context.input.shares <= 50 && context.input.stock like "A*"', True),
        ("if context has output then false else context.input.shares * 2 == 10", True),
        (
            'principal in Drupe::Team::"t" && principal is Drupe::OAuthUser in Drupe::Team::"t" && principal.dept == "eng"',
            True,
        ),
        (
            'context.input.tags.contains("a") && !context.input.tags.isEmpty() && [1, 2].containsAll([2]) && [1].containsAny([1, 3])',
            True,
        ),
        (
            'context.system.now >= datetime("2025-01-01") && context.system.now < datetime("2026-01-01T00:00:00Z")',
            True,
        ),
        (
            'decimal("0.5").lessThan(decimal("1.0")) && decimal("2.0").greaterThanOrEqual(decimal("2.0")) && duration("1h").toMinutes() == 60',
            True,
        ),
        (
            'ip("10.0.0.1").isInRange(ip("10.0.0.0/8")) && ip("::1").isIpv6() && !ip("1.2.3.4").isMulticast()',
            True,
        ),
        (
            'principal.hasTag("k") && principal.getTag("k") == "v" && context has input.stock && !(context has input.x) && !(principal has nope)',
            True,
        ),
        ('context.input.shares == "5" || context.input.shares != 5 || true == 1', False),
        (
            'action in [Drupe::Action::"Mcp"] && action in Drupe::Action::"CallTool" && -context.input.shares == -5',
            True,
        ),
        (
            'context.system.now.offset(duration("1d")).toDate() > context.system.now && context.system.now.durationSince(context.system.now).toSeconds() == 0',
            True,
        ),
        (
            'context.system.now.toTime() == duration("0s") && duration("90m").toHours() == 1 && duration("-1d").toDays() == -1',
            True,
        ),
        (
            '{a: 1, "b": [1]} == {b: [1], a: 1} && {a: 1} has a && context.input["stock"] == "AMZN"',
            True,
        ),
        (
            '"a*b" like "a\\*b" && !("axb" like "a\\*b") && "" like "*" && "line1\\nline2" like "line1*"',
            True,
        ),
        (
            "(1 < 2 && 2 <= 2 && 3 > 2 && 3 >= 3) && 9223372036854775807 - 1 == 9223372036854775806",
            True,
        ),
        (
            'duration("2h") > duration("1h") && datetime("2025-01-02") >= datetime("2025-01-01")',
            True,
        ),
    ],
)
def test_evaluator_semantics(evaluator, src, want):
    assert evaluator.eval(parse_expression(src)) is want


@pytest.mark.parametrize(
    "src",
    [
        "context.input.missing == 1",
        "context.input.shares && true",
        '1 < "a"',
        "principal.nope",
        "context.input.shares + 9223372036854775807",
        "-(-9223372036854775807 - 1)",
        "if 1 then 2 else 3",
        "!5",
        "1 in [1]",
        "principal in [1]",
        'principal in "x"',
        '"s" like 1' if False else '5 like "a"',
        "5 is Drupe::OAuthUser",
        "5.foo",
        "context.input.shares.contains(1)",
        "[1].containsAll(1)",
        'principal.getTag("zz")',
        '"x".isEmpty()',
        'decimal("0.5") < decimal("1.0")',
        "decimal(5)",
        'ip("bad")',
        "5 has a",
        'nonesuch("x")',
        'decimal("1.0", "2.0")',
    ],
)
def test_evaluator_errors_fail_closed(evaluator, src):
    with pytest.raises(EvalError):
        evaluator.eval(parse_expression(src))


def test_like_regex_handles_special_characters():
    assert like_regex("a.b*").fullmatch("a.bXYZ") and not like_regex("a.b*").fullmatch("aXbY")
    assert like_regex("\\**").fullmatch("*anything")


def test_temporal_block_without_engine_is_an_error(evaluator):
    with pytest.raises(EvalError, match="temporal engine"):
        evaluator.eval(
            parse_expression('temporal { formerly within 1h D::Action::"L"::request{} }')
        )


# ------------------------------------------------------------------ authorizer
POLICIES = """
@id("permit-sell")
permit ( principal, action == Drupe::Action::"Read", resource );
@id("forbid-amzn")
forbid ( principal, action in [Drupe::Action::"CallTool"], resource )
when { context.input.stock == "AMZN" };
@id("broken")
permit ( principal, action, resource ) when { context.input.nope == 1 };
@id("eng-only")
permit ( principal is Drupe::OAuthUser in Drupe::Team::"eng", action == Drupe::Action::"Login", resource == Drupe::Gateway::"gw1" )
unless { context.input.user like "guest*" };
"""


def _ev(action, ctx, kind="request", **kw):
    return Event(
        ts=0,
        action=act(action),
        kind=kind,
        principal=U,
        resource=GW,
        request_context=Record(ctx),
        **kw,
    )


def test_policy_set_parse_and_labels():
    ps = PolicySet.parse(POLICIES, schema=parse_schema(SCHEMA))
    assert ps.labels == ["permit-sell", "forbid-amzn", "broken", "eng-only"]
    assert [a.id for a in ps.actions_covered(ps.policies[1])] == ["CallTool", "Login", "Read"]
    assert ps.actions_covered(ps.policies[0]) == [act("Read")]
    assert len(ps.actions_covered(ps.policies[2])) == 4  # every schema action
    assert ps.temporal_blocks() == []
    with pytest.raises(ParseError, match="template slot"):
        PolicySet.parse("permit ( principal == ?principal, action, resource );")


def test_authorizer_decisions_reasons_and_errors():
    schema = parse_schema(SCHEMA)
    auth = Authorizer(PolicySet.parse(POLICIES, schema), schema)
    r = auth.is_authorized(_ev("Read", {"input": Record({"stock": "MSFT"})}))
    assert (
        r.allowed
        and r.rules == ["permit-sell"]
        and r.errors == ["policy `broken`: record does not have attribute `nope`"]
    )
    assert str(r) == "Allow [rules: permit-sell]"
    r = auth.is_authorized(_ev("Read", {"input": Record({"stock": "AMZN"})}))
    assert not r.allowed and r.rules == ["forbid-amzn"]
    assert (
        auth.is_authorized(_ev("Read", {"input": Record({"stock": "MSFT"})}, kind="response"))
        is None
    )
    assert len(auth.history) == 3
    # default deny with no reason
    r = auth.is_authorized(_ev("Login", {"input": Record({"user": "bob"})}))
    assert r.decision == "Deny" and r.rules == []
    # entity store from the event makes the `is ... in` scope match
    ents = {U: EntityData(parents={EntityRef("Drupe::Team", "eng")})}
    r = auth.is_authorized(_ev("Login", {"input": Record({"user": "bob"})}, entities=ents))
    assert r.allowed and r.rules == ["eng-only"]
    r = auth.is_authorized(_ev("Login", {"input": Record({"user": "guest1"})}, entities=ents))
    assert not r.allowed


def test_authorizer_fails_closed_without_scope():
    auth = Authorizer(PolicySet.parse("permit(principal, action, resource);"))
    r = auth.is_authorized(
        Event(ts=0, action=act("Read"), kind="request", principal=None, resource=GW)
    )
    assert r.decision == "Deny" and r.errors == ["request has no principal"]
    r = auth.is_authorized(
        Event(ts=0, action=act("Read"), kind="request", principal=U, resource=None)
    )
    assert r.errors == ["request has no resource"]
    r = auth.authorize(Request(U, act("Read"), GW))
    assert r.allowed and r.rules == ["policy0"]


def test_null_context_values_become_empty_strings():
    auth = Authorizer(
        PolicySet.parse('permit(principal, action, resource) when { context.input.x == "" };')
    )
    assert auth.is_authorized(_ev("Read", {"input": Record({"x": None})})).allowed


# ------------------------------------------------------------------ trace format
LINE = (
    '@100 scope(principal: Drupe::OAuthUser::"alice", resource: Drupe::Gateway::"gw1") '
    'entities(Drupe::OAuthUser::"alice": { dept: "eng", n: null } in [Drupe::Team::"t"]) '
    'request_context(input: { shares: 5, stock: "A,B)" , price: 1.50 }, system: { flag: true }) '
    'Drupe::Action::"Sell::Now"::request(input: { shares: 5 }, output: { ok: false, tags: ["x", 1] }, callerPrincipal: Drupe::OAuthUser::"alice", requestId: "u\\"1")'
)


def test_parse_trace_line_shapes():
    (ev,) = parse_trace("\ufeff\n" + LINE + "\n\n")
    assert (
        ev.ts == 100
        and ev.kind == "request"
        and ev.action == EntityRef("Drupe::Action", "Sell::Now")
    )
    assert ev.principal == U and ev.resource == GW
    assert ev.request_context["input"] == Record(
        {"shares": 5, "stock": "A,B)", "price": Decimal.parse("1.50")}
    )
    assert ev.request_context["system"]["flag"] is True
    assert ev.logged["output"]["tags"] == SetValue(["x", 1]) and ev.logged["requestId"] == 'u"1'
    assert ev.entities[U].attrs == Record({"dept": "eng"}) and ev.entities[U].parents == {
        EntityRef("Drupe::Team", "t")
    }


def test_parse_value_forms():
    assert parse_value("null") is None and parse_value(" true ") is True
    assert parse_value("-3") == -3 and parse_value('"a\\u{41}"') == "aA"
    assert parse_value("[1, [2], {}]") == SetValue([1, SetValue([2]), Record()])
    assert parse_value('A::B::"x"') == EntityRef("A::B", "x")
    assert parse_value("bare") == "bare"  # unquoted text stays a string, as in the reference
    assert parse_value("1.123456") == Decimal.parse("1.1234")


@pytest.mark.parametrize(
    "line, msg",
    [
        ("100 x", "must start with `@`"),
        ("@100", "whitespace after timestamp"),
        ("@abc x()", "bad timestamp"),
        ('@1 scope(principal: A::"a"', "scope missing"),
        ('@1 X::Action::"a"::request', "event missing"),
        ("@1 )(", "out of order"),
        ('@1 X::Action::"a"(a: 1)', "missing a `::kind`"),
        ("@1 X::Action(a: 1)", "missing a quoted action id"),
        ('@1 X::Action::"a"::request(a)', "missing `:`"),
        ('@1 X::Action::"a"::request(a: 1, a: 2)', "duplicate field"),
        ('@1 X::Action::"a"::request(a: {b: 1, b: 2})', "duplicate field"),
        ('@1 entities(A::"a": {} X::Action::"a"::request()', "entities missing"),
        ('@1 request_context(input: {} X::Action::"a"::request()', "request_context missing"),
    ],
)
def test_parse_trace_errors(line, msg):
    with pytest.raises(TraceError, match=msg):
        parse_trace(line)


def test_replay_verdict_stream():
    pol = (
        'permit(principal, action == Drupe::Action::"Read", resource) when { context.input.n > 1 };'
    )
    trace = "\n".join(
        [
            '@0 scope(principal: Drupe::OAuthUser::"a", resource: Drupe::Gateway::"g") request_context(input: { n: 1 }) Drupe::Action::"Read"::request(input: { n: 1 })',
            '@1 scope(principal: Drupe::OAuthUser::"a", resource: Drupe::Gateway::"g") Drupe::Action::"Read"::response(input: { n: 1 })',
            '@5 scope(principal: Drupe::OAuthUser::"a", resource: Drupe::Gateway::"g") request_context(input: { n: 2 }) Drupe::Action::"Read"::request(input: { n: 2 })',
        ]
    )
    assert replay(pol, trace) == "@0 (time point 0): false\n@5 (time point 2): true"
