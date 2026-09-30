"""Parser tests: AST shapes, the reference's rejection wording, and check-parse parity
over every .dw file of the vendored corpus (tests/dogwood_corpus/) plus, when the
reference checkout is present on this machine, over the full reference corpus."""

import glob
import os

import pytest

from strands_inspect.dogwood import ast as A
from strands_inspect.dogwood.errors import DogwoodError, LexError, ParseError
from strands_inspect.dogwood.parser import parse_expression, parse_policy_set, parse_temporal
from strands_inspect.dogwood.values import EntityRef

REF = os.environ.get("DOGWOOD_REF", os.path.expanduser("~/.tiny/dogwood-20260930/ref"))
CORPUS = os.path.join(os.path.dirname(__file__), "dogwood_corpus")


def _ref_files():
    if not os.path.isdir(REF):
        return []
    return sorted(
        glob.glob(f"{REF}/dogwood-language/tests/passing/*/corpus/*/policy_*.dw")
        + glob.glob(f"{REF}/dogwood-docs/examples/*/policy.dw")
    )


def _vendored_files():
    return sorted(glob.glob(f"{CORPUS}/**/*.dw", recursive=True))


# ------------------------------------------------------------------ shapes
def test_policy_anatomy():
    ps = parse_policy_set(
        '@id("sell_small") @reviewed\n'
        'permit ( principal is Drupe::OAuthUser in Drupe::Team::"t", action in [Drupe::Action::"A", Drupe::Action::"B"], resource == Drupe::Gateway::"g" )\n'
        'when { context.input.shares <= 50 } unless { context.input.stock like "TEST_*" };\n'
        "forbid ( );"
    )
    assert len(ps.policies) == 2 and ps.macros == []
    p = ps.policies[0]
    assert p.effect == "permit" and p.id == "sell_small" and p.label == "sell_small"
    assert p.annotations == [("id", "sell_small"), ("reviewed", None)]
    assert p.principal.op == "is_in" and p.principal.entity_type == "Drupe::OAuthUser"
    assert p.principal.entity == EntityRef("Drupe::Team", "t")
    assert p.action.op == "in" and [e.id for e in p.action.entities] == ["A", "B"]
    assert p.resource.op == "eq" and p.resource.entity == EntityRef("Drupe::Gateway", "g")
    assert [c.kind for c in p.conditions] == ["when", "unless"]
    assert isinstance(p.conditions[0].body, A.BinOp) and p.conditions[0].body.op == "<="
    assert isinstance(p.conditions[1].body, A.Like) and p.conditions[1].body.pattern == "TEST_*"
    q = ps.policies[1]
    assert q.label == "policy1" and (q.principal.op, q.action.op, q.resource.op) == (
        "any",
        "any",
        "any",
    )


def test_scope_slots_and_single_action_in():
    p = parse_policy_set(
        'permit ( principal == ?principal, action in Drupe::Action::"X", resource in ?resource );'
    ).policies[0]
    assert (
        p.principal.slot == "principal" and p.resource.slot == "resource" and p.resource.op == "in"
    )
    assert p.action.entities == [EntityRef("Drupe::Action", "X")]


def test_expression_tower_precedence():
    e = parse_expression("context.b < 1 || !context.x && context.y + 2 * 3 == 7")
    assert isinstance(e, A.Or) and isinstance(e.right, A.And)
    assert isinstance(e.right.left, A.Not)
    eq = e.right.right
    assert eq.op == "==" and eq.left.op == "+" and eq.left.right.op == "*"
    assert parse_expression("if context.a then context.b else context.c").__class__ is A.If
    assert isinstance(parse_expression("-5"), A.Lit) and parse_expression("-5").value == -5
    assert isinstance(parse_expression("--context.x"), A.Neg)
    assert parse_expression("-9223372036854775808").value == -(2**63)


def test_member_access_forms():
    e = parse_expression('context.output.categories["VIOLENCE"].contains(decimal("0.5"))')
    assert isinstance(e, A.MethodCall) and e.name == "contains"
    assert isinstance(e.operand, A.GetAttr) and e.operand.attr == "VIOLENCE"
    assert isinstance(e.args[0], A.Call) and e.args[0].name == "decimal"
    h = parse_expression('context has a.b && context has "c" && context has if.x')
    assert (
        h.left.left.attrs == ["a", "b"]
        and h.left.right.attrs == ["c"]
        and h.right.attrs == ["if", "x"]
    )
    i = parse_expression('principal is Drupe::OAuthUser in Drupe::Team::"traders"')
    assert (
        isinstance(i, A.Is)
        and i.entity_type == "Drupe::OAuthUser"
        and isinstance(i.in_expr, A.EntityLit)
    )
    s = parse_expression('[{ label: "review", "count": 3, if: true }, 1]')
    assert isinstance(s, A.SetLit) and [k for k, _ in s.items[0].items] == ["label", "count", "if"]


def test_temporal_inline_and_clause_forms():
    ps = parse_policy_set(
        'permit(principal, action, resource) when { context.input.shares > 5 && temporal { formerly within 1h D::Action::"L"::request{ input.user: context.input.user } } };'
        "permit(principal, action, resource) when guardrails { context.x == 1 };"
        'permit(principal, action, resource) unless temporal { previous within 30s D::Action::"L"::response{ output.ok: true } };'
    )
    tb = ps.policies[0].conditions[0].body.right
    assert (
        isinstance(tb, A.TemporalBlock)
        and isinstance(tb.cond, A.Formerly)
        and tb.cond.window.seconds == 3600
    )
    assert isinstance(ps.policies[1].conditions[0].body, A.BinOp)
    pv = ps.policies[2].conditions[0].body.cond
    assert isinstance(pv, A.Previous) and pv.window.text == "30s" and pv.body.kind == "response"


def test_temporal_operators_precedence_and_binders():
    c = parse_temporal(
        '!D::Action::"Revoke"::request{ input.u: context.input.u } since within 1h D::Action::"Grant"::request{ input.u: context.input.u } && exists (n: Long). ((count for (t: Timepoint). where (D::Action::"L"::request{ input.user: _, x: * } && tp(t))) == n && n > 2)'
    )
    assert isinstance(c, A.TAnd) and isinstance(c.left, A.Since) and isinstance(c.left.left, A.TNot)
    ex = c.right
    assert isinstance(ex, A.Exists) and ex.var.name == "n" and ex.type == "Long"
    assert isinstance(ex.body, A.TAnd) and isinstance(ex.body.left, A.Comparison)
    agg = ex.body.left.left
    assert isinstance(agg, A.TAgg) and agg.kind == "count" and agg.binders[0][1] == "Timepoint"
    pred = agg.body.left
    assert isinstance(pred, A.Pred) and pred.namespace == ["D", "Action"] and pred.action == "L"
    assert isinstance(pred.args[0][1], A.TWildcard) and isinstance(pred.args[1][1], A.TWildcard)
    assert ex.body.right.op == ">" and ex.body.right.right.value == 2


def test_temporal_sum_right_side_aggregate_and_neq():
    c = parse_temporal(
        '0 < count for (t: Timepoint). where (formerly within 1h (D::Action::"T"::request{ requestId: _ } && tp(t)))'
    )
    assert isinstance(c, A.Comparison) and isinstance(c.right, A.TAgg)
    s = parse_temporal(
        '(sum a for (a: Long), (t: Timepoint). where D::Action::"T"::request{ input.amount: a }) != 3'
    )
    assert (
        s.op == "!="
        and s.left.kind == "sum"
        and s.left.sum_var.name == "a"
        and len(s.left.binders) == 2
    )
    v = parse_temporal(
        "exists (count: Long). (count == 1)"
    )  # `count` is an ordinary identifier here
    assert isinstance(v.body, A.Comparison) and v.body.left.name == "count"


def test_macro_definitions_and_calls():
    ps = parse_policy_set(
        "def cedar is_small(?n) { ?n < 100 };\n"
        "def temporal count_within(?w, ?s) { count for ($t: Timepoint). where (formerly within ?w (?s && tp($t))) };\n"
        "def temporal same_session(?w, ?s) { formerly within ?w (?s{ sid: context.sid }) };\n"
        'permit(principal, action, resource) when { is_small(context.input.shares) } when temporal { exists (n: Long). ((count_within(1h, D::Action::"L"::request{ input.u: u })) == n && n > 1) && same_session(2h, D::Action::"L"::request{}) };'
    )
    assert [m.kind for m in ps.macros] == ["cedar", "temporal", "temporal"]
    assert isinstance(ps.macros[0].body, A.BinOp) and isinstance(ps.macros[0].body.left, A.ParamRef)
    agg = ps.macros[1].body
    assert (
        isinstance(agg, A.TAgg)
        and isinstance(agg.binders[0][0], A.TBinder)
        and isinstance(agg.body.window, A.IntervalParam)
    )
    ref = ps.macros[2].body.body
    assert (
        isinstance(ref, A.Refined)
        and isinstance(ref.base, A.TParamCond)
        and ref.blocks[0][0][0] == ["sid"]
    )
    p = ps.policies[0]
    assert isinstance(p.conditions[0].body, A.Call) and p.conditions[0].body.name == "is_small"
    tc = p.conditions[1].body.cond
    assert isinstance(
        tc, A.Exists
    )  # exists is greedy to the right: `&& same_session(..)` is inside it
    call = tc.body.left.left.left
    assert (
        isinstance(call, A.TAggCall)
        and isinstance(call.args[0], A.Interval)
        and isinstance(call.args[1], A.Pred)
    )
    assert isinstance(tc.body.right, A.TCall) and tc.body.right.name == "same_session"


@pytest.mark.parametrize(
    "src, needle",
    [
        ("allow(principal, action, resource);", "policy effect must be `permit` or `forbid`"),
        ("permit(principal : User, action, resource);", "use `principal is Type`"),
        ('permit(principal = User::"a", action, resource);', "did you mean `==`"),
        ("permit(principal, action is Drupe::Action, resource);", "`action is Type` is not valid"),
        ("permit(principal, principal, resource);", "duplicate `principal`"),
        ("permit(principal, action, resource, extra);", "extra element in the scope"),
        ("permit(user, action, resource);", "unexpected scope variable `user`"),
        ('permit(principal < User::"a", action, resource);', "scope only allows `==` or `in`"),
        (
            'permit(principal is User == User::"a", action, resource);',
            "only `is Type in ...` is allowed",
        ),
        (
            "permit(principal, action == ?principal, resource);",
            "template slots are not allowed in the action scope",
        ),
        (
            'permit(principal, action == Drupe::User::"a", resource);',
            "action scope expects an action reference",
        ),
        (
            "permit(principal, action, resource) when { 1 / 2 == 0 };",
            "`/` is not a supported operator",
        ),
        (
            "permit(principal, action, resource) when { 1 % 2 == 0 };",
            "`%` is not a supported operator",
        ),
        ("permit(principal, action, resource) when { context.x = 1 };", "did you mean `==`"),
        ("permit(principal, action, resource) when { foo == 1 };", "`foo` is not a valid variable"),
        (
            "permit(principal, action, resource) when { User::{ id: 1 } == principal };",
            "entity initializer syntax",
        ),
        (
            "permit(principal, action, resource) when { context.a[context.b] == 1 };",
            "string-literal key",
        ),
        ("permit(principal, action, resource) when { context.f(1) };", "unknown method `f`"),
        (
            "permit(principal, action, resource) when { context.s.contains() };",
            "exactly one argument",
        ),
        ("permit(principal, action, resource) when { (context.f)(1) };", "unexpected call"),
        ("permit(principal, action, resource) when { !-context.x };", "cannot mix"),
        ("permit(principal, action, resource) when { 9223372036854775808 == 1 };", "out of range"),
        (
            "permit(principal, action, resource) if { true };",
            "condition keyword must be `when` or `unless`",
        ),
        (
            'permit(principal, action, resource) when { Strings::Matches(context.x, "a").matched };',
            "providers are not supported",
        ),
        ("permit(principal, action, resource) when { ?p == 1 };", "only valid inside a macro body"),
        (
            'permit(principal, action, resource) when temporal { formerly D::Action::"L"::request{} };',
            "`within <interval>` window",
        ),
        (
            'permit(principal, action, resource) when temporal { formerly within 1w D::Action::"L"::request{} };',
            "unit",
        ),
        (
            'permit(principal, action, resource) when temporal { formerly within 1h D::Action::"L"::request{ a: [1] } };',
            "array constants",
        ),
        (
            "permit(principal, action, resource) when temporal { let t = 1 };",
            "expected a temporal condition",
        ),
        ("def macro f(?a) { 1 };", "macro kind must be `cedar` or `temporal`"),
        ("def cedar f(a) { 1 };", "macro parameters are written `?name`"),
        (
            'permit(principal, action, resource) when { context.x == "\\xFF" };',
            "not a valid escape",
        ),
        ('permit(principal, action, resource) when { context.x like "\\q" };', "unknown escape"),
    ],
)
def test_rejections_carry_reference_wording_and_position(src, needle):
    with pytest.raises(DogwoodError) as ei:
        parse_policy_set(src, "policy.dw")
    assert needle in str(ei.value), str(ei.value)
    assert ei.value.line >= 1 and ei.value.col >= 1 and str(ei.value).startswith("policy.dw:1:")


def test_parse_temporal_rejects_trailing_tokens_and_negative_window():
    with pytest.raises(ParseError):
        parse_temporal('D::Action::"L"::request{} )')
    with pytest.raises(ParseError, match="negative"):
        parse_temporal('formerly within -1h D::Action::"L"::request{}')
    with pytest.raises(ParseError, match="unexpected"):
        parse_expression("1 2")


# ------------------------------------------------------------------ corpus parity
@pytest.mark.skipif(not _vendored_files(), reason="vendored corpus not present yet")
def test_every_vendored_dw_parses():
    for f in _vendored_files():
        with open(f, encoding="utf-8") as fh:
            parse_policy_set(fh.read(), f)


@pytest.mark.skipif(not _ref_files(), reason="reference checkout not on this machine")
def test_reference_corpus_check_parse_parity():
    ok = providers = 0
    failures = []
    for f in _ref_files():
        with open(f, encoding="utf-8") as fh:
            src = fh.read()
        try:
            parse_policy_set(src, f)
            ok += 1
        except DogwoodError as exc:
            if "providers are not supported" in str(exc):
                providers += 1
            else:
                failures.append((f, str(exc)))
    assert not failures, failures[:5]
    assert ok >= 900 and providers <= 100, (ok, providers)


@pytest.mark.skipif(
    not os.path.isdir(f"{REF}/dogwood-language/tests/expected_failures"), reason="no ref"
)
def test_reference_expected_failures_rejected_at_parse_sample():
    """A sample of the reference's parse-layer rejections must be errors here too."""
    names = [
        "0426_numeric_field_swap_in_aggregation",  # removed `let ... in` / implicit aggregation
        "0700_unknown_method_on_non_provider",
        "1135_array_predicate_arg",
        "2096_string_hex_out_of_range",
        "2141_pattern_hex_out_of_range",
    ]
    rejected = 0
    for n in names:
        for f in glob.glob(
            f"{REF}/dogwood-language/tests/expected_failures/corpus/{n}/policy_*.dw"
        ):
            with open(f, encoding="utf-8") as fh:
                src = fh.read()
            try:
                parse_policy_set(src, f)
            except (ParseError, LexError):
                rejected += 1
    assert rejected >= 4, rejected
