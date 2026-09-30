"""Lexer and value-model tests for the pure-Python Dogwood implementation."""

import pytest

from strands_inspect.dogwood.errors import EvalError, LexError
from strands_inspect.dogwood.lexer import BINDER, IDENT, INT, OP, PARAM, STRING, tokenize, unescape
from strands_inspect.dogwood.values import (
    DateTime,
    Decimal,
    Duration,
    EntityRef,
    IpAddr,
    Record,
    SetValue,
    hash_key,
    render,
    type_name,
    values_equal,
)


def kinds(src):
    return [(t.kind, t.value) for t in tokenize(src)][:-1]


def test_lexer_double_colon_and_entity_ref():
    assert kinds('Drupe::Action::"Login"') == [
        (IDENT, "Drupe"),
        (OP, "::"),
        (IDENT, "Action"),
        (OP, "::"),
        (STRING, "Login"),
    ]


def test_lexer_sigils_annotation_and_comment():
    toks = kinds('@id("x") ?p $t // comment\n;')
    assert toks == [
        (OP, "@"),
        (IDENT, "id"),
        (OP, "("),
        (STRING, "x"),
        (OP, ")"),
        (PARAM, "p"),
        (BINDER, "t"),
        (OP, ";"),
    ]


def test_lexer_two_char_operators_and_interval_split():
    assert kinds("a <= b >= c != d == e && f || g") == [
        (IDENT, "a"), (OP, "<="), (IDENT, "b"), (OP, ">="), (IDENT, "c"), (OP, "!="),
        (IDENT, "d"), (OP, "=="), (IDENT, "e"), (OP, "&&"), (IDENT, "f"), (OP, "||"), (IDENT, "g"),
    ]  # fmt: skip
    # intervals are INT + unit IDENT; the parser folds them
    assert kinds("within 1h") == [(IDENT, "within"), (INT, "1"), (IDENT, "h")]
    assert kinds("30s") == [(INT, "30"), (IDENT, "s")]


def test_lexer_positions_are_one_based():
    toks = tokenize("permit\n  (principal")
    assert (toks[0].line, toks[0].col) == (1, 1)
    assert (toks[1].line, toks[1].col, toks[1].value) == (2, 3, "(")
    assert toks[2].pos == 10


def test_lexer_string_keeps_raw_body_and_unescape_decodes():
    (tok,) = tokenize(r'"a\"b\\c\n\t\r\0\'"')[:-1]
    assert tok.kind == STRING
    assert unescape(tok.value, 1, 1) == "a\"b\\c\n\t\r\0'"


def test_unescape_unicode_and_hex():
    assert unescape(r"a\u{2764}b", 1, 1) == "a\u2764b"
    assert unescape(r"\u{0_0_0_e}", 1, 1) == "\u000e"
    assert unescape(r"quote\x22group", 1, 1) == 'quote"group'
    assert unescape(r"\x41", 1, 1) == "A"
    assert unescape(r"\*", 1, 1, allow_star=True) == "\\*"


@pytest.mark.parametrize("bad", [r"\q", r"\u{zz}", r"\u{12", r"\x4", r"\u{_1}"])
def test_unescape_rejects_bad_escapes(bad):
    with pytest.raises(LexError):
        unescape(bad, 1, 1)


def test_lexer_errors_carry_position():
    with pytest.raises(LexError) as ei:
        tokenize('permit(\n  "open')
    assert ei.value.line == 2 and ei.value.col == 3
    with pytest.raises(LexError) as ei:
        tokenize("a ^ b")
    assert "^" in str(ei.value) and ei.value.col == 3


# ---------------------------------------------------------------- values
def test_entity_ref_renders_with_escapes():
    e = EntityRef("Drupe::OAuthUser", 'o"admin')
    assert str(e) == 'Drupe::OAuthUser::"o\\"admin"'
    assert e.namespace == "Drupe" and e.base_type == "OAuthUser"


def test_set_and_record_semantics():
    assert SetValue([1, 2, 2]) == SetValue([2, 1])
    assert len(SetValue([1, 1])) == 1
    assert SetValue([1]).contains(1) and not SetValue([1]).contains(True)
    assert hash(SetValue([1, 2])) == hash(SetValue([2, 1]))
    r = Record({"a": 1, "b": SetValue([1])})
    assert r == Record({"b": SetValue([1]), "a": 1}) and hash(r) == hash(
        Record({"b": SetValue([1]), "a": 1})
    )
    assert repr(r) == "{a: 1, b: [1]}"
    assert repr(SetValue(["x"])) == '["x"]'


def test_values_equal_is_typed():
    assert values_equal(1, 1) and not values_equal(True, 1) and not values_equal("1", 1)
    assert values_equal(EntityRef("A", "b"), EntityRef("A", "b"))
    assert hash_key(True) != hash_key(1)


def test_type_names_and_render():
    assert [type_name(v) for v in (True, 1, "s", SetValue(), Record(), EntityRef("A", "b"))] == [
        "Bool", "Long", "String", "Set", "Record", "Entity",
    ]  # fmt: skip
    assert render(True) == "true" and render('a"b') == '"a\\"b"' and render(3) == "3"


def test_decimal_parse_and_range():
    assert Decimal.parse("0.5").value == Decimal.parse("0.5000").value
    assert str(Decimal.parse("-1.25")) == 'decimal("-1.25")'
    for bad in ("1", "1.", "1.00000", "abc", "922337203685478.0"):
        with pytest.raises(EvalError):
            Decimal.parse(bad)


def test_duration_parse():
    assert Duration.parse("1h30m").ms == 5_400_000
    assert Duration.parse("-2d").ms == -2 * 86_400_000
    assert Duration.parse("1s500ms").ms == 1500
    for bad in ("", "-", "1x", "h", "1m1h"):
        with pytest.raises(EvalError):
            Duration.parse(bad)


def test_datetime_parse_and_methods():
    t = DateTime.parse("2024-01-01T00:00:00Z")
    assert t.ms == 1_704_067_200_000
    assert DateTime.parse("2024-01-01").ms == t.ms
    assert DateTime.parse("2024-01-01T00:00:00.123Z").ms == t.ms + 123
    assert DateTime.parse("2024-01-01T01:00:00+0100").ms == t.ms
    assert DateTime.parse("2024-01-01T12:34:56Z").to_date() == t
    assert DateTime.parse("2024-01-01T00:00:01Z").to_time() == Duration(1000)
    assert str(t) == 'datetime("2024-01-01T00:00:00.000Z")'
    for bad in ("2024-13-01", "2024-01-01T25:00:00Z", "yesterday", "2024-01-01T00:00:00+2500"):
        with pytest.raises(EvalError):
            DateTime.parse(bad)


def test_ipaddr():
    a = IpAddr.parse("10.0.0.5")
    assert a.is_ipv4 and not a.is_ipv6 and a.in_range(IpAddr.parse("10.0.0.0/24"))
    assert not a.in_range(IpAddr.parse("::1"))
    assert IpAddr.parse("127.0.0.1").is_loopback and IpAddr.parse("224.0.0.1").is_multicast
    assert IpAddr.parse("::1").is_ipv6
    assert str(IpAddr.parse("10.0.0.0/24")) == 'ip("10.0.0.0/24")'
    with pytest.raises(EvalError):
        IpAddr.parse("999.1.1.1")
