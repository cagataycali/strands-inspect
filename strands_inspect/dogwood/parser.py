"""Recursive-descent parser for Dogwood policy sets.

Grammar: dogwood-docs/guide/08-formal-specification.md section 2 (a transliteration of
the three pest grammars). The parser is deliberately permissive where Cedar's is, and
rejects the same constructs afterwards with the reference's wording (``=`` -> "did you
mean ==", ``/`` unsupported, ``principal : Type`` legacy form, entity initialisers).
"""

from __future__ import annotations

from typing import Any, List, Optional, Tuple

from . import ast as A
from .errors import LexError, ParseError
from .lexer import BINDER, EOF_KIND, IDENT, INT, OP, PARAM, STRING, Token, tokenize, unescape
from .values import I64_MAX, I64_MIN, Decimal, EntityRef

_REQUEST_VARS = ("principal", "action", "resource", "context")
_REL_OPS = ("<=", ">=", "!=", "==", "<", ">", "=")
_TIME_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
_CMP_OPS = ("<=", ">=", "==", "!=", "<", ">")
METHODS = {
    "isEmpty": 0, "isIpv4": 0, "isIpv6": 0, "isLoopback": 0, "isMulticast": 0, "toDate": 0,
    "toTime": 0, "toMilliseconds": 0, "toSeconds": 0, "toMinutes": 0, "toHours": 0, "toDays": 0,
    "contains": 1, "containsAll": 1, "containsAny": 1, "getTag": 1, "hasTag": 1, "isInRange": 1,
    "offset": 1, "durationSince": 1, "lessThan": 1, "lessThanOrEqual": 1, "greaterThan": 1,
    "greaterThanOrEqual": 1,
}  # fmt: skip
_TEMPORAL_KEYWORDS = {
    "formerly",
    "previous",
    "since",
    "within",
    "exists",
    "tp",
    "count",
    "sum",
    "for",
    "where",
}


class _Backtrack(Exception):
    """Internal: an alternative did not match; the caller restores the position."""


class Parser:
    def __init__(self, text: str, source: str = ""):
        self.toks: List[Token] = tokenize(text, source)
        self.i = 0
        self.source = source
        self.in_macro = False  # ?p / $t allowed

    # ------------------------------------------------------------------ helpers
    @property
    def tok(self) -> Token:
        return self.toks[self.i]

    def peek(self, k: int = 1) -> Token:
        j = min(self.i + k, len(self.toks) - 1)
        return self.toks[j]

    def error(self, msg: str, tok: Optional[Token] = None) -> ParseError:
        t = tok or self.tok
        return ParseError(msg, t.line, t.col, self.source)

    def at_op(self, text: str) -> bool:
        return self.tok.kind == OP and self.tok.value == text

    def at_ident(self, text: Optional[str] = None) -> bool:
        return self.tok.kind == IDENT and (text is None or self.tok.value == text)

    def advance(self) -> Token:
        t = self.tok
        if t.kind != EOF_KIND:
            self.i += 1
        return t

    def expect_op(self, text: str, what: str = "") -> Token:
        if not self.at_op(text):
            found = self.tok.value if self.tok.kind != EOF_KIND else "end of input"
            raise self.error(f"expected `{text}`{(' ' + what) if what else ''}, found `{found}`")
        return self.advance()

    def expect_ident(self, what: str = "an identifier") -> Token:
        if self.tok.kind != IDENT:
            found = self.tok.value if self.tok.kind != EOF_KIND else "end of input"
            raise self.error(f"expected {what}, found `{found}`")
        return self.advance()

    def expect_string(self, what: str = "a string literal", allow_star: bool = False) -> str:
        if self.tok.kind != STRING:
            found = self.tok.value if self.tok.kind != EOF_KIND else "end of input"
            raise self.error(f"expected {what}, found `{found}`")
        t = self.advance()
        return self._str(t, allow_star)

    def _str(self, t: Token, allow_star: bool = False) -> str:
        try:
            return unescape(t.value, t.line, t.col, allow_star=allow_star)
        except LexError as exc:
            raise LexError(exc.message, exc.line, exc.col, self.source) from None

    def _pos(self, t: Token) -> dict:
        return {"line": t.line, "col": t.col}

    # ------------------------------------------------------------------ names
    def parse_path(self) -> Tuple[List[str], Token]:
        """``ident { :: ident }`` -- stops before a ``::`` that is followed by a string or ``{``."""
        first = self.expect_ident()
        parts = [first.value]
        while self.at_op("::") and self.peek().kind == IDENT:
            self.advance()
            parts.append(self.advance().value)
        return parts, first

    def parse_entity_ref_after_path(self, parts: List[str]) -> EntityRef:
        self.expect_op("::")
        eid = self.expect_string("an entity id string")
        return EntityRef("::".join(parts), eid)

    def parse_entity_ref(self, what: str) -> EntityRef:
        if self.tok.kind != IDENT:
            raise self.error(f"expected {what}")
        parts, _ = self.parse_path()
        if not (self.at_op("::") and self.peek().kind == STRING):
            raise self.error(f"expected {what}")
        return self.parse_entity_ref_after_path(parts)

    # ------------------------------------------------------------------ Cedar expressions
    def parse_expr(self) -> A.Expr:
        if self.at_ident("if"):
            t = self.advance()
            cond = self.parse_expr()
            if not self.at_ident("then"):
                raise self.error("expected `then` after the `if` condition")
            self.advance()
            then = self.parse_expr()
            if not self.at_ident("else"):
                raise self.error("expected `else` in `if` expression")
            self.advance()
            orelse = self.parse_expr()
            return A.If(cond, then, orelse, **self._pos(t))
        return self.parse_or()

    def parse_or(self) -> A.Expr:
        left = self.parse_and()
        while self.at_op("||"):
            t = self.advance()
            left = A.Or(left, self.parse_and(), **self._pos(t))
        return left

    def parse_and(self) -> A.Expr:
        left = self.parse_rel()
        while self.at_op("&&"):
            t = self.advance()
            left = A.And(left, self.parse_rel(), **self._pos(t))
        return left

    def parse_rel(self) -> A.Expr:
        left = self.parse_add()
        if self.at_ident("has"):
            t = self.advance()
            if self.tok.kind == STRING:
                attrs = [self.expect_string()]
            else:
                attrs = [self.expect_ident("an attribute name after `has`").value]
                while self.at_op(".") and self.peek().kind == IDENT:
                    self.advance()
                    attrs.append(self.advance().value)
            return A.Has(left, attrs, **self._pos(t))
        if self.at_ident("like"):
            t = self.advance()
            if self.tok.kind != STRING:
                raise self.error("`like` requires a string-literal pattern on its right")
            pat_tok = self.advance()
            pattern = self._str(pat_tok, allow_star=True)
            return A.Like(left, pattern, **self._pos(t))
        if self.at_ident("is"):
            t = self.advance()
            parts, _ = self.parse_path()
            in_expr = None
            if self.at_ident("in"):
                self.advance()
                in_expr = self.parse_add()
            return A.Is(left, "::".join(parts), in_expr, **self._pos(t))
        while (self.tok.kind == OP and self.tok.value in _REL_OPS) or self.at_ident("in"):
            t = self.advance()
            op = t.value
            if op == "=":
                raise self.error("`=` is not a valid operator in this scope; did you mean `==`?", t)
            right = self.parse_add()
            left = A.BinOp(op, left, right, **self._pos(t))
        return left

    def parse_add(self) -> A.Expr:
        left = self.parse_mult()
        while self.at_op("+") or self.at_op("-"):
            t = self.advance()
            left = A.BinOp(t.value, left, self.parse_mult(), **self._pos(t))
        return left

    def parse_mult(self) -> A.Expr:
        left = self.parse_unary()
        while self.at_op("*") or self.at_op("/") or self.at_op("%"):
            t = self.advance()
            if t.value != "*":
                raise self.error(f"`{t.value}` is not a supported operator", t)
            left = A.BinOp("*", left, self.parse_unary(), **self._pos(t))
        return left

    def parse_unary(self) -> A.Expr:
        if self.at_op("!") or self.at_op("-"):
            sym = self.tok.value
            ops: List[Token] = []
            while self.at_op(sym):
                ops.append(self.advance())
            if self.at_op("!") or self.at_op("-"):
                raise self.error(f"cannot mix `!` and `-` prefixes (`{sym}{self.tok.value}`)")
            operand = self.parse_member()
            for t in reversed(ops):
                if sym == "!":
                    operand = A.Not(operand, **self._pos(t))
                elif (
                    isinstance(operand, A.Lit)
                    and isinstance(operand.value, int)
                    and not isinstance(operand.value, bool)
                ):
                    operand = A.Lit(-operand.value, **self._pos(t))
                else:
                    operand = A.Neg(operand, **self._pos(t))
            if (
                isinstance(operand, A.Lit)
                and isinstance(operand.value, int)
                and not isinstance(operand.value, bool)
            ):
                if not (I64_MIN <= operand.value <= I64_MAX):
                    raise self.error(f"integer literal `{operand.value}` is out of range", ops[0])
            return operand
        e = self.parse_member()
        if isinstance(e, A.Lit) and isinstance(e.value, int) and not isinstance(e.value, bool):
            if e.value > I64_MAX:
                raise self.error(f"integer literal `{e.value}` is out of range")
        return e

    def parse_member(self) -> A.Expr:
        e = self.parse_primary()
        while True:
            if self.at_op("."):
                t = self.advance()
                name = self.expect_ident("an attribute or method name after `.`").value
                if self.at_op("("):
                    if name not in METHODS:
                        raise self.error(f"unknown method `{name}`", t)
                    self.advance()
                    args = self.parse_expr_list(")")
                    if len(args) != METHODS[name]:
                        what = "no arguments" if METHODS[name] == 0 else "exactly one argument"
                        raise self.error(f"`{name}` takes {what}, got {len(args)}", t)
                    e = A.MethodCall(e, name, args, **self._pos(t))
                else:
                    e = A.GetAttr(e, name, **self._pos(t))
            elif self.at_op("["):
                t = self.advance()
                if self.tok.kind != STRING:
                    raise self.error(
                        'index access requires a string-literal key, e.g. `record["field"]`'
                    )
                key = self.expect_string()
                self.expect_op("]")
                e = A.GetAttr(e, key, **self._pos(t))
            elif self.at_op("("):
                raise self.error(
                    "unexpected call: only extension functions and methods can be called"
                )
            else:
                return e

    def parse_expr_list(self, close: str) -> List[A.Expr]:
        items: List[A.Expr] = []
        while not self.at_op(close):
            items.append(self.parse_expr())
            if self.at_op(","):
                self.advance()
                continue
            if not self.at_op(close):
                raise self.error(f"expected `,` or `{close}`")
        self.advance()
        return items

    def parse_primary(self) -> A.Expr:
        t = self.tok
        if t.kind == INT:
            self.advance()
            return A.Lit(int(t.value), **self._pos(t))
        if t.kind == STRING:
            self.advance()
            return A.Lit(self._str(t), **self._pos(t))
        if t.kind == PARAM:
            self.advance()
            if t.value in ("principal", "resource"):
                return A.Slot(t.value, **self._pos(t))
            if not self.in_macro:
                raise self.error(
                    f"`?{t.value}` is a macro parameter and is only valid inside a macro body", t
                )
            return A.ParamRef(t.value, **self._pos(t))
        if t.kind == BINDER:
            raise self.error(
                f"`${t.value}` is a temporal fresh binder and is not valid in a Cedar expression", t
            )
        if t.kind == OP:
            if t.value == "(":
                self.advance()
                e = self.parse_expr()
                self.expect_op(")")
                return e
            if t.value == "[":
                self.advance()
                return A.SetLit(self.parse_expr_list("]"), **self._pos(t))
            if t.value == "{":
                self.advance()
                return A.RecordLit(self.parse_record_items(), **self._pos(t))
            found = t.value or "end of input"
            raise self.error(f"unexpected `{found}` in expression", t)
        # identifiers
        if t.value in ("true", "false"):
            self.advance()
            return A.Lit(t.value == "true", **self._pos(t))
        if t.value == "temporal" and self.peek().is_op("{"):
            self.advance()
            self.advance()
            cond = self.parse_temporal_condition()
            self.expect_op("}", "to close the `temporal {` block")
            return A.TemporalBlock(cond, **self._pos(t))
        parts, first = self.parse_path()
        if self.at_op("::"):
            if self.peek().kind == STRING:
                return A.EntityLit(self.parse_entity_ref_after_path(parts), **self._pos(first))
            if self.peek().is_op("{"):
                raise self.error(
                    "entity initializer syntax `Type::{ ... }` is not supported", first
                )
            raise self.error("expected an entity id string after `::`")
        if self.at_op("("):
            if len(parts) > 1:
                raise self.error(
                    f"`{'::'.join(parts)}(...)` calls an information provider; providers are not supported "
                    "in this implementation",
                    first,
                )
            self.advance()
            args = self.parse_expr_list(")")
            return A.Call(parts[0], args, **self._pos(first))
        if len(parts) == 1 and parts[0] in _REQUEST_VARS:
            return A.Var(parts[0], **self._pos(first))
        raise self.error(f"`{'::'.join(parts)}` is not a valid variable", first)

    def parse_record_items(self) -> List[Tuple[str, A.Expr]]:
        items: List[Tuple[str, A.Expr]] = []
        while not self.at_op("}"):
            if self.tok.kind == STRING:
                key = self.expect_string()
            else:
                key = self.expect_ident("a record key").value
            self.expect_op(":", "after the record key")
            items.append((key, self.parse_expr()))
            if self.at_op(","):
                self.advance()
                continue
            if not self.at_op("}"):
                raise self.error("expected `,` or `}` in record literal")
        self.advance()
        return items

    # ------------------------------------------------------------------ temporal: conditions
    def _try(self, fn):
        """Run ``fn``; if it signals _Backtrack, restore the position and return None.

        A ParseError propagates: it means the input is definitely wrong, not merely
        "another alternative applies", so its message must reach the user.
        """
        saved = self.i
        try:
            return fn()
        except _Backtrack:
            self.i = saved
            return None

    def parse_temporal_condition(self) -> A.TCond:
        left = self.parse_conjunct_or_since()
        while self.at_op("&&"):
            t = self.advance()
            left = A.TAnd(left, self.parse_conjunct_or_since(), **self._pos(t))
        return left

    def parse_conjunct_or_since(self) -> A.TCond:
        left = self.parse_neg_conjunct()
        if self.at_ident("since"):
            t = self.advance()
            window = self.parse_within()
            right = self.parse_atom()
            return A.Since(left, window, right, **self._pos(t))
        return left

    def parse_neg_conjunct(self) -> A.TCond:
        negs: List[Token] = []
        while self.at_op("!"):
            negs.append(self.advance())
        c = self.parse_conjunct()
        for t in reversed(negs):
            c = A.TNot(c, **self._pos(t))
        return c

    def parse_conjunct(self) -> A.TCond:
        t = self.tok
        cmp = self._try(self.parse_comparison)
        if cmp is not None:
            return cmp
        if self.at_op("("):
            self.advance()
            c = self.parse_temporal_condition()
            self.expect_op(")", "to close the parenthesised temporal condition")
            return c
        if self.at_ident("formerly") or self.at_ident("previous"):
            self.advance()
            window = self.parse_within()
            body = self.parse_atom()
            cls = A.Formerly if t.value == "formerly" else A.Previous
            return cls(window, body, **self._pos(t))
        if self.at_ident("exists"):
            self.advance()
            var, ty = self.parse_typed_binder()
            self.expect_op(".", "after the `exists` binder")
            body = self.parse_temporal_condition()
            return A.Exists(var, ty, body, **self._pos(t))
        if self.at_ident("tp") and self.peek().is_op("("):
            self.advance()
            self.advance()
            var = self.parse_binder_slot()
            self.expect_op(")")
            return A.Tp(var, **self._pos(t))
        if t.kind == IDENT and self.peek().is_op("(") and t.value not in _TEMPORAL_KEYWORDS:
            return self.parse_tcall()
        ref = self._try(self.parse_refinable)
        if ref is not None:
            return ref
        found = t.value if t.kind != EOF_KIND else "end of input"
        raise self.error(f"expected a temporal condition, found `{found}`", t)

    def parse_atom(self) -> A.TCond:
        """``( condition ) | tp(..) | call | refinable | comparison`` -- no bare `&&` chain."""
        t = self.tok
        if self.at_op("("):
            saved = self.i
            cmp = self._try(self.parse_comparison)
            if cmp is not None:
                return cmp
            self.i = saved
            self.advance()
            c = self.parse_temporal_condition()
            self.expect_op(")", "to close the parenthesised temporal condition")
            return c
        if self.at_ident("tp") and self.peek().is_op("("):
            self.advance()
            self.advance()
            var = self.parse_binder_slot()
            self.expect_op(")")
            return A.Tp(var, **self._pos(t))
        cmp = self._try(self.parse_comparison)
        if cmp is not None:
            return cmp
        if t.kind == IDENT and self.peek().is_op("(") and t.value not in _TEMPORAL_KEYWORDS:
            return self.parse_tcall()
        ref = self._try(self.parse_refinable)
        if ref is not None:
            return ref
        found = t.value if t.kind != EOF_KIND else "end of input"
        raise self.error(
            f"expected a temporal atom (predicate, `(...)`, `tp(...)`, call or comparison), found `{found}`",
            t,
        )

    def parse_within(self) -> Any:
        if not self.at_ident("within"):
            raise self.error("temporal operators need a `within <interval>` window")
        self.advance()
        if self.tok.kind == PARAM:
            t = self.advance()
            if not self.in_macro:
                raise self.error(
                    f"`?{t.value}` is a macro parameter and is only valid inside a macro body", t
                )
            return A.IntervalParam(t.value, **self._pos(t))
        return self.parse_interval()

    def parse_interval(self) -> A.Interval:
        t = self.tok
        neg = False
        if self.at_op("-"):
            neg = True
            self.advance()
        if self.tok.kind != INT:
            raise self.error("expected an interval such as `1h`, `30m`, `10s` or `1d`")
        amount = int(self.advance().value)
        if self.tok.kind != IDENT or self.tok.value not in _TIME_UNITS:
            raise self.error("an interval needs a unit: `s`, `m`, `h` or `d`")
        unit = self.advance().value
        if neg:
            raise self.error("a window interval must not be negative", t)
        return A.Interval(amount * _TIME_UNITS[unit], f"{amount}{unit}", **self._pos(t))

    def parse_typed_binder(self) -> Tuple[A.Term, str]:
        self.expect_op("(", "to open a typed binder `(x: Type)`")
        var = self.parse_binder_slot()
        self.expect_op(":", "in the typed binder (`(x: Type)`)")
        parts, _ = self.parse_path()
        self.expect_op(")", "to close the typed binder")
        return var, "::".join(parts)

    def parse_binder_slot(self) -> A.Term:
        t = self.tok
        if t.kind == PARAM:
            self.advance()
            return A.TParam(t.value, **self._pos(t))
        if t.kind == BINDER:
            self.advance()
            return A.TBinder(t.value, **self._pos(t))
        name = self.expect_ident("a variable name").value
        return A.TVar(name, **self._pos(t))

    # ------------------------------------------------------------------ temporal: predicates, calls
    def parse_refinable(self) -> A.TCond:
        t = self.tok
        base: A.TCond
        if t.kind == PARAM:
            self.advance()
            base = A.TParamCond(t.value, **self._pos(t))
            if not self.at_op("{"):
                # a bare `?s` in condition position (macro body); no refinement blocks
                return base
        else:
            base = self.parse_predicate()
        blocks: List[List[Tuple[List[str], A.Term]]] = []
        while self.at_op("{"):
            self.advance()
            blocks.append(self.parse_named_args())
        if blocks:
            return A.Refined(base, blocks, **self._pos(t))
        return base

    def parse_predicate(self) -> A.Pred:
        t = self.tok
        if t.kind != IDENT:
            raise _Backtrack()
        parts, _ = self.parse_path()
        if not (self.at_op("::") and self.peek().kind == STRING):
            raise _Backtrack()
        self.advance()
        atok = self.advance()
        action = self._str(atok)
        if not self.at_op("::"):
            raise _Backtrack()
        self.advance()
        kind = self.expect_ident("an event kind after `::`").value
        self.expect_op("{", "to open the predicate's field patterns")
        args = self.parse_named_args()
        return A.Pred(parts, action, kind, args, **self._pos(t))

    def parse_named_args(self) -> List[Tuple[List[str], A.Term]]:
        """Parse ``field.path: term, ...`` up to and including the closing ``}``."""
        args: List[Tuple[List[str], A.Term]] = []
        while not self.at_op("}"):
            path = [self.expect_ident("a field name").value]
            while self.at_op("."):
                self.advance()
                path.append(self.expect_ident("a field name after `.`").value)
            self.expect_op(":", "after the field path")
            term = self.parse_term()
            if isinstance(term, A.TArray):
                raise self.error(
                    'temporal predicate arguments cannot contain array constants (e.g. `field: ["a", "b"]`); '
                    "use scalar values or `context` field references instead",
                    self.toks[self.i - 1],
                )
            args.append((path, term))
            if self.at_op(","):
                self.advance()
                continue
            if not self.at_op("}"):
                raise self.error("expected `,` or `}` in the field patterns")
        self.advance()
        return args

    def parse_tcall(self) -> A.TCall:
        t = self.expect_ident()
        self.expect_op("(")
        args = self.parse_call_args()
        return A.TCall(t.value, args, **self._pos(t))

    def parse_call_args(self) -> List[Any]:
        """``interval_lit | condition | term`` list up to and including ``)``."""
        args: List[Any] = []
        while not self.at_op(")"):
            arg: Any = None
            if (
                self.tok.kind == INT
                and self.peek().kind == IDENT
                and self.peek().value in _TIME_UNITS
            ):
                arg = self.parse_interval()
            else:
                arg = self._try(self._call_arg_condition)
                if arg is None:
                    arg = self.parse_term()
            args.append(arg)
            if self.at_op(","):
                self.advance()
                continue
            if not self.at_op(")"):
                raise self.error("expected `,` or `)` in the macro call arguments")
        self.advance()
        return args

    def _call_arg_condition(self) -> A.TCond:
        """A call argument read as a condition; anything else falls back to a term."""
        try:
            c = self.parse_temporal_condition()
        except ParseError:
            raise _Backtrack() from None
        if not (self.at_op(",") or self.at_op(")")):
            raise _Backtrack()
        return c

    def parse_comparison(self) -> A.Comparison:
        t = self.tok
        left = self.parse_term()
        if not (self.tok.kind == OP and self.tok.value in _CMP_OPS):
            raise _Backtrack()
        op = self.advance().value
        right = self.parse_term()
        return A.Comparison(op, left, right, **self._pos(t))

    # ------------------------------------------------------------------ temporal: terms
    def parse_term(self) -> A.Term:
        t = self.tok
        pos = self._pos(t)
        if t.kind == INT:
            self.advance()
            return A.TLit(int(t.value), **pos)
        if t.kind == STRING:
            self.advance()
            return A.TLit(self._str(t), **pos)
        if t.kind == PARAM:
            self.advance()
            if not self.in_macro:
                raise self.error(
                    f"`?{t.value}` is a macro parameter and is only valid inside a macro body", t
                )
            return A.TParam(t.value, **pos)
        if t.kind == BINDER:
            self.advance()
            if not self.in_macro:
                raise self.error(
                    f"`${t.value}` is a macro fresh binder and is only valid inside a macro body", t
                )
            return A.TBinder(t.value, **pos)
        if t.kind == OP:
            if t.value == "-" and self.peek().kind == INT:
                self.advance()
                n = int(self.advance().value)
                return A.TLit(-n, **pos)
            if t.value == "*":
                self.advance()
                return A.TWildcard(**pos)
            if t.value == "[":
                self.advance()
                items: List[A.Term] = []
                while not self.at_op("]"):
                    items.append(self.parse_term())
                    if self.at_op(","):
                        self.advance()
                        continue
                    if not self.at_op("]"):
                        raise self.error("expected `,` or `]` in the array term")
                self.advance()
                return A.TArray(items, **pos)
            if t.value == "(":
                # paren_agg: `( agg_expr )`
                self.advance()
                agg = self.parse_agg_expr()
                self.expect_op(")", "to close the parenthesised aggregate")
                return agg
            raise _Backtrack()
        if t.kind != IDENT:
            raise _Backtrack()
        if t.value in ("true", "false"):
            self.advance()
            return A.TLit(t.value == "true", **pos)
        if t.value == "_":
            self.advance()
            return A.TWildcard(**pos)
        if t.value == "decimal" and self.peek().is_op("("):
            self.advance()
            self.advance()
            text = self.expect_string("a decimal literal string")
            self.expect_op(")")
            return A.TLit(Decimal.parse(text), **pos)
        if self._at_aggregate() or (self.peek().is_op("(") and t.value not in _TEMPORAL_KEYWORDS):
            return self.parse_agg_expr()
        if t.value == "context":
            self.advance()
            path: List[str] = []
            while self.at_op(".") and self.peek().kind == IDENT:
                self.advance()
                path.append(self.advance().value)
            if not path:
                raise self.error(
                    "`context` must be followed by a field path (`context.input.x`)", t
                )
            return A.TContextField(path, **pos)
        if t.value in ("principal", "resource"):
            self.advance()
            path = []
            while self.at_op(".") and self.peek().kind == IDENT:
                self.advance()
                path.append(self.advance().value)
            return A.TScopeField(t.value, path, **pos)
        parts, first = self.parse_path()
        if self.at_op("::") and self.peek().kind == STRING:
            ref = self.parse_entity_ref_after_path(parts)
            if self.at_op("::"):
                raise _Backtrack()  # this is a predicate, not an entity term
            return A.TLit(ref, **pos)
        if len(parts) != 1:
            raise self.error(f"`{'::'.join(parts)}` is not a term", first)
        if parts[0] in _TEMPORAL_KEYWORDS and parts[0] not in ("count", "sum"):
            raise _Backtrack()
        return A.TVar(parts[0], **pos)

    def _at_aggregate(self) -> bool:
        """``count for`` or ``sum <slot> for`` -- otherwise `count`/`sum` are plain identifiers."""
        if self.at_ident("count"):
            return self.peek().is_ident("for")
        if self.at_ident("sum"):
            return self.peek().kind in (IDENT, PARAM, BINDER) and self.peek(2).is_ident("for")
        return False

    def parse_agg_expr(self) -> A.Term:
        t = self.tok
        pos = self._pos(t)
        if self._at_aggregate():
            kind = self.advance().value
            sum_var = None
            if kind == "sum":
                sum_var = self.parse_binder_slot()
            if not self.at_ident("for"):
                raise self.error(f"`{kind}` needs a `for (x: Type). where ...` clause")
            self.advance()
            binders = [self.parse_typed_binder()]
            while self.at_op(","):
                self.advance()
                binders.append(self.parse_typed_binder())
            self.expect_op(".", "to end the `for` binder list")
            if not self.at_ident("where"):
                raise self.error("expected `where` after the aggregation's `for` binders")
            self.advance()
            body = self.parse_temporal_condition()
            return A.TAgg(kind, sum_var, binders, body, **pos)
        if t.kind == IDENT and self.peek().is_op("(") and t.value not in _TEMPORAL_KEYWORDS:
            self.advance()
            self.advance()
            args = self.parse_call_args()
            return A.TAggCall(t.value, args, **pos)
        raise _Backtrack()

    # ------------------------------------------------------------------ top level
    def parse_policy_set(self) -> A.PolicySetAst:
        policies: List[A.Policy] = []
        macros: List[A.MacroDef] = []
        start = self.tok
        while self.tok.kind != EOF_KIND:
            if self.at_ident("def"):
                macros.append(self.parse_def())
            elif self.at_op("@") or self.tok.kind == IDENT:
                p = self.parse_policy()
                p.index = len(policies)
                policies.append(p)
            else:
                raise self.error(f"expected a policy or a `def`, found `{self.tok.value}`")
        return A.PolicySetAst(policies, macros, **self._pos(start))

    def parse_def(self) -> A.MacroDef:
        t = self.advance()  # def
        kind_tok = self.expect_ident("`cedar` or `temporal` after `def`")
        if kind_tok.value not in ("cedar", "temporal"):
            raise self.error(
                f"macro kind must be `cedar` or `temporal`, found `{kind_tok.value}`", kind_tok
            )
        name = self.expect_ident("a macro name").value
        self.expect_op("(", "to open the macro parameter list")
        params: List[str] = []
        while not self.at_op(")"):
            if self.tok.kind != PARAM:
                raise self.error("macro parameters are written `?name`")
            params.append(self.advance().value)
            if self.at_op(","):
                self.advance()
                continue
            if not self.at_op(")"):
                raise self.error("expected `,` or `)` in the macro parameter list")
        self.advance()
        self.expect_op("{", "to open the macro body")
        self.in_macro = True
        try:
            body: Any
            if kind_tok.value == "cedar":
                body = self.parse_expr()
            else:
                saved = self.i
                body = self._try(self._def_temporal_condition_body)
                if body is None:
                    self.i = saved
                    body = self.parse_agg_expr()
        finally:
            self.in_macro = False
        self.expect_op("}", "to close the macro body")
        self.expect_op(";", "after the macro definition")
        return A.MacroDef(kind_tok.value, name, params, body, **self._pos(t))

    def _def_temporal_condition_body(self) -> A.TCond:
        try:
            c = self.parse_temporal_condition()
        except ParseError:
            raise _Backtrack() from None
        if not self.at_op("}"):
            raise _Backtrack()
        return c

    def parse_policy(self) -> A.Policy:
        start = self.tok
        annotations: List[Tuple[str, Optional[str]]] = []
        while self.at_op("@"):
            self.advance()
            key = self.expect_ident("an annotation key after `@`").value
            value: Optional[str] = None
            if self.at_op("("):
                self.advance()
                value = self.expect_string("an annotation value string")
                self.expect_op(")")
            annotations.append((key, value))
        eff = self.expect_ident("`permit` or `forbid`")
        if eff.value not in ("permit", "forbid"):
            raise self.error(
                f"policy effect must be `permit` or `forbid`, found `{eff.value}`", eff
            )
        self.expect_op("(", "to open the policy scope")
        scope = self.parse_scope()
        conditions: List[A.Condition] = []
        while not self.at_op(";"):
            conditions.append(self.parse_condition())
        self.advance()
        return A.Policy(
            eff.value,
            annotations,
            scope["principal"],
            scope["action"],
            scope["resource"],
            conditions,
            **self._pos(start),
        )

    def parse_condition(self) -> A.Condition:
        kw = self.tok
        if kw.kind != IDENT:
            found = kw.value if kw.kind != EOF_KIND else "end of input"
            raise self.error(f"expected `when`, `unless` or `;`, found `{found}`")
        if kw.value not in ("when", "unless"):
            raise self.error(f"condition keyword must be `when` or `unless`, found `{kw.value}`")
        self.advance()
        if self.at_ident("temporal") and self.peek().is_op("{"):
            t = self.advance()
            self.advance()
            cond = self.parse_temporal_condition()
            self.expect_op("}", "to close the `temporal {` clause")
            return A.Condition(kw.value, A.TemporalBlock(cond, **self._pos(t)), **self._pos(kw))
        if self.at_ident("guardrails") and self.peek().is_op("{"):
            self.advance()
        self.expect_op("{", "to open the condition body")
        body = self.parse_expr()
        self.expect_op("}", "to close the condition body")
        return A.Condition(kw.value, body, **self._pos(kw))

    def parse_scope(self) -> dict:
        seen: dict = {}
        while not self.at_op(")"):
            t = self.tok
            if t.kind != IDENT:
                raise self.error("expected `principal`, `action` or `resource` in the scope")
            if t.value not in ("principal", "action", "resource"):
                if len(seen) == 3:
                    raise self.error(
                        f"this policy has an extra element in the scope: `{t.value}`", t
                    )
                raise self.error(
                    f"unexpected scope variable `{t.value}`; expected `principal`, `action`, or `resource`",
                    t,
                )
            if t.value in seen:
                raise self.error(f"duplicate `{t.value}` in scope", t)
            self.advance()
            seen[t.value] = self.parse_scope_constraint(t)
            if self.at_op(","):
                self.advance()
                continue
            if not self.at_op(")"):
                raise self.error("expected `,` or `)` in the policy scope")
        self.advance()
        for var in ("principal", "action", "resource"):
            seen.setdefault(var, A.ScopeConstraint(var))
        return seen

    def parse_scope_constraint(self, var_tok: Token) -> A.ScopeConstraint:
        var = var_tok.value
        c = A.ScopeConstraint(var, **self._pos(var_tok))
        if self.at_op(":"):
            raise self.error(f"the `{var} : Type` scope form is not supported; use `{var} is Type`")
        if self.at_ident("is"):
            if var == "action":
                raise self.error("`action is Type` is not valid in the action scope")
            self.advance()
            parts, _ = self.parse_path()
            c.op = "is"
            c.entity_type = "::".join(parts)
            if self.at_ident("in"):
                self.advance()
                c.op = "is_in"
                self._scope_operand(c)
            elif self.tok.kind == OP and self.tok.value in _REL_OPS:
                raise self.error(
                    f"`is Type {self.tok.value} ...` is not valid; only `is Type in ...` is allowed"
                )
            return c
        if self.at_op(",") or self.at_op(")"):
            return c
        if self.at_op("="):
            raise self.error("`=` is not a valid operator in this scope; did you mean `==`?")
        if self.at_op("=="):
            self.advance()
            c.op = "eq"
            if var == "action":
                if self.tok.kind == PARAM:
                    raise self.error("template slots are not allowed in the action scope")
                c.entity = self.parse_entity_ref('an action reference (`Ns::Action::"id"`)')
                self._check_action_ref(c.entity)
            else:
                self._scope_operand(c)
            return c
        if self.at_ident("in"):
            self.advance()
            c.op = "in"
            if var == "action":
                refs: List[EntityRef] = []
                if self.at_op("["):
                    self.advance()
                    while not self.at_op("]"):
                        refs.append(
                            self.parse_entity_ref('an action reference (`Ns::Action::"id"`)')
                        )
                        if self.at_op(","):
                            self.advance()
                            continue
                        if not self.at_op("]"):
                            raise self.error("expected `,` or `]` in the action list")
                    self.advance()
                else:
                    if self.tok.kind == PARAM:
                        raise self.error("template slots are not allowed in the action scope")
                    refs.append(self.parse_entity_ref('an action reference (`Ns::Action::"id"`)'))
                for r in refs:
                    self._check_action_ref(r)
                c.entities = refs
            else:
                self._scope_operand(c)
            return c
        if self.tok.kind == OP and self.tok.value in _REL_OPS:
            raise self.error(f"scope only allows `==` or `in`, found `{self.tok.value}`")
        raise self.error(f"scope only allows `==` or `in`, found `{self.tok.value}`")

    def _scope_operand(self, c: A.ScopeConstraint) -> None:
        if self.tok.kind == PARAM:
            t = self.advance()
            if t.value not in ("principal", "resource"):
                raise self.error(
                    f"`?{t.value}` is not a template slot (`?principal` / `?resource`)", t
                )
            c.slot = t.value
            return
        c.entity = self.parse_entity_ref(
            'an entity reference (`Ns::Type::"id"`) or a template slot (`?principal`)'
        )

    def _check_action_ref(self, ref: EntityRef) -> None:
        if ref.base_type != "Action":
            raise self.error(
                f'action scope expects an action reference (`Ns::Action::"id"`), found `{ref}`'
            )


# ---------------------------------------------------------------------- entry points
def parse_policy_set(text: str, source: str = "") -> A.PolicySetAst:
    """Parse a whole ``.dw`` source into its AST (no macro expansion yet)."""
    p = Parser(text, source)
    return p.parse_policy_set()


def parse_expression(text: str, source: str = "") -> A.Expr:
    """Parse a standalone Cedar expression (used by tests and the CLI)."""
    p = Parser(text, source)
    e = p.parse_expr()
    if p.tok.kind != EOF_KIND:
        raise p.error(f"unexpected `{p.tok.value}` after the expression")
    return e


def parse_temporal(text: str, source: str = "", in_macro: bool = False) -> A.TCond:
    """Parse a standalone temporal condition."""
    p = Parser(text, source)
    p.in_macro = in_macro
    c = p.parse_temporal_condition()
    if p.tok.kind != EOF_KIND:
        raise p.error(f"unexpected `{p.tok.value}` after the temporal condition")
    return c
