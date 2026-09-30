"""Tokeniser shared by the Cedar and temporal grammars of Dogwood.

One token stream serves both sub-languages: ``::``, ``?p`` and ``$t`` sigils, ``@``
annotations, string escapes (``\\n \\t \\r \\0 \\\\ \\" \\' \\* \\u{HEX} \\xHH``), ``//``
comments. Integers are positive at the token level (``-`` is a unary operator); the
parser folds ``1h`` from INT + IDENT when it reads an interval.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator, List, Optional

from .errors import LexError

# token kinds
IDENT = "IDENT"
INT = "INT"
STRING = "STRING"
PARAM = "PARAM"  # ?name
BINDER = "BINDER"  # $name
OP = "OP"  # punctuation and operators, .value is the text
EOF_KIND = "EOF"

_PUNCT3 = ()
_PUNCT2 = ("::", "<=", ">=", "!=", "==", "&&", "||")
_PUNCT1 = "<>=!+-*/%.,:;()[]{}@?"


@dataclass(frozen=True)
class Token:
    kind: str
    value: str
    line: int
    col: int
    pos: int  # byte offset of the first character (used for macro hygiene)

    def is_op(self, text: str) -> bool:
        return self.kind == OP and self.value == text

    def is_ident(self, text: Optional[str] = None) -> bool:
        return self.kind == IDENT and (text is None or self.value == text)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"{self.kind}({self.value!r})@{self.line}:{self.col}"


def _is_ident_start(ch: str) -> bool:
    return ch.isascii() and (ch.isalpha() or ch == "_")


def _is_ident_cont(ch: str) -> bool:
    return ch.isascii() and (ch.isalnum() or ch == "_")


def unescape(body: str, line: int, col: int, allow_star: bool = False) -> str:
    """Decode the escapes of a string-literal body (without its quotes)."""
    out: List[str] = []
    i = 0
    n = len(body)
    while i < n:
        ch = body[i]
        if ch != "\\":
            out.append(ch)
            i += 1
            continue
        i += 1
        if i >= n:
            raise LexError("unterminated escape sequence in string literal", line, col)
        e = body[i]
        i += 1
        simple = {"n": "\n", "t": "\t", "r": "\r", "0": "\0", "\\": "\\", '"': '"', "'": "'"}
        if e in simple:
            out.append(simple[e])
        elif e == "*" and allow_star:
            out.append("\\*")  # kept escaped; the `like` matcher reads it as a literal star
        elif e == "u" and i < n and body[i] == "{":
            close = body.find("}", i)
            if close < 0:
                raise LexError("unterminated `\\u{` escape in string literal", line, col)
            hexdigits = body[i + 1 : close]
            digits = hexdigits.replace("_", "")
            if (
                not digits
                or hexdigits.startswith("_")
                or not all(c in "0123456789abcdefABCDEF" for c in digits)
            ):
                raise LexError(f"invalid unicode escape `\\u{{{hexdigits}}}`", line, col)
            try:
                out.append(chr(int(digits, 16)))
            except (ValueError, OverflowError):
                raise LexError(f"invalid unicode escape `\\u{{{hexdigits}}}`", line, col) from None
            i = close + 1
        elif e == "x":
            hexs = body[i : i + 2]
            if len(hexs) == 2 and all(c in "0123456789abcdefABCDEF" for c in hexs):
                if int(hexs, 16) > 0x7F:
                    raise LexError(
                        f"the input `\\x{hexs}` is not a valid escape (ASCII range only)", line, col
                    )
                out.append(chr(int(hexs, 16)))
                i += 2
            else:
                raise LexError(
                    "invalid `\\x` escape in string literal (two hex digits required)", line, col
                )
        else:
            raise LexError(f"unknown escape `\\{e}` in string literal", line, col)
    return "".join(out)


class Lexer:
    """Turn Dogwood source text into a list of :class:`Token`."""

    def __init__(self, text: str, source: str = ""):
        self.text = text
        self.source = source
        self.pos = 0
        self.line = 1
        self.col = 1

    def _advance(self, n: int = 1) -> None:
        for _ in range(n):
            if self.text[self.pos] == "\n":
                self.line += 1
                self.col = 1
            else:
                self.col += 1
            self.pos += 1

    def _peek(self, k: int = 0) -> str:
        i = self.pos + k
        return self.text[i] if i < len(self.text) else ""

    def tokens(self) -> List[Token]:
        return list(self)

    def __iter__(self) -> Iterator[Token]:
        text = self.text
        n = len(text)
        while self.pos < n:
            ch = text[self.pos]
            if ch in " \t\r\n":
                self._advance()
                continue
            if ch == "/" and self._peek(1) == "/":
                while self.pos < n and text[self.pos] not in "\r\n":
                    self._advance()
                continue
            line, col, start = self.line, self.col, self.pos
            if _is_ident_start(ch):
                while self.pos < n and _is_ident_cont(text[self.pos]):
                    self._advance()
                yield Token(IDENT, text[start : self.pos], line, col, start)
                continue
            if ch.isdigit():
                while self.pos < n and text[self.pos].isdigit():
                    self._advance()
                yield Token(INT, text[start : self.pos], line, col, start)
                continue
            if ch == '"':
                yield self._string(line, col, start)
                continue
            if ch in "?$" and _is_ident_start(self._peek(1)):
                self._advance()
                while self.pos < n and _is_ident_cont(text[self.pos]):
                    self._advance()
                yield Token(
                    PARAM if ch == "?" else BINDER, text[start + 1 : self.pos], line, col, start
                )
                continue
            two = text[self.pos : self.pos + 2]
            if two in _PUNCT2:
                self._advance(2)
                yield Token(OP, two, line, col, start)
                continue
            if ch in _PUNCT1:
                self._advance()
                yield Token(OP, ch, line, col, start)
                continue
            raise LexError(f"unexpected character `{ch}`", line, col, self.source)
        yield Token(EOF_KIND, "", self.line, self.col, self.pos)

    def _string(self, line: int, col: int, start: int) -> Token:
        text = self.text
        n = len(text)
        self._advance()  # opening quote
        while True:
            if self.pos >= n or text[self.pos] in "\r\n":
                raise LexError("unterminated string literal", line, col, self.source)
            ch = text[self.pos]
            if ch == "\\":
                if self.pos + 1 >= n:
                    raise LexError("unterminated string literal", line, col, self.source)
                self._advance(2)
                continue
            if ch == '"':
                self._advance()
                break
            self._advance()
        # the raw body (escapes untouched); the parser decodes with `unescape`
        return Token(STRING, text[start + 1 : self.pos - 1], line, col, start)


def tokenize(text: str, source: str = "") -> List[Token]:
    """Tokenise ``text``; the last token is always EOF."""
    return Lexer(text, source).tokens()
