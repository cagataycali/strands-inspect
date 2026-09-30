"""Error types raised by the Dogwood implementation.

Every error carries a ``line`` and ``col`` (1-based) when the source position is
known, so a message reads ``policy.dw:3:14: ...``.
"""

from __future__ import annotations


class DogwoodError(Exception):
    """Base class for every Dogwood error (parse, expansion, schema, evaluation)."""

    def __init__(self, message: str, line: int = 0, col: int = 0, source: str = ""):
        self.message = message
        self.line = line
        self.col = col
        self.source = source
        super().__init__(self._render())

    def _render(self) -> str:
        where = ""
        if self.line:
            where = f"{self.line}:{self.col}: "
        if self.source:
            where = f"{self.source}:{where}"
        return f"{where}{self.message}"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self._render()


class LexError(DogwoodError):
    """The source text could not be tokenised."""


class ParseError(DogwoodError):
    """The token stream is not a well-formed Dogwood policy set."""


class MacroError(DogwoodError):
    """A macro definition or call is invalid (arity, kind, shape, recursion)."""


class SchemaError(DogwoodError):
    """A ``.cedarschema`` text is malformed or a reference does not resolve."""


class EvalError(DogwoodError):
    """A Cedar or temporal evaluation failed (type error, missing attribute, overflow).

    An evaluation error inside a policy makes that policy *not apply*: a permit cannot
    allow and a forbid cannot deny. The authorizer records the message in
    ``Response.errors`` (fail-closed).
    """


class TraceError(DogwoodError):
    """A ``.log`` trace line is malformed."""
