"""Dogwood: the policy language of strands-inspect (pure Python, stdlib only).

Dogwood (https://github.com/dogwood-policy/dogwood) is a Cedar-derived policy language
with temporal conditions. This package implements it without dependencies and proves
itself against the reference conformance corpus (see tests/dogwood_corpus/).
"""

from .errors import (
    DogwoodError,
    EvalError,
    LexError,
    MacroError,
    ParseError,
    SchemaError,
    TraceError,
)

__all__ = [
    "DogwoodError",
    "EvalError",
    "LexError",
    "MacroError",
    "ParseError",
    "SchemaError",
    "TraceError",
]
