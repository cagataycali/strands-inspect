"""Macro expansion (placeholder until step 5: passes ASTs without macros through)."""

from __future__ import annotations

from typing import Optional

from . import ast as A
from .errors import MacroError


def expand_policy_set(
    ast: A.PolicySetAst, extra_macro_source: Optional[str] = None, source: str = ""
) -> A.PolicySetAst:
    if ast.macros or extra_macro_source:
        raise MacroError("macro expansion is not implemented yet", source=source)
    return ast
