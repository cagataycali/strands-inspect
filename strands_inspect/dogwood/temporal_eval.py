"""Temporal engine (placeholder until step 4)."""

from __future__ import annotations

from .errors import EvalError


class TemporalEngine:
    def __init__(self, policy_set, schema):
        self.policy_set = policy_set
        self.schema = schema

    def observe(self, event) -> None:
        pass

    def evaluate(self, policy, block, event, request, store) -> bool:
        raise EvalError("temporal evaluation is not implemented yet")
