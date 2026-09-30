"""Dogwood: the policy language of strands-inspect (pure Python, stdlib only).

Dogwood (https://github.com/dogwood-policy/dogwood) is a Cedar-derived policy language
with temporal conditions. This package implements it without dependencies and proves
itself against the reference conformance corpus (tests/dogwood_corpus/).

    from strands_inspect import dogwood
    policy = dogwood.DogwoodPolicy.parse(source)          # bound to the Inspect schema
    verdicts = dogwood.replay(policy_src, trace_text)      # the reference corpus format
    schema = dogwood.parse_schema(cedarschema_text)
"""

from .authorizer import Authorizer, Event, PolicySet, Response, replay
from .bridge import PRESETS, DogwoodBridge, DogwoodPolicy, Verdict, build_input, fields_from_detail
from .errors import (
    DogwoodError,
    EvalError,
    LexError,
    MacroError,
    ParseError,
    SchemaError,
    TraceError,
)
from .event_schema import (
    DEFAULT_EVENT_SCHEMA,
    UNPINNED_EVENT_SCHEMA,
    EventSchema,
    parse_event_schema,
)
from .inspect_schema import ACTIONS, INSPECT_SCHEMA_TEXT, classify_sensitive, inspect_schema
from .parser import parse_policy_set
from .projection import project_to_kernel
from .schema import Schema, parse_schema
from .trace import parse_trace

__all__ = [
    "ACTIONS",
    "Authorizer",
    "DEFAULT_EVENT_SCHEMA",
    "DogwoodBridge",
    "DogwoodError",
    "DogwoodPolicy",
    "EvalError",
    "Event",
    "EventSchema",
    "INSPECT_SCHEMA_TEXT",
    "LexError",
    "MacroError",
    "PRESETS",
    "ParseError",
    "PolicySet",
    "Response",
    "Schema",
    "SchemaError",
    "TraceError",
    "UNPINNED_EVENT_SCHEMA",
    "Verdict",
    "build_input",
    "classify_sensitive",
    "fields_from_detail",
    "inspect_schema",
    "parse_event_schema",
    "parse_policy_set",
    "parse_schema",
    "parse_trace",
    "project_to_kernel",
    "replay",
]
