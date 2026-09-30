"""``python -m strands_inspect.dogwood`` -- check, replay and explain Dogwood policies.

    python -m strands_inspect.dogwood check policy.dw [--schema s.cedarschema]
    python -m strands_inspect.dogwood replay policy.dw trace.log [--schema ...] [--event-schema e.dwschema]
                                             [--macros m.dw] [--style corpus|cli] [--unpinned]
    python -m strands_inspect.dogwood explain policy.dw

``check`` parses and expands macros (exit 2 on a rejected policy). ``replay`` prints the
verdict stream. ``explain`` lists every rule with the Inspect actions its scope covers.
Without ``--schema`` the Inspect action schema of strands-inspect is used.
"""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from .authorizer import PolicySet, replay
from .bridge import DogwoodPolicy
from .errors import DogwoodError
from .event_schema import DEFAULT_EVENT_SCHEMA, UNPINNED_EVENT_SCHEMA, parse_event_schema
from .inspect_schema import ACTIONS, inspect_schema
from .projection import project_to_kernel
from .schema import parse_schema


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _schema(path: Optional[str]):
    return parse_schema(_read(path), path) if path else inspect_schema()


def cmd_check(a: argparse.Namespace) -> int:
    ps = PolicySet.parse(
        _read(a.policy), _schema(a.schema), a.policy, _read(a.macros) if a.macros else None
    )
    print(
        f"OK: {len(ps.policies)} rule(s), {len(ps.temporal_blocks())} temporal leaf/leaves: {', '.join(ps.labels)}"
    )
    return 0


def cmd_replay(a: argparse.Namespace) -> int:
    es = (
        parse_event_schema(_read(a.event_schema))
        if a.event_schema
        else (UNPINNED_EVENT_SCHEMA if a.unpinned else DEFAULT_EVENT_SCHEMA)
    )
    out = replay(
        _read(a.policy),
        _read(a.trace),
        _schema(a.schema),
        macros=_read(a.macros) if a.macros else None,
        event_schema=es,
        style=a.style,
    )
    print(out)
    return 0


def cmd_explain(a: argparse.Namespace) -> int:
    pol = DogwoodPolicy.from_file(a.policy)
    ps = pol.policy_set
    print(f"# {a.policy}: {len(ps.policies)} rule(s)")
    for p in ps.policies:
        covered = ps.actions_covered(p)
        names = [r.id for r in covered] if covered is not None else list(ACTIONS)
        conds = ", ".join(
            c.kind + (" temporal" if type(c.body).__name__ == "TemporalBlock" else "")
            for c in p.conditions
        )
        ask = " (@ask)" if pol.asks(p.label) else ""
        print(
            f"- {p.effect:6} {p.label}{ask}: {len(names)} action(s) [{', '.join(names)}]"
            + (f"; {conds}" if conds else "")
        )
    print("# @lock projection:", project_to_kernel(ps))
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m strands_inspect.dogwood",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check")
    c.add_argument("policy")
    c.add_argument("--schema")
    c.add_argument("--macros")
    r = sub.add_parser("replay")
    r.add_argument("policy")
    r.add_argument("trace")
    r.add_argument("--schema")
    r.add_argument("--event-schema")
    r.add_argument("--macros")
    r.add_argument("--style", choices=("corpus", "cli"), default="cli")
    r.add_argument(
        "--unpinned",
        action="store_true",
        help="global-trace semantics (the corpus harness default)",
    )
    e = sub.add_parser("explain")
    e.add_argument("policy")
    a = ap.parse_args(argv)
    try:
        return {"check": cmd_check, "replay": cmd_replay, "explain": cmd_explain}[a.cmd](a)
    except DogwoodError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
