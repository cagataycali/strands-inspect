#!/usr/bin/env python3
"""Vendor and run the Dogwood conformance corpus.

    python scripts/dogwood_corpus.py sync <ref-checkout>     re-sync tests/dogwood_corpus/ from a
                                                              dogwood checkout (a coverage subset)
    python scripts/dogwood_corpus.py run [<corpus-dir>]      replay the vendored corpus, print counts
    python scripts/dogwood_corpus.py --all <ref-checkout>    replay the FULL reference corpus per family

Harness rules (dogwood-language/tests/passing/*/harness.rs): a case's ``policy_*.dw`` files are
concatenated in sorted order; every ``trace_N.log`` is replayed against that set and compared
with ``expected_N.out`` byte for byte; the event schema is the case's ``event.dwschema`` when
present, else the UNPINNED request/response/error schema; ``macros.dw`` is the case's macro
library. Docs examples (``dogwood-docs/examples/*``) compare in CLI style (ALLOW/DENY, verdict
index, ``[rules: ...]``). Cases that call information providers are skipped (not supported).
"""

from __future__ import annotations

import glob
import os
import re
import shutil
import sys
from typing import Dict, List, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from strands_inspect.dogwood.authorizer import replay  # noqa: E402
from strands_inspect.dogwood.errors import DogwoodError  # noqa: E402
from strands_inspect.dogwood.event_schema import (
    UNPINNED_EVENT_SCHEMA,
    parse_event_schema,
)  # noqa: E402
from strands_inspect.dogwood.schema import parse_schema  # noqa: E402

REF_COMMIT = "996d756de1013b7ae209a14f566a80375a59f2f0"
CORPUS_DIR = os.path.join(os.path.dirname(HERE), "tests", "dogwood_corpus")
FAMILIES = ("temporal_only", "macros", "mixed")
CASE_FILES = (
    "policy_*.dw",
    "trace_*.log",
    "expected_*.out",
    "schema.cedarschema",
    "event.dwschema",
    "macros.dw",
)

# temporal_only buckets: each regex must be matched by >= N vendored cases (policy text or name)
COVERAGE = {
    "formerly": (r"\bformerly\b", 40),
    "previous": (r"\bprevious\b", 15),
    "since": (r"\bsince\b", 20),
    "negation": (r"![A-Za-z(]", 15),
    "exists": (r"\bexists\b", 15),
    "tp": (r"\btp\(", 10),
    "count": (r"\bcount\b", 10),
    "sum": (r"\bsum\b", 10),
    "macros": (r"\bdef temporal\b|\bdef cedar\b|count_within|sum_within|bind\(", 5),
    "action groups": (r"action in \[", 8),
    "escapes": (r"\\\\(x|u\{|n|t|\")", 8),
    "key-local / pins": (r"pin |relativize|callerPrincipal: principal", 12),
    "decimal/datetime": (r"decimal\(|datetime\(", 5),
    "unless": (r"\bunless\b", 8),
    "custom event schema": (r"NAME:11[123]\d_", 6),
}


def read(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _case_text(d: str) -> str:
    return (
        "NAME:"
        + os.path.basename(d)
        + "\n"
        + "\n".join(read(p) for p in sorted(glob.glob(f"{d}/policy_*.dw")))
    )


def select_temporal_cases(ref: str) -> List[str]:
    """A deterministic subset of temporal_only cases covering every bucket (>= 120 cases)."""
    root = f"{ref}/dogwood-language/tests/passing/temporal_only/corpus"
    dirs = sorted(glob.glob(f"{root}/*"))
    texts = {d: _case_text(d) for d in dirs}
    chosen: List[str] = []
    for _, (rx, n) in COVERAGE.items():
        hits = [d for d in dirs if re.search(rx, texts[d])]
        step = max(1, len(hits) // n) if hits else 1
        for d in hits[::step][:n]:
            if d not in chosen:
                chosen.append(d)
    # top up with every 4th remaining case so plain permit/forbid shapes are represented too
    for d in dirs[::4]:
        if d not in chosen and len(chosen) < 160:
            chosen.append(d)
    return sorted(chosen)


def _copy_case(src: str, dst: str) -> None:
    os.makedirs(dst, exist_ok=True)
    for pat in CASE_FILES:
        for f in glob.glob(os.path.join(src, pat)):
            shutil.copy(f, dst)


def sync(ref: str) -> None:
    if os.path.isdir(CORPUS_DIR):
        shutil.rmtree(CORPUS_DIR)
    os.makedirs(CORPUS_DIR)
    shutil.copy(f"{ref}/LICENSE", os.path.join(CORPUS_DIR, "LICENSE"))
    shutil.copy(f"{ref}/NOTICE", os.path.join(CORPUS_DIR, "NOTICE"))
    shutil.copy(
        f"{ref}/dogwood-language/tests/passing/temporal_only/shared_schema.cedarschema",
        os.path.join(CORPUS_DIR, "shared_schema.cedarschema"),
    )
    counts: Dict[str, int] = {}
    for d in select_temporal_cases(ref):
        _copy_case(d, os.path.join(CORPUS_DIR, "temporal_only", os.path.basename(d)))
        counts["temporal_only"] = counts.get("temporal_only", 0) + 1
    for fam in ("macros", "mixed"):
        for d in sorted(glob.glob(f"{ref}/dogwood-language/tests/passing/{fam}/corpus/*")):
            if not glob.glob(f"{d}/trace_*.log") or _uses_providers(d):
                continue
            _copy_case(d, os.path.join(CORPUS_DIR, fam, os.path.basename(d)))
            counts[fam] = counts.get(fam, 0) + 1
    for d in sorted(glob.glob(f"{ref}/dogwood-docs/examples/*")):
        if not os.path.exists(f"{d}/trace.log") or _uses_providers(d):
            continue
        dst = os.path.join(CORPUS_DIR, "examples", os.path.basename(d))
        os.makedirs(dst, exist_ok=True)
        for name in (
            "policy.dw",
            "schema.cedarschema",
            "trace.log",
            "expected.out",
            "macros.dw",
            "event.dwschema",
        ):
            if os.path.exists(f"{d}/{name}"):
                shutil.copy(f"{d}/{name}", dst)
        counts["examples"] = counts.get("examples", 0) + 1
    with open(os.path.join(CORPUS_DIR, "README.md"), "w", encoding="utf-8") as fh:
        fh.write(
            "# Vendored Dogwood conformance corpus\n\n"
            f"Copied from https://github.com/dogwood-policy/dogwood at commit `{REF_COMMIT}`\n"
            "(Apache-2.0; see LICENSE and NOTICE alongside). Regenerate with\n"
            "`python scripts/dogwood_corpus.py sync <checkout>`; run with `python scripts/dogwood_corpus.py run`\n"
            "or `pytest tests/test_dogwood_conformance.py`.\n\n"
            + "".join(f"- `{k}/`: {v} cases\n" for k, v in sorted(counts.items()))
            + "\nExpected outputs are the reference interpreter's and are never edited here.\n"
        )
    print("synced:", counts)


def _uses_providers(d: str) -> bool:
    text = "\n".join(read(p) for p in glob.glob(f"{d}/policy*.dw"))
    return re.search(r"\b[A-Z]\w*::[A-Z]\w*\(", text) is not None


# ---------------------------------------------------------------------- running
Result = Tuple[str, str]  # (case/trace id, "ok" | "MISMATCH" | "SKIP <why>" | "ERR <msg>")


def run_case(d: str, shared_schema: Optional[str]) -> List[Result]:
    """Replay every trace of one corpus case directory."""
    name = os.path.basename(d)
    schema_file = (
        f"{d}/schema.cedarschema" if os.path.exists(f"{d}/schema.cedarschema") else shared_schema
    )
    policy = "\n".join(read(p) for p in sorted(glob.glob(f"{d}/policy_*.dw")))
    macros = read(f"{d}/macros.dw") if os.path.exists(f"{d}/macros.dw") else None
    es = (
        parse_event_schema(read(f"{d}/event.dwschema"))
        if os.path.exists(f"{d}/event.dwschema")
        else UNPINNED_EVENT_SCHEMA
    )
    out: List[Result] = []
    for tr in sorted(glob.glob(f"{d}/trace_*.log")):
        n = tr.rsplit("_", 1)[1][:-4]
        exp = f"{d}/expected_{n}.out"
        if not os.path.exists(exp):
            continue
        try:
            got = replay(
                policy, read(tr), parse_schema(read(schema_file)), macros=macros, event_schema=es
            )
        except DogwoodError as exc:
            msg = str(exc)
            out.append((f"{name}/{n}", f"SKIP providers" if "provider" in msg else f"ERR {msg}"))
            continue
        out.append((f"{name}/{n}", "ok" if got.strip() == read(exp).strip() else "MISMATCH"))
    return out


def run_example(d: str) -> Result:
    name = os.path.basename(d)
    macros = read(f"{d}/macros.dw") if os.path.exists(f"{d}/macros.dw") else None
    es = (
        parse_event_schema(read(f"{d}/event.dwschema"))
        if os.path.exists(f"{d}/event.dwschema")
        else UNPINNED_EVENT_SCHEMA
    )
    try:
        got = replay(
            read(f"{d}/policy.dw"),
            read(f"{d}/trace.log"),
            parse_schema(read(f"{d}/schema.cedarschema")),
            macros=macros,
            event_schema=es,
            style="cli",
        )
    except DogwoodError as exc:
        msg = str(exc)
        return (name, "SKIP providers" if "provider" in msg else f"ERR {msg}")
    return (name, "ok" if got.strip() == read(f"{d}/expected.out").strip() else "MISMATCH")


def run_family(root: str, fam: str, shared_schema: Optional[str]) -> List[Result]:
    if fam == "examples":
        return [
            run_example(d)
            for d in sorted(glob.glob(f"{root}/*"))
            if os.path.exists(f"{d}/trace.log")
        ]
    results: List[Result] = []
    for d in sorted(glob.glob(f"{root}/*")):
        if os.path.isdir(d):
            results.extend(run_case(d, shared_schema))
    return results


def summarize(fam: str, results: List[Result]) -> str:
    ok = sum(1 for _, r in results if r == "ok")
    skip = sum(1 for _, r in results if r.startswith("SKIP"))
    bad = [(c, r) for c, r in results if r != "ok" and not r.startswith("SKIP")]
    line = f"{fam}: {ok}/{ok + len(bad)} traces identical, {skip} skipped (providers)"
    for c, r in bad[:20]:
        line += f"\n    FAIL {c}: {r[:120]}"
    return line


def run_vendored(corpus_dir: str = CORPUS_DIR) -> Dict[str, List[Result]]:
    shared = os.path.join(corpus_dir, "shared_schema.cedarschema")
    out: Dict[str, List[Result]] = {}
    for fam in FAMILIES + ("examples",):
        root = os.path.join(corpus_dir, fam)
        if os.path.isdir(root):
            out[fam] = run_family(root, fam, shared)
    return out


def run_all(ref: str) -> Dict[str, List[Result]]:
    shared = f"{ref}/dogwood-language/tests/passing/temporal_only/shared_schema.cedarschema"
    out: Dict[str, List[Result]] = {}
    for fam in FAMILIES:
        out[fam] = run_family(f"{ref}/dogwood-language/tests/passing/{fam}/corpus", fam, shared)
    out["examples"] = run_family(f"{ref}/dogwood-docs/examples", "examples", None)
    return out


def main(argv: List[str]) -> int:
    if len(argv) >= 2 and argv[0] == "sync":
        sync(argv[1])
        return 0
    if len(argv) >= 2 and argv[0] == "--all":
        results = run_all(argv[1])
    elif argv and argv[0] == "run":
        results = run_vendored(argv[1] if len(argv) > 1 else CORPUS_DIR)
    else:
        print(__doc__)
        return 1
    failed = 0
    for fam, res in results.items():
        print(summarize(fam, res))
        failed += sum(1 for _, r in res if r != "ok" and not r.startswith("SKIP"))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
