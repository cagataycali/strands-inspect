"""Conformance: the vendored Dogwood corpus (tests/dogwood_corpus/) replays byte-identically.

Every case is one pytest item so a regression names the case. The reference interpreter's
expected outputs are the oracle and are never edited here (scripts/dogwood_corpus.py sync).
"""

import glob
import os
import sys

import pytest

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")
)
from dogwood_corpus import CORPUS_DIR, FAMILIES, run_case, run_example  # noqa: E402

SHARED = os.path.join(CORPUS_DIR, "shared_schema.cedarschema")


def _cases():
    out = []
    for fam in FAMILIES:
        for d in sorted(glob.glob(os.path.join(CORPUS_DIR, fam, "*"))):
            out.append(pytest.param(fam, d, id=f"{fam}/{os.path.basename(d)}"))
    return out


def _examples():
    return [
        pytest.param(d, id=f"examples/{os.path.basename(d)}")
        for d in sorted(glob.glob(os.path.join(CORPUS_DIR, "examples", "*")))
    ]


def test_corpus_is_vendored_with_its_licence_and_commit():
    for name in ("LICENSE", "NOTICE", "README.md", "shared_schema.cedarschema"):
        assert os.path.exists(os.path.join(CORPUS_DIR, name)), name
    with open(os.path.join(CORPUS_DIR, "README.md"), encoding="utf-8") as fh:
        assert "996d756de1013b7ae209a14f566a80375a59f2f0" in fh.read()
    assert len(glob.glob(os.path.join(CORPUS_DIR, "temporal_only", "*"))) >= 120


@pytest.mark.parametrize("fam, case_dir", _cases())
def test_corpus_case_verdict_stream_is_byte_identical(fam, case_dir):
    results = run_case(case_dir, SHARED)
    assert results, "case has no trace/expected pair"
    bad = [(c, r) for c, r in results if r != "ok"]
    assert not bad, bad


@pytest.mark.parametrize("example_dir", _examples())
def test_docs_example_replays_in_cli_style(example_dir):
    name, verdict = run_example(example_dir)
    assert verdict == "ok", (name, verdict)
