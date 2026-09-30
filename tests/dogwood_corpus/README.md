# Vendored Dogwood conformance corpus

Copied from https://github.com/dogwood-policy/dogwood at commit `996d756de1013b7ae209a14f566a80375a59f2f0`
(Apache-2.0; see LICENSE and NOTICE alongside). Regenerate with
`python scripts/dogwood_corpus.py sync <checkout>`; run with `python scripts/dogwood_corpus.py run`
or `pytest tests/test_dogwood_conformance.py`.

- `examples/`: 38 cases
- `macros/`: 154 cases
- `mixed/`: 18 cases
- `temporal_only/`: 160 cases

Expected outputs are the reference interpreter's and are never edited here.
