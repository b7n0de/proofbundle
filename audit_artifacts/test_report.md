# Phase B test report

Commands, results, and known gaps. Run on the repo `.venv` (Python 3.13; CI matrix 3.10–3.14).

## Commands & results

| Command | Result |
|---|---|
| `.venv/bin/python -m pytest tests/ -q` | **533 passed**, 1 warning (the intentional experimental-preview import warning) |
| `.venv/bin/ruff check src/ tests/` | All checks passed |
| `.venv/bin/mypy src/proofbundle/` | Success: no issues found (41 source files) |
| `.venv/bin/python -m proofbundle.cli verify <receipt> --policy <pass>` | `POLICY: OK`, exit 0 |
| `.venv/bin/python -m proofbundle.cli verify <receipt> --policy <fail>` | `POLICY: FAIL (...)`, **exit 3** |
| `.venv/bin/python -m proofbundle.cli verify <malformed-policy>` | exit 2 |
| `.venv/bin/python -m proofbundle.cli verify <deep-nested.json>` | exit 2 (RecursionError guarded, no traceback) |

## Coverage by work package

- **WP-B1**: `test_cli.py` (`--version` CLI + process-boundary + feature-probe determinism),
  `test_bundle.py`/`test_docs_truth.py` (hash_alg required at both call sites, SPEC↔constant sync).
- **WP-B2**: `test_ok_semantics.py` — exit-code matrix (pure fn + CLI 0/1/2), labelled output (no bare
  `=> OK`), full JSON field contract (present + null-not-true), SD-JWT real-True path + red counters,
  ASSURANCE injection neutralised, error-path field contract, crypto-fail message, deep-JSON exit 2.
- **WP-B3**: `test_trust_policy.py` — fail-closed parse (unknown top-level + nested fields, wrong
  schema, missing policy_id, bad enum, negative age); each check pass/fail (signer/alg/schema/hash/
  status-fail-closed/assurance/prereg/freshness); CLI exit 0/1/2/3; missing-policy NOT_EVALUATED;
  aud/policy ambiguity exit 2; crypto-fail → policy-not-checked; schema↔example↔parser consistency;
  field-order property.

## Mutation / adversarial

- Each WP ran a six-lens adversarial pre-land review (Claude subagents): a lens forces a mutation
  (e.g. a JSON field → null, or `all()` → `any()`) and confirms a test catches it. WP-B2's L5 found a
  mutation gap (SD-JWT fields untested on the True path) — closed with a real key-bound presentation
  test. Findings + fixes in `cross_lens_reviews.md`.
- Repo mutation gate (`mutmut`, CI `mutation` job) passed on WP-B1/B2 (green on PR #39/#40).

## Known gaps (honest)

- Other verify subcommands (`verify-proof`/`show-eval`/`verify-enclave`/…) keep their bare `=> OK`;
  they carry per-check `[PASS]` lines but are not yet under the CRYPTO/POLICY split (WP-B2 scope was
  the core `verify`).
- Trust-policy `status` section is declared but not enforceable in `verify --policy` v0.1 (no snapshot
  input) — it fails closed; a later phase wires a status input.
- Full release gate (mutation + property/fuzz + `proofbundle demo` + offline-verify assertion) is run
  at Release 2.0.0 (§5), pending WP-B3 land.
