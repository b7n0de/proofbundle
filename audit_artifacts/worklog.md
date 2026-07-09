# Phase B worklog — P0 core (hash_alg / SPEC-revision / OK-semantics / trust policy) → 2.0.0

Per-WP: finding, patch, tests, commits. Evidence-bound (SHA, testname, exit code). Live-verified on
the repo `.venv` (proofbundle 1.9.2 backing crypto; the tree under test is the 2.0.0 line).

## WP-B1 — `merkle.hash_alg` REQUIRED + `SPEC_REVISION` + extended `--version` (closes #28)

- **Finding**: SPEC.md §5 said `hash_alg: required no` while the verifier already rejected a missing
  value since v1.6 — a doc/schema-vs-code contradiction; `--version` printed only one line (#28 open).
- **Patch**: SPEC.md §5 → `required yes` + anti-alg-confusion MUST; schema adds `hash_alg` to
  `merkle.required`; shared `_require_hash_alg` helper (presence + value) used by both `verify_bundle`
  and `recompute_merkle_root_b64`; `SPEC_REVISION` constant kept in sync with SPEC.md by a doc-truth
  test; `--version` → 4-line block (version / spec-revision / schema / features, fail-safe probes).
- **Tests**: missing/empty/null hash_alg rejected at both call sites; `--version` CLI + process-boundary;
  feature-probe swallows ImportError/AttributeError/generic (deterministic patch).
- **Commits**: merged as **PR #39** (`9dfe5a8`). Verify-lens review before land (3 findings fixed:
  feature-probe caught only ImportError; #28 mis-attribution; shared-helper dedupe).

## WP-B2 — CRYPTO/POLICY/ASSURANCE separation + exit-code 3 + stable JSON fields

- **Finding**: `verify` printed a bare `=> OK` — a crypto success readable as a policy pass / truth
  verdict. No stable machine-readable single-field contract; exit codes were 0/1/2 only.
- **Patch**: labelled block `CRYPTO:` / `POLICY: NOT_EVALUATED` / `ASSURANCE: <verbatim>` /
  `LIMITATIONS:`; `--json` single-field contract (null for not-applicable, never silently true);
  pure `_verify_exit_code` 0/1/2/3; THREAT_MODEL "Misuse: reading OK as truth".
- **Six-lens review — 10 findings, all fixed** (commit `3d299f5`): [HIGH] `sd_jwt_ok` silently true
  without issuer key → fail-closed null + `sd_jwt_issuer_verified`; [HIGH] ASSURANCE-line injection →
  `decode_eval_claim` enum-validates `assurance_level` + `_safe_line`; [MED] error-path field contract,
  crypto-fail vs not-eval-receipt message, RecursionError→exit2, `--policy`/exit-3 honestly WP-B3-
  pending, CHANGELOG entry, real-True-path SD-JWT tests; [LOW] "§1.4" phantom cite, Mermaid `=> OK`.
  No-fake lens: 0 overclaims.
- **Tests**: `tests/test_ok_semantics.py` (21). **Commits**: merged as **PR #40** (`853d82a`).

## WP-B3 — trust policy v0.1 + `verify --policy` (fail-closed, offline)

- **Finding**: trust was implicit (out-of-band pinning, remembered flags) — no machine-readable,
  enforceable trust decision; `docs/TRUST_ANCHORS.md` had no policy format.
- **Patch**: `schemas/trust_policy_v0_1.schema.json` (snake_case, versioned, fail-closed, offline);
  `src/proofbundle/policy.py` (`load_policy` fail-closed structural parse + `evaluate_policy` over the
  crypto result — issuer-by-public-key, alg, schema, hash_alg, SD-JWT aud/nonce/key-binding, freshness,
  assurance level + prereg); `verify --policy` (crypto first, policy over the result, never on failed
  crypto); `--json` gains `policy_ok`/`policy_id`/`policy_checks[]`; example + TRUST_ANCHORS profile +
  README quickstart. Honest boundaries: status fails closed (no snapshot input in v0.1); `--aud` vs
  policy `expected_aud` conflict = exit 2.
- **Tests**: `tests/test_trust_policy.py` (fail-closed parse, each check pass/fail, CLI exit 0/1/2/3,
  schema↔example↔parser consistency, field-order property). **Commit**: `e93620c` (+ six-lens fixes,
  see cross_lens_reviews.md). Land: PR pending.

## Aggregate

- Full suite green at each step (WP-B1 490 → WP-B2 511 → WP-B3 533+), mypy + ruff clean throughout.
- Release 2.0.0: pending WP-B3 land + release-pipeline confirmation (Phase A verified PyPI current).
