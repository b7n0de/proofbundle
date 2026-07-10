# WP2 — universal content-root foundation — review note

Scope: the non-breaking WP2 foundation on branch `feat/wp2-content-root-foundation` (off `main`), per the
audit consolidation addendum §3. Two deliverables: ADR 0002 (design of `contentRootAlg = jcs-sha256-v1`) and
the shared `canonical.py` primitive. Explicitly **not** in scope: the eval/svr migration (T3), any CLI, any
released wire change.

## What landed

- `docs/adr/0002-universal-content-root.md` — designs the universal content root: full-Statement RFC-8785
  scope, signature bytes never in the preimage, the two-part producer/verifier rule, and a migration plan with
  an explicit **legacy mode** (`legacy-sortkeys-json-v0`) so already-signed `json.dumps(sort_keys=True)`
  receipts keep verifying. Honestly bounded: the released eval/svr default switch is a T3 / SemVer owner gate
  (part of 2.1.0), designed here, **not** activated; its P0 rejection test belongs to the activation phase.
- `src/proofbundle/canonical.py` — the shared primitive: `canonicalize_statement(obj) -> bytes`,
  `statement_content_root(obj | bytes) -> bytes` (producer canonicalize+hash / verifier hash-exact-bytes),
  `CONTENT_ROOT_ALG = "jcs-sha256-v1"`, fail-closed `CanonicalizerUnavailable`. Lazy `[eval]` extra; the base
  install and the verifier byte path pull no canonicalizer.
- `src/proofbundle/__init__.py` — additive lazy public exports of the two primitive functions.
- `tests/test_canonical.py` — 13 tests: key-order independence, idempotence, producer/verifier agreement,
  verifier-never-re-canonicalizes, signature-bytes-never-in-preimage, full-Statement scope (subject +
  predicateType, not predicate-only), fail-closed without the extra, and the public-export contract.

## Break-attempts (each is a regression test)

- **Verifier silently re-canonicalizes** → falsified: `statement_content_root(non_canonical_bytes)` roots
  differently from the object and equals `sha256(exact_bytes)`.
- **Subject / predicateType confusion (predicate-only scope)** → falsified: mutating `subject` or
  `predicateType` changes the root.
- **Signature in the preimage** → falsified: the same statement under one- vs two-signature envelopes roots
  identically (survives counter-signing / key rotation / multi-sig).
- **Silent pass without the canonicalizer** → falsified: the producer path raises `CanonicalizerUnavailable`
  (not a raw `ImportError`, never a silent non-canonical hash); the verifier byte path stays a plain SHA-256.

## Honest rest-item (No-Fake)

The addendum's part-2 wording "decision.py MUST use the primitive (pure refactor)" was initially deferred
because `decision.py` (and `docs/predicates/decision-receipt.md`) lived only on the then-unmerged PR #45
branch, not on `main`. **Update:** PR #45 is now merged to `main`; this branch was rebased onto it and the
decision.py adoption is **done on this branch** (commit `6647f06`): `decision.py._rfc8785_bytes` delegates to
`canonical.canonicalize_statement` (catching `CanonicalizerUnavailable` to keep its identical
`DecisionReceiptError` message) and `anchors.statement_content_root` (bytes→root) delegates to
`canonical.statement_content_root` — byte-identical, no wire change, proven by an old-vs-new comparison over
14 adversarial statements plus the full `test_decision_*` suite unchanged green (637 tests).

## Checks

- `python -m unittest discover -s tests`: 563 passed (550 baseline + 13 new), no regression.
- `ruff check .`: clean. `mypy src` (CI parity): clean.
