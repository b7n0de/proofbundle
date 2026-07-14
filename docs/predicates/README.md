# proofbundle predicates

Each predicate is a vendored in-toto `predicateType` under the `b7n0de.com/proofbundle/predicates/` namespace,
carried in a DSSE (Ed25519) Statement and verified against the exact signed bytes by a hand-rolled fail-closed
validator (the JSON Schemas under [`schemas/`](../../schemas/) are docs-only and never gate a verdict). Every
predicate widens the attestation surface, so each states its **non-claims** as explicitly as its guarantees.

## Predicates

| predicate | status | one line | doc |
|---|---|---|---|
| `eval-result/v0.1` | shipped | an eval number is authored and integral (never that it is *true*) | see SPEC.md |
| `decision-receipt/v0.1` | shipped (2.1.0) | this gate made this verdict over this evidence (never that it was *correct*) | [decision-receipt.md](decision-receipt.md) |
| `action-outcome/v0.1` | EXPERIMENTAL (3.2.0) | this executor did this, bound to a decision, with role separation + `execution_proven` | [action-outcome.md](action-outcome.md) |
| `trust-pack/v0.1` | EXPERIMENTAL (3.2.0) | a TUF-inspired role→key trust root: threshold-of-root, revocation, monotone version, rollback protection | [trust-pack.md](trust-pack.md) |
| `verification-summary/v0.1` | EXPERIMENTAL (3.2.0) | per-level (eval/decision/outcome) receiptRef + status + evidenceClass, with mandatory `nonClaims` | [verification-summary.md](verification-summary.md) |
| `run-ledger/v0.1` | EXPERIMENTAL (3.2.0) | a monotone, prevDigest-chained run history (aborted runs kept visible) against best-of-many cherry-picking | [run-ledger.md](run-ledger.md) |

**Content-root coupling (one-directional):** an outcome references its decision, a decision references its
evidence — never the reverse. Each `*.digest.sha256` is the SHA-256 over the referenced Statement's exact
RFC-8785 canonical bytes (the same rule an anchor root uses), never a re-canonicalized recomputation. See
[ADR 0002](../adr/0002-universal-content-root.md).

## Profile / helper layers (3.2.0 EXPERIMENTAL — NOT predicates)

These operate over predicates or over C2SP checkpoints; they are verification layers, not signed claim types:

- **public-transparency** ([`public_transparency.py`](../../src/proofbundle/public_transparency.py)) — a
  relying-party policy over the checkpoint primitives producing one verdict with named statuses (LOG_ORIGIN,
  CHECKPOINT_SIGNATURE, ROOT_BYTES_AUTHENTICITY, TREE_CONTEXT_AUTHENTICITY, CONSISTENCY, WITNESS_QUORUM,
  PUBLIC_TRANSPARENCY). Fail-closed: a required-but-unevaluable check is FAIL, an optional un-requested check is
  NOT_EVALUATED and stays visible.
- **subject-binding** ([`subject_binding.py`](../../src/proofbundle/subject_binding.py) ·
  [doc](../SUBJECT_BINDING.md)) — classifies a Statement's subject as `DERIVED` (re-derives from the RFC-8785
  canonical predicate and matches) vs `EXTERNAL_ATTESTED` (override / tamper / malformed, fail-closed); plus
  nested schema closure.
- **sdjwt-vc** ([`sdjwt_vc.py`](../../src/proofbundle/sdjwt_vc.py) · [doc](../SDJWT_VC_PROFILE.md)) — an SD-JWT
  VC relying-party profile (`typ = dc+sd-jwt`, `vct` allowlist, offline type-metadata integrity, holder-binding
  required). SSRF-safe by construction: no network I/O — a URL `vct` is an opaque identifier, never
  dereferenced.

EXPERIMENTAL predicates and layers are a v3 preview: API and wire format may change without deprecation.
Do not depend on them in production.
