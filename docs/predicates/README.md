# proofbundle predicates

Each predicate is a vendored in-toto `predicateType` in a namespace hosted by b7n0de.com,
carried in a DSSE (Ed25519) Statement and verified against the exact signed bytes by a hand-rolled fail-closed
validator (the JSON Schemas under [`schemas/`](../../schemas/) are docs-only and never gate a verdict). Every
predicate widens the attestation surface, so each states its **non-claims** as explicitly as its guarantees.

There is no single namespace. The `predicateType` values the code writes, or reads as its own, sit under four
prefixes, each followed by `<name>/v<version>`.

- `https://b7n0de.com/proofbundle/predicates/` carries decision-receipt, action-outcome, trust-pack,
  verification-summary, run-ledger, relation-statement and agent-review (v0.1, v0.2 and v0.3).
- `https://b7n0de.com/attestation/` carries eval-result (v0.1 and v0.2), the vendor form of the shape proposed
  upstream ([../IN_TOTO_PROFILE.md](../IN_TOTO_PROFILE.md)).
- `https://b7n0de.com/proofbundle/` carries the self-hosted eval-receipt view, `eval-receipt/v0.1`, written only
  by the Python function `to_intoto_statement` ([PREDICATE.md](../../PREDICATE.md)).
- `https://in-toto.io/attestation/` carries the community predicates test-result (v0.1) and svr (v0.1). They are
  in-toto's types, not ours, and are not listed in the table below.

## Predicates

| predicate | status | one line | doc |
|---|---|---|---|
| `eval-result/v0.2` | shipped (6.3.0), opt-in; the export writes it only with `--predicate-version v0.2` and still defaults to v0.1 | the revised in-toto/attestation#575 shape: `evaluator`, one identification each for model and dataset, `evidence[]` with a digest | [../IN_TOTO_PROFILE.md](../IN_TOTO_PROFILE.md) |
| `eval-result/v0.1` | shipped | an eval number is authored and integral (never that it is *true*) | see SPEC.md |
| `decision-receipt/v0.1` | shipped (2.1.0) | this gate made this verdict over this evidence (never that it was *correct*) | [decision-receipt.md](decision-receipt.md) |
| `action-outcome/v0.1` | EXPERIMENTAL (3.2.0) | this executor did this, bound to a decision, with role separation + `execution_proven` | [action-outcome.md](action-outcome.md) |
| `trust-pack/v0.1` | EXPERIMENTAL (3.2.0) | a TUF-inspired role→key trust root: threshold-of-root, revocation, monotone version, rollback protection | [trust-pack.md](trust-pack.md) |
| `verification-summary/v0.1` | EXPERIMENTAL (3.2.0) | per-level (eval/decision/outcome) receiptRef + status + evidenceClass, with mandatory `nonClaims` | [verification-summary.md](verification-summary.md) |
| `run-ledger/v0.1` | EXPERIMENTAL (3.2.0) | a monotone, prevDigest-chained run history (aborted runs kept visible) against best-of-many cherry-picking | [run-ledger.md](run-ledger.md) |
| `relation/v0.1` | EXPERIMENTAL (3.3.0) | typed, signed lineage edges onto a predecessor's content root — change becomes a declared back-edge, never a mutation (and never a truth claim) | [relation.md](relation.md) |
| `agent-review/v0.2` | EXPERIMENTAL (6.0.0), the current version | as v0.1, plus: time claims separated by source, a REQUIRED `disclosureCoreDigest` binding the visible block, machine-readable `limitationCodes`, and `fixCommit` as the full 40-character sha | [../AGENT_REVIEW_PREDICATE.md](../AGENT_REVIEW_PREDICATE.md) |
| `agent-review/v0.1` | legacy (shipped 5.1.0) | the previous version. It stays readable and verifiable — six published receipts carry it — and its verifier is byte-pinned to the 5.1.0 source. Emitting it needs an explicit `legacy_v01=True`; the `v02=` argument is deprecated from 6.0.0 and will be removed in a later MAJOR | [../AGENT_REVIEW_PREDICATE.md](../AGENT_REVIEW_PREDICATE.md) |

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
