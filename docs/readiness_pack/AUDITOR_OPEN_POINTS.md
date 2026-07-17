# Auditor open points — what the machine CANNOT decide (No-Fake)

This is the honest boundary of the readiness pack: the points below are exactly the ones no test in
this repository can settle, so they need a human cryptographer's / protocol reviewer's judgement. The
pack states its own limit here rather than letting a green matrix imply completeness. Passing every
internal gate (see `REPRODUCTION_RUNBOOK.md`) is a precondition for this review, not a substitute for it.

## A. Cryptographic construction soundness (Q2_PRIMITIVE_HARDNESS)

- Ed25519 / ECDSA-P256 / ML-DSA-65 / hybrid signature usage: correct domain separation, no nonce or
  malleability pitfalls, correct public-key handling. Our tests prove agreement and tamper-evidence,
  not primitive hardness (IACR 2025/980: formal covers logic, not primitives).
- DSSE PAE binding, RFC 8785 (JCS) canonicalization edge cases, RFC 6962 Merkle construction: we test
  differential agreement Python<->Rust and against the C2SP/Wycheproof style negative vectors, but a
  reviewer should confirm the constructions themselves, not only that two implementations agree.
- SD-JWT / KB-JWT / status-list constructions and the BBS selective-disclosure profile.

## B. Protocol semantics

- The relation-lineage aggregation ladder (relation/v0.1, EXPERIMENTAL): the LOGIC is modelled and
  proven (formal O1-O4) and code-enforced, but the SEMANTIC claim (what a supersedes/revises/retracts
  edge should mean for a downstream consumer) is a design question for review.
- Trust-Pack root-of-trust: threshold semantics, two-stage rotation authorization, revocation, and the
  payloadType/predicateType binding (O7, reserved) are code-enforced and vector-tested but not formally
  modelled.
- Anchor trust-root distribution (Q1_ANCHOR_TRUST_ROOT_DISTRIBUTION): how a verifier obtains and pins
  the OpenTimestamps / RFC 3161 trust roots is an operational trust question outside the code.

## C. Side channels (Q3_SIDE_CHANNELS)

- Timing / cache behaviour of the verify paths. Deliberately out of scope for the formal model and the
  fuzz soak; a permanent external/research remainder (see PROGRESS.md's ~2% irreducible ceiling).

## D. Supply chain / build provenance beyond L3 shape

- The reusable attest workflow provides the SLSA-L3 SHAPE (signing separated from build). A reviewer
  should confirm the actual PyPI Trusted Publishing + PEP 740 attestation chain on a real published
  artifact, and the org-shared reusable workflow question (Q4_REUSABLE_WORKFLOW_ORG_SHARED).

## E. Consciously deferred (documented, not gaps to close for audit-candidate)

- Full TEE-attestation path, whole-program verification, distributed OSS-Fuzz on Google infra
  (ClusterFuzzLite local is sufficient for audit-candidate, SOTA §7).
- The Rust second verifier covers a deliberate slice; the 36 PENDING surfaces are honestly declared,
  not fake-100% (see `rust_parity_scope.md`). Whether that slice is the right one is a review question.

## F. The one remaining gate to stable

The single deliberately-open acceptance criterion is "external audit completed". 4.0.0-stable = this
pack + the external audit ABSCHLUSS + findings closed/accepted + relation wire-freeze. Nothing in this
repository can flip that bit; only the external reviewer can.
