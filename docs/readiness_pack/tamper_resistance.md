# External anchoring as tamper-RESISTANCE (not only evidence)

This chapter answers, up front, the open problem AuditWeave (arXiv:2607.09682) names for hash-chained
evidence ledgers in general — so an external auditor finds it addressed rather than missing.

## The problem AuditWeave states

> "tamper-evident, not resistant — an actor controlling storage could recompute the chains."

A SHA-256 hash chain over evidence proves that *if* you hold an earlier, trusted copy of the head, any
later modification is detectable. But if a single party controls the storage AND the head, they can
recompute the whole chain to a new, internally-consistent state. Evidence of tampering requires an
independent reference point; without one, "tamper-evident" degrades to "tamper-evident to someone who
already has the untampered head."

## How proofbundle answers it

proofbundle binds the content root to an **external append-only reference**, so the head is not solely
producer-controlled:

- **OpenTimestamps / Bitcoin** (`src/proofbundle/anchors_ots.py`): the receipt's canonical content
  root is committed into a Bitcoin-anchored OpenTimestamps proof. Recomputing the chain would require
  rewriting Bitcoin history — outside any single producer's control. The relying-party Bitcoin block
  header is supplied by the RELYING PARTY, not the bundle's producer-controlled `frozen` block
  (WP-A1); a confirmed anchor that only validates against the producer's own frozen header is rejected
  (see the `forged-anchor-own-frozen` conformance vector and the WP-A1 counter-check in
  `conformance/run_conformance.py`).
- **RFC 3161 TSA** (`src/proofbundle/anchors_rfc3161.py`): an independent timestamping authority
  countersigns the root; the token verifies offline against bundled TSA roots.
- **chia-datalayer** (`src/proofbundle/anchors_chia.py`, EXPERIMENTAL): a DataLayer key inclusion under
  a published root, offline-verifiable at level i.

The resistance property is therefore: **to forge or silently rewrite a confirmed receipt, an attacker
must also forge the external append-only reference (a public blockchain / an independent TSA), which a
storage-controlling producer does not control.** That is the difference between tamper-evidence and
tamper-resistance, and it is the property AuditWeave asks a ledger to document.

## The honest limit (what this does NOT claim)

- **Unanchored receipts are tamper-EVIDENT only.** A receipt with no anchor gives you detection if you
  already hold a trusted head, nothing stronger. This is stated, not hidden.
- **Anchoring proves existence-before-a-time and non-silent-rewrite, not correctness.** It says the
  root existed and cannot be silently changed; it says nothing about whether the underlying evaluation
  was well designed or the self-attested issuer is honest (`THREAT_MODEL.md`).
- **The anchor's own trust roots must be distributed and trusted** — that is `OPEN_QUESTIONS.md`
  Q1_ANCHOR_TRUST_ROOT_DISTRIBUTION, an item for the external review, not something the code closes on
  its own.
- **Primitive hardness and side-channels are out of scope** for both the anchor story and the formal
  model (IACR 2025/980) — external-audit terrain, `OPEN_QUESTIONS.md` Q2/Q3.
