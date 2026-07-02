# Compliance profile — using proofbundle receipts as tamper-evident evaluation records

**Status:** informative mapping, v1.3 (2026-07-02). **This is not legal advice**, and a receipt
alone does not make a system compliant. This document maps what a proofbundle receipt *technically
provides* onto the record-keeping language of the EU AI Act, ISO/IEC logging work, and the NIST AI
RMF, so that engineering and compliance teams can decide what it covers — and what it does not.

## What a receipt technically provides

A verified proofbundle receipt is a **tamper-evident, signed, offline-verifiable record** of a
claimed evaluation result: exact bytes, signed by a stated issuer (Ed25519), anchored under an
RFC 6962 Merkle root (optionally checkpointed, witnessed by a quorum, and carried as a C2SP
`.tlog-proof`), with salted commitments to model/dataset identifiers, a signed `assurance_level`,
optional selective disclosure (SD-JWT, RFC 9901, with holder binding), and optional revocation
state via a Token Status List snapshot. See [THREAT_MODEL.md](THREAT_MODEL.md) for what it does
**not** establish (truth of the number, absence of cherry-picking without pre-registration).

## EU AI Act — Article 12 record-keeping (applies to high-risk systems from 2026-08-02)

Article 12 requires automatic recording of events ("logs") over the system lifetime, such that
operation is traceable and records cannot be altered in a way that would affect subsequent
evaluation. proofbundle is a **record-integrity layer** for the evaluation-related subset of that
duty — it does not generate operational event logs.

| Art. 12 concept | receipt mechanism | honest gap |
|---|---|---|
| records "cannot be altered" (tamper-evidence) | Ed25519 signature over exact payload bytes + Merkle anchoring; any bit-flip fails `verify` | integrity is proven from signing time onward, not before |
| independent verifiability by authorities | one self-contained JSON / `.tlog-proof` file, verifiable **offline** with published keys — no vendor system access needed | the authority must obtain trust anchors (keys) out of band |
| traceability of evaluation events | timestamps, suite/version, `assurance_level`, provenance (git commit, harness version), transparency-log index | wall-clock trust requires an external TSA or witness timestamps |
| retention (≥ 6 months) | receipts are small static files; Merkle/checkpoint anchors make silent post-hoc replacement detectable | retention itself is an operational duty |
| GPAI Code of Practice: documented model evaluations in Model Reports | a receipt per reported eval result gives the AI Office a verifiable artifact instead of a bare number | the *quality* of the eval is out of scope (see THREAT_MODEL) |

Related standards in flight: **prEN 18229-1** (AI Act logging harmonized standard) and
**ISO/IEC DIS 24970** (AI system logging) — both concern *what* to log; proofbundle concerns
*how a logged evaluation result stays verifiable*. Revisit this mapping when they publish.

## NIST AI RMF — MEASURE function

MEASURE calls for documented, repeatable measurement of AI risks with evidence retention.
A receipt gives each measurement result authorship, integrity, a reproducibility anchor
(`prereg_sha256`, provenance, salted commitments) and third-party verifiability — the evidence
half of MEASURE 2.x. It does not choose metrics or validate suites.

## UK AISI / Inspect

AISI's evaluation standard expects QA evidence from Inspect logs; Inspect logs carry provenance
but no cryptographic integrity. The opt-in Inspect hook (`PROOFBUNDLE_EMIT=1`) turns each eval
run's result into a signed receipt at task end — an integrity layer the log format itself does
not provide.

## Anti-patterns (do not claim these)

- "proofbundle makes us Article 12 compliant" — no single artifact does; it covers the
  *evaluation-record integrity* slice only.
- Presenting a `self_attested` receipt as independent assurance — the signed `assurance_level`
  exists precisely so that this distinction survives transport.
- Treating a receipt as proof the evaluation was well designed or honestly selected — that
  requires pre-registration (`prereg_sha256`) and/or independent reproduction.
