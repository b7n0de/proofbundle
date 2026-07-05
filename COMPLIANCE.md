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

## EU AI Act — Article 12 record-keeping (high-risk obligations apply from 2027-12-02 / 2028-08-02)

Article 12 requires automatic recording of events ("logs") over the system lifetime, such that
operation is traceable and records cannot be altered in a way that would affect subsequent
evaluation. proofbundle is a **record-integrity layer** for the evaluation-related subset of that
duty — it does not generate operational event logs. Note the timeline: the Digital Omnibus
(adopted 2025-11-19) postponed the high-risk obligations from the original 2026-08-02 to
**2 December 2027** for standalone Annex III systems and **2 August 2028** for AI embedded in
regulated products under Annex I.

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

## Regulatory-safe wording (use these, not stronger)

- "proofbundle supports **evidence retention**, not compliance by itself."
- "proofbundle helps with **eval-record integrity**, not full operational logging."
- "proofbundle can support **Article-12-style traceability**, but does not satisfy Article 12 alone."
- "proofbundle maps to **NIST AI RMF MEASURE** evidence, but does not define risk metrics."
- "proofbundle can **complement** Inspect logs, not replace Inspect."

## Claims that must NEVER be made

1. **Never** "EU AI Act compliant" / "Article 12 compliant" / "makes your system compliant" —
   compliance is a whole-system, provider-level conformity assessment; a receipt is at most one input.
2. **Never** "required by Article 12" for cryptographic/tamper-evident signing — Art. 12 mandates
   *automatic recording* + *traceability*, and does **not** contain the words "cryptographic",
   "signed", "tamper-evident" or "immutable". Tamper-evidence is proofbundle's value-add, not a legal
   requirement.
3. **Never** "NIST AI RMF certified/compliant" — the RMF is voluntary and non-certifiable.
4. **Never** "conforms to the AI-eval attestation standard" — **no such standard exists** as of 2026
   (OpenSSF Model Signing / CoSAI WS1 cover models and datasets, not eval receipts).
5. **Never** "OMS/CoSAI/in-toto compliant" unless the on-disk bytes literally are that format.
6. **Never** "certified", "qualified trust service", "legally binding", or "audit-grade" without an
   actual accreditation.
7. **Never** "guarantees the integrity/authenticity of the eval" — a signature proves the artifact
   was not altered after signing; it says nothing about whether the eval was correct or honest.
8. **Never** imply conformance to prEN 18229 / ISO-IEC 24970 — those harmonized standards are
   **unpublished drafts** in 2026 (ISO/IEC DIS 24970 ballot closed Feb 2026; not yet published).

## Honest mapping (capability → concept → honest gap)

| proofbundle capability | Maps to | Does NOT satisfy / must not claim |
|---|---|---|
| Offline signed eval receipts | Traceability spirit of **EU AI Act Art. 12/19**; **MEASURE** documentation | System-level Art. 12 compliance; the automatic lifetime event-logging Art. 12(1) mandates; a conformity assessment |
| Tamper-evidence via Ed25519 + Merkle | in-toto / OMS / Sigstore attestation approach | "Required by Art. 12" — the law says recording + traceability, not signatures |
| Eval results as verifiable artifacts | **NIST AI RMF MEASURE** evidence | Defining risk metrics/thresholds; GOVERN/MAP/MANAGE |
| Signed bundles of eval artifacts | Parallel to **OpenSSF OMS / CoSAI WS1** signing | OMS conformance (unless byte-for-byte the OMS format); no eval-specific standard to conform to |

**Defensible framing (copy this):** "proofbundle produces offline, cryptographically signed,
tamper-evident receipts for AI-eval artifacts. This can serve as *supporting evidence* toward
record-keeping / traceability goals (cf. EU AI Act Art. 12/19) and as *documentation evidence*
under NIST AI RMF MEASURE. It does not by itself establish regulatory compliance, define risk
metrics, or conform to any AI-eval attestation standard (none is standardized as of 2026)."

**Legal/governance FAQ.** *Does deploying proofbundle make us Art. 12 compliant?* No — it is one
possible evidence input. *Can we say it's NIST-certified?* No — the RMF cannot be certified against.
*Can we cite it in a Model Report / conformity file?* Yes, as tamper-evident evidence of specific
eval results, with the scope stated. *Is the `assurance_level` legally meaningful?* It is
issuer-declared and signed; it records who claimed what level, not an accredited attestation.

## Anti-patterns (do not claim these)

- "proofbundle makes us Article 12 compliant" — no single artifact does; it covers the
  *evaluation-record integrity* slice only.
- Presenting a `self_attested` receipt as independent assurance — the signed `assurance_level`
  exists precisely so that this distinction survives transport.
- Treating a receipt as proof the evaluation was well designed or honestly selected — that
  requires pre-registration (`prereg_sha256`) and/or independent reproduction.

_Standards status verified 2026-07-05 against primary sources: EU AI Act Art. 12 high-risk
obligations postponed by the Digital Omnibus (adopted 2025-11-19) to 2027-12-02 (standalone
Annex III) and 2028-08-02 (AI embedded in Annex I regulated products), from the original
2026-08-02; Art. 53 GPAI (applied 2025-08-02), NIST AI RMF 1.0 + GenAI Profile AI 600-1, OpenSSF
Model Signing + CoSAI WS1, ISO/IEC DIS 24970 (ballot closed, unpublished)._
