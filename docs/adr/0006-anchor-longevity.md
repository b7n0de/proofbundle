# ADR 0006: Anchor longevity — keep OTS/Bitcoin, add standard-anchored renewal + hash-agility

Status: PROPOSED (EXPERIMENTAL, gated on Owner-GO for the renewal implementation B3–B5)
Date: 2026-07-14
Supersedes/relates: builds on the anchor stack in BASELINE_ANCHOR.md; time-anchor choice decided in
`proofbundle_zeitanker_entscheidung_6linsen_20260714.md`.

## Context

proofbundle's anchor stack proves several separate properties (existence-time via OpenTimestamps over
Bitcoin, freshness via a witness quorum, completeness via the transparency layer, optional legal weight
via a TSA). A six-lens review of the time-anchor question concluded that OTS/Bitcoin is the strongest
trust-minimized, free, offline-verifiable existence proof and should stay — the open question for a
proof that must last decades is not *which* chain, but *what keeps an anchor valid as its algorithms
age*. BASELINE_ANCHOR.md verifies the gap: there is no renewal chain and no documented hash-agility.

## Decision

1. **OpenTimestamps over Bitcoin remains the primary time anchor** (neutral, trust-minimized backbone).
   It is not replaced. A second proof-of-work chain is only an optional hedge, never the default.
2. **Longevity is achieved by renewal + hash-agility, modeled ERS-compatibly**, not by swapping the
   anchor:
   - A renewal chain modeled as an RFC 4998 (ASN.1 ERS) / RFC 6283 (XMLERS) **ArchiveTimeStampSequence**
     — an ordered sequence of ArchiveTimeStampChains. *Timestamp renewal* adds an ArchiveTimeStamp to the
     SAME chain when a timestamp's key/signature algorithm weakens; *hash-tree renewal* starts a NEW
     chain whose new ArchiveTimeStamp covers all prior ArchiveTimeStamps AND the data objects when the
     hash algorithm weakens. Operating rule (RFC 4998): only the newest ArchiveTimeStamp must be watched
     for expiry.
   - Explicit hash-algorithm identifiers (no implicit SHA-256), a registry of allowed hashes, optional
     dual-hash for new receipts, and a deprecation policy — the identifier aligns with the ERS
     `digestAlgorithm` field so the renewal chain builds directly on it.
   - The signature layer's renewal target is the NIST-standardized PQ schemes ML-DSA (FIPS 204) primary,
     SLH-DSA (FIPS 205) or stateful LMS/XMSS (SP 800-208) as the hash-based conservative option, with a
     classical+PQ hybrid as the intermediate step. Hash-based anchors survive a signature break; the
     receipt signatures do not, so renewal migrates the signatures.
3. **Modeling the renewal chain ERS-compatibly is an explicit design choice** so the records are
   ingestible by preservation services (ETSI TS 119 512) and the German BSI TR-ESOR (TR-03125) path —
   an interoperability enabler, implemented as an adapter inside the existing `anchors` framework, not a
   third anchor abstraction.
4. **eIDAS/QTSP stays an optional per-receipt legal layer** (Art. 41); **SCITT is raised in rank** now
   that it is published as RFC 9943 (architecture) + RFC 9942 (COSE receipts), for the completeness
   property. Both are complementary, neither is the time anchor.

## Standard anchors (for code and the technical note)

| Surface | Standard | Core point |
|---|---|---|
| Long-term evidence structure | RFC 4998 (ERS, ASN.1), RFC 6283 (XMLERS) | ArchiveTimeStampSequence of ArchiveTimeStampChains |
| Preservation interop | ETSI TS 119 512 (reqs TS 119 511) | preservation API consumes ERS / AdES archive timestamps |
| DE/EU authority path | BSI TR-ESOR (TR-03125) | evidence-preserving long-term storage, ERS-based |
| PQ signature primary | NIST FIPS 204 (ML-DSA) | lattice-based, final Aug 2024 |
| PQ signature conservative | NIST FIPS 205 (SLH-DSA), SP 800-208 (LMS RFC 8554, XMSS RFC 8391) | hash-based, security only from the hash |
| Time anchor | OpenTimestamps over Bitcoin | upgraded proof is self-contained, calendar-independent |
| Hash robustness | SHA-256 under Grover | second-preimage stays ~128 bit, long-term robust |

## Threat model (what the longevity work defends against)

- **Algorithm ageing.** SHA-256 second-preimage under Grover is ~128 bit (robust for existence proofs);
  Ed25519 is broken under the quantum assumption. Without renewal before the ageing, any anchor loses
  its force. Hash-tree renewal defends the hash; signature renewal (PQ) defends the signatures.
- **Calendar outage.** Mitigated by multiple calendar servers and by bundling the Bitcoin block headers
  so the upgraded OTS proof verifies offline with no external fetch.
- **Missing renewal.** A renewal-policy verifier reports (WARN or FAIL per strictness) when the newest
  ArchiveTimeStamp is overdue; no automatic network fetch.

## Consequences

- New surfaces (renewal chain, hash-agility, PQ path, evidence-pack hardening) are EXPERIMENTAL and
  graduate individually. The verifier stays fail-closed: an unknown or deprecated hash algorithm fails,
  a pending OTS stays pending, a broken sequence fails.
- The technical note may describe the renewal path only as a *planned, standard-anchored* long-term
  path (EXPERIMENTAL/roadmap) until the code exists — never as a shipped feature, and never as
  `quantum-safe`, `tamper-proof`, or a compliance guarantee. A PASS attests authorship, integrity,
  existence and a point in time — never the truth of the statement nor completeness.

## Owner-GO gate

The renewal *implementation* (B3 ArchiveTimeStampSequence, B4 policy, B5 PQ path) and every anchor
submission / publication (OTS calendar beyond test quota, log, tag, publish, Zenodo deposit) require
**explicit Owner-GO**. This ADR (B1) and the hash-agility format work (B2) and evidence-pack hardening
(B6) are the ungated, docs-and-local-first steps.

**Owner-GO token to build the ERS-compatible renewal chain (B3) and the PQ signature path (B5):**
`GO_OWNER_ANCHOR_LONGEVITY_RENEWAL_NO_RELEASE`.
