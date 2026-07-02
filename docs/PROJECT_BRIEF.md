# proofbundle — one-page project brief (for funders and reviewers)

## The gap
Every AI eval number the public sees — a safety benchmark, a capability score, a leaderboard entry
— is an **unverifiable claim**: you trust the lab. There is no portable, offline way to prove that
a reported result was signed by a stated party, has not been altered since, and covers the samples
it claims. Model signing (OpenSSF OMS, CoSAI) covers *model weights and datasets*; transparency
logs (Sigstore/Rekor) cover *existence*; eval frameworks (Inspect, lm-eval, promptfoo) produce
*mutable logs*. **No shipped tool occupies "signed, offline-verifiable, eval-shaped receipt with
per-sample auditability."** As the EU AI Act's Article 12 record-keeping duty for high-risk systems
takes effect (2026-08-02) and leaderboard-gaming controversies mount, that gap is now load-bearing.

## What proofbundle is
A small (~600-LOC trusted core, `cryptography` + stdlib only), MIT-licensed Python tool that turns
an eval result into one portable JSON receipt proving **authorship + integrity**: Ed25519
signature, RFC 6962 Merkle anchoring, salted model/dataset commitments (prove a threshold without
revealing the model or test set), optional SD-JWT selective disclosure + Key Binding, C2SP
transparency-log interop (checkpoint / cosignature / tlog-proof, incl. post-quantum ML-DSA-44
witnesses), Token-Status-List revocation, and — the differentiator — a **per-sample Merkle
commitment with a forced-random-sample audit protocol**. It verifies fully offline, one file, no
server. It is deliberately honest about the line it does not cross (not truth, not issuer honesty,
not eval quality, not anti-cherry-picking without pre-registration or reproduction).

## Why it is fundable
- **Uncontested white space** validated by primary-source research: no standard, no shipped
  competitor for signed eval receipts (2026).
- **Standards-native, not NIH**: reuses RFC 6962/9162, RFC 9901, C2SP, DSSE/in-toto, RFC 8785 —
  it composes accepted primitives rather than inventing crypto.
- **Regulatory tailwind**: Art. 12 (2026-08), GPAI Model Reports, NIST AI RMF MEASURE evidence.
- **Reviewable now**: external RFC 6962 vectors + a real Rekor proof (correctness not
  self-referential), a mutation-gated test suite, property-based parser fuzzing, a 30-minute
  reviewer path, and a supply-chain-hardened release (attested == published).

## What funding would buy next
1. **An external cryptographic + supply-chain audit** of the trusted core and the per-sample audit
   protocol — the single highest-credibility step for adoption.
2. **The per-sample audit protocol as a citable spec** (the construction is TRUCE-adjacent +
   proof-of-retrievability soundness 1−(1−m)^k) — a JOSS/short-paper submission with a reference
   implementation, enabling third-party reviewers (METR/AISI-style) to demand sample openings.
3. **Standards engagement**: propose an eval-result predicate at in-toto / OpenSSF AI-ML WG so
   signed eval evidence has a registered home rather than a vendor URI.

## Three grant-abstract seeds
- **A. Verifiable eval receipts for third-party AI evaluation.** Fund the audit + spec + one
  flagship integration (Inspect hook) so external evaluators can publish tamper-evident,
  offline-verifiable results with per-sample spot-checks — closing the "trust the lab's number" gap.
- **B. Anti-cherry-picking for benchmarks via pre-registration + sampled correctness.** Fund the
  pre-registration protocol (`prereg`) and the per-sample Merkle audit into a documented, audited
  workflow, with an empirical study of catch rates vs. gaming strategies on public leaderboards.
- **C. Post-quantum-ready transparency for AI eval evidence.** Fund the C2SP witness-network
  integration (ML-DSA-44 cosignatures) so eval receipts gain split-view resistance and a
  migration path off Ed25519 primaries, aligned with Sigstore's PQ direction.

## Roles this repo demonstrates fit for
Applied-cryptography / security engineer (trusted core, supply chain); AI-eval-infrastructure
engineer (adapters, per-sample audit, framework integrations); open-source maintainer /
standards contributor (honest scoping, reviewer docs, in-toto/OpenSSF engagement).

_Suggested targets: AI Safety Institute (UK AISI), METR, Apollo Research, OpenSSF, the Sigstore
community, model-risk-management teams, frontier-lab eval infrastructure._
