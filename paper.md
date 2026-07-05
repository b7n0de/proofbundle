---
title: "proofbundle: offline-verifiable, tamper-evident receipts for AI evaluation results"
tags:
  - Python
  - cryptography
  - AI evaluation
  - transparency logs
  - reproducibility
authors:
  - name: Konrad Gruszka
    orcid: 0009-0006-8947-6065
    affiliation: 1
affiliations:
  - index: 1
    name: Independent researcher, b7n0de
date: 2 July 2026
bibliography: paper.bib
---

# Summary

An AI evaluation result — a safety-benchmark score, a capability number, a
leaderboard entry — is, as published today, an unverifiable claim: a reader must
trust the party that reported it. `proofbundle` is a small, MIT-licensed Python
tool that turns an evaluation result into a single portable *receipt* that anyone
can verify offline. A verified receipt proves two things and is careful to claim
no more: that these exact bytes were signed by a stated key (authorship), and
that nothing has changed since (integrity). It does not claim the number is true.
The trusted core depends only on the `cryptography` library and composes accepted
standards — Ed25519 signatures, RFC 6962 Merkle inclusion proofs
[@rfc6962], SD-JWT selective disclosure [@rfc9901], and C2SP transparency-log
formats — rather than inventing cryptography. A receipt can keep the model and
dataset as salted commitments (proving a threshold was met without revealing
either), carry a per-sample Merkle commitment that lets an auditor spot-check
individual samples, and record a pre-registration commitment to the evaluation
protocol.

# Statement of need

Third-party and first-party AI evaluations increasingly inform high-stakes
decisions, yet the evidence behind a reported score is typically unsigned prose
in a model card or a row in a leaderboard. Recent work documents that leaderboards
are gameable and that benchmark contamination is widespread
[@leaderboard2025; @contamination2024], and evaluators operating under
non-disclosure constraints cannot simply publish everything to establish trust.
There is no small, portable, offline mechanism to establish that a reported result
was signed by a stated party, has not been altered, and covers the samples it
claims — while still permitting the model or test set to be withheld. Model
signing efforts such as OpenSSF Model Signing [@modelsigning2025] sign model
weights, and transparency logs such as Sigstore Rekor [@rekor] prove artifact
existence, but neither is eval-shaped. `proofbundle` fills this gap: it is the
signature and selective-disclosure layer for an evaluation result, verifiable
from one file with no server.

# State of the field

`proofbundle` is complementary to, not a replacement for, its neighbours.
Sigstore Rekor [@rekor] provides a public append-only transparency log; a
proofbundle receipt uses the same RFC 6962 Merkle primitive and can verify a real
Rekor inclusion proof offline, but it is a portable, private, eval-specific
artifact rather than a log service. in-toto [@intoto] and DSSE provide a generic
signed-statement envelope; proofbundle exports a DSSE-signed in-toto
`test-result` statement, but that predicate lacks fields for a metric-versus-
threshold verdict, salted commitments, or per-sample results. OpenSSF Model
Signing [@modelsigning2025] signs model artifacts, not evaluations. Private
benchmarking work such as TRUCE [@truce2024] keeps test sets confidential using
trusted execution or multi-party computation; proofbundle instead uses
commitments and a random-sample audit whose soundness follows the
proof-of-retrievability bound [@por2007]. To our knowledge no released tool
combines a signed aggregate result, an in-receipt Merkle commitment over
per-sample results, salted selective opening, and an offline spot-check protocol.
We built a standalone tool rather than contributing to an eval framework because
the receipt layer is framework-agnostic and is consumed across a trust boundary;
`proofbundle` provides opt-in adapters for the major frameworks.

# Software design

The design draws a deliberate boundary between a tiny trusted core and everything
else. The core — signature verification, RFC 6962 Merkle hashing with domain
separation, and the bundle verifier — is a few hundred lines depending only on
`cryptography` and the standard library; correctness is anchored to external
RFC 6962 conformance vectors and a real Sigstore Rekor proof, so it is not
self-referential. Optional layers (SD-JWT with Key Binding, C2SP checkpoints and
witnessed cosignatures including post-quantum ML-DSA-44, Token Status List
revocation, and the per-sample audit) are additive and do not weaken the core if
unused. The verify path never canonicalizes JSON — it checks stored bytes — so it
carries no heavyweight dependency, while the emit path uses RFC 8785 JCS
canonicalization [@rfc8785]. Framework adapters (inspect_ai, lm-evaluation-
harness, promptfoo, pytest) read exported logs and never import the framework at
runtime. This architecture matters for the research application because an
evaluation receipt must be checkable by a skeptical third party with minimal
trusted surface, offline, years after issuance.

# Research impact statement

`proofbundle` targets an emerging need in AI governance and evaluation science:
tamper-evident, offline-verifiable evidence for reported evaluation results, with
selective disclosure for evaluators who cannot publish test sets. Its per-sample
audit protocol operationalizes a proof-of-retrievability argument [@por2007] for
benchmark integrity, giving external reviewers a way to challenge random samples
without the full set being public. The software is packaged to community
standards with a mutation-gated test suite and property-based parser fuzzing, and
is intended as a reference implementation for a proposed open standard for eval
evidence. We describe it here to make the construction citable and to invite
external review of its trust model and its stated limits.

# AI usage disclosure

Generative AI assistance was used in preparing this software and paper, and is
disclosed here as required by JOSS policy.

- **Tools.** Anthropic Claude (Claude Opus / Sonnet family, 2026) was used
  through an agentic coding and writing environment.
- **Nature and scope.** AI assistance was used for drafting and refactoring code,
  scaffolding tests, drafting documentation, and drafting the prose of this paper,
  and for literature and standards research. Cryptographic design decisions,
  the trust-model boundaries, the honest-scope framing, and the final wording were
  made and are owned by the human author.
- **Review.** The human author reviewed, edited, and validated all AI-assisted
  outputs, verified every citation in this paper against its primary source, and
  is responsible for the correctness and integrity of the software and the paper.

# Acknowledgements

The author thanks the maintainers of the in-toto, Sigstore, C2SP, and Inspect AI
projects for the standards and tooling this work builds upon. No external
financial support was received for this work.

# References
