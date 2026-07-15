# Audit readiness — a briefing for sourcing an independent security review

This document is preparation, not a substitute for the thing it prepares. No independent audit of
proofbundle has taken place, and nothing in this document — or in the six-lens adversarial reviews
this project runs on itself before every release — is offered as a stand-in for one. Finding 12 of
the audit-readiness assessment names exactly why: institutional independence is the one property a
project cannot manufacture by reviewing its own code more carefully, no matter how many lenses or
iterations. This briefing exists so that when an external reviewer *is* engaged, they do not start
from zero.

## What proofbundle is, and why an independent look matters here

proofbundle turns an AI evaluation result into a single, offline-verifiable, signed receipt (Ed25519
+ RFC 6962 Merkle inclusion, optional SD-JWT selective disclosure per RFC 9901). It is a small,
dependency-light Python tool whose entire value proposition rests on one narrow cryptographic
promise: that `verify` correctly distinguishes an authentic, unmodified receipt from a tampered or
forged one. A tool whose product IS a trust primitive is exactly the kind of project where a bug in
that one promise matters disproportionately to its size, and where "we tested it carefully
ourselves" is the weakest possible form of assurance for the specific claim being made.

It is also, honestly, a **single-maintainer project** (`GOVERNANCE.md`, `MAINTAINERS.md`) with AI
assistance under continuous human review (`GOVERNANCE.md` §Provenance). That combination is common
in the open-source security-tooling space and is exactly the profile programs like OSTIF exist to
serve — a maintainer with a real, narrow, security-relevant surface and no institutional budget for
a commercial audit engagement.

## Existing hardening (what a reviewer would find already in place)

Stated factually, with the artifact each claim is grounded in, so a reviewer can check every line
independently rather than take the list on faith:

- **A mutation-testing gate**, `scripts/mutation_check.py` (Anti-Goodhart discipline): tests are
  required to KILL deliberately broken implementations, not merely stay green; one documented-
  equivalent survivor is asserted rather than hidden, and CI runs this on every change.
- **Property-based and adversarial fuzzing** (`tests/test_fuzz_parsers.py`, Hypothesis): every
  attacker-controlled parser (checkpoint, tlog-proof, cosignature, SD-JWT, KB-JWT, status-list)
  must return or raise a `proofbundle` error on any input, never crash uncaught.
- **External correctness anchors, not self-referential tests**: RFC 6962 conformance vectors
  vendored from `transparency-dev/merkle`; a real Sigstore Rekor inclusion proof (logIndex 25579,
  4.16M-entry tree) recomputed offline; NIST ACVP ML-DSA (FIPS 204) `sigVer` vectors cross-checked
  against the official answer key; real OpenTimestamps fixtures; C2SP signed-note checkpoint KATs
  read from the pinned Go toolchain / Sigstore trusted-root sources; the SD-JWT digest mechanic
  cross-checked against the `sd-jwt-python` reference implementation (`docs/REVIEWERS.md`).
- **Supply-chain provenance for the project's own releases**: PyPI Trusted Publishing (OIDC, no
  long-lived token), PEP 740 digital attestations plus SLSA v1.2 build provenance on every
  published file, a build-once-then-attest release workflow with a sha256 gate so the published
  bytes equal the attested bytes (`SECURITY.md`, `RELEASE.md`).
- **CodeQL and OpenSSF Scorecard** run in CI; GitHub Actions are SHA-pinned repo-wide.
- **Mechanical no-overclaim enforcement**: `scripts/claims_hygiene_check.py` fails CI on a list of
  forbidden overclaim phrasings appearing outside an explicit negation, scanned across every
  user-facing doc; `scripts/doc_link_check.py` fails CI on a broken internal Markdown link. Both
  exist specifically so this project's public claims cannot silently drift ahead of what the code
  actually does — a discipline an outside reviewer can verify mechanically, not just read as prose.
- **A documented threat model that states its own limits** (`THREAT_MODEL.md`): a receipt attests
  authorship and integrity, and the document is explicit, table by table, about what it structurally
  cannot catch (a dishonest self-attested issuer, best-of-many cherry-picking without
  pre-registration, whether the underlying evaluation is well designed).
- **A repeated, documented history of adversarial self-review**: every release in `CHANGELOG.md`
  since v1.3.0 records a "6-lens" (or wider) adversarial pass with named findings and closed fixes,
  including several rounds that found and fixed real fail-open / downgrade classes before release.
  This is the strongest evidence the project takes its own claim seriously — and, precisely because
  it is self-review, the reason Finding 12 asks for an outside party to be the next check.
- **An offline per-sample audit protocol** (`persample.py`, v1.5): a producer commits every
  individual sample into a Merkle tree, and an auditor challenges random indices with a fresh nonce
  to catch selective disclosure — a structural anti-cherry-picking mechanism, not a promise.

## What an audit should examine

The scoped, versioned target is [`docs/AUDIT_SCOPE.md`](AUDIT_SCOPE.md): a STABLE module set
(the original three-file trusted core plus the decision-receipt, checkpoint/witness, SD-JWT, and
trust-policy layers that shipped since 2.1.0) proposed for a format freeze during the engagement,
and an explicit EXPERIMENTAL/out-of-scope set (the 3.2.x attestation-chain preview, anchor
longevity, the TEE bridge) that is documented project-wide as still moving and therefore not yet
worth a paid reviewer's time. `docs/REVIEWERS.md` is the fast, informal 30-minute path for anyone
who wants to try to break it themselves first.

## The realistic path for a project this size: OSTIF

[OSTIF](https://ostif.org) (the Open Source Technology Improvement Fund) sources and funds
independent security audits for underfunded open-source projects, matching them with professional
auditing firms — the standard route for a single-maintainer project that cannot itself commission
a commercial engagement, and the same model referenced by `docs/GRANT_MILESTONES.md` M3
("Independent audit started — pending (OSTIF sourcing)"). `funding.json` now carries a dedicated
`security-audit` funding purpose (alongside the general maintenance plan) so the ask is legible to
a program like OSTIF or a sponsor evaluating where a contribution goes. Complementary references
for the same model: [OpenSSF's guidance on running a security
audit](https://openssf.org/), and the general shape of a scoped third-party review as practiced by
firms like Trail of Bits — cited here as the class of engagement this project is preparing for, not
as an endorsement or a claim that any specific firm has been engaged.

## Honest current state (No-Overclaim)

- No independent audit has occurred. `docs/GRANT_MILESTONES.md` M3 through M6 are pending, plainly
  labeled as such.
- The PyPI `Development Status` classifier stays `4 - Beta` deliberately (Owner decision E1,
  2026-07-12, `CHANGELOG.md` [3.0.0]): stable is meant to be evidenced by a passing external audit,
  not asserted ahead of one. The bump to `5 - Production/Stable` is gated on M4 (findings
  remediated) and a passing external review, tracked as a factual milestone, never a forward
  promise.
- Every hardening item listed above is real and independently verifiable by re-running the
  referenced test/CI artifact — but every one of them is also this project's OWN instrument. That
  is precisely the boundary an external audit is for, and precisely why this document does not, and
  should not, claim to close Finding 12 on its own.
