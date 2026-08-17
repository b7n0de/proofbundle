# ADR 0008: The pre-tag audit record becomes a signed attestation, not prose

- **Status:** proposed. Research answered, design fixed, integration split into a part that can be
  built here and a part that touches the release workflow and therefore belongs to the maintainer.
  This ADR changes no shipped behavior yet.
- **Date:** 2026-08-16
- **Deciders:** proofbundle maintainer (b7n0de)
- **Builds on:** the existing SLSA build-provenance path in `.github/workflows/release.yml`
  (`actions/attest-build-provenance`, keyless OIDC, published==attested digest gate) — this ADR
  extends a mechanism the project already runs rather than introducing a new trust system.

## Context — measured, not assumed

`scripts/pre_tag_audit_gate.py --strict` is the first step of the release workflow and the last
blocking check between a tag and PyPI. It answers "was the adversarial audit run for THIS release"
by searching **prose**: any non-negated marker line in the version-scoped `audit_artifacts/<token>/`
folder, or in the CHANGELOG section for the version.

On 2026-08-16 that gate was satisfied **by a documentation edit**. A measurement report placed in
`audit_artifacts/380/` quoted two sentences that the gate reads as an attestation; the whole suite
then reported 2120 passed with the release gate green, for a release with no audit record. The
report in question opens with a warning against exactly that, and the warning was not enough.

Three behavioural properties were then measured against the gate and written down as an executable
bar (`tests/test_pre_tag_gate_eigenschaften.py`):

| Property | State |
|---|---|
| P5 an empty record folder must not grant a pass (control) | holds |
| P4 a truthful record must grant a pass | holds |
| P1 a file *about* an audit must not grant a pass | **violated** |
| P2 a record naming a *different* version must not grant a pass | **violated** |
| P3 a sentence saying nothing ran must not grant a pass | **violated** |

PR #139 rewrites the gate to require one closed full-line form carrying the version. That closes P2
and P3 and narrows P1. It does not change the *kind* of evidence: the line is still prose that any
writer — or any file — can contain. #139's own comment states this limit plainly.

## Research

**Where the standard sits.** SLSA defines a **Verification Summary Attestation** (VSA,
`https://slsa.dev/verification_summary/v1`) for exactly this shape of claim: a verifier checked an
artifact against a policy and here is the verdict, with `verifier`, `timeVerified`, `resourceUri`,
`policy`, `verificationResult` (`PASSED`/`FAILED`) and `verifiedLevels`. **It does not fit us
directly**, and this is worth stating rather than glossing: the specification's fields and its
guidance are about SLSA *levels*, and it gives no guidance for policy verdicts outside that
framework. Reusing the VSA predicate type for "an adversarial audit ran" would be borrowing a
standard's authority for a claim it does not define. The in-toto attestation framework explicitly
provides for **custom predicate types**, and that is the honest fit — modelled on VSA's *structure*,
carrying its own type URI.

**The signing path is already here.** `actions/attest` accepts a custom `predicate-type` plus
`predicate` and signs the resulting in-toto statement through Sigstore with a short-lived,
keyless OIDC certificate. `release.yml` already grants `id-token: write` and `attestations: write`
and already runs the build-provenance sibling in the same job. The gap is one step, not a system.

**The objection that had to be checked, because it is the product's own thesis.** proofbundle's
pitch is evidence that verifies **offline**, without calling a service. Sigstore is a transparency
system with online components, so adopting it looked like a contradiction. Measured against the
documentation: it is not one. The `.sigstore.json` bundle format carries the full chain of evidence
including signed timestamps, and GitHub documents verifying attestations offline against a pinned
trusted root; air-gapped verification is supported when the roots of trust for the ephemeral keys
and the timestamp authorities are present on both sides.

**The honest limit that comes with it, and it is not small.** Offline you cannot learn that key
material was revoked since your trusted root was captured, and anything signed after that capture
verifies until the instance rotates its keys — typically a few times a year. Keeping the trust root
current is the verifier's responsibility, and a stale or substituted root silently weakens every
verification. That is a *different* trust model from a self-contained proofbundle bundle, not a
worse one, and the difference must be written where a reader will meet it.

## Decision

**Yes — for the release process, and the two trust domains stay separate.**

1. The pre-tag audit record becomes an **in-toto attestation with a custom predicate type**,
   subject-bound to the commit being tagged, signed via `actions/attest` (Sigstore, keyless OIDC).
   Modelled on VSA's structure — verifier identity, time, policy, result — under our own type URI,
   because VSA's own type is defined for SLSA levels.
2. The gate stops grepping prose and **verifies the attestation**. A documentation edit cannot
   produce a signature, so P1, P2 and P3 fall out of the change rather than being patched one
   regex at a time.
3. The **product** keeps its offline, self-contained verification. This decision governs how
   *proofbundle releases itself*, where GitHub is already the trust root because GitHub builds and
   publishes the artifact. It does not move the library's own evidence model onto a transparency
   service.

## Consequences

- The blocklist-of-negations disappears as a security surface. It is a blocklist over an open
  alphabet (CWE-184): each round finds the next sentence not on the list, and today's incident was
  one. Signatures are not enumerable that way.
- `tests/test_pre_tag_gate_eigenschaften.py` is the acceptance bar and needs no rewrite: it tests
  behaviour against the real `evaluate()`, so it applies to whichever gate implementation lands. The
  three `expectedFailure` markers turn into **unexpected success** — loudly, as measured — and must
  then be removed. That is the intended signal, not an inconvenience.
- Ordering: the audit happens *before* the tag, so the attestation's subject is the **commit**, not
  the wheel. The build-provenance attestation continues to cover the wheel. Two subjects, two
  attestations, one workflow.
- **Not built here, and deliberately:** the `release.yml` step itself. That file is the maintainer's
  publish path, and a change to it is a one-way door. The verifier side and the acceptance bar can
  and should be built first, so the workflow change arrives as a reviewed diff against an
  already-passing verifier rather than as an untested edit to the release path.

## What this ADR does not claim

It does not claim the audit was run, for this or any release. It changes what *counts* as a record
of one. And it does not claim a signature makes the audit good — a signed attestation binds an
identity, a time and a subject to a statement; whether the statement is true remains a question
about the process that produced it, which is the same honest boundary #139 states about its line.
