# ADR 0001: Decision Receipt as a separate vendored predicate

- **Status:** accepted
- **Date:** 2026-07-09 (decision date; commit date live)
- **Deciders:** proofbundle maintainer (b7n0de)

## Context

While positioning proofbundle inside the in-toto `eval-result` predicate proposal
([in-toto/attestation#565](https://github.com/in-toto/attestation/issues/565)), reviewer feedback from
clementineCU (2026-07-09) pressed on scope: an eval-result attestation is metric/benchmark evidence, and
folding agent-decision semantics into it would blur what a passing verification means. The maintainer
answered in the thread on 2026-07-09 (a boundary was committed, a separate vendored `decision-receipt`
predicate announced, and a Non-goals section added to the issue body). The full thread state is captured in
[`audit_artifacts/thread_565_snapshot.md`](../../audit_artifacts/thread_565_snapshot.md). This ADR records
the resulting decision so that Phase D implementation does not re-open it.

## Decision

1. **`eval-result` stays pure metric/benchmark evidence.** Its Non-goals are explicit in the proposal since
   2026-07-09; it never carries decision, authorization, or outcome semantics.
2. **Agent decisions are modeled as their own predicate:**
   `https://b7n0de.com/proofbundle/predicates/decision-receipt/v0.1`. This is a **vendored** predicate under
   the b7n0de namespace. It makes **no claim** on the `in-toto.io` namespace; any upstream standardization is a
   separate in-toto discussion tracked via issue #26 (or a new issue), not this vendored track.
3. **Coupling is one-directional and digest-bound only.** A Decision Receipt references signed eval-result
   statements exclusively through digest-bound `evidenceRefs`. Never the reverse, and no semantic mixing of the
   two predicates.
4. **Core fields** (derived from the feedback): input/source snapshot (digests); policy/risk boundary
   (policy id + digest + decision path); proposed action + verdict (`ALLOW` / `DENY` / `REFUSE` / `ESCALATE` /
   `DEFER`); `notChecked`; `decisionChangeConditions`. Optional: outcome / trace / anchors.
5. **Target release: 2.1.0**, built on the Trust Policy foundation shipped in Phase B
   (`proofbundle/trust-policy/v0.1`, snake_case). In 2.1 that schema is extended additively with a
   Decision-Receipt section to v0.2; no breaking change to v0.1.
6. **Non-claims.** A Decision Receipt does not prove that a decision was correct, legal, safe, or fully
   informed. `actionOutcome=executed` without a separately signed tool/mediator outcome is self-assertion,
   not proof.

## Consequences

- Implementation lands in Phase D (proofbundle 2.1.0), not before; this ADR is design-only.
- Threat-model, compliance, and interop implications are named there: the decision-receipt predicate widens the
  attestation surface (a new signed claim type), so its verify path and Non-claims must be as explicit as the
  eval-result path already is.
- The public commitment from the thread (maintainer answer, 2026-07-09) and the issue-body Non-goals edit are
  the external references this ADR honors; deviating from them would require re-opening the #565 discussion.
- Tracking: the upstream-standardization question stays on issue #26 (roadmap: upstream eval predicate); this
  ADR is linked there as the record of the separate-predicate decision.
