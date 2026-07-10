# #565 Thread Snapshot — in-toto/attestation

Erstellt: 2026-07-09. Issue: New predicate proposal: eval-result (AI/ML evaluation results).
Author: b7n0de · Created 2026-07-03 · Updated 2026-07-10 · 8 Kommentare.
Maintainer-Reaktionen (in-toto Org): siehe Autoren-Zeilen. NICHT beantwortet (Phase A = nur Snapshot).

## Issue-Body (verbatim, editiert mit Non-goals)

Hi maintainers — before opening a PR (per `docs/new_predicate_guidelines.md`), I'd like to check whether a new `eval-result` predicate would be welcome, or whether you'd prefer this be expressed as extension fields on an existing predicate.

### Use case

Signed, offline-verifiable AI/ML eval results — a `metric <comparator> threshold` verdict over N samples, with:

- salted model/dataset commitments (prove a threshold without revealing either),
- an optional per-sample RFC 6962 Merkle root (forced-random-sample audit),
- an optional pre-registration binding.

Today that's unsigned prose in a system card.

### Why not an existing predicate / SVR extension

- `test-result` = PASSED|WARNED|FAILED + test names (no metric/threshold/dataset digest/commitments/per-sample).
- `svr` = a property list vs policies — a benchmark result is a structured graded record (metric, comparator, threshold, commitments, assuranceLevel, Merkle root, preRegistration) that doesn't map onto SVR's `properties` array without re-inventing a schema in a free-form field.

Genuinely open to SVR-extension guidance.

### Positioning and non-goals

An ML/eval-metrics predicate (not agent-governance/decision). Describes what was claimed, by whom — not that the eval is uncontaminated/honest.

`eval-result` is metric/benchmark evidence only. It is explicitly NOT an agent-decision attestation, an action authorization, a policy verdict, or an action-outcome record. No action/policy/decision fields will be added to this predicate — a separate decision-oriented predicate MAY reference signed `eval-result` statements by digest instead. The predicate attests a signed claim about an evaluation, not that the metric is true, the benchmark well designed, or the model safe.

### Reference implementation

MIT, which I maintain — already emits DSSE-signed in-toto statements + RFC 6962 proofs: https://github.com/b7n0de/proofbundle

### Ask

A PR would bring `eval-result.md` (per template) + README entry + protobuf, DCO-signed + markdownlint-clean. Would a new-predicate PR be welcome, or prefer a community meeting / SVR extension first?

*(Edit 2026-07-09: reformatted for readability and made the non-goals explicit, following the feedback below.)*


## Kommentare (verbatim, chronologisch)

### 2026-07-05T00:00 — MarkovianProtocol

The pre-registration binding is the part of this proposal where an external anchor earns its place. proofbundle's Ed25519 + RFC 6962 structure already covers who-signed and per-sample integrity, and the verdict (`metric <comparator> threshold`) is recomputable from the salted commitments. What that structure can't establish on its own is that the threshold and dataset/model commitments were fixed *before* the eval was run. Pre-registration is only meaningful if "committed before" is provable to a third party, and a self-emitted timestamp or the producer's own clock doesn't provide that.

The conventional fix is an RFC 3161 TSA over the pre-registration commitment, which works but reintroduces a trusted timestamping authority. An operator-independent alternative is to anchor the RFC 8785 canonical root of the pre-registration object (threshold plus salted commitments) via OpenTimestamps to Bitcoin. That yields a "this commitment existed by time T" proof any verifier can check offline, with no account and no trusted TSA, so the pre-registration claim stands independent of the producer. Anchor latency is hours, which is fine since the commitment is made before the run.

Concretely this could be an optional field on the predicate, an `anchor` object carrying the canonical root and the OTS proof alongside the existing signature. It changes nothing about the offline verdict check; it only makes the temporal ordering (committed-then-ran) verifiable without trusting the producer's clock. If that's a direction you'd take, I can share a minimal worked example and draft the field.


---

### 2026-07-05T00:47 — b7n0de

@MarkovianProtocol Thanks — you've hit exactly the honest gap in this draft, and it's one we
document in the reference implementation: a self-emitted timestamp is producer-clock
testimony, nothing more. Pre-registration without an external anchor proves ordering only
to someone who already trusts the producer.

Agreed on both options, and I'd frame them as complementary optional anchors rather than
either/or:

- **RFC 3161 TSA(s)** — minutes of latency, but reintroduces a trusted authority; partially
  mitigated by anchoring the same commitment at two independent TSAs.
- **OpenTimestamps over the RFC 8785 canonical root** — operator-independent, no account;
  verification is offline given a Bitcoin block-header source, and the hours of anchor
  latency are fine since the commitment precedes the run. One workflow detail worth
  reflecting in a field draft: the initial OTS receipt is a pending attestation until the
  Bitcoin confirmation lands, so producers need an upgrade step before the proof is
  self-contained.

Concretely: an optional `anchors[]` on the predicate — e.g. `{type, canonicalRoot, proof}` —
so a producer can attach a TSA token and/or an OTS proof over the same canonical root, and
relying parties choose their trust model. As you say, it changes nothing about the offline
verdict check; it only makes committed-then-ran verifiable without trusting the producer's
clock. (And the shape isn't eval-specific — other predicates wanting committed-before
evidence could reuse it.)

A minimal worked example and field draft would be very welcome — I've opened
https://github.com/b7n0de/proofbundle/issues/7 as a landing spot to iterate in the
reference implementation, and I'd gladly fold the result into the predicate PR here with
credit to you.

Maintainers: would an optional `anchors[]` like this fit the new-predicate guidelines, or
would you prefer temporal anchoring handled outside the predicate?

---

### 2026-07-06T00:36 — MarkovianProtocol

Happy to land the worked example. `anchors[]` as an array is the better shape, it lets a producer attach more than one anchor over the same commitment and lets the relying party pick which trust model it accepts.

Minimal example, two anchors over one pre-registration object, so a verifier can choose:

```json
"anchors": [
  { "type": "ots",     "canonicalRoot": "sha256:9f2c…e41a", "proof": "<base64 OpenTimestamps receipt, upgraded>" },
  { "type": "rfc3161", "canonicalRoot": "sha256:9f2c…e41a", "proof": "<base64 TSA token>" }
]
```

`canonicalRoot` is the SHA-256 of the RFC 8785 canonicalization of the pre-registration object (threshold plus salted commitments), the same bytes the verdict already recomputes from. Both anchors bind the identical root, so they are interchangeable evidence for one "committed by time T" claim, not two different claims.

On the pending-vs-confirmed point you raised, that is the one workflow rule worth stating in the field draft, because it is where a naive verifier goes wrong:

- The `canonicalRoot` is invariant across the OTS upgrade. Only the `proof` bytes change once the Bitcoin attestation lands.
- A verifier MUST treat an un-upgraded (calendar-only) OTS proof as *not yet anchored*, i.e. the absence of a temporal anchor, not a weaker one. It says nothing about Bitcoin time until the block attestation is present.
- So the producer's upgrade step is a precondition for the anchor to count, and the verifier check reduces to: does `proof` resolve to a Bitcoin block header whose time is at or before the run's start. Offline, given a header source.

Agreed it is not eval-specific. The object only references a canonical root and a proof, nothing about metrics or datasets, so any predicate wanting committed-before evidence can carry the same `anchors[]`. That argues for it living as a shared optional field rather than inside `eval-result`, with `eval-result` being the first predicate to use it, if the maintainers are open to that.

I will iterate the field and a full worked vector (canonicalization input, root, upgraded OTS receipt, verify transcript) on b7n0de/proofbundle#7 and mirror the shape back here for the predicate PR.

---

### 2026-07-06T10:20 — b7n0de

Agreed on all three points. `anchors[]` as a shared optional field rather than something inside `eval-result` matches what we see implementing it: the anchor object references only a canonical root and a proof, nothing eval specific.

On pending versus confirmed, I would pin your rule verbatim in the field draft: a verifier MUST treat a calendar only OTS proof as the absence of a temporal anchor, not as a weaker one, and `canonicalRoot` is invariant across the upgrade while only the proof bytes change.

Implementation status on our side, as a data point for the draft: proofbundle v2.0.0b2 ships the target split (`preRegistration` vs `receipt`) with `canonicalRoot` bound per target and fail closed verify on any present but broken anchor. A Bitcoin confirmed worked vector now exists and was reproduced independently offline. Happy to host the full worked vector including the verify transcript, and to keep proofbundle tracking the field draft as a reference implementation.


---

### 2026-07-09T07:38 — clementineCU

One field-boundary note from agent evaluation work: this proposal is strongest if it keeps `eval-result` as metric evidence, not as an agent-decision attestation.

For autonomous agents, a benchmark result often gets misread as "the agent should act." The reviewable record needs a separate decision receipt: input/source snapshot, policy or risk boundary, action taken or refused, fields explicitly not checked, and the condition that would change the decision.

That does not need to live inside `eval-result`. It may be better as a separate predicate that can reference the signed eval statement, so verifiers can distinguish "this model cleared threshold X on benchmark Y" from "this agent used that evidence to make/refuse action Z."

---

### 2026-07-09T16:46 — b7n0de

Thanks, this boundary is exactly right, and we'll keep it. 
`eval-result` stays metric evidence only; we won't extend it toward agent-decision attestation.

For the agent-decision side we're speccing a separate vendored predicate (`decision-receipt`) in proofbundle that records: input/source snapshot (digests), the policy/risk boundary (policy id + digest + decision path), the proposed action and verdict (allow/deny/refuse/escalate), fields explicitly not checked, and the conditions that would change the decision. It references signed `eval-result` statements via digest-bound evidence refs, so verifiers can distinguish "model cleared threshold X on benchmark Y" from "this agent used that evidence to make/refuse action Z."

I'll update this proposal with an explicit non-goals section to pin that boundary. If a decision-receipt predicate ever seems upstream-worthy, we'd bring it here as a separate discussion rather than widening this one.

---

### 2026-07-10T01:17:25Z — MarkovianProtocol

The boundary is right, and the decision receipt is the right place to draw it. The fields listed above (input/source snapshot, policy or risk boundary, action taken or refused, fields explicitly not checked, the condition that would flip it) are what make a decision reviewable at all, and keeping them out of `eval-result` keeps the two claims honest: the eval statement attests a metric, the decision statement attests a choice that used it.

One thing carries over directly from the anchor discussion above. A `decision-receipt` that binds its evidence by digest proves which `eval-result` statements were referenced and what verdict was recorded, but on its own it does not fix when the decision was made relative to those inputs, and that ordering is exactly what a reviewer wants when a decision is later contested. The same `anchors[]` we've been drafting for `eval-result` applies unchanged: take the RFC 8785 canonical form of the decision object (input digests, policy id and digest, action, verdict, the not-checked set), commit it, and attach an OpenTimestamps-to-Bitcoin and/or RFC 3161 anchor over that `canonicalRoot`. That makes "this decision, over these inputs, existed by time T and has not been altered" checkable offline by someone who was not present when it was made.

So the two predicates compose cleanly: `eval-result` (metric evidence) <- digest ref <- `decision-receipt` (the choice), each carrying its own `anchors[]` over its own canonical root. The evidence is anchored independently of the decision that cites it, which is what lets a verifier separate "model cleared threshold X on benchmark Y" from "agent acted on it at time T."

@b7n0de we have this working end to end on our side (canonicalization, Bitcoin-confirmed anchor, offline verify transcript) and are iterating the field on proofbundle#7. Glad to extend the same worked vector to a decision object so the `decision-receipt` spec has a reference implementation the day it lands.

---

### 2026-07-10T03:06:39Z — b7n0de

Thanks, agreed on all points, and your composition rule is exactly how we intend to build it: each statement anchors its own canonical root, so evidence and decision get independent existence proofs and a reviewer can order them without trusting either issuer's clock.

One spec detail we'd like to pin precisely: what the decision anchor binds to. Rather than canonicalizing a field subset, we currently lean toward anchoring the RFC 8785 canonical form of the full signed statement payload — that way the verdict, evidence digests, policy digest, not-checked set and decision-change conditions are all inside the anchored bytes, and the binding rule matches how our enclave binding already works (SHA-256 over the signed payload). If you see a reason to anchor the pre-signature object instead, b7n0de/proofbundle#7 is the right place to hash that out.

And we'd gladly take you up on extending the worked vector to a decision object. The ADR just landed (b7n0de/proofbundle#44); the draft spec will follow as decision-receipt/v0.1 under our vendored namespace, and an independent reference anchor implementation from day one is exactly the kind of check that keeps it honest.

---

