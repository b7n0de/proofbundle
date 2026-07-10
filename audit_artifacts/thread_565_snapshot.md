# #565 Thread Snapshot — in-toto/attestation

Erstellt: 2026-07-09. Issue: New predicate proposal: eval-result (AI/ML evaluation results).
Author: b7n0de · Created 2026-07-03 · Updated 2026-07-09 · 6 Kommentare.
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



---

## Verlinkter Thread — b7n0de/proofbundle#7 (anchors[]-Iteration, Landing-Spot aus #565)

Snapshot nachgezogen: 2026-07-10. Issue: *anchors[]: external time anchors for pre-registration (RFC 3161 TSA / OpenTimestamps)*.
Der in #565 (Zeile 85) als Iterations-Ort verlinkte Thread. Phase-A-Prinzip: **nur gesichert, NICHT beantwortet.** 8 Kommentare (bis 2026-07-10T04:12Z — MarkovianProtocols Punkt zum Anchor-Binding des pre-signature canonical object, auf dem die predicate-anchors-Komposition WP6 offen iteriert).

### Issue-Body (verbatim)

Tracking issue for the discussion in in-toto/attestation#565.

Sketch: an optional `anchors[]` on the pre-registration path — each entry
`{type: "rfc3161-tsa" | "opentimestamps", canonicalRoot (RFC 8785 root of the
pre-registration object), proof}`. Multiple anchors over the same root; absence
is not a failure, presence is verified fail-closed; the trusted core stays
dependency-free (anchor verification as an optional extra, no network in verify).

Open questions: OTS pending→upgraded receipt workflow; TSA cert chain freezing
for offline re-verification; field naming.

Contributions welcome — a minimal worked example is a great starting point.


### Kommentare (verbatim, chronologisch)


#### 2026-07-05T18:53:32Z — b7n0de

The generic anchor layer is now implemented and shipped in **v2.0.0b2** (behind the opt-in `[anchors]` extra), so this issue moves from "proposed shape" to "here is the interface".

**What's built (v2.0.0b2, EXPERIMENTAL)**

- A generic, fail-closed `anchors[]` layer (`proofbundle.anchors`). Each entry is `{type, target, canonicalRoot, proof, anchoredAt}`. Two targets, never mixed: `preRegistration` (the commitment existed *before* the run — the backdating point) and `receipt` (existed *from* time T). `canonicalRoot` is the target's own canonical root, so a `preRegistration` anchor can never validate a `receipt` target and vice versa.
- Verify contract: missing anchors → SKIP (Monotonic Principle); present → a root mismatch, unknown type, or broken proof is a FAIL, never silent; `--require-anchor <type|any>`.
- **Two built-in types**, both delivered:
  - **rfc3161-tsa** — offline verify against the TSA chain *frozen* into the anchor at emit time (a TSA can rotate — FreeTSA rotated its cert in March 2026). Proven against a real captured FreeTSA token incl. a cert-rotation test.
  - **opentimestamps** — honest lifecycle: a PENDING proof is a WARN (never a full anchor); an upgraded proof needs a Bitcoin block header (a local pruned node) to verify offline, and without one is reported upgraded-unverified, never a silent pass.

**Extension interface (bring your own anchor type)**

```python
from proofbundle.anchors import register_anchor_type

def verify_my_anchor(proof: bytes, canonical_root: bytes, *, frozen: dict, now):
    # return {"ok": bool, "detail": str}; MUST be fail-closed (ok=False on any doubt, never raise
    # for an ordinary bad proof). canonical_root is already matched to the target.
    ...

register_anchor_type("my-org/my-anchor/v1", verify_my_anchor)
```

The layer enforces the `canonicalRoot ↔ target` binding for you; the type just proves its `proof` anchors those exact bytes at/for a time. See `docs/ANCHORS.md`.

A worked example of a third-party anchor type would be very welcome and would be credited. Everything here is EXPERIMENTAL and clearly labelled as such; nothing about it is standardized.


#### 2026-07-06T02:38:06Z — MarkovianProtocol

You shipped the whole layer before I finished the writeup, nice. The `target` split (`preRegistration` vs `receipt`) with `canonicalRoot` bound per-target is the right call: it closes the lift-a-receipt-anchor-onto-a-pre-registration hole structurally, and FAIL-on-present-but-broken (never silent) is exactly the discipline that makes an optional field safe to add.

Two contributions against v2.0.0b2:

**1. A real Bitcoin-confirmed OTS test vector for the `opentimestamps` type.** Your TSA path is proven against a live FreeTSA token, but the OTS *upgraded-verified* branch needs an actual Bitcoin-confirmed receipt to exercise (vs pending-WARN / upgraded-unverified). Here is one, fully confirmed:

- `target`: `preRegistration`
- `canonicalRoot`: `sha256:5afa72991e876da463eb691749eac3424b992406b21cb0e21321d05ee9cc94aa` (SHA-256 of the RFC 8785 canonical pre-registration object, 366 bytes)
- OTS receipt upgraded to `BitcoinBlockHeaderAttestation(956857)`, block header time `2026-07-06 01:26:17 UTC`

Build script, canonical object, and the upgraded `.ots` are here: https://github.com/MarkovianProtocol/eval-anchor-vector . Drop it in as a fixture and the upgraded-verified path has a real end-to-end case (offline given a header source / pruned node, matching your contract).

**2. Taking you up on the third-party anchor type.** The worked example on our side is a `markovian-provenance/v1` anchor type registered via `register_anchor_type`: its `proof` is a Bitcoin-anchored Markovian stamp over the same `canonicalRoot`, fail-closed verify (existence + commitment check, no producer trust, `ok=False` on any doubt). That gives you a second independent Bitcoin-rooted anchor next to OTS, and a concrete exercise of the extension interface. I will build it against your `verify_my_anchor(proof, canonical_root, *, frozen, now)` signature and open it as a PR with the fixture. Good?


#### 2026-07-06T10:20:28Z — b7n0de

Yes to both. Please open the PR.

Before replying I reproduced your vector independently and offline: recomputed both salted commitments from the reveal, recanonicalized the object per RFC 8785 (366 bytes, byte identical), got the same `canonicalRoot`, decoded the receipt (1529 bytes, sha256 848e2615) and parsed it down to `BitcoinBlockHeaderAttestation(956857)` committing to exactly that root. Everything checks out. I also ran that last step the verifier contract calls for, the header check against an independent block header source: block 956857's merkle root matches on two independent explorers, so the vector holds end to end, not just to the attestation.

Plan for the fixture: it lands under the anchors test tree as data only, wired into the upgraded and verified end to end case, keeping FAIL on present but broken semantics. For the `markovian-provenance/v1` PR three guardrails so review is fast: anchor type goes in via `register_anchor_type` only, fixtures are pure data with no executable payload on the verify path, and verify stays fail closed exactly as you describe it, existence plus commitment check, no producer trust, `ok=False` on any doubt. MIT, DCO signoff, CI runs the offline verify.

Thanks for the vector. This is exactly the kind of contribution the extension interface was built for.


#### 2026-07-07T17:43:49Z — b7n0de

Status: the external time-anchor layer is released in the **v2.0.0b3 pre-release** (`anchors[]` with `rfc3161-tsa/v1`, `opentimestamps/v1`, plus the worked third-party types `markovian-provenance/v1` and `chia-datalayer/v1` — see the README section *External time anchors*). Install: `pip install --pre proofbundle`. Keeping this open until the layer lands in a stable 2.0.0 release; feedback on the beta welcome.


#### 2026-07-09T23:34:56Z — b7n0de

The dual-anchor worked vector promised in the #565 thread (OTS + RFC 3161 TSA, `canonicalRoot` invariant across the OTS upgrade, pending vs confirmed) is hosted in this repo: shape in [`docs/ANCHORS_MARKOVIAN.md`](https://github.com/b7n0de/proofbundle/blob/main/docs/ANCHORS_MARKOVIAN.md), verified by `tests/test_anchors_markovian.py` / `test_anchors_rfc3161.py` / `test_anchors_ots.py` against fixtures under `tests/fixtures/anchors/`. The `canonicalRoot` is the SHA-256 of the RFC 8785 canonicalization of the pre-registration object; both anchors bind the identical root as interchangeable evidence for one committed-by-time-T claim. The shape will be mirrored into the predicate PR in Phase D per the #565 note.


#### 2026-07-10T01:17:26Z — MarkovianProtocol

Dual-anchor writeup reads correctly, and the property that matters is stated exactly right: one `canonicalRoot` bound as interchangeable evidence across both anchors, invariant across the OTS pending -> confirmed upgrade. That invariance is the reason to split `target` from `type`, and the tests pin it.

One detail worth underlining because it is the usual OTS interop footgun: the value in `frozen.bitcoinBlockHeaderMerkleRootsByHeight` is `hashMerkleRoot` in internal (node) byte order, what `bitcoind` returns and what the attestation commits to, not the reversed display order an explorer prints. The doc has it right; flagging it so nobody reimplementing the type against a block explorer trips on it.

Next step for real interop: `github.com/MarkovianProtocol/tlog-bitcoin-anchor` has independent Go and Python verifiers and test vectors over the same RFC 8785 -> sha256 -> Bitcoin-anchored-root path. Point `test_anchors_markovian.py` at one of those vectors and the canonicalization and root derivation get checked against a second implementation, not only proofbundle's. The stronger variant the doc flags, OTS over `merkle_root` so the wallet sits inside the Bitcoin-committed preimage, is a clean follow-up fixture when Phase D mirrors the shape into the predicate PR; I can supply that one confirmed the same way.


#### 2026-07-10T03:14:19Z — b7n0de

Confirmed on the byte-order note — the vector commits to hashMerkleRoot in internal byte order as returned by bitcoind, and the tests compare against that form, not explorer display order. Good to have it flagged explicitly for reimplementers.

On interop: we'll vendor one or two of your tlog-bitcoin-anchor test vectors (pinned by digest, so CI stays offline) and point test_anchors_markovian.py at them — that way canonicalization and root derivation get checked against a second implementation rather than only round-tripping our own. We'll also run your Go and Python verifiers against our vectors in the same pass and report anything that doesn't line up.

And yes to the stronger-variant fixture (OTS over merkle_root, wallet inside the Bitcoin-committed preimage) — a confirmed vector of that shape would slot in as a follow-up fixture, and it's the shape we'd mirror into the decision-receipt work as well.


#### 2026-07-10T04:12:51Z — MarkovianProtocol

On what the decision anchor binds to: there's a real reason to anchor the pre-signature canonical object rather than the full signed payload, and it comes from your own composition rule.

Everything you want inside the committed bytes (verdict, evidence digests, policy digest, not-checked set, decision-change conditions) already lives in the pre-signature statement object. The only thing anchoring it excludes is the signature bytes, and excluding them is the point:

- ES256 is non-deterministic. The same content signed twice produces different bytes, so anchoring the signed payload gives one decision two different existence proofs depending on which signature instance you hashed. Anchoring the content gives the decision one stable root.
- Re-signing, counter-signing, and key rotation all preserve the content root but change the signed-payload root. A decision's existence-in-time should not move because a second signer was added.
- Composition needs it. When the decision statement references the evidence statement by canonical root, that reference has to resolve to the evidence's content root, or it breaks the moment the evidence is re-signed. Both sides referencing content roots keeps the ordering property you described.

The signature stays a separate layer binding the same content, so "who attested" is still proven, just not fused into the content's existence proof. Your enclave SHA-256-over-signed-payload can stay as its own "this enclave emitted this exact blob" binding, distinct from the cross-statement anchor root.

On interop: vendoring the `tlog-bitcoin-anchor` vectors pinned by digest and running the Go and Python verifiers against your fixtures is exactly the second-implementation check that keeps canonicalization honest. I'll produce the stronger-variant fixture (OTS over `merkle_root`, wallet inside the committed preimage), confirmed, as a follow-up, and extend the worked vector to a decision object for `decision-receipt/v0.1`.

