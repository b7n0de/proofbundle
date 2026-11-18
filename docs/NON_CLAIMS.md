# What proofbundle does NOT claim

**What a proofbundle receipt does not prove.**

A receipt lets you check the signed content and the integrity properties its format supports. In a native proofbundle evidence bundle, the Ed25519 signature covers the payload, not the entire JSON file. A passing check alone does not identify a trusted signer or establish that the result is true; trust in the key requires an independently obtained public key. This page lists those limits.

## Good to know

- For anything on this list, use an audit, a benchmark study or a governance process.
- The page also names the steps of the decision receipt draft that the verifiers do not perform.

The [full list](#technical-details) follows below, for eval receipts, decision receipts, action outcomes and the experimental enclave bridge.

## Technical details

proofbundle exists to make one narrow thing checkable — *who signed these exact eval bytes, and that
nothing changed since* — and to keep the scope of that claim honest. This page is the negative list.
It is deliberately blunt so a reader never mistakes a receipt for more than it is.

A proofbundle receipt (and any in-toto export or SVR derived from it) does **not** prove:

- **Semantic truth of the result.** That the reported metric is *correct*, that the eval was run the
  way it says, or that the number is not the product of a bug, a leaked test set, or a gamed harness.
  A receipt authenticates a *claim*; it does not audit the computation behind it.
- **Fairness.** Nothing about bias, disparate impact, or representativeness of the dataset.
- **Safety.** A passing safety-suite threshold is a threshold on one suite, not a statement that a
  model is safe to deploy. Safety is a human judgement over context the receipt cannot see.
- **Generalization.** That the score holds on any distribution other than the exact suite that was
  run. A receipt is bound to its suite, not to the world.
- **Correctness of the threshold or the metric choice.** Whether `refusal_rate >= 0.98` is the *right*
  bar is an eval-design question. The receipt only attests that the signed claim asserts it was met.
- **That the model or dataset is what its name suggests.** The identifiers are **salted commitments**;
  a receipt binds to a commitment, not to a verified real-world identity. Disclosure (identifier +
  salt) is a separate, later step.

It also does **not**:

- **Replace an audit.** A receipt is evidence *for* an auditor, not a substitute for one. It removes
  the need to blindly trust the number; it does not remove the need to review the eval.
- **Replace in-toto, SLSA, or a transparency log.** The in-toto export and SVR are *interop* views —
  they let a receipt travel in standard tooling. They add no trust that the native receipt did not
  already carry, and they are **proposed, not standardized** (see in-toto/attestation#565).
- **Require any specific anchor service.** External time anchors (RFC 3161 TSA, OpenTimestamps) are
  *optional*. Without them a pre-registration timestamp is producer-clock testimony only; that
  limitation is stated, never hidden. proofbundle is not tied to any one TSA, calendar, or vendor.
- **Depend on a network to verify.** Verification is offline and pure-Python. An anchor, if present,
  is verified against material bundled at emit time, not by calling out.

## Decision receipts (`decision-receipt/v0.1`)

The same discipline applies to the decision path. A verified Decision Receipt does **not** prove:

- **That the decision was correct, legal, or safe.** It proves the signed decision *record* has not
  been altered — a protocol entry, not a verdict on the decision's quality.
- **Authorization.** A verified ALLOW receipt is a *record* of a decision, **not an authorization
  token, not a bearer token, and not a capability**. Possession of a receipt authorizes nothing; the
  system executing an action must make its own authorization check. Against cross-context replay:
  issue receipts with `validity.audience` / `validity.nonce` and verify with `--aud` / `--nonce`
  (the value binding); a v0.2 trust policy's `require_audience` / `require_nonce` additionally
  enforce that those fields are *present*, so a receipt cannot silently drop replay protection.
- **That the action happened.** `actionOutcome: executed` without a digest-bound `outcomeRef` is
  self-asserted; the CLI says so (`action_outcome_proven: false`). An `outcomeRef` digest pins
  *which* outcome record is meant — whether that record is itself signed and by whom is a separate
  trust decision.

## Action outcomes (`action-outcome/v0.1`)

A verified Action Outcome does **not** prove:

- **That `executor.id` names the party that signed.** `executor.id` is the outcome signer's own
  statement unless a Trust Pack names it. Where the pack's entry for the executor key carries `executorIds`
  (6.6.0), an outcome under another identifier fails with `EXECUTOR_ID_NOT_ATTESTED`; without `executorIds`
  an anchored executor key can write any `executor.id`, and the outcome verifies with `executor_role_trusted`
  true and the warning `EXECUTOR_ID_NOT_BOUND`. Even a named identifier is a permission the pack grants to the
  key, not proof that the signer is that executor or observed its effect. Role separation compares
  `executor.id` with the decision maker's id (docs/predicates/action-outcome.md §5 and §7).

## Steps of draft-gruszka-audit-decision-receipts that proofbundle performs only with their inputs

`proofbundle decision verify`, `proofbundle outcome verify`, `verify_decision_receipt` and
`verify_outcome_receipt` take the inputs the offline verification of that draft names (sections 3.1 to 4): the
action bytes (section 3.2 step 10), the case the relying party chooses with the approval record bytes of Case 1
(section 3.3), the expected `executor.id`, the effect bytes and the bound decision receipt with the expected
`decisionMaker.id` and the evaluation time (section 3.4), and a consumption state with the copies of an approval the
relying party received (section 4).

Without an input its check is not performed. Some inputs depend on others, and a missing partner then fails the
check instead of skipping it; for example a bound decision receipt needs its key and the expected
`decisionMaker.id`, approval record bytes need the approval case, received copies need the consumption state, and a
consumption state needs the approval case. A chosen case fails without an input it requires (Case 1 without the
approval record bytes, Case 3 without the bound decision receipt and its key, the expected `decisionMaker.id` or the
expected `executor.id`). Without an evaluation time the wall clock is read once. Effect bytes stay optional in
Case 3. Section 3.1 requires the expected
`executor.id` and, for Case 1, the approval record bytes, so a pass without them is not a pass of the draft's
procedure.

These verifiers are not a complete implementation of the draft's procedure. Even with every input supplied, a
receipt the draft rejects can pass them: in places the draft's field rules (section 3.8) are narrower than
proofbundle's own. Measured examples, not a complete list:

- **An evaluation time before `decidedAt`** (section 3.2 step 9) outside Case 1. The decision verifier compares
  the evaluation time with `validity.expiresAt` only, and so does the check of a decision an outcome is bound to;
  Case 1 checks approvedAt <= decidedAt <= T itself.
- **Values the draft's field rules refuse:** a `decisionType` other than `preActionAuthorization`, an audience
  entry that is no non-empty string, and a JSON null inside `decision.obligations` or inside an outcome's
  `validity.audience` pass the check of a bound decision and the executed case.
- **A declined decision without `validity.expiresAt`** passes `decision verify` with the declined case. A bound
  decision without it fails the binding, whose time window reads that field.
- **Timestamps outside the form a coming revision of the draft sets** in a field these verifiers read only for its
  RFC 3339 form, such as `recordedAt` of a decision or of an outcome: more than six fraction digits, or second 60.
  The times they compare, `decidedAt` and `validity.expiresAt` of a decision and `performedAt` of an outcome, are
  read in that form and fail with more than six fraction digits.
- **An evaluation time with a fraction of a second.** `--verification-time` takes a whole past second, on
  `decision verify` and on `outcome verify` alike.
- **A trust policy that permits the outcome-signing key to attest `executor.id`** (section 3.4 step 5), other
  than the relying party's own statement: `--executor-id` given beside `--pub` says that this key may attest that
  identifier. `verify_outcome_receipt` checks such a permission only when a Trust Pack is supplied and the
  entry of the executor key carries `executorIds` (6.6.0); a pack without them binds `executor.keyId` to the key,
  not an identifier.
- **Honouring an approval at most once** (section 4 items 1, 3 and 6). proofbundle reads a supplied consumption
  state and never writes it; marking an approval consumed durably, and keeping the state, stay with the relying
  party. A pass says only that the approval identity is not in the state given.

## TEE attestation bridge (experimental)

A verified enclave Attestation Result does **not** prove the enclave is genuine, the vendor's root of
trust is sound, or the eval inside was honest — proofbundle checks the *Verifier's* signature and the
receipt binding, never raw hardware evidence (see EXPERIMENTAL_ENCLAVE.md). "TEE-attested" is never
"computation proven correct".

If you need any of the things on this list, a receipt is the wrong tool for that part — use it for the
one thing it does, and reach for an audit, a benchmark study, or a governance process for the rest.
