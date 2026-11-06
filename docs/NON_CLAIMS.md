# What proofbundle does NOT claim

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
  statement. A Trust Pack binds only `executor.keyId` to the signing key; an anchored executor key can
  write any `executor.id`, and the outcome verifies with `executor_role_trusted` true. Role separation
  compares that statement with the decision maker's id (docs/predicates/action-outcome.md §5 and §7).

## Steps of draft-gruszka-audit-decision-receipts-05 that proofbundle does not perform

The offline verification of that draft (sections 3.1 to 3.4) asks the verifier for three inputs that
`proofbundle decision verify`, `proofbundle outcome verify`, `verify_decision_receipt` and
`verify_outcome_receipt` do not take. A pass of proofbundle on such receipts is therefore not a pass of
the draft's procedure:

- **The effect bytes** (section 3.1, section 3.4 step 6). proofbundle reads `effectDigest` as a digest
  and compares it with no bytes.
- **The expected `executor.id`** (section 3.1, section 3.4 step 5), and a trust policy that permits the
  outcome-signing key to attest that identifier.
- **The approval record bytes of Case 1** (section 3.3), with the bounds approvedAt <= decidedAt <= T <
  validity.expiresAt <= validUntil.

The three inputs are scheduled for 6.6.0.

## TEE attestation bridge (experimental)

A verified enclave Attestation Result does **not** prove the enclave is genuine, the vendor's root of
trust is sound, or the eval inside was honest — proofbundle checks the *Verifier's* signature and the
receipt binding, never raw hardware evidence (see EXPERIMENTAL_ENCLAVE.md). "TEE-attested" is never
"computation proven correct".

If you need any of the things on this list, a receipt is the wrong tool for that part — use it for the
one thing it does, and reach for an audit, a benchmark study, or a governance process for the rest.
