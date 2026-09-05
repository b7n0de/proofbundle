# Proposal: an outcome that cites a refusal gets a verdict, not silence

Status: PROPOSAL for 6.1.0. Nothing here is built, and no code for it exists in this tree. It is
written so that the rule, its blast radius and its cost can be judged before anyone implements it.
The measurement it rests on is our own: on 2026-09-04 and again on 2026-09-05 our verifier read an
`action-outcome` with `status: executed` bound to a `decision-receipt` carrying `DENY` and reported
`ok: true` with no warning, because the verdict is never read on the outcome path.

## The gap, stated once

An outcome receipt names the decision that authorized it by content root. Our outcome verify path
checks that the citation matches what the caller expects, that the executor is not the decision
maker, and that an effect digest is present. It never asks what the cited decision decided. A
receipt pair that records "the gate said no, and it happened anyway" is therefore indistinguishable,
to our verifier, from a pair that records "the gate said yes, and it happened".

This is not a signature bug and not a canonicalization bug. Both receipts are sound: each says
exactly what its signer meant. The gap is that no check reads the two together.

## The rule proposed

When `verify_outcome_receipt` verifies an outcome whose status records an execution, and the cited
decision receipt is available to it, the decision's verdict decides a new field:

- The cited decision is available and its verdict is a refusal (`DENY` or `REFUSE`): the aggregate
  verdict is failure with the reason code `outcome-against-refusal`, fail closed.
- The cited decision is available and its verdict allows (`ALLOW`): unchanged, as today.
- The cited decision is available and its verdict is neither (`ESCALATE`, `DEFER`, `OBSERVE`): a
  typed reason of its own, never silence and never a refusal verdict; the proposal recommends
  `outcome-against-unresolved-decision`.
- The cited decision is not available: a typed `NOT_APPLICABLE` with the reason "cited decision not
  supplied", never a silent clean result.

"Available" means the decision statement itself reached the verifier: attached in the same bundle,
handed over through the `related` channel that the relation path already uses, or resolved by a
caller-supplied resolver. A content root alone is not availability. A root is a name, not a document,
and a rule that read a verdict out of a name would be inventing one.

## What changes for what exists today, measured

Measured on 2026-09-05 on the frozen head `049b3195`, over the tracked tree.

Committed receipt pairs in the repository, fixtures and goldens together

    0

Committed JSON carrying an `action-outcome` predicate: the schema and one parity-registry entry. The
three cross-implementation conformance cases under `conformance/decision/crossimpl/` are decision
only, with no outcome beside them.

`verify_outcome_receipt` call sites in the test suite

    52

Of those, call sites that hand the verifier a decision object through `related`

    3

Of those three, call sites where the attached object is a decision receipt

    0

All three attach a relation target for the lineage checks, not the authorizing decision.

Call sites that pin `expected_decision_ref` and so carry the root but not the document

    10

Decisions built by the test suite carry `ALLOW`; no test binds an executing outcome to a `DENY` or
`REFUSE` decision. Under the rule above, therefore:

- Pairs in this repository that turn from clean into a refusal verdict: **0**.
- Pairs in this repository that turn from clean into `NOT_APPLICABLE`: **0** if the new field is
  additive, **49** call sites if `NOT_APPLICABLE` were ever wired into the aggregate `ok` (52 minus
  the 3 that pass an object today, none of which is a decision).

Two pairs outside the repository do change, and both are ours: the pair measured on 2026-09-04 that
this document exists because of, and the pair the Cedulon adapter builds from a frozen third-party
fixture (`scripts/interop/cedulon_leaked_refusal_adapter.py`, measured 2026-09-05). Both verify clean
today and would be `outcome-against-refusal` under the rule.

## The version question, which is the owner's

The measured blast radius is zero inside the repository, so the change is cheap to make and cheap to
get wrong. Two shapes are possible and the difference is a promise, not a line count.

Additive field, 6.1.0. A new result field and a new reason code, `ok` unchanged, the cross-check
reported and not enforced. Nothing that passes today starts failing. The cost is that a relying party
who reads `ok` alone keeps the blind spot, which is the same shape of defect the `execution_proven`
deprecation notice already warns about in this codebase.

Enforcing field, 6.1.0 with a policy switch defaulting to off, or a breaking version with it on.
`ok` becomes false for a pair that records an effect against a refusal. Nothing in this repository
changes, but any downstream pair of that shape starts failing, which is the point of the rule and
also the reason it cannot be slipped into a patch release.

Recommendation, without pre-empting the decision: ship the field and the reason code additively in
6.1.0, together with the policy switch that promotes it to the aggregate verdict, and leave the
switch off by default. That gives a relying party the choice we do not have the standing to make for
them, and it keeps one promise this project has kept so far, that `ok` never silently changes meaning
between minor versions.

## Test plan

Reproducers, both from bytes that already exist:

- The pair of 2026-09-04, rebuilt with `proofbundle decision init|emit` and `outcome init|emit`, a
  `DENY` decision and an `executed` outcome citing it by content root.
- The adapter pair from the frozen Cedulon fixture at `06c3119`, built by
  `scripts/interop/cedulon_leaked_refusal_adapter.py`, whose report records the fixture digests it
  refuses to run without.

Must-fire test. With the decision attached, the refusal pair reports `outcome-against-refusal`; the
same pair with the verdict changed to `ALLOW` and nothing else touched reports what it reports today.
Both directions in one test, so that a rule which fires on everything cannot pass as a rule that
fires on the right thing.

Availability test. The same refusal pair with the decision NOT attached reports the typed
`NOT_APPLICABLE` with its reason, and never a clean silence and never a refusal verdict on a document
it has not seen.

Mutation. Remove the verdict read and the must-fire test must go red; return `NOT_APPLICABLE` in the
attached case and the must-fire test must go red; return a refusal in the unattached case and the
availability test must go red. A rule whose removal leaves the suite green is not shipped.

Neighbour sweep, because the same blind spot is a shape and not one site:

- `relation`: an edge asserts a lineage between two statements; the verifier checks the edge and the
  targets it is handed. Whether a successor contradicts what its predecessor decided is not asked.
  Sweep for the same question and record the answer, whichever way it comes out.
- `eval`: an eval receipt carries a threshold verdict; a decision citing it as evidence is not
  checked against that verdict either. Same sweep, same recording.
- `agent-review`: a review receipt and the pull request it reviews are bound by digest, not by
  outcome, and the same question can be asked there.

The sweep is part of the work, not a follow-up. A class fix that lands on one driver and leaves its
siblings in the pre-fix shape is a defect class this project has already recorded twice.

## Honest limits of this rule

The cross-check sees only pairs the verifier is given together. An outcome that arrives without its
decision stays outside the rule, and an executor who simply omits the citation is not caught by it at
all. That is the same limit our own documents already state for `execution_proven`, and naming it
here keeps the rule from being read as more than it is.

The rule says nothing about the truth of the outcome. A receipt that records an effect is not an
observation of that effect. A pair that reports `outcome-against-refusal` says the two signed
documents contradict each other, not which of them is lying.

The rule does not detect the case it most wants to detect, an effect with no record at all. Nothing
in a receipt format can, and no wording here should suggest otherwise.

## Where this came from

`draft-dogru-cedulon-decision-profile-02`, section 8.1, lines 980 to 1001, retrieved 2026-09-05,
names this case D1 and cites our measurement of it as `[B7N0DE]`. Its wording is that a decision
carrying a refusal and an outcome recording execution "verified clean with no warning, because the
verdict is not read on the outcome path". That is a description of our artefact, and it is accurate.
The mapping cell it refers to is Table 3c of `docs/SCITT_CPB_MAPPING.md`.

The same frozen fixture was read by a second implementation, the EMILIA Outcome Binding path
(`verifyOutcomeBindingSet`), recorded in the companion's `docs/EXTERNAL_REVIEW.md` Round 10 at
`e26f50f`, retrieved 2026-09-05, which reports `lifecycle_state=reconciled`, `outcome=divergent`,
`valid=false` for it. That is their record of their run, quoted and not interpreted; this proposal
makes no claim about what either implementation should do, and the two readers' own boundary, that a
pinned raw fixture read through separately owned adapters is not native-format interoperability,
belongs with the citation.
