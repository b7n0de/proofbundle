# Agent review predicate `agent-review/v0.1` and `agent-review/v0.2`

Status: **v0.1, Tier 1 — a signed self-declaration.** Emitted and verified by
`src/proofbundle/agent_review.py`; that module is the normative implementation, this document
explains it. Conformance vectors live in `conformance/agent_review/`. **Since 6.0.0 the emitter
produces `agent-review/v0.2` without an argument**; v0.1 stays readable and its verifier is
byte-pinned. What v0.2 adds is in the section *Version 0.2* at the end of this page; everything
above it holds for both versions unless that section says otherwise.

## The one sentence everything follows from

**A strong signature must not optically harden a weak self-report.**

A pull request or an issue often carries a sentence like "an AI agent helped here, and it was
reviewed". Today a reader has to believe that sentence. This predicate lets a reader check, offline,
that the stated key signed exactly these bytes and that they have not changed since. It does not,
and cannot, make the sentence true.

## What a v0.1 receipt does NOT prove

It does not prove that the named agent was really involved. It does not prove that every review run
was captured, that a model was fresh or independent, or that the stated time is externally witnessed.
Every receipt carries these limits in its own `limitations` and `declaration.nonClaims` blocks, and
both are structurally mandatory: a receipt that states no limit is claiming more than this predicate
can carry, and the validator rejects it.

## Three layers, kept apart

| Layer | What it holds | Who can produce it |
|---|---|---|
| `declaration` | what the author or agent CLAIMS | the producing agent |
| `observations` | what a runner, platform or witness SAW | a witness outside the agent — **not available in v0.1** |
| policy | what the relying party requires | the target repository, elsewhere |

Collapsing these into a single green status produces exactly the wrong effect. So each declared item
carries its own `assurance`, drawn from `selfDeclared`, `runnerObserved`, `platformAttested`,
`independentlyWitnessed` — and **v0.1 emits only `selfDeclared`**. The higher rungs are refused at
emit time, not merely reported at verify: a receipt that cannot be produced cannot be shown to
anyone. `observations` must be empty for the same reason.

Tier 2 (runner-observed) and Tier 3 (independently witnessed) need a witness outside the agent's own
workspace. That is a separate product step and is deliberately **not half-built** here.

## Subject binding

A PR number, a branch name or a URL points at something that can still change, so none of them is
the subject. A pull-request receipt binds `repositoryId`, `pullRequestNodeId`, `headSha`, `baseSha`,
`reviewedDiffDigest` and `bodyCoreDigest`. An issue has no head sha, no merge base and no diff, so it
gets its own profile: `issueNodeId`, optional `commentNodeId`, `bodyCoreDigest` and `revisedAt`.

The statement's subject digest is taken over the **subjectContext alone**. A receipt copied onto
another pull request therefore carries the old context and fails the binding check, while remaining
cryptographically sound — which is precisely the failure this binding exists to expose.

### `bodyCoreDigest` and the self-reference problem

The visible disclosure block contains the receipt digest, and the body containing that block is
itself part of what the receipt describes. A digest cannot be defined over bytes that contain its own
value, so the block is delimited by fixed markers and replaced by a fixed token before hashing:

```
<!-- proofbundle:agent-review:begin -->   … block …   <!-- proofbundle:agent-review:end -->
                                    ↓ replaced by ↓
<!-- proofbundle:agent-review:disclosure -->
```

The token is part of the wire format. Two implementations that pick different tokens compute
different digests over the same body, and the mismatch would look like tampering.

**Fail-closed on ambiguity.** Zero blocks is the normal pre-disclosure case and hashes as-is. Two
blocks, or a begin without an end, is not a body that reduces to one canonical form: an actor who may
append a second block could otherwise choose which one defines the digest. That case raises rather
than picks.

## Validity is not currency

A receipt stays cryptographically valid after a force-push, a description edit or a new review. It
then describes a state that is no longer the current one. Currency is a separate axis, and the
offline verifier reports `CURRENTNESS_UNKNOWN` — always. That is not a gap in the implementation: a
verifier with no live lookup and no trusted checkpoint cannot know whether the object still looks
like the reviewed state, and reporting `CURRENT` from offline data would be the exact overclaim this
predicate exists to avoid.

Time is likewise four separate questions, never one field: `declaredAt`, `observedAt`, `signedAt`,
`anchoredAt`. **`anchoredAt` must be null in v0.1.** A signature proves the signed bytes contain a
time value, not that the value is externally true, and this predicate carries no anchor evidence.

## Coverage

`COMPLETE` requires an integer `observedRuns` and an integer `expectedRuns`, and forbids
`knownGaps`. Without a stated expectation, "complete" means "I saw everything I happened to see" and
cannot be falsified. Unobserved work appears as a gap, never as a zero count.

## Findings

Aggregates like "3 findings, 2 fixed, 1 dismissed" are not a reviewable record — anyone can rewrite
them. Each finding carries `id`, `severity`, `title` and `disposition`; a finding marked `fixed` must
name its `fixCommit`, and one marked `dismissed` must carry a one-sentence reason. `findingsRoot`
digests the canonical list so that removing or altering one finding is detectable.

The root is **order-independent by construction**: each finding is canonicalized on its own, the leaf
digests are sorted, and the root covers their concatenation. Two producers listing the same findings
in a different order must not disagree, or the root would report tampering where there is none.

## Supersession

A wrong or outdated receipt is not deleted. `supersedes`, `corrects` and `withdraws` each require the
predecessor's digest **and** a reason — a silent replacement is exactly what supersession exists to
prevent.

## The human block

`render_disclosure_block` derives five fixed lines from the same canonical predicate the receipt is
signed over, so the visible text and the signed object cannot drift apart without a digest changing.
The `Assurance` line reports the **weakest** rung present and the `Limits` line reproduces the
predicate's own limitations verbatim: a reader who only skims the block must not come away with a
stronger impression than a verifier would report.

## Verification axes

`verify_agent_review` reports separate axes and never a single collapsed verdict:
`crypto_ok`, `structure_ok`, `predicate_type_ok`, `subject_binding_ok`, `findings_root_ok`,
`assurance_ok`, and `currentness`. A valid signature can simultaneously be bound to the wrong object,
issued by an untrusted identity, unwitnessed in time, incomplete, or superseded.

**Honest limit of this version:** identity, time, coverage and privacy are *modelled* in the
predicate but are **not** separate verifier axes yet. A relying-party policy layer that turns these
axes into a decision is not part of v0.1.

## Machine-readable reasons

Three fields, and the distinction between them is the point:

| Field | Carries | Read it when |
|---|---|---|
| `reason_codes` | **only fatal** codes — reasons the receipt was rejected | you want to branch on *why* it failed |
| `reason_code` | the **first** entry of `reason_codes`, else `None` | you want one label and accept that it is a sample |
| `advisory_codes` | notes that do **not** determine the outcome (e.g. `LEGACY_SELF_DECLARED_OBSERVED_AT`) | you want context; never as a rejection reason |

**Branch on `in reason_codes`, not on `reason_code ==`.** The scalar is the *first* fatal code in
check order, so an unrelated second defect in the same receipt can displace it while the defect you
care about is unchanged. The list does not have that property. How often the scalar moves depends
entirely on which pair of defects you pick — we deliberately quote no rate here, because two
independent measurements over different defect pairs produced very different ones, and a rate that
depends on the sample is not a property a consumer can rely on. The mechanism is the thing: the
scalar is stable enough to log, and too unstable to dispatch on.

**A rejection may carry no code at all.** Codes today cover the statement-shape family. Measured on
this release, these four reject with an English sentence in `errors` and an **empty** `reason_codes`:

    signature invalid          ok=False   reason_codes=[]
    wrong subject              ok=False   reason_codes=[]
    visible body != signed     ok=False   reason_codes=[]
    no subject expectation     ok=False   reason_codes=[]

Every cryptographic and every binding axis is in that group. An empty list is the honest answer "no
machine-readable reason" — it is **not** a statement that the receipt is fine. Read `ok` first,
always, and treat `reason_codes` as an aid to routing, never as the verdict.

Codes are stable across releases; the sentences beside them are not. A sentence may be reworded for
clarity in any version, which is exactly why matching on text breaks and matching on codes does not.

## Every rule brings its own counter-proof

`conformance/agent_review/` carries positive controls and counter-proofs, run by
`conformance/run_conformance.py` under `kind: agent_review_predicate`. Each case declares exactly one
expectation axis: an under-declared case cannot fail, and an over-declared one hides everything after
the first.

Three classifications, and the difference between the last two is the substance:

| | meaning |
|---|---|
| `valid` | emitted and verified |
| `invalid` | produced, then rejected by the verifier |
| `refused` | the producer would not build it at all |

## Version rule

`v0.1` is `0.1.x`. A change that alters what a receipt asserts, or what a verifier must reject, is a
new version — not a patch. `predicateType` is read, not decoration: a receipt naming a version this
verifier does not know is refused rather than guessed at.

## Version 0.2 — the emitter's default since 6.0.0

`emit_agent_review` and `build_agent_review_statement` produce v0.2 without an argument; v0.1 needs
the explicit `legacy_v01=True`. v0.1 keeps working: `verify_agent_review` is byte-pinned to the
5.1.0 source (a test resolves the function through `git show v5.1.0:` rather than trusting a typed
digest), and the six published v0.1 receipts under `receipts/agent_review/` run as a regression
against values that were measured under 5.1.0 and frozen in
`conformance/agent_review/_regression/v01_unter_510.json`.

What v0.2 adds, each with its conformance case:

- **`subjectContext.disclosureCoreDigest` is required.** Without it the visible disclosure block is
  unbound: an edit from `selfDeclared` to `independentlyWitnessed` in the text would leave every
  digest unchanged.
- **`limitationCodes` is required and derived**, never typed by hand: `derive_limitation_codes`
  produces them from the predicate. The five codes are `IDENTITY_UNBOUND`, `TIME_SELF_DECLARED`,
  `CURRENTNESS_UNKNOWN`, `COVERAGE_PARTIAL` and `NOT_QUALITY_ATTESTATION`; the last one is always
  present, because no receipt of this kind says anything about the quality of the reviewed work.
- **Time claims carry their source.** `declaration.timeClaims[]` entries have `kind`
  (`reviewCompleted`, `receiptCreated`, `reviewStarted`, `evidenceCollected`), `value`,
  `assertedBy` and `assurance`; `times.observedAt` is not allowed on a Tier 1 predicate, because an
  observation without a named observer is not one. The verifier reports four time axes
  (`event_time_status`, `observation_time_status`, `signature_time_status`,
  `external_time_status`) with seven states (`ABSENT`, `SELF_DECLARED`, `RUNNER_OBSERVED`,
  `PLATFORM_ATTESTED`, `EXTERNALLY_ANCHORED`, `CONFLICT`, `NOT_EVALUATED`) and never one
  collapsed verdict about time.
- **`fixCommit` is the full 40-character SHA.** Anything shorter is a validator error
  (`FIXCOMMIT_NOT_FULL_SHA`): seven characters are a search query, not a reference.
- **A named policy axis.** `verify_agent_review_v02(..., policy=load_policy())` evaluates the
  derived limitation codes and the coverage status against a policy that is a file, not code. The
  named standard policy ships inside the package as `proofbundle/policies/agent-review-default-v1.json` (resolved with `importlib.resources`, so an installed package finds it); the copy under `conformance/agent_review/policies/default_v1.json` is byte-identical and kept for readers of the corpus
  (`agent-review/default`); its name and sha256 digest appear in the result, so a later reading can
  say what the decision was made against. Decisions are `accept`, `reject` and
  `insufficient_evidence` (a coverage that is not stated is the absence of evidence, not evidence of
  a defect). Without a policy the result carries `policy_decision: null`, the reason code
  `POLICY_NOT_EVALUATED`, and `automation.safeForAutomation` is false; `ok` is unaffected, because a
  check that was not run is not a failed check. A `reject` or an `insufficient_evidence` sets `ok`
  to false.
- **One dispatcher for both versions.** `verify_agent_review_any` reads the `predicateType` and
  reports `predicateVersionStatus`: `current` for v0.2, `legacy` for v0.1 (with the reason code
  `AGENT_REVIEW_LEGACY_V01` added and the v0.1 verdict left untouched), `unknown` for anything else
  (refused with `AGENT_REVIEW_PREDICATE_TYPE_UNKNOWN` before any signature check, so an unknown
  version is never read under the rules of a known one).

Every rule above has a counter-proof and a positive control in `conformance/agent_review/`, and every
counter-proof has a flip test in `tests/test_agent_review_conformance_runner.py` that removes exactly
its defect and expects the verdict to turn.

Honest limit of v0.2: it still emits only `selfDeclared` assurance. A receipt observed by a runner
or witnessed independently needs a witness outside the agent's own workspace, which this version
does not provide. And a v0.2 receipt can be verified with the published package only from 6.0.0 on;
5.1.0 knows no v0.2 and refuses it by `predicateType`.

## Provenance of this design

Built 31.08.2026 against an external adversarial read of signed agent disclosures (18 findings,
12 product points, 28 test cases). The finding ids referenced in the implementation and in the
conformance rationales are that read's. It was written without access to this package and states its
own claims about our implementation as `NICHT GEPRÜFT`; nothing in it was adopted on trust, each
point was measured against the code.
