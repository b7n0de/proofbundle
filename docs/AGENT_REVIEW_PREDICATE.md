# Agent review predicate `agent-review/v0.1` and `agent-review/v0.2`

Status: **v0.1, Tier 1 — a signed self-declaration.** Emitted and verified by
`src/proofbundle/agent_review.py`; that module is the reference implementation, and this document,
not the module, is normative (SPEC.md §7l). Conformance vectors live in `conformance/agent_review/`. **Since 6.0.0 the emitter
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

The statement's subject digest is taken over the **subjectContext alone**: `subject[0].digest.sha256`
is the SHA-256 of the RFC 8785 (JCS) bytes of the predicate's `subjectContext`, written as 64
lowercase hex characters, in v0.1, v0.2 and v0.3 alike; a supplied `expected_subject_digest` is
compared with that value. A receipt copied onto
another pull request therefore carries the old context and fails the binding check, while remaining
cryptographically sound — which is precisely the failure this binding exists to expose.
The result field `subject_expectation` says whether the receipt was compared with an expectation supplied from outside: `checked` once a supplied `expected_subject_digest` has been compared with the digest of the signed `subjectContext`, and `not_supplied` otherwise, in particular whenever no expectation is passed. Without that comparison `ok` is false even for an internally consistent receipt, and the result carries a warning that names `expected_subject_digest`.

### `reviewedDiffDigest`, and why it needed writing down

**The derivation belongs in this document, because a digest nobody can recompute is a number that
looks like a fact.** The field is sha256 over the bytes of

```
git diff <baseSha>..<headSha>
```

in the repository the receipt names, with default options and no colour. Both shas are in the same
`subjectContext`, so a reader holding the repository can reproduce the value without asking anyone
what was meant.

**CORRECTED 2026-09-25: default options are not one derivation.** Measured on pull request 264, the
same command gives `a5e83b33…` in a large clone, where git abbreviates blob ids on the index lines to
eight characters, `d8c6daf0…` with `core.abbrev=7` as in a fresh clone, and a third value with
`diff.noprefix=true`. A reader in another clone or with other settings could not reproduce the value.

A first correction the same day pinned a list of options on the patch output. A review then named
further settings the list had missed, diff ordering and blank-line formatting among them, and a list
of rendering options does not close. The receipts this repository issues from 2026-09-25 on
therefore take the digest over the raw record instead of the rendered patch:

```
git --no-replace-objects diff-tree -r -z --no-renames --no-abbrev -O/dev/null <baseSha> <headSha>
```

One NUL-separated record per changed path, with both modes, both full blob ids, the status and the
path. It carries no rendering, so no setting changes it: measured on pull request 264, the value is
the same under fourteen settings, including the abbreviation length, `diff.noprefix`,
`diff.orderFile`, `diff.suppressBlankEmpty`, `diff.relative` and a global attributes file. The blob
ids bind the content of every changed file exactly, which the patch text did only through its
rendering. Each receipt states the command in its own known gaps.

**`--no-replace-objects` was missing from the first version of this command**, the same day. Settings
change how git renders an object; a replacement ref (`git replace`) changes which object git reads
for a given id, and it is local to a clone. Measured in a scratch repository: the command without the
switch gave `c137e097…` for two commits, then `a68fe623…` for the same two ids after one of them was
replaced, and `c137e097…` again with the switch (and with `GIT_NO_REPLACE_OBJECTS=1`). So without it,
a digest could be taken over objects no other reader has while the receipt names the original ids.
In this repository no replacement refs exist, so no digest issued with the earlier command changes
value; the receipts that state the command were reissued so that the command they state is this one.

**THE HONEST PART, measured 2026-09-23.** The receipts issued before that date carry the field, and
their derivation is recorded nowhere — not here, not in the emitter, not beside the published
evidence. Three obvious candidates were measured against one of them, the receipt for pull request
241, and none reproduced its value:

| candidate | reproduces `3615bbbc…` |
|---|---|
| `git diff <base>..<head>` (two dots) | no, `32bdb8d8…` |
| `git diff <base>...<head>` (three dots, merge base) | no, `32bdb8d8…` |
| the API's own `.diff` rendering | no, `d1c0d967…` |
| the API's own `.patch` rendering | no, `4410a943…` |

So those earlier values are not checkable by a reader, and this document does not pretend otherwise.
Rather than copy a number whose meaning is unknown, the receipts issued from 2026-09-23 on state the
derivation above in their own `limitations` list, where a reader meets it, and this section is the
place it is defined once.

**What the field does NOT bind.** It is a digest over a diff, not over a tree. Two different trees
with the same diff against their own bases produce the same value, and a diff that git renders
differently under another version or configuration produces a different one for the same trees. The
tree itself is bound by `headSha` and `baseSha`, which is where that question belongs.

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
different digests over the same body, and the mismatch would look like tampering. The replaced span runs
from the first character of the begin marker through the last character of the end marker, both markers
included, and `bodyCoreDigest` is the lowercase hex SHA-256 of the UTF-8 bytes of the result.

**Fail-closed on ambiguity.** Zero blocks is the normal pre-disclosure case and hashes as-is. Two
blocks, a begin without an end, or an end before its begin, is not a body that reduces to one canonical form: an actor who may
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
Of the four, only `declaredAt` is required. An absent time field reads as null, so `anchoredAt` may be absent or null, and in v0.2 and v0.3 "`times.observedAt` is not allowed" means that it is absent or null. `observations` may likewise be absent, which reads as empty.

## Coverage

`COMPLETE` requires an integer `observedRuns` and an integer `expectedRuns`, and forbids
`knownGaps`. Without a stated expectation, "complete" means "I saw everything I happened to see" and
cannot be falsified. Unobserved work appears as a gap, never as a zero count. `PARTIAL` requires a
non-empty `knownGaps`: an incomplete coverage that names no gap cannot be checked against anything. In
v0.2 and v0.3 both demands apply whenever `coverage` carries none of `strata`, `integrity` and
`absenceAssertions`.

**Coverage in the language of CAP-1 (v0.2).** A v0.2 predicate may carry the accounting of
`draft-hillier-coverage-attestation-00` under `coverage`: `strata[]` (one denominator each, with its
`basis`, `eligible`, `examined` and every `unexamined` unit named with a disposition), `integrity`
(`complete`, `statement`, `capped_to`) and `absenceAssertions[]` (each bound to a stratum). The
field names inside a stratum are the profile's own (`catalogue_digest`, `withheld_digest`,
`enumeration_method`); only the top-level keys follow the predicate's camelCase. The rules R0 to R8
of the draft are checked by `proofbundle.cap1`, the same module that runs the author's fifteen
conformance vectors, and each rule reports its own reason code (`COVERAGE_CAP1_SHAPE`,
`COVERAGE_CAP1_SILENT_REMAINDER`, `COVERAGE_CAP1_DISPOSITION_NOT_CLOSED`,
`COVERAGE_CAP1_WITHHELD_WITHOUT_DIGEST`, `COVERAGE_CAP1_BASIS_MISSING`,
`COVERAGE_CAP1_COUNTS_MALFORMED`, `COVERAGE_CAP1_ABSENCE_UNSCOPED`,
`COVERAGE_CAP1_INCOMPLETE_CLAIMED_CLEAN`, `COVERAGE_CAP1_SUPPORTS_MISSING`). With strata present,
`status` is derived from `integrity.complete` (`COMPLETE` if true, `PARTIAL` otherwise) and a
stated status that disagrees is rejected (`COVERAGE_CAP1_STATUS_CONTRADICTS_STRATA`); the older
counters are then aliases, still readable and still type-checked, and a predicate that carries only
them verifies as before with the advisory code `COVERAGE_LEGACY_FIELDS`. v0.1 does not know the
three fields and rejects them as unknown.

## Findings

Aggregates like "3 findings, 2 fixed, 1 dismissed" are not a reviewable record — anyone can rewrite
them. Each finding carries `id`, `severity`, `title` and `disposition`; a finding marked `fixed` must
name its `fixCommit`, and one marked `dismissed` must carry a one-sentence reason. `findingsRoot`
digests the canonical list so that removing or altering one finding is detectable. `findingsTotal` is
required: a non-negative integer, never smaller than the number of findings listed, and when it is
larger, `coverage.knownGaps` must be non-empty, because an unlisted finding has to be named as a gap. A
predicate without it is refused when issued, so the gap duty cannot be switched off by leaving the field
out.

The root is **order-independent by construction**: each finding is canonicalized on its own, the leaf
digests are sorted, and the root covers their concatenation. Two producers listing the same findings
in a different order must not disagree, or the root would report tampering where there is none.
When the signature verifies and `findingsRoot` is present, the verifier recomputes the root over
`declaration.findings`; a root that does not match makes the verification fail, so a receipt whose list
was changed after signing is `invalid`, not merely annotated. Issuing checks only that the root is present
once a finding is listed and that it has the form of the field table; its value is checked at
verification, so a predicate with a well-formed root that does not cover its list is issued and then
verifies as `invalid`.
Precisely: each leaf is the lowercase hex sha256 of one finding's RFC 8785 bytes, and the root is the lowercase hex sha256 over the ASCII bytes of the sorted leaves, concatenated as hex strings without a separator.

## Supersession

A wrong or outdated receipt is not deleted. `supersedes`, `corrects` and `withdraws` each require the
predecessor's digest **and** a reason — a silent replacement is exactly what supersession exists to
prevent.

Resolving a receipt chain orders the receipts by these relations and checks no signature itself: only an
envelope whose receipt digest the caller has verified may mark a predecessor as corrected. The chain's
integrity fails when such an envelope names a `priorDigest` that is not the receipt digest of any envelope
in the set, because a correction whose predecessor has disappeared can no longer be followed.
`receipt_digest(envelope)` is the lowercase hex sha256 over the envelope's base64-decoded `payload` bytes — the signed statement as stored, which the emitter writes in RFC 8785 form — without the signatures and without a `sha256:` prefix; a `priorDigest.sha256` cites this value. `current` is the one receipt digest in the set that no envelope in `verified` names as predecessor, whether or not that receipt is itself in `verified`; when there is not exactly one, `current` is null and `ambiguous` is true. The set is the receipt digests of all envelopes given to the resolution, verified or not, so an unverified receipt that no verified envelope names is a candidate as well.
An envelope that carries a `supersession` block but whose `receipt_digest` is not in `verified` corrects nothing; its own `receipt_digest`, not the `priorDigest` it names, is listed in `unverified_supersession_claims`, so a rejected takeover attempt is reported rather than dropped.

## The human block

`render_disclosure_block` derives five fixed lines from the same canonical predicate the receipt is
signed over, so the visible text and the signed object cannot drift apart without a digest changing.
The `Assurance` line reports the **weakest** rung present and the `Limits` line reproduces the
predicate's own limitations verbatim: a reader who only skims the block must not come away with a
stronger impression than a verifier would report.

The renderers read the predicate version from the predicate (`timeClaims`, `limitationCodes` or
`subjectContext.disclosureCoreDigest` select v0.2) unless the caller states it with
`legacy_v01=`; an explicit answer always wins over the markers.

**The `Receipt:` line is the sha256 of the receipt file as published** — the value a reader
recomputes with `sha256sum` on the `.receipt.json`. It is not `receipt_digest()`, the digest of the
envelope's signed payload (see Supersession) that supersession (`priorDigest`) and `resolve_receipt_chain` key on. The two
differ by construction; a correction must cite the canonical digest, and a block's file hash is a
locator, not a chain key.

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
| `advisory_codes` | notes that do **not** determine the outcome (`LEGACY_SELF_DECLARED_OBSERVED_AT`, `POLICY_NOT_EVALUATED`, `AGENT_REVIEW_LEGACY_V01`, `ARGUMENT_NOT_APPLICABLE_TO_VERSION`) | you want context; never as a rejection reason |

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

## Fields per version

The validator of each version applies these closed field sets; a member outside the set of its object is
an `unknown field` error, a missing required member a `missing` error. v0.2 is v0.1 with the members
marked v0.2, and v0.3 is v0.2 with `producer.verifier`. A *digest object* is an object whose member
`sha256` is 64 lowercase hex; an *RFC 3339 time* is `YYYY-MM-DDTHH:MM:SS`, an optional fraction, and `Z`.
"Required" without a version means required in all three.

| Object | Member | Required | Value |
|---|---|---|---|
| predicate | `schemaVersion` | yes | a string matching `0.1.x`, in all three versions |
| predicate | `reviewId` | yes | a non-empty string |
| predicate | `subjectContext` | yes | an object, see below |
| predicate | `declaration` | yes | an object, see below |
| predicate | `coverage` | yes | an object, see below |
| predicate | `times` | yes | an object, see below |
| predicate | `limitations` | yes | a non-empty array of non-empty strings |
| predicate | `limitationCodes` | v0.2, v0.3 | an array of the five codes, each once |
| predicate | `producer` | no | an object whose members `id` and `keyId` are each optional and a string when present, and no other member; v0.3 adds `verifier` (`docs/VERIFIER_BLOCK.md`) |
| predicate | `observations` | no | an array, and it must be empty |
| predicate | `supersession` | no | an object of `supersedes`, `corrects` and `withdraws`, each an array of objects with a digest object `priorDigest` and a non-empty string `reason` |
| predicate | `planRef` | no | a digest object |
| `subjectContext`, kind `githubPullRequest` | `kind`, `forge`, `repositoryId`, `pullRequestNodeId`, `headSha`, `baseSha`, `reviewedDiffDigest`, `bodyCoreDigest` | yes | `forge`, `repositoryId`, `pullRequestNodeId` non-empty strings; `headSha`, `baseSha` 40 lowercase hex; the two digests 64 lowercase hex |
| `subjectContext`, kind `githubPullRequest` | `renderedDisclosureDigest`, `humanRef` | no | `renderedDisclosureDigest` 64 lowercase hex; `humanRef` not checked |
| `subjectContext`, kind `githubIssue` | `kind`, `forge`, `repositoryId`, `issueNodeId`, `bodyCoreDigest`, `revisedAt` | yes | non-empty strings, `bodyCoreDigest` 64 lowercase hex, `revisedAt` an RFC 3339 time |
| `subjectContext`, kind `githubIssue` | `commentNodeId`, `renderedDisclosureDigest`, `humanRef` | no | `commentNodeId` a non-empty string, the digest 64 lowercase hex, `humanRef` not checked |
| `subjectContext`, both kinds | `disclosureCoreDigest` | v0.2, v0.3 | a string; its form is not checked |
| `declaration` | `authoring`, `reviewRuns` | yes | arrays of entries with a non-empty string `assertedBy` and an `assurance` that must be `selfDeclared`; optional `observedBy` (a string or null) and `evidenceRef` (a digest object or null); further members of an entry are not checked |
| `declaration` | `findings` | yes | an array of findings, see below; ids unique |
| `declaration` | `findingsTotal` | yes | a non-negative integer, not below the number of findings; above it only with a non-empty `coverage.knownGaps` |
| `declaration` | `findingsRoot` | once a finding is listed | 64 lowercase hex, the root of section *Findings* |
| `declaration` | `nonClaims` | yes | a non-empty array of non-empty strings |
| `declaration` | `timeClaims` | no, v0.2 and v0.3 only | an array of objects with `kind` (`reviewCompleted`, `receiptCreated`, `reviewStarted`, `evidenceCollected`), `value` and `assertedBy` (non-empty strings), `assurance` (must be `selfDeclared`), optional `evidenceRef` (a digest object or null); closed |
| finding | `id`, `severity`, `title`, `disposition` | yes | `id` and `title` non-empty strings; `severity` one of `critical`, `high`, `medium`, `low`, `info`; `disposition` one of `fixed`, `dismissed`, `deferred`, `open` |
| finding | `fixCommit`, `reason`, `evidenceRef` | no | `fixCommit` a non-empty string, required when `fixed`, and from v0.2 on, when not null, 40 lowercase hex; `reason` a non-empty string, required when `dismissed`; `evidenceRef` a digest object or null |
| `coverage` | `status` | yes | `COMPLETE`, `PARTIAL` or `UNKNOWN` |
| `coverage` | `window`, `sources`, `observedRuns`, `expectedRuns`, `knownGaps`, `collectionMethod` | no | `sources` and `knownGaps` arrays of strings; `observedRuns` and `expectedRuns` non-negative integers or null; `window` and `collectionMethod` not checked except under `COMPLETE` |
| `coverage` | `strata`, `integrity`, `absenceAssertions` | no, v0.2 and v0.3 only | judged by the CAP-1 rules (SPEC.md §7l) |
| `times` | `declaredAt` | yes | an RFC 3339 time |
| `times` | `observedAt`, `signedAt`, `anchoredAt` | no | each an RFC 3339 time or null; `anchoredAt` must be null, and from v0.2 on `observedAt` too |

Without the CAP-1 members, `COMPLETE` requires integer `observedRuns` and `expectedRuns` with
`observedRuns` not below `expectedRuns` and `expectedRuns` not 0, a non-empty `sources`, `window` and
`collectionMethod`, and no non-empty `knownGaps`; `PARTIAL` requires a non-empty `knownGaps`. With a
CAP-1 member present, `COMPLETE` is refuted only by those counters and by a non-empty `knownGaps`, and the
CAP-1 rules judge the rest.

## Version rule

`v0.1` is `0.1.x`. A change that alters what a receipt asserts, or what a verifier must reject, is a
new version — not a patch. `predicateType` is read, not decoration: a receipt naming a version this
verifier does not know is refused rather than guessed at.
`schemaVersion` is not the predicate version: `agent-review/v0.1`, `v0.2` and `v0.3` predicates all carry a `schemaVersion` of the form `0.1.x`, and the version is read from `predicateType` alone.
The three `predicateType` values are `https://b7n0de.com/proofbundle/predicates/agent-review/v0.1`,
`https://b7n0de.com/proofbundle/predicates/agent-review/v0.2` and
`https://b7n0de.com/proofbundle/predicates/agent-review/v0.3`, each compared as a whole string: the
version dispatcher reports `predicateVersionStatus` `legacy` for the first, `current` for the other
two and `unknown` for any other string, also one that differs only in the scheme, the case, a
trailing `/` or a missing `/predicates/`.

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
  The validator checks that each code is known and appears once; it does not compare the list with `derive_limitation_codes`, and the policy evaluates the derived codes, never the stated ones.
  `derive_limitation_codes` derives each code by one condition on the predicate: `IDENTITY_UNBOUND`
  when no entry of `declaration.authoring` or `declaration.reviewRuns` carries a string `assurance`
  other than `selfDeclared`; `TIME_SELF_DECLARED` when `observations` is not a non-empty array (the
  members of `times` and `declaration.timeClaims` do not enter); `COVERAGE_PARTIAL` when
  `coverage.status` is `PARTIAL` or `UNKNOWN`; `CURRENTNESS_UNKNOWN` and `NOT_QUALITY_ATTESTATION`
  always.
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
  a defect). The decision is `reject` when a derived code is in `blocking` and not in `never_blocking`,
  otherwise `insufficient_evidence` when `require_coverage_status` is set and the coverage status is not
  in it, otherwise `accept`. Without a policy the result carries `policy_decision: null`, the advisory code
  `POLICY_NOT_EVALUATED`, and `automation.safeForAutomation` is false; `ok` is unaffected, because a
  check that was not run is not a failed check. A `reject` or an `insufficient_evidence` sets `ok`
  to false. The policy file itself is validated before it decides: `blocking` and `never_blocking`
  must each be a list of known code strings or null, and `require_coverage_status` a list of known
  status strings or null. Null means no rule, as the loader reads it: with `blocking` null no code
  blocks, with `never_blocking` null no code is exempt, and with `require_coverage_status` null no
  coverage status is required. A string is refused, because it would be read as characters and match
  nothing, or turn the coverage membership test into a substring test. A `time` block, if present,
  must name a known kind. A policy that fails this reaches the result as `POLICY_NOT_EVALUABLE` with
  `insufficient_evidence`. The keys a policy decision reads are `blocking`, `never_blocking`,
  `require_coverage_status`, `time` and `name`, and an absent one reads as null; a policy file may carry
  further keys, such as reasons or measurements beside its rules, and they decide nothing.
  For a policy read by `load_policy`, the result's `policy_name` is the policy's `name` and its `policy_digest` is the string `sha256:` followed by the lowercase hex sha256 of the policy file's bytes.
- **Time claims that contradict each other are fatal.** The event axis is `CONFLICT` when the
  declaration's time claims of kind `reviewCompleted` carry more than one distinct value, compared as
  written and not as instants; claims of the other kinds take no part. Both the event and the
  observation axis are `CONFLICT` when an observation by a named observer lies before the one
  declared `reviewCompleted` time. A `CONFLICT` on the event or observation
  axis sets `time_consistency_ok` to false, adds the reason code `TIME_CLAIMS_CONFLICT`, and makes
  `ok` false regardless of any policy: two statements that disagree are a broken claim, not a weak
  one. A policy may additionally carry a `time` block; it is evaluated with `evaluate_time_policy`,
  reported as `time_policy_decision`, and the stricter decision wins. The standard policy carries
  none.
- **One dispatcher for all versions.** `verify_agent_review_any` reads the `predicateType` and
  reports `predicateVersionStatus`: `current` for v0.2 and v0.3, `legacy` for v0.1 (with the advisory code
  `AGENT_REVIEW_LEGACY_V01` added and the v0.1 verdict left untouched), `unknown` for anything else
  (refused with `AGENT_REVIEW_PREDICATE_TYPE_UNKNOWN` before any signature check, so an unknown
  version is never read under the rules of a known one). Keyword arguments are filtered per
  version: one that neither version knows is a `TypeError` before the envelope is read, the same
  for both; one that only the other version knows (today `policy=` on a v0.1 envelope) is dropped,
  named in `warnings`, and marked with the advisory code `ARGUMENT_NOT_APPLICABLE_TO_VERSION`.

- **`producer.verifier`, the verifier block — `agent-review/v0.3` (since 6.1.0).** v0.3 is v0.2
  plus this one optional field; everything else on this page holds for it unchanged, and
  `verify_agent_review_v03` is the v0.2 verifier with the block admitted. The producing build names
  itself: implementation, version, a digest over its own files with the measurement's source
  stated, the conformance vector set it was held against, and a reference to a separate signed
  in-toto test-result statement, joinable by digest equality. It answers the question a relying
  party asks at T+n — *which build produced this* — that a version string cannot. The verifier
  reports it as the `verifier_block` axis with `matches_this_verifier` in `MATCH` / `MISMATCH` /
  `NOT_EVALUATED`, and never folds it into `ok`; a malformed block is a structural error like any
  other. v0.1 and v0.2 do not know the field and refuse it — v0.2 in 6.0.0 and in 6.1.0 alike,
  which is the measured reason the block is a new version rather than an extension of v0.2 (the
  same bytes must not be refused by one release and accepted by the next under one
  `predicateType`). The emitter picks v0.3 exactly when the predicate carries the block. Contract,
  the version reasoning and limits: [VERIFIER_BLOCK.md](VERIFIER_BLOCK.md).

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
