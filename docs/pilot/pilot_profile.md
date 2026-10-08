# Pilot profile `github-write/1`

How the first pilot's records are written with the two predicates as they ship: the outbound gate's verdict
as a `decision-receipt/v0.1`, what an observer reads from the GitHub API after the write as an
`action-outcome/v0.1` bound to it. This is a profile, a set of rules for filling and reading existing fields;
it adds no field and changes neither predicate. The pilot itself (roles, measures, exit criteria) is fixed in
the pilot contract, `docs/pilot/pilot_contract.md`.

The rules are executable: [`tools/pilot/github_write_profile.py`](../../tools/pilot/github_write_profile.py)
builds both receipts and decides, for one decision and at most one outcome, whether the approved action
arrived as approved. [`tools/pilot/vectors.json`](../../tools/pilot/vectors.json) holds positive and negative
bytes for every rule below, signed with keys derived from public labels (vectors only, never keys of the
pilot).

## The answer

For one decision and at most one outcome the profile answers one of three:

- `accepted`: the gate allowed the action, and an effect arrived with the approved bytes, on the approved
  surface and target, after the approval and before it expired;
- `not accepted`: a check failed, or the gate did not allow the action;
- `unknown`: something the answer needs is missing.

`unknown` and a missing record never become `accepted`. There is no fourth value, and no `accepted` with a
condition attached: an answer that needs a condition is not `accepted`.

## Where each aspect lives

| aspect | decision-receipt/v0.1 (the gate) | action-outcome/v0.1 (the observer) | the rule |
|---|---|---|---|
| byte identity | `proposedAction.parametersDigest.sha256` = SHA-256 of the approved bytes | `requestedActionDigest.sha256` = the same; `effectDigest.sha256` = SHA-256 of the bytes GitHub stores | requested equals approved, and effect equals approved |
| subject | the Statement subject, derived from the predicate (`require_derived_subject`) | the Statement subject, derived from the predicate (`require_derived_subject`); `decisionRef.sha256` = the decision's content root | each subject is derived from its own predicate, and the outcome is bound to this decision (`decision_bound`); a receipt whose subject is not derived is `not accepted` |
| issuer role | signed by the pinned gate key; `decisionMaker.id` is the gate's id | signed by the pinned observer key; `executor.id` is the account GitHub reports as author | both keys pinned by the relying party; the agent holds neither; `executor.id` is observed data and is not compared with the gate's id |
| audience | `validity.audience` names the observer | `validity.audience` names the observer | both are addressed to the observer the relying party pins; another audience is `not accepted` |
| policy digest | `policyBoundary.policyDigest` (required in strict mode) | none | recorded, not interpreted |
| strict mode | the decision is verified in strict mode: `notChecked`, `decisionChangeConditions` and `privacy` are present, `privacy.rawInputsIncluded` is a boolean, `policyBoundary.policyDigest` carries a sha256, and `validity` carries `audience` and `nonce` | the outcome is verified in strict mode too, which adds no required field to `action-outcome/v0.1` today | a decision without one of them does not verify: `not accepted` |
| action id, attempt | `decisionId` = `<action id>#<attempt>`; `validity.nonce` = the `decisionId`, so it names the attempt | `validity.nonce` = the decision's nonce | an outcome answers one attempt |
| freshness | `decidedAt`, `validity.expiresAt` | `performedAt` = the time GitHub states for the effect; `recordedAt` = the observer's reading | `decidedAt` ≤ `performedAt` ≤ `expiresAt`, inclusive at both ends, compared as instants with their fractions of a second, any number of digits for `decidedAt` and `performedAt`; the decision itself is verified one second before its `decidedAt`, not at the reader's clock, so that this window, not the verifier's expiry rule, decides; `expiresAt` is read first by that verifier, which reads at most six fraction digits, so an expiry with more does not verify and is `not accepted` |
| outcome scope | `proposedAction.actionType` = the surface, `proposedAction.target.uri` = the target | `actualActionDigest.sha256` = SHA-256 of the RFC 8785 form of `{surface, target, objectId}`, a descriptor that travels beside the outcome | the descriptor matches the signed digest, has exactly these three keys, each a non-empty string, and its surface and target are the approved ones |
| kind | `decisionType` = `preActionAuthorization`, `proposedAction.method` = `write` | none | another kind or method is no approved write: `not accepted` |
| status | none | `status` = `executed` | only `executed` is an effect that arrived; `failed`, `refused` or `partial`, signed by the observer, is a known answer: `not accepted` |
| version signal | `policyBoundary.policyEngine` = `proofbundle-pilot/github-write`, `policyBoundary.bundleRevision` = `1` | none of its own; it is read only through a decision that carries the signal | without the signal a receipt is not read under this profile: `unknown` |

Surfaces the profile knows: `github.conversationComment`, `github.reviewThreadReply`,
`github.pullRequestBody`, `git.push`, `github.merge`. Any other `actionType` is `unknown`.

The other values the builder writes into the decision (`policyBoundary.policyId` and `decisionPath`, the
`inputSnapshot`, `notChecked`, `decisionChangeConditions` and `privacy`) are recorded, not read: no rule of the
profile depends on what they hold. Strict mode requires `notChecked`, `decisionChangeConditions` and `privacy`
to be present, as the table states, so a decision without one of them is `not accepted`. The same holds for the outcome's `outcomeId`, `recordedAt` and `limitations`. Every check that can be made is made before a gap is reported, so a check known to
fail gives `not accepted` even where another record is missing. The pinned gate key is checked first, before the
version signal or `decidedAt` is read, so a decision another key signed is `not accepted`, never `unknown`, and a
`validity.nonce` that is not the `decisionId` is `not accepted`. The decision maker, the kind, the gate's verdict and
the nonce are checked before any gap of the decision is reported (an unreadable `decidedAt`, a `decisionId` of
another form, a surface the profile does not know), so a refusal is `not accepted` wherever it stands.

Two readings are stated rather than hidden. The outcome's signer is the observer, and `executor.id` names the
account GitHub reports, which the profile treats as observed data, not as a trusted identity. And
`performedAt` comes from GitHub's clock while `decidedAt` and `expiresAt` come from the gate's; the profile
compares them as the instants they name, and a clock difference between the two is not corrected.

## The vectors and what each shows

| vector | answer | what it shows |
|---|---|---|
| approved and arrived as approved | accepted | the positive case |
| wrong issuer: decision signed by another key | not accepted | a valid signature is not enough; the key is pinned |
| wrong issuer: another decision maker named | not accepted | the gate key signing for another maker's id |
| wrong issuer: outcome signed by another key | not accepted | the observer key is pinned too |
| wrong subject: outcome bound to another decision | not accepted | decisionRef names another content root |
| wrong subject: arrived on another target | not accepted | the right bytes on another pull request |
| arrived on another surface | not accepted | the right bytes on another surface: the pilot contract's first example |
| expired approval | not accepted | the effect happened after `validity.expiresAt` |
| effect before the approval | not accepted | GitHub's time precedes the verdict |
| missing effect: approved, nothing observed | unknown | no outcome is not a success |
| missing effect: outcome without a digest of the stored bytes | unknown | an outcome that proves no effect |
| stored bytes differ from the approved bytes | not accepted | an appended line is enough |
| refused, and an effect arrived | not accepted | refused but arrived, the pilot's most important mismatch |
| refused, and nothing arrived | not accepted | consistent, and still not an acceptance |
| deferred, and an effect arrived | not accepted | only ALLOW can be accepted |
| no expiry stated | unknown | freshness cannot be decided |
| no scope observed | unknown | surface and target cannot be decided |
| scope descriptor other than the signed one | not accepted | the descriptor beside the outcome is checked against its digest |
| no version signal: a decision receipt of another use | unknown | the old format is not reinterpreted |
| another revision of the profile | unknown | revision 2 is not read as revision 1 |
| a post-hoc review, not an approval before the write | not accepted | the kind of decision is fixed |
| an approved read, not a write | not accepted | the method is fixed |
| expired approval, by a fraction of a second | not accepted | 00:45:00.9Z is after 00:45:00Z, though "." sorts before "Z" |
| approved and arrived a fraction of a second after the approval | accepted | the lower bound read the same way |
| scope descriptor without objectId, signed so | not accepted | the descriptor is exactly three keys |
| scope descriptor with a key more, signed so | not accepted | the same rule from the other side |
| stored bytes differ, and no scope observed | not accepted | a known failure is not hidden behind a missing record |
| stored bytes differ, and no expiry stated | not accepted | the same at the expiry |
| the observer signed status failed | not accepted | a known failure is not a missing record |
| the observer signed status refused | not accepted | the same for refused |
| the observer signed status partial | not accepted | a partial effect is not the approved one |
| approved and arrived, the time with ten fraction digits | accepted | the outcome takes any number of fraction digits, and so does the profile |
| approved and arrived at the second the approval was made and expires | accepted | the window is inclusive at both ends |
| approved and arrived, GitHub reporting the gate's id as the author | accepted | `executor.id` is observed data, not a role the profile separates |
| approved and arrived, the expiry with seven fraction digits | not accepted | the decision's verifier reads at most six fraction digits of `expiresAt` |
| approved and arrived, the expiry with six fraction digits | accepted | the control: six digits are read |
| tampered decision payload | not accepted | one byte changed after signing |
| the nonce names another attempt | not accepted | `decisionId` names attempt 2 and both nonces name attempt 1 |
| unreadable decidedAt under a broken signature | not accepted | the signature is checked before `decidedAt` is read |
| refused, on a surface the profile does not know | not accepted | the refusal is checked before the unknown surface is reported |
| no version signal under a broken signature | not accepted | the signature is checked before the version signal is read |

## New fields: proposals only

The profile needs no new field. Four would make it simpler, and none of them can be added to v0.1: measured
with the shipped validators at `0ace3039` (strict mode), each is refused.

| proposal | where | what the v0.1 validator says |
|---|---|---|
| `attempt`, a number beside `decisionId` | decision, top level | `unknown top-level field(s) ["'attempt'"] (decision receipt is fail-closed)` |
| the surface as its own key | `proposedAction.surface` | `proposedAction.surface: undeclared nested key (nested closure violated)` |
| an `observer` distinct from `executor` | outcome, top level | `unknown field 'observer' (additionalProperties:false)` |
| the observed scope in clear | `outcomeScope`, outcome top level | `unknown field 'outcomeScope' (additionalProperties:false)` |

Two further gaps are named, not proposed: `action-outcome/v0.1` has no status for "not observed" (the enum is
executed, refused, failed, partial; `notObserved` is refused), so the profile writes no outcome in that case;
and it has no expiry in `validity` (`validity.expiresAt` is refused there), so freshness is read from the
decision.

Each proposal needs a new predicate version with its own `predicateType`, so that a reader never
reinterprets a v0.1 receipt. They are proposals for the maintainer, not part of this profile.

## What the profile does not do

- It does not decide whether the gate's verdict was right, or whether the text is true.
- It does not correct clocks, and it does not check that GitHub's `performedAt` is honest.
- It does not observe GitHub itself; it reads the observer's signed record and the descriptor beside it.
- It says nothing about an effect that no outcome records: the pilot's measures M5 and M6 cover that, over
  an observation window.
