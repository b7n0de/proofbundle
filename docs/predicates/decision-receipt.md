# Decision Receipt predicate `decision-receipt/v0.1`

Status: shipped in proofbundle 2.1.0 (vendored `decision-receipt/v0.1`, stable). Vendored predicate under the b7n0de namespace. Design of record:
[`docs/adr/0001-decision-receipt-separate-predicate.md`](https://github.com/b7n0de/proofbundle/blob/main/docs/adr/0001-decision-receipt-separate-predicate.md).

**Design basis — content-root consensus (2026-07-10).** The anchor / evidence content-root rule (§3, §7.1, §8)
is the consensus reached with an external collaborator on
[proofbundle#7](https://github.com/b7n0de/proofbundle/issues/7): the
[anchor-binding rationale](https://github.com/b7n0de/proofbundle/issues/7#issuecomment-4931914705) and the
maintainer [confirmation](https://github.com/b7n0de/proofbundle/issues/7#issuecomment-4932813354) ("converging
on the same bytes"). The upstream in-toto/attestation#565 thread and the #7 iteration are archived verbatim at
`audit_artifacts/thread_565_snapshot.md`.

## 1. Purpose

A Decision Receipt is a signed, offline-verifiable record that a specific decision maker (an agent gate, a
policy engine boundary, a human escalation point) produced a specific verdict about a specific proposed action,
over specific digest-bound inputs and evidence, at a specific time.

It answers: *who decided, what action was proposed, against which policy boundary, on which evidence, what the
verdict was, and what was explicitly not checked.* It is an in-toto Statement (DSSE) with a vendored
`predicateType`, verified against the exact signed bytes.

## 2. Non-goals (what a Decision Receipt does NOT prove)

- It does **not** prove the decision was correct, legal, safe, compliant, or fully informed.
- It does **not** prove the eval numbers it references are true. That is the separate `eval-result` predicate,
  and even there a PASS proves authorship and integrity, not truth.
- `actionOutcome.status = executed` is **self-assertion** unless the outcome is separately signed by the
  tool/mediator boundary or referenced as a digest-bound tool log (`actionOutcome.outcomeRef`).
- It carries **no** chain-of-thought, no raw secrets, no benchmark-quality claim.

The boundary is deliberate and mirrors `eval-result`: a Decision Receipt widens the attestation surface (a new
signed claim type), so its verify path and non-claims are as explicit as the eval-result path.

## 3. Information architecture

One-directional, **content-root** coupling (ADR §3):

```
eval-result statement  (metric/benchmark evidence; own detached anchors)
        ^
        | evidenceRef.digest = content root of the evidence statement
        | (decision references evidence, never the reverse)
        |
decision-receipt statement  (verdict + boundary + notChecked; own detached anchors)
```

`evidenceRefs[].digest` is the **content root** of the referenced evidence statement — SHA-256 over its
RFC-8785 canonical Statement bytes, the same rule an anchor root uses — not an envelope/file hash and not the
bare predicate hash. It is written as the in-toto digest object `{"sha256": "<64 lowercase hex>"}`
(`$defs/sha256Digest` in `schemas/decision-receipt-v0.1.schema.json`), and a decision binds an evidence
statement when at least one entry of its `predicate.evidenceRefs` carries `digest.sha256` equal to that
statement's content root. Binding the content root binds the claim's identity (including its `subject` and
`predicateType`) and survives counter-signing / key rotation of the evidence; WHO signed it is a separate
Trust-Policy question. An optional `artifactDigest` pins an exact stored blob for retrieval. The evidence is
anchored independently of the decision that cites it (both sides on content roots), so a reviewer can
reconstruct the temporal order of evidence and decision without trusting issuer clocks. Neither predicate
semantically mixes into the other.

> Interop caveat (No-Overclaim): the content root is SHA-256 over the *exact transmitted* payload bytes and is
> never recomputed by re-canonicalizing. For the eval-result ⇄ decision-receipt composition to match
> byte-for-byte, the evidence side must emit its Statement in the same RFC-8785 canonical form. The eval-result
> in-toto export does so by default and declares it inside the signed payload as
> `contentRootAlg: "jcs-sha256-v1"`. A Statement without `contentRootAlg` (the receipts of 2.0.0, or one
> re-emitted in the named legacy mode `legacy-sortkeys-json-v0`) is serialized with `json.dumps(sort_keys=True)`,
> which is **not** full RFC-8785 (it diverges on number formatting and non-ASCII / mixed-case keys), and a
> cross-predicate content-root match is not guaranteed for it.

## 4. Predicate type and payload

- `predicateType`: `https://b7n0de.com/proofbundle/predicates/decision-receipt/v0.1`, the one predicateType of a
  decision receipt. `https://b7n0de.com/proofbundle/decision-receipt/v0.1`, without `/predicates/`, is not one: the
  verify path refuses it as malformed (exit 2). Two content-root vectors of the corpus carry it as fixture bytes only
  (`content-root-cross-predicate-ref`, `content-root-envelope-invariance`); their successor cases
  (`…-predicates-path`) carry the predicateType above.
- Statement `_type`: `https://in-toto.io/Statement/v1`
- DSSE `payloadType`: `application/vnd.in-toto+json` (the in-toto envelope media type, not a predicate subtype)
- `subject`: a commitment to the decision (e.g. `name: "decision:<decisionId>"`, `digest.sha256`). Evidence
  receipts are **never** abused as `subject`; they live in `predicate.evidenceRefs[]`.

## 5. Parsing and versioning rules (fail-closed)

1. Unknown top-level predicate fields are rejected (`additionalProperties: false`), never ignored.
2. Time fields are RFC3339 with a trailing `Z`. No generic `timestamp`; use `decidedAt`, `recordedAt`,
   `performedAt`. A time field names a real instant: month 01 to 12, a day that exists in that month and year,
   hour to 23, minute to 59, second to 60 (RFC 3339 5.7 allows a leap second). `2026-13-15T09:05:00Z` and
   `2026-02-30T09:05:00Z` fail in every mode, as `validity.expiresAt` already did.
3. SemVer: `schemaVersion: "0.1.0"` (or a compatible `0.1.x`); the `predicateType` contains `v0.1`.
4. Field names are **lowerCamelCase** (ITE-9). Only the proofbundle-local trust-policy file is snake_case.

## 6. Required fields (strict v0.1)

`schemaVersion`, `decisionId`, `decisionType`, `decidedAt`, `decisionMaker`, `agent`, `principal`,
`proposedAction`, `inputSnapshot`, `policyBoundary` (incl. `policyDigest` in strict mode), `evidenceRefs`
(may be empty only when the decision explicitly used no additional evidence), `decision`
(`verdict` + `reasonCodes`), `notChecked`, `decisionChangeConditions`, `privacy`.

A `notChecked` entry is an object `{field, reason, impact}`. A bare string is still accepted as a
deprecated legacy form, and the schema marks it so; new receipts use the object form.

Optional: `recordedAt`, `delegationRefs`, `actionOutcome`, `traceContext`, `validity` (strict interactive mode
requires `audience` + `nonce`), `relationships` (`docs/predicates/relation.md`). `anchors` is not a predicate
field: anchors travel detached (§8), and an `anchors` member inside the predicate is an unknown field.

**Default mode.** Without `--strict`, `decision verify` validates the predicate in the default mode, and
the conformance counts of `decision_predicate_findings` are counts of this mode. It requires
`schemaVersion`, `decisionId`, `decisionType`, `decidedAt`, `decisionMaker`, `agent`, `principal`,
`proposedAction`, `inputSnapshot`, `policyBoundary`, `evidenceRefs` and `decision`; `notChecked`,
`decisionChangeConditions` and `privacy` are optional here and required only in the strict mode above, and
no top-level member outside the required and optional fields is allowed. Validation yields a list of
findings, counted as follows: all unknown top-level members together are one finding; each missing
required member is one finding; each `evidenceRefs` entry that lacks a string `relation` or a sha256
content-root `digest` is one finding; each other rule of this section that a member breaks (an enum, an
RFC 3339 `Z` time, a non-empty `decision.reasonCodes` of strings, each of `policyBoundary.policyEngine`,
`policyId` and `decisionPath` as a non-empty string, the `proposedAction` digest or reference, the `id`
of `decisionMaker`, `agent` and `principal`, the digest of each `inputSnapshot` entry, an undeclared
member inside one of these objects) is one finding per member. A required member that is missing, or that
is not an object where this section expects one, is that one finding, and the rules of its own members are
not judged. An empty list of findings means the predicate is valid. A JSON `null` is no finding at `actionOutcome.performedAt`
and `actionOutcome.outcomeRef`, where it states no time and no reference, nor at `decisionMaker.version`,
whose form is not checked; at every other declared member, in both modes, it breaks that member's rule
and is a finding.

The declared members of the objects inside the predicate, the same as the `properties` the machine schema
gives each of them, whether or not this section names a member elsewhere; a member outside its list is
undeclared:
- `decisionMaker`: `id`, `version`
- `agent`: `id`, `version`, `configurationDigest`
- `principal`: `id`, `authnContextRef`; its `authnContextRef`: `uri`, `digest`
- `proposedAction`: `actionType`, `target`, `method`, `parametersDigest`, `parametersRef`,
  `parametersSchemaRef`; its `target`: `name`, `uri`, `digest`; its `parametersSchemaRef`: `uri`, `digest`
- each `inputSnapshot` entry: `name`, `uri`, `digest`, `mediaType`
- `policyBoundary`: `policyEngine`, `policyId`, `policyDigest`, `decisionPath`, `bundleRevision`,
  `validFrom`, `validUntil`
- each `evidenceRefs` entry: `relation`, `digest`, `artifactDigest`, `uri`, `predicateType`,
  `typedDigest`; its `typedDigest`: `type`, `purpose`, `digestAlgorithm`, `digest`
- `decision`: `verdict`, `reasonCodes`, `humanReadableSummary`, `obligations`, `allowedScope`
- each `notChecked` entry in the object form: `field`, `reason`, `impact`
- each `decisionChangeConditions` entry: `conditionType`, `description`, `requiredEvidenceType`
- `actionOutcome`: `status`, `performedAt`, `outcomeRef`; its `outcomeRef`: `uri`, `digest`
- `privacy`: `rawInputsIncluded`, `redactionProfile`, `erased`, `masked`
- `validity`: `audience`, `nonce`, `expiresAt`

Enums:
- `decisionType`: `preActionAuthorization` | `postHocReview` | `humanEscalation` | `policySimulation`
- `decision.verdict`: `ALLOW` | `DENY` | `REFUSE` | `ESCALATE` | `DEFER` | `OBSERVE`
- `actionOutcome.status`: `notAttempted` | `blocked` | `refused` | `attempted` | `executed` | `failed` | `unknown`

With `--strict`, `proofbundle decision verify` checks the signature and the package's v0.1 structure rules. It checks
the expected audience and nonce when `--aud` and `--nonce` are supplied, and checks `validity.expiresAt` against the
evaluation time. These checks do not implement the complete offline verification procedure in
draft-gruszka-audit-decision-receipts-05.

The command does not reject an evaluation time before `decidedAt`, as required by Section 3.2 step 9. A
Statement with two subject entries passes without `--require-derived-subject` and is rejected with that switch;
Section 3.2 step 6 requires exactly one derived subject. Binding `decisionMaker.id` to the signing key requires an
applicable `--policy`, as described in Section 9 below. The action, case and outcome checks of Section 3.2 step 10,
Section 3.3 and Section 3.4 run only when the relying party asks for them. `--action` gives the action bytes, and
without it they are not compared. `--case` chooses the case, and without it no case is checked; the approval case
also needs `--approval` with the approval record bytes, and a record given under another case, or without a case,
fails it. On `outcome verify`, `--executor-id` gives the expected executor identity and `--decision` with
`--decision-pub` and `--decision-maker-id` binds the decision, and the executed case requires both; `--effect` adds
the comparison of the effect bytes and stays optional. The bound decision is checked at `--verification-time`, and
without it at the wall clock. `docs/NON_CLAIMS.md` names the inputs that depend on one another.

For the F5 scenario in Appendix A.5 of revision 05, `proofbundle decision verify v2-declined-good.dsse.json --pub
<gate-1 key> --strict --aud observer-1 --nonce dec-0002 --verification-time 2026-10-15T09:06:00Z` exits 0. This
invocation does not receive the action bytes `a1` whose digest differs from `proposedAction.parametersDigest`. Exit 0
therefore does not mean that those action bytes were compared with the receipt. Given with `--action`, the bytes are
compared, and a digest that differs exits 2.

See `examples/decision_receipt_{allow,deny,escalate}.json` and the wrapped Statement
`examples/decision_receipt_with_eval_ref.intoto.json`. Machine schema:
`schemas/decision-receipt-v0.1.schema.json`.

### 6.1 Programmatic validation (the list-vs-raise contract)

`proofbundle.decision.validate_decision_predicate(pred)` **returns** a list of findings;
an **empty list means valid**. It does **not** raise. Check the list — do **not** wrap
the call in `try/except`, because "no exception" is not "valid": every predicate, valid
or not, returns without raising, so a `try/except` idiom reports invalid input as valid.

```python
errors = validate_decision_predicate(pred)
if errors:            # non-empty == invalid, fail closed
    reject(errors)
```

If you prefer exception control flow, call
`proofbundle.decision.require_valid_decision_predicate(pred)`, which raises
`DecisionReceiptError` (with the finding count and messages) on an invalid predicate and
returns `None` on a valid one. Both accept `strict=True` for the strict-v0.1 rules.

## 7. Verification

`proofbundle decision verify <envelope> --pub KEY [--policy trust_policy.json] [--json]`, where `<envelope>` is the
DSSE envelope of the receipt; a bare in-toto Statement carries no signature and does not verify.

Order: crypto first, then (if a policy is supplied) policy over the crypto result. The structured result uses
**snake_case** field names, each check independently reported, never silently `true`; among them:

```
structure_ok, crypto_ok, signer_trusted, predicate_type_ok, policy_ok, evidence_bound,
audience_ok, nonce_ok, freshness_ok, anchors_ok, action_outcome_proven, warnings[], errors[]
```

Non-applicable checks are `null`. `freshness_ok` is judged only over authenticated bytes: it is `null` when the
signature does not verify or the predicate is not an object. Otherwise it is `null` only when `validity.expiresAt`
is absent and the evaluation time is valid, since there is then no statement expiry to judge. An evaluation time
that is not a POSIX-seconds integer in range (the library argument `now`) makes it `false`, whether or not the
receipt declares an expiry. When `validity.expiresAt` **is** present it is judged (since
6.2.0) at one evaluation time: `true` or `false` against `--verification-time` (a past UTC `Z` instant)
when that option is given, otherwise against the verifier's wall clock; it is `false` (expired) when the
evaluation time is at or after `validity.expiresAt`, so the instant itself is already expired. A `false` folds into `ok` (the
receipt is not OK) and the CLI exits `2` when no earlier check has decided the exit; an unreadable or JSON-`null` `expiresAt` is fail-closed the same
way, never silently treated as "no expiry". The lifecycle of an attached `--policy` is a separate,
relying-party concern, evaluated at that same one instant.
`action_outcome_proven` is `false` (with a warning) when `actionOutcome.status = executed` without a
signed/digest-bound `outcomeRef`.

Exit codes (the Phase B `verify` contract, with the refusal of Section 4 added to exit 3):
`0` crypto OK (and policy OK if supplied) · `1` crypto/verification failure, or a supplied anchor that fails ·
`2` malformed input, an expired receipt, or a requested binding, action, case or lineage check that does not hold ·
`3` crypto OK but policy not satisfied, or the relying party refuses the approval under Section 4 of the draft
(`--consumed`, `--received`). The first check that fails decides, in this order: the signature (`1`), structure
and predicateType (`2`), a requested audience or nonce (`2`), a required derived subject (`2`), a supplied anchor
(`1`), the action bytes, the case and a requested lineage (`2`), the policy (`3`), Section 4 (`3`), and last the
expiry (`2`). A receipt that is expired and whose only other failure is the policy therefore exits `3`.
Without `--policy`, output shows `POLICY: NOT_EVALUATED`, and exit 3 then comes only from Section 4; there is no
bare context-free `OK`.

### 7.1 hash binding (two-part rule, no re-serialization bug)

1. **Emission:** the producer MUST emit the Statement payload in RFC-8785 canonical form.
2. **Anchoring / verify:** an anchor binds SHA-256 over the **exact DSSE payload bytes as transmitted**; the
   verifier **never** re-canonicalizes (DSSE rule: verify exact bytes). If the received payload deviates from
   its own RFC-8785 canonicalization, that is a fail-closed error, not a repair case.
   On the receipt under verification, on the decision, outcome and relation-statement paths alike, that error
   is malformed (exit 2) once the signature verifies, and the receipt's edges are still judged; a signature
   that fails is exit 1 first (`docs/predicates/relation.md`, the statement oracle).

So `hash(exact bytes) == hash(RFC-8785 form)`, consistent with the enclave binding and with the
`RFC 8785 → sha256 → anchored root` path. proofbundle does **not** adopt the field-subset canonicalization
floated in in-toto/attestation#565 (ambiguity risk on extension); this deviation is publicly announced and
tracked on proofbundle#7.

## 8. Anchors (optional, DETACHED, composition)

An anchor commits the decision statement's **content root** = SHA-256 over the exact RFC-8785 canonical
Statement bytes (identical to the DSSE payload bytes; **signature bytes are never part of the anchored
preimage**). An anchor for the statement's OWN root therefore cannot live *inside* the signed predicate: it
would be part of the bytes whose hash it commits, resolvable only by the forbidden subset canonicalization
(a chicken-and-egg self-reference). So anchor evidence for the own root is kept **detached** — a sibling of
the DSSE envelope, `target: "statement"` — exactly as the eval path keeps anchors outside the signed bytes.
An in-predicate `anchors` field is a fail-closed error. The emission order is: emit canonically → sign →
compute the content root → submit to the anchor → attach the anchor evidence detached. A FOREIGN anchor (for
example the pre-registration anchor of a cited evidence statement) may be referenced indirectly via
`evidenceRefs`, because that evidence does not commit *this* statement's root.

Detached anchors reuse the existing proofbundle anchors architecture via `register_anchor_type` and are
verified against the recomputed content root (result field `anchors_ok`). Built-in verifier types are
`rfc3161-tsa` and `opentimestamps` (with the `[anchors]` extra) and `chia-datalayer/v1` (pure-offline, always
registrable). Any other extension type (for example a markovian-provenance verifier) must be registered
before a decision `verify` can check it — an unregistered anchor type is a fail-closed error, never a silent
pass. A `pending` anchor (e.g. OTS calendar-only) does **not** satisfy the anchor
obligation in strict mode: pending is the absence of a timestamp, not a weaker one (`require_external_anchor`
with the default `allow_pending: false`). Anchor-type neutrality: no de-facto coupling to a single anchor type.
Honest limit: an anchor proves existence-until-T and non-alteration, not that the decision was made *after*
reading the inputs or *before* the action. Ed25519 payload signatures are deterministic, so the "two proofs,
one content" case arises from counter-signing, key rotation or multi-signature envelopes, not from re-signing
with the same key; the enclave binding (`eat_nonce`) stays a separate exact-blob binding, never fused with the
content root.

## 9. Trust policy (v0.2)

The Phase B trust policy (`proofbundle/trust-policy/v0.1`, snake_case, fail-closed) is extended **additively**
to `v0.2` with a `decision_receipt` section. A v0.1 policy stays valid unchanged under the v0.2 parser (only
additive; fail-closed preserved). Knobs:

- identity + shape: `accepted_predicate_types`, `trusted_decision_makers` (signer key ↔ `decisionMaker.id`),
  `allowed_decision_types`, `allowed_verdicts`, `required_evidence_relations`, `require_policy_digest`;
- presence requirements: `require_audience`, `require_nonce`, `require_not_checked`,
  `require_decision_change_conditions`, `require_trace_context`;
- `allow_raw_inputs` (default `false`: a receipt with `privacy.rawInputsIncluded: true` is rejected unless
  the relying party opts in);
- `require_external_anchor` + `allow_pending` (default `false`): gated on the REAL detached-anchor
  verification result, never on a claimed in-predicate field — a `pending` anchor does not satisfy.

`decisionMaker.id` is never believed on the JSON claim alone: it is matched against the DSSE signer key via
`trusted_decision_makers`. A `predicateType` confusion attack (a decision receipt presented as an eval-result,
or vice versa) fails via the `predicate_type_ok` check plus `accepted_predicate_types`. Without a policy,
`verify` reports `POLICY: NOT_EVALUATED`; a policy violation over crypto-OK bytes is exit code 3.

The relying party supplies the policy that binds an expected `decisionMaker.id` to the signing key. In vector F3 of
Appendix A.5 of draft-gruszka-audit-decision-receipts-05, the receipt names gate-2 but is signed with the gate-1 key.
`proofbundle decision verify f3.dsse.json --pub <gate-1 key> --strict --aud observer-1 --nonce dec-0002
--verification-time 2026-10-15T09:06:00Z --policy policy_gate1.json` exits 3 when `trusted_decision_makers` maps that
key to gate-1. The same invocation without `--policy` exits 0 and reports `POLICY: NOT_EVALUATED`. That result does
not establish trust in the identity named by the receipt.

Checking the bytes referenced by `evidenceRefs` remains the relying party's responsibility. A true `evidence_bound`
result does not establish that those bytes were read or that their hashes match the references. In the B7
measurement, the receipt with the mismatching evidence digest exits 0 and reports `evidence_bound` true both without
a policy and with the test policy.

## 10. Privacy

`privacy` is required in strict mode and states whether raw inputs are included, which fields were
erased/masked, and the redaction profile. Prefer digests over raw parameters (`parametersDigest`,
`inputSnapshot[].digest`). No chain-of-thought. Only digests/roots leave the system for anchoring.

## 11. Interop

`decision-receipt/v0.1` is a vendored in-toto predicate; it makes no claim on the `in-toto.io` namespace. Any
upstream standardization is a separate discussion (issue #26). Related art it composes with: SLSA VSA
(`decisionMaker` ~ `verifier`), OPA decision logs (`policyBoundary`/`decisionPath`), W3C Trace Context
(`traceContext`).

## 12. Version history

- v0.1 (2.1.0): initial vendored predicate. See ADR 0001.
