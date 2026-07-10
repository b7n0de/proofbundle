# Decision Receipt predicate `decision-receipt/v0.1`

Status: draft for proofbundle 2.1.0. Vendored predicate under the b7n0de namespace. Design of record:
[`docs/adr/0001-decision-receipt-separate-predicate.md`](../adr/0001-decision-receipt-separate-predicate.md).

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

One-directional, digest-bound coupling (ADR §3):

```
eval-result statement  (metric/benchmark evidence, its own anchors[])
        ^
        | digest-bound evidenceRef  (decision references evidence, never the reverse)
        |
decision-receipt statement  (verdict + boundary + notChecked, its own anchors[])
```

The evidence is anchored independently of the decision that cites it. Neither predicate semantically mixes
into the other.

## 4. Predicate type and payload

- `predicateType`: `https://b7n0de.com/proofbundle/predicates/decision-receipt/v0.1`
- Statement `_type`: `https://in-toto.io/Statement/v1`
- DSSE `payloadType`: `application/vnd.in-toto+json` (the in-toto envelope media type, not a predicate subtype)
- `subject`: a commitment to the decision (e.g. `name: "decision:<decisionId>"`, `digest.sha256`). Evidence
  receipts are **never** abused as `subject`; they live in `predicate.evidenceRefs[]`.

## 5. Parsing and versioning rules (fail-closed)

1. Unknown top-level predicate fields are rejected (`additionalProperties: false`), never ignored.
2. Time fields are RFC3339 with a trailing `Z`. No generic `timestamp`; use `decidedAt`, `recordedAt`,
   `performedAt`.
3. SemVer: `schemaVersion: "0.1.0"` (or a compatible `0.1.x`); the `predicateType` contains `v0.1`.
4. Field names are **lowerCamelCase** (ITE-9). Only the proofbundle-local trust-policy file is snake_case.

## 6. Required fields (strict v0.1)

`schemaVersion`, `decisionId`, `decisionType`, `decidedAt`, `decisionMaker`, `agent`, `principal`,
`proposedAction`, `inputSnapshot`, `policyBoundary` (incl. `policyDigest` in strict mode), `evidenceRefs`
(may be empty only when the decision explicitly used no additional evidence), `decision`
(`verdict` + `reasonCodes`), `notChecked`, `decisionChangeConditions`, `privacy`.

Optional: `recordedAt`, `delegationRefs`, `actionOutcome`, `traceContext`, `validity` (strict interactive mode
requires `audience` + `nonce`), `anchors`.

Enums:
- `decisionType`: `preActionAuthorization` | `postHocReview` | `humanEscalation` | `policySimulation`
- `decision.verdict`: `ALLOW` | `DENY` | `REFUSE` | `ESCALATE` | `DEFER` | `OBSERVE`
- `actionOutcome.status`: `notAttempted` | `blocked` | `refused` | `attempted` | `executed` | `failed` | `unknown`

See `examples/decision_receipt_{allow,deny,escalate}.json` and the wrapped Statement
`examples/decision_receipt_with_eval_ref.intoto.json`. Machine schema:
`schemas/decision-receipt-v0.1.schema.json`.

## 7. Verification

`proofbundle decision verify <statement-or-envelope> [--pub KEY] [--policy trust_policy.json] [--json]`.

Order: crypto first, then (if a policy is supplied) policy over the crypto result. The structured result uses
**snake_case** field names, each check independently reported, never silently `true`:

```
structure_ok, crypto_ok, signer_trusted, predicate_type_ok, policy_ok, evidence_bound,
audience_ok, nonce_ok, freshness_ok, anchors_ok, action_outcome_proven, warnings[], errors[]
```

Non-applicable checks are `null`. `action_outcome_proven` is `false` (with a warning) when
`actionOutcome.status = executed` without a signed/digest-bound `outcomeRef`.

Exit codes (identical to the Phase B `verify` contract):
`0` crypto OK (and policy OK if supplied) · `1` crypto/verification failure · `2` malformed input ·
`3` crypto OK but policy not satisfied. Without `--policy`, output shows `POLICY: NOT_EVALUATED`; there is no
bare context-free `OK`.

### 7.1 hash binding (two-part rule, no re-serialization bug)

1. **Emission:** the producer MUST emit the Statement payload in RFC-8785 canonical form.
2. **Anchoring / verify:** an anchor binds SHA-256 over the **exact DSSE payload bytes as transmitted**; the
   verifier **never** re-canonicalizes (DSSE rule: verify exact bytes). If the received payload deviates from
   its own RFC-8785 canonicalization, that is a fail-closed error, not a repair case.

So `hash(exact bytes) == hash(RFC-8785 form)`, consistent with the enclave binding and with the
`RFC 8785 → sha256 → anchored root` path. proofbundle does **not** adopt the field-subset canonicalization
floated in in-toto/attestation#565 (ambiguity risk on extension); this deviation is publicly announced and
tracked on proofbundle#7.

## 8. Anchors (optional, composition)

Decision anchors reuse the existing proofbundle anchors architecture (`register_anchor_type`, rfc3161,
opentimestamps, chia-datalayer/v1, markovian-provenance/v1). A decision receipt anchors its **own** canonical
root; the eval-result it cites anchors its own root independently. A `pending` anchor (e.g. OTS calendar-only)
does **not** satisfy the anchor obligation in strict mode: pending is the absence of a timestamp, not a weaker
one. Anchor-type neutrality: no de-facto coupling of the Decision Receipt to a single anchor type. Honest
limit: an anchor proves existence-until-T and non-alteration, not that the decision was made *after* reading
the inputs or *before* the action.

## 9. Trust policy (v0.2)

The Phase B trust policy (`proofbundle/trust-policy/v0.1`, snake_case, fail-closed) is extended **additively**
to `v0.2` with a `decision_receipt` section (`trusted_decision_makers`, `allowed_decision_types`,
`allowed_verdicts`, `required_evidence_relations`, `require_policy_digest`, `accepted_predicate_types`,
`require_external_anchor`, `allow_pending` (default `false`), …). A v0.1 policy stays valid under the v0.2
parser (only additive). `decisionMaker.id` is never believed on the JSON claim alone: it is matched against the
DSSE signer key via `trusted_decision_makers`. A `predicateType` confusion attack (a decision receipt presented
as an eval-result, or vice versa) fails via the `predicate_type_ok` check plus `accepted_predicate_types`.

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
