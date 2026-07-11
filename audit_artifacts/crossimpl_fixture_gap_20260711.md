# Cross-implementation decision-receipt fixture: canonicalization holds, schema conformance does not (2026-07-11)

Independent re-verification of the MarkovianProtocol/audit-anchor decision-receipt
fixture against `proofbundle@main`. This file is the No-Overclaim record behind the
correction the maintainer is posting to issue #7: the canonicalization/root-binding
interop is proven, but the external predicate does **not** yet satisfy the enforced
`decision-receipt/v0.1` schema. Both statements are recorded here so neither is lost.

Source (read-only clone): `MarkovianProtocol/audit-anchor@3abe69f`
(`examples/decision-receipt/`). Verifier: `proofbundle@main` with `rfc8785`.

## What passes — canonicalization + content-root binding (the hard part, cross-impl)

Recomputed with `statement_content_root()` (jcs-sha256-v1) and byte-compared against
the committed `.jcs` files and `MANIFEST.json`:

| Statement | JCS byte-identical | content root | == MANIFEST |
|---|---|---|---|
| `decision_receipt` | yes | `ff05e3e0126e31090511f9e42494bbde4d86c9b1a9a0a9570850c42e8546029b` | yes |
| `evidence_eval_result` | yes | `323adb188f840e90331c920b32a73f348acc5caea8d40f9a84ea384d46c258d4` | yes |

`predicate.evidenceRefs[0].digest` equals the evidence content root, and both
`predicateType` URIs are the frozen/vendored ones. A second implementation derives
the same RFC 8785 bytes and the same content roots as proofbundle — that is the
interop claim, and it holds.

## What does not pass — decision-receipt/v0.1 schema conformance

`validate_decision_predicate(predicate)` returns **12 findings** (an empty list would
mean valid). Reproduced identically against `schemas/decision-receipt-v0.1.schema.json`:

```
1  unknown top-level field(s) ['action', 'flipConditions', 'inputsSnapshot', 'policy', 'verdict']
2  missing required field 'schemaVersion'
3  missing required field 'decisionId'
4  missing required field 'decisionType'
5  missing required field 'decisionMaker'
6  missing required field 'agent'
7  missing required field 'principal'
8  missing required field 'proposedAction'
9  missing required field 'inputSnapshot'
10 missing required field 'policyBoundary'
11 missing required field 'decision'
12 evidenceRefs[0] needs a string 'relation' and a sha256 content-root 'digest'
```

Cause: the predicate was built from the converged thread prose in #7
(`action`/`verdict`/`policy`/`inputsSnapshot`/`flipConditions`), not from the in-repo
contract (`docs/predicates/decision-receipt.md` + the schema, both public since
2026-07-10). Both fixture generations (`1964ef5`, `3abe69f`) carry the same shape.

## Field mapping thread-prose → v0.1 schema

| Fixture field (present) | v0.1 schema field | note |
|---|---|---|
| `action: "deploy"` | `proposedAction` (object, required) | prose string → structured object |
| `verdict: "allow"` | `decision.verdict` | enum is upper-case `ALLOW\|DENY\|REFUSE\|ESCALATE\|DEFER\|OBSERVE`; add `decision.reasonCodes` |
| `policy: {id, digest}` | `policyBoundary` | carries `policyDigest` |
| `inputsSnapshot` | `inputSnapshot` | singular |
| `flipConditions` | `decisionChangeConditions` | rename |
| `evidenceRefs[0]` (has `predicateType`+`digest`) | same, **plus** required string `relation` | e.g. `relation: "evalResult"` |
| `decidedAt` | `decidedAt` | already present and required — kept |
| `notChecked` | `notChecked` | valid optional field — kept |

Required fields with no source in the current fixture (must be added):
`schemaVersion` (pattern `^0\.1\.\d+$`, e.g. `"0.1.0"`), `decisionId`, `decisionType`,
`decisionMaker`, `agent`, `principal`.

## Reference — the shape that validates clean

`examples/decision_receipt_with_eval_ref.intoto.json` →
`validate_decision_predicate` returns **0 findings**. It is the authoritative example
of the target shape; the schema files above are the contract, the thread prose is not.

## API footgun that produced the earlier wrong "VALID"

`validate_decision_predicate` **returns** a `list[str]` (empty == valid) and does not
raise. A `try/except`-based check sees no exception and falsely reports "VALID". This
is tracked as work item W6 (raising wrapper + doc + regression test).

---

## OWNER-TASK — correction template for b7n0de/proofbundle#7 (posted only by Konrad)

> The agent does not post, comment, or push anywhere. The text below is an archived
> Owner template, verbatim from the scope addendum, to be posted by the Owner (edited
> or as-is). It is reproduced here only so the correction and its evidence live together.

```text
Hi Colin,

your regeneration verifies on my side exactly as the manifest pins it: both content
roots recompute from the RFC 8785 canonical bytes (evidence 323adb18…, decision
ff05e3e0…), your .jcs files are byte-identical with proofbundle's canonical output,
the evidenceRef binds the evidence content root, and both predicateType URIs are the
frozen/vendored ones. The canonicalization + root-binding interop is proven — that's
the hard part, and it holds across implementations.

One correction on my side, before you invest in the next step: I wrote earlier that
the predicate "passes the enforced v0.1 validator as-is" — that was wrong, and the
error was mine (I misread our validator's list-returning API as an exception-based
one). The enforced validator pins a richer predicate shape than the thread prose we
converged on. Against the actual schema your predicate currently reports 12 findings
(field names + required set), e.g.:

  action          → proposedAction (object)
  verdict         → decision.verdict (enum: ALLOW|DENY|REFUSE|ESCALATE|DEFER|OBSERVE,
                    plus decision.reasonCodes)
  policy          → policyBoundary (incl. policyDigest)
  inputsSnapshot  → inputSnapshot
  flipConditions  → decisionChangeConditions
  evidenceRefs[0] additionally needs a string `relation` (e.g. "evalResult")
  required but absent: schemaVersion ("0.1.0"), decisionId, decisionType,
                       decisionMaker, agent, principal

Authoritative references (all in-repo):
  schemas/decision-receipt-v0.1.schema.json
  docs/predicates/decision-receipt.md
  examples/decision_receipt_with_eval_ref.intoto.json  (validates clean)

Plan on my side, so nothing you built is wasted:
1. Your OLD vector (decision root 16b80b4c…, OTS upgraded to Bitcoin block 957504)
   goes in now as the confirmed anchor-lifecycle cross-impl case, digest-pinned,
   credited — it's the only externally confirmed end-to-end OTS case we have.
2. The regenerated vector goes in now as the canonicalization/root-binding
   cross-impl case (that's what it proves today), with the validator gap documented
   as expected-fail, not hidden.
3. If you regenerate once more against the schema above, it graduates to the full
   end-to-end decision-receipt/v0.1 conformance case — and that's the version I'd
   reference from the in-toto thread. Same offer as before: digest-pinned, pure
   data, credited and linked.

Sorry for the churn my earlier sentence caused — the schema files above are the
contract, not my thread prose.

Konrad
```
