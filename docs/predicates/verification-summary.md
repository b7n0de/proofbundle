# Verification Summary predicate `verification-summary/v0.1`

Status: EXPERIMENTAL in proofbundle 3.2.0 (vendored under the b7n0de namespace; API and wire format may change
without deprecation). A Verification Summary is a signed roll-up of a receipt chain — eval → decision →
outcome — that records, per level, the verified receipt's content root, its verdict status, and its evidence
class, plus a mandatory non-claims block.

Schema: [`schemas/verification-summary-v0.1.schema.json`](../../schemas/verification-summary-v0.1.schema.json)
(docs-only; the executable contract is `src/proofbundle/verification_summary.py`).

## 1. Purpose

It answers, for one chain of receipts: *which levels were verified, against which receipt content roots, with
what verdict, and on what class of evidence.* It lets a relying party carry one signed object instead of
re-verifying every level, without ever collapsing the distinct non-claims of each level.

## 2. Non-goals

It does **not** prove the eval number is true, the decision correct, the effect real, or that coverage is
complete. That is exactly what the mandatory `nonClaims` block records verbatim — a summary widens the surface,
so its limits are stated as loudly as its contents.

## 3. Fields

| field | required | meaning |
|---|---|---|
| `schemaVersion` | yes | `0.1.0` |
| `summaryId` | yes | stable id of this summary |
| `producedAt` | yes | RFC-3339 UTC |
| `levels` | yes | array of `{kind, status, evidenceClass, receiptRef?, checks?}` |
| `nonClaims` | yes | non-empty array of strings (the No-Overclaim block is mandatory) |

Per level: `kind` (eval/decision/outcome), `status` ∈ `VERIFIED` / `FAILED` / `NOT_EVALUATED`, `evidenceClass`.
`receiptRef` (the verified receipt's content-root digest) is **structurally optional** — a `NOT_EVALUATED`
level legitimately references no receipt.

## 4. The real (non-tautological) consistency rule

`levels_consistent` is enforced at verify time, not by making `receiptRef` blindly required (that would be a
check that can never fail). The rule: a level with `status = VERIFIED` **MUST** carry a `receiptRef` (you
cannot claim a level verified against nothing); a level with `status = NOT_EVALUATED` and no `receiptRef` stays
consistent (honest absence). A VERIFIED-without-receiptRef fails — a real, testable bidirectional rule.

## 5. Verify

Fail-closed: valid predicate + vendored type + DSSE signature over the exact bytes, then `levels_consistent`.
Read the aggregate verdict. `FAILED` and `NOT_EVALUATED` levels are first-class, honest states — a summary that
hides an un-evaluated level under a green roll-up is the failure mode this predicate is built to prevent.
