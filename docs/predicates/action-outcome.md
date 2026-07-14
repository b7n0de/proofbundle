# Action Outcome predicate `action-outcome/v0.1`

Status: EXPERIMENTAL in proofbundle 3.2.0 (vendored `action-outcome/v0.1` under the b7n0de namespace; API and
wire format may change without deprecation). It closes the eval → decision → **outcome** chain: an eval says
what was measured, a decision says what was permitted, an outcome says what was actually *done* about it.

Schema: [`schemas/action-outcome-v0.1.schema.json`](../../schemas/action-outcome-v0.1.schema.json) (docs-only;
the executable contract is the hand-rolled fail-closed validator in `src/proofbundle/outcome.py`, not the
JSON Schema — the schema never gates a verdict).

## 1. Purpose

An Action Outcome is a signed, offline-verifiable record that a specific **executor** (a tool boundary, a
mediator, a deploy runner) carried out — or refused — the action a specific Decision Receipt permitted, over a
digest-bound requested action, with the actual effect digest-bound, at a specific time.

It answers: *who executed, which decision authorized it, what action was requested, what actually happened
(executed / refused / failed), what the effect digest was, and what was explicitly not proven.* It is an
in-toto Statement (DSSE, Ed25519) whose subject is by default DERIVED from the predicate content (SHA-256 over
its RFC-8785 canonical bytes), verified against the exact signed bytes.

## 2. Non-goals (what an Action Outcome does NOT prove)

- It does **not** prove the action was correct, safe, authorized-in-fact, or that the decision it cites was
  sound. It binds the outcome to a decision; whether that decision was right is the decision-receipt's concern.
- `status = executed` with only a self-asserted effect is **not** proof of execution. `execution_proven` is
  True only when the status is `executed` AND an `effectDigest` or `actualActionDigest` is present; a bare
  `executed` with no such digest returns `execution_proven = False` and a verify warning (No-Fake). For a
  non-`executed` status it is `None` (not applicable).
- It carries **no** chain-of-thought, no raw secrets, no tool credentials.

The boundary mirrors decision-receipt and eval-result: a new signed claim type widens the attestation surface,
so its verify path and non-claims are explicit.

## 3. Information architecture

One-directional, **content-root** coupling (same rule as decision-receipt §3):

```
decision-receipt statement  (verdict + boundary; own detached anchors)
        ^
        | decisionRef.sha256 = content root of the decision statement
        | (outcome references the decision, never the reverse)
        |
action-outcome statement  (executor + status + effect + notProven; own detached anchors)
```

`decisionRef.sha256` is the **content root** of the referenced Decision Receipt — SHA-256 over its exact
RFC-8785 canonical Statement bytes, never a re-canonicalized recomputation and never the bare predicate hash.
`verify_outcome_receipt(..., expected_decision_ref=...)` fails closed when the embedded `decisionRef` does not
equal the caller's expected content root (`decision_bound`). An optional `requestedActionDigest` pins the exact
proposed action; `effectDigest` / `actualActionDigest` pin the observed effect. Neither predicate semantically
mixes into the other.

## 4. Fields (predicate)

| field | required | meaning |
|---|---|---|
| `schemaVersion` | yes | `0.1.0` |
| `outcomeId` | yes | stable id of this outcome record |
| `decisionRef.sha256` | yes | content root of the authorizing Decision Receipt |
| `executor.id` | yes | who executed (checked to differ from the decision maker — role separation — when a `decision_maker_id` is supplied to verify) |
| `requestedActionDigest.sha256` | yes | digest of the action that was requested |
| `status` | yes | `executed` / `refused` / `failed` / `partial` |
| `performedAt` | yes | RFC-3339 UTC (`…Z`), fail-closed on non-Z / malformed |
| `effectDigest.sha256` | for `execution_proven` | digest of the observed effect; `actualActionDigest` satisfies the same proof |
| `actualActionDigest` / `responseDigest` | optional | further digest-bound evidence of what was actually done / returned |
| `policyPurpose` | optional | when present MUST be `outcome` (the reference verifier wires it to the outcome verdict) |

Validation is fail-closed: unknown field, missing required, bad enum, non-RFC3339-Z timestamp, malformed digest
(not 64 lowercase hex), or `policyPurpose != outcome` → `validate_outcome_predicate` rejects.

## 5. Verify path (`verify_outcome_receipt`)

In order, fail-closed — a later check never rescues an earlier failure, and every trust field is `None` when
the crypto step fails:

1. **crypto_ok** — DSSE signature over the exact PAE bytes with the expected Ed25519 key. On failure every
   downstream trust field is `None` (no partial trust).
2. **predicate_type_ok** — vendored `action-outcome/v0.1`.
3. **hash_binding** — `rfc8785(statement)` equals the transmitted body bytes (no re-canonicalization drift).
4. **decision_bound** — embedded `decisionRef.sha256` equals `expected_decision_ref` (when supplied).
5. **role_separation_ok** — `decision_maker_id != executor.id` (an executor may not authorize its own action),
   checked **when `decision_maker_id` is supplied** to verify (like `decision_bound`); not supplied → not
   enforced (`role_separation_ok` stays `None`).
6. **execution_proven** — `status == executed` AND an effect/actual digest is present. Self-asserted
   (`executed` without an effect digest) → `False` + warning.
7. **audience / nonce** — fail-closed when the caller pins them and the statement does not match.

Read the aggregate verdict, never an individual field alone. `status = refused` / `failed` are first-class,
honest outcomes (a refusal is a valid, signable outcome — not an error to hide).

## 6. Subject binding

By default the subject digest is DERIVED (`derive_subject_digest` = SHA-256 over the RFC-8785 canonical
predicate). `classify_subject` re-derives and compares → `DERIVED` (matches) vs `EXTERNAL_ATTESTED` (an
override / tamper / malformed subject, fail-closed `matches = False`). See
[`subject_binding.py`](../../src/proofbundle/subject_binding.py) (3.2.0 O6).

## 7. Open (honest, not yet built)

- Independent attestation of `executor.id` (a trust-pack role binding for executors, 3.2.0 O2 — the trust pack
  can carry `outcomeExecutors`, but a live registry / DID anchor for executors is future work).
- A tool-log profile that turns `execution_proven` from a self-asserted effect digest into a third-party
  signed tool log (`outcomeRef` style, mirroring decision-receipt §2).
