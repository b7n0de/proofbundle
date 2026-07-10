# ADR 0002: Universal content root (`jcs-sha256-v1`)

- **Status:** accepted (design-only; the released-path activation is a separate owner gate — see §Migration)
- **Date:** 2026-07-10 (decision date; commit date live)
- **Deciders:** proofbundle maintainer (b7n0de)
- **Builds on:** ADR 0001 (decision-receipt as a separate vendored predicate)

## Context

Two proofbundle attestation paths hash a Statement, and today they disagree on *how*:

- The **decision-receipt** path (`decision.py`, PR #45 / 2.1.0) defines a receipt's content root over the
  **RFC-8785 (JCS)** canonical Statement bytes, and binds `evidenceRefs[].digest` and `statement`-target
  anchors to that root.
- The released **eval-result / test-result / SVR** in-toto export paths (`intoto.py`) serialize the Statement
  with `json.dumps(sort_keys=True, separators=(",", ":"))` (`_canonical_body`). That is *not* full RFC-8785 —
  it does not normalize number formatting or string escaping, and differs on non-ASCII / mixed-case keys — so
  it cannot carry a stable, cross-implementation content root.

The consequence is real and already documented as a No-Overclaim caveat in
`docs/predicates/decision-receipt.md` §3 (on the PR #45 branch): a decision receipt can only be guaranteed to
compose byte-for-byte with an eval-result statement it cites *when the evidence side was itself emitted
RFC-8785-canonically*. The two content-root definitions must converge on one.

The convergence target was fixed publicly on
[b7n0de/proofbundle#7](https://github.com/b7n0de/proofbundle/issues/7) (2026-07-10) with an external
collaborator ("converging on the same bytes"): the content root is SHA-256 over the RFC-8785 canonical
**Statement** bytes (the pre-signature object), signature bytes never in the preimage.

## Decision

1. **`contentRootAlg = jcs-sha256-v1`.** A Statement's content root is `SHA-256` over the RFC-8785 (JCS)
   canonical bytes of the **full** Statement — `_type`, `subject`, `predicateType`, `predicate` — taken
   **before** signing. The signature/envelope bytes are **never** part of the preimage. The algorithm id is a
   first-class, versioned string (`CONTENT_ROOT_ALG` in `canonical.py`); a future algorithm registers its own
   distinct id and a verifier MUST NOT silently default a missing/unknown value (that is where an
   algorithm-confusion attack would hide, mirroring `merkle.hash_alg`).

2. **Full-Statement scope, never a subset.** The preimage is the whole Statement, not a predicate-only object
   and not any field subset. Binding only the predicate would drop `subject` + `predicateType` and reopen a
   context-confusion attack (the §2.1 finding of the audit addendum, at the primitive level). Subset
   canonicalization is forbidden everywhere.

3. **Signature bytes never in the preimage.** Because the root commits the *claim content* and not the
   signature, it survives counter-signing, key rotation and multi-signature envelopes — the property that lets
   evidence and the decision that cites it both live on content roots and compose.

4. **Two-part producer/verifier rule.**
   - A **producer** MUST emit its Statement canonically (RFC-8785) and sign exactly those bytes.
   - A **verifier** MUST hash the **exact transmitted payload bytes** and MUST NOT re-canonicalize. A payload
     that deviates from its own canonical form is a fail-closed error the verifier rejects (the decision path's
     `hash_binding` check already does this). Re-canonicalizing on verify would let a non-canonical payload
     masquerade as canonical.

5. **One shared primitive.** The two operations live in `src/proofbundle/canonical.py`:
   - `canonicalize_statement(obj) -> bytes` — the producer canonicalization (RFC-8785, lazy `[eval]` extra,
     fail-closed `CanonicalizerUnavailable` when the extra is absent).
   - `statement_content_root(statement) -> bytes` — the 32-byte content root. Given a JSON object it
     canonicalizes then hashes (producer); given raw `bytes` it hashes exactly those bytes (verifier). Both
     yield the same root when the producer emitted canonically. `.hex()` is the form used in
     `evidenceRefs[].digest.sha256` and a `statement` anchor's `canonicalRoot`.

## Migration (this is the crux; nothing released breaks)

The released `intoto.py` export paths (`export_intoto_dsse`, `export_eval_result_dsse`, `export_svr_dsse`) sign
over `_canonical_body(...)` = `json.dumps(sort_keys=True)`. Switching the **signed** bytes to RFC-8785 changes
the wire (existing signatures no longer verify against a re-emitted body), so the migration is a **compatible
evolution with an explicit legacy mode**, not a data-loss cutover:

1. **Versioned algorithm, declared per receipt.** A content root is qualified by its `contentRootAlg`. The new
   default is `jcs-sha256-v1`. The historic `json.dumps(sort_keys=True)` form is retained as a named legacy
   algorithm (`legacy-sortkeys-json-v0`, an explicit declared mode — *not* an unlabeled fallback).

2. **Old receipts keep verifying.** A receipt/attestation that declares (or, for pre-declaration artifacts, is
   verified under an explicitly selected) legacy mode is hashed with the legacy serializer, so already-signed
   bytes still verify. Absence of a declared algorithm is **never** silently treated as JCS — a verifier
   selects legacy only when the caller explicitly opts in.

3. **New receipts default to `jcs-sha256-v1`** via the shared `canonical.canonicalize_statement`, unifying the
   decision-receipt and eval-result/SVR content roots so cross-predicate composition matches byte-for-byte.

4. **The decision-receipt path already uses the target algorithm** — this ADR standardizes the primitive it
   defined and makes it the shared home for the eval-result/SVR paths to adopt during activation.

### Honest scope of THIS ADR (No-Overclaim)

This ADR **designs** the universal content root and its migration. It does **not** activate the default switch
for the released eval-result / test-result / SVR paths. That activation:

- is a **wire change** to released, signed attestations (it changes the signed bytes for new receipts and adds
  a declared-legacy verify branch), and is therefore a **T3 / SemVer owner-gated** step, part of the **2.1.0**
  release owner gate — the same gate that ships the decision-receipt predicate;
- carries a **P0 activation test**: *"a `json.dumps(sort_keys=True)` root offered as a `jcs-sha256-v1` root is
  rejected unless legacy mode is explicitly selected"* (the eval-export migration test named in the audit
  addendum §3.4). That test belongs to the activation phase, not to this foundation, because it asserts the
  behavior the activation introduces.

What lands now (WP2 foundation) is non-breaking and additive: the ADR, the shared `canonical.py` primitive,
its exports and tests. No released path is migrated. The decision-receipt module (`decision.py`, on the still
open PR #45 branch) is the intended first adopter of the primitive — once that branch rebases onto a `main`
carrying `canonical.py`, its local `_rfc8785_bytes` delegates to `canonical.canonicalize_statement` (catching
`CanonicalizerUnavailable` to preserve its own `DecisionReceiptError` message), and `anchors.statement_content_root`
(bytes → root) can delegate to `canonical.statement_content_root` with identical behavior. That adoption is a
pure refactor tracked with PR #45, not part of this design-only ADR.

## Consequences

- The primitive is a stable, tested public API (`proofbundle.canonicalize_statement`,
  `proofbundle.statement_content_root`) with a declared `CONTENT_ROOT_ALG`. It is dependency-light: the base
  install and the plain verify path pull no canonicalizer; the producer path lazily needs `[eval]`.
- The eval-result/SVR migration is a known, owner-gated follow-up with a named P0 test; until it is activated,
  the cross-predicate content-root caveat in the decision-receipt doc §3 remains accurate and stays published.
- The `#7` consensus (content root over pre-signature Statement bytes, no subset canonicalization) and ADR 0001
  (decision-receipt as its own predicate) are the references this ADR honors; deviating would require reopening
  the `#7` discussion.
