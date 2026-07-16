# Lineage / relationship profile `relation/v0.1`

Status: EXPERIMENTAL in proofbundle 3.3.0 (API and wire format may change without deprecation).
Executable contract: the hand-rolled fail-closed validator and chain verifier in
`src/proofbundle/relation.py`; the JSON-Schema mirrors in
[`schemas/decision-receipt-v0.1.schema.json`](../../schemas/decision-receipt-v0.1.schema.json) /
[`schemas/action-outcome-v0.1.schema.json`](../../schemas/action-outcome-v0.1.schema.json) are
docs-only and never gate a verdict. Design record:
[`docs/design/RELATION_V01_DESIGN.md`](../design/RELATION_V01_DESIGN.md).

## 1. The one pattern

Change is never expressed by mutation. A receipt binds exact bytes and stays valid for those
bytes forever; when a result is deliberately corrected, re-run, or withdrawn, the NEW receipt
carries a TYPED, SIGNED relationship edge pointing at its predecessor's content root. The
verifier reports the relationship as its own `lineage` state — instead of leaving replacement
invisible (silent landing) or treating it as tampering.

The honesty boundary, verbatim: **relationship declared by issuer, not a statement of
correctness.** A verified edge proves the issuer declared the derivation over exact bytes —
never that the successor is better, more true, or methodologically sound.

## 2. Placement and edge shape

`relationships: [edge, …]` is an OPTIONAL field of the decision-receipt and action-outcome
predicates — INSIDE the DSSE-signed statement bytes, so the receipt's own signature covers the
edges (deliberately unlike detached `anchors[]`, which is evidence ABOUT a receipt). The outer
Merkle bundle (`proofbundle/v0.1`) is untouched: no wire break for old verifiers. One honest
caveat: the docs-only predicate SCHEMAS are `additionalProperties:false`, so a third party
validating a NEW receipt against an OLD schema file rejects the field (the same inherited
pattern as `receiverRefs`/`sequence`); inside proofbundle the hand-rolled validators — not the
schema files — gate verdicts.

```json
{
  "relation": "supersedes",
  "targetReceiptDigest": {"digestAlgorithm": "jcs-sha256-v1", "digest": "<64 hex>"},
  "targetSubjectDigest": {"digestAlgorithm": "jcs-sha256-v1", "digest": "<64 hex>"},
  "reasonCode": "correction",
  "reason": "optional free text",
  "declaredAt": "2026-07-16T00:00:00Z"
}
```

- `targetReceiptDigest` (required) is the CONTENT ROOT of the exact target statement bytes —
  the same `jcs-sha256-v1` mechanic as `evidenceRefs[].digest` / `decisionRef`. The
  `digestAlgorithm` is EXPLICIT and REQUIRED, never defaulted (a missing value is exactly
  where an algorithm-confusion attack would hide).
- `declaredAt` is issuer testimony, INFORMATIVE only (the `anchoredAt` honesty rule).
- WHO may declare WHICH relation is trust-policy terrain, never format terrain.
- Hard caps: 64 edges per receipt, attached-ancestry depth 32.

## 3. Vocabulary and interop mapping

Closed, versioned vocabulary — extension only via a spec change; an unknown relation is a
fail-closed error:

| proofbundle | W3C PROV | SCITT relationship* | meaning |
|---|---|---|---|
| `supersedes` | (succession) | supersedes | new version replaces fully |
| `revises` | wasRevisionOf | supersedes | revised edition |
| `corrects` | wasRevisionOf | supersedes | error correction |
| `retracts` | wasInvalidatedBy | revokes | target withdrawn; its crypto stays intact |
| `renews` | specializationOf (approximation) | (none; RFC 4998 line) | same bytes, new anchors |
| `derivedFrom` | wasDerivedFrom | derivedFrom | derived, not a replacement |
| `amends` | (supplement) | (none) | supplements without replacing |

\* SCITT relationship = the Individual Draft `draft-nobuo-scitt-protected-object-binding-00`
(2026-07-07), NOT a standard. The mapping was checked against the full draft text on
2026-07-16 — the draft has **no `amends`** relation, so `revises`/`corrects` map onto its
`supersedes` ("replaces the target statement for a purpose") and proofbundle's `amends` is an
own relation with no counterpart, stated honestly rather than bent onto `describes`/`dependsOn`.
Where a standard term exists it is referenced, never renamed. (SCITT *Architecture* is
RFC 9943, published June 2026 — verify publication status at the RFC-Editor, not the
Datatracker.)

## 4. Verification: the four honest lineage states

Targets are attached OFFLINE (`decision verify --with-related PATH`, repeatable; never
fetched). Each attached target is verified STANDALONE first, then keyed by its COMPUTED
content root. Per edge:

- **VERIFIED** — target attached AND standalone-verified AND the edge digest names it.
- **DECLARED_UNRESOLVED** — edge well-formed, target not attached. Explicitly NOT an error,
  but never more than "declared" — no PASS upgrade, ever.
- **FAIL** — structural error (incl. the non-hex-digest never-raise case), unknown relation,
  attached-but-unverified target (present-and-wrong beats absent), cycle, or depth > 32.
- **NOT_EVALUATED** — no profile present.

Invariants: `lineage` NEVER feeds `cryptoValid` in either direction (proven by test — a
forged envelope never computes lineage, and a lineage FAIL never flips `crypto_ok`).
A REQUESTED check that FAILs exits 2 at the CLI, never a silent 0.

A structural note on cycles: under content-root addressing a REAL hash cycle is impossible
to construct (a receipt's root contains its own edges, so a back-edge would need the
successor's final root — a circular hash dependency). The cycle guard is therefore
unit-tested defense-in-depth against manipulated attachment maps; the fixture-realizable
bound is depth-exceeded.

## 5. Trust-policy hook (trust-policy v0.2, section `relations`)

```json
"relations": {
  "require_relation_resolution": ["retracts", "supersedes"],
  "reject_superseded": true
}
```

- `require_relation_resolution`: a named relation that APPEARS as an edge must resolve
  (target attached + verified); a DECLARED_UNRESOLVED edge of a named relation fails the
  policy (exit 3) with the LIVE automation blocker `LINEAGE_REQUIREMENT_FAILED`. An absent
  relation is no violation.
- `reject_superseded`: an attached, verified receipt that declares a successor relation
  (`supersedes`/`revises`/`corrects`) OR a retraction (`retracts`) over the receipt under
  verification blocks automation (retracts-then-use). Without the policy the same finding is
  an advisory warning. The retraction never breaks the target's cryptographic validity — it
  is a declared statement about it.
- `policy explain` lists both pins (explain⟺enforce parity); `relation_signer` (pinned-set)
  and the outcome-path policy gate are documented follow-ups — the CLI `--with-related`
  contract is same-key today.

## 6. Conformance corpus

`conformance/relation/` — 15 vectors, all end-to-end through the real CLI
(`conformance/run_conformance.py`, kind `decision_relation`). The five skeleton vectors carry
`crossFormatId` `xfmt-c0`/`xfmt-t1`…`xfmt-t4` per the No Silent Landing shared-vector
convention; the superset (one per relation, declared-unresolved, depth-exceeded,
unauthorized-signer, retracts-then-use, malformed-digest) stays internal. Fixtures are
generated by `conformance/relation/generate_vectors.py` (fresh throwaway test keys,
committed bytes — never hand-edited).

## 7. Honest limits

- A relationship edge is additive: it never revokes the target's cryptography, never proves
  the successor's quality, and never establishes that the issuer had AUTHORITY to supersede —
  authority is policy terrain.
- The CLI verifies attached targets under the SAME `--pub` (same-key contract); cross-issuer
  chains need the `relation_signer` follow-up.
- The `relation-statement/v0.1` standalone profile (retroactive statements OVER a receipt
  without a successor) is specified in the design note and not yet built.
