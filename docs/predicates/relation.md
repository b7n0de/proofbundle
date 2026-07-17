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
  "reject_superseded": true,
  "relation_signer": {"supersedes": {"mode": "pinned", "keys": ["<b64>", "…"]}},
  "require_relation_target": {"supersedes": ["<64-hex parent root>", "…"]}
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
- `relation_signer` (since 3.4.0, WHO may replace): per relation, `{"mode":"same-key"}` (the
  successor's issuer key must equal the target's) or `{"mode":"pinned","keys":[…]}` (the
  successor's issuer key must be a byte-member of the pinned raw Ed25519 set — never a keyId
  alias). Unmet → `RELATION_SIGNER_UNAUTHORIZED`, exit 3. This is what makes cross-issuer
  chains verifiable: attach a predecessor of a foreign ring with `--with-related PATH
  --related-pub B64` (position-paired), and the check runs against the key the target
  ACTUALLY verified under, never a claim.
- `require_relation_target` (since 3.4.0, WHICH parent): per relation, an expected parent
  content root or a list of them. A supersedes-like edge that resolves to any OTHER parent
  — even a valid, attached, verified one — → `RELATION_TARGET_MISMATCH`, exit 3. This fires
  on EVERY such edge, the accept path (T2) included: it closes the decoy-parent gap where
  `require_relation_resolution` alone only proved that SOME edge resolves, not that it
  resolves to the parent the relying party named.
- `targetSubjectDigest` (edge field): when PRESENT it is now binding — gegengeprueft against
  the resolved target's real subject digest; a mismatch is a lineage FAIL
  (`RELATION_TARGET_SUBJECT_MISMATCH`, exit 2). Absent = optional, no wire-break.
- Authorization and parent-pinning are RELYING-PARTY POLICY, never format truth: a passing
  check proves set membership / the named parent under the verifier's pins, not that anyone
  is "really" authorized or in the right.
- `policy explain` lists all pins (explain⟺enforce parity). The `relations` gate is enforced
  identically on the decision AND outcome verify paths (`outcome verify --policy`).

## 6. Conformance corpus

`conformance/relation/` — end-to-end through the real CLI (`conformance/run_conformance.py`,
kinds `decision_relation` and, since 3.4.0, `outcome_relation`). The five skeleton vectors
carry `crossFormatId` `xfmt-c0`/`xfmt-t1`…`xfmt-t4` per the No Silent Landing shared-vector
convention; the decoy-parent vector adds `xfmt-t3-decoy`. The 3.4.0 additions cover
relation_signer (cross-issuer verified/unauthorized, same-key, verified-under-not-claim),
the decoy-parent fix (target-mismatch + must-pass gegenprobe + accept-path + the documented
no-pin old behavior), the `targetSubjectDigest` gegenpruefung (O2), a JCS-canonical
invalid-signature vector (F2), and the outcome-path mirror. Fixtures are generated by
`conformance/relation/generate_vectors.py` (fresh throwaway test keys, committed bytes —
never hand-edited). The runner derives every case label from the REAL verifier `--json`
output via `conformance/common_vocabulary.py`, so a hand-copied "expected == observed"
cannot mask a regression (the decoy vector falls with the independently-derived label).

## 7. Honest limits

- A relationship edge is additive: it never revokes the target's cryptography, never proves
  the successor's quality, and never establishes that the issuer had AUTHORITY to supersede —
  authority is policy terrain (`relation_signer`), and a passing check proves set membership
  under the verifier's pins, not authority.
- Cross-issuer chains are supported since 3.4.0 (`--related-pub`), gated by the relying
  party's `relation_signer` pin. `require_relation_target` pins WHICH parent an edge may
  resolve to. Both are relying-party policy, never format truth.
- Deliberately OPEN (do not read them into 3.4.0/3.5.0): threshold signer sets (TUF N-of-M)
  and identity indirection (DID/VC controllers, CA chains — the offline contract forbids a
  resolver dependency).

## Standalone profile — `relation-statement/v0.1` (EXPERIMENTAL, since 3.5.0)

The in-receipt edges above express change from the SUCCESSOR's side (a new receipt that carries
the edge). The standalone profile is the independent case: a DSSE-signed statement OVER a target
receipt, carrying EXACTLY ONE typed edge and NO decision/outcome payload of its own. It exists for
the retroactive case the in-receipt edges cannot express — declaring a foreign or older receipt
retracted / superseded / amended WITHOUT emitting a successor result and WITHOUT touching the
original. Status-as-a-separate-object precedent: W3C Bitstring Status List v1.0, CT/OCSP revocation, and the
SCITT protected-object-binding draft (`revokes`/`supersedes`); our `retracts` maps to SCITT
`revokes`, `supersedes` to `supersedes`.

- predicateType `https://b7n0de.com/proofbundle/predicates/relation-statement/v0.1`; predicate
  `{schemaVersion, statementId, relationships:[edge]}` with exactly one edge (the same edge schema
  as above). The edge validation, lineage resolution and the `relations` trust-policy gate REUSE
  the same functions as the in-receipt path — there is no second implementation of the logic.
- Honesty boundary (verbatim, claims-hygiene enforced): a relation statement proves the issuer
  DECLARED the relation over exact bytes; it does not retract the target's cryptographic validity,
  and whether the issuer may declare it is a relying-party policy decision. A `retracts` statement
  sets a visible declared state BESIDE the target — the target receipt stays valid for its bytes
  forever, and a verifier that does not know the statement still sees a valid target. A retraction is
  relying-party knowledge, not a global kill; `lineage` never feeds `cryptoValid`.
- CLI: `proofbundle relation-statement init|emit|verify|inspect`, exit contract 0/1/2/3 identical to
  the decision/outcome verify paths (`verify --with-related PATH --related-pub B64 --policy POLICY`).
- The trust policy gains `relations.reject_retracted` (and `reject_superseded` for the successor
  relations): a relying party who knows BOTH the target and a verified retracts statement of a pinned
  signer can treat continued automated use of the target as an exit-3 block. Without the policy the
  verified statement is pure visibility. `relation_signer` decides WHO may declare it, unchanged.
- Rust parity: the independent Rust verifier carries this profile since 3.5.0
  (`verify-relation-statement`); `crosscheck.py` drives the statement vectors differentially and
  asserts Python and Rust land on the same exit class + lineage. Differential agreement on these
  vectors, not a correctness proof of either implementation.
