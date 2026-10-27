# Lineage / relationship profile `relation/v0.1`

Status: EXPERIMENTAL in proofbundle 3.3.0 (API and wire format may change without deprecation).
Reference implementation: the hand-rolled fail-closed validator and chain verifier in
`src/proofbundle/relation.py`; this page, not the code, is normative (SPEC.md §7l); the JSON-Schema mirrors in
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
  attached-but-unverified target (present-and-wrong beats absent), an attached target whose signed
  PAYLOAD is not a well-formed statement (`RELATION_TARGET_MALFORMED`), cycle, or depth > 32.
- **NOT_EVALUATED** — no profile present.

**Which edges set `lineage`.** `lineage` is computed from the edges the receipt under verification
declares in its own `relationships`. A receipt that declares none is NOT_EVALUATED, also when an
attachment declares an edge over it; such edges feed only the `relations` policy of §5
(`reject_superseded`, `RELATION_MALFORMED_SUCCESSOR`). The states of its own edges combine as: FAIL if
any edge is FAIL, else DECLARED_UNRESOLVED if any edge is DECLARED_UNRESOLVED, else VERIFIED. An edge
whose digest names no attached receipt is DECLARED_UNRESOLVED, whatever else is attached;
"attached-but-unverified" means an attachment whose computed content root the edge names and that does
not verify standalone. An attachment that no edge names changes nothing, whether it verifies or not.

**The attached ancestry.** A VERIFIED edge is followed into the edges its target declares, and on, as
far as targets are attached. The direct targets of the receipt under verification are at depth 1;
resolving a target at depth 33 makes the receipt's edge FAIL (`relation:depth_exceeded`). An attached
ancestor that an edge of the ancestry names and that does not verify standalone makes the receipt's edge
FAIL as well (`relation:ancestor_verification_failed`). An edge of an ancestor whose target is not
attached ends the walk there and does not lower VERIFIED. A target the walk reaches, a direct target
included, whose own `relationships` member is present, not `null`, and not a non-empty array of edges
that each meet the edge table (an empty array, a value that is no array, an edge that breaks the table)
makes the receipt's edge FAIL (`relation:malformed_ancestor`, exit 2); an absent member and `null`
declare nothing, and the walk ends there.

"Verified STANDALONE" covers the payload as well as the signature, and it binds at every hop
(deep gate 2026-09-05, finding L4-01): the resolver parses an attached target's payload with the SAME
strict, canonical oracle the standalone verify path uses. A payload the oracle refuses — a duplicate JSON
key, NaN, a BOM, a non-canonical spelling, a non-object — makes the target `attached_target_malformed`,
never "verified with no edges". Before that, a failing ancestry hidden behind a duplicated `predicate` key
verified as VERIFIED in both shipped verifiers while the same bytes failed standalone: the chain's verdict
depended on which parser read a hop, and the hop's author chooses the bytes.

**The statement oracle.** A signed payload is a well-formed statement iff it is a JSON object
under the strict reader, its bytes are its own RFC 8785 canonical form, its `_type` is exactly
`https://in-toto.io/Statement/v1`, and its `subject` is a non-empty array whose every entry is
an object carrying a non-empty `digest` object with non-empty string values (a `sha256` value is
64 lowercase hex). On an attachment, a `relationships` member whose value is `null` declares nothing
and is treated exactly as an absent member. On the receipt under verification it is malformed (exit 2,
lineage NOT_EVALUATED, `relationships must be a JSON array of edge objects`), and so is an empty array
(exit 2, lineage FAIL, `relation:malformed:`): there the predicate carries a non-empty array or no
`relationships` member. Any other value there that is not a non-empty array of edges that each meet the
edge table, a value that is no array included, is malformed in the same way as the empty array (exit 2,
lineage FAIL, `relation:malformed:`). The receipt under verification is held to the same oracle, after
its signature: a signature that fails is exit 1 whatever the payload; under one that verifies, a payload
that is no JSON object under the strict reader, or whose `_type` or `subject` breaks the rule above, is
malformed (exit 2, lineage NOT_EVALUATED), and one that is only not its own RFC 8785 form is malformed
too (exit 2), its edges judged as usual.

**Stable codes.** The JSON report carries, for each FAIL reason and each policy block, the string
below. A finding of the predicate validation of the receipt under verification is reported in `errors`,
in the words the section of its predicate gives where it gives any (for a relation statement, an unknown
member, section *Standalone profile*). A conformance vector's `errorContains` is one of these strings or
its start.

| situation | string in the report | exit |
|---|---|---|
| structural error of an edge (shape, unknown field, unknown relation, digest not 64 lowercase hex, missing `digestAlgorithm`) | `relation:malformed:` followed by the detail | 2 |
| attached target named by an edge that does not verify standalone (signature, key, `payloadType`) | `relation:target_verification_failed` | 2 |
| attached ancestor, named by an edge of the ancestry, that does not verify standalone | `relation:ancestor_verification_failed` | 2 |
| attached target whose payload is not a well-formed statement | `RELATION_TARGET_MALFORMED` | 2 |
| attached ancestry deeper than 32 | `relation:depth_exceeded` | 2 |
| a cycle | `relation:cycle` | 2 |
| `targetSubjectDigest` against several subjects, a malformed or a wrong one (§5) | `RELATION_TARGET_SUBJECT_AMBIGUOUS`, `RELATION_TARGET_SUBJECT_MALFORMED`, `RELATION_TARGET_SUBJECT_MISMATCH` | 2 |
| `require_relation_resolution` unmet, and a `reject_superseded` or `reject_retracted` block | `LINEAGE_REQUIREMENT_FAILED` | 3 |
| `relation_signer` unmet | `RELATION_SIGNER_UNAUTHORIZED` | 3 |
| `require_relation_target` unmet | `RELATION_TARGET_MISMATCH` | 3 |
| an attached receipt whose own `relationships` block is unreadable, under `reject_superseded` | `RELATION_MALFORMED_SUCCESSOR` | 3 |

Invariants: `lineage` NEVER feeds `cryptoValid` in either direction (proven by test — a
forged envelope never computes lineage, and a lineage FAIL never flips `crypto_ok`).
A REQUESTED check that FAILs exits 2 at the CLI, never a silent 0.
When classes meet, the lower exit decides: a signature of the receipt under verification that does not
verify (exit 1) before a lineage FAIL (exit 2), and a lineage FAIL before an unmet policy (exit 3).

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

  **Since 6.0.0 an UNREADABLE declaration counts too (`RELATION_MALFORMED_SUCCESSOR`).** An
  attached, standalone-verified receipt whose OWN `relationships` block this verifier cannot
  parse used to be skipped in silence — together with any retraction declared inside it. An
  attacker only had to place one deliberately malformed edge next to the `retracts` edge, and
  `safeForAutomation` flipped false→true, exit 3→0. A receipt that carries NO `relationships`
  field still stays silent (it declared nothing); one that carries an unreadable block now
  reports (it declared something this verifier cannot evaluate). Unreadable means present, not
  `null`, and not a non-empty array of edges that each meet the edge table: an empty array is
  unreadable here, `null` declares nothing as an absent field does. Without the policy such an
  attachment, when no edge names it, changes neither the lineage nor the exit code.

  **Widened reach, stated plainly:** the block is unreadable, so we cannot know whether one of
  its edges points at the receipt under verification. A malformed block whose READABLE edges all
  point elsewhere therefore blocks as well — the readable half says nothing about the unreadable
  half, and a verifier that stayed silent here would claim knowledge it does not have. Attachments
  that carry a harmless format error in `relationships` and passed before will block after this
  release; that is deliberate, and it is the honest reading of "unreadable".
- `relation_signer` (since 3.4.0, WHO may replace): per relation, `{"mode":"same-key"}` (the
  successor's issuer key must equal the target's) or `{"mode":"pinned","keys":[…]}` (the
  successor's issuer key must be a byte-member of the pinned raw Ed25519 set — never a keyId
  alias). Unmet → `RELATION_SIGNER_UNAUTHORIZED`, exit 3. This is what makes cross-issuer
  chains verifiable: attach a predecessor of a foreign ring with `--with-related PATH
  --related-pub B64` (position-paired), and the check runs against the key the target
  ACTUALLY verified under, never a claim. On an edge whose target is not attached there is no target key:
  `same-key` is then met, and `pinned` judges the successor's key as on a resolved edge.
- `require_relation_target` (since 3.4.0, WHICH parent): per relation, an expected parent
  content root or a list of them. A supersedes-like edge that resolves to any OTHER parent
  — even a valid, attached, verified one — → `RELATION_TARGET_MISMATCH`, exit 3. This fires
  on EVERY such edge, the accept path (T2) included: it closes the decoy-parent gap where
  `require_relation_resolution` alone only proved that SOME edge resolves, not that it
  resolves to the parent the relying party named. On an edge whose target is not attached, the
  edge's declared target digest is compared with the expected roots in the same way.
- `targetSubjectDigest` (edge field): when PRESENT it is now binding — gegengeprueft against
  the resolved target's real subject digest; a mismatch is a lineage FAIL
  (`RELATION_TARGET_SUBJECT_MISMATCH`, exit 2). Absent = optional, no wire-break. It binds at every hop
  of the attached ancestry: an edge of an attached ancestor whose target is attached is checked against
  that target in the same way, before the walk descends into it, and a failure there makes the receipt's
  own edge FAIL (exit 2) with the error `relation:ancestor_edge:` followed by the pin's code; on the
  receipt's own edge the walk into the target's ancestry comes first and the pin after it. An ancestor
  edge whose target is not attached is not checked.
  **What is compared.** The field has the object form of `targetReceiptDigest`, and its
  `digestAlgorithm` MUST be a registered content-root algorithm (today only `jcs-sha256-v1`),
  but its `digest` is NOT a content root: it is compared, as 64 lowercase hex, with the `sha256`
  entry of the `digest` of the resolved target's only `subject` entry (the in-toto subject
  digest, `subject[0].digest.sha256`). A target with more than one subject entry fails with
  `RELATION_TARGET_SUBJECT_AMBIGUOUS` (the verifier never binds `subject[0]` of several), a single
  entry without a well-formed `sha256` digest with `RELATION_TARGET_SUBJECT_MALFORMED`; each is a
  lineage FAIL, exit 2. A target with no subject entry is not a well-formed statement and fails
  earlier with `RELATION_TARGET_MALFORMED` (§4).
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
  as above). All three members are required: `schemaVersion` a string of the form `0.1.x`,
  `statementId` a non-empty string and `relationships` an array of exactly one edge; a missing member,
  or one of another form, is malformed (exit 2). The predicate is closed: any other member is malformed (exit 2), and the report names
  it as `unknown field '<name>' (additionalProperties:false)`; its `lineage` is still computed from its
  edge, so such a statement whose target is not attached reports DECLARED_UNRESOLVED. The edge validation, lineage resolution and the `relations` trust-policy gate REUSE
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
  On this path `reject_retracted` blocks on the statement's own VERIFIED `retracts` edge and
  `reject_superseded` on its own VERIFIED `supersedes`, `revises` or `corrects` edge; both report
  `LINEAGE_REQUIREMENT_FAILED`, exit 3.
  On this path `relation_signer` judges the key the statement verified under: `pinned` compares that
  key with the pinned set, `same-key` with the key its target verified under. `reject_retracted` and
  `reject_superseded` do not depend on `relation_signer`; when both rules fire, both codes are reported.
- Rust parity: the independent Rust verifier carries this profile since 3.5.0
  (`verify-relation-statement`); `crosscheck.py` drives the statement vectors differentially and
  asserts Python and Rust land on the same exit class + lineage. Differential agreement on these
  vectors, not a correctness proof of either implementation.
