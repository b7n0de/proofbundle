# relation/v0.1 — Lineage/Relationship profile (EXPERIMENTAL) — design note

Status: DESIGN (pre-implementation), branch `feat/relation-v0.1-lineage-profile`.
Owner GO: GO_OWNER_PB_LINEAGE_RELATIONSHIP_V2_20260715. Target release: 3.3.0 (feature minor).
Sources: v2 prompt (2026-07-15, 23:38 revision) + crossformat sync note PB-LINEAGE-XFMT-SYNC +
recon note pb_lineage_v01_recon_20260716 (nobuo-00 full-text vocabulary check) + repo recon maps.

## 0. The one pattern

Change is never expressed by mutation. A new receipt carries a TYPED, SIGNED relationship
edge pointing at an earlier receipt's content root. The old receipt stays valid for its
bytes forever; the verifier reports the relationship as its own state (`lineage`), instead
of leaving replacement invisible (silent landing) or treating it as tampering.

## 1. Placement (READ-PASS decision)

Relationship edges MUST be covered by the receipt's own signature (unlike `anchors[]`,
which is detached evidence ABOUT a receipt). Therefore:

- **decision-receipt / action-outcome predicates**: optional top-level predicate field
  `relationships: [edge, …]` — inside the DSSE-signed statement bytes, so the existing
  signature covers it. Schema: additive, `additionalProperties:false` per edge.
- **eval-claim (`proofbundle/eval-claim/v0.1` payload)**: optional claim field
  `relationships: [edge, …]` — inside `payload_b64`, covered by the bundle Ed25519 signature.
- The outer Merkle bundle (`proofbundle/v0.1`) itself is NOT touched — no new top-level
  bundle field, no wire break for old verifiers (the anchors one-way-compat lesson).
- **relation-statement/v0.1 (§5 of the prompt, optional second profile)**: a standalone
  signed statement OVER a target receipt (retroactive retraction/supersession without
  touching the original). Deferred to a follow-up increment if time-boxed out — the
  in-receipt edges are the core deliverable.

## 2. Edge shape (normative draft)

```json
{
  "relation": "supersedes",
  "targetReceiptDigest": {"digestAlgorithm": "jcs-sha256-v1", "digest": "<64 hex>"},
  "targetSubjectDigest": {"digestAlgorithm": "jcs-sha256-v1", "digest": "<64 hex>"},
  "reasonCode": "correction",
  "reason": "free text (optional)",
  "declaredAt": "2026-07-16T00:00:00Z"
}
```

- `relation` (required): closed, versioned vocabulary, §3.
- `targetReceiptDigest` (required): content root of the exact target statement bytes,
  SAME mechanic as `evidenceRefs[].digest` / `decisionRef` (jcs-sha256-v1 =
  SHA-256 over RFC 8785 canonical statement bytes; `canonical.CONTENT_ROOT_ALG`).
  Unlike the legacy `sha256Digest` `{"sha256": hex}` shape, relation edges carry an
  EXPLICIT `digestAlgorithm` (hash agility, `hashalg.resolve_hash_alg` fail-closed —
  never an implicit default; the renewal line's registry is reused, `jcs-sha256-v1`
  is registered there as a content-root algorithm id).
- `targetSubjectDigest` (optional): names the target's subject so the edge stays
  meaningful without the target receipt attached.
- `reasonCode` (optional): `correction | rerun | data-update | methodology-update |
  policy-change | withdrawal | other`. `reason` free text, display-only.
- `declaredAt` (optional): RFC 3339 Z — testimony of the ISSUER, informative
  (same honesty rule as `anchoredAt`).
- Signer = the receipt's existing signature. WHO may declare WHICH relation is
  trust-policy terrain (§5), never format terrain.

## 3. Vocabulary + interop mapping (corrected against nobuo-00 FULL TEXT, 2026-07-16)

Closed vocabulary v1: `supersedes · revises · corrects · retracts · renews · derivedFrom · amends`.

| proofbundle | W3C PROV | SCITT relationship (draft-nobuo-…-00, 2026-07-07) | note |
|---|---|---|---|
| supersedes | (succession) | supersedes | |
| revises | wasRevisionOf | supersedes | draft def: "replaces the target statement for a purpose"; **no `amends` exists in nobuo-00** |
| corrects | wasRevisionOf | supersedes | correction specialisation |
| retracts | wasInvalidatedBy | revokes | declared statement ABOUT the target; never breaks the target's crypto validity |
| renews | specializationOf (approximation, finalize in review) | (none; RFC 4998 line) | same bytes, new anchors — disjoint from supersedes |
| derivedFrom | wasDerivedFrom | derivedFrom | derivation without replacement claim |
| amends | (supplement) | **(none in nobuo-00)** | own relation, justified in docs/predicates/relation.md; do NOT bend onto describes/dependsOn |

Rule: where a standard term exists it is referenced, never renamed. nobuo-00 is an
Individual Draft (cite with datatracker date 2026-07-07, no standards status).
SCITT Architecture is **RFC 9943** (published June 2026 — verify at rfc-editor, not
datatracker).

## 4. Verification semantics (fail-closed, honest)

New module `src/proofbundle/relation.py`, mirroring the decision/outcome conventions:

- `validate_relationships(pred) -> list[str]` — never-raise structural validation
  (list return, exactly like `validate_decision_predicate`).
- `verify_relationship_edges(edges, related: dict[digest->bytes], *, policy=None,
  max_depth=32) -> RelationLineageResult` — per-edge status + aggregate `lineage`:
  - `VERIFIED` — target attached, target verifies STANDALONE (its own crypto),
    content root matches, policy satisfied.
  - `DECLARED_UNRESOLVED` — edge present, target not attached. Explicitly NOT an
    error; never more than "declared".
  - `FAIL` — digest mismatch, target fails verification, cycle (A→B→A), depth > 32,
    unknown relation value, or policy violation. Stable error codes actually emitted by
    `relation.py`: `relation:cycle`, `relation:depth_exceeded`, `relation:malformed:<msg>`
    (covers a bad/unknown relation value and any structural error), and
    `relation:target_verification_failed` (attached-but-unverified, the unauthorized-signer
    case). A digest mismatch is NOT a lineage error code — the edge simply stays
    DECLARED_UNRESOLVED because attached targets are keyed by their computed content root, and
    a require_relation_resolution policy turns that into LINEAGE_REQUIREMENT_FAILED (exit 3).
  - `NOT_EVALUATED` — no profile present or check not requested.

Invariants (hard, tested + exhaustively checkable lattice property (27 edge-state combinations, 0 violations)):
- `NOT_EVALUATED` and `DECLARED_UNRESOLVED` NEVER act as PASS and NEVER raise any
  other assurance dimension (EvidenceLevel ladder stays untouched; the edges map at
  most to `REFERENCE_WELL_FORMED`/`CONTENT_RESOLVED` — mirrors `classify_digest_evidence`,
  which already caps promotion).
- `lineage` NEVER influences `cryptoValid`. `safeForAutomation` untouched UNLESS the
  policy requires lineage — then blocker `LINEAGE_REQUIREMENT_FAILED` (added to BOTH
  blocker enums, wired live, not dormant).
- Old receipts get NO new state (immutability).
- relation-specific: supersedes/revises/corrects mark the VERIFIED receipt as successor
  (optional warn if an even newer successor is attached — `rejectSuperseded` policy);
  retracts shows a retraction marker and blocks automation only if policy demands;
  renews = same bytes/new anchors, explicitly disjoint from supersedes (table in docs).

## 5. Trust-policy hook (v0.2, additive section `relations`)

```json
"relations": {
  "require_relation_resolution": ["retracts", "supersedes"],
  "reject_superseded": true
}
```
(snake_case, matching the shipped `trust_policy_v0_1.schema.json`; `relation_signer` is a
documented FOLLOW-UP and is NOT yet an accepted key — a camelCase or `relation_signer` key
would be rejected fail-closed by `load_policy`.)
- IMPLEMENTED (2026-07-16): parsed fail-closed in `load_policy` (v0.2-gated), enforced on the
  DECISION verify path (`verify_decision_receipt` — unresolved named relation or attached
  verified successor fails `policy_ok`, exit-3 class, LIVE blocker `LINEAGE_REQUIREMENT_FAILED`),
  listed by `policy explain` (explain⟺enforce parity). `relationSigner` is a documented FOLLOW-UP
  (the CLI --with-related contract is same-key today; pinned-set needs per-target key plumbing);
  the outcome-path policy gate is a FOLLOW-UP too (`verify_outcome_receipt` has no policy
  parameter — outcome authorization runs via trust_pack).

## 6. CLI

- `verify --with-related PATH` (repeatable) — offline attachment of target receipts;
  no network in the standard path; Never-Raise contract; `--json` carries
  `lineage` + per-edge `{relation, targetDigest, resolution}`.
- Wording (No-Overclaim, verbatim): EN "relationship declared by issuer, not a
  statement of correctness." (output is English-only, matching the existing CLI).
- Exit codes: existing contract; a lineage FAIL on a REQUESTED check → non-zero
  (crypto untouched → exit 3 policy-gate class when policy-driven, exit 1/2 per
  the decision/outcome verify subcommands' own inline exit blocks for structural fails).

## 7. Conformance vectors (corpus extension, crossFormatId per sync note §1)

| vector | crossFormatId | expected |
|---|---|---|
| existing valid baseline | xfmt-c0 | PASS, lineage NOT_EVALUATED |
| silent-landing (named core vector: old identity, new bytes, NO declared relation) | xfmt-t1 | FAIL |
| declared-supersedes-verified (A→B attached, same signer, digest ok) | xfmt-t2 | lineage VERIFIED, no truth upgrade |
| digest-mismatch | xfmt-t3 | DECLARED_UNRESOLVED, policy require_relation_resolution -> exit 3 (LINEAGE_REQUIREMENT_FAILED); a lying edge never finds a target since attached targets are keyed by their COMPUTED content root |
| renews-vector (same bytes, new anchors, original age visible) | xfmt-t4 | VERIFIED, disjoint from supersedes |
| one vector per relation (revises/corrects/retracts/renews/derivedFrom/amends) | — | semantics each |
| declared-unresolved | — | DECLARED_UNRESOLVED, no error, no PASS upgrade |
| depth-exceeded (33-chain) · unauthorized-signer (foreign key) | — | FAIL each, stable code. NOTE: a real hash CYCLE is impossible under content-root addressing (see §4) — the cycle guard is unit-tested defense-in-depth, not a fixture |
| malformed-digest (non-hex sentinel, F6 annex — OWN never-raise vector, SEPARATE from digest-mismatch; internal corpus only) | — | FAIL, no exception |
| retracts-then-use (policy active) | — | automation blocker |

Layout: `conformance/relation/<vector>/case.json` + fixtures, registered in the
GLOBAL `conformance/manifest.json` (the repo's actual layout — one global manifest,
case.json per vector); `crossFormatId` as an additive `case.json` field on exactly
the five skeleton vectors. Test keys marked as test keys.

## 8. Tests

Unit + negative + CLI + schema; property-based chain walker (hypothesis — cycles,
depth, mixed relations); single-field mutations of every new field (no false accept);
never-raise fuzz over the new parser paths; Rust-core differential = NOT_RUN
(honest: the Rust core does not carry the profile yet). Test count must not drop
(current baseline: 1598 collected); new tests counted in CHANGELOG.
Claims-hygiene: add forbidden phrase "relationship proves the new version is correct"
(+ the mandatory wording) to `scripts/claims_hygiene_check.py` scope.
Mutation gate: add ≥2 relation operators to `scripts/mutation_check.py` (e.g. cycle
check disabled → must be KILLED; digest compare inverted → must be KILLED).

## 9. Docs / release

SPEC.md profile chapter (vocabulary, mapping table §3, states, limits, renewal
disambiguation, EXPERIMENTAL, verification order); schema + one example per relation;
GLOSSARY (receipt language: the new receipt points typed at the old one — like a
storno receipt, a credit note, or a corrected invoice depending on the relation);
CHANGELOG target **3.3.0**, EXPERIMENTAL, no format-freeze break.

External effects (Loek reply, shared vector publication, GitHub issue, in-toto #565,
grantmaking update, homepage graphics) each remain SEPARATE Owner GOs.
