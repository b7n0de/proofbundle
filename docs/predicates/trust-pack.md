# Trust Pack predicate `trust-pack/v0.1`

Status: EXPERIMENTAL in proofbundle 3.2.0 (vendored `trust-pack/v0.1` under the b7n0de namespace; API and wire
format may change without deprecation). A Trust Pack is the **root of trust** the other predicates resolve
against: which key ids hold which role, and how many of them must agree. It is TUF-inspired — a threshold of
named root keys, offline revocation, monotone versioning, rollback/freeze protection.

Schema: [`schemas/trust-pack-v0.1.schema.json`](../../schemas/trust-pack-v0.1.schema.json) (docs-only; the
executable contract is the hand-rolled fail-closed validator in `src/proofbundle/trust_pack.py`, not the JSON
Schema).

## 1. Purpose

A Trust Pack answers: *for this deployment, which key ids are trusted for which role (root, and role-specific
signer sets like `outcomeExecutors` / `outcomeReceivers`), and what threshold of them must sign for a claim
of that role to be trusted.* It is an in-toto Statement (DSSE, Ed25519) signed by a **threshold of its own
declared root keys**, verified against the exact signed bytes.

Rotation is a new version signed by the OLD root threshold (two-stage: the old root vouches for the new). This
is why a Trust Pack self-authenticates: `verify_trust_pack` counts DISTINCT valid non-revoked root signatures
against the root role's threshold.

## 2. Non-goals

- It does **not** prove any key holder is honest, authorized in law, or that the roles were assigned correctly.
  It proves only that a threshold of the NAMED root keys signed this exact pack (`nonClaims` records that
  verbatim).
- It carries **no** private keys, no secrets.
- A single leaked root key below threshold does **not** forge a pack; a threshold-many compromise does — that
  is the security model, stated openly.

## 3. Fields (predicate)

| field | required | meaning |
|---|---|---|
| `schemaVersion` | yes | `0.1.0` |
| `trustPackId` | yes | stable id of this trust root |
| `version` | yes | monotone integer; a new pack MUST have `version > prev` (rollback/freeze protection) |
| `expires` | yes | RFC-3339 UTC validity bound (`not_expired` fails closed past it) |
| `prevVersionDigest` | yes | content-root digest of the previous version, or `null` for the first |
| `roles` | yes | object including a `root` role; each role = `{keyIds: [...], threshold: int}` |
| `keys` | yes | non-empty `keyId -> {publicKey[, alg, publicKeyPq]}` map resolving every referenced key id |
| `nonClaims` | yes | the explicit "this proves only threshold-signing, not honesty" record |
| `revoked` | optional | offline revocation list of key ids (must be known key ids) |

Validation is fail-closed and **dead-on-arrival aware**: a role whose threshold can no longer be met once
revoked keys are removed is rejected at validate time (a pack whose root can never meet threshold is invalid,
not merely un-verifiable). `threshold` must be in `1..len(keyIds)`; every role key id must be present in `keys`;
`revoked` entries must be known key ids.

**Crypto agility (ADR 0006).** Each `keys[kid]` declares which signature algorithm it holds via `alg`: `ed25519`
(default — absent `alg` means `ed25519`, so every pre-agility pack keeps working unchanged), `mldsa65`
(ML-DSA-65, FIPS 204 — `publicKey` is the 1952-byte raw ML-DSA key), or `hybrid-ed25519-mldsa65` (BOTH legs:
`publicKey` = 32-byte Ed25519 classical leg, `publicKeyPq` = 1952-byte ML-DSA-65 PQ leg). A hybrid key is
authenticated only when BOTH legs verify (an attacker must forge both to forge the key; a signature carrying
only the Ed25519 `sig` leg does not satisfy a policy-declared hybrid key — no downgrade). The signature envelope
entry gains a second field for the PQ leg: `{"keyid":, "sig": <classical or single-alg b64>[, "sigPq": <ML-DSA-65
b64, hybrid only>]}`. The `alg` label lives INSIDE the signed predicate, so it cannot be relabeled without
invalidating every signature over the pack (no separate alg-confusion surface, unlike a bare JWT `alg` header).

## 4. Verify path (`verify_trust_pack`)

Each check fail-closed; read the aggregate `ok`, never an individual field:

1. **structure_ok / predicate_type_ok** — valid predicate, vendored `trust-pack/v0.1`.
2. **root_threshold_met** — `>=` the root role's `threshold` DISTINCT valid non-revoked root signatures over
   the exact PAE bytes. Signatures are counted as a Set of key ids (no double-count); a key id not in the root
   set, or revoked, or with an unresolved / malformed public key, does not count.
3. **not_expired** — `expires > now` (fail-closed past expiry).
4. **version_monotone** — `version > prevVersion` when a previous version is supplied (rollback/freeze catch).
5. **prevVersionDigest chain** — each version links the previous version's content root; the first is `null`.

`root_signers` lists the distinct root key ids whose signatures were counted, for auditability.

### 4a. `ok` is self-authentication; trust needs a relying-party anchor (N43, security-fix 6.2.0)

The checks above are the pack's SELF-authentication: its form validates, a threshold of its OWN declared root
keys signed it, it is unexpired, and (when it claims a predecessor) the chain is intact. A GENESIS pack carries
its own root keys, so it self-authenticates with NO relying-party input — `ok` can be True for a pack the
relying party has never seen and never chose to trust. **`ok` alone is not trust.** A root of trust is trusted
only because a relying party PINNED it out of band.

`verify_trust_pack` therefore returns a field **`pinned`** — `True` (bound to a supplied anchor), `False` (an
anchor was supplied but none matched), `None` (no anchor supplied) — and takes the anchors:

- `expected_genesis_digest` — the pack's content-root digest `sha256(JCS(predicate))` (the value a successor
  carries as its `prevVersionDigest`, and what `build_trust_pack_statement` writes as the subject digest);
- `expected_root_keys` — a `{keyId: publicKey_b64}` / key-object map that must COVER the pack's declared,
  non-revoked root role (every declared root key pinned, the declared threshold reachable within it);
- a rotation anchor — `prev_root_keys` + `prev_root_threshold`: the relying party pins the PREDECESSOR's root,
  and `rotation_authorized` being True binds this pack.

`pinned` does NOT change `ok`. It is the "policy" dimension of the uniform automation verdict:
`automation.safeForAutomation` is positive only under an anchor (unanchored → `POLICY_NOT_EVALUATED`;
mismatch → `POLICY_FAILED`). Pinning is OUT-OF-BAND (`docs/TRUST_ANCHORS.md`, the **Trust Pack root of trust**
row): the relying party obtains the genesis digest or root keys from a channel other than the pack itself.

## 5. How the other predicates use it

A Trust Pack is DESIGNED to resolve *who* is trusted for a role — e.g. `outcomeExecutors` names the key ids
allowed to sign an `action-outcome` as the executor; `outcomeReceivers` (Finding 16, additive) names the key
ids allowed to sign a THIRD-PARTY corroboration of an outcome (an outcome's `receiverRefs[].receiverKeyId`).
The intended split: the Trust Pack answers WHO; the individual predicate answers WHAT and
WHETHER-THRESHOLD-SIGNED (a claim's content root binds its identity; trust in its signer is this pack's job).

**Wiring status (honest, updated).** `outcomeExecutors` role membership IS wired into `verify_outcome_
receipt` (Finding 01, verify-layer hardening): a caller-supplied `trust_pack` param (the PREDICATE of an
ALREADY-authenticated pack) is checked via `outcome.executor_trusted_by_role` and is FAIL-CLOSED — an
untrusted executor breaks the outcome's aggregate `ok`. **N43 (security-fix 6.2.0):** role membership is a
fact about the pack, not trust; `verify_outcome_receipt` reports `executor_role_trusted` / `receiver_role_
trusted` as True only when the pack is ALSO bound to a relying-party anchor — and at the OUTCOME that anchor
must be CONTENT-BOUND to EXACTLY this predicate, because `verify_outcome_receipt` holds only the predicate and
verifies no signature over it (N45, security-fix 6.2.0, a hardening of N43). Supply exactly ONE of three
content-bound anchors (any one suffices): **A** the genesis content digest —
`trust_pack_expected_genesis_digest == sha256(JCS(predicate))`; **B** a verified pack envelope —
`trust_pack_envelope` together with `trust_pack_expected_root_keys`, where the envelope's threshold signature
verifies under the pinned root keys AND its verified content equals this predicate (a bare
`trust_pack_expected_root_keys` ALONE is NOT accepted at the outcome: without the envelope it is only a
declared-identity match, which a naked predicate can copy); or **C** a forwarded rotation verdict —
`trust_pack_pinned=True` together with `trust_pack_pinned_digest == sha256(JCS(predicate))` (a bare
`trust_pack_pinned=True` ALONE is NOT accepted: a rotation needs the old root, not recomputable here, so the
verdict is forwarded, but it MUST be bound to this predicate's content digest). Without a matching anchor a
supplied pack's role verdict is not positive
(`TRUST_PACK_NOT_ANCHORED`), exactly as a genesis pack's own `safeForAutomation` is not. `outcomeReceivers` is ALSO wired (Finding 16, same
`trust_pack` param, `outcome.receiver_trusted_by_role`) but deliberately NOT fail-closed against `ok` — a
`receiverRefs[]` entry is optional supplementary evidence, so an untrusted-labeled receiver only downgrades
the `evidence_levels["receiverRefs"]` strength classification, never the outcome's own core verdict (see
`action-outcome.md` §5 / `outcome.verify_outcome_receipt`'s docstring). `verification-summary` still does not
resolve role identities against a pack, and neither role has a LIVE registry / trust-anchor discovery
(fetching the right pack for a given executor/receiver automatically) — that remains future work. The pack
primitive itself (threshold-of-root, distinct-key-material counting, two-stage rotation authorization) is
built and verified independently of either role's wiring status.

## 6. Open (honest)

- No transparency-log anchoring of the Trust Pack itself yet (a pack is offline-verifiable but not publicly
  witnessed — a future composition with the public-transparency layer).
- Role taxonomy beyond `root` + the outcome/decision signer sets (`outcomeExecutors`, `outcomeReceivers`) is
  intentionally minimal in v0.1.
- A LIVE registry / DID anchor that DISCOVERS and fetches the right Trust Pack for a given executor or
  receiver automatically (rather than the caller supplying an already-authenticated pack) is future work.
