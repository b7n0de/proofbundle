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
signer sets like `outcomeExecutors`), and what threshold of them must sign for a claim of that role to be
trusted.* It is an in-toto Statement (DSSE, Ed25519) signed by a **threshold of its own declared root keys**,
verified against the exact signed bytes.

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
| `keys` | yes | non-empty `keyId -> {publicKey}` map (32-byte Ed25519) resolving every referenced key id |
| `nonClaims` | yes | the explicit "this proves only threshold-signing, not honesty" record |
| `revoked` | optional | offline revocation list of key ids (must be known key ids) |

Validation is fail-closed and **dead-on-arrival aware**: a role whose threshold can no longer be met once
revoked keys are removed is rejected at validate time (a pack whose root can never meet threshold is invalid,
not merely un-verifiable). `threshold` must be in `1..len(keyIds)`; every role key id must be present in `keys`;
`revoked` entries must be known key ids.

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

## 5. How the other predicates use it

`verification-summary` and the decision/outcome verify paths take a Trust Pack to resolve *who* is trusted for
a role — e.g. `outcomeExecutors` names the key ids allowed to sign an `action-outcome` as the executor. The
Trust Pack answers WHO; the individual predicate answers WHAT and WHETHER-THRESHOLD-SIGNED. The two are
deliberately separate (a claim's content root binds its identity; trust in its signer is this pack's job).

## 6. Open (honest)

- No transparency-log anchoring of the Trust Pack itself yet (a pack is offline-verifiable but not publicly
  witnessed — a future composition with the public-transparency layer).
- Role taxonomy beyond `root` + the outcome/decision signer sets is intentionally minimal in v0.1.
