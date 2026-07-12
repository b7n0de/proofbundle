# ADR 0004 — Native Merkle root authenticity

Status: Accepted (3.1.0, non-breaking layer) · the signed-core option is DEFERRED to the next breaking format version
Date: 2026-07-12
Context: Hardening 3.0.1 audit finding P0-A

## Context

A proofbundle bundle signs the **payload bytes** with Ed25519 (SPEC §5). The Merkle
`root_b64` / `tree_size` / `leaf_index` / `inclusion_proof_b64` live in the `merkle`
object, which is **outside** the signature input. `verify_bundle` checks that the payload
is Merkle-*consistent* under the stated root — it does not authenticate the root.

Consequence (reproduced against 3.0.1, `tests/test_root_authenticity.py`): the SAME signed
payload verifies under TWO different roots. A **coherent one-leaf rewrap** takes an
original single-leaf receipt (`tree_size 1`, `proof []`, `root = leaf_hash(payload)`) and
re-anchors the same payload at index 0 of a 2-leaf tree with an attacker-chosen foreign
sibling (`root = node(leaf(payload), sibling)`, `proof = [sibling]`). Both verify `exit 0`,
`CRYPTO: OK`. Nothing in v0.1 pins which root is authentic.

This is not a signature break — it is a **scope** problem: Merkle inclusion answers "is the
payload consistent under THIS root?", never "is THIS root the authentic one?". The two must
be reported as distinct verdicts.

## Decision (3.1.0, non-breaking)

1. **Report separate verdicts** (`root_authenticity_summary`, `verify` CLI): `payloadSignature`,
   `merkleConsistency`, `rootAuthenticity` (PASS/FAIL/NOT_EVALUATED), `publicTransparency`
   (NOT_EVALUATED in the offline core), `safeForAutomation` (true only when the root was
   affirmatively authenticated). `merkle-inclusion`'s human detail now says "Merkle-consistent
   under the STATED root" so it is never read as authentication.
2. **Relying-party root authentication** (additive, backward-compatible): `verify_bundle(...,
   expected_root_b64=, expected_tree_size=)` and CLI `--expected-root` / `--expected-tree-size`.
   A supplied expected root/size is enforced bit-exactly; a mismatch FAILS (exit 1).
3. **Trust-policy `merkle` section** gains `require_authenticated_root` + `trusted_roots`
   (base64 roots the RP trusts, obtained out of band). A policy requiring an authenticated root
   whose stated root matches neither `--expected-root` nor a `trusted_roots` entry is a POLICY
   FAIL (exit 3), evaluated by BYTES (a malformed trusted entry never matches, fail-closed).

`expected_checkpoint` / `expected_log_origin` and the policy `require_checkpoint` /
`require_public_log_receipt` toggles are the SEPARATE public-transparency profile (§10, a later minor release):
they need a signed-checkpoint / public-log receipt verifier and are intentionally NOT shipped in
this non-breaking patch to avoid a half-implemented checkpoint path.

## Options considered for the next breaking version

- **A — Root-pinning as a relying-party input only** (what 3.1.0 ships). Zero format change,
  fully backward-compatible, but the relying party must obtain an authentic root out of band.
- **B — Signed receipt core**: put a Domain Separator, Receipt Profile, Payload Digest, Root,
  Tree Size, Leaf Index, Hash Algorithm (optional Log Origin) INTO the signature input. Then the
  root is authenticated by the issuer's signature; the coherent rewrap is closed at the crypto
  layer with no relying-party input. **Recommended** for the next breaking format version.
- **C — DSSE / PAE** as a universal envelope for the signed core (interop with in-toto/Sigstore
  tooling). Complementary to B; heavier migration.
- **D — Checkpoint-first profile**: authenticate the root via a signed C2SP checkpoint / public
  log rather than pinning. This is the §10 public-transparency profile, not a core change.

## Consequences and constraints

- 3.1.0 is non-breaking: absent an expected root / policy, root authenticity is NOT_EVALUATED
  and every existing verdict is unchanged.
- The signed-core (option B) is a BREAKING format change. It ships only in the next breaking
  version, AFTER: a legacy-verifier path, a migration guide, positive and negative cross-impl
  vectors (including the coherent one-leaf rewrap), an independent second-implementation review,
  and an Owner-GO / audit decision — none of which are in scope for 3.1.0.
