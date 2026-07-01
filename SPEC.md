# proofbundle format specification — `proofbundle/v0.1`

This is the normative description of the `proofbundle/v0.1` evidence-bundle format.
An independent implementation that follows this document MUST interoperate with
`proofbundle verify`. The machine-readable companion is
[`schemas/proofbundle_v0_1.schema.json`](schemas/proofbundle_v0_1.schema.json);
where the two disagree, this document is normative and the schema is a bug.

The key words MUST, MUST NOT, SHOULD, and MAY are to be interpreted as in
[RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

## 1. Overview

A bundle is a single UTF-8 JSON object. It asserts, checkable fully offline, that
a fixed byte string (the *payload*) was:

1. signed by a stated Ed25519 key, and
2. included as a leaf of an RFC 6962 / RFC 9162 Merkle tree with a stated root,

and MAY additionally carry an SD-JWT selective-disclosure credential.

The verifier treats the payload as opaque bytes; it proves that *these exact
bytes* were signed and anchored, not what they mean.

## 2. Encoding conventions

- All top-level and nested string fields carrying binary data use **standard**
  Base64 ([RFC 4648 §4](https://datatracker.ietf.org/doc/html/rfc4648#section-4)),
  with padding. (Exception: the SD-JWT compact string in `sd_jwt_vc.compact`
  uses base64url per the SD-JWT spec.)
- Hashes are SHA-256 (32 bytes).
- Integers are JSON numbers with no fractional part.

## 3. Object fields

| field | required | type | meaning |
|---|---|---|---|
| `schema` | yes | string | MUST be the exact string `"proofbundle/v0.1"`. |
| `payload_b64` | yes | string | Base64 of the payload bytes that were signed and anchored. |
| `signature` | yes | object | Ed25519 signature over the payload (§4). |
| `merkle` | yes | object | RFC 6962 inclusion proof of the payload leaf (§5). |
| `sd_jwt_vc` | no | object | Optional SD-JWT selective-disclosure credential (§6). |

A verifier MUST reject a bundle whose `schema` is not `"proofbundle/v0.1"`
(unsupported), and MUST reject unknown top-level fields (the schema is
`additionalProperties: false`).

### 4. `signature`

| field | required | type | meaning |
|---|---|---|---|
| `alg` | yes | string | MUST be `"ed25519"`. |
| `public_key_b64` | yes | string | Base64 of the 32-byte raw Ed25519 public key. |
| `sig_b64` | yes | string | Base64 of the 64-byte Ed25519 signature over the raw payload bytes. |

Check **ed25519-signature**: decode `payload_b64` to `P`, verify the Ed25519
signature `sig_b64` over `P` under `public_key_b64`. The message is the raw
payload bytes — no pre-hashing, no domain separation.

### 5. `merkle`

| field | required | type | meaning |
|---|---|---|---|
| `hash_alg` | no | string | If present MUST be `"sha256-rfc6962"` (the default). |
| `leaf_index` | yes | integer ≥ 0 | 0-based index of the payload leaf in the tree. |
| `tree_size` | yes | integer ≥ 1 | Number of leaves in the tree. |
| `inclusion_proof_b64` | yes | array of string | The RFC 6962 inclusion proof: sibling hashes, Base64, leaf-to-root order. |
| `root_b64` | yes | string | Base64 of the 32-byte Merkle tree root. |

**Hashing (RFC 6962 / RFC 9162 §2):**

- Leaf hash: `SHA-256(0x00 || leaf_data)`.
- Interior node hash: `SHA-256(0x01 || left_child || right_child)`.
- Empty tree hash: `SHA-256("")`.

Check **merkle-inclusion**: the leaf is the payload bytes `P`. Recompute the
root from `leaf_hash(P)`, `leaf_index`, `tree_size` and `inclusion_proof_b64`
using the RFC 6962 inclusion-proof algorithm, and require it to equal `root_b64`.
`0 <= leaf_index < tree_size` MUST hold. The proof length MUST match the RFC 6962
expected length for `(leaf_index, tree_size)`.

### 6. `sd_jwt_vc` (optional)

| field | required | type | meaning |
|---|---|---|---|
| `compact` | yes | string | SD-JWT in compact serialization: an issuer-signed JWT followed by `~`-separated disclosures. |
| `issuer_public_key_b64` | no | string | If present, Base64 of the 32-byte raw Ed25519 issuer key. |

Check **sd-jwt-disclosures**: the compact string is well formed and every
presented disclosure is committed (its digest appears in the issuer-signed
payload's `_sd` array). If `issuer_public_key_b64` is present, additionally check
**sd-jwt-issuer-signature**: the issuer JWT signature (EdDSA) verifies under it.

Scope of v0.1 SD-JWT (stated honestly): the SD-JWT *core* is
[RFC 9901](https://datatracker.ietf.org/doc/rfc9901/) (2025); the verifier does
**not** verify a Key Binding JWT, an X.509 / trust-list chain, status lists, or
`vct` type metadata (SD-JWT VC is the IETF draft
[draft-ietf-oauth-sd-jwt-vc](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/),
on the roadmap).

## 7. Verification order (normative)

A conforming verifier MUST perform, in this order, and report each result:

1. **schema** — reject if `schema != "proofbundle/v0.1"`.
2. **ed25519-signature** (§4).
3. **merkle-inclusion** (§5).
4. **sd-jwt-disclosures** and **sd-jwt-issuer-signature** — only if `sd_jwt_vc`
   is present (§6).

The bundle **verifies** iff every performed check passes. Trust anchors (the
expected signer key, the expected Merkle root) are inputs the relying party
supplies out of band; the verifier does not fetch anything.

## 8. References

- RFC 6962 — Certificate Transparency (Merkle tree hashing, inclusion proofs).
- RFC 9162 — Certificate Transparency v2.
- RFC 8032 — EdDSA / Ed25519.
- RFC 4648 — Base16/Base32/Base64 encodings.
- RFC 9901 — Selective Disclosure for JWTs (SD-JWT).
