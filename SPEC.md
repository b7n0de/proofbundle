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

Check **sd-jwt-key-binding** (since v1.2, RFC 9901 §4.3): performed **iff** the
compact serialization carries a trailing Key Binding JWT (a compact form ending
in `~` carries none). The check is **fail-closed** — a present KB-JWT that cannot
be verified fails the bundle; it is never silently ignored. The verifier
requires: header `typ` = `kb+jwt` and `alg` = `EdDSA`; payload claims `iat`,
`aud`, `nonce`, `sd_hash` all present; `sd_hash` = base64url(H(US-ASCII of the
presented `<Issuer-signed JWT>~<Disclosure 1>~…~<Disclosure N>~`)) with H the
SD-JWT's `_sd_alg` hash; and the KB-JWT signature verifies under the holder key
from the issuer-signed payload's `cnf.jwk` (RFC 7800, OKP/Ed25519 — the issuer's
binding is authoritative). `aud`/`nonce` *value* policy and `iat` freshness are
the relying party's (an offline verifier has no trusted clock); the library
exposes them and accepts `expected_aud`/`expected_nonce` parameters.

Scope of the SD-JWT support (stated honestly): the SD-JWT *core* is
[RFC 9901](https://datatracker.ietf.org/doc/rfc9901/) (2025); the verifier does
**not** verify an X.509 / trust-list chain, status lists, or
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
5. **sd-jwt-key-binding** — only if `sd_jwt_vc` is present AND its compact
   serialization carries a Key Binding JWT (§6, since v1.2; fail-closed).

The bundle **verifies** iff every performed check passes. Trust anchors (the
expected signer key, the expected Merkle root) are inputs the relying party
supplies out of band; the verifier does not fetch anything.

## 7a. Scope guardrail (honest)

A bundle attests the **authenticity and integrity** of the exact `payload` bytes — signed by the stated
key, anchored under the stated Merkle root. It does **not** attest the correctness of any computation that
produced the payload, nor the absence of cherry-picking in an eval it carries. Those are separate concerns
(e.g. trusted-execution audits) with different trust models.

## 7b. in-toto test-result profile (normative, v0.9)

A receipt MAY be exported as a DSSE-signed in-toto attestation using the **generic** in-toto
`test-result` predicate, so a generic in-toto verifier understands it (alongside the self-hosted
predicate of §PREDICATE.md). The mapping is fixed:

- **Statement** — `_type` = `https://in-toto.io/Statement/v1`; `predicateType` =
  `https://in-toto.io/attestation/test-result/v0.1` (there is no v1; the predicate is v0.1). `subject` is
  a single ResourceDescriptor with a real `digest` (a sha256 over a stable binder of the receipt's model
  and dataset commitments, root, and timestamp — a hash that binds the attestation to the receipt, not the
  model itself).
- **Predicate (test-result/v0.1)** — `result` is `PASSED` when the threshold holds, else `FAILED` (WARNED
  is unused); `configuration` is a required list of ResourceDescriptors for the model and dataset
  commitments. Each descriptor carries a `digest` (a salted commitment hex under a proofbundle-specific
  algorithm key — never `sha256`, which would falsely imply an artifact hash); a bare `name`-only
  descriptor is invalid per the ResourceDescriptor rule. test-result has **no native metric field and no
  predicate-level annotations**, so metric/comparator/threshold/passed/provenance live in the model
  descriptor's `annotations`. `passedTests`/`failedTests` carry the suite name.
- **DSSE** — `payloadType` = `application/vnd.in-toto.test-result+json`; `payload` = standard RFC 4648 §4
  base64 (with padding, **not** base64url) of the serialized Statement bytes; `signatures[].sig` = base64
  of the raw Ed25519 signature. The signature is over the DSSE **PAE**:
  `"DSSEv1" SP LEN(payloadType) SP payloadType SP LEN(body) SP body`, where `LEN` is the ASCII-decimal
  byte length with no leading zeros and `body` is the **raw** Statement bytes — never the base64 string.
  A verifier decodes `payload` and reconstructs the PAE over exactly those bytes (it never re-serializes),
  and pins `payloadType` (sign and verify MUST use the same string).

## 7c. C2SP tlog-checkpoint (normative, v0.9)

A receipt's RFC 6962 Merkle root MAY be published as a
[C2SP tlog-checkpoint](https://github.com/C2SP/C2SP/blob/main/tlog-checkpoint.md) signed note: a note text
of at least three non-empty U+000A-separated lines — origin (schemeless, no space/`+`), tree size (ASCII
decimal, no leading zeros), and the root in **standard** base64 (RFC 4648 §4, not base64url) — ending in
U+000A, followed by an empty line and one or more signature lines. A signature line is
`U+2014 SP keyname SP base64(keyID ‖ signature) U+000A` (U+2014 is the EM DASH, not a hyphen), where
`keyID` = `SHA-256(keyname ‖ 0x0A ‖ 0x01 ‖ ed25519_pubkey)[:4]` and the signature is the raw Ed25519
signature over the note-text bytes **including the trailing newline** (raw bytes, no PAE). The verifier key
is distributed as `keyname + "+" + hex8(keyID) + "+" + base64(0x01 ‖ pubkey)`.

## 7d. C2SP tlog-cosignature, Ed25519 cosignature/v1 (normative, v1.2)

A checkpoint (§7c) MAY additionally carry witness **cosignatures** per
[C2SP tlog-cosignature](https://github.com/C2SP/C2SP/blob/main/tlog-cosignature.md): verifying a quorum of
cosignatures rules out a split view by the log operator, entirely offline. A cosignature is a note
signature line (same `U+2014 SP name SP base64(blob)` framing as §7c) where the blob is exactly
`keyID[4] ‖ timestamp[8, big-endian u64] ‖ ed25519_signature[64]` (76 bytes). The witness
`keyID` = `SHA-256(witness_name ‖ 0x0A ‖ 0x04 ‖ ed25519_pubkey)[:4]` — algorithm byte **0x04**
(cosignature/v1), deliberately distinct from the log's 0x01 so a log key can never masquerade as a
witness. The signed message is `"cosignature/v1\n" ‖ "time <timestamp>\n" ‖ <whole note body including
the final U+000A, excluding signature lines>`. The timestamp is a POSIX timestamp ≤ 2^63−1; freshness
policy is the relying party's (offline verifier, no trusted clock). Witness verifier keys use the §7c
vkey encoding with algorithm byte 0x04. A **witnessed** checkpoint verifies iff the log signature (§7c)
verifies AND at least `threshold` cosignatures from **distinct witness names** verify — witnesses attest
consistency, they never replace the log's own signature. Real split-view resistance additionally requires
the witnesses to be operationally independent, which is a deployment property outside this format.

Since v1.3 the **ML-DSA-44 cosignature type** (algorithm byte **0x06**, FIPS 204) is also
verified: witness `keyID` = `SHA-256(witness_name ‖ 0x0A ‖ 0x06 ‖ 1312-byte pubkey)[:4]`, blob =
`keyID[4] ‖ u64-BE-timestamp ‖ signature[2420]` (2432 bytes exactly). The signed message is the
C2SP `cosigned_message` structure (RFC 8446 conventions): fixed 12-byte label `"subtree/v1\n\0"`,
`opaque<1..2^8-1>` cosigner name, u64 timestamp, `opaque<1..2^8-1>` log origin, u64 start (0 for a
checkpoint), u64 end (= tree size), 32-byte root. Unlike Ed25519 cosignatures it commits to the
cosigner NAME and NOT to checkpoint extension lines. Verification requires a cryptography build
with ML-DSA (`proofbundle[pq]`); a configured ML-DSA witness on a build without it raises
UnsupportedError — fail-closed, never a silent False. Ed25519 and ML-DSA witnesses mix freely in
one quorum; the C2SP spec says ML-DSA-44 SHOULD be used for new witness deployments.

## 7e. C2SP tlog-proof (normative, v1.3)

A receipt's inclusion evidence MAY be carried as a
[C2SP tlog-proof](https://github.com/C2SP/C2SP/blob/main/tlog-proof.md) file (extension
`.tlog-proof`): line 1 exactly `c2sp.org/tlog-proof@v1`; an OPTIONAL `extra <base64>` line
(opaque and **unauthenticated** — a verifier MUST NOT trust it); an `index <decimal>` line
(zero-based, no leading zeros); zero or more standard-base64 SHA-256 inclusion-proof hashes, one
per line, leaf-sibling upward (RFC 6962 §2.1.1); one empty line; then a signed tlog-checkpoint
(§7c/§7d) **verbatim**. The proof/checkpoint split is the FIRST empty line. Verification order:
(1) recompute the leaf hash from the exact payload bytes (RFC 6962 `leaf_hash`, never taken from
the file), (2) log signature over an acceptable origin, (3) witness cosignatures against a k-of-n
policy over DISTINCT witness names, (4) inclusion proof binds the leaf at `index` to the
checkpoint root at its size. The overall verdict is the CONJUNCTION of all four — each sub-verdict
is reported. Cosignature timestamps are verified-then-ignored; freshness is relying-party policy.
Note: the C2SP spec file is on `main` and not yet version-tagged; the format string is pinned.

## 7f. Token Status List snapshot (normative, v1.3)

A receipt SD-JWT MAY carry a `status.status_list.{idx, uri}` claim
([draft-ietf-oauth-status-list](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/),
in the RFC-Editor queue — wire format frozen at draft-21). Revocation state is checked OFFLINE
against a supplied **Status List Token snapshot**: a signed JWT with header `typ` =
`statuslist+jwt` and `alg` = `EdDSA` (this profile), payload `sub` (MUST equal the receipt's
`uri`), `iat` (REQUIRED), optional `exp`/`ttl`, and `status_list: {bits, lst}` with `bits` ∈
{1,2,4,8} and `lst` = base64url(zlib(bit-array)), statuses packed LSB-first. Registered values:
0x00 VALID, 0x01 INVALID, 0x02 SUSPENDED. Freshness is REPORTED (`iat`/`exp`/`ttl`) and only
JUDGED when the relying party supplies its own clock — an offline verifier has no trusted time.
The bundle format (§3) is UNCHANGED: the snapshot is a separate verifier input, never a bundle
field. The SD-JWT issuer header is `typ: dc+sd-jwt` with a `vct` type URI since v1.3 (SD-JWT VC
draft markers; full VC conformance remains deferred until that draft is an RFC).

## 7g. Per-sample commitment and audit protocol (normative, v1.5)

An eval claim MAY carry a ``samples`` object ``{root_b64, n, leaf_alg}``: an RFC 6962 SHA-256
Merkle tree head over ONE leaf per sample, committed in canonical order (sorted by sample
identity; the 0-based position ``idx`` is embedded INSIDE each leaf record). ``samples.n`` MUST
equal the claim's ``n`` — **the signature, not the inclusion proof, is the truth anchor for the
tree size**: an RFC 6962 inclusion proof constrains n only up to path-shape equivalence
(measured: index 4 of a 10-leaf tree verifies under any claimed n′ ∈ [9..16]).

``leaf_alg`` = ``sha256-rfc6962-sdjwt-v1``: leaf hash = RFC 6962 leaf hash (0x00 domain
separation) over the US-ASCII bytes of a base64url **disclosure** encoding ``[salt_b64,
record]`` (RFC 9901 digest mechanic — verification re-hashes the transported string, never
canonicalizes JSON). Salts are per-leaf, ≥128 bit, derived
``HMAC-SHA-256(tree_secret, "proofbundle/v2/leaf-salt" ‖ id ‖ 0x00 ‖ epoch)[:16]`` from ONE
holder-kept secret (never in the receipt); revealing one salt reveals nothing about siblings
(HMAC-as-PRF). An **opening** = ``{index, disclosure, proof_b64[]}``; verification recomputes
the leaf hash, checks inclusion at ``index`` under the SIGNED (root, n), decodes the disclosure,
and enforces ``record.idx == index`` (replay guard against a lying producer — the lie sits
inside the committed leaf, so only this check catches it).

**Audit challenge** = ``SHA-256("proofbundle/v2/audit-challenge" ‖ root ‖ u64(n) ‖ u64(k) ‖
nonce)``, expanded by HMAC-SHA-256 counter mode into u64 draws, mapped to [0, n) by rejection
sampling (accept iff v < ⌊2^64/n⌋·n; zero modulo bias), duplicates skipped until k distinct
indices. Nonce modes: **auditor nonce** (fresh, supplied after signing — grinding impossible;
the default for audits), **public beacon** (a pulse from a round emitting AFTER the signed
timestamp, RFC 3797-style, publicly re-verifiable — since v1.9 formalized as
``nonce = SHA-256("proofbundle/v1.9/beacon-nonce" ‖ 0x00 ‖ beacon_id ‖ 0x00 ‖ u64(round) ‖
pulse_randomness)`` binding a drand/NIST beacon id + round, so any third party re-derives the
same indices; the relying party validates the beacon's own signature and the round's emission
time out of band), **self-challenge** (empty nonce; sanity check ONLY — a producer can grind by
re-salting, escaping with ≈ g·(1−m/n)^k over g attempts). Soundness is the proof-of-retrievability
bound 1−(1−m)^k, independent of n (k=300 → 95% at m=1%; 459 → 99%).
Openings are auditor-directed and never part of the public receipt (every opened sample is
burned for future evals — contamination economics are the relying parties' policy). The domain
strings are pinned at ``proofbundle/v2/*`` (protocol identifiers, independent of the package
version).

## 8. References

- RFC 6962 — Certificate Transparency (Merkle tree hashing, inclusion proofs).
- RFC 9162 — Certificate Transparency v2.
- RFC 8032 — EdDSA / Ed25519.
- RFC 4648 — Base16/Base32/Base64 encodings.
- RFC 9901 — Selective Disclosure for JWTs (SD-JWT), incl. §4.3 Key Binding JWT.
- RFC 7800 — Proof-of-Possession Key Semantics for JWTs (`cnf`).
- C2SP tlog-checkpoint / signed-note / tlog-cosignature / tlog-proof — witness ecosystem formats.
- FIPS 204 — Module-Lattice-Based Digital Signature Standard (ML-DSA).
- draft-ietf-oauth-status-list — Token Status List (RFC-Editor queue).
- RFC 3797 — Publicly Verifiable Nominations Committee Random Selection.
- RFC 2104 / FIPS 198 — HMAC (per-leaf salt PRF).
