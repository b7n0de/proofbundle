# proofbundle format specification — `proofbundle/v0.1`

Revision: 2026-07-13

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
- **Duplicate object keys MUST be rejected** (WP-C1), at any nesting depth, in
  the bundle document and in every other JSON input a verifier parses. JSON
  parsers disagree on duplicates (first-wins vs last-wins), so two
  implementations could verify DIFFERENT `root_b64`/`sig_b64` values from the
  same bytes — an interoperating implementation that silently keeps either
  occurrence is non-conforming. (RFC 8785 forbids duplicates outright; this
  extends the rule to the non-canonical inputs too.)

## 3. Object fields

| field | required | type | meaning |
|---|---|---|---|
| `schema` | yes | string | MUST be the exact string `"proofbundle/v0.1"`. |
| `payload_b64` | yes | string | Base64 of the payload bytes that were signed and anchored. |
| `signature` | yes | object | Ed25519 signature over the payload (§4). |
| `merkle` | yes | object | RFC 6962 inclusion proof of the payload leaf (§5). |
| `sd_jwt_vc` | no | object | Optional SD-JWT selective-disclosure credential (§6). |
| `anchors` | no | array | Optional, **EXPERIMENTAL** external time-anchor evidence, detached from the signed payload (§7i, the `[anchors]` extra). |

A verifier MUST reject a bundle whose `schema` is not `"proofbundle/v0.1"`
(unsupported), and MUST reject unknown top-level fields (the schema is
`additionalProperties: false`). The optional `anchors` field is now a KNOWN
field: a bundle carrying it is not malformed, but the core verifier (§7) does
NOT verify it — anchors are a separate, opt-in relying-party step (§7i), so a
bundle's crypto verdict is identical whether or not it carries `anchors`.

### 4. `signature`

| field | required | type | meaning |
|---|---|---|---|
| `alg` | yes | string | MUST be `"ed25519"`. |
| `public_key_b64` | yes | string | Base64 of the 32-byte raw Ed25519 public key. |
| `sig_b64` | yes | string | Base64 of the 64-byte Ed25519 signature over the raw payload bytes. |

Check **ed25519-signature**: decode `payload_b64` to `P`, verify the Ed25519
signature `sig_b64` over `P` under `public_key_b64`. The message is the raw
payload bytes — no pre-hashing, no domain separation.

### 4a. Verification semantics — the edge-case envelope (normative for this implementation)

Ed25519 implementations disagree on adversarially crafted edge-case signatures
(cofactored vs cofactorless verification, the RFC 8032 S-bound, non-canonical
point encodings, small-order components — "Taming the Many EdDSAs",
[eprint 2020/1244](https://eprint.iacr.org/2020/1244)). proofbundle delegates
verification to `cryptography` (OpenSSL) and PINS that behavior as a documented
property rather than an undocumented accident:

- **cofactorless** verification;
- the RFC 8032 **S-bound is enforced** (a signature whose S ≥ L is rejected);
- a **non-canonical R** encoding is rejected;
- a **non-canonical A** (public key) encoding is *partially* accepted (one of
  the two published variants verifies);
- **small-/mixed-order components are accepted** (no torsion check).

Against the "Taming the Many EdDSAs" 12-vector corpus this profile matches the
**BoringSSL / Dalek (non-strict)** row exactly — ACCEPT {0,1,2,3,11}, REJECT
{4,5,6,7,8,9,10} — observed identically from `cryptography` 42.0.8 (the declared
floor) through the current release. It is NEITHER **Dalek-strict** (which
rejects {0,1,2,11} and accepts only vector 3, whose rejection would need a
full-order check no surveyed library performs) NOR **ZIP-215** (Zebra, which
additionally accepts {4,5,9,10}). The divergence from Dalek-strict is exactly
{0,1,2,11}; from ZIP-215 exactly {4,5,9,10}. Signatures produced by an honest
RFC 8032 signer over a canonical public key verify identically under all of
these profiles — the divergence envelope exists ONLY for adversarially crafted
signatures. **Consequence for cross-verifier consensus:** an independent
verifier using a different profile (e.g. ZIP-215) MAY disagree with proofbundle
on such crafted signatures; a relying party that needs multi-implementation
agreement on hostile inputs must pin one profile across its verifiers. The exact
12-vector envelope is vendored (byte-pinned) and asserted by
`tests/test_ed25519_semantics.py` — a change in the backing library turns the
repository's CI red (a deliberate, documented decision), never a silent drift.
No wire or behavior change is made by documenting this; switching profiles would
be a breaking, versioned change.

### 5. `merkle`

| field | required | type | meaning |
|---|---|---|---|
| `hash_alg` | yes | string | MUST be present and MUST equal `"sha256-rfc6962"` in this schema version (REQUIRED since v1.6; SPEC.md corrected to match the verifier in this revision). A future hashing algorithm MUST register its own distinct `hash_alg` value — a verifier MUST NOT silently default a missing value to `"sha256-rfc6962"`, which is exactly where an algorithm-confusion attack would hide. |
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
| `issuer_public_key_b64` | yes¹ | string | Base64 of the issuer public key, format keyed by the issuer JWT header's `alg`: the 32-byte raw Ed25519 key for `alg: EdDSA`, or (since Finding 20, 2026-07-15) the 65-byte SEC1 **uncompressed** point `0x04‖X‖Y` for `alg: ES256` (ECDSA P-256, RFC 7518 §3.4). ¹Structurally optional for backward wire-compatibility, but **its absence now fails the bundle** — see below. |

The `sd_jwt_vc` block lives **outside** `payload_b64`, so the bundle's Ed25519
signature (§4) does **not** cover it; the only thing that authenticates the
SD-JWT is its own issuer signature. Therefore (secure-by-default since revision
2026-07-11, WP-C1/C2 — a breaking change from the prior null-and-warn behaviour):

Check **sd-jwt-disclosures**: the compact string is well formed and every
presented disclosure is committed (its digest appears in the issuer-signed
payload's `_sd` array). This is self-consistency only — it proves nothing about
provenance and is forgeable without any key.

Check **sd-jwt-issuer-signature**: the issuer JWT signature verifies under
`issuer_public_key_b64`, using the algorithm-specific primitive named by the
issuer JWT header's literal `alg` claim — `EdDSA` (Ed25519) or, since Finding 20
(2026-07-15, issue #27), `ES256` (ECDSA P-256, RFC 7518 §3.4; the JWS signature
is the fixed-width 64-byte `R‖S` concatenation, not DER). `alg` is part of the
signed bytes (the issuer JWT header, base64url-encoded, is covered by its own
signature), so it is cryptographically bound: an attacker cannot relabel it to
route one algorithm's signature through the other's verifier without breaking
the original signature. Any other `alg` value **FAILS** (`sig_ok` false, reason
names the unsupported alg) — no silent "unchecked" downgrade. When `sd_jwt_vc`
is present but `issuer_public_key_b64` is **absent**, this check **FAILS**
(reason: `unsigned`) — the disclosures are unauthenticated and MUST NOT be
treated as a passing credential. There is no opt-out that lets an unsigned
SD-JWT verify.

Check **sd-jwt-issuer-identity** (WP-C1): performed **iff** `sd_jwt_vc` is present,
its issuer signature verified, and the SD-JWT discloses an `issuer`. The key that
verified the signature MUST be the key it names (`issuer_public_key_b64` is already
the Base64 of the raw/SEC1-encoded key, per §6), with a fingerprint prefix keyed by
the alg that verified: `"ed25519:" + issuer_public_key_b64 == disclosed issuer` for
`alg: EdDSA`, `"es256:" + issuer_public_key_b64 == disclosed issuer` for
`alg: ES256`. A signature that verifies under an **attacker-chosen** key while the
always-open `issuer` names a *trusted* party is a forged identity (valid signature,
wrong signer) and **FAILS** (reason: `issuer-key-mismatch`).

Check **sd-jwt-bundle-binding** (WP-C1 + N1): performed when `sd_jwt_vc` is present
and its issuer signature verified, in **two** cases:
1. `payload_b64` decodes to a `proofbundle/eval-claim/v0.1` claim with a
   `merkle.root_b64`: the SD-JWT's always-open disclosures (`passed`, `threshold`,
   `comparator`, `suite`, `issuer`) and its committed `receipt.root_b64` MUST match
   the bundle payload bit-exact and bind **this** bundle's Merkle root. A valid
   issuer signature over disclosures that describe a *different* bundle (a receipt
   lifted and grafted on — cross-receipt substitution) **FAILS** (reason:
   `unbound`/`mismatch`).
2. **N1 (since 3.1.1):** `payload_b64` is **not** an eval-claim, but the SD-JWT
   carries an eval-binding root commitment (a `receipt.root_b64` string in its
   always-open payload). There is nothing on this bundle for that commitment to bind
   to, so the check is added and **FAILS** fail-closed (reason: `unbindable eval
   SD-JWT`). The discriminator is the presence of `receipt.root_b64` (the real
   substitution vector `check_binds_bundle` uses), **not** a heuristic word-match on
   `passed`/`threshold`/etc. A **generic** SD-JWT-VC (`iss`/`vct`, no `receipt.root_b64`
   commitment) carries no eval anchoring claim and is out of scope — it does not add
   this check (backward-compatible). A conforming verifier MUST implement case 2, or
   it remains vulnerable to grafting a signed eval SD-JWT onto an arbitrary payload.

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
**not** verify an X.509 / trust-list chain, status lists, or resolve `vct`
type-metadata *documents* (schema/display metadata — an offline integrity pin
on opaque metadata bytes is a separate, already-implemented capability,
`sdjwt_vc.check_vc_profile`'s `requireTypeMetadataIntegrity`). SD-JWT VC is
the IETF draft
[draft-ietf-oauth-sd-jwt-vc](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/);
proofbundle implements its issuer-signature algorithms (EdDSA and, since
Finding 20, ES256), its `typ`/`vct` syntactic markers, a relying-party `vct`
allowlist check (`sdjwt_vc.check_vc_profile`), and — since Finding 20 — an
exact-`vct` trust-policy pin (`sd_jwt.expected_vct`, evaluated by
`policy.evaluate_policy` — the trust-policy schema itself is not part of this
wire-format spec; see `schemas/trust_policy_v0_1.schema.json`). See
`docs/SD_JWT_VC_PROFILE.md` for the current, honest split of what remains on
the roadmap against issue #27.

## 7. Verification order (normative)

A conforming verifier MUST perform, in this order, and report each result:

1. **schema** — reject if `schema != "proofbundle/v0.1"`.
2. **ed25519-signature** (§4).
3. **merkle-inclusion** (§5).
4. **sd-jwt-disclosures** and **sd-jwt-issuer-signature** — only if `sd_jwt_vc`
   is present (§6). Since revision 2026-07-11, a present `sd_jwt_vc` with **no**
   `issuer_public_key_b64` makes **sd-jwt-issuer-signature** FAIL (unsigned →
   unauthenticated); it is not a skipped or warning-only check.
5. **sd-jwt-key-binding** — only if `sd_jwt_vc` is present AND its compact
   serialization carries a Key Binding JWT (§6, since v1.2; fail-closed).
6. **sd-jwt-issuer-identity** — only if `sd_jwt_vc` is present, its issuer
   signature verified, and it discloses an `issuer` (§6, WP-C1; fail-closed against
   a forged issuer identity).
7. **sd-jwt-bundle-binding** — if `sd_jwt_vc` is present and its issuer signature
   verified, in EITHER of two cases (§6): the payload is a
   `proofbundle/eval-claim/v0.1` claim (WP-C1; fail-closed against cross-receipt
   substitution), OR the payload is NOT an eval-claim but the SD-JWT carries an
   eval-binding `receipt.root_b64` commitment (N1, since 3.1.1; fail-closed against
   grafting a signed eval SD-JWT onto an arbitrary payload). A generic SD-JWT-VC with
   no `receipt.root_b64` is out of scope.
8. **root-authenticity** and **tree-size** — additive relying-party root
   authentication (ADR 0004, since the root is NOT in the signature input, §5).
   Performed ONLY when the relying party supplies an expected value: a given
   `expected_root_b64` MUST equal the stated root's bytes, and a given
   `expected_tree_size` MUST equal `merkle.tree_size`; a mismatch FAILS. Absent an
   expected value, root authenticity is `NOT_EVALUATED` (the verdict is unchanged).
   A trust policy MAY additionally require an authenticated root
   (`merkle.require_authenticated_root` / `merkle.trusted_roots`), enforced over the
   crypto result (exit 3, not part of this crypto order). A conforming verifier
   MUST report `payloadSignature` / `merkleConsistency` / `rootAuthenticity`
   (PASS/FAIL/NOT_EVALUATED) separately, so Merkle inclusion is never read as root
   authentication.
9. **checkpoint-authenticity** (since 3.1.3, A-P0-1) — performed ONLY when the relying
   party supplies a trusted checkpoint (`--trusted-checkpoint` + `--checkpoint-vkey`,
   a signed C2SP note per §7c). The checkpoint signature MUST verify under the
   supplied verifier key; the checkpoint's `(root, tree size)` pair then becomes the
   expected root AND expected tree size ATOMICALLY (feeding check 8). A checkpoint
   that does not verify FAILS the verdict — the expectations it would have carried
   are never used unauthenticated.

The bundle **verifies** iff every performed check passes. Trust anchors (the
expected signer key, the expected Merkle root) are inputs the relying party
supplies out of band; the verifier does not fetch anything.

### Atomic tree context (normative, since 3.1.3 — A-P0-1)

**Root and tree size MUST be authenticated atomically for production trust.** An RFC 6962
inclusion proof constrains `(leaf_index, tree_size)` only up to path-shape equivalence: a
receipt honestly anchored at index 1 of a 2-leaf tree also verifies relabelled as index 2 of
a claimed 3-leaf tree — same payload, same signature, same root, same proof. A root-BYTES
pin (bare `expected_root`, or a policy `trusted_roots` entry) cannot distinguish the two,
because both labelings share the root. Therefore:

- `TREE_CONTEXT_AUTHENTICITY: PASS` requires that the stated root AND the stated
  `tree_size` both match ONE authenticated source: a verified signed checkpoint
  (`--trusted-checkpoint`/`--checkpoint-vkey`, or a policy `merkle.trusted_checkpoints`
  entry — signature-valid under its pinned `checkpointSigner`, unexpired, supported
  `hashAlg`), or a relying-party-supplied `expected_root` + `expected_tree_size` PAIR.
- A naked root pin reaches at most `ROOT_BYTES_AUTHENTICITY: PASS` — NEVER
  `TREE_CONTEXT_AUTHENTICITY: PASS` and never `safeForAutomation: true`
  (`rootTrustLevel: ROOT_BYTES_ONLY`).
- The verifier reports `rootTrustLevel` ∈ `CHECKPOINT` (atomic pair from a verified
  signed checkpoint) / `ROOT_AND_TREE_SIZE_PINNED` (atomic pair supplied directly by the
  relying party) / `ROOT_BYTES_ONLY` / `NONE`, and `checkpointAuthenticity`
  (PASS/FAIL/NOT_EVALUATED). The legacy `rootAuthenticity` key remains as a wire-compat
  ALIAS of `rootBytesAuthenticity`; it never asserted more than root bytes and MUST NOT
  be read as tree-context or automation trust.

### Automation-safety verdict and additive output objects (since 3.1.1)

`safeForAutomation` is a **global** "safe to act on automatically" verdict, distinct from the crypto
verdict. It is `true` ONLY when: the crypto verification passed; the Merkle root was affirmatively
authenticated (`expected_root` or a policy `trusted_roots` / `require_authenticated_root`); root and
tree size were authenticated ATOMICALLY from one source (`TREE_CONTEXT_AUTHENTICITY: PASS`, since
3.1.3 — see "Atomic tree context" above; a root-bytes-only pin never qualifies); a supplied
trust policy PASSED (`policy_ok is True` — no policy, i.e. `None`, never qualifies); that policy pins a
trusted signer identity; the policy is not a raw template (`requiresIdentityOverlay` is not set); the
policy carries no blocking warning, is not expired and is not yet-to-become-valid; and no required
anchor / public-transparency / replay gate FAILED. Expiry is INCLUSIVE: a policy is valid up to and
including its `valid_until` instant and expired strictly after it. A conforming verifier that emits the
field MUST also emit `automationBlockers` — an array naming every reason it is false, drawn from at
least: `POLICY_NOT_EVALUATED`, `POLICY_FAILED`, `SIGNER_NOT_PINNED`, `TEMPLATE_NOT_INSTANTIATED`,
`ROOT_NOT_AUTHENTICATED`, `TREE_CONTEXT_NOT_AUTHENTICATED`, `POLICY_EXPIRED`, `POLICY_NOT_YET_VALID`,
`POLICY_WARNINGS_PRESENT`, `ANCHOR_REQUIRED_FAILED`, `PUBLIC_TRANSPARENCY_REQUIRED_FAILED`,
`REPLAY_BINDING_REQUIRED_FAILED`, `CRYPTO_FAILED`. The human and machine forms of the verdict MUST
agree.

**Policy lifecycle and purpose (normative since 3.1.3 — A-P0-2 / A-P0-4).** Policy lifecycle is part
of the policy EVALUATION itself on BOTH verify paths, not only of the automation verdict: a policy
whose `valid_until` is in the past, whose `valid_from` is still in the future, or which is a raw
template (`requiresIdentityOverlay: true`) FAILS the policy (`POLICY: FAIL`, exit 3). Historical
verification never happens silently: only an explicit `--verification-time <ISO-8601>` (together with
`--policy`) evaluates the lifecycle AS OF that instant, and the output is labelled
(`VERIFICATION_TIME: HISTORICAL`, `CURRENT_POLICY_STATUS`, `HISTORICAL_POLICY_STATUS`). Historical mode
relaxes ONLY the POLICY verdict (exit code + label); `safeForAutomation` is a PRESENT-tense verdict
whose lifecycle and tree-context inputs are always evaluated at the REAL current time, so a policy that
is expired OR not-yet-valid TODAY, or a `trusted_checkpoints` entry whose `validUntil` is past TODAY,
keeps `safeForAutomation: false` (`POLICY_EXPIRED` / `POLICY_NOT_YET_VALID` /
`TREE_CONTEXT_NOT_AUTHENTICATED`) even in historical mode. `--verification-time` MUST be a PAST instant
(a historical query); a future instant is a usage error (exit 2). A policy
MAY declare `policyPurpose` ∈ `eval` / `decision` / `outcome` / `trust-pack` / `public-transparency`:
the eval verify path accepts only `eval`, the decision path only `decision`; the wrong purpose FAILS
the policy (exit 3). A policy without the field is treated as a transitional legacy policy (no purpose
check); `policy lint --strict` requires the field. Pinned `merkle.trusted_roots` entries MUST be valid
standard base64 decoding to exactly 32 bytes — a malformed pin is a load-time error with its own
reason, never a silent never-matches (A-P0-5).

**Enforcement status of the gate conditions (No-Overclaim).** `ANCHOR_REQUIRED_FAILED`,
`POLICY_EXPIRED`, `POLICY_NOT_YET_VALID`, `TEMPLATE_NOT_INSTANTIATED`, `SIGNER_NOT_PINNED`,
`POLICY_FAILED`, `POLICY_NOT_EVALUATED`, `POLICY_WARNINGS_PRESENT`, `ROOT_NOT_AUTHENTICATED`,
`TREE_CONTEXT_NOT_AUTHENTICATED` and `CRYPTO_FAILED` are LIVE:
the reference verifier wires each to a real verdict. `PUBLIC_TRANSPARENCY_REQUIRED_FAILED` and
`REPLAY_BINDING_REQUIRED_FAILED` are **forward-compatible/dormant in the current core**: the reference
CLI never supplies a `False` value for them (the public-transparency policy-evaluation library is built
EXPERIMENTAL as `public_transparency.py` in 3.2.0, but is not yet wired into the reference CLI's `--policy`
enforcement — see `docs/PUBLIC_TRANSPARENCY_PROFILE.md`; replay/audience binding already fails the
CRYPTO verdict when a required KB-JWT is absent). They are enumerated so a future policy layer can flip
them without a format change; today they never fire.

`treeSizeExpectation` is an additive object `{status: PASS|FAIL|NOT_REQUESTED, expected, actual}` making
the tree-size gate's outcome explicit (`NOT_REQUESTED` when no `expected_tree_size` was supplied). The
tree-size check is evaluated INDEPENDENTLY of the root: a mismatch fails the crypto verdict on its own,
and without a pinned root the root itself remains unauthenticated.

A trust policy MAY carry additive metadata: `deploymentReady` / `requiresIdentityOverlay` (a policy is a
raw TEMPLATE until instantiated with a signer overlay) and `valid_until` (an ISO-8601 UTC expiry).
`requiresIdentityOverlay: true` is a HARD gate on the automation verdict — such a policy can never yield
`safeForAutomation: true` (blocker `TEMPLATE_NOT_INSTANTIATED`), and an expired `valid_until` yields
`POLICY_EXPIRED` — not merely `policy lint --strict` advisories; they never change the crypto verdict.
The same template-not-instantiated and expiry gates are ALSO enforced on the `decision verify` path
(over `decision_receipt.trusted_decision_makers`), so a raw or expired decision policy cannot authorise a
decision (exit 3).

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

## 7h. TEE-attestation bridge — enclave_attested (EXPERIMENTAL, v2.0 preview)

A receipt MAY carry ``assurance_level = enclave_attested`` and be accompanied by a TEE Attestation
Result that a relying party verifies offline. This is a **preview** (``proofbundle.experimental``,
``[experimental]`` extra; API/wire-format unstable). Model: IETF RATS Passport (RFC 9334). The
enclave places ``enclave_binding_for(receipt)`` = base64url(SHA-256("proofbundle/v2/enclave-binding"
‖ payload)) into its hardware quote user-data (Intel TDX ``REPORTDATA`` / NVIDIA GPU report nonce);
a RATS **Verifier** appraises the raw evidence out of band and issues a signed **EAT** (RFC 9711,
JSON/JWS, EdDSA) whose ``eat_nonce`` equals that binding. proofbundle verifies, offline: the EAT
signature under the Verifier key (a supplied trust anchor), ``typ`` = ``eat+jwt``, ``alg`` = EdDSA,
``eat_nonce`` == the binding, and optionally ``eat_profile``. It reports the ``tier`` (this
preview's stand-in for the still-draft AR4SI/EAR trustworthiness tier) VERBATIM. proofbundle does
NOT parse or appraise raw hardware evidence — that is the Verifier's role. See
docs/EXPERIMENTAL_ENCLAVE.md.

## 7i. External time anchors — `anchors[]` (EXPERIMENTAL, the `[anchors]` extra)

A receipt MAY carry a top-level `anchors` array of external time-anchor
evidence. An anchor adds evidence of *when*, from a party the producer does not
control — something the receipt's own Ed25519 signature and Merkle structure
cannot establish on their own (a self-emitted timestamp is only producer-clock
testimony). This layer is **EXPERIMENTAL**: the wire format MAY change, the base
install does not verify it, and a receipt with no anchors verifies exactly as
before. The prose companion is [docs/ANCHORS.md](docs/ANCHORS.md).

**This field is DETACHED from the content root.** An anchor is evidence *about*
the receipt, never part of what it attests. A `receipt`-target anchor stamps the
canonical root of the receipt **without its own `anchors` field** (an anchor
cannot attest a root that already contains itself); a verifier computing that
root MUST exclude `anchors`. Anchor bytes are never part of any signed payload.

**Producer rollout — one-way compatibility.** Emitting `anchors[]` is a one-way
compatibility step. `anchors` became a KNOWN top-level field only in this
revision (2026-07-10); a verifier built against an earlier SPEC revision does not
list it, so — because the bundle schema is `additionalProperties: false` (§3) —
it rejects an anchored bundle as **malformed (exit 2)** rather than ignoring the
field. This is not a security bug (a fail-closed verifier erring toward rejection
is correct), but a producer that starts adding `anchors[]` SHOULD know that older
verifiers will refuse the bundle until they are updated to this revision.

### Anchor entry

Each `anchors[]` entry is a JSON object:

| field | required | type | meaning |
|---|---|---|---|
| `type` | yes | string | `rfc3161-tsa`, `opentimestamps`, or an extension `<org>/<name>/vN`. An unknown type is a FAIL, never a silent pass. |
| `target` | yes | string | `receipt` or `preRegistration` (see below). |
| `canonicalRoot` | yes | string | Base64 of the canonical root of the anchor's OWN target. |
| `proof` | yes | string | Base64 of the type-specific proof (an RFC 3161 token, an OpenTimestamps proof, …). |
| `anchoredAt` | no | string \| null | RFC 3339 Z, **INFORMATIVE only** — the trusted time comes from the proof, never this field. |
| `frozen` | no | object | OPTIONAL producer-supplied type-specific EVIDENCE bundled at emit time (e.g. the TSA certificate chain, a Bitcoin block header). **WP-A1 (rev 2026-07-11): `frozen` is producer-controlled and is NEVER a trust source** — it is reported as evidence (`frozenEvidence`) but a confirmed verdict requires the relying party's own trust material (see Trust model). The frozen `intermediateCertsDerB64` / `tsaCertDerB64` are path-building only (validated up to the RP root); an optional `policyOid` still pins stricter-only. |

### Targets (never mixed)

| target | claim | canonical root |
|---|---|---|
| `preRegistration` | the commitment existed **before** the run (backdating protection; in-toto/attestation#565) | SHA-256 of the raw protocol bytes, i.e. the receipt's `prereg_sha256` |
| `receipt` | the receipt existed **from** time T (publication proof) | RFC 8785 (JCS) SHA-256 of the receipt bundle **excluding `anchors`** |

`canonicalRoot` is compared to the root of the anchor's OWN `target`: a
`preRegistration` anchor can never validate a `receipt` target and vice versa
(the roots differ, and a mismatch is a FAIL). A future `statement` target — for
a signed decision receipt whose content root is the DSSE Statement bytes — is
RESERVED (in-toto/attestation#565, proofbundle#7) and is **not** part of this
experimental layer yet.

### Verify contract and the three anchor states

Verification is **fail-closed** and reported as one aggregate status plus a
per-entry status:

- **absent** — missing/empty `anchors` → **SKIP** (never FAIL). This matches
  in-toto's Monotonic Principle: deny only when an attestation is present and
  wrong, not when it is absent.
- **confirmed** — a fully verifying anchor (`ok`): its root matches the target,
  its type is known, and its proof verifies. All entries confirmed → **PASS**.
- **pending** — an anchor that is honestly not yet a full external-time proof
  (a `warn`), e.g. an un-upgraded OpenTimestamps proof or a Merkle-only
  chia-datalayer level-i anchor → **WARN**. It is never conflated with a
  confirmed anchor.

A root mismatch, an unknown type, a broken proof, or a valid-but-untrusted anchor
(**needs_rp_trust** — an upgraded, structurally-bound proof for which the relying
party supplied no trust material; see Trust model) is a hard **FAIL**; a
verifier that raises is treated as FAIL. `verify --require-anchor` (optionally
narrowed by `--anchor-type <type>`) turns "no verifying anchor (of that type)"
into a FAIL — a relying-party gate OVER the crypto result, exit 3 when unmet
(distinct from a crypto failure, exit 1), exactly like `--policy`. A **pending**
anchor does NOT satisfy `--require-anchor` unless `--allow-pending` is given.

**Target gate (WP-A1).** `--anchor-target receipt|preRegistration|statement`
(implies `--require-anchor`) additionally requires the verifying anchor to
stamp THAT target: matched = ok ∧ ¬warn ∧ type ∧ **target**. Without it the
requirement matches the TYPE alone — a `receipt` anchor stamped today would
satisfy a relying party who meant backdating protection (`preRegistration`),
although existence-now proves nothing about existence-before-the-run. The same
requirement is expressible as a policy key (trust-policy **v0.2** `anchors`
section: `require_anchor`, `require_anchor_target`, `allow_pending`); a CLI
flag conflicting with the policy value is an ambiguity error (exit 2), never a
silent override.

**Structured trusted time (WP-A2).** A verifying anchor's per-entry result MAY
carry `trustedTime` — `{source: "rfc3161_gen_time", time: <RFC 3339>, tz: "Z"}`
from a verified RFC 3161 token's own `gen_time`, or
`{source: "bitcoin_block", height: <int>}` from a confirmed OpenTimestamps
attestation (the block HEIGHT is the proof's native unit; no wall-clock value
is guessed for it). The field is present ONLY when the proof genuinely carries
the time; it is never derived from the informative `anchoredAt`. This is what
makes a time-window policy (t₁ < run < t₂) buildable over `verify --json`.

### Built-in types (informative)

- **`rfc3161-tsa`** — an RFC 3161 timestamp token, verified **offline** against
  a TSA **root certificate the RELYING PARTY supplies** (WP-A1: CLI
  `--trusted-tsa-root`, policy `anchors.trusted_tsa_roots`), NOT the anchor's
  own `frozen` root (which the producer controls). The chain is validated at the
  token's own `gen_time`, not the current wall clock, so a token stays
  re-verifiable after the TSA certificate has expired or rotated; a certificate
  that was not valid at `gen_time` fails closed. With no relying-party root the
  token is `needs_rp_trust` (ok=False). The TSA **policy OID** is not pinned by
  default; a relying party MAY pin it (`anchors.trusted_tsa_policy_oids`) or the
  producer MAY declare a stricter-only `frozen.policyOid`; a token whose
  `TSTInfo.policy` differs fails closed.
- **`opentimestamps`** — an OpenTimestamps proof anchored in Bitcoin. A fresh
  stamp is **PENDING** (a WARN) until `ots upgrade` embeds the Bitcoin
  block-header path. Confirming it needs the block's `hashMerkleRoot` for the
  attested height — **supplied by the RELYING PARTY** (WP-A1: CLI
  `--bitcoin-header`, policy `anchors.bitcoin_block_headers`), from their own
  trusted/pruned Bitcoin node, NOT the anchor's `frozen` header. The root is in
  **internal (node) byte order** as returned by `bitcoind` — NOT the
  byte-reversed order block explorers display; a reimplementer MUST use the
  internal order. With no relying-party header the upgraded proof is
  `needs_rp_trust` (ok=False), never confirmed.

### Trust model (WP-A1, normative)

An external time anchor's TRUST comes ONLY from the relying party, never from
the bundle. The `frozen` block is producer-controlled EVIDENCE (surfaced as
`frozenEvidence`), never a trust source: a malicious producer could freeze its
own self-signed TSA root, or a self-committed backdated Bitcoin header, and
self-certify a **backdated** timestamp. Therefore a confirmed verdict requires
the relying party to supply the matching trust material (`--trusted-tsa-root` /
`--bitcoin-header`, or the policy `anchors` section); without it the anchor is
`needs_rp_trust` and `--require-anchor` is unmet → exit 3, never a silent pass.
A per-entry result carries `rp_trusted` (verified against RP material),
`needs_rp_trust` (proof present but no RP material), and `frozenEvidence` (the
bundle carried frozen material, reported but not trusted).

### Privacy

Public anchoring transmits and publishes **only digests / roots**, never
payload contents: the anchored value is `canonicalRoot` (a SHA-256), so nothing
about the underlying claim, protocol, or samples leaks to the timestamping
authority, calendar, or chain.

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
- RFC 9334 — RATS Architecture (Passport model).
- RFC 9711 — Entity Attestation Token (EAT).
