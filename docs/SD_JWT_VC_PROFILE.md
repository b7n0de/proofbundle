# SD-JWT VC profile: what is implemented, what is not

Tracks issue [#27 — "Roadmap: full SD-JWT VC conformance with vct type
metadata"](https://github.com/b7n0de/proofbundle/issues/27). This document
is the honest split the issue itself already calls for: proofbundle's
selective-disclosure layer implements the SD-JWT **core** — now a published
standard, [RFC 9901](https://datatracker.ietf.org/doc/rfc9901/) (November
2025) — completely, including the secure-by-default hardening landed in
3.0.0. It implements a growing set of **SD-JWT VC** (the credential-type
profile, still the IETF draft
[draft-ietf-oauth-sd-jwt-vc](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/))
capabilities — as of **Finding 20** (2026-07-15) this includes ES256
issuer-signature interop and an exact-`vct` trust-policy pin, both closing
items issue #27 asked for (see "Implemented since Finding 20" below). It
still does **not** implement type-metadata *document* resolution or a
status-list/X.509 trust chain. Match against SPEC.md §6 (`sd_jwt_vc`) and §7
(verification order) — this document adds no new normative behavior, it
explains what is already there in one place.

## What "SD-JWT VC" means, precisely

RFC 9901 defines the SD-JWT *mechanism*: how to selectively disclose fields
of a signed JWT via salted digest commitments, and how a holder proves
possession with a Key Binding JWT. **SD-JWT VC** is a separate, still-draft
specification layered on top: it standardizes *what kind of credential* an
SD-JWT is (`vct`, a type identifier), how a verifier resolves that type's
schema/display metadata, how revocation is checked (Token Status List), and
the media type (`typ: dc+sd-jwt`, née `vc+sd-jwt`). A verifier can implement
the mechanism without the credential-type layer — that split is exactly
where proofbundle's `sd_jwt_vc` block sits today.

## Implemented: the SD-JWT core (RFC 9901), secure by default

Every check below is normative in SPEC.md §6/§7 and runs on **every**
bundle carrying an `sd_jwt_vc` block — there is no opt-out.

| Check (SPEC §7 order) | What it proves | Since |
|---|---|---|
| `sd-jwt-disclosures` | every presented disclosure hashes to a digest actually committed in the issuer JWT's `_sd` array (self-consistency; forgeable without a key) | v0.5 |
| `sd-jwt-issuer-signature` | the issuer JWT's signature verifies under `issuer_public_key_b64` — EdDSA (Ed25519) or, **since Finding 20 (2026-07-15, issue #27)**, ES256 (ECDSA P-256, RFC 7518 §3.4), dispatched strictly on the literal `alg` claim. **Since revision 2026-07-11 (WP-C2, 3.0.0, breaking): a present `sd_jwt_vc` with NO `issuer_public_key_b64` now FAILS** (reason `unsigned`) instead of the pre-3.0.0 null-and-warn behavior — there is no way for an unauthenticated SD-JWT to verify | v0.5; secure-by-default since 3.0.0; ES256 since Finding 20 |
| `sd-jwt-key-binding` | a trailing Key Binding JWT (RFC 9901 §4.3), if present, is fail-closed verified: header `typ: kb+jwt`/`alg: EdDSA`; payload `iat`/`aud`/`nonce`/`sd_hash` all present; `sd_hash` binds the exact presented disclosure string; signature verifies under the issuer-bound holder key (`cnf.jwk`, RFC 7800) | v1.2 |
| `sd-jwt-issuer-identity` | for an SD-JWT that discloses an `issuer` claim, the key that verified the signature MUST be the key it names, with an alg-aware fingerprint prefix (`"ed25519:" + issuer_public_key_b64 == disclosed issuer` for `alg: EdDSA`, `"es256:" + issuer_public_key_b64` for `alg: ES256` since Finding 20) — closes a forged-identity gap (valid signature, attacker-chosen key, trusted-sounding disclosed issuer) | WP-C1, 3.0.0; alg-aware since Finding 20 |
| `sd-jwt-bundle-binding` | for an eval-claim payload, the SD-JWT's always-open disclosures (`passed`/`threshold`/`comparator`/`suite`/`issuer`) and its committed `receipt.root_b64` MUST match the bundle it ships in, bit-exact — closes cross-receipt substitution (a valid receipt's SD-JWT grafted onto a different bundle) | WP-C1, 3.0.0 |

`verify --aud <value>` / `--nonce <value>` bind the KB-JWT's audience and
nonce (RFC 9901 §7.3) to the relying party's own challenge, fail-closed on
mismatch; a trust policy's `sd_jwt.expected_aud` / `require_nonce` /
`require_key_binding_when_cnf_present` pin the *same* checks declaratively
(`docs/TRUST_ANCHORS.md`).

## Implemented: the SD-JWT VC syntactic markers (not the semantics)

Since v1.3, `sdjwt_issue.issue_sd_jwt` sets three SD-JWT-VC-shaped values in
every issued SD-JWT, always-open (never hidden behind a disclosure):

- **`typ: dc+sd-jwt`** in the JWT header (the media type
  `application/dc+sd-jwt`; SD-JWT VC's rename from the earlier `vc+sd-jwt`
  — not yet IANA-registered, registration lands with the draft's eventual
  RFC publication).
- **`vct`** — a type URI claim (`sdjwt_issue.DEFAULT_VCT =
  "https://b7n0de.com/proofbundle/vct/eval-receipt/v1"`, overridable per
  call). It identifies *what kind* of credential this is.
- **`status`** — an optional Token Status List pointer (SPEC.md §7f):
  `{status_list: {idx, uri}}`. Revocation is checked **offline** against a
  relying-party-supplied Status List Token *snapshot*
  (`statuslist.verify_status_snapshot`) — proofbundle never fetches the
  status list itself. Freshness (`iat`/`exp`/`ttl`) is reported, and only
  *judged* when the relying party supplies its own clock (an offline
  verifier has none).

**These markers are emitted and structurally present. Since Finding 20
(2026-07-15), `evaluate_policy` CAN enforce `vct` via an opt-in trust-policy
field, `sd_jwt.expected_vct`** — a relying party that sets it gets a
`policy:expected_vct` check requiring the SD-JWT's disclosed `vct` to equal
that exact string, read ONLY from a VERIFIED issuer signature (never an
unauthenticated re-parse; see "Implemented since Finding 20" below). A policy
that does **not** set `expected_vct` still treats `vct` exactly like any
other unexamined field inside the issuer JWT payload — present,
self-consistent (covered by the issuer signature once that verifies), but
not compared against anything: `vct` enforcement is opt-in, not forced on
every bundle. `verify` (the base crypto path with no policy) never reads
`vct` at all — that stays a policy-layer concern, by design (crypto proves
authenticity + integrity; the *policy* is where the relying party states
which types it accepts). This is the honest current boundary the `sdjwt.py`
module docstring states: *"No X.509 / trust-list / status-list checks, no
`vct` type-metadata **document** resolution [...]. Full SD-JWT VC conformance
remains on the roadmap."*

## Implemented since Finding 20 (2026-07-15, issue #27)

Two of issue #27's three concrete items are now closed:

- **ES256 issuer-signature interop.** `sdjwt.verify_sd_jwt` verifies ECDSA
  P-256 (ES256, RFC 7518 §3.4) issuer signatures alongside EdDSA, dispatched
  strictly on the issuer JWT header's literal `alg` claim — the algorithm
  the EUDI Digital Identity Wallet and the OAuth WG's own SD-JWT VC worked
  examples use. `issuer_public_key_b64` is the 65-byte SEC1 **uncompressed**
  point `0x04‖X‖Y` for `alg: ES256` (vs. the 32-byte raw key for `alg:
  EdDSA`). `bundle.py`'s `sd-jwt-issuer-identity` check's fingerprint prefix
  is alg-aware too (`"ed25519:"` / `"es256:"`), so a bundle carrying an
  ES256-signed `sd_jwt_vc` that discloses proofbundle's own `issuer` claim
  format is checked correctly rather than always mismatching.
- **A verifier flag to require a specific `vct`.** `policy.py`'s
  `_SDJWT_KEYS` now includes `expected_vct`; when a trust policy sets
  `sd_jwt.expected_vct`, `evaluate_policy` adds a `policy:expected_vct`
  check requiring the SD-JWT's disclosed `vct` to equal that exact string —
  read ONLY from a payload whose issuer signature actually verified
  (mirrors the "verified vs. merely present" discipline
  `policy:nonce_present` already established; an unverified `vct` proves
  nothing an attacker could not have written themselves, so it fails
  closed). This complements, and is distinct from, `sdjwt_vc.py`'s
  standalone `vctAllowlist` (a separate entry point for a bare compact
  SD-JWT, not a proofbundle bundle) — see `docs/SDJWT_VC_PROFILE.md`.

The remaining item is **not** implemented:

1. **`vct` claim + type-metadata *document* resolution (offline-first:
   embedded or pinned).** The `vct` claim is emitted and, since Finding 20,
   optionally exact-matched (above), but it is still not resolved against
   any type-metadata *document* — no schema/display metadata is fetched,
   parsed, or used to validate claims. `sdjwt_vc.check_vc_profile`'s
   `requireTypeMetadataIntegrity` is a narrower, already-implemented,
   related capability: an offline SHA-256 integrity pin on OPAQUE metadata
   bytes the relying party supplies, never a fetch and never a schema
   resolution. **Not implemented.**

Conformance vectors from the OAuth WG examples are also now real:
`tests/fixtures/sdjwtvc/` vendors the 5 worked SD-JWT VC examples (structure
+ profile checks, WP-W2/3.2.1) **and**, since Finding 20, the issuer public
key those same examples are signed under (from the same pinned commit's
`examples/settings.yml`) — so `test_sdjwtvc_external_vectors.py`
cryptographically verifies the issuer signature, not just the structure.

This document does not claim issue #27 is fully closed — type-metadata
document resolution remains open — but it records precisely what changed,
so a reader is never told a stale "roadmap" story for a capability that
already shipped.

## `proofbundle-policy/sdjwt-vc-v1` (still not shipped as a named profile)

`docs/POLICY_PROFILES.md` names this profile from the v2-audit's WP3 list
and explains why it was **not shipped**: shipping a policy JSON with a
`sd_jwt.expected_vct` field that the loader accepted but `evaluate_policy`
never checked would itself be the silent vacuous-pass trap `policy lint`
(WP-TP1) exists to catch. Since Finding 20 the schema field and its
enforcement now exist together (above) — the precondition
`docs/POLICY_PROFILES.md` named is met — but shipping the actual named
profile file (and the review it would need as a shipped, discoverable
default) is a separate, still-open follow-up, not folded into Finding 20.

## SPEC.md cross-reference

- §6 `sd_jwt_vc` — the wire format and every check listed above, normative.
- §7 items 4–7 — the exact verification order (disclosures/issuer-signature
  before key-binding before issuer-identity before bundle-binding).
- §7f — Token Status List snapshot semantics.
- §8 — RFC 9901, RFC 7800 references.
