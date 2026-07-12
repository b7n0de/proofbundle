# SD-JWT VC profile: what is implemented, what is not

Tracks issue [#27 — "Roadmap: full SD-JWT VC conformance with vct type
metadata"](https://github.com/b7n0de/proofbundle/issues/27). This document
is the honest split the issue itself already calls for: proofbundle's
selective-disclosure layer implements the SD-JWT **core** — now a published
standard, [RFC 9901](https://datatracker.ietf.org/doc/rfc9901/) (November
2025) — completely, including the secure-by-default hardening landed in
3.0.0. It implements a small number of **SD-JWT VC** (the credential-type
profile, still the IETF draft
[draft-ietf-oauth-sd-jwt-vc](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/))
syntactic markers. It does **not** implement `vct`-based policy enforcement,
type-metadata resolution, or a status-list/X.509 trust chain. Match against
SPEC.md §6 (`sd_jwt_vc`) and §7 (verification order) — this document adds no
new normative behavior, it explains what is already there in one place.

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
| `sd-jwt-issuer-signature` | the issuer JWT's EdDSA signature verifies under `issuer_public_key_b64`. **Since revision 2026-07-11 (WP-C2, 3.0.0, breaking): a present `sd_jwt_vc` with NO `issuer_public_key_b64` now FAILS** (reason `unsigned`) instead of the pre-3.0.0 null-and-warn behavior — there is no way for an unauthenticated SD-JWT to verify | v0.5; secure-by-default since 3.0.0 |
| `sd-jwt-key-binding` | a trailing Key Binding JWT (RFC 9901 §4.3), if present, is fail-closed verified: header `typ: kb+jwt`/`alg: EdDSA`; payload `iat`/`aud`/`nonce`/`sd_hash` all present; `sd_hash` binds the exact presented disclosure string; signature verifies under the issuer-bound holder key (`cnf.jwk`, RFC 7800) | v1.2 |
| `sd-jwt-issuer-identity` | for an SD-JWT that discloses an `issuer` claim, the key that verified the signature MUST be the key it names (`"ed25519:" + issuer_public_key_b64 == disclosed issuer`) — closes a forged-identity gap (valid signature, attacker-chosen key, trusted-sounding disclosed issuer) | WP-C1, 3.0.0 |
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

**These markers are emitted and structurally present, but nothing in the
verify path reads or enforces `vct` today.** `verify` and `evaluate_policy`
treat a bundle's `vct` value exactly like any other unexamined field inside
the issuer JWT payload — present, self-consistent (covered by the issuer
signature once that verifies), but not compared against anything. This is
the honest current boundary the `sdjwt.py` module docstring already states:
*"No X.509 / trust-list / status-list checks, no `vct` type-metadata
resolution. Full SD-JWT VC conformance is on the roadmap."*

## Not implemented — issue #27's remaining scope

Issue #27 lists three concrete items. Status of each, honestly:

1. **`vct` claim + type-metadata document resolution (offline-first:
   embedded or pinned).** The `vct` claim is emitted (above) but not
   resolved against any type-metadata document, and no offline metadata
   cache exists. **Not implemented.**
2. **Conformance vectors from the OAuth WG examples.** proofbundle's
   `conformance/` corpus (WP-W2, 3.0.0) covers native-bundle and
   decision-receipt cross-implementation vectors; it does not yet include
   SD-JWT-VC-specific vectors sourced from the OAuth WG's own examples.
   **Not implemented.**
3. **A verifier flag to require a specific `vct`.** No such flag or trust-
   policy field (`sd_jwt.expected_vct` or similar) exists in `policy.py`'s
   schema today; `_SDJWT_KEYS` is `{require_key_binding_when_cnf_present,
   expected_aud, require_nonce, max_iat_age_seconds}`. **Not implemented.**

This document does not close issue #27; it records precisely what remains
open against it, so the next PR that implements one of the three items
above has a concrete, current starting point instead of a stale "roadmap"
mention.

## Why this was scoped as documentation, not new policy code

Adding a `vct`-matching field to the trust-policy schema and
`evaluate_policy` is possible in principle — the JWT payload is already
decoded once its issuer signature verifies, so extracting `vct` from it is
mechanically simple. It was deliberately **not** done in this change: every
existing addition to `policy.py`'s crypto/trust surface in this codebase's
history has gone through the project's 6-lens adversarial review (semantic
misuse-resistance, crypto/canonicalization, policy/verifier UX,
anchors/pre-registration, interop/standards, supply-chain/governance —
`CHANGELOG.md` under WP-C1/C2/A1/TP1) plus dedicated positive AND negative
tests before landing. A same-PR trust-policy change bundled with four
unrelated documentation deliverables would not get that review depth.
Building `sd_jwt.expected_vct` for real — including its interaction with
`require_key_binding_when_cnf_present`, the "verified vs. merely present"
distinction the existing `nonce`/`aud` checks already had to get right
(`policy.py`'s `policy:nonce_present` check explicitly rejects an
*unverified* nonce), and negative tests for a forged `vct` on an unverified
SD-JWT — is scoped as a focused follow-up PR against issue #27, not folded
into this one.

## Proposed (not implemented): `proofbundle-policy/sdjwt-vc-v1`

`docs/POLICY_PROFILES.md` names this profile from the v2-audit's WP3 list
and explains why it is **not shipped**: shipping a policy JSON with a
`sd_jwt.expected_vct` (or similarly named) field that the loader accepts
but `evaluate_policy` never checks would itself be the silent vacuous-pass
trap `policy lint` (WP-TP1) exists to catch. The profile ships only once
the schema field and its enforcement exist together.

## SPEC.md cross-reference

- §6 `sd_jwt_vc` — the wire format and every check listed above, normative.
- §7 items 4–7 — the exact verification order (disclosures/issuer-signature
  before key-binding before issuer-identity before bundle-binding).
- §7f — Token Status List snapshot semantics.
- §8 — RFC 9901, RFC 7800 references.
