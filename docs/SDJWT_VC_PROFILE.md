# SD-JWT VC minimal profile (3.2.0 O7, EXPERIMENTAL)

A relying-party profile check for SD-JWT Verifiable Credentials, layered on the existing key-binding verifier
(`kbjwt.py`). It is a verification LAYER, not a signed predicate type. EXPERIMENTAL: API and wire format may
change without deprecation.

Implementation: [`src/proofbundle/sdjwt_vc.py`](../src/proofbundle/sdjwt_vc.py).

## What it enforces

- **`typ = dc+sd-jwt`** — the issuer JWT header MUST carry the SD-JWT VC media type; `alg = none` / absent is
  rejected.
- **`vct` allowlist** — the `vct` (verifiable credential type) claim is REQUIRED and MUST be on the relying
  party's allowlist. An unknown `vct` is fail-closed, never trusted.
- **type-metadata integrity (optional)** — when `requireTypeMetadataIntegrity` is set, the `vct`'s metadata is
  trusted ONLY from an offline cache the relying party passes in, matched by a `vct#integrity` (sha256) digest.
  A missing offline entry is fail-closed FAIL — **never a fetch**.
- **holder binding** — `requireKeyBinding` defaults to True: an SD-JWT presented under this profile WITHOUT a
  valid key binding (`kbjwt.verify_key_binding`) is FAIL. An unknown/unbound presentation does not verify.

## SSRF safety is structural, not a filter

The module performs **no network I/O whatsoever** — there is no code path that opens a socket. A `vct` that
looks like a URL is treated as an opaque type identifier and matched against the allowlist / offline cache; it
is **never dereferenced**. A malicious `vct` or metadata URL therefore cannot drive a request. Offline metadata
is supplied by the caller as a plain dict. This is a stronger guarantee than a URL allowlist filter: there is
nothing to filter because nothing is ever fetched.

## API

- `validate_vc_policy(policy)` — fail-closed policy validation (`vctAllowlist` required non-empty;
  `requireTypeMetadataIntegrity` / `requireKeyBinding` booleans; unknown key rejected).
- `check_vc_profile(compact, policy, *, offline_metadata=None)` — profile-only check → `{ok, typ_ok, vct_ok,
  metadata_integrity_ok, vct, errors}`. Read `ok`.
- `verify_sdjwt_vc(compact, policy, *, holder_pubkey=None, expected_aud=None, expected_nonce=None,
  offline_metadata=None)` — full check = profile AND (when required) holder key binding → `{ok, profile,
  binding}`.

## No-Overclaim

A passing profile check attests the credential's type is allowlisted and (optionally) its metadata integrity
and holder binding hold — **never** that the credential's CLAIMS are true. The issuer-signature trust anchor
for the SD-JWT itself is a separate concern (the holder key comes from the issuer-signed `cnf.jwk`).
