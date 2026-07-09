# proofbundle 2.0.0 — release notes draft

Consolidates the 2.0.0b1–b3 beta line plus the Phase B P0 core (WP-B1/B2/B3) into the 2.0.0 final.
Draft — the tag + PyPI publish is Owner-gated (the `pypi` GitHub Environment requires a reviewer).

## Headline

The 2.0.0 line finishes the verify-core hardening: `merkle.hash_alg` is REQUIRED, `verify` separates
what it proves (CRYPTO) from what you must decide (POLICY) and what the issuer claims (ASSURANCE), and
a machine-readable **trust policy** makes a relying party's trust decision first-class, fail-closed and
offline. The experimental TEE-attestation bridge and `anchors[]` stay experimental-gated as in the
betas.

## BREAKING changes (with migration)

1. **`merkle.hash_alg` is REQUIRED** (WP-B1). A bundle without it is rejected (the verifier already did
   this since v1.6; the SPEC/schema now match). *Migration*: add `"hash_alg": "sha256-rfc6962"` to the
   `merkle` object — every emitter since v1.6 already writes it, so only hand-authored/pre-v1.6 bundles
   are affected.
2. **`verify` human output no longer prints a bare `=> OK`** (WP-B2). It prints `CRYPTO:` / `POLICY:` /
   `ASSURANCE:` / `LIMITATIONS:`. *Migration*: a script grepping `verify` stdout for `=> OK` must switch
   to `CRYPTO: OK`. Other subcommands keep `=> OK`.
3. **New exit code 3** (WP-B2/B3): `verify` now exits `3` for "crypto OK but a supplied `--policy` was
   NOT satisfied", distinct from `1` (crypto failure). *Migration*: treat exit 3 as a policy outcome,
   not a crypto error.

## Added

- **`proofbundle --version`** prints package version + pinned SPEC revision + JSON schema id + usable
  extras (WP-B1, closes #28).
- **`verify --json` stable single-field contract** (WP-B2): `schema_ok … crypto_ok policy_ok assurance
  sd_jwt_issuer_verified warnings[] limitations[]`; not-applicable checks are `null`, never silently
  true.
- **Trust policy v0.1 + `verify --policy`** (WP-B3): `schemas/trust_policy_v0_1.schema.json`,
  `proofbundle.policy`, fail-closed + offline; pins issuer (by public key), alg, schema, hash alg,
  SD-JWT aud/nonce/key-binding, freshness, assurance level + pre-registration. `examples/trust_policy_
  strict.json`, `docs/TRUST_ANCHORS.md` policy profile.
- **THREAT_MODEL.md** "Misuse: reading OK as truth".

## Honest boundaries (v0.1)

- Trust-policy `status` section is declared but not enforceable without a status-snapshot input →
  fails closed when enabled.
- `require_nonce` binds nonce PRESENCE in a verified KB-JWT; the value binds via `--nonce`.
- No TUF-style key rotation; `allowed_issuers[]` is a static pinned list.

## Verification (release gate — to run on the tagged commit)

- [ ] full test suite (549+), mutation gate, property/fuzz
- [ ] `proofbundle demo` (honest verifies, six tampers fail, sample swap caught)
- [ ] offline-verify assertion (no network in the verify core)
- [ ] wheel built once, installed in a clean venv, `--version` + `verify` smoke
- [ ] tag `v2.0.0` on the merged `main` HEAD (never a feature branch), release workflow attests ==
      publishes, **`pypi` environment approval by the Owner**, then verify PyPI arrival
