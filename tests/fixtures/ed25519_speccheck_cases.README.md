# Vendored fixture: `ed25519_speccheck_cases.json`

**Source:** [`novifinancial/ed25519-speccheck`](https://github.com/novifinancial/ed25519-speccheck)
`cases.json`, vendored **verbatim (byte-identical)**.

- Upstream commit: `5e4bfc4542293286e9ad3cb2b805badee00503de` (2020-10-12)
- Upstream git blob SHA: `8686dcb7eef8b6abe36ca8fa9bb10de112e63774`
- Content SHA-256: `08e47a36d9aead288664930505584f353fff113ab854f2800db1e4f5b3540450`
- License: **Apache-2.0** — full text in `ed25519_speccheck_cases.LICENSE` (copied per §4(a)).

The 12 vectors are the artifact of *"Taming the Many EdDSAs"*
([eprint 2020/1244](https://eprint.iacr.org/2020/1244), SSR'20). `tests/test_ed25519_semantics.py`
pins both the content SHA-256 (so a fixture tamper is a red test, not a silent pass) and the
per-vector ACCEPT/REJECT verdict of proofbundle's backing verifier. See SPEC.md §4a for the
documented edge-case envelope.

## Per-library verdicts (from the upstream README, verified 2026-07-11)

`V` = accept, `X` = reject. proofbundle's backing verifier (cryptography/OpenSSL) matches the
**BoringSSL / Dalek (non-strict)** row exactly:

| case:         | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 |10 |11 |
|---------------|---|---|---|---|---|---|---|---|---|---|---|---|
| BoringSSL/Dalek (= proofbundle) | V | V | V | V | X | X | X | X | X | X | X | V |
| Dalek strict  | X | X | X | V | X | X | X | X | X | X | X | X |
| LibSodium     | X | X | X | V | X | X | X | X | X | X | X | X |
| Zebra (ZIP-215) | V | V | V | V | V | V | X | X | X | V | V | V |

Divergence of proofbundle's pin vs. the other profiles is only for adversarially crafted
signatures: vs. Dalek-strict the set `{0,1,2,11}`, vs. ZIP-215 the set `{4,5,9,10}`. An honest
RFC 8032 signer over a canonical key is accepted by all of them.
