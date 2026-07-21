# Vendored `rootcommit` conformance vectors (third-party, MIT)

These files are the upstream **`rootcommit`** conformance vectors of
[`tlog-bitcoin-anchor`](https://github.com/MarkovianProtocol/tlog-bitcoin-anchor),
vendored here as **pure data**. No file in this directory is executable and none
is ever imported or run by proofbundle; they are read only as fixtures.

- Source: `MarkovianProtocol/tlog-bitcoin-anchor`, commit
  `90342026a89cacf83c94771b349080db1208ba94` (`9034202`, 2026-07-20). This is the
  commit that first carries per-file SHA-256 digests in the upstream manifests.
- License: **MIT**, Copyright (c) 2026 Markovian Protocol (see the upstream
  `LICENSE`). Attribution and per-file SHA-256 pins live in `MANIFEST.json`.
- Retrieved (UTC): 2026-07-21. All 11 digests were independently recomputed on
  retrieval and match `MANIFEST.json` (11/11).

## Two layers

- `vectors/` holds **`rootcommit/v1`** (4 vectors + upstream `manifest.json`): a
  Bitcoin OpenTimestamps attestation over a domain-separated preimage that folds
  the checkpoint Merkle root together with an operator wallet address.
- `vectors_sig/` holds **`rootcommit/v2-sig`** (5 vectors + upstream
  `manifest.json`): the same committed preimage plus the wallet's own
  EIP-191/secp256k1 signature over that commitment.

Both layers share the committed preimage digest
`4d1cc236c3872701bb27f9e27fad315e153eeb43a767a2cae958a3bb4014e771` and operator
wallet `0xdaE76a3C848CafD453dB5EBF8cEb0DbBA7610273`. The upstream `manifest.json`
in each directory carries the expected per-vector outcome and is vendored
verbatim.

## What proofbundle verifies here (No-Overclaim)

`MANIFEST.json` **digest-pins** every vendored file, so any byte change is caught
by `test_rootcommit_vectors_manifest_digests_pinned`.

proofbundle ships its **own second-implementation** verifier for the `rootcommit`
format in `src/proofbundle/anchors_rootcommit.py`
(`tests/test_anchors_rootcommit.py`). It independently rebuilds the
domain-separated preimage from each checkpoint's own `(origin, size, root)` plus
the wallet carried in the anchor line, recomputes `SHA-256(preimage)`, and reuses
proofbundle's OpenTimestamps binding verifier to check the proof commits exactly
that value. Mutating the root **or** the wallet breaks the binding, which is the
property the base `ots/v1` layer does not have.

| layer | what our verifier reproduces | needs |
|---|---|---|
| `rootcommit/v1` (4 vectors) | full binding + reject outcomes; our rebuilt preimage hashes to the upstream `4d1cc236…` commitment | `proofbundle[anchors]` |
| `rootcommit/v2-sig` binding (root/wallet/proof tamper) | full reject outcomes | `proofbundle[anchors]` |
| `rootcommit/v2-sig` signature (EIP-191 recovery to the bound wallet) | the two signature-specific outcomes | additionally a secp256k1 + keccak-256 backend |

NO-OVERCLAIM: without the secp256k1/keccak backend the v2-sig signature outcomes
are honestly reported as `sig_ok=None` / status `no_sig_lib` and their tests
**skip**, never a silent pass. Enabling that optional backend completes the v2-sig
signature check.

### Consumer contract (Berkeley-hardened)

The top-level `reject` boolean encodes the **binding** outcome only. A relying
party MUST NOT read `reject is False` as "anchored" or "signature-valid":

- **temporal:** `reject is False` includes a `pending` OpenTimestamps proof (which
  is offline-forgeable), so a genuine Bitcoin anchor needs `ots_ok is True` /
  status `confirmed` (which requires a relying-party block header). Binding is not
  anchoring.
- **signature (v2-sig):** without the `[rootcommit]` backend `sig_ok` is `None`
  and the signature is not enforced, so require `sig_ok is True`, never
  `reject is False` alone.
- **multiplicity:** more than one rootcommit anchor on one checkpoint is rejected
  (status `multiple_anchors`); `known_anchors` is the real count, so a prepended
  forged anchor cannot silently mis-attribute a wallet.
