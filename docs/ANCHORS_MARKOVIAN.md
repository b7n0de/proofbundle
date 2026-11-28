# `markovian-provenance/v1` — a worked third-party anchor type

This is an EXPERIMENTAL, opt-in **example** of a third-party anchor `type` plugged into proofbundle's
generic `anchors[]` layer via `register_anchor_type` (see [ANCHORS.md](ANCHORS.md)). It is intentionally
**not** a built-in — a third-party type is registered explicitly:

```python
from proofbundle.anchors_markovian import register
register()   # anchors[] entries with type "markovian-provenance/v1" now verify
```

## What it adds over `opentimestamps`

The built-in `opentimestamps` type proves *the data existed no later than the Bitcoin block at the attested
height*; the block's time field is set by the miner and is not a trusted clock. A Markovian stamp
adds a **named wallet**: the stamp envelope ties the committed data to a wallet name,

```
merkle_root = sha256( data_hash ":" salt ":" wallet )
```

so a verified anchor says *the target canonical root existed no later than the Bitcoin block at the
OTS-attested height, and the envelope names wallet W*. The envelope hash is self-consistent, but nothing
authenticates the wallet or shows that the wallet made the commitment: anyone can name another wallet and
recompute the hash without touching the OTS proof (see the trust model below).

## Composition, not reinvention

The Bitcoin time proof is delegated verbatim to the built-in
[`verify_opentimestamps`](../src/proofbundle/anchors_ots.py). This type inherits that verifier's exact
fail-closed lifecycle and only layers the Markovian envelope checks on top:

| Step | Check | Fail-closed status |
|---|---|---|
| 1 | envelope parses as JSON | `malformed` |
| 2 | `schema == markovian-provenance/v1` | `bad_schema` |
| 3 | `data_hash` equals the target `canonicalRoot` | `unbound` |
| 4 | `merkle_root == sha256(data_hash:salt:wallet)` (wallet bound to data) | `envelope_mismatch` |
| 5 | embedded OTS proof (delegated) | `pending` (WARN) / `upgraded_unverified` / `confirmed` |

Swapping the wallet without recomputing `merkle_root` fails step 4; a proof over different bytes fails
step 3; a PENDING OTS proof is a WARN, never a pass — same discipline as the core types.

## `proof` shape

UTF-8 JSON, base64'd into the anchor's `proof` field:

```json
{
  "schema": "markovian-provenance/v1",
  "data_hash": "<hex sha256 of the canonical pre-registration object == the target canonicalRoot>",
  "salt": "<hex>",
  "wallet": "<Markovian wallet the stamp names, not authenticated>",
  "merkle_root": "<hex sha256(data_hash:salt:wallet)>",
  "zk_commitment": "<BN128 Pedersen point, informative>",
  "block_height": 77810,
  "stamped_at": "2026-07-06T00:31:00Z",
  "ots": "<base64 detached OpenTimestamps proof over data_hash>"
}
```

## Trust model (honest)

- **Time** is an upper bound at a block height: the block's time field is part of the header that proof of work commits,
  but the miner chooses it, so it is not an accurate clock. It comes from Bitcoin via the OTS proof, verified offline against a block header
  the **relying party supplies** (WP-A1: `--bitcoin-header` / policy `anchors.bitcoin_block_headers`) from
  their own trusted (pruned) node — NOT the anchor's `frozen` header, which is producer-controlled evidence
  and is never trusted. proofbundle never fetches it. That value is the block's `hashMerkleRoot` in Bitcoin **internal (node) byte order**
  (what `bitcoind` returns and what the OTS attestation commits to), *not* the reversed display order a
  block explorer prints.
- **Wallet name** is *self-consistent within the stamp* and not authenticated: `merkle_root` ties the named
  wallet to `data_hash` by a hash anyone can recompute, and no wallet signature is checked. In this v1 the OTS anchors `data_hash` directly, so a stronger future variant
  can anchor `merkle_root` itself, putting the wallet inside the Bitcoin-committed preimage.

## Worked fixture

[`tests/fixtures/markovian_anchor_confirmed.json`](../tests/fixtures/markovian_anchor_confirmed.json) is a
real, Bitcoin-**confirmed** example: the embedded OpenTimestamps proof is anchored in **Bitcoin block
956857** (header time `2026-07-06 01:26:17 UTC`), over the RFC 8785 canonical root
`sha256:5afa7299…cc94aa`. `tests/test_anchors_markovian.py` verifies it end to end through
`anchors.verify_anchors`, alongside the fail-closed cases above.
