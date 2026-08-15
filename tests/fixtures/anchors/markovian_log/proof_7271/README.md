# Fixture: live tlog-proof from markovianprotocol.com/log, leaf 7271

A frozen, offline-verifiable `c2sp.org/tlog-proof` bundle from a **third-party**
transparency log, together with its leaf payload and the witness keys needed to
check it. Vendored as pure data. Nothing here is fetched at test time.

Origin of this fixture: the follow-on to the merged `rootcommit` vectors,
announced by @MarkovianProtocol in `b7n0de/proofbundle` issue #7.

Digest pins, provenance and the expected verdict per vector live in
`MANIFEST.json`, in the same shape as the neighbouring `tlog_bitcoin_anchor`
manifests. `tests/test_anchors_markovian_log.py` enforces both.

## Why this exists

The `rootcommit` vectors cover the offline layering. This covers the live
counterpart: a real bundle, issued by a log we do not operate, verified with
keys we did not receive from that log.

## What was measured, 2026-08-14

| Step | Result |
|---|---|
| Bundle header | `c2sp.org/tlog-proof@v1`, index 7271, tree size 7341 |
| Inclusion path | 11 nodes, which is exactly what RFC 6962 requires for leaf 7271 in a tree of 7341 |
| Leaf hash | `Du6/Bku7hKc7cSeQ/+yA0uFbq8hzafGWQSNHRHJEwDQ=`, computed as `SHA-256(0x00 \|\| payload)` |
| Recomputed root | `uNXWHpdGz73l2cku1fdg/u3Uff0NdKOGOfjHkTiZPjE=`, byte-identical to the checkpoint root |
| `proofbundle verify-proof`, threshold 4 | `ok=true`, `log_ok=true`, `witnesses_ok=true`, `inclusion_ok=true`, exit 0 |
| Counter-test, one bit flipped in the payload | `ok=false`, `inclusion_ok=false`, `log_ok` and `witnesses_ok` still true, exit 1 |
| Cosignatures | 5 independent witnesses, `ed25519-cosignature/v1`, 2026-08-14T06:35:02Z to 06:35:04Z |

The inclusion half was recomputed with a standalone RFC 6962 implementation
before `proofbundle` was involved at all, and that recomputation is carried into
the test module rather than left in a scratch script, so the two paths keep
agreeing.

## Signature lines in the bundle, measured 2026-08-14

Eleven lines in total. Decoded length distinguishes them, because
`ed25519-cosignature/v1` is 4 byte key ID plus 8 byte timestamp plus signature.

| Bytes | Kind | Name | Count |
|---|---|---|---|
| 68 | Ed25519 note signature | `markovianprotocol.com/log` | 1 |
| 76 | `ed25519-cosignature/v1` | navigli, stagemole, little-garden, ring-any-bells, rgdd, smartit, remora | 7 |
| 2432 | ML-DSA-44 in cosignature shape | navigli, ring-any-bells, `markovianprotocol.com/log` | 3 |

Five of the seven Ed25519 witness cosignatures were verified, which meets the
log's published 4-of-7 quorum. The third ML-DSA-44 line carries the log's own
origin name rather than a witness name, so the log appears once as an Ed25519
note signature and once more in cosignature shape under a second algorithm. That
is recorded as an observation, not a finding; it has not been verified and how a
strict verifier should count it is an open question put to the log operator.

## Key provenance, the point of this fixture

Not one key comes from the audited log's own `/policy`. Sources are recorded per
line in `keys_unabhaengig.txt` and were captured with their own digests in
`SOURCES.md`.

Two witnesses named in the log's policy, `rgdd.se/poc-witness` and
`witness1.smartit.nu/witness1`, are **deliberately absent**. We could not reach
their operators' own pages, so we do not carry their keys. Five independently
sourced witnesses is already above the log's published 4-of-7 quorum.

`witness.navigli.sunlight.geomys.org` rests on **one** source (torchwood), not
two: its own page did not serve the key to a plain fetch.

## Honest limits

- This proves that leaf 7271 sits in the tree whose root that checkpoint states,
  that the checkpoint was signed by that log key, and that five foreign witnesses
  cosigned the same tree head. It proves nothing about the truth of the leaf's
  contents.
- Leaf 7271 is the log's own stream statement, not an entry we submitted. The
  public `POST /submit` path is therefore **not** exercised by this fixture.
- A single bundle is a snapshot. It does not establish that the log presents the
  same view to everyone over time; that needs witnesses observed across
  checkpoints, not one file.
- No witness in the log's policy is a Production entry on witness-network.org,
  whose Production section read "Not available yet" on 2026-08-14. Two of them,
  `transparency.dev/DEV:witness-little-garden` and
  `staging.witness.transparency.goog/ring-any-bells`, are not listed there at all
  and are dev or staging instances from elsewhere. A quorum of these carries
  integrity, not a production assurance.
- The three ML-DSA-44 lines in the bundle were **not** verified; that needs the
  optional `proofbundle[pq]` backend.
- `c2sp.org/tlog-proof` is, as of 2026-08-14, the development version on `main`;
  there is no tagged `v1.0.0`, unlike tlog-checkpoint, tlog-witness and
  tlog-cosignature.

## Why frozen and not fetched

`/proof/7271` is not stable. Fetched on 2026-08-13 it carried tree size 7340,
fetched on 2026-08-14 it carried 7341, because the checkpoint moves with the log.
Pinning the URL would pin nothing. A corpus that calls a third party at test time
measures that party's uptime instead of our correctness.

## Reproduce

```bash
proofbundle verify-proof proof_7271.tlog-proof \
  --payload-file leaf_7271.raw \
  --log-vkey     "$(grep '^markovianprotocol.com/log+' keys_unabhaengig.txt)" \
  $(grep -v '^#' keys_unabhaengig.txt | grep -v '^markovianprotocol.com/log+' | grep . | sed 's/^/--witness-vkey /') \
  --threshold 4 --json
```

Counter-test: flip byte 365 of `leaf_7271.raw` with `^ 0x01` and run the same
command. Expect `inclusion_ok=false` and exit 1 while the signatures stay valid.
