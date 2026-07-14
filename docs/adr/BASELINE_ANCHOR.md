# Baseline: anchor stack (verified 2026-07-14)

The verified current state of proofbundle's anchor layer, before the anchor-longevity work (ADR
0006). No claim without a check; each row was grepped against the source on this branch.

## Built today (anchors v0.1)

| Anchor / layer | Module | State |
|---|---|---|
| RFC 3161 TSA | `anchors_rfc3161.py` | hardened anchor type |
| OpenTimestamps over Bitcoin | `anchors_ots.py` | the time anchor; own-frozen never trusted (WP-A1); a pending proof stays pending |
| Chia DataLayer own-register | `anchors_chia.py`, `anchors_chia_add.py` | `chia-datalayer/v1`, level i / WARN; `anchor_add` now holds an automatic in-progress lock (wallet-switch safety) |
| Witness quorum (freshness) | `checkpoint.py::witness_quorum` | k-of-n distinct witness KEY MATERIAL, ML-DSA + Ed25519 alg-agnostic |
| Transparency-log inclusion | `tlogproof.py` | tlog-proof verify |
| Relying-party root/anchor trust | SPEC §7i (3.0.0) | trust from the relying party, never from the producer's own material |

Each layer proves exactly ONE property (existence-time vs completeness vs freshness vs legal weight).
OTS/Bitcoin is the **time** layer only.

## The longevity gap (missing — the subject of ADR 0006)

| Missing | grep result | Consequence |
|---|---|---|
| Renewal chain (RFC 4998 / 6283 ERS: timestamp + hash-tree renewal) | no `ArchiveTimeStamp` / `renewal` / `rfc4998` in `src/` | an anchor cannot outlive the ageing of its hash / signature algorithm |
| Documented hash-agility (algorithm IDs, dual-hash, deprecation policy) | no `digestAlgorithm` registry / `dual_hash` in `src/` | a future SHA-256 weakness would silently devalue old anchors; there is an implicit-hash assumption |
| Offline long-term hardening (self-contained upgraded OTS in the pack, multi-calendar) | OTS proof is not upgraded/bundled by default | verification still needs an external Bitcoin-header source |

The anchor CHOICE (OTS/Bitcoin) is correct and stays; the gap is longevity mechanics (renewal +
hash-agility), addressed by ADR 0006 and its B2–B6 enablers.
