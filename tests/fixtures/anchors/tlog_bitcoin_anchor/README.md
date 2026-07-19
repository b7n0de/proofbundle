# Vendored `tlog-bitcoin-anchor` conformance vectors (third-party, MIT)

These files are the **upstream conformance corpus** of the C2SP draft
[`tlog-bitcoin-anchor`](https://c2sp.org/tlog-bitcoin-anchor), vendored here as
**pure data**. No file in this directory is executable and none is ever imported
or run by proofbundle; they are read only as fixtures.

- Source: `MarkovianProtocol/tlog-bitcoin-anchor`, commit
  `aaea18da69eb76b37df6c2ea2e262d4aa99cf01f` (`aaea18d`, 2026-07-09).
- License: **MIT**, Copyright (c) 2026 Markovian Protocol (see the upstream
  `LICENSE`). Attribution and per-file SHA-256 pins live in `MANIFEST.json`.
- Retrieved (UTC): 2026-07-19.

## Why they are here

They let proofbundle's **own, independent** verifier act as a *second
implementation* of the spec: `checkpoint.py` derives the checkpoint note body and
`anchors_ots.py` checks that the embedded OpenTimestamps proof commits exactly
that root. `tests/test_anchors_markovian.py::TestTlogBitcoinAnchorVectors`
reproduces the upstream expected outcomes over these vectors, fully offline (no
calendar, no Bitcoin node):

| vector | our derivation |
|---|---|
| `01-valid` | the known anchor binds to our derived note-body root (`7208a041…`); the grease line is ignored |
| `02-unknown-id` | no anchor of our identifier is present — ignored, never a rejection (forward-compat) |
| `03-tampered-body` | our derived root no longer matches the proof — **fail-closed** (`unbound`) |
| `04-tampered-proof` | the corrupted proof no longer commits our derived root — **fail-closed** |

`MANIFEST.json` digest-pins every vendored file, so any byte change is caught by
`test_tlog_bitcoin_vectors_manifest_digests_pinned`.
