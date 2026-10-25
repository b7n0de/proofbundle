# Leaf and node hashing of CCF receipts, re-measured against -05

The -04 finding that the CCF tree hashes leaves without the 0x00 prefix of RFC 9162 was re-measured
against draft-ietf-scitt-receipts-ccf-profile-05, the CCF 7.0.17 code, and one real CCF 7.0.17 ledger
state. -05 still writes leaf and node hashes without prefixes, section 4.2 hashes nodes that way itself,
and CCF computes exactly that. Fixed leaf lengths separate a leaf from a node only while a verifier
enforces the ccf-leaf sizes: proofbundle's reader accepted 0 of 23 forged leaves, and a transcription
of the 3.2 pseudo-code that checks no sizes accepted 23 of 23.

## SOURCES

- -05: https://github.com/ietf-wg-scitt/draft-ietf-scitt-receipts-ccf-profile
- commit `e729c2ec037ac763d0cf422bb58a219f8d6a02f4`, tag `draft-ietf-scitt-receipts-ccf-profile-05`, file `draft-ietf-scitt-receipts-ccf-profile.md`
- file sha256 `7efdb7aa934ab0cfc1093e99932f7d2efd39bb66f5bf43594806d7b282ca0077`, retrieved 2026-09-25
- -04 for comparison: tag `draft-ietf-scitt-receipts-ccf-profile-04`, commit `54f887f0eef26bdac4e667d63b10d328b54a5442`
- CCF C++: https://github.com/microsoft/CCF, tag `ccf-7.0.17`, commit `cdcb74c7365dbe4b3fad739868bfa9802d77ed75`, retrieved 2026-09-25
- CCF Python: https://pypi.org/project/ccf/7.0.17/, Apache-2.0, installed 2026-09-25
- `ccf/ledger.py` sha256 `50fdfa83766886fd64576d146b3bbe208194c6798b59486f0b97d8139a2a46f3`
- `ccf/merkletree.py` sha256 `6bbd9f52f6cadd9ca98af291dfeafbd86e14c9eba6201f31ed9b3d0dd4675ea7`
- prefix values: https://github.com/transparency-dev/merkle at `fbbcd741c3d1c69d8498487baa8edc9e5824847c`, `rfc6962/rfc6962.go` lines 25 and 26, `RFC6962LeafHashPrefix = 0`, `RFC6962NodeHashPrefix = 1`, retrieved 2026-09-25
- the ledger: run 2 of `../consistency_probe.py` on a local scitt-ccf-ledger at `00101f769d872711356e080fbb089ac48589c60a`, CCF 7.0.17, virtual mode, one node, written 2026-09-25
- line numbers below are lines of the -05 markdown source; the rendered draft was not reachable

## PINS

- ledger files, as read (`result.json`, `ledger_files`):
  - `ledger_1-9.committed`: 81329 B, sha256 `125e047461e6422e273c61ae6a8657e15777b98eb76673146c1444eea51d151b`
  - `ledger_10`: 16548 B, sha256 `8a7653046acb4da0324ff4e67b0f9dfff84295d303140bac2a23300e520f0f4a`
- -05 inclusion receipts of the same run (`result.json`, `receipt_files`):
  - `older.receipt.cbor`: 472 B, sha256 `6427bd5fddee00e40e63e6b8c48dcc6a879eb9a0368f293ac52e42c738c203fe`
  - `middle.receipt.cbor`: 508 B, sha256 `ca5350165bf33fb5255a9b14d31210a772f3f54c457b3620a67dd4e2819542d9`
  - `newer.receipt.cbor`: 545 B, sha256 `a8e70390ed9a783ad70b5442fdba8d1f8f07856ae12b1e8d4f51e083232941d6`
- `measure.py`, `same_digests.py`: CPython 3.12.3, ccf 7.0.17, cbor2 5.9.0, cryptography 50.0.1
- `reader_forgery.py`: CPython 3.11.15, cbor2 6.1.4 (the [scitt] extra), proofbundle from this repository's `src`
- measured 2026-09-26; first on proofbundle `30aa897ee86dcc34a4499389b58412b52047f3d1`, then again with these committed scripts on `ff919e01f2e91d579e34ef468dfe0de665d25a83`, the same values in every output

## FILES

| file | what |
|---|---|
| `measure.py` | reads the ledger, recomputes the signed roots under four hashing rules, lengths, receipts against leaves, forgeries against a lax 3.2 transcription |
| `result.json` | its output |
| `forgery_inputs.json` | the 23 interior nodes of the last signed state with their paths, written by `measure.py` for `reader_forgery.py` |
| `reader_forgery.py` | the same forgeries against proofbundle's reader, with a positive control |
| `reader_result.json` | its output |
| `same_digests.py` | the RFC 9162 proofs for the run-2 pairs under both hashings, against the -05 path |
| `same_digests_result.json` | its output |

## WHAT WAS MEASURED

1. -05 still writes the leaf hash without a prefix. Section 2.1, Figure 2, lines 120 to 123: "MTH({d[0]}) = HASH(d[0])."; Figure 3, lines 127 to 130: "MTH(D_n) = HASH(MTH(D[0:k]) || MTH(D[k:n]))". New in -05, section 2.2 lines 158 and 167: d[i] is the 96-byte concatenation internal-transaction-hash || HASH(internal-evidence) || data-hash.
2. Sections 4 and 4.2 use this hashing: the node rule directly (4.2, lines 285, 286, 288), the roots and the anchor by reference (4, lines 250 and 264), and the leaf rule by reference through the older root recomputed from an inclusion receipt (4.1, line 272). `same_digests_result.json`: the RFC 9162 section 2.1.4.1 proof for 19 to 24, 22 to 24 and 19 to 22 equals the -05 anchor and path in 14 of 14 digests under this document's hashing, and in 0 of 14 under RFC 9162's own hashing (0x00 leaf, 0x01 node).
3. CCF 7.0.17 hashes a leaf as SHA-256 over its components with no prefix (`src/node/rpc/claims.h` lines 15 to 39), keeps leaf 0 as 32 zero bytes (`src/node/history.h` line 449), and hashes an interior node as SHA-256 over the 64-byte left || right (`src/node/history.h` lines 237 to 250, full SHA-256 in `src/crypto/openssl/hash.cpp` lines 141 to 175). `result.json`: the service's COSE signature verifies 9 of 9 roots computed without prefixes, and 0 of 9 under RFC 9162 prefixes, leaf prefix only, node prefix only, or RFC 9162 prefixes with leaf 0 kept.
4. Leaf preimages are 96 bytes in 24 of 24 transactions, and interior node preimages 64 bytes in 23 of 23; this ledger has 0 leaves of the 64-byte form the code also knows. Forgeries at the last signed state, every interior node presented as a leaf:
   - A, children as components: a lax 3.2 transcription 0 of 23; the reader 0 accepted.
   - B, sizes and types unchecked (evidence = the right child's own preimage, data-hash empty): the lax transcription 23 of 23; the reader 0 accepted, 22 refused for the -05 CDDL sizes, 1 for an empty path.
   - B32, as B with a 32-byte data-hash, so the leaf preimage is 96 bytes again and not a 64-byte node's: the reader 0 accepted of 23, 22 computed another root, 1 refused for an empty path (`reader_result.json`, `B32`).
   - The right child's preimage is valid UTF-8 in 0 of 23, so strict CBOR text blocks B independently of the sizes.
   - The real newer receipt computes the signed root through the same reader harness (positive control).

## LIMITS

- The RFC 9162 text, section 2.1.1: NOT MEASURABLE here; this environment's proxy refuses rfc-editor.org and the datatracker. The prefix values are from transparency-dev/merkle, above.
- Two one-leaf root values quoted for -04 were NOT REPRODUCED. The input behind them is unknown here, and they are not recorded in this repository.
- Whether microsoft/scitt-verifier at `bd6fb8ba` enforces the 32-byte leaf sizes: NOT MEASURED.
- A production CCF service, other CCF versions, a ledger with 64-byte or write-set-only leaves: NOT MEASURED.
- Whether RFC 9162 prefixes would change the 4.2 acceptance of deeper anchors (G1 of `../SECTION4_WGLC.md`): NOT MEASURED.
- The CCF C++ was read, not built; its behaviour is measured through the ledger it wrote.
- The ledger and the receipts are not stored here: the ledger files are binary (AGENTS.md line 21). They are pinned above by length and SHA-256, and a rerun needs a ledger produced the same way.

## RUNNING IT

    python3 measure.py --ledger LEDGER_DIR --run RUN_DIR       # ccf 7.0.17
    python3 same_digests.py --ledger LEDGER_DIR                # ccf 7.0.17
    python3 reader_forgery.py --run RUN_DIR                    # cbor2 6.1.4, after measure.py

---

Prepared with AI agent involvement, reviewed and submitted under human oversight.
