# Receipt-level vectors for section 4 of draft-ietf-scitt-receipts-ccf-profile-05

Fifteen consistency receipts, each with the older root it is checked against, the public key used to check it,
the tree sizes a caller holds, the sentence of the draft it tests, and its result under two readings of
section 4, reading B both size-free and size-aware. The vectors make
the readings comparable; they do not presume either, and which one the draft means is for the working
group to decide.

## Sources

- Draft: https://github.com/ietf-wg-scitt/draft-ietf-scitt-receipts-ccf-profile, commit
  `e729c2ec037ac763d0cf422bb58a219f8d6a02f4` (tag `draft-ietf-scitt-receipts-ccf-profile-05`), file
  `draft-ietf-scitt-receipts-ccf-profile.md`, SHA-256
  `7efdb7aa934ab0cfc1093e99932f7d2efd39bb66f5bf43594806d7b282ca0077`, retrieved again on 2026-09-30 and
  byte-equal to the copy read on 2026-09-25. Section numbers follow the heading order of that file:
  4 CCF Consistency Proofs, 4.1 CCF Consistency Proof Signature, 4.2 Consistency Proof Verification
  Algorithm, 5 Usage in COSE Receipts. Figure 9 is "CCF Consistency Receipt Verification" in 4.2, the
  ninth titled figure of the file.
- CCF: https://github.com/microsoft/CCF, tag `ccf-7.0.17`, commit
  `cdcb74c7365dbe4b3fad739868bfa9802d77ed75` (as recorded in `../vendored_encoder_result.json`).
- Service: https://github.com/microsoft/scitt-ccf-ledger, commit
  `00101f769d872711356e080fbb089ac48589c60a`, built and run locally on CCF 7.0.17 in virtual mode, one
  node, issuer `127.0.0.1:8000`.
- The ledger's three signed states (tree sizes 19, 22 and 24) and the service's COSE_Sign1 over the
  newest root come from `tests/fixtures/scitt_ccf/local_ledger_consistency.json`; the ledger's 25 leaves
  from `../consistency_result.json`, read with the ccf package 7.0.17.
- The three list messages that asked for these cases. Cowork, the owner's review session, read them in
  the archive on 2026-09-30 and confirmed the sentences cited here. The environment that built the
  vectors could not reach mailarchive.ietf.org (tried 2026-09-30):
  - Team EMILIA, signed vectors at receipt level: https://mailarchive.ietf.org/arch/msg/scitt/FmclkmQ4eDiyOTB409P0WJSjdEk/
  - Tiago Pinto, the 96 bytes and the root N1: https://mailarchive.ietf.org/arch/msg/scitt/eF_K0AwI5dQRDUwnLazYem0YrJA/
  - Nicholas Templeman, several proofs in one receipt: https://mailarchive.ietf.org/arch/msg/scitt/55Ausn8Rf5oyBJ2t67uAyZWpxWs/
- Our own points G1 to G8: `../SECTION4_WGLC.md`.

## Limits

- No service measured emits a -05 consistency receipt. Thirteen vectors carry the service's own
  signature over the newer root R_24 unchanged, beside consistency proofs computed from the leaves of
  its ledger; S4-14 carries that signature with one bit flipped, so it does not verify; S4-10 is signed
  with the test key. The unchanged signature stays valid whatever proofs are placed beside it, because
  `vdp` sits in the unprotected header: the signature covers the protected header and the detached
  newer root only.
- The ledger is a local one in virtual mode, not a production service.
- One vector, S4-10, carries a deliberately noncanonical root. It is signed with the one test key of this
  directory, `TEST_ONLY_es384_private_key.pem`: an ES384 (P-384) key made for these vectors alone,
  published on purpose, and not a key of any service, release or person. Its signatures are
  deterministic (RFC 6979), so `generate_vectors.py` reproduces the same bytes. Its protected header
  carries the txid `2.7`, as a service's header carries the txid of the state it signs.
- The relation between a txid and a tree size (next section) is measured on one ledger, not stated by
  -05.

## The two readings

Reading A is Figure 9 of 4.2, statement by statement: the four asserts on the receipt, then
`compute_roots` for every proof, keeping the newer root of each proof whose older root equals
`older_root`, then `verify_cose` over each kept newer root. The first assert that fails is the result.

Reading B applies the listed wire, root-binding and signature checks. B10 and B11 are derived necessary shape conditions, not complete checks of strict growth or the canonical anchor.

The size-free result runs B1–B13 without tree sizes and reports passes_size_free_checks when they pass. The separate size-aware result adds B14 using the supplied older_size and newer_size. Passing the size-free checks does not establish 0 < m < n or the canonical anchor position.

## The reader's two successes

The vectors record `proofbundle.scitt_ccf.verify_consistency_receipt` without and with the sizes, as
information. `confirmed_without_tree_sizes` means that the implemented checks passed without both
tree sizes being available. It does not establish strict growth or the full anchor rule. `confirmed`
requires both sizes and the corresponding checks; the sizes must be bound to the roots under the
caller's trust model and our local txid-to-size rule.

## Tree sizes

- `older_size`: the size of the ledger tree whose root `older_root` is. A caller takes it from the txid
  of the inclusion receipt that verified `older_root`.
- `newer_size`: the seqno of the receipt's own `ccf.v1` txid.
- Measured on the ledger above: the signature at seqno s signs the tree of s leaves, leaf 0 being 32
  zero bytes, not a transaction (`MTH(leaves[0:s])` equals the signed root at seqnos 19, 22 and 24).
  -05 does not relate a txid to a tree size (`../SECTION4_WGLC.md`, G5).

## Files

- `S4-01.json` to `S4-15.json`: one vector each. Fields: `receipt_hex`, `older_root_hex`,
  `public_key` (kid, alg, curve, SubjectPublicKeyInfo, issuer), `sentences` (section and text of the
  draft the case tests), `reading_a`, `reading_b_size_free`, `older_size`, `newer_size`,
  `tree_sizes_note`, `reading_b_size_aware`, `generator_tree_sizes` (the sizes each proof was built for),
  `consistency_proofs_decoded` (for reading; `check_vectors.py` confirms it equals the receipt),
  `construction`, `provenance`, `list_references`, and `proofbundle_reader`: the status of
  `proofbundle.scitt_ccf.verify_consistency_receipt` at the named commit without and with the sizes,
  information only.
- `check_vectors.py`: recomputes reading A and both results of reading B (rules B1 to B14, each with
  its section) for every vector with the standard library, cbor2 and cryptography, importing nothing
  from proofbundle, and checks `manifest.json`. It does not recompute the recorded reader statuses.
- `generate_vectors.py`: builds the vectors from the inputs above.
- `TEST_ONLY_es384_private_key.pem`: the test key, see Limits.
- `manifest.json`: length and SHA-256 of every other file here.
- `LICENSE`: the MIT License of proofbundle for this directory, and the Revised BSD License with the
  copyright notice of the IETF Trust and the draft's authors for the parts of `check_vectors.py` that
  transcribe Figures 7 and 9 of -05 (IETF Code Components, TLP section 4).

## Running

```sh
pip install cbor2 cryptography
python check_vectors.py            # exit 0: every vector's recorded readings A and B reproduced
python generate_vectors.py         # from a checkout of this repository; rewrites the same bytes
```

## The vectors

| id | case | m, n | reading A | reading B, size-free | reading B, size-aware |
|---|---|---|---|---|---|
| S4-01 | canonical proof 19 to 24, control | 19, 24 | accept | passes_size_free_checks | accept |
| S4-02 | canonical proof 22 to 24, control | 22, 24 | accept | passes_size_free_checks | accept |
| S4-03 | a second proof with one anchor bit flipped | 19, 24 | accept | reject, B8 | reject, B8 |
| S4-04 | two valid proofs to the same newer root, control | 19, 24 | accept | passes_size_free_checks | accept |
| S4-05 | a second proof whose older and newer roots are both other roots | 19, 24 | accept | reject, B8 | reject, B8 |
| S4-06 | a valid consistency proof and an inclusion proof to another root | 19, 24 | accept | reject, B9 | reject, B9 |
| S4-07 | a valid consistency proof and an inclusion proof to the same root, control | 19, 24 | accept | passes_size_free_checks | accept |
| S4-08 | unchanged tree, m = n, left siblings only | 24, 24 | accept | reject, B10 | reject, B10 |
| S4-09 | deeper anchor, the first sibling a left one | 22, 24 | accept | reject, B11 | reject, B11 |
| S4-10 | Tiago Pinto's N1 = HASH(R_6 \|\| HASH(d[6])), path [right leaf 6], test key, txid 2.7 | 6, 7 | accept | passes_size_free_checks | reject, B14 |
| S4-11 | empty consistency-proof array | 19, 24 | reject, `assert(len(proofs) > 0)` | reject, B4 | reject, B4 |
| S4-12 | a vdp key other than -1 and -2 | 19, 24 | accept | reject, B3 | reject, B3 |
| S4-13 | one tag flipped, negative control | 19, 24 | reject, `assert(len(payloads) > 0)` | reject, B11 | reject, B11 |
| S4-14 | one signature byte flipped, negative control | 19, 24 | reject, `assert(verify_cose(...))` | reject, B13 | reject, B13 |
| S4-15 | the older root matches no proof | 22, 24 | reject, `assert(len(payloads) > 0)` | reject, B12 | reject, B12 |
