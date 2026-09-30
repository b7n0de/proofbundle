# Receipt-level vectors for section 4 of draft-ietf-scitt-receipts-ccf-profile-05

Fifteen consistency receipts, each with the older root it is checked against, the key that verifies it,
the sentence of the draft it tests, and its result under two readings of section 4. The vectors make
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
- The three list messages that asked for these cases, by address; they were not retrieved from the
  environment that built the vectors, whose network refuses mailarchive.ietf.org (tried 2026-09-30):
  - Team EMILIA, signed vectors at receipt level: https://mailarchive.ietf.org/arch/msg/scitt/FmclkmQ4eDiyOTB409P0WJSjdEk/
  - Tiago Pinto, mixed receipts and a root without sizes: https://mailarchive.ietf.org/arch/msg/scitt/eF_K0AwI5dQRDUwnLazYem0YrJA/
  - Nicholas Templeman, several proofs in one receipt: https://mailarchive.ietf.org/arch/msg/scitt/55Ausn8Rf5oyBJ2t67uAyZWpxWs/
- Our own points G1 to G8: `../SECTION4_WGLC.md`.

## Limits

- No service measured emits a -05 consistency receipt. The vectors signed by the service combine the
  service's own signature over a newer root with consistency proofs computed from the leaves of its
  ledger. This works because `vdp` sits in the unprotected header: the signature covers the protected
  header and the detached newer root only, so it stays valid whatever proofs are placed beside it.
- The ledger is a local one in virtual mode, not a production service.
- One vector, S4-10, carries a root no service would sign. It is signed with the one test key of this
  directory, `TEST_ONLY_es384_private_key.pem`: an ES384 (P-384) key made for these vectors alone,
  published on purpose, and not a key of any service, release or person. Its signatures are
  deterministic (RFC 6979), so `generate_vectors.py` reproduces the same bytes.

## The two readings

Reading A is Figure 9 of 4.2, statement by statement: the four asserts on the receipt, then
`compute_roots` for every proof, keeping the newer root of each proof whose older root equals
`older_root`, then `verify_cose` over each kept newer root. The first assert that fails is the result.

Reading B enforces every sentence of 4, 4.1 and 5 that the receipt carries enough to check, then the
two checks of Figure 9 that bind the receipt: all proofs in `vdp` are computed and must give the one
newer root the signature covers (4.1, 5); `0 < m < n` holds (4: a path of left siblings only would fold
both roots to one); the anchor MUST of 4 is checked the way it can be checked without `m` (the first
path element is a right sibling); and the CDDL is closed (5: `verifiable-proofs` has the keys -1 and
-2 and no other). The rules are B1 to B13 in `check_vectors.py`, each with its section.

Where a rule needs a tree size the receipt does not carry, a vector also holds the tree sizes the
generator used (`generator_tree_sizes`, not part of the receipt), and reading B is computed with them
too (B14). Where the receipt alone passes every rule and the sizes would decide otherwise, the vector
reads `not_decidable_without_tree_sizes`, not a guessed result.

## Files

- `S4-01.json` to `S4-15.json`: one vector each. Fields: `receipt_hex`, `older_root_hex`,
  `public_key` (kid, alg, curve, SubjectPublicKeyInfo, issuer), `sentences` (section and text of the
  draft the case tests), `reading_a`, `reading_b`, `generator_tree_sizes`,
  `consistency_proofs_decoded` (for reading; `check_vectors.py` confirms it equals the receipt),
  `construction`, `provenance`, `list_references`, and `proofbundle_reader`: the status of
  `proofbundle.scitt_ccf.verify_consistency_receipt` at the named commit, information only.
- `check_vectors.py`: recomputes both readings for every vector with the standard library, cbor2 and
  cryptography, importing nothing from proofbundle, and checks `manifest.json`.
- `generate_vectors.py`: builds the vectors from the inputs above.
- `TEST_ONLY_es384_private_key.pem`: the test key, see Limits.
- `manifest.json`: length and SHA-256 of every other file here.

## Running

```sh
pip install cbor2 cryptography
python check_vectors.py            # exit 0: every vector's recorded results reproduced
python generate_vectors.py         # from a checkout of this repository; rewrites the same bytes
```

## The vectors

| id | case | reading A | reading B |
|---|---|---|---|
| S4-01 | canonical proof 19 to 24, control | accept | accept |
| S4-02 | canonical proof 22 to 24, control | accept | accept |
| S4-03 | a second proof with one anchor bit flipped | accept | reject, B8 |
| S4-04 | two valid proofs to the same newer root, control | accept | accept |
| S4-05 | a second proof whose older and newer roots are both other roots | accept | reject, B8 |
| S4-06 | a valid consistency proof and an inclusion proof to another root | accept | reject, B9 |
| S4-07 | a valid consistency proof and an inclusion proof to the same root, control | accept | accept |
| S4-08 | unchanged tree, m = n, left siblings only | accept | reject, B10 |
| S4-09 | deeper anchor, the first sibling a left one | accept | reject, B11 |
| S4-10 | root N1 over R_6 with one right sibling, test key | accept | not decidable without tree sizes, B14 |
| S4-11 | empty consistency-proof array | reject, `assert(len(proofs) > 0)` | reject, B4 |
| S4-12 | a vdp key other than -1 and -2 | accept | reject, B3 |
| S4-13 | one tag flipped, negative control | reject, `assert(len(payloads) > 0)` | reject, B11 |
| S4-14 | one signature byte flipped, negative control | reject, `assert(verify_cose(...))` | reject, B13 |
| S4-15 | the older root matches no proof | reject, `assert(len(payloads) > 0)` | reject, B12 |
