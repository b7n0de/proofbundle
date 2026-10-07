# Fixture: `vectors.json`

The vectors of `proofbundle.receipt_cose`, the translator between a Signed Evaluation Receipt
(draft-gruszka-signed-evaluation-receipts-00) and a COSE_Sign1 Hash Envelope that cites it
(the section "COSE and SCITT" of draft-gruszka-evaluation-receipt-mappings-00, as proposed for
its next revision).

- Written by `tools/receipt_cose_vectors/generate.py`; two runs write the same bytes.
- Receipts are named by their vector id in `../signed_eval_receipt/draft1_vectors.json`.
- `forward`: 6 receipts, each with the statement bytes it gives or the refusal (no statement). The
  forward direction writes alg -19 only (owner choice B, 2026-10-04), so F2 (alg -8) is a refusal.
  F1 is vector M2 of the mappings draft byte for byte (SHA-256
  `c987b06017a54d89b3c3553c54544bc7d95f7220e6e87e1a9a6369505401260e`). The receipt type and the payload schema are the
  neutral names of 2026-10-07, so every digest and signature differs from the vectors before that day.
- `backward`: 49 statements, each with the receipt it is presented with, the relying party's
  statement keys and the one status `check_statement` must return. The relying party configures each
  statement key as a pair with the issuer URI it trusts the key for, written `[issuer URI, key name]`;
  the received `iss` selects a pair and never makes a key trusted for another issuer. Three are
  `accepted`, among them B2 with alg -8, which is read and never written (byte for byte the statement
  the forward direction wrote for -8 before 2026-10-04); B36 is B2 under a P-256 key alone. B37 to
  B42 were added on 2026-10-07: B37 is B1 with
  `iss` `https://other-issuer.example/eval`, signed with the issuer test seed (SHA-256
  `1e205e47f7f0e71ae16a0c35b55728369561d0984a83253f3f3b38b1f791ad28`), refused as `untrusted_key`; B38
  has the neutral element as R and fails rule 2 of Section 4.4 of the receipts draft, which the
  statement signature now meets with the Sig_structure in place of PAE; B39 names an entry with no
  curve point (rule 1); B40 carries an `iss` with a fragment, which is no absolute URI (RFC 3986
  section 4.3); B41 is signed under the mixed-order key, meets the cofactorless equation and is
  `untrusted_key`, because rule 2 requires a statement key of order L; B42 has an R of mixed order
  under the issuer key and is `signature_invalid` by rule 2. B43 to B45 were added later on
  2026-10-07: B43 is B1 with one byte of `iss` replaced by 0xff, which is no UTF-8, and is `malformed`
  (RFC 8949 section 5.3.1) with the signature of B1 unchanged; B44 is B1 with the empty map as a sixth
  key of the protected header, in the deterministic encoding, and is `outside_profile`; B45 is B1 with
  -1 as a sixth key, the keys ordered length first (RFC 7049 section 3.9) instead of bytewise (RFC 8949
  section 4.2.1), and is `malformed`. B46 to B48 followed the same evening, when the reader came to judge
  the bytes itself: B46 is B1 with the float 1.5 (half precision, f9 3e00) as a sixth key, B47 with true
  (f5) as a sixth key beside the integer label 1, B48 with a sixth key -1 whose value is tag 1 around the
  text "x"; each is in the deterministic encoding and signed over those bytes, and each is
  `outside_profile`, since step 1 does not check whether a tag's content is valid for that tag (RFC
  8949 section 5.3.2) and every label of another kind is step 2's case (all three were `malformed`
  under the earlier reader, which decoded with cbor2). B49 is B1 with iss
  `https://issuer.example/e[val`, signed over those bytes, presented with a pair that names exactly
  that iss: `outside_profile`, since RFC 3986 admits "[" only around an IP-literal (sections 2.2 and
  3.2.2), so iss is no absolute URI (section 4.3). Every other vector differs from a valid statement
  in the one property its `what` names, and is signed over its own bytes where its point is not the
  signature.
- Keys: the receipt key and the relying party's statement key are the Draft 1 issuer test key; the
  foreign key's seed is SHA-256 over the label in `foreign_seed`; `low_order` is the all-zero
  encoding, a point of small order; `p256` is an uncompressed P-256 point whose private scalar is
  given by `p256_seed`; `mixed_order` is the key of Draft 1 vector P11, the issuer's public point
  plus a point of order 8, with no seed of its own; `off_curve` is y = 2, which names no curve point.
  PURE TEST KEYS. They MUST NOT be used for anything real.

`tests/test_receipt_cose.py` asserts every vector. `tests/test_receipt_cose_foreign.py` runs foreign
verifiers on the forward statements where the environment names them. A divergence is red and is
never adjusted silently.
