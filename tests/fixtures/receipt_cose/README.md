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
- `backward`: 36 statements, each with the receipt it is presented with, the relying party's
  statement keys and the one status `check_statement` must return. Three are `accepted`, among them
  B2 with alg -8, which is read and never written (byte for byte the statement the forward direction
  wrote for -8 before 2026-10-04); B36 is that statement under a P-256 key alone. Every
  other vector differs from a valid statement in the one property its `what` names, and is signed
  over its own bytes where its point is not the signature.
- Keys: the receipt key and the relying party's statement key are the Draft 1 issuer test key; the
  foreign key's seed is SHA-256 over the label in `foreign_seed`; `low_order` is the all-zero
  encoding, a point of small order; `p256` is an uncompressed P-256 point whose private scalar is
  given by `p256_seed`. PURE TEST KEYS. They MUST NOT be used for anything real.

`tests/test_receipt_cose.py` asserts every vector. `tests/test_receipt_cose_foreign.py` runs foreign
verifiers on the forward statements where the environment names them. A divergence is red and is
never adjusted silently.
