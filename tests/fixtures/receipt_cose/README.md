# Fixture: `vectors.json`

The vectors of `proofbundle.receipt_cose`, the translator between a Signed Evaluation Receipt
(draft-gruszka-signed-evaluation-receipts-00) and a COSE_Sign1 Hash Envelope that cites it
(the section "COSE and SCITT" of draft-gruszka-evaluation-receipt-mappings-00, as proposed for
its next revision).

- Written by `tools/receipt_cose_vectors/generate.py`; two runs write the same bytes.
- Receipts are named by their vector id in `../signed_eval_receipt/draft1_vectors.json`.
- `forward`: 6 receipts, each with the statement bytes it gives or the refusal (no statement).
  F1 is vector M2 of the mappings draft byte for byte (SHA-256
  `5be4ea02851ee90fc0c44d65b9f77c78450255f237d7de11ce4b18636480a106`).
- `backward`: 35 statements, each with the receipt it is presented with, the relying party's
  statement keys and the one status `check_statement` must return. Three are `accepted`; every
  other vector differs from a valid statement in the one property its `what` names, and is signed
  over its own bytes where its point is not the signature.
- Keys: the receipt key and the relying party's statement key are the Draft 1 issuer test key; the
  foreign key's seed is SHA-256 over the label in `foreign_seed`; `low_order` is the all-zero
  encoding, a point of small order. PURE TEST KEYS. They MUST NOT be used for anything real.

`tests/test_receipt_cose.py` asserts every vector. `tests/test_receipt_cose_foreign.py` runs foreign
verifiers on the forward statements where the environment names them. A divergence is red and is
never adjusted silently.
