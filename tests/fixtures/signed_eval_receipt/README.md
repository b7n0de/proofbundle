# Fixture: `draft1_vectors.json`

The test vectors of draft-gruszka-signed-evaluation-receipts-00 (Signed Evaluation Receipts),
Appendix A, as conformance tests for `proofbundle.signed_eval_receipt`.

- 65 vectors: 9 that verify (P1, P2, P4, P6 to P10, P12) and 56 that do not (P11, and N1 to N60
  without N8, N27 to N29 and N47), each with the expected verdict and the first failing step of the
  draft's Section 5. Only insignificant whitespace may follow the JSON text (owner choice of
  2026-10-07): P12, the receipt of P1 followed by one line feed, verifies; N60, the B of P1 followed
  by one line feed and signed anew, fails at step 5, because B is not its own RFC 8785 form. Rule 2 of the draft's Section 4.4 requires A and R to have order L (owner choice
  of 2026-10-07): P11, a receipt under the mixed-order test key (the issuer test key's public point
  plus a point of order 8, no seed, a pure test key) whose signature meets the cofactorless
  equation, fails at step 11 for rule 2 of the key; N59, under the issuer key with an R of mixed
  order, fails at step 11 for rule 2 of R, where the cofactored equation holds. No other vector
  changed its verdict or first failing step. The receipt has no inclusion member since 2026-10-03; the seven vectors that only
  exercised the inclusion proof (P3, P5, N8, N27, N28, N29, N47) are gone and their identifiers
  are not reused. Since 2026-10-08 the receipt type is
  `application/vnd.signed-evidence.eval-receipt+json` and the payload schema
  `https://signed-evidence.org/eval-receipt/v1`, names under the project domain signed-evidence.org
  (owner choice of 2026-10-08); both enter B or the signature, so every B, signature and receipt digest
  differs from the vectors before that day, while each vector keeps its identifier, verdict and first
  failing step.
- Compact form: every payload B is stored once under `payloads`, and a receipt names its
  `payload_b64` by the token `@Bn@` when that value is exactly the base64 of a stored B. The test
  rebuilds the exact receipt bytes and checks each against the SHA-256 the draft publishes
  (`receipt_sha256`), so a rebuilt receipt that differs by one byte is a red test.
- `source_vectors_json_sha256` is the SHA-256 of the draft's generator output the fixture was
  built from.
- The keys and salts are the draft's PURE TEST material. They MUST NOT be used for any real
  receipt.

`tests/test_signed_eval_receipt_conformance.py` asserts, for every vector, the draft's verdict and
first failing step, and for P1, P2, P6, P7, P8, P9 and P10 that the emitter produces the draft's bytes.
A divergence is red and is never adjusted silently.
