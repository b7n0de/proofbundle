# Fixture: `draft1_vectors.json`

The test vectors of draft-gruszka-signed-evaluation-receipts-00 (Signed Evaluation Receipts),
Appendix A, as conformance tests for `proofbundle.signed_eval_receipt`.

- 65 vectors: 9 that verify (P1 to P9) and 56 that do not (N1 to N56), each with the expected
  verdict and the first failing step of the draft's Section 6.
- Compact form: every payload B is stored once under `payloads`, and a receipt names its
  `payload_b64` by the token `@Bn@` when that value is exactly the base64 of a stored B. The test
  rebuilds the exact receipt bytes and checks each against the SHA-256 the draft publishes
  (`receipt_sha256`), so a rebuilt receipt that differs by one byte is a red test.
- `source_vectors_json_sha256` is the SHA-256 of the draft's generator output the fixture was
  built from.
- The keys and salts are the draft's PURE TEST material. They MUST NOT be used for any real
  receipt.

`tests/test_signed_eval_receipt_conformance.py` asserts, for every vector, the draft's verdict and
first failing step, and for P1, P2, P3, P6, P7, P8 and P9 that the emitter produces the draft's bytes.
A divergence is red and is never adjusted silently.
