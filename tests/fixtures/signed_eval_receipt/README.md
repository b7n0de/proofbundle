# Fixture: `draft1_vectors.json`

The test vectors of draft-gruszka-signed-evaluation-receipts-00 (Signed Evaluation Receipts),
Appendix A, as conformance tests for `proofbundle.signed_eval_receipt`.

- 61 vectors: 8 that verify (P1, P2, P4, P6 to P10) and 53 that do not (N1 to N58 without N8,
  N27 to N29 and N47), each with the expected verdict and the first failing step of the draft's
  Section 5. The receipt has no inclusion member since 2026-10-03; the seven vectors that only
  exercised the inclusion proof (P3, P5, N8, N27, N28, N29, N47) are gone and their identifiers
  are not reused. Since 2026-10-07 the receipt type is `application/eval-receipt+json` and the
  payload schema `urn:ietf:params:eval-receipt:v1`; both enter B or the signature, so every B,
  signature and receipt digest differs from the vectors before that day, while each vector keeps
  its identifier, verdict and first failing step.
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
