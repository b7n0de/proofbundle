# Fixture: `draft1_vectors.json`

The test vectors of draft-gruszka-signed-evaluation-receipts (Signed Evaluation Receipts), Appendix A, as
conformance tests for `proofbundle.signed_eval_receipt`.

- The file is byte-identical to the one at commit a339424e07fd58fa261d8ca3f41af5de4dcbf751 of the work branch
  that Section 11 of draft -04 names, where that implementation reached the expected verdict and the expected
  first failing step on all 66 vectors. The change log of -04 says the vector set is unchanged since -00, and
  the `source` member still names -00 for that reason.
- 66 vectors: 10 that verify (P1, P2, P4, P6 to P10, P12, P13) and 56 that do not (N1 to N61 without N8, N27
  to N29 and N47), each with the expected verdict and the first failing step of the draft's Section 5. An
  identifier is a label for the expected verdict: a P vector expects PASS, an N vector FAIL.
- `tests/test_signed_eval_receipt_conformance.py` holds the ten vectors that Appendix A.2 of -04 gives in
  full against this file, by the size and SHA-256 of each receipt as the draft states them. The other 56 are
  held only against the SHA-256 this file carries, because the complete file of Appendix A.3 lies on
  signed-evidence.org and is not read by a test.
- Compact form: every payload B is stored once under `payloads`, and a receipt names its `payload_b64` by the
  token `@Bn@` when that value is exactly the base64 of a stored B. The test rebuilds the exact receipt bytes
  and checks each against `receipt_sha256`, so a rebuilt receipt that differs by one byte is a red test.
- `source_vectors_json_sha256` is the SHA-256 of the generator output the file was built from. `emit` names
  the vectors whose bytes a producer would have to write; proofbundle has no producer of this format, and no
  test reads it.
- The keys and salts are the draft's PURE TEST material. They MUST NOT be used for any real receipt.

A divergence is red and is never adjusted silently.
