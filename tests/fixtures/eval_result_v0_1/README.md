# eval-result v0.1 envelopes written by a released version

Two DSSE envelopes carrying `https://b7n0de.com/attestation/eval-result/v0.1` statements, written by the
released 6.1.0 wheel (`proofbundle-6.1.0-py3-none-any.whl`, sha256
`f43164161952d78afa19bdbdc324a74f104103f417f8f7c7e8734cad72235b3b`, the digest PyPI lists) with
`export_eval_result_dsse`:

- `envelope_jcs.json`: the default content root `jcs-sha256-v1`;
- `envelope_legacy.json`: `legacy-sortkeys-json-v0`, the 2.0.0 wire.

Inputs: the throwaway example key (seed `bytes(range(32))`, it signs only examples and vectors), the
claim of `tests/test_intoto_examples.py` (salt `0x11` times 16), Merkle root
`cmVjZWlwdC1tZXJrbGUtcm9vdA==`, harness `inspect_ai 0.3.244`.

They are the old evidence of gate G2: `tests/test_intoto_eval_result_v02.py` verifies both under the
v0.1 contract and checks that the v0.1 emitter still writes them byte for byte.
