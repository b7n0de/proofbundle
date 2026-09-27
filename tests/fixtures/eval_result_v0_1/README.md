# eval-result v0.1 statements as released versions emitted them

The old evidence of gate G2: statements of `https://b7n0de.com/attestation/eval-result/v0.1`, which
released versions emitted and signed, must keep verifying under their original rules after the revised
shape (`.../eval-result/v0.2`) arrives. A valid signature alone does not show that, so each statement
here carries its origin and the verdict the released 6.1.0 verifier gives on it.

All statements are signed with the throwaway example key (seed `bytes(range(32))`, it signs only
examples and vectors) over the claim of `tests/test_intoto_examples.py` (salt `0x11` times 16, Merkle
root `cmVjZWlwdC1tZXJrbGUtcm9vdA==`, harness `inspect_ai 0.3.244`).

## Origins

- **fixture from release 6.1.0**: emitted by the published 6.1.0 wheel
  (`proofbundle-6.1.0-py3-none-any.whl`, sha256
  `f43164161952d78afa19bdbdc324a74f104103f417f8f7c7e8734cad72235b3b`, the digest PyPI lists), unpacked and
  run from its own files. Five variants: the receipt profile under both content roots, `public-model`,
  `release-gate`, and a receipt with `preRegistration` and `anchors`.
- **own reconstruction from the source at tag vX.Y.Z**: emitted by the source tree at the release tags
  v2.0.0, v2.1.0, v3.0.0, v3.3.0, v3.6.0, v4.0.0, v5.0.0, v5.1.0 and v6.0.0 (`git archive`), because the
  published artifacts of those versions were not fetched. v2.0.0 is the first tag that carries the
  emitter. Each entry names its tag commit.
- No statement from a foreign tool: none is known to emit this type.

Measured when the corpus was made: the receipt statement of every tag from v2.1.0 to v6.0.0 is byte
identical to the 6.1.0 wheel's `jcs-sha256-v1` statement, and v2.0.0's is byte identical to its
`legacy-sortkeys-json-v0` statement. Every emitting version accepts its own statement.

## Files

- `corpus.json`: 14 envelopes with origin, the emitting version's own verdict, the 6.1.0 verifier's
  verdict under the right key and under another key, and for three of them two negative variants (one
  payload byte changed with the signature kept; re-signed over bytes that are not canonical for the
  declared content root) with the 6.1.0 verifier's verdict.
- `make_corpus.py`: how `corpus.json` was made. Not a test; it needs the release tags and the wheel.
- `envelope_jcs.json`, `envelope_legacy.json`: the first two wheel envelopes as separate files, written
  before the corpus existed; the same bytes as the corpus entries.

`tests/test_intoto_eval_result_v02.py` (`TheReleasedV01Statements`, `TheV01ContractStands`) checks that
this version gives the 6.1.0 verifier's verdict on every entry and variant, that it judges each under
the v0.1 rules, that the v0.1 emitter still writes the wheel's bytes, and that the verifier dispatches
on `predicateType` to the old or the revised rules.
