# Sigstore bundle vectors

Inputs of `tests/test_sigstore_bundle.py` for `proofbundle.adapters.sigstore_bundle`. Two manifests
list every case with its input, its trust material, its contract step, the exit code and the first
failing check a reader of the specifications expects, and the sha256 of the input.

## synthetic_cases.json

Bundles of a test instance of Sigstore written by `generate_vectors.py`: a test Fulcio CA (P-384 root
and intermediate), a test CT log, a test Rekor log and a test registry key, each derived from a fixed
scalar printed in the generator, with deterministic ECDSA (RFC 6979). Each negative is intact but for
one departure, so it fails at exactly the step it names. `trust/` holds the test instance's trusted
root, a variant whose Rekor logId is not the key hash, and its registry keys document. TEST MATERIAL
ONLY: none of these keys protects anything.

Regenerate from the repository root with `python tests/fixtures/sigstore_bundle/generate_vectors.py`
(needs a cryptography release with deterministic ECDSA). The test suite checks that the committed
bytes are what the generator writes.

## public_cases.json

Public bundles, vendored as data and never edited, retrieved 2026-10-26 (UTC):

| File | Source | sha256 of the fetched file |
|---|---|---|
| `public/npm-sigstore-3.0.0-attestations.json` | https://registry.npmjs.org/-/npm/v1/attestations/sigstore@3.0.0 | `aa241f27d54d28ac4ec967d626ce5473418962c54bebf7019531e0e808a22c40` |
| `public/npm-registry-keys.json` | https://registry.npmjs.org/-/npm/v1/keys | `faf23d8753d5bb79df250f10391ac89b63ecf7743e48487a544a99c847f9c8df` |
| `public/ghcli-custom-issuer.sigstore.json` | cli/cli@4f2cfe92e3499f8581bf39db77e0a1431fa7b55c pkg/cmd/attestation/test/data/custom-issuer.sigstore.json (MIT) | `c4ce45401067b13850e76fabc1b23e018a0187f0529d435af829b83f26bc5fca` |
| `public/ghcli-reusable-workflow-attestation.sigstore.json` | same commit, reusable-workflow-attestation.sigstore.json (MIT) | see `public_cases.json` |
| `public/ghcli-sigstore-js-2.1.0-bundle.json` | same commit, sigstore-js-2.1.0-bundle.json (MIT) | see `public_cases.json` |
| `public/sigstore-python-bundle-v3-github.whl.sigstore.json` | sigstore/sigstore-python@6b4755efb554143d47f957a14f4e181fb466a4f3 test/assets/bundle_v3_github.whl.sigstore (Apache-2.0) | see `public_cases.json` |

The two npm bundles are extracted from the attestations document by the generator
(`npm-sigstore-3.0.0-provenance.sigstore.json`, `npm-sigstore-3.0.0-publish.sigstore.json`); the
signatures do not cover the bundle JSON, so the extraction changes no signed byte. The `neg-*` files
are byte edits the generator makes. The public cases verify against the public-good trusted root
already vendored at `../checkpoint/trusted_root.json` (sha256 `6494e21e...0b66`, byte-identical to
sigstore/root-signing@f39569f398fa958b314611e75c637c8d92e6bd4f targets/trusted_root.json).

The artifacts are not vendored (binary). Their digests are in `public_cases.json`; their sources:
https://registry.npmjs.org/sigstore/-/sigstore-3.0.0.tgz and, in cli/cli at the commit above,
`custom-issuer-artifact`, `reusable-workflow-artifact` and `sigstore-js-2.1.0.tgz`.

## What has no vector

- `timestamp-authority`: no public bundle with an RFC 3161 timestamp verifies offline against a
  trusted root available here. GitHub's private-instance root comes from tuf-repo.github.com, which
  was not reachable, and the test instance has no TSA because building an RFC 3161 response needs a
  CMS encoder the core dependencies do not provide.
- Rekor v2 entries, `messageSignature` bundles beyond the one refusal case, and npm's GitLab
  provenance beyond its refusal case: not implemented.
