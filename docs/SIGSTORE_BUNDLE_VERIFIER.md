# Verifying GitHub Artifact Attestations and npm provenance

`proofbundle.adapters.sigstore_bundle.verify_sigstore_bundle` checks one Sigstore bundle against
trust material that the relying party supplies, offline. It reads the bundles that GitHub Artifact
Attestations (`actions/attest-build-provenance`, `actions/attest`) and npm provenance
(`npm publish --provenance`, and the registry's publish attestation) consist of. It was written from
the specifications pinned in `SPEC_PIN` and imports no Sigstore client library.

Status: PROPOSED, Python only. The Rust second verifier has no counterpart yet
(`scripts/rust_parity_registry.json`, PENDING), and there is no CLI command yet.

## What it reads

- Bundle media types 0.1, 0.2 and 0.3, in both spellings of 0.3. Only the lowerCamel JSON names are
  read: a proto field name (`verification_material`) and a member the message does not define are
  refused by name, and a duplicate member anywhere is refused by the strict parser.
- A DSSE envelope with exactly one signature whose payload is an in-toto Statement. A
  `messageSignature` bundle is refused as not implemented (exit 2).
- Rekor v1 entries of kind `dsse` 0.0.1 and `intoto` 0.0.2. Rekor v2 entries are refused as not
  implemented (exit 2).
- RFC 3161 timestamps, only with `rfc3161-client` installed (the `[anchors]` extra). Without it, a
  bundle that carries one is refused as not verified (exit 2), never passed.
- At most 32 log entries and 32 timestamps per bundle.
- Keys in exactly one encoding each: the SubjectPublicKeyInfo of ECDSA P-256 or P-384 with an
  uncompressed point, or of Ed25519. No generic key loader runs, and an Ed25519 key is checked
  through `signature.verify_ed25519_pinned`, which refuses a weak trust anchor.

## Where trust comes from

Only from the relying party:

- `trusted_root`: the `trusted_root.json` of the Sigstore instance it trusts, as wire bytes. For
  public repositories and npm this is the public-good root (vendored for the tests at
  `tests/fixtures/checkpoint/trusted_root.json`); for private repositories it is GitHub's own.
- `artifact_digest`: the digest of the artifact it holds, `sha256:<hex>`, `sha512:<hex>`, or an SRI
  string such as npm's `dist.integrity`. It is required.
- `identity` (certificate profiles): exact values for `issuer`, `san` and the Fulcio extensions
  (`build_signer_uri`, `source_repository_uri`, `source_repository_identifier`,
  `runner_environment`, ...). At least one key must name a workflow or repository, because a Fulcio
  certificate is issued to anyone with an OIDC token. `issuer` defaults to
  `https://token.actions.githubusercontent.com`.
- `registry_keys` (npm-publish): the registry's keys document (`/-/npm/v1/keys`) as wire bytes.
- `version_document` (npm-publish, optional): the registry's version document of the package
  (`https://registry.npmjs.org/<name>/<version>`) as wire bytes. With it, the registry signatures in
  `dist.signatures` are checked (`registry-signature`, contract NP-10 and NP-14); without it, a note
  says they were not.
- `package_json` (npm-provenance, optional): the `package/package.json` of the tarball the relying
  party holds, as wire bytes. The reader does not open the tarball; that this package.json comes
  from the tarball whose digest is `artifact_digest` is the relying party's to ensure.

The `gh attestation verify` flags map onto `identity` as follows: `--repo` to
`source_repository_uri`, `--owner` to `source_repository_owner_uri`, `--cert-identity` to `san`,
`--signer-workflow` to `build_signer_uri` (exact, no regular expression), `--signer-digest` to
`build_signer_digest`, `--source-ref` to `source_repository_ref`, `--source-digest` to
`source_repository_digest`, `--deny-self-hosted-runners` to `runner_environment: github-hosted`.
This mapping is read from the documentation of `gh`; `gh` itself was not run.

## Profiles

| Profile | Signer | Statement | Predicate |
|---|---|---|---|
| `github-artifact-attestation` | Fulcio certificate | v1 | SLSA Provenance v1, buildType `https://actions.github.io/buildtypes/workflow/v1` or the slsa-framework buildType of 2024 |
| `npm-provenance` | Fulcio certificate | v1 | SLSA Provenance v1, buildType `https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1` |
| `npm-publish` | registry key by hint | v0.1 or v1 | `https://github.com/npm/attestation/tree/main/specs/publish/v0.1` |

## Order of checks

Each check is reported by name; the first integrity failure ends the run.

1. `verifier-config`, `readable`, `media-type` (exit 2 on failure)
2. `bundle-structure`, `certificate` or `public-key`, `signature`
3. per log entry: `tlog-entry`, `tlog-body`, `tlog-set`, `tlog-inclusion`, `tlog-checkpoint`; then
   `tlog-threshold`, `timestamp-authority`
4. `signing-time`: at least one verified time (an SET or an RFC 3161 timestamp; an unsigned
   `integratedTime` is none), inside the leaf's validity or before the registry key's expiry
5. `certificate-chain` at every verified time (hybrid model), `sct`
6. `statement`, `predicate-type`, `predicate`, and for npm-publish with a version document
   `registry-signature`
7. relying-party requirements, each judged: `identity`, `subject-digest`, `subject-name`, and with
   a package.json `package-json` (exit 3)

`package-json` holds npm's provenance requirement that package.json carry "a public `repository`
that matches (case-sensitive) where you are publishing with provenance from" (contract NP-15). The
package.json must name the package of a subject of the statement (`pkg:npm/<name>@<version>`) and a
repository that reads as the certificate's `source_repository_uri`, compared case-sensitively. Read
as a GitHub repository are npm's normalized object form `{"type": "git", "url":
"git+https://github.com/<owner>/<repo>.git"}`, the shortcut forms `<owner>/<repo>` and
`github:<owner>/<repo>`, and the https, git, ssh and scp-like URLs of the repository, each with or
without `.git`. The registry's own comparison at publish time is not published, so these forms are
this reader's choice, taken from npm's package.json documentation (npm/cli@311ff5ef
`docs/lib/content/configuring-npm/package-json.md`, "repository").

`registry-signature` reads the version document as npm's open manifest and uses `name`, `version`
and `dist`. It must name the publish attestation's package and version, and `dist.integrity` must be
a digest of the attestation's subject. Every signature in `dist.signatures` (at least one, at most
32) must name a key of the keys document by `keyid` and verify, ECDSA P-256 with SHA-256, over
`${name}@${version}:${dist.integrity}` (npm docs, "About registry signatures"). Its key must not have
expired at the publish attestation's verified time. npm's own client compares the expiry with the
registry's unsigned `time` field instead.

`predicate` holds the predicate to SLSA Provenance v1 and to its buildType's own rules. The external
parameters are read closed, as both buildTypes ask of a consumer: `workflow` for the actions.github.io
buildType; `workflow`, `inputs`, `release` and `vars` for the slsa-framework one, with at most one of
`inputs` and `release`. The actions.github.io buildType also requires the four internal parameters
and a resolved dependency naming the source commit, both MUST in that specification; the
slsa-framework buildType makes them optional. Both buildTypes "MUST NOT be used for any other event type" than `create`, `release`,
`push` and `workflow_dispatch` (contract GH-05, enforced since the owner decision of 2026-10-26):
the event the predicate states (`internalParameters.github.event_name`) and the build trigger in the
certificate must each, where stated, be one of the four, and at least one must be stated. The
certificate is read too, because Fulcio copied its trigger from the OIDC token and the predicate
could hide the run's event. An attestation that `actions/attest-build-provenance` wrote for a run
of another event, such as `pull_request` or `schedule`, therefore fails here with exit 1.

`predicate-binding` is a note, not a check (owner decision of 2026-10-26). It compares the predicate
with the certificate: repository, ref, commit, build config, run invocation, trigger, repository and
owner IDs, and the builder (the signer workflow for the actions.github.io buildType,
`https://github.com/actions/runner/<runner_environment>` for the slsa-framework one). These
equalities come from the producers' source code, not from a specification; they are pinned in
`SPEC_PIN`. Every verdict that read an SLSA predicate carries one note beginning
`predicate-binding: agrees` or `predicate-binding: differs`, and no exit code depends on it.

## Deviations from the specifications

Unknown members of the DSSE envelope are refused (contract DS-03). DSSE says of the envelope:
"Producers, or future versions of the spec, MAY add additional fields. Consumers MUST ignore
unrecognized fields." (secure-systems-lab/dsse `envelope.md`). This reader refuses a member of
`dsseEnvelope`, or of its one signature, that it does not define, with `bundle-structure` (exit 1),
as it refuses one anywhere else in the bundle. In a bundle the envelope is the protobuf message
`io.intoto.Envelope`, whose JSON mapping refuses an unknown field by default, and a member that one
reader ignores while another reads it gives the same bytes two meanings. The owner decided so on
2026-10-26. Vectors: `neg-dsse-envelope-unknown-member`, `neg-dsse-signature-unknown-member`.

## What a pass does not say

The predicate is written by the workflow that signed it. A pass says who signed what and when, as
far as the trusted root vouches for it. It does not say the build was honest. Not checked, and
named in every verdict: revocation, log consistency over time, freshness of the trusted root, and
Rekor's `envelopeHash` and `content.hash`, whose preimage no specification pins. `safeForAutomation`
is false in every verdict.

## Vectors

`tests/fixtures/sigstore_bundle/`: synthetic bundles of a test instance (fixed test keys,
deterministic ECDSA, `generate_vectors.py`) that fail at exactly the step they name, and public
bundles from the npm registry and the cli/cli test data with byte edits of them. Each case carries
its expected exit code and failing check and is verified twice (`tests/test_sigstore_bundle.py`).
