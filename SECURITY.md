# Security Policy

## Scope

`proofbundle` is a verifier. It answers whether a payload was Ed25519 signed and
anchored under a stated Merkle root, plus optional SD-JWT disclosure checks. It
does not fetch trust anchors and does not implement its own cryptographic
primitives. See the security notes in the README for the exact v0.1 scope and
limitations.

## Reporting a vulnerability

Please report suspected correctness or security issues **privately** — do not open a public issue.
The preferred, tracked channel is a
[GitHub security advisory](https://github.com/b7n0de/proofbundle/security/advisories/new)
(private to the maintainers); the repository profile also lists a contact email as a fallback.

Coordinated disclosure: we aim to **acknowledge within 3 business days**, agree a fix and a public
disclosure timeline, and disclose **within 90 days** of a valid report. If a fix needs longer we
will say so and coordinate a date with you rather than let it slip silently. Reporters who want
credit are named in the advisory and CHANGELOG.

## Supported versions

During the 1.x phase, only the latest released minor version receives fixes.

## Handling signing keys

`proofbundle emit --new-key` and `save_signer()` write a raw 32-byte Ed25519
seed. Treat it as a secret: the file is created mode 0600, must stay out of
version control (see `.gitignore`), and should never be shared. Anyone with the
seed can forge signatures under your key.

## Release integrity

Releases are published to PyPI via **Trusted Publishing** (OIDC, no long-lived token) with
`pypa/gh-action-pypi-publish` (>= v1.11.0). Once the first release is published, each release file
**will carry PEP 740 digital attestations** generated automatically, verifiable on PyPI (the Integrity
API exposes the attestation bundle, publisher = GitHub) or with `pip install`'s attestation verification,
plus an SLSA build-provenance attestation (SLSA v1.2 attestation model). The release workflow builds the
artifact ONCE and gates the PyPI upload on a sha256 match against the attested subject, so the published
bytes are exactly the attested bytes (see `RELEASE.md`). proofbundle is published on PyPI; whether a
given release file carries the PEP 740 attestations is verifiable on PyPI's Integrity API.
