# Security Policy

## Scope

`proofbundle` is a verifier. It answers whether a payload was Ed25519 signed and
anchored under a stated Merkle root, plus optional SD-JWT disclosure checks. It
does not fetch trust anchors and does not implement its own cryptographic
primitives. See the security notes in the README for the exact v0.1 scope and
limitations.

## Reporting a vulnerability

Please report suspected correctness or security issues privately by opening a
[GitHub security advisory](https://github.com/b7n0de/proofbundle/security/advisories/new)
or by email to the address in the repository profile. Do not open a public issue
for a suspected vulnerability. We aim to acknowledge within a few days.

## Supported versions

During the 0.x phase, only the latest released minor version receives fixes.

## Handling signing keys

`proofbundle emit --new-key` and `save_signer()` write a raw 32-byte Ed25519
seed. Treat it as a secret: the file is created mode 0600, must stay out of
version control (see `.gitignore`), and should never be shared. Anyone with the
seed can forge signatures under your key.
