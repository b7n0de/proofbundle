# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-01

### Added
- Offline evidence bundle verifier (`proofbundle/v0.1` schema).
- RFC 6962 / RFC 9162 Merkle inclusion and consistency proof verification.
- Ed25519 signature verification via `cryptography`.
- Minimal SD-JWT selective-disclosure verification (EdDSA issuer signatures,
  disclosure-digest commitment check).
- `proofbundle verify` command line interface with human and JSON output.
- Example bundle generator (`examples/make_example.py`) and a real example bundle.
- Full unit test suite (Merkle round-trip across sizes, signature, bundle, CLI).
- Emitter roadmap stub for v0.2 (bundle emission) and v0.3 (eval receipts).
