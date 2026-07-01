<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/b7n0de-logo-dark.svg">
  <img alt="b7n0de, Verified AI Work" src="assets/b7n0de-logo.svg" height="60">
</picture>

<h1>proofbundle</h1>

**Emit and verify, fully offline, portable evidence that a piece of data was
signed and anchored in a tamper-evident log — and optionally carries a
selectively disclosable credential. Pure Python, no server, no daemon, one JSON file.**

[![CI](https://github.com/b7n0de/proofbundle/actions/workflows/ci.yml/badge.svg)](https://github.com/b7n0de/proofbundle/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/proofbundle.svg?color=D6248A)](https://pypi.org/project/proofbundle/)
[![Python](https://img.shields.io/pypi/pyversions/proofbundle.svg?color=D6248A)](https://pypi.org/project/proofbundle/)
[![License: MIT](https://img.shields.io/badge/license-MIT-D6248A.svg)](LICENSE)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![SLSA build provenance](https://img.shields.io/badge/SLSA-build_provenance-D6248A.svg)](https://slsa.dev)

</div>

**At a glance:** `proofbundle emit` signs and anchors a payload; `proofbundle
verify` checks one self-contained `bundle.json` with three offline cryptographic
checks → `OK` or `FAILED`. No network, no daemon, no own crypto. 25 tests.

## Contents

- [Why](#why)
- [What it verifies](#what-it-verifies)
- [How it fits together](#how-it-fits-together)
- [Install](#install)
- [Quickstart](#quickstart)
- [Bundle format](#bundle-format-proofbundlev01)
- [Security notes and scope](#security-notes-and-scope-stated-honestly)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

## Why

Cryptographic evidence today usually needs a running service to check it.
Sigstore Rekor, Certificate Transparency and other transparency logs are
excellent, but verifying an inclusion proof normally means talking to a log
server or wiring up Go tooling. There is no small, portable, Python-native
verifier that takes one self-contained file and answers a simple question
offline:

*Were these exact bytes signed by this key, and anchored under this Merkle root,
yes or no.*

`proofbundle` is that verifier — and, since v0.2, the matching emitter. It is
the verification half of a larger idea: turning a reproducible result (for
example an AI evaluation run) into a signed, third-party-verifiable, selectively
disclosable receipt. The verifier shipped first, small and correct, so it could
be reviewed and trusted on its own; `emit_bundle` now creates bundles that
`verify_bundle` accepts, fully offline on both sides.

## What it verifies

A bundle is a single JSON document. `proofbundle` checks, offline:

1. **ed25519-signature** — the payload was signed by the stated Ed25519 key
2. **merkle-inclusion** — the payload is anchored under the stated tree root,
   using an RFC 6962 / RFC 9162 inclusion proof (the same primitive as Rekor and
   Certificate Transparency)
3. **sd-jwt** (optional) — an embedded SD-JWT selective-disclosure credential is
   well formed, and if an issuer key is given, correctly issuer-signed

The verifier treats the payload as opaque bytes. It proves that these exact
bytes were signed and anchored, not what they mean. That is on purpose: it keeps
the trusted core tiny.

## How it fits together

```mermaid
flowchart LR
    P["payload bytes"]
    P -->|"Ed25519 sign"| S["signature"]
    P -->|"RFC 6962 anchor"| M["Merkle inclusion proof"]
    SD["SD-JWT VC (optional)"] -.-> B
    S --> B["bundle.json"]
    M --> B
    B --> V{{"proofbundle verify"}}
    V --> C1["ed25519-signature"]
    V --> C2["merkle-inclusion"]
    V --> C3["sd-jwt (optional)"]
    C1 --> R{"all checks pass?"}
    C2 --> R
    C3 --> R
    R -->|yes| OK(["=> OK &nbsp; exit 0"])
    R -->|no| FAIL(["=> FAILED &nbsp; exit 1"])

    style V fill:#D6248A,stroke:#D6248A,color:#fff
    style OK fill:#D6248A,stroke:#D6248A,color:#fff
    style FAIL fill:#ef4444,stroke:#ef4444,color:#fff
```

## Install

```bash
pip install proofbundle
```

Requires Python 3.9+ and [`cryptography`](https://cryptography.io). Signature
math is delegated to `cryptography`; this project never rolls its own crypto.
The Merkle and SD-JWT logic is pure standard library.

## Quickstart

```bash
# generate a real example bundle with throwaway keys
python examples/make_example.py

# verify it
proofbundle verify examples/example_bundle.json
```

<div align="center">
<img src="assets/demo.svg" alt="proofbundle verify output: four PASS checks and OK" width="680">
</div>

Machine-readable output and a non-zero exit code on failure:

```bash
proofbundle verify --json bundle.json   # exit 0 = ok, 1 = failed, 2 = malformed
```

Emit a bundle of your own (v0.2): sign a payload with a fresh key and anchor it,
then verify it anywhere, offline.

```bash
proofbundle emit --payload-file result.json --new-key signer.key --out bundle.json
proofbundle verify bundle.json
```

Library use:

```python
from proofbundle import verify_bundle

result = verify_bundle("bundle.json")
print(result.ok)          # True / False
for check in result.checks:
    print(check.name, check.ok, check.detail)
```

Verify a consistency proof between two log states directly:

```python
from proofbundle import verify_consistency
verify_consistency(first_size, second_size, proof, first_root, second_root)  # -> bool
```

## Bundle format (`proofbundle/v0.1`)

A machine-readable JSON Schema lives at
[`schemas/proofbundle_v0_1.schema.json`](schemas/proofbundle_v0_1.schema.json).

```json
{
  "schema": "proofbundle/v0.1",
  "payload_b64": "<the exact bytes that were signed and anchored>",
  "signature": { "alg": "ed25519", "public_key_b64": "...", "sig_b64": "..." },
  "merkle": {
    "hash_alg": "sha256-rfc6962",
    "leaf_index": 1,
    "tree_size": 4,
    "inclusion_proof_b64": ["...", "..."],
    "root_b64": "..."
  },
  "sd_jwt_vc": { "compact": "<sd-jwt>", "issuer_public_key_b64": "..." }
}
```

`sd_jwt_vc` is optional. Base64 fields are standard base64; the SD-JWT compact
string uses base64url as per the spec.

## Security notes and scope, stated honestly

This is v0.1. It does exactly what it says and no more:

- Ed25519 signatures only, for both the payload and the optional SD-JWT issuer
  signature.
- SD-JWT: verifies that every presented disclosure is committed in the
  issuer-signed payload, and the issuer signature if a key is supplied. It does
  **not** verify a Key Binding JWT, an X.509 or trust-list chain, status lists,
  or `vct` type metadata. Full SD-JWT VC conformance is on the roadmap.
- The verifier does not fetch anything. Trust anchors (the signer key, the
  expected root) are inputs you supply out of band.
- No custom cryptography. Ed25519 comes from `cryptography`; Merkle hashing is
  RFC 6962.

If you find a correctness or security issue, please open an issue or see
[SECURITY.md](SECURITY.md).

## Roadmap

- **v0.1** — the offline verifier plus a real example bundle.
- **v0.2 (current release)** — the emitter: `emit_bundle` signs a payload with
  Ed25519 and anchors it as the last leaf of an RFC 6962 Merkle tree, producing
  a bundle that `verify_bundle` accepts. Available as `proofbundle emit`.
- **v0.3** — an eval-receipt emitter: wrap one evaluation framework run
  ([Inspect AI](https://github.com/UKGovernmentBEIS/inspect_ai),
  [lm-evaluation-harness](https://github.com/EleutherAI/lm-evaluation-harness))
  into a signed receipt whose payload is a minimal canonical claim, for example
  `{"suite": "...", "threshold": 0.8, "passed": true}`, optionally wrapped as an
  SD-JWT VC so a holder can disclose *passed above threshold* without revealing
  the model, weights or dataset, and carrying a cluster-bootstrap confidence
  interval, a multiple-testing correction and a preregistration hash.

That last step is the point: today no widely used AI project turns a
reproducible evaluation result into a signed, third-party-verifiable,
selectively disclosable receipt. This repository is the trustworthy verification
core that makes it possible.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and the
[Code of Conduct](CODE_OF_CONDUCT.md). Good first issues are labeled
[`good-first-issue`](https://github.com/b7n0de/proofbundle/labels/good-first-issue).
The verifier core aims to stay small, dependency-light and correct.

## License

MIT, see [LICENSE](LICENSE).

---

<p align="center"><sub>proofbundle is part of <b>b7n0de</b>, Verified AI Work &middot; <a href="https://b7n0de.com">b7n0de.com</a></sub></p>
