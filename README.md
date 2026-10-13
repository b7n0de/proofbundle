<div align="center">

<img alt="proofbundle" src="https://raw.githubusercontent.com/b7n0de/proofbundle/main/assets/proofbundle-hase-pluesch-kopf-512.png" width="180">

<h1>proofbundle</h1>

[![CI](https://github.com/b7n0de/proofbundle/actions/workflows/ci.yml/badge.svg)](https://github.com/b7n0de/proofbundle/actions/workflows/ci.yml)
[![demo reproducible](https://github.com/b7n0de/proofbundle/actions/workflows/demo-reproducible.yml/badge.svg)](https://github.com/b7n0de/proofbundle/actions/workflows/demo-reproducible.yml)
[![PyPI](https://img.shields.io/pypi/v/proofbundle.svg)](https://pypi.org/project/proofbundle/)
[![Python](https://img.shields.io/pypi/pyversions/proofbundle.svg)](https://pypi.org/project/proofbundle/)
[![License: MIT](https://img.shields.io/badge/license-MIT-D6248A.svg)](https://github.com/b7n0de/proofbundle/blob/main/LICENSE)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.21110642.svg)](https://doi.org/10.5281/zenodo.21110642)

**Portable evidence for AI work, verifiable offline. Integrity, not truth**

**One file. No verification server. No network required.**

[Quick start](#quick-start) · [What it proves](#what-a-receipt-proves) · [Current release](#current-release) · [Adoption review](https://github.com/b7n0de/proofbundle/blob/main/docs/REVIEWERS.md) · [Documentation](#documentation)

</div>

## Current release

**[v6.3.0](https://github.com/b7n0de/proofbundle/releases/tag/v6.3.0) · Beta · [Audit status and limits](https://github.com/b7n0de/proofbundle/blob/v6.3.0/audit_artifacts/630/README.md)**

[Known limitations for 6.3.0](https://github.com/b7n0de/proofbundle/blob/v6.3.0/RESTRISIKO_630.md) · [Earlier risk record](https://github.com/b7n0de/proofbundle/blob/v6.3.0/RESTRISIKO_620.md) · [Release notes](https://github.com/b7n0de/proofbundle/blob/v6.3.0/CHANGELOG.md) · [Release scope](https://github.com/b7n0de/proofbundle/blob/v6.3.0/docs/release_scope/6.3.0.md)

<details>
<summary>What was checked, and what remains open</summary>

**A feature release following 6.2.1.** The installed package adds opt-in eval-result v0.2 export and verification, changes the default DSSE key ID handling, and fixes two pytest receipt behaviours. The repository also adds SCITT statement identification material, a pilot profile and contract, and an incremental Merkle accumulator.

- **DSSE key IDs are included by default when available.** Envelopes created by `dsse.sign_envelope`, including in-toto exports, carry the signer's OpenSSH SHA256 fingerprint as an unsigned `keyid` by default when the signer exposes its Ed25519 public key. Use `keyid=""` to omit it; signers without an exposed Ed25519 public key omit it unless supplied explicitly.
- **eval-result v0.2 for the revised in-toto draft.** An opt-in export and verification under its own predicate type; exports still default to v0.1, and `--verify` accepts both.
- **Statement identification material for SCITT.** The repository includes requirements and a verification package in `docs/scitt/statement_identification/`.
- **Repository pilot material and an incremental accumulator.** A profile and vectors for the shipped decision and outcome predicates, the first pilot contract, and an incremental Merkle accumulator with a restart rule are provided under `docs/` and `tools/`.

In the tagged tree, check `audit_artifacts/630/pre_tag_receipt_v6.3.0.json` for the recorded audit command and result.

The package being published and its closing audit passing are separate facts. An audit that was not run makes no statement about the absence of defects.

[Residual risks for 6.3.0](https://github.com/b7n0de/proofbundle/blob/v6.3.0/RESTRISIKO_630.md) · [Earlier risk record](https://github.com/b7n0de/proofbundle/blob/v6.3.0/RESTRISIKO_620.md)

</details>

## Quick start

Install the verifier, download an example, then verify the local file.

```bash
python -m pip install proofbundle==6.3.0

curl -fsSLo receipt.json \
  https://raw.githubusercontent.com/b7n0de/proofbundle/v6.3.0/examples/example_bundle.json

proofbundle verify receipt.json
```

Python 3.10 or newer. Installation and download use the network. **Verification reads the local file only.**

<details>
<summary>Exit codes and the tamper demo</summary>

These exit codes apply to `proofbundle verify`, not to every command in the package.

| Exit code | Meaning |
|---|---|
| `0` | Verified |
| `1` | Verification failed |
| `2` | Malformed input or usage error |
| `3` | Relying party policy not met |

`decision verify`, `outcome verify` and `relation-statement verify` have separate contracts in their own `--help`.

To try deliberate tampering, install the evaluation extra and run the demo.

```bash
python -m pip install 'proofbundle[eval]==6.3.0'
proofbundle demo
```

The demo checks an honest receipt, tampered variants and a sample swap. It exits with a nonzero code if a tamper is accepted.

[Guided walkthrough](https://github.com/b7n0de/proofbundle/blob/v6.3.0/docs/DEMO.md) · [Inspect plugin](#plugins)

</details>

## What a receipt proves

| What verification can establish | What it does not establish |
|---|---|
| Which key signed the content | Whether you should trust that key |
| Whether signed content has changed | Whether the reported result is true |
| Whether supplied proofs and requested policy checks pass | Whether the work was correct or complete |

**A valid signature does not make a reported result true.** Checks depend on the receipt format and the policy you request.

[Threat model](https://github.com/b7n0de/proofbundle/blob/v6.3.0/THREAT_MODEL.md) · [Non claims](https://github.com/b7n0de/proofbundle/blob/v6.3.0/docs/NON_CLAIMS.md)

<a name="choose-the-path-that-matches-your-task"></a>

## Choose your task

| I want to | Start here |
|---|---|
| Verify a receipt | [Quick start](#quick-start) |
| Create evaluation evidence | [Evaluation walkthrough](https://github.com/b7n0de/proofbundle/blob/v6.3.0/docs/DEMO.md) |
| Add receipts to Inspect AI | [Inspect plugin](#plugins) |
| Assess proofbundle for adoption | [Adversarial review guide](https://github.com/b7n0de/proofbundle/blob/v6.3.0/docs/REVIEWERS.md) |

<details>
<summary>Other workflows and optional features</summary>

| Workflow | Package or reference |
|---|---|
| Evaluation receipts and preregistration | `proofbundle[eval]` · [Claim format](https://github.com/b7n0de/proofbundle/blob/v6.3.0/EVAL_CLAIM.md) |
| Inspect AI | `proofbundle[inspect]` · [Plugin setup](#plugins) |
| Agent review disclosures | [Profile inventory](https://github.com/b7n0de/proofbundle/blob/v6.3.0/docs/predicates/README.md) · [Conformance examples](https://github.com/b7n0de/proofbundle/tree/v6.3.0/conformance/agent_review) |
| RFC 3161 and OpenTimestamps | `proofbundle[anchors]` · [Anchor guide](https://github.com/b7n0de/proofbundle/blob/v6.3.0/docs/ANCHORS.md) |
| ML-DSA-44 witness cosignatures | `proofbundle[pq]` · [Anchor guide](https://github.com/b7n0de/proofbundle/blob/v6.3.0/docs/ANCHORS.md) |
| TEE attestation bridge | `proofbundle[experimental]` · [Experimental bridge](https://github.com/b7n0de/proofbundle/blob/v6.3.0/docs/EXPERIMENTAL_ENCLAVE.md) |

Shipped features do not all have the same maturity. Agent review disclosures are self declarations. Anchor and enclave paths have experimental boundaries. Check the [predicate inventory](https://github.com/b7n0de/proofbundle/blob/v6.3.0/docs/predicates/README.md) for the exact profile before relying on it.

</details>

## Plugins

proofbundle ships plugins for pytest and Inspect AI. Receipt emission is opt-in and requires an explicit pass threshold.

| Plugin | Package |
|---|---|
| pytest | `proofbundle[pytest,eval]` |
| Inspect AI | `proofbundle[inspect,eval]` |

<details>
<summary>Commands, threshold and output</summary>

**pytest**

```bash
python -m pip install 'proofbundle[pytest,eval]==6.3.0'
PROOFBUNDLE_EMIT=1 PROOFBUNDLE_THRESHOLD=0.9 pytest
```

**Inspect AI**

```bash
python -m pip install 'proofbundle[inspect,eval]==6.3.0'
PROOFBUNDLE_EMIT=1 PROOFBUNDLE_THRESHOLD=0.9 inspect eval task.py --model <model>
```

These commands use POSIX shell syntax. Run pytest in your test project; replace `task.py` and `<model>` with your Inspect task and configured model.

`0.9` is an example, not a default. pytest records `pass_rate`; Inspect selects the first available metric unless you set `PROOFBUNDLE_METRIC`. The comparison defaults to `>=`; set `PROOFBUNDLE_COMPARATOR` to change it. The threshold verdict is recorded in the receipt and does not change the test or eval exit status. Without `PROOFBUNDLE_THRESHOLD`, receipt emission is skipped.

Receipts go to the current directory by default, and the plugin prints the output path. Set `PROOFBUNDLE_OUT` to choose a file or directory. Set `PROOFBUNDLE_KEY` to the path of a file containing a 32-byte raw Ed25519 seed for a reusable signing key. Otherwise, an emitted receipt uses a temporary key and is not tied to a lasting identity.

</details>

## Documentation

| Your question | Reference |
|---|---|
| How do I implement the format? | [Specification](https://github.com/b7n0de/proofbundle/blob/v6.3.0/SPEC.md) · [Conformance](https://github.com/b7n0de/proofbundle/blob/v6.3.0/CONFORMANCE.md) |
| How do I integrate my workflow? | [pytest and Inspect plugins](#plugins) · [Other integrations](https://github.com/b7n0de/proofbundle/blob/v6.3.0/INTEGRATIONS.md) · [Glossary](https://github.com/b7n0de/proofbundle/blob/v6.3.0/docs/GLOSSARY.md) |
| Which keys and claims should I accept? | [Policies](https://github.com/b7n0de/proofbundle/blob/v6.3.0/docs/POLICY_PROFILES.md) · [Trust anchors](https://github.com/b7n0de/proofbundle/blob/v6.3.0/docs/TRUST_ANCHORS.md) |
| How is security assessed? | [Threat model](https://github.com/b7n0de/proofbundle/blob/v6.3.0/THREAT_MODEL.md) · [Security policy](https://github.com/b7n0de/proofbundle/blob/v6.3.0/SECURITY.md) |
| How was this release prepared? | [Release process](https://github.com/b7n0de/proofbundle/blob/v6.3.0/RELEASE.md) · [Pre tag audit](https://github.com/b7n0de/proofbundle/blob/v6.3.0/docs/PRE_TAG_AUDIT.md) |

<a name="how-it-works"></a>

<details>
<summary>How it works</summary>

```text
Your evaluation, review, decision or action
                    ↓
Canonical statement, signature and supplied proofs
                    ↓
One portable receipt file
                    ↓
Offline verification and explicit policy checks
```

The verifier checks the evidence it receives. Expected subjects, trusted keys, freshness requirements and acceptance policies come from the relying party. Missing evidence is not evidence that omitted work never happened.

</details>

<a name="capabilities-and-maturity"></a>

<details>
<summary>Capabilities and maturity</summary>

The core supports signed receipts and Merkle inclusion proofs. Evaluation receipts can bind metrics, thresholds, provenance and commitments. Selective disclosure can hide selected values while preserving the checks supported by its profile.

Decision receipts record a verdict over named evidence. That does not establish that the decision was correct. Outcome, relation, run ledger, trust pack and verification summary profiles have their own maturity limits.

The Rust cross verifier is experimental and advisory. Agreement on recorded cases does not prove either implementation correct, and the Rust tool is not part of the Python package.

[Predicate inventory](https://github.com/b7n0de/proofbundle/blob/v6.3.0/docs/predicates/README.md) · [Conformance boundaries](https://github.com/b7n0de/proofbundle/blob/v6.3.0/CONFORMANCE.md)

</details>

<a name="security-and-trust"></a>
<a name="openssf-scorecard"></a>

<details>
<summary>Security and trust</summary>

The core uses `cryptography` and `rfc8785`, rather than implementing its own cryptographic primitives. The test approach includes external vectors, mutation checks and parser fuzzing. Those are test signals, not a proof of correctness.

Receipt signatures are Ed25519, not post quantum. ML-DSA-44 witness cosignatures and the experimental renewal path do not turn the payload signature into a post quantum signature. See the [anchor documentation](https://github.com/b7n0de/proofbundle/blob/v6.3.0/docs/ANCHORS.md).

Build provenance and package attestations answer questions about the build and its bytes. They do not establish the truth of an evaluation or replace a security audit. See the [release process](https://github.com/b7n0de/proofbundle/blob/v6.3.0/RELEASE.md).

[Report a vulnerability](https://github.com/b7n0de/proofbundle/blob/v6.3.0/SECURITY.md) · [Conformance](https://github.com/b7n0de/proofbundle/blob/v6.3.0/CONFORMANCE.md) · [Adoption review](https://github.com/b7n0de/proofbundle/blob/v6.3.0/docs/REVIEWERS.md)

The [OpenSSF Scorecard](https://scorecard.dev/viewer/?uri=github.com/b7n0de/proofbundle) is a heuristic, not a product verdict. Read the [per check explanations](https://github.com/b7n0de/proofbundle/blob/v6.3.0/docs/SCORECARD.md) and [self assessment](https://github.com/b7n0de/proofbundle/blob/v6.3.0/docs/openssf_best_practices_self_assessment.md).

</details>

<a name="standards-and-interoperability"></a>

<details>
<summary>Standards and interoperability</summary>

proofbundle complements other evidence systems. A format mapping or an open proposal is not the same as adoption by the upstream project.

[Tool comparison](https://github.com/b7n0de/proofbundle/blob/v6.3.0/INTEROP.md) · [Receipt envelope profile](https://github.com/b7n0de/proofbundle/blob/v6.3.0/docs/RECEIPT_ENVELOPE_PROFILE.md) · [in-toto mapping](https://github.com/b7n0de/proofbundle/blob/v6.3.0/docs/IN_TOTO_PROFILE.md) · [SCITT mapping](https://github.com/b7n0de/proofbundle/blob/v6.3.0/docs/SCITT_CPB_MAPPING.md) · [Related work](https://github.com/b7n0de/proofbundle/blob/v6.3.0/docs/RELATED_WORK.md)

The [interop discussion with inspect-receipts](https://github.com/b7n0de/proofbundle/issues/147) records a specific envelope comparison. It must not be read as evidence of a second independent implementation of every predicate.

</details>

<a name="scope"></a>
<a name="citation"></a>
<a name="contributing"></a>

<details>
<summary>Scope, citation and contributing</summary>

proofbundle is not a hosted transparency service, a complete in-toto client, a trusted execution environment, a consensus system or a compliance product by itself.

[Release scope](https://github.com/b7n0de/proofbundle/blob/v6.3.0/docs/release_scope/6.3.0.md) records what belongs to this release. [Deferred work](https://github.com/b7n0de/proofbundle/blob/v6.3.0/docs/release_scope/6.3.0.md#out--the-register-not-blocking-630) is not a delivered capability.

Use [CITATION.cff](https://github.com/b7n0de/proofbundle/blob/v6.3.0/CITATION.cff) for citation metadata. The software archive has concept DOI [10.5281/zenodo.21110642](https://doi.org/10.5281/zenodo.21110642). The Technical Note has concept DOI [10.5281/zenodo.21230466](https://doi.org/10.5281/zenodo.21230466). Software and Technical Note versions are separate records.

[Contributing guide](https://github.com/b7n0de/proofbundle/blob/v6.3.0/CONTRIBUTING.md) · [Code of Conduct](https://github.com/b7n0de/proofbundle/blob/v6.3.0/CODE_OF_CONDUCT.md) · [Good first issues](https://github.com/b7n0de/proofbundle/labels/good-first-issue) · [Security reports](https://github.com/b7n0de/proofbundle/blob/v6.3.0/SECURITY.md)

</details>

<a name="license"></a>

---

[MIT license](https://github.com/b7n0de/proofbundle/blob/v6.3.0/LICENSE) · Part of [b7n0de](https://b7n0de.com), Verified AI Work
