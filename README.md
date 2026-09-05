<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/b7n0de/proofbundle/main/assets/b7n0de-hase-logo-dark.png">
  <img alt="b7n0de, Verified AI Work, pink rabbit mascot over the B7N0DE wordmark" src="https://raw.githubusercontent.com/b7n0de/proofbundle/main/assets/b7n0de-hase-logo.png" width="200">
</picture>

<h1>proofbundle</h1>

[![CI](https://github.com/b7n0de/proofbundle/actions/workflows/ci.yml/badge.svg)](https://github.com/b7n0de/proofbundle/actions/workflows/ci.yml)
[![demo reproducible](https://github.com/b7n0de/proofbundle/actions/workflows/demo-reproducible.yml/badge.svg)](https://github.com/b7n0de/proofbundle/actions/workflows/demo-reproducible.yml)
[![PyPI](https://img.shields.io/pypi/v/proofbundle.svg)](https://pypi.org/project/proofbundle/)
[![Python](https://img.shields.io/pypi/pyversions/proofbundle.svg)](https://pypi.org/project/proofbundle/)
[![License: MIT](https://img.shields.io/badge/license-MIT-D6248A.svg)](https://github.com/b7n0de/proofbundle/blob/main/LICENSE)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.21110642.svg)](https://doi.org/10.5281/zenodo.21110642)

**AI eval results need receipts.**

Turn an AI evaluation result, review, decision, or action outcome into a portable receipt that can be checked offline.

proofbundle lets a verifier check **which key signed the exact bytes** and **whether those bytes changed**. It does not prove that the result is true, that the signer is trustworthy, or that the evaluation was sound.

**One file. No verification server. No network required.**

[Quick start](#quick-start) · [What it proves](#what-a-receipt-proves) · [New in 6.0.0](#new-in-600) · [New in 5.1.0](#new-in-510) · [Adoption review](https://github.com/b7n0de/proofbundle/blob/main/docs/REVIEWERS.md) · [Documentation](#documentation)

</div>

## New in 6.0.0

[proofbundle 6.0.0](https://github.com/b7n0de/proofbundle/releases/tag/v6.0.0) makes `agent-review/v0.2`
what the emitter produces without an argument. That is the one break of this MAJOR: v0.1 needs an explicit
`legacy_v01=True`, stays readable and verifiable without a deadline, and is reported as
`predicateVersionStatus: legacy` by the new dispatcher `verify_agent_review_any`. v0.2 requires
`subjectContext.disclosureCoreDigest` and derived `limitationCodes`, separates time claims by source,
accepts only the full 40-character `fixCommit`, and carries a named policy axis: `verify_agent_review_v02`
evaluates the derived codes and the coverage status against a policy that is a file (the standard one ships
in the package and its digest appears in the result), with three decisions, `accept`, `reject` and
`insufficient_evidence`.

Two things a relying party should know. A receipt whose own time claims contradict each other is now
rejected with `TIME_CLAIMS_CONFLICT` regardless of policy, and a malformed policy file is refused before it
decides (`POLICY_NOT_EVALUABLE`), never read as a permissive one. Non-fatal notes such as
`POLICY_NOT_EVALUATED` and `AGENT_REVIEW_LEGACY_V01` live in `advisory_codes`; `reason_codes` is empty for
a valid receipt. The six published v0.1 receipts verify as before; the full list is in the
[CHANGELOG](https://github.com/b7n0de/proofbundle/blob/main/CHANGELOG.md).

## New in 5.1.0

[proofbundle 5.1.0](https://github.com/b7n0de/proofbundle/releases/tag/v5.1.0) adds a new receipt kind for disclosing AI agent involvement and review in pull requests and issues.

- **Agent review receipts** bind the reviewed GitHub object, the declared review runs, coverage, findings, limitations, and the human visible disclosure.
- **Stronger subject and disclosure binding** prevents a valid receipt from silently travelling to another object or a visible block from claiming more than the signed predicate.
- **Clearer time and coverage semantics** separate declared event time from witness observation time and reject ambiguous claims of complete coverage.
- **Hardened correction chains** prevent an untrusted receipt from taking over the current position in a correction or supersession chain.
- **Executable conformance coverage** now includes the agent review predicate and the receipt envelope profile.

One behaviour change deserves attention before upgrading. `automation_summary` now adds `RECEIPT_NOT_OK` to its blockers when a receipt is not `ok`. Read the [5.1.0 changelog](https://github.com/b7n0de/proofbundle/blob/main/CHANGELOG.md#510---2026-08-31-the-profile-a-stranger-can-read--minor) before updating automation.

> **Release status**
>
> For 6.0.0 the residual-risk record was frozen BEFORE the closing audit round, by owner decision: [RESTRISIKO_600.md](https://github.com/b7n0de/proofbundle/blob/main/RESTRISIKO_600.md) lists what was known to be open when the tree was frozen, with class and funnel ruling, and its sha256 is bound inside the pre-tag receipt. The verdict of the closing round itself is recorded next to that receipt in [audit_artifacts/600/](https://github.com/b7n0de/proofbundle/tree/main/audit_artifacts/600) once the round has run; a round that had to be written down would have meant a new freeze, not an edit. The 5.1.0 verdict was `PARTIAL_GATE_NO_WITHSTANDS` with its risks in [RESTRISIKO_510.md](https://github.com/b7n0de/proofbundle/blob/main/RESTRISIKO_510.md) and [RESTRISIKO_510_NACHTRAG_20260903.md](https://github.com/b7n0de/proofbundle/blob/main/RESTRISIKO_510_NACHTRAG_20260903.md).

## Quick start

Install the core verifier.

```bash
python -m pip install proofbundle
```

Requires Python 3.10 or newer. The core installs two dependencies, `cryptography` and `rfc8785`.

Download a real example receipt and verify it offline.

```bash
curl -fsSL \
  https://raw.githubusercontent.com/b7n0de/proofbundle/main/examples/example_bundle.json \
  -o receipt.json

proofbundle verify receipt.json
```

The command uses the local file only. Its exit code is part of the public contract.

```text
0  verified
1  verification failed
2  malformed input or usage error
3  relying party policy not met
```

Run the tamper demo.

```bash
python -m pip install "proofbundle[eval]"
proofbundle demo
```

The demo checks an honest receipt, multiple tampered variants, and a sample swap. It exits nonzero if a tamper is accepted.

For a guided walkthrough, see [docs/DEMO.md](https://github.com/b7n0de/proofbundle/blob/main/docs/DEMO.md). For Inspect, see [docs/INSPECT_HAPPY_PATH.md](https://github.com/b7n0de/proofbundle/blob/main/docs/INSPECT_HAPPY_PATH.md).

## What a receipt proves

| A verified receipt can establish | A verified receipt does not establish |
|---|---|
| A stated key signed these exact bytes | The real world identity or honesty of the key holder |
| The signed content has not changed | The truth of the reported score or finding |
| A supplied Merkle inclusion or sample opening is valid | That the evaluation design was good |
| A declared threshold, provenance field, or relation is present and bound | That the computation itself was correct |
| A supplied relying party policy was met | That no omitted run or cherry picked result exists unless the chosen profile makes that claim testable |

This boundary is the product. proofbundle makes a claim attributable and tamper evident without turning the claim into truth.

Read the full [threat model](https://github.com/b7n0de/proofbundle/blob/main/THREAT_MODEL.md) and the project wide [non claims](https://github.com/b7n0de/proofbundle/blob/main/docs/NON_CLAIMS.md).

## Choose the path that matches your task

| Task | Install | Start here |
|---|---|---|
| Verify an existing receipt offline | `proofbundle` | [Quick start](#quick-start), [SPEC.md](https://github.com/b7n0de/proofbundle/blob/main/SPEC.md) |
| Emit an evaluation receipt or preregistration | `proofbundle[eval]` | [docs/DEMO.md](https://github.com/b7n0de/proofbundle/blob/main/docs/DEMO.md), [EVAL_CLAIM.md](https://github.com/b7n0de/proofbundle/blob/main/EVAL_CLAIM.md) |
| Integrate with Inspect AI | `proofbundle[inspect]` | [docs/INSPECT_HAPPY_PATH.md](https://github.com/b7n0de/proofbundle/blob/main/docs/INSPECT_HAPPY_PATH.md) |
| Add a signed agent review disclosure to a PR or issue | `proofbundle` | [5.1.0 release notes](https://github.com/b7n0de/proofbundle/releases/tag/v5.1.0), [conformance/agent_review](https://github.com/b7n0de/proofbundle/tree/main/conformance/agent_review/) |
| Verify RFC 3161 or OpenTimestamps evidence | `proofbundle[anchors]` | [docs/ANCHORS.md](https://github.com/b7n0de/proofbundle/blob/main/docs/ANCHORS.md) |
| Verify ML-DSA-44 witness cosignatures | `proofbundle[pq]` | [docs/ANCHORS.md](https://github.com/b7n0de/proofbundle/blob/main/docs/ANCHORS.md) |
| Explore the TEE attestation bridge | `proofbundle[experimental]` | [docs/EXPERIMENTAL_ENCLAVE.md](https://github.com/b7n0de/proofbundle/blob/main/docs/EXPERIMENTAL_ENCLAVE.md) |

## How it works

```text
evaluation, review, decision, or action
                    │
                    ▼
      canonical statement and commitments
                    │
                    ▼
       signature and optional Merkle proofs
                    │
                    ▼
           one portable receipt file
                    │
                    ▼
        proofbundle verification offline
                    │
                    ▼
   separate verification axes and policy result
```

The verifier checks only the evidence supplied to it. Trust anchors, expected subjects, currentness information, and policy requirements come from the relying party.

## Capabilities and maturity

proofbundle is a **beta project**. Shipped does not mean that every profile has the same maturity.

| Capability | What it provides | Maturity |
|---|---|---|
| Core receipt verification | Ed25519 signatures, RFC 6962 and RFC 9162 Merkle inclusion, strict parsing, offline verification | Shipped |
| Evaluation receipts | Metric and threshold claims, provenance, salted commitments, optional per sample audit | Shipped |
| Selective disclosure | SD-JWT with key binding for hiding selected values while preserving verifiability | Shipped |
| Agent review receipts | Signed self declarations for AI involvement and review in PRs and issues | `agent-review/v0.2` experimental in 6.0.0 and the default; `agent-review/v0.1` legacy, still readable and byte-pinned. Self declared assurance only |
| Inspect, pytest, and Hugging Face bridges | Opt in adapters for existing evaluation workflows | Shipped |
| External time evidence | RFC 3161, OpenTimestamps, and a bring your own anchor interface | Experimental, the `[anchors]` extra |
| Decision receipts | A gate's verdict over named evidence, bound to the receipts it judged, never a claim that the verdict was correct | Shipped |
| Outcome, relation, run ledger, trust pack, and verification summary predicates | Typed evidence graphs and relying party policy inputs | Experimental |
| TEE attestation bridge | RATS and EAT based enclave evidence | Preview, experimental |

The full predicate inventory and maturity labels live in [docs/predicates/README.md](https://github.com/b7n0de/proofbundle/blob/main/docs/predicates/README.md).

## Security and trust

- The verifier uses `cryptography` for Ed25519 and `rfc8785` for canonicalization. It does not implement its own cryptographic primitives.
- Correctness is checked against external RFC 6962 vectors and a real Sigstore Rekor proof, not only against the project's own receipts.
- The test suite sits behind a mutation gate and property based parser fuzzing.
- The receipt signature is Ed25519 and is not post quantum. Post quantum coverage today is limited to witness side ML-DSA-44 cosignatures. A post quantum payload signature is on the roadmap and not yet built. Detail in [docs/ANCHORS.md](https://github.com/b7n0de/proofbundle/blob/main/docs/ANCHORS.md).
- Releases are built once, carry SLSA build provenance, and are published through PyPI Trusted Publishing, where PyPI records PEP 740 attestations for the same bytes.
- The conformance corpus includes positive controls and counter proofs. Read what it does and does not establish in [CONFORMANCE.md](https://github.com/b7n0de/proofbundle/blob/main/CONFORMANCE.md).
- The 30 minute adversarial adoption path is in [docs/REVIEWERS.md](https://github.com/b7n0de/proofbundle/blob/main/docs/REVIEWERS.md).
- Security reports follow [SECURITY.md](https://github.com/b7n0de/proofbundle/blob/main/SECURITY.md).
- Release specific audit artefacts and residual risks remain visible rather than being folded into a single green status.

### OpenSSF Scorecard

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/b7n0de/proofbundle/badge)](https://scorecard.dev/viewer/?uri=github.com/b7n0de/proofbundle)

The aggregate score is a live heuristic, not a product verdict. Several checks score zero for reasons that are written down rather than hidden, one sentence per check, in [docs/SCORECARD.md](https://github.com/b7n0de/proofbundle/blob/main/docs/SCORECARD.md). The [OpenSSF self assessment](https://github.com/b7n0de/proofbundle/blob/main/docs/openssf_best_practices_self_assessment.md) walks the Best Practices criteria honestly.

## Standards and interoperability

proofbundle is a small offline receipt layer that complements, rather than replaces, systems such as in-toto, Sigstore, SCITT, transparency logs, trusted execution environments, and independent reproduction.

- [INTEROP.md](https://github.com/b7n0de/proofbundle/blob/main/INTEROP.md) compares the boundaries tool by tool.
- [docs/RECEIPT_ENVELOPE_PROFILE.md](https://github.com/b7n0de/proofbundle/blob/main/docs/RECEIPT_ENVELOPE_PROFILE.md) defines the portable envelope profile.
- [docs/IN_TOTO_PROFILE.md](https://github.com/b7n0de/proofbundle/blob/main/docs/IN_TOTO_PROFILE.md) describes the in-toto mapping.
- [docs/SCITT_CPB_MAPPING.md](https://github.com/b7n0de/proofbundle/blob/main/docs/SCITT_CPB_MAPPING.md) records the SCITT mapping.
- [docs/RELATED_WORK.md](https://github.com/b7n0de/proofbundle/blob/main/docs/RELATED_WORK.md) holds the research neighbourhood.

## Documentation

| Reader | Start here |
|---|---|
| New user | [docs/GLOSSARY.md](https://github.com/b7n0de/proofbundle/blob/main/docs/GLOSSARY.md), [docs/DEMO.md](https://github.com/b7n0de/proofbundle/blob/main/docs/DEMO.md) |
| Adopter or security reviewer | [docs/REVIEWERS.md](https://github.com/b7n0de/proofbundle/blob/main/docs/REVIEWERS.md), [THREAT_MODEL.md](https://github.com/b7n0de/proofbundle/blob/main/THREAT_MODEL.md) |
| Implementer | [SPEC.md](https://github.com/b7n0de/proofbundle/blob/main/SPEC.md), [CONFORMANCE.md](https://github.com/b7n0de/proofbundle/blob/main/CONFORMANCE.md) |
| Integrator | [INTEGRATIONS.md](https://github.com/b7n0de/proofbundle/blob/main/INTEGRATIONS.md), [docs/INSPECT_HAPPY_PATH.md](https://github.com/b7n0de/proofbundle/blob/main/docs/INSPECT_HAPPY_PATH.md) |
| Relying party | [docs/POLICY_PROFILES.md](https://github.com/b7n0de/proofbundle/blob/main/docs/POLICY_PROFILES.md), [docs/TRUST_ANCHORS.md](https://github.com/b7n0de/proofbundle/blob/main/docs/TRUST_ANCHORS.md) |
| Standards or research reader | [INTEROP.md](https://github.com/b7n0de/proofbundle/blob/main/INTEROP.md), [docs/RELATED_WORK.md](https://github.com/b7n0de/proofbundle/blob/main/docs/RELATED_WORK.md) |
| Release reviewer | [CHANGELOG.md](https://github.com/b7n0de/proofbundle/blob/main/CHANGELOG.md), [docs/PRE_TAG_AUDIT.md](https://github.com/b7n0de/proofbundle/blob/main/docs/PRE_TAG_AUDIT.md) |

## Scope

proofbundle is not a hosted transparency service, a complete in-toto client, a trusted execution environment, a consensus system, or a compliance product by itself.

It is the portable, standards oriented receipt layer between an evidence producer and a relying party.

Roadmap, stated as not yet built. A post quantum payload signature, and a CLI flag to select the content root algorithm, `jcs-sha256-v1` is the signed default today.

## Citation

Machine readable citation metadata is in [CITATION.cff](https://github.com/b7n0de/proofbundle/blob/main/CITATION.cff).

The archival software record uses concept DOI [10.5281/zenodo.21110642](https://doi.org/10.5281/zenodo.21110642). The Technical Note uses concept DOI [10.5281/zenodo.21230466](https://doi.org/10.5281/zenodo.21230466).

## Contributing

Read [CONTRIBUTING.md](https://github.com/b7n0de/proofbundle/blob/main/CONTRIBUTING.md) and the [Code of Conduct](https://github.com/b7n0de/proofbundle/blob/main/CODE_OF_CONDUCT.md).

Good first issues use the [`good-first-issue`](https://github.com/b7n0de/proofbundle/labels/good-first-issue) label. Security findings follow [SECURITY.md](https://github.com/b7n0de/proofbundle/blob/main/SECURITY.md).

The verifier core aims to remain small, dependency light, and auditable.

## License

MIT, see [LICENSE](https://github.com/b7n0de/proofbundle/blob/main/LICENSE).

---

<p align="center"><sub>proofbundle is part of <b>b7n0de</b>, Verified AI Work · <a href="https://b7n0de.com">b7n0de.com</a></sub></p>
