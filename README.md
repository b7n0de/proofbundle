<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/b7n0de/proofbundle/main/assets/b7n0de-hase-logo-dark.png">
  <img alt="b7n0de, Verified AI Work, pink rabbit mascot over the B7N0DE wordmark" src="https://raw.githubusercontent.com/b7n0de/proofbundle/main/assets/b7n0de-hase-logo.png" width="200">
</picture>

<h1>proofbundle</h1>

**AI eval results need receipts.**

Turn an AI evaluation result into one portable, offline-verifiable receipt. It proves *who signed
these exact bytes* and *that nothing changed since* — not that the number is true. Ed25519 + RFC 6962
Merkle, one file, no server, no network.

[![CI](https://github.com/b7n0de/proofbundle/actions/workflows/ci.yml/badge.svg)](https://github.com/b7n0de/proofbundle/actions/workflows/ci.yml)
[![demo reproducible](https://github.com/b7n0de/proofbundle/actions/workflows/demo-reproducible.yml/badge.svg)](https://github.com/b7n0de/proofbundle/actions/workflows/demo-reproducible.yml)
[![PyPI](https://img.shields.io/pypi/v/proofbundle.svg)](https://pypi.org/project/proofbundle/)
[![Python](https://img.shields.io/pypi/pyversions/proofbundle.svg)](https://pypi.org/project/proofbundle/)
[![License: MIT](https://img.shields.io/badge/license-MIT-D6248A.svg)](https://github.com/b7n0de/proofbundle/blob/main/LICENSE)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.21110642.svg)](https://doi.org/10.5281/zenodo.21110642)

**Reviewing this for adoption?** Start with the 30-minute adversarial audit path: **[docs/REVIEWERS.md](https://github.com/b7n0de/proofbundle/blob/main/docs/REVIEWERS.md)**.

</div>

## 60-second try (offline)

```bash
pip install "proofbundle[eval]"
proofbundle demo   # honest receipt => OK, six tampers each => FAILED, sample swap caught
```

The demo runs entirely in memory and exits non-zero if any tamper slips through, so it doubles as a
self-test.

```bash
# verify a real hosted receipt without writing any code — the verify runs fully offline:
curl -fsSL https://raw.githubusercontent.com/b7n0de/proofbundle/main/examples/example_bundle.json -o receipt.json
proofbundle verify receipt.json        # CRYPTO: OK   (exit 0 ok · 1 fail · 2 malformed · 3 policy)
```

Emit your own receipt, apply a trust policy, start from a shipped template, or run the Inspect-native
path (METR Task Standard / UK-AISI ecosystem, mockllm, no API key): **[docs/DEMO.md](https://github.com/b7n0de/proofbundle/blob/main/docs/DEMO.md)** ·
Inspect walkthrough **[docs/INSPECT_HAPPY_PATH.md](https://github.com/b7n0de/proofbundle/blob/main/docs/INSPECT_HAPPY_PATH.md)**.

## The problem

Every AI eval number you read — a safety benchmark, a capability score, a leaderboard entry — is an
**unverifiable claim**. You trust the lab. There is no portable way to check, offline, that a result
was signed by a stated party, has not been altered, and covers the samples it claims.

proofbundle is that check: a small MIT-licensed Python tool (a compact, auditable trusted verify
core that depends only on [`cryptography`](https://cryptography.io); the package installs one more
hard dependency, the RFC 8785 canonicalizer [`rfc8785`](https://pypi.org/project/rfc8785/), used on
the emit and canonicalization paths) that turns a result into a signed receipt
anyone can verify from a single file. In plain terms it is the cash-register receipt of an AI test
result: it shows who claimed the number and that nobody quietly changed it, not that the test was
good. Without a receipt there is nothing to check at all.

## What a receipt proves, and what it doesn't

| ✅ It proves | ❌ It does **not** prove |
|---|---|
| These exact bytes were signed by this key (**authorship**) | That the number is **true** |
| Nothing changed since signing (**integrity**, Ed25519 + RFC 6962) | That the **issuer is honest** |
| The result is attributable to a stated issuer | That the **eval was well-designed** |
| A threshold was met while hiding the model/dataset (salted commitments) | That there was **no cherry-picking** — unless pre-registered |
| Optionally: individual samples, offline-auditable (per-sample Merkle) | That the **computation was correct** — that needs a TEE or independent reproduction |

This boundary is the point, not a weakness. A receipt makes a claim **attributable, tamper-evident,
and — with pre-registration and per-sample auditing — bounded and spot-checkable**. Full detail:
**[THREAT_MODEL.md](https://github.com/b7n0de/proofbundle/blob/main/THREAT_MODEL.md)**.

## How it fits together

*(diagram renders on GitHub — [view it there](https://github.com/b7n0de/proofbundle#how-it-fits-together); PyPI shows the source)*

```mermaid
flowchart LR
    H["eval harness<br/>inspect_ai · lm-eval · promptfoo · pytest"] --> A["adapter → signed claim<br/>salted commitments · provenance · samples root"]
    A --> R["receipt<br/>one portable file"]
    R --> V{{"proofbundle verify — offline"}}
    V --> C["signature · Merkle inclusion · SD-JWT/KB ·<br/>witness quorum · status list · sample openings"]
    C --> OK(["CRYPTO: OK / FAILED"])
    style V fill:#D6248A,stroke:#D6248A,color:#fff
    style OK fill:#D6248A,stroke:#D6248A,color:#fff
```

proofbundle is a **practical, released, offline verifier — complementary to TEE and zero-knowledge
approaches**, not a replacement for any of them. The neighbourhood, honest about the line each one
crosses that a receipt does not (maturity labels stated so nothing reads as a settled standard):

| Neighbour | What it contributes that a receipt does not | Maturity |
|---|---|---|
| **K-Veritas** ([arXiv 2605.08586](https://arxiv.org/abs/2605.08586)) | the academic case for tamper-evident, execution-bound experiment reports | preprint |
| **Attestable Audits** ([arXiv 2506.23706](https://arxiv.org/abs/2506.23706)) | that the computation actually ran, inside a trusted enclave | preprint |
| **BenchJack** ([arXiv 2605.12673](https://arxiv.org/abs/2605.12673)) | whether the benchmark itself is gameable (reward-hacking) | preprint |
| **Evaluation Cards** ([arXiv 2606.09809](https://arxiv.org/abs/2606.09809)) | a structured, human-facing account of what a result means | preprint |
| in-toto / Sigstore, SCITT / Rekor v2, OpenSSF Model Signing | artifact-provenance, public transparency, model-artifact signing | stable |

Tool-by-tool comparison: **[INTEROP.md](https://github.com/b7n0de/proofbundle/blob/main/INTEROP.md)**.

## What's in the box

Each line is a one-sentence summary; the linked doc carries the exact flags, exit codes and
version history (see also [CHANGELOG.md](https://github.com/b7n0de/proofbundle/blob/main/CHANGELOG.md)).

- **Core** — Ed25519 signature + RFC 6962 / 9162 Merkle inclusion, verified fully offline against a
  real [Sigstore Rekor](https://docs.sigstore.dev/) proof, so correctness is not self-referential.
- **Eval receipts** — a signed claim (`metric ⋈ threshold`, `n`, salted model/dataset commitments,
  assurance level, provenance) from your run. [EVAL_CLAIM.md](https://github.com/b7n0de/proofbundle/blob/main/EVAL_CLAIM.md)
- **Selective disclosure** — SD-JWT ([RFC 9901](https://datatracker.ietf.org/doc/rfc9901/)) with Key
  Binding: prove a threshold while withholding the exact score (unsigned or unbound disclosures fail closed).
- **Transparency-log interop** — C2SP `tlog-checkpoint` / cosignature / `.tlog-proof`, with
  post-quantum **ML-DSA-44** witness cosignatures and optional Token-Status-List revocation.
- **Per-sample audit** — an auditor challenges random indices (fresh nonce or **public randomness
  beacon**); 300 samples catch 1% sample-doctoring at 95% confidence, regardless of run size — a
  challenge the issuer chose itself does not give this guarantee.
- **Pre-registration** — `proofbundle prereg <plan>` commits to the protocol before the run, so
  best-of-many publishing becomes visible.
- **Integrations** — opt-in inspect_ai end-of-task hook, pytest plugin, and a Hugging Face Community
  Evals bridge. [INTEGRATIONS.md](https://github.com/b7n0de/proofbundle/blob/main/INTEGRATIONS.md)
- **External time anchors** *(beta, `[anchors]` extra)* — optional evidence of *when* a receipt
  existed, from a party the producer does not control; RFC 3161 and OpenTimestamps built in, plus a
  bring-your-own-type interface. Trust comes only from the relying party. [docs/ANCHORS.md](https://github.com/b7n0de/proofbundle/blob/main/docs/ANCHORS.md)
- **Universal content root** *(`jcs-sha256-v1`)* — SHA-256 over the RFC 8785 (JCS) canonical bytes of
  the full pre-signature statement, so a content root survives counter-signing and key rotation;
  cross-implementation interop proven. [ADR 0002](https://github.com/b7n0de/proofbundle/blob/main/docs/adr/0002-universal-content-root.md)
- **Decision & action-outcome receipts** — a signed *decision* (verdict, policy boundary,
  digest-bound evidence, and what was *not* checked) and a separately signed *outcome* with role
  separation (executor ≠ decision maker) — never a claim that the decision was correct.
  [decision-receipt.md](https://github.com/b7n0de/proofbundle/blob/main/docs/predicates/decision-receipt.md) · [action-outcome.md](https://github.com/b7n0de/proofbundle/blob/main/docs/predicates/action-outcome.md)

## Install

```bash
pip install proofbundle                 # core: offline verify + plain emit (two deps: cryptography, rfc8785)
pip install "proofbundle[eval]"          # + eval receipts, prereg, and the demo (RFC 8785 JCS canonicalizer)
pip install "proofbundle[inspect]"      # inspect_ai adapter + hook
pip install "proofbundle[pq]"           # verify ML-DSA-44 (post-quantum) witness cosignatures
```

Requires Python 3.10+. The verify path never rolls its own crypto — Ed25519 comes from
`cryptography`; Merkle hashing is RFC 6962.

## Post-quantum posture (honest)

proofbundle is **not** "quantum-safe" as a whole. Its hash-based layers (SHA-256, RFC 6962 / 9162
Merkle, RFC 8785 canonicalization, and the OpenTimestamps / `chia-datalayer` anchors) stay secure —
Grover only halves SHA-256's effective strength, leaving a ~128-bit quantum margin. The Ed25519
receipt signature (and the RFC 3161 anchor's classical TSA certificate) are quantum-vulnerable to
Shor. The attack that matters is **back-dated forgery**, and the defense is a hash-based time anchor:
it proves the original receipt existed *before* any such capability, so a forged receipt has no
matching anchor. The witness side already carries post-quantum **ML-DSA-44** (FIPS 204) cosignatures;
a post-quantum *payload* signature is on the roadmap. Detail: [docs/ANCHORS.md](https://github.com/b7n0de/proofbundle/blob/main/docs/ANCHORS.md).

## Cite this work

If proofbundle helped your evaluation pipeline, please cite it. Machine-readable metadata is in
[`CITATION.cff`](https://github.com/b7n0de/proofbundle/blob/main/CITATION.cff). The archival software record is on Zenodo under concept
DOI [10.5281/zenodo.21110642](https://doi.org/10.5281/zenodo.21110642); the Technical Note (design write-up) under concept DOI
[10.5281/zenodo.21230466](https://doi.org/10.5281/zenodo.21230466), also linked from [b7n0de.com/proofbundle](https://b7n0de.com/proofbundle).

## Docs

| For… | Read |
|---|---|
| Skeptics (why not SHA-256 / Sigstore / trust the issuer) | [docs/FAQ.md](https://github.com/b7n0de/proofbundle/blob/main/docs/FAQ.md) |
| New to this? plain-terms glossary | [docs/GLOSSARY.md](https://github.com/b7n0de/proofbundle/blob/main/docs/GLOSSARY.md) |
| Reviewers (30-minute adversarial audit path) | [docs/REVIEWERS.md](https://github.com/b7n0de/proofbundle/blob/main/docs/REVIEWERS.md) |
| Where every trust anchor comes from | [docs/TRUST_ANCHORS.md](https://github.com/b7n0de/proofbundle/blob/main/docs/TRUST_ANCHORS.md) |
| The demos, tier by tier | [docs/DEMO.md](https://github.com/b7n0de/proofbundle/blob/main/docs/DEMO.md) |
| The normative format + verification order | [SPEC.md](https://github.com/b7n0de/proofbundle/blob/main/SPEC.md) |
| Honest comparison to Rekor / in-toto / OMS / ValiChord | [INTEROP.md](https://github.com/b7n0de/proofbundle/blob/main/INTEROP.md) |
| What the conformance corpus does and does not establish | [CONFORMANCE.md](https://github.com/b7n0de/proofbundle/blob/main/CONFORMANCE.md) |
| The commercial boundary of the project | [docs/COMMERCIAL_BOUNDARY.md](https://github.com/b7n0de/proofbundle/blob/main/docs/COMMERCIAL_BOUNDARY.md) |
| Regulatory mapping (and what to never claim) | [COMPLIANCE.md](https://github.com/b7n0de/proofbundle/blob/main/COMPLIANCE.md) |
| Funders / role fit | [docs/PROJECT_BRIEF.md](https://github.com/b7n0de/proofbundle/blob/main/docs/PROJECT_BRIEF.md) |
| **Preview:** TEE-attestation bridge (RATS/EAT, `[experimental]`) | [docs/EXPERIMENTAL_ENCLAVE.md](https://github.com/b7n0de/proofbundle/blob/main/docs/EXPERIMENTAL_ENCLAVE.md) |

## Status, scope and roadmap

Beta, SemVer-committed, with a CI test suite behind a mutation gate + property-based parser fuzzing.
Correctness is anchored to external RFC 6962 vectors and a real Rekor proof, not just its own
bundles; releases carry PEP 740 / SLSA build provenance. It is **not** a log service, a full in-toto
client, a TEE, a consensus network, or a compliance product by itself — it is the small, offline,
standards-native receipt layer between them. Security policy: [SECURITY.md](https://github.com/b7n0de/proofbundle/blob/main/SECURITY.md).

**Roadmap (stated honestly, not yet built):** a post-quantum *payload* signature (today the
post-quantum coverage is witness-side ML-DSA-44 only), and a CLI flag to select the content-root
algorithm (`jcs-sha256-v1` is the signed default). **Already shipped at preview/experimental
maturity** (install extra `[experimental]`, API/wire-format may still change): a TEE-attestation
bridge (RATS/EAT, RFC 9334 + RFC 9711) making `assurance_level = enclave_attested` independently
verifiable — [docs/EXPERIMENTAL_ENCLAVE.md](https://github.com/b7n0de/proofbundle/blob/main/docs/EXPERIMENTAL_ENCLAVE.md).

## Contributing

See [CONTRIBUTING.md](https://github.com/b7n0de/proofbundle/blob/main/CONTRIBUTING.md) and the [Code of Conduct](https://github.com/b7n0de/proofbundle/blob/main/CODE_OF_CONDUCT.md). Good first issues are labeled
[`good-first-issue`](https://github.com/b7n0de/proofbundle/labels/good-first-issue); security findings go through [SECURITY.md](https://github.com/b7n0de/proofbundle/blob/main/SECURITY.md).
The verifier core aims to stay small, dependency-light, and correct.

## License

MIT — see [LICENSE](https://github.com/b7n0de/proofbundle/blob/main/LICENSE).

---

<p align="center"><sub>proofbundle is part of <b>b7n0de</b>, Verified AI Work · <a href="https://b7n0de.com">b7n0de.com</a></sub></p>
