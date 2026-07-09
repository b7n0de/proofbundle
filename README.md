<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/b7n0de/proofbundle/main/assets/b7n0de-logo-dark.svg">
  <img alt="b7n0de, Verified AI Work" src="https://raw.githubusercontent.com/b7n0de/proofbundle/main/assets/b7n0de-logo.svg" height="60">
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
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.21230467.svg)](https://doi.org/10.5281/zenodo.21230467)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Mutation tested](https://img.shields.io/badge/tests-mutation_gated-D6248A.svg)](https://github.com/b7n0de/proofbundle/blob/main/scripts/mutation_check.py)
<!-- SLSA / PEP 740 attestation badges follow once the first attested release lands, see RELEASE.md. -->

**Reviewing this for adoption?** Start with the 30-minute adversarial audit path: **[docs/REVIEWERS.md](https://github.com/b7n0de/proofbundle/blob/main/docs/REVIEWERS.md)**.

</div>

## 60-second try (offline)

```bash
pip install "proofbundle[eval]"
proofbundle demo   # honest receipt => OK, six tampers each => FAILED, sample swap caught
# Inspect-native (METR Task Standard / UK-AISI ecosystem, mockllm, no API key):
git clone https://github.com/b7n0de/proofbundle && cd proofbundle
pip install -e ".[eval,inspect]" && make demo   # or `make full-demo` for log -> receipt -> verify
```

## The problem

Every AI eval number you read — a safety benchmark, a capability score, a leaderboard entry — is an
**unverifiable claim**. You trust the lab. There's no portable way to check, offline, that a result
was signed by a stated party, hasn't been altered, and covers the samples it claims.

proofbundle is that check. It's a small MIT-licensed Python tool (a compact, auditable trusted core,
depends only on [`cryptography`](https://cryptography.io)) that turns a result into a signed
receipt anyone can verify from a single file — and it's honest about the line it does not cross.

## What the demo shows

You'll see an honest receipt verify `=> OK`, then six independent tampers each verify `FAILED`, then
a swapped sample get caught — all in memory. `proofbundle demo` exits non-zero if any tamper slips through,
so it's also a self-test. Full walkthrough: **[docs/DEMO.md](https://github.com/b7n0de/proofbundle/blob/main/docs/DEMO.md)**.

```bash
# verify a real hosted receipt without writing any code:
curl -fsSL https://raw.githubusercontent.com/b7n0de/proofbundle/main/examples/example_bundle.json -o receipt.json
proofbundle verify receipt.json        # CRYPTO: OK  (the verify itself runs fully offline)

# your own receipt, from a signed payload:
proofbundle emit --payload-file result.json --new-key signer.key --out receipt.json
proofbundle verify receipt.json        # exit 0 = crypto OK, 1 = crypto/verification failure, 2 = malformed
                                       #   (3 = crypto OK but --policy unmet — --policy lands with WP-B3)
```

## Inspect-native? (METR Task Standard / UK-AISI ecosystem)

The receipt layer runs directly on [Inspect AI](https://inspect.aisi.org.uk/) — and the proof is
reproducible offline in minutes:

```bash
# setup as in the 60-second try above (clone + pip install -e ".[eval,inspect]"), then:
make full-demo   # a genuine inspect_ai eval log (mockllm: offline, no API key, no GPU)
                 # -> signed receipt next to the log -> proofbundle verify => OK
```

In your own pipeline the end-of-task hook signs every run automatically. Walkthrough:
**[docs/INSPECT_HAPPY_PATH.md](https://github.com/b7n0de/proofbundle/blob/main/docs/INSPECT_HAPPY_PATH.md)** · worked example:
**[examples/inspect_receipt.py](https://github.com/b7n0de/proofbundle/blob/main/examples/inspect_receipt.py)**.

## What a receipt proves — and what it doesn't

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

## Post-quantum posture (honest, two layers)

proofbundle is **not** "quantum-proof" or "quantum-safe" as a whole. It combines two cryptographic layers
with very different quantum exposure, and it is honest about both:

- **Quantum-robust (hash-based)** — SHA-256, RFC 6962 / 9162 Merkle inclusion, RFC 8785 canonicalization,
  and, among the external time anchors, the OpenTimestamps (Bitcoin hash-chain) and `chia-datalayer/v1`
  (Merkle inclusion) types. Grover only halves the effective bit-strength (SHA-256 keeps a ~128-bit quantum
  margin, which NIST currently treats as adequate), so these stay secure.
- **Quantum-vulnerable (elliptic-curve / classical PKI, Shor)** — the Ed25519 receipt signature; for the
  `chia-datalayer` anchor, Chia's BLS12-381 wallet layer; and, for the RFC 3161 anchor, the TSA's own
  classical (RSA/ECDSA) certificate-chain signature. A large enough quantum computer could forge any of these.

The attack that matters is not decryption but **back-dated forgery**: an attacker with a quantum computer
could mint a fake signature on a tampered receipt. The defense — **when a receipt carries a hash-based time
anchor** (optional, the `[anchors]` beta extra: OpenTimestamps or `chia-datalayer`) — is that the anchor
proves the original receipt existed *before* that capability, so a forged receipt has no matching anchor.
That protects the evidence long-term even if the signature layer later breaks. A plain receipt with no anchor
does not carry this property.

On the witness side, C2SP checkpoints already carry post-quantum **ML-DSA-44** (FIPS 204) cosignatures
(`proofbundle[pq]`); a post-quantum *payload* signature — crypto-agility for the receipt itself — is on the
roadmap.

## In plain language

A proofbundle receipt is the cash-register receipt of an AI test result: it shows who claimed the
number and that nobody quietly changed it afterwards. It does not show the test was good — the way a
cash-register receipt does not show the meal was good — but without a receipt there is nothing to
check at all.

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

## What's in the box

- **Core** — Ed25519 signature + RFC 6962 / 9162 Merkle inclusion, verified fully offline. Checks a
  real [Sigstore Rekor](https://docs.sigstore.dev/) proof, so correctness isn't self-referential.
- **Eval receipts** — a signed claim (`metric ⋈ threshold`, `n`, salted model/dataset commitments,
  assurance level, provenance) from your run. See [EVAL_CLAIM.md](https://github.com/b7n0de/proofbundle/blob/main/EVAL_CLAIM.md).
- **Selective disclosure** — SD-JWT ([RFC 9901](https://datatracker.ietf.org/doc/rfc9901/)) with Key
  Binding: prove a threshold while withholding the exact score.
- **Transparency-log interop** — C2SP `tlog-checkpoint` / cosignature / `.tlog-proof`, with
  post-quantum **ML-DSA-44** witness cosignatures. Optional Token-Status-List revocation snapshots.
- **Per-sample audit** — commit to every sample; an auditor challenges random indices (with a fresh
  nonce or a **public randomness beacon**, v1.9) and openings must bind to the signed root. With
  such an auditor-supplied or beacon-bound challenge, 300 samples catch 1% sample-doctoring with 95%
  confidence, regardless of run size — a challenge the issuer chose itself does not give this
  guarantee.
- **Pre-registration** — `proofbundle prereg <plan>` commits to the protocol before the run, so
  best-of-many publishing becomes visible.
- **Integrations** — opt-in inspect_ai end-of-task hook and pytest plugin (emit only when
  `PROOFBUNDLE_EMIT=1` / `--proofbundle`), plus a Hugging Face Community Evals bridge. See
  [INTEGRATIONS.md](https://github.com/b7n0de/proofbundle/blob/main/INTEGRATIONS.md), or the end-to-end walkthrough
  [docs/INSPECT_HAPPY_PATH.md](https://github.com/b7n0de/proofbundle/blob/main/docs/INSPECT_HAPPY_PATH.md) — run an eval, get a receipt, verify it offline.
- **External time anchors** *(v2.0 beta, the `[anchors]` extra)* — an optional `anchors[]` layer that
  attaches external evidence of *when* a commitment or receipt existed, from a party the producer does not
  control. Two built-in types verify offline: **RFC 3161** TSA tokens (against a frozen cert chain) and
  **OpenTimestamps** Bitcoin proofs (honest pending → confirmed lifecycle). A `register_anchor_type`
  extension interface lets a third party ship its own fail-closed type; two worked examples ship — a
  first-party **`chia-datalayer/v1`** (offline Merkle inclusion of a canonical root under a published Chia
  DataLayer root) and a third-party **`markovian-provenance/v1`** (a wallet-attributable, Bitcoin-anchored
  stamp). See [docs/ANCHORS.md](https://github.com/b7n0de/proofbundle/blob/main/docs/ANCHORS.md).

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
| Regulatory mapping (and what to never claim) | [COMPLIANCE.md](https://github.com/b7n0de/proofbundle/blob/main/COMPLIANCE.md) |
| Funders / role fit | [docs/PROJECT_BRIEF.md](https://github.com/b7n0de/proofbundle/blob/main/docs/PROJECT_BRIEF.md) |
| External time anchors + the bring-your-own-type extension interface (v2.0 beta) | [docs/ANCHORS.md](https://github.com/b7n0de/proofbundle/blob/main/docs/ANCHORS.md) |
| **Preview:** TEE-attestation bridge (v2.0 beta) | [docs/EXPERIMENTAL_ENCLAVE.md](https://github.com/b7n0de/proofbundle/blob/main/docs/EXPERIMENTAL_ENCLAVE.md) |

## Install

```bash
pip install proofbundle                 # core: offline verify + plain emit (dependency-free)
pip install "proofbundle[eval]"          # + eval receipts, prereg, and the demo (adds an RFC 8785 JCS canonicalizer)
pip install "proofbundle[inspect]"      # inspect_ai adapter + hook
pip install "proofbundle[pq]"           # verify ML-DSA-44 (post-quantum) witness cosignatures
```

Requires Python 3.10+. The verify path never rolls its own crypto — Ed25519 comes from
`cryptography`; Merkle hashing is RFC 6962.

## Status & scope

Beta, SemVer-committed, with a CI test suite behind a mutation gate + property-based parser fuzzing. Correctness
is anchored to external RFC 6962 vectors and a real Rekor proof, not just its own bundles. It is
**not** a log service, a full in-toto client, a TEE, a consensus network, or a compliance product
by itself — it is the small, offline, standards-native receipt layer between them. Security policy:
[SECURITY.md](https://github.com/b7n0de/proofbundle/blob/main/SECURITY.md).

## Contributing

See [CONTRIBUTING.md](https://github.com/b7n0de/proofbundle/blob/main/CONTRIBUTING.md) and the [Code of Conduct](https://github.com/b7n0de/proofbundle/blob/main/CODE_OF_CONDUCT.md). Good first
issues are labeled [`good-first-issue`](https://github.com/b7n0de/proofbundle/labels/good-first-issue);
security findings go through [SECURITY.md](https://github.com/b7n0de/proofbundle/blob/main/SECURITY.md). The verifier core aims to stay small,
dependency-light, and correct.

## License

MIT — see [LICENSE](https://github.com/b7n0de/proofbundle/blob/main/LICENSE).

---

<p align="center"><sub>proofbundle is part of <b>b7n0de</b>, Verified AI Work · <a href="https://b7n0de.com">b7n0de.com</a></sub></p>
