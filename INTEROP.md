# Interoperability — where proofbundle sits, honestly

proofbundle answers exactly one question: **did this model pass a stated eval threshold, verifiably,
without revealing the model or the data.** This document maps it against adjacent standards and marks
what is deliberately out of scope. No claim here implies proofbundle implements any of these specs.

## OpenSSF Model Signing (OMS)

[OMS](https://github.com/ossf/model-signing-spec) signs model *artifacts* and explicitly does **not**
cover quality or evaluation. The two are complementary, not competing:

- **OMS** answers *is this the real model* (artifact integrity + provenance).
- **proofbundle** answers *did this model pass an eval, provably, without disclosing model or data*.

Together they cover integrity **and** verified performance. That is the cleanest positioning.

## CycloneDX ML-BOM (spec v1.7; ML-BOM introduced in v1.6)

CycloneDX [ML-BOM](https://cyclonedx.org/capabilities/mlbom/) can carry performance/quality metrics, but
they are **unsigned and self-asserted**. A CycloneDX ML-BOM metric field can **reference** a proofbundle
receipt (by its merkle `root_b64` / bundle URL) to add a signature and selective disclosure it does not
provide itself. This is a mapping only — proofbundle does not implement CycloneDX.

## in-toto test-result predicate

in-toto defines a generic test-result predicate,
[`https://in-toto.io/attestation/test-result/v0.1`](https://github.com/in-toto/attestation/blob/main/spec/predicates/test-result.md).
As of mid-2026 there is **no registered ML-eval predicate** — that is the open niche proofbundle's
self-hosted `https://b7n0de.com/proofbundle/eval-receipt/v0.1` predicate fills (see PREDICATE.md). Field
alignment with test-result/v0.1:

| test-result/v0.1 | proofbundle eval-receipt predicate |
|---|---|
| `result` (PASSED/FAILED/…) | `claims[].passed` (per metric) |
| `configuration` (resource descriptors) | `harness` (name+version), `datasetCommit` |
| `url` / `passedTests` etc. | `receipt.root_b64` (bundle anchor), `suite` |

proofbundle keeps its own predicate (a boolean pass carries a threshold + salted commitments that
test-result has no field for) but documents the mapping so a test-result consumer can locate the data.

## C2PA (spec ~v2.4)

[C2PA](https://c2pa.org/specifications/) is content provenance for media, **not** evaluation. It is
**out of scope** for proofbundle, mentioned only because it shares the same signed-provenance narrative.

## Every Eval Ever (EEE)

[Every Eval Ever](https://github.com/evaleval/every_eval_ever) ([arXiv:2606.14516](https://arxiv.org/abs/2606.14516))
is a schema + Hugging Face datastore for aggregating eval results — **without cryptography**. proofbundle is
the missing integrity + selective-disclosure layer *underneath* it: an EEE record can reference a
proofbundle receipt (by `root_b64`), and a small converter from the eval claim to the EEE schema is a
plausible bridge. Integration target, not a competitor.

## Attestable Audits (TEE) — different trust model

[Attestable Audits](https://arxiv.org/abs/2506.23706) use trusted execution (TEE) to attest the
**correctness of the computation** itself. That is a stronger, hardware-rooted guarantee than proofbundle
offers — and out of scope here. proofbundle deliberately targets the lightweight, hardware-free case: a
portable, tamper-evident, selectively disclosable *result artifact*. The two are complementary trust models
for different threats (computation-correctness vs. artifact authenticity/integrity + private disclosure).

## ValiChord — an adjacent eval-attestation library

[ValiChord](https://github.com/topeuph-ai/ValiChord) is a real neighbour: its `valichord_attestation` (Apache-2.0) also attests eval runs and, like proofbundle, canonicalizes with RFC 8785 JCS. Named fairly, the v1 library differs in exactly the standards proofbundle leads with: its format v1 carries **no digital signature** (`signatures` is reserved for v2), uses a **simple SHA-256 Merkle tree** (no RFC 6962 domain separation), and has **no SD-JWT, no in-toto, and no Every Eval Ever converter**; blind peer consensus and an attested log live in its Holochain layer (v2 scope). proofbundle is complementary — the portable, standards-native, transparency-log-anchored receipt layer — not a rival network.

## Comparison tables (fair, at-a-glance)

### vs Sigstore Rekor / Rekor v2
| | Rekor / Rekor v2 | proofbundle |
|---|---|---|
| What it is | Operated public transparency-log **service** (v2: tile-backed, C2SP-aligned) | A **file format + offline verifier/emitter library** |
| Trust model | Log operator + witnesses + monitors; keys via TUF | Anchors the relying party supplies out of band (see docs/TRUST_ANCHORS.md) |
| Online / offline | Sign/upload online; offline verify of persisted proofs | Fully offline both directions |
| Proves | Public append-only *existence* at time T | These bytes signed by this key, anchored under this root — same RFC 6962 math (verifies a real Rekor proof offline) |
| Does NOT | Anything eval-specific; no selective disclosure | Global append-only guarantee — a lone `emit_bundle` tree is issuer-local |
| Use when | You want public discoverability / non-equivocation | You want a portable, private, eval-shaped receipt (anchor it INTO Rekor for the log properties) |

### vs Inspect AI logs (.eval)
| | inspect_ai `.eval` log | proofbundle receipt |
|---|---|---|
| What it is | Full mutable run record (samples, messages, scores) | Minimal signed claim derived from it |
| Trust model | None — bytes on disk | Ed25519 + Merkle + optional witnesses |
| Proves | Nothing cryptographic; full transparency | Integrity/authorship of the extracted claim; can hide model/dataset |
| Use when | Debugging, reanalysis with a trusted channel | Publishing/attesting a result across a trust boundary — keep the log, ship the receipt |

### vs in-toto test-result predicate (+ DSSE)
| | in-toto test-result/v0.1 (DSSE) | proofbundle eval receipt |
|---|---|---|
| What it is | Generic "tests PASSED/FAILED" statement | Eval-specific: metric ⋈ threshold, n, salted commitments, assurance level, samples root |
| Proves | Which tests passed, config descriptors | Threshold verdict without revealing model/dataset; per-sample auditability |
| Does NOT | Carry metric/threshold/commitment fields | Bring a policy-verifier ecosystem (predicate self-hosted, unregistered) |
| Interop | — | proofbundle **exports** a DSSE-signed test-result view (`export_intoto_dsse`) |

### vs ValiChord (per its docs; not independently re-verified here)
| | ValiChord v1 | proofbundle |
|---|---|---|
| Crypto today | JCS + plain SHA-256 Merkle + HMAC; **no signature** (v2 scope) | Ed25519 + RFC 6962 domain-separated Merkle + SD-JWT/KB + C2SP |
| Offline | Yes | Yes |
| Proves | Integrity vs a shared secret / future Holochain net | Third-party-verifiable public-key authorship |

**One-line positionings:** DSSE = the signing *envelope* (proofbundle emits into it). C2SP =
transparency-log *wire formats* (proofbundle verifies them, incl. real Rekor artifacts). SD-JWT VC
= the credential *profile* on RFC 9901 (proofbundle does SD-JWT core + KB; full VC deferred). Token
Status List = offline *revocation snapshots* (proofbundle verifies a bundled snapshot).

## Summary

proofbundle is the missing **signature + selective-disclosure layer** for a trustworthy eval log — the
provenance/verification piece that OMS (artifacts), CycloneDX (unsigned metrics) and in-toto (generic
test results) each leave open for ML evaluation. It implements none of them; it maps to them.

**The niche in ≤25 words:** offline, standards-native signed receipts for AI eval results —
threshold verdicts with salted model/dataset commitments and per-sample audit hooks, verifiable
from one file. **The bound:** it attests who claimed what and that nothing changed since — never
that the eval was honest, well-designed, or the only run performed.

_Neighbour claims about ValiChord / ai-audit-trail here are sourced to their own docs; standards
versions verified 2026-07 (Rekor v2 GA Oct 2025; RFC 9901 Nov 2025; in-toto test-result v0.1)._

## Decision receipts (`decision-receipt/v0.1`)

A Decision Receipt is a *separate* vendored predicate for a signed agent-decision claim; it references
eval receipts by content-root digest and never mixes metric evidence into the decision. It maps to
neighbouring systems as reference fields, never as a hard dependency:

| System | Mapping in a Decision Receipt |
|---|---|
| in-toto / DSSE | Own `predicateType` in a Statement/v1, DSSE-signed; verified over the exact bytes. |
| SLSA VSA | `decisionMaker` ~ `verifier`; `policyBoundary.policyDigest` ~ policy; `evidenceRefs` ~ `inputAttestations` (each pinned by content-root digest). |
| OPA decision logs | `decision_id`→`decisionId`, `path`→`policyBoundary.decisionPath`, `result`→`decision.verdict`, `bundles.revision`→`policyBoundary.bundleRevision`, `erased`/`masked`→`privacy`. |
| OpenTelemetry / OpenInference | `traceContext.traceparent` correlates to spans (correlation only, never an integrity proof). |
| CloudEvents | may wrap a receipt as an event payload; not the core format. |
| MCP | `proposedAction.target` = tool URI + `digest`; a schema-digest change after approval is a tool-poisoning signal (§THREAT_MODEL). |
| A2A | `agent` / `principal` / `delegationRefs` carry delegation and skill/authorization context. |
| Sigstore / Rekor · SCITT | a public-anchoring / transparent-statement profile *could* attach via the detached anchors layer (`target: statement`) once such an anchor verifier is registered; none ships by default. |
| EEE / ValiChord / OMS | referenced as an `evidenceRefs[]` content root (eval run / model artifact), never re-implemented. |

The reference is one-directional and content-root bound: the decision cites evidence, never the reverse.
