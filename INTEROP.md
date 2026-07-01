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

## CycloneDX ML-BOM (spec v1.6)

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

## C2PA (spec ~v2.3)

[C2PA](https://c2pa.org/specifications/) is content provenance for media, **not** evaluation. It is
**out of scope** for proofbundle, mentioned only because it shares the same signed-provenance narrative.

## Summary

proofbundle is the missing **signature + selective-disclosure layer** for a trustworthy eval log — the
provenance/verification piece that OMS (artifacts), CycloneDX (unsigned metrics) and in-toto (generic
test results) each leave open for ML evaluation. It implements none of them; it maps to them.
