# Predicate type: ML eval-result

<!-- READY-TO-SUBMIT DRAFT for in-toto/attestation (spec/predicates/eval-result.md). NOT yet opened as
a PR — held until a maintainer signal on in-toto/attestation#565, per the project's "review at the next
maintainers meeting" process. When opened, this PR contains ONLY this spec file + a README entry; the
protobuf definition follows as a separate PR (as SVR did: spec #470, proto #519, README #537). -->

Type URI: https://in-toto.io/attestation/eval-result/v0.1

Version: v0.1

Authors: Konrad Gruszka (ORCID 0009-0006-8947-6065)

## Purpose

Attest the result of a machine-learning **evaluation** in a way a generic in-toto verifier can consume,
while keeping the evaluated model and dataset **private**. An ML eval has three properties the generic
[`test-result`](test-result.md) predicate does not model: a **metric threshold** with a pass/fail
against it, the need to withhold the model/dataset identity, and an optional binding to an external
signed receipt (and, later, an external time anchor for pre-registration).

This predicate authenticates a *claim* — *who signed these exact eval bytes, and that nothing changed
since*. It does **not** assert the semantic truth, fairness, safety, or generalization of the result;
those remain human judgements (see [Non-claims](#non-claims)).

## Use cases

- **Private-model eval**: publish "model M passed safety suite S at `refusal_rate >= 0.98`" without
  revealing M or the dataset, via salted commitments; a relying party verifies the signed claim offline.
- **Release gating**: bind a release artifact (image/wheel/service digest) to a passing eval — "deploy
  only if the eval passed" — as the ML attach point for a policy/SLSA decision.
- **Pre-registration**: commit to the threshold and the dataset/model *before* the run, and later prove
  the commitment predated the result (strengthened by an external time anchor).

## Prerequisites

in-toto attestation [spec v1](../v1/README.md). The evaluation is expressed as one or more
threshold-based claims `{metric, comparator, threshold, passed}`. Identifiers that must stay private are
carried as **salted commitments** (a hash over a secret salt ‖ identifier); the salt stays with the
issuer and is never in the attestation.

## Model

An evaluation run produces a signed, tamper-evident receipt. This predicate is a projection of that
receipt onto an in-toto Statement: the `subject` is what the attestation is *about* (the receipt itself,
a public model artifact, or a gated release artifact), and the predicate carries the eval's facts. The
detailed per-metric result lives here; a companion [SVR](https://github.com/in-toto/attestation/pull/470)
may summarize "a verifier confirmed this passed" as passing property strings.

## Schema

```jsonc
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{ "name": "<optional>", "digest": { "<alg>": "<hex>" } }],
  "predicateType": "https://in-toto.io/attestation/eval-result/v0.1",
  "predicate": {
    "verifier": { "id": "<TypeURI>" },
    "evaluatedAt": "<RFC 3339>",
    "suite": { "name": "<string>", "version": "<string>" },
    "claims": [
      { "metric": "<string>", "comparator": ">=|>|<=|<", "threshold": "<decimal string>", "passed": <bool> }
    ],
    "sampleSize": <int>,
    "commitments": {
      "model":   { "alg": "<string>", "value": "<hex>", "salted": true },
      "dataset": { "alg": "<string>", "value": "<hex>", "salted": true }
    },
    "assuranceLevel": "self_attested|third_party|reproduced|enclave_attested",
    "subjectProfile": "receipt|public-model|release-gate",
    "preRegistration": { "alg": "sha256", "value": "<hex>" },   // OPTIONAL
    "receipt": { "schema": "<string>", "merkleRootB64": "<base64>" },  // OPTIONAL
    "harness": { "name": "<string>", "version": "<string>" },   // OPTIONAL
    "anchors": [ /* external time anchors — OPTIONAL, see the anchors extension */ ]
  }
}
```

## Parsing rules

This predicate follows the in-toto attestation
[spec v1 parsing rules](../v1/README.md#parsing-rules): consumers **match on the subject `digest`
alone**; `subject[].name` is a hint and MAY be `"_"` or omitted; unknown predicate fields MUST be
ignored (forward compatibility); and the
[Monotonic Principle](../../docs/validation.md) applies — a verifier denies unless a valid attestation
exists. Time fields are RFC 3339. `threshold` is a decimal **string**, never a JSON float, so a value
is never altered by float round-tripping.

## Fields

`verifier.id` _(TypeURI, required)_: the party that emitted/verified the result.

`evaluatedAt` _(Timestamp, required)_: when the evaluation ran.

`suite` _(object, required)_: `{name, version}` of the eval suite.

`claims` _(array, required)_: one or more `{metric, comparator, threshold, passed}`. `comparator` is one
of `>=`, `>`, `<=`, `<`; `passed` is the pass of `metric comparator threshold`.

`sampleSize` _(int, required)_: number of samples the result is over.

`commitments` _(object, required)_: `model` and `dataset`, each `{alg, value, salted}`. When `salted` is
`true` the `value` is a commitment (a hash over a secret salt ‖ identifier), **NOT** an artifact content
digest — a generic verifier MUST NOT treat it as one. This is what lets the evaluated model/dataset stay
private while the claim is still verifiable.

`assuranceLevel` _(string, required)_: how much a pass is worth — `self_attested` (producer testimony),
`third_party`, `reproduced`, or `enclave_attested`.

`subjectProfile` _(string, required)_: which subject the attestation binds to — `receipt` (a binder over
the receipt; reveals nothing), `public-model` (a disclosed model's real digest), or `release-gate` (a
release artifact gated on the pass).

`preRegistration` _(object, optional)_: `{alg, value}` over the eval protocol committed before the run.

`receipt` _(object, optional)_: `{schema, merkleRootB64}` binding to the external signed receipt.

`harness` _(object, optional)_: `{name, version}` of the eval harness.

`anchors` _(array, optional)_: external time anchors (e.g. RFC 3161 TSA, OpenTimestamps) for the
receipt or the pre-registration. Defined by a separate anchors extension.

## Non-claims

A verifier that accepts this attestation learns that the signed claim is authentic and unchanged. It
does **not** learn that the metric is correct, that the eval was well designed, that the model is safe
or fair, or that the score generalizes. Those are out of scope for this predicate.

## Examples

A private-model eval (subject is the receipt; the model stays secret):

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{ "name": "eval-receipt", "digest": { "sha256": "…" } }],
  "predicateType": "https://in-toto.io/attestation/eval-result/v0.1",
  "predicate": {
    "verifier": { "id": "https://example.com/verifier" },
    "evaluatedAt": "2026-07-05T12:00:00Z",
    "suite": { "name": "safety-refusals", "version": "1.2.0" },
    "claims": [{ "metric": "refusal_rate", "comparator": ">=", "threshold": "0.98", "passed": true }],
    "sampleSize": 500,
    "commitments": {
      "model":   { "alg": "sha256-salted-v1", "value": "…", "salted": true },
      "dataset": { "alg": "sha256-salted-v1", "value": "…", "salted": true }
    },
    "assuranceLevel": "self_attested",
    "subjectProfile": "receipt",
    "receipt": { "schema": "proofbundle/v0.1", "merkleRootB64": "…" }
  }
}
```

A release-gate example (subject is the deployed artifact's real digest) is in the reference
implementation's `examples/intoto/release-gate.statement.json`.

## Changelog

- v0.1 — initial draft. Reference emitter/verifier: [proofbundle](https://github.com/b7n0de/proofbundle)
  (`proofbundle intoto`). Discussion: in-toto/attestation#565. Until this type is registered upstream,
  the reference implementation emits the vendor-namespaced `predicateType`
  `https://b7n0de.com/attestation/eval-result/v0.1` and migrates to the `in-toto.io` URI on
  registration (a redirect/alias is added at that point). Consumers match on the subject digest, so a
  `predicateType` rename does not affect binding.
