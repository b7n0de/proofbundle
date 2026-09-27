# in-toto profile: the `eval-result` predicate and the SVR export

Status: **PROPOSED**. Discussed at [in-toto/attestation#565](https://github.com/in-toto/attestation/issues/565)
and submitted as [PR #575](https://github.com/in-toto/attestation/pull/575), which is **open, not merged**.
Not standardized. The `predicateType` lives in a vendor namespace until (and unless) it is registered
upstream. Nothing here changes the native receipt or what it proves — see [NON_CLAIMS.md](NON_CLAIMS.md).

The v0.2 field table below mirrors the submitted spec as revised on 2026-09-28. When the two differ, the
PR is the source of truth and this page is the one that is wrong; a byte-for-byte copy of the submitted
file lives in [docs/upstream/eval-result.md](upstream/eval-result.md).

This page answers, for a first-time reader, three questions in a few minutes:

1. **What is the predicate?** A privacy-preserving in-toto Statement for an ML eval result.
2. **What does it NOT prove?** Authenticity and integrity of a *claim*, never its semantic truth.
3. **Why is neither `test-result` nor an SVR alone enough?** See the two sections below.

## The problem

in-toto has a generic [`test-result/v0.1`](https://github.com/in-toto/attestation/blob/main/spec/predicates/test-result.md)
predicate and a [Summary Verification Result (SVR)](https://github.com/in-toto/attestation/pull/470)
predicate. Neither models an ML evaluation, which has three properties a generic test does not:

- a **metric threshold** and a pass/fail *against that threshold* (not just a status),
- the need to keep the **model and dataset private** while still proving the claim, and
- optional references to **supporting evidence**, such as an external signed receipt (and, later, an
  external time anchor).

## Why `test-result/v0.1` is not enough

The community `test-result` predicate (`predicateType` `https://in-toto.io/attestation/test-result/v0.1`)
carries:

- `result`: one of `PASSED` | `WARNED` | `FAILED`,
- `configuration`: a list of ResourceDescriptors,
- `passedTests` / `warnedTests` / `failedTests`: string lists.

It has **no** native field for a metric, a comparator, a threshold, a sample size, or a privacy-
preserving commitment. You *can* map a receipt onto it (proofbundle still offers that export via
`to_test_result_statement`, stuffing the metric into a descriptor's `annotations`), but the eval's
core facts — *which metric, which threshold, met by how much* — become unstructured annotations that
no generic verifier understands. The threshold semantics are lost.

## Why an SVR alone is not enough

An SVR (`https://in-toto.io/attestation/svr/v0.1`) is a *verifier's summary*: `verifier.id`,
`timeCreated`, and a list of passing **property strings**. It is excellent for saying "this verifier
checked these things and they held", and proofbundle emits one (see below). But an SVR is
intentionally lossy: it records *that* properties held, not the metric, the threshold, the sample
size, or the commitments. It also has **no FAILED form** — it lists only passing properties (a
PASSED|FAILED verdict would be a VSA, which we deliberately do not implement). So an SVR is a good
*summary layer on top of* a receipt, not a replacement for the detailed `eval-result` predicate.

The two compose: emit the `eval-result` Statement for the detail, and an SVR for the one-line
"a verifier confirmed this passed" summary. Both are derived from the same verified receipt.

## The `eval-result/v0.2` predicate

`predicateType`: `https://b7n0de.com/attestation/eval-result/v0.2` (vendor namespace; the revised #575
draft, see the migration below). Statement `_type` is the standard `https://in-toto.io/Statement/v1`; the
DSSE `payloadType` is the canonical `application/vnd.in-toto+json`. Written by
`proofbundle intoto --predicate-version v0.2 --evaluator <URI>` and `intoto.export_eval_result_v02_dsse`;
verified by `verify_eval_result_dsse(..., expected_predicate_type=EVAL_RESULT_V02_PREDICATE_TYPE)`, which
adds the shape below to the verdict (`classify_eval_result_v02_predicate`). Fields (lowerCamelCase; time
fields are speaking RFC-3339):

| field | meaning |
|---|---|
| `evaluator.id` | **required**, the URI of the party that ran the evaluation and produced the `claims`. Not the signer (the DSSE envelope names that) and not a verifier in the SVR sense. The emitter has no default: proofbundle records a result, it does not run the evaluation |
| `evaluatedAt` | when the eval ran (from the signed receipt) |
| `suite` | `{name, version}`, both required |
| `claims[]` | `{metric, comparator, threshold, passed}`. `passed` is the producer's **signed threshold verdict**, not a recomputable relation: proofbundle discards the exact score after the comparison, so without a disclosed value a generic consumer can authenticate the verdict but cannot recompute it |
| `sampleSize` | `n` |
| `commitments` | per **private** identity, `model` and/or `dataset`, each `{alg, value, salted}` — a **salted commitment**, NOT an artifact hash |
| `model`, `dataset` | a **public** identity: a ResourceDescriptor that MUST carry `digest` (a DigestSet over the real content) |
| `assuranceLevel` | an **issuer-declared** assurance claim: `self_attested` \| `third_party` \| `reproduced` \| `enclave_attested`. The predicate does not corroborate it; external corroboration belongs in `evidence` |
| `subjectProfile` | which subject profile produced the `subject` (below) |
| `preRegistration` | optional `{alg, value}` — present only if the receipt carries a prereg hash |
| `evidence[]` | optional ResourceDescriptors for supporting material. Each entry MUST carry `digest`, and SHOULD carry `mediaType` and one of `uri` or `downloadLocation`. proofbundle writes the receipt as the first entry: the SHA-256 of the receipt file's exact bytes, `application/json`, the `--receipt-uri` if given, and the Merkle root as the annotation `merkleRootB64` |
| `harness` | optional `{name, version}` plus an optional `digest` ([DigestSet](https://github.com/in-toto/attestation/blob/main/spec/v1/digest_set.md)) for consumers that need to bind the exact artifact that produced the result. A `harness` carrying only `name` and `version` stays conforming. The digest binds **identity only** and asserts nothing about the harness's detection performance |

**One identification each.** For each of the model and the dataset, exactly one identification MUST be
present: `commitments.<x>` or the top-level descriptor. The verifier refuses a predicate that identifies
either of them twice or not at all. With `--subject-profile public-model`, the emitter writes the model as
a descriptor with the subject's name and digest instead of a commitment; the dataset stays a commitment.

**Written beyond the draft, allowed by its parsing rules.** `subjectDigestNote` stays, for the `receipt`
profile only: that subject digest is a binder that names no file, and the note says so. `anchors` is not
written in v0.2: the draft scoped it out, and an external anchor now travels as an `evidence` entry with
its own digest.

## The `eval-result/v0.1` predicate (released, still verified)

`predicateType`: `https://b7n0de.com/attestation/eval-result/v0.1`. Emitted and signed by released
versions and still the CLI default. It is verified under its own contract, unchanged: signature, content
root, type; no shape check (`predicate_shape_ok` is `None`). Fields:

| field | meaning |
|---|---|
| `verifier.id` | the emitter/verifier TypeURI (replaced by `evaluator.id` in v0.2) |
| `evaluatedAt` | when the eval ran (from the signed receipt) |
| `suite` | `{name, version}` |
| `claims[]` | `{metric, comparator, threshold, passed}`. `passed` is the producer's **signed threshold verdict**, not a recomputable relation: proofbundle discards the exact score after the comparison, so without a disclosed value a generic consumer can authenticate the verdict but cannot recompute it |
| `sampleSize` | `n` |
| `commitments` | `{model, dataset}`, each `{alg, value, salted:true}` — a **salted commitment**, NOT an artifact hash |
| `assuranceLevel` | an **issuer-declared** assurance claim: `self_attested` \| `third_party` \| `reproduced` \| `enclave_attested`. The predicate does not corroborate it; external corroboration belongs in separately referenced evidence |
| `subjectProfile` | which subject profile produced the `subject` (below) |
| `preRegistration` | optional `{alg, value}` — present only if the receipt carries a prereg hash |
| `receipt` | optional `{schema, merkleRootB64}` — binds to the external signed receipt (replaced by `evidence[]` in v0.2) |
| `harness` | optional `{name, version}` plus an optional `digest` ([DigestSet](https://github.com/in-toto/attestation/blob/main/spec/v1/digest_set.md)) for consumers that need to bind the exact artifact that produced the result. A `harness` carrying only `name` and `version` stays conforming. The digest binds **identity only** and asserts nothing about the harness's detection performance |

`anchors` is **not** a field of this predicate. External time anchors were drafted in #565 and
deliberately scoped out of #575: they are not eval-specific and belong as a shared optional field in
their own discussion. Earlier revisions of this page listed them; that was wrong and is corrected here.

**Parsing rules** follow in-toto Statement v1: matching is on the subject `digest` alone; unknown
predicate fields are ignored by consumers; and the [Monotonic Principle](https://github.com/in-toto/attestation/blob/main/docs/validation.md)
applies — a verifier denies unless a valid attestation exists. **Absence rule:** unless a field says
otherwise, the absence of an optional field means only that no claim is made for it — a consumer MUST
NOT infer or synthesize a default from absence.

## Subject profiles — what the `subject` IS

in-toto matches on the subject digest, so the subject must be chosen deliberately. `--subject-profile`:

- **`receipt`** (default): the subject is the **receipt itself** — the digest is a sha256 binder over
  the receipt's commitments + Merkle root + timestamp. It binds the attestation to the receipt
  **without revealing the model**. Use this when the model/dataset stay private.
- **`public-model`**: the subject is a **disclosed public model artifact**; you supply its real
  `sha256` (`--subject-sha256`) and a name. Use this when the model is public and you want the
  attestation to match on the model's own digest.
- **`release-gate`**: the subject is a **release artifact** (an image, a wheel, a service digest) whose
  deployment is gated on the passing eval — the "deploy only if the eval passed" hook, the natural
  attach point for SLSA/policy. You supply the artifact's `sha256`.

## Policy questions (for a relying party)

Before you trust an `eval-result` attestation for a decision, answer:

1. **Whose key signed it, and do you trust that key for this claim?** (The DSSE key; in v0.2
   `evaluator.id` names who ran the eval, which need not be the signer.)
2. **What is the `assuranceLevel`?** `self_attested` is producer testimony; `third_party` / `reproduced`
   / `enclave_attested` are stronger — do you require one of them?
3. **Which subject profile is it, and is that the thing you meant to gate on?** A `receipt` subject
   binds to a private model; a `release-gate` subject binds to the artifact you deploy.
4. **Is there a pre-registration, and is it anchored?** Without an external anchor, ordering is
   producer-clock testimony only (external time anchors are a proposed experimental extra).
5. **Does the threshold and metric match your policy?** The attestation proves the signed claim; *you*
   decide whether that bar is the right one.
6. **Do you require an SVR / specific passing properties** (e.g. `PROOFBUNDLE_SAMPLE_ROOT_VALID`)?

## What it does not prove

Everything in [NON_CLAIMS.md](NON_CLAIMS.md) applies unchanged. In short: authenticity and integrity
of a claim, never its semantic truth, fairness, safety, or generalization.

Added to the submitted spec on 2026-08-07 and repeated here because it is easy to assume otherwise:
the predicate does **not** establish that the evaluation harness or grader is fit for purpose, or
that it has any particular detection performance. Binding a harness digest pins *which* artifact ran,
not *how well* it detects.

The consequences of that non-claim **can be asymmetric**, and the direction depends on which class the
detector counts as positive. Where detected positives are evidence of capability, missed positives can
understate the subject. Where `passed: true` depends on the *absence* of detected failures, missed
failures can instead yield a passing verdict although the failures occurred. The attestation
authenticates either verdict without establishing the harness's detection capability. The submitted
spec carries this as its own paragraph in `## Non-claims`; it deliberately says *can be* rather than
*is*, because the predicate never fixes which class a detector counts.

## Migration: eval-result v0.1 → v0.2 (6.3.0)

The revised #575 draft changed the predicate in three places. The vendor type cannot keep its version
while its shape changes, because v0.1 statements were emitted and signed by released versions and a
consumer that keys on the type must never read them under the new rules. So the revised shape is its own
type, `https://b7n0de.com/attestation/eval-result/v0.2`.

| v0.1 | v0.2 | reason in the draft |
|---|---|---|
| `verifier.id` (the tool) | `evaluator.id`, required, set by the caller | the party that ran the evaluation; `verifier` stays reserved for the SVR sense, the signer stays in the envelope |
| `commitments.model` and `commitments.dataset`, both required | per identity: a commitment (private) or a top-level ResourceDescriptor with `digest` (public), exactly one each | salted commitments are only needed for a private identity |
| `receipt: {schema, merkleRootB64}` | `evidence[]`, each entry with `digest` | a generic reference to supporting material instead of an emitter-specific block |

What does not change (gate G2):

- a v0.1 statement verifies exactly as before, under `verify_eval_result_dsse`'s default, which still
  expects v0.1; two envelopes written by the released 6.1.0 wheel are pinned in
  `tests/fixtures/eval_result_v0_1/` and verified on every run, and the v0.1 emitter still writes them
  byte for byte;
- `proofbundle intoto` still writes v0.1 unless `--predicate-version v0.2` is given, because an existing
  consumer's default is never switched silently ([MIGRATION_EVAL_PREDICATE.md](MIGRATION_EVAL_PREDICATE.md)).
  Switching the default is a release decision, not part of this change;
- `proofbundle intoto --verify` accepts both types, each under its own contract.

A v0.1 statement relabelled as v0.2 is refused (it has no `evaluator`). A v0.2 statement verified with the
default call is refused (wrong type), so a caller that reads v0.1 fields never receives a v0.2 predicate.

## Readings of the draft

Where the draft text admits more than one reading, the reading implemented is named here; each is a
finding for the draft, not a settled question. Line numbers are those of
[docs/upstream/eval-result.md](upstream/eval-result.md).

- **A1, `salted: false`** (lines 107-111, schema lines 62-63). The draft says what `salted: true` means and
  shows `true` as a literal; it says nothing about `false`. Readings: `false` is not allowed; `false` is
  allowed with no stated meaning; `false` marks a plain content digest. Implemented: any boolean is
  accepted.
- **A2, a present `null`** (lines 116-118). Whether `"commitments": {"model": null}` counts as an
  identification. Readings: null is absence (the protobuf JSON mapping); null is a present, unusable value.
  Implemented: present and unusable, so it is refused, and beside a descriptor it counts as twice.
- **A3, "decimal string"** (line 83). No grammar is given. Readings: any string; a plain decimal
  `-?[0-9]+(\.[0-9]+)?`; a decimal with exponent or sign. Implemented: the plain decimal, the grammar the
  claim builder enforces.
- **A4, `suite.version`** (line 98). Whether both members of `{name, version}` are required. Implemented:
  both, as non-empty strings. The v0.1 emitter wrote `version: null` for a claim without a suite version;
  the v0.2 emitter refuses such a claim.
- **A5, `public-model` and the `model` descriptor** (lines 113-114, 126-127). The draft does not say whether
  a `public-model` subject requires a `model` descriptor, or whether its digest must equal the subject's.
  Implemented: no cross-check in the verifier; the CLI writes the descriptor with the subject's digest.
- **A6, `harness` members** (lines 138-142). Whether `name` and `version` are required when `harness` is
  present. Implemented: required.
- **A7, empty `evidence`** (line 132). An empty array violates no entry rule. Implemented: accepted.
- **A8, `sampleSize` range** (line 105). No range is given. Implemented: an integer from 0 to 2^53 − 1.

## Migration path (vendor namespace → in-toto.io)

Using a vendor `predicateType` for a v0.x predicate is common practice (cf. `cosign.sigstore.dev/…`,
`apko.dev/…`) and is fully in-toto-spec-conform — no upstream PR is needed for a self-hosted type. If
the predicate is accepted upstream (#565), the `predicateType` moves to an `https://in-toto.io/…`
namespace; at that point a redirect from the vendor URI to the registered one is added and the old
value is documented as an alias. The draft keeps the version `v0.1` for the revised shape, so the alias of
the registered type is the vendor **v0.2** type; the vendor v0.1 type names the earlier draft and is not an
alias of anything registered. Consumers match on the digest, so the subject binding is unaffected by a
predicateType rename.
