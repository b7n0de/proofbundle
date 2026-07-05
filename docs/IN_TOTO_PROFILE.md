# in-toto profile: the `eval-result` predicate and the SVR export

Status: **PROPOSED**, under discussion at [in-toto/attestation#565](https://github.com/in-toto/attestation/issues/565).
Not standardized. The `predicateType` lives in a vendor namespace until (and unless) it is registered
upstream. Nothing here changes the native receipt or what it proves — see [NON_CLAIMS.md](NON_CLAIMS.md).

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
- an optional binding to an **external signed receipt** (and, later, an external time anchor).

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

## The `eval-result/v0.1` predicate

`predicateType`: `https://b7n0de.com/attestation/eval-result/v0.1` (vendor namespace; migration path
below). Statement `_type` is the standard `https://in-toto.io/Statement/v1`; the DSSE `payloadType` is
the canonical `application/vnd.in-toto+json`. Fields (lowerCamelCase; time fields are speaking RFC-3339,
never a bare `timestamp`):

| field | meaning |
|---|---|
| `verifier.id` | the emitter/verifier TypeURI |
| `evaluatedAt` | when the eval ran (from the signed receipt) |
| `suite` | `{name, version}` |
| `claims[]` | `{metric, comparator, threshold, passed}` — the threshold-based pass |
| `sampleSize` | `n` |
| `commitments` | `{model, dataset}`, each `{alg, value, salted:true}` — a **salted commitment**, NOT an artifact hash |
| `assuranceLevel` | `self_attested` \| `third_party` \| `reproduced` \| `enclave_attested` |
| `subjectProfile` | which subject profile produced the `subject` (below) |
| `preRegistration` | optional `{alg, value}` — present only if the receipt carries a prereg hash |
| `receipt` | optional `{schema, merkleRootB64}` — binds to the external signed receipt |
| `harness` | optional `{name, version}` |
| `anchors` | optional external time anchors (RFC 3161 TSA / OpenTimestamps); experimental, a separate `[anchors]` extra that is proposed and not yet shipped |

**Parsing rules** follow in-toto Statement v1: matching is on the subject `digest` alone; unknown
predicate fields are ignored by consumers; and the [Monotonic Principle](https://github.com/in-toto/attestation/blob/main/docs/validation.md)
applies — a verifier denies unless a valid attestation exists.

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

1. **Whose key signed it, and do you trust that key for this claim?** (`verifier.id` + the DSSE key.)
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

## Migration path (vendor namespace → in-toto.io)

Using a vendor `predicateType` for a v0.x predicate is common practice (cf. `cosign.sigstore.dev/…`,
`apko.dev/…`) and is fully in-toto-spec-conform — no upstream PR is needed for a self-hosted type. If
the predicate is accepted upstream (#565), the `predicateType` moves to an `https://in-toto.io/…`
namespace; at that point a redirect from the vendor URI to the registered one is added and the old
value is documented as an alias. Consumers match on the digest, so the subject binding is unaffected by
a predicateType rename.
