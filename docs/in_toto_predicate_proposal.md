<!-- Draft proposal to submit the eval-receipt predicate upstream to in-toto/attestation.
     HUMAN decides whether/when to open the PR/issue. Factual, no marketing. -->

# Draft — proposing an ML eval-result predicate for in-toto/attestation

## Context

in-toto has a generic [`test-result/v0.1`](https://github.com/in-toto/attestation/blob/main/spec/predicates/test-result.md)
predicate, but as of mid-2026 there is **no registered predicate for ML evaluation results**. Model
evaluations have properties a generic test result does not model: a metric threshold, a pass/fail against
it, and — importantly — the need to keep the model and dataset *private* while still proving the claim.

## What proofbundle already does

proofbundle emits an eval receipt as a self-hosted in-toto Statement v1
(`https://b7n0de.com/proofbundle/eval-receipt/v0.1`, see PREDICATE.md). Its subject is a **salted
commitment** to the model identifier (custom digest key, never `sha256`), and the predicate carries the
suite, per-metric `{comparator, threshold, passed}`, an optional harness name/version, and a `receipt`
that binds an Ed25519-signed, RFC 6962 Merkle-anchored bundle. Selective disclosure (SD-JWT, RFC 9901)
lets a holder reveal `passed`/`threshold` while withholding the exact score.

## Proposal

Register an `eval-result` (or `ml-eval-result`) predicate that extends the test-result shape with:

- `claims[]`: `{ metric, comparator, threshold, passed }` (a threshold-based pass, not just a status);
- privacy-preserving subjects: allow a **salted commitment** digest (documented as such, not `sha256`),
  since the evaluated model/dataset are often secret;
- an optional binding to an external signed receipt (anchor + selective disclosure).

proofbundle can serve as a reference emitter/verifier. Happy to align field names with test-result/v0.1
and iterate on the shape with the maintainers.

— Konrad Gruszka (ORCID 0009-0006-8947-6065)
