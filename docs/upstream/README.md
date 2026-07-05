# Upstream materials (ready to submit, not yet opened)

These are drafts prepared for the **in-toto/attestation** project. They are held here and are **not**
opened as PRs until a maintainer signals interest on the tracking issue
([in-toto/attestation#565](https://github.com/in-toto/attestation/issues/565)) — the project reviews
new predicates "at the next maintainers meeting", and standards work is a marathon (the SVR predicate,
the closest precedent, took ~6 months and 66 review comments from spec to merge).

- [`eval-result.md`](eval-result.md) — the `eval-result/v0.1` predicate spec, written to the official
  `spec/predicates/template/template.md` (ITE-9) structure. When opened, the PR contains ONLY this spec
  file plus a one-line entry in `spec/predicates/README.md`. The protobuf definition is a **separate
  follow-up PR** (as SVR did it: spec #470 → proto #519 → README #537). Every commit is DCO signed off.

Nothing here is authoritative or standardized. The reference implementation is
[proofbundle](https://github.com/b7n0de/proofbundle) (`proofbundle intoto`).
