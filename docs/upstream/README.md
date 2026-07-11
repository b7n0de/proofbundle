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
- [`eval_result.proto`](eval_result.proto) — the protobuf definition for the follow-up PR (WP-U1c),
  prepared NOW so the spec review is not the long pole twice: proto3, standard JSON mapping produces
  the spec's lowerCamelCase field names, layout mirroring
  `protos/in_toto_attestation/predicates/<name>/v0/` upstream.
- [`eval_result_example.cue`](eval_result_example.cue) — CUE constraints mirroring the spec's field
  rules (a policy starting point, per the new-predicate guidelines).
- `audit_artifacts/565_pr_body_draft.md` (repo root) — the READY spec-only PR body. **Send gate:**
  the PR is opened by the OWNER (or after the owner's explicit go), never by automation — the same
  owner-only rule that governs every comment on #565/#7.

Nothing here is authoritative or standardized. The reference implementation is
[proofbundle](https://github.com/b7n0de/proofbundle) (`proofbundle intoto`).
