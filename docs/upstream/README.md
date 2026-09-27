# Upstream materials

The `eval-result` predicate is proposed to the **in-toto/attestation** project as
[in-toto/attestation#575](https://github.com/in-toto/attestation/pull/575), which is **open, not merged**.
Discussion started on the tracking issue
([in-toto/attestation#565](https://github.com/in-toto/attestation/issues/565)). Nothing here is
authoritative or standardized. The reference implementation is
[proofbundle](https://github.com/b7n0de/proofbundle) (`proofbundle intoto`).

- [`eval-result.md`](eval-result.md) is a mirror of the proposed spec file
  (`spec/predicates/eval-result.md`), byte for byte, so that proofbundle's own docs and the submission
  cannot drift apart. When the two differ, **the PR is the source of truth** and this copy is the one
  that is wrong. The PR contains only this spec file plus a one-line entry in
  `spec/predicates/README.md`; the protobuf definition is a separate follow-up PR (as SVR did it: spec
  #470, proto #519, README #537).

## What the mirror holds

The revised draft: the PR head `35c83da` plus three commits prepared on top of it (the `evaluator` role,
one identification each for model and dataset, `evidence[]` in place of the `receipt` block). Whether
those commits have reached the PR is not stated here; the PR shows it.

SHA-256 of the mirror as committed: `9b971867f7e8b0ff6213db3add8e43d2235487f3ca50c553d4df4399b4bc8d29`
(10231 bytes). `tests/test_intoto_spec_diff.py` recomputes it, so an edit of the mirror that does not
also update this line fails.

The mirror carries no proofbundle-specific note, because the upstream file carries none. What used to
stand in the mirror as a comment and an appended section stands here instead.

## The vendor types proofbundle emits

The draft proposes `https://in-toto.io/attestation/eval-result/v0.1`. Until a type is registered
upstream, the reference implementation emits vendor-namespaced types:

| vendor type | shape | status |
|---|---|---|
| `https://b7n0de.com/attestation/eval-result/v0.1` | the draft as of `35c83da`: `verifier`, both commitments required, `receipt` block | emitted and signed by released versions; verified under its own contract; still the CLI default |
| `https://b7n0de.com/attestation/eval-result/v0.2` | the revised draft mirrored here | `proofbundle intoto --predicate-version v0.2`; verified with its shape checked |

The in-toto.io draft keeps the version `v0.1` while its shape changed; the vendor namespace cannot,
because statements of the vendor v0.1 type already exist. If the draft is registered, the vendor v0.2
type is the alias of the registered type, not the vendor v0.1 type. Consumers match on the subject
digest, so a `predicateType` rename does not affect binding. The field-level migration is in
[`docs/IN_TOTO_PROFILE.md`](../IN_TOTO_PROFILE.md).
