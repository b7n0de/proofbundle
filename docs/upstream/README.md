# Upstream materials

The `eval-result` predicate is proposed to the **in-toto/attestation** project as
[in-toto/attestation#575](https://github.com/in-toto/attestation/pull/575), which is **open, not merged**.
Discussion started on the tracking issue
([in-toto/attestation#565](https://github.com/in-toto/attestation/issues/565)). Nothing here is
authoritative or standardized. The reference implementation is
[proofbundle](https://github.com/b7n0de/proofbundle) (`proofbundle intoto`).

- [`eval-result.md`](eval-result.md) is a mirror of the proposed spec file
  (`spec/predicates/eval-result.md`), so that proofbundle's own docs and the submission cannot drift
  apart. When the two differ, **the PR is the source of truth** and this copy is the one that is wrong.
  The PR contains only this spec file plus a one-line entry in `spec/predicates/README.md`; the protobuf
  definition is a separate follow-up PR (as SVR did it: spec #470, proto #519, README #537).

## What the mirror holds

The mirror is the upstream file byte for byte plus one thing: the repository's header comment after the
title, which says what the copy is and when it was last aligned. Remove that comment and the upstream
file remains.

The upstream file is the revised draft of 2026-09-28: the PR head `35c83da` plus the commits `3166f71`,
`4476f0e` and `648b764` (the `evaluator` role, exactly one of commitment and descriptor for each of
model and dataset, `salted` fixed to `true`, `evidence[]` with the digest of the artifact itself in place
of the `receipt` block). Whether those commits have reached the PR is not stated here; the PR shows it.

SHA-256 of the upstream file (the mirror without its header):
`122f8b2c0edcd3108517e4353a4433cebc72f54cd54aacd6d577640f9ded018d` (11806 bytes, git blob `46a33e7`).
`tests/test_intoto_spec_diff.py` removes the header and recomputes it, so any other edit of the mirror
fails. Line numbers quoted from the draft elsewhere in this repository are those of the upstream file;
in the mirror they are seven lines further down.

## The vendor types proofbundle emits

The draft proposes `https://in-toto.io/attestation/eval-result/v0.1`. Until a type is registered
upstream, the reference implementation emits vendor-namespaced types:

| vendor type | shape | status |
|---|---|---|
| `https://b7n0de.com/attestation/eval-result/v0.1` | the draft as of `35c83da`: `verifier`, both commitments required, `receipt` block | emitted and signed by released versions 2.0.0 to 6.1.0; verified under its own rules; still the CLI default |
| `https://b7n0de.com/attestation/eval-result/v0.2` | the revised draft mirrored here | `proofbundle intoto --predicate-version v0.2`; verified with its shape checked |

The in-toto.io draft keeps the version `v0.1` while its shape changed; the vendor namespace cannot,
because statements of the vendor v0.1 type already exist. If the draft is registered, the vendor v0.2
type is the alias of the registered type, not the vendor v0.1 type. Consumers match on the subject
digest, so a `predicateType` rename does not affect binding. The field-level migration is in
[`docs/IN_TOTO_PROFILE.md`](../IN_TOTO_PROFILE.md).
