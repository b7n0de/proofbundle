# Pre-tag adversarial audit — proofbundle 3.7.0 audit-candidate

Internal six-lens / master-prompt adversarial audit run on the 3.7.0 release candidate
(commit 02509ca3, version bump + changelog PR head) before any tag. **This internal audit is
explicitly NOT a substitute for the external human crypto / protocol audit** — it is the
precondition the external reviewer starts from, not a replacement for their judgement.

Status boundary held: 3.7.0 remains audit-candidate, BETA, relation EXPERIMENTAL. Not stable,
not externally audited, not production-ready.

## Scope reviewed

The 3.7.0 delta on top of the audited 3.6.3 state: the lm-eval adapter sample-count provenance
binding (#116: `effective_samples` / `original_samples` / `skipped_samples` signed with
fail-closed validation), the conformance authority policy and commercial boundary docs (#107),
the CI dependency consolidation (#119 to #126), and the full verifier surface regression under
the new version.

## Six lenses, refute-to-kill jury

Six diverse falsification-first lenses with executable reproducers under the project venv,
followed by a three-juror refute-to-kill pass (one round, zero findings survived):

1. **Crypto / canonicality** — canonicalizer-absent minimal install fails closed
   (`ok=False`, `structure_ok=False`, never a raw ImportError, never fail-open); non-canonical
   re-signed payloads keep `structure_ok=False`.
2. **Budget / resource exhaustion** — direct-dict verify budgets (`json_nodes`, `string_len`,
   `json_depth`) enforced with typed errors; iterative structural walk, no recursion blowup.
3. **Malformed / type confusion** — every oversized / over-wide / deep / non-dict / non-b64 /
   empty-signature vector across the six DSSE verifiers yields a clean fail-closed verdict or a
   typed error, never an uncaught exception, never a false accept.
4. **Relation / subject binding** — all six invalid subject states under a declared
   `targetSubjectDigest` pin fail closed with distinct wire codes; multi-subject input never
   silently binds `subject[0]`; the same-key edge without `verified_under` stays unauthorized.
   Confirmed in both the Python engine and the Rust mirror.
5. **Assertion-by-absence** — validly signed but structurally deceptive findings registers
   (dangling / self / cyclic supersession, spoofed severity including zero-width and fullwidth
   unicode, duplicate-id contradiction) all fail closed; negated audit markers do not grant PASS.
6. **Packaging / supply chain** — reproducible build, byte-identical sdists, sdist-install test
   run fully green, exact graft/prune contract; nothing fails open.

Four standing regression targets from earlier audit rounds were attacked by name and confirmed
fail-closed (subject-absent binding, canonicalizer-absent minimal environment, same-key
authorization edge, malformed-input verdict stability), plus the two register-integrity classes
learned in the previous round.

## Honest residuals (recorded, not blocking this audit)

- **P2, findings-register freshness:** the readiness gate does not bind the signed register to a
  tree version, so a validly signed but stale register could grant PASS on a newer tree.
  Recorded as a follow-up before external publication.
- **Documentation overclaim:** `rfc8785` is a hard core dependency while a doc comment still
  calls the verifier core dependency-free. Reconcile the wording; no code invariant is broken.

## Verdict

The 3.7.0 candidate withstood the audit: zero confirmed findings after the jury pass. Ready for
the owner-gated release decision; this record does not itself mean released or safe.
