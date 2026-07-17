# Honest progress accounting (No-Overclaim)

The denominator is the full distance from today (3.3.0) to "4.0.0-stable, externally audited,
trustworthy". This is a factual progress statement, not a forward promise, and it is deliberately
placed in the readiness pack so an auditor reads our own honest number before forming theirs.

## Achievable in advance (internal, machine-checkable, no external party): ~85%

- **100% of the engineering work packages**: pins, statement, Rust parity of all paths, hermetic
  sdist, fuzz-soak, deterministic build, SLSA-L3, the formal model within its honest frame, docs, and
  this readiness pack.
- **100% of the internal adversarial audit** (the six-lens master-prompt pass run before every tag —
  see F7 discipline, `docs/PRE_TAG_AUDIT.md`).

## NOT achievable in advance (~15%, structurally external)

- **~8–10% external human audit + remediation of its UNKNOWN findings.** No readiness pack replaces a
  cryptographer's judgement of construction / protocol semantics / side-channels (IACR 2025/980
  confirms: formal covers logic, not primitives or side-channels).
- **~3–5% real interop / adoption** with external parties (a genuine five-case pass with an external
  reviewer such as Loek; in-toto maintainer guidance; first outside users). Our side is preparable;
  the other side is not.
- **~2% irreducible ceiling** (a full TEE-attestation path, whole-program verification, side-channel
  freedom) — deliberately outside 4.0.0, a permanent external/research remainder.

## Consequence

With the five front-loaded foundations plus the pre-tag audit discipline, the audit-candidate (3.6.0)
is reachable at ~85% of the total distance with **practically zero avoidable rework**; the remaining
~15% is, by definition, not anticipatable — only best-prepared, which is what this pack is.

## Where this number is enforced against drift

The 85% / 15% split lives here as a claim; the No-Overclaim discipline that keeps the project's public
statements from drifting ahead of the code is `scripts/claims_hygiene_check.py` (CI). The bump of the
PyPI `Development Status` classifier from `4 - Beta` to `5 - Production/Stable` stays gated on a
passing external review, never asserted ahead of one (`pyproject.toml`, `docs/AUDIT_READINESS.md`).
