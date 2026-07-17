# Pre-tag adversarial audit — proofbundle 3.6.0 audit-candidate

Internal six-lens / master-prompt-v2 adversarial audit run before the 3.6.0 tag (Front-Load §7
discipline). **This internal audit is explicitly NOT a substitute for the external human crypto /
protocol audit** — it is the precondition the external reviewer starts from, not a replacement for
their judgement (see `docs/readiness_pack/AUDITOR_OPEN_POINTS.md`).

Status boundary held: 3.6.0 is audit-candidate, BETA, relation EXPERIMENTAL. Not stable, not audited,
not production-ready.

## Scope reviewed

The 3.6.0 delta: the 33-check audit-candidate matrix, the trust-pack payloadType-binding change
(`verify_trust_pack`), the WP-B locked test manifest, the WP-D fuzz-soak harness + ClusterFuzzLite leg +
regression vectors, the WP-C differential evidence, the WP-G readiness pack, and the claims-hygiene
extension.

## Six lenses

1. **No-Fake / No-Overclaim** — the matrix separates `audit_candidate_ready` (nothing broken/unclosed)
   from `fully_verified_here` (also 0 DATA_BLOCKED); a DATA_BLOCKED is never counted as a PASS (test:
   `test_data_blocked_is_not_a_pass`). O7 stays RESERVED with no fabricated proof. The Rust PENDING
   surface is documented as deliberately not-covered (no fake 100%). The 24h soak is honestly
   DATA_BLOCKED until a real artifact records it; the self-receipt is honestly advisory (ephemeral key).
2. **Security / fail-closed** — the trust-pack payloadType binding uses `!=` (never raises on any field
   type, incl. dict/list/None), early-returns `ok=False` with the automation summary, and is strictly
   more restrictive (sign_trust_pack always sets the in-toto constant, so no legitimate path breaks).
   Negative vectors green (`test_trust_pack_payloadtype_negatives.py`). The fuzz-soak OSError excusal is
   narrowed to `union_str AND isinstance(payload, str)` so it cannot mask a real crash.
3. **Correctness / regression** — full suite 1655 passed / 118 skipped; differential crosscheck 54/54
   corpus cases + 40 relation vectors Python==Rust; every foundation gate green. The matrix is
   crash-safe (an erroring check becomes an honest FAIL, test: `test_an_erroring_check_is_honest_fail`).
4. **Robustness / edge cases** — gates handle missing files without crashing; `test_manifest_gate`
   treats an unparseable collection or a collection error as a FAIL; the soak's false-accept detector
   and never-raise contract are exercised bidirectionally.
5. **Maintainability / SOTA** — ClusterFuzzLite config matches current SOTA (Dockerfile + build.sh +
   project.yaml, address/undefined sanitizers, coverage-regression); SLSA-L3 shape acknowledged;
   reproducible sdist via tar-normalization beyond SOURCE_DATE_EPOCH. Ruff clean.
6. **Honesty of the deliverable boundary** — `AUDITOR_OPEN_POINTS.md` itemizes exactly what the machine
   cannot decide (primitive hardness, protocol semantics, side channels), and the single EXTERNAL_PENDING
   gate is the external audit itself.

## Findings and dispositions

| # | Lens | Severity | Finding | Disposition |
|---|---|---|---|---|
| F1 | Correctness | P2 | matrix C9.1 used the wrong flag (`--check-determinism` vs the real `--check`) so the determinism check could never PASS | FIXED |
| F2 | Correctness | P2 | `_formal()` used `import model`, which a top-level `model` module on sys.path could shadow | FIXED (path-load) |
| F3 | Robustness | P2 | fuzz-soak false-flagged a `verify_bundle` path-resolution OSError on a str input as a crash | FIXED (OSError excusal narrowed to union-str path verifiers) |
| F4 | Maintainability | P3 | mid-file `import functools`; dead `per_parser_iters` variable | FIXED (import to top; per-parser iterations now surfaced as coverage evidence) |
| F5 | No-Fake | P3 | claims-hygiene self-reference (the CHANGELOG bullet naming the forbidden phrasings tripped the gate) | FIXED (inline-code wrapping); readiness docs added to the scan set (PROGRESS.md excluded, it quotes the future goal) |

## Verdict

**0 open P0 / P1.** The five findings above were P2/P3 and are all fixed. The two DATA_BLOCKED matrix
checks (the full 24h soak and the two-sdist byte-identity) are not defects: they need a soak box and the
`build` backend respectively, and the byte-identity is proven in CI on every PR by
`published-artifact-gate.yml`. The single deliberately-open acceptance criterion is the external audit.

`audit_candidate_ready = True` (29 PASS, 1 PENDING = this pack now written, 2 DATA_BLOCKED, 1
EXTERNAL_PENDING, 0 FAIL).
