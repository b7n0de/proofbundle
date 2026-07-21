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

## Addendum — reconciled to the shipped v3.6.0 release tree (2026-07-17)

The section above was authored at the branch base, before the v3.6.0 release integration completed.
Several workstreams landed afterwards, so this addendum reconciles the record to what actually ships
in v3.6.0 (No-Fake: the audit trail must match the released code, not an earlier snapshot).

- **Most important post-audit event — an OTS CRITICAL was found and fixed.** A dedicated adversarial-deep-gate-grade
  six-lens re-review of the OTS calendar-risk hardening found a CRITICAL on the standalone
  `anchor verify-pack` / `verify_evidence_pack` surface: a self-fabricated Null-Op pack
  (`file_digest == canonicalRoot`, a `BitcoinBlockHeaderAttestation` planted directly on the root with
  no hash op) was confirmed as `ok: true` / exit 0, and a `LitecoinBlockHeaderAttestation` with a
  colliding integer height could confirm against a Bitcoin header. Both are fixed:
  `verify_opentimestamps` now requires at least one cryptographic hash op on the path to each
  attestation (`status: null_op` fail-closed otherwise) and filters to `isinstance
  BitcoinBlockHeaderAttestation`. See CHANGELOG `[3.6.0]` and the regression suite
  `tests/test_ots_calendar_hardening.py`. The canonical `verify --require-anchor` path was and remains
  unaffected. This CRITICAL post-dates the original audit above and is the reason the audit-candidate
  status boundary (BETA, external audit still the single open gate) is unchanged.
- **Matrix result against the shipped tree** (`scripts/audit_candidate_matrix.py --json`, live):
  **31 PASS, 0 PENDING, 1 DATA_BLOCKED, 1 EXTERNAL_PENDING, 0 FAIL** — greener than the base-snapshot
  figure above (the pre-tag pack now exists so C12.1 PASSes, and one previously DATA_BLOCKED check
  cleared). The direction is monotone: no check regressed.
- **Suite / differential**: the full test suite is green in CI across Python 3.10-3.14 on PR #101
  (the exact pytest count varies with installed extras and is authoritatively the CI `test` job, not a
  pinned number here); the differential crosscheck remains 54/54 conformance cases + 40 relation vectors
  Python == Rust.
- **0 open P0 / P1 still holds.** The OTS finding was resolved before this release; no P0/P1 is open.
  The single deliberately-open acceptance criterion remains the external human crypto / protocol audit.

## Addendum 2 — reconciled to the shipped v3.6.1 release tree (2026-07-18, P5 of the release-vorlauf)

The 3.6.1 security-patch cycle (Teil-1..Teil-5 audit findings + an iterative 6-lens adversarial deep-gate re-gate)
landed on top of the above. This addendum reconciles every number to the 3.6.1 tree; each carries its
command source (No-Fake, `b7n0de.pb_361_vorlauf.v2` P5). Numbers that changed vs the v3.6.0 addendum are
called out explicitly so nothing here contradicts the shipped state.

- **Audit-candidate matrix** (`python scripts/audit_candidate_matrix.py`, live on the 3.6.1 tree):
  **31 PASS, 0 PENDING, 1 DATA_BLOCKED (24h soak, env), 1 EXTERNAL_PENDING (the external audit), 0 FAIL** —
  identical shape to the v3.6.0 addendum, no regression. C12.2 now derives its "0 open P0/P1" from the
  SIGNED structured findings register (`audit_artifacts/findings_register_361.json`), not a lexical
  substring (RT-10 fix), so the 0-open claim is machine-checkable.
- **Differential Python==Rust crosscheck** (`PYTHONPATH=src python tools/pb_verify_rs/crosscheck.py`):
  now **56/56 conformance-corpus cases incl. 42 relation vectors** — CHANGED from the v3.6.0 figure of
  54/54 + 40 relation vectors (the 3.6.1 relation subject-pin work added conformance + relation vectors).
- **Test suite** (authoritatively the CI `test` job across Python 3.10-3.14; local command sources given,
  the exact count varies with installed extras): in-repo `pytest tests/ -q` = **1951 passed / 7 skipped**;
  from an EXTRACTED sdist `pip install proofbundle[eval,test] && pytest` = **1812 passed / 138 skipped / 0
  failed**; a bare `pip install proofbundle[eval]` degrades to clean skips = **1613 passed / 197 skipped /
  0 failed** (the shipped-sdist self-testability invariant, PB-2026-0718-L6-01). The v3.6.0 base figure of
  1655/118 above is a historical branch-base snapshot, NOT the shipped 3.6.1 count.
- **0 open P0 / P1** holds on the 3.6.1 tree, verified by the signed findings register (all Teil-2..Teil-5
  P0/P1 closed). The single deliberately-open gate remains the external human crypto/protocol audit; status
  boundary unchanged (audit-candidate BETA, relation/v0.1 EXPERIMENTAL, not stable/audited/production-ready).
