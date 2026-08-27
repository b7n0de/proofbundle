# Pre-tag adversarial deep-gate — run record — release 5.0.0

This is the run record for the pre-tag adversarial deep gate (DEEP 6 lenses / up to 7 iterations,
the MAJOR/external mode) whose six falsification targets were frozen, before the run, in
[PRE_REGISTRATION_DEEP_500.md](PRE_REGISTRATION_DEEP_500.md). Each target is refuted-or-holds by an
executable probe, not an opinion.

**It took four runs.** The first three returned `FIX_FIRST`, each with real findings; the fourth
returned `WITHSTANDS_DEEPGATE` with zero jury-confirmed findings. That sequence is the honest
content of this record, and it is written out below rather than summarised away.

Attestation line (the pre-tag gate reads this file for exactly this line; the CHANGELOG text is
presentational and cannot grant it):

pre-tag-adversarial-audit: RUN | version=5.0.0

## Digests

```
iteration 1 (pre-registration frozen BEFORE the run)
  graded commit   a7d162a   (release/v5.0.0, branched from origin/main c669d39)
  graded src tree 8897965acbac94585cc57267abc54ce4c9d06099
  verdict         FIX_FIRST — 1 confirmed finding (L6-01, P3)

iteration 2 (after the L6-01 class fix)
  graded commit   ab90699
  verdict         FIX_FIRST — 2 confirmed findings (L2-BDOS-HUGEINT, L6-F1-SDIST-PYYAML, both P2)

iteration 3 (after both P2 class fixes)
  graded commit   388a4d4
  verdict         FIX_FIRST — 2 confirmed findings (L2-BDOS-RENEWAL-HUGEINT-01/02, both P2)

iteration 4 (after the render-axis class fix) — THE DIGEST THIS VERDICT BINDS TO
  graded commit   9bc179e
  verdict         WITHSTANDS_DEEPGATE — 0 jury-confirmed findings
  ledger replay   pass, 80 of 140 learned classes replayed (coverage 0.5714), 0 regressed
```

A verdict for an earlier digest does not carry to a later one. This verdict binds to `9bc179e`.

## What each round found, and why the sequence matters

**Round 1 — L6-01 (P3), three lenses convergent.** `scripts/audit_candidate_matrix.py` reported
`audit_candidate_ready=True` with exit 0 while its `VERSION_UNDER_TEST` pin read `3.6.0` and the
package shipped `5.0.0`. A release-readiness gate wired into CI was attesting readiness from
evidence about a different release, and nothing compared the two numbers. Fixed as a class: the pin
is bound to the shipping identity in three states (`bound` / `drift` / `not_determinable`), all four
call sites read one budget dimension, and the literal copy is gone. *Editing the literal would have
made the instance green and recreated the class at the next bump — the gate's own remediation says
so.*

**Round 2 — L2-BDOS-HUGEINT (P2) and L6-F1-SDIST-PYYAML (P2).** The first: `verify_inclusion`,
`verify_consistency` and `verify_sample_opening` had no magnitude guard, so `2**300000` bought 3.3
seconds of CPU while returning the correct `False` (~34 s extrapolated at `2**1000000`, against
`verify_bundle`'s 0.015 s). The 8192-bit ceiling had existed since an earlier round — as a literal
*inside* `bundle._require_int`, which the three argument-taking surfaces could not honour. The
second: from an extracted sdist in a base-only install, seven tests FAILED instead of skipping; the
production code correctly reported `DATA_BLOCKED`, and the *test* turned the third state into a
failure.

**Round 3 — L2-BDOS-RENEWAL-HUGEINT-01/02 (P2), the neighbour of round 2's own fix.** Round 2's
sweep asked *which surfaces take an untrusted integer as an argument*. It never asked what happens
to the value. CPython caps int→str at `sys.get_int_max_str_digits` (4300, CVE-2020-10735), so
interpolating an untrusted integer into a **diagnostic message** raised a raw `ValueError` out of a
never-raise surface. The value was not computed with — it was used to explain why the input was
rejected. Fixed with three different, contract-appropriate answers: eight diagnostic sites render
through `render_safe` (`<int, 16610 bits>`), `token()` *refuses* the magnitude typed rather than
rendering it differently (there the string IS the signed material, and shortening it would break
every existing signature), and `verify_sequence` checks before the token path and returns a verdict.

**Round 4 — clean.** Zero findings survived the three-juror refute-to-kill.

## Targets — result at iteration 4

| # | Target (pre-registered invariant) | Result |
|---|---|---|
| E1 | The cap removes work, not acceptance — no verdict changes. | HOLDS |
| E2 | Exactly ONE input class changes its exit code, and it is the one the CHANGELOG names. | HOLDS |
| E3 | `expected_origin_wellformed` is purely additive. | HOLDS |
| E4 | Nothing loosens an existing check; every shipped vector keeps its verdict. | HOLDS |
| E5 | The two fail-closed additions refuse only unusable states. | HOLDS |
| E6 | The record's and CHANGELOG's numbers and claims match the tree. | HOLDS |

## Standing targets RT-01..RT-04 — each explicitly attacked

* **RT-01** (relation subject-pin absent/ambiguous/malformed/mismatch): each state yields
  `lineage=FAIL` with the exact wire code, never `VERIFIED`, never a silent `subject[0]` bind.
  Verified end-to-end through the CLI with a genuine two-subject DSSE target (`rc=2`,
  `safeForAutomation=False`, no traceback). **Fail-closed confirmed.**
* **RT-02** (JCS/rfc8785 absent, minimal install): simulated by forcing `ImportError` on the lazy
  import. A genuinely-signed decision receipt and a signed relation statement both return
  `ok=False` / `structure_ok=False` with an explicit "canonicalizer unavailable — hash_binding
  fail-closed", under `strict=True` **and** `strict=False`. Never a raw `ImportError`, never
  `ok=true`. **Fail-closed confirmed.**
* **RT-03** (same-key edge without `verified_under`): `None` / `''` / missing / different-well-formed
  each produce `RELATION_SIGNER_UNAUTHORIZED`; the positive control (byte-match to the successor
  key) produces no violation. **Fail-closed confirmed.**
* **RT-04** (malformed untrusted input → stable verdict, never a raw exception): ~15 exported
  `verify_*` surfaces plus `verify_bundle`/`load_bundle` fed `None`, wrong types, non-base64, wrong
  length, huge negative ints, lone surrogates — every escape a documented **typed**
  `ProofBundleError`. CLI: 205 malformed-file runs including directory / `/dev/zero` / FIFO /
  0-byte / path-traversal → exit distribution `{2: 193, 0: 7, 1: 4}`, **zero raw tracebacks**, zero
  exit codes outside `{0,1,2,3}`. The seven exit-0 are read-only `anchor inspect`
  (`self_contained=False`, never confirms). **Fail-closed confirmed.**

## Packaging (L6)

Two normalised sdists **byte-identical** (`sha256 747f654f…bc01`); grafted dirs present, pruned dirs
absent; zero `*.rs`, zero `__pycache__`; all third-party actions SHA-pinned across nine workflows;
`pip install <sdist>` then pytest from a non-git temp tree → `rc=0`, **2154 passed / 198 skipped /
0 failed**; `PKG-INFO Version == __version__ == 5.0.0`; no key, secret, `.venv` or `.git` leak.

## NOT rubber-stamped — one candidate carried forward openly

L5 raised a **reproducible** register fail-open candidate: `findings_register`'s `superseded_by`
link resolution applies `_norm()` (NFKC + Cc/Cf stripping), so a `superseded_by` that
normalises-equal to a byte-**distinct** clean id silently resolves and can drop an open P0 from the
count. Reproducer `gate6_L5_supersede_probe.py`, with a passing control.

**It did not survive the three-juror refute-to-kill and is therefore not a confirmed finding of this
run.** Exploitability is reduced by key-custody separation: a validly-signed hostile register is
required, and a key holder can already write `status='closed'` directly.

It is recorded here anyway, because three things about it are true: it also fires on an honest
author's `superseded_by` encoding typo; it touches the module's own core invariant *"a finding must
never vanish from the count"*; and the existing regression
(`tests/test_findings_register_identity_axis.py`) covers only the same-character **collision**
direction, not this clean-decoy variant. It goes into the release recommendation as a
fix-the-class follow-up, not into a drawer.

## Ledger coverage — the honest gap

The learned-class replay covered **80 of 140** classes (0.5714) and returned `pass` with zero
regressions. **Sixty classes were not re-exercised this round** — they rest on their standing
regression tests, not on fresh gate evidence from this run. That is this round's coverage gap and it
is stated rather than rounded away.

Specific closed classes were additionally confirmed green *in passing* by the lens probes (not
merely replayed): canonicality fail-open, malformed never-raise, subject-pin, relation distance
invariance, both hugeint classes via `render_safe`/magnitude, the register id-normalisation
collision path, the pre-tag substring-negation bypass, and L6-01's version-pin drift.

## Method compliance

Falsification-first with executable reproducers (opinion does not count). Negative state including
**absent** (no pin supplied, empty proof list, zero cap, canonicalizer missing). Independent oracle
and anti-parity: the exit-code comparison ran against an actual v4.0.0 checkout, and each fix's
regression carries a must-still-pass half so no guard becomes a constant refusal. Minimal
environment: as-shipped, without the `[experimental]` / `[pq]` extras. Gate-meta-test: each round's
fix was re-gated by an independent pass, and rounds 2 and 3 are the living proof that the gate
catches its own author's incomplete sweep.

## No-Fake boundary

`WITHSTANDS_DEEPGATE` on `9bc179e` means **"ready for the Owner's tag"**, NOT "released" and NOT
"proven secure". This record grades the code that would ship; the tag, the merge to main and the
PyPI publish remain separate Owner acts. Four runs were needed, three of which found real defects —
that is what the gate is for, and it is not evidence that the fourth is exhaustive.
