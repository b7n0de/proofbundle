# Falsification pass F1–F7 on the 3.8.0 candidate — INTERIM, the full run has NOT finished

**Status: the N-lens jury has not run yet, so this is not a pre-tag audit record.** This file
deliberately does not assert a completed adversarial audit; `scripts/pre_tag_audit_gate.py` must stay
red until the full run exists. What follows is one lens — falsification-first with executable
exploits — measured on the candidate.

| Field | Value |
|---|---|
| Candidate | `release/v3.8.0` @ `f64d35e` (base `origin/main` `ac0688c`) |
| Targets | frozen in `PRE_REGISTRATION_380.md` before any of this ran |
| Environment | `[pq,pytest,test,dev,anchors]`, `cryptography 50.0.0`, `rfc3161-client 1.0.8` |
| Probe | `scratchpad/falsifikation_380.py`, run from the candidate worktree |

## Result: seven targets stated, five hold, TWO FELL

The first version of this table graded all seven **holds**. Two of those grades were wrong and are
corrected below rather than silently amended; the falsification pass found them by being pointed at
this file. Both failures share one shape: the target was graded against the CHEAPEST reading of its own
sentence. F6 asked whether the CHANGELOG claims something the tree does not do, and was answered by
checking that the named commits and files EXIST. F7 asked whether a fourth place carries a version, and
was answered with a repository-wide grep for the literal `3.8.0`.

The class is worth naming because it recurs: **a computed coupling is invisible to a literal search.**
`scripts/pre_tag_audit_gate.py::_version_token` turns `3.8.0` into the directory name `380` at run time,
so the path `audit_artifacts/380/` is version-coupled without the string `3.8.0` appearing anywhere in
it. A grep for the version number is not a weak test of that coupling, it is a structurally blind one —
and F7 was the target written to catch exactly this.

| # | Target | Outcome | Evidence |
|---|---|---|---|
| F1 | `--expected-origin` accepts a DIFFERENT origin (flag is decorative) | **holds** | `rc=1`, `ok=False`, `log_ok=False` against `example.invalid/some-other-log` |
| F2 | Omitting the flag changes an existing verdict | **holds** | `rc 0/0`; all seven reported fields (`ok`, `log_ok`, `witnesses_ok`, `inclusion_ok`, `origin`, `tree_size`, `index`) identical with the flag absent and with a matching origin |
| F3 | The failure is indistinguishable from a broken signature | **holds** | on mismatch `inclusion_ok` stays `True` and `origin` still reports the real value; the text path prints the expected origin |
| F4 | The comparison is not exact | **holds** | seven near-misses each rejected: prefix, trailing space, leading space, uppercase, mixed case, trailing newline, empty string |
| F5 | The flag raises instead of returning a verdict | **holds** | four hostile values (100 000 chars, NUL/control bytes, embedded newlines, bidi override) each returned `rc=1` without raising |
| F6 | The CHANGELOG claims something the tree does not do | **FELL** | the `### Added` / `### Fixed` entries check out (`911fd5c`, `03bf127`, `331f8cc` resolve; `tests/test_verify_proof_expected_origin.py` and `TestMarkovianLogMldsaKeysAreAbsent` exist; the manifest test pins the measured reason). The STATUS PARAGRAPH above them was never read, and it carried two false claims: `expected_origin` was dated "since 3.6" when `src/proofbundle/tlogproof.py` has carried it since **1.3.0** (3 occurrences at `v1.3.0`, continuous to `v3.7.0`), and the precedent claim "never shipped a new user-facing CLI flag in a patch release" is contradicted by four patch releases shipping ten flags (3.1.1, 3.1.3, 3.2.2, 3.2.3 — measured by diffing `add_argument("--…")` in `src/proofbundle/cli.py` across the tags). Both are corrected in the CHANGELOG; the "since 3.6" wording also sits in shipped source at `src/proofbundle/cli.py:949` on `main`, which is a pre-existing finding and is reported, not silently amended here |
| F7 | Version inconsistent, or a fourth place carries a version | **FELL** | `check_version_and_changelog: OK` is correct, but the grep claim in the first version of this row was false on its own digest: `3.8.0` appears in **four** files at `f64d35e` (the CHANGELOG too) and **seven** at `f1e9cea`. More importantly the target itself was met and missed — the fourth version-coupled place is `audit_artifacts/380/`, whose name `pre_tag_audit_gate.py::_version_token` computes from the version at run time. Measured consequence: `python scripts/pre_tag_audit_gate.py --strict` exits 1 and `tests/test_roadmap_frontload_foundations.py::TestF7PreTagAudit` is the single red test in an otherwise green suite (`1 failed, 1970 passed, 116 skipped`), while `main` at `ac0688c` is green across all 13 CI jobs |

## Honest gap in this probe, declared rather than left implicit

**The NFD case of F4 was not exercised.** `markovianprotocol.com/log` is pure ASCII, so
`unicodedata.normalize("NFD", origin)` returns the identical string and the probe's own
"skip if identical to the origin" branch skipped it. The unicode-normalisation axis of F4 is therefore
**untested**, not passed. Closing it needs a vector whose origin carries a decomposable character;
none exists in the corpus today.

## What this does and does not establish

It establishes that the one behavioural change in this release does what it says, does not disturb the
default path, and fails in a way a relying party can read. It establishes nothing about the five other
lenses, the learned-class pre-sweep replay, or the gate meta-test — those have not run. No verdict is
claimed here, and no `WITHSTANDS_DEEPGATE` tag is asserted for this digest.
