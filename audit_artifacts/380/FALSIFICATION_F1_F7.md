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

## Result: seven targets stated, seven hold, none fell

| # | Target | Outcome | Evidence |
|---|---|---|---|
| F1 | `--expected-origin` accepts a DIFFERENT origin (flag is decorative) | **holds** | `rc=1`, `ok=False`, `log_ok=False` against `example.invalid/some-other-log` |
| F2 | Omitting the flag changes an existing verdict | **holds** | `rc 0/0`; all seven reported fields (`ok`, `log_ok`, `witnesses_ok`, `inclusion_ok`, `origin`, `tree_size`, `index`) identical with the flag absent and with a matching origin |
| F3 | The failure is indistinguishable from a broken signature | **holds** | on mismatch `inclusion_ok` stays `True` and `origin` still reports the real value; the text path prints the expected origin |
| F4 | The comparison is not exact | **holds** | seven near-misses each rejected: prefix, trailing space, leading space, uppercase, mixed case, trailing newline, empty string |
| F5 | The flag raises instead of returning a verdict | **holds** | four hostile values (100 000 chars, NUL/control bytes, embedded newlines, bidi override) each returned `rc=1` without raising |
| F6 | The CHANGELOG claims something the tree does not do | **holds** | `911fd5c`, `03bf127`, `331f8cc` all resolve; `tests/test_verify_proof_expected_origin.py` exists; `TestMarkovianLogMldsaKeysAreAbsent` exists; the manifest test pins the measured reason (`no ML-DSA-44 verifier key`), not the old wording |
| F7 | Version inconsistent, or a fourth place carries a version | **holds** | `check_version_and_changelog: OK`; a repo-wide grep finds `3.8.0` in exactly the three enforced files and nowhere else |

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
