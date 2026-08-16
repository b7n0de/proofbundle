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

## Result: seven targets stated, four hold, THREE FELL

The first version of this table graded all seven **holds**. Three of those grades were wrong and are
corrected below rather than silently amended; they were found by pointing the falsification pass at
this file instead of only at the release. All three share one shape: the target was graded against the
CHEAPEST reading of its own sentence. F6 asked whether the CHANGELOG claims something the tree does not
do, and was answered by checking that the named commits and files EXIST — the status paragraph carrying
two false claims was never read. F7 asked whether a fourth place carries a version, and was answered
with a repository-wide grep for the literal `3.8.0`. F5 registered four value classes and reported
four values, but not the same four: `non-str` was dropped without the note §5 requires, and it was the
class that had a live defect in it.

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
| F5 | The flag raises instead of returning a verdict | **FELL** | the four values reported here (100 000 chars, NUL/control bytes, embedded newlines, bidi override) do each return `rc=1` without raising — but the registered target names **"non-str, empty, very long, and control-character values"**, and the `non-str` class was dropped without the note the pre-registration requires for an unreachable target (§5: *"a target that turns out to be unreachable is recorded as unreachable, not removed"*). It was not unreachable, and it was not empty. Measured on the candidate against the real fixture, with the good call returning `ok=True` first so the harness is known to work: `int` / `bytes` / `list` / `dict` / `nan` all reach a clean `ok=False` verdict, and an object whose `__eq__` raises escapes with a raw **`RuntimeError`** out of a surface `tlogproof.py` documents as never-raise. The catch clause is `except (ProofBundleError, ValueError, TypeError, KeyError)` and `RuntimeError` is not in it. HONEST SEVERITY: the hostile object is supplied by the relying party's own code, not over the wire, so this is type confusion in one's own configuration and not a remote path. It is still the exception-taxonomy axis of the never-raise class that PR #141 addresses, on a surface that IS inside `_MODULES` — the family property never reaches it because it fuzzes only positional argument 0 and skips every parameter with a default, and `expected_origin` is a defaulted keyword |
| F6 | The CHANGELOG claims something the tree does not do | **FELL** | the `### Added` / `### Fixed` entries check out (`911fd5c`, `03bf127`, `331f8cc` resolve; `tests/test_verify_proof_expected_origin.py` and `TestMarkovianLogMldsaKeysAreAbsent` exist; the manifest test pins the measured reason). The STATUS PARAGRAPH above them was never read, and it carried two false claims: `expected_origin` was dated "since 3.6" when `src/proofbundle/tlogproof.py` has carried it since **1.3.0** (3 occurrences at `v1.3.0`, continuous to `v3.7.0`), and the precedent claim "never shipped a new user-facing CLI flag in a patch release" is contradicted by four patch releases shipping ten flags (3.1.1, 3.1.3, 3.2.2, 3.2.3 — measured by diffing `add_argument("--…")` in `src/proofbundle/cli.py` across the tags). Both are corrected in the CHANGELOG; the "since 3.6" wording also sits in shipped source at `src/proofbundle/cli.py:949` on `main`, which is a pre-existing finding and is reported, not silently amended here |
| F7 | Version inconsistent, or a fourth place carries a version | **FELL** | `check_version_and_changelog: OK` is correct, but the grep claim in the first version of this row was false on its own digest: `3.8.0` appears in **four** files at `f64d35e` (the CHANGELOG too) and **seven** at `f1e9cea`. More importantly the target itself was met and missed — the fourth version-coupled place is `audit_artifacts/380/`, whose name `pre_tag_audit_gate.py::_version_token` computes from the version at run time. Measured consequence: `python scripts/pre_tag_audit_gate.py --strict` exits 1 and `tests/test_roadmap_frontload_foundations.py::TestF7PreTagAudit` is the single red test in an otherwise green suite (`1 failed, 1970 passed, 116 skipped`), while `main` at `ac0688c` is green across all 13 CI jobs |

## The declared gap was declared for a wrong reason — and the axis holds

The first version of this section said the NFD case of F4 **could not** be exercised: every corpus
origin is pure ASCII, so `unicodedata.normalize("NFD", origin)` returns an identical string and the
probe's own "skip if identical" branch skipped it. It then concluded that closing the axis "needs a
vector whose origin carries a decomposable character; none exists in the corpus today."

The factual half is right — all corpus origins are ASCII (`markovianprotocol.com/log`,
`log2025-1.rekor.sigstore.dev`, `go.sum database tree`). The conclusion was convenient rather than
compelling: **the corpus is not the only source of a vector.** `checkpoint.sign_checkpoint`,
`checkpoint.vkey` and `tlogproof.format_tlog_proof` are shipped public API and accept any origin
without whitespace, so a decomposable one takes about fifteen lines and no fixture at all. Under the
pre-registration's own §5 a target filed as unreachable that is in fact reachable is a misfiling, not
a gap.

Measured, positive control FIRST so the harness is known to produce a passing verdict before any
negative is read (`ok=True log_ok=True inclusion_ok=True` on an ASCII origin with no expectation):

| Checkpoint built in | expecting NFC | expecting NFD | expectation absent |
|---|---|---|---|
| NFC (`café.example/log`) | `ok=True` | `ok=False` | `ok=True` |
| NFD (same, decomposed) | `ok=False` | `ok=True` | `ok=True` |

**The unicode-normalisation axis of F4 holds.** `tlogproof.py` compares
`log_res["origin"] == expected_origin` — codepoint equality — and nothing under `src/proofbundle/`
normalises an origin on this path, so the two forms stay distinguishable in both directions while the
absent case is unaffected. The axis is now tested and passed rather than declared untestable.

## What this does and does not establish

It establishes that the one behavioural change in this release does what it says, does not disturb the
default path, and fails in a way a relying party can read. It establishes nothing about the five other
lenses, the learned-class pre-sweep replay, or the gate meta-test — those have not run. No verdict is
claimed here, and no `WITHSTANDS_DEEPGATE` tag is asserted for this digest.
