# PRE-REGISTRATION — deep gate on the 3.8.0 release candidate

**Frozen 2026-08-16, before the run.** This document exists so the run cannot be graded against
targets chosen after seeing its results. Nothing below may be edited once the jury starts; a target
that turns out to be unreachable is recorded as unreachable, not removed.

| Field | Value |
|---|---|
| Subject | `b7n0de/proofbundle`, branch `release/v3.8.0` |
| Candidate commit | `f64d35e` (base `origin/main` `ac0688c`) |
| Version under test | 3.8.0 |
| Mode | `[DEEP-GATE: DEEP 6L/7I]` — a release candidate always declares DEEP |
| Methodology | v4, resolved from `office/governance/berkeley_gate_surfaces.json::canonical_prompt_version` |
| Verdict tag sought | `WITHSTANDS_DEEPGATE` on **this digest**, not on a neighbouring one |

## 1. Threat model for this candidate

The shipped delta over 3.7.0 is **one file**: `src/proofbundle/cli.py`, +14 lines, adding
`verify-proof --expected-origin`. Everything else that landed since 3.7.0 is fixture, test, CI or
documentation. The threat model is therefore narrow and stated narrowly — a wide model here would be
theatre.

**The capability under test:** a relying party at the command line can now demand that a validly
signed checkpoint carries the origin it expects. Before this, it could not. The interesting failure is
not "the flag does nothing" — that a test would catch — but the two asymmetric ones below.

## 2. Falsification targets, frozen

Each target is stated as something that would make the release **wrong**, with the shape of the
executable exploit that would demonstrate it. Opinion does not count; a target falls only to a run.

| # | Target — what would falsify the candidate | Exploit shape |
|---|---|---|
| F1 | `--expected-origin` accepts a checkpoint from a DIFFERENT origin (the flag is decorative) | craft a signed checkpoint with origin A, verify with `--expected-origin B`, expect exit 1; a 0 falsifies |
| F2 | Omitting the flag CHANGES an existing verdict (silent behaviour change in a release claiming none) | run every corpus vector with and without the flag absent; any verdict difference falsifies |
| F3 | The flag's failure is indistinguishable from a broken signature (a relying party misreads the cause) | mismatching origin must keep `inclusion_ok` true and name the expectation; a bare FAIL falsifies |
| F4 | The origin comparison is not exact (prefix, case, unicode, trailing byte) | feed near-miss origins: `example.com/log ` (trailing space), case variants, NFC/NFD pairs, a prefix `example.com/lo` |
| F5 | The flag raises rather than returning a verdict on hostile input (never-raise contract) | `--expected-origin` with non-str, empty, very long, and control-character values |
| F6 | The CHANGELOG claims something the tree does not do | every claim in the `[3.8.0]` section must point at a commit or a test that exists |
| F7 | The version bump is inconsistent across the three enforced places, or a fourth place carries a version | `check_version_and_changelog.py` plus a grep for version-shaped strings |

## 3. Negative-state requirement, including **absent**

For every target, three states must be exercised, and `absent` is the one usually skipped:

- **present and correct** — the flag is given and matches
- **present and wrong** — the flag is given and does not match
- **absent** — the flag is not given at all

`absent` is pre-registered explicitly because the default path is the one every existing user is on,
and a release that changes it while claiming it does not is the worst outcome available here.

## 4. Standing targets carried in (RT-01..RT-08)

The standing round-table targets are in scope unchanged. Two are called out because this candidate
touches their surface:

- **RT-05 / RT-06 (category missed?)** — the deliberate question "is there a class here that the
  category names do not cover?" must be answered in writing, not skipped.
- **RT-08 (environment matrix)** — the run measures both the as-shipped minimal install and the full
  one. This is pre-registered because a measurement earlier today was green for a reason unrelated to
  the defence it named: `verify_rfc3161` returned at its optional-import guard before reaching the
  lines under test, and only installing `[anchors]` made the probe measure its subject.

## 5. Pre-sweep, before any jury

`scripts/b7_berkeley_pre_sweep.py` replays every learned class first. Measured baseline at freeze
time: `class_ledger.jsonl` carries **120 entries** over **116 distinct classes**. A single red
learned class aborts the run as `FIX_FIRST` before the jury is paid for.

## 6. Gate meta-test

Before the verdict counts, the gate must be shown to catch a planted defect of the class it claims to
close, in an **untouched** file family. A gate that cannot demonstrate this is `BLOCKED`, not green.

## 7. What a verdict here does and does not mean

`WITHSTANDS_DEEPGATE` means **ready for Owner submission**. It does not mean released, does not mean
tagged, and does not mean safe. Merge, tag, GitHub release and PyPI publish remain four separate
Owner-GOs. The standing GO `GO_OWNER_PB_RELEASE_371_NACH_WITHSTANDS_20260807` makes this verdict
precondition 1 of seven, not a substitute for the other six.

## 8. Declared boundaries of this run

- The 27 commits on `ci/version-consistency-gate` (PR #139) are **not** in this candidate and are not
  graded here. That branch is red for a separate reason and is a separate decision.
- The candidate is graded on its digest `f64d35e`. If the branch moves, the verdict does not follow
  it — a new digest needs a new run, per the standing GO's own wording.
