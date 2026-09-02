# Pre-tag adversarial audit (Front-Load F7 discipline)

**The six-lens / master-prompt-v2 adversarial internal audit runs before EVERY release tag, not only
before the audit-candidate (3.6.0).**

## Why

On 2026-07-16 an EXTERNAL reviewer (Loek) found the decoy-parent structural issue (F1) *after* 3.3.0
had shipped. Structural problems are cheapest to fix when they surface early. Running the adversarial
audit before every tag (3.4.0, 3.5.0, 3.6.0, ...) means a 3.4.0-class structural problem is caught at
3.4.0, where it is cheap, instead of just before the paid external audit, where it is expensive. The
cost is low (the master-prompt already exists); the benefit is avoiding exactly the late rework the
front-load program exists to prevent.

## The mechanised gate

`scripts/pre_tag_audit_gate.py` enforces that the audit was actually run for the release being tagged:

- The CHANGELOG section for the version (`## [X.Y.Z]`) must record an adversarial / N-lens audit
  (the note the project has carried on every release section since v1.3.0), **or**
- an `audit_artifacts/` file must name the version and carry an audit marker.

It is wired `--strict` into `release.yml` as a pre-build step, so a `v*` tag whose release records no
adversarial audit fails before it can build or publish. It enforces an EXISTING convention, so real
releases pass; it only fires when the discipline was genuinely skipped.

```bash
python scripts/pre_tag_audit_gate.py --version X.Y.Z --strict
```

## What the audit itself must cover (the checklist the gate cannot read for you)

The gate proves the audit was *recorded*; the human/agent running it is responsible for its *content*.
Each release's adversarial pass should, at minimum:

1. Run the six-lens review (correctness / No-Fake / adversarial / SOTA / regression / fidelity).
2. Attempt to REFUTE the release's new invariants, not only confirm them.
3. For a release that adds a verifier or a vector kind: confirm F1 (one vocabulary), F3 (a new formal
   obligation if the logic changed), F4 (the new verifier is auto-covered or honestly NEEDS_FIXTURE).
4. Record named findings + closed fixes in the CHANGELOG section (that is also what the gate reads).

## Where each release drops its audit evidence

Into the readiness pack (`docs/readiness_pack/index.json`, the release's named slot) and the CHANGELOG
section. The reserved slots for 3.4.0 / 3.5.0 / 3.6.0 are already laid out (Front-Load F5).

## The mutation gate has two roles, and they are not interchangeable (2026-09-02)

Since the sharding change there are **two** ways to run `scripts/mutation_check.py`. They measure
the same thing and are used at different moments. Confusing them is the failure this section exists
to prevent.

| | canonical full run | sharded PR gate |
|---|---|---|
| command | `python scripts/mutation_check.py` | `--shard i/K`, K jobs in the CI matrix |
| when | **before every tag** (step B1 of the release run), plus nightly on the Farmer | on every pull request |
| operators | all 88 in one process, sequentially | 88 split deterministically across K jobs |
| per-mutant suite | full | minus the named exclusion list |
| wall clock | ~100 min measured 2026-09-02 | longest shard, K=10 → ~1005 s projected |
| what it settles | the release verdict | whether this change broke the gate |

### Why both measure the same thing

The verdict of an operator is differential: a mutant is KILLED when it is *strictly more red* than
the baseline of the same run. The exclusion list removes tests that query the **repository** — the
candidate matrix builds two sdists and compares them byte for byte — and never read the mutated
source. Removing them shifts the mutant and the baseline by the same amount, so the difference, and
with it the verdict, is unchanged.

That is an argument, and arguments are not evidence. It was therefore **measured**: the full
88-operator run with the exclusion active reproduced the canonical result exactly — 87 KILLED,
1 expected SURVIVED (`cosign: blob length exact -> lax (EQUIVALENT)`), 0 gaps. No operator died only
through an excluded test; had one, the count would not have reached 87.

### Why the canonical run stays

The sharded gate answers a narrower question. It runs in K separate processes on a runner we do not
control, and its per-mutant suite is smaller by construction. Before a tag we want the widest
statement the tool can make, from one process, with the complete suite — and cheap enough to keep,
because it runs once per release rather than once per push.

**A tag is never cut on a sharded run alone.**
