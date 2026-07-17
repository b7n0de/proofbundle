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
