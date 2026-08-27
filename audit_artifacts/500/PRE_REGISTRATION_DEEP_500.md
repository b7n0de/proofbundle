# Pre-registration — DEEP 6L/7I, release 5.0.0

Frozen BEFORE anything ran (the run record may only cite what is fixed here).

## Why this file exists before the run record

The run record for 4.0.0 carries the line `pre-tag-adversarial-audit: RUN | version=4.0.0`, and the
pre-tag gate reads exactly that line. **The equivalent line for 5.0.0 does not exist yet, and this
file does not create it.** Writing a RUN record before the run would be the precise failure this
project's gate is built to catch: an attestation whose subject never happened.

**Measured 2026-08-25:** every adversarial gate receipt from 23.–25.08. runs in mode `NORMAL-3L3I`
(22 of 22). The most recent `WITHSTANDS` receipt (24.08. 11:40:41Z, strength FULL, runner-signed)
carries `topic: control_plane_phase01` — it grades the control-plane work on a feature branch, not
this release, and it grades it in the NORMAL mode. A release is the external/MAJOR mode by rule:
DEEP, six lenses, up to seven iterations. **No existing receipt covers 5.0.0.**

## The graded object

```
graded code        src/ tree 8897965acbac94585cc57267abc54ce4c9d06099
frozen at          c669d39e3d8e8bf235ec1c03e40378cb146fba7a  (origin/main, after PR #151 merge)
delta graded       v4.0.0..c669d39 under src/: 7 files, 180 insertions, 21 deletions
                   v4.0.0..c669d39 overall:    21 files, 978 insertions, 68 deletions
commits graded     18 (v4.0.0..origin/main)
mode               [DEEP-GATE: DEEP 6L/7I]  (MAJOR / external release)
```

The version bump itself (pyproject.toml · src/proofbundle/__init__.py · CITATION.cff, 4.0.0 → 5.0.0)
and this release's CHANGELOG section sit on `release/v5.0.0` on top of the frozen commit. They change
no behaviour; D6 grades whether what they CLAIM matches the tree.

## Falsification targets (what WOULD be the defect; the executable exploit refutes it)

| # | Target (the invariant the release asserts) | Falsified by |
|---|---|---|
| E1 | **The cap removes work, not acceptance.** Running the `merkle_path` cap before the decoding it bounds changes no verdict: anything that verified under 4.0.0 still verifies, anything that failed still fails. | a proof/bundle/sample-opening input whose verdict DIFFERS between v4.0.0 and this tree — in either direction |
| E2 | **Exactly ONE input class changes its exit code, and it is the one the CHANGELOG names** (over the cap AND invalid base64: exit 2 → exit 1). No second class moved unnoticed. | any other input class whose CLI exit code differs between v4.0.0 and this tree; or the named class NOT actually moving (the claimed breaking change being fictional) |
| E3 | **`expected_origin_wellformed` is purely additive.** The comparison itself is untouched: a malformed pin still yields a verdict, never an exception, and `inclusion_ok` is unchanged by the new field. | a pin value for which `inclusion_ok` differs from v4.0.0; or the new field raising; or a fail-closed path where `verify-proof --json` omits it despite the claim of "every invocation" |
| E4 | **Nothing this release loosens an existing check; every shipped external vector keeps its verdict.** | a Go-sumdb / Rekor / rootcommit / Colin vector whose verdict changed, or an input refused before and accepted now |
| E5 | **The two fail-closed additions refuse only unusable states.** `checkpoint_note` refusing an empty root, and `save_signer`'s path type floor, reject nothing a valid producer could previously use. | a producer call that worked under 4.0.0, produced something a verifier ACCEPTED, and is refused now |
| E6 | **The record's and CHANGELOG's numbers and claims match the tree** (fidelity), including the MAJOR justification: `SPEC.md` really does document the exit-code contract normatively at the cited lines. | a claimed count / file / line reference that a fresh measurement contradicts; or a SPEC.md citation that does not say what the record says it says |

## Method (fixed here)

Six lenses — correctness · No-Fake · adversarial · SOTA (SemVer 2.0.0 / RFC 2119 normative-spec
reading) · regression · fidelity — each attempts to REFUTE its target with an executable probe, not
to confirm it. Negative state including **absent** (no pin supplied; empty proof list; zero cap).
Independent oracle + anti-parity: the exit-code comparison is driven against an actual v4.0.0
checkout, not against this tree's own expectations. Minimal environment: as-shipped, without the
`[experimental]` / `[pq]` extras. Gate-meta-test: a planted defect of the E2 class (a silently moved
exit code) must turn the corpus red. Generator-hardening over point fixtures.

`WITHSTANDS_DEEPGATE` would mean "ready for the Owner's tag", NOT "released" or "proven secure".
The tag, the merge to main, and the PyPI publish remain separate Owner acts.

## Honest boundary of this file

This is a pre-registration and nothing more. It asserts no verdict, and the pre-tag gate must not
pass on it — `pre_tag_audit_gate --strict` looks for `pre-tag-adversarial-audit: RUN | version=5.0.0`
and will correctly keep reporting MISSING until a real run writes it.
