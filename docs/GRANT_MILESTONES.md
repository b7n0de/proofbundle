# Grant milestones (independent security review)

Public deliverables for the funded audit track. Status is factual, linked to
repo evidence, never aspirational.

## M1 — Audit scope frozen

Verification logic, bundle parsing, canonicalization, SD-JWT checks, anchor
verification, CI/build provenance. **Status:** pending scope-freeze PR.

## M2 — External interop fixture — DONE 2026-07-11

Two externally produced decision-receipt vectors vendored digest-pinned and
credited under `conformance/decision/crossimpl/` (one Bitcoin-confirmed anchor,
block 957504, verified offline; canonicalization byte-identical). Honest gap
recorded: external fixture does not yet satisfy the strict v0.1 predicate schema
(12 findings, expected-fail, regeneration upstream in progress).

## M3 — Independent audit started — pending (OSTIF sourcing)

## M4 — Findings remediated — pending (each fix with regression test)

## M5 — Public report and hardened release — pending

---

Evidence: the external time-anchor design (canonicalization / content-root
binding) is tracked in issue #7; the M2 conformance vectors and their offline CI
job landed in PRs #61 / #62 / #64; the wider funded-review programme is issue #55
(Standard-track P1 backlog). Milestone status here is a factual mirror of that
repo evidence, not a forward promise.
