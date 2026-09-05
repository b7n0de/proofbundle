# Residual risk, release 6.0.0 — the record before the closing gate round

This file exists because the release may take the `PARTIAL_GATE_NO_WITHSTANDS` exit, as 5.1.0 did.
That exit comes with one condition: every finding that stays open is named here, with its class,
its funnel verdict and the reason. A residual risk that is not written down is not a residual
risk, it is an omission.

**Nothing in this file is a claim that the release is defect free.** It is the list of what was
known and open when the tree was frozen, and why each item was judged not to block.

## Why this file is committed before the round, not after it

For 5.1.0 the record was written after the closing round. For 6.0.0 the owner fixed the order on
2026-09-05: this file lands on `main` first, the head that carries it is the frozen tree (the
byte-freeze standard of 2026-07-31: freeze first, publish later, never reload mid-sequence), and the
closing gate round — DEEP, six lenses, refute-to-kill jury — runs on exactly that frozen head. The
pre-tag receipt that the tag depends on binds this file by its sha256, so it cannot be edited once
the receipt exists.

What follows from that order is stated plainly: a finding of the closing round that must be fixed
or must be written down is a **new iteration with a new freeze** (standard, rule 2), never an edit
of this file and never a second file next to it — a new top-level file would move the tree digest
the receipt binds. The round's own outcome (verdict tag, lens count, the standing targets by name)
is recorded in `audit_artifacts/600/README.md` next to the receipt, where 5.1.0 recorded it too.

## The funnel, so the verdicts below can be checked

A finding blocks this release only if it can reach a user of the shipped package: a wrong
verification result, a receipt that verifies when it should not or is refused when it should not,
data loss, an import error in the shipped package, a security hole, a broken public interface.

A finding does not block if it lives in the guards above the guards, in ratchets, in test
coverage, or in the self consistency of test files. Those are recorded, classified, and written to
the class ledger. They are not nothing, they are simply not this release.

## Carried over from 5.1.0, measured again on 2026-09-05 at `658ed063`

Each row says whether it was re-measured. "Not re-measured" is a state, not a pass.

### R1 · A shipped specification artefact contradicts the shipped code — open, re-measured

`scripts/rust_parity_registry.json` (in the sdist) still says of the v0.2 verifier that it
"deliberately does not decide that for it (`policy_decision stays None`)" — one occurrence, measured
with `grep -c`. In 6.0.0 the same state is reported as `policy_decision: null` plus the advisory
code `POLICY_NOT_EVALUATED`, and `automation.safeForAutomation` is `false` for it (CHANGELOG
6.0.0, "a named policy axis"). The registry frames that state as neutral; the verifier treats it as
"not authorised for automation". `POLICY_NOT_EVALUATED` appears three times in
`automation_verdict.py`, as at 5.1.0.

**Funnel: it can reach a reader** building a second implementation from the registry. **Why it does
not block:** it shipped unchanged since 5.0.0, and correcting the registry would move the frozen
tree for a defect this cycle did not introduce. **Class:** a shipped document describing intended
behaviour that the shipped code no longer has.

### R2 · A subfield reads safer than before, against the invariant the round enforced — open, NOT re-measured

The 36-case measurement of 5.1.0 (`referencesResolved` false → true, `subject_binding_ok`
False → None when `SUBJECT_NAME_UNDERIVABLE` fails the structure early) was not repeated in this
cycle. Nothing in the 6.0.0 diff touches that code path by intent, and that is an argument, not a
measurement. Funnel as before: `safeForAutomation` stayed `false` in all 36 cases.

### R3 · `resolve_receipt_chain` raises a raw exception on a non-mapping envelope — open, re-measured

Measured at `658ed063` against `proofbundle.agent_review.resolve_receipt_chain`:

    resolve_receipt_chain(None,     verified=None)  TypeError: 'NoneType' object is not iterable
    resolve_receipt_chain(42,       verified=None)  TypeError: 'int' object is not iterable
    resolve_receipt_chain(['text'], verified=None)  AttributeError: 'str' object has no attribute 'get'
    resolve_receipt_chain([42],     verified=None)  AttributeError: 'int' object has no attribute 'get'
    resolve_receipt_chain([{}],     verified=None)  returns a dict, no raise

Unchanged. One fact is added this cycle because the deep gate's public contract needs it: the name
is **not exported** (`"resolve_receipt_chain" in dir(proofbundle)` is `False`), so under the
never-raise contract of the public surface it is an internal helper whose public callers must
wrap it. The round attacks the public entry points; a crash reachable only through the helper
called directly stays recorded here, not as a gate finding.

**Funnel: it reaches a caller who passes malformed input** and produces a crash instead of a
verdict, never a wrong verdict.

### R4 · Verify sites report an internal error for a truthy non-list — open, re-measured in count only

`or []` occurs **19 times** in `agent_review.py` at `658ed063` (13 at 5.1.0; the module grew by
582 lines with v0.2). The four reachable verify sites named at 5.1.0 were not re-derived for the
new positions, and the new occurrences were not classified as reachable or not. That is a gap of
this record, stated rather than smoothed over. Funnel as before: reaching a site requires the
trusted key; a foreign key yields `crypto_ok=False` first.

### R5 · The guard that should catch changelog omissions is blind to content — open, unchanged by design

`scripts/check_version_and_changelog.py` verifies that a `## [6.0.0]` heading exists (its own
docstring, rule 2) and never reads the section. The 6.0.0 section was therefore written and checked
by hand from the merged pull requests (#171 to #186), and the closing round's fidelity lens reads
it again. **Funnel: no user is affected.**

### R6 · The witness cannot see the lenses of a round run in a foreign repository — open, unchanged

`scripts/b7_abschluss_beleg.py` counts lens artefacts under
`office/governance/berkeley_gate/runs/lenses/<topic>` inside the tree it signs — this repository's
tree, which carries no such directory. The closing evidence record for 6.0.0 will therefore read
`PARTIAL` with `0 of 6 lenses` as its named cause, exactly as the 5.1.0 record did, while the six
lenses live in the operator's repository. **Funnel: no user is affected.** A witness that reads a
second tree is filed on the operator's side and is not part of this release.

### R7 · Three numbers in shipped artefacts are wrong, each already wrong when written — open, re-measured

Measured at `658ed063`:

    pyproject.toml:111   claims `test_adapters.py` "19 of 19"   -> 10 `def test_` in that file
    MANIFEST.in:43       claims "14 conformance cases"          -> 30 `case.json` under conformance/agent_review/
    pyproject.toml:140   claims mypy over "63 files"            -> 67 source files

All three still wrong; two drifted further since 5.1.0 (14 → 30, 63 → 67). Both files are inside
the sdist. **Funnel: no user breaks** — no code path reads these comments. **Why they stay open:**
correcting them moves the frozen object for three comment lines; that trade is the owner's to make,
and it was not made for 6.0.0.

## New in this cycle, known before the round

| Id | Finding | Class | Funnel verdict |
|---|---|---|---|
| N1 | Lens 2 on PR 185: the flip oracle of the A5 corpus test read one field; fixed to require `ok` (`bc95dd6`). The wider class — narrow-scope comparison oracles — is not swept repo-wide | test integrity | does not reach a user; recorded |
| N2 | Lens 2: the corpus input key serialised the whole `params`; fixed to the keys the runner reads, meta test both ways (`bc95dd6`) | test integrity | does not reach a user |
| N3 | Lens 3: the `Receipt:` line of a published disclosure block is the file hash, not `receipt_digest()`; documented in 6.0.0 rather than changed, because two published receipts carry it | documentation, chain semantics | can mislead a reader who copies the line into `priorDigest`; written down in the CHANGELOG and AGENT_REVIEW_PREDICATE.md |
| N4 | `POLICY_NOT_EVALUATED` and `AGENT_REVIEW_LEGACY_V01` moved from `reason_codes` to `advisory_codes`; a consumer of an unpublished pre-6.0.0 build that branched on `reason_codes` changes behaviour | interface | none for published users — no release carried either code before 6.0.0 |
| N5 | `agent-review/v0.2` emits only `selfDeclared` assurance; a witness outside the agent workspace is not provided | scope | documented honest limit |
| N6 | The `time` block of a policy file is new and evaluated only when present; the shipped standard policy carries none (`time_policy_decision: null`) | interface | documented |
| N7 | The sibling-venv full run on PR 185 reported 3245 passed and 22 skipped; the skipped set was not enumerated. The audit run of the freeze (`pytest -rs`) enumerates it and the receipt README lists it | test coverage | recorded when measured; not a package defect |
| N8 | `audit-candidate-matrix` reports C12.1 as not applicable on a pull request and as absent on `main` until the signed 6.0.0 receipt exists — the gate at work, not a defect | process | none |
| N9 | The relative `CHANGELOG.md` link in the new README section was dead in the sdist; fixed to an absolute URL (`72c21e7`). Class: links on surfaces without a root; the shipped-docs test checks its named links, the README was not swept beyond them | documentation | none after the fix |
| N10 | CAP-1 coverage (`feat/cap1-abdeckung`, target 6.1.0) is not part of 6.0.0 by decision; the branch is not in the frozen tree | scope | none |
| N11 | The canonical full mutation run (`scripts/mutation_check.py`, docs/PRE_TAG_AUDIT.md: "a tag is never cut on a sharded run alone") was started on `658ed063`, the merge of PR 186, before this file existed. Its inputs — `src/`, `tests/` and `scripts/` — must be byte-identical between `658ed063` and the frozen head for the result to count; that identity is measured with `git diff --stat` and recorded in the receipt README, or the run is repeated | process | none if identical, repeated otherwise |

## What was measured and did not become a finding

At `658ed063`, before the round: the version is single-sourced (6.0.0 in `pyproject.toml`,
`__init__.py`, `CITATION.cff`, `check_version_and_changelog.py` OK); the 6.0.0 section exists and
carries the break in one sentence; the readiness slot for 6.0.0 is filled and the advisory
candidate matrix was green on the pull request head `5657a98`; the CI of PR 186 was green on all
33 checks before the merge; the CAP-1 branch is outside the tree.

## Honest limit of this file

Written by the same agent that made the changes, before the closing round, from measurements
taken on 2026-09-05 at `658ed063` and from the 5.1.0 record. It lists what is known to be open; it
does not list what no lens has looked for yet. Coverage of the measurements above is one
interpreter (CPython 3.10) and one platform; the Rust counter implementation was not run.
