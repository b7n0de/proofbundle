# Residual risk, release 5.1.0

This file exists because the release may take the `PARTIAL_GATE_NO_WITHSTANDS` exit. That exit is
a regular outcome for this release by explicit owner decision, and it comes with one condition:
every finding that stays open is named here, with its class, its funnel verdict, and the reason.
A residual risk that is not written down is not a residual risk, it is an omission.

**Nothing in this file is a claim that the release is defect free.** It is the list of what the
closing gate round found and did not fix, and why each item was judged not to block.

## The funnel, so the verdicts below can be checked

A finding blocks this release only if it can reach a user of the shipped package: a wrong
verification result, a receipt that verifies when it should not or is refused when it should not,
data loss, an import error in the shipped package, a security hole, a broken public interface.

A finding does not block if it lives in the guards above the guards, in ratchets, in test
coverage, or in the self consistency of test files. Those are recorded, classified, and written to
the class ledger. They are not nothing, they are simply not this release.

## Open findings

Eight, ordered with the most serious first.

### R0 · No test result was a required check on `main` — RESOLVED during this round

Measured against the live ruleset, not read from documentation:

    gh api repos/b7n0de/proofbundle/rules/branches/main --jq '.[].type'
      deletion
      non_fast_forward
      required_status_checks

    ... --jq '.[] | select(.type=="required_status_checks")
                  | .parameters.required_status_checks[].context'
      guard

`guard` is the fork pull request secret isolation job (`.github/workflows/fork-pr-isolation.yml`).
It proves that a fork pull request cannot reach a secret. **It runs no tests.** The only job that
runs pytest at all is `coverage` (`ci.yml:148`), on Python 3.12 alone, and it is not a required
check. The five version matrix runs `unittest discover`, which does not see the 372 pytest only
test functions that make up this release's new surface. The ruleset carries no pull request review
requirement either.

**A merge into `main` can therefore land with every test red, provided `guard` is green.** And
`main` is what gets tagged and published.

**Funnel: it can reach a user**, not through this release's code but through the process that
ships it. Nothing here says the current tests are failing. They are not: the suite is green on the
candidate, and the checks on the pull request are green apart from the receipt check that this
release itself resolves. The finding is that nothing *compels* them to be.

**Why it does not block this release:** it is not a property of 5.1.0, it is the state of the
branch protection, and it has been that way for every release before this one. Changing branch
protection is an owner act and is out of scope for a release order. It is recorded here so the
decision is made rather than inherited.

**How it was found:** an adversarial lens judged a related finding and stated honestly that it
could not determine which checks were required, and that if `coverage` was not one of them the
severity would rise considerably. That question was answerable from here, and the answer is worse
than the lens could establish: it is not only `coverage` that is missing, it is every check that
runs a test.

**Resolved on 2026-09-02, by owner decision taken while this round was still open.** The required
set on `main` is now `guard`, `coverage`, and `test (3.10)` through `test (3.14)` — seven contexts
instead of one, with the job names taken from the measured check list of the previous pull request
rather than guessed. `mutation` stays out deliberately. Verified independently at both endpoints,
not from the echo of the write, and every one of the seven appears green on this release's pull
request. The previous state is recorded as complete JSON with a one-command rollback.

One deviation from the instruction's wording, named rather than smoothed over: it said to set the
rules *before* the landing pull request. That pull request was already open. The purpose holds —
rules are evaluated at merge time and all seven are green — but the sequence was not as written.

### R1 · A shipped specification artefact contradicts the shipped code

`scripts/rust_parity_registry.json` ships in the sdist and states, for the v0.2 verifier, that
`policy_decision stays None` is the deliberate state. Measured on this release, that same value
produces `safeForAutomation: false` and `policyAuthorized: false`.

**Funnel: it can reach a reader.** Someone building a second implementation from that registry
would reproduce a verifier that disagrees with ours.

**Why it does not block this release: it is not a regression of this round.**
`POLICY_NOT_EVALUATED` appears three times in `automation_verdict.py` at tag `v5.0.0` and three
times today, unchanged. The contradiction has shipped since 5.0.0. Correcting the registry would
change the sdist and therefore move the object this gate round froze, for a defect this round did
not introduce.

**Class:** a shipped document describing intended behaviour that the shipped code no longer has.

### R2 · A subfield reads safer than before, against the invariant the round enforced

In 36 measured cases `referencesResolved` moves `false → true` and `subject_binding_ok` moves
`False → None`, and the binding error line disappears. Cause: `SUBJECT_NAME_UNDERIVABLE` makes the
structure fail earlier, the axis is never computed, and `None` does not block.

**Funnel: it does not reach a user's decision.** `safeForAutomation` stays `false` in all 36 cases,
so no automated action is permitted that was previously refused.

**Why it is still written here:** it is the inversion of the very invariant this round added. A
field that reads safer than the state it describes is the shape of defect the round was built
against, appearing one level down.

### R3 · The verifier raises a raw exception on a non mapping envelope

`resolve_receipt_chain` raises rather than returning a typed refusal when handed something that is
not a dict. Reachable without any signature. Measured directly against the shipped function:

    resolve_receipt_chain(None,     verified=None)  TypeError: 'NoneType' object is not iterable
    resolve_receipt_chain(42,       verified=None)  TypeError: 'int' object is not iterable
    resolve_receipt_chain(['text'], verified=None)  AttributeError: 'str' object has no attribute 'get'
    resolve_receipt_chain([42],     verified=None)  AttributeError: 'int' object has no attribute 'get'
    resolve_receipt_chain([{}],     verified=None)  returns a dict, no raise

The last line is why the existing test does not catch it: it passes `{"kein": "payload"}`, a dict,
and dicts are exactly the shape that already works. The module's own docstring asks for robustness
here.

**Funnel: it reaches a caller who passes malformed input**, and it produces a crash instead of a
verdict. It does not produce a wrong verdict.

### R4 · Four verify sites report an internal error for a truthy non list

`or []` catches only falsy values, so a truthy non list reaches the code as itself and is reported
as `internal_error`. The module defines that state as a defect in the verifier, not a verdict about
the receipt, so a malformed receipt is announced as our own fault.

Counted here rather than taken over: the pattern occurs **13 times** in `agent_review.py`. The lens
named **four** of them as the reachable verify path (`:2026`, `:2049`, `:2281`, `:2293` — the
`findingsRoot` comparison and the assurance gathering, once for v0.1 and once for v0.2). The other
nine sit outside the verify path. Two different scopes, and neither number is wrong; they answer
different questions.

**Funnel: reaching it requires the trusted key.** The emitter refuses to produce such a receipt,
and a foreign key yields `crypto_ok=False` correctly. No remote party can trigger it.

### R5 · The guard that should have caught the changelog omissions is blind to content

`scripts/check_version_and_changelog.py` verifies that a section for the current version exists.
It never reads what the section says. That is why an entry describing a tree from 48 commits
earlier, and a semantic change with no entry at all, both survived into the closing round.

**Funnel: no user is affected.** It explains why three documentation findings of this round were
found by an adversarial lens rather than by the project's own gate.

### R6 · The witness cannot see the lenses of a foreign repository round

The witness resolves lens artefacts under a path constant inside the content addressed tree it
signs. The lenses of this round live in the operator's repository. The witness therefore counts
zero and says so, and it is right to.

**Funnel: no user is affected.** It is the reason a closing evidence record for this release will
read `PARTIAL` with that one named cause. A change to the witness is filed separately and is not
part of this release.

### R7 · Three numbers in shipped artefacts are wrong, each already wrong when written

Measured against the shipped tree, not read:

    pyproject.toml:111   claims `test_adapters.py` "19 of 19"   -> 10 `def test_` in that file
    MANIFEST.in:43       claims "14 conformance cases"          -> 17 under conformance/agent_review/
    pyproject.toml:140   claims mypy over "63 files"            -> 66 source files

`pyproject.toml` and `MANIFEST.in` both ship. The first two were false on the day they were
written: the `def test_` count has been 10 since 23 August, and the MANIFEST line was written in
the very commit that raised the case count from 14 to 17. The third is stale rather than false —
the statement it supports still holds.

**Funnel: no user breaks.** No code path reads these numbers; they are comments. They reach a
reader of a published artefact, which is why they are here and not dismissed.

**Why they stay open:** both files are inside the sdist. Correcting them moves the object this
round froze, for three comment lines. That trade is the owner's to make, not mine.

**Class:** a number written into a shipped artefact without a command behind it — the same class
this session has met repeatedly, here at the outermost surface.

## What was measured and did not become a finding

The single axis that must block was tested and did not yield: 5126 fuzzed verification calls
produced zero false positives, zero false negatives, and zero raw exceptions; six published
receipts still validate unchanged; the conformance corpus is byte identical; across the whole
public surface zero names and zero signatures were removed, and no reason code disappeared.

## Honest limit of this file

It lists what this round found. It does not list what no lens looked for. Coverage was one
interpreter and one platform, the Rust counter implementation was not run, and no fix was
counter measured for R3 and R4.
