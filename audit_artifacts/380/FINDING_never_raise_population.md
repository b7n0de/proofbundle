# Finding — the never-raise family property is green over an incomplete population

**Pre-existing (`main`), not introduced by 3.8.0.** Per the implementation order this is reported and
not silently fixed: a finding on `main` is an Altbefund. Recorded here because the deep-gate run on the
3.8.0 candidate surfaced it, and because it bears on what a class-closure claim in this repository is
worth.

**This file does not assert that a pre-tag audit ran.** The N-lens jury has not completed.

## The claim under test

`tests/test_never_raise_surface_family_property.py` is the executable form of the never-raise class:
no public surface may terminate with a raw exception on hostile input. The 3.6.3 release closed that
class, and the property is the evidence.

## What was measured

Two planted defects, identical in kind, in a throwaway copy of the candidate tree
(`git archive HEAD | tar -x`, the candidate worktree was never written to):

| Plant | Module in `_MODULES`? | Family test result |
|---|---|---|
| `raise RuntimeError(...)` at the head of `anchors.verify_anchors` | **yes** | `FAILED (errors=1)` — caught |
| `raise RuntimeError(...)` at the head of `anchors_ots.verify_opentimestamps` | **no** | `Ran 5 tests ... OK` — **not caught** |

Bidirectional validation as v4 requires: green on known-good, red on known-bad. The test is not
broken. It is correct over the set it walks, and that set is smaller than the set it is read as
covering.

## The population gap, enumerated

`_MODULES` in that test lists **36** modules. The package ships **50**. A sweep over the difference,
applying the test's own `_NAME_PATTERN`, finds **11 never-raise surfaces across 7 modules that the
property never enters**:

```
anchors_chia        2  verify_offline_merkle, verify_chia_datalayer
anchors_markovian   1  verify_markovian
anchors_ots         1  verify_opentimestamps
anchors_rfc3161     1  verify_rfc3161
anchors_rootcommit  2  verify_rootcommit_v1, verify_rootcommit_v2sig
emit                1  load_signer
pqsig               3  verify_mldsa, verify_slhdsa, verify_hybrid
```

All eleven match the test's own name pattern. They are absent for one reason only: their **module** is
not in `_MODULES`. Nothing about them is out of scope by intent — the list is hand-maintained.

## Why this matters beyond the count

One of the eleven is already known to violate the contract. The self-gate run of 2026-07-31 recorded
F3: `anchors_rfc3161.verify_rfc3161` raises `AttributeError` on a non-dict `frozen` / `rp_trust`,
breaking the never-raise rule that `register_anchor_type` prescribes to third-party authors. Measured
again today against `main` `ac0688c`, with `[anchors]` installed so the code actually reaches the
lines:

```
rp_trust=123 (non-dict)      -> AttributeError: 'int' object has no attribute 'get'
frozen=123  (non-dict)       -> AttributeError: 'int' object has no attribute 'get'
frozen=123 + valid rp roots  -> no raise, ok=False, status=chain_fail
```

It still reproduces sixteen days later. It survived the 3.6.3 class fix not because the fix was wrong
but because the population never contained it.

## The class

- **class_id:** `family_property_green_over_a_hand_maintained_population_that_omits_members`
- **invariant:** a property that claims to close a class must enumerate its family from the tree, not
  from a maintained list; otherwise "green" measures the list, not the class.
- **surface_family_query:** every module under `src/proofbundle/` exporting a function whose name
  matches the property's own `_NAME_PATTERN`, discovered at run time.
- **oracle_predicate:** plant a raw raise in a discovered surface; the property must go red. A surface
  where it stays green is outside the population and the claim does not cover it.
- **outcome:** `class_open` — 11 members outside, one of them a live violation.

This is the same shape as the finding the 31.07. run recorded as F2 ("the class sweep plays only
argument position 0"), one level up: there the *argument* axis was truncated, here the *module* axis
is. Both make a green print mean less than it reads.

## Honest boundary

The candidate's own delta (`src/proofbundle/cli.py`, +14 lines) is unaffected: targets F1 through F7
were measured against it separately and each held. This finding concerns code that shipped in 3.7.0
and the instrument that measures it. Whether it should block a 3.8.0 verdict is not decided here —
it is put in front of the decision rather than into a footnote, which is what the methodology requires
of a confirmed finding.
