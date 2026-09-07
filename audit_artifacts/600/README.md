# Pre-tag audit artefacts for release 6.0.0

## Status right now: a receipt exists, and it no longer binds this head

Corrected 2026-09-07. This section used to say "the receipt does not exist yet". It does — a
receipt signed by the owner was committed in `c31adec` on 2026-09-06, and later re-committed in
`9e742bf`. What is true is something narrower and more useful:

    $ python scripts/pre_tag_audit_gate.py --repo . --version 6.0.0
    [pre-tag-audit] version=6.0.0 receipt-verified=False (NO_VALID_RECEIPT) tree=a862d6e45d51 trusted_keys=1
      REJECTED audit_artifacts/600/pre_tag_receipt_v6.0.0.json:
      receipt subject_tree_digest does not bind THIS tree ('877cd4f9…' != 'a862d6e4…')

Measured, so the reason is not guessed: the receipt binds `877cd4f98ffc8924`, which is the digest
of `bf143a0` **under the pre-`b9d35d4` definition of `subject_tree_digest`**. Both halves of that
sentence matter. The tree moved (thirteen commits since), and the definition moved with it — the
old one excluded the whole `audit_artifacts/` directory, the current one excludes only the receipt
file and the two mutable evidence paths. Under either definition this receipt does not bind the
present head, so `rejected` is the correct state, not a defect.

A receipt is minted last, after everything else, and `.github/workflows/release.yml` runs the gate
with `--strict` as the third step of its first job — so a tag pushed before a binding receipt
exists fails before anything is built. The present one will be re-minted at the frozen head.

Order, fixed: land the code and the register, then mint the receipt, then tag. Since `b9d35d4`
that order carries one more requirement, and it is load-bearing rather than incidental:
**everything else under `audit_artifacts/<token>/` must be committed BEFORE the receipt is minted.**
A note written beside the receipt afterwards now moves the digest and invalidates it.

## Why the receipt lives here and not next to the code

`subject_tree_digest` is a recursive `git ls-tree -r HEAD` minus exactly the receipt file itself
and the two mutable evidence paths a release run rewrites while measuring. The exclusion removes the
circular binding: adding the receipt here leaves the bound tree unchanged. The opposite is equally
true — a change under `src/`, `scripts/`, or anywhere else including the rest of this directory,
DOES move the tree and invalidates a signature taken before it.

**This paragraph used to say the opposite, and the hole it described was closed IN THIS RELEASE, not
in the follow-up.** What stood here: `subject_tree_digest` is `git ls-tree HEAD` with the line for
this directory removed, therefore `audit_artifacts/pre_tag_trusted_pubkeys.txt` — the file the gate
reads to decide who may sign — lay outside the binding, and `load_trusted_pubkeys`'s docstring claim
that "reading the committed blob binds it by the same digest" was false. The measurement printed
here on 2026-09-06 was correct for that code.

`b9d35d4` changed the code, so the measurement no longer holds. Re-measured on this head, same
three steps:

    digest before any change                 e9ba462912c3979d404a387e5fe702f6755f738b4c86fb…
    digest after committing to the anchor    8de15f03280980b2c0f58f9511ea2894be643a2d2054dd…   different
    digest after committing to README.md     fc0fa4007da9ff53e8db81cdda38197fe8cf8ead1b65b0…   different

The trust anchor is inside the binding now, and the `load_trusted_pubkeys` docstring is correct
again. The readiness side of this repository had already fixed the same thing the right way and was
the model for it: `sign_readiness_artifact.tree_digest` excludes only the two named mutable evidence
paths, recursively, instead of a whole directory.

Why the correction is written out rather than silently applied: two documents of the same candidate
said opposite things about the same quantity, and the wrong one sat next to the receipt. A reader
who trusts the file closest to the artefact would have drawn the wrong conclusion about what the
signature covers.

## What the audit outcome actually was

**`FIX_FIRST`. `WITHSTANDS_DEEPGATE` is NOT claimed for 6.0.0.**

The closing round was the adversarial deep gate, DEEP profile: six lenses, seven iterations,
falsification-first with executable exploits, refute-to-kill jury. It ran on the frozen candidate
`a62d8cb43e5d202f0bdd5ebbe8fd5795901be37d`.

    pre-tag-adversarial-audit: RUN | version=6.0.0

That line is the canonical form this repository uses for "the audit ran for exactly this version".
It is true, and it is deliberately not what grants the gate — the gate rules on the signed receipt
alone, and a line of prose cannot move it in either direction.

### Three findings confirmed, all open, all closed in the follow-up release

| Register | Finding | Why it does not stop 6.0.0 |
|---|---|---|
| N16 | `action/action.yml:35-36` interpolates `${{ inputs.version }}` and `${{ inputs.extras }}` straight into a `run:` shell body, one line above a step that routes `inputs.command` through `env:` and says why | The file is byte-identical to the public tag `v1.0.0` (`a8aca8cd`, sha256 prefix `91cfcdc4ecbab94c` on both sides) and exactly one commit has ever touched it, an ancestor of this candidate. 6.0.0 neither creates the injection nor removes it. Measured separately: a fix on `main` would not reach the documented users either — `INTEGRATIONS.md` pins `action@v1.0.0`, there is no moving major tag, and the one self-updating channel (the composite action's `pip install proofbundle`) carries no copy of `action.yml` at all |
| N17 | `scripts/rust_parity_gate.py` swallows an unparseable or unreadable source file and then rules from the ABSENCE of complaints over what is left — a release-deciding check can report PASS over a population that shrank quietly | On this candidate the population is complete: 68 of 68 files under `src/proofbundle` parse and read, `registry_integrity_ok: true`, `untracked`, `orphaned` and `stale` all empty. What is open is the capability, not its occurrence |
| N18 | `pip install <sdist> && pytest` without the `[test]` extras is RED, not skipped, while the shipped `pyproject.toml` promises a bare install "degrades to clean skips". Measured: 1 failed, 3075 passed, 482 skipped | The wrong thing is the promise, not the test. Either the promise is kept or the wording is corrected; that choice belongs to the follow-up release |

### The scope each statement of this round holds over

Named here rather than left to be inferred, because a verdict that rules over an excerpt without
saying so cannot be checked by a reader:

- **2537 of 3702 tests** — the mutation gate collects with `unittest discover`, which sees only
  methods of `unittest.TestCase`; 59 of 252 test files carry pytest functions only and are invisible
  to it. Every mutation statement of this round holds over that subset (`N19`).
- **The replay's coverage — NOT MEASURABLE, and this section previously said otherwise.** It read
  "94 of 182 classes". Withdrawn: the two numbers count different things. **94** counts CLASSES with
  status `class_closed`; **182** counts the pytest NODES the replay runs. Measured 2026-09-06: 183
  effective classes, 94 closed, all 94 carrying both evidence fields as real in-repo nodes; the node
  set is 182 and not 2 x 94 = 188 because six nodes are shared between classes. The pairing looked
  like a ratio only because the effective class count was itself 182 until this round's own class
  was written.
  Well defined instead, definition beside it: **94 of 183 ledger classes carry in-repo runnable
  evidence** — a class counts iff it is `class_closed`, which the validator grants only for two
  DISTINCT in-repo pytest nodes (live regression guard plus plant-and-must-catch meta test). The
  other 89 carry no runnable test and all 89 say why; none is unexplained. That is a fact about the
  ledger's contents, NOT the replay's coverage: the replay set is defined by the closed status, so
  the ratio cannot express how much assurance goes unchecked. That question needs a complete class
  population, and completeness is exactly what is not measured.
- **68 of 68 files** — the parity gate's population is complete on this candidate. The one figure
  here that is not a subset, and what keeps `N17` below the release-stopping bar.

`N20` records one mutation operator whose outcome is NOT MEASURABLE rather than killed or survived:
it removes the very resource ceiling under test, and the mutated run reached 111 GiB resident
(88.3 % of memory, 1 GiB free) before it was stopped deliberately rather than left to the OOM
killer. Not measurable is its own state — not a kill, not a survivor.

## Why this round's findings are not edited into `RESTRISIKO_600.md`

That file states the rule itself, in its own words: a finding of the closing round is a new
iteration with a new freeze, "never an edit of this file", because the receipt binds it by sha256
and a second top-level file would move the tree digest. So the round's outcome is recorded here,
next to the receipt, exactly where 5.1.0 recorded it. `RESTRISIKO_600.md` continues to hold what was
known and open **before** the round, R1–R7 and N1–N15.

The structured, signed carrier of the findings is `findings_register_600` — 20 entries, 13 closed,
7 open, **0 open P0/P1**. That register, not any prose here, is what `C12.2` reads and counts.

## One caveat about reading the receipt, carried over from 5.1.0 because it is still true

`audit_exit_code` will be `0`, and that number carries no information: `verify_receipt` rejects
every other value, so a valid receipt can only ever show `0` and therefore cannot express a verdict.
The verdict is in `audit_command` in words, and in this file in detail.

## N11 identity measurement — recorded, because without it the run does not count

N11 requires byte identity of `src/`, `tests/` and `scripts/` between the tree the canonical mutation
run executed against and the head that gets tagged. Without it the run speaks about a different
subject than the one being published. This record is required whether the outcome is green or not;
here it is negative, and that is precisely what it is for.

### Measured 2026-09-07

Base of the canonical run: `658ed063` (*Merge pull request #186 from b7n0de/chore/version-6.0.0*).

**Every number below names the head it was measured on, and that is the correction.** The table
that stood here was headed *vs. today's candidate `5242b0c6`* — correct when written, and stale
seven commits later. A round whose purpose was adding measuring points had let its own identity
record drift, which is the exact failure N11 exists to prevent. The numbers do not get maintained
per commit; the head gets named.

| directory | `658ed063` → `5242b0c6` (as recorded 2026-09-07) | `658ed063` → `68aa6f32` | `658ed063` → `5e9aa66` (after the collector merge) |
|---|---|---|---|
| `src/` | 32 files (+1577 / −373) | 32 files (+1577 / −373) | 32 files (+1577 / −373) |
| `tests/` | 45 files (+10235 / −156) | 46 files (+10631 / −165) | 51 files (+11637 / −189) |
| `scripts/` | 10 files (+3059 / −213) | 12 files (+3268 / −224) | 12 files (+3577 / −262) |
| **total** | **87 files** | **90 files** | **95 files** |

**Identity does not hold, and the count is not the point** — one changed file already breaks it.
The canonical run covers no head of this line. That is not an interpretation; it is the condition
N11 states, and it holds for every head this branch has had.

### The collector on this head is no longer blind — measured after the merge

**This section said the opposite until 2026-09-07, and the correction is the point of N11.** It
read *"A fix that moves the collector to pytest exists on a separate branch and is **not** contained
in this head — measured, not assumed."* That was true when written and became false with the merge
of `fix/mutationstor-sammler-sieht-alle-tests` (merge commit `733a8c4`, owner decision on card
`OA-1a00701d0f`, answer A: the collector goes in **before** the freeze). A record that keeps
asserting an absence after the thing arrived is exactly the drift this file was corrected for once
already, one section above.

`scripts/mutation_check.py` now collects with the normative runner. Measured on `5e9aa66` by
**asking the collector**, the same call the gate makes:

    the gate's collector:  3820 tests across 259 files
    blind:                 0 tests, 0 files

The figures kept for comparison, each naming its head: 3736 / 2524 (25 % blind) on `22dc97b5`,
3767 / 2571 (23 % blind, 59 files) on `68aa6f32`, and the collector's own commit message records
2565 / 3728 on the candidate at merge time. The blind share moved with the tree until the merge
removed it; the numbers are kept because a share that vanishes is only credible next to the shares
that preceded it.

The `N19` figures in the scope section above (**2537 of 3702**, **59 of 252**) were measured on
`a62d8cb4` and describe that tree. They are not wrong; they are about a head that no longer exists
on this line.

### What follows, without varnish

Of the two reasons that made the mutation condition **NOT MEASURABLE** when this section was first
written, one is gone and one stands:

* **Gone:** the collector no longer misses a quarter of the test files. It collects the full
  population, measured above.
* **Stands:** identity under N11 does **not** hold — 95 files differ between `658ed063` and this
  head. One changed file already breaks it; ninety-five is not a closer call, only a louder one.

N11 states what follows when identity fails, and it is not "report and stop": the run **is
repeated** against the head that gets tagged. That is the path taken here, on the owner's decision
of 2026-09-07 (card `OA-1a00701d0f`, answer A): collector first, then the full suite, then the
canonical mutation run on the frozen head, and the freeze happens exactly once.

So this section no longer reports an impossibility. It records the condition that makes the repeat
necessary, and the repeat is the release's own next step — not a deferred one.
