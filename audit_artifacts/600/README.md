# Pre-tag audit artefacts for release 6.0.0

## Status right now: a receipt exists, and it no longer binds this head

Corrected 2026-09-07. This section used to say "the receipt does not exist yet". It does — a
receipt signed by the owner was committed in `c31adec` on 2026-09-06, and later re-committed in
`9e742bf`. What is true is something narrower and more useful:

    $ python scripts/pre_tag_audit_gate.py --repo . --version 6.0.0
    [pre-tag-audit] version=6.0.0 receipt-verified=False (NO_VALID_RECEIPT) tree=<this head> trusted_keys=1
      REJECTED audit_artifacts/600/pre_tag_receipt_v6.0.0.json:
      receipt subject_tree_digest does not bind THIS tree ('877cd4f9…' != '<this head>…')

**The tree digest is deliberately NOT pinned in this line, and that is a correction.** It used to
read `tree=a862d6e45d51`, measured when written and stale fifteen commits later — the digest of
`68aa6f32`, while the head this file sits on produced a different one. A `ls-tree`-derived digest
changes with EVERY commit, this file's own included, so any value written here is wrong by the time
it is committed. Two lenses of the closing round found it independently (L4 and L6, 2026-09-07).
The receipt side is what stays quotable: `877cd4f9…` is a fixed field of the receipt file, not a
measurement of the moving tree. Whoever wants the current value runs the command; that is what a
command in a document is for.

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

## The closing round ran a second time, and it was not a formality

The first pass of the adversarial deep gate on this candidate produced `FIX_FIRST` (above). A
second pass ran on 2026-09-07 against the frozen head `4c4f294`, six lenses, preregistered targets
written down BEFORE any result. It returned five REJECTs. All of them are fixed on THIS head, each
with a catch-test that is RED without the fix and green with it — a fix whose test passes either way
has proven nothing.

| Lens | What it broke | The fix, and the proof it works |
|---|---|---|
| L2 | `_RECEIPT_MUSTER` matched a path ENDING, not a path. A committed `src/proofbundle/audit_artifacts/1/pre_tag_receipt_v1.json` fell out of `subject_tree_digest` — digest byte-identical, gate still `verified`, nobody re-signed | Tab anchor at the path start (`pre_tag_receipt_lib.py`). Counter-run: 7 of 7 prefixes silently fell out of the binding without it. The neighbour in the same function (`MUTABLE_EVIDENCE_RELS`, `endswith("\t"+path)`) was anchored all along |
| L5 | The kill signal came from free text: `re.search(r"(\d+) failed", blob)` took the FIRST match in stdout+stderr, and pytest dumps the failing test body — docstrings included — BEFORE the summary. A planted defect raised the true red count 1→2; the parser said 0 both times, verdict SURVIVED | The count now comes from `--junitxml`, a machine interface with fields instead of prose. The text path stays as a fallback and is itself anchored to the LAST summary line. End-to-end gate-meta test with a real pytest subprocess: two red tests must count as two |
| L4 | Three divergences in this file: a tree digest fifteen commits stale, `424c5e3` called "the frozen head" three times when it is that head's PARENT, and a register named `findings_register_600` that does not exist | All three corrected above. The digest is no longer pinned at all — see the first section for why a value that changes with every commit cannot live in a committed file |
| L6 | The rule for a RED repeated mutation run did not exist anywhere. Measured, not assumed: `pre_tag_audit_gate.py` contains no reference to mutation, and `mutation_check.py` does not appear in `release.yml` | Written out in the N11 section, including the honest limit that the release workflow does not enforce it |
| L1 | (withstood its target) but found the wording that claimed a receipt binds a "sha" and did so in the present tense, for a receipt that does not exist yet | Corrected in the N11 section |

**The class, not the five instances.** L2 and L5 are the same violated assumption at surfaces that
share no code: *a string search decides a quantity that means a BOUNDARY*. A sweep over the
`.search()` sites in `scripts/` and `src/` followed (45 real sites on this head — the figure used to
read "50" with no head attached to it, which lens C measured as wrong and, worse, as uncheckable).
It found one more live instance — `test_manifest_gate` read the collected-test count with the first
match in a blob that carries diagnostics before the summary — and one latent sub-class: **five**
scripts read the release version out of `pyproject.toml` with `(?m)^\s*version\s*=`, which anchors
to a LINE and not to the `[project]` TOML section. That one is bound by a property test rather than
rebuilt on the eve of a tag, and the test says so out loud.

**The count in that last sentence read "six" while the property test's own list carried four, and
the fifth real reader was in neither** — `audit_candidate_matrix._version_aus_pyproject`, which
assigns the result to the module-global `VERSION_UNDER_TEST`. The exclusion note in the test's
header even named that file, but for a DIFFERENT and genuinely anchored site inside it. So the class
fix this document reports as done did not cover its own stated population, and nothing said so:
fourth instance of the day's other class — a typed count standing in for a set — this time inside
the test written to bind it. Fixed in the same pass: the list now carries all five, and a new case
sweeps `scripts/*.py` for the pattern and fails if a reader is missing from it. The count is no
longer written anywhere; it is derived. Found by lens C of the verify lane, not by me. It also RETRACTED one of its own candidates: the diff hunk header looked like
the same class, a fix was written, and the catch-test stayed green without it — so the fix came back
out. A withdrawn finding belongs in a sweep as much as a confirmed one.

**One more finding came out of reading rather than from a lens, and it was the blocking one.** The
CI summary job that proves the mutation shards cover the whole operator list held its expectation as
a typed constant, `ERWARTET=88`. Twelve operators were added on 2026-09-06 (`15d05ab`); the list has
stood at 100 since. The guard that exists to find a GAP in the partition would have reported one at
every complete run — including the canonical run this release needs next. The expectation now comes
from the runs themselves, and the shards must agree on it.

## Why this round's findings are not edited into `RESTRISIKO_600.md`

That file states the rule itself, in its own words: a finding of the closing round is a new
iteration with a new freeze, "never an edit of this file", because the receipt binds it by sha256
and a second top-level file would move the tree digest. So the round's outcome is recorded here,
next to the receipt, exactly where 5.1.0 recorded it. `RESTRISIKO_600.md` continues to hold what was
known and open **before** the round, R1–R7 and N1–N15.

The structured, signed carrier of the findings is `audit_artifacts/findings_register_361.json` —
20 entries, 13 closed, 7 open, **0 open P0/P1** (counted, not quoted). That register, not any prose
here, is what `C12.2` reads and counts. **The name used to read `findings_register_600`, and no such
file exists** (L4, 2026-09-07): the register is versioned by the finding-numbering scheme, not by the
release token, and `scripts/findings_register.py:34` pins the real path. A reference that names a
file which is not there cannot be checked by a reader — it can only be believed.

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

| directory | `658ed063` → `68aa6f32` | `658ed063` → `5e9aa66` (after the collector merge) | `658ed063` → `424c5e3` | `658ed063` → `cd91b65` (**the head these figures were measured on**) |
|---|---|---|---|---|
| `src/` | 32 files (+1577 / −373) | 32 files (+1577 / −373) | 32 files (+1577 / −373) | 32 files (+1577 / −373) |
| `tests/` | 46 files (+10631 / −165) | 51 files (+11637 / −189) | 51 files (+11851 / −188) | 54 files (+12747 / −198) |
| `scripts/` | 12 files (+3268 / −224) | 12 files (+3577 / −262) | 12 files (+3577 / −262) | 14 files (+3782 / −277) |
| **total** | **90 files** | **95 files** | **95 files** | **100 files** |

The 2026-09-07 fix cycle for the five closing-round REJECTs moved three more test files and two
more scripts, so the count rose from 95 to 100. That is the expected direction: N11 measures
distance from the canonical run's base, and a candidate that fixes findings gets further from it,
never closer. The condition is unchanged — identity does not hold, so the run is repeated.

The counter-read that followed the fix cycle moved LINES but not FILES: the file count stayed at
100 while `tests/` and `scripts/` grew, because its six findings landed in modules the cycle had
already touched. That is worth writing down, because a file count that holds still while the tree
changes is exactly the kind of number that gets mistaken for "nothing happened".

**A FILE CANNOT NAME THE SHA OF THE COMMIT THAT INTRODUCES IT, and pretending otherwise is how
this table went stale twice.** The last column names `424c5e3`, the head the figures were MEASURED
on. The frozen head is that commit's child — the one this record is part of.

**What pins that child is NOT a commit sha in this file, and the previous wording got this wrong in
two ways at once (L1, 2026-09-07).** It read "its sha is recorded where it can be: in the pre-tag
receipt, which binds the tree". First: the receipt binds a `subject_tree_digest`, a sha256 over the
`ls-tree` entries — 64 hex characters. A commit sha is a sha1, 40 characters. They are structurally
different quantities, and calling one by the other's name invites a reader to compare values that
can never match. Second, and worse: that sentence stood in the PRESENT tense while no receipt for
this head existed. The three receipts in the tree attest earlier candidates; the one for the frozen
head is minted in the signing round, AFTER this text is committed — which is exactly why the order
in the first section is load-bearing. The argument the sentence was reaching for still holds, and
only as a NECESSITY, not as a fact already accomplished: a file cannot contain the digest it is
itself an input to, so the binding has to come afterwards.

That is not a gap, because the figures are INVARIANT across the step: the freeze commit changes
`audit_artifacts/600/README.md` and nothing else, and `audit_artifacts/` is neither `src/` nor
`tests/` nor `scripts/`. Recording the measurement therefore cannot disturb the measurement.
Checkable, not asserted — `git diff --numstat 658ed063 <frozen head> -- src tests scripts` must
return the same four figures, and the collector count below must be unchanged too. If either moved,
something other than this record was committed, and the freeze was broken.

The earlier columns stay. A record that silently replaces its own history is worth less than one
that shows the drift it corrected.

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

`scripts/mutation_check.py` now collects with the normative runner. Measured by **asking the
collector**, the same call the gate makes (`_lauf_der_suite`: `pytest -q -p no:cacheprovider
-p no:randomly`):

    on `5e9aa66`:  3820 tests across 259 files, blind 0
    on `424c5e3`:  3827 tests across 259 files, blind 0
    on `cd91b65`:  3861 tests across 261 files, blind 0   (after the fix cycle and the counter-read)
    on `51af438`:  3866 tests across 261 files, blind 0   (after the partition hardening)
    on this head:  3890 tests across 263 files, blind 0   (measured at the freeze, after the sweep)

**That last figure was written as 3870 while the head was still open, and it was wrong twice over**
(lens C of the verify lane): the number itself, and the count of what this head adds — four was
claimed, eight were there. It then moved twice more, to 3874 when the lens findings' own fixes
landed and to 3890 when the riegel sweep bound what it found. A figure that describes a head still
being written is a moving target, and every intermediate value here was honest at the moment it was
taken and stale one commit later. The rule this document now follows: the collected set is
re-measured immediately before the freeze and named against the frozen head, never carried forward.

**The difference is accounted for per file and per test, not rounded off.** Collected sets measured
with the gate's own collector on both heads, at the freeze:

| file | `51af438` | this head | difference |
|---|---|---|---|
| `test_mutationstor_sammler_sieht_die_freigabeflaeche.py` | 40 | 46 | **+6** |
| `test_claims_hygiene_deckt_die_release_flaeche.py` | — | 4 | **+4** (new file) |
| `test_budget_aufrufpunkte_sind_vollstaendig_erfasst.py` | — | 3 | **+3** (new file) |
| `test_pre_tag_receipt_gate.py` | 39 | 42 | **+3** |
| `test_audit_candidate_360.py` | 28 | 30 | **+2** |
| `test_mutation_shard_partition.py` | 34 | 36 | **+2** |
| `test_rust_parity_gate.py` | 20 | 22 | **+2** |
| `test_zeichenkettensuche_bindet_eine_grenze.py` | 4 | 6 | **+2** |
| whole suite (261 → 263 files) | **3866** | **3890** | **+24** |

All twenty-four are NEW test functions and **nothing was removed** — the set difference in the other
direction is empty, measured with `comm` over the two sorted collect-only listings, not inferred
from the totals. Six bind the abort riegel of the mutation gate, three the committed trust anchor,
four the claims-hygiene surface, three the budget call sites, two the manifest expectation, two the
evidence-free COVERED claim, two the shard collector's red leg, two the version-reader list.

### The skipped side: 25 → 24, and it is NOT a property of either head

The earlier draft of this file said WHICH test moved is **not measurable after the fact**, because
the first run was not recorded with `-rs`. That was wrong, and the correction is worth more than the
number: the fact was unrecorded, not unrecoverable.

**Method.** A `pytest -q` run prints exactly one progress character per test, in collection order,
and `-p no:randomly` was set in every run here. The character strings can therefore be diffed
against each other and indexed into the collect-only listing. The premise is measured, not assumed:
the two runs of `51af438` yield **3866** progress characters each and the run of this head **3890** —
each exactly its own collected count, so the 954 passing subtests contribute none.

**Result.** The two strings differ at exactly ONE position, index 2883 of 3866:

    tests/test_relation_statement_rust_parity.py::TestRelationDifferential
        ::test_crosscheck_relation_differential_green

**Counter-check of the method itself**, because an index mapping that is off by one would name a
neighbour with full confidence: the 24 `s` positions of the recorded run are mapped through the same
listing and compared to that run's `-rs` output. They agree file for file and count for count —
13 + 4 + 3 + 1 + 1 + 1 + 1 = 24. The mapping is not off.

**Cause.** The case carries `@unittest.skipUnless(_binary_available(), …)`, and `_binary_available()`
tests for `tools/pb_verify_rs/target/release/pb_verify_rs` — a cargo artifact, `.gitignore`d, and
therefore part of no checkout of any head. A decorator argument is evaluated at import time, so the
decision is made during collection, before a single test runs.

The worktree for the first run was fresh: no binary at collection, hence the skip. Then, 941 tests
later, `tests/test_wire_bytes_strict.py` (index ~3824) ran `cargo build --release` and **built the
binary inside that same run** — file timestamp `22:04:58.057`, 0.9 s before that run wrote its last
line. Every later run in that tree sees the binary and does not skip. The tree used for this head has
carried it since `11:53:43` and read 24 from its first run onwards.

So the 25 belongs to the FIRST run in a fresh tree, and the 24 to every run after it. It is a
property of the working tree, not of the commit — which is the practical form of the rule that a
skipped count must never be read as a property of a head.

**The honest limit, since this is now understood rather than merely counted:** CI's `test` job runs
the suite without a preceding `cargo build`, so this case is skipped there in every job of the
matrix, permanently. That is declared design, not drift — the module's own docstring calls it
"honest DATA_BLOCKED, never a false pass" — and the differential it guards is still exercised in CI,
by the separate `crosscheck.py` step of the `rust` job, which builds the binary first.

**The full suite on THIS head**, run with the sister virtualenv (the system Python lacks
`opentimestamps`, which would have silently skipped the anchor tests): **3866 passed, 24 skipped,
0 failed, rc=0**, 954 subtests, 1204.99 s. The cross-check that makes the number mean something:
3866 + 24 = 3890, exactly the collected set of THIS head, measured in the same run — the suite ran
the whole population, not a subset of it. `git status --porcelain` before and after the run lists
the same fifteen entries, and the fifteen file digests were re-taken after the run and before the
commit: the tree that was measured is the tree that was frozen.

The parent `51af438` reads the same way: **3841 passed, 25 skipped, 0 failed, rc=0**, 945 subtests,
1171.52 s, clean tree before and after, 3841 + 25 = 3866. Its second run in the same tree read
3842 + 24 — the worktree-dependent skip resolved above. The run on `cd91b65` two heads earlier read
3836 + 25 = 3861 the same way.

**These two lines carried the PREVIOUS head's figures under this head's name until the confirmation
round caught it**, and the mistake is worth naming because it is this document's own recurring one:
the head was renamed when the numbers moved, and the numbers were not. 3827 + 25 = 3852 is a correct
measurement — of `16dcc17`, one commit earlier. A figure that names the wrong head is not a small
error here; it is the exact defect this release cycle spent its day removing.

The seven added tests are the four that close the lens REJECT on the sdist-derivation guard plus
three siblings; the file count is unchanged because they went into existing modules.

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
* **Stands:** identity under N11 does **not** hold — 100 files differ between `658ed063` and
  `cd91b65`, the head these figures were measured on. One changed file already breaks it; a hundred
  is not a closer call, only a louder one.

N11 states what follows when identity fails, and it is not "report and stop": the run **is
repeated** against the head that gets tagged. That is the path taken here, on the owner's decision
of 2026-09-07 (card `OA-1a00701d0f`, answer A): collector first, then the full suite, then the
canonical mutation run on the frozen head, and the freeze happens exactly once.

So this section no longer reports an impossibility. It records the condition that makes the repeat
necessary, and the repeat is the release's own next step — not a deferred one.

### The release standard's conditions, and the head each one was measured on

Six of the eight conditions the standing owner GO of 2026-09-05 makes the release train depend on
are measured here, each with the command that produced it AND the head it ran against. The two that
are missing are missing on purpose: they come AFTER this record exists, and naming them as open is
the point of the list.

**The heading used to read "measured on this head", and that was false for three of the rows** —
caught by the confirmation round, not by me. Two of these quantities CANNOT be measured on this head
from inside this file: the sdist and wheel digests are digests of the tree, and this file is part of
that tree, so writing them here changes them. The same structural fact as the receipt's
`subject_tree_digest` two sections above. The honest form is therefore not a fresher number but a
named head per row.

| Condition | Measured on `16dcc17` |
|---|---|
| full suite exit 0 (on THIS head) | 3866 passed, 24 skipped, 0 failed, rc=0, 954 subtests, 1204.99 s. Cross-check: 3866 + 24 = 3890, the collected set of this head exactly, measured in the same run. Working tree identical before and after, and re-verified by file digest between the run and the commit. Parent `51af438`: 3841 + 25 = 3866, rc=0 |
| two normalised sdists byte-identical (on `16dcc17`; a tree digest cannot be measured from inside the tree it describes) | `REPRODUCIBLE OK`, sha256 `e7c2a5a8fdcde589…`, epoch 1788803738 (`scripts/build_reproducible.py --check`) |
| wheel from the shipped sdist = direct build (on `16dcc17`, same reason) | `WHEEL FREEZE OK`, sha256 `e76fb670a6a40069…` (`--check-wheel`) |
| audit matrix with no red row | 33 checks: 28 PASS, 4 FAIL, 1 EXTERNAL_PENDING, 0 unknown, 0 DATA_BLOCKED. **All four FAILs are signing-round-bound** — C6.2/C6.3/C8.2 still bind `9e742bf` and get re-measured and re-signed in that round, C12.1 has no receipt for this tree yet, which is the same necessity the N11 section states above |
| findings register, 0 open P0/P1 | PASS via C12.2 — 20 findings evaluated from the signed, version-bound register (`6.0.0`), anchor key authorised, measured 2026-09-06 |
| `RESTRISIKO_600.md` carries N12 and N13 | both present (`RESTRISIKO_600.md:142` and `:143`) |
| claims hygiene over the docs | `PASS · 49 docs scanned · 0 violation(s) · 0 missing listed doc(s)` (`scripts/claims_hygiene_check.py`) |
| naming gate over release note and tag text (re-measured on this head) | `[release-text-hygiene] PASS · commit-subjects v5.1.0.post1..HEAD · 16255 Zeichen · 0 Verletzung(en)` — quoted in the language the tool actually prints; the earlier line here silently translated it AND carried 16168, a figure from an earlier head (lens C) (`scripts/release_text_hygiene.py --since-tag v5.1.0.post1`). Worth naming because of WHAT it scanned: every commit subject since the last tag, including this round's, which talk at length about defects, a withdrawn finding and a relapse of my own. The hygiene rule is about overclaiming, and a round that reports its own failures does not trip it |
| canonical mutation run, 0 gaps | **not measured** — it runs against the frozen head, which is this commit's child |
| deep gate run 5 with 0 confirmed findings | **not measured** — it confirms the frozen head after that run |

One number in the mutation condition deserves a word, because the standard states it as "88
operators". The list has carried **100** since 2026-09-06 (`15d05ab`): twelve operators were added
for the release-deciding surface, which until then had none at all. The condition is therefore read
as a PROPERTY — the canonical run over ALL operators of the list, 0 gaps — and the owner replaced
the typed number accordingly on 2026-09-07. A number in a standard goes stale silently the moment
the list grows, which is the same class this release's fix cycle spent its day on.

### The summary job now computes the partition instead of inferring it

The confirmation round asked one question of the mutation gate that the first round had not:
does the summary job CHECK the shard memberships, or only their sum? Measured: only the sum. Each
shard wrote `operators=N total=M` into its artefact; the membership was printed to its log and never
carried over.

That gap is not theoretical here. The two partition procedures this repository can run — weighted
and round-robin — produce identical shard SIZES on the current operator list (`[10,10,10,10,10,10,
10,10,10,10]` for both, summing to 100 either way) while the MEMBERSHIPS differ on **10 of 10
shards**. A summary job that adds sizes cannot tell them apart. Neither can it catch an overlap that
cancels against a gap: eight shards of ten, one of fifteen, one of five also sums to 100.

Each shard now reports its indices, and the summary job computes the union against the operator list
and checks pairwise disjointness — red on a gap, on a duplicate, and on a shard that reports no
membership at all. Sum equality is kept as the cheap first check; it is necessary and, on its own,
was never sufficient.

The same confusion showed up three times in one day, always as a COUNT standing in for a SET: the
summary job's sum, a catch-test comparing sizes instead of memberships, and a number guard checking
set membership instead of the module↔number pairing. All three now stand on the set.

### A banner's fill width is not a property of the abort

The un cross-read of this cycle (`un_turbov1`, `qwen3.8:27b`, direct endpoint) called
`_ABBRUCH_BANNER = ^!{5,} .* !{5,}$` a release blocker, on the grounds that pytest writes FOUR
exclamation marks. Measured in this gate's own run path: the ordinary interrupt writes TWENTY per
side. The objection as stated does not hold — and measuring it found the real path beside it, which
is worse.

`TerminalWriter.sep` computes `N = max((width - len(title) - 2) // 2, 1)`. The fill width is a
function of the TITLE LENGTH, and `session.shouldstop` carries an arbitrary string. At 80 columns
N drops below five once the title passes 68 characters; with a long reason exactly ONE exclamation
mark remains per side. Executed with real pytest in this gate's run path: banner with a single `!`,
`_ABBRUCH_BANNER` did not match, `_rote_aus_lauf` read the summary line `1 failed, 1 passed` and
returned 1 — and against this tree's measured baseline of 0, `1 > 0` books the mutant as KILLED
while the run had aborted. A false green produced by the safety net itself.

The fix takes the quantity out of a machine interface instead of widening the pattern: pytest's
RETURN CODE (2 interrupted, 3 internal, 4 usage) decides first, the banner form stays as a second
riegel and is widened to `!+`. The same move as `--junitxml` against the text parser, and as the tab
anchor in `pre_tag_receipt_lib` — a boundary read from a structured source rather than from the
shape of a string.

**The verify lens found the reason this riegel is NECESSARY rather than merely redundant, and it is
not the one I had written down.** My account said the summary line of an aborted run carries a
partial count. Measured by the lens with real pytest: the JUnit report of that same aborted run is
**well-formed and carries a plausible count too** — `tests="2" failures="1" errors="0"` for a run
that never executed its third test. So the gap was not confined to the text fallback; it ran
straight through the STRUCTURED source, the one this repository moved to precisely because it has
fields instead of prose. A machine interface is only as honest as the completeness of the run it
describes, and nothing in the XML says the run stopped early. The return code is the only field in
the whole picture that does.

**One residual gap, named rather than closed:** `session.shouldfail` — what `-x` and `--maxfail`
trigger — ends a genuinely incomplete run with rc=1, which is NOT in the not-measurable set. Such a
run would pass the return-code riegel. It is unreachable in this gate's call path: `_lauf_der_suite`
passes neither flag and `pyproject.toml` sets no `addopts` carrying them (both checked). Should one
ever be added, pytest still writes a `!`-banner for `shouldfail`, which the widened banner form
catches. The gap is therefore double-covered today and written down here so that adding `--maxfail`
to the gate's invocation is recognised as the load-bearing change it would be.

**Two catch-proofs refuted two of my own versions of this test, and that is the section's real
content.** The first assertion used `! Interrupted: <long reason> !`, which trips the OLD wording
riegel `^!+ Interrupted` still present in `_rote_aus_text` — green with the fix removed, so it bound
a neighbouring riegel rather than the one it named. Rewritten to the `pytest.exit` form, all three
assertions went red without the fix, and I took that as proof.

It was not. **The un cross-read caught the flaw in the proof itself**: my counter-run removed BOTH
parts of the fix at once — the return-code riegel and the widened banner — so a case that fell told
me only that *something* had held it, never which. The rewritten assertion still carried a `!…!`
line, so the widened banner alone would have kept it green. **A check that lifts two causes together
measures neither**, and that is the same class as the summary job's sum, the size-based catch test
and the number guard: a single observation standing in for a set of distinct ones.

The three assertions now each own one riegel: the banner form is bound with `rc=1` (return code
deliberately harmless, only the shape can decide), the return code is bound with no `!` line in the
text at all, and a fourth case removes each riegel SEPARATELY in memory and requires that at least
one assertion loses its redness per riegel. Measured both ways: without the return-code riegel two
cases fall, without the widened banner two other cases fall, and the anti-parity control stays green
in both states, as a control must.

**The verify lane rejected this section's own proof a second time, and the third shape of the class
is the one I would not have found alone.** Lens B moved the return-code check BEHIND
`_rote_aus_bericht` and made it a mere fallback — the documented precedence reversed — and all 45
cases stayed green. Not one of them supplies a REAL, non-empty JUnit report together with a return
code from the not-measurable set; they all use a non-existent report path, where the structured
source returns None anyway and the ordering cannot show. So the riegel was present, effective, and
in the wrong place — and nothing said so.

That precedence is load-bearing for exactly the reason lens A had measured without either of us
connecting it: the JUnit report of an aborted run is well-formed and carries `tests="2"
failures="1"`. The structured source cannot say the run stopped early; the return code is the only
field that can. Put the report first and the gate reads the partial count.

`test_der_RUECKGABEWERT_schlaegt_den_BERICHT_und_das_ist_die_ganze_pointe` now binds the ordering
itself: real report with a countable number, return code 2, text carrying neither banner nor
`INTERNALERROR`. Catch-proof run: it fails under the reversed precedence. Counter-check in the same
case: with rc=1 the report must still count, so the riegel is a precedence and not a blanket
not-measurable.

**One correction to this document's own account of its evidence**: the end-to-end case named after
the abort does NOT bind the banner form. Measured by lens B — the real pytest interrupt returns
rc=2, so the return-code riegel catches it independently, and the case stays green with the banner
form rolled back. A test binds what actually fires in its run, not what its name says.

### Four sufficient conditions, and one of them is not about the result at all

The un cross-read of the precedence fix (`un_turbov1`, `qwen3.8:27b`, second round) returned NO
release blocker and two findings worth the round.

**The counter-check inside the new precedence case was not a counter-check.** It asserted that with
rc=1 the report still counts — using a text that read `1 failed, 1 passed`. With a BROKEN
`_rote_aus_bericht` that assertion stays green, because the text path reads the same 1 out of the
summary line. It proved that SOME source yields 1, never that the report does. The text is now
`collected 2 items`, carrying nothing countable, and the case first asserts that the text path finds
nothing — so the 1 can only come from the report. Catch-proof: blind the report reader, and the case
falls. Before the change it did not.

**And the count of riegel in this path is four, not three.** `_red_count` catches
`subprocess.TimeoutExpired` and `OSError` around the whole run and returns not-measurable without
ever calling `_rote_aus_lauf`. The three inside that function ask what the RESULT says; this one
asks whether the run happened at all — a different kind of question with the same answer. The lens
reported it as unbound; measured, it is bound, just by an older case
(`test_eine_stoerung_des_unterprozesses_ist_NICHT_MESSBAR`, which throws both exceptions for real):
weaken the except branch to return 0 instead of None and that case falls. What the lens got right is
the count, and the count is what the family detector has to cover — a detector written for "the two
riegel" was already short by two.

### The riegel sweep the owner ordered, and what it found in this gate's own summary job

Ordered before the second freeze: walk every riegel that speaks an assertion and ask whether a test
binds its EFFECT or only its WORDING — each finding with a catch-proof that goes red without the fix.
Six strands ran; three are reported here because they touched this release's surfaces.

**P0 — the summary job's RED riegel was bound by nothing.** The job has three documented riegel: a
shard is missing, a shard is RED, the partition is incomplete. Two were bound. The middle one was
not, because all nine cases of `DerSammelJobWirdALSPROGRAMMGefahren` hard-wired
`MUTATION_RESULT=success` into the environment they ran the block with — the variable never carried
the value the riegel tests against. Measured: remove the whole `if` block and all nine stay green.

That is the most dangerous of the three gaps, and the reason is structural. When a shard reports a
SURVIVING mutant, `mutation_check.py` still prints its closing line in full — `total=`, `indizes=`
and all. The sum check and the membership check therefore see a perfect partition and report OK. The
`MUTATION_RESULT` branch is the ONLY place that sees the red run, and nothing tested it. A gate whose
red detection is untested is a gate that only knows the normal case.

Two cases now bind it: a run with a FLAWLESS shard set under `failure` must exit 1 and say so in its
own words, and the anti-parity control keeps the green run green — plus `cancelled`, because
`!= "success"` covers every non-success and a riegel that only knew `failure` would be an enumeration
rather than a condition.

**The un cross-read then named a weakening I had not measured**: cutting the exit rather than the
condition — `exit 1` becoming `exit 0`, so the riegel still PRINTS its error and no longer stops the
job. Measured afterwards, predicted ONE failing case and got TWO: the assertion falls, and so does the
anti-parity control, because its `cancelled` branch also expects exit 1. Correct, and a gap in my own
catch-proof: I had varied the condition and never the effect. A riegel that speaks without acting is
the quietest failure of all, and it was the reviewer who thought of it. Catch-proof, and it took two attempts: removing the block outright made
ELEVEN cases fall, because `_shell_block()` asserts on the word `MUTATION_RESULT` and the removal
took the word with it — a mutation that breaks more than it means does not measure what it claims.
Narrowed to a riegel that stays visible but decides nothing, exactly the two new cases fall and the
other 34 stay green.

**P1 — `test_manifest_gate.pytest_only_modules` survives inversion.** Drop the `not` from its
condition and it selects the exact complement (199 modules instead of 62); `evaluate()` still returns
`ok=True` because 199 clears a floor of 5. All three cases said to bind it stayed green. A floor with
57 of headroom cannot detect a misclassification, and no case pairs a positive with a negative
fixture. Recorded, not yet fixed.

**P1 — the claims-hygiene gate does not scan this document.** Its `_DEFAULT_DOCS` lists 49 files;
`audit_artifacts` does not occur in the script at all. Planted `production-ready and quantum-safe`
into THIS README and the gate still returned `PASS · 49 docs scanned · 0 violation(s)`. The gate is
not broken — the naming gate catches the same phrase in a commit subject and exits 1, measured in the
same run. What was wrong is the use this document made of that PASS: it is quoted above as evidence
about the release text, and it says nothing whatsoever about the file it is quoted in. The scan set
is the finding, and so is the quoting.

### Both P1s closed as a class, on the owner's instruction

**The claims-hygiene gate now derives its release surface instead of listing it.** Adding three
paths would have repeated the same failure at the next release token — a future
`audit_artifacts/610/README.md` would have been outside again. `release_flaeche_docs()` derives the
set: the Markdown of the HIGHEST numeric token plus the root's `RESTRISIKO_*.md`. Scanned set went
from 49 to 53 documents, still PASS.

A first attempt took `rglob("*.md")` over the whole directory and was **too wide**: 89 documents, 9
hits, eight of them on one phrase in sentences that describe our own WORKING METHOD — a ledger
kept without rewriting entries — rather than promising a stranger something about the product. The rule set is built for
product claims. Pointing it at a process log would have meant either weakening the rule or accepting
eight false findings — both worse than a precise set. The narrowing is recorded as an anti-parity case
so the boundary does not get lost.

**The new derivation caught this very document on its first run**, and that is a better proof than
the planted one: the paragraph above quoted the offending phrase in running prose, un-negated, and
the gate flagged it at `audit_artifacts/600/README.md:578`. The first repair failed too — a code
span was put around it, but `_strip_code` recognises inline spans only WITHIN a line (`` `[^`\n]*` ``)
and mine ran across the wrap, so the phrase stayed visible to the scanner. It is now paraphrased
instead. Two things worth keeping from that: a gate that fires on the text explaining the gate is
working exactly as intended, and the second attempt only succeeded because the fix was read out of
the function rather than guessed.

Catch-proof, predicted before running and matched exactly: with the fix, `FAIL · 53 docs · 1
violation` naming file and line; with the derivation rolled back, `PASS · 49 docs · 0 violations` for
the same planted `production-ready`.

**The test-manifest gate now takes its expectation from the TREE, not from a floor.** The floor
checks the SIZE of the pytest-only set; it cannot notice a WRONG set of the same or larger size —
inverting the regex selects the exact complement, 199 modules instead of 62, and `ok` stayed True
because 199 clears a floor of 5. The riegel is now the DIFFERENCE between two independent
derivations: one reads the source as a string, the other as a syntax tree. An import is a node in the
tree, not a text pattern; an error in one reading cannot carry the other with it. **No number appears
in the assertion** — it demands agreement, not a value. Same rule the owner set for the mutation run:
the expectation is measured, never typed.

Catch-proof: predicted TWO failing cases, measured THREE. The third is `test_real_floor_met`, which
reads `ok` and is dragged along by the new problem entry — correct, and something I should have seen
coming. Naming the count before the run is what made the coupling visible instead of letting it pass
as noise; that discipline is itself an owner instruction from this round, and its first application
found me wrong.

### The riegel sweep, closed out with numbers

Six strands, each required to take a riegel back IN ISOLATION and to compare control against variant
on an identical measurement set. What it produced:

| | count |
|---|---|
| riegel measured by mutation | 24 |
| found unbound (a mutation no test caught) | 9 |
| fixed and bound in this cycle | 6 |
| recorded open, with a named reason | 3 |
| findings withdrawn as my own measurement error | 2 |

**Fixed and bound:** the summary job's RED riegel (P0) · the committed trust anchor (P0) · the
claims-hygiene release surface (P1) · the pytest-only expectation, now derived from the tree (P1) ·
the empty-evidence COVERED claim in the parity gate (P1) · the number guard's control, which had been
checking a stale copy of its own derivation.

**Open, each with its reason:** six of twelve budget caps stay unbound — the new case books them by
name and stops the set growing silently, but binding each one is a rebuild of the cost curve and a
separate quiet move. The skip-count assertion in the package guard needs a real sdist as its
measurement surface, and building one on the eve of a tag would measure a fixture, not the artefact.
`pre_tag_audit_gate:311` accepts as soon as ANY receipt candidate verifies, regardless of rejected
candidates beside it — probably intended, not measured either way, so it is written down rather than
changed.

**Withdrawn:** four mutation attempts against the audit matrix produced no finding, and the reasons
differ. Two were INERT — one touched a constant the checked path no longer reads, the other added a
word to an allowlist that never occurs; green after an inert mutation is not a finding but a
measurement that did not happen. The two EFFECTIVE replacements also survived, and that is not a gap
either: `counts[FAIL] == 0` is REDUNDANT rather than unbound — the `all(...)` condition beside it
rejects any FAIL independently, verified by evaluating both variants (`False` either way), so no test
CAN notice its removal. Removing FAIL from the verdict allowlist only makes the gate stricter.

The matrix therefore stands after four attempts, and the honest summary is that its readiness
condition is over-determined rather than under-tested. That distinction was worth three rounds of
measurement, because the first two would have been reported as defects in a release gate.

**And the sweep's own failure mode, six times in one evening:** the measurement surface did not
represent the subject. A copy tree without `.git` let cases skip themselves; a clone carried the
COMMITTED state while the case under test was uncommitted; a nested heredoc silently mangled the
mutation so an UNCHANGED tree reported green — its script said so, in a line my filter did not print.
Each would have produced a false verdict, in both directions. The ledger class now carries three
conditions instead of one: the relevant tests must have RUN, the tree must carry the state under
test, and the mutation must be read back before the result is believed.

### What this record can and cannot show about its own evidence

Three of this round's claim sets carry a runner-signed receipt (`rc_haertung_mutationstor`,
`rc_haertung_isolierter_fangnachweis`, `nachbar_sweep_internalerror_riegel`, plus
`riegel_sweep_zahlen_guard`), each at strength **PARTIAL** and each saying why: no lenses are filed
under the topic, and three of the receipt's components report `env_blocked` because their files live
in the other lane's tree, not in this repository. A PARTIAL that names its gaps is a usable answer; a
FULL would only have been reachable by pointing the witness at the wrong repository.

The riegel-sweep claim set has **no receipt**: the witness answered `busy — a signing run is already
computing`, its own work cap. That is a measured refusal, not a failure of the claim, and it does not
license the claim either. What stands behind the sweep's numbers is what is written beside each one:
the command, the control run, the counts on both sides, and — since the owner's instruction of
2026-09-07 — the predicted number of failing cases stated BEFORE the run.

Two more limits belong here rather than in a footnote. Getting a receipt at all required fetching the
commit into a local clone first, because the witness does not resolve it on its own; that is a crutch
this lane worked around, not a repair. And the naming gate's PASS is quoted in this document for the
release text, which is what it measures — the claims-hygiene PASS beside it was, until this round,
quoted for a document it did not read.

### The suite caught the fix for the class inside the fix for the class

The full run after the sweep came back **RED — one case, rc=1**, and it is the most useful red of the
round. `tests/test_claims_hygiene.py:64` compares the scanned count against `len(_DEFAULT_DOCS)` and
failed with **`53 != 49`**: deriving the release surface moved the effective set, and the assertion
held a TYPED number beside a set that had just grown. That is the exact class this cycle has spent
the day removing, committed by the fix for that class.

Two things follow, and both are measurements rather than opinions. The existing case DOES bind its
effect — it noticed within one run, which is more than most of the riegel the sweep examined could
say. And the repair could not be a bigger number: `main()` and the assertion now read the same
`standard_scan_set()`, one derivation with two readers. Rebuilding the calculation in the test would
have been form (b) of the class — an oracle that shares the implementation's mistake — and the sweep
found that shape twice today already.

A second assertion was added beside it: the derived surface must CONTRIBUTE something. Without it,
someone could quietly return an empty list from `release_flaeche_docs()` and the count would match
`_DEFAULT_DOCS` again — the P1 restored, with every number still agreeing.

**The neighbour sweep for that red case found nothing, and the distinction is the point.** Seven
sites in the corpus assert a length against a typed number; six are FORMAT constants — sha256 is 64
hex characters, an Ed25519 signature 64 bytes, a compressed key 33, a beacon 32 — and none of them
moves because the suite grows. The seventh pins `len(manifest["files"]) == 11` over eleven vendored
test vectors, each digest-pinned, composition spelled out in the comment: a FROZEN set, where the
number is the riegel and a fall is the intended signal when someone adds a vector.

That is the line this class runs along: a number beside a GROWING set goes stale in silence; a number
pinning a FROZEN set is the guard itself. Seven sites, zero instances — reported because a sweep that
finds nothing is also a result, as long as it shows the distinction rather than asserting it.

### And if the repeated run comes back RED

**This paragraph did not exist until 2026-09-07, and its absence was the finding** (deep gate lens 6,
REJECT). The document said what happens — the run is repeated — and never what FOLLOWS when the
repetition fails. A rule whose failure case is unwritten is not a rule; it is an expectation that
whoever reads it at the wrong moment will improvise, under time pressure, alone.

The rule, stated so it can be checked rather than remembered:

**A red repeated run blocks the tag.** `scripts/mutation_check.py` exits 1 on any gap (a mutant that
should die and survives, an equivalent mutant that starts dying, a run that leaves no verdict at
all). That exit code is the verdict for THIS head, and a candidate whose anti-Goodhart layer reports
a gap is not a candidate. There is no partial credit and no "carry it as a known risk": the gate
exists precisely to answer whether the tests still kill broken implementations, and a gap is the
answer NO.

What follows a red run is a new iteration, not an exception: fix the gap, land it, freeze ONCE more,
repeat the run against the new head. That is the same loop N11 already prescribes for a failed
identity check, and it is the loop this release is in right now.

**The honest limit, measured rather than assumed** (lens 6, `grep -n "mutation"
scripts/pre_tag_audit_gate.py` → no hits; `mutation_check` does not appear in
`.github/workflows/release.yml` at all): this rule is NOT enforced by the release workflow. The
`--strict` pre-tag gate rules on the signed receipt and never reads a mutation result; the sharded
mutation job is wired to CI for pull requests, not to the tag path. So the rule above is carried by
the release procedure and by whoever runs it — a human checkpoint, and it is written down here
instead of being assumed, which is the whole difference between a documented gap and an undocumented
one. Wiring it into the tag path is a change to the release surface and belongs to the owner, not to
a quiet edit made the day before a tag.
