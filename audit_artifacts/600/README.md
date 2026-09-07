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
share no code: *a string search decides a quantity that means a BOUNDARY*. A sweep over all 50
`.search()` sites in `scripts/` and `src/` followed. It found one more live instance —
`test_manifest_gate` read the collected-test count with the first match in a blob that carries
diagnostics before the summary — and one latent sub-class: six scripts read the release version out
of `pyproject.toml` with `(?m)^\s*version\s*=`, which anchors to a LINE and not to the `[project]`
TOML section. That one is bound by a property test rather than rebuilt on the eve of a tag, and the
test says so out loud. It also RETRACTED one of its own candidates: the diff hunk header looked like
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

The full suite on `cd91b65`, run in a detached tree with the sister virtualenv (the system Python
lacks `opentimestamps`, which would have silently skipped the anchor tests): **3827 passed, 25
skipped, 0 failed, rc=0**, 945 subtests, 1254.85 s, `git status --porcelain` empty before and after.
The cross-check that makes the number mean something: 3827 + 25 = 3852, exactly the collected set —
the suite ran the whole population, not a subset of it.

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

### The release standard's conditions, measured on this head

Six of the eight conditions the standing owner GO of 2026-09-05 makes the release train depend on
are measured here, each with the command that produced it. The two that are missing are missing on
purpose: they come AFTER this record exists, and naming them as open is the point of the list.

| Condition | Measured on `16dcc17` |
|---|---|
| full suite exit 0 | 3836 passed, 25 skipped, 0 failed, rc=0, 948 subtests, 1193.08 s — detached tree, `git status --porcelain` empty before and after. Cross-check: 3836 + 25 = 3861, the collected set exactly |
| two normalised sdists byte-identical | `REPRODUCIBLE OK`, sha256 `e7c2a5a8fdcde589…`, epoch 1788803738 (`scripts/build_reproducible.py --check`) |
| wheel from the shipped sdist = direct build | `WHEEL FREEZE OK`, sha256 `e76fb670a6a40069…` (`--check-wheel`) |
| audit matrix with no red row | 33 checks: 28 PASS, 4 FAIL, 1 EXTERNAL_PENDING, 0 unknown, 0 DATA_BLOCKED. **All four FAILs are signing-round-bound** — C6.2/C6.3/C8.2 still bind `9e742bf` and get re-measured and re-signed in that round, C12.1 has no receipt for this tree yet, which is the same necessity the N11 section states above |
| findings register, 0 open P0/P1 | PASS via C12.2 — 20 findings evaluated from the signed, version-bound register (`6.0.0`), anchor key authorised, measured 2026-09-06 |
| `RESTRISIKO_600.md` carries N12 and N13 | both present (`RESTRISIKO_600.md:142` and `:143`) |
| claims hygiene over the docs | `PASS · 49 docs scanned · 0 violation(s) · 0 missing listed doc(s)` (`scripts/claims_hygiene_check.py`) |
| naming gate over release note and tag text | `PASS · commit-subjects v5.1.0.post1..HEAD · 16092 characters · 0 violation(s)` (`scripts/release_text_hygiene.py --since-tag v5.1.0.post1`). Worth naming because of WHAT it scanned: every commit subject since the last tag, including this round's, which talk at length about defects, a withdrawn finding and a relapse of my own. The hygiene rule is about overclaiming, and a round that reports its own failures does not trip it |
| canonical mutation run, 0 gaps | **not measured** — it runs against the frozen head, which is this commit's child |
| deep gate run 5 with 0 confirmed findings | **not measured** — it confirms the frozen head after that run |

One number in the mutation condition deserves a word, because the standard states it as "88
operators". The list has carried **100** since 2026-09-06 (`15d05ab`): twelve operators were added
for the release-deciding surface, which until then had none at all. The condition is therefore read
as a PROPERTY — the canonical run over ALL operators of the list, 0 gaps — and the owner replaced
the typed number accordingly on 2026-09-07. A number in a standard goes stale silently the moment
the list grows, which is the same class this release's fix cycle spent its day on.

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
