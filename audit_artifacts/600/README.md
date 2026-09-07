# Pre-tag audit artefacts for release 6.0.0

## Status right now: the receipt does not exist yet, and the gate says so

    $ python scripts/pre_tag_audit_gate.py --repo . --version 6.0.0
    [pre-tag-audit] version=6.0.0 receipt-verified=False (NO_VALID_RECEIPT)
    rc = 1

That is the correct state, not a defect. The receipt binds `subject_tree_digest`, and the tree is
not final until the register commit and the rebuilt distributions are in. It is minted last, after
everything else, and `.github/workflows/release.yml` runs the gate with `--strict` as the third
step of its first job — so a tag pushed before the receipt exists fails before anything is built.

Order, fixed: land the code and the register, then mint the receipt, then tag.

## Why the receipt lives here and not next to the code

`subject_tree_digest` is `git ls-tree HEAD` with the line for this directory removed. The exclusion
removes the circular binding: adding the receipt here leaves the bound tree unchanged. The opposite
is equally true — a change under `src/`, `scripts/` or any other top-level entry DOES move the tree
and invalidates a signature taken before it.

**One consequence of that exclusion is worth writing down, because a docstring in this repository
currently says the opposite.** `pre_tag_receipt_lib.load_trusted_pubkeys` explains that it reads the
trust anchor from the committed tree rather than the working tree — which is true and closes a real
hole — and then concludes that "reading the committed blob binds it by the same digest". It does
not. `audit_artifacts/pre_tag_trusted_pubkeys.txt` lives inside the excluded directory. Measured on
2026-09-06 in a throwaway clone of this candidate, with a control in the opposite direction:

    digest before any change                 4c91c4746768e88262ce3b7067a32389e579ae195e6533a…
    digest after committing to the anchor    4c91c4746768e88262ce3b7067a32389e579ae195e6533a…   same
    digest after committing to README.md     a70cc3fa87fa76d8c60a63a6c8d126526276c75638d6f7b…   different

So the trusted-key set is not covered by the digest the receipt commits to. Exploiting it requires
the ability to commit to the release tree, which is the trust boundary this process already assumes,
and no assurance made to a user of the package rests on it — that is why it did not stop 6.0.0. It
is recorded as its own entry and the sentence is corrected in the follow-up release. The readiness
side of this repository has already fixed the same thing the right way, and its shape is the
remedy: `audit_candidate_matrix._live_tree_digest` excludes only the two named mutable evidence
paths, recursively, instead of a whole directory.

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

## N11, die Identitätsmessung — aufgezeichnet, weil ohne sie kein Lauf zählt

Owner-Anordnung `OA-a8aec4079e`, wörtlich: *„Den kanonischen Lauf abwarten. Sein Ergebnis geht in die
Zeremonie, und die Identitätsmessung nach N11 wird in `audit_artifacts/600/README.md` aufgezeichnet,
so wie N11 es verlangt. Ohne diese Aufzeichnung gilt der Lauf auch dann nicht, wenn er grün ist."*

Hier steht sie. Sie fällt negativ aus, und das ist ihr Zweck.

### Was N11 verlangt

Byte-Identität von `src/`, `tests/` und `scripts/` zwischen dem Baum, auf dem der kanonische
Mutationslauf lief, und dem Kopf, der getaggt wird. Ohne sie sagt der Lauf etwas über einen anderen
Gegenstand als den, der veröffentlicht wird.

### Gemessen 2026-09-07

Basis des kanonischen Laufs: `658ed063` (*Merge pull request #186 from b7n0de/chore/version-6.0.0*,
2026-09-05 04:37:26 +0200).

| Verzeichnis | gegen den heutigen Kandidaten `5242b0c6` | gegen den ursprünglichen Kandidaten `37eab913` |
|---|---|---|
| `src/` | 32 Dateien (+1577 / −373) | 32 Dateien (+1577 / −373) |
| `tests/` | 45 Dateien (+10235 / −156) | 43 Dateien (+9892 / −156) |
| `scripts/` | 10 Dateien (+3059 / −213) | 8 Dateien (+2728 / −204) |
| **Summe** | **87 Dateien** | **83 Dateien** |

**Die Identität hält nicht.** Der kanonische Lauf gilt damit für keinen der beiden Köpfe — weder für
den ursprünglichen Kandidaten noch für den heutigen. Das ist keine Auslegung, sondern die Bedingung,
die N11 selbst formuliert.

### Und der Kopf trägt weiterhin den blinden Sammler

Unabhängig von der Identitätsfrage: `scripts/mutation_check.py` sammelt auf diesem Kopf nach wie vor
mit `unittest discover`. Ein solcher Sammler sieht ausschließlich Methoden von `unittest.TestCase` —
alles, was als schlichte Testfunktion geschrieben ist, ist für ihn nicht vorhanden. Gemessen:

    pytest:            3736 Tests aus 256 Dateien
    unittest discover: 2524 Tests aus 193 Dateien
    blind:             1212 Tests, 63 Dateien — 25 % der Dateien

Diese Zahlen wurden auf `22dc97b5` gemessen. Für `5242b0c6` gelten sie unverändert, soweit es die
Dateien betrifft: der Unterschied zwischen beiden Köpfen umfasst vier Dateien und legt unter `tests/`
weder eine an noch entfernt er eine — nachgemessen, nicht angenommen.

Der Abschnitt „The scope each statement of this round holds over" oben nennt für `N19` **2537 von
3702** und **59 von 252**; diese Zahlen wurden auf `a62d8cb4` gemessen. Sie sind nicht falsch, sie
gelten für einen anderen Baum. Für den heutigen Kopf sind es die Zahlen darüber, und der Anteil ist
größer geworden, nicht kleiner.

Ein Fix, der den Sammler auf pytest umstellt, existiert (`f023a590a6cf376d31f369a3c5a16482e7e0bc33`,
Vollsuite ohne roten Fall, drei Gegenlesungen), liegt aber auf einem **anderen Zweig** und ist in
diesem Kopf **nicht** enthalten — nachgemessen, nicht angenommen.

### Was daraus folgt, ohne Beschönigung

Für die Mutationsbedingung des Release-Standards gibt es auf diesem Kopf kein gültiges Ergebnis:
die Identität nach N11 hält nicht, und der Sammler, der ein Ergebnis erzeugen würde, sieht ein
Viertel der Testdateien nicht. Beides zusammen heißt **NICHT MESSBAR**, nicht „grün" und nicht „rot".

Der Standard sagt für diesen Fall: anhalten und berichten. Genau das ist geschehen; diese Zeilen sind
der Bericht an der Stelle, an der N11 ihn verlangt.
