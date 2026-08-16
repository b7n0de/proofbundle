# PRE-REGISTRATION — deep gate on the 3.8.0 release candidate

**Frozen 2026-08-16, before the run.** This document exists so the run cannot be graded against
targets chosen after seeing its results. Nothing below may be edited once the jury starts; a target
that turns out to be unreachable is recorded as unreachable, not removed.

| Field | Value |
|---|---|
| Subject | `b7n0de/proofbundle`, branch `release/v3.8.0` |
| Candidate commit | `f64d35e` (base `origin/main` `ac0688c`) |
| Version under test | 3.8.0 |
| Mode | `[DEEP-GATE: DEEP 6L/7I]` — a release candidate always declares DEEP |
| Methodology | v4, resolved from `office/governance/berkeley_gate_surfaces.json::canonical_prompt_version` |
| Verdict tag sought | `WITHSTANDS_DEEPGATE` on **this digest**, not on a neighbouring one |

## 1. Threat model for this candidate

The shipped delta over 3.7.0 is **one file**: `src/proofbundle/cli.py`, +14 lines, adding
`verify-proof --expected-origin`. Everything else that landed since 3.7.0 is fixture, test, CI or
documentation. The threat model is therefore narrow and stated narrowly — a wide model here would be
theatre.

**The capability under test:** a relying party at the command line can now demand that a validly
signed checkpoint carries the origin it expects. Before this, it could not. The interesting failure is
not "the flag does nothing" — that a test would catch — but the two asymmetric ones below.

## 2. Falsification targets, frozen

Each target is stated as something that would make the release **wrong**, with the shape of the
executable exploit that would demonstrate it. Opinion does not count; a target falls only to a run.

| # | Target — what would falsify the candidate | Exploit shape |
|---|---|---|
| F1 | `--expected-origin` accepts a checkpoint from a DIFFERENT origin (the flag is decorative) | craft a signed checkpoint with origin A, verify with `--expected-origin B`, expect exit 1; a 0 falsifies |
| F2 | Omitting the flag CHANGES an existing verdict (silent behaviour change in a release claiming none) | run every corpus vector with and without the flag absent; any verdict difference falsifies |
| F3 | The flag's failure is indistinguishable from a broken signature (a relying party misreads the cause) | mismatching origin must keep `inclusion_ok` true and name the expectation; a bare FAIL falsifies |
| F4 | The origin comparison is not exact (prefix, case, unicode, trailing byte) | feed near-miss origins: `example.com/log ` (trailing space), case variants, NFC/NFD pairs, a prefix `example.com/lo` |
| F5 | The flag raises rather than returning a verdict on hostile input (never-raise contract) | `--expected-origin` with non-str, empty, very long, and control-character values |
| F6 | The CHANGELOG claims something the tree does not do | every claim in the `[3.8.0]` section must point at a commit or a test that exists |
| F7 | The version bump is inconsistent across the three enforced places, or a fourth place carries a version | `check_version_and_changelog.py` plus a grep for version-shaped strings |

## 3. Negative-state requirement, including **absent**

For every target, three states must be exercised, and `absent` is the one usually skipped:

- **present and correct** — the flag is given and matches
- **present and wrong** — the flag is given and does not match
- **absent** — the flag is not given at all

`absent` is pre-registered explicitly because the default path is the one every existing user is on,
and a release that changes it while claiming it does not is the worst outcome available here.

## 4. Standing targets carried in (RT-01..RT-08)

The standing round-table targets are in scope unchanged. Two are called out because this candidate
touches their surface:

- **RT-05 / RT-06 (category missed?)** — the deliberate question "is there a class here that the
  category names do not cover?" must be answered in writing, not skipped.
- **RT-08 (environment matrix)** — the run measures both the as-shipped minimal install and the full
  one. This is pre-registered because a measurement earlier today was green for a reason unrelated to
  the defence it named: `verify_rfc3161` returned at its optional-import guard before reaching the
  lines under test, and only installing `[anchors]` made the probe measure its subject.

## 5. Pre-sweep, before any jury

`scripts/b7_berkeley_pre_sweep.py` replays every learned class first. Measured baseline at freeze
time: `class_ledger.jsonl` carries **120 entries** over **116 distinct classes**. A single red
learned class aborts the run as `FIX_FIRST` before the jury is paid for.

## 6. Gate meta-test

Before the verdict counts, the gate must be shown to catch a planted defect of the class it claims to
close, in an **untouched** file family. A gate that cannot demonstrate this is `BLOCKED`, not green.

## 7. What a verdict here does and does not mean

`WITHSTANDS_DEEPGATE` means **ready for Owner submission**. It does not mean released, does not mean
tagged, and does not mean safe. Merge, tag, GitHub release and PyPI publish remain four separate
Owner-GOs. The standing GO `GO_OWNER_PB_RELEASE_371_NACH_WITHSTANDS_20260807` makes this verdict
precondition 1 of seven, not a substitute for the other six.

## 8. Declared boundaries of this run

- The commits on `ci/version-consistency-gate` (PR #139) are **not** in this candidate
  (KORRIGIERT nach Gegenlesung: hier stand "the 27 commits". Die 27 reproduziert AUSSCHLIESSLICH
  gegen eine veraltete lokale Ref `a83f01e` vom 12.08. Zum Einfrierzeitpunkt trug der echte PR
  28 Commits, heute 29 mit bzw. 27 ohne Merges — und dass 27 heute zufaellig auch der
  no-merges-Wert ist, machte die Verwechslung unsichtbar. Weder Ref noch Merge-Politik waren
  genannt.) and are not
  graded here. That branch is red for a separate reason and is a separate decision.
- The candidate is graded on its digest `f64d35e`. If the branch moves, the verdict does not follow
  it — a new digest needs a new run, per the standing GO's own wording.

## 9. Appended after the run started — a rule of mine that, read literally, forbids its own use

The freeze in the preamble says nothing below may be EDITED once the jury starts. This section is
therefore APPENDED, and section 8 above stands unchanged. What follows is a clarification of it, with
the measurement that makes the clarification necessary.

**The problem.** Section 8 says: *"If the branch moves, the verdict does not follow it — a new digest
needs a new run."* Writing the pre-tag audit record IS a branch move. Under the literal rule, recording
a verdict invalidates the verdict being recorded, and no release can ever be graded. That is not a
subtlety I reasoned my way to; it is what the sentence says.

**Why I wrote it that way.** The rule does not distinguish a move of the CODE from a move of the
RECORD. When it was written the two had not yet come apart, and the stricter reading looked free.

**The measurement that settles it.** Between the graded digest `f64d35e` and the current branch head:

```
git diff --name-only f64d35e..<head> -- src/      ->  0
git diff --name-only f64d35e..<head> -- tests/    ->  0
git diff --name-only f64d35e..<head> -- scripts/  ->  0
changed:  CHANGELOG.md  +  the three audit_artifacts/380/ files
```

The code that was graded is byte-identical. What moved is the record and the claims about it — and
those moves are the corrections the falsification pass itself produced (F5, F6 and F7 fell, plus the
arithmetic errors a counter-read found in the first correction).

**The house form, for comparison.** `audit_artifacts/370/pre_tag_adversarial_audit_370.md` opens by
naming the digest it graded — *"run on the 3.7.0 release candidate (commit 02509ca3, version bump +
changelog PR head)"* — and is itself a later commit. The record names its subject rather than
pretending to be contemporaneous with it.

**The clarified rule, narrower than the loose reading and stricter than none:** a verdict binds the
`src/` + `tests/` + `scripts/` tree of the digest it names. A commit that changes ONLY the record
(CHANGELOG prose, `audit_artifacts/`) does not require a new run, and the record must NAME the digest
it graded. A commit that touches any of those three paths does require a new run, without exception.
Whether the code moved is a `git diff`, not a judgement call — which is the point: the escape hatch is
measurable, so it cannot be argued open.

**Honest limit.** This is me loosening a rule I wrote, in the run it governs, and that deserves the
suspicion it invites. Two things bound it: the loosening is defined by a command whose output anyone
can reproduce, and it is narrower than the 3.7.0 precedent it aligns with. It does not touch the seven
preconditions of the standing GO, and it does not make a verdict out of anything.

## 10. Angehaengt nach der Gegenlesung — meine Lockerung in §9 war weiter, als sie behauptete

§9 bleibt unveraendert stehen; dieser Abschnitt korrigiert sie, statt sie umzuschreiben.

**Der Befund, ausfuehrbar gezeigt.** §9 band das Verdikt an `src/ + tests/ + scripts/` und nannte das
"der Code". Zwei der DREI Orte, die `check_version_and_changelog.py` als Versions-Wahrheit erzwingt,
liegen ausserhalb dieser Blende — `pyproject.toml` und `CITATION.cff`. F7 ist der Zielpunkt, der genau
diese drei Orte prueft; sein eigener Gegenstand konnte sich also bewegen, ohne dass §9 es bemerkt.

Und es ist nicht theoretisch. `ed8c3b5` liegt IN diesem Release-Delta:

```
git diff --name-only ed8c3b5^..ed8c3b5                        -> pyproject.toml
git diff --name-only ed8c3b5^..ed8c3b5 -- src/ tests/ scripts/ -> (leer)   <- §9: bindet weiter
git diff ed8c3b5^..ed8c3b5 -- pyproject.toml | grep '^[+-]dev'
  -dev = [... "ruff>=0.5" ...]
  +dev = [... "ruff>=0.5,<0.16" ...]
```

Der Linter, der in CI blockierend urteilt, wird gewechselt — und die §9-Messung meldet sauber.

**Der Satz, der dabei am meisten schmerzt**, steht in §9 selbst: *"the escape hatch is measurable, so
it cannot be argued open."* Das ist als Formulierung falsch. Die Luke muss nicht aufargumentiert
werden — sie ist konstruktiv offen. Ein `pyproject.toml`-Commit ist nicht "ONLY the record" und
loest die Pflicht-Klausel trotzdem nicht aus. Und *"The code that was graded is byte-identical"* misst
drei Pfade und berichtet ueber "den Code": dieselbe Klasse, fuer die sich der CHANGELOG zwei Dateien
weiter entschuldigt. Ich habe sie im selben Atemzug begangen.

**Die korrigierte Bindemenge.** Ein Verdikt bindet den Baum des genannten Digests ueber:

```
src/  tests/  scripts/  conformance/  schemas/  formal/  examples/
pyproject.toml  CITATION.cff  MANIFEST.in  .github/workflows/
```

Begruendung je Zugang, damit die Liste nicht selbst zur Aufzaehlung ohne Regel wird — die REGEL ist:
alles, was den ausgelieferten Inhalt, seine Metadaten, sein Pruefkorpus oder das Urteil ueber ihn
bestimmt. `pyproject.toml` traegt Version, Abhaengigkeiten und den Entry-Point, den F1-F5 fahren ·
`CITATION.cff` ist die dritte erzwungene Versionsstelle · `MANIFEST.in` entscheidet den sdist-Inhalt
(der CHANGELOG nennt ihn selbst als Delta-Bestandteil) · `conformance/` und `schemas/` sind das
Vektorkorpus, gegen das geurteilt wird · `formal/` traegt die Beweisverpflichtungen ·
`.github/workflows/` ist die Quelle jeder CI-Aussage in dieser Akte.

Ausserhalb bleiben bewusst: `docs/` und `audit_artifacts/` (das ist die Akte selbst, und ihre
Bewegung ist genau der Fall, den §9 erlauben sollte), `README`/`CHANGELOG` (Prosa ueber den Stand),
`tools/` (unabhaengig versioniert, Cargo-Crate `0.1.0`).

**Ehrliche Grenze, und sie ist dieselbe wie beim ersten Mal:** ich erweitere hier eine Regel, die ich
geschrieben und dann zu eng gemessen habe, wieder im laufenden Verfahren. Was sie bindet, ist
nachrechenbar (`git diff --name-only <digest>..<head> -- <liste>`); was sie NICHT faengt, ist eine
Aenderung an einem Pfad, den niemand auf die Liste gesetzt hat. Eine Aufzaehlung bleibt eine
Aufzaehlung. Die dauerhafte Form waere die Umkehrung — alles bindet, ausser einer kurzen, begruendeten
Ausschlussliste — und die gehoert in den naechsten Lauf, nicht in eine dritte Anhaengung an diesen.

## 11. Die Umkehrung — angehaengt, obwohl Abschnitt 10 sie in den naechsten Lauf schob

§10 endet mit: *"Die dauerhafte Form waere die Umkehrung … und die gehoert in den naechsten Lauf,
nicht in eine dritte Anhaengung an diesen."* Das war ein Fehler, und zwar genau der, den §10 an §9
korrigiert: **eine Instanz erweitern und den Klassen-Fix vertagen.** Eine Gegenlesung hat die
erweiterte Liste gegen ihre eigene Regel gemessen — *"alles, was den ausgelieferten Inhalt, seine
Metadaten, sein Pruefkorpus oder das Urteil ueber ihn bestimmt"* — und VIER Verstoesse gefunden, einen
davon live:

| ausgeschlossen | warum das die eigene Regel verletzt |
|---|---|
| `docs/readiness_pack/` | `MANIFEST.in:26` sagt `graft docs/readiness_pack` — es IST ausgelieferter Inhalt. Und es hat sich seit `f64d35e` bewegt (4 Dateien). Der Live-Verstoss. |
| `README.md` | `pyproject.toml:9` `readme = "README.md"` — das ist die `long_description` auf PyPI, also "seine Metadaten". |
| `fuzz/`, `.clusterfuzzlite/` | vier Seed-Vektoren und der Fuzz-Treiber — die Regel nennt "sein Pruefkorpus" ausdruecklich. |
| `action/action.yml` | eine veroeffentlichte GitHub-Action, die bei Konsumenten `pip install proofbundle[…]` fahrt. |

Der letzte Absatz von §10 nennt den Grund selbst: **eine Aufzaehlung bleibt eine Aufzaehlung.** Sie
faengt nicht, woran niemand gedacht hat, und genau daran hatte ich viermal nicht gedacht.

**Die Regel ab hier.** Ein Verdikt bindet den Baum des genannten Digests ueber **jede verfolgte
Datei**, ausser diesen Ausschluessen:

| ausgeschlossen | Grund |
|---|---|
| `audit_artifacts/` | die Akte UEBER den Digest; ihre Bewegung ist der Fall, den §9 erlauben soll. `MANIFEST.in:32` prunt sie. |
| `tools/` | eigenstaendig versionierter Cargo-Crate `0.1.0`, `MANIFEST.in:31` prunt ihn, kein Bestandteil des Python-Artefakts. |
| `assets/` | Bilder, kein Verhalten. |
| `paper.md`, `paper.bib` | JOSS-Einreichungstext. |
| `docs/` **ausser** `docs/readiness_pack/` und `docs/adr/renewal_policy.example.json` | Prosa. Die zwei Ausnahmen liefert `MANIFEST.in:26-27` aus. |

**Die Ausschlussliste hat selbst einen Waechter, und das ist der eigentliche Klassen-Fix.** Eine Liste
kann still etwas ausschliessen, das ausgeliefert wird — genau so ist `docs/readiness_pack`
durchgerutscht. Deshalb wird sie gegen `MANIFEST.in` geprueft: **kein `graft`- oder `include`-Pfad
darf von der Ausschlussliste erfasst sein.** Gemessen: `MANIFEST.in` liefert 8 Eintraege aus, davon
erfasst die Ausschlussliste **null**. Die Pruefung braucht keine zweite Messstelle — `MANIFEST.in`
ist die eine Quelle dafuer, was im sdist landet, und sie wird gelesen statt nachgebildet.

**Was das fuer diesen Lauf bedeutet, gemessen statt behauptet:**

```
git diff --name-only f64d35e..039ac5d      -> 21 Dateien   §11: 15   §10: 5
git diff --name-only f64d35e..c9e94b3      -> 22 Dateien   §11: 16   §10: 6
zusaetzlich gefangen: docs/readiness_pack/ (4 Dateien, AUSGELIEFERT) · .gitignore ·
                      RELEASE.md · CHANGELOG.md · die drei entfernten dist_*-Artefakte
```

**Die zwei Zeilen stehen hier, weil die erste Fassung nur EINE hatte — und `HEAD` statt eines
Pins.** Sie nannte 21/15/5, gemessen an `039ac5d`, und wurde in `c9e94b3` eingefuegt. Genau dieser
Commit legt eine 22. Datei dazu (`tests/fixtures/.../MANIFEST.json`, der Herkunfts-Vermerk), die
nach BEIDEN Regeln bindet — ab der Sekunde des Commits waren die eigenen Zahlen also falsch. Eine
Messung mit `HEAD` im Befehlstext ist selbstwidersprechend, sobald sie aufgeschrieben wird: das
Aufschreiben bewegt `HEAD`. Der Klammerzusatz darunter bleibt richtig, er zaehlt die Differenz der
beiden Regeln, nicht den Stand.

Die drei `dist_*`-Dateien sind der zweite lehrreiche Fall: sie waren **verfolgt** und lagen damit in
jedem Quell-Archiv und in jedem Zenodo-Deposit — 19,3 % des unkomprimierten Archivs von v3.7.0 — und
standen auf keiner Liste. Eine Regel, die "alles ausser" sagt, haette sie vom ersten Tag an gebunden.

**Damit bindet das Verdikt vom Digest `f64d35e` diesen Kopf nicht.** Das ist keine Formalie: `cli.py`
hat nach dem benoteten Digest eine sicherheitsrelevante Aenderung (Steuerzeichen) und ein neues
Ausgabefeld bekommen, gegen die F1-F5 nie gemessen wurden. Ein neuer Digest braucht einen neuen Lauf,
und das ist die Konsequenz aus meiner eigenen Korrektur, nicht eine Auflage von aussen.

**Ehrliche Grenze, dreifach.** (1) `docs/`-Prosa faellt weiterhin frei, obwohl eine Aussage, die mehr
verspricht als der Code haelt, ein echter Defekt ist — das faengt hier `claims_hygiene_check` und
`doc_link_check` in der Batterie, nicht diese Regel. Wer sie fuer lueckenlos haelt, taeuscht sich.
(2) Der Waechter prueft die Ausschlussliste gegen den **sdist**-Inhalt; ein Pfad, der weder im sdist
noch auf der Ausschlussliste steht, bindet per Default — das ist die gewollte Richtung, heisst aber
auch, dass ein neues Verzeichnis ohne Nachdenken bindet und einen Lauf ungueltig macht. Das ist der
Preis der Umkehrung, und er ist billiger als der umgekehrte Fehler. (3) Die Regel steht heute in
dieser Datei und wird von Hand angewandt; ein ausfuehrbarer Riegel dafuer existiert nicht.
