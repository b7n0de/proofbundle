# Linsenlauf Claude-Familie, 249 Runde 2, Kopf 8879d736

Geprueft wurde `fix/a70-clean-tree-before-binding-work` (PR 249) am Kopf
`8879d736f2ed62fe6cd2c97f06dc9eaf054cf788` ("wip(pre-tag): round 2 state, not judged"), Diff gegen main
`31816e08afeababcf024969fd7bbb5c4d1647b28` (Merge-Basis 31816e08, 11 Commits, 9 Dateien, +2452/-53).
Der Trichter haelt, was er fuer Umgebung und Konfiguration verspricht, und die Sauberkeit wird aus den
Bytes berechnet; der Vertrauensanker der Kette wird aber aus dem Objektspeicher gelesen, und git liefert
dort unter einer Objekt-ID jeden Inhalt, der unter ihr liegt. Das Verdikt ist FIX_FIRST.

Modell laut Harness: `session_context.model` claude-opus-5-5, `external_metadata.last_served_model`
claude-opus-5-5.
Umgebung: Python 3.11.15, git 2.43.0, uid 0, ruff 0.16.9, mypy 2.3.1, pytest mit pytest-subtests.
Roter Test: `tests/test_lens_claude_249_8879d736f2ed.py`, ein Fall L1.

## Behauptete Eigenschaft in einem Satz

Das Sauberkeitstor vor dem Tag beurteilt den wirklichen Baum ueber einen einzigen hermetischen
git-Trichter: die Umgebung ist eine Zulassungsliste, System- und globale Konfiguration sind aus, die
Hebel des Repositorys sind festgesetzt, ein `--repo`, das nicht die oberste Ebene ist, wird abgelehnt, und
ein Generator-Test deckt jeden git-Aufruf der Kette.

## 1. Verdikt

FIX_FIRST, hoechste Schwere P0 (L1).

## 2. Funde

Aufruf: `PYTHONPATH=src python -m pytest tests/test_lens_claude_249_8879d736f2ed.py`.
Ergebnis: rot an 8879d736 und rot an main 31816e08, also vorbestehend und vom Branch nicht geschlossen.
Nachtrag: waehrend dieses Laufs rueckte der Fix-Branch auf 995cabdd (16:39:38Z, nur Tests und CHANGELOG).
Der Lauf bewertet 8879d736 und wurde nicht wiederholt; L1 wurde an 995cabdd erneut gemessen: rot. Die
drei geaenderten Testdateien des Branches ergeben dort 68 passed, 3 skipped; die Beobachtung zu git 2.43.0
in Abschnitt 4 ist an 995cabdd erledigt.

| Nr | Richtung | Flaeche | Eigenschaft | Schwere | Aufruf | Ergebnis |
|---|---|---|---|---|---|---|
| L1 | Geschwister (Klasse von `refs/replace`) | `pre_tag_receipt_lib.load_trusted_pubkeys` ueber `git show HEAD:audit_artifacts/pre_tag_trusted_pubkeys.txt`, gelesen von `pre_tag_audit_gate.py` | Das Tor beurteilt den Baum, den die Quittung nennt, und vertraut nur den Schluesseln der festgeschriebenen Datei. Das lose Objekt der Schluesseldatei wird mit anderen Schluesseln neu geschrieben, unter derselben ID: `ls-tree` und der Baum-Digest bleiben gleich, die Datei im Arbeitsbaum bleibt die festgeschriebene, und das Tor antwortet `ok: true, state: verified` fuer eine Quittung eines Schluessels, den die festgeschriebene Datei nicht nennt. Ohne die Ersetzung lehnt es dieselbe Quittung ab (Vorbedingung im Test). | P0 | `-k test_l1` | rot |

Messung (git 2.43.0): nach dem Ueberschreiben des losen Objekts liefern `git show HEAD:<pfad>` und
`git cat-file -p <oid>` den neuen Inhalt mit Exit 0; nur `git fsck` meldet `hash-path mismatch`. Orakel:
das Objektmodell von git (eine Objekt-ID benennt ihren Inhalt), fremdes Werkzeug `git fsck`.

Bewertung (getrennt von der Messung):
- Die Vorbedingung ist Schreibzugriff auf `.git/objects` des Baums, den das Tor prueft. Denselben Zugriff
  setzt die Klasse voraus, die der Branch schliesst (`refs/replace`, `core.useReplaceRefs`, Index-Bits,
  Konfiguration im Repository): Zustand ausserhalb des festgeschriebenen Baums entscheidet, was das Tor
  sieht. Der Unterschied: diese Ersetzung bleibt in der festgeschriebenen Schluesseldatei unsichtbar, eine
  Aenderung der Datei im Commit waere es nicht.
- Hinweis, kein Fix: der gelesene Inhalt laesst sich gegen die ID pruefen (`git hash-object --stdin` ueber
  den Inhalt gleich `git rev-parse HEAD:<pfad>`), wie der Branch es fuer die Sauberkeit schon tut
  (`hash-object --no-filters` gegen die `ls-tree`-ID).

## 3. Klassen und Geschwister

Klasse "ein git-Lesen liefert ein anderes Objekt als das, das seine ID nennt":
- `refs/replace` und `core.useReplaceRefs`: vom Branch geschlossen (`--no-replace-objects`, `-c
  core.useReplaceRefs=false`, `GIT_NO_REPLACE_OBJECTS=1`).
- Vertrauensanker ueber `git show` in `pre_tag_receipt_lib.py:352`: L1, gemessen.
- `pre_tag_receipt.py:192`: der Erzeuger hasht die Tor-Quelle aus `cat-file blob` (gelesen, NICHT GEMESSEN).
- `verify_pre_tag_receipt.py:427` und `:448`: der Drittpruefer liest Tor-Quelle und Pfade mit `show`, und
  `:441` holt die vertrauten Schluessel ueber dieselbe `load_trusted_pubkeys` (gelesen, NICHT GEMESSEN).
- Alternates (`.git/objects/info/alternates`) als zweiter Weg zu einem fremden Objekt unter derselben ID:
  NICHT GEMESSEN.

## 4. Gepruefte Flaechen ohne Fund

- Trichter (`git_environment`, `git_run`): Umgebung aus `PATH`, `SYSTEMROOT` und festen Werten gebaut,
  `GIT_WORK_TREE` und `GIT_CEILING_DIRECTORIES` gesetzt, System- und globale Konfiguration aus,
  Top-Level-Pruefung vor jedem Aufruf (gelesen).
- Sauberkeit aus Bytes: jede `ls-tree`-Datei per `hash-object --no-filters` gegen die ID, Modus per
  `S_IXUSR`, Verzeichnisse oberhalb per `lstat`, gestagte Aenderungen per `diff-index --cached`,
  unverfolgte Pfade vom Dateisystem (gelesen; die Index-Bits `assume-unchanged` und `skip-worktree`
  stehen nicht mehr zwischen Platte und Vergleich).
- Die bekannte offene Stelle von main, `subject_tree_digest` unter `GIT_DIR`: der Fall
  `test_RED_the_release_gate_judges_the_named_tree_not_the_one_GIT_DIR_names` ist an diesem Kopf gruen.
- Beobachtung, kein Fund: `pre_tag_audit_gate.py` vergleicht den Arbeitsbaum nicht mit HEAD (gemessen:
  `ok: true, verified` mit einer geaenderten, nicht festgeschriebenen `payload.py`). Das Tor behauptet das
  nicht, und der Tag benennt den Commit; ob ein Release aus dem Arbeitsbaum gebaut wird, NICHT GEMESSEN.
- Eigene Testdateien des Branches (5): 55 passed, 81 subtests passed, 2 failed und 1 Subtest failed, alle
  drei an der Vorbedingung, nicht an der Eigenschaft: auf git 2.43.0 aendert `core.useReplaceRefs=true` in
  `.git/config` die Antwort eines gewoehnlichen git nicht ("this row measures nothing", "precondition: the
  configuration switches replacement back on"). Der Commit 8879d736 misst "all 26 pass" ohne git-Version.
  Schwere P3 (Testumgebung), kein eigener Test.
- `ruff check src tests scripts`: keine Befunde. `mypy src` 2.3.1: keine Befunde in 73 Dateien (der Branch
  aendert `src/` nicht).

## 5. Grenzen

- Der Kopf ist als WIP markiert ("round 2 state, not judged"); geprueft wurde er so, wie er steht.
- Mutationsgate: NICHT GEMESSEN.
- Rust-Differenz: NICHT ANWENDBAR, die Quittungskette ist Python-Werkzeug ohne Rust-Gegenstueck.
- git-Versionen ausser 2.43.0: NICHT GEMESSEN; ob die drei Vorbedingungen auf neuerem git halten, auch nicht.
- Volle Suite auf dem Linsenbranch: nicht gelaufen.
- Keine Aussage ueber Vollstaendigkeit.

Prepared with AI agent involvement, reviewed and submitted under human oversight.
