# Where the version number lives, and which places are allowed to be wrong

Erhoben am 2026-08-07 unter `QITEM-PB-RUNDE-DOKU-UND-RIEGEL-01`. Die Liste ist **gemessen**
(`git ls-files` plus Zeilen-Scan), nicht aus dem Gedächtnis geschrieben. Der Riegel dazu ist
`scripts/check_version_and_changelog.py`.

## Die eine Quelle

| Ort | Zeile | Wert |
|---|---|---|
| `pyproject.toml` | 7 | `version = "3.7.0"` |

**Bestätigt wie vorgeschlagen.** Begründung, nicht nur Zustimmung: `pyproject.toml` ist die einzige
Stelle, die das Build-Werkzeug beim Paketieren tatsächlich liest. Jede andere Stelle kann falsch
sein, ohne dass ein Artefakt anders wird; diese nicht. Der Riegel liest die Quelle über
`_source_version()`, das Wert **und** Herkunftsdatei zusammen zurückgibt — getrennt gelesen wäre der
nächste Fall von „Zahl ohne Gegenstand".

## Abgeleitet — **keine**

Gemessen: es gibt **keine** Stelle, die die Version automatisch zieht. Weder `importlib.metadata`
noch ein `dynamic`-Feld in `pyproject.toml`. `src/proofbundle/__init__.py` trägt die Zahl von Hand.

Das ist ein Befund, keine Einstufung: die Kategorie „abgeleitet" ist im Repo derzeit leer, und jede
Kopie hängt an einem Menschen, der sie nachzieht. Der Riegel gleicht das aus, indem er vergleicht —
er ersetzt die Ableitung nicht. **Nicht in dieser Runde geändert** (der Auftrag verbietet
Semantikänderungen an Code).

## Geprüft — bleibt von Hand, wird aber verglichen

Diese Stellen müssen die Quelle wörtlich nennen. Eine Abweichung ist ein Fehlschlag, kein Hinweis.

| Ort | Zeile | Ankerform | am 2026-08-07 gemessen | Prüfung |
|---|---|---|---|---|
| `src/proofbundle/__init__.py` | 16 | `__version__ = "<v>"` | 3.7.0 | Check 1 (Single-Sourcing) |
| `CITATION.cff` | 18 | `version: <v>` | 3.7.0 | Check 1 (Single-Sourcing) |
| `RELEASE.md` | 81 | `(current&#58; <v>)` | 3.7.0 | Check 4 (`_TRACKED_PLACES`) |
| `docs/readiness_pack/PROGRESS.md` | 3 | `(current release&#58; <v>)` | 3.7.0 | Check 4 (`_TRACKED_PLACES`) |
| PyPI | — | `info.version` | 3.7.0 | Check 5, nur mit `--external` |
| `b7n0de.com/proofbundle` | — | `PyPI latest <code>&lt;v&gt;</code>` | nicht in dieser Runde abgefragt | Check 5, nur mit `--external` |

Die Ankerformen stehen hier mit Platzhalter statt mit der Zahl, und das ist kein Schönheitsgriff:
in der ersten Fassung dieser Seite stand die Form wörtlich mit `3.7.0` — **Check 6 hat genau das
gefangen**, weil eine Doku über Versionsstellen sonst selbst zu einer wird. Der Riegel hat seinen
ersten echten Fund an seinem eigenen Autor gemacht.

Die beiden Aussenstellen kennen drei Zustände. Nicht erreichbar heisst `NICHT MESSBAR` und ist
**weder grün noch rot**; `--require-external` macht daraus einen Fehlschlag und gehört in die
Release-Checkliste, wo „wir konnten nicht nachsehen" blockieren muss.

## Nachtrag 2026-09-04 — zwei Stellen fehlten, und eine Form auch

Erhoben beim Bau von `5.1.0.post1`, gemessen wie oben und nicht erinnert. Die Liste vom 07.08. war
für ihren Tag richtig; sie war **nicht vollständig**, und das fiel erst auf, als eine Versionsform
auftrat, die es damals nicht gab.

### Die zwei fehlenden Stellen

| Ort | Art | warum sie hier fehlte |
|---|---|---|
| `scripts/audit_candidate_matrix.py::VERSION_UNDER_TEST` | **Vorschrift** | Sie war eine feste Zeichenkette. Ein Literal driftet lautlos: es hat am Tag des Schreibens recht. Gemessen am 04.09. meldete das Skript seine **eigene** Drift (`version_pin: {state: drift, pinned: 5.1.0, shipping: 5.1.0.post1}`) — und niemand musste handeln, weil ein fester Wert nichts erzwingt. Sie wird jetzt aus `pyproject.toml` gelesen. |
| `docs/readiness_pack/index.json::release_evidence_slots` | **Nachschlag-Schlüssel** | Kein Spiegel, deshalb fiel sie durch das Raster dieser Liste: sie trägt die Zahl nicht als Aussage, sondern als **Schlüssel** einer Tabelle mit exaktem String-Vergleich. Genau dadurch brach sie, als die Version `5.1.0.post1` hiess — ein Folgefehler der Behebung oben, kein Altbestand. |

Der zweite Fall ist der lehrreichere: eine Liste, die nach „Stellen, die die Zahl **nennen**"
sucht, findet keine Stelle, die die Zahl **nachschlägt**. Die Kategorien dieser Seite (Quelle,
abgeleitet, geprüft, historisch) hatten für ihn kein Fach.

### Die fehlende Form

Alle Ankerformen dieser Seite standen als `X.Y.Z`. PEP 440 kennt mehr: `.postN`, `aN`/`bN`/`rcN`,
`.devN`. Das Muster des Riegels war reines SemVer und las aus `5.1.0.post1` die Zeichenfolge
`5.1.0` — verglichen gegen die korrekt gelesene volle Quellversion ergab das FAIL, **und zwar in
beide Richtungen**: die Dokumente sagten `5.1.0` → FAIL, sie sagten `5.1.0.post1` → auch FAIL. Ein
Tor, das eine gültige Form strukturell nicht bestehen kann, ist keine Prüfung, sondern eine Sperre.
Derselbe Defekt sass ein zweites Mal in derselben Datei, in `_semver_tuple`.

### Was seither bewacht wird

`tests/test_version_single_source.py` hält jede bekannte Stelle gegen die Quelle und nennt die
Datei im Befund. Drei Bauentscheidungen darin sind gegen genau die Fehler gerichtet, die diese
Seite beschreibt:

- Die Matrix wird über die **Bauform** geprüft, nicht über den Wert — eine wieder fest
  geschriebene Konstante hätte am Tag des Schreibens recht.
- Die Prosa-Stellen werden gegen den **echten** Baum geprüft, nicht nur gegen einen synthetischen.
  Eine Gegenlesung hat gemessen, dass `pytest` grün blieb, während das echte Tor eine gepflanzte
  Drift in `RELEASE.md` meldete.
- Die Ordnung der Versionen wird gegen ein **unabhängiges Orakel** gehalten (`packaging.version`),
  nicht gegen eine zweite Ableitung derselben Annahme.

### Was dieser Nachtrag NICHT behauptet

Die Zahl steht nach dieser Messung an **sieben** Stellen. Der Test bewacht die, die er kennt — er
kann keine achte verhindern. Er nennt sie namentlich, damit die nächste beim ersten Fehlschlag
auffällt statt still zu driften. Das ist eine gebundene Grenze, keine Vollständigkeit.

## Historisch — darf und soll alt bleiben

17 gemessene Zeilen. Sie halten fest, **wann** etwas wahr wurde. Wer sie mitzieht, macht aus einer
Tatsache eine Falschaussage, deshalb stehen sie ausdrücklich **nicht** unter dem Riegel:

- `CHANGELOG.md` — alle `## [X.Y.Z]`-Überschriften und die Prosa darunter
- `INTEGRATIONS.md:75,91` — „sample-count provenance **since** v3.7.0"
- `CROSS_IMPLEMENTATION_REPORT.md:86`, `docs/readiness_pack/differential_matrix.md:24`,
  `docs/readiness_pack/rust_parity_scope.md:27` — „56/56 **as of** v3.7.0"
- `docs/release_scope/3.7.1.md` — Planung der **nächsten** Fassung, keine Aussage über die aktuelle
- `audit_artifacts/370/` — eingefrorene Artefakte einer vergangenen Fassung

Zwei weitere Mengen bleiben ebenfalls aussen vor, aus je eigenem Grund: `tests/` nennt falsche
Versionen **mit Absicht** (20 Zeilen, das sind die Fixtures der Muss-Fangen-Tests), und untracked
Dateien sind keine Aussage des Repos.

## Was der Riegel deswegen prüft

| # | Prüfung | Wirkung |
|---|---|---|
| 1 | Single-Sourcing über die drei Code-/Metadaten-Stellen | fail-closed |
| 2 | `CHANGELOG.md` trägt einen Abschnitt für die aktuelle Version | fail-closed |
| 3 | Post-Tag-Drift, verankert am letzten **Release**-Tag | fail-closed, git-gated |
| 4 | Die deklarierten Prosa-Stellen nennen die Quelle; ein **verschwundener Anker ist ebenfalls ein Fehlschlag** | fail-closed |
| 5 | PyPI und Projektseite, drei Zustände | fail-closed bei Abweichung |
| 6 | **Neu:** eine Stelle, die eine aktuelle Version behauptet, ohne deklariert zu sein | fail-closed |

Check 6 schliesst die Lücke, die Check 4 bauartbedingt hat: Check 4 bewacht, was jemand
**eingetragen** hat. Eine neue Zeile, die anfängt, die aktuelle Fassung zu nennen, war bis dahin
unsichtbar — und genau die Stelle, die niemand deklariert hat, ist die, die veraltet. Der Fund
verlangt eine Entscheidung (eintragen oder umformulieren), weil ein Scan nicht wissen kann, ob eine
Aussage aktuell gemeint ist. Er greift auch dann, wenn die Zahl **heute stimmt**: Übereinstimmung im
Moment ist nicht die Eigenschaft, um die es geht.

## Wo der Riegel läuft

- CI: `.github/workflows/release-integrity.yml:31` — `python3 scripts/check_version_and_changelog.py --repo .`
- Release-Checkliste: `RELEASE.md:20` — `--external --require-external` muss grün sein

## Ehrliche Grenzen

- Der Riegel prüft **Übereinstimmung von Zeichenketten**, nicht ob die Version die richtige ist. Eine
  überall konsistente falsche Zahl besteht ihn.
- Check 6 findet Behauptungs-**Formen** (`current: X.Y.Z`, `latest release: X.Y.Z`). Eine Zeile, die
  die aktuelle Fassung in einer anderen Formulierung behauptet, findet er nicht. Er verengt die
  Lücke, er schliesst sie nicht.
- Die Aussenstellen werden nur mit `--external` befragt. Ohne das Flag sagt die Ausgabe
  ausdrücklich, dass sie **nicht** geprüft wurden — kein stilles Grün.
