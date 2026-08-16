# OpenSSF Best Practices — honest self-assessment

Erhoben am 2026-08-07 unter `QITEM-PB-RUNDE2-371-AUSLIEFERUNGSFAEHIG-01`.

**Kein Antrag, keine Anmeldung, kein Profil.** Diese Datei ist eine Selbsteinschätzung gegen den
Kriterienkatalog, damit man sieht, wo das Projekt steht, bevor jemand ein Abzeichen beantragt. Der
Antrag selbst ist Aussenwirkung und braucht einen eigenen Owner-GO.

Drei Zustände, nie zwei: **erfüllt** · **nicht erfüllt** · **nicht messbar / nicht anwendbar**. Der
dritte wird nicht zu „erfüllt" geschönt.

---

## Teil 1: OpenSSF Scorecard — der gemessene Wert

Kein Fragebogen, sondern ein Werkzeug, das das Repository von aussen abtastet. Der Lauf ist bereits
verdrahtet (`.github/workflows/scorecard.yml`, `publish_results: true`) und das Ergebnis öffentlich
abrufbar.

**Gesamtwert: 6,5 von 10.** Gelesen aus `api.securityscorecards.dev` für
`github.com/b7n0de/proofbundle`, Stand `2026-08-07T18:37:54Z`, Scorecard **v5.5.0**.

| Wert | Check | Anmerkung |
|---:|---|---|
| 0/10 | Maintained | überrascht bei täglicher Arbeit — der Check zählt Aktivität auf dem **Standard-Zweig** und Issue-Verkehr, und beides läuft hier über Arbeitszweige. **Nicht weginterpretiert:** der Wert steht so da. |
| 0/10 | CII-Best-Practices | genau das Abzeichen, um das es in Teil 2 geht. Kein Antrag gestellt → 0. |
| 0/10 | Signed-Releases | der Release-Workflow hängt eine **SLSA-Build-Provenance** an und gated den Upload auf sha256. Der Check sucht Sigstore-Signaturen an den Release-Assets und findet keine. Zwei verschiedene Dinge; der Wert ist trotzdem 0 und wird hier nicht schöngeredet. |
| 0/10 | Contributors | verlangt Beiträger aus mindestens zwei Organisationen. Ein-Personen-Projekt. |
| 1/10 | Code-Review | die meisten Commits sind nicht von einer zweiten Person geprüft. Strukturell, nicht behebbar durch Fleiss. |
| 3/10 | Pinned-Dependencies | **widerspricht dem eigenen Kommentar** in `scorecard.yml`, der behauptet, dieser Check sei ausgereizt („all actions SHA-pinned"). Gemessen: 3/10. Der Kommentar ist eine Überbehauptung und gehört korrigiert. |
| 3/10 | Branch-Protection | teilweise. |
| 9/10 | Binary-Artifacts | |
| 10/10 | Security-Policy · Dependency-Update-Tool · Dangerous-Workflow · Token-Permissions · Vulnerabilities · Packaging · License · SAST · Fuzzing · CI-Tests | zehn Checks auf Vollwert |

**Der Wert wird weder geschönt noch verschwiegen.** 6,5 ist mittelmässig, und die vier Nullen haben
drei verschiedene Ursachen: eine ist ein fehlender Antrag (behebbar), eine ist ein Werkzeug, das eine
andere Signaturform sucht als die vorhandene (erklärbar), und zwei sind Eigenschaften eines
Ein-Personen-Projekts (nicht behebbar, ohne dass eine zweite Person dazukommt).

---

## Teil 2: Best-Practices-Katalog, Stufe `passing`

| Kriterium | Zustand | Beleg / was fehlt |
|---|---|---|
| Projektseite beschreibt Zweck | **erfüllt** | `README.md` |
| Projektseite nennt Beitrags-Weg | **erfüllt** | `CONTRIBUTING.md`, verlinkt |
| Freie Lizenz, in der üblichen Datei | **erfüllt** | `LICENSE`, MIT |
| Dokumentation der Grundfunktionen | **erfüllt** | `README.md`, `SPEC.md`, `docs/` |
| Dokumentierte Schnittstelle | **erfüllt** | `SPEC.md`, `docs/IN_TOTO_PROFILE.md` |
| Fehlerberichte werden angenommen | **erfüllt** | GitHub Issues aktiv (gemessen: `hasIssuesEnabled: true`) |
| Weg für Sicherheitsmeldungen | **erfüllt** | `SECURITY.md` |
| Wie man Unterstützung bekommt | **erfüllt** | `SUPPORT.md` (neu in dieser Runde) |
| Öffentliches Versionskontroll-Repository | **erfüllt** | GitHub, öffentlich |
| Eindeutige Versionsnummerierung | **erfüllt** | SemVer; `scripts/check_version_and_changelog.py` erzwingt Einheitlichkeit über alle Stellen |
| Release-Notizen je Version | **erfüllt** | `CHANGELOG.md`; der Riegel prüft, dass die aktuelle Version einen Abschnitt hat |
| Release-Notizen nennen behobene Schwachstellen | **erfüllt** | z. B. der M2-Eintrag |
| Automatisierte Testsuite | **erfüllt** | `make test` (`unittest discover -s tests`), 155 Testdateien, in `ci.yml`. Gemessen am 2026-08-07 mit dem Läufer des Repos: **2007 Tests, OK, 7 übersprungen, rc 0** in 75,8 s. (Nebenbei ein Beispiel für den Punkt, um den es hier geht: derselbe Baum unter `pytest` meldet 740 Sammelfehler — das ist eine Aussage über das fremde Werkzeug, nicht über das Repo, und wäre als Repo-Zahl falsch.) |
| Neue Funktionalität braucht Tests | **erfüllt** | `CONTRIBUTING.md`; zusätzlich ein Mutations-Gate |
| Warnungen behandelt | **erfüllt** | `ruff` mit gepinntem Regelsatz, `mypy` |
| Statische Analyse | **erfüllt** | CodeQL (`codeql.yml`), Scorecard SAST 10/10 |
| Dynamische Analyse | **erfüllt** | Property-based Fuzzing (Hypothesis), Scorecard Fuzzing 10/10 |
| Gesicherte Auslieferung | **erfüllt** | HTTPS durchgehend; PyPI-Upload sha256-gated gegen das attestierte Artefakt |
| Keine bekannten offenen Schwachstellen | **erfüllt** | Scorecard Vulnerabilities 10/10 |
| Öffentlich bekannte Schwachstellen binnen 60 Tagen behoben | **nicht messbar** | es gab bisher keine gemeldete öffentliche Schwachstelle — kein Nachweis, aber auch kein Verstoss. Wird nicht als „erfüllt" gebucht. |
| Kryptographie: öffentliche Standardverfahren | **erfüllt** | Ed25519 über `cryptography`, DSSE, sha256 — keine Eigenbauten |
| Zwei-Personen-Review | **nicht erfüllt** | Ein-Personen-Projekt; deckungsgleich mit Scorecard Code-Review 1/10 |
| Beitrags-Weg für Änderungsvorschläge | **erfüllt** | Pull Requests |
| Verhaltenskodex | **erfüllt** | `CODE_OF_CONDUCT.md` |
| Wer entscheidet | **erfüllt** | `GOVERNANCE.md`, `MAINTAINERS.md` |
| Abkündigungs- und Kompatibilitätszusage | **erfüllt** | `COMPATIBILITY.md` (neu in dieser Runde) |

**Zusammengefasst:** die `passing`-Kriterien sind bis auf **zwei** erfüllt. Beide verbleibenden sind
dieselbe Tatsache aus zwei Blickwinkeln — es gibt eine Person. Zwei-Personen-Review ist **nicht
erfüllt**, und die 60-Tage-Zusage ist **nicht messbar**, weil der Fall nie eintrat.

## Stufen `silver` und `gold`

Nicht durchgegangen, und das ist eine bewusste Grenze statt einer Lücke: beide verlangen mehrere
Beiträger beziehungsweise mehrere Prüfer, und daran scheitert es vorher. Eine Bewertung der übrigen
Kriterien wäre Aufwand ohne Aussage, solange das eine bindende Kriterium nicht erfüllbar ist.

## Was der Owner entscheiden muss

1. **Scorecard-Ergebnis veröffentlichen** (Badge im README)? Der Wert **6,5** würde damit sichtbar.
   Die Empfehlung ist ja: ein veröffentlichter mittelmässiger Wert ist mehr wert als ein
   verschwiegener guter, und die Zahl ist über die API ohnehin öffentlich abrufbar.
2. **Best-Practices-Abzeichen beantragen?** Das ist eine Anmeldung bei einem Dienst und damit
   Aussenwirkung — in dieser Runde ausdrücklich **nicht** getan.

## Ehrliche Grenzen dieser Seite

- Der Katalog wurde **aus dem bekannten Kriterienbestand** abgearbeitet, nicht von der Website
  abgerufen — der Antrag ist nicht gestellt und die Seite nicht aufgerufen worden. Einzelne
  Formulierungen können abweichen; die Zustände beruhen auf gemessenen Repo-Eigenschaften.
- Der Scorecard-Wert ist ein Stand vom `2026-08-07T18:37:54Z`. Er ändert sich mit jedem Lauf.
- „Erfüllt" heisst hier: die geforderte Sache existiert und ist belegbar. Es heisst nicht, dass sie
  gut ist.
