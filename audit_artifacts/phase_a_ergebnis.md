# Phase A Ergebnis — CI-Hygiene / Release-Pipeline / #565

Datum: 2026-07-09, Europe/Berlin. Ausführender: Release-Engineer/CI-Auditor. Quellengebunden, fail-closed.

## PR-Nachschluss (A1)

| PR | Ergebnis | Commit/Begründung | Teststatus |
|---|---|---|---|
| #32 | GESCHLOSSEN (superseded #37) | Einzelmerge erzeugte init/analyze-Mismatch | n.a. |
| #33 | GESCHLOSSEN (superseded #37) | dito | n.a. |
| #36 | GESCHLOSSEN (superseded #37) | dito | n.a. |
| #37 | GEMERGED (be26334) | codeql-action konsistent auf 4.37.0 | CI success |
| #35 | **GEMERGED 2026-07-09 (eb7ca47)** | upload-artifact 4.6.2→7.0.1 `@043fb46d…` (v7.0.1, gepinnter Commit == Prompt-verifizierte SHA) | PR-Checks alle pass (CodeQL/analyze/anchors/branch-base/crypto-floor/guard/mutation/pypi-sixty-second-try), MERGEABLE/CLEAN |
| #34 | **GEMERGED 2026-07-09 (009f89a)** | download-artifact 4.3.0→8.0.1 `@3e5f45b2…` (v8.0.1, gepinnter Commit == Prompt-verifizierte SHA) | PR-Checks alle pass, MERGEABLE/CLEAN; nach #35 sauber (non-overlapping Hunks, kein Rebase nötig) |

**A1-Akzeptanz:** `gh pr list --state open` = leer (kein Dependabot-/CI-PR-Rest). release.yml jetzt auf upload-artifact v7.0.1 + download-artifact v8.0.1.

## CI-Status (A2)

- CodeQL/analyze nach #37 (konsolidierter 4.37.0-Bump): **success** (main-Runs 07-09T09:03).
- main-Runs nach #34/#35-Merge (07-09T17:21): CodeQL, Scorecard, demo-reproducible, fork-pr-isolation = **success**; CI-Run zum Prüfzeitpunkt noch laufend (kein Fehler beobachtet).
- Hinweis (Prompt): release.yml wird von PR-Checks NICHT ausgeführt — der echte Test der v7/v8-Bumps ist der nächste Release-Run.

## Release-Pipeline (A3) — KRITISCHER BEFUND ÜBERHOLT

Der Prompt-Kernbefund („PyPI fehlen 1.9.2, 2.0.0b2, 2.0.0b3, latest stable 1.9.1") ist bei Live-Prüfung am 2026-07-09 **nicht mehr reproduzierbar**:

- PyPI (live `https://pypi.org/pypi/proofbundle/json`, 2026-07-09): Versionen enthalten **1.9.2, 2.0.0b2, 2.0.0b3**; `info.version` (latest stable) = **1.9.2**.
- Release-Workflow-Runs für die Tags: v1.9.2 (07-05T14:07), v2.0.0b2 (07-05T18:35), v2.0.0b3 (07-06T19:00) = alle **success**.

**Folgerung:** Der PyPI-Publish-Pfad lief zwischenzeitlich erfolgreich durch; die im Prompt vermutete Lücke existiert aktuell nicht mehr. **Kein Nachpublizieren nötig, keine Pipeline-Reparatur nötig.** (Kein neuer Release-Tag erstellt — Scope-Grenze eingehalten.) Root-Cause der zwischenzeitlichen Verzögerung nicht weiter aufgeklärt, da der Zustand behoben ist; falls gewünscht, retrospektive Log-Analyse als Follow-up.

## #565 Snapshot (A4)

OFFEN — der vollständige verbatim-Thread-Snapshot (`thread_565_snapshot.md`) ist noch nicht erstellt. Aus den späteren Prompts (Phase C) bekannt: die Antwort auf den clementineCU-Kommentar (9.7.) wurde vom Maintainer bereits gepostet + der Issue-Body editiert (Non-goals-Sektion) — in Phase A nur zu snapshotten, nicht zu beantworten. **Nächster Schritt.**

## Blocker / Follow-ups

- A4 #565-Snapshot erstellen (read-only).
- Optional: retrospektive Log-Analyse der PyPI-Verzögerung (behoben, daher niedrige Prio).
- Workflow-Permissions Least-Privilege (A2.2) nur zu dokumentieren — noch offen.
