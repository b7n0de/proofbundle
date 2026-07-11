# Live-Stand 2026-07-11 (Gate 1, Standard-Track-Master-Prompt)

Erhoben: 2026-07-11 (Session-Start der Standard-Track-Abarbeitung), alle Werte live abgefragt.

## Repo / Git

- Remote: `git@github-b7n0de:b7n0de/proofbundle.git`
- Lokaler Clone: auf `main` gestellt (war auf gemergtem `feat/wp2-content-root-foundation`), ff-pull auf `2e23bb4`
- HEAD main: `2e23bb4` — Merge PR #51 (docs/readme-2.1.0-sync) — deckungsgleich mit Snapshot §0
- Tags (neueste): v2.1.0, v2.0.0, v2.0.0b3, v2.0.0b2, v1.9.2
- Tree: clean

## GitHub

- `b7n0de/proofbundle`: default branch main, 1 Star, 1 Fork, nicht archiviert
- Release: v2.1.0, published 2026-07-10T18:54:46Z, target main
- **Offene PRs: 0** → Gate 2 (PR-Hygiene) PASSED
- Offene Issues: #7 (anchors[], updated 2026-07-11T02:32Z), #24 (JOSS Jan 2027), #26 (in-toto upstream), #27 (SD-JWT VC conformance) — deckungsgleich mit Snapshot

## CI (main)

Letzte Runs alle `completed success`: CI, CodeQL, Scorecard, demo-reproducible, fork-pr-isolation (Push 2e23bb4, 2026-07-10T20:01Z) + Release-Workflow v2.1.0 success. **Main grün** → Gate 2 PASSED.

## PyPI

- `proofbundle` latest: **2.1.0** (JSON-API), Releases: 2.0.0, 2.0.0b1, 2.0.0b2, 2.0.0b3, 2.1.0
- Latest == Git-Tag v2.1.0 ✓

## in-toto/attestation#565

- 9 Kommentare; **weiterhin 0 Maintainer-Reaktion** (nur b7n0de, MarkovianProtocol, clementineCU)
- Letzter Stand: MarkovianProtocol 2026-07-11T00:55Z (worked vector geliefert)
- clementineCU-Boundary: beantwortet + Issue-Body-Non-Goals + ADR 0001 (erledigt, `thread_565_snapshot.md`)

## proofbundle#7 / Colin-Zweitimpl (§12 NACHTRAG)

- Owner-Kommentar 2026-07-11T01:51:38Z gepostet ✓ (deckt sich mit Vorlage)
- Colin-Antwort 02:32Z: beide Fixes drin (frozen decision-URI + vendored eval-result-URI), Commit `3abe69f`
- Regenerierte Roots: evidence `323adb18…`, decision `ff05e3e0…`
- ALTER Anker bestätigt bei Bitcoin-Block 957504 (Commit `9ab2ed2`) — Upgrade-Flow end-to-end belegt
- **NEUER Anker: pending** — `audit-anchor` HEAD ist weiterhin `3abe69f` (02:31Z), kein `ots upgrade`-Push
  → **S1a bleibt gegated** (read-only warten), U1b-Meldung „bereit für Owner-Post" erst danach
- Versand-Regel §12 aktiv: Agent postet NIE extern; nur Owner

## Homepage (bekannte Drifts, Fix in WP-N2)

- Technical-Note-PDF verlinkt „2.0.0b3" auf der 2.1.0-Seite (Monorepo `frontend/proofbundle/`)
- `docs/EXPERIMENTAL_ENCLAVE.md` nennt `2.0.0b1` als Install

## Gate-Entscheidung

- **Gate 1: PASS** (Live-Stand == Snapshot §0, keine Abweichung außer neuem #7-Verlauf, der §12 bereits einpreist)
- **Gate 2: PASS** (0 offene PRs, main grün, keine neuen Dependabot/CodeQL/Scorecard-Funde)
- **Gate 3: aktiv** (Semantik-Kontrolle gilt für jede Änderung)

→ Feature-Arbeit freigegeben, Start mit PR 1 (N1 + N2).
