# Klassen-Ledger — Defektklassen, die in diesem Repo geschlossen wurden

Append-only. Ein Eintrag beschreibt eine KLASSE (die verletzte Invariante), nicht die Instanz, an
der sie auffiel. Granularitaet: ODC `defect_type x trigger x source_layer` — nicht so abstrakt, dass
sie nichts mehr ausschliesst, nicht so konkret, dass sie eine Datei:Zeile ist.

Zwei Funde derselben Runde koennen zwei KLASSEN sein. Sie zu einer zusammenzuziehen, weil sie in
derselben Datei sassen, waere Symptom-Zusammenlegung: die Oberflaeche ist geteilt, die Ursache nicht.

---

## KLASSE-A-2026-0905 — Freigabeentscheidende Evidenz ohne Provenienz und ohne Kandidatenbindung

**Verletzte Invariante.** Eine Pruefung, die ueber die Freigabe entscheidet, darf ein Bestehen nur
aus Evidenz bilden, die (1) unter einem eingecheckten Vertrauensanker signiert ist, (2) den exakten
Release-KANDIDATEN bindet (Commit, Baumkennung, sdist- und wheel-Digest), (3) ihre Provenienz nennt
(Schema, Erzeuger, Werkzeugversion, Eingabe-Digest, Zeit, Signiererrolle), (4) frisch ist,
(5) Arbeitszaehler ungleich null traegt und (6) ihren eigenen Fehlerfeldern nicht widerspricht — und
deren Aussage (7) ausschliesslich aus den SIGNIERTEN Feldern gebildet wird.

**ODC.** defect_type = checking (missing validation) · trigger = data/artefact provenance ·
source_layer = release-gate.

**Wie es auffiel.** Tiefen-Gate 2026-09-05, Linse `L5_assertion_by_absence`, Fund L5-G7-02 (P2).
Vier reproduzierte Bestehen: das echte, auf `3.6.0` lautende, unsignierte Soak-Artefakt entschied
ueber `6.0.0`; ein JSON mit zwei Schluesseln ergab „0 crash, 0 false-accept"; ein Artefakt mit
`ok=false` und nichtleerer `untriaged_crashes`-Liste ergab dasselbe Gruen; und
`{"all_agree": true}` ergab „Python==Rust on all" ueber null Vektoren.

**Nachbarn im selben Durchgang gefegt.** C6.2, C6.3, C8.2 (Zulassungspfad), C8.3 (Existenz einer
Datei plus Teilzeichenkette ueber einen JSON-Abzug), C10.2 (das handgetippte Wort „filled"),
C9.1 (Urteil aus Teilzeichenketten der Standardausgabe eines Unterprozesses).

**Wo die Klasse jetzt lebt.** `scripts/audit_candidate_matrix.py`:
`_signed_versioned_artifact` / `_artifact_verdict` / `_trust_anchor` / `_live_tree_digest` /
`_candidate_binding_error` / `_provenance_error` / `_freshness_error`. Erzeuger:
`scripts/sign_readiness_artifact.py`. Anker: `audit_artifacts/readiness_trusted_pubkeys.txt`.

**Orakel.** `tests/test_freigabe_evidenz_provenienz_l5_g7_02.py` — eine Matrix aus 24 erfundenen
Evidenzen gegen jeden freigabeentscheidenden Leser, mit Anti-Paritaets-Zeile und Gate-Meta-Test.

**Ehrliche Grenzen.** Die Digests von sdist und wheel werden verlangt, mitsigniert und nicht
nachgerechnet. Der Anker dieses Repos ist heute leer, also ist heute keine Evidenz zulassbar — die
betroffenen Zeilen sind rot, und das ist der wahre Zustand.

---

## KLASSE-B-2026-0905 — Eine AUSFUEHRUNG aus QUELLTEXT abgeleitet

**Verletzte Invariante.** Aus Quelltext (einer Workflow-Datei, einer CHANGELOG-Zeile, einem
Kommentar) darf keine freigabeentscheidende Zeile ableiten, dass etwas GELAUFEN ist. Sie darf
hoechstens sagen, was DEKLARIERT und EINGESCHALTET ist, muss genau das sagen, muss es STRUKTURELL
lesen (Dokument parsen, Kommentare fallen weg, abgeschaltete Jobs/Schritte zaehlen nicht) und muss
bei fehlendem Parser Datenblockade melden. Die staerkere Aussage braucht einen kandidatsgebundenen
Laufbeleg; gibt es den nicht, gehoert sie nicht in die entscheidende Matrix.

**ODC.** defect_type = checking (wrong evidence kind) · trigger = source-text inference ·
source_layer = release-gate.

**Wie es auffiel.** Tiefen-Gate 2026-09-05, Fund L5-G7-04 (P3): das Bein fuer das veroeffentlichte
Artefakt in `c1_1_two_ci_gates` war
`"sdist" in pub.lower() or "published" in pub.lower() or "cleanroom" in pub.lower()`. Eine
`published-artifact-gate.yml` mit `name: nothing`, leeren `jobs: {}` und dem Kommentar
„this file used to check the sdist; the leg was removed" ergab PASS.

**Warum das NICHT Klasse A ist.** Geteilt ist die Oberflaeche (dieselbe Datei), nicht die Ursache.
Ein Signaturanker haette diesen Fund nicht verhindert; eine YAML-Analyse haette jenen nicht
verhindert. Zusammengezogen waeren beide Klassen unscharf und die Nachbarsuche liefe ins Leere.

**Wo die Klasse jetzt lebt.** `scripts/audit_candidate_matrix.py`:
`_published_artifact_leg_facts` / `_run_touches_distribution` neben dem schon bestehenden
`_ci_workflow_facts`; die AUSSAGE von C1.1 ist auf „Konfiguration deklariert und eingeschaltet"
zurueckgenommen, samt Titel.

**Orakel.** `tests/test_ausfuehrung_aus_quelltext_l5_g7_04.py` — zehn Attrappen, die das Bein nur
behaupten, eine Anti-Paritaets-Zeile, ein Test auf die AUSSAGE selbst und ein Gate-Meta-Test.

**Nachbarflaeche geprueft (Auflage C5).** `scripts/pre_tag_audit_gate.py::_positive_audit_marker`
ist dieselbe Bauform (Schluss von Prosa auf ein Ereignis). Gemessen: sie traegt KEIN
freigabeentscheidendes Verdikt — `evaluate()["ok"]` entsteht ausschliesslich aus verifizierten
Receipts, `changelog_records_audit` ist als `changelog_is_presentational` ausgewiesen, und der
zweite Aufrufer `audit_records_for` ist ein Lokalisierer ohne Produktionskonsumenten. Der Zustand
ist mit zwei Tests festgehalten, damit ein spaeteres Verdrahten auffaellt. Nebenbefund, nicht
behoben: `attesting_records_for` / `attests_version` — die gehaertete Allowlist-Form aus L5-02 —
haben ueberhaupt keinen Produktionsaufrufer.
