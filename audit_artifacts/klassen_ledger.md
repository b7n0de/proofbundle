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

---

## KLASSE-C-2026-0905 — Eine Zusicherung verkleinert ihre eigene Positivmenge, um eine Zahl zu erzwingen

**Verletzte Invariante.** Eine Eigenschaftszusicherung ("die akzeptierte Menge entspricht der
Referenzmenge") darf ihren Korpus nicht durch einen Ausschluss VOR dem Zaehlen auf das gewuenschte
Ergebnis zurechtstutzen. Gueltige, von der Referenz-Spezifikation ausdruecklich zugelassene
Umformungen desselben signierten Inhalts (hier: Umordnung des C2SP-Signaturblocks — eine MENGE ohne
Reihenfolge — und eine zusaetzliche wohlgeformte Zeile eines unbekannten Schluessels, die note.Open
ignoriert statt ablehnt) gehoeren in die POSITIVMENGE. Eine Formulierung wie "genau eine akzeptierte
Drahtform", die nur durch Herausfiltern dieser gueltigen Formen wahr wird, behauptet mehr Praezision
(globale Byte-Einzigkeit), als sie tatsaechlich zeigt (Mengengleichheit mit der Referenz).

**ODC.** defect_type = assertion (Zusicherung praeziser als geprueft, false precision) · trigger =
test-oracle/property specification · source_layer = test-Eigenschaftsformulierung + begleitender
Docstring-Vertrag.

**Wie es auffiel.** Externer Review Runde 2 (2026-09-05), Framing-Lane, Bedingung "Der Korpus darf
nicht durch eine falsche Einzigkeitsaussage seine eigene Positivmenge verkleinern": der Reviewer
zeigte an `tests/test_note_rahmung_kanonisch.py::test_eine_note_hat_genau_eine_angenommene_drahtform`,
dass die Zaehlung `and not k.startswith("umordnung-") and not k.startswith("fremde-")` genau die
gueltigen Positivfaelle aus der Menge nahm, BEVOR `len(formen) == 1` geprueft wurde — ohne den
Ausschluss haette der Test seine eigene Zusicherung nicht mehr erfuellt.

**Wo die Klasse jetzt lebt.** `src/proofbundle/checkpoint.py::_split_signed_note` (Docstring, die
Formulierung "akzeptierte Menge entspricht der Referenzmenge innerhalb des erklaerten Vertrags" statt
"genau eine Drahtform"); `tests/test_note_rahmung_kanonisch.py` (Moduldocstring plus
`test_akzeptierte_menge_entspricht_referenzmenge_ohne_formausschluss`, ohne Ausschluss, mit expliziter
Positivmengen-Zusicherung fuer Umordnungen und fremde wohlgeformte Zeilen).

**Orakel.** Die Zaehlung haengt am extrahierten Notentext (`cp._split_signed_note(b)[0]`), nicht an den
rohen Bytes der ganzen Nachricht — eine gueltige Umformung aendert per Konstruktion nur den
Signaturblock, nie den Text, waehrend eine faelschlich angenommene ANDERE Note (verschobener
Leerzeilenlauf, eingespeiste Klartextzeile) einen zweiten Textdigest erzeugen wuerde. Das macht die
Zaehlung UNABHAENGIG vom Spezifikations-Orakel (das in derselben Lane, FUND 1-3 auf defda6a, nachweislich
zeitweise dieselben zwei Fehler wie die Implementierung trug).

**Ehrliche Grenzen.** Die Klasse ist bislang nur an dieser EINEN Note-Framing-Zusicherung behoben; ein
repo-weiter Sweep auf denselben Formulierungsfehler ("Zusicherung X erreicht durch Vorfilterung") wurde
NICHT gefahren — `tests/test_wire_bytes_strict.py`s verwandte, aber semantisch andere Aussage (ein
base64-FELD hat wirklich nur eine kanonische Kodierung, keine Mengengleichheit ueber Umformungen einer
ganzen Note) liegt ausserhalb des Auftrags dieser Lane und wurde nicht angefasst.

---

## KLASSE-D-2026-0906 — Eine strukturelle Sicherung, die in Wahrheit eine Textsuche ist

**Warum dieser Eintrag existiert.** Nicht wegen eines Defekts, sondern wegen einer BEHAUPTUNG.
Review Runde 3 wertet die Rust-Sicherung als „ERFUELLT fuer den heutigen Bestand, die neue Sicherung
selbst ist nur TEILWEISE strukturell" und Nachtrag 3 (Teil A1) verlangt, das hier festzuhalten. Der
Eintrag ist also die Grenze eines Riegels, nicht sein Fehlschlag — und genau diese Sorte Eintrag
fehlt in Ledgern am haeufigsten, weil ein funktionierender Riegel niemanden zwingt, ihn zu schreiben.

**Die Invariante, um die es geht.** `tests/test_tools_baum_kein_zweiter_note_parser.py` soll rot
werden, sobald im `tools`-Baum ein zweiter Note-Parser entsteht. Ein Parser ist aber eine
FAEHIGKEIT, und Faehigkeiten stehen nicht im Text — sie ergeben sich aus dem, was ein Programm mit
seiner Eingabe tut. Der Riegel misst statt dessen zwei Oberflaechen: ein Vokabular (Note-, Checkpoint-
und Signaturbegriffe) und eine Bauform (das Literal `\n\n` UND eine Em-Dash-Schreibweise im selben
File). Beides ist Text.

**Was er deshalb NICHT faengt, ausgeschrieben statt angedeutet.** Einen Parser, der seine beiden
Konstanten zur Laufzeit zusammensetzt (`"\n" + "\n"`, `char(0x2014)`); einen, der sie aus einer
Datendatei oder einem anderen Modul importiert; einen, der eine andere Kodierung waehlt; einen, der
das Notenformat ohne diese Merkmale implementiert. Eine echte strukturelle Antwort waere eine
Sprach- oder Datenflussanalyse ueber den Rust-Baum — die gibt es hier nicht, und sie zu behaupten
waere teurer als sie zu bauen: ein Riegel, dem man mehr zutraut als er kann, ersetzt eine offene
Frage durch eine falsche Sicherheit.

**Was er dafuer WIRKLICH leistet, ebenfalls gemessen.** Das reproduzierbare Inventar
(`33_RUST_INVENTAR_48159022.txt`) belegt den HEUTIGEN Bestand: vier Rust-Dateien, keine
Note-Flaeche. Die Bauform-Schicht kam hinzu, nachdem eine Review-Linse die reine Vokabelsuche mit
einem neutral benannten Parser widerlegt hatte — der steht seither als Fixture im Test. Und drei
Meta-Tests halten fest, dass jedes Merkmal FUER SICH nicht genuegt und die Bauform im echten Baum
null zusaetzliche Treffer erzeugt. Der Riegel ist also nicht wertlos; er ist ein Fruehwarner gegen
die naheliegende Wiederkehr, nicht ein Beweis der Abwesenheit.

**ODC.** defect_type = checking (Oberflaeche statt Eigenschaft) · trigger = coverage/variation ·
source_layer = test-oracle. **Zustand: OFFEN als Grenze**, nicht als Fund — sie wird geschlossen,
wenn ein Rust-Parser tatsaechlich entsteht und dann eine Analyse verlangt, die diesen Namen verdient.
