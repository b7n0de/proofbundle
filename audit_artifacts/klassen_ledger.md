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

## KLASSE-E-2026-0905 — Selbstbeglaubigung: derselbe Prozess baut UND signiert die Evidenz
<!-- KENNUNG GEAENDERT 2026-09-06, von C auf E. Der Probe-Merge der vier Lanes auf den Mergekopf
     kollidierte genau hier: die framing2-Lane hatte unabhaengig ebenfalls KLASSE-C-2026-0905
     vergeben ("Eine Zusicherung verkleinert ihre eigene Positivmenge"). Zwei verschiedene Klassen
     unter einer Kennung machen den Ledger mehrdeutig — und ein append-only Ledger, der zwei Dinge
     gleich nennt, verliert genau die Eigenschaft, wegen der er append-only ist. Dass zwei Lanes
     parallel dieselbe Kennung vergeben, ist kein Zufall, sondern die Folge davon, dass die Kennung
     aus Buchstabe plus Datum gebildet wird und keine Lane sieht, was die andere schon nahm. Der
     Probe-Merge hat es gefunden, bevor es jemand von Hand aufloesen musste. -->

**Verletzte Invariante.** Ein Skript, das im auslieferbaren Baum liegt (`MANIFEST.in: graft
scripts`), darf keinen Codepfad tragen, der einen privaten Signierschluessel liest UND im selben
Prozess den zu signierenden Rumpf baut. Eine Signatur beweist nur dann etwas, wenn Schluesselinhaber
und Erbauer des Inhalts verschiedene Parteien sind; sonst schuetzt sie nur die eigene Aussage vor
NACHTRAEGLICHER Aenderung, nicht vor Erfindung.

**ODC.** defect_type = missing function (fehlende Schluesseltrennung) · trigger = design/build
process · source_layer = release-tooling (auslieferbares Skript).

**Wie es auffiel.** Externer Review, Deep-Gate-Lauf 4, Runde 2 (2026-09-05), Auflage C9:
`scripts/sign_readiness_artifact.py` bot einen dritten, inline Modus (`--privkey-file`), der einen
ed25519-Privatschluessel las und den selbst gebauten Rumpf im selben Prozess signierte.

**Nachbarn im selben Durchgang gepruft, NICHT gefixt (dokumentiert, keine stille Luecke).**
`scripts/pre_tag_receipt.py` traegt DIESELBE Bauform (`--privkey-file`, "inline (default,
--privkey-file)"). Das ist ein AELTERES, eigenstaendig Owner-genehmigtes Mechanismus
("Option C, owner-GO", siehe `scripts/pre_tag_receipt_lib.py`), an das echte, bereits
ausgelieferte Receipts (v5.0.0, v5.1.0) gebunden sind — eine Aenderung dort haette diese Receipts
ungueltig gemacht und liegt ausserhalb des Auftrags dieser Lane (matrix2). Owner-Entscheidung
noch ausstehend, ob dieselbe Trennung dort nachgezogen wird.

**Wo die Klasse jetzt lebt.** `scripts/sign_readiness_artifact.py`: der Inline-Modus, `sign_body`
und `--privkey-file` sind ENTFERNT; es bleiben `--emit-payload` (schluessellos) und `--assemble`
(prueft eine extern erzeugte Signatur, verweigert bei Nichtpassen).

**Orakel.** `tests/test_c9_signierskript_ohne_privaten_schluessel.py` — AST-basiert, mit
Gate-Meta-Test (eine nachgebaute Fassung MIT dem alten Pfad muss durchfallen).

---

## KLASSE-D-2026-0905 — Baumkennung schliesst pauschal einen ganzen Ordner statt namentlicher Pfade aus

**Verletzte Invariante.** Eine Baumkennung, die einen Kandidaten bindet, darf nur genau die Pfade
ausschliessen, die aus einem benannten, dokumentierten Grund mutabel sein muessen (hier: die zwei
Evidenz-Artefakte, die ein Lauf selbst schreibt). Ein pauschaler Ordner-Ausschluss versteckt ALLES
darunter vor der Bindung — einschliesslich eines Vertrauensankers, der darunter liegt.

**ODC.** defect_type = checking (zu weite Ausschlussmenge) · trigger = trust-anchor placement ·
source_layer = release-gate (Baumdigest-Berechnung).

**Wie es auffiel.** Review Runde 2, Auflage C3 (Nachtrag 2): `audit_artifacts/` wurde als EIN
nicht-rekursiver `git ls-tree`-Eintrag komplett ausgeschlossen — das versteckte auch
`audit_artifacts/readiness_trusted_pubkeys.txt` (den Vertrauensanker aus KLASSE-A-2026-0905) vor der
Kandidatenbindung. Ein Schluessel, der im selben ungeschuetzten Commit wie der Kandidat eingefuehrt
wird, waere dadurch unsichtbar fuer die Bindung gewesen.

**Zwei Haelften, beide geschlossen.** (1) `git ls-tree -r HEAD` (rekursiv) statt `git ls-tree HEAD`,
mit einer NAMENTLICHEN Ausschlussliste (`MUTABLE_EVIDENCE_RELS`, zwei Pfade) statt eines
Ordner-Praefix-Ausschlusses. (2) Zusaetzlich, weil (1) allein nicht reicht, solange Anker und
Kandidat im SELBEN Commit landen koennten: der Anker darf nicht in genau dem Commit zuletzt
veraendert worden sein, den er autorisiert (`_anchor_last_touched_at_head`).

**Wo die Klasse jetzt lebt.** `scripts/sign_readiness_artifact.py::tree_digest` +
`MUTABLE_EVIDENCE_RELS` (Erzeuger); `scripts/audit_candidate_matrix.py::_live_tree_digest` (ruft den
Erzeuger auf, statt ein zweites Mal zu implementieren) + `_anchor_last_touched_at_head` +
`_artifact_signature_ok`.

**Orakel.** `tests/test_freigabe_evidenz_provenienz_l5_g7_02.py` —
`test_ein_anker_im_selben_commit_wie_der_kandidat_ist_selbstregistrierung` (muss FAIL),
`test_ein_anker_in_einem_frueheren_commit_bleibt_zulaessig` (Anti-Paritaet, muss PASS).

**Nachbarflaeche geprueft, NICHT gefixt.** `scripts/pre_tag_receipt_lib.py::subject_tree_digest`
traegt dieselbe pauschale Ordner-Ausschluss-Form ("Option C, owner-GO" — bereits einmal durch ein
Deep-Gate gegangen). Bindet echte, bereits ausgelieferte v5.0.0/v5.1.0-Receipts; eine Aenderung dort
wuerde deren Nachpruefbarkeit brechen und liegt ausserhalb dieses Auftrags.
