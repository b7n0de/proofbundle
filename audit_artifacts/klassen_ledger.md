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

## KLASSE-I-2026-0906 — Eine strukturelle Sicherung, die in Wahrheit eine Textsuche ist
<!-- KENNUNG GEAENDERT 2026-09-06, von D auf I. Beim Merge von matrix2 auf den Integrationskopf
     stand hier zum ZWEITEN Mal derselbe Fall wie bei C->E: die framing2-Lane hatte KLASSE-D-2026-0906
     vergeben, die matrix2-Lane unabhaengig KLASSE-D-2026-0905 fuer eine voellig andere Klasse
     ("Baumkennung schliesst pauschal einen ganzen Ordner aus"). Diesmal fiel es NICHT durch den
     Riegel auf: `tests/test_klassen_ledger_kennungen_eindeutig.py` verglich die VOLLE Kennung, und
     KLASSE-D-2026-0906 ist als Zeichenkette verschieden von KLASSE-D-2026-0905. Der ordnende
     Schluessel ist aber der BUCHSTABE — das beweist die Umbenennung C->E selbst: haette das Datum
     unterschieden, haette dort ein anderes Datum genuegt statt eines anderen Buchstabens.
     KLASSE-F beschreibt die Klasse richtig und hat sie halb geschlossen; ihre eigene "Ehrliche
     Grenze" nennt sogar die Handpruefung "framing2: A B C" — die war korrekt, als sie gemacht
     wurde, und war wenige Stunden spaeter falsch, weil framing2 mit `edd0f9f` sein D nachtrug.
     Der Riegel ist mit diesem Merge auf den Buchstaben umgestellt, siehe NACHTRAG zu KLASSE-F. -->

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

---

## NACHTRAG 2026-09-06 zu KLASSE-E-2026-0905 — die dort offene Owner-Frage ist beantwortet

Der Absatz „Nachbarn im selben Durchgang geprueft, NICHT gefixt" oben endet mit
„Owner-Entscheidung noch ausstehend, ob dieselbe Trennung dort nachgezogen wird". Sie steht seit
dem 06.09.2026 (Karte OA-8b1a31cc4f). Der Eintrag selbst bleibt unveraendert, weil dieser Ledger
append-only ist; was gilt, steht hier.

**Die Entscheidung.** Nur Packaging, mit zwei Auflagen. `scripts/pre_tag_receipt.py` BEHAELT den
Inline-Modus, weil er der Owner-Signierweg am Mac ist und die bereits ausgelieferten v5.0.0- und
v5.1.0-Receipts an ihm haengen. Dafuer (1) faellt das Skript aus dem sdist — `MANIFEST.in` fuehrt
seit dem 06.09. eine namentliche Liste statt `graft scripts` und laesst es weg — und (2) traegt es
eine Sperre gegen Ausfuehrung auf dem Bau-Konto (`_inline_erlaubt_oder_stop`, vor der
Schluesselabfrage, Freigabe nur ueber `PB_INLINE_SIGNING=1`).

**Was das an der Klasse aendert und was nicht.** Die Instanz ist entschaerft: kein ausgeliefertes
Skript liest mehr einen privaten Schluessel, und auf dem messenden Konto laeuft der Weg nicht mehr.
Die KLASSE bleibt OFFEN — die Selbstbeglaubigungs-Bauform existiert im Repo weiter, sie ist nur
nicht mehr ausgeliefert und nicht mehr unbeaufsichtigt ausfuehrbar. Sie ist als `N14` in
`RESTRISIKO_600.md` gefuehrt und wird mit 6.1 neben `b7sign` auf dieselbe emit/assemble-Trennung
umgebaut. Ein Eintrag hier waere sonst zu frueh geschlossen worden, und ein zu frueh geschlossener
Klasseneintrag ist schlimmer als keiner.

**Auch veraltet im Eintrag oben, damit es niemand als heutigen Zustand liest:** die „Verletzte
Invariante" beschreibt den Auslieferungsweg mit `MANIFEST.in: graft scripts`. Diese Zeile gibt es
seit dem 06.09. nicht mehr.

---

## KLASSE-F-2026-0906 — Zwei Lanes vergeben unabhaengig dieselbe Ledger-Kennung

**Verletzte Invariante.** In einem append-only Ledger bezeichnet eine Kennung FUER IMMER genau eine
Sache. Belege, Commits, Berichte und spaetere Eintraege verweisen auf sie; zwei Klassen unter einem
Namen machen jeden dieser Verweise rueckwirkend zweideutig — und zwar still, ohne dass irgendwo
etwas rot wird. Das ist keine Unordnung, sondern der Verlust genau der Eigenschaft, wegen der ein
Ledger append-only gefuehrt wird.

**ODC.** defect_type = assignment (Kennungsvergabe ohne globale Sicht) · trigger = concurrent
branches / parallel lanes · source_layer = evidence-ledger.

**Wie es auffiel.** Probe-Merge der vier Lanes auf den Mergekopf `48159022`, 06.09.2026. Zwei der
drei Konflikte waren reine Anhaengekonflikte, der dritte war es NICHT: `framing2` hatte
`KLASSE-C-2026-0905` fuer „Eine Zusicherung verkleinert ihre eigene Positivmenge" vergeben,
`matrix2` unabhaengig dieselbe Kennung fuer „Selbstbeglaubigung". Wer den Konflikt stumpf aufloest
und beide Bloecke behaelt — die naheliegendste Handlung — haette den Doppelnamen dauerhaft in den
Ledger geschrieben.

**Warum es kein Zufall war.** Die Kennung wird aus einem Buchstaben und dem Datum gebildet. Keine
Lane sieht, welchen Buchstaben eine andere am selben Tag schon nahm. Parallele Lanes MUESSEN also
kollidieren, sobald zwei am selben Tag eine Klasse schliessen; die Frage war nie ob, nur wann.

**Wo die Klasse jetzt lebt.** `tests/test_klassen_ledger_kennungen_eindeutig.py`. Der Riegel liegt
bewusst im Testbaum jeder Lane und nicht in einem Merge-Werkzeug: so faellt die Kollision in dem
Augenblick auf, in dem sie real wird — beim ersten Suitenlauf auf dem zusammengefuehrten Baum —
statt erst dann, wenn ein Mensch den Ledger liest.

**Orakel.** Sechs Pruefungen: Eindeutigkeit; jede Kennung traegt einen tragfaehigen Titel (ein
Platzhalter ist die Stelle, an der zwei Lanes wieder kollidieren); ein Gate-Meta-Test mit einer in
eine KOPIE des echten Textes gepflanzten Dublette; Gedanken- und Bindestrich; und zwei Tests gegen
den TATSAECHLICHEN Vorfall — `TestGegenDenEchtenVorfall` baut aus den echten Commits die stumpfe
Merge-Aufloesung nach und verlangt, dass sie `KLASSE-C` zweimal zaehlt, waehrend die Gegenrichtung
verlangt, dass derselbe Riegel nach der Umbenennung still bleibt. Ein Riegel, der auch den
reparierten Zustand rot faerbt, haette nichts gemessen, sondern nur zugemacht.

**Ehrliche Grenze — die Klasse ist halb geschlossen.** Geschlossen ist die ERKENNUNG. Die VERGABE
ist unveraendert: es gibt kein Werkzeug, das die naechste freie Kennung aus dem Ledger-Stand
ableitet, der Ledger wird von Hand geschrieben. Der Buchstabe `F` dieses Eintrags wurde deshalb
von Hand gegen alle vier Lanes geprueft (framing2: A B C · renewal2: A B · matrix2: A B D E ·
nachlauf: kein Ledger) — also genau die Handarbeit, die die Klasse eigentlich abschaffen soll. Ein
Vergabe-Werkzeug in einer release-nahen Lane einzufuehren waere mehr Risiko als Nutzen; es gehoert
nach 6.0.0. Bis dahin faengt der Riegel das Ergebnis, und diese Zeile haelt fest, dass die Ursache
noch steht.

---

## KLASSE-G-2026-0906 — Eine Liste, die ein Verzeichnis-`graft` ersetzt, entscheidet unvollstaendig

**Verletzte Invariante.** Wer eine pauschale Auslieferungs-Vollmacht (`graft <ordner>`) durch eine
ausdrueckliche Liste ersetzt, uebernimmt damit die Entscheidung fuer JEDE Datei, die die Vollmacht
getragen hat — jede Sprache, jede Tiefe, jede Konsumentenbeziehung. Eine Teilmenge zu entscheiden
und den Rest unerwaehnt zu lassen ist nicht "strenger als vorher", sondern eine stille Aenderung
des Lieferumfangs: der Ordner ist ja noch da, die Skripte sind da, und die Abwesenheit faellt erst
beim Anwender zur Laufzeit auf.

**ODC.** defect_type = assignment (unvollstaendige Ersetzungsmenge) · trigger = coverage/variation
(Sprache, Verzeichnistiefe, Namensform) · source_layer = packaging.

**Wie es auffiel — und WIE OFT, denn das ist der Kern.** Die Owner-Auflage OA-8b1a31cc4f ersetzte
`graft scripts` durch eine Liste. Dieselbe Klasse schlug danach VIERMAL zu, jedes Mal an einer
anderen Dimension, und jedes Mal fand sie ein anderes Werkzeug:

| # | Dimension | gefunden von | Wirkung |
|---|---|---|---|
| 1 | Sprache: der Riegel entschied nur ueber `*.py` | Probe-Merge, Vollsuite rot | vier Dateien aus dem sdist, zwei davon von ausgelieferten Skripten gelesen |
| 2 | Tiefe: `iterdir()` statt rekursiv | Review-Linse 1 | `scripts/git-hooks/pre-commit` von KEINER Fassung entschieden |
| 3 | Namensform: Pfadvergleich statt Basisname | Review-Linse 2 | ein `include scripts/nested/pre_tag_receipt.py` haette das schluessel-lesende Skript ausgeliefert |
| 4 | Sprache, zweite Runde: der Schluessel-Detektor las nur `.py` | Review-Linse 3 | ein Shell-Skript mit `python3 -c "...from_private_bytes..."` waere unsichtbar |

Der erste Fix schloss die Klasse an der Stelle, an der sie gesehen wurde, und nannte sich schon
"die Klasse". Er war es nicht. Genau dafuer ist die Gegenlesung da.

**Wo die Klasse jetzt lebt.** `tests/test_sdist_ohne_signierwerkzeug.py`:
`test_jede_datei_unter_scripts_ist_in_manifest_entschieden` (rekursiv, alle Sprachen, begruendete
Ausschlussmenge), `_fehlende_datendateien` + `test_ein_ausgeliefertes_skript_bekommt_seine_
datendateien_mit` (Geschwisterdateien am Syntaxbaum), `test_kein_ausgeliefertes_nicht_python_skript_
liest_einen_privaten_schluessel` (zweiter Korb der Fixture). Dazu
`tests/test_sdist_packaging_361.py::test_scripts_ship_by_an_explicit_list_not_by_a_graft`
(Basisnamen-Vergleich, `graft scripts` darf nicht zurueckkehren).

**Orakel.** Vier Meta-Tests, alle mit Pflanzung und Gegenrichtung. Der wichtigste ist
`test_meta_eine_entfernte_datendatei_wird_wirklich_gefunden`: seine erste Fassung war selbst eine
Tautologie (`name in gebraucht - ohne` ist algebraisch `name in gebraucht`, weil `ohne` den Namen
per Konstruktion nie enthaelt) und wurde von Linse 2 durch Streichen des Terms widerlegt — der Test
blieb gruen. Deshalb ruft der Meta-Test jetzt die PRIMAERLOGIK mit manipulierter Eingabe, statt
danebenzurechnen.

**Ehrliche Grenzen, beide angenommen und nicht abgestellt.** (1) Der Geschwister-Detektor sieht nur
die `/`-Idiom-Form; `os.path.join` oder ein reiner String-Zugriff entgehen ihm. Jede Erweiterung
darauf zaehlt die blosse ERWAEHNUNG wieder mit — `audit_candidate_matrix.py:1570` nennt die
Registry in einem Meldungstext, ohne sie zu lesen —, und genau davor schuetzt die AST-Form.
(2) Dieselbe Konstruktion steht im selben MANIFEST.in fuer `docs/` (Einzelpfad-`include` statt
`graft docs`) ohne symmetrischen Riegel. Eigene Flaeche, release-nah nicht nebenbei; hier notiert,
damit sie nicht verloren geht.

---

## KLASSE-H-2026-0906 — Gleichzeitigkeit im selben Job als Datenflussrelation gelesen

**Warum dieser Eintrag existiert.** Nachtrag 3, Teil A6, verlangt ausdruecklich: „Entweder echten
Artefaktfluss binden … oder den PASS-Wortlaut auf die geprueste syntaktische Koexistenz verengen.
**Die Wahl im Ledger begruenden.**" Hier steht die Wahl und ihr Grund.

**Die verletzte Invariante.** Eine Aussage der Form „dieser Job baut die Distribution UND benutzt
sie" behauptet eine RELATION zwischen zwei Ereignissen — das eine erzeugt, was das andere
verbraucht. Eine Menge kennt aber kein Vorher und kein Nachher, und ein Ordnername ist kein Pfad.
Wer beide Haelften nur ZUSAMMEN im selben Job verlangt, hat die Relation durch ihre schwaechste
notwendige Bedingung ersetzt.

**ODC.** defect_type = checking (Relation durch Koexistenz ersetzt) · trigger = sequencing ·
source_layer = release-gate (CI-Deklarationsanalyse).

**Wie es auffiel.** Review Runde 3, Abschnitt 2, „Die C1-Relation": „Im selben Job genuegt aber
weiterhin irgendein Buildbefehl neben irgendeinem Zugriff auf `dist/…`; Reihenfolge, Pfadgleichheit
und Uebergabe des gerade gebauten Artefakts werden nicht nachgewiesen. Ein Job kann zuerst ein altes
Wheel installieren und spaeter in einen anderen Ordner bauen und trotzdem bestehen." Beide Faelle
sind nachgebaut und bestanden die Fassung aus Runde 2.

**DIE WAHL, und warum sie so ausfiel.** Genommen wurde der ERSTE Weg — echten Artefaktfluss binden —
und nicht die Verengung des Wortlauts. Drei Gruende, in dieser Reihenfolge:

1. Die schwaechere Aussage waere fuer C1.1 fast wertlos gewesen. „In einer Workflow-Datei stehen
   irgendwo ein Buildbefehl und irgendwo ein Zugriff auf dist/" ist kaum mehr als „die Datei ist
   nicht leer" — eine Zeile, die praktisch nie rot wird, misst nichts.
2. Die Information war bereits DA. `_run_touches_distribution` zerlegte den `run:`-Text ohnehin
   kommandoweise; sie warf Reihenfolge und Ordner nur weg. Die Haertung nimmt nichts Neues auf, sie
   hoert auf wegzuwerfen — das ist billiger und weniger fehleranfaellig als eine neue Analyse.
3. Der echte Workflow erfuellt die staerkere Aussage. Das `hermetic-cleanroom`-Bein baut und
   installiert im selben Job in derselben Reihenfolge. Eine Verengung des Wortlauts haette also die
   Aussage geschwaecht, ohne dass der Baum sie gebraucht haette.

**Wo die Klasse jetzt lebt.** `scripts/audit_candidate_matrix.py`: `_run_touches_distribution`
liefert eine GEORDNETE Liste `(art, ordner)` statt zweier Wahrheitswerte; `_ausgabeordner` liest das
Ziel aus `--outdir`/`-o` (sonst die dokumentierte Voreinstellung `dist`), `_artefakt_ordner` den
Ordnerteil des konsumierten Archivs; `_published_artifact_leg_facts` verlangt einen Bau nach `P` und
DANACH eine Benutzung aus `P` im selben nicht fehlertoleranten Job. Der PASS-Wortlaut von C1.1 sagt
das jetzt auch.

**Orakel.** `tests/test_ausfuehrung_aus_quelltext_l5_g7_04.py`:
`test_gate_meta_koexistenz_im_selben_job_reicht_nicht_mehr` haelt die zwei Attrappen des Reviewers
fest UND die Gegenrichtung (ein echter Fluss in einen anderen Ordner muss weiter bestehen, sonst
waere die Haertung nur eine Verweigerung). Der aeltere Gate-Meta-Test baut die Vorfassung aus der
neuen Zerlegung nach und bleibt damit das, was er sein soll: die ALTE Regel in den heutigen
Bausteinen.

**Ehrliche Grenze.** Die Erkennung bleibt eine Positivliste von Kommandokoepfen (`python -m build`,
`pyproject-build`, `build_reproducible.py`, `pip`/`tar`/`unzip`/`twine`). `make sdist` oder
`tox -e build` werden weiterhin NICHT erkannt — sie zu erkennen hiesse Makefile- und tox-Konfiguration
zu parsen. Das ist dieselbe dokumentierte Grenze, die der Nachbar `_is_real_test_invocation` schon
traegt, und sie ist hier nicht groesser geworden: was vorher nicht als Bau galt, gilt auch jetzt
nicht als Bau.

---

## NACHTRAG 2026-09-06 zu KLASSE-F-2026-0906 — der Riegel mass die Kennung, nicht den Buchstaben

KLASSE-F beschreibt die Klasse richtig: parallele Lanes vergeben unabhaengig dieselbe
Ledger-Kennung, und der Riegel `tests/test_klassen_ledger_kennungen_eindeutig.py` soll das fangen.
Der Riegel fing die INSTANZ (`KLASSE-C-2026-0905` zweimal) und liess die naechste durch.

**Was schiefging.** Er zaehlte die VOLLE Kennung, also Buchstabe UND Datum. Beim Merge von matrix2
auf den Integrationskopf am 06.09.2026 trafen `KLASSE-D-2026-0906` (framing2, Rust-Sicherung als
Textsuche) und `KLASSE-D-2026-0905` (matrix2, pauschaler Ordner-Ausschluss) aufeinander — zwei
verschiedene Klassen, beide `D`, als Zeichenketten verschieden. Der Riegel war still. Schlimmer:
`test_und_nach_der_umbenennung_ist_er_still` bescheinigte diesem Zustand ausdruecklich, sauber zu
sein. Ein gruener Test, der den Defekt zertifiziert.

**Warum der Buchstabe der Schluessel ist, und nicht das Datum.** Der Beweis steht in der Historie:
als `C` kollidierte, wurde matrix2 zu `E` umbenannt — nicht zu `C` mit anderem Datum. Haette das
Datum unterschieden, waere die Umbenennung unnoetig gewesen. Das Datum ist Beiwerk; der Buchstabe
traegt die Identitaet, weil Berichte, Commits und Belege mit „Klasse D" verweisen.

**Was geaendert wurde.** Die Eindeutigkeit wird auf dem BUCHSTABEN geprueft, nicht auf der vollen
Kennung, und der Gate-Meta-Test pflanzt eine Dublette mit ABWEICHENDEM Datum — genau der Fall, den
die alte Fassung nicht sah. Die Umbenennung dieser Runde: framing2s `D-2026-0906` heisst jetzt
`I-2026-0906` (naechster freier Buchstabe: A B gemeinsam, C framing2, D E matrix2, F G H matrix2).

**Ehrliche Grenze, unveraendert.** Geschlossen ist weiterhin nur die ERKENNUNG, jetzt auf der
richtigen Groesse. Die VERGABE bleibt Handarbeit ohne Werkzeug — und dieser Nachtrag ist der Beleg,
dass Handarbeit hier ein zweites Mal versagt hat, nicht ein erstes.
