# Lane-Bericht matrix — Deep-Gate-Behebung 600, Bahn `fix/deepgate600/matrix`

**Modell, das wirklich gerechnet hat:** Claude Opus 5 (1M context), Modell-ID `claude-opus-5[1m]`,
durchgehend vom Beginn dieser Runde bis zu diesem Bericht. Kein Modellwechsel.

**Arbeitsbaum:** `/mnt/bigstore/claude_scratch/lane_matrix` · **Python:**
`/home/konrad/proofbundle/.venv/bin/python`, Tests mit `PYTHONPATH=src`. Kein anderer Baum wurde
angefasst — weder `pb_gate600`, noch `pb_freeze600_neu`, noch `~/2bedone`.

---

## 1. Gemessener Endstand des Zweigs

Alles unten ist ABGELESEN, nicht abgeleitet (`git rev-parse`, `git show --stat`, `git status`,
2026-09-05, 19:24Z).

```
Zweig            fix/deepgate600/matrix
Ausgangskopf     917edc695b280c6fa80e0ab2a76490ff0f30632e
Endkopf          bedb0a55d317ca79593e468660ae744f19790adb
Commits darauf   1   (bedb0a5, Sa 5. Sep 2026 21:24:19 +0200, kraxo <support@zudiroderzumir.de>)
Arbeitsbaum      sauber (git status --short: leer)
kein Push, kein Merge, kein Tag
```

Geänderte Dateien des Commits (`git show --stat bedb0a5`):

```
 audit_artifacts/klassen_ledger.md                  |  85 ++      (neu)
 audit_artifacts/readiness_trusted_pubkeys.txt      |  25 +       (neu)
 scripts/audit_candidate_matrix.py                  | 885 ++++--
 scripts/build_reproducible.py                      |  34 +-
 scripts/sign_readiness_artifact.py                 | 239 ++++    (neu)
 tests/test_audit_candidate_360.py                  |  38 +-
 tests/test_ausfuehrung_aus_quelltext_l5_g7_04.py   | 297 +++++   (neu)
 tests/test_freigabe_evidenz_provenienz_l5_g7_02.py | 640 +++++   (neu)
 8 files changed, 2162 insertions(+), 81 deletions(-)
```

Der Lane-Bericht selbst ist ABSICHTLICH nicht committet: er ist internes Bahn-Material und gehoert
nicht in das oeffentliche OSS-Repo.

---

## 2. Zwei Klassen, nicht eine (Auflage C3 des Gegenlesers)

Der urspruengliche Auftrag zog L5-G7-02 und L5-G7-04 zu EINER Klasse zusammen. Der Gegenleser hat
das als zu grob zurueckgewiesen, und die Messung gibt ihm recht: die beiden teilen die OBERFLAECHE
(dieselbe Datei), nicht die URSACHE. Ein Signaturanker haette den Kommentar-Fund nicht verhindert,
eine YAML-Analyse den unsignierten Soak nicht. Sie werden deshalb getrennt gefuehrt — getrennte
Eigenschaft, getrenntes Orakel, getrennter Ledger-Eintrag (`audit_artifacts/klassen_ledger.md`).

**KLASSE A — Provenienz und Kandidatenbindung freigabeentscheidender Evidenz** (L5-G7-02, P2).
ODC: defect_type = checking (missing validation) · trigger = data/artefact provenance ·
source_layer = release-gate.

**KLASSE B — eine AUSFUEHRUNG aus QUELLTEXT geschlossen** (L5-G7-04, P3).
ODC: defect_type = checking (wrong evidence kind) · trigger = source-text inference ·
source_layer = release-gate.

---

## 3. Reproducer vorher und nachher, woertlich

Der Reproducer des Gates
(`.../scratchpad/gate6_L5_assertion_by_absence.py`) wurde vollstaendig gelesen und mit EINER
Aenderung gefahren: `REPO` zeigt auf diese Bahn statt auf `pb_gate600` (Kopie unter
`.../scratchpad/lane_matrix/gate6_L5_lane.py`). Beide Baeume standen dabei auf demselben
Ausgangskopf 917edc69.

### VORHER (auf 917edc69, 19:03Z)

```
[FINDING] D1-C6.2-live: verdict='PASS' detail='recorded soak: 582120 iters, 0 crash, 0 false-accept' (source: audit_artifacts/360/fuzz_soak_latest.json, unsigned, version-unbound while VERSION_UNDER_TEST='6.0.0')
[FINDING] D2-C6.2-vacuous-artifact: a 2-key unsigned JSON ({'untriaged_crash_count':0,'false_accept_count':0}) yields verdict='PASS' detail='recorded soak: None iters, 0 crash, 0 false-accept' — 0 iterations, 0 parsers, no schema, no signature
[FINDING] D3-C8.2-vacuous-artifact: a 1-key unsigned JSON ({'all_agree':true}) yields verdict='PASS' detail='differential matrix: None vector(s), Python==Rust on all' — 0 differential vectors is a vacuous all()
[FINDING] D4-C6.2-contradicted-artifact: verdict='PASS' detail='recorded soak: 0 iters, 0 crash, 0 false-accept' while the SAME artefact carries ok=False and a non-empty untriaged_crashes list
[FINDING] D5-C1.1-published-leg-substring: verdict='PASS' for a published-artifact-gate.yml whose ONLY 'sdist' occurrence is in a comment saying the leg was removed: two named CI gates present: ci.yml (repository/test gate, name: CI + a real run: step executing the test suite) + publis

FINDINGS: ['D1-C6.2-live', 'D2-C6.2-vacuous-artifact', 'D3-C8.2-vacuous-artifact', 'D4-C6.2-contradicted-artifact', 'D5-C1.1-published-leg-substring']
```

### NACHHER (auf dem Endstand, 19:16Z)

```
[PASS   ] D1-C6.2-live: verdict='FAIL' detail="audit_artifacts/360/fuzz_soak_latest.json: carries no version field, so it cannot be shown to be about '6.0.0'. Re-run the measurement for this candidate and sign it with `scripts/sign_readiness_artifact.py`, then pin the signing key's public half in audit_artifacts/readiness_trusted_pubkeys.txt in an owner-approved commit" (source: audit_artifacts/360/fuzz_soak_latest.json, unsigned, version-unbound while VERSION_UNDER_TEST='6.0.0')
[PASS   ] D2-C6.2-vacuous-artifact: a 2-key unsigned JSON ({'untriaged_crash_count':0,'false_accept_count':0}) yields verdict='FAIL' detail="audit_artifacts/360/fuzz_soak_latest.json: declares schema None, expected 'proofbundle.fuzz_soak.v1'. …"
[PASS   ] D3-C8.2-vacuous-artifact: a 1-key unsigned JSON ({'all_agree':true}) yields verdict='FAIL' detail="audit_artifacts/360/rust_differential_matrix.json: declares schema None, expected 'proofbundle.rust_relation_differential_matrix.v1'. …"
[PASS   ] D4-C6.2-contradicted-artifact: verdict='FAIL' detail="audit_artifacts/360/fuzz_soak_latest.json: declares schema None, expected 'proofbundle.fuzz_soak.v1'. …" while the SAME artefact carries ok=False and a non-empty untriaged_crashes list
[PASS   ] D5-C1.1-published-leg-substring: verdict='FAIL' for a published-artifact-gate.yml whose ONLY 'sdist' occurrence is in a comment saying the leg was removed: published-artifact-gate.yml declares no enabled published-artifact leg (declares_build=False, declares_use_of_built_dist…

FINDINGS: []
```

Die Gruppen A, B, C und E des Reproducers (findings_register, pre_tag_audit_gate, RT-01..RT-04)
waren VORHER und NACHHER ohne Fund — sie gehoeren zu den bereits gelandeten Bahnen.

---

## 4. Die Matrix, mit Urteil je Zelle

Keine Punktfixture: 24 erfundene Evidenzen, jede eine eigene Verletzung, gegen JEDEN der drei
freigabeentscheidenden Evidenz-Leser. Dazu die Anti-Paritaets-Zeile. Gemessen am Endstand
(`.../scratchpad/lane_matrix/matrix_tabelle.py`, 19:16Z), in einem echten kleinen git-Baum mit
EINGECHECKTEM Vertrauensanker — sonst waere jede Zelle nur „Umgebung nicht messbar" und die Matrix
saehe gruen aus, ohne etwas ueber die Evidenz zu sagen.

| Zelle | C6.2 | C6.3 | C8.2 |
|---|---|---|---|
| fehlend | FAIL | DATA_BLOCKED | DATA_BLOCKED |
| null_byte | FAIL | FAIL | FAIL |
| leeres_objekt | FAIL | FAIL | FAIL |
| zwei_schluessel_ohne_substanz | FAIL | FAIL | FAIL |
| schema_falsch | FAIL | FAIL | FAIL |
| versionsabweichend | FAIL | FAIL | FAIL |
| version_fehlt | FAIL | FAIL | FAIL |
| kandidat_fehlt | FAIL | FAIL | FAIL |
| kandidat_fremder_baum | FAIL | FAIL | FAIL |
| kandidat_ohne_wheel | FAIL | FAIL | FAIL |
| kandidat_commit_unformig | FAIL | FAIL | FAIL |
| erzeuger_fehlt | FAIL | FAIL | FAIL |
| werkzeugversion_fehlt | FAIL | FAIL | FAIL |
| eingabe_digest_fehlt | FAIL | FAIL | FAIL |
| signiererrolle_fehlt | FAIL | FAIL | FAIL |
| zeit_fehlt | FAIL | FAIL | FAIL |
| zeit_aus_der_zukunft | FAIL | FAIL | FAIL |
| zeit_zu_alt | FAIL | FAIL | FAIL |
| nullzaehler | FAIL | FAIL | FAIL |
| selbst_widersprechend | FAIL | FAIL | FAIL |
| zaehler_gegen_liste | FAIL | FAIL | FAIL |
| unsigniert_sonst_makellos | FAIL | FAIL | FAIL |
| fremder_schluessel | FAIL | FAIL | FAIL |
| nach_dem_signieren_veraendert | FAIL | FAIL | FAIL |
| **ANTIPARITAET_echte_signierte_evidenz** | **PASS** | **PASS** | **PASS** |

**75 Urteile insgesamt. 72 Verletzungszellen: kein einziges Bestehen. 3 Anti-Paritaets-Zellen: alle
drei bestehen.** Ein Fix, der alles ablehnt, wuerde an der letzten Zeile scheitern.

Die zwei DATA_BLOCKED in der Zeile `fehlend` sind kein Durchrutscher, sondern die einzige Zelle,
deren richtige Antwort je Pflicht ANDERS lautet, und sie wird je Pflicht festgeschrieben: ein
kurzer Fuzz-Soak laeuft ueberall, seine Abwesenheit ist eine Aussage ueber die Arbeit (C6.2 = FAIL);
der 24-Stunden-Lauf braucht eine Soak-Box und die Rust-Matrix eine gebaute Rust-Binaerdatei — deren
Abwesenheit ist eine Aussage ueber die Umgebung (C6.3/C8.2 = DATA_BLOCKED). Bei C8.2 wird die
Verfuegbarkeit der Binaerdatei GEMESSEN (`rust_parity_gate.binary_available`) und nicht angenommen.

Die Klasse B hat ihre eigene Matrix (10 Attrappen, `tests/test_ausfuehrung_aus_quelltext_l5_g7_04.py`):
Kommentar-behauptet-die-Entfernung, nur-ein-Kommentar, Job-abgeschaltet, Schritt-abgeschaltet,
nur-ein-echo, Shell-Kommentar-im-run, baut-aber-benutzt-nie, benutzt-aber-baut-nie,
nur-ein-Name-der-das-Bein-behauptet, kein-YAML-Dokument. **Alle zehn FAIL**; die echte
Deklaration besteht (Anti-Paritaet); ohne PyYAML DATA_BLOCKED.

Beide Klassen tragen einen **Gate-Meta-Test**: die jeweils eingepflanzte ALTE Zeile muss auf
mindestens einer Zelle ein Bestehen erteilen, sonst misst die Matrix nichts.

---

## 5. Was mitgefegt wurde (Inventar, Auflage C2)

Freigabeentscheidend sind 26 der 33 Zeilen (7 sind `_INFORMATIVE_CHECKS`). Der Inventarschnitt
`grep -n '_json_artifact(\|_read(' scripts/audit_candidate_matrix.py`, geschnitten mit den
entscheidenden Zeilen, ergibt am Endstand:

| Zeile | vorher | jetzt |
|---|---|---|
| **C6.2** | zwei Zaehler, sonst nichts | ueber den Zulassungspfad, Schema + Kandidat + Provenienz + Frische + Zaehler + eigene Fehlerlisten |
| **C6.3** | `a.get("is_full_soak_24h")` — ein Bool in einer unsignierten Datei | derselbe Zulassungspfad; PASS nur bei attestiertem Lauf ≥ 86400 s |
| **C8.2** | `a.get("all_agree")` — ein Bool | derselbe Zulassungspfad; danach ZEILEN: rows nichtleer, `len(rows) == total_relation_vectors`, jede Zeile `agree_python_rust`, `all_agree` konsistent |
| **C8.3** | `bool(doc) or "rust" in json.dumps(slot).lower()` | Prosa-Datei bleibt Pflicht, entscheidend ist aber: JEDER der 57 PENDING-Eintraege der Registry nennt seinen EIGENEN Grund (kein leerer, keiner der nur die Kennung wiederholt) |
| **C9.1** | Teilzeichenketten `reproducible ok` / `byte-identical` / `not reproducible` der Standardausgabe | `build_reproducible.py --check --json` liefert ein strukturiertes Messergebnis; gelesen werden Schema, beide sha256 und `reproducible`. Messbarkeit via `importlib.util.find_spec("build")`, nicht aus einer Fehlermeldung |
| **C10.2** | das handgetippte Wort `filled` | Index digest-gebunden an `MANIFEST.sha256` PLUS Substanz: der Slot muss gelieferte Evidenz NENNEN |
| **C1.1** | `"sdist" in pub.lower() or "published" … or "cleanroom" …` ueber die ganze Datei | YAML-Parse, nicht abgeschalteter Job + Schritt, der einen Bau UND eine Benutzung der Distribution DEKLARIERT; ohne PyYAML DATA_BLOCKED |

Geprueft und unveraendert gelassen, weil Aussage und Pruefung schon zusammenpassen: C6.1 (sagt
„Harness vorhanden", prueft Vorhandensein), C10.1 (`readiness_pack_gate` prueft strukturell, dass
jede referenzierte Evidenz existiert), C11.2 (der Klassifizierer IST der Text), C2.x/C3.x/C4.x/C5.1/
C7.x/C8.1/C11.1 (Live-Messungen bzw. Exit-Codes, keine abgelegte Evidenz).

**Erklaerte Abweichung, offen benannt:** C10.2 geht NICHT ueber `_signed_versioned_artifact`.
`docs/readiness_pack/index.json` ist kein Messartefakt eines Laeufers, sondern eine handgepflegte
Reviewer-Tabelle ohne Kandidaten, ohne Erzeuger, ohne Eingabe-Digest; ihr das anzudichten waere eine
Behauptung, keine Bindung. Das Selbst-Receipt des Packs ist ausdruecklich BERATEND (ephemerer
Schluessel), also gibt es HEUTE keine zurechenbare Attestierung fuer diese Flaeche. Was dort steht,
ist bewusst weniger: Integritaet innerhalb des Packs plus Substanz des Slots — strikt mehr als das
Wort „filled", strikt weniger als eine Signatur. Steht so im Docstring und bleibt offen.

---

## 6. Die Auflagen des Gegenlesers, einzeln

**C1 — Bindung an den KANDIDATEN, nicht an die Zeichenkette.** Umgesetzt. Der Zulassungspfad
verlangt jetzt einen signierten `candidate`-Block mit **commit** (40 hex), **tree_digest** (64 hex),
**sdist_sha256** und **wheel_sha256**, dazu **schema**, **producer.tool** + **producer.tool_version**,
**input_digest**, **produced_at** und **signer_role**. Die Baumkennung wird gegen den LEBENDEN Baum
nachgerechnet (`git ls-tree HEAD` ohne `audit_artifacts/` — dieselbe Groesse, die ein Pre-Tag-Receipt
bindet). Frische: wohlgeformte RFC-3339-Z-Zeit, nicht in der Zukunft (5 min Versatz), nicht aelter
als das erklaerte Fenster von 180 Tagen. „Ein signiertes ok mit Nullzaehlern ist kein Beleg" ist als
eigener Zustand `vacuous` umgesetzt. Und die Aussage wird STRUKTURELL nur aus signierten Feldern
gebildet: bei Zulassung liefert der Helfer `signed_body` OHNE den Signatur-Umschlag, und der Umschlag
ist das einzige unsignierte Element — fuer ein nicht mitsigniertes Feld gibt es keinen Platz. Ein
eigener Test prueft die Byte-Gleichheit von zugelassenem und signiertem Rumpf.

**C2 — Inventar, alle ueber denselben Pfad, FAIL vs DATA_BLOCKED sauber.** Umgesetzt, siehe
Abschnitt 5. `_ART_DATA_BLOCKED_STATES` enthaelt genau EINEN Zustand (`unmeasurable_here`); alles,
was an der Evidenz liegt — fehlend, kaputt, unsigniert, fremd signiert, ungebunden, leer, sich selbst
widersprechend — und auch ein Repo, das gar keinen Anker eincheckt, ist FAIL. Dafuer unterscheidet
`_trust_anchor` drei Zustaende (`ok` / `empty` / `unmeasurable`) statt zweimal dieselbe leere Liste;
die git-Wortlaute dahinter wurden GEMESSEN, nicht geraten, und stehen als Kommentar im Code.
Ein eigener Test erzeugt alle drei Zustaende. Die eine Abweichung (C10.2) ist oben benannt.

**C3 — getrennte Klassen, Eigenschaften, Orakel, Ledger.** Umgesetzt: zwei Testdateien mit je eigener
Eigenschaftsformulierung (P-A1..P-A7 und P-B1..P-B4), je eigenem Orakel und je eigenem Gate-Meta-Test;
zwei Eintraege in `audit_artifacts/klassen_ledger.md`.

**C4 — bei C1.1 zuerst die AUSSAGE.** Gewaehlt wurde ausdruecklich Variante 1 (nur
Konfigurations-Anwesenheit). Die Zeile heisst jetzt „two CI gate configurations declared + enabled",
ihr Text nennt die beiden Workflow-Digests und sagt woertlich „This is configuration presence, NOT
evidence that either workflow ran for this candidate". Die staerkere Aussage („der Lauf hat
stattgefunden") ist aus der entscheidenden Matrix HERAUSGENOMMEN, weil dieses Repo fuer 6.0.0 keinen
kandidatsgebundenen Laufbeleg baut; ein Test prueft, dass KEINE freigabeentscheidende Zeile eine
Ausfuehrung behauptet. Kaeme der Laufbeleg, waere sein Fehlen DATA_BLOCKED und sein Widerspruch FAIL.

**C5 — Nachbarflaeche `pre_tag_audit_gate._positive_audit_marker`.** Geprueft, Datei vollstaendig
gelesen. Ergebnis, mit zwei Tests festgehalten: die Funktion ist dieselbe Bauform wie Klasse B
(Schluss von Prosa auf ein Ereignis) und traegt **kein freigabeentscheidendes Verdikt**.
`evaluate()["ok"]` entsteht ausschliesslich aus verifizierten Receipts (`ok = bool(verified)`), die
CHANGELOG-Zeile ist als `changelog_is_presentational: True` ausgewiesen, und der zweite Aufrufer
`audit_records_for` ist ein Fund-LOKALISIERER, dessen einzige Konsumenten Tests sind. Gemessen wurde
das an einem Baum mit und ohne maximal attestierende CHANGELOG-Prosa: `ok` und `state` blieben
identisch. **Nebenbefund, NICHT behoben:** `attesting_records_for` / `attests_version` — die
gehaertete Allowlist-Form aus L5-02 — haben ueberhaupt keinen Produktionsaufrufer; die strengere
Form existiert, wird aber von niemandem benutzt. Das ist ein eigener Fund fuer eine andere Runde.

---

## 7. Vollsuite

```
PYTHONPATH=src /home/konrad/proofbundle/.venv/bin/python -m pytest tests/ -q -p no:cacheprovider
3391 passed, 21 skipped, 932 subtests passed in 1443.73s (0:24:03)
exit=0
```

Gefahren auf dem Stand, der committet wurde (Lauf 19:00Z–19:24Z). Zusaetzlich:

* `ruff check` auf allen sechs beruehrten Dateien: **All checks passed** (line-length 100).
* `scripts/gate_qualification_harness.py` (in CI BLOCKIEREND): **32/32 Klassen erkannt, 5/5
  Positivkontrollen gruen, exit 0**.
* Die beiden neuen Testdateien allein: **32 Tests, alle gruen**.

Die 21 Skips sind der bestehende Repo-Kontext-Mechanismus aus `tests/conftest.py`, keiner davon neu.

---

## 8. Lebende Matrix nach der Aenderung — ehrlich zum Preis

```
[audit-candidate-matrix] 33 checks · PASS 27 · PENDING 0 · DATA_BLOCKED 0 · EXTERNAL 1 · NICHT ANWENDBAR 0 · FAIL 5
  audit_candidate_ready=False fully_verified_here=False
```

Vorher: PASS 29 · DATA_BLOCKED 1 · FAIL 2. **C6.2, C6.3 und C8.2 sind jetzt ROT.** Das ist der
wahre Zustand, kein Werkzeugfehler: der Vertrauensanker ist leer (nur Kommentare), und die beiden
abgelegten Artefakte lauten auf gar keine Version. Sie waren vorher gruen, ohne dass irgendetwas
ueber 6.0.0 gemessen war. `audit_candidate_ready` war schon vorher `False` (C12.1, C12.2) — es
aendert sich also keine Freigabe, sondern nur, ob drei Zeilen weiter etwas behaupten, das sie nicht
wissen. Jede rote Zeile nennt den Weg heraus (Messung fuer diesen Kandidaten neu fahren, mit
`scripts/sign_readiness_artifact.py` signieren, den oeffentlichen Schluesselteil in einem
owner-freigegebenen Commit in `audit_artifacts/readiness_trusted_pubkeys.txt` pinnen).

Der Erzeuger ist kein Papier: er wird im Test als PROZESS gefahren, in allen drei Modi (inline,
schluessellos emit + assemble), und die zusammengesetzte Evidenz wird vom Tor zugelassen. Dieser
Erzeuger-gegen-Verbraucher-Test hat sofort einen echten Fehler im neuen Werkzeug gefunden (`--in`
hat die Ablage `quelle`, `_need` starb an einem `AttributeError` statt zu sagen was fehlt) — genau
die Sorte, die sonst erst bei der Freigabe auffaellt. Behoben und mit Begruendung im Code vermerkt.

---

## 9. Was NICHT gemessen wurde

* **`candidate.sdist_sha256` / `candidate.wheel_sha256` werden nicht nachgerechnet.** Sie werden
  als vorhanden, wohlgeformt und mitsigniert VERLANGT — ein Leser kann sie nachrechnen, ein
  Faelscher sie nicht unbemerkt aendern. Sie hier neu zu bauen hiesse zwei Distributionen pro
  Matrixlauf zu erzeugen.
* **Es gibt heute keine zulassbare Evidenz auf diesem Baum.** Die Anti-Paritaets-Haelfte wurde in
  einem synthetischen git-Baum mit eingechecktem Testschluessel gemessen, nicht auf dem echten. Das
  ist unvermeidbar, solange der Anker leer ist, und ausdruecklich so aufgeschrieben.
* **Das 180-Tage-Frischefenster ist eine Setzung**, kein gemessener Wert. Die eigentliche Frische
  ist die Kandidatenbindung; das Fenster ist ein grober Zusatzriegel fuer den Fall, dass die
  Toolchain um denselben Baum herum eine andere geworden ist.
* **`docs/readiness_pack/` wurde bewusst NICHT angefasst.** Eine Aenderung dort haette
  `MANIFEST.sha256` treiben lassen und damit ausgerechnet die neue C10.2-Bindung gebrochen. Der
  REPRODUCTION_RUNBOOK erwaehnt das Signieren deshalb noch nicht — offener Punkt fuer die Runde,
  die das Pack ohnehin neu erzeugt.
* **Kein Push, kein Merge, kein Tag**, und kein anderer Baum wurde beruehrt. Ob dieser Zweig zu den
  drei anderen Bahnen konfliktfrei merged, ist NICHT gemessen — das ist Sache der Kopf-Bahn.
* **Der Reproducer wurde mit einer Pfad-Aenderung gefahren** (`REPO` auf diese Bahn). Alles andere
  an ihm ist unveraendert; die Gruppen A/B/C/E messen weiterhin `pb_gate600`-fremde Module, die in
  dieser Bahn nicht angefasst wurden.
* **Ein Prozessfehler dieser Runde, offen benannt:** ich habe Warteschleifen als Dateipoller
  angelegt und nach jeder Statusabfrage eine NEUE gestartet, statt die alte zu beenden — 58 Stueck.
  Auf Owner-Anweisung alle beendet und durch genau EINEN prozessgebundenen Warter ersetzt
  (`while kill -0 <PID>`), der auch bei Absturz oder Kill endet. Die Suite selbst war davon nicht
  betroffen, die Maschinenlast schon.
