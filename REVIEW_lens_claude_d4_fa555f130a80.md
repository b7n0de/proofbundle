# Linsenlauf Claude-Familie, D4 Runde 10, Kopf fa555f13

Geprueft wurde `fix/the-commit-pattern-holds-at-the-verify-boundary` am Kopf
`fa555f130a80cdfedd5965715bc7f8451c974bbe`, Diff gegen main `31816e08afeababcf024969fd7bbb5c4d1647b28`
(Merge-Basis `126ed1dc`, 14 Commits, 30 Dateien, +6423/-324).
Die Aussagen von Runde 10 halten auf ihren eigenen Flaechen, aber auf den Verify-Flaechen, die der Branch
beruehrt, liefern vier oeffentliche Funktionen Inhalte als verifiziert, die die Signatur nicht deckt; das
Verdikt ist deshalb FIX_FIRST.

Modell laut Harness: `session_context.model` claude-opus-5-5, `external_metadata.last_served_model`
claude-opus-5-5.
Umgebung: Python 3.11.15, ruff 0.16.9, mypy 2.3.1, pytest mit pytest-subtests, node v22.22.2 (nur als
Orakel fuer ECMA-262), pb_verify_rs aus `tools/pb_verify_rs` am Kopf (Baum gleich main).
Rote Tests: `tests/test_lens_claude_d4_fa555f130a80.py`, zwoelf Faelle L1 bis L12.

## Behauptete Eigenschaft in einem Satz

Ein Hash oder eine Zusage im Beweisstueck wird an der Verify-Grenze neu berechnet oder in der Form
geprueft, die `salted_commit` erzeugt, und jede Grenze liest den Wert des Aufrufers als das, was er
speichert (exakte `str`-Schluessel im OrderedDict, bool-Schluesselwoerter exakt, `expected_context` nach
Zeichen, `svr_properties` zaehlt nur `ok is True`, `verify_commitment` antwortet False statt zu werfen).

## 1. Verdikt

FIX_FIRST, hoechste Schwere P0 (Fund L1 bis L6).

## 2. Funde

Aufruf fuer jede Zeile: `PYTHONPATH=src python -m pytest tests/test_lens_claude_d4_fa555f130a80.py -k <fall>`.
Ergebnis: rot am Kopf fa555f13 und rot an main 31816e08 (dieselben 23 fehlschlagenden Faelle an beiden),
also vorbestehend und vom Branch nicht geschlossen. Gruen ist keiner.

| Nr | Richtung | Flaeche | Eigenschaft | Schwere | Aufruf (`-k`) | Ergebnis |
|---|---|---|---|---|---|---|
| L1 | Umgehung (anderer Traeger) | `evalclaim.decode_eval_claim` | Nur was die Signatur deckt, wird als verifiziert geliefert. `payload_b64` wird fuer `verify_bundle` und danach zum Parsen gelesen, beide Male ueber `__getitem__` des Aufrufer-Objekts. | P0 | `test_l1` | rot |
| L2 | Umgehung (anderer Traeger) | `evalclaim.decode_eval_claim` | Wie L1, gewoehnliches dict, `payload_b64` ist eine `str`-Unterklasse; `_wire_b64._as_bytes` ruft deren eigenes `encode` zweimal. | P0 | `test_l2` | rot |
| L3 | Geschwister | `evalclaim.classify_eval_claim` | `CLAIM_VALID` nur fuer den signierten Claim. Dreifaches Lesen (verify, parse, decode). | P0 | `test_l3` | rot |
| L4 | Geschwister | `intoto.verify_intoto_dsse` | `ok` True nur ueber das signierte Statement. `dsse.verify_envelope` und `dsse.load_payload` lesen `payload` getrennt. | P0 | `test_l4` | rot |
| L5 | Geschwister | `intoto.verify_eval_result_dsse` | wie L4 | P0 | `test_l5` | rot |
| L6 | Geschwister | `intoto.verify_svr_dsse` | wie L4; geliefert wurden `PROOFBUNDLE_ANCHOR_VALID` und `PROOFBUNDLE_PREREG_BOUND`, die nicht signiert sind | P0 | `test_l6` | rot |
| L7 | Geschwister | `hashalg.compute_digest`, `hashalg.resolve_hash_alg` | Ein bool-Schluesselwort ist True oder False (Runde 10, `_flagge`, R-B4). `allow_deprecated="false"`, `"no"`, `1`, `[0]` oeffnen das Tor fuer sha1 und md5. | P1 | `test_l7` | rot |
| L8 | Geschwister (Musterklasse) | `trust_pack.validate_trust_pack_predicate` | Der Validator nimmt nichts an, was `schemas/trust-pack-v0.1.schema.json` ablehnt. `^...$` und `\d` unter Python `re`: Hex mit Zeilenende, `expires` mit Zeilenende oder arabisch-indischen Ziffern, `schemaVersion` mit Zeilenende oder `0.1.٣` ergeben `[]`. | P1 | `test_l8` | rot |
| L9 | Umgehung (andere Form) | `evalclaim.emit_eval_receipt`, Paarform | Zwei Schluessel mit gleichen Zeichen werden abgelehnt (`_plain_for_jcs`). In der Paarform gewinnt der letzte: `passed` False dann True wird als True signiert. | P1 | `test_l9` | rot |
| L10 | Umgehung (Duplikat) | `intoto.svr_properties` | Eine Eigenschaft nur ueber einen Check mit `ok is True`. Zwei Checks `ed25519-signature`, False dann True, ergeben `PROOFBUNDLE_SIGNATURE_VALID`; True dann False nicht. Reihenfolge entscheidet. | P1 | `test_l10` | rot |
| L11 | Geschwister (Klasse von 234) | `evalclaim.classify_eval_claim`, Payload-`schema` | Eine Ablehnung braucht eine Deklaration (Regel der Funktion fuer den Umschlag). Fehlend, null, leer, Zahl, Liste ergeben `refused_unknown_schema` statt `invalid`. | P1 | `test_l11` | rot |
| L12 | Regression nein, bekannt offen | `evalclaim.build_eval_claim`, `salted_commit` | Der Emitter lehnt mit `EvalClaimError` ab. Ein einzelnes Surrogat im Identifikator wirft rohes `UnicodeEncodeError`. Im Commit fa555f13 als nicht geaendert benannt. | P2 | `test_l12` | rot |

Messung zu L1 bis L6 (Sonde, nicht Test): Rueckgabe `passed True, suite forged-suite` bzw. `ok True`
mit `result PASSED` gegenueber signiertem `FAILED`, gemessen an fa555f13 und an 31816e08, jeweils beim
ersten Lesen die signierte Nutzlast, ab dem zweiten die gefaelschte. Die gefaelschte Nutzlast allein
verifiziert nicht (`ok False`, Kontrolle im Test).

Bewertung (getrennt von der Messung):
- L1 bis L6: Die Vorbedingung ist ein vom Aufrufer gebautes Objekt (dict-Unterklasse, oder
  `str`-Unterklasse im Feld). Aus Bytes, ueber die CLI (liest Dateien in gewoehnliche dicts) und im
  Rust-Verifier ist das nicht erreichbar. Nach der Hausregel dieses Branches (Runde 10 schliesst
  `expected_context` wegen eines `__ne__` des Aufrufers) ist es dieselbe Klasse an derselben Funktion,
  mit schwererer Wirkung: nicht ein falscher Kontext, sondern eine nicht signierte Nutzlast. Die
  Docstring-Aussage von `decode_eval_claim` "the same object is both verified and parsed" haelt fuer den
  Pfad-Fall, nicht fuer den Objekt-Fall (CWE-367 im Objekt statt in der Datei).
- L7: Schwere P1, weil kein fremdes Beweisstueck allein das Tor oeffnet; mit True, False und dem Standard
  korrekt.
- L8: Orakel ist ECMA-262 (JSON Schema 2020-12 verweist fuer `pattern` darauf), gemessen mit node v22.22.2:
  alle fuenf Werte `false`. `python-jsonschema` waere kein Orakel dafuer, es prueft `pattern` mit Python
  `re` und hat denselben Defekt. Die Geschwister-Module tragen den `\A..\Z`-Fix mit Kommentar, trust_pack.py
  nicht. Eine Wirkung auf `verify_trust_pack` ueber den Validator hinaus ist NICHT GEMESSEN.
- L9: Kein fremder Beteiligter kann es ausloesen; die Eingabe des Aufrufers widerspricht sich selbst, und
  der Emitter loest den Widerspruch still auf, wo die Kopie fuer Objekte ablehnt.
- L10: `verify_bundle` benennt jeden Check einmal (gelesen in `bundle.py`, `result.add`), daher nur ueber
  ein vom Aufrufer gebautes Ergebnis erreichbar; `export_svr_dsse` baut sein eigenes und ist nicht
  betroffen.
- L11: Kein Verbraucher in `src/` und kein Exit-Code; nur die oeffentliche API. Die Klasse gehoert zu
  Branch 234 und wird dort erneut gemessen.
- L12: fail-closed, falscher Fehlertyp; bekannt, im Commit benannt, hier nur mit einem Aufruf belegt.

## 3. Klassen und Geschwister

- Klasse A, "verifizierte Bytes und geparste Bytes sind zwei Lesungen des Aufrufer-Objekts": gemessen an
  fuenf Funktionen (L1 bis L6). Gleiches Muster `dsse.verify_envelope` gefolgt von `dsse.load_payload(envelope)`
  steht ausserdem in `decision.py:567`, `verification_summary.py:223`, `trust_pack.py:463`,
  `run_ledger.py:275`, `outcome.py:599`, `relation_statement.py:215`, `agent_review.py:2300`, `:2626`,
  `:3044` (geschaetzt per grep, NICHT GEMESSEN). `cli.py:1842` liest Dateien und ist nicht betroffen
  (gelesen, nicht ausgefuehrt).
- Klasse B, "ein bool-Schluesselwort wird nach Wahrheit gelesen": gemessen an `allow_deprecated` (L7).
  Weitere Schluesselwoerter `strict`, `require_derived_subject`, `require_canonical`, `applicable`,
  `leaf_witnessed`, `include_token`, `require_signature_line` (grep, NICHT GEMESSEN); bei `strict` und
  `require_*` wirkt "false" in die strengere Richtung.
- Klasse C, "ein Muster, das seine Form knapp verfehlt" (`$` vor Zeilenende, `\d` ueber Unicode): in
  `src/` gefunden nur in `trust_pack.py:41-43` und `:98` (grep nach einzeiligem `re.compile`, `re.match`,
  `re.search`, `re.fullmatch` mit `$`-Ende und nach `\d` ueber `src/proofbundle`; mehrzeilige Muster und
  Muster aus Variablen sind so nicht erfasst). `evalclaim._COMMIT_RE` und `_DECIMAL_RE` sind `\A..\Z`
  mit `[0-9]`.
- Klasse D, "Duplikat wird still aufgeloest": L9 (Paarform), L10 (Check-Namen).
- Klasse E, "Nachschlagen mit einem fremden Schluessel ohne Klassifikation": L11.

## 4. Gepruefte Flaechen ohne Fund

- `verify_commitment`, 13 Faelle (exakt, bytearray, memoryview, Grossbuchstaben-Hex, Zeilenende, ohne
  Praefix, Salz 15 Byte, einzelnes Surrogat, Nicht-ASCII-Zusage, bytes-Identifikator, str-Salz, None,
  NFD gegen NFC): am Kopf nur `exakt` und `bytearray` True, keiner wirft. An main warfen Surrogat
  (`UnicodeEncodeError`) und Nicht-ASCII (`TypeError`); memoryview war an beiden False, keine Regression.
- `hmac.compare_digest` in `merkle.py`, `policy.py`, `bundle.py`, `statuslist.py`: vergleichen dekodierte
  Bytes, kein `str`-Pfad (gelesen, nicht ausgefuehrt).
- OrderedDict im Kopierer, sechs Faelle: eigene Reihenfolge nach `move_to_end`, `str`-Unterklassen-Schluessel,
  verwaister Schluessel in der Liste nach `dict.__delitem__`, eigene Klasse mit Metaklassen-`__hash__` in
  der Liste, Slot mit Fremdobjekt. Jeder Fremdfall ergibt `CanonicalizationError`, 0 Aufrufe von
  Aufrufer-Code gezaehlt.
- `expected_context`, sieben Faelle (exakt, anders, luegende `str`-Unterklasse mit fremden Zeichen und mit
  den richtigen Zeichen, int, leer gegen Bindung, leer gegen keine Bindung): wie behauptet, 0 Aufrufe.
- `require_statement_shape` an `canonicalize_statement` und `statement_content_root`, Werte True, False,
  "false", 0, None: nur die beiden bool werden angenommen.
- `svr_properties` mit `ok` True, False, "true", 1, [0], None: nur True verdient die Eigenschaft.
- Rust-Differenz `content-root`, sechs Statements (astral gegen BMP-Sortierung, Zahlen, Escapes,
  Verschachtelung, kombinierende Zeichen, leer): 6 von 6 gleich.
- Eigene Testdateien des Branches (19 Dateien aus dem Diff): 491 passed, 7208 subtests passed, 22,5 s.
- `ruff check src tests scripts`: keine Befunde. `mypy src` 2.3.1: keine Befunde in 73 Dateien. mypy 2.3.0
  in einer Umgebung ohne die optionalen Abhaengigkeiten meldet `pqsig.py:91` unused-ignore, ebenso an
  einem Baum ohne diese Aenderung; umgebungsabhaengig, kein Fund.

## 5. Grenzen

- Mutationsgate (`scripts/mutation_check.py`, von diesem Branch um 13 Zeilen geaendert): NICHT GEMESSEN.
- Rust-Differenz fuer L1 bis L12: NICHT ANWENDBAR, der Rust-Verifier liest Dateien und beurteilt weder
  Claim-Inhalt noch Trust-Pack-Muster; nur `content-root` wurde verglichen.
- Die Geschwister in Klasse A ausserhalb von `evalclaim` und `intoto`: NICHT GEMESSEN.
- Volle Suite auf dem Linsenbranch: zum Zeitpunkt dieses Berichts nicht gelaufen; wird nachgereicht.
- Ob L1 bis L6 im Register gefuehrt sind: gesucht in `RESTRISIKO_6*.md`, `THREAT_MODEL.md`, `CHANGELOG.md`
  nach Doppellesung und TOCTOU im Objekt, kein Eintrag gefunden; Issues auf GitHub NICHT GEPRUEFT.
- Keine Aussage ueber Vollstaendigkeit. Die Sonden liegen nicht im Repo; jeder Fund ist durch seinen
  roten Test reproduzierbar.

Prepared with AI agent involvement, reviewed and submitted under human oversight.
