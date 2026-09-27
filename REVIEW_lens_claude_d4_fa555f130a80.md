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
Rote Tests: `tests/test_lens_claude_d4_fa555f130a80.py`, zwoelf Faelle L1 bis L12; im Nachtrag (Abschnitt 6)
dreizehn weitere, L13 bis L25.

## Behauptete Eigenschaft in einem Satz

Ein Hash oder eine Zusage im Beweisstueck wird an der Verify-Grenze neu berechnet oder in der Form
geprueft, die `salted_commit` erzeugt, und jede Grenze liest den Wert des Aufrufers als das, was er
speichert (exakte `str`-Schluessel im OrderedDict, bool-Schluesselwoerter exakt, `expected_context` nach
Zeichen, `svr_properties` zaehlt nur `ok is True`, `verify_commitment` antwortet False statt zu werfen).

## 1. Verdikt

FIX_FIRST, hoechste Schwere P0 (Fund L1 bis L6; im Nachtrag L13 bis L19).

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
  `:3044` (hier zuerst per grep geschaetzt; gemessen im Nachtrag, Abschnitt 6.1). `cli.py:1842` liest
  Dateien und ist nicht betroffen (gelesen, nicht ausgefuehrt).
- Klasse B, "ein bool-Schluesselwort wird nach Wahrheit gelesen": gemessen an `allow_deprecated` (L7).
  Weitere Schluesselwoerter `strict`, `require_derived_subject`, `require_canonical`, `applicable`,
  `leaf_witnessed`, `include_token`, `require_signature_line` (hier per grep; gemessen im Nachtrag,
  Abschnitt 6.3); bei `strict` und `require_*` wirkt "false" in die strengere Richtung.
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
- Die Geschwister in Klasse A ausserhalb von `evalclaim` und `intoto`: im Nachtrag gemessen (Abschnitt 6).
- Volle Suite auf dem Linsenbranch, nachgereicht: an 78455de3 (pytest tests/, CPython 3.11.15, uid 0,
  15:42:01Z bis 16:18:20Z) 26 failed, 5936 passed, 156 skipped, 9151 subtests passed, 2177,4 s. Die 26
  sind die 23 roten Faelle dieses Laufs, die zwei nur-als-root-Faelle von
  `test_sammelabbruch_vor_dem_import.py` (an main ebenso) und ein Fehler meiner Testdatei:
  `test_sdist_ohne_signierwerkzeug.py` erlaubt `from_private_bytes` in einem ausgelieferten Test nur ueber
  einen ausgeschriebenen Seed, und L8 baute drei Seeds aus einer Schleifenvariablen. Behoben in d6c12c73
  (dort 20 passed fuer diese Datei); die volle Suite wurde an d6c12c73 nicht erneut gefahren.
- Ob L1 bis L6 im Register gefuehrt sind: gesucht in `RESTRISIKO_6*.md`, `THREAT_MODEL.md`, `CHANGELOG.md`
  nach Doppellesung und TOCTOU im Objekt, kein Eintrag gefunden; Issues auf GitHub NICHT GEPRUEFT.
- Keine Aussage ueber Vollstaendigkeit. Die Sonden liegen nicht im Repo; jeder Fund ist durch seinen
  roten Test reproduzierbar.

## 6. Nachtrag: Owner-Auftrag vom 27.09., 19:3x Berlin (Klasse A an neun Stellen, Klasse B per Sweep)

Gemessen mit dem `src/` von fa555f13 (Linsenzweig, `src/` gleich fa555f13), CPython 3.11.15, pytest 9.1.1,
17:2xZ bis 17:4xZ. Neue rote Tests L13 bis L25 in derselben Datei. Das Verdikt bleibt FIX_FIRST, hoechste
Schwere P0. Der Fix-Branch stand beim Messen und beim Push auf fa555f13.

### 6.1 Klasse A, je Stelle

Verfahren: je Stelle ein signiertes Statement S, das der Verifier an einem signierten Feld ablehnt, und F,
dasselbe Statement mit diesem Feld so geaendert, dass es besteht. F kommt ab einer spaeteren Lesung: eine
dict-Unterklasse (`__getitem__` und `get`) oder eine `str`-Unterklasse im Feld (`encode`). Kontrollen je
Fall: S wird abgelehnt, F in S' Umschlag wird abgelehnt, F vom selben Schluessel signiert wird angenommen.
Orakel: die signierten Bytes des Pakets selbst.

| Stelle | oeffentlich erreichbar ueber | Lesungen von `payload` | Rueckgabe, wenn die Lesungen verschieden antworten | Test | Schwere |
|---|---|---|---|---|---|
| `decision.py:562`/`:567` | `verify_decision_receipt` (auch `_or_raise`, gelesen) | 2 | `ok` True, `crypto_ok` True fuer F (Nonce des Verifiers); S allein: `nonce mismatch`, `ok` False. dict und str ab Lesung 2 | L13 | P0 |
| `verification_summary.py:220`/`:223` | `verify_verification_summary` | 2 | `ok` True fuer F (Ebene VERIFIED mit `receiptRef`); S allein: `levels_consistent` False | L14 | P0 |
| `trust_pack.py:463` | `verify_trust_pack` | 1 | keine Abweichung moeglich: eine Lesung, die Signaturen werden ueber dieselben Bytes geprueft. Ab Lesung 1 bzw. Aufruf 1 gefaelscht: `ok` False; ab Lesung 2: das Urteil ueber S | keiner | haelt |
| `run_ledger.py:272`/`:275` | `verify_run_ledger` | 2 | `ok` True fuer F (`runBudget` 5); S allein: 3 Laeufe bei `runBudget` 2, `ok` False | L15 | P0 |
| `outcome.py:596`/`:599` | `verify_outcome_receipt` (auch `_or_raise`, gelesen) | 2 | `ok` True fuer F (`decisionRef` b...); S allein: an eine andere Entscheidung gebunden | L16 | P0 |
| `relation_statement.py:211`/`:215` | `verify_relation_statement` | 2 | `ok` True fuer F (`schemaVersion` 0.1.0); S allein (0.2.0): `structure_ok` False | L17 | P0 |
| `agent_review.py:2296`/`:2300` | `verify_agent_review`; `verify_agent_review_any` (Weg v0.1) | 2; ueber `any` 3 | `ok` True fuer F (anderer `headSha`, erwarteter Subjekt-Digest von F); S allein gehoert zu einem anderen Pull Request. Ueber `any` ab Lesung 3 | L18 | P0 |
| `agent_review.py:2622`/`:2626` | `verify_agent_review_v02`, `verify_agent_review_v03`; `verify_agent_review_any` (Weg v0.2) | 2; ueber `any` 3 | wie die Zeile davor | L19 | P0 |
| `agent_review.py:3044` | `verify_agent_review_any` (Weichen-Lesung) | 1 von 3 | weicht nur die Weichen-Lesung ab (v0.1 oder v0.3 statt signiert v0.2), lehnt der gewaehlte Verifier ab: `ok` False, `UNKNOWN_PREDICATE_VERSION`. Kein eigener Fund; hinter ihr liegen die zwei Zeilen davor | keiner | lehnt ab |

Aufruf: `PYTHONPATH=src python -m pytest tests/test_lens_claude_d4_fa555f130a80.py -k "l13 or l14 or l15 or l16 or l17 or l18 or l19"`.
Ergebnis an fa555f13: 7 Tests, 20 fehlschlagende Faelle, genau dict und str bei Lesung 2 (direkt) und 3
(ueber `any`); alle Kontrollen gruen.

Bewertung (getrennt von der Messung):
- Erreichbar nur mit einem vom Aufrufer gebauten Objekt, wie L1 bis L6; aus Bytes, ueber die CLI (liest
  Dateien in gewoehnliche dicts) und im Rust-Verifier nicht. P0 nach derselben Begruendung wie L4 bis L6:
  `ok` True ueber ein Statement, das die Signatur nicht deckt, an einem Urteil, das ein signiertes Feld
  bindet (Nonce, Entscheidung, Pull Request, Laufbudget).
- Sonde ohne Test: bei gueltigem S und einem F, das nur ein urteilsfreies Feld aendert, ist die Rueckgabe von
  `verify_verification_summary` und `verify_run_ledger` gleich der fuer S. Das Ergebnis traegt den Inhalt
  nicht; ein Verbraucher, der danach `load_payload` ruft, liest mit demselben Objekt F. Die Tests messen
  deshalb das Urteil, nicht den Inhalt.

### 6.2 Geschwister ausserhalb der neun Stellen

- `agent_review.resolve_receipt_chain`: der Digest kommt aus `receipt_digest` (Lesung 1), die
  `supersession`-Angaben aus `env["payload"]` (Lesung 2). Gemessen mit zwei v0.2-Receipts A und B,
  `verified={dA, dB}`: gewoehnlich `current` None, `ambiguous` True; dict ab Lesung 2 mit einer Angabe
  `corrects: dB`, die dA nicht deckt: `current` A, `corrected` [dB]. Die Ordnung haengt an einem Anspruch,
  den der geprueft gemeldete Digest nicht deckt. P1, Vorbedingung wie Klasse A. Kein Test: der Auftrag
  begrenzt die Tests auf die neun Stellen.
- `trust_pack.verify_trust_pack`, Feld `signatures`: zwei Lesungen (Kappe, Schleife). dict mit den drei
  gueltigen und 600 fremden Eintraegen ab Lesung 2: `ok` True; dieselbe Liste als gewoehnliches dict:
  `ok` False (`signatures = 603 > limit 512`). Die Kappe gilt nicht der Liste, die die Schleife liest. Das
  Urteil bleibt eines ueber die signierten Bytes; Wirkung nur auf die DoS-Grenze. P3, kein Test.
- `intoto.py:808`, `:1058`, `:1273`: L4 bis L6.
- `cli.py:1842`/`:1845`, `cli.py:2111`, `:2310`, `:2450`: lesen Dateien in gewoehnliche dicts (gelesen,
  nicht ausgefuehrt), nicht erreichbar.

### 6.3 Klasse B, Sweep

Werkzeug: der Sweep aus Linse 3 (Familie und Samen aus dem Korpus des Branches 234 an b78450ee), jedes
bool-Schluesselwort jeder oeffentlichen Funktion der Familie mit False, True und `"false"`, `"no"`, `1`,
`0`, `[0]`, `""`. Ein Treffer: ein Nicht-bool gibt dieselbe Antwort wie das bool seiner Wahrheit, und False
und True antworten verschieden. Gerufen: 73 Schluesselwoerter. Treffer an fa555f13: 134 an 23
Schluesselwoertern (an 3a8074fc: 144 an 24).

| Schluesselwort (Funktion) | Vorgabe | Nicht-bool gelesen als | Richtung | Urteil oder signiertes Feld | Test |
|---|---|---|---|---|---|
| `allow_pending` (`anchors.verify_anchors`) | False | "false", "no", 1, [0] als True | lockert: ein wartender Anker erfuellt `require` | Urteil, FAIL wird WARN | L20, P1; an 3a8074fc typgeprueft |
| `allow_value_mismatch` (`hf_evals.to_eval_results_entry`) | False | wie oben als True | lockert: ein Wert, der dem signierten Urteil widerspricht, wird veroeffentlicht | die Ablehnung faellt | L21, P1; an 3a8074fc typgeprueft |
| `allow_deprecated` (`hashalg.resolve_hash_alg`, `compute_digest`) | False | wie oben als True | lockert | das sha1/md5-Tor | L7 (bestehend) |
| `legacy_v01` (`agent_review.emit_agent_review`; dazu `require_valid_agent_review_predicate_any` und `render_disclosure_block`, Vorgabe None, ausserhalb des Sweeps) | False | wie oben als True | lockert: v0.1-Regeln statt v0.2 | signiert | L22, P1, wie N3 auf 291 |
| `bound` (`adapters._provenance.bind_reported_version`) | True | wie oben als True, "" und 0 als False | "false" lockert (Status `reported`); "" und 0 strenger (`not_bound`) | signiertes Feld | L23, P1, wie N2 |
| `applicable` (`assurance.classify_digest_evidence`, `classify_receiver_corroboration`) | True | "" und 0 als False, "false" als True | "" und 0 (per Test auch None, []) lockern: das schwache Feld faellt aus der Leiter | Urteil (Leiterstufe) | L24, P1, wie N1 |
| `strict` (`decision.emit_decision_receipt`) | True | "" und 0 als False | lockert: signiert, was die Vorgabe ablehnt (per Test auch None) | signiert | L25, P2 |
| `leaf_witnessed` (`agent_review.render_disclosure_line`) | False | wie oben als True | lockert: die Zeile laesst ", not yet in a witnessed checkpoint" weg | gerenderter Text, weder Urteil noch signiertes Feld | keiner; P2 |
| `include_token` (`hf_evals.to_eval_results_entry`) | True | als True bzw. False | "false" nimmt das Token auf (die Vorgabe), "" und 0 lassen es weg | weder | keiner; P3 |
| `require_derived_subject` (`decision.verify_decision_receipt`, `_or_raise`, `outcome.verify_outcome_receipt`), `strict` (`policy.lint_policy`), `require_pq`, `require_current_hash`, `require_external_token` (`renewal.verify_sequence`) | False | "false" usw. als True | strenger (fail-closed) | ja, in die strengere Richtung | keiner |
| `strict` (`decision.require_valid_decision_predicate`), `require_verified_prior` (`renewal.renew_hashtree`, `renew_timestamp`) | False | "" und 0 als False (die Vorgabe); "false" nicht als True getroffen | keine Lockerung gegen die Vorgabe | nein | keiner |
| `_raise_on_malformed` (decision, outcome), `flag` (`_integration.emit_enabled`) | False | "" und 0 als die Vorgabe | private Namen | nein | keiner |
| `require_signature_line` (`checkpoint._split_signed_note`, `_note_body_and_sigs`, `_note_text_of`) | True | nach Wahrheit (`if not lines and require_signature_line`, gelesen) | aus keiner oeffentlichen Funktion erreichbar: die oeffentlichen Aufrufer reichen die Vorgabe oder ein literales False | nein | kein Fund |
| `require_canonical` (`_statement_payload.load_statement_strict`) | False | gerufen, kein Treffer | privates Modul; `cli.py:1867` reicht True | nein | kein Fund |

An fa555f13 ohne Treffer, an 3a8074fc getroffen: `require_statement_shape` (`canonicalize_statement`,
`statement_content_root`), `anchor_verified` und `prereg_verified` (`svr_properties`, `export_svr_dsse`),
von Runde 9 und 10 geschlossen. Die uebrigen `strict`-Schluesselwoerter der Verify- und
Validator-Funktionen: gerufen, kein Treffer.

Aufruf: `PYTHONPATH=src python -m pytest tests/test_lens_claude_d4_fa555f130a80.py -k "l20 or l21 or l22 or l23 or l24 or l25"`.
Ergebnis an fa555f13: 6 Tests, 25 fehlschlagende Faelle, alle Kontrollen gruen.

### 6.4 Die ganze Datei an drei Koepfen

- `src/` von fa555f13: 68 fehlschlagende Faelle (L1 bis L25).
- main 0ace3039 (eigener Arbeitsbaum, Datei hineinkopiert): 68, dieselbe Menge (Vergleich der sortierten
  Namen, kein Unterschied). An main ist also keiner der Faelle geschlossen.
- `src/` von 3a8074fc (Branch 291), zum Vergleich: 56; L7, L20 und L21 sind dort gruen.
- `ruff check` der Datei: keine Befunde.

### 6.5 Grenzen des Nachtrags

- Klasse A: je Stelle ein signiertes Feld gemessen; die `_or_raise`-Varianten laufen durch dieselbe innere
  Funktion (gelesen), nicht eigens gemessen. `verify_agent_review_any` auf dem Weg v0.3: NICHT GEMESSEN
  (L19 misst `any` mit v0.2, `verify_agent_review_v03` direkt).
- Klasse B: der Sweep erreicht, was die Samen erreichen, und erkennt einen Wahrheitsleser nur, wenn False und
  True fuer den Samen verschieden antworten. Schluesselwoerter mit einer Vorgabe, die kein bool ist (etwa
  `legacy_v01: bool | None` an den Renderern), liegen ausserhalb; fuer `legacy_v01` deckt L22 sie ab.
- Die Richtung "lockert" ist gegen die Vorgabe und gegen die Hausregel (nur das exakte bool zaehlt)
  beurteilt; eine Aussage ueber die Absicht eines Aufrufers ist das nicht.
- Rust-Differenz: NICHT ANWENDBAR, Objekte und Schluesselwoerter gibt es nur in der Python-API.
- Mutationsgate: NICHT GEMESSEN. Volle Suite auf dem Linsenbranch mit L13 bis L25: nicht gelaufen.
- Keine Aussage ueber Vollstaendigkeit.

Prepared with AI agent involvement, reviewed and submitted under human oversight.
