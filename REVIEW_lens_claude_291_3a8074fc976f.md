# Linsenlauf Claude-Familie, 291 Runde 2, Kopf 3a8074fc

Geprueft wurde `fix/a-resolver-promotes-only-on-exact-true` (PR 291) am Kopf
`3a8074fc976ff027cdc5197930d31ef5a631af61`, Diff gegen main `31816e08afeababcf024969fd7bbb5c4d1647b28`
(Merge-Basis 31816e08, 4 Commits, 21 Dateien, +2391/-106).
Die Flaechen, die der Branch nennt, halten; ausserhalb davon lesen drei Schluesselwoerter des Aufrufers
ihren Wert weiter nach Wahrheit, eine davon in `assurance`, dem Modul, fuer das der Branch die Regel
ausspricht, und die Runde fuehrt eine Regression fuer registrierte Anker-Pruefer ein. Das Verdikt ist
FIX_FIRST.

Modell laut Harness: `session_context.model` claude-opus-5-5, `external_metadata.last_served_model`
claude-opus-5-5.
Umgebung: Python 3.11.15, ruff 0.16.9, mypy 2.3.1, pytest mit pytest-subtests.
Rote Tests: `tests/test_lens_claude_291_3a8074fc976f.py`, fuenf Faelle N1 bis N5.

## Behauptete Eigenschaft in einem Satz

Eine Antwort, ein Status oder ein Schalter, den der Aufrufer liefert (Resolver, Anker-Pruefer, registrierter
Pruefer, Pruefergebnis, erlaubender Schalter), befoerdert ein Urteil nur als das exakte JSON-true; `1`,
`"true"`, wahrheitsfaehige Objekte, Abbildungen mit fremder Metaklasse und Iteratoren von Paaren
befoerdern nie, und ein Schluesselmaterial zaehlt nur als einfaches `bytes` oder `bytearray`.

## 1. Verdikt

FIX_FIRST, hoechste Schwere P0 (N4, solange der Branch ohne den D4-Branch auf main steht; ohne N4: P1).

## 2. Funde

Aufruf: `PYTHONPATH=src python -m pytest tests/test_lens_claude_291_3a8074fc976f.py -k <fall>`.
Ergebnis an 3a8074fc: 17 fehlschlagende Faelle. An main 31816e08: 15 (N1 bis N4; N5 ist dort gruen, also
von dieser Runde eingefuehrt). Am D4-Kopf fa555f13 (Linsenzweig d6c12c73): 10 (N1 bis N3; N4 dort
geschlossen).
Nachtrag 0cd498f8 (N3 prueft jetzt drei Stellen statt einer, je "false" und "no"): an 3a8074fc 21, an main
31816e08 19, an main 0ace3039 19, mit dem `src/` von fa555f13 14 (gemessen 17:4xZ, dieselbe Datei an allen
vier Koepfen, CPython 3.11.15, pytest 9.1.1).

| Nr | Richtung | Flaeche | Eigenschaft | Schwere | Aufruf (`-k`) | Ergebnis |
|---|---|---|---|---|---|---|
| N1 | Geschwister im beruehrten Modul | `assurance.classify_digest_evidence(applicable=...)`, damit `classify_receiver_corroboration` | Was der Aufrufer liefert, zaehlt nur als exaktes bool (67bb104e). `if not applicable`: None, 0, "", [] machen ein schwaches Feld nicht anwendbar, `evidence_ladder_summary` uebergeht es, die Zusammenfassung aus CLAIMED und CONTENT_RESOLVED steigt auf CONTENT_RESOLVED. "false" bleibt anwendbar. | P1 | `test_n1` | rot |
| N2 | Geschwister (Emitter) | `adapters._provenance.bind_reported_version(bound=...)` | Derselbe Satz. `if bound and ...`: "false", "no", 1, [0] schreiben die Version mit Status `reported`; False schreibt `not_bound` mit Grund. Der Block wird in den Beleg signiert. | P1 | `test_n2` | rot |
| N3 | Geschwister im beruehrten Modul | `agent_review.emit_agent_review`, `require_valid_agent_review_predicate_any`, `render_disclosure_block` (je `legacy_v01=...`) | Derselbe Satz. `return not legacy_v01` (`_fassung_fuer_renderer`): "false" und "no" stellen ein v0.1-Predicate nach den v0.1-Regeln aus, nehmen es an und rendern es, wo False, 0 und None nach den v0.2-Regeln ablehnen (`subjectContext.disclosureCoreDigest is required`). | P1 | `test_n3` | rot |
| N4 | Geschwister (Runde 2, "Urteile, die der Aufrufer baut") | `intoto.svr_properties`, `export_svr_dsse` | Ein Check und ein attestierter Schalter verdienen eine signierte SVR-Eigenschaft nur als exaktes True. `Check("ed25519-signature", "false")` ergibt PROOFBUNDLE_SIGNATURE_VALID, `anchor_verified="false"` PROOFBUNDLE_ANCHOR_VALID (auch `export_svr_dsse`, per Sweep). Hier nicht beruehrt; am D4-Kopf fa555f13 geschlossen. | P0 | `test_n4` | rot |
| N5 | Regression | `anchors.verify_anchor` mit registriertem Pruefer | Ein registrierter Pruefer liefert ein dict. Ein `OrderedDict` oder `defaultdict` ohne eigene Methode mit ok True ist jetzt ein gescheiterter Anker; Detail: "returned no result object". An main PASS. Der Test haelt die schwaechere Eigenschaft, dass die Ablehnung den gelieferten Typ nennt. | P2 | `test_n5` | rot |

Bewertung (getrennt von der Messung):
- N1 bis N3 sind dieselbe Klasse wie die Runde: ein Schalter des Aufrufers, der nach Wahrheit gelesen wird.
  Die Richtung ist je Schalter verschieden: bei `applicable` (Vorgabe True) lockert ein falscher Nicht-bool,
  bei `bound` und `legacy_v01` lockert ein wahrer Nicht-bool. Reichweite: nur die Python-API; die Aufrufer
  im Paket reichen fuer `applicable` selbst berechnete bools (`outcome.py:741`, `decision.py:643`).
- N4 ist P0 nach der Definition (signierte Eigenschaft falsch), gehoert aber zum D4-Branch, der es schliesst.
  Landet 291 vor D4, bleibt es auf main offen.
- N5: Der Branch nennt die Ablehnung von dict-Unterklassen mit eigenem `get` ausdruecklich; getroffen wird
  auch eine Unterklasse ohne eigene Methode. Ein Lesen der gespeicherten Inhalte (`dict.get` des
  Basistyps, wie D4 es fuer den Kopierer tut) wuerde beide Faelle trennen; das ist ein Hinweis, kein Fix.

## 3. Klassen und Geschwister

- Klasse "Schalter nach Wahrheit gelesen", Laufzeit-Sweep: alle oeffentlichen Funktionen mit einem
  bool-Schluesselwort (73 Schalter), je Samen mit False, True und "false", "no", 1, 0, [0], "" gerufen
  (Samenkorpus des Branches 234 an e5b39b81, gegen den Code dieses Kopfes). Nach Wahrheit gelesen und
  hier nicht gefuehrt, weil die Richtung strenger ist (fail-closed): `strict` (decision, policy.lint_policy),
  `require_derived_subject` (decision, outcome), `require_pq`, `require_current_hash`,
  `require_external_token` (renewal.verify_sequence), `require_verified_prior` (Vorgabe False).
  `hf_evals.to_eval_results_entry(include_token="false")` nimmt das Token auf (P3, kein eigener Test).
  `canonicalize_statement(require_statement_shape=...)` und `svr_properties`/`export_svr_dsse` sind am
  D4-Kopf geschlossen.
- Erlaubende Schalter des Branches, gelesen: `allow_unauthenticated_anchor` (`is True` und Typpruefung),
  `allow_deprecated` (Typpruefung, D4-Lauf L7 hier gruen), `allow_pending` (`is True`; der Wahrheitslesen
  in `cli.py:713` sieht nur ein von `load_policy` gepruefte bool, `policy.py:544`), `allow_raw_inputs`
  (`is not True`), `allow_unverified_rotation` (`is True`), `allow_value_mismatch` (Typpruefung).

## 4. Gepruefte Flaechen ohne Fund

- Eigene Testdateien des Branches (2): 71 passed, 458 subtests passed. `ruff check src tests scripts`:
  keine Befunde. `mypy src` 2.3.1: keine Befunde in 73 Dateien.
- `classify_receiver_corroboration`: Schluesselmaterial per `type()`, Schluessel-IDs per `type() is str`,
  `expected_receiver_public_key` typgeprueft (gelesen).
- `VerificationResult.ok` exakt True (gemessen: Check ok "false", 1, [0] ergeben `result.ok False`);
  `policy.py:998` `ra_check.ok is True`; `bundle.automation_summary` `is True`; `hashalg.py:265` liest
  selbst gebaute bool-Checks.
- `verify_anchors(allow_pending=...)` typgeprueft (gelesen).
- D4-Lauf L1 bis L6, L8 bis L12 und 234-Lauf M1 bis M4 sind an diesem Kopf weiter rot; sie gehoeren nicht
  zu dieser Klasse.

## 5. Grenzen

- Mutationsgate: NICHT GEMESSEN.
- Rust-Differenz: NICHT ANWENDBAR, die Rueckrufe und Schalter gibt es nur in der Python-API.
- Der Sweep erreicht nur, was die Samen des Korpus erreichen, und erkennt einen Wahrheitsleser nur, wenn False
  und True fuer den Samen verschieden antworten; 73 Schalter wurden gerufen, entscheidbar war ein Teil davon.
- `legacy_v01` an `render_disclosure_block` und `require_valid_agent_review_predicate_any`: gemessen im
  Nachtrag 0cd498f8 (N3), vorher nur gelesen.
- Volle Suite auf dem Linsenbranch, nachgereicht: an 452c67f9 (pytest tests/, CPython 3.11.15, uid 0,
  17:08:12Z bis 17:43:30Z) 19 failed, 5968 passed, 174 skipped, 3526 subtests passed, 2115,9 s. Das Protokoll
  nennt drei davon mit Namen (N4 `anchor_verified` und die zwei nur-als-root-Faelle von
  `test_sammelabbruch_vor_dem_import.py`, an main ebenso); die SUBFAILED-Zeilen hat mein Filter nicht
  mitgeschrieben. Die Zahl 19 ist 17 Linsenfaelle der Datei in der Fassung 452c67f9 plus die zwei
  root-Faelle; die Datei wurde um 17:16:15Z waehrend des Laufs erweitert (0cd498f8), die erweiterte
  Fassung ergaebe 21 plus 2. Welche Fassung gesammelt wurde, ist aus der Zahl geschlossen, nicht
  protokolliert. Die volle Suite an 0cd498f8: nicht gelaufen.
- Keine Aussage ueber Vollstaendigkeit.

Prepared with AI agent involvement, reviewed and submitted under human oversight.
