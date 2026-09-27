# Linsenlauf Claude-Familie, 234 Runde 10, Kopf e5b39b81

Geprueft wurde `fix/every-constant-lookup-on-a-foreign-key-is-classified` am Kopf
`e5b39b81228bc24b5ed837547721fbdf4b24a7d9`, Diff gegen main `31816e08afeababcf024969fd7bbb5c4d1647b28`
(Merge-Basis `10f3466b`, 22 Commits, 65 Dateien, +8646/-460).
Der Waechter fuer Nachschlagen auf konstanten Containern haelt gegen jede Schreibweise, die dieser Lauf
gepflanzt hat. Offen bleiben Klassifikationen, bei denen der fremde Wert hashbar ist und trotzdem die falsche
Klasse bekommt, sowie eine Menge, die aus der Liste des Aufrufers gebaut wird. Das Verdikt ist FIX_FIRST.

Modell laut Harness: `session_context.model` claude-opus-5-5, `external_metadata.last_served_model`
claude-opus-5-5.
Umgebung: Python 3.11.15, ruff 0.16.9, mypy 2.3.1, pytest mit pytest-subtests, node v22.22.2 (nur als
Orakel fuer ECMA-262). Nicht installiert: `rfc3161-client` (Extra `anchors`), ein keccak-Backend
(`eth-hash` oder `pycryptodome`).
Rote Tests: `tests/test_lens_claude_234_e5b39b81228b.py`, vier Faelle M1 bis M4; M5 ist ein Test des
Branches selbst.

## Behauptete Eigenschaft in einem Satz

Jedes Nachschlagen, Schreiben oder jeder Mitgliedschaftstest auf einem konstanten Container (auf
Modulebene oder abgeleitet) mit einem Schluessel von aussen laeuft ueber `is_member` oder steht mit Grund
in der Liste des Waechters, sodass ein Wert aus geparstem JSON als bekannt, unbekannt oder abgelehnt
klassifiziert wird und nie roh wirft; dazu rendert jede oeffentliche Funktion einen Wert von aussen
beschraenkt.

## 1. Verdikt

FIX_FIRST, hoechste Schwere P1 (Funde M2, M3, M4).

## 2. Funde

Aufruf: `PYTHONPATH=src python -m pytest tests/test_lens_claude_234_e5b39b81228b.py -k <fall>`.
Ergebnis M1 bis M4: rot am Kopf e5b39b81 (14 fehlschlagende Faelle) und rot an main 31816e08 (dieselben
14), also vorbestehend und vom Branch nicht geschlossen.

| Nr | Richtung | Flaeche | Eigenschaft | Schwere | Aufruf (`-k`) | Ergebnis |
|---|---|---|---|---|---|---|
| M1 | Geschwister | `adapters.agt_receipt.verify_agt_receipt` | Antwort oder typisierte Ablehnung. `a_key in set(trusted_authorizer_keys)` hasht jedes Element der Liste des Aufrufers; `[]`, `{}`, `["a"]` darin werfen rohes `TypeError`. Der Waechter nennt die Stelle sicher "behind an isinstance(x, str)", das gilt fuer `a_key`, nicht fuer die Liste. | P2 | `test_m1` | rot |
| M2 | Umgehung (anderer Typ) | `statuslist.verify_status_snapshot`, `issue_status_list_token` | `bits` ist eine der Ganzzahlen 1, 2, 4, 8. `bits not in (1, 2, 4, 8)` klassifiziert `true` als bekannt (True == 1, gleicher Hash): ein signiertes Token mit `"bits": true` ergibt `ok True`, gelesen als 1-Bit-Liste; der Emitter signiert `"bits": true`. | P1 | `test_m2` | rot |
| M3 | Umgehung (anderer Typ) | `statuslist.verify_status_snapshot` | Ergebnis-Dict fuer jedes Token ("never crashes" an den Waechtern der Funktion). `"bits": 1.0`, `2.0`, `4.0`, `8.0` passieren die Mitgliedschaft, `8 // bits` wird float, `bit_array[byte_i]` wirft rohes `TypeError`. | P1 | `test_m3` | rot |
| M4 | Geschwister (Klasse dieses Branches) | `evalclaim.classify_eval_claim`, Payload-`schema` | Eine Ablehnung braucht eine Deklaration (Regel der Funktion fuer den Umschlag). Fehlend, null, leer, Zahl, Liste ergeben `refused_unknown_schema` statt `invalid`. Derselbe Fall ist L11 des D4-Laufs. | P1 | `test_m4` | rot |
| M5 | Regression (Umgebung) | `tests/test_public_functions_render_a_value_from_outside_bounded.py` | Eine blanke `[eval]`-Installation endet in sauberen Skips (N18, `tests/test_bare_install_degrades_to_clean_skips.py`). Ohne `rfc3161-client` und ohne keccak-Backend schlagen `test_a_planted_value_leaves_the_function_typed[...create_rfc3161_anchor]` (ModuleNotFoundError nicht gepinnt) und `[...eip191_recover_address]` (`_NoSigLib` ist ein RuntimeError ohne ImportError in der Ursache, `_absent_dependency` erkennt ihn nicht) fehl. | P3 | `-k "create_rfc3161_anchor or eip191_recover_address"` in dieser Umgebung | rot |

Messung (Sonde, nicht Test):
- M2/M3 an beiden Koepfen: bits 1 und true: `ok True, status 1`; 1.0, 2.0, 4.0, 8.0: `TypeError: byte
  indices must be integers or slices, not float`; false und 0: `ok False` mit Grund.
  `issue_status_list_token(bits=True)` signiert `"bits": true`, `bits=2.0` wirft rohes `TypeError`.

Bewertung (getrennt von der Messung):
- M2 und M3 sind dieselbe Klasse: ein Mitgliedschaftstest auf einem Tupel ganzer Zahlen, der einen Wert
  anderen JSON-Typs ueber `==` als bekannt einordnet. Die Funktion haelt fuer `iat`, `exp` und `ttl` die
  Hausregel (`isinstance(x, bool) or not isinstance(x, int)`), fuer `bits` nicht. Der Status, der bei `true`
  gelesen wird, ist derselbe wie bei 1; falsch ist, dass ein Token, dessen Form der Entwurf ablehnt, als
  gueltig gilt. Kein Rust-Gegenstueck fuer Status-Listen.
- M1 ist nur ueber die Konfiguration der vertrauenden Partei erreichbar, nicht ueber das Beleg-JSON
  (`a_key` wird vorher auf `str` geprueft, `agt_receipt.py:290`).
- M4: Kein Verbraucher in `src/` und kein Exit-Code; nur die oeffentliche API.
- M5 betrifft nur die Testumgebung; die CI installiert die Extras (gelesen im Branch, nicht gemessen).

## 3. Klassen und Geschwister

- Klasse "hashbar, aber typfremd als bekannt klassifiziert" (True == 1 == 1.0): im Baum per grep nach
  Ganzzahl-Tupeln und -Mengen in Mitgliedschaftstests gesucht, gefunden nur `statuslist._ALLOWED_BITS`
  (zwei Stellen, `:194` Verify, `:250` Emit). `isinstance(..., int)` ohne bool-Ausschluss: elf Zeilen, die drei
  auf Verify-Pfaden (`outcome.py:847/850`, `run_ledger.py:122`, `trust_pack.py:282`) sind vorher geprueft
  oder lesen selbst erzeugte Werte (gelesen, nicht ausgefuehrt).
- Klasse "eine Menge aus einem nicht konstanten Wert" (`x in set(allowed)`): zwei Stellen laut Waechter,
  `agt_receipt.py:333` (M1) und `relation.py:757`; die zweite ist durch `isinstance(_td, str)` vor dem
  `in` geschuetzt, `allowed` dort NICHT GEMESSEN.
- Klasse "Klassifikation nach fremdem Schluessel ohne Deklaration": M4.

## 4. Gepruefte Flaechen ohne Fund

- Der AST-Waechter `tests/test_membership_hashable_guard.py` in einer Kopie des Baums: Kontrolle (harmlose
  Funktion) gruen, 60 passed. Gepflanzt in `hashalg.py`, je einzeln: zwoelf Leseformen (Parameter-Default,
  kw-only-Default, Lambda-Default, Methoden-Default im Klassenrumpf, Alias im Klassenrumpf,
  `dict.get(CONST, k)`, `CONST.get.__call__(k)`, `global`-Umbindung, `get(*[k])`, `{**CONST}.get(k)`,
  `CONST.copy().get(k)`, `(m or CONST).get(k)`) und zwoelf Container-Definitionen (annotiert, annotiert im
  `if`, `dict(a=1)`, `set((...))`, `{*(...)}`, `frozenset([...])`, `OrderedDict(...)`, Dict- und
  Set-Comprehension, `dict.fromkeys`, Differenz zweier Literale, annotierte frozenset-Mitgliedschaft):
  24 von 24 rot, die Meldung nennt jeweils die gepflanzte Stelle oder den Container.
- Laufzeit-Suche mit dem Samenkorpus des Branches: 103 Funktionen (`verify*`, `validate*`, `classify*`,
  `decode*`, `evaluate*`, `check*`, `lint*`, `load*`), 10.635 Aufrufe mit `[]`, `{}`, `set()`, `([],)`,
  `["a"]` an jedem Knoten: ein einziges rohes `unhashable`-TypeError, M1.
- Typwechsel-Suche (jede Ganzzahl eines Samens durch bool- bzw. float-Zwilling ersetzt): 102 Funktionen, 181
  Aufrufe, kein Fund ausser einem entarteten Fall (`evaluate_relations_policy` mit einem Nicht-Objekt als
  Abschnitt, 123 gegen 123.0), den der Branch absichtlich als abwesend liest (897cb2b1).
- `_schema_shapes` gegen ECMA-262 (node v22.22.2, Muster aus `schemas/`): 31 Randfaelle (Zeilenende, CR,
  Leerzeichen, Grossbuchstaben, 63/65 Stellen, Vollbreite, arabisch-indische Ziffern, `z`, Offset,
  Schaltsekunde, `0.1.`, `0.1.1a`), 0 Abweichungen.
- Samenkorpus schluesselfrei (Neuaufbau d6d89763): 34 Marker `$ed25519_private`, nur die Namen `a` und `b`;
  kein `PRIVATE`, kein `BEGIN`; kein JWK-`d` mit Schluesselmaterial (einziges `d` ist ein Testwert 2.5).
  Drei triviale 32-Byte-Muster (0x11 x 32, 0x22 x 32, 0..31), die Tests anderswo als Test-Seeds nutzen,
  stehen nur an Digest-Positionen; kein Wert steht an einer Position fuer einen privaten Schluessel.
- Unbekannter Anker-Typ: `verify_anchor` antwortet `ok False` (`anchors.py:233`, `is_member`).
- D4-Lauf L8 (Trust-Pack-Muster): an diesem Kopf gruen, dieser Branch schliesst ihn.
- Eigene Testdateien des Branches (16 Dateien aus dem Diff): 978 passed, 2 failed (M5), 1 skipped, 472
  subtests passed, 52,4 s. `ruff check src tests scripts`: keine Befunde. `mypy src` 2.3.1: keine Befunde in 73
  Dateien.

## 5. Grenzen

- Mutationsgate (`scripts/mutation_check.py`, vom Branch um 24 Zeilen geaendert): NICHT GEMESSEN.
- Rust-Differenz: NICHT ANWENDBAR fuer M1 bis M4 (kein Rust-Gegenstueck fuer AGT-Belege, Status-Listen,
  Claim-Klassifikation). Die Relation-Paritaet, die der Branch in `_schema_shapes.py` nennt, NICHT GEMESSEN.
- Die Laufzeit-Suchen erreichen nur, was die ein bis zwei Samen je Funktion erreichen; Ganzzahlen in
  base64-verpackten signierten Nutzlasten erreicht die Typwechsel-Suche nicht (daher nur 181 Aufrufe).
- D4-Lauf L1 bis L7, L9, L10, L12 sind an diesem Kopf weiter rot; sie gehoeren nicht zur Klasse dieses
  Branches und sind hier nicht erneut bewertet.
- Volle Suite auf dem Linsenbranch: zum Zeitpunkt dieses Berichts nicht gelaufen.
- Keine Aussage ueber Vollstaendigkeit.

Prepared with AI agent involvement, reviewed and submitted under human oversight.
