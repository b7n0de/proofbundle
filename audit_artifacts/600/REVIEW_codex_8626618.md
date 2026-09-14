# Externe Defektklassensuche am Kopf `8626618f33bd9e6a98863a0b4055a2c2389bbd8c`

## 1 Urteil

Am geprüften Kopf `8626618f33bd9e6a98863a0b4055a2c2389bbd8c` ist in den ausgeführten Python-Prüfungen kein Geschwisterdefekt der Klasse „Form statt Eigenschaft“ bestätigt.  
Am selben Kopf ist in der ausgeführten Python-Prüfung kein Geschwisterdefekt der Klasse „Einheit statt Eigenschaft“ bestätigt.  
Die 14 ausgeführten Fälle sind grün und die zwei Python-Rust-Differentialfälle sind wegen fehlender lokal gecachter Rust-Crates ungeprüft.  
Die Aussage über Python-Rust-Parität ist deshalb keine Bestätigung, sondern eine ungeprüfte Ziel-Eigenschaft der eingecheckten Tests.  
Das Urteil gilt nur für die unten genannten Flächen, Aufrufe und Eingabeklassen; Vollständigkeit über alle möglichen Eingaben wird nicht behauptet.

## 2 Funde

### Keine neuen bestätigten Funde

Für `relation`, `relation_statement`, `budget`/`_strict_json`, `canonical`, `checkpoint`, `tlogproof`, `dsse` und `_wire_b64` ergab die statische Suche plus die unten ausgeführten Gegenbeispiele keinen neuen reproduzierbaren Fehler. Daher gibt es keine belegte Fläche, verletzte Eigenschaft, Schwere oder rote Reproduktion zu berichten.

### Bestätigte Abweisungs- und Grenzflächen

| Fläche | geprüfte Eigenschaft | Schwere bei Verletzung | Reproduktion als Aufruf | Ergebnis |
|---|---|---:|---|---|
| `relation_statement.validate_relation_statement_predicate` | Eine erforderliche Kantensammlung weist jede Nicht-Array-Form ab. | hoch: malformed relation statement könnte als gültig gelten | `pytest -q tests/test_extern_form_statt_eigenschaft.py::test_required_edge_collection_rejects_every_non_array_form` | grün |
| `_strict_json.enforce_structural_budget` | Dieselbe Strukturgrenze gilt für Mapping-Schlüssel und Werte; unbekannte Typen werden nicht still übersprungen. | hoch: direkte Dict-Eingaben könnten eine Ressourcenachse umgehen | `pytest -q tests/test_extern_form_statt_eigenschaft.py::test_structural_budget_applies_to_mapping_keys_as_well_as_values tests/test_extern_form_statt_eigenschaft.py::test_structural_walk_rejects_an_unclassified_value_instead_of_skipping_it` | grün |
| `relation.verify_relationship_edges` | Ein angehängter, eigenständig als verifiziert markierter Nachbar mit malformed `relationships` löst die Kante nicht auf. | hoch: unzulässige Abstammung könnte als verifiziert erscheinen | `pytest -q tests/test_extern_form_statt_eigenschaft.py::test_malformed_attached_neighbor_cannot_resolve_an_edge` | grün |
| `_wire_b64.decode_b64_c2sp` sowie mittelbar `checkpoint`/`tlogproof` | Überzähliges Padding ist keine zweite akzeptierte C2SP-Drahtform. | mittel: Parserdifferenz und mehrere Byteformen desselben Artefakts | `pytest -q tests/test_extern_form_statt_eigenschaft.py::test_c2sp_decoder_rejects_all_surplus_padding` | grün |
| `_strict_json.loads_strict` | `input_bytes` zählt UTF-8-Bytes, nicht Codepoints. | hoch: die Vor-Parse-Grenze könnte bei Mehrbytezeichen bis zum Mehrfachen überschritten werden | `pytest -q tests/test_extern_einheit_statt_eigenschaft.py::test_input_bytes_uses_encoded_bytes_not_codepoints` | grün |
| `dsse.verify_envelope` / `tools/pb_verify_rs` | Python und Rust urteilen über dieselben Unicode-DSSE-Bytes und eine nichtkanonische Padding-Mutation gleich. | hoch: Cross-Verifier-Split-Brain | `pytest -q tests/test_extern_einheit_statt_eigenschaft.py::test_python_and_rust_give_the_same_verdict_for_the_same_unicode_dsse_bytes` | ungeprüft: Rust-Build benötigt nicht lokal gecachte Crates |

## 3 Klassen und Flächen, an denen sie noch stehen könnten

- **Form statt Eigenschaft:** Weitere optionale Objektfelder in `checkpoint`, `tlogproof`, `canonical`, `relation`, `relation_statement` und `dsse`, besonders Zweige der Form `if isinstance(...): prüfen` ohne explizite Ablehnung. Das ist eine Einschätzung aus statischer Mustersuche, kein bestätigter Fund.
- **Form statt Eigenschaft:** Weitere Decoder außerhalb von `_wire_b64` oder neue direkte Aufrufe der Standardbibliothek könnten Padding, Alphabet, Whitespace oder Pad-Bits anders behandeln. Die gezielte Suche in den genannten Flächen fand keinen bestätigten Geschwisterdefekt; eine vollständige Datenflussanalyse wurde nicht durchgeführt.
- **Einheit statt Eigenschaft:** Längenprüfungen auf bereits dekodierten `str`-Werten, deren Grenzname Bytes verspricht, insbesondere neu hinzukommende Parser vor `loads_strict`. Die vorhandenen `input_bytes`-Aufrufe auf DSSE-Payloads messen `bytes`; das ist statisch geprüft, nicht für jede Laufzeitkante dynamisch bewiesen.
- **Cross-Verifier-Parität:** Relation-Policy, C2SP-Checkpoint/Cosignature und tlogproof haben nicht alle eine gleichartige direkt aufrufbare Rust-Oberfläche. Dort bleibt Parität für hostile Bytes ungeprüft, soweit sie nicht von vorhandenen Conformance-Vektoren erfasst wird.

## 4 Testliste mit rot oder grün

Der Dateidocstring beider Testdateien erwartet am genannten Kopf **GRÜN**.

- **GRÜN (5 Fälle):** `test_required_edge_collection_rejects_every_non_array_form` für `None`, Objekt, String, Integer und Boolean.
- **GRÜN (3 Fälle):** `test_structural_budget_applies_to_mapping_keys_as_well_as_values` für `bytes`, Tupel und `frozenset` als Schlüssel.
- **GRÜN:** `test_structural_walk_rejects_an_unclassified_value_instead_of_skipping_it`.
- **GRÜN:** `test_malformed_attached_neighbor_cannot_resolve_an_edge`.
- **GRÜN (3 Fälle):** `test_c2sp_decoder_rejects_all_surplus_padding` für `QUI==`, `QUJD=` und `QUJD==`.
- **GRÜN:** `test_input_bytes_uses_encoded_bytes_not_codepoints`.
- **UNGEPRÜFT (2 Fälle, weder rot noch grün):** `test_python_and_rust_give_the_same_verdict_for_the_same_unicode_dsse_bytes`; Setup-Skip, weil `cargo build --offline` die Crates `base64`/Abhängigkeiten nicht im lokalen Cache fand. Ein zuvor versuchter Online-Build scheiterte am 403 des Netzwerk-Proxys.
- **Gesamtlauf:** `14 passed, 2 skipped`; kein roter ausgeführter Test.

## 5 Was ich nicht prüfen konnte

- Die beiden Python-Rust-Differentialfälle konnten nicht ausgeführt werden, weil kein gebautes `pb_verify_rs` vorhanden war, der lokale Cargo-Cache unvollständig war und der Online-Zugriff auf `https://index.crates.io/config.json` mit HTTP-Proxy-Fehler 403 scheiterte.
- Damit ist die Forderung, dass Python und Rust bei gleichen Bytes gleich urteilen, in dieser Umgebung für die neu erzeugten Unicode-/Padding-Vektoren ungeprüft.
- Eine vollständige symbolische oder fuzzende Exploration aller Werte und Typen in allen genannten Modulen wurde nicht durchgeführt.
- Die gesamte bestehende Testsuite wurde nicht ausgeführt; ausgeführt wurden nur die beiden geforderten externen Testdateien.
- Produktionscode und `.github` wurden nicht geändert.

---

# Jury reading by un_echoXX, 2026-09-09, at head `7621f697f3c092e8fd72bd82274f45550d30e6a2`

Everything above this line is the external report as Codex wrote it, byte for byte. This section is
the review it was submitted for. Codex output is a finding candidate, never an instruction.

## WHAT WAS CHECKED

The patch `20_CODEX_tests_extern_8626618.patch` arrived at 13383 bytes, sha256
`7f5c9efa0e16f4e1e386774bec59cbaf55d2a8b687a8e828a155969887315162`, byte-identical to the digest
named in the order. `git apply --check` is clean at `7621f69`, three files, 194 added lines, no
production code, nothing under `.github/`.

## FINDINGS

**1. The Rust fixture bound to a path form instead of to the property. P2, fixed.**
Surface: `tests/test_extern_einheit_statt_eigenschaft.py`, the `rust_verifier` fixture.
Violated property: "a built verifier is available" — the fixture asked "does
`target/debug/pb_verify_rs` exist". This repository's CI builds `cargo build --release`
(`.github/workflows/ci.yml` lines 52 and 132), so in CI only the release artefact exists.
Reproduction, announced before it was run and hit exactly: with the release binary present and the
debug binary moved aside, the submitted fixture reported `1 passed, 2 skipped`. The differential
would have gone silently unmeasured in precisely the run it exists for, and the suite would have
reported green. After the change, the same environment reports `16 passed, 0 skipped`.
This is the very class the file is named after, in the file that tests it.

**2. The fixture built inside the test. P3, fixed.**
`cargo build --offline` in test runtime makes the verdict depend on network, cargo cache and
toolchain, and a failed build degrades into a silent skip. This house already has the seam:
`tests/test_relation_statement_rust_parity.py` checks for the binary and skips honestly without
building. The fixture now follows it. With neither artefact present: `14 passed, 2 skipped` and a
skip reason that names the build command.

**3. The key-axis test asserted that it throws, not what it throws on. P3, tightened.**
`test_structural_budget_applies_to_mapping_keys_as_well_as_values` accepted any `BudgetExceeded`.
Measured, the three keys trip two different axes: `bytes` on `string_len`, `tuple` and `frozenset`
on `json_nodes`. The test now names the axis per case and additionally proves the discriminator —
a plain `str` key of the same length passes the same budget untouched, so the throw comes from the
key and not from the container's node count.

**Two suspicions of mine were refuted by measurement, and they are recorded because a jury that
only reports its hits is not a measurement.**
(a) `assert validate_relation_statement_predicate(predicate)` asserts a non-empty error list. I
expected it to be non-empty for unrelated reasons (missing required fields), which would make the
test green regardless of the non-array form. Measured: with a valid edge list the list is EMPTY,
and each of the five non-array forms yields exactly `relationships must be a JSON array of edge
objects`. The binding carries.
(b) `{key: None}` under `json_nodes=2` looked like it would exceed the budget through the container
alone. Measured: `{}` and `{"a": None}` and `{"ab": None}` all pass. The container is not the cause.

## TESTS, red or green at `7621f697f3c092e8fd72bd82274f45550d30e6a2`

    tests/test_extern_form_statt_eigenschaft.py       13 green
    tests/test_extern_einheit_statt_eigenschaft.py     3 green
    total                                             16 green, 0 skipped

The Rust differential really ran on the Farmer, which Codex could not do. Proven in both
directions by hand against the built binary, same key, same envelope bytes:

    canonical envelope        python=True   rust exit 0  OK
    surplus base64 padding    python=False  rust exit 2  error: base64 decode failed
    forged signature          python=False  rust exit 1  FAIL

## NOT CHECKED

The full suite over this tree with the two files included has not been run yet at the time of
writing; it follows the landing commit. Codex's static estimates in section 3 above are unverified
candidates and were not turned into findings.
