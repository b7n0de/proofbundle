# Lane-Bericht — framing (L1-600-NOTE-FRAMING-01)

**Modell:** Claude Opus 5 (1M context), Modell-Kennung `claude-opus-5[1m]`. Dieses Modell hat die
gesamte Runde gerechnet — Lesen, Fix, Korpus, Orakel, Messungen und diesen Bericht. Kein Modellwechsel
waehrend der Lane.

---

## 1. Gemessener Endstand des Zweigs

Alle Werte unten sind mit `git` gegen die Basis `917edc69` GEMESSEN, nicht aus einem frueheren Lauf
plus Delta abgeleitet.

| Groesse | Wert | Messbefehl |
|---|---|---|
| Zweig | `fix/deepgate600/framing` | `git rev-parse --abbrev-ref HEAD` |
| Kopf (voll) | `defda6afba53f6c66bee49be1ebcb3816e2ff2c1` | `git rev-parse HEAD` |
| Kopf (kurz) | `defda6a` | `git rev-parse --short HEAD` |
| Commits ueber der Basis | 3 | `git rev-list --count 917edc69..HEAD` |
| Geaenderte Dateien | 12 | `git diff --name-only 917edc69..HEAD` |
| Arbeitsbaum | sauber (ausser dem ungetrackten Bericht) | `git status --porcelain=v1` |

Geaenderte Dateien:

```
src/proofbundle/anchors_rootcommit.py  |  22 +-
 src/proofbundle/checkpoint.py          | 225 ++++++++++--
 src/proofbundle/public_transparency.py |   8 +-
 src/proofbundle/tlogproof.py           |  24 +-
 tests/test_bughunt_361_never_raise.py  |  15 +-
 tests/test_go_note_differential.py     | 156 +++++++++
 tests/test_note_rahmung_kanonisch.py   | 624 +++++++++++++++++++++++++++++++++
 tools/go_note_differential/README.md   |  54 +++
 tools/go_note_differential/go.mod      |   5 +
 tools/go_note_differential/go.sum      |   2 +
 tools/go_note_differential/main.go     |  64 ++++
 tools/go_note_differential/treiber.py  |  71 ++++
 12 files changed, 1233 insertions(+), 37 deletions(-)
```

Der Bericht selbst ist bewusst NICHT eingecheckt: er nennt den Kopf, und ein Commit des Berichts
wuerde genau diesen Kopf wieder veraendern.

---

## 2. Der Fund und was gebaut wurde

**Fund:** L1-600-NOTE-FRAMING-01, P1, `class_open`. Die Rahmung signierter C2SP-Notizen war nicht
kanonisch: Trennung an der ERSTEN Leerzeile (`checkpoint.py` 269-271, dieselbe Erst-Trennung in
`_note_text_of` 402 und in der Cosignatur-Schleife 637) und stilles Ueberspringen jeder Blockzeile
ohne EM DASH + Leerzeichen (317-318). Damit hatte EINE signierte Note eine unbegrenzte Familie
byteverschiedener Formen mit `ok=True`, jede faehig, unsignierten Angreifertext mitzufuehren.

**Gebaut:** ein gemeinsamer Helfer `checkpoint._split_signed_note(signed_note, what, *,
apply_budget_cap=True) -> (note_text, sig_block)`. Er traegt den VOLLEN Rahmungsvertrag, nicht nur den
Trenner:

0. gueltiges UTF-8 (kein einzelnes UTF-16-Surrogat) und ausser U+000A kein ASCII-Steuerzeichen,
   0x7F eingeschlossen — geprueft ueber die GANZE Nachricht, wie `note.Open`;
1. Trennung am LETZTEN `"\n\n"`, **bytegenau** ueber `rfind` + Schnitt, NIE `rsplit`;
2. der Notentext ist `msg[:i+1]` und endet damit auf genau dem Zeilenumbruch, ueber den signiert
   wurde;
3. der Signaturblock ist nicht leer, endet auf `"\n"` und traegt MINDESTENS EINE Zeile;
4. JEDE Zeile beginnt mit EM DASH + Leerzeichen — kein stilles Ueberspringen;
5. jede Zeile traegt Name (nicht leer, ohne `+`) + Leerzeichen + nicht-leeres Standard-base64 mit
   mindestens 5 Nutzbytes.

Alles andere faellt als typisierter `BundleFormatError`.

**Reihenfolge im Helfer, und sie ist Teil des Vertrags:** (0) und (4) sind Scans in C ohne jede
Dekodierung → dann faellt die Zeilenkappe `_cap_signature_lines` → erst danach dekodiert (5). Die
gelandete Haertung L2-BDOS-C2SP-SIGLINES-01 ("refused before any signature is decoded or verified")
wird dadurch strikt FRUEHER wirksam als vorher, nicht schwaecher; gemessen in
`DieKappeBleibtVorDerArbeit`.

**Zwei Korrekturen unterwegs, die ich nicht verschweige — beide an DERSELBEN Grenze, und beide hat
nicht mein Nachdenken gefunden, sondern die Suite:**

1. Im ersten Zuschnitt hing die **Zeilenkappe** auch am EMITTER. Das fiel auf, weil
   `tests/test_kappe_vor_arbeit_signaturzeilen.py` seine eigene feindliche Note nicht mehr bauen
   konnte. Kein Testproblem, sondern ein Fehlgriff an der Grenze zwischen Formatregel und
   Verifikations-Budget: C2SP begrenzt die Signaturzahl nicht. → `apply_budget_cap=False` am Emitter.
2. Danach hing **"mindestens eine Signaturzeile"** ebenfalls am Emitter. Das fiel erst im VOLLEN
   Lauf auf: `tests/test_origin_quorum_rule.py::...::test_a_valid_ascii_extension_line_note_still_verifies`
   cosigniert einen blossen Notenkoerper samt Leerzeile — der dokumentierte Selbstbezeugungs-Pfad.
   "Mindestens eine Signaturzeile" ist eine Aussage ueber die FERTIGE Note, nicht ueber den Bauplatz,
   auf dem gerade die erste entsteht. → `require_signature_line=False` in `cosign_checkpoint` und
   `cosign_checkpoint_mldsa`. Das Ergebnis beider Emitter ist in jedem Fall kanonisch, die Eigenschaft
   bleibt also unangetastet.

Dass ich dieselbe Grenze ZWEIMAL falsch gezogen habe, ist der eigentliche Befund an mir: die Frage
"gilt diese Regel fuer das fertige Artefakt oder fuer den, der es baut" habe ich beim ersten Mal
punktuell beantwortet statt als Klasse. Die neue Testklasse
`DieGrenzeZwischenEmitterUndVerifizierer` haelt jetzt beide Faelle plus die Gegenrichtung fest.

---

## 3. Inventar der Rahmungsstellen (Auflage A2)

Gesucht ueber den GANZEN Baum (`rg` ueber `\n\n`, `— `, `sig_block`, `signed_note`,
`_note_text_of`, `_cap_signature_lines`, `startswith`), nicht nur ueber `src/`. Zusaetzlich habe ich
ALLE `def verify_*` des Pakets aufgezaehlt und danach sortiert, welche ueberhaupt eine signierte Note
als Eingabe nehmen: es sind genau SECHS (`verify_checkpoint`, `verify_cosignature`,
`verify_witnessed_checkpoint`, `verify_tlog_proof`, `verify_rootcommit_v1`, `verify_rootcommit_v2sig`)
— alle sechs haengen jetzt am Helfer. Jede andere `verify_*`-Flaeche nimmt ein dict, ein Envelope oder
Bytes und hat keine Notenrahmung.

| Stelle | Art | Ergebnis |
|---|---|---|
| `checkpoint.verify_checkpoint` (war 269-271) | Trennung | ueber den Helfer |
| `checkpoint._note_text_of` (war 402) | Trennung | ueber den Helfer, jetzt `_note_body_and_sigs` |
| `checkpoint.verify_cosignature` (war 637) | ZWEITE eigene Trennung | entfaellt — Text und Block kommen aus DERSELBEN Rahmung |
| `checkpoint.verify_checkpoint` Signaturzeilenschleife (317-318) | stilles `continue` | die Zeilenregel liegt im Helfer; die Schleife sieht nur noch gepruefte Zeilen |
| `checkpoint.verify_cosignature` Signaturzeilenschleife | dito | dito |
| `checkpoint._cap_signature_lines` | Zaehlkappe | wird aus dem Helfer gerufen (Schritt b), Emit-Seite ausgenommen |
| `checkpoint.verify_witnessed_checkpoint` | ruft `verify_checkpoint` + `witness_quorum` | ueber den Helfer |
| `checkpoint.witness_quorum` | ruft `_note_text_of` / `verify_cosignature` | ueber den Helfer |
| `tlogproof.verify_tlog_proof` | ruft `verify_checkpoint` | ueber den Helfer |
| `tlogproof.parse_tlog_proof` (146) | schwaechere Rahmungspruefung der eingebetteten Note | ueber den Helfer |
| `tlogproof.parse_tlog_proof` (105) | AEUSSERE Trennung an der ERSTEN Leerzeile | **bewusst unveraendert** — das ist die Formatregel des tlog-proof selbst, nicht die der Note |
| `tlogproof.format_tlog_proof` (76) | Emit | ueber den Helfer, `apply_budget_cap=False` |
| `tlogproof.tlog_proof_for_bundle` (164) | Emit | ueber den Helfer, `apply_budget_cap=False` |
| `public_transparency.evaluate_public_transparency` (190) | eigene Trennung | ueber den Helfer, `ProofBundleError` faengt fail-closed |
| `anchors_rootcommit.parse_checkpoint_head` (65) | Trennung | ueber den Helfer; never-raise bleibt (typisierter Fehler → `None`) |
| `anchors_rootcommit._iter_our_anchor_opaques` (81) | Blockdurchlauf | ueber den Helfer; never-raise bleibt (→ leer) |
| `policy.py` 1238 (`trusted_checkpoints`) | baut eine Note, ruft `verify_checkpoint` | ueber den Helfer |
| CLI-Weg 1: `verify --trusted-checkpoint` (`cli.py` 621) | ruft `verify_checkpoint` | ueber den Helfer; gefaelschte Datei jetzt Exit 2 |
| CLI-Weg 2: `verify-proof` | ruft `verify_tlog_proof` | ueber den Helfer; gefaelschte Datei jetzt Exit 1 |
| Rust-Zweitverifizierer `tools/pb_verify_rs/src/main.rs` | — | **keine Notenflaeche**: gemessen, kein `checkpoint`-Unterkommando, kein EM DASH, keine `\n\n`-Rahmung. Seine Unterkommandos sind `content-root`, `verify-dsse`, `merkle-root`, `strict-parse`, `verify-bundle`, `verify-trust-pack-threshold`, `coverage-report`. Es gibt dort nichts zu fuehren |
| `anchors_ots`, `anchors_markovian`, `anchors_chia`, `anchors_rfc3161` | — | keine eigene Notenrahmung (gemessen: kein `\n\n`) |
| `agent_review.py` 195-203 | `\n\n` | Markdown-Offenlegungsblock, keine Note |

---

## 4. Reproducer vorher rot, nachher gruen

Der Reproducer des Gates liegt unter
`/mnt/bigstore/claude_scratch/claude-1000/-home-konrad-2bedone/d6bfd499-31fa-4fb1-8f2e-9db0696207bf/scratchpad/gate6_L1_crypto_canonicality.py`. Er ist auf zwei Arten angepasst, beide dokumentiert:
der Quellbaum ist ein Parameter (statt fest auf `pb_gate600`), eine TYPISIERTE Ablehnung wird als
Ablehnung GEZAEHLT statt als Absturz, und die Spalte `go_reference` heisst jetzt
`pyport_framing_only` — sie wurde nie von Go erzeugt, sondern von einer 12-zeiligen Python-Nachbildung
im Reproducer selbst (Owner-Anweisung 2026-09-05: der Name gehoert an die Sache gebunden). Das echte
Go-Verdikt steht in Abschnitt 5 und in `tools/go_note_differential/` — ohne das kann er den erwuenschten Endzustand gar nicht
beobachten, weil er an der ersten Ablehnung stirbt. **Beide Laeufe unten benutzen dasselbe
angepasste Skript**, einmal gegen einen unberuehrten Auscheck von `917edc69` (per `git archive`
in ein Scratch-Verzeichnis, mein Arbeitsbaum wurde dafuer nicht angefasst), einmal gegen den
Arbeitsbaum mit dem Fix.

### VORHER — Quellbaum 917edc69, unveraendert (ROT)

```
GENUINE note sha256: f40bcda567b7b271fdc1f21963e8dfaf50d9c47f775283848cf06b83b0750b62
GENUINE verify_witnessed_checkpoint ok=True log_ok=True witnesses_ok=True

=== A. arbitrary UNSIGNED content smuggled into a 'verified' checkpoint file ===
  genuine                            bytes_differ=False python.ok=True  typed_reject=-                  | pyport_framing_only=ACCEPT
  one extra blank line               bytes_differ=False python.ok=True  typed_reject=-                  | pyport_framing_only=ACCEPT
  injected plain line                bytes_differ=True  python.ok=True  typed_reject=-                  | pyport_framing_only=REJECT (errMalformedNote: non-signature line in block: 'INJECTED-UNSIGNED-LINE')
  injected FAKE checkpoint           bytes_differ=True  python.ok=True  typed_reject=-                  | pyport_framing_only=REJECT (errMalformedNote: non-signature line in block: 'evil.com/log')
  2 KiB of injected filler           bytes_differ=True  python.ok=True  typed_reject=-                  | pyport_framing_only=REJECT (errMalformedNote: non-signature line in block: 'filler')

=== B. unbounded wire-form family (N blank lines, N = 1..20) ===
  DISTINCT sha256 wire forms of ONE signed checkpoint accepted as ok=True: 24

=== C. every PUBLIC checkpoint surface accepts the smuggling form ===
  verify_witnessed_checkpoint      ok=True typed_reject=-
  verify_cosignature               ok=True typed_reject=-
  verify_checkpoint (internal)     ok=True typed_reject=-

=== D. CLI surface: proofbundle verify --trusted-checkpoint <forged> ===
  exit: 0
    [PASS] checkpoint-authenticity: checkpoint origin 'example.com/log' authenticates (root, tree_size=4) atomically
    ROOT-AUTHENTICITY: PASS (payload-signature PASS, merkle-consistency PASS, tree-context PASS, root-trust-level CHECKPOINT, safe-for-automation false)

=== E. NEIGHBOUR (fix-the-class): the same framing reaches verify_tlog_proof ===
  genuine  verify_tlog_proof ok=True
  forged   verify_tlog_proof ok=True log_ok=True witnesses_ok=True inclusion_ok=True  bytes_differ=True
  CLI verify-proof exit: 0 | => OK
```

### NACHHER — Arbeitsbaum mit dem Fix (GRUEN)

```
GENUINE note sha256: 39bb97ada2830f54833530ab85a6de17eaaea8c9d0a834c1633b73e8ccb8b218
GENUINE verify_witnessed_checkpoint ok=True log_ok=True witnesses_ok=True

=== A. arbitrary UNSIGNED content smuggled into a 'verified' checkpoint file ===
  genuine                            bytes_differ=False python.ok=True  typed_reject=-                  | pyport_framing_only=ACCEPT
  one extra blank line               bytes_differ=False python.ok=True  typed_reject=-                  | pyport_framing_only=ACCEPT
  injected plain line                bytes_differ=True  python.ok=False typed_reject=BundleFormatError  | pyport_framing_only=REJECT (errMalformedNote: non-signature line in block: 'INJECTED-UNSIGNED-LINE')
  injected FAKE checkpoint           bytes_differ=True  python.ok=False typed_reject=BundleFormatError  | pyport_framing_only=REJECT (errMalformedNote: non-signature line in block: 'evil.com/log')
  2 KiB of injected filler           bytes_differ=True  python.ok=False typed_reject=BundleFormatError  | pyport_framing_only=REJECT (errMalformedNote: non-signature line in block: 'filler')

=== B. unbounded wire-form family (N blank lines, N = 1..20) ===
  DISTINCT sha256 wire forms of ONE signed checkpoint accepted as ok=True: 1

=== C. every PUBLIC checkpoint surface accepts the smuggling form ===
  verify_witnessed_checkpoint      ok=False typed_reject=BundleFormatError
  verify_cosignature               ok=False typed_reject=BundleFormatError
  verify_checkpoint (internal)     ok=False typed_reject=BundleFormatError

=== D. CLI surface: proofbundle verify --trusted-checkpoint <forged> ===
  exit: 2

=== E. NEIGHBOUR (fix-the-class): the same framing reaches verify_tlog_proof ===
  genuine  verify_tlog_proof ok=True
  forged   verify_tlog_proof ok=False log_ok=False witnesses_ok=False inclusion_ok=False  bytes_differ=True
  CLI verify-proof exit: 1 | => FAILED
```

Der Unterschied in einer Zeile: **24 byteverschiedene Drahtformen einer Signatur wurden angenommen,
jetzt 1** — und zwar genau die echte. Beide CLI-Wege drehen von Exit 0 auf 2 bzw. 1, der Nachbar
`verify_tlog_proof` von `ok=True` auf `ok=False`. Die ECHTE Note bleibt in beiden Laeufen `ok=True`
(Antiparitaet).

---

## 5. Korpus und Orakelherkunft

**Korpus:** `tests/test_note_rahmung_kanonisch.py`, generiert statt handverlesen —
**73 Faelle** auf dem Ed25519-Arm und **82 Faelle** auf dem
ML-DSA-44-Arm, zusammen **155**.
Familien: Klartextzeile an JEDER Einfuegestelle (3) · zweites (Ursprung, Groesse, Wurzel)-Tripel an
jeder Stelle (3) · Fuellmaterial 1/4/16 KiB an jeder Stelle (9) · Leerzeilenlaeufe r = 2..24 am
Trenner (23, also ausdruecklich auch die Laeufe aus drei und mehr Umbruechen der Auflage A1) ·
Leerzeilen im Block und am Blockende (10) · ALLE Permutationen des Signaturblocks (2 bei zwei
Zeilen) · 22 Rahmungskanten (ohne Schluss-Umbruch, ohne Trenner, leerer Block, nur Text, fuehrende
Leerzeile, Steuerzeichen in Text und in Zusatzzeile, Surrogat, Junk hinter EM DASH, leerer Name,
`+` im Namen, zu kurze und leere Nutzlast, fremde wohlgeformte Zeile vorn und hinten, sowie die
sieben Faelle der zweiten Gegenlesung: vier Unicode-Leerzeichen im Namen, ZWSP und DEL als
Negativkontrollen, DEL im Notentext). Die Summe
1 + 3 + 3 + 9 + 23 + 5 + 5 + 2 + 22 ergibt die gemessenen 73 Faelle — nachgerechnet,
weil eine getippte Familienzahl genau die Art Zahl ist, die unbemerkt danebenliegt (meine erste
Fassung schrieb hier 16).
Groesster Einzelfall 16672 Byte, Summe 86926 Byte (gemessen).

**Verdikt des Orakels auf dem Ed25519-Arm: 8 angenommen, 65 abgelehnt.** Angenommen sind (gemessen):
`echt`, `leerzeilenlauf-2`, `umordnung-01`, `umordnung-10`, `fremde-wohlgeformte-zeile`, `fremde-zeile-voran`, `fremde-zeile-name-zwsp`, `fremde-zeile-name-del-0x7f` — die echte Note, der Leerzeilenlauf r=2
(das IST die echte Form), die Permutationen des Signaturblocks und die Formen mit einer zusaetzlichen
wohlgeformten Zeile eines UNBEKANNTEN Schluessels, darunter ausdruecklich die beiden
Negativkontrollen (Name mit U+200B, Name mit 0x7F) — beides nimmt die REFERENZ an, also nehmen wir es
auch an. Genau diese Menge ist die Antiparitaets-Kontrolle: ein Fix, der einfach alles ablehnt oder
der jedes Nicht-ASCII im Namen verbietet, faellt hier durch.

**Orakelherkunft — das Go-Differential ist GEFAHREN, nicht ersetzt** (Owner-Auftrag 2026-09-05).
Go war anfangs nicht installiert; ich habe es auf Owner-Anweisung ohne `sudo` nach
`/mnt/bigstore/claude_scratch/go-toolchain` geholt, den sha256 **vor** dem Entpacken geprueft und
danach das echte Differential gefahren:

| Groesse | Wert (gemessen) |
|---|---|
| Tarball | `go1.27.1.linux-amd64.tar.gz` |
| sha256 erwartet (Koordinator) | `63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445` |
| **sha256 GEMESSEN** | `63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445` — gleich, erst dann entpackt |
| Toolchain | `go version go1.27.1 linux/amd64`, ohne `sudo`, nichts unter `/usr` |
| Referenzmodul | `golang.org/x/mod v0.29.0`, `go.sum`-Pin `h1:HV8lRxZC4l2cr3Zq1LvtOsi/ThTgWnUk/y64QSs8GwA=` |
| Ergebnis ueber den Ed25519-Arm | **Faelle 73 · einig 73 · UNEINIG 0** |
| Antiparitaet | Antiparitaet: die ECHTE Note -> python.ok=True, go=ACCEPT |

Der Lauf gibt Python- und Go-Verdikt je Fall in DERSELBEN Zeile aus
(`tools/go_note_differential/treiber.py`), und derselbe Vergleich haengt als Test im Repo
(`tests/test_go_note_differential.py`, laeuft mit Toolchain, SKIPpt sonst mit Begruendung — nie
stilles Gruen).

**GELTUNGSBEREICH, eng und ausdruecklich:** `note.Open` kennt nur Ed25519 (0x01). Das Go-Differential
deckt daher **nur den Ed25519-Arm** (66 Faelle). Fuer **ML-DSA-44 (0x06) ist Go nicht zustaendig** —
dort bleibt das Spezifikations-Orakel aus Auflage A3 die Referenz (75 Faelle). Ich behaupte den
Go-Arm ausdruecklich NICHT ueber den ganzen Korpus.

**Und das Nachmessen hat sich gelohnt — ein Befund, kein Haken:** die kurze Python-Nachbildung von
`note.Open` im Reproducer des Gates (das Feld hiess dort `go_reference`) ist gegen echtes Go auf
**7 von 66** Faellen ZU MILD: `steuerzeichen-in-zusatzzeile`, `surrogat-in-zusatzzeile`,
`junk-hinter-em-dash`, `leerer-name`, `plus-im-namen`, `nutzlast-zu-kurz`, `leere-nutzlast` haette sie
ANGENOMMEN, echtes Go nennt alle sieben `malformed note`. Genau diese sieben sind die Regeln, die ueber
die reine Rahmung hinausgehen. Wer die Nachbildung fuer die Referenz genommen haette, haette sie offen
gelassen. Das ist als Meta-Test festgehalten
(`test_meta_die_kurze_nachbildung_ist_nachweislich_milder_als_die_referenz`).

**Das zweite, unabhaengige Orakel bleibt daneben bestehen:** es ist aus der Spezifikation neu geschrieben (C2SP
`signed-note.md` plus die Parse-Regeln von `note.Open`) und teilt KEINE Zeile mit proofbundle: eigener
base64-Aufruf, eigene keyID-Rechnung `SHA-256(name ‖ 0x0A ‖ 0x01 ‖ pub)[:4]`, eigene Ed25519-Pruefung
ueber `cryptography`, eigene Rahmungslogik. Es hat zwei Arme (Auflage A3): ein **Rahmungs-Orakel**
(algorithmusfrei, entscheidet auch dort, wo keine Ed25519-Signatur die Frage beantwortet — ML-DSA-44,
Leerzeilenlaeufe, Blockkanten) und ein **Signatur-Orakel** (Ed25519). Auf beiden Armen und allen 141
Faellen stimmen Implementierung und Orakel ueberein (gemessen: Signaturarm True, Rahmungsarm True, ML-DSA-Rahmungsarm True).

**ML-DSA-44** war in diesem venv verfuegbar (`cryptography` 49.0.0), der Arm lief also wirklich und
wurde nicht uebersprungen.

**Antitautologie:** der Meta-Test pflanzt die Vor-Fix-Rahmung zurueck (`_vorfix_split`) und verlangt,
dass der Korpus sie faengt; zusaetzlich wird geprueft, dass der eingepflanzte Defekt die ECHTE Note
weiterhin annahm — sonst haette der Korpus ihn aus dem falschen Grund gesehen.

**Echte Vektoren als zweite Antiparitaet:** alle **20** ausgelieferten Notenfixtures
(sum.golang.org, Rekor v2, MarkovianProtocol, rootcommit v1 und v2-sig) werden vom vollen Vertrag
weiterhin angenommen — gemessen, 20 angenommen, 0 abgelehnt.

**Bytegenauigkeit der Trennung** (der heikelste Punkt der Auflage A1) ist gemessen, nicht geglaubt:
`_split_signed_note(note)[0] == checkpoint_note(origin, size, root)` byteidentisch, und die
Gegenprobe zeigt, dass `note.rsplit("\n\n", 1)[0]` genau ein signiertes Byte verloren haette.

---

## 6. Vollsuite

```
3387 passed, 20 skipped, 938 subtests passed in 1368.16s (0:22:48)
EXIT=0
```

**Es gab mehrere volle Laeufe, und der erste war ROT — das gehoert in diesen Bericht, nicht in eine
Fussnote.** Es waren VIER volle Laeufe: (1) rot, (2) auf d453cb3 von mir ABGEBROCHEN — nicht
weil er rot war, sondern weil der Owner-Auftrag zum Go-Differential danach neue Dateien in den Baum
brachte und eine Suite-Zahl fuer Bytes, die es nicht mehr gibt, keine Aussage waere, (3) gruen auf
3f708ad (`3387 passed, 20 skipped, 938 subtests, EXIT=0`), inzwischen ueberholt durch die drei
Korrekturen der zweiten und dritten Gegenlesung, und (4) der Lauf im Kasten oben auf dem ENDKOPF
`defda6a`. Lauf 1 (auf dem Stand vor den beiden Grenz-Korrekturen oben) endete mit
`2 failed, 3378 passed, 20 skipped, 935 subtests passed in 1475.02s (0:24:35)`; die zwei roten Tests waren
`tests/test_origin_quorum_rule.py::TestNoteBodyExtensionLineNeverRaises::test_a_valid_ascii_extension_line_note_still_verifies`, `tests/test_bughunt_361_never_raise.py::Round5PolicyCanonicalRenewalCheckpoint::test_witness_quorum_mldsa_witness_returns_verdict_never_raises`.
Beide waren ECHTE Fehler meines ersten Zuschnitts, keine veralteten Tests — siehe Abschnitt 2.
Der Lauf im Kasten oben ist der auf dem ENDKOPF, also gegen genau die Bytes, die committet sind.

Kommando: `PYTHONPATH=src /home/konrad/proofbundle/.venv/bin/python -m pytest tests/ -q -p no:cacheprovider`
im Worktree `/mnt/bigstore/claude_scratch/lane_framing`. `ruff check src/proofbundle/ tests/test_note_rahmung_kanonisch.py` → `All checks passed!`.

---

## 7. Auflagen des Reviewers — Stand je Punkt

- **A1 (voller Vertrag):** umgesetzt, alle sechs Teilpunkte. Text endet auf Zeilenumbruch (per
  Konstruktion `msg[:i+1]`, mit Test) · bytegenaue Trennung ohne `rsplit` (mit Test und Gegenprobe) ·
  mindestens eine Signaturzeile am VERIFIZIERER (eigener, benannter Vertragspunkt; der Emitter ist
  ausgenommen, siehe Abschnitt 2) · UTF-8 + keine ASCII-Steuerzeichen
  ausser `\n` · Name- und Signatursyntax je Zeile, unbekannte Schluessel werden ignoriert, ein
  BEKANNTER Schluessel mit ungueltiger Signatur zaehlt nie (eigene Testklasse
  `EinBekannterSchluesselMitUngueltigerSignaturZaehltNie`, inklusive des Falls, dass er der einzige
  Traeger seiner keyID ist) · Leerzeilenlaeufe r >= 3 im Korpus (r = 2..24).
- **A2 (Inventar statt Annahme):** Tabelle in Abschnitt 3, ueber den ganzen Baum gesucht. Der
  Rust-Zweitverifizierer hat gemessen KEINE Notenflaeche — das ist ein Messergebnis, keine Annahme.
- **A3 (Go ist EIN Arm):** geschlossen mit ECHTEM Go-Lauf — go1.27.1 + `golang.org/x/mod v0.29.0`,
  73 Faelle, 73 einig, 0 uneinig, Python- und Go-Verdikt je Fall
  in einer Zeile. Der Lauf hat zwei echte Divergenzen aufgedeckt, die das Spezifikations-Orakel nicht
  sehen konnte (Abschnitt 7a) — er war also nicht Zierde, sondern die Messung, die den Fund machte. Der algorithmusfreie
  Spezifikations-Rahmungsarm bleibt daneben zustaendig fuer ML-DSA-44 (75 Faelle) und die
  Leerzeilenlaeufe; der Go-Arm wird ausdruecklich NICHT ueber den ganzen Korpus behauptet.
- **A4 (keine absolute Mengengleichheit):** die Zusicherung ist im Docstring des Helfers UND im
  Kopf des Testmoduls eingeschraenkt formuliert — sie gilt fuer `str`-Eingabe, die unterstuetzten
  Signaturtypen 0x01/0x04/0x06 und Eingaben unter `DEFAULT_BUDGET`. Ausserhalb dieser Grenzen lehnt
  proofbundle typisiert ab, wo die Referenz noch parst; das ist absichtlich strenger und wird
  weder behauptet noch geprueft.

---

## 7a. Die zweite und dritte Gegenlesung — drei Funde, alle bestaetigt und geschlossen

Nach dem Go-Lauf haben zwei weitere Pruefinsen den Helfer und den Go-Test selbst angegriffen. Alle
drei Funde waren ECHT, alle drei mit lauffaehigem Gegenbeispiel, alle drei habe ich vor dem Fix
selbst nachgefahren (`scratchpad/linse_a_nachgefahren/probe.py`), und alle drei gegen die QUELLE
geprueft (`golang.org/x/mod@v0.29.0/sumdb/note/note.go`), nicht gegen meine Erinnerung.

**Fund 1 — Unicode-Leerzeichen im Namen, die gefaehrliche Richtung (false accept).** Eine echte Note
plus eine sonst wohlgeformte Signaturzeile, deren NAME ein U+00A0 / U+2003 / U+3000 / U+2028 traegt,
wurde von `verify_checkpoint` mit `ok=True` angenommen; `note.Open` lehnt die GANZE Note ab, weil
`isValidName` mit `unicode.IsSpace` prueft (note.go:238). Mein Schnitt am ASCII-Leerzeichen liess sie
durch, die Zeile galt als unbekannter Schluessel und wurde still uebersprungen. **Geschlossen:** der
Name faellt jetzt auf `any(ch.isspace() for ch in name)`. Negativkontrolle U+200B (kein
`unicode.IsSpace`) bleibt auf beiden Seiten ANGENOMMEN — ohne sie waere auch ein zu strenger Fix
"gruen" gewesen.

**Fund 2 — 0x7F, die umgekehrte Richtung (false reject), und meine falsche Zusicherung.** Mein
`_CTRL_RE` enthielt ``, und der Docstring behauptete dazu Zeichen-fuer-Zeichen-Paritaet mit
note.Open. Beides zusammen war falsch: note.Opens Scan ist `r < 0x20 && r != '
'` (note.go:524),
0x7F faellt NICHT darunter. **Entscheidung, begruendet: 0x7F wird NICHT mehr abgelehnt, also echte
Paritaet statt behaupteter.** Das Argument "Terminal-Escape-Schutz" traegt fuer 0x7F nicht — der
Escape-Einleiter ist ESC (0x1B), liegt unter 0x20 und faellt auf BEIDEN Seiten; 0x7F ist DEL und
leitet nichts ein. Die Gegenrichtung waere teuer gewesen: eine von einem echten Log signierte Note,
die die Referenz annimmt, haetten wir abgelehnt. Der Origin bleibt unabhaengig davon strenger
(printable ASCII), und in einer Signaturzeile ueberlebt ein 0x7F die base64-Pruefung ohnehin nur im
NAMEN.

**Fund 3 — mein eigener Meta-Test bestand, wenn Go schwieg.**
`test_meta_die_kurze_nachbildung_ist_nachweislich_milder_als_die_referenz` urteilte mit
`go.get(k) != "ACCEPT"` ueber die Inhalte, ohne vorher zu verlangen, dass ueberhaupt etwas gelesen
wurde: bei leerer Go-Ausgabe ist "Schluessel fehlt" von "Go hat abgelehnt" nicht unterscheidbar.
Gemessen mit einem `main.go`, das vor der ersten Ausgabezeile `os.Exit(0)` macht: zwei der drei Tests
fielen um, dieser bestand. **Geschlossen als KLASSE, nicht als Instanz:** der Vollstaendigkeitsriegel
sitzt jetzt im Helfer `_go_lauf`, durch den JEDE Frage an Go laeuft — ein neuer Test kann ihn nicht
mehr vergessen. Mit demselben gepflanzten Defekt nachgemessen: jetzt fallen **alle drei** Tests
(vorher zwei), und nach dem Zurueckstellen sind wieder alle drei gruen.

**Was das ueber die Methode sagt, und das ist der unangenehme Teil:** mein Spezifikations-Orakel im
Testmodul trug bei Fund 1 und Fund 2 GENAU DIESELBEN zwei Fehler wie die Implementierung. Deshalb hat
das Spezifikations-Differential sie nicht gesehen — zwei Fehler in dieselbe Richtung heben sich auf.
Genau diese Restunsicherheit hatte ich im Bericht benannt, und genau sie ist eingetreten. Gefunden
hat sie erst der Lauf gegen ECHTES Go. Das Orakel ist jetzt gegen die Quelle korrigiert.

**BEKANNTE, SPEC-KONFORME ABWEICHUNG (kein Vertragsbruch, aber benannt statt verschwiegen):**
note.Open bricht hart bei mehr als 100 Signaturzeilen ab (note.go:568), `DEFAULT_BUDGET.signatures`
steht hier auf 512. Die Spezifikation ueberlaesst die Zahl ausdruecklich der Implementierung
("An implementation can reject a note with too many signatures (for example, more than 100
signatures)", note.go:38-39). Beide Werte sind konform — im Bereich **101..512 divergieren die
Implementierungen trotzdem**, und der Korpus faehrt dort bewusst nicht hin.

---

## 7b. Ein fremder Test wurde angefasst — offen gesagt

`tests/test_bughunt_361_never_raise.py::Round5PolicyCanonicalRenewalCheckpoint::test_witness_quorum_mldsa_witness_returns_verdict_never_raises`
baute seine Note OHNE abschliessenden Zeilenumbruch. Unter der kanonischen Rahmung ist das malformed
(sonst waeren `"...SIG
"` und `"...SIG"` zwei Drahtformen derselben Signatur — genau die Klasse, die
hier faellt). Ich habe **den Aufbau korrigiert, nicht die Zusicherung**: der Test prueft weiterhin, dass
`witness_quorum` mit einem ML-DSA-Zeugen ein Verdikt liefert. Zusaetzlich habe ich zwei Zeilen
ANGEHAENGT — die nicht-kanonische Fassung derselben Note muss TYPISIERT fallen (nicht roh krachen), und
die dokumentierte never-raise-Flaeche darueber (`verify_tlog_proof`) muss dafuer ein Verdikt liefern.
Der Test ist damit strenger als vorher, nicht milder. Wer das anders sieht, findet die Aenderung im
Diff als solche markiert.

---

## 8. Was ich NICHT gemessen habe

- **ML-DSA-44 gegen die Referenz.** Das Go-Differential deckt **nur Ed25519**; `note.Open` kennt
  ML-DSA-44 nicht. Fuer die 75 ML-DSA-Faelle bleibt mein Spezifikations-Orakel die Referenz, und dort
  gilt die urspruengliche Restunsicherheit weiter: es ist meine LESART der Spezifikation, und ein
  Denkfehler, der Implementierung und Orakel gleich trifft, waere im Differential unsichtbar. Fuer den
  Ed25519-Arm ist diese Unsicherheit jetzt AUSGERAEUMT (66/66 gegen die Referenz), fuer den
  ML-DSA-Arm NICHT.
- **Die Rahmung ist algorithmusfrei — das ist ein Argument, keine Messung.** Dass der Ed25519-Arm
  gegen die Referenz haelt, macht den ML-DSA-Arm plausibel (beide gehen durch denselben Helfer), aber
  bewiesen ist er dadurch nicht.
- **Der Bereich 101..512 Signaturzeilen.** Dort divergieren wir von note.Open (100 vs. 512), beide
  spec-konform; der Korpus faehrt bewusst nicht hin, also ist ueber das Verhalten dort NICHTS gemessen.
- **Wie viele Nachbarn noch offen sind, weiss ich nicht.** Drei Gegenlesungen haben drei echte Funde
  gebracht, zwei davon in Code, den ich fuer fertig hielt, und einen in meinem eigenen Meta-Test. Die
  ehrliche Lesart ist nicht "jetzt ist es dicht", sondern "die letzten drei Runden haben je etwas
  gefunden".
- **Laufzeit unter Last.** Die Wanduhrzeit der neuen Scans habe ich gemessen (echte Note 0,011 ms je
  Aufruf · 511 Zeilen unter der Kappe, voll validiert inkl. Dekodierung 2,98 ms · 5 000 Zeilen /
  0,52 MiB, ueber der Kappe abgelehnt 13,1 ms · 200 000 Zeilen / 20,8 MiB, ueber der Kappe abgelehnt
  525 ms — linear, ohne Kryptografie, gegenueber 9,9 s fuer die 74k Ed25519-Pruefungen vor der
  gelandeten Kappe). NICHT gemessen habe ich dieselben Zahlen unter Parallellast oder auf anderer
  Hardware; die Maschine trug waehrend der Runde fremde Testlaeufe.
- **Pad-Bit-Schreibweisen** in Signaturzeilen (`QUJ=` statt `QUI=`). Die gehoeren zur
  Schwesterklasse in `tests/test_wire_bytes_strict.py` und sind hier bewusst nicht im Korpus.
- **Netz.** Keine Live-Note eines laufenden Logs geholt; die Fixtures sind die eingefrorenen
  Schnappschuesse des Repos.
- **rootcommit-Semantik.** Die Rahmung ist dort jetzt kanonisch, aber der 0xFF-Anker ist nach der
  FREMDEN Spezifikation ohnehin nicht von der Notensignatur gedeckt. Der Fix macht die Annahme
  kanonisch, er gibt dort KEINE neue Signaturzusage.
- **Die Asymmetrie zwischen Emitter und Verifizierer.** Der Emitter wendet die Zeilenkappe bewusst
  NICHT an, der Verifizierer schon. Ein Betreiber kann also eine Note mit mehr Signaturzeilen als
  `DEFAULT_BUDGET.signatures` bauen, die genau dieser Build danach als malformed ablehnt. Das ist die
  richtige Trennung (Formatregel vs. Verifikations-Budget), aber ich habe NICHT gemessen, ob ein
  realer Zeugenverbund je in die Naehe dieser Zahl kommt.
- **Kein Merge, kein Push, kein Tag.** Nur dieser Worktree. Der Zweig liegt in einem verlinkten
  git-Worktree, dessen Objektspeicher unter `pb_gate600/.git` liegt; dessen Arbeitsbaum und HEAD
  wurden gemessen NICHT veraendert (beide sauber auf `917edc6`), ebenso `pb_freeze600_neu` und
  `~/2bedone` — an letzterem habe ich keine Datei angefasst.
