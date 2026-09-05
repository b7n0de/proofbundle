# Lane-Bericht — renewal (deep gate 6.0.0, Fund L2-600-01)

**Modell, das wirklich gerechnet hat:** Claude Opus 5 (1M context), Modell-Kennung `claude-opus-5[1m]`.
Kein Modellwechsel waehrend dieser Lane; Anfang und Ende derselbe Rechner, dasselbe Modell.

**Maschine:** Farmer, 24 Kerne, Linux 6.8.0-138, CPython 3.10.12 aus `/home/konrad/proofbundle/.venv`.
Waehrend der gesamten Lane liefen drei weitere Bahnen auf derselben Maschine; das Lastmittel lag
zwischen 22 und 34. **Jede Rechenzeit-Zahl in diesem Bericht stammt aus `resource.getrusage`
(ru_utime + ru_stime des eigenen Prozesses), nicht von der Uhr.** Wo Uhrzeit steht, ist es
ausdruecklich gesagt — sie ist unter dieser Last nach oben verzerrt.

**Worktree:** `/mnt/bigstore/claude_scratch/lane_renewal`, Zweig `fix/deepgate600/renewal`,
Ausgangskopf `917edc695b280c6fa80e0ab2a76490ff0f30632e`. Kein anderer Baum wurde angefasst;
`/home/konrad/2bedone` wurde ausschliesslich ueber `scripts/lib/b7_befund_queue_jsonl.anhaengen()`
beschrieben.

---

## 1. Was der Fund war, und was daran nicht stimmte

`proofbundle.verify_sequence` traegt seit Finding 15b eine Schranke gegen Ueberlastung:
`budget.renewal_ats_chain = 10_000`. Sie feuert korrekt — und begrenzte trotzdem nichts, weil der
Durchlauf DAHINTER quadratisch war. Jeder Kettenanfang deckt nach RFC 4998 ALLE vorherigen
ArchiveTimeStamp, und `_cover_prior_and_data` baute diese Tokenliste fuer jeden Kettenanfang neu.

**Korrektur am Fund selbst (Auflage B3), gemessen statt ausgelegt:** `budget.within` prueft
`value <= getattr(self, dimension)`. Der groesste ZUGELASSENE Wert ist damit **10.000, nicht 9.999**.
Der urspruengliche Fund mass 9.999 und damit nicht den teuersten zugelassenen Fall. Nachgeholt, alle
drei Punkte an der Grenze:

| n | Rechenzeit VOR dem Fix, Lauf A | Lauf B | zugelassen? |
|---|---|---|---|
| 9.999 (L-1) | — | 63,577 s | ja |
| **10.000 (L)** | **59,463 s** | **54,111 s** | **ja** |
| 10.001 (L+1) | 0,002 s | 0,004 s | nein, `renewal:budget` |

Lauf A ist die Verdopplungsreihe unten, Lauf B der Kostenkurven-Riegel gegen den alten Stand
(Abschnitt 8). Die Streuung zwischen den beiden (54 bis 64 s) ist Fremdlast auf den anderen Kernen,
nicht Systematik; fuer die Aussage ist sie ohne Belang, weil die Obergrenze bei 1 s liegt.

## 2. Die Verdopplungsreihe, mit dem n je Punkt (Auflage B3)

Rechenzeit, `resource.getrusage`, Worktree `lane_renewal` auf 917edc69, Skript
`lane_renewal_belege/messreihe.py`. Der Wert "1.000 Eintraege = 0,71 s" aus dem Ausgangsbericht
entspricht meinem n=1.000 mit 0,691 s.

| n | VOR dem Fix | NACH dem Fix |
|---|---|---|
| 1.000 | 0,691 s | 0,005 s |
| 2.000 | 2,745 s | 0,008 s |
| 4.000 | 9,344 s | 0,016 s |
| 8.000 | 43,240 s | 0,034 s |
| **10.000 (Limit)** | **59,463 s** | **0,043 s** |
| Exponent (Median der log-Steigungen ueber 1.000..8.000) | **1,991** | **0,963** |

Faktor am Limit: **1383**.

**Deterministische Arbeitszaehlung** (maschinenunabhaengig, `token()`-Aufrufe, gezaehlt ueber eine
`ArchiveTimeStamp`-Unterklasse — der Shape-Guard laesst sie durch, weil `isinstance` wahr bleibt):

| n | VOR dem Fix | NACH dem Fix |
|---|---|---|
| 50 | 1.225 | 50 |
| 100 | 4.950 | 100 |
| 200 | 19.900 | 200 |
| 400 | 79.800 | 400 |

Vorher exakt `n(n-1)/2`, nachher exakt `n`. Diese Zahl haengt an keiner Maschine und an keiner Last.

## 3. Welche Loesung, und warum (Auflage B1)

**Gewaehlt: die lineare Deckungsberechnung. Die Absenkung der Schranke waere keine Behebung.**

Drei Gruende, jeder gemessen:

1. Die Absenkung laesst die quadratische FORM stehen. Sie verschiebt nur, wo es weh tut. Beim vom
   Ausgangsbericht genannten "sicheren Punkt" n≈1.000 kostet der Durchlauf bereits 0,691 s — **70 %
   der erklaerten Obergrenze von einer Sekunde**, auf einer Maschine gemessen, die schneller sein
   kann als die naechste. Fuer echten Abstand haette die Schranke auf etwa 300 gemusst.
2. Der Klassenteil dieses Auftrags haette sich selbst widersprochen: die Kostenkurve fordert einen
   Exponenten <= 1,2, und nach einer blossen Absenkung bliebe er bei 2,0. Ein Riegel, der die eigene
   Behebung als Fund meldet, ist kein Riegel.
3. Eine Schranke von 300 waere eine Aussage ueber legitime Erneuerungsgeschichten, die niemand
   gemessen hat. Der lineare Weg braucht diese Aussage nicht.

**Die Form der Behebung.** `_PraefixDeckung` fuehrt den Hash-Zustand inkrementell mit: `hashlib`-
Objekte koennen `copy()`, ein Praefix waechst nur am Ende. Je ATS wird einmal gefuettert, je
Kettenanfang eine Kopie genommen und der immer gleiche Daten-Schwanz angehaengt. Die gehashten BYTES
sind Zeichen fuer Zeichen dieselben (`_SEP.join([token je vorherigem ATS] + sorted(data_digests))`),
und die Fehlerreihenfolge — erst die Datendigests, dann die Tokens, zuletzt der Algorithmus — ist
nachgebaut, damit dieselbe Eingabe dieselbe Meldung bekommt.

Eine Zwischenstufe ist verworfen worden und steht deshalb im Code: zuerst fuehrte der Helfer alle
sieben Registry-Algorithmen mit. Das ist ordnungsgemaess, kostet aber im teuersten zulaessigen Fall
(10.000 ATS mit einer 8192-Bit-`time`) gemessen 0,224 s statt 0,013 s. Jetzt meldet der Durchlauf
genau die Kennungen der Kettenanfaenge an; eine nicht angemeldete Kennung bekommt eine typisierte
Absage statt eines Digests ueber einen unvollstaendigen Praefix.

## 4. Zwei getrennte Orakel (Auflage B2)

**(a) Das ERGEBNIS-Orakel** — `tests/test_renewal_praefix_deckung_orakel.py`, 51 Tests.
Der naive Durchlauf ist Wort fuer Wort nachgebaut und ruft `_cover_data` / `_cover_prior_and_data`,
also den Code, den der Fix NICHT angefasst hat (`renew_hashtree` benutzt ihn weiter). Verglichen wird
die VOLLSTAENDIGE Checkliste (Name, ok, Text), nicht nur `.ok`, ueber einen erzeugten Korpus von 20
Sequenzen: echte Erneuerungsketten (signiert und unsigniert, ueber sha256/sha512/sha3-256/sha384),
leere Datendigests, ungueltige Datendigests, unsortierte Datendigests, eine leere Kette am Anfang,
veralteter Algorithmus, unbekannter Algorithmus, unhashbare Algorithmus-Kennung, nicht-klein-hexes
`covered_digest` und drei Formen, in denen `token()` wirft und damit den Praefix vergiftet.
Zusaetzlich wird an JEDER Praefixlaenge und fuer JEDEN Algorithmus byte-identisch verglichen — ein
Fehler, der sich erst ab dem dritten Kettenanfang zeigt, faende ein Vergleich nur am Schluss nicht.

**Gegenprobe, dass dieses Orakel etwas faengt** (Gate-Meta-Test): fuenf gepflanzte Defekte, jeder
einzeln eingebaut und wieder entfernt, gefahren gegen GENAU den Code, der committet wird (md5
`c9a71440bd0db788b98a354b146ed1a9`, in der Sandkopie `lane_renewal_vorfix`, damit der Lane-Worktree
waehrenddessen unberuehrt bleibt):

| gepflanzter Defekt | Ergebnis |
|---|---|
| Trenner vor dem Datenschwanz weggelassen | 21 failed, 30 passed |
| Trenner zwischen den Tokens weggelassen | 17 failed, 34 passed |
| vergifteter Praefix wird verschluckt | 8 failed, 43 passed |
| Datendigests unsortiert | 3 failed, 48 passed |
| Daten-Schwanz auch bei LEERER Datenliste angehaengt | 1 failed, 50 passed |
| (wiederhergestellt) | 51 passed |

Der letzte ist der duennste — genau EIN Test faengt ihn. Das ist kein Zufall, sondern die Stelle, an
der der Korpus am schmalsten ist: nur ein Fall uebergibt eine leere Datendigest-Liste. Wer den Korpus
erweitert, faengt ihn breiter.

**(b) Die deterministische ARBEITSZAEHLUNG** statt der Uhr: siehe Tabelle in Abschnitt 2. In der
Kostenkurve wird zusaetzlich die Zahl der Python-Aufrufe (`sys.setprofile`, GC aus) je Dimension
erhoben; wo sie ueber die Reihe nicht mindestens auf das Doppelte waechst, gilt sie fuer diese
Dimension als UNEMPFINDLICH und wird nicht als Beleg benutzt — dieser dritte Zustand wird berichtet,
nicht verschwiegen.

**(c) Kreuzprobe ueber die beiden Staende.** Eine Sequenz mit 6 ATS in 4 Ketten (sha256 -> sha512 ->
sha3-256 -> sha384, mit Zeitstempel- und Hashbaum-Erneuerungen) wurde vom ALTEN Code gebaut und
beurteilt, dann vom NEUEN Code beurteilt: `ok=True` hier wie dort, Checklisten identisch, gedeckte
Digests unveraendert.

## 5. Der Klassenteil: die Kostenkurve je Budget-Dimension

`tests/test_budget_kostenkurve.py`. Die Menge der Dimensionen ist aus `VerificationBudget`
ABGELEITET (`dataclasses.fields`), nicht aufgezaehlt — eine neue Dimension ohne Last faellt auf.
Gemessen wird an L/8, L/4, L/2, L sowie an L-1, L, L+1; jeder billige Punkt als MINIMUM aus drei
Laeufen (Rauschen addiert nur).

Ergebnis nach dem Fix (`pytest -s`, Rechenzeit am Limit):

```
Dimension                Limit    CPU@L  Exp(Zeit)  Exp(Arbeit)  Arbeit empf.  Flaeche
input_bytes            8388608   0.0081       1.13         0.32          True  _strict_json.loads_strict
json_nodes              200000   0.0821       1.01         1.00          True  _strict_json.loads_strict
json_depth                  64   0.0000       0.55         0.90          True  _strict_json.loads_strict
string_len             1000000   0.0010       0.88         0.00         False  _strict_json.loads_strict
signatures                 512   0.0019       0.75         0.99          True  dsse.verify_envelope
merkle_path                256   0.0002       0.76         0.78          True  merkle.verify_inclusion
disclosures                256   0.0050       0.91         0.98          True  sdjwt.verify_sd_jwt
renewal_ats_chain        10000   0.0386       1.00         1.00          True  renewal.verify_sequence
witnesses                  256   0.0009       0.90         0.98          True  trust_pack.validate_trust_pack_predicate
int_bits                  8192   0.0045       1.53         0.00         False  merkle.verify_inclusion
```

Bestehensgrenzen als Zahlen im Test, nicht nach Ermessen: `GRENZE_S = 1.0` Rechenzeit am groessten
zugelassenen Wert, `EXPONENT_MAX = 1.2`, `RESERVE_S = 0.02` (darunter wird der Exponent berichtet,
entscheidet aber nicht — sonst meldet Messrauschen Funde).

**Warum 1,2 haelt, gemessen:** der Zeit-Exponent der beiden teuersten LINEAREN Dimensionen wurde je
9 mal erhoben, unter Volllast: `renewal_ats_chain` 0,960..1,132, `json_nodes` 0,975..1,097. Der
schlechteste von 18 Werten war 1,132.

`int_bits` ist der Fall, fuer den die Reserve existiert: die Kurve IST ueberlinear (Exponent 1,53 —
der Schiebe-Loop in `root_from_inclusion`), kostet am groessten zugelassenen Wert aber 0,0045 s. Bei
rund 1/200 der Obergrenze kann die Form der Kurve keine Ueberlastung erzeugen; sie als Fund zu melden
waere ein Fehlbefund. Der Wert steht trotzdem in der Tabelle.

**Die sechs Punkte je Dimension, mit dem n je Punkt** (Auflage B2; `zu` = zugelassen, `AB` =
abgewiesen; Rechenzeit, Baum 9168da8):

```
# Kostenkurve je Budget-Dimension, Rechenzeit (getrusage), Baum 9168da8
# GRENZE_S=1.0  EXPONENT_MAX=1.2  RESERVE_S=0.02
Dimension                                  L/8                   L/4                   L/2                     L-1                       L                       L+1
input_bytes                n=1048576:0.0011s       n=2097152:0.0020s       n=4194304:0.0051s   n=8388607:0.0090s(zu)   n=8388608:0.0067s(zu)   n=8388609:0.0000s(AB)
json_nodes                   n=25000:0.0108s         n=50000:0.0164s        n=100000:0.0357s    n=199999:0.0795s(zu)    n=200000:0.0884s(zu)    n=200001:0.0106s(AB)
json_depth                       n=8:0.0000s            n=16:0.0000s            n=32:0.0000s        n=63:0.0001s(zu)        n=64:0.0001s(zu)        n=65:0.0001s(AB)
string_len                  n=125000:0.0001s        n=250000:0.0002s        n=500000:0.0005s    n=999999:0.0009s(zu)   n=1000000:0.0009s(zu)   n=1000001:0.0010s(AB)
signatures                      n=64:0.0004s           n=128:0.0006s           n=256:0.0011s       n=511:0.0019s(zu)       n=512:0.0020s(zu)       n=513:0.0006s(AB)
merkle_path                     n=32:0.0000s            n=64:0.0001s           n=128:0.0001s       n=255:0.0003s(zu)       n=256:0.0003s(zu)       n=257:0.0000s(AB)
disclosures                     n=32:0.0007s            n=64:0.0014s           n=128:0.0027s       n=255:0.0034s(zu)       n=256:0.0051s(zu)       n=257:0.0003s(AB)
renewal_ats_chain             n=1250:0.0069s          n=2500:0.0152s          n=5000:0.0271s      n=9999:0.0628s(zu)     n=10000:0.0648s(zu)     n=10001:0.0040s(AB)
witnesses                       n=32:0.0002s            n=64:0.0002s           n=128:0.0007s       n=255:0.0015s(zu)       n=256:0.0014s(zu)       n=257:0.0007s(AB)
int_bits                      n=1024:0.0002s          n=2048:0.0005s          n=4096:0.0014s      n=8191:0.0046s(zu)      n=8192:0.0039s(zu)      n=8193:0.0000s(AB)
```

Lesehilfe: jeder Punkt trifft seinen Wert exakt — auch `input_bytes`, wo das Dokument BYTE-genau
gebaut wird (`_json_mit_genau` behauptet das nicht, es prueft es mit einem `assert len(txt) == n`).
`L+1` kostet ueberall wenig, weil dort die Schranke greift; genau dieser Kontrast zu `L` ist der
Fund, und genau deshalb steht `L` daneben statt nur `L+1`.

**Kombinierte Achsen** (Auflage B2), Obergrenze = Summe der beteiligten Einzelgrenzen:

| Kombination | Rechenzeit | Obergrenze |
|---|---|---|
| renewal_ats_chain (10.000) x int_bits (8192-Bit `.time`) | 0,7621 s | 2,0 s |
| renewal_ats_chain (10.000) x 5 Hash-Algorithmen | 0,0953 s | 2,0 s |
| merkle_path (256) x int_bits (8192 Bit) | 0,0034 s | 2,0 s |
| signatures (512) x Payload 900 kB | 0,0005 s | 2,0 s |
| input_bytes x json_depth (64) x string_len | 0,0075 s | 3,0 s |

(Dieselbe Kombination mass in einer ruhigeren Minute 0,684 s; der Unterschied ist die Fremdlast auf
den anderen Kernen, nicht der Code.)

Der teuerste ist `renewal_ats_chain x int_bits`. Seine 0,76 s bestehen zu 0,607 s aus dem
EINMALIGEN Rendern von 10.000 Zahlen mit 8192 Bit nach dezimal; das ist nicht wegzuoptimieren, weil
die dezimale Form das gedeckte Material IST. Vor dem Fix wurde sie je Kettenanfang neu gerendert.

## 6. Der falsifizierte Ausschluss in `test_structural_budget_reachability.py`

Die Begruendung dort sagte, `renewal_ats_chain` begrenze die Kette "bereits fachlich und schaerfer" —
und meinte damit auch die KOSTEN. Genau das hat die Messung widerlegt.

Der Eintrag ist NICHT ersatzlos entfernt worden, und das ist eine bewusste Abweichung vom
Auftragswortlaut. Grund, gemessen: `enforce_structural_budget` laeuft ueber `ArchiveTimeStamp`-
Instanzen HINWEG (sie sind weder `str` noch `dict` noch `list`), wuerde also nur die Listenlaenge
zaehlen — und die gegen `json_nodes = 200.000`, also **20-fach LOSER als die eigene Dimension**. Ein
ersatzloses Entfernen haette den Riegel nur gruen bekommen, indem die Flaeche eine Schranke bekommt,
die nichts schuetzt. Genau davor warnt der Kopf dieser Datei selbst.

Stattdessen zwei Aenderungen:
1. Die falsifizierte Begruendung ist ersetzt: sie nennt jetzt die Messung (10.000 zugelassen,
   59,5 s; 10.001 abgewiesen, 0,002 s) und sagt, was der alte Satz zu viel behauptete.
2. Neuer Test `test_eine_eigene_schranke_muss_ihre_KOSTEN_belegen`: ein Ausschluss von der
   generischen Schranke gilt nur noch, wenn die Dimension eine gemessene Kostenkurve hat. Das ist
   die zweite Haelfte des Belegs, und sie fehlte — dass eine ZAHL begrenzt ist, sagt nichts darueber,
   was sie kostet.

## 7. Zwei Nachbarn, als eigene Befunde eingetragen (nicht hier gefixt)

Geschrieben ueber `scripts/lib/b7_befund_queue_jsonl.anhaengen()`, danach gefaltet und auf `offen`
gesetzt (ein `anlegen` ohne Zustandsfeld erscheint in `BEFUNDE_OFFEN.md` als "unklar", nicht als
offen — nachgeholt).

**`RENEWAL-POLICY-OHNE-KETTENSCHRANKE-EINE-MILLION-ATS-OK-TRUE-01`** (wie beauftragt).
Selbst gemessen, nicht uebernommen: `evaluate_renewal_policy` nimmt n=10.000 / 10.001 / 200.000 /
1.000.000 ArchiveTimeStamp an und antwortet mit `ok=True` in 0,002 / 0,002 / 0,041 / 0,200 s. Die
Checkliste ist immer genau `['renewal:policy']` — kein Budget-Check, in keinem Fall. Dieselben
Sequenzen an der Schwesterflaeche `verify_sequence`: ab 10.001 abgewiesen. Der Verlauf ist linear,
also kein Ueberlastungsproblem; es ist eine Semantik-Frage — zwei exportierte Flaechen, dasselbe
Argument, derselbe Shape-Guard, gegensaetzliche Antwort.

**`RENEWAL-DATA-DIGESTS-OHNE-DIMENSION-MULTIPLIZIERT-DIE-ATS-SCHRANKE-01`** (zusaetzlich gefunden).
Nach dem Fix gemessen, mit 10.000 ATS am Limit: `data_digests` d=1 -> 0,042 s, d=100 -> 0,077 s,
d=1.000 -> 0,356 s, d=10.000 (650 kB) -> 3,268 s, d=50.000 (3,25 MB) -> **15,938 s**. `data_digests`
wird nur auf FORM geprueft, nie auf ANZAHL. Das ist die ehrliche Grenze dieses Fixes: die
Kalibrierungs-Invariante ist eindimensional, und eine Achse ohne Limit hat keinen "groessten
zugelassenen Wert", ueber den sie sprechen koennte. Dieselbe Klasse wie F2 im selben Reproducer
(aggregate volume).

Zusaetzlich ein `vermerk` am Elternbefund `DEEPGATE-LAUF4-L2-600-01` mit den Zahlen dieser Lane. Der
Elternbefund bleibt **offen**: die Arbeit liegt auf einem Zweig, nicht auf main.

## 8. Faengt der neue Riegel den Fund wirklich? (Gate-Meta-Test am Original)

Nicht behauptet, gefahren: eine Kopie des Baums unter
`/mnt/bigstore/claude_scratch/lane_renewal_vorfix` mit `src/proofbundle/renewal.py` vom Stand
917edc69 (md5 `72c9367707800a32b3b2f54fa8c795e0`), dieselbe neue Testdatei, 12 min 45 s Laufzeit:

```
$ PYTHONPATH=src pytest tests/test_budget_kostenkurve.py -q -k "renewal_ats_chain and not kombi"
F..F                                                                     [100%]

AssertionError: renewal_ats_chain: 54.111 s Rechenzeit am groessten zugelassenen Wert (10000),
Obergrenze 1.0 s. Die Schranke laesst mehr zu, als sie zu begrenzen behauptet — genau der Fund
L2-600-01.
    die drei Punkte um das Limit: n=9999: 63.5769 s (zugelassen) | n=10000: 54.1111 s (zugelassen)
    | n=10001: 0.0044 s (abgewiesen)

AssertionError: renewal_ats_chain: Arbeits-Exponent 2.00 > 1.2
(Zaehlung [21957668, 87665168, 350330168, 1400660168])

2 failed, 2 passed, 45 deselected in 765.69s (0:12:45)
```

Beide Kriterien schlagen an, und das zweite ohne jede Uhr: 21,9 Mio. -> 1,4 Mrd. Python-Aufrufe ueber
eine Verachtfachung der Eingabe, Exponent 2,00. Die zwei bestandenen Tests sind die, die die SCHRANKE
pruefen (erreicht die Last das Limit; ist L+1 abgewiesen) — die war nie kaputt, sie begrenzte nur
nichts.

Ehrlich dazu: n=9999 mass 63,58 s und n=10000 nur 54,11 s. Die beiden Punkte liegen ueber
`WIEDERHOLEN_UNTER_S`, werden also nur EINMAL gemessen; der Unterschied ist Fremdlast, nicht
Systematik. Fuer die Aussage ist er ohne Belang — beide liegen um den Faktor 54 bis 64 ueber der
Obergrenze.

Die Testdatei in der Kopie unterscheidet sich vom endgueltigen Stand um 21 Zeilen, alle innerhalb des
Modul-Docstrings (Hunks `@@ -35,8 +35,8 @@` und `@@ -47,10 +47,17 @@`, der Docstring endet in Zeile
61). Keine Zusicherung, keine Grenze, keine Last hat sich geaendert; Beleg
`lane_renewal_belege/diff_testdatei_vorfixlauf_vs_final.txt`.

## 9. Der Reproducer des Gates, wortwoertlich

Gefahren wurde `scratchpad/gate6_L2_budget_dos.py` in einer Kopie mit ZWEI geaenderten Pfadzeilen
(`sys.path.insert` und `git -C`), sonst Zeichen fuer Zeichen dasselbe Skript; Ablage
`lane_renewal_belege/gate6_L2_lane_renewal.py`. Die Zeiten darin sind UHRZEIT, nicht Rechenzeit, und
die Maschine trug waehrenddessen drei weitere Bahnen.

**VORHER** (`lane_renewal_belege/repro_VORHER_renewal.txt`):

```
### F1 — verify_sequence: O(n^2) INSIDE the renewal_ats_chain DoS guard (limit 10000)
  n=   500  input~ 0.06 MB  ->     0.20s  ok=False  (   3.2 s per MB of input)
  n=  1000  input~ 0.12 MB  ->     0.67s  ok=False  (   5.4 s per MB of input)
  n=  2000  input~ 0.25 MB  ->     2.82s  ok=False  (  11.2 s per MB of input)
  n=  4000  input~ 0.50 MB  ->     7.16s  ok=False  (  14.2 s per MB of input)
  n=  8000  input~ 1.01 MB  ->    34.60s  ok=False  (  34.4 s per MB of input)
  n=  9999  input~ 1.26 MB  ->    57.51s  ok=False  (  45.7 s per MB of input)
  n= 10001 (OVER the guard) ->  0.002s  :: renewal:budget=False
  => the guard is real but useless: it only refuses inputs MORE expensive than the ~57 s one it admits.
[F2-Block hier ausgelassen, siehe unten; die Auslassung ist eine Kuerzung im Zitat,
keine fehlende Messung]
### RT-04 — 1200-case hostile argument matrix over every exported verify_/evaluate_ surface
  surfaces: 21   cases: 1200   RAW (non-ProofBundleError) escapes: 0
  RT-04: fail-closed CONFIRMED
```

**NACHHER** — gefahren auf dem COMMITTETEN Stand `9168da8`, Arbeitsbaum sauber (0 getrackte
Aenderungen, das Skript druckt den Kopf selbst mit), Lastmittel 29,4
(`lane_renewal_belege/repro_NACHHER_9168da8.txt`):

```
HEAD   9168da8bfff919eed7c8e9f5ab05db66db548720
### F1 — verify_sequence: O(n^2) INSIDE the renewal_ats_chain DoS guard (limit 10000)
  n=   500  input~ 0.06 MB  ->     0.01s  ok=False  (   0.1 s per MB of input)
  n=  1000  input~ 0.12 MB  ->     0.01s  ok=False  (   0.1 s per MB of input)
  n=  2000  input~ 0.25 MB  ->     0.01s  ok=False  (   0.1 s per MB of input)
  n=  4000  input~ 0.50 MB  ->     0.05s  ok=False  (   0.1 s per MB of input)
  n=  8000  input~ 1.01 MB  ->     0.11s  ok=False  (   0.1 s per MB of input)
  n=  9999  input~ 1.26 MB  ->     0.15s  ok=False  (   0.1 s per MB of input)
  n= 10001 (OVER the guard) ->  0.006s  :: renewal:budget=False
  => the guard is real but useless: it only refuses inputs MORE expensive than the ~57 s one it admits.
[F2-Block hier ausgelassen, siehe unten; die Auslassung ist eine Kuerzung im Zitat,
keine fehlende Messung]
### RT-04 — 1200-case hostile argument matrix over every exported verify_/evaluate_ surface
  surfaces: 21   cases: 1200   RAW (non-ProofBundleError) escapes: 0
  RT-04: fail-closed CONFIRMED
```

Ein frueherer Nachher-Lauf (`repro_NACHHER_renewal.txt`, Arbeitsbaum vor den letzten
Docstring-Korrekturen) mass n=9999 mit 0,07 s. Der Unterschied zu 0,15 s ist die Fremdlast, nicht der
Code; berichtet wird der Lauf auf dem committeten Stand.

Der Schlusssatz unter F1 ist eine feste Zeichenkette im Skript, keine Messung des Laufs — die Zahlen
darueber sind die Aussage: 57,51 s -> 0,15 s, und die Kennzahl des Gates selbst (Sekunden je MB
Eingabe) faellt von 45,7 auf 0,1.

RT-04 ist der wichtige Nebenbefund: 1200 feindliche Argumente ueber 21 exportierte Flaechen, NULL rohe
Ausnahmen — der never-raise-Vertrag der Erneuerungs-Flaechen ist durch den Umbau unveraendert.

F2 (aggregate volume auf dem direct-dict-Pfad) ist vorher wie nachher offen. Anderer Fund, andere
Bahn, nicht angefasst.

## 10. Vollsuite

Gefahren auf dem EINGEFRORENEN Baum — also auf genau dem Stand, der committet wurde. Ein erster Lauf
war bei 48 % , als ich noch einen Docstring korrigiert habe; der wurde deshalb abgebrochen und
verworfen statt berichtet. Ein Lauf, der einen anderen Baum beurteilt als den, der landet, ist keine
Freigabe.

```
$ cd /mnt/bigstore/claude_scratch/lane_renewal
$ PYTHONPATH=src /home/konrad/proofbundle/.venv/bin/python -m pytest tests/ -q -p no:cacheprovider
3460 passed, 21 skipped, 939 subtests passed in 1374.06s (0:22:54)
EXIT=0
```

Die 21 Skips sind der Bestand (Repo-Kontext / optionale Extras), keiner davon neu. Von den 3460
bestandenen sind 100 neu aus dieser Lane, gezaehlt mit `--collect-only`: 51 im Ergebnis-Orakel, 49 in
der Kostenkurve. Dazu ein neuer Test in `test_structural_budget_reachability.py` (7 statt 6 in der
Datei, 2 statt 1 Subtest).

Der Baum zum Zeitpunkt des Laufs, gegen die Pruefsummen der Einfrierung geprueft:

```
$ md5sum -c frozen_md5.txt
src/proofbundle/renewal.py: OK
tests/test_budget_kostenkurve.py: OK
tests/test_renewal_praefix_deckung_orakel.py: OK
tests/test_structural_budget_reachability.py: OK
```

Zusaetzlich, weil `ruff check .` in diesem Repo ein blockierender Schritt ist: `ruff 0.15.20` ueber
die vier Dateien — `All checks passed!`.

## 11. Gemessener Endstand des Zweigs

Nicht abgeleitet, sondern abgefragt (`git rev-parse`, `git show --stat`, `git status`):

```
Zweig:          fix/deepgate600/renewal
Ausgangskopf:   917edc695b280c6fa80e0ab2a76490ff0f30632e
Endkopf:        9168da8bfff919eed7c8e9f5ab05db66db548720
Baum-Pruefwert: 02fd2dbcbfac779a2dc49c9dee3ad6b27fdca7ed
Commits ueber dem Ausgangskopf: 1
  9168da8 fix(renewal): die Ueberlastungs-Schranke der Erneuerungskette begrenzte nichts —
          10.000 zugelassene Eintraege kosteten 59,5 s, jetzt 0,04 s
Arbeitsbaum nach dem Commit: sauber (nur dieser Bericht liegt ungetrackt daneben)
```

Geaenderte Dateien in diesem Commit:

```
 src/proofbundle/renewal.py                   | 142 +++++++-
 tests/test_budget_kostenkurve.py             | 490 +++++++++++++++++++++++++++
 tests/test_renewal_praefix_deckung_orakel.py | 302 +++++++++++++++++
 tests/test_structural_budget_reachability.py |  39 ++-
 4 files changed, 961 insertions(+), 12 deletions(-)
```

Die Commit-Nachricht endet auf

```
Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01EZmkvU6eFeuFa4R3cGiBAe
```

Kein Push, kein Merge, kein Tag. `LANE_BERICHT_renewal.md` ist ABSICHTLICH nicht committet: er ist
Prozess-Meldung dieser Bahn, kein Inhalt des Pakets.

## 12. Was ich NICHT gemessen habe

Diese Liste ist keine Hoeflichkeitsfloskel. Jeder Punkt ist eine Stelle, an der jemand mehr in diesen
Bericht lesen koennte, als darin steht.

* **Eine Maschine, ein Interpreter.** Alle Zahlen stammen von Farmer (24 Kerne) unter CPython
  3.10.12. Kein anderer Interpreter, keine andere Architektur, kein PyPy. Die Bestehensgrenzen der
  Kostenkurve sind damit an EINE Referenz gebunden; auf einer deutlich langsameren Maschine ist ihre
  Reserve kleiner, als sie hier aussieht.
* **Die Maschine war nie ruhig.** Waehrend der ganzen Lane liefen drei weitere Bahnen; das Lastmittel
  lag zwischen 22 und 34 bei 24 Kernen. Rechenzeit (`getrusage`) ist dagegen weitgehend robust,
  Uhrzeit nicht — deshalb sind die Reproducer-Zahlen (Uhrzeit) nach oben verzerrt, und deshalb steht
  in den Zusicherungen keine Uhrzeit.
* **Kein Wiederholungslauf des Reproducers.** Vorher und nachher wurden je EINMAL gefahren. Die
  Verdopplungsreihe und die Kostenkurve sind wiederholt gemessen worden, der Reproducer nicht.
* **Speicher nur an EINEM Punkt gemessen.** Spitzenspeicher (`ru_maxrss`, frischer Prozess je Baum)
  bei n=4000: vorher 23,1 -> 26,4 MB (also +3,3 MB), nachher 22,9 -> 24,0 MB (+1,1 MB). Der Fix
  spart dort Spitzenspeicher, aber das ist EIN n und EIN Lauf je Baum, keine Kurve.
* **Die Kalibrierungs-Invariante ist eindimensional.** Sie sichert die Kosten am groessten
  ZUGELASSENEN Wert JE Dimension zu, plus fuenf ausgewaehlte Kombinationen. Sie sagt NICHTS ueber
  eine Achse ohne Limit — und genau so eine (`data_digests`) multipliziert hier eine begrenzte
  (15,9 s gemessen). Das ist als eigener Befund festgehalten, nicht als gedeckt behandelt.
* **Die fuenf Kombinationen sind ausgewaehlt, nicht abgeleitet.** Die Menge der EINZEL-Dimensionen
  kommt aus `VerificationBudget` und kann nicht luecken; die Menge der PAARE ist von Hand gewaehlt.
  Ein Paar, an das ich nicht gedacht habe, faellt hier nicht auf.
* **Kein voller Deep-Gate-Lauf.** Gefahren wurden der Reproducer der Linse L2, die eigenen Riegel und
  die Vollsuite dieser Bahn. Keine Jury, keine sechs Linsen, kein `WITHSTANDS_DEEPGATE`. Dieser
  Bericht ist eine Lane-Meldung, keine Freigabe.
* **F2 aus dem Reproducer ist unveraendert offen.** Der Nachher-Lauf zeigt weiterhin, dass ein
  250-MB-Bundle auf dem direct-dict-Pfad angenommen wird. Das ist ein anderer Fund und eine andere
  Bahn; ich habe ihn nicht angefasst.
* **Der Reproducer druckt am Ende von F1 einen festen Satz** ("the guard is real but useless ... ~57 s").
  Das ist eine Zeichenkette im Skript, keine Messung des aktuellen Laufs — die Messwerte darueber sind
  die Aussage.
* **Zwei meiner eigenen Warter sind blind gestorben, und das ist kein Nebensatz.** Sie warteten auf
  `^EXIT=` in der Ausgabe des ERSTEN, spaeter verworfenen Suite-Laufs. Als ich den Lauf zum Einfrieren
  des Baums abbrach, schrieb die Zeremonie `EXIT=143` OHNE Zeilenumbruch davor — die Marke klebte am
  Ende der Fortschrittszeile (`...........EXIT=143`), und `grep '^EXIT='` findet sie nicht. Die Warter
  liefen weiter, bis sie mit 144 abgeraeumt wurden. Gemessen und nachgeprueft: `vollsuite.txt` endet
  mitten in einer Fortschrittszeile und hat 0 Treffer auf `^EXIT=`; `vollsuite_frozen.txt` — der Lauf,
  der berichtet wird — endet mit der Zusammenfassungszeile und `EXIT=0` auf eigener Zeile. Die Lehre
  ist die, vor der die Koordination heute gewarnt hat: eine Datei, die mitten in einer
  Fortschrittszeile endet, ist abgebrochen, nicht laufend. Ein Warter, der nur auf ein Erfolgsmuster
  am Zeilenanfang schaut, kann das nicht unterscheiden.
* **Der Korpus ist an einer Stelle duenn.** Der gepflanzte Defekt D5 (Daten-Schwanz auch bei leerer
  Datenliste angehaengt) wird von genau EINEM Test gefangen, weil nur ein Korpusfall eine leere
  Datendigest-Liste uebergibt. Ein zweiter Fall (leere Liste, mehrere Ketten, verschiedene
  Algorithmen) waere billig und wuerde ihn breiter fangen. Ich habe ihn NICHT mehr eingebaut, weil der
  Baum zu dem Zeitpunkt fuer den Vollsuite-Lauf eingefroren war — eine Aenderung danach haette
  bedeutet, dass die Suite einen anderen Baum beurteilt als den, der committet wird.
* **Der Commit schreibt in das gemeinsame git-Verzeichnis von `pb_gate600`.** Der Worktree
  `lane_renewal` haengt technisch an `/mnt/bigstore/claude_scratch/pb_gate600/.git/worktrees/`; ein
  Commit auf meinem Zweig legt dort Objekte an und bewegt MEINE Referenz. Der ARBEITSBAUM von
  pb_gate600, sein HEAD und seine Zweige bleiben unberuehrt. Anders ist ein Commit in einem
  git-Worktree nicht moeglich; ich sage es, statt "kein anderer Baum angefasst" pauschal zu behaupten.
* **Nicht gepusht, nicht gemerged, nicht getaggt.** Der Zweig liegt lokal. Ob die Aenderung landet,
  entscheidet niemand in dieser Lane.
