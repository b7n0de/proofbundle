# Zwei Lesarten desselben Dokuments, zwei Wurzeln

Messung 2 aus dem Auftrag `20260912T0849Z`. Frage von **Henri Sirkkavaara**, Befund 4 im Last
Call zu `draft-ietf-scitt-receipts-ccf-profile`.

**Owner-Entscheid 1A** (`20260912T0948Z`): Ablage als GitHub-Artefakt. Der Versand an Henri ist
ein **eigener Zug mit eigenem GO** — *„Eine Mail an eine Person im IETF-Umfeld ist ein Beitrag,
berührt BCP 78 und BCP 79."* Ausdrücklich **nicht auf die Liste**; die Chair-Ansage vom 04.09.
bindet weiter.

## Quelle

| | |
|---|---|
| Dokument | `draft-ietf-scitt-receipts-ccf-profile-04`, 24.06.2026 |
| geholt | 2026-09-13 von `https://www.ietf.org/archive/id/draft-ietf-scitt-receipts-ccf-profile-04.txt` |
| Umfang | 21295 B, sha256 `80ba0dd88f5109598952bff4ef0d8f0d83936345abd951f0e330924b149b847a` |
| Zustand | laut Datatracker am 12.09. *Waiting for AD Go-Ahead*, Last Call zu, keine -05 |

## Die beiden Lesarten, wörtlich

**Abschnitt 2.1** definiert den Baum:

    MTH({})     = HASH()
    MTH({d[0]}) = HASH(d[0])
    MTH(D_n)    = HASH(MTH(D[0:k]) || MTH(D[k:n]))

`d[i]` ist dort eine *„serialized transaction (as byte string)"*. **Wie** serialisiert wird, sagt
2.1 nicht; **Abschnitt 2.2** gibt dafür die CDDL `ccf-leaf = [bstr .size 32, tstr, bstr .size 32]`.
Die naheliegende Lesart ist deshalb: Blatt = `HASH(CBOR(ccf-leaf))`.

**Abschnitt 3.2** definiert die Verifikation:

    h := HASH( internal-transaction-hash || HASH(internal-evidence) || data-hash )

Das ist **keine Serialisierung** der drei Felder, sondern eine Verkettung roher Bytes, bei der
das **mittlere** Feld vorher einzeln gehasht wird.

## Gemessen

    GEGENPROBE: BESTANDEN -- gleich-Fall und ungleich-Fall beide richtig

     n  Urteil
     0  gleich (3.2 kennt keinen leeren Baum -- NICHT ANWENDBAR)
     1  WEICHT AB
     2  WEICHT AB
     3  WEICHT AB
     4  WEICHT AB
     5  WEICHT AB

    ERGEBNIS: 5 von 6 Faellen weichen ab (n=0 bis n=5).

Voller Lauf mit beiden Wurzeln je `n`: `LAUF_20260913.txt`.

**Für `n=0` bis `n=4` sind das 4 von 5** — genau die Zahl, die die Owner-Antwort vom 12.09. nennt.
Diese Messung ist unabhängig davon entstanden und stimmt mit ihr überein.

**Zu `e3b0c442…` bei `n=0`:** das ist der sha256 des leeren Strings und damit sonst ein typisches
Zeichen für eine *fehlgeschlagene* Messung. Hier ist er richtig — 2.1 schreibt `MTH({}) = HASH()`
wörtlich vor. Der Fall ist trotzdem als **NICHT ANWENDBAR** markiert, weil 3.2 gar keinen leeren
Baum kennt; er als „gleich" zu zählen wäre geschmeichelt.

## Was der Befund IST, und was er nicht ist

Der Unterschied sitzt **an genau einer Stelle**: dem Urbild des Blattes. Die Knotenregel
`HASH(links || rechts)` ist in beiden Lesarten identisch, und der leere Baum ist es auch. Wer mehr
behauptet, übertreibt — die Abweichung pflanzt sich von den Blättern fort, sie entsteht nicht an
mehreren Stellen.

**Nicht gemessen, mit Grund:** was eine reale CCF-Instanz rechnet. Gegenstand ist das Dokument,
nicht eine Implementierung. Eine Aussage über CCF selbst wäre aus dieser Messung nicht gedeckt.

## Kein zweiter Erzeuger

Unser eigener Merkle-Code `src/proofbundle/merkle.py` rechnet **RFC 6962** mit den Präfixen `0x00`
am Blatt und `0x01` am Knoten (Zeilen 34–41, gemessen). Der CCF-Baum hat **keine** Präfixe. Das ist
eine andere Struktur, nicht dieselbe Frage; unser Code kann eine CCF-Wurzel gar nicht rechnen, und
ihn hier einzusetzen wäre falsch, nicht sparsam.

Die CBOR-Serialisierung wird dagegen **nicht** neu geschrieben: `zwei_lesarten.py` lädt
`schreibe()` aus `tools/scitt_ccf_datahash_vector/cbor_min.py`. Liegt die Datei nicht im
Arbeitsbaum, liest das Skript sie aus dem festgenagelten Commit `4e32e83b` — ausdrücklich per
`git show` und **nicht als Kopie**, denn eine Kopie driftet und ein Ref nicht.

## Ausführen

    python3 zwei_lesarten.py

Nur Standardbibliothek. Die Eingangsdaten sind deterministisch aus sichtbaren Urbildern erzeugt
(`itx-<i>`, `ce-<i>`, `dh-<i>`), damit jeder Wert von Hand nachrechenbar ist.

**Die Gegenprobe läuft vor dem Ergebnis und bricht ab, wenn sie fällt.** Ohne sie belegt ein
durchgängiges „weicht ab" nichts: es könnte ebenso gut heißen, dass der Vergleich immer ungleich
meldet. Geprüft wird beides — derselbe Eingang muss *gleich* ergeben, ein geänderter *ungleich*.

## Zielablage

`tools/scitt_ccf_merkle_lesarten/` neben dem Schwesterwerkzeug. **Noch nicht gelandet**: die Bahn
proofbundle ruht unter `RELEASE_NACHLAUF_601`.

## Fangnachweis — und er hat meine Ansage widerlegt

`fangnachweis.py` pflanzt sechs Defekte in `zwei_lesarten.py` und misst, ob sie auffallen. Jede
Mutation trägt einen **Pflanznachweis** (`assert neu != orig`): ohne ihn meldet `str.replace()`
stillschweigend Erfolg, wenn das Muster nicht passt.

**Erster Lauf: angesagt 4 ZÄHLT, gemessen 3.** `A2` (das innere `HASH(internal-evidence)` aus
Lesart 3.2 entfernt) rutschte durch. Der Grund ist schärfer als der Defekt: die Messfläche war nur
die **Zahl** der Abweichungen — und A2, A5, A6 lassen diese Zahl bei 5 stehen. `A3` wurde obendrein
nur gefangen, weil das Skript *abstürzte*, nicht weil es etwas maß.

**Die Klasse:** ein Prüfer, der zwei Lesarten **gegeneinander** hält, ist blind gegen jeden Fehler,
der **beide gleich** trifft. Das liegt an der Bauart, nicht an mangelnder Sorgfalt, und schärferes
Hinsehen behebt es nicht.

**Die Härtung ist deshalb keine schärfere Regel, sondern eine zweite, unabhängige Größe:** die
Wurzelwerte selbst gehören in die Messfläche. Sie binden das Ergebnis an feste Bytes statt an einen
Vergleich. Neue Ansage vor dem zweiten Lauf: **6 ZÄHLT von 6** — gemessen **6 von 6**, die Ansage
traf. Protokoll: `FANGNACHWEIS_LAUF_20260913.txt`.

**Was weiterhin NICHT MESSBAR ist, mit Grund:** ob unsere Wurzeln die *richtigen* sind. Der Entwurf
nennt keine Testvektoren, und eine fremde Implementierung liegt hier nicht vor. Der Nachweis zeigt,
dass der Prüfer auf Änderungen reagiert — nicht, dass er das Dokument richtig liest.
