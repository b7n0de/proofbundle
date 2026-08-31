# CAP-1 — eine unabhaengige Umsetzung und eine gemessene Mehrdeutigkeit

Zwei Verifier fuer `draft-hillier-coverage-attestation-00` (CAP-1), geschrieben aus dem
Prosatext des Entwurfs, plus ein Probenpaket zu einer Stelle, an der der Entwurf schweigt.

**Nichts hiervon ist veroeffentlicht.** Ein Beitrag an die SCITT-Liste faellt unter BCP 78
und BCP 79 und ist eine Owner-Entscheidung.

## Warum es das gibt

Abschnitt 7.3 des Entwurfs, woertlich:

> *All three are the work of the author, so the class is implementation independent rather
> than author independent … An implementation by an unaffiliated party is the most useful
> contribution a reader could make to this work.*

## Was hier steht

| Datei | Rolle |
|---|---|
| `py/cap1_verify.py` | erste Umsetzung, Python-Standardbibliothek |
| `rs/` | zweite Umsetzung, Rust, ohne Abhaengigkeiten, mit eigenem JSON-Leser |
| `sonden.py` | erzeugt die Sonden aus dem Baum des Autors, kopiert seine Dateien nicht |
| `lauf.py` | laeuft drei Lesarten gegen die Sonden |
| `run.sh` | ein Einstiegspunkt |

Beide Umsetzungen sind aus den Abschnitten 4, 4.1, 4.2, 4.3, 5 und 6 geschrieben, mit den
Feldnamen aus `CAP-1.schema.json`, das Abschnitt 4 zur normativen Form erklaert.
`verify.mjs`, `verify.py`, `verify.html`, `run.mjs` und `mutate.mjs` des Autors wurden
NICHT gelesen und NICHT uebersetzt — wer sie abschreibt, misst dieselbe Lesart zweimal.

## Ausfuehren

    ./run.sh /pfad/zu/certisyn-drafts/cap-1

Baum: `https://github.com/Certisyn-Inc/certisyn-drafts`, Commit `0980d32`,
zu klonen mit `core.autocrlf=false`.

Python 3 genuegt. Fehlt `cargo`, meldet der Lauf die strenge Lesart als `-` statt als gruen.

## Was gemessen wurde

**Uebereinstimmung, 15 von 15.** Beide Umsetzungen stimmen auf allen fuenfzehn Vektoren mit
der Konformitaetsklasse ueberein — und in der exakten Menge der gefeuerten Regeln mit dem
aufgezeichneten `runs/conformance_run.json` des Autors, einschliesslich der Doppelung bei
NC-05 (R1 und R5).

**Eine Mehrdeutigkeit.** CAP-1 sagt nichts ueber doppelte Namen in einem JSON-Objekt.
RFC 8259 Abschnitt 4 sagt `SHOULD be unique` und nennt das Verhalten bei Verletzung
ausdruecklich *unpredictable*. Drei gleichermassen konforme Leser beurteilen dieselben
Bytes verschieden:

| Sonde | last-wins | first-wins | streng |
|---|---|---|---|
| `S10` PV-03, doppeltes `integrity.complete` (true, dann false) | CONFORMS | REFUSED (R7) | JSON-Fehler |
| `S09` PV-01, doppeltes `eligible` (6, dann 13) | REFUSED (R1) | CONFORMS | JSON-Fehler |

`last-wins` ist auch das gemessene Verhalten des Referenzverifiers des Autors.

**Positivkontrollen.** `K1` und `K2` sind unveraenderte Vektoren und muessen ueberall
angenommen werden; `K3` bricht R1 einfach und muss ueberall verweigert werden. Zeigen sie
das nicht, misst der Lauf nichts.

## Ehrliche Grenzen

* Der `first-wins`-Leser ist SIMULIERT (`object_pairs_hook`), kein gemessener Fremdparser.
  Mit echten Umsetzungen gemessen sind `last-wins` und `streng`.
* Beide Umsetzungen stammen vom SELBEN Verfasser. Sie teilen keine Zeile und keinen Parser,
  aber eine geteilte Fehllesart des Prosatexts waere fuer beide unsichtbar. Was sie leisten,
  ist Unabhaengigkeit vom AUTOR DES ENTWURFS, nicht voneinander.
* Ob die Mehrdeutigkeit im Faden bereits gemeldet ist, ist NICHT MESSBAR: die Suche nach
  `coverage` meldet 129 Treffer, der Archivzugang ist von diesem Host aus gesperrt.
  Belegbar ist nur, dass sie nicht unter den fuenf bekannten Funden steht.
* Ein eigener Defekt auf dem Weg: die erste Fassung des Rust-Lesers akzeptierte die
  fuehrende Null (`04`), was RFC 8259 verbietet. Die eigene Sonde fand es, und es sah
  zuerst wie eine Abweichung des fremden Dokuments aus.
