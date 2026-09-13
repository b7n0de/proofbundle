# Go-Differential gegen `golang.org/x/mod/sumdb/note`

Dieses Verzeichnis faehrt den Mutationskorpus aus `tests/test_note_rahmung_kanonisch.py` gegen die
**Referenzimplementierung** des Formats — `note.Open` aus `golang.org/x/mod/sumdb/note` — statt gegen
eine Nachbildung.

## Warum

`tests/test_note_rahmung_kanonisch.py` misst gegen ein aus der Spezifikation NEU GESCHRIEBENES
Python-Orakel. Das ist stark, aber es bleibt eine **Lesart** der Spezifikation: ein Denkfehler, der
Implementierung und Orakel gleichermassen trifft, hebt sich in einem Differential auf und wird
unsichtbar. Nur die Referenz selbst schliesst diese Luecke.

**Dass die Sorge berechtigt war, ist gemessen.** Der Reproducer des Gates trug eine kurze
Python-Nachbildung von `note.Open` (Feld hiess `go_reference`, prueft nur die Rahmung). Gegen echtes Go
gefahren war sie auf **7 von 66** Faellen zu mild — `steuerzeichen-in-zusatzzeile`,
`surrogat-in-zusatzzeile`, `junk-hinter-em-dash`, `leerer-name`, `plus-im-namen`, `nutzlast-zu-kurz`,
`leere-nutzlast`: alle sieben nimmt die Nachbildung an, echtes Go nennt alle sieben `malformed note`.

## Geltungsbereich, eng

`note.Open` kennt **nur Ed25519** (Algorithmusbyte 0x01). Dieses Differential misst deshalb
ausschliesslich den Ed25519-Arm, gegen das Praedikat "Rahmung kanonisch UND mindestens eine Signatur
eines bekannten Schluessels verifiziert" — dasselbe Praedikat wie `verify_checkpoint(...)["ok"] is True`.
Fuer **ML-DSA-44 (0x06) ist Go nicht zustaendig**; dort bleibt das Spezifikations-Orakel in
`tests/test_note_rahmung_kanonisch.py` die Referenz. Dieses Verzeichnis behauptet darueber nichts.

## Fahren

```
# Toolchain ohne sudo, irgendwo im Benutzerraum:
curl -fsSLO https://go.dev/dl/go1.27.1.linux-amd64.tar.gz
sha256sum go1.27.1.linux-amd64.tar.gz          # VOR dem Entpacken pruefen
tar -xzf go1.27.1.linux-amd64.tar.gz
export PATH="$PWD/go/bin:$PATH"

# als Test (skippt sauber, wenn keine Toolchain da ist):
PYTHONPATH=src python -m pytest tests/test_go_note_differential.py -q

# oder als Tabelle, Python- und Go-Verdikt je Fall in EINER Zeile:
PYTHONPATH=src python tools/go_note_differential/treiber.py
```

## Gemessen am 2026-09-05

| Groesse | Wert |
|---|---|
| Go | `go version go1.27.1 linux/amd64` |
| Modul | `golang.org/x/mod v0.29.0` (`go.sum`-Pin `h1:HV8lRxZC4l2cr3Zq1LvtOsi/ThTgWnUk/y64QSs8GwA=`) |
| Tarball sha256, GEMESSEN | `63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445` |
| Faelle (Ed25519-Arm) | 66 |
| einig | 66 |
| uneinig | **0** |
| Antiparitaet | die echte Note: `python.ok=True`, `go=ACCEPT` |
