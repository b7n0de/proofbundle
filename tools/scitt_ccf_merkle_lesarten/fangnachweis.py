#!/usr/bin/env python3
"""Fangnachweis fuer zwei_lesarten.py — pflanzt Defekte und misst, was auffaellt.

WARUM DAS NOETIG IST: zwei_lesarten.py meldet "5 von 6 Faellen weichen ab". Ein Messwerkzeug,
das immer dasselbe sagt, saehe genauso aus. Dieser Nachweis pflanzt Defekte in den Pruefer und
misst, ob sie das Ergebnis veraendern.

ANSAGE VOR DEM LAUF (aus dem gemessenen Grundzustand abgeleitet, nicht geraten):
  ERSTER LAUF, Ansage 4 ZAEHLT / 2 GEGEN — GEMESSEN 3 / 3. Die Ansage traf NICHT.
  A2 rutschte durch, weil nur die ZAHL der Abweichungen gemessen wurde.
  NACH DER HAERTUNG (Wurzeln gehoeren zur Messflaeche): ANGESAGT 6 ZAEHLT / 0 GEGEN.
  ZAEHLT = der Defekt veraendert das, WAS DAS SKRIPT MELDET (Urteilszeile, Gegenprobe
           ODER eine Wurzel).
  GEGEN  = der Defekt bleibt in der gemessenen Flaeche unsichtbar. Nach der Haertung
           duerfte es keinen solchen Fall mehr geben; bleibt einer, ist ER der Befund.

PFLANZNACHWEIS: jede Mutation prueft mit `assert neu != orig`, dass sie ueberhaupt gegriffen
hat. Ohne diese Zeile meldet str.replace() stillschweigend Erfolg, wenn das Muster nicht passt —
genau daran hat ein frueherer Nachweis dieser Sitzung "1 von 8" statt "3 von 9" gemeldet.
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys
import tempfile

QUELLE = pathlib.Path(__file__).resolve().parent / "zwei_lesarten.py"

# (Name, alt, neu, angesagte Klasse, warum)
DEFEKTE = [
    (
        "A1 Blatt-Urbilder gleichgesetzt",
        "    serialisiert = CBOR.schreibe([",
        "    return blatt_hash_b(b)\n    serialisiert = CBOR.schreibe([",
        "ZAEHLT",
        "Lesart 2.1 rechnet dann dasselbe wie 3.2 — die Abweichung muss auf 0 fallen.",
    ),
    (
        "A2 inneres HASH in Lesart 3.2 entfernt",
        '+ H(b["internal_evidence"].encode("utf-8"))',
        '+ b["internal_evidence"].encode("utf-8")',
        "ZAEHLT",
        "3.2 verlangt HASH(internal-evidence) woertlich. Ohne das Hash ist es eine andere "
        "Lesart — die Wurzeln aendern sich, die Abweichungszahl bleibt aber 5. Ansage "
        "ZAEHLT nur, wenn das Skript es MELDET; sonst faellt der Fall auf GEGEN zurueck.",
    ),
    (
        "A3 k-Grenze verschoben",
        "    while k * 2 < n:",
        "    while k * 2 <= n:",
        "ZAEHLT",
        "Die Baumform kippt (k muss die groesste Zweierpotenz mit k < n sein). Bei n=2 und "
        "n=4 wird die Aufteilung leer — das muss sichtbar werden.",
    ),
    (
        "A4 Gegenprobe entschaerft",
        '    return True, "gleich-Fall und ungleich-Fall beide richtig"',
        '    return True, "immer gruen"',
        "ZAEHLT",
        "Die Gegenprobe ist der einzige Schutz davor, dass 'weicht ab' bedeutungslos wird. "
        "Ihre Begruendungszeile steht in der Ausgabe; wird sie beliebig, ist das sichtbar.",
    ),
    (
        "A5 RFC-6962-Praefixe in BEIDEN Lesarten",
        "    return H(mth(blatt_hashes[:k]) + mth(blatt_hashes[k:]))",
        '    return H(b"\\x01" + mth(blatt_hashes[:k]) + mth(blatt_hashes[k:]))',
        "ZAEHLT",
        "Aendert JEDE Wurzel ab n=2, aber symmetrisch in beiden Lesarten — die Zahl der "
        "Abweichungen bleibt 5. Der Pruefer kann das nicht sehen, weil er Lesarten "
        "VERGLEICHT statt gegen feste Sollwerte zu pruefen. Benannter blinder Fleck.",
    ),
    (
        "A6 Reihenfolge der Verkettung gedreht",
        "    return H(mth(blatt_hashes[:k]) + mth(blatt_hashes[k:]))",
        "    return H(mth(blatt_hashes[k:]) + mth(blatt_hashes[:k]))",
        "ZAEHLT",
        "Dieselbe Klasse wie A5: beide Lesarten teilen die Baumregel, ein Fehler darin "
        "trifft beide gleich und hebt sich im Vergleich auf.",
    ),
]


def lauf(quelltext: str) -> tuple[int, str]:
    with tempfile.TemporaryDirectory() as d:
        p = pathlib.Path(d) / "kandidat.py"
        p.write_text(quelltext, encoding="utf-8")
        r = subprocess.run([sys.executable, str(p)], capture_output=True, text=True, timeout=120)
        return r.returncode, r.stdout + r.stderr


def kennzahlen(ausgabe: str) -> dict:
    """Die Dinge, die das Skript MELDET — daran wird gemessen, nicht am Innenleben.

    DIE WURZELN GEHOEREN DAZU, und das ist eine Haertung aus dem ersten Lauf dieses
    Nachweises: er mass nur die ZAHL der Abweichungen, und drei von sechs Defekten
    (A2, A5, A6) liessen diese Zahl bei 5 stehen. Ein Pruefer, der zwei Lesarten
    GEGENEINANDER haelt, ist gegen einen Fehler blind, der BEIDE gleich trifft --
    das ist der Bauart geschuldet und nicht durch schaerferes Hinsehen zu beheben.
    Die zweite, UNABHAENGIGE Pruefung ist deshalb der Wurzelwert selbst: er bindet
    das Ergebnis an feste Bytes statt an einen Vergleich.
    """
    m = re.search(r"ERGEBNIS: (\d+) von (\d+) Faellen weichen ab", ausgabe)
    g = re.search(r"GEGENPROBE: (\w+) -- (.*)", ausgabe)
    # je Zeile der Tabelle: n, Wurzel A, Wurzel B
    wurzeln = tuple(
        (int(a), b, c)
        for a, b, c in re.findall(r"^\s*(\d+)\s+([0-9a-f]{64})\s+([0-9a-f]{64})", ausgabe, re.M)
    )
    return {
        "abweichend": int(m.group(1)) if m else None,
        "gesamt": int(m.group(2)) if m else None,
        "gegenprobe": g.group(1) if g else None,
        "gegenprobe_grund": g.group(2).strip() if g else None,
        "wurzeln": wurzeln,
    }


def main() -> int:
    orig = QUELLE.read_text(encoding="utf-8")
    rc0, aus0 = lauf(orig)
    grund = kennzahlen(aus0)
    print("GRUNDZUSTAND, gemessen (nicht angesagt):")
    print(f"  RC={rc0}  {grund}")
    if grund["abweichend"] is None:
        print("ABBRUCH: der Grundzustand meldet keine Ergebniszeile — ohne Grundlinie ist "
              "jede Mutationszahl bedeutungslos.")
        return 2
    print()

    angesagt_zaehlt = sum(1 for d in DEFEKTE if d[3] == "ZAEHLT")
    print(f"ANGESAGT: {angesagt_zaehlt} ZAEHLT von {len(DEFEKTE)} gepflanzten Defekten.")
    print()

    zaehlt = gegen = ungepflanzt = 0
    for name, alt, neu, klasse, warum in DEFEKTE:
        if alt not in orig:
            print(f"  {name:42s} NICHT GEPFLANZT — Muster nicht im Quelltext")
            ungepflanzt += 1
            continue
        kandidat = orig.replace(alt, neu, 1)
        # PFLANZNACHWEIS: ohne diese Zusicherung meldet replace() stillschweigend Erfolg
        assert kandidat != orig, f"{name}: Mutation hat nicht gegriffen"

        rc, aus = lauf(kandidat)
        k = kennzahlen(aus)
        sichtbar = (rc != rc0) or (k != grund)
        urteil = "GEFANGEN" if sichtbar else "durchgerutscht"
        ist = "ZAEHLT" if sichtbar else "GEGEN"
        treffer = "ok" if ist == klasse else "ANDERS ALS ANGESAGT"
        if sichtbar:
            zaehlt += 1
        else:
            gegen += 1
        print(f"  {name:42s} {urteil:14s} angesagt={klasse:6s} gemessen={ist:6s} {treffer}")
        if k != grund:
            print(f"      {grund}  ->  {k}")

    print()
    print(f"GEMESSEN: {zaehlt} ZAEHLT · {gegen} GEGEN · {ungepflanzt} nicht gepflanzt "
          f"(von {len(DEFEKTE)})")
    print(f"ANGESAGT war: {angesagt_zaehlt} ZAEHLT.")
    if zaehlt == angesagt_zaehlt:
        print("Die Ansage traf.")
    else:
        print("DIE ANSAGE TRAF NICHT — das ist der Befund, nicht das Ergebnis der Defekte.")
    print()
    print("WAS DIESER NACHWEIS GELERNT HAT, und es steht hier, weil es die Ansage "
          "widerlegt hat: der erste Lauf sagte 4 ZAEHLT an und mass 3. A2 rutschte durch, "
          "weil die Messflaeche nur die ZAHL der Abweichungen war -- und A2, A5 und A6 "
          "lassen diese Zahl bei 5 stehen. Ein Pruefer, der zwei Lesarten GEGENEINANDER "
          "haelt, ist blind gegen jeden Fehler, der BEIDE gleich trifft; das liegt an der "
          "Bauart und nicht an mangelnder Sorgfalt. Die Haertung ist deshalb keine "
          "schaerfere Regel, sondern eine ZWEITE, unabhaengige Groesse: die Wurzelwerte "
          "selbst. Sie binden das Ergebnis an feste Bytes statt an einen Vergleich. "
          "Danach: 6 von 6.")
    print()
    print("WAS WEITERHIN NICHT MESSBAR IST, mit Grund: ob unsere Wurzeln die RICHTIGEN "
          "sind. Der Entwurf nennt keine Testvektoren, und eine fremde Implementierung "
          "liegt hier nicht vor. Dieser Nachweis zeigt, dass der Pruefer auf Aenderungen "
          "reagiert -- nicht, dass er das Dokument richtig liest.")
    return 0 if zaehlt == angesagt_zaehlt else 1


if __name__ == "__main__":
    sys.exit(main())
