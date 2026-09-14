"""`docs/register/G1.md` ist NACH AUSSEN GEBUNDEN und darf sich nicht bewegen.

WOZU, und der Anlass ist mein eigener Fehler vom 14.09.2026. `docs/register/G1.md` traegt 3669
Byte, `audit_artifacts/600/register_evidence/G1.md` 3670 — ein Zeilentrenner am Dateiende. Ich
habe die Differenz fuer einen Defekt gehalten und die Kopie an das Zitat angeglichen. Sie ist
KEIN Defekt: die 3669-Byte-Fassung wurde am 12.09.2026 per Mail nach aussen gegeben, ihr sha256
`9cc2181744900fbb535666873356968cb486c08c0982512da1e8651229941830` ist beim Empfaenger. Wer die
Datei angleicht, zieht ihren Digest auf `9c013e50…` und bricht eine Zusage, die das Haus nicht
mehr einseitig aendern kann.

DIE ABWEICHUNG IST GEWOLLT und wird im Register begruendet. Beide Seiten sind richtig:
  `register_evidence/G1.md` 3670 B  — woertliches Byte-Zitat aus RESTRISIKO_600.md, an seinen
                                      byte_range gebunden, vom Erzeuger geschrieben
  `docs/register/G1.md`     3669 B  — die nach aussen gegebene Fassung, an die Mail gebunden

WAS DIESER VERTRAG DESHALB PRUEFT: nicht Gleichheit, sondern UNVERAENDERLICHKEIT der aeusseren
Fassung. Er ist die Klammer, die meinen Fehler beim naechsten Mal vor dem Commit faengt.
"""
from __future__ import annotations

import hashlib
import pathlib

WURZEL = pathlib.Path(__file__).resolve().parents[1]
AUSSEN = WURZEL / "docs" / "register" / "G1.md"
ZITAT = WURZEL / "audit_artifacts" / "600" / "register_evidence" / "G1.md"

#: Gemessen am 14.09.2026 an origin/main; identisch mit dem per Mail versendeten Artefakt.
GEBUNDEN_SHA = "9cc2181744900fbb535666873356968cb486c08c0982512da1e8651229941830"
GEBUNDEN_BYTES = 3669


def test_die_aeussere_fassung_traegt_ihren_versendeten_digest():
    """[ZAEHLT] Der Digest ist beim Empfaenger — er darf sich hier nicht bewegen."""
    roh = AUSSEN.read_bytes()
    ist = hashlib.sha256(roh).hexdigest()
    assert ist == GEBUNDEN_SHA, (
        f"{AUSSEN.relative_to(WURZEL)} traegt jetzt sha256 {ist} bei {len(roh)} Byte, gebunden "
        f"ist {GEBUNDEN_SHA} bei {GEBUNDEN_BYTES} Byte. Diese Fassung wurde am 12.09.2026 nach "
        f"aussen gegeben; eine Aenderung hier bricht eine Zusage, die nicht einseitig "
        f"zurueckgenommen werden kann. Wenn die Angleichung an das Zitat gemeint war: sie ist "
        f"ausdruecklich NICHT gewollt.")


def test_die_abweichung_zum_zitat_besteht_und_ist_genau_ein_zeilentrenner():
    """[ZAEHLT] Die Differenz ist gewollt. Waere sie weg, haette jemand eine Seite angeglichen."""
    a, z = AUSSEN.read_bytes(), ZITAT.read_bytes()
    assert a != z, (
        "die aeussere Fassung und das Byte-Zitat sind byte-gleich geworden — eine der beiden "
        "Seiten wurde angeglichen. Beide sollen unterschiedlich bleiben.")
    assert a.rstrip(b"\n") == z.rstrip(b"\n"), (
        "die Differenz ist NICHT mehr nur das Zeilenende — der Inhalt weicht ab, und das ist "
        "ein echter Fund statt der gewollten Abweichung.")
    assert len(z) - len(a) == 1, f"erwartet ein Byte Unterschied, gemessen {len(z) - len(a)}"
