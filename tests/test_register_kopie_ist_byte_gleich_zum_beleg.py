"""Die Kopie unter docs/register muss BYTE-GLEICH zum Beleg sein, den sie zitiert.

WOZU, gemessen am 14.09.2026 (Owner-Entscheid OA-7e67ca98d0, Antwort 1A): `docs/register/G1.md`
trug 3669 Byte, `audit_artifacts/600/register_evidence/G1.md` 3670. Der Unterschied war ein
einziger Zeilentrenner am Dateiende, `diff` meldete `44d43`.

WELCHE SEITE NACHGIBT, und warum das nicht beliebig ist: der Beleg ist ein woertliches Zitat aus
`RESTRISIKO_600.md`, geschrieben von `gen_findings_register.py` als `roh[von:bis]` — genau die
Bytes des Bereichs, nichts davor, nichts dahinter. Wer das Zitat beschneidet, damit ein Vergleich
gruen wird, zerstoert den Beleg; genau diese Klasse hat PR 198 schon einmal gekostet. Also gibt die
KOPIE nach, nie das Zitat.

WAS DIESER VERTRAG MISST: Bytes, nicht Text. Ein Vergleich ueber `read_text()` oder mit
`splitlines()` haette den Fund nie gesehen — der Unterschied IST das Zeilenende.

DIE GRENZE DER MESSUNG: geprueft werden nur Dateien, die unter BEIDEN Praefixen denselben Namen
tragen. Eine Kopie ohne Beleg und ein Beleg ohne Kopie fallen hier nicht auf; gemessen am
14.09.2026 traegt `docs/register` genau eine Datei und `register_evidence` 145.
"""
from __future__ import annotations

import pathlib

import pytest

WURZEL = pathlib.Path(__file__).resolve().parents[1]
KOPIE = WURZEL / "docs" / "register"
BELEG = WURZEL / "audit_artifacts" / "600" / "register_evidence"


def _paare() -> list[tuple[pathlib.Path, pathlib.Path]]:
    if not KOPIE.is_dir() or not BELEG.is_dir():
        return []
    return [(k, BELEG / k.name) for k in sorted(KOPIE.glob("*.md"))
            if (BELEG / k.name).is_file()]


def test_es_gibt_ueberhaupt_ein_paar_zu_pruefen():
    """[ZAEHLT] Ein Vertrag ueber eine leere Menge ist gruen und misst nichts."""
    assert _paare(), (
        f"keine Datei traegt denselben Namen unter {KOPIE} und {BELEG} — dieser Vertrag "
        f"haette nichts gemessen und waere trotzdem gruen geworden")


@pytest.mark.parametrize("kopie,beleg", _paare(), ids=lambda p: p.name)
def test_die_kopie_ist_byte_gleich_zum_beleg(kopie: pathlib.Path, beleg: pathlib.Path):
    """[ZAEHLT] Byteweise, nicht zeilenweise — der Unterschied war das Zeilenende."""
    k, b = kopie.read_bytes(), beleg.read_bytes()
    if k == b:
        return
    raise AssertionError(
        f"{kopie.relative_to(WURZEL)} ({len(k)} B) weicht von "
        f"{beleg.relative_to(WURZEL)} ({len(b)} B) ab. "
        f"Letzte vier Bytes: Kopie {k[-4:].hex()}, Beleg {b[-4:].hex()}. "
        f"DIE KOPIE GIBT NACH, NIE DAS ZITAT: der Beleg ist ein woertliches Byte-Zitat aus "
        f"RESTRISIKO_600.md und an seinen byte_range gebunden.")
