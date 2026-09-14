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


#: Die EINE begruendete Abweichung, Owner-Entscheid im Nachtrag 3 zu 2155Z. Jede andere ist rot.
#: Der Schluessel ist der Dateiname, weil am Ziel ohnehin nur er zaehlt.
BEGRUENDETE_ABWEICHUNG = {"G1.md"}


def _paare() -> list:
    """Alle Namen, die unter BEIDEN Praefixen liegen. Die Menge ist gemessen, nicht gepflegt."""
    if not AUSSEN.parent.is_dir() or not ZITAT.parent.is_dir():
        return []
    return [(k, ZITAT.parent / k.name) for k in sorted(AUSSEN.parent.glob("*.md"))
            if (ZITAT.parent / k.name).is_file()]


def test_jede_NICHT_begruendete_abweichung_ist_rot():
    """[ZAEHLT] K2: die Probe kennt EINE Abweichung und meldet jede andere.

    Die fruehere Fassung prueffte nur G1 namentlich. Ein zweites Paar mit einer stillen
    Abweichung waere ihr entgangen — eine Probe, die nur ihren Anlassfall kennt, waechst nicht
    mit dem Bestand.
    """
    abweichend = [k.name for k, z in _paare() if k.read_bytes() != z.read_bytes()]
    unerlaubt = sorted(set(abweichend) - BEGRUENDETE_ABWEICHUNG)
    assert not unerlaubt, (
        f"diese Paare weichen ab, ohne dass die Abweichung begruendet waere: {unerlaubt}. "
        f"Begruendet ist ausschliesslich {sorted(BEGRUENDETE_ABWEICHUNG)} — dort ist die "
        f"aeussere Fassung seit 12.09.2026 per Mail gebunden. Fuer jedes andere Paar gilt: die "
        f"Kopie gibt nach, nie das Zitat.")


def test_die_begruendete_abweichung_besteht_noch():
    """[ZAEHLT] Gegenrichtung. Waere sie weg, haette jemand eine Seite angeglichen."""
    namen = {k.name for k, z in _paare() if k.read_bytes() != z.read_bytes()}
    fehlend = sorted(BEGRUENDETE_ABWEICHUNG - namen)
    assert not fehlend, (
        f"die begruendete Abweichung ist verschwunden: {fehlend}. Entweder wurde die aeussere "
        f"Fassung an das Zitat angeglichen — dann ist eine Aussenbindung gebrochen — oder das "
        f"Zitat an die Kopie, dann ist ein Beleg verfaelscht.")


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
    # GENAU DIESE FORM, und der Weg dahin gehoert dazu. Eine Gegenlesung am 14.09.2026 hielt
    # die fruehere Fassung `a.rstrip(b"\n") == z.rstrip(b"\n")` zusammen mit
    # `len(z) - len(a) == 1` fuer zu schwach: rstrip entferne ALLE Zeilentrenner am Ende, ein
    # Zitat mit zwei zusaetzlichen Leerzeilen komme durch. NACHGEMESSEN STIMMT DAS NICHT — mit
    # einer Laengendifferenz von genau 1 daneben kann der Unterschied nichts anderes sein als
    # ein einzelner abschliessender Zeilentrenner; der eingepflanzte Fall faellt in BEIDEN
    # Fassungen. Die Einwaende einer Gegenlesung sind Kandidaten, keine Funde.
    # Geblieben ist die Form trotzdem, aus einem schwaecheren aber echten Grund: sie sagt die
    # Eigenschaft in EINER Gleichung statt in zwei Zusicherungen, die man zusammendenken muss.
    assert z == a + b"\n", (
        f"das Zitat ist nicht mehr die aeussere Fassung plus genau einem Zeilentrenner. "
        f"Gemessen: {len(a)} B gegen {len(z)} B; die letzten vier Bytes lauten "
        f"{a[-4:].hex()} und {z[-4:].hex()}. Entweder hat sich der Inhalt geaendert, oder die "
        f"Abweichung sitzt nicht mehr am Dateiende — beides ist ein echter Fund und nicht die "
        f"gewollte Differenz.")
