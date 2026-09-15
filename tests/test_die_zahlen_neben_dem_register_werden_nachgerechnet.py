"""Eine Zahl neben einer wachsenden Menge veraltet lautlos — also wird sie nachgerechnet.

FUND, Codex 4000296671 (P2). Das signierte Register `audit_artifacts/findings_register_361.json`
traegt 21 Eintraege und endet auf N21, waehrend `audit_artifacts/600/README.md` an zwei Stellen
weiter 20 nannte — einmal in der Prosa ueber den Traeger, einmal in der Zeile, die das
release-entscheidende C12.2-Urteil traegt. Der hinzugefuegte Eintrag verschob die genannte
Pruefgrenze, ohne die abhaengige Zahl mitzunehmen.

DIE KLASSE steht in DIESEM DOKUMENT bereits ueber sich selbst geschrieben, ein paar Zeilen unter
der falschen Zahl: "A number beside a growing set goes stale in silence — the class this document
names about others and missed about itself." Damals war es die Zahl der gescannten Dokumente,
49 statt 53. Jetzt dieselbe Klasse, dieselbe Datei, eine andere Zahl. Eine Klasse, die man nur
BESCHREIBT, faengt nichts.

DESHALB STEHT DIE ZAHL JETZT UNTER EINEM RIEGEL statt unter einer Mahnung. Dieser Vertrag rechnet
sie aus dem Register aus und haelt sie gegen das, was die Prosa sagt. Wer einen Eintrag hinzufuegt,
sieht die Abweichung hier, nicht erst in einem fremden Review.
"""
from __future__ import annotations

import json
import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
REGISTER = REPO / "audit_artifacts" / "findings_register_361.json"
README = REPO / "audit_artifacts" / "600" / "README.md"


def _gemessen() -> dict:
    if not REGISTER.is_file():
        pytest.skip(f"NICHT MESSBAR: {REGISTER} fehlt")
    f = json.loads(REGISTER.read_text(encoding="utf-8"))["findings"]
    zu = [x for x in f if x.get("status") == "closed"]
    hoch_offen = [x for x in f
                  if x.get("severity") in ("P0", "P1") and x.get("status") != "closed"]
    return {"gesamt": len(f), "zu": len(zu), "offen": len(f) - len(zu),
            "hoch_offen": len(hoch_offen)}


def _text() -> str:
    if not README.is_file():
        pytest.skip(f"NICHT MESSBAR: {README} fehlt")
    return README.read_text(encoding="utf-8")


def abweichungen(text: str, g: dict) -> list[str]:
    """Welche genannten Zahlen weichen von den gemessenen ab? EIN Pruefer fuer beide Richtungen."""
    raus = []
    m = re.search(r"(\d+) entries, (\d+) closed, (\d+) open", text)
    if not m:
        raus.append("der Satz ueber den Traeger ist nicht auffindbar")
    elif tuple(int(x) for x in m.groups()) != (g["gesamt"], g["zu"], g["offen"]):
        raus.append(f"Prosa nennt {m.groups()}, gemessen ({g['gesamt']}, {g['zu']}, {g['offen']})")
    r = re.search(r"PASS via C12\.2 — (\d+) findings evaluated", text)
    if not r:
        raus.append("die C12.2-Zeile ist nicht auffindbar")
    elif int(r.group(1)) != g["gesamt"]:
        raus.append(f"Release-Zeile nennt {r.group(1)}, Register traegt {g['gesamt']}")
    return raus


def test_die_prosa_nennt_die_gemessenen_zahlen():
    """[ZAEHLT] Der Fund selbst: drei Zahlen in einem Satz, aus dem Register gerechnet."""
    offen = [x for x in abweichungen(_text(), _gemessen()) if "Prosa" in x or "Traeger" in x]
    assert not offen, offen


def test_die_release_zeile_nennt_die_gemessene_zahl():
    """[ZAEHLT] Die Zeile, die das release-entscheidende Urteil traegt, zaehlt doppelt."""
    offen = [x for x in abweichungen(_text(), _gemessen()) if "C12.2" in x or "Release" in x]
    assert not offen, offen


def test_die_zusicherung_0_offene_P0_P1_stimmt_noch():
    """[ZAEHLT] Die Aussage selbst, nicht nur die Zahl daneben."""
    g = _gemessen()
    assert g["hoch_offen"] == 0, f"{g['hoch_offen']} offene P0/P1 im Register — die Zusicherung faellt"
    assert "0 open P0/P1" in _text()


def test_FANG_eine_veraltete_zahl_faellt_hier_durch():
    """[ZAEHLT] Gegenrichtung am ECHTEN Text: genau der gemeldete Zustand, wiederhergestellt.

    Die erste Fassung baute sich eine Zeichenkette und verglich sie mit sich selbst — gruen, ohne
    den Pruefer je auf den echten Text zu lassen. Zweimal heute dieselbe Form, deshalb hier
    ausdruecklich: genommen wird die echte Datei, die Zahl auf den Stand VOR dem Fix zurueckgedreht,
    und der Pruefer MUSS das melden.
    """
    g, t = _gemessen(), _text()
    assert abweichungen(t, g) == [], "Vorbedingung: der heutige Text stimmt"
    vorher = t.replace(f"{g['gesamt']} entries, {g['zu']} closed, {g['offen']} open",
                       f"{g['gesamt'] - 1} entries, {g['zu']} closed, {g['offen'] - 1} open", 1)
    vorher = vorher.replace(f"PASS via C12.2 — {g['gesamt']} findings evaluated",
                            f"PASS via C12.2 — {g['gesamt'] - 1} findings evaluated", 1)
    assert vorher != t, "die Ruecknahme hat nichts veraendert — dann misst dieser Fall nichts"
    gemeldet = abweichungen(vorher, g)
    assert len(gemeldet) == 2, f"erwartet zwei Abweichungen, gemessen {gemeldet}"


def test_der_letzte_eintrag_ist_der_hoechste():
    """[GETRENNT] Eine Luecke in der Nummerierung waere eine andere Klasse, hier nur benannt."""
    if not REGISTER.is_file():
        pytest.skip(f"NICHT MESSBAR: {REGISTER} fehlt")
    ids = [x["id"] for x in json.loads(REGISTER.read_text(encoding="utf-8"))["findings"]]
    nummern = [int(i[1:]) for i in ids if i[1:].isdigit()]
    assert nummern == sorted(nummern), f"die Kennungen stehen nicht in Reihenfolge: {ids}"
