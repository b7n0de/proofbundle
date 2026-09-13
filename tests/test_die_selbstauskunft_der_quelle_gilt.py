"""Was die Quelle SELBST als Nicht-Fund ausweist, wird nicht als Fund gezaehlt.

HERKUNFT, Codex r3999944594 in PR 198. `RESTRISIKO_600.md` beschriftet S3 in seiner eigenen
Ueberschrift mit "NO FINDING, measured in both directions" und haelt fest, dass der vorgeschlagene
Angriff unmoeglich ist. Die Objektklassen-Datei setzte fuer denselben Eintrag `zaehlt_als_fund` auf
true, und der erzeugte Traeger wies ihn als `record_role: finding` aus und zaehlte ihn in die
ausgewiesene Population von 132.

DIE KLASSE, die der Fund aufwirft, ist BEANTWORTET statt offen. Er sagt, dasselbe koenne an jeder
anderen S-Kennung mit negativem Messergebnis stehen. Gemessen ueber alle 145 Eintraege und alle 132
Ueberschriften: S3 ist die EINZIGE, die sich selbst als Nicht-Fund ausweist. Ein Sweep, der eine
Zahl liefert, ist mehr wert als eine Vermutung ueber eine Menge.

WAS HIER GEMESSEN WIRD. Die Selbstauskunft der Quelle gegen das Feld der Objektklassen-Datei. Wo
eine Ueberschrift sich als Nicht-Fund ausweist, MUSS `zaehlt_als_fund` false sein.

EHRLICHE GRENZE. Erkannt wird eine benannte Menge von Marken in der UEBERSCHRIFT. Eine Absage, die
erst im Fliesstext drei Absaetze weiter steht, faellt durch. Eine Messung, die ergibt dass nichts
vorliegt, ist ein Beleg, aber kein Fund — diese Regel steht hier, die Erkennung ihrer Schreibweise
ist die Untergrenze.
"""
from __future__ import annotations

import json
import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
QUELLE = REPO / "RESTRISIKO_600.md"
KLASSEN = REPO / "RESTRISIKO_600_OBJEKTKLASSEN.json"

#: Marken, mit denen eine Ueberschrift sich selbst als Nicht-Fund ausweist.
_KEIN_FUND = re.compile(r"\b(?:NO FINDING|KEIN FUND|kein Fund|not a defect)\b")
_KOPF = re.compile(r"^(#{2,4}) ([A-Z]\d+)(?![0-9A-Za-z])([^\n]*)$", re.M)


#: Eine Tabellenzeile, deren erste Spalte eine Kennung traegt.
_ZEILE = re.compile(r"^\|\s*([A-Z]\d+)\s*\|([^\n]*)$", re.M)


def selbst_als_nicht_fund() -> list[str]:
    """Kennungen, deren Quelle sie SELBST als Nicht-Fund ausweist, in BEIDEN Formen.

    ZWEITE FASSUNG, und der Fund kam wieder von der Fremdfamilie (Codex r4000054883), diesmal
    gegen diesen Riegel selbst, elf Minuten nach seinem Bau. Die erste Fassung sah nur
    UEBERSCHRIFTEN. Ihre ehrliche Grenze war als solche benannt — und sie hatte gemessen zwei
    Instanzen: N8 und N21 tragen "not a defect" in ihrer TABELLENZEILE und zaehlten trotzdem als
    Fund. Eine deklarierte Grenze entschuldigt keinen Fund, sie benennt ihn nur vorher.

    Das Register fuehrt seine Kennungen in zwei Formen, Ueberschrift und Tabellenzeile. Ein
    Riegel, der eine davon prueft, prueft die Haelfte.
    """
    text = QUELLE.read_text(encoding="utf-8")
    aus_koepfen = [m.group(2) for m in _KOPF.finditer(text) if _KEIN_FUND.search(m.group(3))]
    aus_zeilen = [m.group(1) for m in _ZEILE.finditer(text) if _KEIN_FUND.search(m.group(2))]
    return sorted(set(aus_koepfen) | set(aus_zeilen))


def _eintraege() -> dict:
    return {e["kennung"]: e for e in json.loads(KLASSEN.read_text(encoding="utf-8"))["eintraege"]}


def test_kein_selbsterklaerter_nicht_fund_zaehlt_als_fund():
    """[ZAEHLT] Die Eigenschaft, ueber den ganzen Bestand."""
    if not (QUELLE.is_file() and KLASSEN.is_file()):
        pytest.skip("NICHT MESSBAR: Quelle oder Objektklassen-Datei fehlt")
    eintraege = _eintraege()
    falsch = [k for k in selbst_als_nicht_fund()
              if (eintraege.get(k) or {}).get("zaehlt_als_fund")]
    assert not falsch, (
        f"{falsch} weisen sich in der Quelle selbst als Nicht-Fund aus, tragen aber "
        f"zaehlt_als_fund=true und werden als Fund gezaehlt")


def test_die_menge_der_selbsterklaerten_nicht_funde_ist_gemessen():
    """[ZAEHLT] Der Sweep liefert eine ZAHL, damit die Klassenfrage beantwortet ist.

    Faellt dieser Fall, ist eine neue solche Ueberschrift dazugekommen — dann ist sie zu
    entscheiden, nicht stillschweigend mitzuzaehlen.
    """
    if not QUELLE.is_file():
        pytest.skip("NICHT MESSBAR: Quelle fehlt")
    assert selbst_als_nicht_fund() == ["N21", "N8", "S3"], (
        f"gemessen {selbst_als_nicht_fund()}, erwartet genau ['N21', 'N8', 'S3'] — eine neue "
        f"Selbstauskunft braucht eine Entscheidung, kein stilles Mitzaehlen")


def test_S3_traegt_die_entscheidung_MIT_begruendung():
    """[ZAEHLT] Ein umgestelltes Feld ohne Grund ist beim naechsten Leser wieder offen."""
    if not KLASSEN.is_file():
        pytest.skip("NICHT MESSBAR: Objektklassen-Datei fehlt")
    e = _eintraege().get("S3")
    assert e, "S3 fehlt in der Objektklassen-Datei"
    assert e.get("zaehlt_als_fund") is False
    grund = e.get("warum_diese_klasse") or ""
    assert "NO FINDING" in grund, "die Begruendung zitiert die Selbstauskunft der Quelle nicht"
    assert len(grund) >= 120, "die Begruendung ist zu kurz, um beim naechsten Leser zu tragen"


def test_FANG_eine_erfundene_selbstauskunft_wuerde_gemeldet(tmp_path):
    """[ZAEHLT] Gegenrichtung: der Riegel meldet, wenn die zwei Quellen auseinandergehen."""
    eintraege = {"S99": {"kennung": "S99", "zaehlt_als_fund": True}}
    kopf = "### S99 · irgendein Weg — NO FINDING, measured in both directions\n"
    selbst = [m.group(2) for m in _KOPF.finditer(kopf) if _KEIN_FUND.search(m.group(3))]
    assert selbst == ["S99"]
    falsch = [k for k in selbst if (eintraege.get(k) or {}).get("zaehlt_als_fund")]
    assert falsch == ["S99"], "eine widersprechende Zeile muss auffallen"
