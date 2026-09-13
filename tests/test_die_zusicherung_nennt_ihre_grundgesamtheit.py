"""Eine Zusicherung ueber ALLE spricht nicht ueber die Teilmenge, die sich einstufen liess.

FUND, Codex 4000140168 (P2). Die Rechnung zu "0 open P0/P1" ueberspringt jeden Datensatz, dessen
Schwere nicht P0 oder P1 ist — und damit auch jeden, dessen Schwere GAR NICHT GEMESSEN ist. Beides
sah gleich aus. GEMESSEN am Bestand: 120 von 145 Datensaetzen tragen in Schwere UND Zustand
NICHT MESSBAR, waehrend die Zusicherung ueber die verbleibenden 25 rechnete und `holds: true`
meldete. Ein Fund mit beiden Feldern ungemessen anzuhaengen aendert das Urteil nicht.

DIE KLASSE: eine Aussage ueber eine Grundgesamtheit wird ueber der Teilmenge gerechnet, die sich
messen liess, und die Teilmenge wird nicht genannt. Wer die Ungemessenen ueberspringt, verbucht sie
stillschweigend als "nicht betroffen" — ein Freispruch ohne Messung.

NICHT EINGESTUFT IST WEDER HOCH NOCH NIEDRIG. Sie als offen zu zaehlen erfindet Funde, sie als
geschlossen zu zaehlen spricht sie frei. Der dritte Zustand ist der ehrliche: UNBESTIMMT, mit der
Zahl der Ungemessenen daneben. `holds` traegt dann None — kein `true`, das mehr behauptet, als die
Datenlage hergibt, und kein `false`, das einen Fund erfindet.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
TRAEGER = REPO / "audit_artifacts" / "600" / "findings_register_v2.json"


def _gen():
    p = REPO / "scripts" / "gen_findings_register.py"
    if not p.is_file():
        pytest.skip(f"NICHT MESSBAR: {p} fehlt")
    s = importlib.util.spec_from_file_location("_gfr5", p)
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


def _satz(kennung, schwere=None, zustand=None):
    return {"id": kennung,
            "severity": {"value": schwere} if schwere else {"value": None, "state": "NOT MEASURED"},
            "status": {"value": zustand} if zustand else {"value": None, "state": "NOT MEASURED"}}


def test_die_zusicherung_nennt_wie_viele_sie_einstufen_konnte():
    """[ZAEHLT] Der Fund selbst: die uebersprungene Menge gehoert in die Aussage."""
    g = _gen()
    z = g._zusicherungen("", [_satz("A4", "P1", "closed"), _satz("S5"), _satz("S6")])[0]
    gg = z["computed"]["population"]
    assert gg["records_gesamt"] == 3
    assert gg["ohne_schwere"] == 2, gg
    assert gg["ohne_schwere_beispiele"], "die Ungemessenen werden nicht einmal beispielhaft genannt"


def test_bei_ungemessenen_ist_die_zusicherung_UNBESTIMMT():
    """[ZAEHLT] Kein `true`, das mehr behauptet, als die Datenlage hergibt."""
    g = _gen()
    z = g._zusicherungen("", [_satz("A4", "P1", "closed"), _satz("S5")])[0]
    assert z["holds"] is None, z
    assert z["holds_state"] == "INDETERMINATE"
    assert z["holds_reason"], "ein unbestimmter Zustand ohne Grund ist eine leere Marke"


def test_FANG_ein_angehaengter_ungemessener_fund_kippt_das_urteil():
    """[ZAEHLT] Die kleinste Reproduktion des Berichts, als Vertrag."""
    g = _gen()
    vollstaendig = [_satz("A4", "P1", "closed"), _satz("A5", "P2", "closed")]
    assert g._zusicherungen("", vollstaendig)[0]["holds"] is True, "Vorbedingung: alles eingestuft"
    assert g._zusicherungen("", [*vollstaendig, _satz("NEU")])[0]["holds"] is None, (
        "ein Fund mit ungemessener Schwere laesst die Zusicherung unveraendert wahr")


def test_ANTI_eine_vollstaendig_eingestufte_menge_bleibt_bestimmbar():
    """[ZAEHLT] Gegenrichtung: die Verschaerfung darf nicht jede Zusicherung unbestimmt machen."""
    g = _gen()
    z = g._zusicherungen("", [_satz("A4", "P1", "closed"), _satz("A5", "P3", "closed")])[0]
    assert z["holds"] is True and z["holds_state"] == "MEASURED", z
    assert z["holds_reason"] is None


def test_ein_offener_P1_bleibt_ein_DOES_NOT_HOLD():
    """[ZAEHLT] Der Fall, fuer den die Zusicherung ueberhaupt da ist, geht nicht verloren."""
    g = _gen()
    z = g._zusicherungen("", [_satz("A4", "P1", "open")])[0]
    assert z["holds"] is False, z
    assert z["computed"]["open_entries"] == ["A4"]


def test_der_echte_bestand_ist_heute_unbestimmt_und_sagt_warum():
    """[ZAEHLT] Am Bestand gemessen, nicht an einer Attrappe.

    Faellt dieser Fall, ist die Einstufung nachgezogen worden — dann gehoert die Zusicherung
    wieder bestimmbar, und diese Zusicherung ist nachzuziehen statt zu loeschen.
    """
    if not TRAEGER.is_file():
        pytest.skip(f"NICHT MESSBAR: {TRAEGER} fehlt")
    a = json.loads(TRAEGER.read_text(encoding="utf-8"))["inventory"]["assurance_checks"][0]
    assert a["holds"] is None and a["holds_state"] == "INDETERMINATE", a
    gg = a["computed"]["population"]
    assert gg["ohne_schwere"] > 0 and gg["records_gesamt"] == 145, gg


def test_beide_ansichten_rendern_den_dritten_zustand():
    """[ZAEHLT] Ein Zustand, den keine Ansicht zeigt, wirkt nicht.

    Vorher las jede Ansicht `holds` als Wahrheitswert — None waere dort als DOES NOT HOLD
    erschienen, also als FUND statt als Luecke. Zwei verschiedene Aussagen, ein Wort.
    """
    md = REPO / "audit_artifacts" / "600" / "views" / "uebersicht.md"
    html = REPO / "audit_artifacts" / "600" / "views" / "uebersicht.html"
    for p in (md, html):
        if not p.is_file():
            pytest.skip(f"NICHT MESSBAR: {p} fehlt")
        t = p.read_text(encoding="utf-8")
        assert "INDETERMINATE" in t, f"{p.name} zeigt den dritten Zustand nicht"
        assert "DOES NOT HOLD" not in t, f"{p.name} liest die Luecke als Fund"


def test_die_grenze_der_zusicherung_steht_im_text():
    """[GETRENNT] Die Klasse gehoert benannt, nicht nur behoben."""
    q = pathlib.Path(__file__).read_text(encoding="utf-8")
    assert "NICHT EINGESTUFT IST WEDER HOCH NOCH NIEDRIG" in q
