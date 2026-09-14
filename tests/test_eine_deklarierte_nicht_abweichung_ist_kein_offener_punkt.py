"""`zaehlt_als_fund: false` hat ZWEI Gruende — nur einer heisst "kein Defekt".

FUND, Codex 4000176743 (P2). N21 traegt `record_role: boundary`, die Quelle nennt das Verhalten
ausdruecklich "not a defect", und trotzdem machte sein offener Handlungszustand `_offen` wahr und
stellte ihn in `views/known_issues.md`.

DIE NAHELIEGENDE ABHILFE WAERE FALSCH GEWESEN, und das ist hier die Sache. Der Bericht schlaegt vor,
Grenzen aus der Ansicht zu nehmen. GEMESSEN tragen ACHT Grenzen den Zustand offen, und sie
zerfallen in zwei Mengen:

  * N21 ist als `messung_ohne_fund` DEKLARIERT — gemessen, nichts vorgefunden. Kein Defekt.
  * R1 bis R7 sind `nachgemessene_fassung_einer_runde`. Sie zaehlen nicht mit, weil man sonst
    DIESELBE Runde mehrfach zaehlte — aber die Defekte sind offen und echt: "contradicts the
    shipped code", "raises a raw exception", "three numbers are wrong".

Der Vorschlag haette also SIEBEN echte offene Funde aus der Ansicht der offenen Punkte entfernt.
`record_role` beantwortet eine ZAEHLfrage, nicht die Frage nach einem Defekt; entschieden wird
deshalb an der DEKLARIERTEN Ausnahme mit Grund und Beleg.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
TRAEGER = REPO / "audit_artifacts" / "600" / "findings_register_v2.json"
ANSICHT = REPO / "audit_artifacts" / "600" / "views" / "known_issues.md"


def _gen():
    p = REPO / "scripts" / "gen_findings_register.py"
    if not p.is_file():
        pytest.skip(f"NICHT MESSBAR: {p} fehlt")
    s = importlib.util.spec_from_file_location("_gfr7", p)
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


def _doc():
    if not TRAEGER.is_file():
        pytest.skip(f"NICHT MESSBAR: {TRAEGER} fehlt")
    return json.loads(TRAEGER.read_text(encoding="utf-8"))


def test_eine_deklarierte_nicht_abweichung_gilt_nicht_als_offen():
    """[ZAEHLT] Der Fund selbst, am Praedikat."""
    g = _gen()
    assert g._offen({"status": {"value": "open"}, "not_a_defect": {"value": True}}) is False
    assert g._offen({"status": {"value": "open"}, "not_a_defect": {"value": False}}) is True


def test_ANTI_eine_GRENZE_OHNE_deklaration_bleibt_offen():
    """[ZAEHLT] Die teuerste Zusicherung: die naheliegende Abhilfe haette sieben Funde versteckt."""
    g = _gen()
    r = {"record_role": "boundary", "status": {"value": "open"}, "not_a_defect": {"value": False}}
    assert g._offen(r) is True, (
        "eine Grenze OHNE deklarierte Ausnahme faellt aus der Ansicht — dann verschwinden die "
        "nachgemessenen Fassungen einer Runde, und die sind offene Defekte")


def test_N21_ist_draussen_und_R1_bis_R7_sind_drin():
    """[ZAEHLT] Die Wirkung am Bestand, beide Richtungen in einem Fall."""
    d = _doc()
    if not ANSICHT.is_file():
        pytest.skip(f"NICHT MESSBAR: {ANSICHT} fehlt")
    ansicht = ANSICHT.read_text(encoding="utf-8")
    assert "N21" not in ansicht, "die deklarierte Nicht-Abweichung steht unter den offenen Punkten"
    fehlend = [f"R{i}" for i in range(1, 8) if f"R{i}" not in ansicht]
    assert not fehlend, f"offene Defekte fehlen in der Ansicht: {fehlend}"
    n21 = [r for r in d["records"] if r["id"] == "N21"][0]
    assert n21["not_a_defect"]["value"] is True
    assert n21["not_a_defect"]["beleg"], "die Deklaration ohne Beleg ist eine leere Marke"


def test_die_deklaration_kommt_aus_der_datei_nicht_aus_dem_erzeuger():
    """[ZAEHLT] Eine Liste im Code waere eine zweite Wahrheit neben der Quelle."""
    ok = REPO / "RESTRISIKO_600_OBJEKTKLASSEN.json"
    if not ok.is_file():
        pytest.skip(f"NICHT MESSBAR: {ok} fehlt")
    a = (json.loads(ok.read_text(encoding="utf-8")).get("ausnahmen_von_der_klasse")
         or {}).get("messung_ohne_fund") or {}
    kennungen = set(a.get("kennungen") or [])
    assert "N21" in kennungen, "die Ausnahme steht nicht in der Datei"
    assert not (kennungen & {f"R{i}" for i in range(1, 8)}), (
        "eine nachgemessene Fassung waere als Nicht-Defekt deklariert — das waere ein Freispruch")
    d = _doc()
    erklaert = {r["id"] for r in d["records"] if (r.get("not_a_defect") or {}).get("value")}
    assert erklaert == kennungen & {r["id"] for r in d["records"]}, (
        f"der Traeger erklaert {erklaert} fuer nicht-abweichend, die Datei {kennungen}")


def test_jedes_als_nicht_defekt_erklaerte_traegt_seinen_beleg():
    """[ZAEHLT] Ein Freispruch ohne Beleg ist der gefaehrlichste Zustand hier."""
    for r in _doc()["records"]:
        nd = r.get("not_a_defect") or {}
        if nd.get("value"):
            assert nd.get("beleg"), f"{r['id']} ist als kein Defekt erklaert, ohne Beleg"
            assert nd.get("source"), f"{r['id']} nennt nicht, woher die Erklaerung kommt"


def test_ein_geschlossener_fund_bleibt_draussen():
    """[GETRENNT] Der alte Weg darf nicht verloren gehen."""
    g = _gen()
    assert g._offen({"status": {"value": "closed"}, "not_a_defect": {"value": False}}) is False
