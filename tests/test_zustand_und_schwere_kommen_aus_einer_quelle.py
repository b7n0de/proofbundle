"""Zustand und Schwere eines Fundes werden GELESEN, nicht geraten, und das Etikett sagt die Wahrheit.

DREI CODEX-FUNDE, EINE WURZEL.

r3999621596. `_offen` fiel fuer jede Kennung ausserhalb der Erzeugerliste auf
`bool(severity) and record_role == "finding"` zurueck und las den Zustand der Quelle NIE. Gemessen
trat es ein: A4 steht in der Quelltabelle ausdruecklich als `closed` und erschien in der erzeugten
Ansicht `known_issues.md` als offener P1. Ein Zustand, der aus Schwere und Rolle geraten wird, ist
eine Auskunft ueber die FORM des Datensatzes, nicht ueber den Fund.

r3999796578. Die Schwere kam aus einer Python-Liste im Erzeuger, das Ergebnis trug aber das Etikett
"findings_register v1, signiert". Eine Aenderung an der Liste aendert die veroeffentlichte Schwere,
waehrend sie sich als signierte Evidenz ausweist. Der WEG ist derselbe geblieben — es ist die
Aussage darueber, die falsch war.

r3999820857. Die Zusicherung "0 open P0/P1" wurde ueber einen Regex auf den Rohtext gerechnet, der
nur Zeilen der A-Tabelle trifft. Gemessen ist das 1 von 145 Datensaetzen; alle Funde in
Ueberschriftenform und alle Eintraege der Erzeugerliste waren strukturell unsichtbar.

EHRLICHE GRENZE zu r3999820857: der Fund ist eine FAEHIGKEIT, kein Vorkommen. Gemessen traegt heute
kein Eintrag ausserhalb der A-Tabelle ein P0 oder P1. Der Unterschied zwischen einem falschen
Bestehen und der Moeglichkeit eines falschen Bestehens gehoert benannt, nicht verwischt.
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
    s = importlib.util.spec_from_file_location("_gfr3", p)
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


def _doc():
    if not TRAEGER.is_file():
        pytest.skip(f"NICHT MESSBAR: {TRAEGER} fehlt")
    return json.loads(TRAEGER.read_text(encoding="utf-8"))


def test_jeder_zustand_nennt_seine_quelle_oder_ist_ein_lueckenwort():
    """[ZAEHLT] Kein geratener Zustand, ueber den ganzen Traeger."""
    fehlend = []
    for r in _doc()["records"]:
        st = r.get("status") or {}
        if st.get("value") in ("open", "closed"):
            if not st.get("source"):
                fehlend.append(f"{r['id']}: Zustand {st['value']} ohne Quelle")
        elif st.get("state") != "NOT MEASURED" or not st.get("reason"):
            fehlend.append(f"{r['id']}: weder Zustand mit Quelle noch Lueckenwort mit Grund")
    assert not fehlend, fehlend


def test_A4_ist_geschlossen_und_steht_NICHT_in_der_ansicht():
    """[ZAEHLT] Die Instanz von r3999621596, an beiden Orten."""
    r = [x for x in _doc()["records"] if x["id"] == "A4"]
    assert r, "A4 wird nicht getragen"
    assert (r[0].get("status") or {}).get("value") == "closed", r[0].get("status")
    if ANSICHT.is_file():
        offen = [z.split()[1] for z in ANSICHT.read_text(encoding="utf-8").splitlines()
                 if z.startswith("* ")]
        assert "A4" not in offen, f"A4 steht weiter in der Ansicht: {offen}"


def test_FANG_ein_unbekannter_zustand_gilt_NICHT_als_offen():
    """[ZAEHLT] Gegenrichtung: geraten wird in KEINE Richtung."""
    g = _gen()
    assert g._offen({"id": "X1", "severity": {"value": "P1"}, "record_role": "finding",
                     "status": {"value": None, "state": "NOT MEASURED", "reason": "x"}}) is False
    assert g._offen({"id": "X2", "severity": {"value": "P1"}, "record_role": "finding",
                     "status": {"value": "open", "source": "q"}}) is True
    assert g._offen({"id": "X3", "severity": {"value": "P1"}, "record_role": "finding",
                     "status": {"value": "closed", "source": "q"}}) is False


def test_das_etikett_der_schwere_behauptet_keine_signierte_quelle():
    """[ZAEHLT] Die Instanz von r3999796578: keine Quelle nennen, die der Code nie liest."""
    for r in _doc()["records"]:
        sev = r.get("severity") or {}
        q = str(sev.get("source") or "")
        if "signiert" in q:
            assert sev.get("source_state"), (
                f"{r['id']}: die Quelle nennt sich signiert, ohne den Pruefzustand mitzufuehren")


def test_die_zusicherung_rechnet_ueber_die_datensaetze_nicht_ueber_einen_regex():
    """[ZAEHLT] Die Instanz von r3999820857: dieselbe Menge, ueber die das Register spricht."""
    doc = _doc()
    a = doc["inventory"]["assurance_checks"][0]
    ids = {e["id"] for e in a["computed"]["entries"]}
    aus_records = {r["id"] for r in doc["records"]
                   if (r.get("severity") or {}).get("value") in ("P0", "P1")}
    assert ids == aus_records, (
        f"die Zusicherung zaehlt {sorted(ids)}, die Datensaetze tragen {sorted(aus_records)}")
    for e in a["computed"]["entries"]:
        assert e.get("state_source"), f"{e['id']}: Zustand ohne benannte Quelle"


def test_FANG_ein_offener_P1_in_UEBERSCHRIFTENFORM_wuerde_gezaehlt():
    """[ZAEHLT] Gegenrichtung rot: genau die Menge, die der alte Regex nicht sehen konnte.

    Der alte Weg suchte Tabellenzeilen. Ein Fund in Ueberschriftenform mit P1 und offenem Zustand
    war unsichtbar. Hier wird er in die Datensatzmenge gelegt und MUSS die Zusicherung kippen.
    """
    g = _gen()
    records = [
        {"id": "A4", "severity": {"value": "P1"}, "status": {"value": "closed", "source": "q"}},
        {"id": "S999", "severity": {"value": "P1"}, "status": {"value": "open", "source": "q"}},
    ]
    a = g._zusicherungen("", records)[0]
    assert a["computed"]["p0_p1_total"] == 2, a["computed"]
    assert a["computed"]["p0_p1_open"] == 1, a["computed"]
    assert a["holds"] is False, "ein offener P1 in Ueberschriftenform muss die Zusicherung kippen"


def test_heute_traegt_KEIN_eintrag_ausserhalb_der_A_tabelle_ein_P0_oder_P1():
    """[ZAEHLT] Die ehrliche Grenze als Messung: Faehigkeit ja, Vorkommen nein.

    Faellt dieser Fall, ist ein solcher Eintrag dazugekommen — dann ist die Zusicherung neu zu
    lesen, und das soll auffallen statt stillzustehen.
    """
    hoch = [r["id"] for r in _doc()["records"]
            if (r.get("severity") or {}).get("value") in ("P0", "P1")]
    assert hoch == ["A4"], f"gemessen {hoch}, erwartet genau ['A4']"
