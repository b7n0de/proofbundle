"""Die Arten von Korpus-Faellen stehen an EINER Stelle — und der Notpfad kennt sie alle.

DER GEMESSENE ANLASS (01.09.2026, gefunden beim Bau des reproduzierbaren Reviewerpakets, nicht
beim Programmieren): `cross_format._structural_validate` ist der Notpfad OHNE `jsonschema` und
trug eine EIGENE, fest eingetragene Liste mit VIER Arten. Der Laeufer unterstuetzt ACHT.

WARUM DAS NIEMAND SAH: im Entwicklungs-venv ist `jsonschema` installiert (4.26.0), der Notpfad
laeuft dort NIE. Die Luecke zeigte sich erst in einem frischen venv mit nur dem Wheel — also genau
in der Umgebung, die N09/P1.3 der Gegenlese fuer die oeffentliche Verify-Anweisung verlangt. Dort
fielen ALLE 14 agent-review-Faelle mit `unknown kind 'agent_review_predicate'` aus der
Korpus-Integritaet, obwohl im Repo 91 von 91 gruen waren.

DIE KLASSE: ein Ersatzpfad, der im Alltag nicht ausgefuehrt wird, veraltet lautlos. Eine zweite
Liste ueber dieselbe Groesse ist eine zweite Wahrheit, und die zweite ist die, die niemand
mitpflegt. Diese Tests halten fest, dass es nur EINE gibt.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "conformance"))
sys.path.insert(0, str(REPO / "src"))


def test_der_laeufer_und_der_notpfad_kennen_DIESELBEN_arten():
    """DIE EIGENSCHAFT. Was der Laeufer bedienen kann, muss der Integritaets-Boden kennen —
    sonst wirft er gueltige Faelle raus, und zwar nur dort, wo `jsonschema` fehlt."""
    import run_conformance
    from common_vocabulary import CASE_KINDS

    dispatch = set(run_conformance._DISPATCH)
    assert dispatch == set(CASE_KINDS), (
        "Laeufer und Vokabular sind auseinandergelaufen — "
        f"nur im Laeufer: {sorted(dispatch - set(CASE_KINDS))}, "
        f"nur im Vokabular: {sorted(set(CASE_KINDS) - dispatch)}")
    assert len(dispatch) >= 8, f"nur {len(dispatch)} Arten — misst dieser Test noch etwas?"


def test_der_notpfad_liest_das_vokabular_statt_einer_eigenen_liste():
    """DER KLASSEN-TEIL, strukturell. Ein gruener Vergleich oben nuetzt nichts, wenn der Notpfad
    seine Arten weiterhin selbst auflistet — dann stimmen sie heute zufaellig ueberein."""
    quelle = (REPO / "conformance" / "cross_format.py").read_text(encoding="utf-8")
    assert "CASE_KINDS" in quelle, "der Notpfad liest das gemeinsame Vokabular nicht"
    assert '"decision_crossimpl", "native_bundle", "decision_relation"' not in quelle, (
        "die alte, fest eingetragene Artenliste steht wieder im Notpfad")


def test_jede_art_im_manifest_ist_eine_bekannte_art():
    """Die dritte Richtung: das Manifest darf keine Art fuehren, die keiner der beiden kennt."""
    import json

    from common_vocabulary import CASE_KINDS

    wurzel = REPO / "conformance"
    m = json.loads((wurzel / "manifest.json").read_text(encoding="utf-8"))
    unbekannt = []
    for rel in m.get("cases", []):
        cj = wurzel / rel / "case.json"
        if not cj.is_file():
            continue
        art = json.loads(cj.read_text(encoding="utf-8")).get("kind")
        if art not in CASE_KINDS:
            unbekannt.append((rel, art))
    assert not unbekannt, f"Faelle mit unbekannter Art: {unbekannt}"
    assert len(m.get("cases", [])) >= 50, "das Manifest ist zu klein — misst dieser Test etwas?"
