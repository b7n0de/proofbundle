"""Punkt 2e: die Tafel gegen den CODE gerechnet, nicht gegen mein Gedaechtnis."""
from __future__ import annotations

import json
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
TAFEL = REPO / "audit_artifacts/600/intoto_test_result_abgleich.json"

pytestmark = pytest.mark.skipif(not TAFEL.is_file(), reason="die Tafel liegt hier nicht vor")


@pytest.fixture(scope="module")
def tafel():
    return json.loads(TAFEL.read_text(encoding="utf-8"))


def test_jede_zeile_traegt_feld_lage_und_entscheidung(tafel):
    for z in tafel["tafel"]:
        assert z.get("feld") and isinstance(z["vorhanden"], bool) and z.get("entscheidung")


def test_der_erzeuger_schreibt_wirklich_die_als_vorhanden_gemeldeten_felder(tafel):
    """Zweiter Messweg: der Quelltext des Erzeugers, nicht die Tafel."""
    src = (REPO / "src/proofbundle/intoto.py").read_text(encoding="utf-8")
    for z in tafel["tafel"]:
        if not z["vorhanden"]:
            continue
        name = z["feld"].split(" ")[0].split("/")[0]
        if name == "subject":
            continue
        assert f'"{name}"' in src, f"{name} als vorhanden gemeldet, steht aber nicht im Erzeuger"


def test_warnedtests_wird_nirgends_erzeugt(tafel):
    src = (REPO / "src/proofbundle/intoto.py").read_text(encoding="utf-8")
    zeile = next(z for z in tafel["tafel"] if z["feld"] == "warnedTests")
    assert zeile["vorhanden"] is False
    assert '"warnedTests"' not in src


def test_das_subjekt_ist_als_SPEC_ABWEICHUNG_ausgewiesen(tafel):
    """un-Gegenlesung 15.09.: 'Entscheidung' stellte den Grund ueber die Folge.

    Ein guter Grund macht eine Abweichung nicht zur Konformitaet. Die Tafel muss BEIDES tragen.
    """
    z = next(x for x in tafel["tafel"] if x["feld"].startswith("subject"))
    assert z["vorhanden"] is False
    assert z.get("abweichung_von_der_spec") is True
    assert "Inkompatibilitaet" in z["entscheidung"]
    assert "GRUND BLEIBT RICHTIG" in z["entscheidung"]


def test_die_null_wurde_MIT_dekodierung_gemessen(tafel):
    """Eine Textsuche ueber base64 ist eine Aussage ueber die Kodierung."""
    l = tafel["lage_im_bestand"]
    assert "rekursiver Dekodierung" in l["wie_gemessen"]
    assert l["davon_mit_test_result_feldern"] == 0
    src = (REPO / "src/proofbundle/intoto.py").read_text(encoding="utf-8")
    assert "binder = json.dumps(" in src


def test_faehigkeit_und_bestand_bleiben_getrennt(tafel):
    l = tafel["lage_im_bestand"]
    assert l["davon_mit_test_result_feldern"] == 0
    assert "Faehigkeit und Bestand sind zwei Fragen" in l["reason"]


def test_das_signiersystem_wird_nicht_gewechselt(tafel):
    assert "DSSE" in tafel["was_nicht_geaendert_wird"]
