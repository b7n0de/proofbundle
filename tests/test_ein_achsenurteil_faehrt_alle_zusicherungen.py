"""Ein Urteil ueber eine Achse, das nur eine ihrer Zusicherungen gefahren hat.

Codex r4001145754 (P1), am Kopf c53ee88370ee03b08238925d9fb73e2ff31d8bdc nachgestellt.
`messe()` fuhr je Achse GENAU EINE der sechs Zusicherungen, die das Quellmodul fuer eine Achse
fuehrt, und gab ihren Ausgang als `urteil` der ganzen Achse aus. Reisst der Lastbau, bleibt der
CPU-Test schnell und meldet BESTANDEN.

DIE KOMBIS HATTEN DENSELBEN DEFEKT und standen in keinem Kommentar: dort lief eine von drei.
Er wurde beim Beheben des ersten gefunden, nicht danach.

Diese Vertraege pruefen die EIGENSCHAFT: verdichtet der gemeinsame Ausgang mehrere Ausgaenge
fail-closed, faehrt er ALLE statt beim ersten Riss abzubrechen, und fragen beide Aufrufstellen
ihn wirklich. Sie fahren KEINE echte Budgetmessung, die gehoert in die Budget-Suite.
"""
from __future__ import annotations

import importlib.util
import pathlib
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
QUELLE = REPO / "scripts" / "budget_axis_measurement.py"


@pytest.fixture(scope="module")
def m():
    sys.path.insert(0, str(REPO / "src"))
    sys.path.insert(0, str(REPO / "tests"))
    s = importlib.util.spec_from_file_location("bam_vertrag", QUELLE)
    mod = importlib.util.module_from_spec(s)
    sys.modules["bam_vertrag"] = mod
    s.loader.exec_module(mod)
    return mod


def _ok():
    return None


def _reisst(text="gepflanzt"):
    def f():
        raise AssertionError(text)
    return f


def test_ein_riss_unter_lauter_bestandenen_faerbt_das_urteil(m):
    """DER FANGNACHWEIS. Genau dieser Fall gab vorher BESTANDEN."""
    urteil, meldung = m._gesamtausgang([("a", _ok), ("b", _reisst("der Lastbau reisst")), ("c", _ok)])
    assert urteil == "GERISSEN"
    assert "b" in meldung and "der Lastbau reisst" in meldung


def test_alle_bestanden_bleibt_bestanden(m):
    """DIE GEGENRICHTUNG. Ein Ausgang, der alles rot faerbt, waere genauso falsch."""
    urteil, meldung = m._gesamtausgang([("a", _ok), ("b", _ok)])
    assert urteil == "BESTANDEN"
    assert "2" in meldung


def test_es_wird_nicht_beim_ersten_riss_abgebrochen(m):
    """Abbrechen hiesse, die uebrigen Zusicherungen wieder nicht zu messen."""
    gelaufen = []

    def spur(name, reissen=False):
        def f():
            gelaufen.append(name)
            if reissen:
                raise AssertionError(name)
        return f

    m._gesamtausgang([("a", spur("a", True)), ("b", spur("b")), ("c", spur("c", True))])
    assert gelaufen == ["a", "b", "c"], "nach dem ersten Riss wurde abgebrochen"


def test_das_schwerste_urteil_gewinnt(m):
    """ABGEBROCHEN vor GERISSEN: ein Ausfall der Messung ist kein Fehlschlag der Achse."""
    def bricht():
        raise RuntimeError("die Messung selbst faellt aus")
    urteil, meldung = m._gesamtausgang([("a", _reisst()), ("b", bricht)])
    assert urteil == "ABGEBROCHEN"
    # GEPRUEFT WIRD DIE GERENDERTE ZEILE, NICHT DER BLOSSE NAME (gemessen 14.09.2026). Vorher stand
    # hier `"a" in meldung and "b" in meldung`. Die Schablone von _gesamtausgang enthaelt immer das
    # Wort "nicht bestanden" — und darin stecken a, b UND c. Beide Proben waren also wahr,
    # unabhaengig davon, ob der Name je im Text stand; der einzige inhaltliche Halt dieses Tests
    # war damit leer. Ein Mutant, der nur die schwerste Meldung behaelt, blieb gruen.
    assert "a: GERISSEN" in meldung, f"die leichtere Meldung wurde verschluckt: {meldung!r}"
    assert "b: ABGEBROCHEN" in meldung, f"die schwerere Meldung fehlt: {meldung!r}"


def test_jede_nicht_bestandene_wird_namentlich_genannt(m):
    urteil, meldung = m._gesamtausgang([("a", _reisst()), ("b", _ok), ("c", _reisst())])
    assert "2 von 3" in meldung
    # Dieselbe Falle wie oben: "c" steckt in "nicht", "a" und "b" in "bestanden". Nur die
    # gerenderte Zeile `<name>: <urteil>` bindet den Namen wirklich an sein Urteil.
    assert "a: GERISSEN" in meldung, f"die erste gerissene fehlt namentlich: {meldung!r}"
    assert "c: GERISSEN" in meldung, f"die letzte gerissene fehlt namentlich: {meldung!r}"
    assert "b:" not in meldung, f"eine BESTANDENE wurde mitgemeldet: {meldung!r}"


@pytest.mark.parametrize("marke", ["dim", "kombi"])
def test_beide_aufrufstellen_fragen_den_gemeinsamen_ausgang(m, marke):
    """Ein Fix an einer von zwei Stellen laesst die zweite still zurueckkehren."""
    quelle = QUELLE.read_text(encoding="utf-8")
    assert quelle.count("_gesamtausgang(") >= 3, "Definition plus zwei Aufrufstellen erwartet"
    assert "_ausgang(lambda d=dim:" not in quelle, "die Achse ruft noch die Einzelzusicherung"
    assert "urteil, meldung = _ausgang(" not in quelle, "eine Aufrufstelle umgeht den gemeinsamen Ausgang"


def test_die_achse_faehrt_alle_sechs_benannten_zusicherungen(m):
    """Die ZAHL ist Teil der Zusicherung: sechs je Achse, drei je Kombi."""
    quelle = QUELLE.read_text(encoding="utf-8")
    fuer_achse = ["last_erreicht_das_limit", "l_minus_eins_l_und_l_plus_eins",
                  "kosten_am_limit_unter_der_obergrenze", "speicher_am_limit_unter_der_grenze",
                  "prozessspitze_gemessen_und_messweg_genannt", "kurve_ist_nicht_ueberlinear"]
    for n in fuer_achse:
        assert f'"{n}"' in quelle, f"die Achse faehrt {n} nicht"
    for n in ("kombi_erreicht_jede_benannte_dimension",
              "kombi_bleibt_unter_der_summe_der_obergrenzen",
              "kombi_speicher_bleibt_unter_der_grenze"):
        assert f'"{n}"' in quelle, f"die Kombi faehrt {n} nicht"


def test_eine_leere_liste_ist_kein_bestanden(m):
    """Ohne eigenen Ausgang wirft `max()` einen ValueError — ein Absturz ohne Urteil ist in einem
    Modul gegen die vakuose Zustimmung die falsche Antwort, und ein BESTANDEN waere die
    schlimmere: es haette nichts gemessen und trotzdem zugestimmt."""
    urteil, meldung = m._gesamtausgang([])
    assert urteil == "ABGEBROCHEN", f"eine leere Liste ergab {urteil}"
    assert "nichts gemessen" in meldung, meldung
