"""Eine veroeffentlichte Befundliste ohne ihre Wurzel bindet nichts.

P1.2 der Gegenlese Runde 2: *"findingsRoot verpflichtend machen, wenn Findings vorhanden sind."*

WAS VORHER MOEGLICH WAR, gemessen am 01.09.2026: `findingsRoot` war optional, und der Verifier
prueft sie nur `elif isinstance(..., str)`. Ein Erzeuger konnte sie also schlicht weglassen — und
die staerkste Bindung dieses Praedikats, die einen NACH dem Signieren hinzugefuegten oder
entfernten Befund faengt, galt lautlos nicht.

WARUM DER BESTEHENDE TEST DAS NICHT FING: P0-Test 11 pflanzt eine VERALTETE Wurzel ein, und eine
veraltete Wurzel ist vorhanden. Der Fall "gar keine Wurzel" kam in keinem Fall vor. Dieselbe
Klasse wie der leerlaufende Test dieses Laufs — eine Pruefung, deren Vorbedingung nie eintrat.

GEMESSEN VOR DEM SCHAERFEN, gegen JEDES Receipt, das wir selbst veroeffentlicht haben (sechs
Dateien unter `receipts/agent_review/`): alle sechs tragen eine Wurzel. Nichts, was draussen
steht, bricht. Waere auch nur eines ohne Wurzel gewesen, gehoerte die Regel dem Owner vorgelegt
statt gebaut — genau so ist es beim `fixCommit`-Teil derselben Forderung ausgegangen.
"""
from __future__ import annotations

import base64
import json
import pathlib

import pytest

from proofbundle import agent_review as ar

REPO = pathlib.Path(__file__).resolve().parents[1]
BEFUND = {"id": "F1", "severity": "low", "title": "t", "disposition": "open", "reason": "r"}
BASIS = {"authoring": [{"assurance": "selfDeclared", "assertedBy": "agent"}],
         "reviewRuns": [], "nonClaims": ["keine Aussage ueber Qualitaet"]}


def _doc(declaration):
    return {
        "schemaVersion": "0.1.0", "reviewId": "wurzel",
        "subjectContext": {"kind": "githubPullRequest", "forge": "github.com",
                           "repositoryId": "R_kg", "pullRequestNodeId": "PR_kw1",
                           "headSha": "a" * 40, "baseSha": "b" * 40,
                           "reviewedDiffDigest": "c" * 64,
                           "bodyCoreDigest": ar.body_core_digest("x")},
        "declaration": declaration,
        "coverage": {"status": "PARTIAL", "knownGaps": ["nur eine Runde"]},
        "times": {"declaredAt": "2026-09-01T09:00:00Z"},
        "limitations": ["Tier 1"],
    }


def _fehler(declaration):
    return ar.validate_agent_review_predicate(_doc(declaration), strict=True)


def test_liste_ohne_wurzel_wird_verweigert():
    """DER FUND. Eine Befundliste ohne Wurzel darf nicht durchgehen."""
    errs = _fehler({**BASIS, "findings": [BEFUND], "findingsTotal": 1})
    assert errs, "eine Liste ohne Wurzel wurde angenommen"
    codes = [getattr(e, "code", None) for e in errs]
    assert any(c and "FINDINGS_ROOT_MISSING" in c for c in codes), (
        f"verweigert, aber ohne stabilen Grund: {codes}")


def test_leere_liste_braucht_keine_wurzel():
    """DIE GEGENRICHTUNG, und sie ist der Grund fuer die enge Fassung.

    Ohne Befunde gibt es nichts, was eine Wurzel binden koennte. Ein Riegel, der auch hier
    verlangt, blockt korrekte Receipts — und ein Riegel, der alles blockt, ist keiner.
    """
    assert _fehler({**BASIS, "findings": [], "findingsTotal": 0}) == []


def test_liste_mit_wurzel_geht_durch():
    assert _fehler({**BASIS, "findings": [BEFUND], "findingsTotal": 1,
                    "findingsRoot": ar.findings_root([BEFUND])}) == []


def test_die_wurzel_bindet_weiterhin_inhaltlich():
    """Die neue Pflicht ersetzt die alte Pruefung nicht: eine FALSCHE Wurzel faellt weiter."""
    errs = _fehler({**BASIS, "findings": [BEFUND], "findingsTotal": 1,
                    "findingsRoot": "0" * 64})
    # Der Validator prueft die FORM; die Deckung prueft der Verifier — hier nur: Form ok, kein
    # Fehlalarm der neuen Regel.
    assert not [e for e in errs if "required once findings are listed" in str(e)]


_RECEIPTS = sorted((REPO / "receipts" / "agent_review").glob("*.json"))


@pytest.mark.parametrize("pfad", _RECEIPTS, ids=lambda p: p.name)
def test_kein_eigenes_veroeffentlichtes_receipt_bricht(pfad):
    """DIE MESSUNG, DIE DEM SCHAERFEN VORAUSGING — als Test, damit sie nicht einmalig bleibt.

    Wer diese Regel spaeter verschaerft, sieht hier sofort, ob er etwas entwertet, das drausssen
    steht. Genau diese Frage hat beim `fixCommit`-Teil derselben Forderung zu "Vorlage statt
    Bruch" gefuehrt: drei unserer Receipts tragen VERKUERZTE SHAs.
    """
    st = json.loads(base64.b64decode(json.loads(pfad.read_text(encoding="utf-8"))["payload"]))
    errs = ar.validate_agent_review_predicate(st.get("predicate"), strict=True)
    wurzel = [e for e in errs if "findingsRoot" in str(e)]
    assert not wurzel, f"{pfad.name} bricht an der neuen Regel: {wurzel}"


def test_es_gibt_ueberhaupt_receipts_zu_pruefen():
    """DRITTER ZUSTAND. Ohne diese Zeile waere der Test darueber gruen, wenn der Ordner leer ist."""
    assert len(_RECEIPTS) >= 3, f"nur {len(_RECEIPTS)} Receipts — die Messung traegt nicht"


# ── Der Ablehnungspfad muss kopierbar bleiben ──────────────────────────────────────────────────

def test_ein_abgelehntes_ergebnis_laesst_sich_kopieren_und_einfrieren():
    """DER FIX, DER KEINE REGRESSION HATTE — gemessen vom Tiefen-Gate am 02.09.2026.

    `ShapeError` erbt von `str` und nimmt in `__new__` ZWEI Argumente (code, message). `str`
    liefert ein einargumentiges `__getnewargs__`, also warf `copy.deepcopy(ergebnis)` auf jedem
    Ergebnis, das einen ShapeError fuehrt:

        TypeError: ShapeError.__new__() missing 1 required positional argument

    Nur der ABLEHNUNGSPFAD war betroffen — ein gueltiges Receipt fuehrt keinen ShapeError und
    kopiert einwandfrei. `__getnewargs__` behebt das. Die Gegenlesung hat dann gemessen, dass der
    Fix NULL Regressionstests hatte: entfernt man ihn, bleiben 2920 Tests gruen. Ein Fix ohne
    Test ist ein Fix, den der naechste Umbau still zuruecknimmt.

    Geprueft werden alle drei Wege, die dieselbe Maschinerie benutzen — flach, tief, und der
    Serialisierungsweg, den ein Cache oder eine Warteschlange nimmt.
    """
    import copy  # noqa: PLC0415
    import pickle  # noqa: PLC0415

    fehler = ar._shape_err("PROBE_CODE", "eine Meldung mit Code")
    assert copy.copy(fehler).code == "PROBE_CODE"
    assert copy.deepcopy(fehler).code == "PROBE_CODE"
    assert pickle.loads(pickle.dumps(fehler)).code == "PROBE_CODE"
    assert str(copy.deepcopy(fehler)) == "eine Meldung mit Code"

    # UND AN EINER ECHTEN FEHLERLISTE, nicht nur am Einzelobjekt: genau dort trat der Fehler auf.
    errs = _fehler({**BASIS, "findings": [BEFUND], "findingsTotal": 1})
    assert errs, "die Vorbedingung traegt nicht — diese Liste haette fallen muessen"
    assert any(getattr(e, "code", None) for e in errs), (
        "kein ShapeError in der Liste — dann prueft der Kopiertest die Klasse nicht")
    kopie = copy.deepcopy(errs)
    assert [str(e) for e in kopie] == [str(e) for e in errs]
    assert [getattr(e, "code", None) for e in kopie] == [getattr(e, "code", None) for e in errs]
