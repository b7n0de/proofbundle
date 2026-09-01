"""P0.4 der Gegenlesung Runde 2 — Coverage und Zeit semantisch haerten.

DREI DER VIER LUECKEN WAREN LIVE MESSBAR, bevor hier etwas gebaut wurde:

    Boolean statt Zahl     -> ANGENOMMEN
    negative Zahl          -> ANGENOMMEN
    COMPLETE 0 von 0       -> ANGENOMMEN

Die erste ist die interessanteste, weil sie keine Nachlaessigkeit war, sondern eine Eigenschaft der
Sprache: `isinstance(True, int)` ist in Python WAHR. Die Pruefung war korrekt geschrieben und
trotzdem blind. Wer sie nur liest, findet den Fehler nicht — man muss sie ausfuehren.
"""
from __future__ import annotations

import pytest

from proofbundle import agent_review as AR


def _cov(**kw) -> dict:
    return dict(kw)


# ── 1) Boolean und negative Counts ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("feld", ["observedRuns", "expectedRuns"])
def test_ein_boolean_ist_keine_laufzahl(feld):
    errs = AR._validate_coverage(_cov(status="UNKNOWN", **{feld: True}))
    assert any("boolean" in e for e in errs), errs


@pytest.mark.parametrize("feld", ["observedRuns", "expectedRuns"])
def test_eine_negative_laufzahl_beschreibt_nichts(feld):
    errs = AR._validate_coverage(_cov(status="UNKNOWN", **{feld: -1}))
    assert any("negative" in e for e in errs), errs


def test_eine_echte_null_bleibt_erlaubt():
    """0 ist eine Zahl, kein Fehler — nur COMPLETE ueber 0 ist einer."""
    assert AR._validate_coverage(_cov(status="UNKNOWN", observedRuns=0, expectedRuns=0)) == []


# ── 2) COMPLETE ueber nichts ──────────────────────────────────────────────────────────────────

def test_COMPLETE_ueber_null_erwartete_laeufe_wird_abgelehnt():
    errs = AR._validate_coverage(_cov(status="COMPLETE", observedRuns=0, expectedRuns=0,
                                      sources=["s"], window="w", collectionMethod="m"))
    assert any("empty expectation" in e for e in errs), errs


# ── 3) COMPLETE muss sagen, worueber ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("fehlt", ["sources", "window", "collectionMethod"])
def test_COMPLETE_ohne_universum_wird_abgelehnt(fehlt):
    cov = _cov(status="COMPLETE", observedRuns=3, expectedRuns=3,
               sources=["s"], window="w", collectionMethod="m")
    del cov[fehlt]
    errs = AR._validate_coverage(cov)
    assert any(fehlt in e for e in errs), errs


def test_ein_vollstaendig_beschriebenes_COMPLETE_geht_durch():
    assert AR._validate_coverage(_cov(status="COMPLETE", observedRuns=3, expectedRuns=3,
                                      sources=["s"], window="w", collectionMethod="m")) == []


def test_PARTIAL_ist_von_der_COMPLETE_haertung_unberuehrt():
    """Alle sechs bisher ausgestellten Receipts tragen PARTIAL — sie duerfen nicht brechen."""
    assert AR._validate_coverage(_cov(status="PARTIAL", knownGaps=["g"], observedRuns=1,
                                      expectedRuns=3)) == []


# ── 6) standardisierte Einschraenkungs-Codes ──────────────────────────────────────────────────

def test_die_codes_werden_abgeleitet_nicht_getippt():
    p = {"declaration": {"authoring": [{"assurance": "selfDeclared", "assertedBy": "x"}],
                         "reviewRuns": []},
         "coverage": {"status": "PARTIAL"}}
    codes = AR.derive_limitation_codes(p)
    assert "IDENTITY_UNBOUND" in codes
    assert "TIME_SELF_DECLARED" in codes
    assert "COVERAGE_PARTIAL" in codes
    assert "NOT_QUALITY_ATTESTATION" in codes


def test_NOT_QUALITY_ATTESTATION_steht_IMMER_drin():
    """Es ist eine Eigenschaft des Belegtyps, nicht des Einzelfalls."""
    for p in ({}, {"coverage": {"status": "COMPLETE"}},
              {"declaration": {"authoring": [{"assurance": "independentlyWitnessed"}]}}):
        assert "NOT_QUALITY_ATTESTATION" in AR.derive_limitation_codes(p)


def test_eine_benannte_beobachtung_nimmt_TIME_SELF_DECLARED_weg():
    """Sonst waere der Code eine Konstante und wuerde nichts unterscheiden."""
    p = {"declaration": {"authoring": [{"assurance": "selfDeclared"}]},
         "observations": [{"observer": {"id": "runner"}}], "coverage": {"status": "COMPLETE"}}
    assert "TIME_SELF_DECLARED" not in AR.derive_limitation_codes(p)


def test_eine_staerkere_stufe_nimmt_IDENTITY_UNBOUND_weg():
    p = {"declaration": {"authoring": [{"assurance": "platformAttested"}], "reviewRuns": []},
         "coverage": {"status": "COMPLETE"}}
    assert "IDENTITY_UNBOUND" not in AR.derive_limitation_codes(p)


def test_ein_erfundener_code_wird_abgelehnt():
    assert AR._validate_limitation_codes(["FREI_ERFUNDEN"])


def test_doppelte_codes_werden_abgelehnt():
    assert AR._validate_limitation_codes(["IDENTITY_UNBOUND", "IDENTITY_UNBOUND"])


def test_die_abgeleiteten_codes_sind_selbst_gueltig():
    """Sonst koennte die Ableitung etwas erzeugen, das die Validierung ablehnt."""
    p = {"declaration": {"authoring": [{"assurance": "selfDeclared"}]},
         "coverage": {"status": "PARTIAL"}}
    assert AR._validate_limitation_codes(AR.derive_limitation_codes(p)) == []


def test_v02_verlangt_die_codes():
    p = {"schemaVersion": "0.1.0", "reviewId": "r",
         "subjectContext": {"kind": "githubPullRequest", "forge": "g", "repositoryId": "R",
                            "pullRequestNodeId": "P", "headSha": "a" * 40, "baseSha": "b" * 40,
                            "reviewedDiffDigest": "c" * 64, "bodyCoreDigest": "d" * 64,
                            "disclosureCoreDigest": "e" * 64},
         "declaration": {"authoring": [{"assurance": "selfDeclared", "assertedBy": "x"}],
                         "reviewRuns": [], "findings": [], "findingsTotal": 0, "nonClaims": ["n"]},
         "coverage": {"status": "UNKNOWN"},
         "times": {"declaredAt": "2026-08-31T20:00:00Z", "signedAt": "2026-08-31T20:00:00Z"},
         "limitations": ["l"]}
    assert any("limitationCodes is required" in e
               for e in AR.validate_agent_review_v02_predicate(p))
    p["limitationCodes"] = AR.derive_limitation_codes(p)
    assert not any("limitationCodes" in e for e in AR.validate_agent_review_v02_predicate(p))


def test_v01_verlangt_sie_NICHT_aber_erlaubt_sie():
    p = {"schemaVersion": "0.1.0", "reviewId": "r",
         "subjectContext": {"kind": "githubPullRequest", "forge": "g", "repositoryId": "R",
                            "pullRequestNodeId": "P", "headSha": "a" * 40, "baseSha": "b" * 40,
                            "reviewedDiffDigest": "c" * 64, "bodyCoreDigest": "d" * 64},
         "declaration": {"authoring": [{"assurance": "selfDeclared", "assertedBy": "x"}],
                         "reviewRuns": [], "findings": [], "findingsTotal": 0, "nonClaims": ["n"]},
         "coverage": {"status": "UNKNOWN"},
         "times": {"declaredAt": "2026-08-31T20:00:00Z", "signedAt": "2026-08-31T20:00:00Z"},
         "limitations": ["l"]}
    assert AR.validate_agent_review_predicate(p) == []
    p["limitationCodes"] = AR.derive_limitation_codes(p)
    assert AR.validate_agent_review_predicate(p) == []


# ── 5) signedAt ist deklariert, nicht beobachtet ──────────────────────────────────────────────
#
# Der Auftrag laesst zwei Wege zu: `signedAt` durch den Signierpfad SETZEN, oder es als DEKLARIERT
# kennzeichnen. Der zweite gilt bereits — und genau deshalb steht dieser Test hier: eine erfuellte
# Eigenschaft ohne Test ist eine, die beim naechsten Umbau still verschwindet. Er pinnt sie, statt
# sie zu behaupten.

def test_signedAt_wird_als_selbstdeklariert_gefuehrt_nie_staerker():
    achsen = AR._zeitachsen({"times": {"signedAt": "2026-08-31T20:00:00Z"},
                             "declaration": {}, "coverage": {"status": "UNKNOWN"}})
    assert achsen["signature_time_status"] == "SELF_DECLARED"


def test_ohne_signedAt_heisst_es_ABSENT_nicht_etwa_ok():
    achsen = AR._zeitachsen({"times": {}, "declaration": {}, "coverage": {"status": "UNKNOWN"}})
    assert achsen["signature_time_status"] == "ABSENT"


def test_externe_zeit_bleibt_NOT_EVALUATED_denn_wir_haben_nicht_nachgesehen():
    """NOT_EVALUATED und ABSENT sind zwei verschiedene Aussagen, und die Verwechslung waere ein
    stiller Freibrief: 'es gibt keinen Anker' klingt wie eine Messung, ist aber keine."""
    achsen = AR._zeitachsen({"times": {"anchoredAt": "2026-08-31T20:00:00Z"},
                             "declaration": {}, "coverage": {"status": "UNKNOWN"}})
    assert achsen["external_time_status"] == "NOT_EVALUATED"


def test_die_ganzzahl_pruefung_an_allen_randfaellen():
    """Eine Jury-Linse (qwen2.5-coder:32b) hielt `isinstance(v, bool) or not isinstance(v, int)` fuer
    zu streng und meinte, sie lehne auch echte Ganzzahlen ab. Gemessen an acht Faellen trifft das
    NICHT zu — aber die genannte Risikoklasse ist echt, und ein widerlegter Einwand ist ein guter
    Grund, die Eigenschaft festzuschreiben statt sie nur einmal nachzurechnen.

    Besonders `IntEnum`: es IST ein int und kein bool, wird also zu Recht angenommen. Genau dort
    haette eine zu grobe Pruefung zugeschlagen.
    """
    import enum

    class Stufe(enum.IntEnum):
        DREI = 3

    for wert in (5, 0, Stufe.DREI, None):
        assert AR._validate_coverage(_cov(status="UNKNOWN", observedRuns=wert)) == [], wert
    for wert in (True, False, "5", 5.0, [], {}):
        assert AR._validate_coverage(_cov(status="UNKNOWN", observedRuns=wert)), wert
