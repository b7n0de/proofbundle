"""Die fuenf P0-Tests 1, 8, 9, 12 und 19 — exakt nach ihrer URSPRUENGLICHEN Mutation.

WARUM SIE NEU GEBAUT WERDEN (P0.5.3 der Gegenlesung Runde 2). Die Gegenlesung hat drei davon
ausdruecklich als WIDERLEGT eingestuft — nicht, weil die Software sie nicht besteht, sondern weil
die gelieferten Vektoren etwas ANDERES mutierten als der Bericht behauptete:

    Test  1  WIDERLEGT   der Vektor mutierte die Assurance-Sprosse, nicht ein falsches Modelllabel
    Test  8  BELEGT OFFEN  der Digest-Helfer lehnt ab, Renderer und Verifier sahen den Body nicht
    Test  9  BELEGT OFFEN  ein abweichender Expected Digest faellt — OHNE ihn nahm der Verifier an
    Test 12  WIDERLEGT   nur "COMPLETE braucht Counts", kein verschwiegener Lauf
    Test 19  WIDERLEGT   als gefahren genannt, ein Supersession-Fall existierte gar nicht

Zwei davon liessen sich vorher gar nicht ehrlich bauen: Test 8 brauchte einen Verifier, der den
tatsaechlichen Body sieht (P0.2), Test 19 einen Resolver (heute gebaut). Test 9 brauchte die
Trennung von `ok` und `internal_consistency_ok` (P0.3).
"""
from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofbundle import agent_review as AR
from proofbundle import canonical, dsse

SK = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
PK = SK.public_key().public_bytes_raw()


def _block(assurance: str = "selfDeclared") -> str:
    return (f"{AR.DISCLOSURE_BEGIN}\n**Agent review receipt** · Tier 1, {assurance}\n"
            f"<sub><code>sha256:{'a' * 64}</code></sub>\n{AR.DISCLOSURE_END}")


def _rumpf() -> str:
    return "Der Vorgang.\n\n" + _block() + "\n"


def _pred(body: str | None = None, **zusatz) -> dict:
    body = _rumpf() if body is None else body
    sc = {"kind": "githubPullRequest", "forge": "github", "repositoryId": "R",
          "pullRequestNodeId": "P", "headSha": "a" * 40, "baseSha": "b" * 40,
          "reviewedDiffDigest": "c" * 64, "bodyCoreDigest": AR.body_core_digest(body)}
    if AR.DISCLOSURE_BEGIN in body:
        sc["disclosureCoreDigest"] = AR.disclosure_core_digest(body)
    p = {"schemaVersion": "0.1.0", "reviewId": "r1", "subjectContext": sc,
         "declaration": {"authoring": [{"assurance": "selfDeclared", "assertedBy": "agent"}],
                         "reviewRuns": [], "findings": [], "findingsTotal": 0,
                         "nonClaims": ["kein Sicherheitsaudit"]},
         "coverage": {"status": "UNKNOWN"},
         "times": {"declaredAt": "2026-08-31T20:00:00Z", "signedAt": "2026-08-31T20:00:00Z"},
         "limitations": ["selbstdeklariert"]}
    p.update(zusatz)
    return p


def _env(p: dict) -> dict:
    st = {"_type": AR.STATEMENT_TYPE,
          "subject": [{"name": AR._subject_name(p), "digest": {"sha256": AR._subject_digest(p)}}],
          "predicateType": AR.AGENT_REVIEW_PREDICATE_TYPE, "predicate": p}
    return dsse.sign_envelope(canonical.canonicalize_statement(st), SK,
                              payload_type=AR.INTOTO_STATEMENT_PAYLOAD_TYPE)


# ══ Test 1 · falsches Modelllabel, verweigert beim ERZEUGEN ════════════════════════════════════

def test_01_ein_producer_feld_das_die_form_verletzt_wird_beim_emit_verweigert():
    p = _pred(producer={"id": "claude-x", "modell": "erfunden"})
    with pytest.raises(AR.AgentReviewError):
        AR.emit_agent_review(p, SK, strict=True)


def test_01b_ein_nicht_stringiges_modelllabel_wird_verweigert():
    p = _pred(producer={"id": {"nicht": "string"}})
    assert AR.validate_agent_review_predicate(p, strict=True)


def test_01c_DIE_GRENZE_ein_falsches_aber_wohlgeformtes_label_ist_NICHT_erkennbar():
    """DIE EHRLICHE FASSUNG VON TEST 1, und sie ist der eigentliche Wert dieses Tests.

    Die urspruengliche Formulierung lautete "falsches Modelllabel, verweigert beim Erzeugen". Der
    Teil, der maschinell geht, ist die FORM: ein unbekanntes Feld oder ein Nicht-String faellt.
    Der Teil, der NICHT geht, ist der Inhalt: kein Validator dieser Welt weiss, welches Modell
    tatsaechlich gelaufen ist. `producer.id = "claude-opus-5"` ist wohlgeformt, auch wenn ein
    anderes Modell gearbeitet hat.

    Dieser Test PINNT die Grenze, statt sie zu verschweigen — und er verlangt, dass das Predicate
    sie selbst benennt. Ein Beleg, der eine Zusicherung nicht geben kann, muss das sagen.
    """
    p = _pred(producer={"id": "ein-modell-das-nicht-gelaufen-ist"})
    assert AR.validate_agent_review_predicate(p, strict=True) == [], (
        "die Form ist gueltig — das ist die Grenze, nicht ein Defekt")
    codes = AR.derive_limitation_codes(p)
    assert "IDENTITY_UNBOUND" in codes, (
        "das Predicate behauptet eine Identitaet, ohne sie zu binden, und sagt es nicht")


# ══ Test 8 · Renderer UND Verifier sehen den tatsaechlichen Body ═══════════════════════════════

def test_08_doppelte_marker_werden_vom_digest_helfer_abgelehnt():
    body = _rumpf() + "\n" + _block()
    with pytest.raises(AR.AgentReviewError):
        AR.body_core_digest(body)


def test_08b_der_VERIFIER_sieht_den_tatsaechlichen_body_jetzt_auch():
    """Der offene Teil von Test 8: frueher prueften Renderer und Verifier den Body NICHT."""
    body = _rumpf()
    p = _pred(body)
    r = AR.verify_agent_review(_env(p), PK, strict=True,
                               expected_subject_digest=AR._subject_digest(p),
                               observed_body=body + "\n" + _block())
    assert r["body_core_digest_match"] == "NOT_MEASURABLE"
    assert r["ok"] is False, "ein doppelter Block im gepruefen Body blieb folgenlos"


def test_08c_ein_veraenderter_body_faellt_beim_verifier():
    body = _rumpf()
    p = _pred(body)
    r = AR.verify_agent_review(_env(p), PK, strict=True,
                               expected_subject_digest=AR._subject_digest(p),
                               observed_body="Ein ganz anderer Vorgang.\n\n" + _block() + "\n")
    assert r["body_core_digest_match"] == "MISMATCH"
    assert r["ok"] is False


# ══ Test 9 · OHNE Expected Digest darf der Verifier NICHT annehmen ═════════════════════════════

def test_09_ein_abweichender_expected_digest_faellt():
    p = _pred()
    r = AR.verify_agent_review(_env(p), PK, strict=True, expected_subject_digest="f" * 64)
    assert r["subject_binding_ok"] is False and r["ok"] is False


def test_09b_OHNE_expected_digest_ist_ok_FALSCH_und_das_war_der_offene_teil():
    """Der Befund lautete woertlich: "Ohne Expected Digest akzeptiert der Verifier das Receipt."

    Er tut es nicht mehr. `internal_consistency_ok` bleibt True — das Receipt IST in sich stimmig —
    aber `ok` ist False, weil nichts belegt, dass es zu dem Objekt vor dem Leser gehoert. Zwei
    Aussagen, zwei Felder; die Verwechslung war der Angriff.
    """
    p = _pred()
    r = AR.verify_agent_review(_env(p), PK, strict=True)
    assert r["internal_consistency_ok"] is True
    assert r["ok"] is False
    assert r["subject_expectation"] == "not_supplied"
    assert any("no expected subject digest" in e for e in r["errors"])


# ══ Test 12 · der verschwiegene Lauf ═══════════════════════════════════════════════════════════

def test_12_COMPLETE_ohne_erwartung_wird_verweigert():
    p = _pred()
    p["coverage"] = {"status": "COMPLETE"}
    assert AR.validate_agent_review_predicate(p, strict=True)


def test_12b_COMPLETE_null_von_null_wird_verweigert():
    """Der Produzent konnte sich frueher selbst COMPLETE 0/0 erklaeren."""
    p = _pred()
    p["coverage"] = {"status": "COMPLETE", "observedRuns": 0, "expectedRuns": 0,
                     "sources": ["s"], "window": "w", "collectionMethod": "m"}
    errs = AR.validate_agent_review_predicate(p, strict=True)
    assert any("empty expectation" in e for e in errs), errs


def test_12c_DER_VERSCHWIEGENE_LAUF_wird_erkannt():
    """Der Kern von Test 12: mehr Funde behauptet als aufgefuehrt, ohne die Luecke zu benennen."""
    p = _pred()
    p["declaration"]["findings"] = []
    p["declaration"]["findingsTotal"] = 8
    p["coverage"] = {"status": "PARTIAL", "knownGaps": []}
    errs = AR.validate_agent_review_predicate(p, strict=True)
    assert errs, "acht behauptete Funde, keiner aufgefuehrt, keine Luecke benannt — angenommen"


def test_12d_dieselbe_luecke_MIT_benannter_gap_ist_zulaessig():
    """Sonst waere die Regel ein Verbot statt einer Offenlegungspflicht."""
    p = _pred()
    p["declaration"]["findings"] = []
    p["declaration"]["findingsTotal"] = 8
    p["coverage"] = {"status": "PARTIAL",
                     "knownGaps": ["acht Funde erhoben, aus Vertraulichkeit nicht aufgefuehrt"]}
    assert AR.validate_agent_review_predicate(p, strict=True) == []


# ══ Test 19 · Supersession, der Fall der ganz fehlte ═══════════════════════════════════════════

def test_19_die_supersession_wird_AUFGELOEST_nicht_nur_validiert():
    """Der Befund lautete: der Fall fehlte, und "der Verifier loest Supersession zudem nicht auf"."""
    alt = _env(_pred())
    d_alt = AR.receipt_digest(alt)
    neu_p = _pred()
    neu_p["reviewId"] = "r2"
    neu_p["supersession"] = {"corrects": [
        {"priorDigest": {"sha256": d_alt}, "reason": "Zeitsemantik praezisiert"}]}
    kette = AR.resolve_receipt_chain([alt, _env(neu_p)], verified={AR.receipt_digest(e) for e in [alt, _env(neu_p)] if isinstance(e, dict) and isinstance(e.get('payload'), str)})
    assert kette["current"] == AR.receipt_digest(_env(neu_p))
    assert kette["corrected"] == [d_alt]
    assert kette["integrity_ok"] is True


def test_19b_der_korrigierte_vorgaenger_bleibt_kryptografisch_gueltig():
    p_alt = _pred()
    alt = _env(p_alt)
    r = AR.verify_agent_review(alt, PK, strict=True,
                               expected_subject_digest=AR._subject_digest(p_alt))
    assert r["crypto_ok"] is True and r["ok"] is True


def test_19c_ein_verschwundener_vorgaenger_macht_die_kette_kaputt():
    alt = _env(_pred())
    neu_p = _pred()
    neu_p["reviewId"] = "r2"
    neu_p["supersession"] = {"corrects": [
        {"priorDigest": {"sha256": AR.receipt_digest(alt)}, "reason": "praezisiert"}]}
    assert AR.resolve_receipt_chain([_env(neu_p)], verified={AR.receipt_digest(e) for e in [_env(neu_p)] if isinstance(e, dict) and isinstance(e.get('payload'), str)})["integrity_ok"] is False


def test_die_fuenf_tests_sind_vollstaendig_und_benannt():
    """Ein Test, der zaehlt — damit ein spaeter entfallener Fall auffaellt statt zu verschwinden."""
    import sys
    namen = [n for n in dir(sys.modules[__name__]) if n.startswith("test_")]
    for nr in ("01", "08", "09", "12", "19"):
        assert any(n.startswith(f"test_{nr}") for n in namen), f"P0-Test {nr} fehlt"
