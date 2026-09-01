"""Die zwoelf offenen Tests aus dem Zeitsemantik-Entscheid — Nummern 9 bis 20.

Die acht Versions- und Kompatibilitaetstests (1 bis 8) stehen in
`test_agent_review_zeitsemantik.py`. Hier stehen die sechs POLICYTESTS und die sechs
SUPERSESSIONTESTS, mit der Nummer des Entscheids im Namen, damit die Zuordnung nachpruefbar ist
und nicht behauptet werden muss.

DIE EINE EINSICHT, die alle sechs Policytests tragen: eine Selbstauskunft ueber die eigene Zeit
kann keine Zeitpolicy erfuellen, denn genau diese Auskunft ist das, was die Policy pruefen soll.
Und ein RFC-3161- oder OpenTimestamps-Beleg hebt daran NICHTS: er sagt, dass ein Byte-Objekt
existierte, nicht wann jemand einen Review durchgefuehrt hat. Zwei verschiedene Tatsachen.
"""
from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofbundle import agent_review as AR
from proofbundle import canonical, dsse

SK = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
PK = SK.public_key().public_bytes_raw()

_SELBST = {"event_time_status": "SELF_DECLARED", "signature_time_status": "SELF_DECLARED",
           "observation_time_status": "ABSENT", "external_time_status": "NOT_EVALUATED"}


# ══ Policytests 9 bis 14 ═══════════════════════════════════════════════════════════════════════

def test_09_selbstdeklarierte_reviewzeit_erfuellt_keine_frische_policy():
    e = AR.evaluate_time_policy(_SELBST, {"kind": "freshness"})
    assert e["decision"] == "insufficient_evidence"
    assert "cannot satisfy" in e["reason"]


def test_10_selbstdeklarierte_signaturzeit_erfuellt_keine_ttl_policy():
    assert AR.evaluate_time_policy(_SELBST, {"kind": "ttl"})["decision"] == "insufficient_evidence"
    assert AR.evaluate_time_policy(
        _SELBST, {"kind": "certificate_validity"})["decision"] == "insufficient_evidence"


def test_11_rfc3161_hebt_die_signaturachse_und_NICHT_die_ereigniszeit():
    """Die Grenze ist der ganze Punkt: der Zeitstempel belegt Existenz, nicht den Review."""
    nach = AR.apply_time_evidence(_SELBST, {"kind": "rfc3161", "verified": True})
    assert nach["signature_time_status"] == "PLATFORM_ATTESTED"
    assert nach["event_time_status"] == "SELF_DECLARED", "die Ereigniszeit wurde mit angehoben"
    assert AR.evaluate_time_policy(nach, {"kind": "ttl"})["decision"] == "accept"
    assert AR.evaluate_time_policy(
        nach, {"kind": "freshness"})["decision"] == "insufficient_evidence"


def test_12_opentimestamps_begruendet_eine_existenzgrenze_nicht_den_reviewzeitpunkt():
    nach = AR.apply_time_evidence(_SELBST, {"kind": "opentimestamps", "verified": True})
    assert nach["external_time_status"] == "EXTERNALLY_ANCHORED"
    assert nach["event_time_status"] == "SELF_DECLARED"
    assert nach["signature_time_status"] == "SELF_DECLARED", (
        "OTS hat die Signaturachse angehoben — es benennt aber keinen signierenden Dienst")
    assert AR.evaluate_time_policy(nach, {"kind": "existence"})["decision"] == "accept"
    assert AR.evaluate_time_policy(
        nach, {"kind": "freshness"})["decision"] == "insufficient_evidence"


def test_12b_ungepruefte_evidenz_hebt_gar_nichts():
    """Sonst waere die Anhebung eine Behauptung der Gegenseite."""
    for ev in ({"kind": "rfc3161"}, {"kind": "rfc3161", "verified": False},
               {"kind": "rfc3161", "verified": "ja"}):
        assert AR.apply_time_evidence(_SELBST, ev) == _SELBST


def test_13_beobachtung_ohne_benannte_identitaet_bleibt_selbstauskunft():
    ohne = {"declaration": {"timeClaims": [{"kind": "reviewCompleted",
                                            "value": "2026-08-31T15:45:00Z"}]},
            "observations": [{"observedAt": "2026-08-31T16:00:00Z"}], "times": {}}
    assert AR._zeitachsen(ohne)["observation_time_status"] == "SELF_DECLARED"
    mit = dict(ohne)
    mit["observations"] = [{"observer": {"id": "runner-1"}, "observedAt": "2026-08-31T16:00:00Z"}]
    assert AR._zeitachsen(mit)["observation_time_status"] == "RUNNER_OBSERVED"


def test_14_widersprechende_zeiten_ergeben_CONFLICT_und_die_policy_lehnt_ab():
    """Ein Zeuge kann nicht beobachten, was noch nicht geschehen ist."""
    p = {"declaration": {"timeClaims": [{"kind": "reviewCompleted",
                                         "value": "2026-08-31T15:45:00Z"}]},
         "observations": [{"observer": {"id": "runner-1"},
                           "observedAt": "2026-08-31T10:00:00Z"}], "times": {}}
    achsen = AR._zeitachsen(p)
    assert achsen["event_time_status"] == "CONFLICT"
    assert achsen["observation_time_status"] == "CONFLICT"
    e = AR.evaluate_time_policy(achsen, {"kind": "freshness"})
    assert e["decision"] == "reject", "CONFLICT wurde zu einem schwachen Beleg statt zu einem kaputten"


def test_14b_eine_beobachtung_NACH_dem_ereignis_ist_kein_widerspruch():
    """Sonst waere CONFLICT eine Konstante und wuerde nichts unterscheiden."""
    p = {"declaration": {"timeClaims": [{"kind": "reviewCompleted",
                                         "value": "2026-08-31T15:45:00Z"}]},
         "observations": [{"observer": {"id": "runner-1"},
                           "observedAt": "2026-08-31T16:00:00Z"}], "times": {}}
    assert AR._zeitachsen(p)["event_time_status"] == "SELF_DECLARED"


def test_ohne_benannte_policy_gibt_es_keine_zeitfreigabe():
    e = AR.evaluate_time_policy(_SELBST, {"kind": "erfunden"})
    assert e["decision"] == "insufficient_evidence"


# ══ Supersessionstests 15 bis 20 ═══════════════════════════════════════════════════════════════

def _pred(reviewid: str, *, supersession: dict | None = None) -> dict:
    p = {"schemaVersion": "0.1.0", "reviewId": reviewid,
         "subjectContext": {"kind": "githubPullRequest", "forge": "g", "repositoryId": "R",
                            "pullRequestNodeId": "P", "headSha": "a" * 40, "baseSha": "b" * 40,
                            "reviewedDiffDigest": "c" * 64, "bodyCoreDigest": "d" * 64},
         "declaration": {"authoring": [{"assurance": "selfDeclared", "assertedBy": "x"}],
                         "reviewRuns": [], "findings": [], "findingsTotal": 0, "nonClaims": ["n"]},
         "coverage": {"status": "UNKNOWN"},
         "times": {"declaredAt": "2026-08-31T20:00:00Z", "signedAt": "2026-08-31T20:00:00Z"},
         "limitations": ["l"]}
    if supersession is not None:
        p["supersession"] = supersession
    return p


def _env(p: dict) -> dict:
    st = {"_type": AR.STATEMENT_TYPE,
          "subject": [{"name": AR._subject_name(p), "digest": {"sha256": AR._subject_digest(p)}}],
          "predicateType": AR.AGENT_REVIEW_PREDICATE_TYPE, "predicate": p}
    return dsse.sign_envelope(canonical.canonicalize_statement(st), SK,
                              payload_type=AR.INTOTO_STATEMENT_PAYLOAD_TYPE)


def test_15_das_korrektur_receipt_bindet_exakt_den_digest_des_vorgaengers():
    alt = _env(_pred("r1"))
    d_alt = AR.receipt_digest(alt)
    neu = _env(_pred("r2", supersession={"corrects": [
        {"priorDigest": {"sha256": d_alt}, "reason": "Zeitsemantik praezisiert"}]}))
    kette = AR.resolve_receipt_chain([alt, neu])
    assert kette["current"] == AR.receipt_digest(neu)
    assert kette["corrected"] == [d_alt]
    assert kette["integrity_ok"] is True


def test_16_ein_falscher_vorgaengerdigest_faellt():
    alt = _env(_pred("r1"))
    neu = _env(_pred("r2", supersession={"corrects": [
        {"priorDigest": {"sha256": "f" * 64}, "reason": "zeigt ins Leere"}]}))
    kette = AR.resolve_receipt_chain([alt, neu])
    assert kette["integrity_ok"] is False
    assert "f" * 64 in kette["missing_predecessors"]


def test_17_ein_fehlender_korrekturgrund_faellt():
    p = _pred("r2", supersession={"corrects": [{"priorDigest": {"sha256": "a" * 64}}]})
    errs = AR.validate_agent_review_predicate(p)
    assert any("reason" in e for e in errs), errs
    p2 = _pred("r2", supersession={"corrects": [
        {"priorDigest": {"sha256": "a" * 64}, "reason": ""}]})
    assert any("reason" in e for e in AR.validate_agent_review_predicate(p2))


def test_18_der_vorgaenger_bleibt_kryptografisch_gueltig_und_ist_trotzdem_korrigiert():
    """Beides gilt gleichzeitig — ein korrigiertes Receipt wird nicht ungueltig, es wird ueberholt."""
    palt = _pred("r1")
    alt = _env(palt)
    d_alt = AR.receipt_digest(alt)
    neu = _env(_pred("r2", supersession={"corrects": [
        {"priorDigest": {"sha256": d_alt}, "reason": "praezisiert"}]}))
    r = AR.verify_agent_review(alt, PK, strict=True,
                               expected_subject_digest=AR._subject_digest(palt))
    assert r["crypto_ok"] is True and r["ok"] is True, r["errors"]
    kette = AR.resolve_receipt_chain([alt, neu])
    assert d_alt in kette["corrected"]
    assert kette["current"] != d_alt


def test_19_der_aktuelle_verweis_zeigt_nur_auf_das_korrektur_receipt():
    alt = _env(_pred("r1"))
    neu = _env(_pred("r2", supersession={"corrects": [
        {"priorDigest": {"sha256": AR.receipt_digest(alt)}, "reason": "praezisiert"}]}))
    kette = AR.resolve_receipt_chain([alt, neu])
    assert kette["ambiguous"] is False
    assert kette["current_candidates"] == [AR.receipt_digest(neu)]


def test_19b_zwei_unverbundene_receipts_sind_MEHRDEUTIG_und_das_wird_gesagt():
    """Raten waere hier der Fehler: der Resolver nennt die Mehrdeutigkeit, statt eines zu waehlen."""
    kette = AR.resolve_receipt_chain([_env(_pred("r1")), _env(_pred("r2"))])
    assert kette["ambiguous"] is True
    assert kette["current"] is None
    assert len(kette["current_candidates"]) == 2


def test_20_das_entfernen_des_alten_receipts_macht_den_integritaetstest_rot():
    alt = _env(_pred("r1"))
    neu = _env(_pred("r2", supersession={"corrects": [
        {"priorDigest": {"sha256": AR.receipt_digest(alt)}, "reason": "praezisiert"}]}))
    assert AR.resolve_receipt_chain([alt, neu])["integrity_ok"] is True
    ohne_alt = AR.resolve_receipt_chain([neu])
    assert ohne_alt["integrity_ok"] is False, (
        "die Korrektur ist ohne ihren Vorgaenger nicht mehr nachvollziehbar")
    assert AR.receipt_digest(alt) in ohne_alt["missing_predecessors"]


def test_der_receipt_digest_ist_der_des_OBJEKTS_nicht_der_datei():
    """Eine andere Einrueckung derselben Signatur darf nicht wie Faelschung aussehen."""
    env = _env(_pred("r1"))
    umverpackt = json.loads(json.dumps(env, indent=4, sort_keys=True))
    assert AR.receipt_digest(env) == AR.receipt_digest(umverpackt)


def test_der_resolver_prueft_KEINE_signaturen_und_sagt_es():
    kette = AR.resolve_receipt_chain([_env(_pred("r1"))])
    assert "verifies no signatures" in kette["note"]


def test_ein_kaputter_umschlag_bringt_den_resolver_nicht_um():
    kette = AR.resolve_receipt_chain([{"kein": "payload"}, _env(_pred("r1"))])
    assert kette["integrity_ok"] is True
    assert len(kette["current_candidates"]) == 1


# ══ der v0.2-Emit-Weg: Typ und Validator gehen zusammen ════════════════════════════════════════

def _pred_v02(**kw) -> dict:
    p = _pred("r-v02", **kw)
    p["subjectContext"]["disclosureCoreDigest"] = "e" * 64
    p["limitationCodes"] = AR.derive_limitation_codes(p)
    p["declaration"]["timeClaims"] = [
        {"kind": "reviewCompleted", "value": "2026-08-31T15:45:00Z",
         "assertedBy": "ownerOrder", "assurance": "selfDeclared"}]
    return p


def test_der_v02_typ_zieht_seinen_validator_MIT():
    """Ein v0.2-Typ mit v0.1-Pruefung waere die schlimmste der drei Moeglichkeiten: der Leser sieht
    die staerkere Version und bekommt die schwaechere Pruefung."""
    p = _pred_v02()
    del p["limitationCodes"]
    with pytest.raises(AR.AgentReviewError) as e:
        AR.build_agent_review_statement(p, v02=True)
    assert "v0.2" in str(e.value)

    # DER VERGLEICH, den mein erster Entwurf falsch gezogen hatte: ich hatte behauptet, DERSELBE
    # Predicate sei als v0.1 gueltig, der Unterschied liege allein am Schalter. Der Test wurde rot
    # und hatte recht — `declaration.timeClaims` ist in v0.1 gar kein zugelassenes Feld. Der
    # ehrliche Vergleich nimmt deshalb ein Predicate OHNE timeClaims: dort ist das fehlende
    # limitationCodes unter v0.1 in Ordnung und unter v0.2 ein Befund.
    q = _pred("r-vergleich")
    q["subjectContext"]["disclosureCoreDigest"] = "e" * 64
    assert AR.validate_agent_review_predicate(q) == []
    assert any("limitationCodes is required" in x
               for x in AR.validate_agent_review_v02_predicate(q))


def test_ein_v02_statement_traegt_den_v02_predicate_type():
    st = AR.build_agent_review_statement(_pred_v02(), v02=True)
    assert st["predicateType"] == AR.AGENT_REVIEW_PREDICATE_TYPE_V02
    assert AR.build_agent_review_statement(_pred("r1"))["predicateType"] == \
        AR.AGENT_REVIEW_PREDICATE_TYPE


def test_ein_v02_receipt_laesst_sich_emittieren_und_verifizieren():
    p = _pred_v02()
    env = AR.emit_agent_review(p, SK, strict=True, v02=True)
    r = AR.verify_agent_review_v02(env, PK, strict=True,
                                   expected_subject_digest=AR._subject_digest(p))
    assert r["crypto_ok"] is True, r["errors"]
    assert r["event_time_status"] == "SELF_DECLARED"
