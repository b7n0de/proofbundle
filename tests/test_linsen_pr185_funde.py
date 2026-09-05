"""Die Funde der drei Review-Linsen auf PR 185 (05.09.2026) — je Fund die Messung, die rot war.

Linse 1 (Verifier-Korrektheit) gab REJECT mit drei P1-Funden, Linse 2 (Korpus- und
Test-Integritaet) und Linse 3 (Paket, Doku, Receipts) FOLLOWUP. Jeder Fund wurde VOR dem Fix am
Quelltext bestaetigt; die Reproducer der Linsen liegen ausserhalb des Repos. Diese Datei haelt
die Faelle fest, an denen gemessen wurde — mit Predicates AUS DEM KORPUS, nicht selbstgebaut:
ein selbstgebautes Fixture prueft die Form, die man im Kopf hat (Teil A4 hat das gemessen).
"""
from __future__ import annotations

import base64
import copy
import inspect
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofbundle import agent_review as ar
from proofbundle.experimental import attested_inference as ai

REPO = Path(__file__).resolve().parents[1]
KORPUS = REPO / "conformance" / "agent_review"
SK = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
PK = SK.public_key().public_bytes_raw()


def _korpus_predicate(name: str) -> dict:
    return json.loads((KORPUS / name / "predicate.json").read_text(encoding="utf-8"))


def _v02() -> dict:
    return _korpus_predicate("agent-review-v02-positive-control-default-policy-decides-accept")


def _v01() -> dict:
    env = json.loads((KORPUS / "agent-review-positive-control-valid-self-declared"
                      / "envelope.json").read_text(encoding="utf-8"))
    return json.loads(base64.b64decode(env["payload"], validate=True))["predicate"]


def _claim(wert: str) -> dict:
    return {"kind": "reviewCompleted", "value": wert, "assertedBy": "Agent A",
            "assurance": "selfDeclared"}


# ── F1 (P1): CONFLICT ist fatal, mit und ohne Policy ────────────────────────────────────────────

def test_f1_zwei_widerspruechliche_reviewzeiten_sind_unter_der_standardpolicy_nicht_ok():
    """GEMESSEN vor dem Fix: ok=True, safeForAutomation=True, errors=[] — unter load_policy()."""
    p = copy.deepcopy(_v02())
    p["declaration"]["timeClaims"] = [_claim("2026-09-01T10:00:00Z"), _claim("2026-09-04T22:00:00Z")]
    assert ar.validate_agent_review_v02_predicate(p) == [], "der Validator laesst den Fall durch — das ist die Vorbedingung des Funds"
    env = ar.emit_agent_review(p, SK)
    sd = ar._subject_digest(p)
    for pol in (ar.load_policy(), None):
        r = ar.verify_agent_review_v02(env, PK, expected_subject_digest=sd, policy=pol)
        assert r["event_time_status"] == "CONFLICT"
        assert r["time_consistency_ok"] is False
        assert r["ok"] is False, f"policy={pol is not None}: {r['errors'][:2]}"
        assert "TIME_CLAIMS_CONFLICT" in r["reason_codes"]
        assert r["automation"]["safeForAutomation"] is not True


def test_f1_kontrolle_eine_reviewzeit_bleibt_ok():
    p = copy.deepcopy(_v02())
    p["declaration"]["timeClaims"] = [_claim("2026-09-01T10:00:00Z")]
    env = ar.emit_agent_review(p, SK)
    r = ar.verify_agent_review_v02(env, PK, expected_subject_digest=ar._subject_digest(p),
                                   policy=ar.load_policy())
    assert r["time_consistency_ok"] is True
    assert r["ok"] is True, r["errors"][:2]
    assert "TIME_CLAIMS_CONFLICT" not in r["reason_codes"]


def test_f1_die_zeitpolicy_hat_einen_aufrufer():
    """`evaluate_time_policy` hatte NULL Produktions-Aufrufer. Eine Policy mit `time` wird jetzt
    gegen die Achsen gehalten, und die strengere Entscheidung gewinnt."""
    p = _v02()
    env = ar.emit_agent_review(p, SK)
    sd = ar._subject_digest(p)
    ohne = ar.verify_agent_review_v02(env, PK, expected_subject_digest=sd, policy=ar.load_policy())
    assert ohne["time_policy_decision"] is None, "die Standard-Policy fuehrt keine Zeitanforderung"
    assert ohne["policy_decision"] == "accept"
    pol = dict(ar.load_policy())
    pol["time"] = {"kind": "freshness"}
    mit = ar.verify_agent_review_v02(env, PK, expected_subject_digest=sd, policy=pol)
    assert mit["time_policy_decision"] == "insufficient_evidence", mit["policy_reason"].get("time")
    assert mit["policy_decision"] == "insufficient_evidence", "die strengere Entscheidung gewinnt"
    assert mit["ok"] is False


# ── F2 (P1): die Weiche wirft nicht, wenn der Absender die Fassung waehlt ───────────────────────

def test_f2_policy_auf_einem_v01_umschlag_ist_ein_urteil_kein_typeerror():
    """GEMESSEN vor dem Fix: TypeError 'unexpected keyword argument policy' — nur fuer v0.1."""
    p = _v01()
    env = ar.emit_agent_review(p, SK, legacy_v01=True)
    r = ar.verify_agent_review_any(env, PK, expected_subject_digest=ar._subject_digest(p),
                                   policy=ar.load_policy())
    assert r["predicateVersionStatus"] == "legacy"
    assert r["policy_decision"] is None
    assert "ARGUMENT_NOT_APPLICABLE_TO_VERSION" in r["advisory_codes"]
    assert ar.POLICY_NOT_EVALUATED in r["advisory_codes"]
    assert any("policy" in w for w in r["warnings"]), r["warnings"]


def test_f2_ein_argument_das_keine_fassung_kennt_faellt_fuer_beide_gleich():
    for pred, legacy in ((_v02(), False), (_v01(), True)):
        env = ar.emit_agent_review(pred, SK, legacy_v01=legacy)
        with pytest.raises(TypeError, match="unknown to both"):
            ar.verify_agent_review_any(env, PK, polcy=ar.load_policy())


# ── F3 (P1): die Policy-Datei ist Eingabe ───────────────────────────────────────────────────────

@pytest.mark.parametrize("feld, wert", [
    ("blocking", "COVERAGE_PARTIAL"),
    ("never_blocking", "NOT_QUALITY_ATTESTATION"),
    ("require_coverage_status", "XPARTIALX"),
    ("require_coverage_status", "COMPLETE"),
    ("blocking", ["COVERAGE_PARTIAL", "COVERAGE_PARTIAL"]),
    ("blocking", ["KEIN_CODE"]),
    ("require_coverage_status", ["VOLLSTAENDIG"]),
    ("time", {"kind": "morgens"}),
    ("time", "freshness"),
])
def test_f3_eine_falsch_geformte_policy_entscheidet_nicht(feld, wert):
    """GEMESSEN vor dem Fix: blocking als Zeichenkette -> set() der ZEICHEN, blocking_hit=[],
    accept, ok=True, safeForAutomation=True; require_coverage_status 'XPARTIALX' -> Teilstring-
    Test -> accept, wo ['COMPLETE'] korrekt insufficient_evidence gibt."""
    pol = dict(ar.load_policy())
    pol[feld] = wert
    with pytest.raises(ar.AgentReviewError):
        ar.evaluate_limitation_policy(_v02(), pol)
    p = _v02()
    env = ar.emit_agent_review(p, SK)
    r = ar.verify_agent_review_v02(env, PK, expected_subject_digest=ar._subject_digest(p), policy=pol)
    assert r["policy_decision"] == "insufficient_evidence"
    assert "POLICY_NOT_EVALUABLE" in r["reason_codes"]
    assert r["ok"] is False
    assert r["automation"]["safeForAutomation"] is not True


def test_f3_load_policy_prueft_die_datei(tmp_path):
    pfad = tmp_path / "policy.json"
    pfad.write_text(json.dumps({"name": "x", "blocking": "COVERAGE_PARTIAL"}), encoding="utf-8")
    with pytest.raises(ar.AgentReviewError, match="list of code strings"):
        ar.load_policy(pfad)
    assert ar.load_policy()["name"] == ar.STANDARD_POLICY_NAME, "die Standard-Policy besteht ihre eigene Pruefung"


# ── F4 (P2): die Renderer lesen drei Marker, und ein ausdrueckliches Argument gewinnt ────────────

_V02_GEGENBEWEISE = (
    "agent-review-v02-counter-proof-limitation-codes-are-required",
    "agent-review-v02-counter-proof-disclosure-core-digest-is-required",
    "agent-review-v02-counter-proof-fixcommit-must-be-the-full-sha",
)


@pytest.mark.parametrize("name", _V02_GEGENBEWEISE, ids=lambda s: s[-40:])
def test_f4_die_drei_v02_gegenbeweise_rendern_nicht_mehr_durch(name):
    """GEMESSEN vor dem Fix: 0 von 10 v0.2-Korpus-Predicates als v0.2 erkannt (alle ohne
    timeClaims); diese drei rendern ueber beide Flaechen durch, weil sie unter v0.1 gelesen wurden."""
    p = _korpus_predicate(name)
    assert "timeClaims" not in p["declaration"], "der Fall traegt genau NICHT den alten einzigen Marker"
    assert ar._traegt_v02_felder(p)
    with pytest.raises(ar.AgentReviewError, match="v0.2"):
        ar.render_disclosure_block(p, receipt_digest="a" * 64)
    with pytest.raises(ar.AgentReviewError, match="v0.2"):
        ar.render_disclosure_line(p, receipt_digest="a" * 64, receipt_url="https://x/r")


def test_f4_alle_v02_korpus_predicates_werden_erkannt_und_keines_der_v01():
    v02 = [d for d in KORPUS.iterdir() if d.is_dir() and d.name.startswith("agent-review-v02-")
           and (d / "predicate.json").is_file()]
    assert len(v02) >= 10, len(v02)
    for d in v02:
        assert ar._traegt_v02_felder(_korpus_predicate(d.name)), d.name
    assert not ar._traegt_v02_felder(_v01())


def test_f4_ein_ausdrueckliches_argument_gewinnt_ueber_die_marker():
    p01 = _v01()
    assert not ar._traegt_v02_felder(p01)
    ar.render_disclosure_block(p01, receipt_digest="a" * 64)  # ohne Argument: v0.1, rendert
    with pytest.raises(ar.AgentReviewError, match="v0.2"):
        ar.render_disclosure_block(p01, receipt_digest="a" * 64, legacy_v01=False)
    p02 = _korpus_predicate(_V02_GEGENBEWEISE[2])  # kurzer fixCommit: unter v0.1 zulaessig
    assert ar.render_disclosure_block(p02, receipt_digest="a" * 64, legacy_v01=True)


# ── F5 + F8 (P2/P3): attested_inference wirft nicht roh ─────────────────────────────────────────

@pytest.mark.parametrize("evidence", [{"x": {1, 2}}, {"x": object()}, {"x": b"bytes"}, {1: "a", "b": 2}])
def test_f5_nicht_serialisierbarer_inhalt_ist_malformed_kein_typeerror(evidence):
    r = ai.check_on_receipt(evidence, provider="p", nonce="n", request_bytes=b"r", response_bytes=b"a")
    assert r["outcome"] == ai.OUTCOME_ATTESTATION_FAILURE
    assert r["reasons"] == [ai.REASON_MALFORMED]
    assert r["evidence_digest"] is None


@pytest.mark.parametrize("kaputt", [None, "accepted", 42, [], ["accepted"]])
def test_f8_counts_as_own_domain_urteilt_ueber_nicht_dicts(kaputt):
    assert ai.counts_as_own_domain(kaputt) is False


def test_f8_kontrolle_ein_akzeptiertes_urteil_zaehlt():
    assert ai.counts_as_own_domain({"outcome": ai.OUTCOME_ACCEPTED}) is True


# ── F6 (P2): die Weiche dekodiert wie dsse ──────────────────────────────────────────────────────

def test_f6_ein_urlsafe_umschlag_ist_ueber_die_weiche_dasselbe_urteil_wie_direkt():
    p = _v02()
    env = ar.emit_agent_review(p, SK)
    roh = base64.b64decode(env["payload"], validate=True)
    env_url = dict(env)
    env_url["payload"] = base64.urlsafe_b64encode(roh).decode("ascii")
    assert env_url["payload"] != env["payload"] or "-" not in env_url["payload"], "Vorbedingung: das Alphabet unterscheidet sich nur, wenn die Bytes es zeigen"
    sd = ar._subject_digest(p)
    direkt = ar.verify_agent_review_v02(env_url, PK, expected_subject_digest=sd)
    weiche = ar.verify_agent_review_any(env_url, PK, expected_subject_digest=sd)
    assert weiche["ok"] == direkt["ok"], (weiche["reason_codes"], direkt["reason_codes"])
    assert weiche["reason_code"] != "AGENT_REVIEW_ENVELOPE_UNREADABLE"
    assert weiche["predicateVersionStatus"] == "current"


# ── F7 (P3): reason_codes traegt nur fatale Codes ───────────────────────────────────────────────

def test_f7_ein_gueltiges_receipt_ohne_policy_hat_leere_reason_codes():
    p = _v02()
    env = ar.emit_agent_review(p, SK)
    r = ar.verify_agent_review_v02(env, PK, expected_subject_digest=ar._subject_digest(p))
    assert r["ok"] is True
    assert r["reason_codes"] == [], r["reason_codes"]
    assert r["reason_code"] is None
    assert ar.POLICY_NOT_EVALUATED in r["advisory_codes"]


def test_f7_die_altfassung_ist_ein_hinweis_kein_grund():
    p = _v01()
    env = ar.emit_agent_review(p, SK, legacy_v01=True)
    r = ar.verify_agent_review_any(env, PK, expected_subject_digest=ar._subject_digest(p))
    assert r["ok"] is True, r["errors"][:2]
    assert ar.AGENT_REVIEW_LEGACY_V01 in r["advisory_codes"]
    assert ar.AGENT_REVIEW_LEGACY_V01 not in r["reason_codes"]
    assert r["reason_codes"] == []


# ── Linse 3, FUND-1: die Receipts reisen in der sdist ───────────────────────────────────────────

def test_l3_manifest_nimmt_die_receipts_mit():
    m = (REPO / "MANIFEST.in").read_text(encoding="utf-8")
    assert "receipts/agent_review" in m
    assert (REPO / "receipts" / "agent_review" / "proofbundle_185.r2.receipt.json").is_file()


def test_die_weiche_filtert_nach_den_echten_signaturen():
    """Die erlaubten Argumente kommen aus den Signaturen, nicht aus einer getippten Liste."""
    p02 = set(inspect.signature(ar.verify_agent_review_v02).parameters)
    p01 = set(inspect.signature(ar.verify_agent_review).parameters)
    assert "policy" in p02 and "policy" not in p01, "die Vorbedingung des Funds F2 gilt weiter"
