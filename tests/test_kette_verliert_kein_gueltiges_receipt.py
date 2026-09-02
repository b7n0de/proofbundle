"""Was der Verifier annimmt, muss die Kette halten koennen — oder es sagen.

DER BEFUND (Tiefen-Gate 5.1.0, 01.09.2026, von zwei unabhaengigen Linsen gefunden und danach von
Hand reproduziert): `dsse` akzeptiert BEIDE base64-Alphabete (die DSSE-Spec verlangt das),
`receipt_digest` nur das Standard-Alphabet und WIRFT — und `resolve_receipt_chain` fing das mit
einem stillen `continue`. Ein kryptografisch gueltiges Receipt fiel damit aus der
Mitgliedschaftsmenge, und die Kette meldete trotzdem `integrity_ok=True`.

BEIDE EINZELENTSCHEIDUNGEN SIND RICHTIG. `validate=True` im Digest steht mit Begruendung da: ohne
es verwirft CPython stillschweigend fremde Zeichen, und ein Angreifer koennte sich den Digest durch
eingestreuten Muell aussuchen. Der Defekt war die ASYMMETRIE plus das stille Verschlucken.

WAS DIESER TEST NICHT TUT: das Digest-Alphabet aufweichen. Er prueft die Eigenschaft, dass ein
nicht platzierbarer Beleg BENANNT wird und gegen die Unversehrtheit zaehlt.
"""
from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofbundle import agent_review as ar

SK = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
PK = SK.public_key().public_bytes_raw()


def _doc(rid: str):
    return {"schemaVersion": "0.1.0", "reviewId": rid,
            "subjectContext": {"kind": "githubIssue", "forge": "github.com",
                               "repositoryId": "R_kg", "issueNodeId": "I_kw1",
                               "revisedAt": "2026-09-01T09:00:00Z",
                               "bodyCoreDigest": ar.body_core_digest("x")},
            "declaration": {"authoring": [{"assurance": "selfDeclared", "assertedBy": "agent"}],
                            "reviewRuns": [], "findings": [], "findingsTotal": 0,
                            "findingsRoot": ar.findings_root([]), "nonClaims": ["x"]},
            "coverage": {"status": "PARTIAL", "knownGaps": ["y"]},
            "times": {"declaredAt": "2026-09-01T09:00:00Z"},
            "limitations": ["Tier 1"]}


def _divergierender_umschlag():
    """Ein Umschlag, dessen Standard-b64 wirklich `+` oder `/` enthaelt.

    DAS IST DER TEIL, AN DEM MEIN ERSTER REPRODUKTIONSVERSUCH SCHEITERTE: bei den meisten Inhalten
    enthaelt der Standard-b64 keines der beiden Zeichen, dann sind beide Alphabete IDENTISCH und
    es gibt gar keine Divergenz. Ein Test, der das nicht sicherstellt, prueft nichts — er waere
    gruen, weil der Angriff gar nicht stattfand.
    """
    for i in range(400):
        env = ar.emit_agent_review(_doc(f"kette-{'?' * (i % 7)}{i}"), SK)
        if any(c in env["payload"] for c in "+/"):
            roh = base64.b64decode(env["payload"], validate=True)
            url = dict(env)
            url["payload"] = base64.urlsafe_b64encode(roh).decode()
            assert url["payload"] != env["payload"], "keine Divergenz — der Aufbau taugt nicht"
            return env, url
    pytest.fail("in 400 Versuchen keinen divergierenden Umschlag erzeugt")


def test_die_vorbedingung_des_tests_ist_erfuellt():
    """GEGENPROBE zuerst: ohne echte Divergenz misst alles Folgende nichts."""
    env, url = _divergierender_umschlag()
    assert env["payload"] != url["payload"]
    assert ar.verify_agent_review(url, PK, strict=True)["crypto_ok"] is True, (
        "der Verifier nimmt die url-safe Fassung nicht an — dann gibt es die Asymmetrie nicht")
    with pytest.raises(ar.AgentReviewError):
        ar.receipt_digest(url)


def test_ein_nicht_platzierbarer_beleg_wird_benannt_und_zaehlt_gegen_die_unversehrtheit():
    """DIE INVARIANTE. Vorher: `integrity_ok=True`, obwohl ein gueltiger Beleg verschwunden war."""
    _, url = _divergierender_umschlag()
    k = ar.resolve_receipt_chain([url], verified=None)
    assert k.get("unaddressable"), "der Verlust wird nicht benannt"
    assert k.get("integrity_ok") is False, (
        f"integrity_ok={k.get('integrity_ok')!r}, obwohl ein vorgelegter Beleg nicht platziert "
        f"werden konnte — die Kette haelt sich fuer vollstaendig, ohne es zu sein")


def test_der_kontrollfall_bleibt_gruen():
    """Ein Riegel, der jede Kette fuer kaputt erklaert, ist kein Riegel."""
    env, _ = _divergierender_umschlag()
    k = ar.resolve_receipt_chain([env], verified=None)
    assert k.get("integrity_ok") is True, f"integrity_ok={k.get('integrity_ok')!r}"
    assert k.get("unaddressable") == []
    assert k.get("ambiguous") is False and k.get("current")
