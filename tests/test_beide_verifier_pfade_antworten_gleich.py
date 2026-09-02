"""Dieselbe kaputte Eingabe muss in v0.1 UND v0.2 dieselbe Antwort bekommen.

DER BEFUND (Tiefen-Gate 5.1.0, 01.09.2026): bei `declaration` als String meldete der v0.1-Pfad
`assurance_ok=False` (ausdruecklicher fail-closed-Riegel), der v0.2-Pfad dagegen
`assurance_ok=True` — weil `dec_v2` dort auf `{}` faellt, `rungs` leer wird und `not []` True ist.
Gleiche Eingabe, zwei Antworten. Die Achse meldete Gruen, obwohl sie nichts geprueft hatte.

DIE KLASSE, an EINEM Tag dreimal in diesem Modul aufgetreten: "ein Fix erreichte nur eine Kopie".
Erst die Weiche im Konformitaets-Laeufer, dann die Automations-Nachkorrektur, dann dieser Riegel.
Ein Test, der nur einen Pfad prueft, ist deshalb hier nicht genug — dieser faehrt BEIDE gegen
dieselben Eingaben und vergleicht.

EHRLICHE GRENZE: verglichen werden die fail-closed-Achsen, nicht jedes Feld. v0.1 und v0.2 duerfen
sich unterscheiden, wo sie verschiedene Dinge pruefen; sie duerfen sich NICHT darin unterscheiden,
ob eine unpruefbare Eingabe als geprueft gilt.
"""
from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofbundle import agent_review as ar

#: DIE ZWEI ECHTEN EINSTIEGSPUNKTE. Mein erster Entwurf rief fuer BEIDE Fassungen
#: `verify_agent_review` — das ist der v0.1-Verifier, und er VERWEIGERT einen v0.2-Typ
#: ("this is the v0.1 verifier and it refuses rather than guessing"). Der v0.2-Zweig wurde damit
#: nie ausgefuehrt; `assurance_ok=False` kam aus der Versionsverweigerung, nicht aus dem geprueften
#: Riegel. Beide eingepflanzten Defekte ueberlebten den Test, und das Gate-Meta hat es gemeldet.
#: Das ist dieselbe Klasse, die dieser Lauf im Konformitaets-Korpus gefunden hat: ein Fall, der aus
#: einem ANDEREN Grund besteht als dem, den er benennt.
PRUEFER = {False: ar.verify_agent_review, True: ar.verify_agent_review_v02}

SK = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
PK = SK.public_key().public_bytes_raw()

#: Eingaben, die KEINE der beiden Fassungen fuer geprueft halten darf.
UNPRUEFBAR = {
    "declaration_als_string": "das ist kein Objekt",
    "declaration_als_liste": ["auch", "nicht"],
    "declaration_als_zahl": 7,
    "declaration_None": None,
}


def _envelope_mit(dv, v02: bool):
    """Baut einen Umschlag von Hand — der Emitter wuerde diese Eingaben zu Recht ablehnen,
    geprueft wird hier der VERIFIER."""
    import base64  # noqa: PLC0415
    import json  # noqa: PLC0415
    from proofbundle import dsse
    pred = {
        "schemaVersion": "0.2.0" if v02 else "0.1.0", "reviewId": "paritaet",
        "subjectContext": {"kind": "githubIssue", "forge": "github.com",
                           "repositoryId": "R_kg", "issueNodeId": "I_kw1",
                           "bodyCoreDigest": ar.body_core_digest("Rumpf")},
        "declaration": dv,
        "coverage": {"status": "PARTIAL", "knownGaps": ["kaputt"]},
        "times": {"declaredAt": "2026-09-01T09:00:00Z"},
        "limitations": ["Tier 1"],
    }
    name = ar._subject_name(pred) if hasattr(ar, "_subject_name") else "x"
    stmt = {"_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": name, "digest": {"sha256": ar._subject_digest(pred)}}],
            "predicateType": (ar.AGENT_REVIEW_PREDICATE_TYPE_V02 if v02
                              else ar.AGENT_REVIEW_PREDICATE_TYPE),
            "predicate": pred}
    payload = json.dumps(stmt, separators=(",", ":"), sort_keys=True).encode()
    sig = SK.sign(dsse.pae("application/vnd.in-toto+json", payload))
    return {"payload": base64.b64encode(payload).decode(),
            "payloadType": "application/vnd.in-toto+json",
            "signatures": [{"sig": base64.b64encode(sig).decode()}]}


@pytest.mark.parametrize("name,dv", sorted(UNPRUEFBAR.items()))
def test_keine_fassung_haelt_eine_unpruefbare_deklaration_fuer_geprueft(name, dv):
    """DIE INVARIANTE: was nicht auswertbar ist, faellt zu — in BEIDEN Fassungen."""
    for v02 in (False, True):
        r = PRUEFER[v02](_envelope_mit(dv, v02), PK, strict=True)
        fassung = "v0.2" if v02 else "v0.1"
        assert r.get("assurance_ok") is not True, (
            f"{fassung} / {name}: assurance_ok={r.get('assurance_ok')!r} — eine nicht auswertbare "
            f"Deklaration gilt als geprueft")
        assert r.get("ok") is not True, f"{fassung} / {name}: ok={r.get('ok')!r}"


@pytest.mark.parametrize("name,dv", sorted(UNPRUEFBAR.items()))
def test_beide_fassungen_antworten_GLEICH(name, dv):
    """Der eigentliche Klassen-Test: nicht nur beide falsch-sicher-frei, sondern GLEICH."""
    a = PRUEFER[False](_envelope_mit(dv, False), PK, strict=True)
    b = PRUEFER[True](_envelope_mit(dv, True), PK, strict=True)
    for achse in ("assurance_ok", "findings_root_ok"):
        assert a.get(achse) == b.get(achse), (
            f"{name}: v0.1 meldet {achse}={a.get(achse)!r}, v0.2 meldet {b.get(achse)!r} — "
            f"gleiche Eingabe, zwei Antworten")


def test_der_kontrollfall_bleibt_gruen():
    """Ein Riegel, der jede Deklaration ablehnt, ist kein Riegel."""
    gut = {"authoring": [{"assurance": "selfDeclared", "assertedBy": "agent"}],
           "reviewRuns": [], "findings": [], "findingsTotal": 0,
           "findingsRoot": ar.findings_root([]),
           "nonClaims": ["keine Aussage ueber Qualitaet"]}
    r = ar.verify_agent_review(_envelope_mit(gut, False), PK, strict=True)
    assert r.get("assurance_ok") is True, f"assurance_ok={r.get('assurance_ok')!r}"
