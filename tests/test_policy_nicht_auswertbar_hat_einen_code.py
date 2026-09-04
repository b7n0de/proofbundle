"""Der Code POLICY_NOT_EVALUABLE muss AUSLOESBAR sein, nicht nur vergeben.

Er entstand am 04.09.2026 zusammen mit der Policy-Achse (Teil A3) und hatte beim ersten vollen
Lauf KEINEN Test — gefunden nicht von einem roten Test, sondern von der Code-Tafel
(`test_jeder_code_meint_genau_eine_lage`), die fuer jeden Code eine ausloesende Eingabe verlangt.
Genau das ist ihr Zweck: ein Code, den nichts ausloest, ist entweder unerreichbar oder ungeprueft,
und beides sieht im Betrieb gleich aus.

DIE LAGE, DIE ER MEINT: die Policy wurde UEBERGEBEN und ihre Auswertung ist GESCHEITERT. Das ist
etwas anderes als `POLICY_NOT_EVALUATED` (gar keine Policy uebergeben) und etwas anderes als
`insufficient_evidence` (die Auswertung lief und konnte nicht entscheiden). Drei Lagen, drei
Namen — wer sie zusammenwirft, verliert die Unterscheidung zwischen „nicht gefragt", „gefragt und
kaputt" und „gefragt und unentscheidbar".
"""
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofbundle import agent_review as AR

SK = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
PK = SK.public_key().public_bytes_raw()


def _umschlag():
    sk = SK
    p = {
        "coverage": {"knownGaps": ["nur eine Datei"], "status": "PARTIAL"},
        "declaration": {"authoring": [{"assertedBy": "x", "assurance": "selfDeclared"}],
                        "findings": [], "findingsTotal": 0, "nonClaims": ["n"], "reviewRuns": []},
        "limitationCodes": ["COVERAGE_PARTIAL", "CURRENTNESS_UNKNOWN", "IDENTITY_UNBOUND",
                            "NOT_QUALITY_ATTESTATION", "TIME_SELF_DECLARED"],
        "limitations": ["selbsterklaert"],
        "reviewId": "ar-policy-kaputt", "schemaVersion": "0.1.0",
        "subjectContext": {"baseSha": "b" * 40, "bodyCoreDigest": "d" * 64,
                           "disclosureCoreDigest": "e" * 64, "forge": "github",
                           "headSha": "a" * 40, "kind": "githubPullRequest",
                           "pullRequestNodeId": "P", "repositoryId": "R",
                           "reviewedDiffDigest": "c" * 64},
        "times": {"declaredAt": "2026-09-04T00:00:00Z", "observedAt": None,
                  "signedAt": "2026-09-04T00:00:00Z"},
    }
    return AR.emit_agent_review(p, sk), AR._subject_digest(p)


class _Sprengsatz(dict):
    """Eine Policy, die beim LESEN wirft. Kein Nachbau der Auswertung, kein Monkeypatch am Modul —
    die Ausnahme entsteht dort, wo eine kaputte Policy sie im Betrieb auch erzeugen wuerde."""

    def get(self, *a, **k):
        raise RuntimeError("policy ist kaputt")


def test_eine_kaputte_policy_wird_benannt_statt_zu_reissen():
    env, digest = _umschlag()
    r = AR.verify_agent_review_v02(env, PK, expected_subject_digest=digest,
                                   policy=_Sprengsatz())
    codes = [getattr(e, "code", None) for e in (r.get("errors") or [])]
    assert "POLICY_NOT_EVALUABLE" in codes, (
        f"die kaputte Policy muss BENANNT werden, gemessen: {codes}")
    assert r["policy_decision"] == "insufficient_evidence", (
        "eine gescheiterte Auswertung ist keine Zustimmung")


def test_die_gegenrichtung_eine_heile_policy_vergibt_den_code_nicht():
    """OHNE SIE WAERE DER TEST OBEN AUCH GRUEN, wenn der Code IMMER vergeben wuerde."""
    env, digest = _umschlag()
    r = AR.verify_agent_review_v02(env, PK, expected_subject_digest=digest,
                                   policy=AR.load_policy())
    codes = [getattr(e, "code", None) for e in (r.get("errors") or [])]
    assert "POLICY_NOT_EVALUABLE" not in codes, f"heile Policy, trotzdem der Code: {codes}"


def test_ohne_policy_ist_es_die_ANDERE_lage():
    """DIE DRITTE LAGE. `POLICY_NOT_EVALUATED` heisst: gar nicht gefragt. Wer die beiden Codes
    zusammenwirft, kann eine kaputte Policy nicht mehr von einer fehlenden unterscheiden."""
    env, digest = _umschlag()
    r = AR.verify_agent_review_v02(env, PK, expected_subject_digest=digest)
    codes = [getattr(e, "code", None) for e in (r.get("errors") or [])]
    assert "POLICY_NOT_EVALUABLE" not in codes, codes
    assert AR.POLICY_NOT_EVALUATED in (r.get("reason_codes") or []), r.get("reason_codes")
