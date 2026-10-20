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
    """A policy whose own ``get`` raises. Until the class fix of the 6.2.0 deep gate (2348f0a7) this was
    the trigger of the case below, because the verifier read the policy through that ``get``. The
    verifier reads what the policy stores now and runs none of its methods, so this object is the
    empty policy it stores, and it serves as the case that says so."""

    def get(self, *a, **k):
        raise RuntimeError("policy ist kaputt")


class _KeinJsonWert:
    """A value no JSON document can hold."""


def test_eine_kaputte_policy_wird_benannt_statt_zu_reissen():
    """The trigger is a policy that cannot be read by what it stores: it holds a value that is no JSON
    value. It gives the code at the base of the class fix (2074d814) and after it."""
    env, digest = _umschlag()
    r = AR.verify_agent_review_v02(env, PK, expected_subject_digest=digest,
                                   policy={**AR.load_policy(), "x": _KeinJsonWert()})
    codes = [getattr(e, "code", None) for e in (r.get("errors") or [])]
    assert "POLICY_NOT_EVALUABLE" in codes, (
        f"die kaputte Policy muss BENANNT werden, gemessen: {codes}")
    assert r["policy_decision"] == "insufficient_evidence", (
        "eine gescheiterte Auswertung ist keine Zustimmung")


def test_eine_policy_wird_gelesen_als_das_was_sie_speichert():
    """The class fix (deep gate 6.2.0 at 2348f0a7, found by the extended sweep): the verifier read
    ``policy.get("time")`` through the caller's own ``get``. A dict subclass whose ``get`` raises is
    judged as the plain dict it stores, and its ``get`` never runs. Red at 2074d814, where it gave
    ``insufficient_evidence`` with POLICY_NOT_EVALUABLE while the plain empty dict gave another verdict."""
    env, digest = _umschlag()
    gespeichert = AR.verify_agent_review_v02(env, PK, expected_subject_digest=digest, policy={})
    r = AR.verify_agent_review_v02(env, PK, expected_subject_digest=digest, policy=_Sprengsatz())
    assert r["policy_decision"] == gespeichert["policy_decision"], (r["policy_decision"],
                                                                   gespeichert["policy_decision"])
    assert [getattr(e, "code", None) for e in (r.get("errors") or [])] == [
        getattr(e, "code", None) for e in (gespeichert.get("errors") or [])]


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
    assert AR.POLICY_NOT_EVALUATED in (r.get("advisory_codes") or []), r.get("advisory_codes")
    assert AR.POLICY_NOT_EVALUATED not in (r.get("reason_codes") or []), r.get("reason_codes")
