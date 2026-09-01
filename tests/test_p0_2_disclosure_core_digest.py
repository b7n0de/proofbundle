"""P0.2 der Gegenlesung Runde 2 — der sichtbare Block wird gebunden, nicht nur der Rumpf um ihn.

DIE LUECKE, WOERTLICH GEMESSEN. `bodyCoreDigest` ersetzt den GANZEN Block durch einen festen Token.
Das ist fuer seine Aufgabe genau richtig: ein Receipt, das signiert wurde, bevor der Block gerendert
war, muss das Rendern ueberleben. Als Aussage ueber den Blockinhalt ist es genau falsch — eine
Handaenderung von `selfDeclared` auf `independentlyWitnessed` bewegt keinen einzigen Digest, die
Signatur prueft weiter gruen, und der Leser bekommt eine staerkere Behauptung erzaehlt, als das
signierte Objekt traegt.

DIE ABNAHME AUS DEM AUFTRAG, woertlich: „selfDeclared zu independentlyWitnessed im sichtbaren Block
macht den Pfad rot." Genau das misst `test_die_aufwertung_im_sichtbaren_block_macht_rot`. Der Test
daneben zeigt, dass `bodyCoreDigest` dabei UNVERAENDERT bleibt — ohne diese Haelfte koennte man
glauben, der alte Digest haette gereicht.
"""
from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofbundle import agent_review as AR
from proofbundle import canonical, dsse

# Derselbe Schluesselaufbau wie in den bestehenden agent-review-Tests. Ausdruecklich KEIN
# try/except-skip: ein uebersprungener Test sieht gruen aus und misst nichts, und genau diese
# Klasse steht in unserem eigenen Klassen-Ledger.
SK = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
PK = SK.public_key().public_bytes_raw()


def _block(assurance: str = "selfDeclared", digest: str = "a" * 64) -> str:
    return (f"{AR.DISCLOSURE_BEGIN}\n"
            f"**Agent review receipt** · Tier 1, {assurance}\n"
            f"[abc123def456](https://example.com/r) · [log](https://example.com/l)\n"
            f"<sub><code>sha256:{digest}</code></sub>\n"
            f"{AR.DISCLOSURE_END}")


def _rumpf(assurance: str = "selfDeclared", digest: str = "a" * 64) -> str:
    return "Die Beschreibung des Vorgangs.\n\n" + _block(assurance, digest) + "\n"


def _predicate(body: str, *, mit_disclosure: bool = True) -> dict:
    sc = {"kind": "githubPullRequest", "forge": "github", "repositoryId": "R",
          "pullRequestNodeId": "P", "headSha": "a" * 40, "baseSha": "b" * 40,
          "reviewedDiffDigest": "c" * 64, "bodyCoreDigest": AR.body_core_digest(body)}
    if mit_disclosure:
        sc["disclosureCoreDigest"] = AR.disclosure_core_digest(body)
    return {"schemaVersion": "0.1.0", "reviewId": "r1", "subjectContext": sc,
            "declaration": {"authoring": [{"assurance": "selfDeclared", "assertedBy": "agent"}],
                            "reviewRuns": [], "findings": [], "findingsTotal": 0,
                            "nonClaims": ["kein Sicherheitsaudit"]},
            "coverage": {"status": "UNKNOWN"},
            "times": {"declaredAt": "2026-08-31T20:00:00Z", "signedAt": "2026-08-31T20:00:00Z"},
            "limitations": ["selbstdeklariert"]}


def _receipt(p: dict) -> dict:
    st = {"_type": AR.STATEMENT_TYPE,
          "subject": [{"name": AR._subject_name(p), "digest": {"sha256": AR._subject_digest(p)}}],
          "predicateType": AR.AGENT_REVIEW_PREDICATE_TYPE, "predicate": p}
    return dsse.sign_envelope(canonical.canonicalize_statement(st), SK,
                              payload_type=AR.INTOTO_STATEMENT_PAYLOAD_TYPE)


def _verify(env, p, body):
    return AR.verify_agent_review(env, PK, strict=True,
                                  expected_subject_digest=AR._subject_digest(p),
                                  observed_body=body)


# ── die Abnahme selbst ────────────────────────────────────────────────────────────────────────

def test_der_unveraenderte_rumpf_ist_gruen():
    body = _rumpf()
    p = _predicate(body)
    r = _verify(_receipt(p), p, body)
    assert r["body_core_digest_match"] == "MATCH"
    assert r["disclosure_core_digest_match"] == "MATCH"
    assert r["ok"] is True, r["errors"]


def test_die_aufwertung_im_sichtbaren_block_macht_rot():
    """Die Abnahme aus dem Auftrag, woertlich."""
    body = _rumpf()
    p = _predicate(body)
    env = _receipt(p)
    manipuliert = _rumpf(assurance="independentlyWitnessed")
    r = _verify(env, p, manipuliert)
    assert r["disclosure_core_digest_match"] == "MISMATCH"
    assert r["ok"] is False
    assert any("disclosureCoreDigest mismatch" in e for e in r["errors"]), r["errors"]


def test_und_bodyCoreDigest_allein_haette_es_NICHT_gefangen():
    """Ohne diese Haelfte koennte man glauben, der alte Digest habe schon gereicht."""
    body = _rumpf()
    manipuliert = _rumpf(assurance="independentlyWitnessed")
    assert AR.body_core_digest(body) == AR.body_core_digest(manipuliert)
    assert AR.disclosure_core_digest(body) != AR.disclosure_core_digest(manipuliert)


# ── die Selbstreferenz, und warum sie ausgenommen bleiben MUSS ────────────────────────────────

def test_der_receipt_digest_selbst_geht_nicht_in_seinen_eigenen_digest_ein():
    a, b = _rumpf(digest="a" * 64), _rumpf(digest="b" * 64)
    assert AR.disclosure_core_digest(a) == AR.disclosure_core_digest(b)


def test_die_kurze_linkbeschriftung_ebenfalls_nicht():
    a = _rumpf()
    b = a.replace("[abc123def456]", "[0123456789ab]")
    assert AR.disclosure_core_digest(a) == AR.disclosure_core_digest(b)


def test_aber_der_link_selbst_geht_ein_sonst_koennte_man_umleiten():
    a = _rumpf()
    b = a.replace("https://example.com/r", "https://boeswillig.example/r")
    assert AR.disclosure_core_digest(a) != AR.disclosure_core_digest(b)


# ── die drei Zustaende, und warum keiner davon still zu MATCH wird ────────────────────────────

def test_ohne_rumpf_steht_NOT_EVALUATED_nie_MATCH():
    body = _rumpf()
    p = _predicate(body)
    r = AR.verify_agent_review(_receipt(p), PK, strict=True,
                               expected_subject_digest=AR._subject_digest(p))
    assert r["disclosure_core_digest_match"] == "NOT_EVALUATED"
    assert r["body_core_digest_match"] == "NOT_EVALUATED"


def test_ein_altes_v01_receipt_ohne_das_feld_bleibt_gueltig():
    """Sechs bereits ausgestellte Receipts tragen es nicht, zwei sind veroeffentlicht.

    Sie ungueltig zu machen waere ein Bruch, keine Haertung — deshalb ABSENT_IN_RECEIPT statt
    MISMATCH, und deshalb bleibt `ok` davon unberuehrt.
    """
    body = _rumpf()
    p = _predicate(body, mit_disclosure=False)
    r = _verify(_receipt(p), p, body)
    assert r["disclosure_core_digest_match"] == "ABSENT_IN_RECEIPT"
    assert r["body_core_digest_match"] == "MATCH"
    assert r["ok"] is True, r["errors"]


def test_ein_rumpf_ohne_block_ist_NICHT_MESSBAR_und_keine_freigabe():
    body = _rumpf()
    p = _predicate(body)
    r = _verify(_receipt(p), p, "Ein Rumpf ganz ohne Offenlegungsblock.")
    assert r["disclosure_core_digest_match"] == "NOT_MEASURABLE"
    assert r["body_core_digest_match"] == "MISMATCH"
    assert r["ok"] is False


def test_zwei_bloecke_sind_fail_closed():
    body = _rumpf() + "\n" + _block()
    with pytest.raises(AR.AgentReviewError):
        AR.disclosure_core_digest(body)


def test_ein_rumpf_ohne_block_wirft_statt_den_leeren_digest_zu_liefern():
    with pytest.raises(AR.AgentReviewError):
        AR.disclosure_core_digest("nur Text")


# ── v0.2: dort ist das Feld Pflicht ───────────────────────────────────────────────────────────

def test_v02_verlangt_das_feld():
    body = _rumpf()
    p = _predicate(body, mit_disclosure=False)
    p["declaration"]["timeClaims"] = []
    errs = AR.validate_agent_review_v02_predicate(p)
    assert any("disclosureCoreDigest is required" in e for e in errs), errs


def test_v02_ist_mit_dem_feld_zufrieden():
    body = _rumpf()
    p = _predicate(body)
    p["declaration"]["timeClaims"] = []
    errs = AR.validate_agent_review_v02_predicate(p)
    assert not any("disclosureCoreDigest" in e for e in errs), errs


def test_v01_verlangt_es_NICHT_denn_das_waere_ein_bruch():
    body = _rumpf()
    p = _predicate(body, mit_disclosure=False)
    assert AR.validate_agent_review_predicate(p) == []


def test_das_feld_ist_in_v01_erlaubt_nicht_nur_geduldet():
    body = _rumpf()
    p = _predicate(body)
    assert AR.validate_agent_review_predicate(p) == []


def test_der_verifier_faellt_bei_kaputtem_rumpf_nicht_roh_um():
    body = _rumpf()
    p = _predicate(body)
    r = AR.verify_agent_review(_receipt(p), PK, strict=True,
                               expected_subject_digest=AR._subject_digest(p),
                               observed_body=json.dumps({"kein": "string-rumpf"}))
    assert r["ok"] is False
    assert "internal_error" not in (r["reason_codes"] or [])


def test_NICHT_MESSBAR_blockt_auf_BEIDEN_achsen_und_ABSENT_auf_keiner():
    """Meine erste Fassung dieses Tests behauptete eine Asymmetrie — und war falsch.

    Sie lautete: die Disclosure-Achse duerfe bei NOT_MEASURABLE nicht blocken, weil ein Rumpf ohne
    Block der Normalzustand vor dem Rendern sei. Ein Mutationslauf hat das widerlegt: die
    Gegenmutation machte NICHTS rot, also deckte kein Test das Argument. Nachgesehen landet jener
    Normalzustand gar nicht auf NOT_MEASURABLE, sondern auf ABSENT_IN_RECEIPT.

    NOT_MEASURABLE entsteht auf der Disclosure-Achse AUSSCHLIESSLICH, wenn das Receipt einen
    Disclosure-Digest BEHAUPTET und der vorgelegte Rumpf keinen Block traegt — ein Widerspruch
    zwischen Beleg und Gegenstand, kein Normalzustand. Beide Achsen blocken deshalb gleich, und
    ABSENT_IN_RECEIPT blockt auf keiner.
    """
    body = _rumpf()

    # (a) missgebildeter Rumpf -> beide nicht messbar, Urteil rot
    p = _predicate(body)
    r = _verify(_receipt(p), p, body + "\n" + _block())
    assert r["body_core_digest_match"] == "NOT_MEASURABLE"
    assert r["ok"] is False

    # (b) das Receipt behauptet einen Disclosure-Digest, der Rumpf traegt keinen Block -> rot
    r2 = _verify(_receipt(p), p, "Ein Vorgang ganz ohne Offenlegungsblock.\n")
    assert r2["disclosure_core_digest_match"] == "NOT_MEASURABLE"
    assert r2["ok"] is False, "Beleg und Gegenstand widersprechen sich und es blieb gruen"

    # (c) das Receipt behauptet gar keinen -> ABSENT, und das blockt zu Recht NICHT
    ohne = "Ein Vorgang ganz ohne Offenlegungsblock.\n"
    p3 = _predicate(ohne, mit_disclosure=False)
    r3 = _verify(_receipt(p3), p3, ohne)
    assert r3["disclosure_core_digest_match"] == "ABSENT_IN_RECEIPT"
    assert r3["ok"] is True, r3["errors"]


def test_die_body_achse_blockt_ALLEIN():
    """ISOLIERT, weil ein Mutationslauf zeigte, dass sich die Achsen gegenseitig verdecken.

    Der Test darueber prueft beide Achsen, aber in seinen Faellen ist IMMER auch die andere rot —
    nimmt man einer das Blocken weg, bleibt das Urteil trotzdem rot, und die Mutation sieht wie
    ein Erfolg aus. Zwei Waechter, die einander decken, sind gemessen EIN Waechter.

    Hier ist die Body-Achse allein zustaendig: doppelter Block (Body nicht messbar) bei einem
    Receipt OHNE `disclosureCoreDigest` (Disclosure = ABSENT und damit stumm).
    """
    body = _rumpf()
    p = _predicate(body, mit_disclosure=False)
    r = _verify(_receipt(p), p, body + "\n" + _block())
    assert r["body_core_digest_match"] == "NOT_MEASURABLE"
    assert r["disclosure_core_digest_match"] == "ABSENT_IN_RECEIPT"
    assert r["ok"] is False, "die Body-Achse allein hat nicht geblockt"


def test_die_disclosure_achse_blockt_ALLEIN():
    """Die Gegenrichtung derselben Isolierung: Body MATCH, Disclosure nicht messbar.

    Gebaut wird ein Receipt, dessen `bodyCoreDigest` ueber einen Rumpf OHNE Block gebildet ist,
    das aber trotzdem einen `disclosureCoreDigest` behauptet. Das ist genau der Widerspruch, den
    die Achse fangen soll: der Beleg spricht von einer Offenlegung, die der Gegenstand nicht hat.
    """
    ohne_block = "Ein Vorgang ganz ohne Offenlegungsblock.\n"
    p = _predicate(ohne_block, mit_disclosure=False)
    p["subjectContext"]["disclosureCoreDigest"] = "e" * 64
    r = _verify(_receipt(p), p, ohne_block)
    assert r["body_core_digest_match"] == "MATCH"
    assert r["disclosure_core_digest_match"] == "NOT_MEASURABLE"
    assert r["ok"] is False, "die Disclosure-Achse allein hat nicht geblockt"
