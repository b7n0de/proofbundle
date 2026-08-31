"""`ok` heisst nicht "gueltig", sondern "brauchbar als Beleg FUER DAS OBJEKT VOR DIR".

DER ANGRIFF, DER DIESE TRENNUNG ERZWANG (externe Gegenlesung, zweite Runde, 31.08.2026). Ein
Angreifer nimmt ein gueltiges Receipt fuer Vorgang A und legt es bei Vorgang B vor. Am Envelope
aendert er nichts — er luegt daneben. Ein Pruefpfad, der nur `ok` liest (etwa eine Pipeline mit der
Frage "gibt es hier ein gueltiges Receipt"), bekam gruen.

Die naheliegende Abwehr waere eine Warnung gewesen. Sie traegt nicht: neben einem gruenen Ergebnis
wird sie ueberlesen. Also zwei Felder, zwei Aussagen — und `ok` ist die staerkere.
"""
import base64
import copy
import json
import sys
import unittest
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from proofbundle import agent_review as AR  # noqa: E402

BODY = "# T\n\nText.\n"
FINDINGS = [{"id": "F1", "severity": "low", "title": "t", "disposition": "dismissed", "reason": "r"}]


def _pred(**patch):
    p = {
        "schemaVersion": "0.1.0", "reviewId": "r",
        "subjectContext": {"kind": "githubPullRequest", "forge": "github.com",
                           "repositoryId": "R", "pullRequestNodeId": "PR",
                           "headSha": "a" * 40, "baseSha": "b" * 40,
                           "reviewedDiffDigest": "c" * 64,
                           "bodyCoreDigest": AR.body_core_digest(BODY)},
        "declaration": {"authoring": [{"assurance": "selfDeclared", "assertedBy": "x"}],
                        "reviewRuns": [], "findings": FINDINGS, "findingsTotal": 1,
                        "findingsRoot": AR.findings_root(FINDINGS), "nonClaims": ["n"]},
        "coverage": {"status": "UNKNOWN"},
        "times": {"declaredAt": "2026-08-31T17:00:00Z"},
        "limitations": ["l"],
    }
    p.update(patch)
    return p


@pytest.fixture
def paar():
    sk = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    return sk, sk.public_key().public_bytes_raw()


def test_ohne_erwartung_ist_ok_falsch_und_die_konsistenz_wahr(paar):
    """DER KERN. Das Receipt ist in sich stimmig — aber nichts hier sagt, dass es hierher gehoert."""
    sk, pk = paar
    r = AR.verify_agent_review(AR.emit_agent_review(_pred(), sk), pk)
    assert r["internal_consistency_ok"] is True
    assert r["ok"] is False
    assert r["subject_expectation"] == "not_supplied"
    assert any("belongs to the object" in e for e in r["errors"])


def test_mit_richtiger_erwartung_ist_ok_wahr(paar):
    sk, pk = paar
    p = _pred()
    r = AR.verify_agent_review(AR.emit_agent_review(p, sk), pk,
                               expected_subject_digest=AR._subject_digest(p))
    assert r["ok"] is True and r["subject_expectation"] == "checked"


def test_fremdes_receipt_faellt_gegen_die_erwartung_durch(paar):
    """Der Angriff selbst: gueltiges Receipt fuer A, vorgelegt bei B."""
    sk, pk = paar
    a = _pred()
    b = copy.deepcopy(a)
    b["subjectContext"]["pullRequestNodeId"] = "PR_ANDERER"
    r = AR.verify_agent_review(AR.emit_agent_review(b, sk), pk,
                               expected_subject_digest=AR._subject_digest(a))
    assert r["ok"] is False and r["subject_binding_ok"] is False


def test_eine_warnung_allein_haette_nicht_getragen(paar):
    """Festgehalten, weil es die verworfene Alternative ist: die Warnung STEHT weiterhin da, aber
    sie ist nicht mehr das Einzige. Wer nur `ok` liest, ist jetzt sicher."""
    sk, pk = paar
    r = AR.verify_agent_review(AR.emit_agent_review(_pred(), sk), pk)
    assert any("expected_subject_digest" in w for w in r["warnings"])
    assert r["ok"] is False, "die Warnung ersetzt das Urteil nicht, sie begleitet es"


def test_kaputte_signatur_macht_auch_die_konsistenz_falsch(paar):
    """Die Gegenrichtung: `internal_consistency_ok` ist kein Trostpreis, den es immer gibt."""
    sk, pk = paar
    env = AR.emit_agent_review(_pred(), sk)
    env["signatures"][0]["sig"] = base64.b64encode(b"\x00" * 64).decode()
    r = AR.verify_agent_review(env, pk, expected_subject_digest="0" * 64)
    assert r["internal_consistency_ok"] is False and r["ok"] is False


def test_das_statement_traegt_die_erwartete_form(paar):
    sk, _ = paar
    env = AR.emit_agent_review(_pred(), sk)
    stmt = json.loads(base64.b64decode(env["payload"]))
    assert stmt["predicateType"] == AR.AGENT_REVIEW_PREDICATE_TYPE
    assert stmt["subject"][0]["digest"]["sha256"] == AR._subject_digest(_pred())


# ── never-raise: der Verify-Pfad liefert IMMER ein typisiertes Ergebnis ────────────────────────

def _handgebaut(assurance_wert):
    """Ein Statement, das der Emitter ABLEHNEN wuerde — genau deshalb von Hand gebaut. Ein
    Angreifer benutzt den Emitter nicht."""
    from proofbundle import canonical, dsse
    sk = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    stmt = {
        "_type": AR.STATEMENT_TYPE,
        "subject": [{"name": "x", "digest": {"sha256": "a" * 64}}],
        "predicateType": AR.AGENT_REVIEW_PREDICATE_TYPE,
        "predicate": {
            "schemaVersion": "0.1.0", "reviewId": "r",
            "subjectContext": {"kind": "githubPullRequest", "forge": "g", "repositoryId": "R",
                               "pullRequestNodeId": "P", "headSha": "a" * 40, "baseSha": "b" * 40,
                               "reviewedDiffDigest": "c" * 64, "bodyCoreDigest": "d" * 64},
            "declaration": {"authoring": [{"assurance": assurance_wert, "assertedBy": "x"}],
                            "reviewRuns": [], "findings": [], "findingsTotal": 0,
                            "nonClaims": ["n"]},
            "coverage": {"status": "UNKNOWN"},
            "times": {"declaredAt": "2026-08-31T17:00:00Z"},
            "limitations": ["l"]},
    }
    env = dsse.sign_envelope(canonical.canonicalize_statement(stmt), sk,
                             payload_type=AR.INTOTO_STATEMENT_PAYLOAD_TYPE)
    return env, sk.public_key().public_bytes_raw()


@pytest.mark.parametrize("wert,beschreibung", [
    (["unhashbar"], "eine Liste"),
    ({"a": 1}, "ein Dict"),
    (42, "eine Zahl"),
])
def test_ein_unhashbarer_assurance_wert_wirft_nicht(wert, beschreibung):
    """DER DEFEKT, DEN CI GEFUNDEN HAT — und der schwerere lag eine Zeile ueber dem gemeldeten.

    Der Linter monierte einen ungeschuetzten `in`-Test auf einer hashenden Menge. Die eigentliche
    Gefahr war die MENGE selbst: `rungs` war eine set-Comprehension ueber produzentenbestimmte
    Werte, und ein unhashbarer Wert liess dort eine ROHE TypeError aus einem Verify-Pfad fallen,
    der vertraglich immer ein typisiertes Ergebnis liefert. Ausgefuehrt gemessen, bevor der Fix
    kam: `unhashable type: 'list'`.

    Haette ich nur den gemeldeten Punkt gefixt, waere der schwerere geblieben und die Suite
    gruen geworden."""
    env, pk = _handgebaut(wert)
    r = AR.verify_agent_review(env, pk)          # darf NICHT werfen
    assert r["ok"] is False and r["assurance_ok"] is False, beschreibung


def test_ein_zulaessiger_wert_bleibt_zulaessig():
    """Die Gegenrichtung: die Haertung darf den Normalfall nicht miterschlagen."""
    env, pk = _handgebaut("selfDeclared")
    assert AR.verify_agent_review(env, pk)["assurance_ok"] is True


# ── der Erwartungsvergleich wird EXAKT gefuehrt ────────────────────────────────────────────────

class ErwartungsvergleichIstExakt(unittest.TestCase):
    """`expected_subject_digest` wird exakt verglichen — nicht per startswith, casefold oder strip.

    WARUM DAS EIN EIGENER TEST IST. Der Vergleich ist die einzige Stelle, an der ein Leser sagen
    kann "dieses Receipt gehoert zu DEM Vorgang vor mir". Waere er lockerbar, koennte ein Receipt
    mit einem Digest durchgehen, der dem erwarteten nur AEHNELT — und Aehnlichkeit ist bei einem
    Hash keine Naehe, sondern ein anderer Gegenstand. Ein Riegel des Hauses meldete diesen
    Vergleich als einzigen ohne Beinahe-Treffer-Korpus; er hatte recht.

    Korpus aus `tests/_beinahe_treffer.py` — dieselbe Quelle wie kbjwt, statuslist und intoto.
    """

    def test_expected_subject_digest_wird_EXAKT_verglichen(self):
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from _beinahe_treffer import pruefe_exakt

        sk = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        pk = sk.public_key().public_bytes_raw()
        p = _pred()
        env = AR.emit_agent_review(p, sk)
        erwartet = AR._subject_digest(p)

        # Gegenprobe des Aufbaus: mit dem RICHTIGEN Digest ist es gueltig. Ohne diese Zeile misst
        # der Korpus unten nichts — jede Abwandlung waere schon deshalb falsch, weil alles falsch ist.
        self.assertTrue(
            AR.verify_agent_review(env, pk, expected_subject_digest=erwartet)["ok"],
            "der selbstgebaute Beleg verifiziert nicht — die Pruefung unten misst dann nichts")

        pruefe_exakt(
            lambda v: AR.verify_agent_review(env, pk, expected_subject_digest=v)["ok"],
            erwartet, self)
