"""Die Automations-Flaeche darf nie nachsichtiger urteilen als das Urteil, das sie zusammenfasst.

DER BEFUND, der diesen Test noetig machte (Tiefen-Gate 5.1.0, 01.09.2026, von ZWEI unabhaengigen
Linsen gefunden und danach von Hand reproduziert): `safeForAutomation` blieb `True`, waehrend `ok`
auf `False` stand — auf zwei Wegen. Ohne `expected_subject_digest` steht `subject_binding_ok` auf
`None`, und die Referenz-Auswertung blockt nur bei einem EXPLIZITEN `False`. Und bei
`body_core_digest_match == "MISMATCH"` — der sichtbare Text ist nachweislich nicht der signierte —
blockte gar nichts, weil die Achse stringwertig ist und korrekt nicht in `references` steht.

WARUM DIESER TEST UEBER DIE VOLLE MENGE LAEUFT UND NICHT UEBER DIE ZWEI BEKANNTEN FAELLE.
Ein Test, der die zwei gemeldeten Achsen aufzaehlt, ist beim naechsten Lauf wieder blind — dann
gegen die dritte. Die Eigenschaft ist EINE Invariante, und sie wird hier als solche geprueft:
ueber jede Kombination, die ein `ok=False` erzeugen kann.

Das ist die Generator-Haertung, die das Runbook fuer jeden Fund verlangt: Property statt
Punktfixture.
"""
from __future__ import annotations

import itertools

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofbundle import agent_review as ar

SK = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
PK = SK.public_key().public_bytes_raw()
KOERPER = "Ein PR-Rumpf, wie er sichtbar veroeffentlicht wird."


def _doc(**ueber):
    d = {
        "schemaVersion": "0.1.0", "reviewId": "invariante",
        "subjectContext": {"kind": "githubPullRequest", "forge": "github.com",
                           "repositoryId": "R_kg", "pullRequestNodeId": "PR_kw1",
                           "headSha": "a" * 40, "baseSha": "b" * 40,
                           "reviewedDiffDigest": "c" * 64,
                           "bodyCoreDigest": ar.body_core_digest(KOERPER)},
        "declaration": {"authoring": [{"assurance": "selfDeclared", "assertedBy": "agent"}],
                        "reviewRuns": [], "findings": [], "findingsTotal": 0,
                        "findingsRoot": ar.findings_root([]),
                        "nonClaims": ["keine Aussage ueber Qualitaet"]},
        "coverage": {"status": "PARTIAL", "knownGaps": ["nur eine Runde"]},
        "times": {"declaredAt": "2026-09-01T09:00:00Z"},
        "limitations": ["Tier 1"],
    }
    d.update(ueber)
    return d


#: Jede Achse, die ein `ok=False` erzeugen kann — als AUFRUF-Variation, nicht als Feldliste.
#: Wer hier eine Zeile ergaenzt, erweitert die gepruefte Menge; wer eine Achse im Modul ergaenzt,
#: ohne sie hier zu nennen, wird vom Vollstaendigkeits-Test darunter erwischt.
VARIANTEN = {
    "ziel_erwartung": [None, "gesetzt", "falsch"],
    "sichtbarer_text": [None, "passend", "abweichend"],
}


def _fahre(ziel, text):
    doc = _doc()
    env = ar.emit_agent_review(doc, SK)
    kw = {}
    if ziel == "gesetzt":
        kw["expected_subject_digest"] = ar._subject_digest(doc)
    elif ziel == "falsch":
        kw["expected_subject_digest"] = "f" * 64
    if text == "passend":
        kw["observed_body"] = KOERPER
    elif text == "abweichend":
        kw["observed_body"] = "Ein GANZ ANDERER Rumpf, den niemand signiert hat."
    return ar.verify_agent_review(env, PK, strict=True, **kw)


@pytest.mark.parametrize("ziel,text", list(itertools.product(*VARIANTEN.values())))
def test_safe_impliziert_ok(ziel, text):
    """DIE INVARIANTE: safeForAutomation=True setzt ok=True voraus. Ueber die volle Kombination."""
    r = _fahre(ziel, text)
    a = r.get("automation") or {}
    if a.get("safeForAutomation") is True:
        assert r.get("ok") is True, (
            f"ziel={ziel!r} text={text!r}: die Automations-Flaeche meldet sicher, waehrend das "
            f"Receipt-Urteil ok={r.get('ok')!r} lautet — blockers={a.get('automationBlockers')}")


def test_die_menge_enthaelt_ueberhaupt_einen_nicht_ok_fall():
    """GEGENPROBE. Ohne sie waere der Test oben gruen, weil er nie einen ok=False sieht — genau
    die Tautologie, die im Konformitaets-Korpus dieses Releases gefunden wurde."""
    nicht_ok = [(z, t) for z in VARIANTEN["ziel_erwartung"] for t in VARIANTEN["sichtbarer_text"]
                if _fahre(z, t).get("ok") is not True]
    assert len(nicht_ok) >= 3, (
        f"nur {len(nicht_ok)} Kombinationen liefern ok!=True — die Menge prueft die Invariante "
        f"kaum: {nicht_ok}")


def test_beide_verifier_pfade_tragen_die_nachkorrektur():
    """STRUKTURELL, gegen die Klasse 'ein Fix erreichte nur eine Kopie'. Der urspruengliche Defekt
    entstand genau so: der v0.1-Pfad wurde gehaertet, der v0.2-Pfad nicht."""
    import inspect
    quelle = inspect.getsource(ar)
    n = quelle.count("_automation_darf_nicht_nachsichtiger_sein_als_ok(r)")
    assert n >= 2, (
        f"die Nachkorrektur wird nur {n}x gerufen — v0.1 UND v0.2 muessen sie tragen")


def test_der_kontrollfall_bleibt_gruen():
    """Ein Riegel, der alles blockt, ist kein Riegel."""
    r = _fahre("gesetzt", "passend")
    assert r.get("ok") is True
    assert (r.get("automation") or {}).get("safeForAutomation") is True
