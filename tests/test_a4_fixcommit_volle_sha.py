"""Teil A4: in v0.2 traegt `fixCommit` die volle 40-stellige SHA, alles andere ist ein Fehler.

WARUM DIE VOLLE. Ein gekuerzter Hash ist eine Suchanfrage, keine Angabe — er bindet nichts,
solange nicht feststeht, in welchem Repo und zu welchem Zeitpunkt gesucht wird, und Kollisionen
kurzer Praefixe sind in grossen Repos alltaeglich. Ein Receipt, das eine Behebung mit sieben
Zeichen benennt, verlangt vom Leser genau die Arbeit, die es ihm abnehmen soll.

WARUM NUR IN v0.2. `_validate_finding` ist zwischen beiden Fassungen GETEILT. Die Regel dort
einzubauen haette die Altfassung mitverschaerft und damit sechs bereits ausgestellte Receipts
nachtraeglich beurteilt — eine Schnittstelle brechen statt sie zu haerten. Der Nachbarcode
(`disclosureCoreDigest`) hat dieselbe Ruecksicht schon dokumentiert; diese Datei prueft, dass sie
auch hier gilt.
"""
from __future__ import annotations

import pytest

from proofbundle import agent_review as AR

VOLL = "a" * 40


def _pred(fix):
    """Ein v0.2-Praedikat mit genau EINEM Befund, dessen fixCommit variiert."""
    return {
        "schemaVersion": "0.2",
        "declaration": {"reviewer": {"name": "t"}, "assurance": "selfDeclared",
                        "timeClaims": [{"kind": "reviewCompleted", "at": "2026-09-04T00:00:00Z"}]},
        "subjectContext": {"kind": "pullRequest", "repository": "b7n0de/proofbundle",
                           "number": 1, "headCommit": "b" * 40,
                           "disclosureCoreDigest": "c" * 64},
        "coverage": {"claim": "partial", "gap": "nur ein Befund"},
        "findings": [{"id": "F1", "severity": "low", "title": "t",
                      "disposition": "fixed", "fixCommit": fix}],
        "limitationCodes": ["SELF_DECLARED"],
    }


def _fehler(fix) -> list[str]:
    return [e for e in AR.validate_agent_review_v02_predicate(_pred(fix), strict=True)
            if "FIXCOMMIT_NOT_FULL_SHA" in e]


def test_die_volle_sha_ist_zulaessig():
    assert _fehler(VOLL) == []


@pytest.mark.parametrize("fix,warum", [
    ("a" * 7,  "gekuerzt auf sieben"),
    ("a" * 12, "gekuerzt auf zwoelf"),
    ("a" * 39, "eins zu kurz"),
    ("a" * 41, "eins zu lang"),
    ("A" * 40, "GROSSbuchstaben — Hex ist hier kleingeschrieben"),
    ("g" * 40, "kein Hex"),
    ("a" * 39 + "z", "letztes Zeichen kein Hex"),
    (" " + "a" * 39, "fuehrendes Leerzeichen"),
    (12345, "gar keine Zeichenkette"),
    ([VOLL], "in einer Liste verpackt"),
])
def test_alles_andere_faellt_mit_dem_benannten_code(fix, warum):
    assert _fehler(fix), f"{warum}: kam durch"


def test_ohne_fixcommit_greift_die_regel_nicht():
    """GEGENRICHTUNG. Ein Befund ohne `fixCommit` ist kein Fall dieser Regel — sonst haette sie
    jede offene Feststellung mitbeschuldigt. Ob ein GESCHLOSSENER Befund einen tragen MUSS,
    entscheidet die bestehende v0.1-Regel, und die bleibt unberuehrt."""
    p = _pred(VOLL)
    p["findings"][0]["disposition"] = "open"
    del p["findings"][0]["fixCommit"]
    assert not [e for e in AR.validate_agent_review_v02_predicate(p, strict=True)
                if "FIXCOMMIT_NOT_FULL_SHA" in e]


def test_die_altfassung_bleibt_unberuehrt():
    """DER KERN DER ENTWURFSENTSCHEIDUNG. Sechs v0.1-Receipts stehen draussen; wuerde die Regel im
    geteilten `_validate_finding` sitzen, waeren sie nachtraeglich beurteilt worden."""
    p = {"schemaVersion": "0.1",
         "declaration": {"reviewer": {"name": "t"}, "assurance": "selfDeclared"},
         "subjectContext": {"kind": "pullRequest", "repository": "b7n0de/proofbundle",
                            "number": 1, "headCommit": "b" * 40},
         "coverage": {"claim": "partial", "gap": "x"},
         "findings": [{"id": "F1", "severity": "low", "title": "t",
                       "disposition": "fixed", "fixCommit": "a1b2c3d"}]}
    assert not [e for e in AR.validate_agent_review_predicate(p, strict=True)
                if "FIXCOMMIT_NOT_FULL_SHA" in e], (
        "die v0.1-Validierung hat die v0.2-Regel geerbt — genau das sollte sie nicht")
