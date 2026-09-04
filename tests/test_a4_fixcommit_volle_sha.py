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

from pathlib import Path

import pytest

from proofbundle import agent_review as AR

REPO = Path(__file__).resolve().parents[1]

VOLL = "a" * 40


#: DIE ECHTE FORM, AUS DEM KORPUS GELESEN — nicht die, die ich im Kopf hatte.
#:
#: Die erste Fassung dieser Datei baute ihr Praedikat selbst, mit einem Top-Level-`findings` und
#: erfundenen Feldnamen. Alle dreizehn Tests waren bestanden, der A4-Mutant fing zehn davon — und
#: die REGEL griff trotzdem nie, weil die Befunde in Wirklichkeit unter `declaration.findings`
#: liegen. Test, Mutant und Regel teilten denselben Irrtum; aufgedeckt hat ihn erst ein Fall aus
#: dem Konformitaetskorpus. Ein selbstgebautes Fixture prueft die Form, die man im Kopf hat.
_KORPUS = REPO / "conformance" / "agent_review"
_VORLAGE = _KORPUS / "agent-review-v02-positive-control-fixcommit-full-sha-is-accepted" / "predicate.json"


def _pred(fix):
    """Ein v0.2-Praedikat aus dem KORPUS, dessen fixCommit variiert."""
    import copy
    import json as _j
    p = copy.deepcopy(_j.loads(_VORLAGE.read_text(encoding="utf-8")))
    p["declaration"]["findings"][0]["fixCommit"] = fix
    return p


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
    p["declaration"]["findings"][0]["disposition"] = "open"
    del p["declaration"]["findings"][0]["fixCommit"]
    assert not [e for e in AR.validate_agent_review_v02_predicate(p, strict=True)
                if "FIXCOMMIT_NOT_FULL_SHA" in e]


def test_die_altfassung_bleibt_unberuehrt():
    """DER KERN DER ENTWURFSENTSCHEIDUNG. Sechs v0.1-Receipts stehen draussen; wuerde die Regel im
    geteilten `_validate_finding` sitzen, waeren sie nachtraeglich beurteilt worden."""
    p = _pred("a1b2c3d")   # dieselbe ECHTE Form, nur gegen den v0.1-Validator gehalten
    assert not [e for e in AR.validate_agent_review_predicate(p, strict=True)
                if "FIXCOMMIT_NOT_FULL_SHA" in e], (
        "die v0.1-Validierung hat die v0.2-Regel geerbt — genau das sollte sie nicht")
