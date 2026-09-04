"""CAP-1 als Paketfunktion: die fuenfzehn Vektoren, die acht Mutanten, und kein Absturz.

DIE VEKTOREN sind die des Autors (Certisyn-Inc/certisyn-drafts, Commit 0980d32, Apache-2.0, Kopie
unter conformance/cap1/vectors/ mit LICENSE.author). Erwartet wird nicht nur "refused", sondern
die EXAKTE Menge gefeuerter Regeln aus dem aufgezeichneten Lauf des Autors
(`_author_conformance_run.json`) — einschliesslich der Doppelung bei NC-05 (R1 und R5), die eine
Umsetzung nur trifft, wenn sie R5 unabhaengig von R1 misst. Ein Gegenbeweis, der aus dem falschen
Grund faellt, belegt seine Regel nicht (Entwurf §7.1).

DIE MUTANTEN, Entwurf §7.2 woertlich: "Each of the eight rules is silenced in turn and the class is
re-run; the class MUST fail in each case. Eight rules, eight mutants, eight kills." R0 hat im Korpus
des Autors keinen eigenen Vektor und wird hier ueber ein eigenes Dokument gefangen.
"""
from __future__ import annotations

import json
import pathlib

import pytest

from proofbundle import cap1

VEKTOREN = pathlib.Path(__file__).resolve().parents[1] / "conformance" / "cap1" / "vectors"
MANIFEST = json.loads((VEKTOREN / "manifest.json").read_text(encoding="utf-8"))
AUTOR_LAUF = {r["id"]: r for r in json.loads(
    (VEKTOREN / "_author_conformance_run.json").read_text(encoding="utf-8"))["results"]}


def _vektor(vid: str) -> dict:
    return cap1.load_cap1_document((VEKTOREN / f"{vid}.json").read_bytes())


def _gefeuert(doc: object) -> set[str]:
    return {e["rule"] for e in cap1.check_cap1_document(doc)}


def test_es_sind_fuenfzehn_vektoren_und_acht_regeln():
    """DRITTER ZUSTAND: ohne diese Zeile waeren die parametrisierten Tests bei leerem Ordner gruen."""
    assert len(MANIFEST) == 15
    assert sum(1 for e in MANIFEST if e["expect"] == "conform") == 5
    assert set(cap1.RULE_IDS) >= {f"R{i}-" + s for i, s in (
        (1, "no-silent-remainder"), (2, "closed-disposition"), (3, "withholding-digest-bound"),
        (4, "denominator-basis"), (5, "counts-well-formed"), (6, "absence-is-scoped"),
        (7, "incomplete-not-clean"), (8, "supports-bounds-citation"))}


@pytest.mark.parametrize("eintrag", MANIFEST, ids=[e["id"] for e in MANIFEST])
def test_jeder_vektor_feuert_genau_die_regeln_des_autors(eintrag):
    vid = eintrag["id"]
    gefeuert = _gefeuert(_vektor(vid))
    erwartet = set(AUTOR_LAUF[vid]["rules"])
    assert gefeuert == erwartet, f"{vid}: gefeuert {sorted(gefeuert)} != Autor {sorted(erwartet)}"
    if eintrag["expect"] == "conform":
        assert cap1.is_conformant(_vektor(vid))
    else:
        assert eintrag["rule"] in gefeuert, f"{vid} faellt nicht an seiner Regel {eintrag['rule']}"


@pytest.mark.parametrize("regel", [r for r in cap1.RULE_IDS if r != "R0-shape"])
def test_meta_acht_regeln_acht_mutanten_acht_kills(monkeypatch, regel):
    """Die Regel stumm geschaltet: mindestens ein negativer Vektor, der sie zum Ziel hat, wird
    nicht mehr abgewiesen — sonst waere die Regel Dekoration (Entwurf §7.2)."""
    ziele = [e["id"] for e in MANIFEST if e.get("rule") == regel]
    assert ziele, f"kein Vektor zielt auf {regel}"
    monkeypatch.setitem(cap1.RULES, regel, lambda doc, f: None)
    ueberlebt = [vid for vid in ziele if regel not in _gefeuert(_vektor(vid))]
    assert ueberlebt == ziele, f"{regel} stumm, aber {set(ziele) - set(ueberlebt)} fallen weiter an ihr"
    # Und die Positivkontrollen bleiben konform — ein Mutant, der alles rot faerbt, beweist nichts.
    for e in MANIFEST:
        if e["expect"] == "conform":
            assert cap1.is_conformant(_vektor(e["id"]))


def test_meta_r0_faengt_ein_dokument_ohne_gestalt(monkeypatch):
    kaputt = {"profile": "cap/2", "strata": [], "integrity": {"complete": "ja"}}
    assert "R0-shape" in _gefeuert(kaputt)
    monkeypatch.setitem(cap1.RULES, "R0-shape", lambda doc, f: None)
    assert "R0-shape" not in _gefeuert(kaputt)


@pytest.mark.parametrize("muell", [None, "text", 7, 2.5, [], [1, 2], {"strata": "x"},
                                   {"profile": "cap/1", "strata": [None, 3], "integrity": None},
                                   {"profile": "cap/1", "strata": [{"unexamined": [None, "u"], "basis": 5}]},
                                   {"absence_assertions": "nein"}, {"absence_assertions": [None]}])
def test_never_raise_auf_muell(muell):
    out = cap1.check_cap1_document(muell)
    assert isinstance(out, list) and out, "Muell muss abgewiesen werden, nicht durchgewinkt"
    assert all(set(e) == {"rule", "reason"} for e in out)


def test_doppelte_namen_werden_beim_lesen_abgewiesen():
    with pytest.raises(cap1.Cap1DuplicateKey):
        cap1.load_cap1_document(b'{"profile": "cap/1", "profile": "cap/2"}')
    assert cap1.load_cap1_document(b'{"a": 1}') == {"a": 1}


def test_positivkontrolle_bleibt_nach_kleinster_aenderung_nicht_konform():
    """Kontrolle gegen einen Verifizierer, der alles annimmt: eine Einheit aus der Buchfuehrung
    entfernt, und PV-01 muss an R1 fallen."""
    doc = _vektor("PV-01")
    s = doc["strata"][0]
    s["eligible"] = s["eligible"] + 1
    assert "R1-no-silent-remainder" in _gefeuert(doc)
