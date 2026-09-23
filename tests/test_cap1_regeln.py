"""CAP-1 as a package function: the fifteen vectors, the eight mutants, and no crash.

THE VECTORS are the author's (Certisyn-Inc/certisyn-drafts, commit 0980d32, Apache-2.0, copied to
conformance/cap1/vectors/ with LICENSE.author). What is expected is not merely "refused" but the
EXACT set of fired rules from the author's recorded run (`_author_conformance_run.json`) —
including the duplication at NC-05 (R1 and R5), which an implementation only hits if it measures R5
independently of R1. A counter-proof that fails for the wrong reason does not establish its rule
(draft §7.1).

THE MUTANTS, draft §7.2 verbatim: "Each of the eight rules is silenced in turn and the class is
re-run; the class MUST fail in each case. Eight rules, eight mutants, eight kills." R0 has no vector
of its own in the author's corpus and is caught here through a document written for it.
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
    """THIRD STATE: without this line the parametrised tests would be green on an empty folder."""
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
    assert gefeuert == erwartet, f"{vid}: fired {sorted(gefeuert)} != author {sorted(erwartet)}"
    if eintrag["expect"] == "conform":
        assert cap1.is_conformant(_vektor(vid))
    else:
        assert eintrag["rule"] in gefeuert, f"{vid} does not fail at its rule {eintrag['rule']}"


@pytest.mark.parametrize("regel", [r for r in cap1.RULE_IDS if r != "R0-shape"])
def test_meta_acht_regeln_acht_mutanten_acht_kills(monkeypatch, regel):
    """With the rule silenced, at least one negative vector aimed at it is no longer refused —
    otherwise the rule is decoration (draft §7.2)."""
    ziele = [e["id"] for e in MANIFEST if e.get("rule") == regel]
    assert ziele, f"no vector targets {regel}"
    monkeypatch.setitem(cap1.RULES, regel, lambda doc, f: None)
    ueberlebt = [vid for vid in ziele if regel not in _gefeuert(_vektor(vid))]
    assert ueberlebt == ziele, f"{regel} silenced, yet {set(ziele) - set(ueberlebt)} still fail at it"
    # And the positive controls stay conformant — a mutant that turns everything red proves nothing.
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
    assert isinstance(out, list) and out, "garbage has to be refused, not waved through"
    assert all(set(e) == {"rule", "reason"} for e in out)


def test_doppelte_namen_werden_beim_lesen_abgewiesen():
    """With the package's ONE strict reader — not with a hook of its own."""
    from proofbundle.errors import BundleFormatError
    with pytest.raises(BundleFormatError, match="duplicate JSON key"):
        cap1.load_cap1_document(b'{"profile": "cap/1", "profile": "cap/2"}')
    with pytest.raises(BundleFormatError):
        cap1.load_cap1_document('{"strata": [{"id": "a", "id": "b"}]}')  # nested, too
    assert cap1.load_cap1_document(b'{"a": 1}') == {"a": 1}


@pytest.mark.parametrize("roh", [None, 42, 4.2, True, [], {}, object()])
def test_falscher_typ_ist_ein_typisierter_fehler(roh):
    with pytest.raises(ValueError):
        cap1.load_cap1_document(roh)


def test_positivkontrolle_bleibt_nach_kleinster_aenderung_nicht_konform():
    """A control against a verifier that accepts everything: remove one unit from the bookkeeping
    and PV-01 has to fail at R1."""
    doc = _vektor("PV-01")
    s = doc["strata"][0]
    s["eligible"] = s["eligible"] + 1
    assert "R1-no-silent-remainder" in _gefeuert(doc)
