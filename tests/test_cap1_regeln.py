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
    """Mit dem EINEN strikten Leser des Pakets — nicht mit einem eigenen Hook."""
    from proofbundle.errors import BundleFormatError
    with pytest.raises(BundleFormatError, match="duplicate JSON key"):
        cap1.load_cap1_document(b'{"profile": "cap/1", "profile": "cap/2"}')
    with pytest.raises(BundleFormatError):
        cap1.load_cap1_document('{"strata": [{"id": "a", "id": "b"}]}')  # auch in der Tiefe
    assert cap1.load_cap1_document(b'{"a": 1}') == {"a": 1}


@pytest.mark.parametrize("roh", [None, 42, 4.2, True, [], {}, object()])
def test_falscher_typ_ist_ein_typisierter_fehler(roh):
    with pytest.raises(ValueError):
        cap1.load_cap1_document(roh)


def test_positivkontrolle_bleibt_nach_kleinster_aenderung_nicht_konform():
    """Kontrolle gegen einen Verifizierer, der alles annimmt: eine Einheit aus der Buchfuehrung
    entfernt, und PV-01 muss an R1 fallen."""
    doc = _vektor("PV-01")
    s = doc["strata"][0]
    s["eligible"] = s["eligible"] + 1
    assert "R1-no-silent-remainder" in _gefeuert(doc)


def _viele_einheiten(n: int, mit_duplikat: bool) -> dict:
    namen = [f"unit.{i}" for i in range(n)]
    if mit_duplikat and n >= 2:
        namen[-1] = namen[0]
    return {"schemaVersion": "0.1.0", "strata": [{
        "id": "PV-01", "eligible": n, "examined": 0,
        "unexamined": [{"unit": u, "reason": "not examined"} for u in namen]}]}


def test_die_pruefung_bleibt_linear_in_der_zahl_der_einheiten():
    """THE COST OF REFUSING MUST NOT GROW FASTER THAN THE INPUT.

    Codex, review of 2026-09-23 on pull request 252: the duplicate report called `benannt.count(x)`
    once per entry over the same list, so a 1.37 MB document with 30,000 entries and ONE duplicate
    passed the parser budgets, loaded in 0.085 s, and then spent 10.49 s inside the check. The
    refusal was correct; the cost of reaching it was the defect.

    WHY THIS CASE IS HERE AND NOT IN THE COST-CURVE GUARD, and that is a correction of something I
    wrote in the reply to that finding. I said the cap1 dimension would be wired into
    `tests/test_budget_kostenkurve.py`. Measured afterwards, that does not fit: that file's
    `test_keine_dimension_ohne_last` asserts SET EQUALITY between the fields of `VerificationBudget`
    and its dimension list, so a cap1 entry there would need a new budget field — a change to a
    public verification interface, which is not something to slip in alongside a test. The promise
    named a mechanism whose shape I had not measured.

    So the assurance is built here instead, with the guard's own METHOD: a doubling series, own-process
    CPU time, the minimum of several runs, and the exponent over the series. Measured 2026-09-24 at
    2500, 5000, 10000 and 20000 units — exponent 1.053 without a duplicate and 1.024 with one, both
    under the 1.2 that file uses as its ceiling, and 20,000 units cost about 25 ms.

    THE DUPLICATE ARM IS THE POINT. Without it this case would pass over the exact input the finding
    was about, because the quadratic path only ran when a duplicate existed.
    """
    import math
    import resource

    def cpu() -> float:
        r = resource.getrusage(resource.RUSAGE_SELF)
        return r.ru_utime + r.ru_stime

    def kosten(doc) -> float:
        beste = math.inf
        for _ in range(3):
            a = cpu()
            cap1.check_cap1_document(doc)
            beste = min(beste, cpu() - a)
        return beste

    def exponent(paare):
        xs = [math.log(n) for n, _ in paare]
        ys = [math.log(max(k, 1e-9)) for _, k in paare]
        mx, my = sum(xs) / len(xs), sum(ys) / len(ys)
        ob = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
        un = sum((x - mx) ** 2 for x in xs)
        return ob / un if un else 0.0

    for mit_duplikat in (False, True):
        reihe = [(n, kosten(_viele_einheiten(n, mit_duplikat)))
                 for n in (2500, 5000, 10000, 20000)]
        e = exponent(reihe)
        assert e <= 1.35, (
            f"mit_duplikat={mit_duplikat}: exponent {e:.3f} over {reihe} — the cost of the check "
            f"grows faster than its input, which is the class the quadratic duplicate scan was")
        # AND THE REFUSAL MUST STILL FIRE. A check that got fast because it stopped finding the
        # duplicate would be the more expensive regression, and a cost measurement over a check that
        # reports nothing measures nothing.
        if mit_duplikat:
            assert "R1-no-silent-remainder" in _gefeuert(_viele_einheiten(2500, True)), \
                "the duplicate is no longer reported, so the measurement above is over nothing"
