"""Contract for the landing card (owner GO 2026-09-14, part D).

BOTH CASES BELOW ARE DEFECTS THE CARD HAD BEFORE IT SHIPPED, and both are the same one: a
numerator and a denominator drawn from different units. The counting unit of the scope is the
LINE. An identifier is not a line, and neither is a branch.

The first version collected landed lines in a dict keyed by IDENTIFIER while the denominator
counted lines, so two lines under one identifier could never both be counted and the difference
looked like unfinished work. The second reported the number of rider IDENTIFIERS while the
denominator subtracted rider LINES, so the header did not add up: a reader got 42 and read 41.
"""
from __future__ import annotations

import importlib.util
import pathlib

import pytest

_WURZEL = pathlib.Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "lk", _WURZEL / "scripts" / "b7_release_scope_landing_card.py")
LK = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(LK)


#: A FROZEN SCOPE OF ITS OWN, not the scope of the release being built. Until 2026-10-09 these cases
#: counted the real scope `karte()` picks without a version, and that is the next release: after the
#: tag v6.2.0 it was 6.3.0, which names no branch, and six of these cases went red on main for every
#: pull request. They test the counting logic, so they count a scope that no release moves: two
#: countable lines, one identifier leading two lines with branches of their own, and one rider
#: identifier leading two lines.
_UMFANG = """# Release scope — 9.9.9 (frozen for the landing card contract)

## In

| Identifier | Subject | Branch |
|---|---|---|
| A1 | the first countable line | `fix/a1` |
| A2 | the second countable line | `fix/a2` |
| A3 | an identifier leading two lines | `fix/a3-one` |
| A3 | the same identifier, a second line | `fix/a3-two` |
| R1 | a rider | with A1 |
| R1 | the same rider, a second line | with A2 |

## Out

| Identifier | Subject | Branch |
|---|---|---|
| X1 | not being built | `fix/x1` |
"""


@pytest.fixture
def umfang(tmp_path):
    p = tmp_path / "9.9.9.md"
    p.write_text(_UMFANG, encoding="utf-8")
    return p


def _karte(monkeypatch, umfang, prs, zuordnung=None):
    monkeypatch.setattr(LK, "_gelandete_titel", lambda *a, **k: (prs, "measured"))
    monkeypatch.setattr(LK, "_nachtrag",
                        lambda: (zuordnung or {}, "measured" if zuordnung else "not present"))
    d = LK.karte(version="9.9.9", scope_pfad=umfang)
    # A case that returns early on an empty list asserts nothing; the frozen scope keeps lines open.
    assert d["zustand"] == "gemessen" and d["offen"], d
    return d


def test_die_posten_der_kopfzeile_gehen_auf(monkeypatch, umfang):
    """Total minus rider LINES minus ambiguous LINES equals countable. If this does not hold,
    the header is a claim with digits in it rather than a measurement.
    """
    d = _karte(monkeypatch, umfang, [])
    assert (d["zeilen_gesamt"] - d["mitlaeufer_zeilen"] - d["kennung_mehrdeutig_zeilen"]
            == d["zeilen_zaehlbar"]), d
    assert (d["zeilen_gesamt"], d["mitlaeufer_zeilen"], d["kennung_mehrdeutig_zeilen"],
            d["zeilen_zaehlbar"]) == (6, 2, 2, 2), d


def test_rider_zeilen_und_rider_kennungen_sind_verschiedene_zahlen(monkeypatch, umfang):
    """The frozen scope has one rider identifier leading two lines. A card that reports only
    the identifier count cannot be reconciled with its own denominator.
    """
    d = _karte(monkeypatch, umfang, [])
    assert d["mitlaeufer_kennungen"] == ["R1"] and d["mitlaeufer_zeilen"] == 2, d


def test_eine_mehrdeutige_kennung_ist_nicht_zaehlbar(monkeypatch, umfang):
    """An identifier leading more than one line cannot be assigned from a title, so it belongs
    to neither the numerator nor the denominator. That is a finding about the FILE.
    """
    d = _karte(monkeypatch, umfang, [])
    assert d["kennung_mehrdeutig"] == ["A3"], d
    assert "A3" not in d["offen"], d["offen"]


def test_ein_titel_zaehlt_seine_zeile(monkeypatch, umfang):
    d = _karte(monkeypatch, umfang, [])
    k = d["offen"][0]
    # The card's own release, not a typed one: the title named 6.1.0 here while the card's default
    # was 6.1.0, and it stopped counting the day that default became the release being built.
    e = _karte(monkeypatch, umfang, [{"number": 999, "title": f"[{d['version']} {k}] feat(x): y",
                                      "mergedAt": "2026-09-16T00:00:00Z"}])
    assert e["gelandet"] == d["gelandet"] + 1, (d["gelandet"], e["gelandet"])
    assert e["aus_titeln"] == 1 and k not in e["offen"]


def test_die_zuordnungsdatei_zaehlt_ohne_den_titel_zu_aendern(monkeypatch, umfang):
    """Retroactive assignment is the whole point of the file: a merged title is never rewritten."""
    d = _karte(monkeypatch, umfang, [])
    k = d["offen"][0]
    e = _karte(monkeypatch, umfang, [], zuordnung={k: 123})
    assert e["aus_zuordnung"] == 1 and e["aus_titeln"] == 0
    assert e["gelandet"] == d["gelandet"] + 1


def test_eine_fremde_version_im_titel_zaehlt_nicht(monkeypatch, umfang):
    """A bracket of another release names another scope. Counting it would inflate this one."""
    d = _karte(monkeypatch, umfang, [])
    k = d["offen"][0]
    e = _karte(monkeypatch, umfang, [{"number": 998, "title": f"[6.0.1 {k}] feat(x): y",
                                      "mergedAt": "2026-09-16T00:00:00Z"}])
    assert e["gelandet"] == d["gelandet"], (d["gelandet"], e["gelandet"])


def test_eine_unlesbare_pr_liste_ist_nicht_messbar_und_kein_null(monkeypatch, umfang):
    """Zero landed and not-measurable look the same in a number and mean the opposite."""
    monkeypatch.setattr(LK, "_gelandete_titel", lambda *a, **k: ([], "NOT MEASURABLE: no network"))
    d = LK.karte(version="9.9.9", scope_pfad=umfang)
    assert d["zustand"] == "NOT MEASURABLE" and d["rc"] == 2 and "no network" in d["grund"], d


#: A scope file as a release that has not started writes it: the title says so, and its In tables
#: name items without a branch column. The real 6.3.0 scope after the tag v6.2.0 has this shape.
_NICHT_BEGONNEN = """# Release scope — 9.9.9 (not started)

## In

| Item | Why it carries no outward outcome |
|---|---|
| P30 | something for later |
| P31 | something else for later |

## Out — what was already out stays out

| Item | Why |
|---|---|
| X1 | not being built |
"""


def test_ein_nicht_begonnener_umfang_wird_mit_null_zweigen_gezaehlt(monkeypatch, tmp_path):
    """Red before 2026-10-09: the card answered NOT MEASURABLE for such a file, and after the tag
    v6.2.0 that was the scope of the release being built. Measured, nought of nought, and named."""
    p = tmp_path / "9.9.9.md"
    p.write_text(_NICHT_BEGONNEN, encoding="utf-8")
    monkeypatch.setattr(LK, "_gelandete_titel", lambda *a, **k: ([], "measured"))
    d = LK.karte(version="9.9.9", scope_pfad=p)
    assert d["zustand"] == "gemessen" and d["rc"] == 0, d
    assert d["umfang_nicht_begonnen"] is True and d["zeilen_zaehlbar"] == 0, d


def test_ohne_die_ausweisung_bleibt_ein_umfang_ohne_zweig_nicht_messbar(monkeypatch, tmp_path):
    """The other direction. The same file without "(not started)" in its title is no declared
    release, and a scope without a branch stays NOT MEASURABLE, as before."""
    p = tmp_path / "9.9.9.md"
    p.write_text(_NICHT_BEGONNEN.replace(" (not started)", ""), encoding="utf-8")
    monkeypatch.setattr(LK, "_gelandete_titel", lambda *a, **k: ([], "measured"))
    d = LK.karte(version="9.9.9", scope_pfad=p)
    assert d["zustand"] == "NOT MEASURABLE" and d["rc"] == 2, d
    assert "kein einziger Zweig" in d["grund"], d
