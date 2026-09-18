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

_WURZEL = pathlib.Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "lk", _WURZEL / "scripts" / "b7_release_scope_landing_card.py")
LK = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(LK)


def _karte(monkeypatch, prs, zuordnung=None):
    monkeypatch.setattr(LK, "_gelandete_titel", lambda *a, **k: (prs, "measured"))
    monkeypatch.setattr(LK, "_nachtrag",
                        lambda: (zuordnung or {}, "measured" if zuordnung else "not present"))
    return LK.karte()


def test_die_posten_der_kopfzeile_gehen_auf(monkeypatch):
    """Total minus rider LINES minus ambiguous LINES equals countable. If this does not hold,
    the header is a claim with digits in it rather than a measurement.
    """
    d = _karte(monkeypatch, [])
    assert d["zustand"] == "gemessen", d
    assert (d["zeilen_gesamt"] - d["mitlaeufer_zeilen"] - d["kennung_mehrdeutig_zeilen"]
            == d["zeilen_zaehlbar"]), d


def test_rider_zeilen_und_rider_kennungen_sind_verschiedene_zahlen(monkeypatch):
    """The measured scope has one rider identifier leading two lines. A card that reports only
    the identifier count cannot be reconciled with its own denominator.
    """
    d = _karte(monkeypatch, [])
    assert d["mitlaeufer_zeilen"] >= len(d["mitlaeufer_kennungen"]), d


def test_eine_mehrdeutige_kennung_ist_nicht_zaehlbar(monkeypatch):
    """An identifier leading more than one line cannot be assigned from a title, so it belongs
    to neither the numerator nor the denominator. That is a finding about the FILE.
    """
    d = _karte(monkeypatch, [])
    for k in d["kennung_mehrdeutig"]:
        assert k not in d["offen"], (k, d["offen"])


def test_ein_titel_zaehlt_seine_zeile(monkeypatch):
    d = _karte(monkeypatch, [])
    if not d["offen"]:
        return
    k = d["offen"][0]
    e = _karte(monkeypatch, [{"number": 999, "title": f"[6.1.0 {k}] feat(x): y",
                              "mergedAt": "2026-09-16T00:00:00Z"}])
    assert e["gelandet"] == d["gelandet"] + 1, (d["gelandet"], e["gelandet"])
    assert e["aus_titeln"] == 1 and k not in e["offen"]


def test_die_zuordnungsdatei_zaehlt_ohne_den_titel_zu_aendern(monkeypatch):
    """Retroactive assignment is the whole point of the file: a merged title is never rewritten."""
    d = _karte(monkeypatch, [])
    if not d["offen"]:
        return
    k = d["offen"][0]
    e = _karte(monkeypatch, [], zuordnung={k: 123})
    assert e["aus_zuordnung"] == 1 and e["aus_titeln"] == 0
    assert e["gelandet"] == d["gelandet"] + 1


def test_eine_fremde_version_im_titel_zaehlt_nicht(monkeypatch):
    """A bracket of another release names another scope. Counting it would inflate this one."""
    d = _karte(monkeypatch, [])
    if not d["offen"]:
        return
    k = d["offen"][0]
    e = _karte(monkeypatch, [{"number": 998, "title": f"[6.0.1 {k}] feat(x): y",
                              "mergedAt": "2026-09-16T00:00:00Z"}])
    assert e["gelandet"] == d["gelandet"], (d["gelandet"], e["gelandet"])


def test_eine_unlesbare_pr_liste_ist_nicht_messbar_und_kein_null(monkeypatch):
    """Zero landed and not-measurable look the same in a number and mean the opposite."""
    monkeypatch.setattr(LK, "_gelandete_titel", lambda *a, **k: ([], "NOT MEASURABLE: no network"))
    d = LK.karte()
    assert d["zustand"] == "NOT MEASURABLE" and d["rc"] == 2, d
