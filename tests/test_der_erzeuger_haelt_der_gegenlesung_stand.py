"""What six review lenses broke in the register producer on 2026-09-20, kept as executable cases.

The lenses ran against the head that introduced the 610 line and the third find form. Each case
below reproduces one of their counter-examples and asserts the repair. They are written from the
counter-example inwards, not from the fix outwards: every one of them was RED before its repair.

WHAT IS NOT CLAIMED. These are the defects that were found, not the defects that exist. Two of the
lens findings are carried as named limits instead of as cases, and they are named in the module
that carries them: a heading of the form `## Open questions, all resolved` still reads as open,
and a promise denied in a wording other than the short negation list still reads as a promise.
Deciding whether prose asserts or denies is not a job a pattern finishes.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]


def _erzeuger():
    s = importlib.util.spec_from_file_location(
        "_gen_under_test", REPO / "scripts" / "gen_findings_register.py")
    m = importlib.util.module_from_spec(s)
    sys.modules["_gen_under_test"] = m
    s.loader.exec_module(m)
    return m


ZUSAGE = "Register entry `{}`, target 6.2.0."


def test_ein_absatz_mit_CRLF_verschluckt_nicht_die_ganze_datei():
    """Lens 1, target 2. Measured: with CRLF the literal two-newline search never fires, and one
    identifier received the WHOLE 371 KB source document as its evidence, accepted by the checker
    because a whole file is a range inside the file."""
    g = _erzeuger()
    text = ("Head.\r\n\r\nSome paragraph before.\r\n\r\n"
            + ZUSAGE.format("AAA-BBBBBBB-01") + "\r\n\r\nTail after it.\r\n")
    von, bis, art = g.schneide_beleg(text, "AAA-BBBBBBB-01")
    stueck = text.encode()[von:bis].decode()
    assert art == "prosa_zusage"
    assert "Some paragraph before" not in stueck, stueck
    assert "Tail after it" not in stueck, stueck


def test_eine_zeile_aus_leerzeichen_trennt_zwei_absaetze():
    """Lens 1, target 4. A separator line carrying spaces let two paragraphs merge, so one
    finding's evidence swallowed its neighbour's sentence."""
    g = _erzeuger()
    text = ("Head.\n\nNeighbour sentence that must stay out.\n   \n"
            + ZUSAGE.format("CCC-DDDDDDD-01") + "\n\nTail.\n")
    von, bis, _ = g.schneide_beleg(text, "CCC-DDDDDDD-01")
    assert "Neighbour sentence" not in text.encode()[von:bis].decode()


def test_eine_verneinte_zusage_ist_keine():
    """Lens 1, target 3. `there is no Register entry X` produced a record whose title was the
    sentence denying it."""
    g = _erzeuger()
    text = ("Head.\n\nThis is closed, so there is no Register entry `EEE-FFFFFFF-01` for it.\n\n")
    assert g.schneide_beleg(text, "EEE-FFFFFFF-01") is None


def test_eine_kennung_die_aus_dem_belegverzeichnis_ausbricht_wird_abgewiesen(tmp_path):
    """Lens 2, target 4, the sharpest of the round. An entry whose identifier is a traversal path
    produced a record the checker accepted with zero errors, and the evidence write landed outside
    the repository."""
    g = _erzeuger()
    quelle = tmp_path / "RESTRISIKO_PROBE.md"
    kennung = "../../../../tmp/ausbruch"
    quelle.write_text(f"## {kennung}\n\nSomething.\n", encoding="utf-8")
    ok = tmp_path / "PROBE_OBJEKTKLASSEN.json"
    ok.write_text(json.dumps({"gemessen_an": {"datei": "RESTRISIKO_PROBE.md",
                                              "sha256": "0" * 64, "utc": "2026-09-20T00:00:00Z"},
                              "eintraege": [{"kennung": kennung, "klasse": "x",
                                             "zaehlt_als_fund": True}]}),
                  encoding="utf-8")
    g.RESTRISIKO_REL, g.OBJEKTKLASSEN_REL = "RESTRISIKO_PROBE.md", "PROBE_OBJEKTKLASSEN.json"
    with pytest.raises(SystemExit) as e:
        g.baue_v2(tmp_path, "2026-09-20T00:00:00Z")
    assert "Kennung" in str(e.value)


def test_eine_fehlende_quelle_endet_in_einem_urteil_nicht_in_einem_traceback(tmp_path):
    """Lens 2, target 3. A missing per-entry source raised a raw FileNotFoundError, so the run had
    no NOT MEASURABLE path at all."""
    g = _erzeuger()
    (tmp_path / "RESTRISIKO_PROBE.md").write_text("## K1\n\nSomething.\n", encoding="utf-8")
    ok = tmp_path / "PROBE_OBJEKTKLASSEN.json"
    ok.write_text(json.dumps({"gemessen_an": {"datei": "RESTRISIKO_PROBE.md",
                                              "sha256": "0" * 64, "utc": "2026-09-20T00:00:00Z"},
                              "eintraege": [{"kennung": "K1", "klasse": "x",
                                             "zaehlt_als_fund": True,
                                             "quelle": "GIBT_ES_NICHT.md"}]}),
                  encoding="utf-8")
    g.RESTRISIKO_REL, g.OBJEKTKLASSEN_REL = "RESTRISIKO_PROBE.md", "PROBE_OBJEKTKLASSEN.json"
    with pytest.raises(SystemExit) as e:
        g.baue_v2(tmp_path, "2026-09-20T00:00:00Z")
    assert "nicht" in str(e.value) and "lesbar" in str(e.value)


def test_zwei_datensaetze_unter_derselben_kennung_fallen_auf():
    """Lens 2, target 2. The sum check stayed arithmetically true while the register carried two
    contradictory records under one identifier."""
    g = _erzeuger()
    doc = {"records": [{"id": "K1", "kind": None, "kind_state": "NOT MEASURED",
                        "kind_reason": "x", "severity": {"value": None, "state": "NOT MEASURED",
                                                         "reason": "x"},
                        "status": {"value": None, "state": "NOT MEASURED", "reason": "x"},
                        "evidence": []} for _ in range(2)],
           "inventory": {"source_documents": [], "identifiers_total": 2,
                         "identifiers_in_this_register": 2, "identifiers_without_evidence": [],
                         "coverage_gaps": [], "cross_count": {}},
           "assessment_cutoff": "2026-09-20", "generated_at": "2026-09-20T00:00:00Z",
           "signature": {"state": "UNSIGNED", "reason": "x", "consequence_for_the_reader": "x"}}
    fehler = g.pruefe_v2(doc, REPO)
    assert any("dieselbe Kennung" in f for f in fehler), fehler


def test_eine_zwischenueberschrift_verdeckt_die_offene_sektion_nicht():
    """Lens 3, target 2. A deeper heading between the finding and its `## Open` section made a real
    open finding fall to NOT MEASURED, and with it out of the known-issues view."""
    g = _erzeuger()
    text = ("## Open — the outer section\n\n### A detail heading\n\n"
            + ZUSAGE.format("GGG-HHHHHHH-01") + "\n")
    stelle = text.index("Register entry")
    assert g._status_aus_abschnitt(text, len(text[:stelle].encode())) == "open"


def test_ein_absatz_der_eine_FREMDE_kennung_nennt_belegt_nicht_diesen_fund(tmp_path):
    """Lens 1, target 1. The refusal counted promises, not mentions, so a paragraph discussing one
    finding by name while promising an entry for another absorbed the foreign text."""
    g = _erzeuger()
    quelle = tmp_path / "RESTRISIKO_PROBE.md"
    quelle.write_text(
        "Head.\n\nThis is related to FREMD-KENNUNG-01, discussed elsewhere. "
        + ZUSAGE.format("IIII-JJJJJJ-01") + "\n\n## FREMD-KENNUNG-01\n\nIts own section.\n",
        encoding="utf-8")
    ok = tmp_path / "PROBE_OBJEKTKLASSEN.json"
    ok.write_text(json.dumps(
        {"gemessen_an": {"datei": "RESTRISIKO_PROBE.md",
                         "sha256": __import__("hashlib").sha256(quelle.read_bytes()).hexdigest(),
                         "utc": "2026-09-20T00:00:00Z"},
         "eintraege": [{"kennung": "IIII-JJJJJJ-01", "klasse": "x", "zaehlt_als_fund": True},
                       {"kennung": "FREMD-KENNUNG-01", "klasse": "x", "zaehlt_als_fund": True}]}),
        encoding="utf-8")
    g.RESTRISIKO_REL, g.OBJEKTKLASSEN_REL = "RESTRISIKO_PROBE.md", "PROBE_OBJEKTKLASSEN.json"
    doc = g.baue_v2(tmp_path, "2026-09-20T00:00:00Z")
    assert "IIII-JJJJJJ-01" in doc["inventory"]["identifiers_without_evidence"]


def test_KONTROLLE_die_gesunde_zusage_geht_weiter_durch():
    """A guard that refuses everything measures nothing. The ordinary form must still be cut."""
    g = _erzeuger()
    text = "Head.\n\n" + ZUSAGE.format("KKK-LLLLLLL-01") + "\n\nTail.\n"
    t = g.schneide_beleg(text, "KKK-LLLLLLL-01")
    assert t is not None and t[2] == "prosa_zusage"
    von, bis, _ = t
    assert text.encode()[von:bis].decode().strip() == ZUSAGE.format("KKK-LLLLLLL-01")
