"""Die Bewertungsgrenze hat die FORM eines Datums — sie muss auch eines SEIN.

FUND, Codex 4000140173 (P2). `_bewertungsgrenze` schnitt mit `\\d{4}-\\d{2}-\\d{2}` das
Datumspraefix aus `gemessen_an.utc` und gab es weiter. Vier Ziffern, zwei, zwei — mehr prueft der
Ausdruck nicht. GEMESSEN am 13.09.2026 in einem Wegwerfklon: `gemessen_an.utc` auf
"2026-99-99T00:00:00Z" gesetzt und neu gebaut endet mit Rueckgabewert 0, meldet "gruen" und
schreibt `assessment_cutoff: "2026-99-99"`. `pruefe_v2` findet null Fehler, weil es dort nur
gegen eine nichtleere Zeichenkette prueft. Monat 99, Tag 99 — eine Bewertungsgrenze, die es im
Kalender nicht gibt, wurde als erfolgreich geprueft veroeffentlicht.

DIE KLASSE: ein Praefix-Schnitt mit Ziffernmaske wird fuer eine Datumspruefung gehalten. Die
Ziffernform stimmt bei jedem unmoeglichen Datum; sie stimmt sogar bei 2026-02-30, das nur ein
Kalender ausschliessen kann. Dieselbe Klasse steht ueberall dort, wo ein Wert per Praefix
uebernommen statt gedeutet wird.

BEIDE STELLEN, weil es zwei Wege in den Traeger gibt: der Erzeuger rechnet den Kalender nach, und
der Pruefer tut es AUCH — er urteilt ueber einen fertigen Traeger, der nicht aus diesem Erzeuger
stammen muss. Ein Riegel, der sich auf seinen Erzeuger verlaesst, prueft den einen Fall nicht, fuer
den er da ist.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]


def _gen():
    p = REPO / "scripts" / "gen_findings_register.py"
    if not p.is_file():
        pytest.skip(f"NICHT MESSBAR: {p} fehlt")
    s = importlib.util.spec_from_file_location("_gfr3", p)
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


UNMOEGLICH = ["2026-99-99T00:00:00Z", "2026-13-45T99:99:99Z", "2026-02-30T00:00:00Z",
              "2026-00-10T00:00:00Z", "2026-04-31T00:00:00Z"]
MOEGLICH = ["2026-09-13T06:00:00Z", "2024-02-29T00:00:00Z", "2026-09-13T0?:??Z"]


@pytest.mark.parametrize("utc", UNMOEGLICH)
def test_ein_unmoegliches_datum_ist_NICHT_MESSBAR_mit_grund(utc):
    """[ZAEHLT] Der Fund selbst: Ziffernform ja, Kalendertag nein."""
    g = _gen()
    r = g._bewertungsgrenze({"gemessen_an": {"utc": utc}})
    assert isinstance(r, dict), f"{utc} wurde als Datum durchgereicht: {r!r}"
    assert r.get("state") == "NOT MEASURED", r
    assert r.get("reason"), "ein Lueckenwort ohne Grund ist eine leere Marke"


@pytest.mark.parametrize("utc", MOEGLICH)
def test_ANTI_ein_echter_kalendertag_bleibt_ein_datum(utc):
    """[ZAEHLT] Gegenrichtung, und sie enthaelt den Schaltjahrfall und den Platzhalter.

    `2024-02-29` gibt es wirklich, `2026-09-13T0?:??Z` traegt eine unbekannte STUNDE bei bekanntem
    Tag — beides darf die Verschaerfung nicht wegwerfen.
    """
    g = _gen()
    r = g._bewertungsgrenze({"gemessen_an": {"utc": utc}})
    assert isinstance(r, str) and r == utc[:10], f"{utc} wurde verworfen: {r!r}"


def test_FANG_der_pruefer_meldet_eine_unmoegliche_grenze_im_fertigen_traeger():
    """[ZAEHLT] Die zweite Stelle: ein Traeger von aussen geht nicht durch den Erzeuger."""
    g = _gen()
    t = REPO / "audit_artifacts" / "600" / "findings_register_v2.json"
    if not t.is_file():
        pytest.skip(f"NICHT MESSBAR: {t} fehlt")
    doc = json.loads(t.read_text(encoding="utf-8"))
    assert g.pruefe_v2(doc, REPO) == [], "Vorbedingung: der echte Traeger ist fehlerfrei"

    import copy  # noqa: PLC0415
    k = copy.deepcopy(doc)
    k["assessment_cutoff"] = "2026-99-99"
    f = g.pruefe_v2(k, REPO)
    assert any("Kalender" in x for x in f), f"gemessen {f[:2]}"


def test_ANTI_der_pruefer_meldet_einen_ECHTEN_tag_nicht():
    """[ZAEHLT] Ein Riegel, der jede Grenze meldet, misst nichts."""
    g = _gen()
    t = REPO / "audit_artifacts" / "600" / "findings_register_v2.json"
    if not t.is_file():
        pytest.skip(f"NICHT MESSBAR: {t} fehlt")
    import copy  # noqa: PLC0415
    k = copy.deepcopy(json.loads(t.read_text(encoding="utf-8")))
    k["assessment_cutoff"] = "2024-02-29"
    assert not [x for x in g.pruefe_v2(k, REPO) if "Kalender" in x]
