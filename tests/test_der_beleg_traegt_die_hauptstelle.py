"""Ein Beleg traegt die HAUPTSTELLE seiner Kennung, nicht einen spaeteren Nachtrag.

HERKUNFT, Codex r3999820860 in PR 198. `schneide_beleg` suchte von der TIEFSTEN Ueberschriftenebene
aufwaerts (4, 3, 2) und nahm damit bei neun Kennungen einen spaeteren `### <K>, Nachtrag` statt der
Hauptstelle `## <K>`. GEMESSEN an der erzeugten Datei: `register_evidence/S35.md`, 3755 B und
bereits committet, trug AUSSCHLIESSLICH den ersten Nachtrag. Die Hauptstelle fehlte vollstaendig,
der zweite Nachtrag ebenso. Der Titel im Traeger war entsprechend der des Nachtrags.

WARUM ES DURCH ZWEI FRUEHERE HAERTUNGEN KAM, und das ist die eigentliche Lehre: der Selbsttest der
Funktion mass `keine Ueberlappung` — eine ECHTE Eigenschaft, aber nicht DIE, auf die es ankommt.
Ein Schnitt, der konsequent den falschen Abschnitt nimmt, ueberlappt mit nichts. Eine Eigenschaft,
die niemand prueft, haelt nur zufaellig.

DIE AUSNAHME IST GEMESSEN, NICHT VERMUTET. Ueber alle 132 Ueberschriften des Bestands: NEUN
Kennungen haben mehrere, und GENAU EINE davon (S102) eroeffnet eine SPANNE (`## S102 bis S114`).
Ein Spannenkopf gehoert mehreren Kennungen und darf nicht der Beleg EINER sein; dort ist die
tiefere Ebene richtig, und das war die dokumentierte Absicht der Vorgaengerfassung.

EHRLICHE GRENZE: die Spannenform ist eng gefasst, `bis` oder `to` plus Kennung. Eine erste,
weitere Fassung nahm auch einen Gedankenstrich vor einer Kennung und hielt damit S21, S24, S49 und
Z5 faelschlich fuer Sammelkoepfe. Eine Spanne in einer dritten Schreibweise faellt durch.
"""
from __future__ import annotations

import importlib.util
import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
QUELLE = REPO / "RESTRISIKO_600.md"

#: Die neun Kennungen mit mehreren Ueberschriften, gemessen am Bestand, und die Ebene, die GILT.
#: Acht nehmen die Hauptstelle; S102 ist die gemessene Ausnahme, seine flache Ebene ist ein
#: Spannenkopf. Fester Sollwert, nicht aus dem Lauf abgeleitet.
SOLL_EBENE = {"S22": 2, "S30": 2, "S34": 2, "S35": 2, "S36": 2,
              "S50": 2, "S61": 2, "S66": 2, "S102": 3}


def _gen():
    p = REPO / "scripts" / "gen_findings_register.py"
    if not p.is_file():
        pytest.skip(f"NICHT MESSBAR: {p} fehlt")
    s = importlib.util.spec_from_file_location("_gfr", p)
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


def _erste_zeile(text: str, kennung: str) -> str:
    g = _gen()
    t = g.schneide_beleg(text, kennung)
    assert t is not None, f"{kennung}: keine Fundstelle"
    roh = QUELLE.read_bytes()
    return roh[t[0]:t[1]].decode("utf-8", errors="replace").splitlines()[0]


def test_jede_mehrfach_kennung_traegt_die_richtige_ebene():
    """[ZAEHLT] Die Eigenschaft, die der alte Selbsttest NICHT mass."""
    if not QUELLE.is_file():
        pytest.skip(f"NICHT MESSBAR: {QUELLE} fehlt")
    text = QUELLE.read_text(encoding="utf-8")
    falsch = []
    for k, soll in SOLL_EBENE.items():
        z = _erste_zeile(text, k)
        ist = len(z) - len(z.lstrip("#"))
        if ist != soll:
            falsch.append(f"{k}: Ebene {ist}, erwartet {soll} — {z[:70]!r}")
    assert not falsch, "\n".join(falsch)


def test_S35_traegt_die_hauptstelle_und_nicht_den_nachtrag():
    """[ZAEHLT] Die Instanz des Fundes, positiv formuliert."""
    if not QUELLE.is_file():
        pytest.skip(f"NICHT MESSBAR: {QUELLE} fehlt")
    z = _erste_zeile(QUELLE.read_text(encoding="utf-8"), "S35")
    assert z.startswith("## S35"), f"S35 beginnt bei {z[:70]!r}"
    assert "Nachtrag" not in z, "der Beleg beginnt weiterhin an einem Nachtrag"


def test_S102_behaelt_die_tiefere_ebene_weil_die_flache_eine_spanne_ist():
    """[ZAEHLT] Anti-Paritaet: die Ausnahme bleibt, sonst traegt EIN Beleg dreizehn Kennungen."""
    if not QUELLE.is_file():
        pytest.skip(f"NICHT MESSBAR: {QUELLE} fehlt")
    text = QUELLE.read_text(encoding="utf-8")
    z = _erste_zeile(text, "S102")
    assert z.startswith("### S102"), f"S102 beginnt bei {z[:70]!r}"
    assert re.search(r"^## S102 bis S114", text, re.M), (
        "der Spannenkopf steht nicht mehr so in der Quelle — dann ist diese Ausnahme neu zu messen")


def test_kein_beleg_ueberlappt_einen_anderen():
    """[ZAEHLT] Die alte Eigenschaft bleibt erhalten, sie war richtig, nur nicht genug."""
    if not QUELLE.is_file():
        pytest.skip(f"NICHT MESSBAR: {QUELLE} fehlt")
    import json  # noqa: PLC0415
    ok_datei = REPO / "RESTRISIKO_600_OBJEKTKLASSEN.json"
    if not ok_datei.is_file():
        pytest.skip(f"NICHT MESSBAR: {ok_datei} fehlt")
    g = _gen()
    text = QUELLE.read_text(encoding="utf-8")
    ok = json.loads(ok_datei.read_text(encoding="utf-8"))
    spannen = []
    for e in ok["eintraege"]:
        t = g.schneide_beleg(text, e["kennung"])
        if t:
            spannen.append((t[0], t[1], e["kennung"]))
    spannen.sort()
    ueber = [(spannen[i][2], spannen[i + 1][2])
             for i in range(len(spannen) - 1) if spannen[i][1] > spannen[i + 1][0]]
    assert not ueber, f"{len(ueber)} Ueberlappung(en): {ueber[:5]}"
    assert len(spannen) >= 100, (
        f"nur {len(spannen)} Belege gemessen — eine leere Flaeche ist kein Freispruch")


def test_die_spannenform_ist_ENG_und_faengt_keinen_gedankenstrich():
    """[ZAEHLT] Anti-Paritaet gegen meine eigene erste, zu weite Fassung.

    Sie nahm auch `— C6.3 verlangt ...` als Spanne und haette S21, S24, S49 und Z5 faelschlich zu
    Sammelkoepfen erklaert. Gemessen am Bestand: genau EINE Ueberschrift eroeffnet eine Spanne.
    """
    if not QUELLE.is_file():
        pytest.skip(f"NICHT MESSBAR: {QUELLE} fehlt")
    text = QUELLE.read_text(encoding="utf-8")
    kopf = re.compile(r"^(#{2,4}) ([A-Z]\d+)(?![0-9A-Za-z])([^\n]*)$", re.M)
    spannen = [m.group(2) for m in kopf.finditer(text)
               if re.match(r"^\s*(?:bis|to)\s+[A-Z]\d+\b", m.group(3))]
    assert spannen == ["S102"], f"erwartet genau S102 als Spannenkopf, gemessen {spannen}"
