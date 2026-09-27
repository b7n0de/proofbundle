"""Die Quelle nennt Zustaende in ZWEI Gestalten — gelesen wurde nur eine.

FUND, Codex 4000140162 (P2). `RESTRISIKO_600.md` fuehrt seine Funde als Tabellenzeile MIT
Zustandsspalte und als Ueberschrift, deren Text den Zustand nach einem Gedankenstrich nennt
("… — open, reproduced …", "… — CLOSED, and …"). Gelesen wurde nur die Tabelle. GEMESSEN ueber die
Quelle: 50 Ueberschriften tragen eine Kennung, 12 nennen darin `open`, 5 `closed`, 33 nennen
nichts. Die mit Zustand kamen als NOT MEASURED heraus — und `known_issues.md` liess sie weg. S5
steht in der Quelle ausdruecklich offen und fehlte in der Ansicht der offenen Punkte.

DIE KLASSE: ein Leser, der EINE von zwei Gestalten kennt, prueft die Haelfte — dieselbe Klasse wie
r3999820857, wo ein Riegel Ueberschriften las und Tabellenzeilen nicht. Diesmal andersherum. Eine
Quelle, die zwei Gestalten fuehrt, braucht einen Leser, der beide kennt.

EHRLICHE GRENZE, GEMESSEN STATT GESCHAETZT: erkannt wird das Zustandswort NACH einem
Gedankenstrich, also die Hausform. Das trifft 15 der 17. Zwei (S1, S11) tragen "CLOSED" mitten im
Satz und bleiben NOT MEASURED. Ein Muster, das jedes `open` irgendwo im Titel als Zustand liest,
macht aus "opened the file" einen Fund; eine benannte Luecke ist besser als ein geratener Zustand.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
QUELLE = REPO / "RESTRISIKO_600.md"
TRAEGER = REPO / "audit_artifacts" / "600" / "findings_register_v2.json"


def _gen():
    p = REPO / "scripts" / "gen_findings_register.py"
    if not p.is_file():
        pytest.skip(f"NICHT MESSBAR: {p} fehlt")
    s = importlib.util.spec_from_file_location("_gfr6", p)
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


def test_die_ueberschriftsform_wird_erkannt():
    """[ZAEHLT] Der Fund selbst, an den Formen der echten Quelle."""
    g = _gen()
    faelle = {
        "## S5 · The two riegel are bound one at a time — open, named by the lens": "open",
        "### S2 · The package-guard skip assertion — CLOSED, and the reason was named": "closed",
        "#### R1 · A shipped artefact contradicts the code — open, reproduced": "open",
    }
    for zeile, erwartet in faelle.items():
        kennung = zeile.split("·")[0].split()[-1]
        assert g._status_aus_ueberschrift(zeile, kennung) == erwartet, zeile


def test_ANTI_eine_ueberschrift_OHNE_zustandswort_bleibt_stumm():
    """[ZAEHLT] Gegenrichtung: kein geratener Zustand."""
    g = _gen()
    for zeile in ("## S9 · A guard that reads one of two shapes checks half",
                  "## S8 · The witness cannot see the lenses of a foreign round"):
        kennung = zeile.split("·")[0].split()[-1]
        assert g._status_aus_ueberschrift(zeile, kennung) is None, zeile


def test_ANTI_ein_open_ohne_gedankenstrich_gilt_NICHT_als_zustand():
    """[ZAEHLT] Die teuerste Zusicherung: die Fachsprache darf nicht zum Zustand werden."""
    g = _gen()
    zeile = "## S12 · The verifier opened the file and left it open for the next reader"
    assert g._status_aus_ueberschrift(zeile, "S12") is None, (
        "ein `open` in der Prosa wurde als Zustand gelesen — dann erfindet der Leser Funde")


def test_die_ueberschrift_zaehlt_erst_NACH_der_tabelle():
    """[ZAEHLT] Zwei Quellen, eine Rangfolge — sonst entscheidet der Zufall."""
    g = _gen()
    r = g._status("X1", aus_tabelle="closed (fixed in 6.0.0)", aus_ueberschrift="open")
    assert r["value"] == "closed" and "state column" in r["source"], r


#: Which sources `_status` asks, PER FIND FORM. The table is read only from a table row and the
#: section heading only from a prose promise, so a reason that names them everywhere names a step
#: that never ran.
_GEFRAGT = {
    None: ["the producer list", "a heading that names its state after a dash"],
    "ueberschrift": ["the producer list", "a heading that names its state after a dash"],
    "tabelle_spalte1": ["the producer list", "a table with a state column",
                        "a heading that names its state after a dash"],
    "prosa_zusage": ["the producer list", "a heading that names its state after a dash",
                     "a section heading in the house form `## Open`"],
}


def test_ohne_beide_bleibt_es_NICHT_MESSBAR_und_nennt_GENAU_die_gefragten_wege():
    """[ZAEHLT] The reason names exactly the sources that were asked — for the form that asked.

    THE FIRST VERSION OF THIS CASE PINNED THE DEFECT. It demanded all three ways in every reason,
    and the producer duly listed all three regardless of find form. Measured on line 600: 120 of
    145 records carry the heading form, where no table is ever consulted, so the sentence reported
    an unperformed step as performed in 120 places at once. That is the class this whole file is
    written against, one level up — a reader who checks where the tool looked was told something
    that was not true.

    Asserted against the STRUCTURED field `sources_asked` rather than against the prose, and the
    prose is then held against that field. A contract that reads a sentence measures its wording.
    """
    g = _gen()
    for fundart, erwartet in _GEFRAGT.items():
        r = g._status("GIBTESNICHT", fundart=fundart)
        assert r["state"] == "NOT MEASURED", (fundart, r)
        assert r["sources_asked"] == erwartet, (fundart, r.get("sources_asked"))
        for quelle in erwartet:
            assert quelle in r["reason"], (fundart, quelle, r["reason"])


def test_ANTI_der_grund_nennt_KEINEN_weg_der_nicht_gefragt_wurde():
    """[ZAEHLT] The direction that matters, and the one the old case could not see.

    A reason may be short; it may not be wrong. For the heading form the table is never opened, so
    naming it would be the defect — and for anything but a prose promise the same holds for the
    section heading.
    """
    g = _gen()
    r = g._status("GIBTESNICHT", fundart="ueberschrift")
    assert "a table with a state column" not in r["reason"], r
    assert "## Open" not in r["reason"], r
    t = g._status("GIBTESNICHT", fundart="tabelle_spalte1")
    assert "## Open" not in t["reason"], t


def test_S5_steht_im_traeger_offen_und_in_der_ansicht():
    """[ZAEHLT] Die Wirkung am Bestand, nicht nur an der Funktion."""
    if not TRAEGER.is_file():
        pytest.skip(f"NICHT MESSBAR: {TRAEGER} fehlt")
    d = json.loads(TRAEGER.read_text(encoding="utf-8"))
    s5 = [r for r in d["records"] if r["id"] == "S5"]
    assert s5, "S5 fehlt im Traeger"
    assert s5[0]["status"]["value"] == "open", s5[0]["status"]
    ansicht = REPO / "audit_artifacts" / "600" / "views" / "known_issues.md"
    assert "S5" in ansicht.read_text(encoding="utf-8"), "S5 fehlt in der Ansicht der offenen Punkte"


def test_die_gemessene_grenze_steht_im_text_und_stimmt():
    """[ZAEHLT] Die Grenze wird nachgerechnet, nicht behauptet.

    Faellt dieser Fall, hat sich die Quelle geaendert — dann gehoert die Zahl im Kopftext
    nachgezogen, nicht der Test entfernt.
    """
    if not QUELLE.is_file():
        pytest.skip(f"NICHT MESSBAR: {QUELLE} fehlt")
    t = QUELLE.read_text(encoding="utf-8")
    kopf = re.compile(r"^#{2,4}\s+([A-Z]\d+)\s*·\s*(.+)$", re.M)
    eng = re.compile(r"[—–-]{1,2}\s*\**(open|closed)\b", re.I)
    weit = re.compile(r"\b(open|closed)\b", re.I)
    mit_eng = sum(1 for m in kopf.finditer(t) if eng.search(m.group(2)))
    mit_weit = sum(1 for m in kopf.finditer(t) if weit.search(m.group(2)))
    assert mit_eng == 15 and mit_weit == 17, (
        f"die Quelle traegt jetzt {mit_eng} Hausform- und {mit_weit} Wortvorkommen; der Kopftext "
        f"dieser Datei nennt 15 von 17 und ist damit nicht mehr wahr")
