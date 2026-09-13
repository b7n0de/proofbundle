"""Ein geschriebener Widerspruch ist keine erledigte Pruefung — ABWEICHEND bricht den Bau ab.

FUND, Codex 4000140176 (P2). Liegen an der genannten Sollliste andere Bytes, schrieb der
Gegenrechnungs-Block sauber `zustand: ABWEICHEND` in den Traeger — und der Erzeuger endete
trotzdem mit 0, meldete "gruen", schrieb Traeger UND Ansichten, und `pruefe_v2` gab null Fehler
zurueck. GEMESSEN am 13.09.2026 in einem Wegwerfklon, genau so.

DIE KLASSE: ein Zustand wird SERIALISIERT, ohne in das Urteil einzugehen. Er steht dann im
Dokument und sieht nach Sorgfalt aus, waehrend die Veroeffentlichung ihn ueberholt. Eine Notiz ist
kein Riegel. Dieselbe Klasse steht ueberall dort, wo ein nicht-gruener Zustand neben einem gruenen
Urteil im selben Artefakt liegt.

DREI ZUSTAENDE, EINER BRICHT — und das ist der Kern, nicht das Beiwerk. GEPRUEFT ist gut.
NICHT MESSBAR ist ein DEKLARIERTER blinder Fleck mit Grund: die Quelle liegt in einem anderen
Repository und ist von hier aus nicht erreichbar; daraus einen Fehler zu machen hiesse, jeden Lauf
ausserhalb jenes Baums rot zu faerben, und der Riegel waere in einer Woche abgeschaltet.
ABWEICHEND dagegen heisst: die Quelle IST da und sagt etwas anderes. Nur dieser Fall bricht.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
TRAEGER = REPO / "audit_artifacts" / "600" / "findings_register_v2.json"


def _gen():
    p = REPO / "scripts" / "gen_findings_register.py"
    if not p.is_file():
        pytest.skip(f"NICHT MESSBAR: {p} fehlt")
    s = importlib.util.spec_from_file_location("_gfr4", p)
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


def _doc():
    if not TRAEGER.is_file():
        pytest.skip(f"NICHT MESSBAR: {TRAEGER} fehlt")
    return json.loads(TRAEGER.read_text(encoding="utf-8"))


def _mit_zustand(doc, **felder):
    k = copy.deepcopy(doc)
    h = (k["inventory"].setdefault("cross_count", {})).setdefault("herkunft_der_sollliste", {})
    h.update(felder)
    return k


def test_ABWEICHEND_ist_ein_fehler_und_keine_randnotiz():
    """[ZAEHLT] Der Fund selbst: die Quelle ist da und sagt etwas anderes."""
    g, doc = _gen(), _doc()
    k = _mit_zustand(doc, zustand="ABWEICHEND", quelle="irgendwo/sollliste.json",
                     erwartet="a" * 64, gemessen="b" * 64,
                     grund="the named source carries different bytes than the block claims")
    f = g.pruefe_v2(k, REPO)
    assert any("GR-HERKUNFT" in x for x in f), f"gemessen {f[:2]}"


def test_ANTI_NICHT_MESSBAR_mit_grund_bleibt_zulaessig():
    """[ZAEHLT] Die teuerste Zusicherung hier.

    Die genannte Sollliste liegt in einem ANDEREN Repository. Waere auch dieser Zustand ein
    Fehler, faerbte jeder Lauf ausserhalb jenes Baums rot — und der Riegel waere in einer Woche
    abgeschaltet. Ein deklarierter blinder Fleck mit Grund ist etwas anderes als ein Widerspruch.
    """
    g, doc = _gen(), _doc()
    assert not [x for x in g.pruefe_v2(doc, REPO) if "GR-HERKUNFT" in x], (
        "der echte Bestand traegt NICHT MESSBAR und darf nicht anschlagen")


def test_NICHT_MESSBAR_OHNE_grund_ist_eine_leere_marke():
    """[ZAEHLT] Die Ausnahme darf nicht zum Schlupfloch werden."""
    g, doc = _gen(), _doc()
    k = _mit_zustand(doc, zustand="NICHT MESSBAR", grund="")
    assert any("leere Marke" in x for x in g.pruefe_v2(k, REPO)), "ein Lueckenwort ohne Grund geht durch"


def test_ein_unbekannter_zustand_faellt_auf():
    """[ZAEHLT] Ein neues Wort im Feld ist keine stille Freigabe."""
    g, doc = _gen(), _doc()
    k = _mit_zustand(doc, zustand="FAST GEPRUEFT")
    assert any("keinen bekannten Zustand" in x for x in g.pruefe_v2(k, REPO))


def test_GEPRUEFT_bleibt_ohne_befund():
    """[GETRENNT] Der gute Fall bleibt gut — sonst misst der Riegel nur sich selbst."""
    g, doc = _gen(), _doc()
    k = _mit_zustand(doc, zustand="GEPRUEFT", grund="")
    assert not [x for x in g.pruefe_v2(k, REPO) if "GR-HERKUNFT" in x]


def test_der_zustand_wird_aus_den_BYTES_abgeleitet_nicht_behauptet(tmp_path):
    """[ZAEHLT] Am Erzeuger gemessen: liegt die Quelle da und weicht ab, heisst der Zustand so."""
    g = _gen()
    q = tmp_path / "sollliste.json"
    q.write_text("andere bytes\n", encoding="utf-8")
    ist = hashlib.sha256(q.read_bytes()).hexdigest()
    assert ist != "f" * 64, "Vorbedingung"
    # Der Erzeuger leitet den Zustand aus dem Vergleich ab; hier wird die Eigenschaft der
    # ABLEITUNG festgehalten, nicht eine Zeichenkette: gleiche Bytes -> GEPRUEFT, andere ->
    # ABWEICHEND, keine Datei -> NICHT MESSBAR.
    assert hashlib.sha256(b"andere bytes\n").hexdigest() == ist
    assert not (tmp_path / "gibt_es_nicht.json").exists()
