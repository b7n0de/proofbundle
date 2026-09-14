"""NICHT ANWENDBAR war das falsche Wort — der Traeger ist unsigniert, nicht signaturfrei.

FUND, Codex 3999796576 (P2). Der Traeger fuehrte `signature.state: NOT APPLICABLE` mit der
Begruendung, er werde ueber den emit-und-assemble-Weg signiert. GEMESSEN: der `--v2`-Lauf schreibt
Traeger und Ansichten und endet mit 0, ohne `emit` oder `assemble` je zu rufen. Ein Leser konnte
den Aussteller damit nicht pruefen — und las im selben Feld, das sei bauartbedingt so.

DIE KLASSE: ein Lueckenwort, das die FALSCHE Luecke benennt. "Nicht anwendbar" heisst "hier ohne
Bedeutung"; richtig ist das Gegenteil, der Traeger IST fuer den Signierweg gebaut und nur noch
nicht durch ihn gegangen. Wer die Art der Luecke verwechselt, macht aus einer offenen Aufgabe eine
Eigenschaft.

SIGNIEREN BLEIBT EINE OWNER-TUER. Der private Schluesselteil liegt beim Owner; diese Sitzung kann
den Traeger nicht signieren und behauptet das auch nicht. Was in ihrer Macht steht, ist die
ehrliche Auskunft: was fehlt, was es braeuchte, und was das fuer den Leser bedeutet — und dass die
Auskunft den Leser ERREICHT, also in beiden Ansichten steht und nicht nur im Rohdokument.
"""
from __future__ import annotations

import copy
import importlib.util
import json
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
TRAEGER = REPO / "audit_artifacts" / "600" / "findings_register_v2.json"
MD = REPO / "audit_artifacts" / "600" / "views" / "uebersicht.md"
HTML = REPO / "audit_artifacts" / "600" / "views" / "uebersicht.html"


def _gen():
    p = REPO / "scripts" / "gen_findings_register.py"
    if not p.is_file():
        pytest.skip(f"NICHT MESSBAR: {p} fehlt")
    s = importlib.util.spec_from_file_location("_gfr8", p)
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


def _doc():
    if not TRAEGER.is_file():
        pytest.skip(f"NICHT MESSBAR: {TRAEGER} fehlt")
    return json.loads(TRAEGER.read_text(encoding="utf-8"))


def test_der_zustand_heisst_UNSIGNED_und_nicht_NICHT_ANWENDBAR():
    """[ZAEHLT] Der Fund selbst: das Lueckenwort benannte die falsche Luecke."""
    s = _doc().get("signature") or {}
    assert s.get("state") == "UNSIGNED", s
    assert s.get("reason") and s.get("what_would_change_it"), s
    assert s.get("consequence_for_the_reader"), (
        "die Einschraenkung ohne ihre Folge zu nennen heisst, sie nicht zu veroeffentlichen")


def test_beide_ansichten_sagen_es_dem_leser():
    """[ZAEHLT] Eine Auskunft, die nur im Rohdokument steht, erreicht den Leser nicht."""
    for p in (MD, HTML):
        if not p.is_file():
            pytest.skip(f"NICHT MESSBAR: {p} fehlt")
        t = p.read_text(encoding="utf-8")
        assert "UNSIGNED" in t, f"{p.name} nennt den Signaturzustand nicht"
        assert "unauthenticated" in t, f"{p.name} nennt die Folge fuer den Leser nicht"


def test_FANG_ein_zustand_OHNE_grund_wird_gemeldet():
    """[ZAEHLT] Gegenrichtung am Pruefer."""
    g, doc = _gen(), _doc()
    k = copy.deepcopy(doc)
    k["signature"] = {"state": "UNSIGNED"}
    f = g.pruefe_v2(k, REPO)
    assert any("leere Marke" in x for x in f), f[:2]


def test_FANG_UNSIGNED_ohne_die_folge_wird_gemeldet():
    """[ZAEHLT] Die Folge ist das, was den Leser schuetzt — sie darf nicht wegfallen."""
    g, doc = _gen(), _doc()
    k = copy.deepcopy(doc)
    k["signature"] = {"state": "UNSIGNED", "reason": "weil"}
    assert any("Folge fuer den Leser" in x for x in g.pruefe_v2(k, REPO))


def test_FANG_eine_behauptete_signatur_ohne_ihre_teile_wird_gemeldet():
    """[ZAEHLT] Eine Signatur, die man nicht pruefen kann, ist keine."""
    g, doc = _gen(), _doc()
    k = copy.deepcopy(doc)
    k["signature"] = {"sig_b64": "AAAA"}
    assert any("nicht pruefbar" in x for x in g.pruefe_v2(k, REPO))


def test_FANG_ein_traeger_ganz_OHNE_signaturblock_wird_gemeldet():
    """[ZAEHLT] Schweigen ueber die Echtheit ist die schlechteste Auskunft."""
    g, doc = _gen(), _doc()
    k = copy.deepcopy(doc)
    k.pop("signature", None)
    assert any("gar nichts" in x for x in g.pruefe_v2(k, REPO))


def test_ANTI_ein_SIGNIERTER_traeger_geht_durch():
    """[ZAEHLT] Die Verschaerfung darf den Weg, auf den sie zeigt, nicht verbauen."""
    g, doc = _gen(), _doc()
    k = copy.deepcopy(doc)
    # DIE ATTRAPPE MUSS DIE FORM HABEN, NACH DER GEFRAGT WIRD (gemessen 14.09.2026). Vorher
    # stand hier `"AAAA"` — base64 fuer DREI Bytes, waehrend ein Ed25519-Schluessel 32 hat. Das
    # ging durch, solange `pruefe_v2` nur die ANWESENHEIT der Felder pruefte. Genau diese
    # Anwesenheits-Pruefung ersetzt dieser Pull Request durch eine Eigenschafts-Pruefung
    # (`_signatur_lage`, Codex-Thread 'Presence-as-verification') — und damit ueberholte die
    # Aenderung die Vorrichtung, die sie begleiten soll. Der Riegel hat recht, die Attrappe war
    # falsch: sie mass, ob eine Attrappe durchgeht, die keine sein darf.
    # 32 bzw. 64 Nullbytes sind formal gueltig; verifiziert wird an DIESER Stelle nichts, nur die
    # Form geprueft — deshalb genuegt und gehoert hier die formal richtige Groesse.
    k["signature"] = {"alg": "ed25519",
                      "public_key_b64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                      "sig_b64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}
    assert not [x for x in g.pruefe_v2(k, REPO) if x.startswith("Signatur")]


def test_ANTI_der_echte_traeger_bleibt_fehlerfrei():
    """[GETRENNT] Ein Riegel, der alles meldet, misst nichts."""
    g, doc = _gen(), _doc()
    assert g.pruefe_v2(doc, REPO) == []
