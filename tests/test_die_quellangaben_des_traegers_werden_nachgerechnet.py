"""Ein Digest, den der Traeger nennt, wird nachgerechnet — oder als ungeprueft ausgewiesen.

ZWEI FUNDE DER FREMDFAMILIE, dieselbe Klasse an zwei Orten.

r3999918378 (P1). `inventory.source_documents[]` fuehrt je Quelle einen sha256. Geprueft wurde er
nie. Die BELEGeintraege tragen einen zweiten Digest ueber dieselben Dateien, und DER wurde geprueft
— zwei Angaben ueber dieselbe Sache, von denen nur eine geprueft wird, driften. Gemessen am Kopf
d6b24ef war genau das eingetreten: der Traeger nannte fuer RESTRISIKO_600_OBJEKTKLASSEN.json einen
Digest, den die Datei nicht mehr trug, und `pruefe_v2` meldete null Fehler.

r3999944593 (P2). Der Gegenrechnungs-Block nennt `quelle` und `sha256_der_sollliste` nebeneinander,
und beides las sich wie eine gepruefte Herkunft. Gemessen oeffnete die Funktion keine Datei. Wer die
eingebettete Liste aendert und den Digest stehen laesst, bekommt eine gruene Herkunftsaussage ueber
Bytes, die niemand gesehen hat.

DREI ZUSTAENDE, NICHT ZWEI, und das ist hier der Kern. Die genannte Sollliste liegt in einem ANDEREN
Repository und ist von hier aus nicht erreichbar. Eine Pruefung, die nicht stattfinden kann, darf
nicht wie eine bestandene aussehen: GEPRUEFT, ABWEICHEND oder NICHT MESSBAR mit Grund.
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
    s = importlib.util.spec_from_file_location("_gfr2", p)
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


def _doc():
    if not TRAEGER.is_file():
        pytest.skip(f"NICHT MESSBAR: {TRAEGER} fehlt")
    return json.loads(TRAEGER.read_text(encoding="utf-8"))


def test_die_quellangaben_des_inventars_stimmen():
    """[ZAEHLT] Die Instanz des P1, am Bestand."""
    doc = _doc()
    falsch = []
    for q in doc["inventory"].get("source_documents") or []:
        p = REPO / q["path"]
        if not p.is_file():
            falsch.append(f"{q['path']}: fehlt")
            continue
        ist = hashlib.sha256(p.read_bytes()).hexdigest()
        if ist != q["sha256"]:
            falsch.append(f"{q['path']}: Datei {ist[:12]}, Traeger {q['sha256'][:12]}")
    assert not falsch, falsch


def test_FANG_ein_verdrehter_quell_digest_wird_gemeldet():
    """[ZAEHLT] Gegenrichtung rot: genau die Lage, die am Kopf d6b24ef gruen war."""
    g, doc = _gen(), _doc()
    k = copy.deepcopy(doc)
    assert k["inventory"]["source_documents"], "kein Quelleintrag zu verdrehen"
    k["inventory"]["source_documents"][-1]["sha256"] = "0" * 64
    f = g.pruefe_v2(k, REPO)
    assert any("Inventar" in x for x in f), f"erwartet ein Inventar-Fehler, gemessen {f[:2]}"


def test_FANG_eine_fehlende_quelle_wird_gemeldet():
    """[ZAEHLT] Eine Datei, die es nicht gibt, ist kein bestandener Digest."""
    g, doc = _gen(), _doc()
    k = copy.deepcopy(doc)
    k["inventory"]["source_documents"][-1]["path"] = "gibt_es_hier_nicht.json"
    f = g.pruefe_v2(k, REPO)
    assert any("Quelle fehlt" in x for x in f), f"gemessen {f[:2]}"


def test_ANTI_der_unveraenderte_traeger_bleibt_fehlerfrei():
    """[ZAEHLT] Der Riegel darf nicht alles melden."""
    g, doc = _gen(), _doc()
    assert g.pruefe_v2(doc, REPO) == []


def test_die_herkunft_der_sollliste_traegt_einen_ZUSTAND():
    """[ZAEHLT] Die Instanz des P2: kein durchgereichter Digest ohne Urteil."""
    cc = _doc()["inventory"].get("cross_count") or {}
    h = cc.get("herkunft_der_sollliste")
    assert h, "der Block nennt keine Herkunft der Sollliste"
    assert h.get("zustand") in ("GEPRUEFT", "ABWEICHEND", "NICHT MESSBAR"), h
    if h["zustand"] != "GEPRUEFT":
        assert h.get("grund"), "ein nicht gepruefter Zustand ohne Grund ist eine leere Marke"


def test_der_heutige_zustand_ist_NICHT_MESSBAR_und_sagt_warum():
    """[ZAEHLT] Ehrlich statt gruen: die genannte Quelle liegt in einem anderen Repository.

    Faellt dieser Fall, ist die Quelle erreichbar geworden — dann gehoert sie GEPRUEFT, und diese
    Zusicherung ist nachzuziehen statt zu loeschen.
    """
    h = (_doc()["inventory"].get("cross_count") or {}).get("herkunft_der_sollliste") or {}
    assert h.get("zustand") == "NICHT MESSBAR", h
    assert "nicht erreichbar" in (h.get("grund") or ""), h


# ── DIE ANWESENHEIT DER INNEREN HERKUNFT, als eigene Zusicherung ──────────────────────────

def test_der_echte_bestand_FUEHRT_eine_innere_herkunftsangabe():
    """[ZAEHLT] Sie darf nicht still verschwinden, nur weil ihr Fehlen kein Widerspruch ist.

    `pruefe_v2` fragt die WIDERSPRUCHSFREIHEIT einer vorhandenen Angabe; fehlt sie ganz, gibt es
    nichts zu widerlegen, und ein minimaler Wegwerf-Baum darf sie deshalb weglassen. Damit sie im
    echten Bestand nicht unbemerkt herausfaellt, steht ihre ANWESENHEIT hier.
    """
    k = REPO / "RESTRISIKO_600_OBJEKTKLASSEN.json"
    if not k.is_file():
        pytest.skip(f"NICHT MESSBAR: {k} fehlt")
    g = json.loads(k.read_text(encoding="utf-8")).get("gemessen_an")
    assert isinstance(g, dict), "die Objektklassen-Datei fuehrt keinen Block `gemessen_an`"
    assert g.get("datei") and g.get("sha256"), f"halbe Herkunftsangabe: {g!r}"
    p = REPO / g["datei"]
    assert p.is_file(), f"`gemessen_an.datei` zeigt ins Leere: {g['datei']!r}"
    assert hashlib.sha256(p.read_bytes()).hexdigest() == g["sha256"], (
        "die Objektklassen-Datei widerspricht sich ueber ihre eigene Quelle")


def test_FANG_eine_HALBE_herkunftsangabe_wird_gemeldet(tmp_path):
    """[ZAEHLT] Gegenrichtung: vorhanden aber unvollstaendig ist NICHT dasselbe wie abwesend."""
    g, doc = _gen(), _doc()
    import copy  # noqa: PLC0415
    k = REPO / "RESTRISIKO_600_OBJEKTKLASSEN.json"
    sicher = k.read_bytes()
    try:
        d = json.loads(sicher.decode("utf-8"))
        d["gemessen_an"] = {"datei": "RESTRISIKO_600.md"}          # Digest fehlt
        k.write_text(json.dumps(d, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        f = g.pruefe_v2(copy.deepcopy(doc), REPO)
        assert any("halbe Angabe" in x for x in f), f"gemessen {f[:2]}"
    finally:
        k.write_bytes(sicher)
    assert k.read_bytes() == sicher, "die Datei wurde nicht byte-gleich wiederhergestellt"
