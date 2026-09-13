"""Ein Beleg, dessen Digest nicht der seiner Datei ist, ist von aussen nicht nachrechenbar.

GEFUNDEN beim Nachmessen von Feld 5 des Zitatpakets G1 (Auftrag `20260912T1242Z`):
der Traeger nennt in EINEM Beleg zwei Dinge nebeneinander — `path` und `sha256` — und
sie bezeichnen verschiedene Objekte. `sha256` ist der Digest des AUSSCHNITTS aus der
Quelle; die Datei unter `path` traegt zusaetzlich einen vierzeiligen Herkunftskopf.
Gemessen 13.09.2026 ueber alle 145 Belege: **0** stimmen gegen die Datei, 145 gegen den
Ausschnitt. Wer `sha256sum <path>` fährt, bekommt jedes Mal etwas anderes als das Feld.

Das ist genau die Form, gegen die der Owner-Auftrag 1242Z schreibt: „Der Digest muss nach
der Veroeffentlichung mit 6.1 von jedem nachrechenbar sein, ohne dass wir ihm erklaeren
muessen, was wir gehasht haben."

DIE ZWEITE HAELFTE derselben Klasse sitzt im Pruefer: `pruefe_v2` vergleicht den Digest
gegen `quelle[von:bis]` und OEFFNET DIE DATEI NIE, die es unter `path` nennt. Ein
geloeschter oder veraenderter Beleg blieb gruen. Ein Werkzeug sagt mehr, als es prueft.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]

# WARUM NICHT `sys.path.insert` PLUS `import gen_findings_register`.
#
# `scripts/gen_findings_register.py` wird ABSICHTLICH nicht ausgeliefert (MANIFEST.in, Owner-Auflage
# zu OA-8b1a31cc4f: es liest einen privaten Schluessel aus Umgebung oder Datei). Im entpackten sdist
# fehlt die Datei also, und das ist richtig so.
#
# Die blanke Form hat daraus einen SAMMELABBRUCH gemacht, nicht ein ehrliches SKIP: gemessen am
# gebauten Paket dieses Kopfes brach `pytest tests/` mit `ModuleNotFoundError: No module named
# 'gen_findings_register'` und `exit code 2` ab, und mit ihm ALLE uebrigen Tests des Pakets
# (`published-artifact-gate / hermetic-cleanroom`, PR 198). Der Riegel in `conftest.py` konnte nicht
# greifen: ein blanker Modulname traegt kein Verzeichnis, und ohne Verzeichnis ist "gehoert zu diesem
# Projekt" nicht entscheidbar — er bleibt dann fail-closed laut, was fuer `import numpy` genau
# richtig ist. Die Information, die hier fehlte, steht nicht im Fehler, sondern in DIESER Datei.
#
# Die Pfadform sagt sie aus: sie nennt die Datei, das Fehlen wird zu `FileNotFoundError` mit vollem
# Pfad, und `conftest` kann den Fall als "nicht ausgeliefert" erkennen und ehrlich ueberspringen.
# Dieselbe Form fuehrt `tests/test_budget_axis_measurement.py` seit dem 08.09.2026 aus demselben
# Grund. Der Klassenriegel dazu ist `tests/test_kein_blanker_import_eines_nicht_ausgelieferten.py`.
_spec = importlib.util.spec_from_file_location(
    "_gen_findings_register", REPO / "scripts" / "gen_findings_register.py")
gen = importlib.util.module_from_spec(_spec)
sys.modules["_gen_findings_register"] = gen
_spec.loader.exec_module(gen)

TRAEGER = REPO / "audit_artifacts/600/findings_register_v2.json"


def _doc():
    if not TRAEGER.is_file():
        pytest.skip(f"kein v2-Traeger unter {TRAEGER} — nichts zu messen (das ist keine Freigabe)")
    return json.loads(TRAEGER.read_text(encoding="utf-8"))


def test_belegdigest_ist_der_digest_der_datei():
    """[ZAEHLT] `sha256sum <path>` muss das Feld `sha256` ergeben. Ohne Erklaerung."""
    doc = _doc()
    abweichend = []
    for r in doc["records"]:
        for b in r["evidence"]:
            p = REPO / b["path"]
            if not p.is_file():
                abweichend.append(f"{r['id']}: Datei fehlt ({b['path']})")
                continue
            ist = hashlib.sha256(p.read_bytes()).hexdigest()
            if ist != b["sha256"]:
                abweichend.append(f"{r['id']}: Feld {b['sha256'][:12]}, Datei {ist[:12]}")
    assert not abweichend, (
        f"{len(abweichend)} von {len(doc['records'])} Belegen tragen einen Digest, den die "
        f"genannte Datei nicht hat: " + "; ".join(abweichend[:5])
    )


def test_belegdatei_traegt_genau_die_quellbytes():
    """[ZAEHLT] Zweite Ableitung derselben Eigenschaft, ueber die Bytes statt ueber den Digest."""
    doc = _doc()
    quelle = (REPO / doc["records"][0]["evidence"][0]["source_path"]).read_bytes()
    abweichend = []
    for r in doc["records"]:
        for b in r["evidence"]:
            p = REPO / b["path"]
            if not p.is_file():
                abweichend.append(f"{r['id']}: Datei fehlt")
                continue
            von, bis = b["byte_range"]
            if p.read_bytes() != quelle[von:bis]:
                abweichend.append(
                    f"{r['id']}: Datei {len(p.read_bytes())} B, Ausschnitt {bis - von} B")
    assert not abweichend, (
        f"{len(abweichend)} Belegdateien tragen nicht genau die Bytes ihres Bereichs: "
        + "; ".join(abweichend[:5]))


# ── META: prueft der Pruefer, was er zu pruefen behauptet ──────────────────────────────

def _gestellte_lage(tmp_path):
    """Ein winziger, vollstaendiger Baum — Quelle, Objektklassen, Traeger, Belege."""
    quelle = tmp_path / "RESTRISIKO_600.md"
    quelle.write_bytes(b"## S1 Titel\n\nText eins.\n\n## S2 Titel\n\nText zwei.\n")
    (tmp_path / "RESTRISIKO_600_OBJEKTKLASSEN.json").write_text(json.dumps({
        "eintraege": [
            {"kennung": "S1", "klasse": "fund", "warum_diese_klasse": "gestellt",
             "zaehlt_als_fund": True},
            {"kennung": "S2", "klasse": "fund", "warum_diese_klasse": "gestellt",
             "zaehlt_als_fund": True},
        ],
        "luecken_in_der_nummernfolge": {},
    }), encoding="utf-8")
    return tmp_path


def test_pruefer_faellt_wenn_die_belegdatei_veraendert_wird(tmp_path):
    """[ZAEHLT] Ein Pruefer, der eine Datei NENNT und nie oeffnet, prueft sie nicht."""
    repo = _gestellte_lage(tmp_path)
    doc = gen.schreibe_v2(repo, "2026-09-13T00:00:00Z")
    assert not gen.pruefe_belege_auf_platte(doc, repo), "der Baum muss zuerst gruen sein"

    ziel = repo / doc["records"][0]["evidence"][0]["path"]
    ziel.write_bytes(ziel.read_bytes() + b"\nEINGESCHMUGGELT\n")
    fehler = gen.pruefe_belege_auf_platte(doc, repo)
    assert fehler, "ein veraenderter Beleg muss den Pruefer rot machen"
    assert any("S1" in f for f in fehler), fehler


def test_pruefer_faellt_wenn_die_belegdatei_fehlt(tmp_path):
    """[ZAEHLT] Ein fehlender Beleg ist kein Beleg."""
    repo = _gestellte_lage(tmp_path)
    doc = gen.schreibe_v2(repo, "2026-09-13T00:00:00Z")
    assert not gen.pruefe_belege_auf_platte(doc, repo), "der Baum muss zuerst gruen sein"

    (repo / doc["records"][1]["evidence"][0]["path"]).unlink()
    fehler = gen.pruefe_belege_auf_platte(doc, repo)
    assert fehler, "ein fehlender Beleg muss den Pruefer rot machen"
    assert any("S2" in f for f in fehler), fehler


# ── KONTROLLE: gruen VOR und NACH dem Fix. Ohne sie misst die Datei nichts ─────────────

def test_gegenprobe_der_digest_haelt_gegen_die_quelle():
    """[GEGEN] Bindung an die Quelle. Haelt in beiden Zustaenden — sonst waere jede Zeile
    dieser Datei nur ein immer-rotes Orakel."""
    doc = _doc()
    quelle = (REPO / doc["records"][0]["evidence"][0]["source_path"]).read_bytes()
    assert hashlib.sha256(quelle).hexdigest() == doc["records"][0]["evidence"][0]["source_sha256"]
    for r in doc["records"]:
        for b in r["evidence"]:
            von, bis = b["byte_range"]
            assert hashlib.sha256(quelle[von:bis]).hexdigest(), r["id"]


def test_pruefer_weist_einen_unmoeglichen_bytebereich_ab(tmp_path):
    """[ZAEHLT] Python schneidet klaglos: `roh[500:400]` und `roh[10**7:10**7+1]` ergeben
    beide `b''`, dessen sha256 die feste Konstante e3b0c442… ist. Ein Beleg mit NULL
    echten Bytes bestand den Pruefer. Gefunden von der Gegenlese-Linse 12.09.2026,
    nachgemessen am echten Korpus (dort kommt er nicht vor — die FAEHIGKEIT, nicht das
    Eintreten)."""
    quelle = tmp_path / "RESTRISIKO_600.md"
    quelle.write_bytes(b"## S1 Titel\n\nText eins.\n")
    qd = hashlib.sha256(quelle.read_bytes()).hexdigest()
    leer = hashlib.sha256(b"").hexdigest()

    def _doc_mit(bereich):
        return {"records": [{"id": "GESTELLT", "kind": None, "kind_state": "NOT MEASURED",
                             "kind_reason": "gestellt",
                             "severity": {"value": None, "state": "NOT MEASURED",
                                          "reason": "gestellt"},
                             "evidence": [{"path": "egal.md", "sha256": leer,
                                           "role": "historical_record",
                                           "source_path": "RESTRISIKO_600.md",
                                           "source_sha256": qd, "byte_range": bereich,
                                           "fundart": "ueberschrift"}]}],
                "inventory": {"identifiers_in_this_register": 1,
                              "identifiers_without_evidence": [], "identifiers_total": 1,
                              "coverage_gaps": []}}

    for bereich in ([500, 400], [10_000_000, 10_000_001], [7, 7], [-5, 3]):
        fehler = gen.pruefe_v2(_doc_mit(bereich), tmp_path)
        assert any("Bytebereich" in f for f in fehler), (bereich, fehler)

    # KONTROLLE: ein gesunder Bereich geht durch — sonst pruefte die Zeile oben nichts.
    gut = _doc_mit([0, 11])
    gut["records"][0]["evidence"][0]["sha256"] = hashlib.sha256(
        quelle.read_bytes()[0:11]).hexdigest()
    assert not [f for f in gen.pruefe_v2(gut, tmp_path) if "Bytebereich" in f]
