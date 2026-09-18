"""CAP-1 Teil B, Block 3: die fuenfzehn Autor-Vektoren als Faelle des Konformitaetslaeufers
(Art `cap1_document`, eine Achse `cap1Rules`).

Was hier gemessen wird: jeder Fall laeuft gruen durch den ECHTEN Pruefer des Laeufers; die Achse ist
eine MENGE (ein Gegenbeweis, der aus dem falschen Grund faellt, faellt hier); die Deklaration ist
fail-closed (ohne Achse kein Pass); die erzeugten Bytes sind die committeten Bytes (Generator
deterministisch, Korpus nicht von Hand); und die Korpus-Integritaet (Schema, Manifest) haelt.
"""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
KORPUS = REPO / "conformance" / "cap1"
VEKTOREN = KORPUS / "vectors"


def _laeufer():
    if "_rc_fuer_test" in sys.modules:
        return sys.modules["_rc_fuer_test"]
    pfad = REPO / "conformance/run_conformance.py"
    spec = importlib.util.spec_from_file_location("_rc_fuer_test", pfad)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_rc_fuer_test"] = mod
    spec.loader.exec_module(mod)
    return mod


def _faelle() -> list[Path]:
    return sorted(d for d in KORPUS.iterdir() if d.is_dir() and (d / "case.json").is_file())


def _fall(d: Path) -> dict:
    return json.loads((d / "case.json").read_text(encoding="utf-8"))


def test_es_sind_fuenfzehn_faelle_und_sie_stehen_im_manifest():
    faelle = _faelle()
    assert len(faelle) == 15, [d.name for d in faelle]
    manifest = json.loads((REPO / "conformance" / "manifest.json").read_text(encoding="utf-8"))
    im_manifest = {c for c in manifest["cases"] if c.startswith("cap1/")}
    assert im_manifest == {f"cap1/{d.name}" for d in faelle}


@pytest.mark.parametrize("d", _faelle(), ids=lambda d: d.name[:48])
def test_jeder_fall_laeuft_gruen_durch_den_echten_pruefer(d):
    rc = _laeufer()
    r = rc._check_cap1_document(_fall(d), d, require_anchors=False)
    assert r["ok"] is True, r["detail"]


def test_die_achse_ist_eine_menge_nicht_nur_refused():
    """NC-05 muss R1 UND R5 feuern (Autor-Lauf). Ein Pruefer, der nur 'refused' misst, saehe den
    Unterschied nicht; dieser Pruefer faellt, wenn eine der beiden fehlt oder eine dritte dazukommt."""
    rc = _laeufer()
    d = next(x for x in _faelle() if "-nc-05-" in x.name)
    fall = _fall(d)
    assert set(fall["expected"]["cap1Rules"]) == {"R1-no-silent-remainder", "R5-counts-well-formed"}
    zu_wenig = dict(fall, expected={"cap1Rules": ["R5-counts-well-formed"]})
    assert rc._check_cap1_document(zu_wenig, d)["ok"] is False
    zu_viel = dict(fall, expected={"cap1Rules": fall["expected"]["cap1Rules"] + ["R0-shape"]})
    assert rc._check_cap1_document(zu_viel, d)["ok"] is False


def test_flip_ein_gegenbeweis_mit_dem_dokument_der_positivkontrolle_faellt(tmp_path):
    """Der Fall pinnt das DOKUMENT an seine Regeln: dasselbe case.json ueber PV-01 statt NC-01
    muss rot werden — sonst wuerde der Fall auch mit einem vertauschten Fixture bestehen."""
    rc = _laeufer()
    nc = next(x for x in _faelle() if "-nc-01-" in x.name)
    pv = next(x for x in _faelle() if "-pv-01-" in x.name)
    ordner = tmp_path / nc.name
    ordner.mkdir()
    shutil.copy(pv / "document.json", ordner / "document.json")
    r = rc._check_cap1_document(_fall(nc), ordner)
    assert r["ok"] is False, r
    assert "rules fired [] != expected" in r["detail"], r["detail"]


def test_ohne_achse_kein_pass():
    rc = _laeufer()
    d = next(x for x in _faelle() if "-pv-01-" in x.name)
    fall = dict(_fall(d), expected={"classification": "valid"})
    r = rc._check_cap1_document(fall, d)
    assert r["ok"] is False and "cap1Rules" in r["detail"], r
    zwei = dict(_fall(d), expected={"cap1Rules": [], "classification": "valid"})
    r2 = rc._check_cap1_document(zwei, d)
    assert r2["ok"] is False and "EXACTLY ONE" in r2["detail"], r2


def test_ein_eingang_der_aus_dem_fallordner_fluechtet_wird_abgewiesen():
    rc = _laeufer()
    d = next(x for x in _faelle() if "-pv-01-" in x.name)
    fall = dict(_fall(d), input="../vectors/PV-01.json")
    r = rc._check_cap1_document(fall, d)
    assert r["ok"] is False and "escapes" in r["detail"], r


def test_ein_dokument_mit_doppeltem_namen_ist_kein_pass(tmp_path):
    rc = _laeufer()
    d = next(x for x in _faelle() if "-pv-01-" in x.name)
    ordner = tmp_path / d.name
    ordner.mkdir()
    roh = (d / "document.json").read_text(encoding="utf-8")
    doppelt = roh.replace('"profile": "cap/1"', '"profile": "cap/1", "profile": "cap/1"', 1)
    assert doppelt != roh
    (ordner / "document.json").write_text(doppelt, encoding="utf-8")
    r = rc._check_cap1_document(_fall(d), ordner)
    assert r["ok"] is False and "strictly" in r["detail"], r


def test_die_erzeugten_bytes_sind_die_committeten(tmp_path):
    """Der Korpus ist nicht von Hand: der Generator in ein Temp-Verzeichnis, byteweise verglichen."""
    env = dict(os.environ, CAP1_CASES_ROOT=str(tmp_path), PYTHONPATH=str(REPO / "src"))
    subprocess.run([sys.executable, str(KORPUS / "_generator" / "build_cases.py")],
                   check=True, env=env, capture_output=True)
    for d in _faelle():
        for name in ("case.json", "document.json"):
            assert (tmp_path / d.name / name).read_bytes() == (d / name).read_bytes(), f"{d.name}/{name} weicht ab"
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted(d.name for d in _faelle())


def test_korpus_integritaet_haelt_mit_den_neuen_faellen():
    sys.path.insert(0, str(REPO / "conformance"))
    import cross_format  # noqa: PLC0415
    ok, probleme = cross_format.run()
    assert ok, probleme


def test_die_art_steht_im_vokabular_und_im_schema():
    sys.path.insert(0, str(REPO / "conformance"))
    import common_vocabulary  # noqa: PLC0415
    assert "cap1_document" in common_vocabulary.CASE_KINDS
    schema = json.loads((REPO / "conformance" / "vector_schema.json").read_text(encoding="utf-8"))
    assert "cap1_document" in schema["properties"]["kind"]["enum"]
    assert "cap1Rules" in schema["properties"]["expected"]["properties"]
