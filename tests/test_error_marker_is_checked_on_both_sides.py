"""S32 (6.2.0 E1): a case's `errorContains` marker is held against BOTH implementations.

MEASURED 2026-09-25: 21 relation vectors declare a marker. The Python output carried 21 of them,
the Rust verifier 0, because it printed `{"lineage": ...}` and no reason at all. The differential
compared exit class and lineage only, so Rust could reach the same verdict for an entirely
different reason and nothing noticed, while the corpus read as though it checked both sides.

Rust now prints `reasons` beside `lineage`, in Python's wording and with Python's stable codes, and
`crosscheck.py` requires the marker in both outputs.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
RS = REPO / "tools" / "pb_verify_rs"


def _crosscheck():
    s = importlib.util.spec_from_file_location("_s32_crosscheck", RS / "crosscheck.py")
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


def test_the_marker_rule_names_each_side_that_lacks_it():
    """No Rust build needed: the rule itself, in both directions."""
    befunde = _crosscheck().marker_befunde
    assert befunde("CODE_X", "... CODE_X ...", "... CODE_X ...") == []
    nur_py = befunde("CODE_X", "CODE_X", '{"lineage":"FAIL"}')
    assert len(nur_py) == 1 and "Rust" in nur_py[0]
    nur_rs = befunde("CODE_X", "nothing", "CODE_X")
    assert len(nur_rs) == 1 and "Python" in nur_rs[0]
    assert len(befunde("CODE_X", "", "")) == 2


def _rust_bin() -> pathlib.Path:
    for t in ("debug", "release"):
        b = RS / "target" / t / "pb_verify_rs"
        if b.exists():
            return b
    pytest.skip("pb_verify_rs is not built here: the Rust side of the marker is NOT measured "
                "(CI builds it and runs crosscheck.py, which holds the same rule)")


def _relation_faelle():
    cc = _crosscheck()
    manifest = json.loads((REPO / "conformance" / "manifest.json").read_text(encoding="utf-8"))
    for rel in manifest["cases"]:
        cdir = REPO / "conformance" / rel
        case = json.loads((cdir / "case.json").read_text(encoding="utf-8"))
        if case.get("kind") in cc._RELATION_KINDS:
            yield rel, cdir, case, cc


def _rust(cdir: pathlib.Path, case: dict, cc) -> tuple[int, dict, str]:
    sub, _ = cc._RELATION_KINDS[case["kind"]]
    pub = (cdir / case.get("pub", "pub.b64")).read_text(encoding="utf-8").strip()
    p = subprocess.run([str(_rust_bin()), sub, str(cdir / case.get("input", "receipt.json")), pub,
                        *cc._relation_argv_common(case, cdir)],
                       capture_output=True, text=True, timeout=60)
    return p.returncode, json.loads(p.stdout), p.stdout + p.stderr


def test_every_declared_marker_is_in_the_rust_output():
    gezaehlt, fehlt = 0, []
    for rel, cdir, case, cc in _relation_faelle():
        marker = case.get("expected", {}).get("errorContains")
        if marker is None:
            continue
        gezaehlt += 1
        _rc, bericht, blob = _rust(cdir, case, cc)
        assert isinstance(bericht.get("reasons"), list), (rel, bericht)
        if marker not in blob:
            fehlt.append((rel, marker, blob.strip()[:160]))
    assert gezaehlt >= 21, f"only {gezaehlt} relation vectors declare a marker; the corpus shrank"
    assert fehlt == [], fehlt


def test_CONTROL_a_verified_case_names_no_reason():
    """The counter-direction: a verifier that printed every code for every input would pass the
    case above. A case that verifies with exit 0 and declares nothing must carry no failure reason."""
    geprueft = 0
    for rel, cdir, case, cc in _relation_faelle():
        exp = case.get("expected", {})
        if exp.get("exitCode") != 0 or exp.get("lineage") != "VERIFIED":
            continue
        rc, bericht, _ = _rust(cdir, case, cc)
        assert rc == 0, (rel, rc, bericht)
        fehlerhaft = [r for r in bericht["reasons"] if "relation:" in r or r.isupper()]
        assert fehlerhaft == [], (rel, fehlerhaft)
        geprueft += 1
    assert geprueft >= 3, f"only {geprueft} verified relation vectors: the control is too thin"
