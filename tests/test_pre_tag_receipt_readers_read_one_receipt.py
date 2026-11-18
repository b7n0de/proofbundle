"""The gate and the third-party verifier read a receipt file the one same way.

Local review of 8a05ceef (2026-11-10, P1). The gate decoded a receipt with `errors="ignore"` and the verifier
strictly, and both parsed with `json.loads`, which keeps the last of two equal member names. A receipt carrying
`audit_exit_code` 17 and then 0 verified as 0 while a reader keeping the first saw 17, and a byte that is not UTF-8
was dropped by the gate and refused by the verifier. Both read through `pre_tag_receipt_lib.receipt_json` now. These
cases run the gate's own candidate reader on files in a folder; the verifier's case runs end to end through git in
tests/test_verify_pre_tag_receipt_third_party.py.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


def _gate():
    spec = importlib.util.spec_from_file_location("_gate_one_reading", SCRIPTS / "pre_tag_audit_gate.py")
    modul = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modul)
    return modul


def _candidates(tmp_path: Path, raw: bytes):
    ordner = tmp_path / "audit_artifacts" / "500"
    ordner.mkdir(parents=True)
    (ordner / "pre_tag_receipt_5.0.0.json").write_bytes(raw)
    return _gate()._receipt_candidates(tmp_path, "5.0.0")


def test_positive_control_a_plain_object_is_a_candidate(tmp_path):
    [(_pfad, receipt, grund)] = _candidates(tmp_path, b'{"schema": "x", "audit_exit_code": 0}')
    assert receipt == {"schema": "x", "audit_exit_code": 0} and grund is None


@pytest.mark.parametrize("raw, wort", [
    (b'{"audit_exit_code": 17, "audit_exit_code": 0}', "'audit_exit_code' twice"),
    (b'{"schema": "x", "nested": {"b": 1, "b": 2}}', "'b' twice"),
    (b'{"schema": "x\xff"}', "UnicodeDecodeError"),
])
def test_the_gate_refuses_what_the_verifier_refuses(tmp_path, raw, wort):
    [(_pfad, receipt, grund)] = _candidates(tmp_path, raw)
    assert receipt is None, receipt
    assert wort in grund, grund


def test_the_library_is_the_one_reading(tmp_path):
    """The rule stands once, in the library both readers load by path, and both call it."""
    for name in ("pre_tag_audit_gate.py", "verify_pre_tag_receipt.py"):
        text = (SCRIPTS / name).read_text(encoding="utf-8")
        assert ".receipt_json(" in text, name


def _ordner(tmp_path: Path) -> Path:
    ordner = tmp_path / "audit_artifacts" / "500"
    ordner.mkdir(parents=True)
    (ordner / "pre_tag_receipt_5.0.0.json").write_text('{"schema": "x"}')
    return ordner


def test_a_link_in_the_receipt_folder_is_rejected_by_the_gate(tmp_path):
    """Local review of 9f5d5eec (P2): the gate read a committed link to a regular receipt as that receipt, so it counted
    one receipt twice, while the third-party verifier reads the link text from the commit and rejected it."""
    ordner = _ordner(tmp_path)
    (ordner / "pre_tag_receipt_5.0.0-alias.json").symlink_to("pre_tag_receipt_5.0.0.json")
    kandidaten = {pfad: (receipt, grund) for pfad, receipt, grund in _gate()._receipt_candidates(tmp_path, "5.0.0")}
    assert kandidaten["audit_artifacts/500/pre_tag_receipt_5.0.0.json"] == ({"schema": "x"}, None)
    receipt, grund = kandidaten["audit_artifacts/500/pre_tag_receipt_5.0.0-alias.json"]
    assert receipt is None and "symbolic link" in grund, grund


def test_a_subdirectory_the_gate_cannot_list_is_a_rejected_candidate(tmp_path):
    """The walk of the gate dropped the error of a subdirectory it could not list (mode 0111), so a candidate in it was
    neither verified nor rejected; the third-party verifier reads the commit's tree and sees it."""
    import os
    import stat
    ordner = _ordner(tmp_path)
    versteck = ordner / "unter"
    versteck.mkdir()
    (versteck / "kaputt.json").write_text("{ broken")
    versteck.chmod(stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    try:
        try:
            os.listdir(versteck)
        except PermissionError:
            pass
        else:
            pytest.skip("this user can list a directory without its read bit (root?): the case does not exist here")
        kandidaten = _gate()._receipt_candidates(tmp_path, "5.0.0")
        assert any(receipt is None and "cannot be listed" in (grund or "") for _p, receipt, grund in kandidaten), \
            kandidaten
    finally:
        versteck.chmod(stat.S_IRWXU)
    kandidaten = _gate()._receipt_candidates(tmp_path, "5.0.0")
    assert [p for p, receipt, _g in kandidaten if receipt is None] == ["audit_artifacts/500/unter/kaputt.json"]
