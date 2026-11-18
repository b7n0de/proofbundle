"""C10.4 passes on the self-receipt the pack script writes, not on any file in its folder.

DELTA2 N5 (2026-11-06). `c10_4_manifest_self_receipt` returned PASS as soon as
`docs/readiness_pack/proofbundle/` held any entry at all, so a stray `.DS_Store` stood in for the
self-receipt. The folder holds exactly the two files `scripts/readiness_pack_manifest.py` writes
(RECEIPT and PUBKEY). A missing one or an entry beside them, file, folder or link, is no self-receipt
and is named by repr. An absent or empty folder stays PENDING, the check is advisory.
"""
from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
for _sub in ("src", "scripts"):
    if str(REPO / _sub) not in sys.path:
        sys.path.insert(0, str(REPO / _sub))


def _matrix(repo: Path):
    spec = importlib.util.spec_from_file_location("_acm_c10_4", str(REPO / "scripts" / "audit_candidate_matrix.py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules["_acm_c10_4"] = m
    spec.loader.exec_module(m)
    m.REPO = repo
    return m


def _pack(tmp_path: Path, *names: str) -> Path:
    d = tmp_path / "docs" / "readiness_pack"
    (d / "proofbundle").mkdir(parents=True)
    (d / "MANIFEST.sha256").write_text("x\n")
    for n in names:
        (d / "proofbundle" / n).write_text("x\n")
    return d / "proofbundle"


def test_positive_control_the_two_files_pass(tmp_path):
    _pack(tmp_path, "readiness_pack.bundle.json", "readiness_pack.pub.b64")
    m = _matrix(tmp_path)
    verdict, _ = m.c10_4_manifest_self_receipt()
    assert verdict == m.PASS


def test_an_empty_folder_stays_pending(tmp_path):
    _pack(tmp_path)
    m = _matrix(tmp_path)
    assert m.c10_4_manifest_self_receipt()[0] == m.PENDING


@pytest.mark.parametrize("names", [(".DS_Store",), ("readiness_pack.bundle.json",),
                                   ("readiness_pack.pub.b64",)])
def test_a_folder_without_both_files_does_not_pass(tmp_path, names):
    _pack(tmp_path, *names)
    m = _matrix(tmp_path)
    verdict, reason = m.c10_4_manifest_self_receipt()
    assert verdict == m.FAIL, reason


@pytest.mark.parametrize("art", ["file", "dir", "link"])
def test_an_entry_beside_the_two_files_is_refused_and_named(tmp_path, art):
    d = _pack(tmp_path, "readiness_pack.bundle.json", "readiness_pack.pub.b64")
    fremd = d / "fremd\nname"
    if art == "file":
        fremd.write_text("x")
    elif art == "dir":
        fremd.mkdir()
    else:
        os.symlink(d / "readiness_pack.pub.b64", fremd)
    m = _matrix(tmp_path)
    verdict, reason = m.c10_4_manifest_self_receipt()
    assert verdict == m.FAIL, reason
    assert repr("fremd\nname") in reason
