"""A case directory the manifest does not name is a foreign member of the vector set.

DELTA2 N4 (2026-11-06). `measure_vector_set` hashed the manifest and every file of every case
directory the manifest names. A directory carrying a `case.json` that the manifest leaves out moved
neither the digest nor `cases`, so a corpus with a case nobody runs measured exactly like the corpus
without it. A case is what `conformance/cross_format.py` loads, a directory with `case.json`. Helper
directories without one (generators, regression inputs) stay outside the set, as on the real corpus.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from proofbundle import verifier_block as VB


def _corpus(root: Path, cases=("a", "b")) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "manifest.json").write_text(json.dumps(
        {"schema": "proofbundle.conformance.manifest.v1", "cases": list(cases)}))
    for c in cases:
        (root / c).mkdir(parents=True, exist_ok=True)
        (root / c / "case.json").write_text(json.dumps({"caseId": c}))
    return root


def test_positive_control_a_helper_directory_without_a_case_is_not_a_case(tmp_path):
    root = _corpus(tmp_path / "c")
    (root / "_generator").mkdir()
    (root / "_generator" / "make.py").write_text("print('x')\n")
    assert VB.measure_vector_set(root)["cases"] == 2


@pytest.mark.parametrize("rel", ["c", "group/c", "a/../d"])
def test_an_unnamed_case_directory_is_refused_and_named(tmp_path, rel):
    root = _corpus(tmp_path / "c")
    ziel = (root / rel)
    ziel.mkdir(parents=True, exist_ok=True)
    (ziel / "case.json").write_text(json.dumps({"caseId": "foreign"}))
    name = ziel.resolve().relative_to(root.resolve()).as_posix()
    with pytest.raises(VB.VerifierBlockError, match="does not name") as exc:
        VB.measure_vector_set(root)
    assert repr(name) in str(exc.value)
