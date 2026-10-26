"""The readiness binding and the pre-tag receipt exclude the same paths from what a candidate binds.

FINDING (external review of the 6.4.0 preparation, 2026-10-26, RELEASEPLAN P7; owner choice A on card
OA-c04430c2ea, 2026-10-26). Two bindings of one candidate excluded different paths. The pre-tag receipt
binds `subject_tree_digest`, which leaves out the mutable evidence of `MUTABLE_EVIDENCE_RELS` AND the
receipt itself (`pre_tag_receipt_lib._RECEIPT_MUSTER`). The signed short soak and Rust differential bind
`sign_readiness_artifact.tree_digest`, which left out only the mutable evidence, and the audit matrix
allowed a later commit only when it touched nothing but that set. So no commit after the candidate C could
carry the receipt and the evidence together: with the receipt, C6.2 and C8.2 were `candidate_unbound`;
without it, C12.1 had no receipt. The audit matrix could not be green at any one commit.

THE FIX, as the owner chose it: the readiness binding leaves out the receipt path exactly as the receipt's
own digest does, from the one pattern in `pre_tag_receipt_lib`. `MUTABLE_EVIDENCE_RELS` is not widened;
the owner boundary in `pre_tag_receipt_lib.subject_tree_digest` stays as it is.

The oracle is independent: each case builds its own small git tree and compares digests and the relation
of the audit matrix, with a control that must still move and a lookalike path that must not be excluded.
"""
from __future__ import annotations

import importlib.util
import pathlib
import shutil
import subprocess
import sys
import tempfile

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
for _sub in ("src", "scripts"):
    _p = str(REPO / _sub)
    if _p not in sys.path:
        sys.path.insert(0, _p)

RECEIPT = "audit_artifacts/640/pre_tag_receipt_v6.4.0.json"
SOAK = "audit_artifacts/360/fuzz_soak_latest.json"
DIFF = "audit_artifacts/360/rust_differential_matrix.json"


def _modul(name: str, datei: str):
    spec = importlib.util.spec_from_file_location(name, str(REPO / "scripts" / datei))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


def _git(repo: pathlib.Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True,
                          check=True).stdout.strip()


def _commit(repo: pathlib.Path, dateien: dict[str, str], nachricht: str) -> str:
    for rel, inhalt in dateien.items():
        p = repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(inhalt, encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "-c", "user.email=a@b", "-c", "user.name=a", "commit", "-q", "-m", nachricht)
    return _git(repo, "rev-parse", "HEAD")


@pytest.fixture
def baum():
    td = pathlib.Path(tempfile.mkdtemp(prefix="receipt_binding_"))
    try:
        if subprocess.run(["git", "init", "-q", str(td)], capture_output=True).returncode != 0:
            pytest.skip("NOT MEASURABLE: git is not usable here")
        kandidat = _commit(td, {"pyproject.toml": '[project]\nversion = "9.9.9"\n',
                                "src/pkg/__init__.py": "", "audit_artifacts/640/README.md": "page\n"},
                           "candidate")
        yield td, kandidat
    finally:
        shutil.rmtree(td, ignore_errors=True)


def test_a_receipt_and_the_evidence_after_the_candidate_keep_both_bindings(baum):
    """[COUNTS] The finding: one evidence commit E on C with the receipt, the soak and the differential.
    Both digests stay those of C, and the audit matrix admits E as a later evidence commit."""
    repo, c = baum
    sra = _modul("_sra_receipt_binding", "sign_readiness_artifact.py")
    lib = _modul("_lib_receipt_binding", "pre_tag_receipt_lib.py")
    m = _modul("_acm_receipt_binding", "audit_candidate_matrix.py")
    vorher = (sra.tree_digest(repo), lib.subject_tree_digest(repo))
    e = _commit(repo, {RECEIPT: "{}\n", SOAK: "{}\n", DIFF: "{}\n"}, "evidence")
    assert (sra.tree_digest(repo), lib.subject_tree_digest(repo)) == vorher
    erlaubt, grund = m._evidenz_relation_erlaubt(repo, c, e)
    assert erlaubt is True, grund


def test_the_control_and_the_lookalike_still_move_the_binding(baum):
    """[COUNTS] Counter-cases: another file beside the receipt, and a path that only ends like a receipt
    below src/, change both digests and are refused by the relation, as before."""
    repo, c = baum
    sra = _modul("_sra_receipt_binding2", "sign_readiness_artifact.py")
    lib = _modul("_lib_receipt_binding2", "pre_tag_receipt_lib.py")
    m = _modul("_acm_receipt_binding2", "audit_candidate_matrix.py")
    vorher = (sra.tree_digest(repo), lib.subject_tree_digest(repo))
    e = _commit(repo, {RECEIPT: "{}\n", "audit_artifacts/640/README.md": "changed page\n"}, "receipt and page")
    assert sra.tree_digest(repo) != vorher[0] and lib.subject_tree_digest(repo) != vorher[1]
    assert m._evidenz_relation_erlaubt(repo, c, e)[0] is False
    f = _commit(repo, {"src/audit_artifacts/640/pre_tag_receipt_v6.4.0.json": "{}\n"}, "lookalike")
    assert m._evidenz_relation_erlaubt(repo, e, f)[0] is False
    nach_e = sra.tree_digest(repo)
    assert nach_e != vorher[0]


def test_both_bindings_name_one_exclusion_rule():
    """[COUNTS] The class: the readiness binding reads the receipt pattern from the receipt library and
    the mutable set from itself; no third copy of either."""
    sra = _modul("_sra_receipt_binding3", "sign_readiness_artifact.py")
    lib = _modul("_lib_receipt_binding3", "pre_tag_receipt_lib.py")
    assert sra.ist_quittungspfad(RECEIPT) and sra.ist_quittungspfad("audit_artifacts/641rc1/pre_tag_receipt_v6.4.1rc1.json")
    assert not sra.ist_quittungspfad("src/" + RECEIPT)
    assert not sra.ist_quittungspfad("audit_artifacts/640/README.md")
    assert sra._quittungsmuster().pattern == lib._RECEIPT_MUSTER.pattern
