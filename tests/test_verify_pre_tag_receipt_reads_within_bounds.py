"""The third-party receipt verifier reads a committed candidate within bounds, and refuses what it cannot read.

A review of the stack at 1ecc2aca, on main as well, measured 2026-09-26: a committed receipt nested
100000 deep ended `scripts/verify_pre_tag_receipt.py` with a RecursionError traceback and exit 1,
where its docstring promises a verdict with a reason. A candidate is also read whole, so its size is
asked first. Each case runs the real script against a real repository built here; the verifier's
own preconditions (the named commit checked out, a clean scripts/ and src/, the gate source in the
commit) are met so that the receipt is what decides.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "verify_pre_tag_receipt.py"
GATE = REPO / "scripts" / "pre_tag_audit_gate.py"
RECEIPT = "audit_artifacts/610/pre_tag_receipt_v6.1.0.json"


def _git(repo: Path, *args: str) -> str:
    r = subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t", *args],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


def _verify(tmp_path: Path, receipt: bytes, *extra: str) -> subprocess.CompletedProcess:
    if not (SCRIPT.is_file() and GATE.is_file()):
        pytest.skip("the verifier or the gate is not here (sdist without repo context)")
    repo = tmp_path / "r"
    (repo / "scripts").mkdir(parents=True)
    (repo / "scripts" / "pre_tag_audit_gate.py").write_bytes(GATE.read_bytes())
    (repo / RECEIPT).parent.mkdir(parents=True)
    (repo / RECEIPT).write_bytes(receipt)
    (repo / "a.txt").write_text("x\n", encoding="utf-8")
    _git(repo, "init", "-q")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "a candidate")
    commit = _git(repo, "rev-parse", "HEAD")
    return subprocess.run([sys.executable, "-B", str(SCRIPT), "--repo", str(repo), "--commit", commit,
                           "--version", "6.1.0", *extra], capture_output=True, text=True, timeout=120)


def test_a_receipt_nested_too_deep_is_rejected_with_its_reason(tmp_path):
    r = _verify(tmp_path, b"[" * 100000 + b"]" * 100000)
    assert "Traceback" not in r.stderr, r.stderr
    assert r.returncode == 1, r.stdout + r.stderr
    assert "verdict=NOT_VERIFIED" in r.stdout and "RecursionError" in r.stdout, r.stdout


def test_a_candidate_larger_than_a_receipt_is_rejected_unread(tmp_path):
    r = _verify(tmp_path, b'{"pad": "' + b"x" * (4 * 1024 * 1024) + b'"}')
    assert "Traceback" not in r.stderr, r.stderr
    assert r.returncode == 1, r.stdout + r.stderr
    assert "more than a receipt is" in r.stdout and "is not read" in r.stdout, r.stdout


def test_control_a_receipt_that_is_no_object_was_already_a_typed_rejection(tmp_path):
    """R1 did not reproduce for this verifier: `[1]` was rejected with its reason at 1ecc2aca too."""
    r = _verify(tmp_path, b"[1]")
    assert r.returncode == 1 and "is not a JSON object (got list)" in r.stdout, r.stdout + r.stderr
