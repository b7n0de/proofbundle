"""A committed declaration that holds only a done check is not an absent or an uncommitted one (D5, D26).

Measured on 2026-10-08 at 582cef6a and 395f0a87: a repository whose committed `.proofbundle/evidence.json` declares
an empty evidence list and a done section (the shape `done-init` and the order of D28 write) was read as declaring
nothing, and the absence nuance of D5 then found the declaration in the working tree and answered
`declaration_uncommitted`, "A declaration exists in the working tree but is not committed", on every path that
asks it: a shell push, a `gh pr create`, the pre-push hook (Level 2), the CI mode and the MCP diagnosis. The CI mode
failed such a repository with exit 1 even where the workflow does not require a declaration.

The class is a branch on the shape `inactive` without a branch for `done_only`. Each path is checked here; the
controls keep the D5 cases that are real: a declaration only in the working tree still asks, and a repository that
declares nothing anywhere is still inactive.
"""
from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
GATE = ROOT / "plugins" / "proofbundle" / "hooks" / "proofbundle_gate.py"

_bytecode, sys.dont_write_bytecode = sys.dont_write_bytecode, True
sys.path.insert(0, str(GATE.parent))
import proofbundle_gate as gate  # noqa: E402

sys.path.pop(0)
sys.dont_write_bytecode = _bytecode

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")

WRONG = {"declaration_uncommitted", "absence_not_measured"}
POLICY = {"schema": "proofbundle/trust-policy/v0.1", "policy_id": "done-test",
          "allowed_issuers": [{"public_key_b64": "A" * 43 + "="}], "signature": {"require_expected_signer": True}}


@pytest.fixture(autouse=True)
def _clean_git_environment(monkeypatch):
    for key in [k for k in os.environ if k.startswith("GIT_")]:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", os.devnull)


def _git(repo: pathlib.Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.org", *args],
                          check=True, capture_output=True, text=True, timeout=60).stdout.strip()


def _repo(tmp_path: pathlib.Path, declaration: dict | None, commit_it: bool = True) -> pathlib.Path:
    """A repository whose main tracks origin/main. The declaration, when given and committed, is already on the
    remote, so the push of the next commit changes no evidence rule and reaches the evidence verdicts; uncommitted,
    it stays in the working tree only."""
    bare = tmp_path / "remote.git"
    subprocess.run(["git", "init", "--bare", "-q", str(bare)], check=True, timeout=60)
    repo = tmp_path / "r"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    (repo / "a.txt").write_text("a\n", encoding="utf-8")
    if declaration is not None:
        folder = repo / ".proofbundle"
        folder.mkdir()
        (folder / "done-policy.json").write_text(json.dumps(POLICY), encoding="utf-8")
        (folder / "evidence.json").write_text(json.dumps(declaration), encoding="utf-8")
    _git(repo, "add", "a.txt", *([".proofbundle"] if declaration is not None and commit_it else []))
    _git(repo, "commit", "-q", "-m", "base")
    _git(repo, "remote", "add", "origin", str(bare))
    for rule in ("+refs/tags/*:refs/recorded/origin/tags/*", "+refs/refs/*:refs/recorded/origin/refs/*"):
        _git(repo, "config", "--add", "remote.origin.fetch", rule)   # what git push also matches (R8-2)
    _git(repo, "push", "-q", "-u", "origin", "main")
    (repo / "a.txt").write_text("a\nb\n", encoding="utf-8")
    _git(repo, "add", "a.txt")
    _git(repo, "commit", "-q", "-m", "work")
    return repo


def _done_only() -> dict:
    return {"schema": gate.DECLARATION_SCHEMA, "evidence": [],
            "done": {"receipt": gate.DONE_RECEIPT, "policy": gate.DONE_POLICY}}


def _deadline() -> float:
    return gate.time.monotonic() + 60


def _pre_push_lines(repo: pathlib.Path) -> list[tuple]:
    return [("refs/heads/main", _git(repo, "rev-parse", "HEAD"), "refs/heads/main",
             _git(repo, "rev-parse", "origin/main"))]


@pytest.mark.parametrize("command", ["git push origin main", "git push", "gh pr create --fill"])
def test_a_shell_push_never_reads_a_done_only_declaration_as_uncommitted(tmp_path, command):
    repo = _repo(tmp_path, _done_only())
    outcome = gate.decide(command, str(repo), _deadline())
    assert outcome is not None
    assert not {v.reason_id for v in outcome.verdicts} & WRONG, outcome.verdicts
    assert "is not committed" not in outcome.text and "not committed" not in outcome.text


def test_the_pre_push_hook_never_reads_a_done_only_declaration_as_uncommitted(tmp_path):
    repo = _repo(tmp_path, _done_only())
    verdict = gate.pre_push_verdict(str(repo), _pre_push_lines(repo), _deadline())
    assert verdict.reason_id not in WRONG and "not committed" not in verdict.text(), verdict.text()


def test_the_ci_mode_reads_a_done_only_declaration_as_declaring_no_evidence(tmp_path):
    repo = _repo(tmp_path, _done_only())
    verdict = gate.evaluate_repository(str(repo), _deadline())
    assert (verdict.decision, verdict.reason_id) == ("inactive", "done_only"), verdict.text()
    assert "only a done check" in verdict.detail
    code, report = gate.ci_check(str(repo), False, _deadline())
    assert (code, report["outcome"]) == (0, "not_required"), report
    code, report = gate.ci_check(str(repo), True, _deadline())
    assert (code, report["outcome"], report["reason_id"]) == (1, "declaration_required", "declaration_required")
    assert "declares only a done check, no evidence" in report["message"]


def test_the_mcp_diagnosis_names_the_done_only_declaration(tmp_path):
    repo = _repo(tmp_path, _done_only())
    outcome = gate.decide_mcp("mcp__github__create_pull_request", str(repo), _deadline())
    assert outcome is not None and outcome.decision == "ask"
    assert "only a done check" in outcome.text and "not committed" not in outcome.text


# --- the D5 cases that are real stay as they were ------------------------------------------------------------------

def test_a_declaration_only_in_the_working_tree_still_asks_as_uncommitted(tmp_path):
    repo = _repo(tmp_path, _done_only(), commit_it=False)
    outcome = gate.decide("git push origin main", str(repo), _deadline())
    assert outcome is not None and outcome.decision == "ask"
    assert "declaration_uncommitted" in {v.reason_id for v in outcome.verdicts}
    assert gate.evaluate_repository(str(repo), _deadline()).reason_id == "declaration_uncommitted"


def test_a_repository_that_declares_nothing_is_still_inactive(tmp_path):
    repo = _repo(tmp_path, None)
    outcome = gate.decide("git push origin main", str(repo), _deadline())
    assert outcome is not None and outcome.decision == "inactive"
    assert {v.reason_id for v in outcome.verdicts} == {"nothing_declared"}
    assert gate.evaluate_repository(str(repo), _deadline()).reason_id == "nothing_declared"
