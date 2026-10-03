"""Review Runde 7 (stand 36d991f3): one regression test per finding, each exactly the review's case.

These tests judge the gate's verdict. The only programs they start are marker scripts inside the test folder,
and only where a test first shows that plain git starts the marker, so the case is not vacuous. Red against
36d991f3, green after.
"""
from __future__ import annotations

import os
import pathlib
import shlex
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

#: The program-selecting variables the gate reads from the hook's environment (as tests/test_plugin_gate_runde6b.py).
_PROGRAM_ENV = ["EDITOR", "GIT_ASKPASS", "GIT_EDITOR", "GIT_EXEC_PATH", "GIT_EXTERNAL_DIFF", "GIT_PAGER",
                "GIT_PROXY_COMMAND", "GIT_SSH", "GIT_SSH_COMMAND", "PAGER", "SSH_ASKPASS", "VISUAL"]


@pytest.fixture(autouse=True)
def _clean_git_config(monkeypatch):
    for key in [k for k in os.environ if k.startswith("GIT_CONFIG")] + _PROGRAM_ENV + ["GIT_NO_LAZY_FETCH"]:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", os.devnull)


def _git(repo: pathlib.Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.org",
                           "-c", "commit.gpgsign=false", *args], check=True, capture_output=True,
                          text=True).stdout.strip()


def _repo(tmp_path: pathlib.Path, name: str = "r") -> pathlib.Path:
    """A plain repository with one commit and a bare remote `origin`, no hook and no helper."""
    repo, bare = tmp_path / name, tmp_path / f"{name}.git"
    repo.mkdir(parents=True)
    _git(repo, "init", "-q", "-b", "main")
    (repo / "a.txt").write_text("a\n", encoding="utf-8")
    _git(repo, "add", "a.txt")
    _git(repo, "commit", "-q", "-m", "base")
    _git(repo, "init", "-q", "--bare", str(bare))
    _git(repo, "remote", "add", "origin", str(bare))
    return repo


def _deadline() -> float:
    return gate.time.monotonic() + 30


def _decision(command: str, repo: pathlib.Path, host: str = "claude") -> tuple[str | None, str]:
    outcome = gate.decide(command, str(repo), _deadline(), host=host)
    if outcome is None:
        return None, ""
    return outcome.decision, outcome.text


def _marker_program(tmp_path: pathlib.Path, marker: pathlib.Path, name: str) -> pathlib.Path:
    """A script inside the test folder that leaves marker when something starts it."""
    program = tmp_path / name
    program.write_text(f"#!/bin/sh\ntouch {shlex.quote(str(marker))}\nexit 1\n", encoding="utf-8")
    program.chmod(0o700)
    return program


# --- R7-7: lazy fetch in a partial clone, during the gate's own check ------------------------------------------

def _partial_clone(repo: pathlib.Path, tmp_path: pathlib.Path, marker: pathlib.Path) -> None:
    """repo turned into a partial clone whose promisor remote's uploadpack leaves marker (the review's setup)."""
    program = _marker_program(tmp_path, marker, "uploadpack-marker.sh")
    for key, value in (("remote.origin.url", str(tmp_path / "promisor-nowhere")), ("remote.origin.promisor", "true"),
                       ("extensions.partialClone", "origin"), ("remote.origin.uploadpack", str(program))):
        _git(repo, "config", "--local", key, value)


def _drop_loose(repo: pathlib.Path, oid: str) -> None:
    loose = repo / ".git" / "objects" / oid[:2] / oid[2:]
    assert loose.is_file(), "precondition: the object is a loose object that can be taken out"
    loose.unlink()


def test_r7_7_a_free_object_read_in_a_partial_clone_is_not_measured(tmp_path):
    """R7-7, first case: in a partial clone with a missing object, `git cat-file -p <OID>` got no answer from the
    gate and started the uploadpack the promisor remote names. The anti-vacuity half: plain git starts it."""
    repo, marker = _repo(tmp_path), tmp_path / "marker-lazy-fetch"
    (repo / "b.txt").write_text("b\n", encoding="utf-8")
    _git(repo, "add", "b.txt")
    _git(repo, "commit", "-q", "-m", "b")
    oid = _git(repo, "rev-parse", "HEAD:b.txt")
    _partial_clone(repo, tmp_path, marker)
    _drop_loose(repo, oid)
    subprocess.run(["git", "-C", str(repo), "cat-file", "-p", oid], capture_output=True, check=False)
    assert marker.exists(), "the promisor transport is not live for a plain git; the case would be vacuous"
    marker.unlink()
    decision, text = _decision(f"git cat-file -p {oid}", repo)
    assert decision == "ask", text
    assert "promisor" in text, text
    assert not marker.exists(), "the gate's check started the promisor transport"


@pytest.mark.parametrize("host, expected", [("claude", "ask"), ("codex", "deny")])
def test_r7_7_the_mcp_diagnosis_reads_no_object_of_a_partial_clone(tmp_path, host, expected):
    """R7-7, second case: the committed declaration .proofbundle/evidence.json is missing locally; decide_mcp for
    create_pull_request started the promisor's uploadpack in its local diagnosis before it answered."""
    repo, marker = _repo(tmp_path), tmp_path / "marker-lazy-fetch"
    (repo / ".proofbundle").mkdir()
    (repo / ".proofbundle" / "evidence.json").write_text('{"schema": "x"}\n', encoding="utf-8")
    _git(repo, "add", ".proofbundle/evidence.json")
    _git(repo, "commit", "-q", "-m", "declaration")
    oid = _git(repo, "rev-parse", "HEAD:.proofbundle/evidence.json")
    _partial_clone(repo, tmp_path, marker)
    _drop_loose(repo, oid)
    outcome = gate.decide_mcp("mcp__github__create_pull_request", str(repo), _deadline(), host=host)
    assert not marker.exists(), "the gate's diagnosis started the promisor transport"
    assert outcome is not None and outcome.decision == expected, outcome
    assert "partial clone" in outcome.text, outcome.text
    subprocess.run(["git", "-C", str(repo), "cat-file", "-t", "HEAD:.proofbundle/evidence.json"],
                   capture_output=True, check=False)
    assert marker.exists(), "the promisor transport is not live for a plain git; the case would be vacuous"
