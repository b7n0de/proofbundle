"""Owner choice 2 A of 2026-10-11: with an unresolved source and an unresolved destination the answer names both reasons,
the source's first, each found on its own.

An unknown resolution of the destination is no proven ambiguity on the remote, and with an unresolved source no commit is
checked in its place. Measured with git 2.43.0 and 2.51.1 (rf10/probes/w2/src_probe.sh): with a branch and a tag
`main`, git push refuses the source ("src refspec main matches more than one"); with refs/remotes/main/HEAD beside the
branch, rev-parse warns that `main` is ambiguous, and git push sends refs/heads/main with exit 0. Red against 1537a7ee,
where the answer named the destination (or a list of possible causes) and no reason for the source.
"""
from __future__ import annotations

import json
import pathlib
import subprocess

import pytest

import test_plugin_gate_n2c_push_done as n2c
from _gate_answer import long_text

pytestmark = n2c.pytestmark
env = n2c.env
_clean_git_environment = n2c._clean_git_environment
gate = n2c.gate

TOLD = "the gate cannot tell which commits the push sends, so it checked no evidence"
REFUSED = ("the source main matches refs/tags/main, refs/heads/main in this repository, and git push refuses a source "
           "that matches more than one ref")


def _git(repo: pathlib.Path, *args: str) -> subprocess.CompletedProcess:
    return n2c._git(repo, *args)


def _commit(repo: pathlib.Path, name: str, content: str = "x\n") -> str:
    (repo / name).parent.mkdir(parents=True, exist_ok=True)
    (repo / name).write_text(content, encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", name)
    return n2c._rev(repo, "HEAD")


def _repo(tmp_path: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
    remote, work = tmp_path / "remote.git", tmp_path / "work"
    subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(remote)], check=True)
    subprocess.run(["git", "init", "-q", "-b", "main", str(work)], check=True)
    _commit(work, "a.txt")
    _git(work, "remote", "add", "origin", str(remote))
    _git(work, "push", "-q", "--no-verify", "origin", "main")
    _git(work, "fetch", "-q", "origin")
    _commit(work, "b.txt")
    return work, remote


def _ask(env: dict, work: pathlib.Path, command: str) -> str:
    answer, entry = n2c._level1(env, work, command=command)
    assert answer["hookSpecificOutput"].get("permissionDecision") == "ask", answer
    assert entry["reason_ids"] == ["push_not_measured"], entry
    return long_text(answer).split(" Details: ", 1)[1]


@pytest.mark.parametrize("command, destination", [
    ("git push origin main", "which ref the push writes on the remote for main is not known: a refspec without `:` "
                             "writes the full name of its source, which is not determined here"),
    ("git push origin main:main", "git push also matches refs/main, refs/tags/main for main, and whether the remote "
                                  "holds one of them is not known here"),
])
def test_both_reasons_are_named_the_source_first(env, tmp_path, command, destination):
    work, _remote = _repo(tmp_path)
    _git(work, "tag", "main", "HEAD~1")
    details = _ask(env, work, command)
    assert REFUSED in details and destination in details, details
    assert details.index(REFUSED) < details.index(TOLD) < details.index(destination), details


def test_an_unknown_destination_is_no_proven_ambiguity_on_the_remote(env, tmp_path):
    work, _remote = _repo(tmp_path)
    _git(work, "tag", "main", "HEAD~1")
    details = _ask(env, work, "git push origin main")
    destination = details[details.index("for the destination, "):]
    assert "refuses" not in destination and "more than one" not in destination, destination


def test_git_refuses_the_branch_and_tag_source(env, tmp_path):
    """Non-vacuous for REFUSED."""
    work, remote = _repo(tmp_path)
    _git(work, "tag", "main", "HEAD~1")
    push = subprocess.run(["git", "-C", str(work), "push", "--porcelain", "--no-verify", "origin", "main"],
                          capture_output=True, text=True, timeout=60, check=False)
    assert push.returncode != 0 and "src refspec main matches more than one" in push.stderr, push.stderr


def test_a_source_that_git_resolves_by_strength_is_not_called_a_refusal(env, tmp_path):
    work, remote = _repo(tmp_path)
    _git(work, "update-ref", "refs/remotes/main/HEAD", "HEAD~1")
    details = _ask(env, work, "git push origin main")
    assert ("the source main answers to refs/heads/main, refs/remotes/main/HEAD in this repository by git's rules, "
            "and which of them git push takes is not determined here") in details, details
    source = details[:details.index(TOLD)]
    assert "refuses" not in source, source
    push = subprocess.run(["git", "-C", str(work), "push", "--porcelain", "--no-verify", "origin", "main"],
                          capture_output=True, text=True, timeout=60, check=False)
    assert push.returncode == 0, push.stderr   # non-vacuous: git took refs/heads/main
    assert subprocess.run(["git", "--git-dir", str(remote), "rev-parse", "refs/heads/main"], capture_output=True,
                          text=True, check=True).stdout.strip() == n2c._rev(work, "HEAD")


def test_control_with_an_unresolved_source_no_commit_is_checked_in_its_place(env, tmp_path):
    """Both candidates of the source hold a declaration that is not JSON, a deny wherever the gate reads it; the answer
    stays an ask that checked no evidence (unchanged by this choice; the reasons are the choice)."""
    work, _remote = _repo(tmp_path)
    _commit(work, gate.DECLARATION, "{")
    _git(work, "tag", "main")
    _commit(work, "c.txt")
    details = _ask(env, work, "git push origin main")
    assert TOLD in details and REFUSED in details, details
    assert "is not JSON" not in json.dumps(details), details


def test_control_a_detached_head_names_its_own_source_reason(env, tmp_path):
    work, _remote = _repo(tmp_path)
    _git(work, "checkout", "-q", "--detach")
    details = _ask(env, work, "git push origin")
    assert details.startswith("the gate cannot resolve what this push sends: HEAD is detached, so a push that names "
                              "no refspec names no branch"), details


def test_d3_states_the_choice():
    decisions = (pathlib.Path(gate.__file__).resolve().parents[1] / "DECISIONS.md").read_text(encoding="utf-8")
    flat = " ".join(decisions.split())
    assert ("Where neither the source nor the destination of a push is resolved, the answer names both reasons, the "
            "source's first, each found on its own (owner choice 2 A of 2026-10-11)") in flat
    assert ("A destination whose resolution is unknown is never named as an ambiguity on the remote, and no commit is "
            "checked in place of an unresolved source") in flat
