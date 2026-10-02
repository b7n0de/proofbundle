"""Nachtrag 19b (S1): before Ebene 1 frees an allow-listed git form it reads the bound repository's effective
configuration (local, global, system, every included file) and its effective hook directory with the hook's
environment. The form stays free only when no key that selects a program for this subcommand is set and no
executable hook this subcommand starts is present; an unknown directory, unreadable configuration or an
unsure mapping is NOT MEASURED. Writes by the file tools to a repository's configuration or hooks are NOT
MEASURED too: ask under Claude, deny under Codex.

These tests judge only the gate's verdict. They run no helper program, no hook and no editor, and transfer
nothing: every helper path below is a file that is never executed. Red against c159b817, green after.
"""
from __future__ import annotations

import json
import os
import pathlib
import shutil
import stat
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


@pytest.fixture(autouse=True)
def _clean_git_config(monkeypatch):
    for key in [k for k in os.environ if k.startswith("GIT_CONFIG")]:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", os.devnull)


def _git(repo: pathlib.Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.org",
                           "-c", "commit.gpgsign=false", *args], check=True, capture_output=True, text=True)


def _repo(tmp_path: pathlib.Path, name: str = "r") -> pathlib.Path:
    """A plain repository with one commit, a branch `side`, a bare remote `origin`, and no hook or helper.
    git init's sample hooks (*.sample) stay; git never runs them, and the gate must not count them."""
    repo, bare = tmp_path / name, tmp_path / f"{name}.git"
    repo.mkdir(parents=True)
    _git(repo, "init", "-q", "-b", "main")
    (repo / "a.txt").write_text("a\n", encoding="utf-8")
    _git(repo, "add", "a.txt")
    _git(repo, "commit", "-q", "-m", "base")
    _git(repo, "branch", "side")
    _git(repo, "init", "-q", "--bare", str(bare))
    _git(repo, "remote", "add", "origin", str(bare))
    return repo


def _helper(tmp_path: pathlib.Path) -> str:
    """A path that names a program. It is never executed by these tests."""
    path = tmp_path / "helper-never-run.sh"
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)
    return str(path)


def _hook(hooks_dir: pathlib.Path, name: str) -> None:
    hooks_dir.mkdir(parents=True, exist_ok=True)
    path = hooks_dir / name
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _deadline() -> float:
    return gate.time.monotonic() + 30


def _decision(command: str, repo: pathlib.Path, host: str = "claude") -> tuple[str | None, str]:
    outcome = gate.decide(command, str(repo), _deadline(), host=host)
    if outcome is None:
        return None, ""
    return outcome.decision, outcome.text


# --- the six S1 forms: with a program-selecting key or hook NOT MEASURED, without it free -------------------

def _set_fsmonitor(repo, tmp_path):
    _git(repo, "config", "core.fsmonitor", _helper(tmp_path))


def _set_clean_filter(repo, tmp_path):
    (repo / ".gitattributes").write_text("*.txt filter=f\n", encoding="utf-8")
    _git(repo, "config", "filter.f.clean", _helper(tmp_path))


def _set_diff_driver(repo, tmp_path):
    (repo / ".gitattributes").write_text("*.txt diff=d\n", encoding="utf-8")
    _git(repo, "config", "diff.d.command", _helper(tmp_path))


def _set_post_checkout(repo, tmp_path):
    _hook(repo / ".git" / "hooks", "post-checkout")


def _set_editor(repo, tmp_path):
    _git(repo, "config", "core.editor", _helper(tmp_path))


def _set_uploadpack(repo, tmp_path):
    _git(repo, "config", "remote.origin.uploadpack", _helper(tmp_path))


S1_FORMS = [
    ("git status --short", _set_fsmonitor),
    ("git add a.txt", _set_clean_filter),
    ("git diff HEAD", _set_diff_driver),
    ("git checkout side", _set_post_checkout),
    ("git commit", _set_editor),
    ("git fetch origin", _set_uploadpack),
]


@pytest.mark.parametrize("command, setup", S1_FORMS, ids=[c for c, _ in S1_FORMS])
def test_s1_form_with_a_program_selecting_key_or_hook_is_not_measured(tmp_path, command, setup):
    repo = _repo(tmp_path)
    setup(repo, tmp_path)
    decision, text = _decision(command, repo)
    assert decision == "ask", (command, decision, text)
    assert text.startswith("NOT MEASURED:"), text
    assert "selects a program" in text or "hook" in text, text


@pytest.mark.parametrize("command", [c for c, _ in S1_FORMS])
def test_s1_form_in_a_repository_without_such_keys_or_hooks_stays_free(tmp_path, command):
    repo = _repo(tmp_path)
    assert _decision(command, repo) == (None, ""), command


def test_a_pre_commit_hook_makes_git_commit_not_measured_but_leaves_git_status_free(tmp_path):
    """Point 4: a repository with a pre-commit hook, as the pre-commit framework installs it."""
    repo = _repo(tmp_path)
    _hook(repo / ".git" / "hooks", "pre-commit")
    assert _decision("git commit", repo)[0] == "ask"
    assert _decision("git status", repo) == (None, "")


# --- unreadable configuration, core.hooksPath ---------------------------------------------------------------

def test_an_included_file_that_cannot_be_read_is_not_measured(tmp_path, monkeypatch):
    """As root, a mode-000 file stays readable; an include that names a directory is a read failure git
    itself reports (measured: `unable to access ...: Is a directory`, exit 128)."""
    repo = _repo(tmp_path)
    unreadable = tmp_path / "included-dir"
    unreadable.mkdir()
    cfg = tmp_path / "global.gitconfig"
    cfg.write_text(f"[include]\n\tpath = {unreadable}\n", encoding="utf-8")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(cfg))
    decision, text = _decision("git status", repo)
    assert decision == "ask" and text.startswith("NOT MEASURED:"), text
    assert "configuration" in text, text


def test_core_hookspath_to_another_directory_is_where_hooks_are_read(tmp_path):
    repo = _repo(tmp_path)
    elsewhere = tmp_path / "shared-hooks"
    _git(repo, "config", "core.hooksPath", str(elsewhere))
    _hook(elsewhere, "post-checkout")
    assert _decision("git checkout side", repo)[0] == "ask"
    # a hook in .git/hooks is not the effective one while core.hooksPath points elsewhere
    repo2 = _repo(tmp_path, "r2")
    empty = tmp_path / "empty-hooks"
    empty.mkdir()
    _git(repo2, "config", "core.hooksPath", str(empty))
    _hook(repo2 / ".git" / "hooks", "post-checkout")
    assert _decision("git checkout side", repo2) == (None, "")


def test_a_global_program_key_counts(tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    cfg = tmp_path / "global.gitconfig"
    cfg.write_text(f"[core]\n\tpager = {_helper(tmp_path)}\n", encoding="utf-8")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(cfg))
    assert _decision("git log --oneline", repo)[0] == "ask"


# --- unknown directory, wrappers, entries that left the list (A) --------------------------------------------

def test_a_free_form_after_a_directory_change_is_not_measured(tmp_path):
    repo = _repo(tmp_path)
    assert _decision("cd . && git status", repo)[0] == "ask"
    assert _decision("git status && git log --oneline -n 3", repo) == (None, "")


@pytest.mark.parametrize("command", ["git merge side", "git pull", "git rebase side", "git cherry-pick side",
                                     "git clone x y", "git gc", "git worktree list", "git verify-commit HEAD"])
def test_entries_whose_program_list_is_not_fully_justified_left_the_allow_list(tmp_path, command):
    repo = _repo(tmp_path)
    assert _decision(command, repo)[0] == "ask", command


def test_under_codex_a_free_form_is_not_measured_because_the_directory_is_not_bound(tmp_path):
    repo = _repo(tmp_path)
    assert _decision("git status", repo, host="codex")[0] == "ask"   # the host answer turns ask into deny


# --- the write path: file tools on configuration and hooks ------------------------------------------------

def _run(event: dict, host: str = "claude") -> dict:
    args = [sys.executable, "-I", str(GATE)] + (["--host", "codex"] if host == "codex" else [])
    out = subprocess.run(args, input=json.dumps(event), capture_output=True, text=True, timeout=120,
                         env=dict(os.environ))
    return json.loads(out.stdout) if out.stdout.strip() else {}


def _file_event(tool: str, path: pathlib.Path, cwd: pathlib.Path) -> dict:
    key = "notebook_path" if tool == "NotebookEdit" else "file_path"
    tool_input = {key: str(path)}
    if tool == "Write":
        tool_input["content"] = "x\n"
    elif tool == "Edit":
        tool_input.update(old_string="a", new_string="b")
    return {"hook_event_name": "PreToolUse", "tool_name": tool, "cwd": str(cwd), "tool_input": tool_input}


def _patch_event(paths: list[str], cwd: pathlib.Path) -> dict:
    body = "".join(f"*** Update File: {p}\n@@\n-a\n+b\n" for p in paths)
    return {"hook_event_name": "PreToolUse", "tool_name": "apply_patch", "cwd": str(cwd),
            "tool_input": {"command": f"*** Begin Patch\n{body}*** End Patch"}}


def _decision_of(answer: dict) -> str | None:
    return answer.get("hookSpecificOutput", {}).get("permissionDecision")


@pytest.mark.parametrize("tool", ["Write", "Edit"])
@pytest.mark.parametrize("target", [".git/config", ".git/hooks/pre-push"])
def test_a_file_tool_write_to_configuration_or_hooks_asks_under_claude(tmp_path, tool, target):
    repo = _repo(tmp_path)
    answer = _run(_file_event(tool, repo / target, repo))
    assert _decision_of(answer) == "ask", answer
    assert answer["systemMessage"].startswith("NOT MEASURED:"), answer
    assert "configuration or hooks" in answer["systemMessage"], answer


@pytest.mark.parametrize("tool", ["Write", "Edit", "apply_patch"])
@pytest.mark.parametrize("target", [".git/config", ".git/hooks/pre-push"])
def test_a_file_tool_write_to_configuration_or_hooks_denies_under_codex(tmp_path, tool, target):
    repo = _repo(tmp_path)
    event = _patch_event([target], repo) if tool == "apply_patch" else _file_event(tool, repo / target, repo)
    answer = _run(event, host="codex")
    assert _decision_of(answer) == "deny", answer
    assert answer["systemMessage"].startswith("NOT MEASURED:"), answer


def test_a_write_through_a_symlink_into_the_hooks_is_resolved(tmp_path):
    repo = _repo(tmp_path)
    link = tmp_path / "innocent-looking"
    link.symlink_to(repo / ".git" / "hooks")
    answer = _run(_file_event("Write", link / "post-checkout", repo))
    assert _decision_of(answer) == "ask", answer


def test_a_write_to_an_included_configuration_file_asks(tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    included = tmp_path / "included.gitconfig"   # not yet existing: git skips it, a write would create it
    _git(repo, "config", "include.path", str(included))
    answer = _run(_file_event("Write", included, repo))
    assert _decision_of(answer) == "ask", answer


def test_a_write_to_an_ordinary_file_gets_no_decision(tmp_path):
    repo = _repo(tmp_path)
    assert _run(_file_event("Write", repo / "notes.md", repo)) == {}
    assert _run(_file_event("Edit", repo / "a.txt", repo)) == {}


def test_the_hook_matcher_covers_the_file_tools():
    hooks = json.loads((GATE.parent / "hooks.json").read_text(encoding="utf-8"))["hooks"]["PreToolUse"]
    matchers = [h["matcher"] for h in hooks]
    import re
    for tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        assert any(re.fullmatch(m, tool) for m in matchers), (tool, matchers)
    assert not any(re.fullmatch(m, "Read") for m in matchers)
