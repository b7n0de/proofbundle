"""The work-tree layout of the pilot of follow-up note 15 under tmp_path, shared by the tests of D40.

Account A keeps the clone at /home/<nutzer>/proofbundle and a linked work tree per order under /mnt/<speicher>/claude_worktrees;
commit messages lie under /mnt/<speicher>/claude_scratch. The tests rebuild the same paths below tmp_path, with no remote:
`origin/main` is a remote-tracking ref set to the first commit. Every helper runs git and the gate with plugin_env().
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys

import test_plugin_done_check as d
from _plugin_env import plugin_env

G = str(d.GATE)
CODEX_TEXT = "Under Codex, even with an absolute git -C path"


def clean(monkeypatch, tmp_path: pathlib.Path) -> None:
    """The hook's environment: no GIT_* name of the caller, empty global and system files, a home of its own."""
    for key in [k for k in os.environ if k.startswith("GIT_")]:
        monkeypatch.delenv(key, raising=False)
    (tmp_path / "home").mkdir(exist_ok=True)
    (tmp_path / "marker").mkdir(exist_ok=True)
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("LC_ALL", "C")


def git(repo: pathlib.Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=60, check=True,
                          env=plugin_env()).stdout


def main_repo(tmp_path: pathlib.Path) -> pathlib.Path:
    """The clone: one commit on main, `origin/main` at it, an identity, no remote."""
    main = tmp_path / "home" / "nutzer" / "proofbundle"
    main.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", "-b", "main", str(main)], check=True, timeout=60, env=plugin_env())
    for key, value in (("user.name", "t"), ("user.email", "t@example.org"), ("commit.gpgsign", "false")):
        git(main, "config", key, value)
    (main / "README.md").write_text("one\n")
    git(main, "add", "README.md")
    git(main, "commit", "-q", "-m", "one")
    git(main, "update-ref", "refs/remotes/origin/main", "HEAD")
    return main


def worktree_target(tmp_path: pathlib.Path) -> pathlib.Path:
    return tmp_path / "mnt" / "speicher" / "claude_worktrees" / "scope_631"


def linked_worktree(tmp_path: pathlib.Path, main: pathlib.Path) -> pathlib.Path:
    """The work tree of the order, added as account A adds it, with the new scope file in it."""
    target = worktree_target(tmp_path)
    git(main, "worktree", "add", "-q", "-b", "docs/release-scope-6-3-1", str(target), "origin/main")
    (target / "docs" / "release_scope").mkdir(parents=True)
    (target / "docs" / "release_scope" / "6.3.1.md").write_text("# 6.3.1\n")
    return target


def message_file(tmp_path: pathlib.Path) -> pathlib.Path:
    path = tmp_path / "mnt" / "speicher" / "claude_scratch" / "n15" / "commit_message_scope_631.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("docs(release): scope 6.3.1\n")
    return path


def proxy(tmp_path: pathlib.Path, path: pathlib.Path, name: str, body: str = "exit 0") -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f'#!/bin/sh\necho "$0 $*" >> {tmp_path / "marker" / name}.log\n{body}\n')
    path.chmod(0o755)
    return str(path)


def started(tmp_path: pathlib.Path) -> list[str]:
    return sorted(p.stem for p in (tmp_path / "marker").glob("*.log"))


def answer(cwd: pathlib.Path, command: str, host: str = "claude") -> tuple[int, str | None, str]:
    event = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(cwd),
                        "tool_input": {"command": command}})
    args = [] if host == "claude" else ["--host", host]
    proc = subprocess.run([sys.executable, "-I", G, *args], input=event, capture_output=True, text=True,
                          env=plugin_env(), timeout=120, check=False)
    out = json.loads(proc.stdout).get("hookSpecificOutput", {}) if proc.stdout.strip() else {}
    return proc.returncode, out.get("permissionDecision"), ((out.get("additionalContext") or "") if out.get("permissionDecision") else "")   # D53: the long reason


def bash(cwd: pathlib.Path, command: str) -> int:
    return subprocess.run(["bash", "-c", command], cwd=cwd, capture_output=True, timeout=60, check=False,
                          env=plugin_env(), stdin=subprocess.DEVNULL).returncode
