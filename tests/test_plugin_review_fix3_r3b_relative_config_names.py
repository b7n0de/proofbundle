"""Review round 3 of 2026-10-09, R3-3, a sibling found while probing the fix: a configuration file name git reports
relative is protected where git reads it.

Measured with git 2.43: with GIT_CONFIG_GLOBAL=~/cfg git opens the literal `~/cfg` (no interpolation) and names it
`file:~/cfg`. `git config` reads it against the work tree, while an alias looked up from a subdirectory reads it
against that subdirectory, before git sets up the repository. At 252333ec the origin went through os.path.expanduser,
so the gate protected $HOME/cfg, a file git does not read here; at b58ae7a3 it protected the work-tree reading only,
and the name git var reports stayed relative, so it was compared against the hook's own working directory.

Now every relative name (an origin, a git var answer, the environment value) is protected against both the work tree
and the command's directory, and no relative name is left in the set. Red against b58ae7a3.
"""
from __future__ import annotations

import os
import pathlib
import subprocess
import time

import pytest

import test_plugin_gate_n24 as n24

gate = n24.gate
_clean_git_config = n24._clean_git_config


@pytest.fixture
def relative_global(tmp_path, monkeypatch) -> tuple[pathlib.Path, pathlib.Path]:
    repo = n24._repo(tmp_path)
    home = tmp_path / "home"
    home.mkdir()
    (repo / "~").mkdir()
    (repo / "sub" / "~").mkdir(parents=True)
    (repo / "~" / "cfg").write_text("[alias]\n\tpbx = !echo TOP\n", encoding="utf-8")
    (repo / "sub" / "~" / "cfg").write_text("[alias]\n\tpbx = !echo SUB\n", encoding="utf-8")
    (home / "cfg").write_text("[alias]\n\tpbx = !echo HOME\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", "~/cfg")
    return repo, home


def _alias(directory: pathlib.Path) -> str:
    return subprocess.run(["git", "-C", str(directory), "pbx"], capture_output=True, text=True, timeout=60,
                          check=True).stdout.strip()


def _real(files: set) -> set:
    return {os.path.realpath(f) for f in files}


def test_git_reads_the_relative_global_file_where_it_starts(relative_global):
    """Non-vacuous: git names `file:~/cfg`, reads the work-tree copy for `git config` and the subdirectory copy for
    an alias from the subdirectory, and never the file under HOME."""
    repo, _home = relative_global
    origin = subprocess.run(["git", "-C", str(repo / "sub"), "config", "--show-origin", "--get", "alias.pbx"],
                            capture_output=True, text=True, timeout=60, check=True).stdout
    assert origin.startswith("file:~/cfg\t") and origin.rstrip().endswith("TOP"), origin
    assert _alias(repo) == "TOP"
    assert _alias(repo / "sub") == "SUB"


def test_the_protected_files_name_both_readings_and_no_relative_name(relative_global):
    repo, _home = relative_global
    files, _dirs, problem = gate._state_files(str(repo / "sub"), time.monotonic() + 30)
    assert not problem
    assert {os.path.realpath(repo / "~" / "cfg"), os.path.realpath(repo / "sub" / "~" / "cfg")} <= _real(files)
    assert all(os.path.isabs(f) for f in files), sorted(f for f in files if not os.path.isabs(f))


@pytest.mark.parametrize("where,target", [("", "~/cfg"), ("sub", "~/cfg"), ("sub", "sub/~/cfg")])
def test_a_write_to_either_reading_is_gated(relative_global, where, target):
    repo, _home = relative_global
    cwd = repo / where
    path = repo / target
    reason = gate._protected_write(str(path), str(cwd), time.monotonic() + 30)
    assert reason is not None and "configuration" in reason, reason
    outcome = gate.decide_write("Write", {"file_path": str(path), "content": "[alias]\n\tpbx = !echo X\n"},
                                str(cwd), time.monotonic() + 30, host="claude")
    assert outcome is not None
    assert gate.answer(outcome.decision, outcome.text, host="claude")["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_control_an_ordinary_file_beside_it_is_not_gated(relative_global):
    repo, _home = relative_global
    assert gate._protected_write(str(repo / "sub" / "~" / "notes.txt"), str(repo / "sub"), time.monotonic() + 30) is None
