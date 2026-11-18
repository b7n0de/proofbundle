"""Review round 4 of 2026-10-09: the second locks of R4-1 and R4-2 hold on their own.

The mutation run against 1fbd854b left four changes of the fixed code that no test caught: a relative attribute file
name taken against the command's directory instead of the work tree (M1e), a digest serialisation that replaces what
is not UTF-8 (M2b), git's lines split with str.splitlines (M2c), and the work tree path stripped of blanks (M2d). Each
test below fails under exactly that change and passes at 1fbd854b. The properties are those of R4-1 and R4-2: the
digest binds the attribute file git opens, and every name keeps the bytes git printed.
"""
from __future__ import annotations

import os
import pathlib
import subprocess
import time

import _git_version as _gv
import pytest

import test_plugin_gate_n24 as n24
from _plugin_env import plugin_env

gate = n24.gate
_clean_git_config = n24._clean_git_config


def _digest(directory: pathlib.Path | str) -> str | None:
    return gate._bound_state_digest(str(directory), time.monotonic() + 30, plugin_env())


def _attr(directory: pathlib.Path | str) -> bytes:
    return subprocess.run(["git", "-C", str(directory), "check-attr", "review", "--", "a.txt"], capture_output=True,
                          timeout=60, check=True).stdout.strip()


def _init(repo: pathlib.Path) -> pathlib.Path:
    repo.mkdir(parents=True)
    subprocess.run(["git", "-C", str(repo), "init", "-q", "-b", "main"], check=True, timeout=60)
    (repo / "a.txt").write_text("a\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "a.txt"], check=True, timeout=60)
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.org", "-c",
                    "commit.gpgsign=false", "commit", "-q", "-m", "base"], check=True, timeout=60)
    return repo


@_gv.needs_git(2, 42, "git var names the configuration and attribute files git reads")
def test_m1e_a_relative_attribute_file_is_bound_where_git_reads_it_from_a_subdirectory(tmp_path):
    """git opens a relative core.attributesFile against the work tree, also for a command started in a subdirectory;
    the digest computed from that subdirectory follows the work-tree file."""
    repo = _init(tmp_path / "r")
    (repo / "sub").mkdir()
    (repo / "rel").mkdir()
    (repo / "rel" / "attrs").write_text("a.txt review=one\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "config", "core.attributesFile", "rel/attrs"], check=True, timeout=60)
    assert _attr(repo / "sub").endswith(b"review: one")
    before = _digest(repo / "sub")
    (repo / "rel" / "attrs").write_text("a.txt review=two\n", encoding="utf-8")
    assert _attr(repo / "sub").endswith(b"review: two")
    after = _digest(repo / "sub")
    assert before is not None and after is not None and before != after


@_gv.needs_git(2, 42, "git var names the configuration and attribute files git reads")
def test_m2b_two_bytes_that_are_not_utf8_are_two_states(tmp_path):
    """FE and FF in the same value: a serialisation that replaces both by one character would make them one state."""
    repo = _init(tmp_path / "r")
    subprocess.run(["git", "-C", str(repo), "config", "review.value", os.fsdecode(b"x\xfe")], check=True, timeout=60)
    before = _digest(repo)
    subprocess.run(["git", "-C", str(repo), "config", "review.value", os.fsdecode(b"x\xff")], check=True, timeout=60)
    after = _digest(repo)
    assert before is not None and after is not None and before != after


@_gv.needs_git(2, 42, "git var names the configuration and attribute files git reads")
@pytest.mark.parametrize("separator", ["\x1c", "\x1d", "\x1e", "\x85", " "])
def test_m2c_a_repository_whose_path_carries_a_line_separator_is_read(tmp_path, separator):
    """str.splitlines splits on these, git does not: the layout stays readable and a new hook changes the digest."""
    repo = _init(tmp_path / f"r{separator}x")
    before = _digest(repo)
    hook = repo / ".git" / "hooks" / "pre-commit"
    hook.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    hook.chmod(0o755)
    after = _digest(repo)
    assert before is not None and after is not None and before != after


@_gv.needs_git(2, 42, "git var names the configuration and attribute files git reads")
def test_m2d_a_work_tree_whose_name_ends_in_a_blank_binds_its_relative_attribute_file(tmp_path):
    repo = _init(tmp_path / "r ")
    (repo / "rel").mkdir()
    (repo / "rel" / "attrs").write_text("a.txt review=one\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "config", "core.attributesFile", "rel/attrs"], check=True, timeout=60)
    before = _digest(repo)
    (repo / "rel" / "attrs").write_text("a.txt review=two\n", encoding="utf-8")
    assert _attr(repo).endswith(b"review: two")
    after = _digest(repo)
    assert before is not None and after is not None and before != after
