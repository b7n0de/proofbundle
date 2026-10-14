"""Review round 5 of 2026-10-09, the class of R5-1 in the state check: a boolean is false only where git reads false.

The class search found a strip in the state check of the two free forms (K-NW-2 B): core.fsmonitor and
commit.gpgSign counted as off when value.strip().lower() was false, no, off or 0. git does not strip: measured with git
2.43.0, `git config --type=bool` reads ` no`, `no `, ` false`, `false ` and `0 ` as no boolean at all, and
core.fsmonitor then names a program git starts through the shell for `git add` and `git commit` (` no` and `no ` start
the program `no` from PATH). The gate freed both forms. Property: changed effective program sources keep the forms not
free; a value is off only where git itself reads it as false. Red against e54a241c.
"""
from __future__ import annotations

import os
import subprocess

import pytest

import test_plugin_gate_k_nw_2_b as knw
from _plugin_env import plugin_env

gate = knw.gate
_clean_git_environment = knw._clean_git_environment

NOT_BOOLEAN = [" no", "no ", " false", "false ", "0 "]


def _path_with(tmp_path, name):
    program, marker = knw._marker(tmp_path, name)
    return f"{tmp_path}{os.pathsep}{os.environ['PATH']}", marker


@pytest.mark.parametrize("value", NOT_BOOLEAN)
@pytest.mark.parametrize("command", ["git add a.txt", "git commit -am msg"])
def test_a_blank_padded_fsmonitor_value_keeps_both_forms_not_free(tmp_path, value, command):
    repo = knw._repo(tmp_path)
    knw._git(repo, "config", "core.fsmonitor", value)
    knw._refused(command, repo, "a fsmonitor: core.fsmonitor")


@pytest.mark.parametrize("value", [" no", "no "])
def test_git_starts_the_program_a_blank_padded_fsmonitor_value_names(tmp_path, value):
    """Non-vacuous: git starts `no` from PATH for both values, for git add."""
    repo = knw._repo(tmp_path)
    knw._git(repo, "config", "core.fsmonitor", value)
    path, marker = _path_with(tmp_path, "no")
    knw._change(repo)
    subprocess.run(["git", "-C", str(repo), "add", "a.txt"], capture_output=True, timeout=60,
                   env=plugin_env(PATH=path))
    assert marker.exists(), f"git does not start `no` for core.fsmonitor={value!r}; the case would be vacuous"


@pytest.mark.parametrize("value", NOT_BOOLEAN)
def test_a_blank_padded_gpgsign_value_keeps_git_commit_not_free(tmp_path, value):
    """git refuses such a value for commit.gpgSign (bad boolean); the gate no longer reads it as off."""
    repo = knw._repo(tmp_path)
    knw._git(repo, "config", "commit.gpgSign", value)
    knw._refused("git commit -m msg", repo, "a signature program: commit.gpgsign")
    probe = subprocess.run(["git", "-C", str(repo), "config", "--type=bool", "--get", "commit.gpgsign"],
                           capture_output=True, text=True, timeout=60)
    assert probe.returncode != 0 and "bad boolean" in probe.stderr, probe


@pytest.mark.parametrize("value", ["false", "FALSE", "no", "Off", "0", " 0", "00", ""])
@pytest.mark.parametrize("key", ["core.fsmonitor", "commit.gpgSign"])
def test_control_a_value_git_reads_as_false_keeps_the_forms_free(tmp_path, key, value):
    repo = knw._repo(tmp_path)
    knw._git(repo, "config", key, value)
    probe = knw._git(repo, "config", "--type=bool", "--get", key.lower())
    assert probe.stdout == "false\n", probe   # non-vacuous: git itself reads the value as false
    knw._free("git add a.txt", repo)
    knw._free("git commit -m msg", repo)
