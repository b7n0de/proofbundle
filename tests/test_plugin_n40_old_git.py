"""Follow-up note 40, point 2: on a git older than 2.42 the gate keeps its stricter answer where it needs `git var`.

The the operator's machine runs git 2.34.1; account A found 106 plugin test cases red there at f9e5f18e and at 9e0d071b, cause NOT MEASURED.
Measured here with a stand-in of git 2.34.1 in front of git 2.43.0 (tools/n40/sim2341_n40.sh, a wrapper bound over
/usr/bin/git in a private mount namespace): 94 cases of 44 functions in 13 files are red, every one through `git var`,
which knows GIT_CONFIG_GLOBAL, GIT_CONFIG_SYSTEM, GIT_ATTR_SYSTEM and GIT_ATTR_GLOBAL only since git 2.42 (before:
usage, exit 129); fsmonitor--daemon (2.36) and merge-tree --write-tree (2.38) made none red. Those tests now name
git 2.42 (tests/_git_version.py). A wrapper that only passes every call through makes 65 cases of the push hand-over
red as well, so those are an artefact of the stand-in, not of the version.

These tests run on every git and show what the gate does without those variables: the state digest that binds a
person's rule and the push hand-over is not built (the gate asks), the person's own global and system files are not
known (D74 does not act), and the attribute files git reads outside the work tree are unknown.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import time

import _git_version as _gv
import pytest
from _plugin_env import plugin_env

import test_plugin_n29_work_profile_d71 as d71

gate = d71.gate
pytestmark = d71.pytestmark
_clean = d71._clean
OLD_VAR = ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_ATTR_SYSTEM", "GIT_ATTR_GLOBAL")


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "r"
    subprocess.run(["git", "init", "-q", "-b", "main", str(r)], check=True, timeout=60, env=plugin_env())
    (r / "a.txt").write_text("a\n")
    subprocess.run(["git", "-C", str(r), "add", "a.txt"], check=True, timeout=60, env=plugin_env())
    subprocess.run(["git", "-C", str(r), "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c",
                    "commit.gpgsign=false", "commit", "-q", "-m", "A"], check=True, timeout=60, env=plugin_env())
    return r


def _older_git(tmp_path, monkeypatch) -> None:
    """A git first on PATH whose `git var` knows none of OLD_VAR, as git before 2.42 (usage, exit 129)."""
    real = shutil.which("git")
    folder = tmp_path / "git_before_2_42"
    folder.mkdir()
    (folder / "git").write_text(
        "#!/bin/sh\nfor a in \"$@\"; do case \"$a\" in " + "|".join(OLD_VAR) +
        f") echo 'usage: git var (-l | <variable>)' >&2; exit 129;; esac; done\nexec \"{real}\" \"$@\"\n")
    (folder / "git").chmod(0o755)
    monkeypatch.setenv("PATH", os.pathsep.join([str(folder), os.environ["PATH"]]))


def _home_with_gitconfig(tmp_path, monkeypatch) -> str:
    home = tmp_path / "home_old_git"
    home.mkdir()
    (home / ".gitconfig").write_text("[core]\n\tfsmonitor = true\n")
    monkeypatch.delenv("GIT_CONFIG_GLOBAL", raising=False)
    monkeypatch.setenv("HOME", str(home))
    return str(home / ".gitconfig")


def test_on_a_git_before_2_42_there_is_no_state_digest(repo, tmp_path, monkeypatch):
    _older_git(tmp_path, monkeypatch)
    assert gate._bound_state_digest(str(repo), time.monotonic() + 60) is None


def test_on_a_git_before_2_42_the_attribute_files_are_unknown(repo, tmp_path, monkeypatch):
    _older_git(tmp_path, monkeypatch)
    assert gate._attribute_files(str(repo), str(repo), time.monotonic() + 60) is None


def test_on_a_git_before_2_42_the_own_file_is_not_known(repo, tmp_path, monkeypatch):
    origin = _home_with_gitconfig(tmp_path, monkeypatch)
    _older_git(tmp_path, monkeypatch)
    env = {"HOME": os.environ["HOME"], "PATH": os.environ["PATH"]}
    assert gate._own_file("global", f"file:{origin}", str(repo), time.monotonic() + 60, env) is False


@_gv.needs_git(2, 42, "git var names the configuration and attribute files git reads")
def test_control_on_the_measured_git_the_digest_and_the_own_file_stand(repo, tmp_path, monkeypatch):
    origin = _home_with_gitconfig(tmp_path, monkeypatch)
    env = {"HOME": os.environ["HOME"], "PATH": os.environ["PATH"]}
    assert gate._bound_state_digest(str(repo), time.monotonic() + 60) is not None
    assert gate._own_file("global", f"file:{origin}", str(repo), time.monotonic() + 60, env) is True


def test_the_version_helper_reads_the_git_on_path(tmp_path, monkeypatch):
    folder = tmp_path / "git_2_34_1"
    folder.mkdir()
    (folder / "git").write_text("#!/bin/sh\necho 'git version 2.34.1'\n")
    (folder / "git").chmod(0o755)
    monkeypatch.setenv("PATH", str(folder))
    assert _gv.git_version() == (2, 34, 1)
    monkeypatch.setenv("PATH", str(tmp_path / "none"))
    assert _gv.git_version() == (0,)
