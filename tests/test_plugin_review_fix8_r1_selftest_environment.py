"""Review round 8 of 2026-10-10, the class of R8-1: the self-test's git calls act only on its own throwaway repositories.

Found in the class search of R8-1 (every process the plugin starts that reads git, with its environment and directory):
gate_selftest_prepare ran git init, add, commit, remote add and push in the server's environment as it came. With an
exported GIT_DIR naming another repository, the self-test committed twice onto that repository's current branch and
added a remote to it (measured at 3d27486d with git 2.43.0 and 2.51.1); its note still said the push goes "never to a
real remote", and the command it hands out runs in the same environment, so it would push that repository.

Property: a GIT_ name the host exported changes which repository git takes, so the self-test makes and reads its
throwaway repositories with none of them, and asks git, in the environment its command will run in, whether a call in
its folder takes that folder's repository, index and object store and pushes origin to its throwaway remote. Where git
answers otherwise the self-test is NOT MEASURABLE and leaves nothing behind. Red against 3d27486d.
"""
from __future__ import annotations

import pathlib
import subprocess

import pytest

import test_plugin_gate_log as gl

pytestmark = gl.pytestmark
env = gl.env
_clean_git_config = gl._clean_git_config


def _user_repo(tmp_path: pathlib.Path) -> pathlib.Path:
    """A repository the self-test must not touch, with one commit on main."""
    user = tmp_path / "user"
    user.mkdir()
    gl._git(user, "init", "-q", "-b", "main")
    (user / "one.txt").write_text("one\n", encoding="utf-8")
    gl._git(user, "add", "one.txt")
    gl._git(user, "commit", "-q", "-m", "user commit")
    return user


def _state(repo: pathlib.Path) -> tuple:
    """Refs, local configuration, index bytes and the set of loose objects of `repo`."""
    git_dir = repo / ".git"
    refs = subprocess.run(["git", "--git-dir", str(git_dir), "for-each-ref", "--format=%(refname) %(objectname)"],
                          capture_output=True, text=True, check=True).stdout
    objects = sorted(str(p.relative_to(git_dir)) for p in (git_dir / "objects").rglob("*") if p.is_file())
    return refs, (git_dir / "config").read_text(encoding="utf-8"), (git_dir / "index").read_bytes(), objects


def _prepare(env: dict, tmp_path: pathlib.Path, **names: str) -> dict:
    temp = tmp_path / "temp"
    temp.mkdir(exist_ok=True)
    (prepared,) = gl._server(dict(env, TMPDIR=str(temp), **names), [("gate_selftest_prepare", {})])
    return prepared


def _left_behind(tmp_path: pathlib.Path) -> list[str]:
    return sorted(p.name for p in (tmp_path / "temp").iterdir())


#: Each GIT_ name makes git write the self-test's commits, refs, index or objects into the user's repository.
WRITES = {
    "GIT_DIR": lambda user: str(user / ".git"),
    "GIT_COMMON_DIR": lambda user: str(user / ".git"),
    "GIT_INDEX_FILE": lambda user: str(user / ".git" / "index"),
    "GIT_OBJECT_DIRECTORY": lambda user: str(user / ".git" / "objects"),
}
#: And GIT_WORK_TREE makes git take the user's files for the self-test's work tree.
REDIRECTS = dict(WRITES, GIT_WORK_TREE=lambda user: str(user))


def test_git_takes_the_exported_repository_for_a_call_in_another_folder(tmp_path):
    """Non-vacuous: with GIT_DIR exported, `git -C <folder>` reads the exported repository, not the folder's."""
    user = _user_repo(tmp_path)
    folder = tmp_path / "folder"
    folder.mkdir()
    gl._git(folder, "init", "-q")
    shown = subprocess.run(["git", "-C", str(folder), "rev-parse", "--absolute-git-dir"], capture_output=True,
                           text=True, check=True, env={"GIT_DIR": str(user / ".git"), "PATH": "/usr/bin:/bin"})
    assert pathlib.Path(shown.stdout.strip()) == (user / ".git").resolve()


@pytest.mark.parametrize("name", WRITES)
def test_an_exported_git_name_leaves_the_repository_it_names_untouched(env, tmp_path, name):
    user = _user_repo(tmp_path)
    before = _state(user)
    _prepare(env, tmp_path, **{name: WRITES[name](user)})
    assert _state(user) == before, name


@pytest.mark.parametrize("name", REDIRECTS)
def test_an_exported_git_name_makes_the_selftest_not_measurable(env, tmp_path, name):
    user = _user_repo(tmp_path)
    prepared = _prepare(env, tmp_path, **{name: REDIRECTS[name](user)})
    assert prepared["is_error"] and prepared["error"].startswith("NOT MEASURABLE: "), prepared
    assert "command" not in prepared
    assert _left_behind(tmp_path) == [], name


def test_control_without_a_git_name_the_command_acts_on_the_throwaway_repository(env, tmp_path):
    prepared = _prepare(env, tmp_path)
    assert not prepared["is_error"], prepared
    work = pathlib.Path(prepared["work"])
    shown = subprocess.run(["git", "-C", str(work), "rev-parse", "--absolute-git-dir"], capture_output=True,
                           text=True, check=True)
    assert pathlib.Path(shown.stdout.strip()) == (work / ".git").resolve()
    remote = subprocess.run(["git", "--git-dir", prepared["remote"], "rev-parse", "refs/heads/main"],
                            capture_output=True, text=True, check=True)
    assert remote.stdout.strip() == (work.parent / "base_oid").read_text(encoding="utf-8").strip()
