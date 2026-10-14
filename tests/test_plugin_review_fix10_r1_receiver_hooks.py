"""The class of review round 10, R10-1: the hook programs a configuration gives the throwaway remote's receiver.

Measured at bf10fa6a, the head of the round-10 fixes (git 2.43.0): an isolated HOME whose .gitconfig set core.hooksPath to
a folder with a post-receive hook that moves each updated ref back to its old value. gate_selftest_prepare handed out
its command, the push exited 0, the hook ran in the throwaway remote's receive-pack and moved main back to the base,
and gate_selftest_check reported target_changed=false and other_refs_changed=false. The same with core.hooksPath in a
system configuration file (GIT_CONFIG_SYSTEM). receive-pack reads core.hooksPath from the files of the configuration
(the local push clears GIT_CONFIG_COUNT and GIT_CONFIG_PARAMETERS for it, so a value given only there did not reach it),
and a relative value is taken from the remote's git directory.

Property: as for remote.origin.receivepack (R10-1), the command the self-test hands out is bound to the receiver its
check reads; a hook program the receiver runs where it updates refs (pre-receive, update, proc-receive, post-receive,
post-update, reference-transaction, push-to-checkout) can refuse, change or undo the write, so prepare refuses, before
it hands out the command, any of them in the hooks folder git names for the throwaway remote in the server's
environment, as long as no binding of them is built. A hooks folder without such a hook, or one that does not exist,
is no choice of a receive program. Red against bf10fa6a.
"""
from __future__ import annotations

import pathlib
import shutil
import subprocess

import pytest

import test_plugin_gate_log as gl
import test_plugin_review_fix10_r1_selftest_receiver as r1
from _plugin_env import plugin_env

pytestmark = gl.pytestmark
env = gl.env
_clean_git_config = gl._clean_git_config

RECEIVE_HOOKS = ("pre-receive", "update", "proc-receive", "post-receive", "post-update", "reference-transaction",
                 "push-to-checkout")
RESET = '#!/bin/sh\necho post-receive >> "{log}"\nwhile read old new ref; do git update-ref "$ref" "$old"; done\n'


def _hooks(folder: pathlib.Path, names: dict[str, str]) -> pathlib.Path:
    folder.mkdir(parents=True)
    for name, body in names.items():
        (folder / name).write_text(body, encoding="utf-8")
        (folder / name).chmod(0o755)
    return folder


def _home(tmp_path: pathlib.Path, hooks_path: str) -> pathlib.Path:
    home = tmp_path / "home"
    home.mkdir()
    (home / ".gitconfig").write_text(f"[core]\n\thooksPath = {hooks_path}\n", encoding="utf-8")
    return home


@pytest.mark.parametrize("relative", [False, True])
def test_git_runs_a_hook_the_configuration_names_and_a_post_receive_undoes_the_write(tmp_path, relative):
    """Non-vacuous: the push exits 0, the hook runs in the receiver and main of the remote stays at its old value; a
    relative core.hooksPath is taken from the remote's git directory."""
    work, bare = r1._pair(tmp_path)
    log = tmp_path / "hook.log"
    folder = _hooks(tmp_path / "hk", {"post-receive": RESET.format(log=log)})
    home = _home(tmp_path, "../../hk" if relative else str(folder))
    before = r1._main(bare)
    environ = plugin_env(without=("GIT_CONFIG_GLOBAL",))
    push = subprocess.run(["git", "-C", str(work), "push", "-q", "origin", "main"], capture_output=True, text=True,
                          env=dict(environ, HOME=str(home)), timeout=60, check=False)
    assert push.returncode == 0, push.stderr
    assert r1._main(bare) == before and log.exists()


def test_a_post_receive_in_the_home_hooks_path_is_not_measurable(env, tmp_path):
    log = tmp_path / "hook.log"
    folder = _hooks(tmp_path / "hk", {"post-receive": RESET.format(log=log)})
    prepared = r1._prepare(env, tmp_path, HOME=str(_home(tmp_path, str(folder))), GIT_CONFIG_GLOBAL=None)
    r1._not_measurable(prepared, tmp_path)
    assert "hook" in prepared["error"], prepared


def test_a_hooks_path_in_the_system_configuration_is_not_measurable(env, tmp_path):
    folder = _hooks(tmp_path / "hk", {"post-receive": RESET.format(log=tmp_path / "hook.log")})
    system = tmp_path / "system.cfg"
    system.write_text(f"[core]\n\thooksPath = {folder}\n", encoding="utf-8")
    prepared = r1._prepare(env, tmp_path, GIT_CONFIG_SYSTEM=str(system))
    r1._not_measurable(prepared, tmp_path)


@pytest.mark.parametrize("name", RECEIVE_HOOKS)
def test_each_hook_receive_pack_runs_is_not_measurable(env, tmp_path, name):
    folder = _hooks(tmp_path / "hk", {name: "#!/bin/sh\nexit 0\n"})
    prepared = r1._prepare(env, tmp_path, HOME=str(_home(tmp_path, str(folder))), GIT_CONFIG_GLOBAL=None)
    r1._not_measurable(prepared, tmp_path)
    assert name in prepared["error"], prepared


def test_a_relative_hooks_path_is_read_from_the_remotes_git_directory(env, tmp_path):
    """The throwaway remote is <TMPDIR>/proofbundle-selftest-*/remote.git, so ../../hk names <TMPDIR>/hk for its
    receive-pack, whatever the server's working directory."""
    (tmp_path / "temp").mkdir()
    _hooks(tmp_path / "temp" / "hk", {"post-receive": RESET.format(log=tmp_path / "hook.log")})
    prepared = r1._prepare(env, tmp_path, HOME=str(_home(tmp_path, "../../hk")), GIT_CONFIG_GLOBAL=None)
    assert prepared["is_error"] and prepared["error"].startswith("NOT MEASURABLE: "), prepared
    assert sorted(p.name for p in (tmp_path / "temp").iterdir()) == ["hk"]


def test_control_a_hooks_folder_with_client_hooks_only_is_measurable(env, tmp_path):
    folder = _hooks(tmp_path / "hk", {"pre-commit": "#!/bin/sh\nexit 0\n", "pre-push": "#!/bin/sh\nexit 0\n"})
    prepared = r1._prepare(env, tmp_path, HOME=str(_home(tmp_path, str(folder))), GIT_CONFIG_GLOBAL=None)
    assert not prepared["is_error"], prepared
    shutil.rmtree(pathlib.Path(prepared["work"]).parent)


def test_control_a_hooks_path_naming_no_folder_is_measurable(env, tmp_path):
    prepared = r1._prepare(env, tmp_path, HOME=str(_home(tmp_path, str(tmp_path / "missing"))),
                           GIT_CONFIG_GLOBAL=None)
    assert not prepared["is_error"], prepared
    shutil.rmtree(pathlib.Path(prepared["work"]).parent)
