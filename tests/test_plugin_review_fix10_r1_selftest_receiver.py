"""Review round 10 of 2026-10-11, R10-1: the self-test binds the receive program of the push it hands out.

Measured by the reviewer at 1698db61: a second empty bare other.git and an executable wrapper receive-pack containing
`exec git receive-pack /absolute/probe/other.git`; in an isolated HOME, before prepare, [remote "origin"] receivepack =
/absolute/probe/receive-pack. gate_selftest_prepare, the command shown to the real PreToolUse gate (deny/stale_subject
logged), the push run anyway, gate_selftest_check; server, gate and push in the same environment. Under git 2.43.0 and
2.51.1: prepare handed out its command, the push exited 0 and wrote main into other.git, remote.git stayed as it was,
and check reported target_changed=false, other_refs_changed=false and "Expected denial logged; test target unchanged.".

Property: the command the self-test hands out is bound to the receiver its check reads. Every effective choice of
another receive program or transport in the server's environment is refused before the command is handed out (NOT
MEASURABLE), as long as no binding of it is built: remote.origin.receivepack from any configuration source,
GIT_EXEC_PATH naming another program folder than git's own, remote.origin.vcs (a remote helper), and
receive.procReceiveRefs on the throwaway remote (refs handed to a proc-receive program). A setting only the host's shell
carries is not visible to the server; the skill and the prepare note say that the check observes the refs of the
throwaway remote and nothing else, and no longer that the push goes "nowhere else". Red against 1698db61.
"""
from __future__ import annotations

import os
import pathlib
import shutil
import subprocess

import pytest

import test_plugin_gate_log as gl
from _plugin_env import plugin_env

pytestmark = gl.pytestmark
env = gl.env
_clean_git_config = gl._clean_git_config

SKILL = pathlib.Path(__file__).resolve().parents[1] / "plugins" / "proofbundle" / "skills" / "selftest" / "SKILL.md"


def _wrapper(tmp_path: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path]:
    """other.git, an executable receive-pack wrapper that receives into it, and a log of its starts."""
    other, wrapper, log = tmp_path / "probe" / "other.git", tmp_path / "probe" / "receive-pack", tmp_path / "probe" / "log"
    other.parent.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", "--bare", str(other)], check=True)
    wrapper.write_text(f'#!/bin/sh\necho "$*" >> "{log}"\nexec git receive-pack "{other}"\n', encoding="utf-8")
    wrapper.chmod(0o755)
    return other, wrapper, log


def _pair(tmp_path: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
    bare, work = tmp_path / "pair" / "remote.git", tmp_path / "pair" / "work"
    work.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", "--bare", str(bare)], check=True)
    gl._git(work, "init", "-q", "-b", "main")
    (work / "a.txt").write_text("a\n", encoding="utf-8")
    gl._git(work, "add", "-A")
    gl._git(work, "commit", "-q", "-m", "a")
    gl._git(work, "remote", "add", "origin", str(bare))
    gl._git(work, "push", "-q", "origin", "HEAD:refs/heads/main")
    (work / "b.txt").write_text("b\n", encoding="utf-8")
    gl._git(work, "add", "-A")
    gl._git(work, "commit", "-q", "-m", "b")
    return work, bare


def _main(bare: pathlib.Path) -> str:
    return subprocess.run(["git", "--git-dir", str(bare), "rev-parse", "--verify", "--quiet", "refs/heads/main"],
                          capture_output=True, text=True, check=False).stdout.strip()


def test_git_sends_the_push_to_the_receive_program_a_configuration_names(tmp_path):
    """Non-vacuous: remote.origin.receivepack moves the write to another repository, the named remote stays."""
    work, bare = _pair(tmp_path)
    other, wrapper, log = _wrapper(tmp_path)
    before = _main(bare)
    subprocess.run(["git", "-C", str(work), "-c", f"remote.origin.receivepack={wrapper}", "push", "-q", "origin", "main"],
                   check=True, capture_output=True)
    head = subprocess.run(["git", "-C", str(work), "rev-parse", "HEAD"], capture_output=True, text=True,
                          check=True).stdout.strip()
    assert (_main(bare), _main(other)) == (before, head) and log.exists()


def test_git_takes_its_receive_program_from_git_exec_path(tmp_path):
    """Non-vacuous: GIT_EXEC_PATH names the folder git starts git-receive-pack from for a local push."""
    work, bare = _pair(tmp_path)
    other, wrapper, log = _wrapper(tmp_path)
    exec_path = pathlib.Path(subprocess.run(["git", "--exec-path"], capture_output=True, text=True,
                                            check=True).stdout.strip())
    folder = tmp_path / "exec"
    folder.mkdir()
    for entry in exec_path.iterdir():
        (folder / entry.name).symlink_to(entry)
    (folder / "git-receive-pack").unlink()
    shutil.copy(wrapper, folder / "git-receive-pack")
    before = _main(bare)
    subprocess.run(["git", "-C", str(work), "push", "-q", "origin", "main"], check=True, capture_output=True,
                   env=plugin_env(GIT_EXEC_PATH=str(folder)))
    assert _main(bare) == before and _main(other) and log.exists()


def test_git_hands_the_push_to_the_remote_helper_remote_vcs_names(tmp_path):
    """Non-vacuous: remote.origin.vcs selects a remote helper as the transport."""
    work, _bare = _pair(tmp_path)
    bin_dir, log = tmp_path / "bin", tmp_path / "helper.log"
    bin_dir.mkdir()
    (bin_dir / "git-remote-probe").write_text(f'#!/bin/sh\necho "$*" >> "{log}"\nexit 1\n', encoding="utf-8")
    (bin_dir / "git-remote-probe").chmod(0o755)
    subprocess.run(["git", "-C", str(work), "-c", "remote.origin.vcs=probe", "push", "-q", "origin", "main"],
                   capture_output=True, env=plugin_env(PATH=f"{bin_dir}{os.pathsep}{os.environ['PATH']}"))
    assert log.exists()


def _prepare(env: dict, tmp_path: pathlib.Path, **names) -> dict:
    temp = tmp_path / "temp"
    temp.mkdir(exist_ok=True)
    server_env = dict(env, TMPDIR=str(temp), **{k: v for k, v in names.items() if v is not None})
    for key in [k for k, v in names.items() if v is None]:
        server_env.pop(key, None)
    (prepared,) = gl._server(server_env, [("gate_selftest_prepare", {})])
    return prepared


def _left_behind(tmp_path: pathlib.Path) -> list[str]:
    return sorted(p.name for p in (tmp_path / "temp").iterdir())


def _not_measurable(prepared: dict, tmp_path: pathlib.Path) -> None:
    assert prepared["is_error"] and prepared["error"].startswith("NOT MEASURABLE: "), prepared
    assert "command" not in prepared
    assert _left_behind(tmp_path) == []


def test_the_reviewers_case_a_receivepack_in_the_home_configuration_is_not_measurable(env, tmp_path):
    """The review's setting: an isolated HOME whose .gitconfig names the wrapper as origin's receivepack."""
    _other, wrapper, _log = _wrapper(tmp_path)
    home = tmp_path / "home"
    home.mkdir()
    (home / ".gitconfig").write_text(f'[remote "origin"]\n\treceivepack = {wrapper}\n', encoding="utf-8")
    prepared = _prepare(env, tmp_path, HOME=str(home), GIT_CONFIG_GLOBAL=None)
    _not_measurable(prepared, tmp_path)
    assert "receive" in prepared["error"], prepared


@pytest.mark.parametrize("key", ["remote.origin.receivepack", "remote.origin.vcs"])
def test_a_receive_program_or_transport_named_through_the_environment_is_not_measurable(env, tmp_path, key):
    _other, wrapper, _log = _wrapper(tmp_path)
    value = str(wrapper) if key.endswith("receivepack") else "probe"
    prepared = _prepare(env, tmp_path, GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0=key, GIT_CONFIG_VALUE_0=value)
    _not_measurable(prepared, tmp_path)


def test_an_empty_receivepack_value_is_a_choice_too(env, tmp_path):
    """git reads a present value; the gate does not guess what an empty one starts."""
    prepared = _prepare(env, tmp_path, GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="remote.origin.receivepack",
                        GIT_CONFIG_VALUE_0="")
    _not_measurable(prepared, tmp_path)


def test_another_program_folder_in_git_exec_path_is_not_measurable(env, tmp_path):
    folder = tmp_path / "exec"
    folder.mkdir()
    prepared = _prepare(env, tmp_path, GIT_EXEC_PATH=str(folder))
    _not_measurable(prepared, tmp_path)


def test_control_git_exec_path_naming_gits_own_folder_is_measurable(env, tmp_path):
    exec_path = subprocess.run(["git", "--exec-path"], capture_output=True, text=True, check=True).stdout.strip()
    prepared = _prepare(env, tmp_path, GIT_EXEC_PATH=exec_path)
    assert not prepared["is_error"], prepared
    shutil.rmtree(pathlib.Path(prepared["work"]).parent)


def test_proc_receive_refs_for_the_throwaway_remote_is_not_measurable(env, tmp_path):
    """receive.procReceiveRefs hands matching refs to a proc-receive program instead of receive-pack's own update; a
    global value reaches the throwaway remote's receive-pack."""
    prepared = _prepare(env, tmp_path, GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="receive.procReceiveRefs",
                        GIT_CONFIG_VALUE_0="refs/heads")
    _not_measurable(prepared, tmp_path)


def test_control_without_any_receiver_setting_the_selftest_is_measurable(env, tmp_path):
    prepared = _prepare(env, tmp_path)
    assert not prepared["is_error"], prepared
    shutil.rmtree(pathlib.Path(prepared["work"]).parent)


def test_the_skill_and_the_note_promise_only_what_the_check_reads(env, tmp_path):
    """The skill no longer says the command pushes "nowhere else": a setting only the host's shell carries (a push URL,
    a receive program) can send it elsewhere, and the check reads the throwaway remote's refs only."""
    text = SKILL.read_text(encoding="utf-8")
    assert "nowhere else" not in text, text
    assert "only the refs of the throwaway remote" in text and "host's shell" in text, text
    prepared = _prepare(env, tmp_path)
    assert "only the refs of the throwaway remote" in prepared["note"], prepared
    shutil.rmtree(pathlib.Path(prepared["work"]).parent)
