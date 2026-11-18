"""Review round 11 of 2026-10-12, R11-1 and R11-2: the two cautious refusals the mutation probe found unpinned.

Measured here at 6ed084f6 with git 2.43.0: two mutants of the self-test's hooks check survived every self-test case
(70 cases in eight files). One asks the hooks folder only in the environment git gives a local receive-pack, not also in
the server's; the other reads an answer of git that spans more than one line as one folder. Neither changes what the
receiver runs, each gives up a refusal the review round kept.

Properties: a hooks folder named only through the environment's configuration (GIT_CONFIG_COUNT or
GIT_CONFIG_PARAMETERS), which a local receive-pack does not read, is refused all the same where it holds a receive hook
(the owner's word of 2026-10-12: the cautious refusal through GIT_CONFIG_COUNT stays); and an answer of git that is not
one line names no folder, so prepare refuses it even where the folder holds no hook. Each case runs the whole chain where
prepare hands out the command.
"""
from __future__ import annotations

import os
import subprocess

import pytest

import test_plugin_gate_log as gl
import test_plugin_review_fix10_r1_selftest_receiver as r1
import test_plugin_review_fix11_r1_receiver_environment as e1
import test_plugin_review_fix11_r2_hooks_path_text as e2
from _plugin_env import plugin_env

pytestmark = gl.pytestmark
env = gl.env
_clean_git_config = gl._clean_git_config


def test_git_gives_a_local_receive_pack_no_hooks_folder_from_the_environment(tmp_path):
    """Non-vacuous: with core.hooksPath only in GIT_CONFIG_COUNT, naming a folder with the post-receive that moves each
    ref back, the push exits 0, the hook does not run and main moves."""
    work, bare = r1._pair(tmp_path)
    log = tmp_path / "hook.log"
    hooks = e1._reset_hooks(tmp_path / "hk", log)
    before = r1._main(bare)
    push = subprocess.run(["git", "-C", str(work), "push", "-q", "origin", "main"], capture_output=True, text=True,
                          env=plugin_env(GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="core.hooksPath",
                                   GIT_CONFIG_VALUE_0=str(hooks)), timeout=60, check=False)
    assert push.returncode == 0, push.stderr
    assert r1._main(bare) != before and not log.exists()


@pytest.mark.parametrize("carrier", ["GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS"])
def test_a_receive_hook_named_only_through_the_environment_is_refused_all_the_same(env, tmp_path, carrier):
    hooks = str(e1._reset_hooks(tmp_path / "hk", tmp_path / "hook.log"))
    names = ({"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.hooksPath", "GIT_CONFIG_VALUE_0": hooks}
             if carrier == "GIT_CONFIG_COUNT" else {"GIT_CONFIG_PARAMETERS": f"'core.hooksPath'='{hooks}'"})
    e1._refused(e1.chain(env, tmp_path, **names), tmp_path)


def test_git_names_a_hooks_folder_with_a_line_break_over_two_lines(tmp_path):
    """Non-vacuous: git's answer for a folder whose name holds a line break spans two lines."""
    _work, bare = r1._pair(tmp_path)
    folder = tmp_path / "hk\nx"
    folder.mkdir()
    home = e2._quoted_home(tmp_path, folder)
    environ = plugin_env(without=("GIT_CONFIG_GLOBAL",))
    answer = subprocess.run(["git", "-C", str(bare), "rev-parse", "--path-format=absolute", "--git-path", "hooks"],
                            capture_output=True, env=dict(environ, HOME=str(home)), timeout=60, check=True).stdout
    assert answer == os.fsencode(folder) + b"\n" and answer.count(b"\n") == 2


def test_a_hooks_folder_with_a_line_break_is_refused_without_a_hook_in_it(env, tmp_path):
    folder = tmp_path / "hk\nx"
    folder.mkdir()
    home = e2._quoted_home(tmp_path, folder)
    e1._refused(e1.chain(env, tmp_path, HOME=str(home), GIT_CONFIG_GLOBAL=None), tmp_path)


def test_control_an_empty_hooks_folder_on_one_line_is_measurable(env, tmp_path):
    folder = tmp_path / "hk"
    folder.mkdir()
    home = e2._quoted_home(tmp_path, folder)
    outcome = e1.chain(env, tmp_path, HOME=str(home), GIT_CONFIG_GLOBAL=None)
    assert "refused" not in outcome and outcome["target_changed"] is True, outcome
