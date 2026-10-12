"""Review round 11 of 2026-10-12, R11-2: prepare checks exactly the hooks folder git chooses.

Measured by the reviewer at 3bbbf66f: an isolated HOME whose global configuration reads [core] hooksPath = "/absolute/hk "
with a trailing space; only that folder exists, with the post-receive that moves each ref back. git took the folder
with the space, prepare stripped the space with str.strip() and looked into a folder that does not exist, handed out the
command, and after the gate's deny, the push run anyway (exit 0) and the hook's reset, the check said "Expected denial
logged; test target unchanged." A trailing tab the same.

Property: the folder prepare checks is the folder git names, with every character of its path; only the line end of
git's answer is removed, and an answer that is not one line is not read as a folder. Each catch case runs the whole
chain where prepare hands out the command. Red against 0d69f996.
"""
from __future__ import annotations

import os
import pathlib
import subprocess

import pytest

import test_plugin_gate_log as gl
import test_plugin_review_fix10_r1_selftest_receiver as r1
import test_plugin_review_fix11_r1_receiver_environment as e1

pytestmark = gl.pytestmark
env = gl.env
_clean_git_config = gl._clean_git_config


def _quoted_home(tmp_path: pathlib.Path, folder: pathlib.Path) -> pathlib.Path:
    """A HOME whose core.hooksPath names `folder` exactly, quoted, with a newline written as \\n."""
    value = str(folder).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\t", "\\t")
    return e1._home(tmp_path, f'[core]\n\thooksPath = "{value}"\n')


@pytest.mark.parametrize("tail", [" ", "\t"])
def test_git_takes_the_hooks_folder_with_its_trailing_blank(tmp_path, tail):
    """Non-vacuous: the push exits 0, the hook of the folder with the trailing blank runs and moves main back."""
    work, bare = r1._pair(tmp_path)
    log = tmp_path / "hook.log"
    home = _quoted_home(tmp_path, e1._reset_hooks(tmp_path / f"hk{tail}", log))
    before = r1._main(bare)
    environ = {k: v for k, v in os.environ.items() if k != "GIT_CONFIG_GLOBAL"}
    push = subprocess.run(["git", "-C", str(work), "push", "-q", "origin", "main"], capture_output=True, text=True,
                          env=dict(environ, HOME=str(home)), timeout=60, check=False)
    assert push.returncode == 0, push.stderr
    assert r1._main(bare) == before and log.exists()


@pytest.mark.parametrize("tail", [" ", "\t", "  ", " \t"])
def test_a_hooks_folder_whose_name_ends_in_a_blank_is_checked_as_git_names_it(env, tmp_path, tail):
    home = _quoted_home(tmp_path, e1._reset_hooks(tmp_path / f"hk{tail}", tmp_path / "hook.log"))
    e1._refused(e1.chain(env, tmp_path, HOME=str(home), GIT_CONFIG_GLOBAL=None), tmp_path)


def test_a_hooks_folder_whose_name_holds_a_line_break_is_not_measurable(env, tmp_path):
    home = _quoted_home(tmp_path, e1._reset_hooks(tmp_path / "hk\nx", tmp_path / "hook.log"))
    e1._refused(e1.chain(env, tmp_path, HOME=str(home), GIT_CONFIG_GLOBAL=None), tmp_path)


def test_control_a_folder_with_a_trailing_blank_and_client_hooks_only_is_measurable(env, tmp_path):
    folder = tmp_path / "hk "
    folder.mkdir()
    (folder / "pre-push").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    (folder / "pre-push").chmod(0o755)
    outcome = e1.chain(env, tmp_path, HOME=str(_quoted_home(tmp_path, folder)), GIT_CONFIG_GLOBAL=None)
    assert "refused" not in outcome and outcome["target_changed"] is True, outcome
