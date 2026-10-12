"""Review round 11 of 2026-10-12, on mutant M4 of the FIX-10 report: every hook entry counts, executable or not.

The FIX-10 report called M4 ("only executable hooks count") equivalent, since git runs only executable hooks. The review
keeps the reading that every entry at a receive hook's name is refused, so M4 is not equivalent against this contract,
and a catch case must hold it: a hook that is present but not executable, and a link that leads nowhere, are refused
like an executable one.
"""
from __future__ import annotations

import os
import pathlib

import pytest

import test_plugin_gate_log as gl
import test_plugin_review_fix11_r1_receiver_environment as e1

pytestmark = gl.pytestmark
env = gl.env
_clean_git_config = gl._clean_git_config


@pytest.mark.parametrize("shape", ["not executable", "dangling link"])
def test_a_present_receive_hook_git_would_not_run_is_refused_too(env, tmp_path, shape):
    folder = tmp_path / "hk"
    folder.mkdir()
    if shape == "not executable":
        (folder / "post-receive").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        (folder / "post-receive").chmod(0o644)
        assert not os.access(folder / "post-receive", os.X_OK)
    else:
        (folder / "post-receive").symlink_to(tmp_path / "nowhere")
        assert not os.path.exists(folder / "post-receive")
    home = e1._home(tmp_path, f"[core]\n\thooksPath = {folder}\n")
    e1._refused(e1.chain(env, tmp_path, HOME=str(home), GIT_CONFIG_GLOBAL=None), tmp_path)
