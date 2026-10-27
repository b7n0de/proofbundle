"""The version of the git on PATH, for a test whose measurement needs what an older git does not have.

Follow-up note 40, point 2: the operator's machine runs git 2.34.1, the plugin tests were measured with git 2.43.0. git 2.36 added
`fsmonitor--daemon`, git 2.38 `merge-tree --write-tree`, git 2.42 the variables GIT_CONFIG_GLOBAL, GIT_CONFIG_SYSTEM,
GIT_ATTR_SYSTEM and GIT_ATTR_GLOBAL of `git var`. On an older git the gate cannot read what such a test expects it to
read and keeps the stricter answer; the test then names the version it needs instead of failing.
"""
from __future__ import annotations

import re
import shutil
import subprocess

import pytest


def git_version() -> tuple[int, ...]:
    """(major, minor, patch) of `git --version` of the git on PATH; (0,) where there is none or no number."""
    git = shutil.which("git")
    if git is None:
        return (0,)
    out = subprocess.run([git, "--version"], capture_output=True, text=True, check=False, timeout=60).stdout
    m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", out)
    return tuple(int(x) for x in m.groups() if x is not None) if m else (0,)


def needs_git(major: int, minor: int, what: str):
    """A skip mark for a git older than major.minor, with what the test needs from that version."""
    return pytest.mark.skipif(git_version() < (major, minor),
                              reason=f"needs git {major}.{minor} or later ({what}); git on PATH is "
                                     f"{'.'.join(map(str, git_version()))}")
