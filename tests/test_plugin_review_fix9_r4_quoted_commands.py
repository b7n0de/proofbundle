"""Review round 9 of 2026-10-11, R9-4: a command the answer suggests quotes every argument whole.

Measured by the reviewer at b288ee66: the standard rule only, `git remote rename origin "o'brien"`, the hook for `git
push "o'brien" main`. The suggested `git fetch o'brien` fails under `bash -n` with exit 2, and remote.<name>.fetch and
the refspec were not quoted whole either. Property: every argument of a suggested command is quoted whole, so the
command parses and names the remote as one word. Red against b288ee66. Since R9-1 the answer offers no fetch rule as a
repair, so the answer case holds with no command naming the remote; the builder case carries the property.
"""
from __future__ import annotations

import json
import re
import shlex
import subprocess

import test_plugin_gate_n2c_push_done as n2c

pytestmark = n2c.pytestmark
env = n2c.env
_clean_git_environment = n2c._clean_git_environment
_git = n2c._git
gate = n2c.gate

NAME = "o'brien"


def _parses(command: str) -> bool:
    return subprocess.run(["bash", "-n", "-c", command], capture_output=True, timeout=30).returncode == 0


def test_every_command_in_the_answer_parses_and_names_the_remote_whole(env, tmp_path):
    r = n2c.Repo(tmp_path)
    r.make("valid")
    _git(r.path, "config", "--replace-all", "remote.origin.fetch", "+refs/heads/*:refs/remotes/origin/*")
    _git(r.path, "remote", "rename", "origin", NAME)
    answer, _entry = n2c._level1(env, r.path, command="git push \"o'brien\" main")
    text = answer.get("systemMessage", "") + json.dumps(answer.get("hookSpecificOutput", {}), ensure_ascii=False)
    for command in re.findall(r"`([^`]+)`", answer.get("systemMessage", "")):
        assert _parses(command), command
        words = shlex.split(command)
        if any("brien" in w for w in words):
            assert any(NAME in w for w in words) and not any(w in ("o", "brien") for w in words), words
    assert text


def test_the_command_builder_quotes_every_word_whole():
    for words in (["git", "fetch", NAME], ["git", "config", "--add", f"remote.{NAME}.fetch",
                                            f"+refs/tags/*:refs/recorded/{NAME}/tags/*"],
                  ["git", "checkout", "0123456789ab"], ["printf", "%s", "a b", "$HOME", "`x`", "c;d"]):
        command = gate._shell_command(*words)
        assert _parses(command), command
        assert shlex.split(command) == words, command
