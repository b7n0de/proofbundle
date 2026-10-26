"""D70, Nachtrag 28 (O26-2): a command wholly of the closed read forms of D66 names no program for D27 and D3 either.

Measured in Nachtrag 26 and again at 0efaf38d: `find … | xargs grep -l "git push"` asked with D27 (the safety net counts
the word git of the pattern) and `find … | xargs grep -l git` with D3 (the scan reads git after xargs as the program
xargs starts); under Codex both were denied. Measured with strace (truth_xargs_grep_n28.py of the delivery): such a
command starts find, xargs and grep and nothing else, a program named git or gh first on PATH included.

The rule: a command that is wholly of the closed read forms of _read_only_form gets no answer. Every other command keeps
its answer: xargs that runs git, find -exec, a grep pattern with a command substitution, a git push after the search.

RED at 0efaf38d (the head of Nachtrag 27): the read forms that name git or gh; the counter cases are controls, green at
both.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time

import pytest

import _gate_answer as ga
import test_plugin_gate_n2c_push_done as n2c

gate = n2c.gate
pytestmark = n2c.pytestmark
_clean_git_environment = n2c._clean_git_environment

FIND = "find /work/notes -name '*.md'"
#: Read forms whose words name git or gh: silent at the head under both hosts.
READS = [
    f'{FIND} | xargs grep -l "git push"',
    f"{FIND} | xargs grep -l git",
    f'{FIND} | xargs grep -l "gh pr create" 2>/dev/null',
    f"{FIND} -print0 | xargs -0 grep -l git",
    f"{FIND} | xargs -r grep -c 'git push --no-verify'",
    f"{FIND} | xargs --no-run-if-empty grep -n gh",
    f'{FIND} | xargs grep -l "git push" | while read f; do echo "$f $(grep -c "git push" "$f")"; done',
    f'{FIND} | xargs grep -l "git push" > /dev/null 2>&1; echo "gh pr merge"',
    f'{FIND} | xargs grep -l "core.hooksPath"',
    'echo "git push origin main"',
]
#: Keep their answer, asked at 0efaf38d and at the head under Claude Code (denied under Codex).
ASKS = [
    f"{FIND} | xargs git push",
    f"{FIND} | xargs -I{{}} git push {{}}",
    f"{FIND} -exec git push \\;",
    'grep "$(git push)" /work/notes/a.md',
    f"{FIND} | xargs sh -c 'git push'",
    f"{FIND} | xargs env git push",
    f'{FIND} | xargs grep -l "git push"; git push origin main',
    f"{FIND} | xargs grep -l git > /work/notes/list.txt",
    f"{FIND} | xargs grep -l git && git push",
    f"{FIND} | xargs gh pr create --fill",
]


@pytest.fixture
def repo(tmp_path):
    subprocess.run(["git", "init", "-q", "-b", "main", str(tmp_path / "r")], check=True, timeout=60)
    return tmp_path / "r"


def decided(repo, command, host):
    return gate.decide(command, str(repo), time.monotonic() + 60, host)


@pytest.mark.parametrize("host", ["claude", "codex"])
@pytest.mark.parametrize("command", READS)
def test_D70_a_read_form_that_names_git_or_gh_is_silent(repo, command, host):
    out = decided(repo, command, host)
    assert out is None, (command, out and [v.reason_id for v in out.verdicts])
    assert gate._read_only_form(command) is True, command


@pytest.mark.parametrize("host", ["claude", "codex"])
@pytest.mark.parametrize("command", ASKS)
def test_D70_control_every_other_command_keeps_its_answer(repo, command, host):
    out = decided(repo, command, host)
    assert out is not None and out.decision in ("ask", "deny"), (command, out and out.decision)
    assert gate._read_only_form(command) is False, command


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_D70_the_hook_as_the_host_runs_it(repo, tmp_path, host):
    """The whole hook path, `python -I gate --host <host>` with the event on stdin: the search of D70 gets no answer under
    either host."""
    event = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(repo),
                        "tool_input": {"command": READS[0]}})
    env = {"PATH": os.environ["PATH"], "HOME": str(tmp_path), "LANG": "C", "GIT_CONFIG_GLOBAL": "/dev/null",
           "GIT_CONFIG_SYSTEM": "/dev/null", "PROOFBUNDLE_GATE_DIR": str(tmp_path / "gatedir")}
    proc, entry = ga.run_hook([sys.executable, "-I", gate.__file__, "--host", host], event, env, cwd=str(repo))
    assert proc.returncode == 0, proc.stderr
    assert ga.parsed(proc, entry) is None
