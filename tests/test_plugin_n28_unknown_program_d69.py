"""D69, Nachtrag 28 (O27-1 C): a program word the line does not set asks before what Level 2 does not check.

Measured in Nachtrag 27, Teil b, at its head: `$GIT push origin main`, `"$GH" pr merge 1` and the other forms below got
no answer under either host. Level 2 catches such a push only where its pre-push hook is installed, and it was not at
delta (O23-2); `--no-verify` and `-c core.hooksPath=…` skip the hook (measured), and gh never runs it.

The rule: where the program word of a simple command holds a parameter expansion whose value the command line does not
set, and a later word of the same simple command is `push`, `--no-verify`, a word that names core.hooksPath, or two
words in a row that name a gh pair that writes (pr create, pr new, release create, release new, pr merge), the gate asks
under Claude Code and denies under Codex. Every other such command keeps its answer: the silent cases of D67, the two
test commands of Nachtrag 27 that hold such a program word, and `$GIT commit -am x`.

RED at 0efaf38d (the head of Nachtrag 27): the forms of Teil b word for word and the further spellings and positions;
the silent cases are controls, green at both. `${GIT} push origin main` asks at both (the safety net reads the name GIT
inside the braces as git).
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
import test_plugin_n27_program_variable_d67 as d67

gate = n2c.gate
pytestmark = n2c.pytestmark
_clean_git_environment = n2c._clean_git_environment

#: The forms of Teil b of Nachtrag 27 that D69 asks for, word for word, with the later word it names.
TEIL_B = [
    ("$GIT push origin main", "push"),
    ('"$GIT" push origin main', "push"),
    ("$GIT push --no-verify origin main", "push"),
    ("$GIT -c core.hooksPath=/dev/null push origin main", "core.hooksPath=/dev/null"),
    ("$GH pr merge 1", "pr merge"),
    ('"$GH" pr create --fill', "pr create"),
    ("$GH release create v1", "release create"),
    ("$1 push", "push"),
    ("${GIT:-git} push origin main", "push"),
]
#: Further spellings, positions and words.
FURTHER = [
    ('"$@" push origin main', "push"),
    ("$HOME/bin/tool push", "push"),
    ("$GIT -C /work/clone --no-verify", "--no-verify"),
    ("$GIT -c CORE.HOOKSPATH=/x commit -m x", "CORE.HOOKSPATH=/x"),
    ("$GH pr new --fill", "pr new"),
    ("$GH -R b7n0de/proofbundle release new v1", "release new"),
    ("true && $GIT push", "push"),
    ("if true; then $GIT push; fi", "push"),
    ('echo "$($GIT push origin main)"', "push"),
    ("$GIT push\n", "push"),
]
#: Keeps its answer, no answer at 0efaf38d and at the head under both hosts.
SILENT = d67.SILENT + [
    "$SUBCOMMAND --repo /work/clone",
    "$CMD -c proofbundle_gate.py /work/a.jsonl",
    "$GIT commit -am x",
    "$GIT reset --hard HEAD~1",
    "$GIT status",
    "$EDITOR push.md",
    "echo $GIT push",
    "$GIT $SUB origin main",
    "G=python3; $G push",
    "$GH pr view 1",
    "'$X' push",                     # in single quotes: a program named $X, no expansion
    "\\$X push origin main",          # an escaped dollar: the same
    '"$(printf tool)" push',          # a command substitution is no parameter expansion
    '"$(printf tool)" pr merge 1',
]


@pytest.fixture
def repo(tmp_path):
    subprocess.run(["git", "init", "-q", "-b", "main", str(tmp_path / "r")], check=True, timeout=60)
    return tmp_path / "r"


def decided(repo, command, host):
    return gate.decide(command, str(repo), time.monotonic() + 60, host)


@pytest.mark.parametrize("host", ["claude", "codex"])
@pytest.mark.parametrize("command, word", TEIL_B + FURTHER)
def test_D69_a_program_word_the_line_does_not_set_asks_before_what_level_2_does_not_check(repo, command, word, host):
    out = decided(repo, command, host)
    assert out is not None and out.decision in ("ask", "deny"), (command, out and out.decision)
    assert out.verdicts[-1].reason_id == "program_word_unknown", (command, [v.reason_id for v in out.verdicts])
    assert gate._unknown_program_word(command)[1] == word, command


@pytest.mark.parametrize("host", ["claude", "codex"])
@pytest.mark.parametrize("command", SILENT)
def test_D69_control_every_other_program_word_keeps_its_answer(repo, command, host):
    assert decided(repo, command, host) is None, command


@pytest.mark.parametrize("command", SILENT + ["'$GIT' push", "\\$GIT push", '"$(command -v git)" push'])
def test_D69_the_detector_finds_no_word_in_the_silent_cases(command):
    assert gate._unknown_program_word(command) is None, command


@pytest.mark.parametrize("command", ["${GIT} push origin main", "$GIT push origin main; git push origin main",
                                     "G=$(command -v git); $G push", "'$GIT' push", "\\$GIT push"])
def test_D69_a_command_that_asks_already_keeps_its_answer(repo, command):
    """Each asks at 0efaf38d already: `${GIT}` because the safety net reads the name GIT inside the braces as git, the
    second for its literal git push, the third for `command -v git` (D3), the two literal program words `$GIT` as a
    program the gate does not know whose name reads git (D33). D69 adds nothing to an ask."""
    out = decided(repo, command, "claude")
    assert out is not None and out.decision == "ask", command
    assert "program_word_unknown" not in [v.reason_id for v in out.verdicts], [v.reason_id for v in out.verdicts]


@pytest.mark.parametrize("host, expected", [("claude", "ask"), ("codex", "deny")])
@pytest.mark.parametrize("command", ["$GIT push origin main", '"$GH" pr merge 1'])
def test_D69_the_hook_as_the_host_runs_it(repo, tmp_path, command, host, expected):
    """The whole hook path, `python -I gate --host <host>` with the event on stdin: asked under Claude Code, denied under
    Codex, the short line naming D69 and the long reason the program word and the later word."""
    event = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(repo),
                        "tool_input": {"command": command}})
    env = {"PATH": os.environ["PATH"], "HOME": str(tmp_path), "LANG": "C", "GIT_CONFIG_GLOBAL": "/dev/null",
           "GIT_CONFIG_SYSTEM": "/dev/null", "PROOFBUNDLE_GATE_DIR": str(tmp_path / "gatedir")}
    proc, entry = ga.run_hook([sys.executable, "-I", gate.__file__, "--host", host], event, env, cwd=str(repo))
    answer = ga.parsed(proc, entry)
    assert proc.returncode == 0, proc.stderr
    assert answer["hookSpecificOutput"]["permissionDecision"] == expected, answer
    assert "(D69)" in ga.short_text(answer), answer
    assert "(DECISIONS.md D69)" in ga.long_text(answer), ga.long_text(answer)


def test_D69_the_pairs_are_what_the_decision_names():
    assert gate._UNKNOWN_PROGRAM_GH_PAIRS == {("pr", "create"), ("pr", "new"), ("release", "create"),
                                              ("release", "new"), ("pr", "merge")}
