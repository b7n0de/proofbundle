"""D67, Nachtrag 27 (O23-6, Teil a): a program word the same command line sets to git or gh is judged with its value.

Measured at 9f578c2a, ab14e1ae and 76dc0cfc (the head of Nachtrag 26): `CMD=git; $CMD push origin main` and `X=gh;
${X} pr merge 1` got no answer under either host; `export G=/usr/bin/git && "$G" push` asked only because the word
`G=/usr/bin/git` itself ends in git, with the answer of a git form (D3), never as the push it runs. Neither the scan nor
the safety net reads a parameter expansion at the program position as git or gh.

The rule: where a parameter expansion stands at the program position of a simple command (`$X`, `${X}`, `"$X"`,
`"${X}"`) and the same command line sets X to git or gh, by name or by a path ending in /git or /gh (an assignment word,
or an argument of export, declare, local or readonly), the gate judges the command with the value substituted. Every
expansion whose value is not git or gh, and every one the line does not set, keeps the answer it had: no answer for
`"$PYTHON" -m pytest`, `$EDITOR datei` and `"$SHELL" -c true`.

RED at 76dc0cfc: the cases of D67, each judged as its substituted command is (the three examples word for word among
them); the silent cases are controls, green at both.
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

#: The three examples of Nachtrag 27, word for word, with the command each is judged as.
EXAMPLES = [
    ("CMD=git; $CMD push origin main", "CMD=git; git push origin main"),
    ('export G=/usr/bin/git && "$G" push', "export G=/usr/bin/git && /usr/bin/git push"),
    ("X=gh; ${X} pr merge 1", "X=gh; gh pr merge 1"),
]

#: The four spellings, the path form, the declaration builtins and the positions a program word stands at.
FORMS = [
    ("CMD=git; ${CMD} push origin main", "CMD=git; git push origin main"),
    ('CMD=git; "$CMD" push origin main', "CMD=git; git push origin main"),
    ('CMD=git; "${CMD}" push origin main', "CMD=git; git push origin main"),
    ('X=gh; "$X" pr merge 1', "X=gh; gh pr merge 1"),
    ('X=gh; "${X}" pr create', "X=gh; gh pr create"),
    ("G=/usr/bin/git; $G push origin main", "G=/usr/bin/git; /usr/bin/git push origin main"),
    ('G="/usr/bin/gh"; "$G" pr merge 1', 'G="/usr/bin/gh"; /usr/bin/gh pr merge 1'),
    ("export G=git; $G push", "export G=git; git push"),
    ("declare G=git; $G push origin main", "declare G=git; git push origin main"),
    ("declare -x G=/usr/bin/git; $G push", "declare -x G=/usr/bin/git; /usr/bin/git push"),
    ("readonly G=gh; $G pr merge 1", "readonly G=gh; gh pr merge 1"),
    ("f() { local G=git; $G push origin main; }; f", "f() { local G=git; git push origin main; }; f"),
    ("CMD=git; $CMD status", "CMD=git; git status"),
    ("G=git && $G push origin main", "G=git && git push origin main"),
    ("G=git\n$G push origin main", "G=git\ngit push origin main"),
    ("G=git; if true; then $G push; fi", "G=git; if true; then git push; fi"),
    ("G=git; ( $G push )", "G=git; ( git push )"),
    ("G=git; { $G push; }", "G=git; { git push; }"),
    ("G=git; echo $($G push)", "G=git; echo $(git push)"),
    ('G=git; echo "$($G push origin main)"', 'G=git; echo "$(git push origin main)"'),
    ("echo $(G=gh; $G pr merge 1)", "echo $(G=gh; gh pr merge 1)"),
    ('G="git push"; $G origin main', 'G="git push"; git push origin main'),
    ("G=git-push; $G origin main", "G=git-push; git-push origin main"),
    ("G=git; $G -C /tmp push", "G=git; git -C /tmp push"),
]

#: Program words the line does not set to git or gh: no answer at the base, none at the head (under both hosts).
SILENT = [
    '"$PYTHON" -m pytest',
    "$EDITOR datei",
    '"$SHELL" -c true',
    'PYTHON=python3; "$PYTHON" -m pytest',
    "EDITOR=vim; $EDITOR datei",
    'SHELL=/bin/bash; "$SHELL" -c true',
    "GIT=python3; $GIT -m pytest",
    "G=gitk; $G",
    "G=/usr/bin/git2; $G status",
    "G=git; echo $G",
    'G=git; echo "$G push"',
    'X=gh; printf "%s\\n" "$X"',
    'G=git; ls "$G"',
    'G="git push"; "$G" origin main',
]


@pytest.fixture
def repo(tmp_path):
    subprocess.run(["git", "init", "-q", "-b", "main", str(tmp_path / "r")], check=True, timeout=60)
    return tmp_path / "r"


def judged(repo, command, host):
    out = gate.decide(command, str(repo), time.monotonic() + 60, host)
    return None if out is None else (out.decision, [v.reason_id for v in out.verdicts])


@pytest.mark.parametrize("host", ["claude", "codex"])
@pytest.mark.parametrize("command, substituted", EXAMPLES + FORMS)
def test_D67_a_program_variable_set_to_git_or_gh_is_judged_with_its_value(repo, command, substituted, host):
    expected = judged(repo, substituted, host)
    assert expected is not None and expected[0] in ("ask", "deny"), (substituted, expected)
    out = gate.decide(command, str(repo), time.monotonic() + 60, host)
    assert out is not None and (out.decision, [v.reason_id for v in out.verdicts]) == expected, (command, out and [
        v.reason_id for v in out.verdicts], expected)
    assert "(DECISIONS.md D67)" in out.text, out.text


@pytest.mark.parametrize("host", ["claude", "codex"])
@pytest.mark.parametrize("command", SILENT)
def test_D67_control_a_program_word_the_line_does_not_set_to_git_or_gh_keeps_no_answer(repo, command, host):
    assert judged(repo, command, host) is None, command


@pytest.mark.parametrize("command, substituted", EXAMPLES + FORMS)
def test_D67_the_text_the_gate_judges(command, substituted):
    assert gate._program_values(command) == substituted, command


@pytest.mark.parametrize("command", SILENT + [
    "$GIT push",                            # Teil b: the line does not set GIT
    "G=$(command -v git); $G push",         # Teil b: a value the shell builds
    "${G:-git} push",                       # Teil b: a spelling outside the four
    "G=git; sudo $G push",                  # behind a wrapper: the net's answer (D33) stays
    "G=git; cat <<< $G",                    # a here-string is data
    "G=git; echo \\$G push",                # an escaped dollar is no expansion
    "G=git; echo '$G push'",                # nor one in single quotes
])
def test_D67_the_text_stays_as_it_is(command):
    assert gate._program_values(command) == command, command


def test_D67_a_path_value_with_a_blank_stays_one_word():
    assert gate._program_values('G="/opt/my tools/git"; "$G" push') == \
        "G=\"/opt/my tools/git\"; '/opt/my tools/git' push"


@pytest.mark.parametrize("host, expected", [("claude", "ask"), ("codex", "deny")])
@pytest.mark.parametrize("command, substituted", EXAMPLES)
def test_D67_the_hook_as_the_host_runs_it(repo, tmp_path, command, substituted, host, expected):
    """The whole hook path, `python -I gate --host <host>` with the event on stdin: each example of Nachtrag 27 is asked
    under Claude Code and denied under Codex, the long reason says the program word was read with its value, and the
    log names the gated calls of the substituted command."""
    event = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(repo),
                        "tool_input": {"command": command}})
    env = {"PATH": os.environ["PATH"], "HOME": str(tmp_path), "LANG": "C", "GIT_CONFIG_GLOBAL": "/dev/null",
           "GIT_CONFIG_SYSTEM": "/dev/null", "PROOFBUNDLE_GATE_DIR": str(tmp_path / "gatedir")}
    proc, entry = ga.run_hook([sys.executable, "-I", gate.__file__, "--host", host], event, env, cwd=str(repo))
    answer = ga.parsed(proc, entry)
    assert proc.returncode == 0, proc.stderr
    assert answer["hookSpecificOutput"]["permissionDecision"] == expected, answer
    assert "(DECISIONS.md D67)" in ga.long_text(answer), ga.long_text(answer)
    assert entry["actions"] == sorted({name for name, _d, _x in gate.gated_calls(substituted)}), entry


def test_D67_the_closed_sets_are_what_the_decision_names():
    assert gate._DECLARATION_BUILTINS == {"export", "declare", "typeset", "local", "readonly"}
    assert gate._PROGRAM_POSITION_KEYWORDS == {"!", "if", "then", "else", "elif", "while", "until", "do", "time"}
    assert [bool(gate._PROGRAM_EXPANSION.fullmatch(w)) for w in ("$X", "${X}", '"$X"', '"${X}"', '"$X', "$X\"",
                                                                 "${X:-git}", "$1", "x$X", "$X/git")] == \
        [True, True, True, True, False, False, False, False, False, False]
