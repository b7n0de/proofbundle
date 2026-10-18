"""D77, Ergänzung 1 to Nachtrag 31 (O26-1): head, tail, ls, date, sleep, wc and the shell's test command `[` in a chain
that only reads name no program for D27, D3 and D38 under Claude Code.

Owner choice O26-1 of 2026-10-18, 16:4x Berlin: head, tail, ls, sort, date, `[`, sleep and wc become free in a chain that
only reads, each after a measurement with strace; cd does not. Measured with GNU coreutils 9.4 and bash 5.2.21 under
strace -f in bash -c (truth_readprog_e1.py of the delivery, 336 runs under four sources): each started only itself
(`[` nothing, a builtin), opened no file for writing but /dev/null, made no socket but the lookup of a user name over the
local socket of nscd (ls -l), wrote no file, and started no git or gh first on PATH. sort wrote temporary files of its
own from a pipe of 0.8 MB on (truth_sort_temp_e1.sh), so it is not among them (owner question O31E1-1).

The rule: under Claude Code a command wholly of the closed read forms of D66 and of D77 gets no answer, where each read
program of D77 it starts is GNU coreutils of a measured version on a PATH of absolute entries. Each program has a closed
list of switches; every other switch, a word the shell builds, an output into a file, a program beside them that writes,
a wrapper other than xargs, and the same command under Codex keep their answer.

RED at 0c4e10e8 (the head of Nachtrag 31 before Ergänzung 1): the free chains under Claude Code and the unit rows of the
new grammar. The counter cases and the answers under Codex are controls, green at both. No case reaches a network.
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

SEARCH = "find src | xargs grep -l 'git push'"
#: Chains of the read programs that name git or gh: asked at 0c4e10e8 under Claude Code, silent at the head. At least
#: three spellings per program.
FREE = [
    f"head -5 README.md; {SEARCH}", f"head -n 3 README.md && {SEARCH}", f"head --lines=2 -q README.md; {SEARCH}",
    f"head -c10 README.md || {SEARCH}",
    f"tail -n 3 README.md; {SEARCH}", f"tail -2 README.md && {SEARCH}", f"tail --bytes 5 README.md; {SEARCH}",
    f"ls -la; {SEARCH}", f"ls -1 src && {SEARCH}", f"ls --color=never -R src; {SEARCH}", f"ls -lh -- src; {SEARCH}",
    f"date -u +%F; {SEARCH}", f"date -I && {SEARCH}", f"date --iso-8601=seconds; {SEARCH}",
    f"date -d yesterday +%s; {SEARCH}",
    f"sleep 0; {SEARCH}", f"sleep 0.1 && {SEARCH}", f"sleep 1s; {SEARCH}",
    f"wc -l README.md; {SEARCH}", f"wc -lw README.md && {SEARCH}", f"wc --chars README.md; {SEARCH}",
    "[ -f README.md ] && echo gh", "[ -n git ] && echo ja", "[ -d .git ] || echo gh fehlt",
    "if [ -e .git/hooks/pre-push ]; then echo gh; else echo fehlt; fi",
    "find src | xargs head -1 | grep git", "grep -rl 'git push' src | xargs wc -l",
    "grep -rl 'git push' src | xargs ls -l", "grep -rl 'gh pr' src | xargs -r head -n 2",
    "[ -d .git ] && ls -la .git/hooks | head -3 && echo gh",
    f"ls -la .git/hooks 2>/dev/null | wc -l; {SEARCH} 2>&1",
]
#: Counter cases: each asks at 0c4e10e8 and at the head under Claude Code (an excluded switch, an output into a file, a
#: program beside them that writes or is not in the set, a wrapper, a word the shell builds, git itself).
KEEP = [
    f"sort README.md; {SEARCH}", f"sort -o out.txt README.md; {SEARCH}", f"tail -f README.md; {SEARCH}",
    f"tail -F README.md; {SEARCH}", f"tail --follow README.md; {SEARCH}", f"tail -5f README.md; {SEARCH}",
    f"tail +5f README.md; {SEARCH}", f"tail --pid=1 README.md; {SEARCH}", f"date -s 2020-01-01; {SEARCH}",
    f"date --set=2020-01-01; {SEARCH}", f"date 01011200; {SEARCH}", f"date -f dates.txt; {SEARCH}",
    f"date -I seconds; {SEARCH}", f"head --unknown README.md; {SEARCH}", f"wc --files0-from=list README.md; {SEARCH}",
    f"ls --dired; {SEARCH}", f"sleep infinity; {SEARCH}", f"sleep $T; {SEARCH}", f"head -n $N README.md; {SEARCH}",
    f"wc -l *.md; {SEARCH}", f"head -5 README.md > out.txt; {SEARCH}", f"ls | tee out.txt; {SEARCH}",
    f"head -5 README.md >> out.txt; {SEARCH}", f"cd src; {SEARCH}", f"rm -f out.txt; {SEARCH}",
    f"timeout 5 head README.md; {SEARCH}", f"env head README.md; {SEARCH}", f"command head README.md; {SEARCH}",
    f"$P -5 README.md; {SEARCH}", f"head -5 README.md & {SEARCH}", f"( head -5 README.md ); {SEARCH}",
    "find src | xargs tail -f | grep git", "find src | xargs sort | grep git", "find src | xargs date | grep gh",
    "find src | xargs -I{} head {} | grep git",
    "[ -f README.md ] && git push", "if [ -f README.md ]; then git push origin main; fi",
    '[ -n "$(git status --porcelain)" ] && echo gh', "[ -f README.md && echo gh", "[[ -f README.md ]] && echo gh",
    f"! head -5 README.md; {SEARCH}",
]


@pytest.fixture
def repo(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", "/usr/local/bin:/usr/bin:/bin")
    subprocess.run(["git", "init", "-q", "-b", "main", str(tmp_path / "r")], check=True, timeout=60)
    (tmp_path / "r" / "README.md").write_text("git push\n")
    return tmp_path / "r"


def decided(repo, command, host="claude"):
    return gate.decide(command, str(repo), time.monotonic() + 60, host)


def shown(out):
    return None if out is None else (out.decision, [v.reason_id for v in out.verdicts])


@pytest.mark.parametrize("command", FREE)
def test_D77_a_chain_of_read_programs_is_silent_under_claude_code(repo, command):
    assert decided(repo, command) is None, (command, shown(decided(repo, command)))


@pytest.mark.parametrize("command", FREE)
def test_D77_control_under_codex_the_chain_keeps_its_answer(repo, command):
    out = decided(repo, command, "codex")
    assert out is not None and out.decision in ("ask", "deny"), (command, shown(out))


@pytest.mark.parametrize("command", KEEP)
def test_D77_control_every_other_chain_keeps_its_answer(repo, command):
    out = decided(repo, command)
    assert out is not None and out.decision in ("ask", "deny"), (command, shown(out))


def _fake(folder, name, text, code=0):
    folder.mkdir(exist_ok=True)
    program = folder / name
    program.write_text(f"#!/bin/sh\nprintf '%s\\n' '{text}'\nexit {code}\n")
    program.chmod(0o755)


@pytest.mark.parametrize("line, code", [("head (GNU coreutils) 8.32", 0), ("head (GNU coreutils) 9.5", 0),
                                        ("usage: head [-n lines | -c bytes] [file ...]", 1),
                                        ("head (BusyBox) 1.36", 0), ("head (GNU coreutils) 9.4", 1)])
def test_D77_a_read_program_of_a_version_not_measured_keeps_the_answer(repo, tmp_path, monkeypatch, line, code):
    """NOT MEASURED: another version of GNU coreutils, BSD head, BusyBox, or a head that names 9.4 and fails."""
    _fake(tmp_path / "bin", "head", line, code)
    monkeypatch.setenv("PATH", f"{tmp_path / 'bin'}:/usr/local/bin:/usr/bin:/bin")
    out = decided(repo, f"head -5 README.md; {SEARCH}")
    assert out is not None and out.decision == "ask", shown(out)


def test_D77_the_version_is_read_from_the_program_on_path(repo, tmp_path, monkeypatch):
    """A head that names the measured version first on PATH counts as measured: the check shows a version, not an
    origin (as for gh, D27). The same for a read program the chain does not start: it is not asked."""
    _fake(tmp_path / "bin", "head", "head (GNU coreutils) 9.4")
    _fake(tmp_path / "bin", "tail", "tail (GNU coreutils) 1.0")
    monkeypatch.setenv("PATH", f"{tmp_path / 'bin'}:/usr/local/bin:/usr/bin:/bin")
    assert decided(repo, f"head -5 README.md; {SEARCH}") is None
    assert decided(repo, f"tail -5 README.md; {SEARCH}").decision == "ask"


@pytest.mark.parametrize("path", ["bin:/usr/bin:/bin", ":/usr/bin:/bin", "/usr/bin:/proc/self/cwd"])
def test_D77_a_path_that_depends_on_the_process_keeps_the_answer(repo, monkeypatch, path):
    monkeypatch.setenv("PATH", path)
    out = decided(repo, f"head -5 README.md; {SEARCH}")
    assert out is not None and out.decision == "ask", shown(out)


def test_D77_the_bracket_test_needs_no_version(repo, tmp_path, monkeypatch):
    """`[` is the shell's builtin (no execve, measured): a `[` program on PATH is never asked for its version."""
    _fake(tmp_path / "bin", "[", "[ (GNU coreutils) 1.0", 1)
    monkeypatch.setenv("PATH", f"{tmp_path / 'bin'}:/usr/local/bin:/usr/bin:/bin")
    assert decided(repo, "[ -f README.md ] && echo gh") is None


@pytest.mark.parametrize("name, args, free", [
    ("head", ["-5", "f"], True), ("head", ["-n", "5"], True), ("head", ["-n5", "-qv", "f"], True),
    ("head", ["--lines", "5", "f"], True), ("head", ["--lines"], False), ("head", ["-n"], False),
    ("head", ["-5c", "f"], False), ("head", ["--lines5"], False), ("head", ["--quiet=1"], False),
    ("tail", ["-n", "+5", "f"], True), ("tail", ["+5", "f"], False), ("tail", ["-5f"], False),
    ("tail", ["-f"], False), ("tail", ["-qf"], False), ("tail", ["--follow=name"], False), ("tail", ["-s", "1"], False),
    ("tail", ["--", "-f"], True), ("tail", ["--", "+5f"], False),
    ("ls", ["-la", "--color=never", "--sort=time", "src"], True), ("ls", ["--color"], True),
    ("ls", ["-w", "80"], True), ("ls", ["-w"], False), ("ls", ["--dired"], False), ("ls", ["-D"], False),
    ("ls", ["--hyperlink"], False), ("ls", ["--zero"], False),
    ("date", [], True), ("date", ["+%F"], True), ("date", ["-u", "+%F"], True), ("date", ["-Iseconds"], True),
    ("date", ["--iso-8601"], True), ("date", ["--iso-8601", "--set=x"], False), ("date", ["-d", "-1 day"], True),
    ("date", ["-s", "x"], False), ("date", ["--set", "x"], False), ("date", ["0101"], False),
    ("date", ["+%F", "+%s"], False), ("date", ["-f", "x"], False), ("date", ["--file=x"], False),
    ("date", ["--", "0101"], False), ("date", ["-I", "x"], False),
    ("sleep", ["1"], True), ("sleep", ["0.5", "2m"], True), ("sleep", [".5s"], True), ("sleep", [], False),
    ("sleep", ["infinity"], False), ("sleep", ["inf"], False), ("sleep", ["-1"], False), ("sleep", ["1x"], False),
    ("wc", ["-l"], True), ("wc", ["-lwcmL", "f"], True), ("wc", ["--total=never"], False), ("wc", ["-x"], False),
])
def test_D77_the_closed_grammar_of_each_read_program(name, args, free):
    assert gate._read_program_args(name, [(a, False, a) for a in args]) is free, (name, args)


def test_D77_a_word_the_shell_builds_is_no_word_of_the_grammar():
    assert gate._read_program_args("head", [("-5", False, "-5"), ("$F", True, "$F")]) is False
    assert gate._read_program_args("wc", [("*.md", False, "*.md")]) is False


def test_D77_the_closed_sets_are_what_the_decision_names():
    assert set(gate._READ_PROGRAMS) == {"head", "tail", "ls", "date", "sleep", "wc"}
    assert gate._READ_XARGS_PROGRAMS == {"head", "ls", "wc"}
    assert gate._READ_PROGRAM_VERSIONS == {"9.4"}
    assert gate._READ_D77_KEYWORDS == {"if", "then", "elif", "else", "fi"}
    assert gate._READ_D77_LISTS == {"&&", "||"}
    assert gate._READ_ONLY_KEYWORDS == {"while", "do", "done"}


@pytest.mark.parametrize("host, expected", [("claude", None), ("codex", "deny")])
def test_D77_a_read_chain_that_names_a_done_order_change(repo, tmp_path, host, expected):
    """D38 as D66 reads it: the gate's script named as a pattern of grep is read, not run, beside a read program of D77
    under Claude Code; Codex denies as before."""
    command = "head -3 README.md; find . -name '*.jsonl' | xargs grep -l proofbundle_gate.py"
    out = decided(repo, command, host)
    if expected is None:
        assert out is None, shown(out)
    else:
        event = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(repo),
                 "tool_input": {"command": command}}
        assert out is not None and "done_order_change" in shown(out)[1], shown(out)
        printed = gate.pre_tool_answer(out, host, event, gate._step_of_event(event), {})
        assert printed["hookSpecificOutput"]["permissionDecision"] == expected, printed


@pytest.mark.parametrize("host, silent", [("claude", True), ("codex", False)])
def test_D77_the_hook_as_the_host_runs_it(repo, tmp_path, host, silent):
    """The whole hook path, `python -I gate --host <host>` with the event on stdin."""
    event = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(repo),
                        "tool_input": {"command": "[ -d .git ] && ls -la .git/hooks | head -3 && echo gh"}})
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(tmp_path), "LANG": "C",
           "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null",
           "PROOFBUNDLE_GATE_DIR": str(tmp_path / "gatedir")}
    proc, entry = ga.run_hook([sys.executable, "-I", gate.__file__, "--host", host], event, env, cwd=str(repo))
    assert proc.returncode == 0, proc.stderr
    assert (ga.parsed(proc, entry) is None) is silent, ga.parsed(proc, entry)
