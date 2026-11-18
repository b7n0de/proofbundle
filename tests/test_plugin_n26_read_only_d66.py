"""D66, follow-up note 26: a command whose every program only reads calls no done-order, so D38 does not ask for it.

Measured on account A on 2026-10-17, 20:54Z (gate at 9f578c2a), and again at 3694e34e: a find over a session folder,
`xargs grep -l "proofbundle_gate.py"` and a while loop that counts with `grep -c proofbundle_gate.py "$f"` asked with
D38, "the command changes a local done order", under Codex it was denied. The cause: _done_order_run reads every word
named proofbundle_gate.py as the gate's script, wherever it stands in a run; in `grep -c proofbundle_gate.py "$f"` the
word after it, `"$f"`, is one the shell builds, which D38 answers as a done-order call it cannot read whole (owner
choice O2 of follow-up note 13). The path under ~/.claude-*/projects plays no part.

The rule: a command that is wholly of the closed read forms of _read_only_form (find without -delete, -exec, -execdir,
-ok, -okdir, -fprint, -fprint0, -fprintf and -fls; xargs that runs grep; grep; read and echo; a while loop around them;
a pipe or a list; output only to /dev/null or onto another descriptor; every command substitution of the same kind)
runs no done-order, whatever words it names. Every other command is read as before: the same command that writes a
file, under ~/.claude-* or anywhere, removes, moves, edits in place, tees, or runs a program through -exec or xargs that
is not grep, asks with D38 as it did. Local writes the gate never asked for (`rm`, `xargs rm`, `find -delete` on their
own) stay as they were; nothing is freed.

RED at 3694e34e (the head of the quick round): the read forms that name the gate's script; the writing forms and the
done-order calls are controls, green at both.
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

D = "/home/konrad/.claude-deltaxx/projects/-home-konrad-workrepo/2ebe4050-e3e2-46e4-b533-e7025f29980a"
FIND = f"find {D} -name '*.jsonl'"
GREP = 'xargs grep -l "proofbundle_gate.py" 2>/dev/null'
LOOP = 'while read f; do echo "$f $(grep -c proofbundle_gate.py "$f")"; done'
#: The command of account A, word for word.
DELTA = f"{FIND} | {GREP} | {LOOP}"
G = "/home/konrad/.claude/plugins/proofbundle/hooks/proofbundle_gate.py"

READS = [
    DELTA,
    f"{FIND} | xargs grep -l proofbundle_gate.py | {LOOP}",
    f"{FIND} -print0 | xargs -0 grep -l proofbundle_gate.py 2>/dev/null | {LOOP}",
    f"{FIND} | xargs -r grep -c proofbundle_gate.py",
    f"{FIND} | {LOOP}",
    f'{FIND} | while read f; do echo "$f $(grep -c proofbundle_gate.py "$f" 2>/dev/null)"; done',
    f'grep -c proofbundle_gate.py "{D}/a.jsonl" > /dev/null 2>&1',
    f"{FIND} | {GREP} | {LOOP} 2>&1",
    f"{FIND}\n{FIND} | {GREP} | {LOOP}",
    f"{FIND} -type f -newer {D}/a.jsonl | {GREP} | {LOOP}",
]

#: The same command with a write, each still asked with D38 (denied under Codex), as at 3694e34e.
WRITES = [
    f"{DELTA} > /home/konrad/.claude-deltaxx/projects/zaehlung.txt",
    f"{DELTA} >> /home/konrad/.claude-deltaxx/projects/zaehlung.txt",
    f"{DELTA} | tee /home/konrad/.claude-deltaxx/projects/zaehlung.txt",
    f"{FIND} -delete | {GREP} | {LOOP}",
    f"{FIND} -exec rm {{}} \\; | {GREP} | {LOOP}",
    f"{FIND} -fprint /tmp/liste.txt | {GREP} | {LOOP}",
    f"{FIND} | xargs rm -f | {LOOP}",
    f"{FIND} | xargs sed -i 's/proofbundle_gate.py/x/' | {LOOP}",
    f"{DELTA}; rm {D}/a.jsonl",
    f"{DELTA}; mv {D}/a.jsonl /tmp/a.jsonl",
    f'{FIND} | {GREP} | while read f; do echo "$f $(grep -c proofbundle_gate.py "$f")" > {D}/count.txt; done',
    f'{FIND} | {GREP} | while read f; do echo "$f $(grep -c proofbundle_gate.py "$f")"; sed -i "s/a/b/" "$f"; done',
]

#: The calls of done-order D38 is for: they ask at both heads.
DONE_ORDER = [
    f"echo x | xargs python3 {G} done-order --remove --key",
    f"python3 {G} done-order --replace --repo /work/clone",
    "echo done-order | xargs proofbundle_gate.py",
    f"{FIND} -exec python3 {G} done-order --remove --key {{}} \\;",
    f"{DELTA}; python3 {G} done-order --remove --key k",
    f'{FIND} | while read f; do python3 {G} done-order --remove --key "$f"; done',
]


@pytest.fixture
def repo(tmp_path):
    subprocess.run(["git", "init", "-q", "-b", "main", str(tmp_path / "r")], check=True, timeout=60)
    return tmp_path / "r"


def decided(repo, command, host):
    return gate.decide(command, str(repo), time.monotonic() + 60, host)


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_D66_the_command_of_delta_word_for_word_is_silent(repo, host):
    out = decided(repo, DELTA, host)
    assert out is None, out and [v.reason_id for v in out.verdicts]


@pytest.mark.parametrize("host", ["claude", "codex"])
@pytest.mark.parametrize("command", READS)
def test_D66_read_forms_naming_the_gate_script_are_silent(repo, command, host):
    out = decided(repo, command, host)
    assert out is None, (command, out and [v.reason_id for v in out.verdicts])


@pytest.mark.parametrize("host", ["claude", "codex"])
@pytest.mark.parametrize("command", WRITES)
def test_D66_control_the_same_command_with_a_write_asks_with_d38(repo, command, host):
    out = decided(repo, command, host)
    assert out is not None and out.decision in ("ask", "deny"), command
    assert "done_order_change" in [v.reason_id for v in out.verdicts], (command, [v.reason_id for v in out.verdicts])


@pytest.mark.parametrize("host", ["claude", "codex"])
@pytest.mark.parametrize("command", DONE_ORDER)
def test_D66_control_a_done_order_call_asks_with_d38(repo, command, host):
    out = decided(repo, command, host)
    assert out is not None and "done_order_change" in [v.reason_id for v in out.verdicts], command


@pytest.mark.parametrize("host, write, expected", [("claude", False, None), ("codex", False, None),
                                                     ("claude", True, "ask"), ("codex", True, "deny")])
def test_D66_the_hook_as_the_host_runs_it(repo, tmp_path, host, write, expected):
    """The whole hook path, `python -I gate --host <host>` with the event on stdin: the read of account A gets no answer under
    either host; the same command writing under ~/.claude-* is asked under Claude Code and denied under Codex."""
    command = WRITES[0] if write else DELTA
    event = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(repo),
                        "tool_input": {"command": command}})
    env = {"PATH": os.environ["PATH"], "HOME": str(tmp_path), "LANG": "C", "GIT_CONFIG_GLOBAL": "/dev/null",
           "GIT_CONFIG_SYSTEM": "/dev/null", "PROOFBUNDLE_GATE_DIR": str(tmp_path / "gatedir")}
    proc, entry = ga.run_hook([sys.executable, "-I", gate.__file__, "--host", host], event, env, cwd=str(repo))
    answer = ga.parsed(proc, entry)
    assert proc.returncode == 0, proc.stderr
    if expected is None:
        assert answer is None, answer
    else:
        assert answer["hookSpecificOutput"]["permissionDecision"] == expected, answer
        assert "(D38)" in ga.long_text(answer)


@pytest.mark.parametrize("command", READS)
def test_D66_the_read_form_holds_for_the_reads(command):
    assert gate._read_only_form(command) is True, command


@pytest.mark.parametrize("command", WRITES + DONE_ORDER + [
    "printf 'a\\n' | " + LOOP,                         # printf is not in the closed set
    f"cat {D}/a.jsonl | {LOOP}",                       # nor cat
    f"$CMD -c proofbundle_gate.py {D}/a.jsonl",        # a program word the shell builds
    f"g[r]ep -c proofbundle_gate.py {D}/a.jsonl",      # a glob in the program word
    f"{FIND} | xargs -I% grep -c proofbundle_gate.py %",  # an xargs switch outside the set
    f"{FIND} | xargs env grep -l x",                   # xargs runs env, not grep
    f"{FIND} | xargs $G -l x",                         # xargs runs a program the shell builds
    f"{FIND} && {GREP}",                               # && is outside the set
    f"{FIND} & {GREP}",                                # so is a background job
    f"grep -l x <(find {D})",                          # a process substitution
    f"{LOOP} < /tmp/liste.txt",                        # an input redirection
    f"{DELTA} >&/tmp/liste.txt",                       # >& onto a file is a write
    f"{DELTA} 2>&3",                                   # a descriptor outside 1 and 2
    f'echo "$(rm {D}/a.jsonl)"',                       # a command substitution that writes
    f"{FIND} -name $PAT",                              # a find word the shell builds
    f"x=1 {FIND}",                                     # an assignment before the program
    "for f in a b; do echo \"$f\"; done",              # for is not among the loop words
    f"{FIND} -name 'unclosed",                         # a command the gate cannot read whole
])
def test_D66_the_read_form_holds_for_nothing_else(command):
    assert gate._read_only_form(command) is False, command


def test_D66_the_closed_sets_are_what_the_decision_names():
    assert gate._READ_ONLY_FIND_ACTIONS == {"-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprint0",
                                            "-fprintf", "-fls"}
    assert gate._READ_ONLY_XARGS_SWITCHES == {"-0", "--null", "-r", "--no-run-if-empty"}
    assert gate._READ_ONLY_KEYWORDS == {"while", "do", "done"}
