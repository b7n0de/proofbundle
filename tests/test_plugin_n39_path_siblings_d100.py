"""D100, follow-up note 39 (the siblings of F35-1 and F35-2): a path the command spells out itself is judged as D96 and D97 judge
a literal one.

The order: a Bash command that writes into the hook folder carries the weight of _D72_WRITES, and so does one that writes
a start file of the shell; as a class, with its siblings. Measured with the gate of D97 (siblings_n39.py): D96 and D97
judged `cp f.txt .git/hooks/pre-commit`, but `bash -c 'cp f.txt .git/hooks/pre-commit'`, `eval 'cp …'`,
`R=.git/hooks; cp f.txt $R/pre-commit` and `cp f.txt .git/hook{s,x}/pre-commit` got no answer there, as at f9e5f18e.

Measured with GNU bash 5.2.21 and dash as sh (truth_siblings_n39.py, 25 forms, an empty folder each, HOME in it): the
script of `bash -c`, `bash -lc`, `bash -c --`, `sh -c`, `env bash -c` and of eval writes what it says, nested too; a
variable a step of the command sets alone, with export or declare, writes where `$R/x`, `"$R/x"` or `${R}/x` names, a
value `~/x` or `$HOME/x` from HOME; a brace writes each word bash makes of it (`{q,r}`, `s{1..3}`, `{t,u{v,w}}`, a tilde
before it too), `x{y}` is a name. A prefix assignment (`H=DIR touch ./$H/o`) and one in a subshell do not reach the word.

The rule: the steps of the literal script of a shell of _SHELL_DASH_C run with -c (also behind a wrapper) and of eval are
judged as the command's own steps, in the step's directory; a word `$X/rest`, `${X}/rest` or `"$X/rest"` of a variable
the command sets alone or by a declaration builtin names each of its values with the rest; a word with braces and no
quote or substitution names each word of its brace expansion, at most 64. Each such path is judged as D96 and D97 judge
one (decide_write).

RED at f8d07104 (the head of D97) and at f9e5f18e: every write of these forms into the hooks, the configuration, the
gate's directory or a start file. The counter cases (other folders, reads, a prefix assignment, a variable the command does not
set, a script the shell builds, a relative path after cd) are green at both.
"""
from __future__ import annotations

import itertools
import json
import os
import sys
import time

import pytest

import _gate_answer as ga
import test_plugin_n30_short_line_d72 as d72

gate = d72.gate
pytestmark = d72.pytestmark
_clean = d72._clean
HOSTS = ("claude", "codex")


@pytest.fixture
def repo(tmp_path):
    r = d72._repo(tmp_path)
    (r / "f.txt").write_text("b\na\n")
    (r / "sub").mkdir()
    return r


def _out(repo, form, host="claude"):
    command = form.replace("{R}", str(repo)).replace("{GATE}", os.environ["PROOFBUNDLE_GATE_DIR"])
    return gate.decide(command, str(repo), time.monotonic() + 60, host)


def _ids(out):
    return [] if out is None else [v.reason_id for v in out.verdicts]


#: Writes into the configuration or the hooks the command spells out itself; each got no answer at f8d07104.
INTO_REPO_STATE = [
    "bash -c 'cp f.txt .git/hooks/pre-commit'", "sh -c 'echo x > .git/hooks/pre-commit'",
    "bash -lc \"install -m 755 f.txt .git/hooks/pre-push\"", "dash -c 'ln -sf ../../f.txt .git/hooks/post-merge'",
    "bash -c -- 'touch .git/hooks/post-checkout'", "env bash -c 'cp f.txt .git/hooks/pre-commit'",
    "sudo sh -c 'cat f.txt > .git/config'", "eval 'cp f.txt .git/hooks/pre-commit'", "eval cp f.txt .git/hooks/pre-push",
    "bash -c \"sh -c 'cp f.txt .git/hooks/pre-commit'\"", "bash -c 'R=.git/hooks; cp f.txt $R/pre-commit'",
    "R=.git/hooks; cp f.txt $R/pre-commit", "R=.git/hooks && cp f.txt \"$R/pre-commit\"",
    "export P=.git; cp f.txt ${P}/hooks/pre-commit", "R=.git/hooks; echo x > $R/pre-commit",
    "declare D=.git; tee $D/config < f.txt", "R='.git/hooks'; touch $R/x", "cp f.txt .git/hook{s,x}/pre-commit",
    "cp f.txt .git/{hooks,info}/pre-commit", "touch .git/hooks/{pre-commit,pre-push}", "rm -f .git/hooks/x{1..3}",
    "chmod +x .git/{hooks/pre-commit,description}",
    # after the mutants M100d and M100l: a script the outer shell expands first, a value split into its fields
    "R=.git/hooks; sh -c \"cp f.txt $R/pre-commit\"", "F='f.txt .git/hooks/pre-commit'; cp $F",
]


@pytest.mark.parametrize("host", HOSTS)
@pytest.mark.parametrize("form", INTO_REPO_STATE)
def test_D100_a_path_the_command_spells_out_into_configuration_or_hooks_asks(repo, form, host):
    out = _out(repo, form, host)
    assert out is not None and out.decision in ("ask", "deny") and "write_to_repo_state" in _ids(out), \
        (form, host, _ids(out))


#: Writes into a start file of the shell the command spells out itself; each got no answer at f8d07104.
INTO_SHELL_START = [
    "bash -c 'echo x >> ~/.bashrc'", "eval 'echo x >> ~/.bashrc'", "B=~/.bashrc; echo x >> $B",
    "P=$HOME/.profile; cp f.txt \"$P\"", "cp f.txt ~/.{bashrc,profile}", "sh -c 'cp f.txt ~/.bash_profile'",
    "bash -c \"echo x >> $HOME/.bashrc\"", "eval \"cp f.txt $HOME/.profile\"",
]


@pytest.mark.parametrize("form", INTO_SHELL_START)
def test_D100_a_path_the_command_spells_out_into_a_start_file_asks(repo, form):
    out = _out(repo, form)
    # an append outside the work folder is denied since D104; the write still names the start file
    assert out is not None and out.decision in ("ask", "deny") and "write_to_shell_start" in _ids(out), (form, _ids(out))


@pytest.mark.parametrize("form", ["bash -c 'touch {GATE}/x'", "G={GATE}; cp f.txt $G/mode", "rm {GATE}/{mode,rules.json}"])
def test_D100_a_path_the_command_spells_out_into_the_gate_directory_is_denied(repo, form):
    out = _out(repo, form)
    assert out is not None and out.decision == "deny" and "write_to_gate_dir" in _ids(out), (form, _ids(out))


@pytest.mark.parametrize("form", ["bash -c 'cp f.txt .git/hooks/pre-commit' && git status",
                                  "R=.git/hooks; cp f.txt $R/pre-commit; git status"])
def test_D100_the_write_gives_the_chain_its_reason_and_the_line_its_weight(repo, form):
    out = _out(repo, form)
    assert out.decision == "ask" and "write_to_repo_state" in _ids(out), _ids(out)
    assert " git status because the write can change hooks or git settings that start programs later (D8)." in \
        d72._line(out), d72._line(out)   # D116: what can go wrong, before the D number


@pytest.mark.parametrize("form", [
    "bash -c 'cp f.txt g.txt'", "sh -c 'echo ok > out.txt'", "bash -c 'cat .git/config'", "bash -c 'ls -la .git/hooks'",
    "eval echo ok", "R=build; cp f.txt $R/x", "R=.git/hooks; ls $R", "cp f.txt {a,b}.txt", "touch notes-{1..3}.md",
    "bash scripts/x.sh", "echo bash -c 'cp f.txt .git/hooks/pre-commit'", "bash -c \"$CMD\"",
    "H=.git/hooks cp f.txt $H/x", "cp f.txt $D/pre-commit", "touch .git/x{hooks}",
    "bash -c 'cd sub && cp ../f.txt ../.git/hooks/pre-commit'"])
def test_D100_control_other_folders_reads_and_words_the_command_does_not_spell_get_no_answer(repo, form):
    """A prefix assignment does not reach the word (measured), a variable the command does not set and a script the
    shell builds are not known, `x{hooks}` is a name, and the folder after cd is unknown (D33)."""
    assert _out(repo, form) is None, (form, _ids(_out(repo, form)))


@pytest.mark.parametrize("raw, expected", [
    ("a{b,c}d", ["abd", "acd"]), ("{1..3}", ["1", "2", "3"]), ("x{a..c}", ["xa", "xb", "xc"]),
    ("{a,b}{c,d}", ["ac", "ad", "bc", "bd"]), ("{a,b{c,d}}", ["a", "bc", "bd"]), ("x{y}", ["x{y}"]),
    ("a{b,c", ["a{b,c"]), ("{3..1}", ["3", "2", "1"]), ("'{a,b}'", None), ("$X{a,b}", None), ("{1..100}", None),
    ("{a,b}" * 7, None), ("{a,b}" * 6, ["".join(c) for c in itertools.product("ab", repeat=6)]),   # 128 and 64 words
])
def test_D100_the_words_of_a_brace_expansion(raw, expected):
    assert gate._sh_brace_expand(raw) == expected, (raw, gate._sh_brace_expand(raw))


@pytest.mark.parametrize("command", ["bash -c 'cp f.txt .git/hooks/pre-commit'", "R=.git/hooks; cp f.txt $R/pre-commit"])
def test_D100_under_the_switch_of_claude_code_the_write_is_denied(repo, tmp_path, command):
    event = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(repo), "session_id": "s-d98",
             "tool_input": {"command": command}}
    env = {k: os.environ[k] for k in ("PATH", "HOME", "LC_ALL", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
                                      "PROOFBUNDLE_GATE_DIR")}
    env["CLAUDE_PLUGIN_DATA"] = str(tmp_path / "data")
    proc, entry = ga.run_hook([sys.executable, "-I", gate.__file__, "--host", "claude", gate.AUTONOMOUS_FLAG],
                              json.dumps(event), env, cwd=str(repo))
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny", proc.stdout
    assert "write_to_repo_state" in entry["reason_ids"], entry
