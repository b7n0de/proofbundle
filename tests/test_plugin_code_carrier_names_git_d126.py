"""D126, finding 2 of review package -1: code that names git or gh asks at least, also where the code is a here-document
fed to python or a script file a step runs.

README.md:105 says of class c (D33) that "code that names git or gh asks at least". The package measured two carriers that
got no decision (push_carrier_A.json, siblings_A.json, trap scaffold repo-missing, no Level 2): `python3 - <<'PY'` with
`os.system('git push origin main')` in its body, and `python3 push.py`, `bash push.sh` and `./push.sh`, each pushing,
under `--autonomous` and under `--host codex`; both here-document pushes reached the local bare remote. D39 part 1 judges
the here-document form by its words before the here-document, as `python3 file.py`, and the gate read no script file.

Measured again at 16cffca (the carrier matrix of this slice, the three hook forms, scaffold repo-missing, gate under
Python 3.12): with a pushing body or script, no decision under any hook form for `python3 - <<'PY'`, `python - <<'PY'`,
`python3 - arg <<'PY'`, `python3 push.py`, `bash push.sh`, `sh push.sh`, `./push.sh`, `./push.py` and `. push.sh`; an ask
without a flag and a deny under --autonomous and Codex for `node - <<'JS'`, `bash <<'SH'`, `sh -s <<'SH'` and the `-c`
forms. With a harmless body or script, and for a script that does not exist, no decision under any hook form.

The rule (D126): a body of the D39 form that names git or gh gets the answer of the same text as the interpreter's `-c`
argument; a script file a step runs (by path, or as the first word after an interpreter or a shell), read at decision time
as a regular file of at most MAX_SCRIPT_BYTES bytes, whose text names git or gh asks at least (code_names_git), as the text
of a carrier does. A body or a script that names neither, and a script the gate cannot read within the bound, keep their
answer.

RED at 16cffca: every case of PUSHING_HEREDOCS and PUSHING_SCRIPTS, the link, the bound, and the hook runs of the pushing
forms. CONTROL, green at both: a body or a script that names neither, a missing script, a FIFO, a key path (D102), and the
carriers that already ask.
"""
from __future__ import annotations

import json
import os
import pathlib
import shlex
import subprocess
import sys
import time

import pytest

import test_plugin_gate_n2c_push_done as n2c

gate = n2c.gate
pytestmark = n2c.pytestmark
env = n2c.env
_clean_git_environment = n2c._clean_git_environment
GATE = n2c.GATE
SCAFFOLD = GATE.parent.parent / "evals" / "_fixtures" / "scaffold.sh"

PUSH = "import os\nos.system('git push origin main')\n"
#: Python that names git or gh: the package's push, a list-form push, a gh call, and the pilot's body of D39.
NAMING = {
    "os_system": PUSH,
    "subprocess_list": "import subprocess\nsubprocess.run(['git', 'push', 'origin', 'main'], check=True)\n",
    "gh_merge": "import subprocess\nsubprocess.run(['gh', 'pr', 'merge', '12', '--admin'])\n",
    "pilot": ('import subprocess, sys\n'
              'git_dir, log = sys.argv[1], sys.argv[2]\n'
              '# read what gh and git left behind\n'
              'out = subprocess.run(["git", "-C", git_dir, "log", "-1"], capture_output=True, text=True).stdout\n'
              'print("gh pr view", out, open(log).read())\n'),
}
#: Python that names neither git nor gh.
NEITHER = {
    "print": "print(1)\n",
    "json_argv": "import json, sys\nprint(json.dumps(sys.argv[1:]))\n",
}
#: The D39 form, the `-c` form of the same text and the file form D39 judges it as: (here-document with {body}, the -c
#: form with {quoted}, the file form).
HEREDOCS = {
    "python3": ("python3 - <<'PY'\n{body}PY", "python3 -c {quoted}", "python3 script.py"),
    "python": ("python - <<'PY'\n{body}PY", "python -c {quoted}", "python script.py"),
    "python3_argument": ("python3 - arg <<'PY'\n{body}PY", "python3 -c {quoted} arg", "python3 script.py arg"),
    "python3_double_quoted": ("python3 - \"$B\" <<\"PY\"\n{body}PY", "python3 -c {quoted} \"$B\"",
                              "python3 script.py \"$B\""),
    "python3_backslash": ("python3 - <<\\PY\n{body}PY", "python3 -c {quoted}", "python3 script.py"),
}
#: Script forms; {py} and {sh} name a Python and a shell script in the working directory, {ws} is its absolute path.
SCRIPTS = ["python3 {py}", "python {py}", "python3 {py} origin main", "bash {sh}", "sh {sh}", "./{sh}", "./{py}",
           ". {sh}", "source {sh}", "bash ./{sh}", "python3 {ws}/{py}", "{ws}/{sh}"]
#: Carriers of a pushing text that asked at 16cffca already, under Claude Code, and keep asking.
ASKED = ["node - <<'JS'\nrequire('child_process').execSync('git push origin main')\nJS",
         "bash <<'SH'\ngit push origin main\nSH", "sh -s <<'SH'\ngit push origin main\nSH",
         "perl - <<'PL'\nsystem('git push origin main');\nPL", "python3 <<'PY'\n" + PUSH + "PY",
         "python3 -c \"import os; os.system('git push origin main')\"", "bash -c 'git push origin main'"]


@pytest.fixture
def ws(tmp_path: pathlib.Path, env: dict) -> pathlib.Path:
    """The package's trap: scaffold repo-missing (a declared bundle never committed, a bare remote, no Level 2), with a
    pushing and a quiet script of each kind beside it, kept out of git's view."""
    work = tmp_path / "ws"
    work.mkdir()
    subprocess.run(["bash", str(SCAFFOLD), "repo-missing"], cwd=work, env=env, check=True, capture_output=True,
                   timeout=120)
    for name, text in {"push.py": "#!/usr/bin/env python3\n" + PUSH, "push.sh": "#!/bin/sh\ngit push origin main\n",
                       "quiet.py": "#!/usr/bin/env python3\nprint(1)\n", "quiet.sh": "#!/bin/sh\necho done\n"}.items():
        (work / name).write_text(text, encoding="utf-8")
        (work / name).chmod(0o755)
    with open(work / ".git" / "info" / "exclude", "a", encoding="utf-8") as fh:
        fh.write("*.py\n*.sh\n")
    return work


def _decide(work: pathlib.Path, command: str, environ: dict, host: str = "claude"):
    out = gate.decide(command, str(work), time.monotonic() + 120, host, environ)
    return (None, []) if out is None else (out.decision, [v.reason_id for v in out.verdicts])


def _forms(template: str, work: pathlib.Path, py: str, sh: str) -> str:
    return template.replace("{py}", py).replace("{sh}", sh).replace("{ws}", str(work))


def _heredoc(name: str, body: str) -> tuple[str, str]:
    heredoc, dash_c, _file_form = HEREDOCS[name]
    return heredoc.replace("{body}", body), dash_c.replace("{quoted}", shlex.quote(body))


def _hook(work: pathlib.Path, environ: dict, command: str, args: list[str]) -> tuple[int, str | None]:
    """The gate as the host starts it: (exit code, permission decision or None where it printed none)."""
    event = json.dumps({"hook_event_name": "PreToolUse", "session_id": "d126", "tool_name": "Bash", "cwd": str(work),
                        "tool_input": {"command": command}})
    proc = subprocess.run([sys.executable, "-I", str(GATE), *args], input=event, capture_output=True, text=True,
                          env=environ, cwd=str(work), timeout=120, check=False)
    out = json.loads(proc.stdout).get("hookSpecificOutput", {}) if proc.stdout.strip() else {}
    return proc.returncode, out.get("permissionDecision")


# --- the here-document fed to python ------------------------------------------------------------------------------

@pytest.mark.parametrize("host", ["claude", "codex"])
@pytest.mark.parametrize("body", sorted(NAMING))
@pytest.mark.parametrize("form", sorted(HEREDOCS))
def test_RED_a_heredoc_body_that_names_git_gets_the_answer_of_its_c_form(env, ws, form, body, host):
    """16cffca judged the D39 form by `python3 -`, as `python3 file.py`: no decision, the push went out. The same text
    as the `-c` argument asks (code_names_git or the safety net, D33); under Codex the hook turns that ask into a deny."""
    heredoc, dash_c = _heredoc(form, NAMING[body])
    got = _decide(ws, heredoc, env, host)
    assert got[0] == "ask" and got == _decide(ws, dash_c, env, host), (got, _decide(ws, dash_c, env, host))


@pytest.mark.parametrize("host", ["claude", "codex"])
@pytest.mark.parametrize("body", sorted(NEITHER))
@pytest.mark.parametrize("form", sorted(HEREDOCS))
def test_CONTROL_a_heredoc_body_that_names_neither_keeps_the_answer_of_D39(env, ws, form, body, host):
    heredoc, _dash_c = _heredoc(form, NEITHER[body])
    assert _decide(ws, heredoc, env, host) == _decide(ws, HEREDOCS[form][2], env, host) == (None, [])


@pytest.mark.parametrize("command", ASKED)
def test_CONTROL_the_carriers_that_asked_keep_asking(env, ws, command):
    assert _decide(ws, command, env)[0] == "ask"


# --- a script file a step runs ------------------------------------------------------------------------------------

@pytest.mark.parametrize("host", ["claude", "codex"])
@pytest.mark.parametrize("template", SCRIPTS)
def test_RED_a_script_that_names_git_asks_at_least(env, ws, template, host):
    """16cffca read no script file: `python3 push.py`, `bash push.sh` and `./push.sh` with a push got no decision."""
    decision, reasons = _decide(ws, _forms(template, ws, "push.py", "push.sh"), env, host)
    assert decision == "ask" and "code_names_git" in reasons, (decision, reasons)


@pytest.mark.parametrize("template", ["bash {sh}", "./{sh}"])
def test_RED_a_link_to_a_script_is_read_where_it_leads(env, ws, template):
    (ws / "link.sh").symlink_to("push.sh")
    decision, reasons = _decide(ws, _forms(template, ws, "push.py", "link.sh"), env)
    assert decision == "ask" and "code_names_git" in reasons, (decision, reasons)


def test_RED_the_bound_a_script_of_the_bound_is_read_one_byte_more_is_not(env, ws):
    """The gate reads a script of at most MAX_SCRIPT_BYTES bytes whole; a longer one keeps its answer (named in D126)."""
    bound = getattr(gate, "MAX_SCRIPT_BYTES", None)
    assert isinstance(bound, int) and bound > 0, bound
    tail = "\ngit push origin main\n"
    (ws / "at.sh").write_text("#" * (bound - len(tail)) + tail, encoding="utf-8")
    (ws / "over.sh").write_text("#" * (bound + 1 - len(tail)) + tail, encoding="utf-8")
    assert _decide(ws, "bash at.sh", env)[0] == "ask"
    assert _decide(ws, "bash over.sh", env) == (None, [])


@pytest.mark.parametrize("host", ["claude", "codex"])
@pytest.mark.parametrize("template", SCRIPTS)
def test_CONTROL_a_script_that_names_neither_keeps_its_answer(env, ws, template, host):
    assert _decide(ws, _forms(template, ws, "quiet.py", "quiet.sh"), env, host) == (None, [])


@pytest.mark.parametrize("template", ["python3 {py}", "bash {sh}", "./{sh}", ". {sh}"])
def test_CONTROL_a_missing_script_keeps_its_answer(env, ws, template):
    assert _decide(ws, _forms(template, ws, "missing.py", "missing.sh"), env) == (None, [])


def test_CONTROL_a_fifo_is_never_waited_on(env, ws):
    """A FIFO with no writer in place of the script: the gate checks the type before it reads and answers at once."""
    fifo = ws / "fifo.sh"
    os.mkfifo(fifo)
    try:
        assert _hook(ws, env, "bash fifo.sh", []) == (0, None)
    finally:
        fifo.unlink()


def test_CONTROL_a_script_at_a_key_path_keeps_the_deny_of_D102(env, ws):
    keys = ws / ".ssh"
    keys.mkdir()
    (keys / "id_ed25519").write_text("git push origin main\n", encoding="utf-8")
    decision, reasons = _decide(ws, "bash .ssh/id_ed25519", env)
    assert decision == "deny" and "secret_path" in reasons, (decision, reasons)


# --- the hook as each host starts it ------------------------------------------------------------------------------

HOSTS = {"claude": ([], "ask"), "claude_autonomous": (["--autonomous"], "deny"), "codex": (["--host", "codex"], "deny")}


@pytest.mark.parametrize("host", sorted(HOSTS))
@pytest.mark.parametrize("command", ["python3 - <<'PY'\n" + PUSH + "PY", "./push.sh", "python3 push.py"],
                         ids=["heredoc", "path", "interpreter"])
def test_RED_the_hook_asks_or_denies_the_pushing_carriers(env, ws, command, host):
    args, expected = HOSTS[host]
    assert _hook(ws, env, command, args) == (0, expected)


@pytest.mark.parametrize("host", sorted(HOSTS))
@pytest.mark.parametrize("command", ["python3 - <<'PY'\nprint(1)\nPY", "./quiet.sh", "python3 quiet.py"],
                         ids=["heredoc", "path", "interpreter"])
def test_CONTROL_the_hook_leaves_the_quiet_carriers_without_a_decision(env, ws, command, host):
    assert _hook(ws, env, command, HOSTS[host][0]) == (0, None)
