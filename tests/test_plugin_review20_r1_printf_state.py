"""R20-1 of review round 20 (Nachtrag 10 to FIX-18): a printf format that sets a variable is a state change.

Class c (D33) frees `git add` after a data step that changes no state. bash's printf assigns, through a %n conversion
of its format, the number of characters written so far to the variable its argument names, not only through -v:
`printf '%n' PATH` sets PATH to 0, and the following `git` is ./0/git. Such a step is no data step, so the later
step's free answer does not hold and the command keeps an ask; a printf whose format assigns nothing stays a data step.

RED at b34ba9a2 (pass free_after_state_check under both hosts), green after. The ground truth runs each command in
bash with stand-ins 0/git, 1/git and 2/git in the repository that only leave a marker.
"""
from __future__ import annotations

import os
import shutil
import subprocess

import pytest

import test_plugin_ask_load_c_steps as c

pytestmark = c.pytestmark
env = c.env
_clean_git_environment = c._clean_git_environment

#: The reviewer's reproduction and the siblings of the same format class.
SETS_A_VARIABLE = {
    "reviewer_n": "printf '%n' PATH; git add notes/a.md",
    "after_text": "printf '%s%n' ab PATH; git add notes/a.md",
    "after_double_dash": "printf -- '%n' PATH; git add notes/a.md",
    "with_width": "printf '%5n' PATH; git add notes/a.md",
    "after_literal_percent": "printf '%%%n' PATH; git add notes/a.md",
    "long_modifier": "printf '%ln' PATH; git add notes/a.md",
    "v_option": "printf -v PATH 0; git add notes/a.md",
}
#: printf that assigns nothing: the data case stays free.
DATA_ONLY = {
    "reviewer_control": "printf '%s' note; git add notes/a.md",
    "number": "printf '%d\\n' 3; git add notes/a.md",
    "literal_percent_n": "printf '%%n' x; git add notes/a.md",
    "plain_text": "printf 'done\\n'; git add notes/a.md",
}


@pytest.mark.parametrize("host", ["claude", "codex"])
@pytest.mark.parametrize("name", sorted(SETS_A_VARIABLE))
def test_R20_1_a_printf_that_sets_a_variable_keeps_the_later_step_from_being_free(env, tmp_path, name, host):
    work = c._repo(tmp_path)
    decision, reasons = c._decide(work, SETS_A_VARIABLE[name], env, host=host)
    assert decision in ("ask", "deny"), (name, decision, reasons)


@pytest.mark.parametrize("host", ["claude", "codex"])
@pytest.mark.parametrize("name", sorted(DATA_ONLY))
def test_R20_1_control_a_printf_that_assigns_nothing_stays_free(env, tmp_path, name, host):
    work = c._repo(tmp_path)
    decision, reasons = c._decide(work, DATA_ONLY[name], env, host=host)
    assert decision == "pass" and set(reasons) == {"free_after_state_check"}, (name, decision, reasons)


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash is not installed")
@pytest.mark.parametrize("command", sorted({**SETS_A_VARIABLE, **DATA_ONLY}.values()))
def test_R20_1_ground_truth_the_gate_is_free_only_where_bash_starts_git(env, tmp_path, command):
    """In bash without start files: where the command makes bash start a stand-in instead of git, the gate is not
    free; where git itself runs, the data case is free."""
    work = c._repo(tmp_path)
    marker = tmp_path / "stand-in-ran"
    for folder in ("0", "1", "2"):
        (work / folder).mkdir()
        (work / folder / "git").write_text(f'#!/bin/sh\necho "$0" >> "{marker}"\n', encoding="utf-8")
        (work / folder / "git").chmod(0o755)
    decision, _reasons = c._decide(work, command, env)
    run_env = {"PATH": os.environ.get("PATH", ""), "HOME": str(tmp_path), "GIT_CONFIG_GLOBAL": os.devnull,
               "GIT_CONFIG_SYSTEM": os.devnull}
    proc = subprocess.run(["bash", "--norc", "--noprofile", "-c", command], cwd=work, env=run_env,
                          capture_output=True, text=True, timeout=60, check=False)
    started_stand_in = marker.exists()
    assert started_stand_in == (command in SETS_A_VARIABLE.values()), (command, proc.stdout, proc.stderr)
    if started_stand_in:
        assert decision in ("ask", "deny"), (command, decision)
    else:
        assert decision == "pass", (command, decision)
