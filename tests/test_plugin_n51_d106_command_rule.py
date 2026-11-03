"""Follow-up note 51, point 1 (O46-3, finding 1 of PLUGIN_N46): D106 is bound to the command rule of D114.

D106 frees `git add` and `git commit` under `--autonomous` where the owner recorded the clone's hooks in
hook-state.json and the bytes are unchanged when the gate answers. The gate reads the hooks before the command runs;
another step of the same line can rewrite a hook between that read and git's run, and a write in a language the gate
does not read is not gated (D8). D114 answers only a command of plain git calls joined by `&&` or `;`
(_pinned_command); D106 had no such rule, so `python3 -c '…pre-commit…' && git commit -m work` and the same with
`perl -e` were free with a recorded hook (measured at 70e98e91 and d3ce27a2, probe_n46_d106_sibling.py). Now D106
answers only the command _pinned_command takes; every other command gets the answer of D91 and D85, as without a record.

RED at d3ce27a2 (measured, 13 of 23): the ten hook-rewriting chains (pass with free_recorded_hooks there), the pipe
form, the piped call of a rewrite and the case on the signature of _autonomy_recorded. The two redirection forms were
already kept there, as under the pin; they and the controls are green at both.
"""
from __future__ import annotations

import time

import pytest
from _owner_state import owner_state_protected  # noqa: F401 - D124: a person's hook record is read

import test_plugin_n29_work_profile_d71 as d71
from _plugin_env import plugin_env
import test_plugin_n33_recorded_hooks_d106 as d106

gate = d71.gate
pytestmark = d71.pytestmark
_clean = d71._clean

#: Chains whose first step rewrites or replaces the recorded hook in a language the gate does not read (finding 1 and
#: its siblings), then runs git add or git commit.
REWRITE_CHAINS = [
    "python3 -c 'open(\".git/hooks/pre-commit\", \"a\").write(\"x\")' && git commit -m work",
    "perl -e 'open(F, \">>.git/hooks/pre-commit\")' && git commit -m work",
    "python3 -c 'open(\".git/hooks/pre-commit\", \"a\").write(\"x\")'; git add -A",
    "node -e 'require(\"fs\").appendFileSync(\".git/hooks/pre-commit\", \"x\")' && git commit -m work",
    "ruby -e 'File.write(\".git/hooks/pre-commit\", \"x\", mode: \"a\")' && git add -A && git commit -m work",
]


def _recorded_repo(tmp_path, kind="fremd"):
    repo = d106._repo(tmp_path, kind)
    d106._hook(repo / ".git" / "hooks")
    d106._record([(repo, {"pre-commit": d106._sha(d106.PRE_COMMIT)})])
    return repo


@pytest.mark.parametrize("kind", ("b7n0de", "fremd"))
@pytest.mark.parametrize("command", REWRITE_CHAINS)
def test_D106_a_chain_whose_other_step_can_rewrite_the_hook_is_not_free(tmp_path, command, kind):
    repo = _recorded_repo(tmp_path, kind)
    decision, reasons, _klasse = d106.answered(repo, command)
    assert decision != "pass" and "free_recorded_hooks" not in reasons, (command, decision, reasons)


@pytest.mark.parametrize("command", ["git commit -m work 2>&1", "git add -A > /dev/null && git commit -m work",
                                     "git commit -m work | cat"])
def test_D106_a_redirection_or_a_pipe_keeps_the_answer_as_under_the_pin(tmp_path, command):
    repo = _recorded_repo(tmp_path)
    decision, reasons, _klasse = d106.answered(repo, command)
    assert "free_recorded_hooks" not in reasons, (command, decision, reasons)


def test_D106_the_rule_reads_the_command_it_answers(tmp_path):
    """_autonomy_recorded takes the command and answers None for one that is not plain git calls, before it reads any
    state: the rule does not depend on what the clone holds."""
    repo = _recorded_repo(tmp_path)
    command = REWRITE_CHAINS[0]
    out = gate.decide(command, str(repo), time.monotonic() + 60, "claude")
    assert out is not None and out.decision == "ask", out and out.decision
    assert gate._autonomy_recorded(out, command, str(repo), time.monotonic() + 60, plugin_env()) is None
    plain = gate.decide("git commit -m work", str(repo), time.monotonic() + 60, "claude")
    freed = gate._autonomy_recorded(plain, "git commit -m work", str(repo), time.monotonic() + 60,
                                    plugin_env())
    assert freed is not None and freed.decision == "pass", freed and freed.decision


def test_D106_a_rewrite_call_the_gate_judges_keeps_the_rule_too(tmp_path):
    """The check of a rewrite (D85, _autonomy_judge) asks D106 about each call with that call's own text; a call that
    is a pipe is no plain git call and is not freed by the record, a plain one is."""
    repo = _recorded_repo(tmp_path)
    environ = plugin_env()
    piped = {"kind": "bash", "pipe": [["git", "commit", "-m", "work"], ["cat"]], "directory": str(repo)}
    assert gate._autonomy_judge(piped, str(repo), time.monotonic() + 60, environ)[0] == "blocked"
    plain = {"kind": "bash", "words": ["git", "commit", "-m", "work"], "directory": str(repo)}
    assert gate._autonomy_judge(plain, str(repo), time.monotonic() + 60, environ) == ("free", "")


# --- the controls: green at both ----------------------------------------------------------------------------------

@pytest.mark.parametrize("form", ["git commit -m work", "git add -A && git commit -m work", "git add notes.md; git commit -m x",
                                  "git -C {R} add -A && git -C {R} commit -m work", "git status && git commit -m work"])
def test_D106_control_plain_git_calls_stay_free(tmp_path, form):
    repo = _recorded_repo(tmp_path)
    decision, reasons, klasse = d106.answered(repo, d106._form(form, repo, tmp_path))
    assert (decision, klasse) == ("pass", "lokal") and "free_recorded_hooks" in reasons, (form, reasons)


@pytest.mark.parametrize("command", ["printf x > .git/hooks/pre-commit && git commit -m work",
                                     "cp notes.md .git/hooks/pre-commit && git commit -m work"])
def test_D106_control_a_gated_write_of_the_hook_stays_blocked(tmp_path, command):
    repo = _recorded_repo(tmp_path)
    decision, reasons, _klasse = d106.answered(repo, command)
    assert decision == "deny" and "free_recorded_hooks" not in reasons, (command, reasons)


def test_D106_control_the_merge_of_d91_with_a_recorded_hook_stays_free(tmp_path):
    repo = _recorded_repo(tmp_path)
    decision, reasons, _klasse = d106.answered(repo, "git merge -m 'Merge main' main")
    assert decision == "pass" and "free_recorded_hooks" in reasons, reasons
