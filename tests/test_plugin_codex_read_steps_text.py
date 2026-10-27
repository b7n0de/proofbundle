"""Owner choice of 2026-10-15: under Codex, a read step of a longer command carries the
reviewer's text in the answer of the whole command.

A step is a read form by the check class a frees with under Claude Code (_read_form, the words the shell rewrites
included), applied to its run as to the whole command: a bare `git` at the head of the run, at most one literal `-C`, no
global option, no expansion, no redirection, no unvetted assignment. Under Codex its verdict in the answer of the whole
command carries the explanation and the next step of D37 word for word; with an absolute `git -C` it claims no missing
directory. A step outside the grammar keeps its own text: `git remote` directory_unresolved, `git stash list` and a git
form with a global option the text of D3. The verdict, the exit code and the reason ids stay, and under Claude Code
nothing changes. A command in which the word git may not name the git program, as far as the command shows, keeps the
text of D3 for every step (owner question, not built): a function definition, an alias, a printf that sets a variable,
a nested shell, a substitution, a wrapper, a redirection, an unvetted assignment.

RED at 35214a8c for the chain of milestone run 2 and its `-C` variant; every control is green there and after. Each case
runs the gate as the host starts it and reads the verdicts of decide() beside it.
"""
from __future__ import annotations

import shlex

import pytest

import test_plugin_review20_codex_read_text as t
from _plugin_env import plugin_env

a = t.a
pytestmark = a.pytestmark
_clean = a._clean

D3 = "may start a program the gate does not see"
MISSING = ("cannot resolve the directory", "cannot tell which repository")
CHAIN = "git status && git branch && git remote show origin"


def _chain_with_minus_c(repo) -> str:
    where = shlex.quote(str(repo))
    return f"git -C {where} status && git -C {where} branch && git remote show origin"


def _decide(repo, command: str, host: str):
    return a.gate.decide(command, str(repo), a.time.monotonic() + 120, host, plugin_env())


def _named(out, name: str) -> list:
    return [v for v in out.verdicts if v.failed.startswith(name + " ") or v.evidence.endswith(f" {name} acts on")]


@pytest.mark.parametrize("variant", ["plain", "minus_c"])
def test_N11_the_chain_of_milestone_run_2_carries_the_reviewers_text_for_its_read_steps(tmp_path, variant):
    repo = a._repo(tmp_path)
    command = CHAIN if variant == "plain" else _chain_with_minus_c(repo)
    code, decision, text = t._host(repo, command)
    assert (code, decision) == (0, "deny"), (code, decision, text)
    assert text.count(t.EXPLANATION) == 2 and text.count(t.NEXT_STEP) == 2, text
    assert D3 not in text, text
    out = _decide(repo, command, "codex")
    assert [v.reason_id for v in out.verdicts] == ["git_form_not_free", "git_form_not_free", "directory_unresolved"]
    for name in ("git status", "git branch"):
        (verdict,) = _named(out, name)
        assert verdict.reason_id == "git_form_not_free" and t.EXPLANATION in verdict.text(), verdict.text()
        assert not any(m in verdict.text() for m in MISSING), verdict.text()
    (remote,) = _named(out, "git remote")
    assert remote.reason_id == "directory_unresolved" and t.EXPLANATION not in remote.text(), remote.text()


def test_N11_control_a_chain_judged_step_by_step_keeps_one_text_each(tmp_path):
    repo = a._repo(tmp_path)
    code, decision, text = t._host(repo, "git status && git stash list")
    assert (code, decision) == (0, "deny"), (code, decision, text)
    assert text.count(t.EXPLANATION) == 1 and text.count(D3) == 1, text
    out = _decide(repo, "git status && git stash list", "codex")
    assert [v.reason_id for v in out.verdicts] == ["git_form_not_free", "git_form_not_free"], out.verdicts


@pytest.mark.parametrize("command", ["git status && git -c core.pager=cat log -1 && git remote show origin",
                                     "git status && git stash list && git remote show origin"])
def test_N11_control_a_form_outside_the_grammar_in_a_chain_keeps_its_text(tmp_path, command):
    repo = a._repo(tmp_path)
    code, decision, text = t._host(repo, command)
    assert (code, decision) == (0, "deny"), (code, decision, text)
    out = _decide(repo, command, "codex")
    assert [v.reason_id for v in out.verdicts] == ["git_form_not_free", "git_form_not_free", "directory_unresolved"]
    other = "git log" if "log" in command else "git stash"
    (verdict,) = _named(out, other)
    assert verdict.reason_id == "git_form_not_free" and D3 in verdict.text() and t.EXPLANATION not in verdict.text()
    (remote,) = _named(out, "git remote")
    assert remote.reason_id == "directory_unresolved" and t.EXPLANATION not in remote.text(), remote.text()


@pytest.mark.parametrize("variant", ["plain", "minus_c", "stash"])
def test_N11_control_claude_code_keeps_its_answer(tmp_path, variant):
    repo = a._repo(tmp_path)
    command = {"plain": CHAIN, "minus_c": _chain_with_minus_c(repo), "stash": "git status && git stash list"}[variant]
    code, decision, text = t._host(repo, command, host="claude")
    assert (code, decision) == (0, "ask"), (code, decision, text)
    assert t.EXPLANATION not in text and t.NEXT_STEP not in text, text
    out = _decide(repo, command, "claude")
    if variant == "stash":
        assert text.count(D3) == 1, text
        assert [v.reason_id for v in out.verdicts] == ["free_after_read_profile", "git_form_not_free"], out.verdicts
    else:
        # D46 changed this text: the reason names first the step that asks on its
        # own and no finding of D3 for the read steps it names as free; the decision and the verdicts stay
        assert text.count(D3) == 0 and text.startswith("NOT MEASURED: the step `git remote show origin` of this command asks on "
                                                       "its own"), text
        assert [v.reason_id for v in out.verdicts] == ["git_form_not_free", "git_form_not_free",
                                                       "directory_unresolved"], out.verdicts


@pytest.mark.parametrize("command", [
    "git status $X && git remote show origin",
    "git -c core.pager=cat status && git remote show origin",
    "git -C a -C b status && git remote show origin",
    "git() { :; }; git status && git remote show origin",
    "printf -v PATH /tmp; git status && git remote show origin",
    "hash -p /bin/true git; git status && git remote show origin",
    "source ./env.sh; git status && git remote show origin",
    "aliases[git]=true; git status && git remote show origin",
    "alias git=true; git status && git remote show origin",
    "sh -c 'git status && git remote show origin'",
    "echo $(git status) && git remote show origin",
    "env git status && git remote show origin",
    "git status > out.txt && git remote show origin",
    "GIT_DIR=.git git status && git remote show origin",
    "git status && git status > out.txt && git remote show origin",
])
def test_N11_control_a_step_outside_the_grammar_or_of_unclear_membership_keeps_the_text_of_D3(tmp_path, command):
    repo = a._repo(tmp_path)
    code, decision, text = t._host(repo, command)
    assert (code, decision) == (0, "deny"), (code, decision, text)
    assert t.EXPLANATION not in text and t.NEXT_STEP not in text, text
    assert D3 in text, text


def test_N11_control_a_git_word_that_is_an_argument_is_no_step(tmp_path):
    """`git log -1 -- git status`: git and status are paths of git log. The scan reports them as a call of their own,
    which keeps the text of D3; only the head of a run is a step that can be a read form."""
    repo = a._repo(tmp_path)
    out = _decide(repo, "git log -1 -- git status && git remote show origin", "codex")
    (status,) = _named(out, "git status")
    assert D3 in status.text() and t.EXPLANATION not in status.text(), status.text()


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_N11_control_a_read_form_the_scan_names_a_possible_transfer_keeps_its_reason(tmp_path, host):
    """`git worktree list` is a read form of the grammar, but in a longer command the scan names its subcommand a
    possible transfer and answers directory_unresolved; the reason ids stay, so it keeps that answer under both hosts
    (corpus row B193)."""
    repo = a._repo(tmp_path)
    out = _decide(repo, "git worktree list | head", host)
    assert [v.reason_id for v in out.verdicts] == ["directory_unresolved"], out.verdicts
    assert t.EXPLANATION not in out.text, out.text
