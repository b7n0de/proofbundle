"""D130: the work profile of D71 is the house's, the gate started with --autonomous (owner answer 10 of Nachtrag 7).

The owner's answer (2026-10-26, option A): "D71 in the public default: A, in -4 behind the house's opt-in." The finding
that prompted it: D71 (_work_profile) stood in the base decision path, so it applied without any flag, and the public
hook commands carry none since D125. A contributor's clone of a repository of b7n0de, which declares and whose every
remote is https://github.com/b7n0de/<repo>, got the owner's work profile: `git stash`, `git checkout <branch>` and
`gh pr merge <n> -R b7n0de/<repo> --auto --merge` passed without a question.

The rule: D71 applies only where the gate is started with --autonomous (AUTONOMOUS_FLAG, the house's opt-in of D85 and
D125). Without the flag every form D71 frees gets the answer decide() gives without D71: a deny stays a deny, an ask an
ask. With the flag D71 frees as before, in the base path and in a call of a rewrite of D85.

RED at f21f785d: without the flag each form of the work profile below passes (free_work_profile), in process and through
the hook as hooks.json starts it, and an ask whose check found a hook names the work profile in its text. Controls,
green at both: with --autonomous the forms pass as before, in process and through the hook, and a chain of two gh forms
of D71 gets the rewrite into two free calls; under Codex, which never had D71, no form is free with or without the flag;
`git commit -m work` is free by the state check of D3, not by D71, with and without the flag.
"""
from __future__ import annotations

import json
import sys
import time

import pytest

import _gate_answer as ga
import test_plugin_n29_work_profile_d71 as d71
import test_plugin_public_hooks_without_autonomous_d125 as d125

gate = d71.gate
pytestmark = d71.pytestmark
_clean = d71._clean
#: Forms of D71, one or two of each class, that the base path asks about without D71: local (stash, checkout, commit
#: --amend), read (the tag list), target (bundle create) and gh (merge --auto, edit). {R} is the repository, {T} the
#: test's folder.
FORMS = ["git stash", "git checkout topic", "git commit --amend --no-edit", "git tag -l",
         "git bundle create {T}/x.bundle main", "gh pr merge 12 -R b7n0de/proofbundle --auto --merge",
         "gh pr edit 12 -R b7n0de/proofbundle --body text"]
#: The forms of the finding, run through the hook.
HOOK_FORMS = ["git stash", "git checkout topic", "gh pr merge 12 -R b7n0de/proofbundle --auto --merge"]


def _event(repo, command: str) -> str:
    return json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(repo),
                       "tool_input": {"command": command}})


def _outcome(repo, command: str, autonomous: bool, host: str = "claude"):
    """(decision, reason ids, text, autonomy record) of the base path as main runs it, the flag as given."""
    _event_read, out, _actions = gate.tool_outcome(_event(repo, command), host, time.monotonic() + 60,
                                                   autonomous=autonomous)
    return (None, [], None, None) if out is None else \
        (out.decision, [v.reason_id for v in out.verdicts], out.text, getattr(out, "autonomy", None))


def _without_d71(monkeypatch, repo, command: str, autonomous: bool):
    """The same, with D71 taken out of the base path: the answer decide() gives without D71."""
    with monkeypatch.context() as m:
        m.setattr(gate, "_work_profile", lambda outcome, *args, **kwargs: outcome)
        return _outcome(repo, command, autonomous)


@pytest.mark.parametrize("form", FORMS)
def test_D130_without_the_flag_a_form_of_the_work_profile_gets_the_answer_of_decide_without_d71(tmp_path, monkeypatch,
                                                                                              form):
    repo = d71._repo(tmp_path)
    command = d71._command(form, repo, tmp_path)
    got = _outcome(repo, command, autonomous=False)
    assert got[0] == "ask" and "free_work_profile" not in got[1], (form, got[:2])
    assert got == _without_d71(monkeypatch, repo, command, autonomous=False), form


@pytest.mark.parametrize("form", FORMS)
def test_D130_control_with_the_flag_a_form_of_the_work_profile_passes_as_before(tmp_path, form):
    repo = d71._repo(tmp_path)
    assert _outcome(repo, d71._command(form, repo, tmp_path), autonomous=True)[:2] == ("pass", ["free_work_profile"])


def test_D130_without_the_flag_an_ask_whose_check_found_a_hook_does_not_name_the_work_profile(tmp_path, monkeypatch):
    """The note of D71 in an ask ("The work profile frees … only where its check finds nothing") is D71's answer too."""
    repo = d71._repo(tmp_path)
    d71._hook(repo, "pre-commit")
    got = _outcome(repo, "git commit --amend --no-edit", autonomous=False)
    assert got[0] == "ask" and "The work profile frees" not in got[2], got[2]
    assert got == _without_d71(monkeypatch, repo, "git commit --amend --no-edit", autonomous=False)


@pytest.mark.parametrize("form", HOOK_FORMS)
def test_D130_the_hook_as_hooks_json_starts_it_asks_for_a_form_of_the_work_profile(tmp_path, form):
    repo = d71._repo(tmp_path)
    answer, entry = d125._run_shipped(repo, tmp_path, "Bash", {"command": form})
    assert d125._decision(answer) == "ask", (form, answer)
    assert "free_work_profile" not in entry["reason_ids"] and "autonomy" not in entry, (form, entry)


@pytest.mark.parametrize("form", HOOK_FORMS)
def test_D130_control_the_gate_started_with_the_flag_frees_the_form_as_before(tmp_path, form):
    repo = d71._repo(tmp_path)
    proc, entry = ga.run_hook([sys.executable, "-I", gate.__file__, "--autonomous"], _event(repo, form),
                              d125._env(tmp_path, "data-flag"), cwd=str(repo))
    assert proc.returncode == 0, proc.stderr
    answer = ga.parsed(proc, entry)
    assert isinstance(answer, ga.Silent) and answer.entry.get("reason_ids") == ["free_work_profile"], (form, answer)
    assert not (tmp_path / "gh_started.log").exists()


def test_D130_control_with_the_flag_a_rewrite_whose_calls_d71_frees_is_split_as_before(tmp_path):
    """A call of a rewrite of D85 is judged as the gate with the flag judges it: the two gh forms of D71 are each free,
    so the chain gets the rewrite into its two calls (umweg), not the card of D93 for an external effect."""
    repo = d71._repo(tmp_path)
    command = "gh pr merge 12 -R b7n0de/proofbundle --auto --merge; gh pr edit 12 -R b7n0de/proofbundle --title t"
    decision, reasons, _text, autonomy = _outcome(repo, command, autonomous=True)
    assert decision == "deny" and reasons[-1] == "autonomy_rewrite", reasons
    assert autonomy["klasse"] == "umweg" and len(autonomy["aufrufe"]) == 2, autonomy


@pytest.mark.parametrize("autonomous", [False, True])
@pytest.mark.parametrize("form", HOOK_FORMS)
def test_D130_control_under_codex_no_form_of_the_work_profile_is_free(tmp_path, form, autonomous):
    """Codex never had D71: the outcome is an ask, which the answer under Codex sends as a deny (D12)."""
    repo = d71._repo(tmp_path)
    decision, reasons, _text, _autonomy = _outcome(repo, form, autonomous, host="codex")
    assert decision in ("ask", "deny") and "free_work_profile" not in reasons, (form, autonomous, reasons)


@pytest.mark.parametrize("autonomous", [False, True])
def test_D130_control_a_commit_with_a_message_stays_free_by_the_state_check_of_d3(tmp_path, autonomous):
    repo = d71._repo(tmp_path)
    assert _outcome(repo, "git commit -m work", autonomous)[:2] == ("pass", ["free_after_state_check"])
