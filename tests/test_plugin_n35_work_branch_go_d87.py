"""D87, follow-up note 35, point 5: a push to the own work branch is free under the standing GO for work branches, once the
gate measured it.

The order, translated: "a push to an own work branch is to be free under the standing GO for work branches, once it
is measured". AGENTS.md names the work branches `<agent>/<topic>`; under Claude Code the own ones are claude/… (owner
question O35-3).

The rule (D87, in the autonomous answer of D85, under Claude Code): one `git push` call that decide() asked for only
because the destination's state on the remote is not measured (push_not_measured), the evidence at every commit it
sends having shown no failure (Verdict.sources_clean), passes where D86 measured exactly one destination, refs/heads/
claude/<name> with the branch grammar of the fetch form, with no force, mirror, deletion or tag, to a configured remote;
the repository is one of D71 (it declares, every URL of every remote is https://github.com/b7n0de/…); the push
configuration adds nothing and the push URL is the fetch URL; GIT_NAMESPACE is unset; and the evidence rules at the
commit it sends equal those at the local record of the destination or, for a new branch, of the branch the remote's HEAD
names (D20). The pass shows one line to the user and carries no permission decision (as a call a rule frees, D25).
Nothing else gets freer.

Changed by D129 (owner answer 9 of Nachtrag 7): the GO applies only where the hook's environment also sets
PROOFBUNDLE_STANDING_GO to `protected`, the house's consent to it. Every case here runs with that setting
(tests/_standing_go.py); tests/test_plugin_standing_go_consent_d129.py holds the answer without it.

RED at the head of D86: the free pushes (they asked). Every counter case (another branch, force, another owner, no record
of the remote, other evidence rules, a chain, Codex) is a control, green at both.
"""
from __future__ import annotations

import json
import os
import sys

import pytest
from _standing_go import standing_go_consented  # noqa: F401 - D129: the house consents to the standing GO

import _gate_answer as ga
import test_plugin_n29_work_profile_d71 as d71

gate = d71.gate
pytestmark = d71.pytestmark
_clean = d71._clean
#: The flag with which the plugin's hook of Claude Code starts the gate (hooks.json, D85); a gate without the autonomous
#: answer (the base of the red run) is started as it always was.
AUTONOMOUS = [gate.AUTONOMOUS_FLAG] if hasattr(gate, "AUTONOMOUS_FLAG") else []
#: D129: the house's consent to the standing GO, which _hook carries where the case's environment sets it.
STANDING_GO = "PROOFBUNDLE_STANDING_GO"

#: Changed in follow-up note 37 (D92): `claude/x:claude/y` names another branch than the one it sends, so it left this list.
FREE = ["git push origin claude/x", "git push -u origin HEAD", "git push origin HEAD:refs/heads/claude/x",
        "git push -q origin claude/x", "git -C {R} push origin claude/x",
        "git push origin claude/x --dry-run", "git push --set-upstream origin claude/x"]
#: Counter cases in the same repository: each keeps its answer. Changed in follow-up note 37 (D92): `git push origin topic`
#: is the local branch of the same name and passes, `claude/x:claude/y` names another branch and asks.
KEEP = [("git push origin claude/x:codex/y", "ask"), ("git push origin claude/x:claude/y", "ask"),
        ("git push -f origin claude/x", "deny"), ("git push origin +claude/x", "deny"),
        ("git push origin claude/x:main", "deny"), ("git push origin --delete claude/x", "ask"),
        ("git push --tags origin", "ask"), ("git push origin claude/x claude/z", "ask"),
        ("git add -A && git push origin claude/x", "deny"), ("git push origin claude/x:refs/tags/claude", "ask")]


def _fixture(tmp_path, url=d71.URL, record=True, declared_main=True):
    repo = d71._repo(tmp_path, url=url, declaration=d71.DECLARATION if declared_main else None)
    if record:
        d71._git(repo, "update-ref", "refs/remotes/origin/main", "main")
        d71._git(repo, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
    d71._git(repo, "checkout", "-q", "-b", "claude/x", "main")
    if not declared_main:
        (repo / ".proofbundle").mkdir()
        (repo / ".proofbundle" / "evidence.json").write_text(d71.DECLARATION)
    (repo / "w.txt").write_text("work\n")
    d71._git(repo, "add", "-A")
    d71._git(repo, "commit", "-q", "-m", "W")
    d71._git(repo, "branch", "claude/z", "HEAD")
    return repo


def _hook(repo, tmp_path, command, host="claude", extra=None):
    event = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(repo), "session_id": "s-d87",
             "tool_input": {"command": command.replace("{R}", str(repo))}}
    env = {k: os.environ[k] for k in ("PATH", "HOME", "LC_ALL", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
                                      "PROOFBUNDLE_GATE_DIR")}
    if STANDING_GO in os.environ:   # D129: set where a module takes tests/_standing_go.py
        env[STANDING_GO] = os.environ[STANDING_GO]
    env["CLAUDE_PLUGIN_DATA"] = env["PLUGIN_DATA"] = str(tmp_path / "data")
    env.update(extra or {})
    proc, entry = ga.run_hook([sys.executable, "-I", gate.__file__, "--host", host, *AUTONOMOUS], json.dumps(event), env,
                              cwd=str(repo))
    assert proc.returncode == 0, proc.stderr
    return (json.loads(proc.stdout) if proc.stdout.strip() else None), entry


@pytest.mark.parametrize("form", FREE)
def test_D87_a_push_to_the_own_work_branch_is_free_under_the_standing_go(tmp_path, form):
    repo = _fixture(tmp_path)
    answer, entry = _hook(repo, tmp_path, form)
    assert "permissionDecision" not in answer["hookSpecificOutput"], answer
    # changed in follow-up note 37: the short line names D92, which widened D87
    assert "(D92)." in ga.short_text(answer) and "free_work_branch_go" in entry["reason_ids"]
    assert (entry["verdict"], entry["decision"], entry["autonomy"]["klasse"]) == ("ask", "none", "go"), entry


@pytest.mark.parametrize("form, decision", KEEP)
def test_D87_control_every_other_push_keeps_its_answer(tmp_path, form, decision):
    repo = _fixture(tmp_path)
    answer, entry = _hook(repo, tmp_path, form)
    # changed in follow-up note 37 (D93): in this repository of the work profile of b7n0de an ask of the closed list is a
    # card on the owner's decision board, a deny with autonomy_card
    if decision == "ask":
        decision = "deny" if "autonomy_card" in entry["reason_ids"] else "ask"
        assert "autonomy_card" in entry["reason_ids"], (form, entry["reason_ids"])
    assert answer["hookSpecificOutput"].get("permissionDecision") == decision, (form, answer)
    assert "free_work_branch_go" not in entry["reason_ids"]


@pytest.mark.parametrize("setup", ["other_owner", "no_record", "rules_differ", "no_declaration_at_head",
                                   "push_url", "namespace", "push_list"])
def test_D87_control_the_go_needs_every_measured_condition(tmp_path, setup):
    if setup == "other_owner":
        repo = _fixture(tmp_path, url="https://github.com/someone/proofbundle.git")
    elif setup == "no_record":
        repo = _fixture(tmp_path, record=False)
    elif setup == "rules_differ":
        repo = _fixture(tmp_path, declared_main=False)   # main declares nothing, the work branch adds the declaration
    else:
        repo = _fixture(tmp_path)
    if setup == "no_declaration_at_head":
        d71._git(repo, "rm", "-q", ".proofbundle/evidence.json")
        d71._git(repo, "commit", "-q", "-m", "drop")
    elif setup == "push_url":
        d71._git(repo, "remote", "set-url", "--push", "origin", "https://github.com/b7n0de/other.git")
    elif setup == "push_list":
        d71._git(repo, "config", "remote.origin.push", "refs/heads/*:refs/heads/*")
    extra = {"GIT_NAMESPACE": "x"} if setup == "namespace" else None
    answer, entry = _hook(repo, tmp_path, "git push origin claude/x", extra=extra)
    assert answer is not None and answer["hookSpecificOutput"].get("permissionDecision") in ("ask", "deny"), \
        (setup, answer)
    assert "free_work_branch_go" not in entry["reason_ids"], setup


def test_D87_control_codex_keeps_its_answer(tmp_path):
    repo = _fixture(tmp_path)
    answer, entry = _hook(repo, tmp_path, "git push origin claude/x", host="codex")
    assert answer is not None and "free_work_branch_go" not in entry["reason_ids"]


def test_D87_the_destinations_of_the_go_are_branches():
    # changed in follow-up note 37 (D92): the prefix claude/ gave way to the local branch of the same name (_go_source)
    assert gate.GO_BRANCHES == "refs/heads/"
