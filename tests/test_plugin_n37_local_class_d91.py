"""D91, Nachtrag 37, Ergänzung 1: the local class that can be taken back is free in autonomous operation.

The owner's screens of delta (gate 89d2e8b7, 2026-10-18 23:11 Berlin): `git merge` of main into the own branch with a
message from a file asked (D8), and so did `git -C <absolute path> merge-tree --write-tree <sha> refs/remotes/origin/main`.
At the head of Nachtrag 35 (d2314682) both were blocked under Claude Code (autonomy_blocked), as no rewrite of them is free.
The order: add, commit, merge and merge-tree, a branch or a work tree made, stash, all in the own clone without the
network, are free and stand in the gate log; a write into hooks, the configuration, the gate directory or the
declaration blocks.

Measured with git 2.43.0 (truth_local_n37.py of the delivery, 30 runs, every hook a marker, strace -f): merge with -m,
-F or --file= starts no editor, on a pipe and on a terminal, and runs the hooks of a merge commit; merge-tree
--write-tree starts no hook and no program and changes no path outside the object store; stash pop and apply run
post-index-change and reference-transaction.

The rule (D91, in the autonomous answer of D85, under Claude Code): an ask of decide() whose every reason is one D71
replaces, for one form of the local class (the read, local and target forms of D71, merge with a message, merge-tree
--write-tree, stash pop and apply), in any repository that does not overlap the gate directory, is free where the check
of its class finds nothing; it is blocked where the form writes configuration or hooks (write_to_repo_state) or the
declaration (write_to_declaration); it keeps the ask where a program of the clone starts (local_program, O37-1).

RED at d2314682 (the head of Nachtrag 35): the new free forms, the reasons of the blocks, the kept ask for a program and
the rewrite through `cd`. The counter cases (an editor, standard input, two revisions, merge-tree without --write-tree,
a ref git refuses, Codex, the hook without the flag) are controls, green at both.
"""
from __future__ import annotations

import json
import os
import sys
import time

import pytest

import _gate_answer as ga
import test_plugin_n29_work_profile_d71 as d71

gate = d71.gate
pytestmark = d71.pytestmark
_clean = d71._clean
#: The flag with which the plugin's hook of Claude Code starts the gate (hooks.json, D85).
AUTONOMOUS = [gate.AUTONOMOUS_FLAG] if hasattr(gate, "AUTONOMOUS_FLAG") else []
OTHER_DECLARATION = '{"schema": "proofbundle-plugin/evidence/v0.2", "evidence": [], "note": "other"}\n'


def _repos(tmp_path):
    """b7n0de: the declared repository of D71; fremd: the same of another owner; ohne: no declaration, no remote."""
    return {"b7n0de": d71._repo(tmp_path), "fremd": d71._repo(tmp_path, url="https://github.com/someone/x.git",
                                                              name="f"),
            "ohne": d71._repo(tmp_path, url=None, declaration=None, name="o")}


def _form(form, repo, tmp_path):
    (tmp_path / "msg.txt").write_text("Merge topic\n")
    return d71._command(form, repo, tmp_path).replace("{SHA}", d71._git(repo, "rev-parse", "main"))


def answered(repo, command, host="claude"):
    deadline = time.monotonic() + 60
    out = gate.decide(command, str(repo), deadline, host)
    if host == "claude" and out is not None and out.decision == "ask":
        out = gate.autonomous_outcome(out, command, str(repo), deadline, host)
    if out is None:
        return None, [], None
    return out.decision, [v.reason_id for v in out.verdicts], (getattr(out, "autonomy", None) or {}).get("klasse")


#: Free at the head in every repository; blocked or asked at d2314682 in every one.
NEW_FREE = [
    "git -C {R} merge -F {T}/msg.txt topic", "git merge -F {T}/msg.txt topic", "git merge --file={T}/msg.txt topic",
    "git merge --no-ff -F {T}/msg.txt topic", "git merge -m 'Merge topic' topic", "git merge -q --no-ff -m x topic",
    "git -C {R} merge-tree --write-tree {SHA} refs/heads/topic", "git merge-tree --write-tree main topic",
    "git merge-tree --write-tree --name-only --no-messages main topic",
    "git merge-tree --write-tree -z --merge-base={A} main topic",
]
#: Free under D71 in the declared repository of b7n0de already; free at the head in the others too.
NEW_FREE_ELSEWHERE = ["git branch feature-o", "git switch -c feature-m", "git checkout -b feature-n topic",
                      "git stash list", "git tag -l", "git -C {R} branch feature-p main"]


@pytest.mark.parametrize("kind", ["b7n0de", "fremd", "ohne"])
@pytest.mark.parametrize("form", NEW_FREE)
def test_D91_merge_with_a_message_and_merge_tree_are_free_in_every_repository(tmp_path, form, kind):
    repo = _repos(tmp_path)[kind]
    decision, reasons, klasse = answered(repo, _form(form, repo, tmp_path))
    assert (decision, klasse) == ("pass", "lokal") and "free_local_reversible" in reasons, (form, kind, reasons)


@pytest.mark.parametrize("kind", ["fremd", "ohne"])
@pytest.mark.parametrize("form", NEW_FREE_ELSEWHERE)
def test_D91_the_local_forms_of_d71_are_free_outside_b7n0de_too(tmp_path, form, kind):
    repo = _repos(tmp_path)[kind]
    decision, reasons, klasse = answered(repo, _form(form, repo, tmp_path))
    assert (decision, klasse) == ("pass", "lokal") and "free_local_reversible" in reasons, (form, kind, reasons)


@pytest.mark.parametrize("form", NEW_FREE_ELSEWHERE)
def test_D91_control_d71_keeps_its_own_pass_in_b7n0de(tmp_path, form):
    repo = _repos(tmp_path)["b7n0de"]
    assert answered(repo, _form(form, repo, tmp_path))[:2] == ("pass", ["free_work_profile"])


@pytest.mark.parametrize("form", ["git stash pop", "git stash pop -q", "git stash apply", "git stash apply 'stash@{0}'",
                                  "git -C {R} stash pop --index"])
def test_D91_stash_pop_and_apply_are_free(tmp_path, form):
    repo = _repos(tmp_path)["fremd"]
    (repo / "README.md").write_text("changed\n")
    d71._git(repo, "stash", "-q")
    decision, reasons, klasse = answered(repo, _form(form, repo, tmp_path))
    assert (decision, klasse) == ("pass", "lokal") and "free_local_reversible" in reasons, (form, reasons)


@pytest.mark.parametrize("hook", ["post-merge", "pre-merge-commit", "commit-msg", "reference-transaction"])
def test_D91_a_hook_the_merge_starts_keeps_the_ask(tmp_path, hook):
    repo = _repos(tmp_path)["fremd"]
    (repo / ".git" / "hooks" / hook).write_text("#!/bin/sh\nexit 0\n")
    (repo / ".git" / "hooks" / hook).chmod(0o755)
    decision, reasons, klasse = answered(repo, _form("git merge -F {T}/msg.txt topic", repo, tmp_path))
    assert (decision, klasse) == ("ask", "aussen") and "local_program" in reasons, reasons


def test_D91_merge_tree_starts_no_hook_but_a_merge_driver_counts(tmp_path):
    repo = _repos(tmp_path)["fremd"]
    for hook in ("post-merge", "pre-commit", "pre-commit.local"):
        (repo / ".git" / "hooks" / hook).write_text("#!/bin/sh\nexit 0\n")
        (repo / ".git" / "hooks" / hook).chmod(0o755)
    form = _form("git merge-tree --write-tree main topic", repo, tmp_path)
    assert answered(repo, form)[0] == "pass"
    d71._git(repo, "config", "merge.mine.driver", "true %O %A %B")
    decision, reasons, _klasse = answered(repo, form)
    assert decision == "ask" and "local_program" in reasons, reasons


def test_D91_a_configuration_file_in_the_work_tree_blocks_a_form_that_writes_it(tmp_path):
    repo = _repos(tmp_path)["fremd"]
    (repo / "inc.cfg").write_text("[user]\n\tname = t\n")
    d71._git(repo, "config", "include.path", "../inc.cfg")
    decision, reasons, klasse = answered(repo, _form("git merge -F {T}/msg.txt topic", repo, tmp_path))
    assert (decision, klasse) == ("deny", "sperre") and "write_to_repo_state" in reasons, reasons


def test_D91_a_work_tree_in_the_hook_directory_is_blocked(tmp_path):
    repo = _repos(tmp_path)["fremd"]
    decision, reasons, _klasse = answered(repo, f"git -C {repo} worktree add -b wtx {repo}/.git/hooks/wtx")
    assert decision == "deny" and "write_to_repo_state" in reasons, reasons


def _declaration_branch(repo, name="decl"):
    d71._git(repo, "checkout", "-q", "-b", name, "main")
    (repo / ".proofbundle" / "evidence.json").write_text(OTHER_DECLARATION)
    d71._git(repo, "commit", "-q", "-am", "D")
    d71._git(repo, "checkout", "-q", "main")


@pytest.mark.parametrize("form", ["git merge -F {T}/msg.txt decl", "git merge-tree --write-tree main decl"])
def test_D91_a_merge_that_brings_another_declaration_is_blocked_merge_tree_is_not(tmp_path, form):
    repo = _repos(tmp_path)["b7n0de"]
    _declaration_branch(repo)
    decision, reasons, _klasse = answered(repo, _form(form, repo, tmp_path))
    if "merge-tree" in form:
        assert decision == "pass", reasons   # it writes objects only, no work tree
    else:
        assert decision == "deny" and "write_to_declaration" in reasons, reasons


def test_D91_control_a_merge_whose_other_side_kept_the_declaration_is_free(tmp_path):
    repo = _repos(tmp_path)["b7n0de"]
    d71._git(repo, "branch", "plain", "main")
    (repo / ".proofbundle" / "evidence.json").write_text(OTHER_DECLARATION)
    d71._git(repo, "commit", "-q", "-am", "D on main")
    assert answered(repo, _form("git merge -F {T}/msg.txt plain", repo, tmp_path))[0] == "pass"


def test_D91_a_stash_or_a_switch_that_writes_the_declaration_is_blocked(tmp_path):
    repo = _repos(tmp_path)["fremd"]
    _declaration_branch(repo)
    decision, reasons, _klasse = answered(repo, "git switch decl")
    assert decision == "deny" and "write_to_declaration" in reasons, reasons
    (repo / ".proofbundle" / "evidence.json").write_text(OTHER_DECLARATION)
    d71._git(repo, "stash", "-q")
    decision, reasons, _klasse = answered(repo, "git stash pop")
    assert decision == "deny" and "write_to_declaration" in reasons, reasons


#: Not a form of the class: each keeps the answer it had at d2314682 (D85 blocks, no rewrite of it is free). An unquoted
#: `stash@{0}` is a word the shell may rewrite for the grammar (_shell_rewrites), so only its quoted form is one.
KEEP = ["git merge topic", "git merge -F - topic", "git merge -F {T}/msg.txt topic main", "git merge-tree main topic",
        "git merge -e -m x topic", "git stash pop stash@{x}", "git merge -F {T}/msg.txt nosuch",
        "git stash pop", "git merge -s ours -m x topic", "git stash apply stash@{0}", "git merge-tree --write-tree --trivial-merge main topic"]


@pytest.mark.parametrize("form", KEEP)
def test_D91_control_other_forms_keep_their_answer(tmp_path, form):
    repo = _repos(tmp_path)["fremd"]
    decision, reasons, klasse = answered(repo, _form(form, repo, tmp_path))
    assert decision == "deny" and "free_local_reversible" not in reasons and klasse == "sperre", (form, reasons)


def test_D91_control_codex_keeps_the_answer_of_decide(tmp_path):
    repo = _repos(tmp_path)["fremd"]
    command = _form("git merge -F {T}/msg.txt topic", repo, tmp_path)
    out = gate.decide(command, str(repo), time.monotonic() + 60, "codex")
    assert answered(repo, command, "codex")[:2] == (out.decision, [v.reason_id for v in out.verdicts])
    assert "free_local_reversible" not in [v.reason_id for v in out.verdicts]


def test_D91_a_rewrite_through_cd_is_now_a_detour(tmp_path):
    repo = _repos(tmp_path)["fremd"]
    decision, reasons, klasse = answered(repo, _form("cd {R} && git merge -F {T}/msg.txt topic", repo, tmp_path))
    assert (decision, klasse) == ("deny", "umweg") and "autonomy_rewrite" in reasons, reasons


def _hook(repo, tmp_path, command, flag=True):
    event = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(repo), "session_id": "s-d91",
             "tool_input": {"command": command}}
    env = {k: os.environ[k] for k in ("PATH", "HOME", "LC_ALL", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
                                      "PROOFBUNDLE_GATE_DIR")}
    env["CLAUDE_PLUGIN_DATA"] = env["PLUGIN_DATA"] = str(tmp_path / "data")
    proc, entry = ga.run_hook([sys.executable, "-I", gate.__file__, "--host", "claude", *(AUTONOMOUS if flag else [])],
                              json.dumps(event), env, cwd=str(repo))
    assert proc.returncode == 0, proc.stderr
    return proc, entry


def test_D91_the_hook_lets_it_run_silently_and_logs_the_class(tmp_path):
    repo = _repos(tmp_path)["ohne"]
    proc, entry = _hook(repo, tmp_path, _form("git merge-tree --write-tree main topic", repo, tmp_path))
    assert proc.stdout.strip() == "", proc.stdout
    assert (entry["verdict"], entry["decision"], entry["autonomy"]["klasse"]) == ("ask", "none", "lokal"), entry
    assert "free_local_reversible" in entry["reason_ids"]


def test_D91_control_without_the_flag_the_hook_asks(tmp_path):
    repo = _repos(tmp_path)["ohne"]
    proc, entry = _hook(repo, tmp_path, _form("git merge-tree --write-tree main topic", repo, tmp_path), flag=False)
    assert json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert "autonomy" not in entry
