"""D86, Nachtrag 35, point 5 (point 2 of Nachtrag 33): the targets of a push read from its words, its refspecs and the
local refs, never the network, and the case book's own reasons in place of push_not_measured.

The case book of Nachtrag 33 (delta, FALLBUCH_plugin_20261018): f01 to f03 (a forced push, -f, --force-with-lease), g03
(--mirror), m01 and m02 (a push to main) are to be blocked with a reason of their own; z01 and z02 (--delete, `:branch`)
are to be asked with a reason of their own. Under Claude Code the gate of the head of Nachtrag 34 asked each with
push_not_measured; under Codex it denied them, and that stays (D12).

The rule (D86, in the autonomous answer of D85, under Claude Code): for one `git push` call that decide() asks for,
_push_measure reads whether it forces (-f, --force, --force-with-lease, --force-if-includes, a `+` refspec), mirrors,
deletes (-d, --delete, --prune, `:dst`) or sends tags, and the full refs it updates (a refspec, its source's full name,
the default push of _default_push, every local branch for --all). A forced push, a mirror and a push to a protected
branch (main, master, release, release/…, the branch refs/remotes/<remote>/HEAD names) are blocked, and so is a push
whose targets the words and the local refs do not name (a URL remote, a wildcard, a `-c`, a refspec of no single ref).
A push that deletes a remote branch asks with push_delete; a tag asks (H2 of D73 stays); a push to another branch asks.

RED at the head of D85: every block and every own reason (the hook asked with push_not_measured). The pushes that keep
the ask of the closed list, a deny of decide() and Codex are controls, green at both.
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
#: The flag with which the plugin's hook of Claude Code starts the gate (hooks.json, D85); a gate without the autonomous
#: answer (the base of the red run) is started as it always was.
AUTONOMOUS = [gate.AUTONOMOUS_FLAG] if hasattr(gate, "AUTONOMOUS_FLAG") else []

#: (form, reason): blocked under Claude Code with a reason of D86; each asked at the head of D85.
BLOCKED = [
    ("git push -f origin topic", "push_force"), ("git push --force origin topic", "push_force"),
    ("git push --force-with-lease origin topic", "push_force"),
    ("git push --force-with-lease=topic origin topic", "push_force"), ("git push origin +topic", "push_force"),
    ("git push -uf origin topic", "push_force"), ("git push --force-if-includes origin topic", "push_force"),
    ("git -C {R} push -f origin topic", "push_force"), ("git push -f origin claude/x", "push_force"),
    ("git push --mirror origin", "push_mirror"),
    ("git push origin main", "push_protected"), ("git push origin HEAD:main", "push_protected"),
    ("git push origin topic:main", "push_protected"), ("git push origin topic:refs/heads/main", "push_protected"),
    ("git push origin release/1", "push_protected"), ("git push --all origin", "push_protected"),
    ("git push origin topic:develop", "push_protected"),
    ("git push https://github.com/b7n0de/proofbundle.git topic", "push_unmeasured"),
    ("git -c remote.origin.url=x push origin topic", "push_unmeasured"),
    ("git push origin 'refs/heads/*:refs/heads/*'", "push_unmeasured"), ("git push", "push_unmeasured"),
    ("git push origin nosuchbranch", "push_unmeasured"),
]
#: Asked with push_delete; each asked with push_not_measured alone at the head of D85.
DELETES = ["git push origin --delete topic", "git push origin :topic", "git push -d origin topic",
           "git push origin --delete claude/x"]
#: The closed list: still an ask, as at the head of D85.
ASKED = [("git push origin topic", "push"), ("git push origin v0", "tag"), ("git push --tags origin", "tag"),
         ("git push origin topic:feature/y", "push"), ("git -C {R} push origin topic", "push")]


def _fixture(tmp_path):
    repo = d71._repo(tmp_path)
    d71._git(repo, "branch", "release/1", "main")
    d71._git(repo, "branch", "claude/x", "topic")
    d71._git(repo, "update-ref", "refs/remotes/origin/develop", "main")
    d71._git(repo, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/develop")
    return repo


def _hook(repo, tmp_path, command, host="claude"):
    event = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(repo), "session_id": "s-d86",
             "tool_input": {"command": command.replace("{R}", str(repo))}}
    env = {k: os.environ[k] for k in ("PATH", "HOME", "LC_ALL", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
                                      "PROOFBUNDLE_GATE_DIR")}
    env["CLAUDE_PLUGIN_DATA"] = env["PLUGIN_DATA"] = str(tmp_path / "data")
    proc, entry = ga.run_hook([sys.executable, "-I", gate.__file__, "--host", host, *AUTONOMOUS], json.dumps(event), env,
                              cwd=str(repo))
    assert proc.returncode == 0, proc.stderr
    return ga.parsed(proc, entry), entry


@pytest.mark.parametrize("form, reason", BLOCKED)
def test_D86_force_mirror_a_protected_branch_and_an_unmeasured_target_are_blocked(tmp_path, form, reason):
    repo = _fixture(tmp_path)
    answer, entry = _hook(repo, tmp_path, form)
    assert answer["hookSpecificOutput"]["permissionDecision"] == "deny", answer
    assert reason in entry["reason_ids"] and entry["verdict"] == "ask", entry
    assert "(D86)." in ga.short_text(answer) and "(DECISIONS.md D86)" in \
        answer["hookSpecificOutput"]["permissionDecisionReason"]


@pytest.mark.parametrize("form", DELETES)
def test_D86_a_push_that_deletes_a_remote_branch_asks_with_its_own_reason(tmp_path, form):
    repo = _fixture(tmp_path)
    answer, entry = _hook(repo, tmp_path, form)
    assert answer["hookSpecificOutput"]["permissionDecision"] == "ask", answer
    assert "push_delete" in entry["reason_ids"], entry
    assert entry["autonomy"] == {"klasse": "aussen", "wirkung": ["push_delete"]}
    assert "(D86)." in ga.short_text(answer)


@pytest.mark.parametrize("form, effect", ASKED)
def test_D86_control_a_tag_and_another_branch_keep_the_ask(tmp_path, form, effect):
    repo = _fixture(tmp_path)
    answer, entry = _hook(repo, tmp_path, form)
    assert answer["hookSpecificOutput"]["permissionDecision"] == "ask", answer
    assert not {"push_force", "push_mirror", "push_protected", "push_unmeasured"} & set(entry["reason_ids"])


@pytest.mark.parametrize("form", ["git push --no-verify origin topic", "git -c core.hooksPath=/dev/null push origin topic"])
def test_D86_control_a_deny_of_decide_stays(tmp_path, form):
    repo = _fixture(tmp_path)
    answer, entry = _hook(repo, tmp_path, form)
    assert answer["hookSpecificOutput"]["permissionDecision"] == "deny" and "hooks_disabled" in entry["reason_ids"]
    assert "autonomy" not in entry


@pytest.mark.parametrize("form", [f for f, _r in BLOCKED] + DELETES)
def test_D86_control_codex_answers_as_before(tmp_path, form):
    repo = _fixture(tmp_path)
    answer, entry = _hook(repo, tmp_path, form, host="codex")
    assert answer["hookSpecificOutput"].get("permissionDecision") in ("deny", None), answer
    assert not {"push_force", "push_mirror", "push_protected", "push_unmeasured", "push_delete"} & \
        set(entry["reason_ids"])


@pytest.mark.parametrize("words, expected", [
    ("git push origin topic", (False, False, False, False, ["refs/heads/topic"])),
    ("git push -f origin topic", (True, False, False, False, ["refs/heads/topic"])),
    ("git push origin +topic:refs/heads/x", (True, False, False, False, ["refs/heads/x"])),
    ("git push --force-with-lease=topic:abc origin topic", (True, False, False, False, ["refs/heads/topic"])),
    ("git push origin :topic", (False, False, True, False, ["refs/heads/topic"])),
    ("git push --delete origin a b", (False, False, True, False, ["refs/heads/a", "refs/heads/b"])),
    ("git push origin v0", (False, False, False, True, ["refs/tags/v0"])),
    ("git push origin topic:v9", (False, False, False, False, ["refs/heads/v9"])),
    ("git push --tags origin", (False, False, False, True, [])),
    ("git push --mirror origin", (False, True, False, False, None)),
    ("git push origin HEAD", (False, False, False, False, ["refs/heads/main"])),
    ("git push -o ci.skip origin topic", (False, False, False, False, ["refs/heads/topic"])),
    ("git push --push-option=x origin topic", (False, False, False, False, ["refs/heads/topic"])),
    ("git push --receive-pack=x origin topic", None), ("git push -x origin topic", None),
    ("git push origin 'refs/heads/*'", None), ("git push /tmp/elsewhere topic", None),
])
def test_D86_the_measure_reads_the_words_and_the_local_refs(tmp_path, words, expected):
    repo = _fixture(tmp_path)
    import shlex
    m = gate._push_measure(shlex.split(words), str(repo), time.monotonic() + 60)
    if expected is None:
        assert m.why is not None, m
    else:
        assert (m.force, m.mirror, m.delete, m.tags, m.dests) == expected and m.why is None, m


@pytest.mark.parametrize("dest, protected", [("refs/heads/main", True), ("refs/heads/master", True),
                                             ("refs/heads/release", True), ("refs/heads/release/2.0", True),
                                             ("refs/heads/develop", True), ("refs/heads/claude/x", False),
                                             ("refs/heads/releases", False), ("refs/heads/main2", False),
                                             ("refs/tags/main", False)])
def test_D86_the_protected_branches(tmp_path, dest, protected):
    repo = _fixture(tmp_path)
    assert gate._push_protected(str(repo), "origin", dest, time.monotonic() + 60) is protected, dest
