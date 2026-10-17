"""D40, part 3 of Nachtrag 15: `git -C <absolute path> worktree add [-q] [-b <name>] <absolute target> [<revision>]`
after a checkout check.

Measured in the pilot at 14a5feb1: `git -C /home/konrad/proofbundle worktree add -q -b docs/release-scope-6-3-1
/mnt/bigstore/claude_worktrees/scope_631 origin/main` asked with the text for unresolved push forms; delta adds a work
tree for every order. The form writes only locally: a branch, a folder and the records under .git/worktrees. Measured
with git 2.43.0 (measure/worktree_add_starts.sh): it runs the hooks post-checkout, post-index-change and
reference-transaction, from the hook directory and through core.hooksPath, a smudge or process filter an attribute
assigns, and fsmonitor; it runs no other hook and no signing program. Under Claude Code the form is free after a check
of those ways, with a target that does not exist and is no path the gate guards; under Codex it carries the reviewer's
text of D37. --detach, --lock, --orphan, --track, -B and --force stay as they are, and so does `git fetch`.

RED at ff554382 for the form of the pilot under both hosts (Codex: the reviewer's text instead of the push text) and
for the asks that name what the check found; the controls answer the same at both heads.
"""
from __future__ import annotations

import pytest

import _worktree_layout as w

pytestmark = w.d.pytestmark
PILOT = "git -C {main} worktree add -q -b docs/release-scope-6-3-1 {target} origin/main"


@pytest.fixture(autouse=True)
def _clean(monkeypatch, tmp_path):
    w.clean(monkeypatch, tmp_path)


@pytest.fixture
def main(tmp_path):
    return w.main_repo(tmp_path)


def _pilot(main, tmp_path) -> str:
    return PILOT.format(main=main, target=w.worktree_target(tmp_path))


def test_P3_the_worktree_add_of_the_pilot_is_free_under_claude_code(tmp_path, main):
    assert w.answer(tmp_path, _pilot(main, tmp_path)) == (0, None, "")
    assert not w.worktree_target(tmp_path).exists()        # the gate ran nothing


def test_P3_the_worktree_add_of_the_pilot_carries_the_reviewer_text_under_codex(tmp_path, main):
    code, decision, reason = w.answer(tmp_path, _pilot(main, tmp_path), "codex")
    assert (code, decision) == (0, "deny") and w.CODEX_TEXT in reason and "this form" in reason, reason


@pytest.mark.parametrize("form", ["git -C {main} worktree add {target}", "git -C {main} worktree add -b x {target}",
                                  "git -C {main} worktree add -b x -q {target} main"])
def test_P3_the_shorter_spellings_are_free(tmp_path, main, form):
    assert w.answer(tmp_path, form.format(main=main, target=w.worktree_target(tmp_path))) == (0, None, "")


@pytest.mark.parametrize("hook", ["post-checkout", "reference-transaction", "post-index-change"])
def test_P3_a_hook_the_checkout_runs_asks_and_starts_in_bash(tmp_path, main, hook):
    path = main / ".git" / "hooks" / hook
    w.proxy(tmp_path, path, hook.replace("-", "_"))
    command = _pilot(main, tmp_path)
    code, decision, reason = w.answer(tmp_path, command)
    # D49 as sharpened by Nachtrag 21: the hook by its name, the directory by its role, no path
    assert (code, decision) == (0, "ask") and f"a hook: {path.name} in the repository's own hook directory" in reason, reason
    assert w.started(tmp_path) == []
    w.bash(tmp_path, command)
    assert hook.replace("-", "_") in w.started(tmp_path)


def test_P3_a_hook_of_a_linked_work_tree_lives_in_the_common_directory(tmp_path, main):
    """The repository the -C path names is itself a linked work tree: git reads the hooks of the common directory."""
    scope = w.linked_worktree(tmp_path, main)
    path = main / ".git" / "hooks" / "post-checkout"
    w.proxy(tmp_path, path, "post_checkout")
    command = f"git -C {scope} worktree add -q -b second {tmp_path / 'second'} origin/main"
    code, decision, reason = w.answer(tmp_path, command)
    assert (code, decision) == (0, "ask") and f"a hook: {path.name} in the repository's own hook directory" in reason, reason   # D49, N21
    w.bash(tmp_path, command)
    assert w.started(tmp_path) == ["post_checkout"]


def test_P3_core_hooks_path_asks_and_starts_in_bash(tmp_path, main):
    hooks = tmp_path / "shared_hooks"
    w.proxy(tmp_path, hooks / "post-checkout", "hooks_path")
    w.git(main, "config", "core.hooksPath", str(hooks))
    command = _pilot(main, tmp_path)
    code, decision, reason = w.answer(tmp_path, command)
    assert (code, decision) == (0, "ask") and "a hook: post-checkout in the hook directory core.hooksPath names" in reason, reason   # D49, N21
    w.bash(tmp_path, command)
    assert w.started(tmp_path) == ["hooks_path"]


@pytest.mark.parametrize("way", ["smudge", "process", "fsmonitor"])
def test_P3_a_filter_or_fsmonitor_asks_and_starts_in_bash(tmp_path, main, way):
    if way == "fsmonitor":
        w.git(main, "config", "core.fsmonitor", w.proxy(tmp_path, tmp_path / "fsm.sh", "fsmonitor"))
    else:
        (main / ".gitattributes").write_text("*.md filter=probe\n")
        w.git(main, "add", ".gitattributes")
        w.git(main, "commit", "-q", "-m", "attributes")
        w.git(main, "update-ref", "refs/remotes/origin/main", "HEAD")
        body = "cat" if way == "smudge" else "exit 1"
        w.git(main, "config", f"filter.probe.{way}", w.proxy(tmp_path, tmp_path / f"{way}.sh", way, body))
    command = _pilot(main, tmp_path)
    code, decision, reason = w.answer(tmp_path, command)
    assert (code, decision) == (0, "ask") and (way if way == "fsmonitor" else "a filter") in reason, reason
    w.bash(tmp_path, command)
    assert w.started(tmp_path) == [way]


def test_P3_a_hook_the_checkout_does_not_run_and_the_signing_settings_leave_it_free(tmp_path, main):
    w.proxy(tmp_path, main / ".git" / "hooks" / "pre-push", "pre_push")
    w.proxy(tmp_path, main / ".git" / "hooks" / "pre-commit", "pre_commit")
    w.git(main, "config", "commit.gpgsign", "true")
    w.git(main, "config", "gpg.program", w.proxy(tmp_path, tmp_path / "gpg.sh", "gpg", "exit 1"))
    command = _pilot(main, tmp_path)
    assert w.answer(tmp_path, command) == (0, None, "")
    w.bash(tmp_path, command)
    assert w.started(tmp_path) == []


@pytest.mark.parametrize("where", ["exists", "hook_directory", "gate_directory"])
def test_P3_a_target_that_exists_or_that_the_gate_guards_asks(tmp_path, main, monkeypatch, where):
    target = {"exists": tmp_path, "hook_directory": main / ".git" / "hooks" / "new",
              "gate_directory": tmp_path / "gate" / "new"}[where]
    monkeypatch.setenv("PROOFBUNDLE_GATE_DIR", str(tmp_path / "gate"))
    command = f"git -C {main} worktree add -q -b x {target} origin/main"
    code, decision, reason = w.answer(tmp_path, command)
    assert (code, decision) == (0, "ask"), reason


@pytest.mark.parametrize("form", ["--force", "--detach", "--lock", "--orphan", "--track", "-B", "relative", "chain",
                                  "two_dash_C", "option_name", "fetch", "fetch_dash_C"])
@pytest.mark.parametrize("host, expected", [("claude", "ask"), ("codex", "deny")])
def test_P3_control_every_other_form_keeps_its_answer(tmp_path, main, form, host, expected):
    target = w.worktree_target(tmp_path)
    command = {
        "--force": f"git -C {main} worktree add --force -b x {target} origin/main",
        "--detach": f"git -C {main} worktree add --detach {target} origin/main",
        "--lock": f"git -C {main} worktree add --lock -b x {target} origin/main",
        "--orphan": f"git -C {main} worktree add --orphan -b x {target}",
        "--track": f"git -C {main} worktree add --track -b x {target} origin/main",
        "-B": f"git -C {main} worktree add -B x {target} origin/main",
        "relative": f"git -C {main} worktree add -b x scope_631 origin/main",
        "chain": f"{_pilot(main, tmp_path)} && echo added",
        "two_dash_C": f"git -C {main} -C {main} worktree add -b x {target} origin/main",
        "option_name": f"git -C {main} worktree add -b -x {target} origin/main",
        "fetch": "git fetch",
        "fetch_dash_C": f"git -C {main} fetch origin",
    }[form]
    code, decision, reason = w.answer(tmp_path, command, host)
    assert (code, decision) == (0, expected), reason
