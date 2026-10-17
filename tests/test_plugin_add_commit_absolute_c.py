"""D40, part 1 of Nachtrag 15: `git add` and `git commit` after exactly one `-C` with a literal absolute path.

Measured in the pilot at 14a5feb1: `git -C /mnt/<speicher>/claude_worktrees/scope_631 add docs/release_scope/6.3.1.md`
asked. K-NW-2 B (D3, D33) freed add and commit only with no global option, while the read forms of class a take one
literal `-C`, and the gate's own answer tells the agent to name the repository with `git -C <absolute path>`. delta
works in linked work trees and starts its sessions elsewhere. Now such a form is judged as the form without `-C` is: the
same options, the repository the path names, and the same state check, which reads a linked work tree through git
(its `.git` file, gitdir and commondir, the hooks of the common directory or of core.hooksPath, config.worktree).
More than one `-C`, a relative path, a path the shell may rewrite and any other global option stay as they are today.

RED at ff554382 for the form of the pilot under both hosts, for the plain chain, and for the asks that name what the
state check of a linked work tree found (there the form was not free at all, and the ask named no source). The
controls answer the same at both heads.
"""
from __future__ import annotations

import pytest

import _worktree_layout as w

pytestmark = w.d.pytestmark


@pytest.fixture(autouse=True)
def _clean(monkeypatch, tmp_path):
    w.clean(monkeypatch, tmp_path)


@pytest.fixture
def layout(tmp_path):
    main = w.main_repo(tmp_path)
    return main, w.linked_worktree(tmp_path, main)


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_P1_the_add_of_the_pilot_is_free_after_the_state_check(tmp_path, layout, host):
    _main, scope = layout
    command = f"git -C {scope} add docs/release_scope/6.3.1.md"
    assert w.answer(tmp_path, command, host) == (0, None, "")


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_P1_a_commit_with_a_message_after_one_absolute_dash_C_is_free(tmp_path, layout, host):
    _main, scope = layout
    assert w.answer(tmp_path, f"git -C {scope} commit -q -m 'docs: scope'", host) == (0, None, "")


def test_P1_add_and_commit_after_dash_C_are_free_in_a_plain_chain(tmp_path, layout):
    _main, scope = layout
    command = f"git -C {scope} add docs/release_scope/6.3.1.md && git -C {scope} commit -q -m 'docs: scope'"
    assert w.answer(tmp_path, command) == (0, None, "")


@pytest.mark.parametrize("host, expected", [("claude", "ask"), ("codex", "deny")])
def test_P1_a_hook_in_the_common_directory_of_a_linked_work_tree_asks_and_starts_in_bash(tmp_path, layout, host,
                                                                                           expected):
    main, scope = layout
    hook = main / ".git" / "hooks" / "pre-commit"
    w.proxy(tmp_path, hook, "pre_commit")
    w.git(scope, "add", "docs/release_scope/6.3.1.md")
    command = f"git -C {scope} commit -q -m 'docs: scope'"
    code, decision, reason = w.answer(tmp_path, command, host)
    # D49 as sharpened by Nachtrag 21: the hook by its name, the directory by its role, no path
    assert (code, decision) == (0, expected) and f"a hook: {hook.name} in the repository's own hook directory" in reason, reason
    assert w.started(tmp_path) == []          # the gate's own check started nothing
    w.bash(tmp_path, command)
    assert w.started(tmp_path) == ["pre_commit"]


def test_P1_core_hooks_path_of_a_linked_work_tree_asks_and_starts_in_bash(tmp_path, layout):
    main, scope = layout
    hooks = tmp_path / "shared_hooks"
    w.proxy(tmp_path, hooks / "pre-commit", "hooks_path")
    w.git(main, "config", "core.hooksPath", str(hooks))
    w.git(scope, "add", "docs/release_scope/6.3.1.md")
    command = f"git -C {scope} commit -q -m 'docs: scope'"
    code, decision, reason = w.answer(tmp_path, command)
    assert (code, decision) == (0, "ask") and "a hook: pre-commit in the hook directory core.hooksPath names" in reason, reason   # D49, Nachtrag 21
    w.bash(tmp_path, command)
    assert w.started(tmp_path) == ["hooks_path"]


def test_P1_the_configuration_of_the_linked_work_tree_asks_and_starts_in_bash(tmp_path, layout):
    """extensions.worktreeConfig with core.fsmonitor in config.worktree of the linked work tree only."""
    main, scope = layout
    w.git(main, "config", "extensions.worktreeConfig", "true")
    w.git(scope, "config", "--worktree", "core.fsmonitor", w.proxy(tmp_path, tmp_path / "fsm.sh", "fsmonitor"))
    command = f"git -C {scope} add docs/release_scope/6.3.1.md"
    code, decision, reason = w.answer(tmp_path, command)
    # D49, Nachtrag 21: the file by its scope, never its path
    assert (code, decision) == (0, "ask") and "core.fsmonitor in the worktree configuration" in reason, reason
    w.bash(tmp_path, command)
    assert w.started(tmp_path) == ["fsmonitor"]


@pytest.mark.parametrize("form", ["two_dash_C", "relative_dash_C", "tilde_dash_C", "dash_c_before", "git_dir"])
@pytest.mark.parametrize("host, expected", [("claude", "ask"), ("codex", "deny")])
def test_P1_control_every_other_global_option_keeps_its_answer(tmp_path, layout, form, host, expected):
    main, scope = layout
    command = {
        "two_dash_C": f"git -C {scope} -C {scope} add docs/release_scope/6.3.1.md",
        "relative_dash_C": "git -C mnt/speicher/claude_worktrees/scope_631 add docs/release_scope/6.3.1.md",
        "tilde_dash_C": "git -C ~/scope_631 add docs/release_scope/6.3.1.md",
        "dash_c_before": f"git -c core.quotepath=false -C {scope} add docs/release_scope/6.3.1.md",
        "git_dir": f"git --git-dir={main / '.git'} -C {scope} add docs/release_scope/6.3.1.md",
    }[form]
    code, decision, reason = w.answer(tmp_path, command, host)
    assert (code, decision) == (0, expected), reason
