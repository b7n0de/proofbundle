"""D50, Ergänzung 1 to Nachtrag 20, part 4: extensions.worktreeConfig hinders no read form, no form of the state check
and not the fetch of D45; every key it lets git read is judged.

Measured by delta at a8ca017a: `git log` in 2bedone asked with "a configuration key the read profile does not know to
start no program: extensions.worktreeconfig in the local configuration .git/config".

Ground truth, git 2.43.0 under strace -f with no network (truth_n20_local.py, truth_n20_fetch.py of the delivery): with
the key true or false, under format version 0 and 1, ten read forms, add, commit -m and worktree add -q started what they
start without it and opened no connection; the fetch of D45 started git-remote-https alone and reached github.com alone,
as without it. An invalid value ended git with exit 128 before it started anything. With the key true, config.worktree
took effect in the main and in a linked worktree (core.fsmonitor and diff.external started), and `git config --list
--show-scope --show-origin`, the listing every check of the gate reads, named those keys with the scope worktree.

RED at a8ca017a for each freed case. A program key in config.worktree asks at both heads; at a8ca017a its reason named
the extension first, so those cases are red there by their text. An invalid value and Codex are controls, green at both.
"""
from __future__ import annotations

import pytest

import _worktree_layout as w
import test_plugin_fetch_github_profile as f
import test_plugin_uploadpack_read_profile as d44

pytestmark = w.d.pytestmark
DELTA, _answer = d44.DELTA, d44._answer
READ = ["git log -3 --oneline", "git status --short", "git diff --stat", "git show --stat HEAD", "git grep -n one"]
STATE = ["git add README.md", "git -C {repo} commit -m one-more", "git -C {repo} worktree add -q -b n20 {target} HEAD"]


@pytest.fixture(autouse=True)
def _clean(monkeypatch, tmp_path):
    w.clean(monkeypatch, tmp_path)


@pytest.fixture
def main(tmp_path):
    repo = w.main_repo(tmp_path)
    (repo / "README.md").write_text("one\ntwo\n")
    return repo


def _extension(repo, value: str = "true") -> None:
    w.git(repo, "config", "core.repositoryformatversion", "1")
    w.git(repo, "config", "extensions.worktreeConfig", value)


def _command(main, tmp_path, form: str) -> str:
    if "commit" in form:
        w.git(main, "add", "README.md")
    return form.format(repo=main, target=tmp_path / "wt_n20")


@pytest.mark.parametrize("value", ["true", "false"])
@pytest.mark.parametrize("form", READ + STATE)
def test_N20_a_form_with_extensions_worktreeconfig_is_free(tmp_path, main, form, value):
    _extension(main, value)
    code, decision, reason = _answer(main, _command(main, tmp_path, form), **DELTA)
    assert (code, decision) == (0, None), (form, reason)


@pytest.mark.parametrize("value", ["true", "false"])
def test_N20_the_fetch_of_D45_with_extensions_worktreeconfig_is_free(tmp_path, monkeypatch, value):
    f._clean.__wrapped__(monkeypatch, tmp_path)
    repo = f.repo.__wrapped__(tmp_path)
    _extension(repo, value)
    out = f._decide(repo, "git -C {a} fetch -q origin main")
    assert f._fetch_free(out), out and out.text


@pytest.mark.parametrize("form", ["git status --short", "git diff --stat"])   # the forms fsmonitor counts for (D34)
def test_N20_control_core_fsmonitor_in_config_worktree_asks(tmp_path, main, form):
    _extension(main)
    w.git(main, "config", "--worktree", "core.fsmonitor", str(tmp_path / "fsm"))
    code, decision, reason = _answer(main, form, **DELTA)
    assert (code, decision) == (0, "ask") and "core.fsmonitor" in reason and "config.worktree" in reason, reason


def test_N20_control_diff_external_in_config_worktree_asks(tmp_path, main):
    _extension(main)
    w.git(main, "config", "--worktree", "diff.external", str(tmp_path / "ext"))
    code, decision, reason = _answer(main, "git diff --stat", **DELTA)
    assert (code, decision) == (0, "ask") and "diff.external" in reason, reason


def test_N20_control_a_program_key_in_the_config_worktree_of_a_linked_worktree_asks(tmp_path, main):
    _extension(main)
    linked = tmp_path / "linked"
    w.git(main, "worktree", "add", "-q", str(linked), "HEAD")
    w.git(linked, "config", "--worktree", "core.fsmonitor", str(tmp_path / "fsm"))
    code, decision, reason = _answer(linked, f"git -C {linked} status --short", **DELTA)
    assert (code, decision) == (0, "ask") and "core.fsmonitor" in reason, reason
    code, decision, reason = _answer(main, f"git -C {main} status --short", **DELTA)
    assert (code, decision) == (0, None), reason      # the main worktree does not read the linked one's file


def test_N20_control_an_invalid_value_asks(tmp_path, main):
    _extension(main, "bogus")
    code, decision, reason = _answer(main, "git log -3 --oneline", **DELTA)
    assert (code, decision) == (0, "ask"), reason


def test_N20_control_under_codex_a_read_form_keeps_its_answer(tmp_path, main):
    before = _answer(main, "git log -3 --oneline", host="codex", **DELTA)[:2]
    _extension(main)
    assert _answer(main, "git log -3 --oneline", host="codex", **DELTA)[:2] == before
