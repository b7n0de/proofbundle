"""D71, Nachtrag 29: the work profile of Claude Code in a declared repository of b7n0de.

Owner choice of 2026-10-18 ("Lokal frei, gh pr merge --auto frei"): under Claude Code, in a repository whose HEAD
declares and whose every remote is https://github.com/b7n0de/<repo>, the reads, the local changes that can be taken
back, fetch and ls-remote, `gh pr merge --auto` and `gh pr edit` are free after the check of their class. Everything
else keeps its answer: a push to a protected branch, a tag, force, gh pr merge without --auto, gh release, a hook turned
off, a write into the configuration or the gate directory, a command the gate cannot read whole, and every form that
loses work not yet saved.

RED at c8e1e8d7 (the head of Teil A of Nachtrag 28): the free forms (FREE, the hook test, the pre-push hook case, the
note of D71 in an ask and the unit rows of _work_form). The counter cases (KEEP), the repositories D71 does not apply to
and the answers under Codex are controls, green at both. The gh the gate checks is a script that answers `--version` as
gh 2.89.0 does and records any other start; no case reaches a network.
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import time

import pytest

import _gate_answer as ga
import test_plugin_gate_n2c_push_done as n2c

gate = n2c.gate
pytestmark = n2c.pytestmark
URL = "https://github.com/b7n0de/proofbundle.git"
DECLARATION = '{"schema": "proofbundle-plugin/evidence/v0.2", "evidence": []}\n'

#: Free at the head in a declared repository of b7n0de under Claude Code; each asks at c8e1e8d7. {R} is the repository,
#: {T} the test's folder, {A} the full object name of the first commit.
FREE = [
    "git tag", "git tag -l", "git tag --list 'v*'", "git tag -l --sort=-refname", "git stash list",
    "git bundle verify {T}/have.bundle",
    "git fetch origin", "git fetch -q --prune origin main", "git ls-remote origin", "git ls-remote --heads origin",
    "git commit --amend --no-edit", "git commit --amend -m 'new message'", "git commit --allow-empty -m empty",
    "git commit -s -m signed",
    "git checkout topic", "git -C {R} checkout topic", "git checkout --detach topic", "git checkout {A}",
    "git checkout -b feature-n", "git checkout -b feature-n topic",
    "git switch topic", "git switch -c feature-m", "git switch --detach topic",
    "git branch feature-o", "git branch feature-o topic",
    "git stash", "git stash push -m note", "git stash push -u",
    "git merge --no-edit topic", "git merge --ff-only topic", "git merge --squash topic", "git merge --abort",
    "git rebase main", "git rebase --onto main {A} topic", "git rebase --abort",
    "git worktree add -b wt {T}/wt",
    "git bundle create {T}/x.bundle main", "git -C {R} bundle create {T}/y.bundle --all",
    "gh pr merge 12 -R b7n0de/proofbundle --auto --merge", "gh pr merge 12 --auto --squash",
    "gh pr merge 12 --repo=b7n0de/proofbundle --auto --rebase", "gh pr merge 12 -R b7n0de/proofbundle --disable-auto",
    "gh pr edit 12 -R b7n0de/proofbundle --body text", "gh pr edit 12 --title title --add-label bug",
]
#: Keep their answer at the head as at c8e1e8d7, under Claude Code, in the same repository: points 2 and 3 of the order.
KEEP = [
    # a push to a protected branch, a tag, force, and a push to another branch (D61, not D71)
    "git push origin main", "git push origin release/1", "git push origin chore/prepare-1", "git push origin v0",
    "git push --tags origin", "git push -f origin topic", "git push --force-with-lease origin topic",
    "git push origin topic",
    # force in the local forms
    "git checkout -f topic", "git checkout -B topic", "git switch -C topic", "git switch --discard-changes topic",
    "git switch --force topic", "git branch -f topic main", "git rebase -f main", "git worktree add -f {T}/wt2 topic",
    # gh beyond the form
    "gh pr merge 12 -R b7n0de/proofbundle --merge", "gh pr merge 12 --auto --merge --admin",
    "gh pr merge 12 --auto --merge -d", "gh pr merge 12 --auto", "gh pr merge 12 --auto --merge --squash",
    "gh pr merge 12 -R other/repo --auto --merge", "gh pr merge 12 -R github.com/b7n0de/proofbundle --auto --merge",
    "gh pr merge 012 --auto --merge", "gh release create v1",
    "gh api -X PATCH repos/b7n0de/proofbundle/pulls/12 -f body=x", "gh pr edit 12 --body-file notes.md",
    "gh pr edit 12 --base main", "gh pr edit 12 -R other/repo --body text",
    # hooks off, the configuration
    "git commit --no-verify -m x", "git -c core.hooksPath=/dev/null commit -m x", "git config core.hooksPath /dev/null",
    "git config user.name x",
    # work not yet saved
    "git reset --hard HEAD~1", "git clean -fd", "git checkout -- README.md", "git checkout README.md",
    "git restore README.md", "git stash drop", "git stash clear", "git branch -D topic",
    "git worktree remove --force {T}/wt",
    # an editor, a new tag
    "git commit", "git commit --amend", "git merge topic", "git rebase -i main", "git tag v1", "git tag -a v1 -m x",
    "git tag -d v0",
    # what the gate does not read whole
    "cd {R} && git checkout topic", "git checkout topic && git push origin topic", "git stash; git stash drop",
    "git tag -l > {T}/tags.txt", "GIT_DIR={R}/.git git tag -l",
]


def _git(repo: pathlib.Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True,
                          timeout=60).stdout.strip()


@pytest.fixture(autouse=True)
def _clean(monkeypatch, tmp_path):
    """The hook's environment: no GH_* or GIT_* name but the two empty configuration files, no PAGER, a home and a gh
    configuration folder of its own, the gate directory outside every repository, and the stand-in gh first on PATH."""
    for key in [k for k in os.environ if k.startswith(("GH_", "GIT_")) or k in ("PAGER", "GITHUB_ENTERPRISE_TOKEN",
                                                                               "XDG_CONFIG_HOME", "AI_AGENT")]:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", os.devnull)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("LC_ALL", "C")
    monkeypatch.setenv("PROOFBUNDLE_GATE_DIR", str(tmp_path / "gatedir"))
    (tmp_path / "home" / ".config" / "gh").mkdir(parents=True)
    (tmp_path / "bin").mkdir()
    _fake_gh(tmp_path / "bin")
    monkeypatch.setenv("PATH", os.pathsep.join([str(tmp_path / "bin"), "/usr/local/bin", "/usr/bin", "/bin"]))


def _fake_gh(folder: pathlib.Path, version: str = "2.89.0") -> None:
    (folder / "gh").write_text(f'#!/bin/sh\nif [ "$1" = "--version" ]; then echo "gh version {version} (2026-03-26)"; '
                               f'echo "https://github.com/cli/cli/releases/tag/v{version}"; exit 0; fi\n'
                               f'echo "$*" >> {folder.parent / "gh_started.log"}\nexit 0\n')
    (folder / "gh").chmod(0o755)


def _repo(tmp_path: pathlib.Path, url: str | None = URL, declaration: str | None = DECLARATION,
          name: str = "r") -> pathlib.Path:
    """main with commits A and C, topic from A with commit B, a declaration at HEAD, origin at url, a bundle file."""
    repo = tmp_path / name
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True, timeout=60)
    _git(repo, "config", "user.name", "t")
    _git(repo, "config", "user.email", "t@example.invalid")
    (repo / "README.md").write_text("readme\n")
    (repo / "notes.md").write_text("notes\n")
    if declaration is not None:
        (repo / ".proofbundle").mkdir()
        (repo / ".proofbundle" / "evidence.json").write_text(declaration)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "A")
    _git(repo, "tag", "v0")
    _git(repo, "checkout", "-q", "-b", "topic")
    (repo / "t.txt").write_text("t\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "B")
    _git(repo, "checkout", "-q", "main")
    (repo / "c.txt").write_text("c\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "C")
    if url is not None:
        _git(repo, "remote", "add", "origin", url)
    if not (tmp_path / "have.bundle").exists():
        _git(repo, "bundle", "create", str(tmp_path / "have.bundle"), "main")
    return repo


def _command(form: str, repo: pathlib.Path, tmp_path: pathlib.Path) -> str:
    return (form.replace("{R}", str(repo)).replace("{T}", str(tmp_path))
            .replace("{A}", _git(repo, "rev-parse", "v0^{commit}")))


def _decide(repo: pathlib.Path, command: str, host: str = "claude"):
    out = gate.decide(command, str(repo), time.monotonic() + 60, host)
    return (None, []) if out is None else (out.decision, [v.reason_id for v in out.verdicts])


@pytest.mark.parametrize("form", FREE)
def test_D71_a_form_of_the_work_profile_is_free_in_a_declared_repository_of_b7n0de(tmp_path, form):
    repo = _repo(tmp_path)
    assert _decide(repo, _command(form, repo, tmp_path)) == ("pass", ["free_work_profile"]), form


@pytest.mark.parametrize("form", FREE)
def test_D71_control_under_codex_every_form_keeps_its_answer(tmp_path, form):
    repo = _repo(tmp_path)
    decision, reasons = _decide(repo, _command(form, repo, tmp_path), "codex")
    assert decision in ("ask", "deny") and "free_work_profile" not in reasons, (form, decision, reasons)


@pytest.mark.parametrize("form", KEEP)
def test_D71_control_a_counter_case_keeps_its_answer(tmp_path, form):
    repo = _repo(tmp_path)
    decision, reasons = _decide(repo, _command(form, repo, tmp_path))
    assert decision in ("ask", "deny", "warn") and "free_work_profile" not in reasons, (form, decision, reasons)


#: Repositories D71 does not apply to; the forms keep their ask (controls, green at both).
OTHER_REPOSITORIES = {
    "no declaration": dict(declaration=None),
    "a declaration the gate does not read": dict(declaration="{not json\n"),
    "another owner": dict(url="https://github.com/o/proofbundle.git"),
    "scp form on github.com": dict(url="git@github.com:b7n0de/proofbundle.git"),
    "a host word of its own": dict(url="git@gh-b7n0de:b7n0de/proofbundle.git"),
    "no remote": dict(url=None),
}
FORMS_OF_EACH_CLASS = ["git checkout topic", "git tag -l", "git fetch origin", "git commit --amend --no-edit",
                       "gh pr merge 12 -R b7n0de/proofbundle --auto --merge", "git bundle create {T}/x.bundle main"]


@pytest.mark.parametrize("form", FORMS_OF_EACH_CLASS)
@pytest.mark.parametrize("case", sorted(OTHER_REPOSITORIES))
def test_D71_control_a_repository_d71_does_not_apply_to(tmp_path, case, form):
    repo = _repo(tmp_path, **OTHER_REPOSITORIES[case])
    decision, reasons = _decide(repo, _command(form, repo, tmp_path))
    assert decision in ("ask", "deny") and "free_work_profile" not in reasons, (case, form, decision, reasons)


@pytest.mark.parametrize("setup", ["second remote of another owner", "pushurl of another owner",
                                   "insteadOf onto a host word", "pushInsteadOf onto another owner"])
@pytest.mark.parametrize("form", FORMS_OF_EACH_CLASS)
def test_D71_control_every_url_of_every_remote_counts(tmp_path, setup, form):
    repo = _repo(tmp_path)
    if setup == "second remote of another owner":
        _git(repo, "remote", "add", "upstream", "https://github.com/o/proofbundle.git")
    elif setup == "pushurl of another owner":
        _git(repo, "remote", "set-url", "--push", "origin", "https://github.com/o/proofbundle.git")
    elif setup == "insteadOf onto a host word":
        _git(repo, "config", "url.git@gh-b7n0de:.insteadOf", "https://github.com/")
    else:
        _git(repo, "config", "url.https://github.com/o/.pushInsteadOf", "https://github.com/b7n0de/")
    decision, reasons = _decide(repo, _command(form, repo, tmp_path))
    assert decision in ("ask", "deny") and "free_work_profile" not in reasons, (setup, form, decision, reasons)


def test_D71_only_an_ask_of_the_not_modeled_kind_becomes_a_pass(tmp_path):
    """The guard of _work_profile: for a form of D71 in a repository it applies to, a deny, a pass and an ask with a
    reason outside _WORK_REPLACEABLE (a push the gate does not resolve, a step after a state change) stay as they are;
    only the not-free ask of D3 becomes the pass."""
    repo = _repo(tmp_path)
    deadline = time.monotonic() + 60
    for decision, reason in (("ask", "push_not_measured"), ("ask", "step_after_state_change"),
                             ("deny", "git_form_not_free"), ("pass", "free_after_read_profile")):
        verdict = gate.Verdict(decision, "detail (DECISIONS.md D3).", reason)
        outcome = gate.Outcome(decision, verdict.detail, [verdict])
        assert gate._work_profile(outcome, "git checkout topic", str(repo), deadline, "claude", None) is outcome
    verdict = gate.Verdict("ask", "detail (DECISIONS.md D3).", "git_form_not_free")
    asked = gate.Outcome("ask", verdict.detail, [verdict])
    assert gate._work_profile(asked, "git checkout topic", str(repo), deadline, "claude", None).decision == "pass"


def _hook(repo: pathlib.Path, name: str, where: pathlib.Path | None = None) -> None:
    hooks = where or repo / ".git" / "hooks"
    hooks.mkdir(exist_ok=True)
    (hooks / name).write_text("#!/bin/sh\nexit 0\n")
    (hooks / name).chmod(0o755)


def test_D71_a_hook_the_form_runs_keeps_the_ask_and_the_text_names_d71(tmp_path):
    repo = _repo(tmp_path)
    _hook(repo, "pre-commit")
    out = gate.decide("git commit --amend --no-edit", str(repo), time.monotonic() + 60, "claude")
    assert out.decision == "ask" and "free_work_profile" not in [v.reason_id for v in out.verdicts]
    assert "The work profile frees git commit in this repository only where its check finds nothing" in out.text
    assert "pre-commit" in out.text and "(DECISIONS.md D71)" in out.text


def test_D71_the_pre_push_hook_of_level_2_leaves_the_form_free(tmp_path):
    repo = _repo(tmp_path)
    _hook(repo, "pre-push")
    assert _decide(repo, "git checkout topic") == ("pass", ["free_work_profile"])


@pytest.mark.parametrize("hook", ["post-checkout", "post-index-change", "reference-transaction", "an-unknown-hook"])
def test_D71_control_any_other_hook_keeps_a_local_form_asking(tmp_path, hook):
    repo = _repo(tmp_path)
    _hook(repo, hook)
    decision, reasons = _decide(repo, "git checkout topic")
    assert decision == "ask" and "free_work_profile" not in reasons, (hook, reasons)


def test_D71_control_a_hook_directory_in_the_work_tree_keeps_a_checkout_asking(tmp_path):
    repo = _repo(tmp_path)
    (repo / "githooks").mkdir()
    _git(repo, "config", "core.hooksPath", "githooks")
    decision, reasons = _decide(repo, "git checkout topic")
    assert decision == "ask" and "free_work_profile" not in reasons, reasons


def test_D71_control_an_include_from_the_work_tree_keeps_a_checkout_asking(tmp_path):
    repo = _repo(tmp_path)
    (repo / "extra.gitconfig").write_text("[user]\n\tname = t\n")
    _git(repo, "config", "include.path", "../extra.gitconfig")
    decision, reasons = _decide(repo, "git switch topic")
    assert decision == "ask" and "free_work_profile" not in reasons, reasons


def test_D71_a_pager_keeps_a_read_asking_unless_the_host_gives_no_terminal(tmp_path, monkeypatch):
    """The read profile of D34 applies: a pager the configuration names keeps `git tag -l` asking; under the host of D42,
    whose Bash tool gives the command no terminal, it is noted and does not count."""
    repo = _repo(tmp_path)
    _git(repo, "config", "core.pager", "cat")
    decision, reasons = _decide(repo, "git tag -l")
    assert decision == "ask" and "free_work_profile" not in reasons, reasons
    monkeypatch.setenv("AI_AGENT", "claude-code_2-1-301_harness")
    assert _decide(repo, "git tag -l") == ("pass", ["free_work_profile"])


def test_D71_control_the_fetch_profile_keeps_a_fetch_with_a_proxy_asking(tmp_path):
    repo = _repo(tmp_path)
    _git(repo, "config", "http.proxy", "http://127.0.0.1:9")
    for form in ("git fetch origin", "git ls-remote origin"):
        decision, reasons = _decide(repo, form)
        assert decision == "ask" and "free_work_profile" not in reasons, (form, reasons)


def test_D71_control_a_filter_keeps_a_stash_asking(tmp_path):
    repo = _repo(tmp_path)
    _git(repo, "config", "filter.x.clean", "cat")
    decision, reasons = _decide(repo, "git stash")
    assert decision == "ask" and "free_work_profile" not in reasons, reasons


def test_D71_control_a_branch_that_is_also_a_path_keeps_the_checkout_asking(tmp_path):
    repo = _repo(tmp_path)
    _git(repo, "branch", "notes.md")
    decision, reasons = _decide(repo, "git checkout notes.md")
    assert decision == "ask" and "free_work_profile" not in reasons, reasons


def test_D71_control_a_remote_tracking_start_keeps_the_new_branch_asking(tmp_path):
    repo = _repo(tmp_path)
    _git(repo, "update-ref", "refs/remotes/origin/main", "main")
    for form in ("git checkout -b feature-x origin/main", "git branch feature-x origin/main",
                 "git switch -c feature-x origin/main"):
        decision, reasons = _decide(repo, form)
        assert decision == "ask" and "free_work_profile" not in reasons, (form, reasons)


def test_D71_control_a_bundle_onto_an_existing_file_or_into_the_gate_directory(tmp_path):
    repo = _repo(tmp_path)
    (tmp_path / "gatedir").mkdir()
    for form in (f"git bundle create {tmp_path}/have.bundle main", f"git bundle create {tmp_path}/gatedir/x.bundle main"):
        decision, reasons = _decide(repo, form)
        assert decision in ("ask", "deny") and "free_work_profile" not in reasons, (form, reasons)


def test_D71_control_the_gate_directory_in_the_work_tree_keeps_every_form(tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    monkeypatch.setenv("PROOFBUNDLE_GATE_DIR", str(repo / "gatedir"))
    decision, reasons = _decide(repo, "git checkout topic")
    assert decision == "ask" and "free_work_profile" not in reasons, reasons


def test_D71_GH_REPO_of_another_owner_counts_only_where_the_command_names_no_repository(tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    monkeypatch.setenv("GH_REPO", "other/repo")
    decision, reasons = _decide(repo, "gh pr merge 12 --auto --merge")
    assert decision == "ask" and "free_work_profile" not in reasons, reasons
    assert _decide(repo, "gh pr merge 12 -R b7n0de/proofbundle --auto --merge") == ("pass", ["free_work_profile"])


def test_D71_control_a_gh_whose_version_the_gate_has_not_measured(tmp_path):
    repo = _repo(tmp_path)
    _fake_gh(tmp_path / "bin", "2.0.0")
    decision, reasons = _decide(repo, "gh pr merge 12 -R b7n0de/proofbundle --auto --merge")
    assert decision == "ask" and "free_work_profile" not in reasons, reasons


@pytest.mark.parametrize("host, expected", [("claude", None), ("codex", "deny")])
def test_D71_the_hook_as_the_host_runs_it(tmp_path, host, expected):
    """The whole hook path, `python -I gate --host <host>` with the event on stdin: `gh pr merge --auto` of the owner's
    word gets no answer under Claude Code (a pass is silent, D53) and is denied under Codex."""
    repo = _repo(tmp_path)
    event = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(repo),
                        "tool_input": {"command": "gh pr merge 12 -R b7n0de/proofbundle --auto --merge"}})
    env = {k: os.environ[k] for k in ("PATH", "HOME", "LC_ALL", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
                                      "PROOFBUNDLE_GATE_DIR")}
    proc, entry = ga.run_hook([sys.executable, "-I", gate.__file__, "--host", host], event, env, cwd=str(repo))
    answer = ga.parsed(proc, entry)
    assert proc.returncode == 0, proc.stderr
    if expected is None:
        assert isinstance(answer, ga.Silent) and answer.entry.get("reason_ids") == ["free_work_profile"], answer
        assert not (tmp_path / "gh_started.log").exists()
    else:
        assert answer["hookSpecificOutput"]["permissionDecision"] == expected, answer


@pytest.mark.parametrize("command, name", [
    ("git tag -l", "git tag"), ("git stash", "git stash push"), ("git stash list", "git stash list"),
    ("git checkout topic", "git checkout"), ("git -C /abs/r switch -c x", "git switch"),
    ("git merge --no-edit topic", "git merge"), ("git rebase main", "git rebase"),
    ("git bundle verify f.bundle", "git bundle verify"), ("git fetch origin", "git fetch origin"),
    ("gh pr merge 1 --auto --merge", "gh pr merge --auto"), ("gh pr edit 1 --title t", "gh pr edit"),
    ("git checkout -f topic", None), ("git checkout -B topic", None), ("git switch -C topic", None),
    ("git switch --force topic", None), ("git switch --discard-changes topic", None), ("git branch -f a b", None),
    ("git rebase -f main", None), ("git worktree add -f /abs/w", None), ("gh pr merge 1 --auto --merge --admin", None),
    ("git push -f origin topic", None), ("git push origin topic", None), ("git status", None),
    ("git checkout topic | cat", None), ("git -c a=b checkout topic", None), ("git -C rel checkout topic", None),
    ("git checkout 'topic'*", None), ("git merge topic", None), ("git commit", None),
])
def test_D71_the_forms_of_the_grammar(command, name):
    form = gate._work_form(command)
    assert (form.name if form is not None else None) == name, (command, form)
