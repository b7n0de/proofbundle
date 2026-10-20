"""D114 and D115, Nachtrag 46, Teil B: fewer asks at the gate where the owner pinned the state of the own clone.

The order: in the house profile (Claude Code with `--autonomous`), `git add` and `git commit` ask no more (D114), and the
read forms rev-parse, status, log, show, diff, ls-files, merge-base and cat-file are free (D115), where the session works
in its own tree on its own claude/ branch and the hooks, core.hooksPath and .git/config are unchanged against a pinned
state. Where any of them is new, changed or points elsewhere, the answer stays. A read form keeps the read grammar of D34:
an option that starts a program (a pager, an external diff, textconv, a signature) keeps its answer. Push, gh, the MCP
write tools and every external effect are not touched, nor is any answer without the flag or under Codex. Measured at
delta on 2026-10-20 (gate 63b88d07): git add and git commit asked in the own tree on the own claude/ branch with the
repository's own pre-commit hook, and `git rev-parse` was blocked (D85, D3).

The pin: pin-state.json in the gate directory, which only a person writes (D25), names each clone by its work tree, the
hook directory git uses for it, the sha256 of every hook in it and the sha256 of its .git/config;
`proofbundle_gate.py pin-state <path>` prints that entry and writes nothing. With the pin, the state check of D3 and the
read profile of D34 leave out the hooks whose bytes match it and the keys of the pinned .git/config they do not know,
and count as before every key that names a program by path (a filter, fsmonitor with a command, a signature program, a
configuration hook), every key of another file, every GIT_* name, and for a read the pager, fsmonitor, filter and
promisor keys.

RED at 70e98e91 (before the rule), measured 67 of 130: every free case below, the cases where a changed state takes the
freedom away (they assert the freedom first), the pinned hook of a read and the subcommand. The 63 counter cases are
green at both.
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import subprocess
import sys

import pytest

import test_plugin_n29_work_profile_d71 as d71
import test_plugin_n37_local_class_d91 as d91

gate = d71.gate
pytestmark = d71.pytestmark
_clean = d71._clean
SCHEMA = "proofbundle-plugin/pin-state/v0.1"
PRE_COMMIT = b"#!/bin/sh\n# the house's pre-commit\nexit 0\n"
KINDS = ("b7n0de", "fremd")
LOCAL = ["git add notes.md", "git add -A", "git commit -m work", "git commit -q -m work",
         "git add -A && git commit -m work"]
READS = ["git rev-parse HEAD", "git rev-parse --abbrev-ref HEAD", "git status --short", "git status",
         "git log --oneline -3", "git show --stat HEAD", "git diff", "git diff --stat HEAD~1", "git ls-files",
         "git merge-base HEAD main", "git cat-file -p HEAD"]


def _repo(tmp_path, kind="fremd", branch="claude/work", unknown_key=True, hook=True):
    """A clone of D71 on the branch, with the repository's own pre-commit hook and a configuration key the profiles do
    not know (delta's two causes), and a change to add."""
    repo = {"b7n0de": lambda: d71._repo(tmp_path),
            "fremd": lambda: d71._repo(tmp_path, url="https://github.com/someone/x.git", name="f")}[kind]()
    if branch == "detached":
        d71._git(repo, "checkout", "-q", "--detach", "topic")
    elif branch in ("topic", "main"):
        d71._git(repo, "checkout", "-q", branch)
    else:
        d71._git(repo, "checkout", "-q", "-b", branch, "topic")
    if unknown_key:
        d71._git(repo, "config", "frob.knob", "1")
    if hook:
        _hook(repo / ".git" / "hooks")
    (repo / "notes.md").write_text("changed\n")
    return repo


def _hook(folder, name="pre-commit", body=PRE_COMMIT):
    folder = pathlib.Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / name
    path.write_bytes(body)
    path.chmod(0o755)
    return path


def _sha_file(path) -> str:
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def _gate_dir() -> pathlib.Path:
    folder = pathlib.Path(os.environ["PROOFBUNDLE_GATE_DIR"])
    folder.mkdir(parents=True, exist_ok=True)
    return folder


def _entry(repo, hooks_dir=None) -> dict:
    """The entry of the pin as the owner records it now: the work tree, the hook directory git uses, every hook in it
    that is no sample, and .git/config."""
    hooks_dir = pathlib.Path(hooks_dir or repo / ".git" / "hooks")
    hooks = {p.name: _sha_file(p) for p in sorted(hooks_dir.iterdir())
             if p.is_file() and not p.name.endswith(".sample")} if hooks_dir.is_dir() else {}
    return {"pfad": str(repo), "hakenordner": str(hooks_dir), "haken": hooks,
            "konfig": _sha_file(repo / ".git" / "config")}


def _pin(entries: list, text: str | None = None) -> None:
    data = {"schema": SCHEMA, "klone": entries}
    (_gate_dir() / "pin-state.json").write_text(json.dumps(data) if text is None else text)


def answered(repo, command, host="claude"):
    return d91.answered(repo, command, host)


def _free(answer) -> bool:
    return answer[0] == "pass" and "free_pinned_state" in answer[1]


# --- the free cases ------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("form", LOCAL)
def test_D114_add_and_commit_in_the_own_tree_on_the_own_claude_branch_are_free_with_the_pin(tmp_path, form, kind):
    repo = _repo(tmp_path, kind)
    before = answered(repo, form)
    assert before[0] in ("ask", "deny") and not _free(before), before
    _pin([_entry(repo)])
    after = answered(repo, form)
    assert _free(after) and after[2] == "lokal", (form, after)


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("form", READS)
def test_D115_the_read_forms_in_the_own_tree_on_the_own_claude_branch_are_free_with_the_pin(tmp_path, form, kind):
    repo = _repo(tmp_path, kind)
    before = answered(repo, form)
    assert before[0] in ("ask", "deny") and not _free(before), before
    _pin([_entry(repo)])
    after = answered(repo, form)
    assert _free(after) and after[2] == "lokal", (form, after)


def test_D114_commit_signing_with_the_default_program_in_the_pinned_config_is_free(tmp_path):
    repo = _repo(tmp_path)
    for key, value in (("gpg.format", "ssh"), ("commit.gpgsign", "true"), ("user.signingkey", "/nonexistent/k.pub")):
        d71._git(repo, "config", key, value)
    _pin([_entry(repo)])
    assert _free(answered(repo, "git commit -m work"))


def test_D114_a_hook_directory_the_pin_names_in_the_work_tree_is_read_by_its_bytes(tmp_path):
    repo = _repo(tmp_path, hook=False)
    d71._git(repo, "config", "core.hooksPath", ".githooks")
    _hook(repo / ".githooks")
    _pin([_entry(repo, repo / ".githooks")])
    assert _free(answered(repo, "git commit -m work"))
    _hook(repo / ".githooks", body=PRE_COMMIT + b"echo changed\n")
    assert not _free(answered(repo, "git commit -m work"))


# --- what stays: the condition does not hold ------------------------------------------------------------------------

@pytest.mark.parametrize("branch", ["topic", "main", "detached", "feature/claude", "claude"])
@pytest.mark.parametrize("form", ["git commit -m work", "git rev-parse HEAD"])
def test_D114_D115_another_branch_than_an_own_claude_branch_keeps_the_answer(tmp_path, branch, form):
    repo = _repo(tmp_path, branch=branch)
    before = answered(repo, form)
    _pin([_entry(repo)])
    assert answered(repo, form) == before


def _changed(repo, tmp_path, how):
    if how == "config_key_added":
        d71._git(repo, "config", "frob.other", "2")
    elif how == "config_value_changed":
        d71._git(repo, "config", "frob.knob", "3")
    elif how == "hook_changed":
        _hook(repo / ".git" / "hooks", body=PRE_COMMIT + b"echo more\n")
    elif how == "hook_new":
        _hook(repo / ".git" / "hooks", name="commit-msg")
    elif how == "hook_removed_and_linked":
        target = _hook(tmp_path / "elsewhere")
        (repo / ".git" / "hooks" / "pre-commit").unlink()
        (repo / ".git" / "hooks" / "pre-commit").symlink_to(target)
    elif how == "hooks_path_elsewhere":
        _hook(tmp_path / "other_hooks")
        subprocess.run(["git", "-C", str(repo), "config", "core.hooksPath", str(tmp_path / "other_hooks")], check=True)
    elif how == "config_worktree":
        (repo / ".git" / "config.worktree").write_text("[frob]\n\tknob = 1\n")
    elif how == "include_with_unknown_key":
        (tmp_path / "inc.cfg").write_text("[frob]\n\tthird = 1\n")
        d71._git(repo, "config", "include.path", str(tmp_path / "inc.cfg"))
    else:
        raise AssertionError(how)


@pytest.mark.parametrize("how", ["config_key_added", "config_value_changed", "hook_changed", "hook_new",
                                 "hook_removed_and_linked", "hooks_path_elsewhere", "config_worktree"])
@pytest.mark.parametrize("form", ["git add -A", "git commit -m work", "git rev-parse HEAD", "git status --short"])
def test_D114_D115_a_state_that_is_new_changed_or_points_elsewhere_keeps_the_answer(tmp_path, how, form):
    repo = _repo(tmp_path)
    _pin([_entry(repo)])
    assert _free(answered(repo, form))
    _changed(repo, tmp_path, how)
    after = answered(repo, form)
    assert not _free(after) and after[0] in ("ask", "deny"), (how, form, after)


def test_D114_an_include_the_pinned_config_names_is_judged_as_before(tmp_path):
    repo = _repo(tmp_path, unknown_key=False)
    (tmp_path / "inc.cfg").write_text("[frob]\n\tthird = 1\n")
    d71._git(repo, "config", "include.path", str(tmp_path / "inc.cfg"))
    _pin([_entry(repo)])
    assert not _free(answered(repo, "git rev-parse HEAD"))


@pytest.mark.parametrize("key,value", [("filter.x.clean", "cat"), ("core.fsmonitor", "/bin/true"),
                                       ("gpg.ssh.program", "/usr/bin/ssh-keygen"), ("hook.pre-commit.command", "true")])
def test_D114_a_pinned_key_that_names_a_program_keeps_the_answer_of_add_and_commit(tmp_path, key, value):
    repo = _repo(tmp_path)
    d71._git(repo, "config", key, value)
    if key == "gpg.ssh.program":
        d71._git(repo, "config", "commit.gpgsign", "true")
    _pin([_entry(repo)])
    for form in ("git add -A", "git commit -m work"):
        assert not _free(answered(repo, form)), (key, form)


@pytest.mark.parametrize("key,value,form", [("core.pager", "less", "git log --oneline -3"),
                                            ("pager.log", "less", "git log --oneline -3"),
                                            ("core.fsmonitor", "/bin/true", "git status --short"),
                                            ("filter.x.clean", "cat", "git status --short"),
                                            ("remote.origin.promisor", "true", "git cat-file -p HEAD")])
def test_D115_a_pinned_key_that_starts_a_program_for_the_read_keeps_its_answer(tmp_path, key, value, form):
    repo = _repo(tmp_path)
    d71._git(repo, "config", key, value)
    if key == "filter.x.clean":
        (repo / ".gitattributes").write_text("*.md filter=x\n")
    _pin([_entry(repo)])
    assert not _free(answered(repo, form)), (key, form)


@pytest.mark.parametrize("key,value", [("hook.pre-commit.command", "true"), ("gc.recentObjectsHook", "true"),
                                       ("maintenance.strategy", "incremental")])
@pytest.mark.parametrize("form", ["git rev-parse HEAD", "git status --short"])
def test_D115_a_pinned_key_that_names_a_program_keeps_the_answer_of_a_read(tmp_path, key, value, form):
    """A key of the pinned .git/config the read profile does not know is left out only where it names no program
    (_program_source): a configuration hook and automatic maintenance keep the read's answer, pinned or not."""
    repo = _repo(tmp_path, unknown_key=False)
    d71._git(repo, "config", key, value)
    _pin([_entry(repo)])
    assert not _free(answered(repo, form)), (key, form)


@pytest.mark.parametrize("keys,form", [
    ([("diff.external", "/bin/true")], "git diff"),
    ([("diff.drv.textconv", "cat")], "git log -p -1"),
    ([("diff.drv.textconv", "cat")], "git show HEAD"),
    ([("log.showSignature", "true")], "git log --oneline -1"),
    ([("core.alternateRefsCommand", "true")], "git rev-parse HEAD"),
])
def test_D115_a_pinned_key_by_which_a_read_starts_a_program_keeps_its_answer(tmp_path, keys, form):
    """Nachtrag 46, point 2: no external diff, no textconv, no program of any kind for a read, pinned or not. The keys of
    the corpus contexts prog_diffext, prog_textconv and prog_showsig, which the first pin of D115 left out because
    _program_source, written for add and commit, names none of them (measured in the pinned variant of the corpus)."""
    repo = _repo(tmp_path, unknown_key=False)
    for key, value in keys:
        d71._git(repo, "config", key, value)
    (repo / ".gitattributes").write_text("*.md diff=drv\n")
    d71._git(repo, "add", ".gitattributes")
    d71._git(repo, "commit", "-q", "-m", "attributes")
    _pin([_entry(repo)])
    assert not _free(answered(repo, form)), (keys, form)


def test_D114_a_hook_directory_outside_the_clone_pins_nothing(tmp_path):
    """core.hooksPath on a folder beside the clone (the corpus context prog_hook): the pin names no state of the clone, so
    the gate pins nothing, and pin-state refuses to print an entry."""
    repo = _repo(tmp_path, hook=False)
    outside = tmp_path / "hooks_beside"
    _hook(outside)
    _hook(outside, name="post-index-change")
    d71._git(repo, "config", "core.hooksPath", str(outside))
    _pin([_entry(repo, outside)])
    for form in ("git commit -m work", "git status --short"):
        assert not _free(answered(repo, form)), form
    proc = subprocess.run([sys.executable, str(gate.__file__), "pin-state", str(repo)], capture_output=True, text=True,
                          timeout=60)
    assert proc.returncode == 1 and proc.stdout == "" and "outside" in proc.stderr, (proc.returncode, proc.stderr)


def test_D115_a_hook_a_read_starts_is_left_out_only_with_its_pinned_bytes(tmp_path):
    """git status starts post-index-change (D34, _HOOKS_STARTED_BY_READ): with the pin its pinned bytes do not count,
    and a changed hook counts again."""
    repo = _repo(tmp_path, hook=False)
    _hook(repo / ".git" / "hooks", name="post-index-change")
    before = answered(repo, "git status --short")
    _pin([_entry(repo)])
    assert not _free(before) and _free(answered(repo, "git status --short")), before
    _hook(repo / ".git" / "hooks", name="post-index-change", body=PRE_COMMIT + b"echo changed\n")
    assert not _free(answered(repo, "git status --short"))


def test_D114_D115_a_clone_that_holds_the_gate_directory_gets_no_free_answer(tmp_path, monkeypatch):
    """A repository that overlaps the gate directory gets no free answer (_repo_overlap_problem), pinned or not: a
    commit or an add could take the pin itself."""
    repo = _repo(tmp_path)
    monkeypatch.setenv("PROOFBUNDLE_GATE_DIR", str(repo / "gate"))
    _pin([_entry(repo)])
    for form in ("git commit -m work", "git add -A", "git rev-parse HEAD"):
        assert not _free(answered(repo, form)), form


@pytest.mark.parametrize("form", ["git diff --ext-diff", "git log --show-signature -1", "git show --textconv HEAD",
                                  "git log --format=%G? -1", "git -c core.pager=less log -1", "git rev-list --all"])
def test_D115_an_option_that_starts_a_program_or_a_form_outside_the_list_keeps_its_answer(tmp_path, form):
    repo = _repo(tmp_path)
    before = answered(repo, form)
    _pin([_entry(repo)])
    assert answered(repo, form) == before


@pytest.mark.parametrize("text", [
    None,   # the pin names another clone
    '{"schema": "proofbundle-plugin/pin-state/v0.1", "klone": [], "klone": []}',
    '{"schema": "proofbundle-plugin/pin-state/v0.2", "klone": []}',
    "not json",
])
def test_D114_a_pin_that_does_not_read_whole_or_names_another_clone_pins_nothing(tmp_path, text):
    repo = _repo(tmp_path)
    entry = _entry(repo)
    if text is None:
        entry["pfad"] = str(tmp_path / "another")
        _pin([entry])
    else:
        _pin([], text=text)
    assert not _free(answered(repo, "git commit -m work"))


def test_D114_two_entries_for_one_clone_pin_nothing(tmp_path):
    repo = _repo(tmp_path)
    _pin([_entry(repo), _entry(repo)])
    assert not _free(answered(repo, "git commit -m work"))


@pytest.mark.parametrize("field,value", [("konfig", "0" * 64), ("hakenordner", "/elsewhere/hooks"),
                                         ("haken", {"pre-commit": "0" * 64}), ("haken", {})])
def test_D114_an_entry_that_does_not_match_the_clone_pins_nothing(tmp_path, field, value):
    repo = _repo(tmp_path)
    entry = _entry(repo)
    entry[field] = value
    _pin([entry])
    assert not _free(answered(repo, "git commit -m work"))


@pytest.mark.parametrize("form", [
    "python3 -c 'open(\".git/hooks/pre-commit\", \"a\").write(\"x\")' && git commit -m work",
    "true && git commit -m work", "git commit -m work | cat", "git status --short > out.txt",
    "cd {R} && git commit -m work", "GIT_DIR=.git git commit -m work", "git -c core.hooksPath=/elsewhere commit -m work",
    "git log --oneline -3 | head -1", "git commit -m work &", "git add -A || git commit -m work",
    "'git' commit -m work", "\\git commit -m work", "g''it commit -m work"])
def test_D114_D115_a_command_with_another_step_than_a_plain_pinned_git_call_keeps_the_answer(tmp_path, form):
    """Another step of the line can change a hook or the configuration after the gate read them and before git runs
    them (a write in another language is not gated, D8): the pin frees only plain git calls joined by && or ;, each
    spelled `git` as written, without quotes or a backslash. The decision stays; a block may now name a rewrite into the
    plain pinned call (D85) where it named none before."""
    repo = _repo(tmp_path)
    form = form.replace("{R}", str(repo))
    before = answered(repo, form)
    _pin([_entry(repo)])
    after = answered(repo, form)
    assert after[0] == before[0] and not _free(after), (form, before, after)


@pytest.mark.parametrize("form", ["git add -A; git commit -m work", "git -C {R} status --short && git -C {R} log -1"])
def test_D114_D115_plain_pinned_git_calls_joined_by_and_or_semicolon_are_free(tmp_path, form):
    repo = _repo(tmp_path)
    _pin([_entry(repo)])
    assert _free(answered(repo, form.replace("{R}", str(repo))))


# --- what is not touched ----------------------------------------------------------------------------------------------

@pytest.mark.parametrize("form", ["git push origin claude/work", "git push -f origin claude/work", "git tag v9",
                                  "gh pr create --title t --body b", "git fetch origin"])
def test_D114_external_effects_and_other_forms_answer_as_without_the_pin(tmp_path, form):
    repo = _repo(tmp_path, kind="b7n0de")
    before = answered(repo, form)
    _pin([_entry(repo)])
    assert answered(repo, form) == before


@pytest.mark.parametrize("form", ["git commit -m work", "git rev-parse HEAD"])
def test_D114_D115_without_the_flag_and_under_codex_nothing_changes(tmp_path, form):
    repo = _repo(tmp_path)
    plain = gate.decide(form, str(repo), gate.time.monotonic() + 60, "claude")
    codex = answered(repo, form, host="codex")
    _pin([_entry(repo)])
    again = gate.decide(form, str(repo), gate.time.monotonic() + 60, "claude")
    assert (again.decision, [v.reason_id for v in again.verdicts]) == (plain.decision,
                                                                        [v.reason_id for v in plain.verdicts])
    assert answered(repo, form, host="codex") == codex


def test_D114_a_write_into_the_pin_is_denied(tmp_path):
    repo = _repo(tmp_path)
    target = _gate_dir() / "pin-state.json"
    out = gate.decide_write("Write", {"file_path": str(target), "content": "{}"}, str(repo),
                            gate.time.monotonic() + 60, host="claude")
    assert out is not None and out.decision == "deny" and "write_to_gate_dir" in [v.reason_id for v in out.verdicts]
    bash = answered(repo, f"echo x > {target}")
    assert bash[0] == "deny" and "write_to_gate_dir" in bash[1], bash


# --- the subcommand -----------------------------------------------------------------------------------------------------

def test_D114_pin_state_prints_the_entry_and_writes_nothing(tmp_path):
    repo = _repo(tmp_path)
    folder = _gate_dir()
    before = sorted(p.name for p in folder.iterdir())
    proc = subprocess.run([sys.executable, str(gate.__file__), "pin-state", str(repo)], capture_output=True, text=True,
                          timeout=60)
    assert proc.returncode == 0, proc.stderr
    entry = json.loads(proc.stdout)
    assert entry == _entry(repo) | {"pfad": os.path.realpath(repo),
                                    "hakenordner": os.path.realpath(repo / ".git" / "hooks")}
    assert sorted(p.name for p in folder.iterdir()) == before
    _pin([entry])
    assert _free(answered(repo, "git commit -m work"))


def test_D114_pin_state_refuses_a_path_that_is_no_work_tree(tmp_path):
    proc = subprocess.run([sys.executable, str(gate.__file__), "pin-state", str(tmp_path)], capture_output=True,
                          text=True, timeout=60)
    assert proc.returncode == 1 and proc.stdout == ""
