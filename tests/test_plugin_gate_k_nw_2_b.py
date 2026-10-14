"""Owner choice K-NW-2 B (2026-10-08): `git add` and `git commit -m` are free after the state check of their repository.

The gate frees exactly these two plain forms, as the whole command, when the state check finds nothing that starts a
program for them (DECISIONS.md D3, "two forms after a state check"). Every other form stays as it was (it asks under
Claude Code and is denied under Codex). One test per program source the owner named: a filter, a hook, fsmonitor, a
signature program (gpg.program, gpg.ssh.program, a numeric commit.gpgSign) and an include onto one of them. Each case
first shows that the gate refuses the free answer and names the source, then that plain git starts the marker program
for the same form, so the case is not vacuous. The marker programs live in the test folder. Red against 395f0a87, where
both forms always asked with a reason that names no source; green after.
"""
from __future__ import annotations

import json
import os
import pathlib
import shlex
import shutil
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
GATE = ROOT / "plugins" / "proofbundle" / "hooks" / "proofbundle_gate.py"

_bytecode, sys.dont_write_bytecode = sys.dont_write_bytecode, True
sys.path.insert(0, str(GATE.parent))
import proofbundle_gate as gate  # noqa: E402

sys.path.pop(0)
sys.dont_write_bytecode = _bytecode

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")


@pytest.fixture(autouse=True)
def _clean_git_environment(monkeypatch):
    """The hook's environment as a plain user has it: no configuration file outside the repository and no GIT_* name
    beyond the two that point git at no global or system file."""
    for key in [k for k in os.environ if k.startswith("GIT_")]:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", os.devnull)


def _git(repo: pathlib.Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo), *args], check=check, capture_output=True, text=True, timeout=60)


def _repo(tmp_path: pathlib.Path) -> pathlib.Path:
    """A plain repository with one commit a.txt, an identity in its own configuration, no hook and no helper."""
    repo = tmp_path / "r"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.name", "t")
    _git(repo, "config", "user.email", "t@example.org")
    (repo / "a.txt").write_text("a\n", encoding="utf-8")
    _git(repo, "add", "a.txt")
    _git(repo, "commit", "-q", "-m", "base")
    return repo


def _marker(tmp_path: pathlib.Path, name: str = "prog.sh") -> tuple[pathlib.Path, pathlib.Path]:
    """A program in the test folder that leaves its marker when something starts it, and reads its input so a filter
    or a hook that is handed data does not block."""
    marker = tmp_path / f"marker-{name}"
    program = tmp_path / name
    program.write_text(f"#!/bin/sh\ntouch {shlex.quote(str(marker))}\ncat >/dev/null 2>&1\nexit 0\n", encoding="utf-8")
    program.chmod(0o700)
    return program, marker


def _deadline() -> float:
    return gate.time.monotonic() + 30


def _refused(command: str, repo: pathlib.Path, source: str) -> str:
    """The free answer is refused under both hosts and the text names the source; returns the reason."""
    claude = gate.decide(command, str(repo), _deadline())
    codex = gate.decide(command, str(repo), _deadline(), host="codex")
    assert claude is not None and claude.decision == "ask", (command, claude and claude.text)
    assert codex is not None and gate.answer(codex.decision, codex.text, host="codex")[
        "hookSpecificOutput"]["permissionDecision"] == "deny", command
    failed = " ".join(v.failed for v in claude.verdicts)
    assert {v.reason_id for v in claude.verdicts} == {"git_form_not_free"}, claude.verdicts
    assert source.lower() in failed.lower(), (source, failed)   # git lower-cases section and key names
    return failed


def _free(command: str, repo: pathlib.Path) -> None:
    for host in ("claude", "codex"):
        outcome = gate.decide(command, str(repo), _deadline(), host=host)
        assert outcome is not None and outcome.decision == "pass", (host, command, outcome and outcome.text)
        assert {v.reason_id for v in outcome.verdicts} == {"free_after_state_check"}, (host, outcome.verdicts)
        assert "permissionDecision" not in gate.answer(outcome.decision, outcome.text, host=host)["hookSpecificOutput"]


def _change(repo: pathlib.Path) -> None:
    with open(repo / "a.txt", "a", encoding="utf-8") as handle:
        handle.write("b\n")


# --- the two forms are free in a clean repository ------------------------------------------------------------------

@pytest.mark.parametrize("command", ["git add a.txt", "git add -A", "git add -- a.txt", "git commit -m msg",
                                     "git commit -am msg", "git commit -qam msg -- a.txt", "git commit --message=msg",
                                     'git commit -m "a > b; not a chain"', "LANG=C git add a.txt"])
def test_the_two_forms_are_free_in_a_clean_repository(tmp_path, command):
    _free(command, _repo(tmp_path))


def test_the_hook_answer_of_a_free_form_carries_no_permission_decision(tmp_path):
    """The whole path through the hook: the answer is a message, no allow and no deny, so the host's own permission
    flow decides."""
    repo = _repo(tmp_path)
    for host in ("claude", "codex"):
        event = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(repo),
                 "tool_input": {"command": "git commit -m msg"}}
        proc = subprocess.run([sys.executable, "-I", str(GATE), "--host", host], input=json.dumps(event),
                              capture_output=True, text=True, timeout=120,
                              env={**os.environ, "PROOFBUNDLE_GATE_DIR": str(tmp_path / "gate")})
        answer = json.loads(proc.stdout)
        assert "permissionDecision" not in answer["hookSpecificOutput"], (host, answer)
        assert "is free" in answer["systemMessage"], answer


def test_a_free_commit_starts_no_program_in_the_clean_repository(tmp_path):
    """The state the check freed is one where the commit itself runs no marker: no filter, hook or signing program
    takes part."""
    repo = _repo(tmp_path)
    _change(repo)
    _free("git commit -am msg", repo)
    assert _git(repo, "commit", "-q", "-am", "msg").returncode == 0
    assert _git(repo, "log", "--format=%s", "-n", "1").stdout.strip() == "msg"


@pytest.mark.parametrize("name", ["pre-push", "post-checkout", "post-merge", "pre-rebase", "post-rewrite"])
def test_a_hook_neither_form_runs_keeps_the_forms_free(tmp_path, name):
    """githooks(5): a pre-push hook (Level 2, D24) and the hooks of checkout, merge, rebase and rewrite do not run for
    git add or git commit -m. Measured for pre-push: plain git add and commit leave its marker untouched."""
    repo = _repo(tmp_path)
    program, marker = _marker(tmp_path)
    shutil.copy(program, repo / ".git" / "hooks" / name)
    _free("git add a.txt", repo)
    _free("git commit -m msg", repo)
    _change(repo)
    _git(repo, "add", "a.txt")
    _git(repo, "commit", "-q", "-m", "msg")
    assert not marker.exists(), name


def test_core_hooks_path_to_a_directory_with_only_a_pre_push_hook_keeps_the_forms_free(tmp_path):
    """The Level-2 prototype is installed through a local core.hooksPath (D24); the check reads the directory git
    resolves, and a pre-push hook there runs for neither form."""
    repo = _repo(tmp_path)
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    program, _marker_file = _marker(tmp_path)
    shutil.copy(program, hooks / "pre-push")
    _git(repo, "config", "core.hooksPath", str(hooks))
    _free("git commit -m msg", repo)


def test_an_include_of_inert_settings_keeps_the_forms_free(tmp_path):
    repo = _repo(tmp_path)
    included = tmp_path / "inert.cfg"
    included.write_text("[user]\n\tname = someone\n[color]\n\tui = auto\n", encoding="utf-8")
    _git(repo, "config", "include.path", str(included))
    _git(repo, "config", "commit.gpgSign", "false")
    _git(repo, "config", "core.fsmonitor", "false")
    _free("git commit -m msg", repo)


# --- one case per program source: refused with the source named, and plain git starts it ----------------------------

def test_a_clean_filter_keeps_git_add_not_free(tmp_path):
    repo = _repo(tmp_path)
    program, marker = _marker(tmp_path)
    (repo / ".gitattributes").write_text("*.txt filter=f\n", encoding="utf-8")
    _git(repo, "config", "filter.f.clean", str(program))
    _refused("git add a.txt", repo, "a filter: filter.f.clean")
    assert not marker.exists(), "the gate started the filter"
    _change(repo)
    _git(repo, "add", "a.txt")
    assert marker.exists(), "git does not start the filter; the case would be vacuous"


def test_a_filter_with_an_empty_driver_name_keeps_git_add_not_free(tmp_path):
    """Review Runde 9: an empty `filter=` value selects the driver with the empty name, `filter..clean`."""
    repo = _repo(tmp_path)
    program, marker = _marker(tmp_path)
    (repo / ".gitattributes").write_text("*.txt filter=\n", encoding="utf-8")
    _git(repo, "config", "filter..clean", str(program))
    _refused("git add a.txt", repo, "a filter: filter..clean")
    _change(repo)
    _git(repo, "add", "a.txt")
    assert marker.exists(), "git does not start the filter; the case would be vacuous"


@pytest.mark.parametrize("hook, command", [("pre-commit", "git commit -am msg"),
                                           ("reference-transaction", "git commit -am msg"),
                                           ("post-index-change", "git add a.txt")])
def test_a_hook_the_form_runs_keeps_it_not_free(tmp_path, hook, command):
    repo = _repo(tmp_path)
    program, marker = _marker(tmp_path)
    shutil.copy(program, repo / ".git" / "hooks" / hook)
    _refused(command, repo, f"a hook: {repo / '.git' / 'hooks' / hook}")
    _change(repo)
    _git(repo, *shlex.split(command)[1:])
    assert marker.exists(), f"git does not run {hook} for {command}; the case would be vacuous"


def test_a_hook_in_the_core_hooks_path_directory_keeps_git_commit_not_free(tmp_path):
    repo = _repo(tmp_path)
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    program, marker = _marker(tmp_path)
    shutil.copy(program, hooks / "pre-commit")
    _git(repo, "config", "core.hooksPath", str(hooks))
    _refused("git commit -am msg", repo, f"a hook: {hooks / 'pre-commit'}")
    _change(repo)
    _git(repo, "commit", "-q", "-am", "msg")
    assert marker.exists(), "git does not run the pre-commit hook; the case would be vacuous"


def test_a_recent_objects_hook_keeps_git_commit_not_free(tmp_path):
    """Review Runde 9, R9-5: automatic maintenance after a commit starts gc.recentObjectsHook (the reviewer's
    measurement under git 2.51.1). No anti-vacuity half: under git 2.43.0 the same setup runs the maintenance but not
    the hook (measured in Nachtrag 23 and again on 2026-10-08)."""
    repo = _repo(tmp_path)
    program, marker = _marker(tmp_path)
    _git(repo, "config", "gc.recentObjectsHook", str(program))
    _refused("git commit -m msg", repo, "a hook: gc.recentObjectsHook")
    assert not marker.exists()


@pytest.mark.parametrize("command", ["git add a.txt", "git commit -am msg"])
def test_fsmonitor_keeps_both_forms_not_free(tmp_path, command):
    repo = _repo(tmp_path)
    program, marker = _marker(tmp_path)
    _git(repo, "config", "core.fsmonitor", str(program))
    _refused(command, repo, "a fsmonitor: core.fsmonitor")
    _change(repo)
    _git(repo, *shlex.split(command)[1:], check=False)
    assert marker.exists(), f"git does not start the fsmonitor hook for {command}; the case would be vacuous"


@pytest.mark.parametrize("value", ["true", "2", "1k", "0x1", "yes", "on"])
def test_commit_gpg_sign_on_keeps_git_commit_not_free(tmp_path, value):
    """Review Runde 9: a numeric value is true too. commit.gpgSign is the only key set, so the check has to read the
    value itself. Plain git then starts the default signer, `gpg` from PATH, for every one of these values; the marker
    stands in for it in a PATH directory of the test folder (the program PATH selects is the D27 class, not read)."""
    repo = _repo(tmp_path)
    program, marker = _marker(tmp_path)
    _git(repo, "config", "commit.gpgSign", value)
    _refused("git commit -am msg", repo, "a signature program: commit.gpgsign")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    shutil.copy(program, bin_dir / "gpg")
    _change(repo)
    subprocess.run(["git", "-C", str(repo), "commit", "-q", "-am", "msg"], capture_output=True, timeout=60,
                   env={**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}"})
    assert marker.exists(), f"git does not start gpg for commit.gpgSign={value}; the case would be vacuous"


@pytest.mark.parametrize("value", ["false", "no", "off", "0"])
def test_commit_gpg_sign_off_keeps_the_forms_free(tmp_path, value):
    repo = _repo(tmp_path)
    _git(repo, "config", "commit.gpgSign", value)
    _free("git commit -m msg", repo)


def test_gpg_ssh_program_with_signing_on_keeps_git_commit_not_free(tmp_path):
    repo = _repo(tmp_path)
    program, marker = _marker(tmp_path)
    for key, value in (("gpg.format", "ssh"), ("gpg.ssh.program", str(program)), ("user.signingKey", "key::x"),
                       ("commit.gpgSign", "true")):
        _git(repo, "config", key, value)
    _refused("git commit -am msg", repo, "a signature program: gpg.ssh.program")
    _change(repo)
    _git(repo, "commit", "-q", "-am", "msg", check=False)
    assert marker.exists(), "git does not start gpg.ssh.program; the case would be vacuous"


@pytest.mark.parametrize("key", ["gpg.program", "gpg.ssh.program", "gpg.x509.program"])
def test_a_signing_program_alone_keeps_git_commit_not_free(tmp_path, key):
    """The owner named gpg.program and gpg.ssh.program as sources. With signing off, plain `git commit -m` does not
    start them (measured on 2026-10-08 for gpg.program); the check refuses anyway, because a later commit.gpgSign or a
    -S would, and it frees only what it knows to start nothing."""
    repo = _repo(tmp_path)
    program, marker = _marker(tmp_path)
    _git(repo, "config", key, str(program))
    _refused("git commit -m msg", repo, f"a signature program: {key}")
    assert not marker.exists()


def test_an_include_onto_a_filter_keeps_git_add_not_free_and_names_the_include(tmp_path):
    repo = _repo(tmp_path)
    program, marker = _marker(tmp_path)
    included = tmp_path / "filter.cfg"
    included.write_text(f'[filter "f"]\n\tclean = {program}\n', encoding="utf-8")
    _git(repo, "config", "include.path", str(included))
    (repo / ".gitattributes").write_text("*.txt filter=f\n", encoding="utf-8")
    failed = _refused("git add a.txt", repo, "a filter: filter.f.clean")
    assert f"through an include, in {included}" in failed, failed
    _change(repo)
    _git(repo, "add", "a.txt")
    assert marker.exists(), "git does not start the included filter; the case would be vacuous"


def test_an_include_if_onto_a_signature_program_keeps_git_commit_not_free_and_names_the_include(tmp_path):
    repo = _repo(tmp_path)
    program, marker = _marker(tmp_path)
    included = tmp_path / "sign.cfg"
    included.write_text(f"[commit]\n\tgpgSign = true\n[gpg]\n\tprogram = {program}\n", encoding="utf-8")
    _git(repo, "config", f"includeIf.gitdir:{repo / '.git'}.path", str(included))
    failed = _refused("git commit -am msg", repo, "a signature program")
    assert f"through an include, in {included}" in failed, failed
    _change(repo)
    _git(repo, "commit", "-q", "-am", "msg", check=False)
    assert marker.exists(), "git does not start the included signing program; the case would be vacuous"


def test_an_include_if_onto_a_hook_directory_keeps_git_commit_not_free(tmp_path):
    repo = _repo(tmp_path)
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    program, marker = _marker(tmp_path)
    shutil.copy(program, hooks / "pre-commit")
    included = tmp_path / "hooks.cfg"
    included.write_text(f"[core]\n\thooksPath = {hooks}\n", encoding="utf-8")
    _git(repo, "config", f"includeIf.gitdir:{repo / '.git'}.path", str(included))
    _refused("git commit -am msg", repo, f"a hook: {hooks / 'pre-commit'}")
    _change(repo)
    _git(repo, "commit", "-q", "-am", "msg")
    assert marker.exists(), "git does not run the included hook directory's pre-commit; the case would be vacuous"


# --- what the check does not know keeps the forms not free ---------------------------------------------------------

@pytest.mark.parametrize("key, value", [("diff.external", "x"), ("core.attributesFile", "x"), ("pager.commit", "true"),
                                        ("maintenance.auto", "true"), ("trailer.sign.command", "x"),
                                        ("remote.origin.promisor", "true")])
def test_a_key_the_check_does_not_know_keeps_the_forms_not_free(tmp_path, key, value):
    repo = _repo(tmp_path)
    _git(repo, "config", key, value)
    _refused("git commit -m msg", repo, key)


@pytest.mark.parametrize("name", ["GIT_EXEC_PATH", "GIT_DIR", "GIT_INDEX_FILE", "GIT_TRACE"])
def test_an_environment_name_the_check_does_not_know_keeps_the_forms_not_free(tmp_path, monkeypatch, name):
    """Each name points at a path git can use (GIT_DIR at the repository's own .git), so the check reaches the
    environment instead of stopping at an unreadable repository."""
    repo = _repo(tmp_path)
    monkeypatch.setenv(name, str(repo / ".git") if name == "GIT_DIR" else str(tmp_path / "x"))
    _refused("git add a.txt", repo, name)


@pytest.mark.parametrize("command", ["git commit", "git commit -m", "git commit -S -m x", "git commit -e -m x",
                                     "git commit -v -m x", "git commit --amend -m x", "git commit -F msg.txt",
                                     "git commit --trailer x=y -m x", "git commit --no-verify -m x", "git add -p",
                                     "git add -i", "git add -e", "git add --renormalize .", "git add -",
                                     "git -C . add a.txt", "git -c core.fsmonitor=false add a.txt", "FOO=1 git add a.txt",
                                     "git add a.txt > out", "git commit -m x 2>&1", "git add . || git commit -m x",
                                     "git add a.txt; git status", "cd . && git add a.txt", "env git add a.txt",
                                     "./git add a.txt", "git add $(echo a.txt)"])
def test_every_other_form_stays_not_free(tmp_path, command):
    """Options that start an editor, a signer, a diff or a trailer command, a global option, an unvetted assignment, a
    redirection, a chain other than the plain one of Nachtrag 2 (owner choice of 2026-10-14, 16:2x: `git add . && git
    commit -m x` is free now, its `||` form stands in), a wrapper, a path to another git and an expansion leave the form
    as it was before K-NW-2 B."""
    repo = _repo(tmp_path)
    claude = gate.decide(command, str(repo), _deadline())
    codex = gate.decide(command, str(repo), _deadline(), host="codex")
    assert claude is not None and claude.decision == "ask", (command, claude and claude.decision)
    assert codex is not None and gate.answer(codex.decision, codex.text, host="codex")[
        "hookSpecificOutput"]["permissionDecision"] == "deny", command
    # the same reason as at 395f0a87 (measured for these forms and 23 more on 2026-10-08), so not only the decision
    # but the answer a person reads stays as it was
    assert {v.reason_id for v in claude.verdicts} == {"git_form_not_free"}, claude.verdicts


def test_the_free_answer_under_codex_says_which_directory_was_checked(tmp_path):
    """Measured with Codex 0.161.0 on 2026-10-08: a workdir the model sets reaches the command and not the hook, whose
    event names the session directory. The pass says that the session directory was checked."""
    outcome = gate.decide("git add a.txt", str(_repo(tmp_path)), _deadline(), host="codex")
    assert outcome is not None and outcome.decision == "pass"
    assert "the session directory" in outcome.text and "does not tell the gate where a command runs" in outcome.text


def test_a_human_rule_still_frees_a_form_the_state_check_refuses(tmp_path, monkeypatch):
    """N24 stays as it was: in with-approvals mode a rule bound to the state digest frees the plain form even where
    the state check refuses it (here a signing program), because a person wrote the rule for that state."""
    repo = _repo(tmp_path)
    program, _marker_file = _marker(tmp_path)
    _git(repo, "config", "gpg.program", str(program))
    gate_dir = tmp_path / "gate"
    gate_dir.mkdir()
    monkeypatch.setenv("PROOFBUNDLE_GATE_DIR", str(gate_dir))
    (gate_dir / "mode").write_text("with-approvals\n", encoding="utf-8")
    digest = gate._bound_state_digest(str(repo), _deadline(), dict(os.environ))
    common = os.path.realpath(repo / ".git")
    (gate_dir / "rules.json").write_text(json.dumps([{"repo": common, "form": "git commit -m msg", "effect": "free",
                                                      "state_digest": digest}]), encoding="utf-8")
    outcome = gate.decide("git commit -m msg", str(repo), _deadline(), environ=dict(os.environ))
    assert outcome is not None and outcome.decision == "pass"
    assert outcome.applied_rule is not None


@pytest.mark.parametrize("command", ["git add . || git commit -m x", "sed -i s/a/b/ a.txt && git add a.txt",
                                     "git commit -S -m x", "git add -p", "cd . && git commit -m x"])
def test_a_refused_add_or_commit_form_names_the_two_free_forms(tmp_path, command):
    """Measured in a Claude Code run on 2026-10-08: an agent that chained its edit, `git add` and `git commit` read
    only "have a person review the call" and stopped. The refusal now names the two forms the gate frees."""
    outcome = gate.decide(command, str(_repo(tmp_path)), _deadline())
    assert outcome is not None and outcome.decision == "ask"
    assert "each as a whole command of its own" in outcome.text and "`git commit -m <message>`" in outcome.text


def test_another_refused_git_form_keeps_its_next_step(tmp_path):
    # `git stash list`, not `git status`: class a frees that read form after the read profile since FIX-18 part B (D34)
    outcome = gate.decide("git stash list", str(_repo(tmp_path)), _deadline())
    assert outcome is not None and "each as a whole command of its own" not in outcome.text
    assert "have a person review the call" in outcome.text

