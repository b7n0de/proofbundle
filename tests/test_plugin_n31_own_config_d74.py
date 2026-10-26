"""D74, Nachtrag 31, R1: the filter block of `git lfs install` and core.fsmonitor set true in the person's own global or
system file.

Owner choice of 2026-10-18, 15:3x Berlin ("fewer questions from the own configuration", translated): the four entries `git lfs
install` writes, with exactly its values, and core.fsmonitor set true count as known where the person's own global or
system file holds them, never the local or worktree file, an include, GIT_CONFIG_* or `-c`; another value asks as
before. Measured with git 2.43.0 and git-lfs 3.4.1 (truth_lfs_n31.py of the delivery): git-lfs started for no form where
no attribute assigns a filter, and where one does it started, wrote four hooks and, in the plain form, tried the
network; so the block counts where an attribute assigns a filter to a path. core.fsmonitor true started nothing on a git
without the fsmonitor daemon.

RED at 44db2056 (the head of Nachtrag 30): the free forms of Claude Code and the unit rows. The counter cases and the
answers under Codex are controls, green at both. No case reaches a network.
"""
from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import time

import _git_version as _gv
import pytest

import test_plugin_n29_work_profile_d71 as d71

gate = d71.gate
pytestmark = d71.pytestmark

LFS_PLAIN = ('[filter "lfs"]\n\tclean = git-lfs clean -- %f\n\tsmudge = git-lfs smudge -- %f\n'
             '\tprocess = git-lfs filter-process\n\trequired = true\n')
LFS_SKIP = ('[filter "lfs"]\n\tclean = git-lfs clean -- %f\n\tsmudge = git-lfs smudge --skip -- %f\n'
            '\tprocess = git-lfs filter-process --skip\n\trequired = true\n')
BLOCKS = {"plain": LFS_PLAIN, "skip-smudge": LFS_SKIP}
HOSTS = ("claude", "codex")


def _daemon_absent() -> bool:
    probe = subprocess.run(["git", "fsmonitor--daemon", "status"], capture_output=True, timeout=60, check=False)
    return probe.returncode == 128 and b"not supported on this platform" in probe.stderr


DAEMON_ABSENT = _daemon_absent()


@pytest.fixture(autouse=True)
def _clean(monkeypatch, tmp_path):
    """The hook's environment as in the tests of D71, except that the global file is HOME/.gitconfig, the one git reads
    by default, and no system file is read (GIT_CONFIG_NOSYSTEM)."""
    for key in [k for k in os.environ if k.startswith(("GH_", "GIT_")) or k in ("PAGER", "GITHUB_ENTERPRISE_TOKEN",
                                                                               "XDG_CONFIG_HOME", "AI_AGENT")]:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("LC_ALL", "C")
    monkeypatch.setenv("PROOFBUNDLE_GATE_DIR", str(tmp_path / "gatedir"))
    (tmp_path / "home" / ".config" / "gh").mkdir(parents=True)
    (tmp_path / "bin").mkdir()
    d71._fake_gh(tmp_path / "bin")
    monkeypatch.setenv("PATH", os.pathsep.join([str(tmp_path / "bin"), "/usr/local/bin", "/usr/bin", "/bin"]))


def _global(tmp_path: pathlib.Path, text: str) -> None:
    (tmp_path / "home" / ".gitconfig").write_text(text)


def _decide(repo: pathlib.Path, form: str, tmp_path: pathlib.Path, host: str = "claude"):
    out = gate.decide(d71._command(form, repo, tmp_path), str(repo), time.monotonic() + 60, host)
    return (None, []) if out is None else (out.decision, [v.reason_id for v in out.verdicts])


#: Read forms of class a (D34) that walk the work tree; free under Claude Code with the block in the global file.
READ = ["git -C {R} status --short --branch", "git -C {R} status", "git -C {R} status --porcelain",
        "git -C {R} diff --stat v0 main -- c.txt", "git -C {R} diff"]
#: The two forms of K-NW-2 B (D3, D40); free under Claude Code with the block in the global file.
STATE = ["git -C {R} add notes.md", "git add notes.md", "git -C {R} commit -m one", "git commit -m 'two words'"]
#: The forms of D71 that bring no other tree into the work tree, in a declared repository of b7n0de.
WORK = ["git commit --amend --no-edit", "git stash push -m note", "git branch feature-o"]


@_gv.needs_git(2, 42, "git var names the configuration and attribute files git reads")
@pytest.mark.parametrize("block", sorted(BLOCKS))
@pytest.mark.parametrize("form", READ + STATE)
def test_D74_the_lfs_block_in_the_global_file_leaves_the_form_free(tmp_path, form, block):
    repo = d71._repo(tmp_path, declaration=None)
    _global(tmp_path, BLOCKS[block])
    reason = "free_after_state_check" if form in STATE else "free_after_read_profile"
    assert _decide(repo, form, tmp_path) == ("pass", [reason]), form


@_gv.needs_git(2, 42, "git var names the configuration and attribute files git reads")
@pytest.mark.parametrize("block", sorted(BLOCKS))
@pytest.mark.parametrize("form", WORK)
def test_D74_the_lfs_block_leaves_a_form_of_d71_free_that_brings_no_other_tree(tmp_path, form, block):
    repo = d71._repo(tmp_path)
    _global(tmp_path, BLOCKS[block])
    assert _decide(repo, form, tmp_path) == ("pass", ["free_work_profile"]), form


@pytest.mark.skipif(not DAEMON_ABSENT, reason="this git has an fsmonitor daemon, which D74 did not measure")
@pytest.mark.parametrize("value", ["true", "yes", "1"])
@pytest.mark.parametrize("form", ["git -C {R} status --short --branch", "git -C {R} diff", "git -C {R} add notes.md",
                                  "git -C {R} fetch -q --prune origin", "git -C {R} fetch origin"])
def test_D74_fsmonitor_true_in_the_global_file_leaves_the_form_free(tmp_path, form, value):
    repo = d71._repo(tmp_path, declaration=None)
    _global(tmp_path, f"[core]\n\tfsmonitor = {value}\n")
    reason = ("free_after_state_check" if " add " in form else "free_after_fetch_profile" if " fetch " in form
              else "free_after_read_profile")
    assert _decide(repo, form, tmp_path) == ("pass", [reason]), form


@pytest.mark.parametrize("host", HOSTS)
@pytest.mark.parametrize("form", READ + STATE)
def test_D74_control_under_codex_and_without_any_block_the_answer_stays(tmp_path, form, host):
    """Under Codex the block frees nothing (a read form is never free there, D37, and the relaxation of the state check
    is for Claude Code alone); without any block the form is free under Claude Code as at the base."""
    repo = d71._repo(tmp_path, declaration=None)
    if host == "codex":
        _global(tmp_path, LFS_PLAIN + "[core]\n\tfsmonitor = true\n")
        decision, reasons = _decide(repo, form, tmp_path, host)
        assert decision in ("ask", "deny") and not any(r.startswith("free_") for r in reasons), (form, reasons)
    else:
        assert _decide(repo, form, tmp_path)[0] == "pass", form


def _include_in_work_tree(tmp_path, repo):
    (repo / "lfs.cfg").write_text(LFS_PLAIN)
    _global(tmp_path, f"[include]\n\tpath = {repo / 'lfs.cfg'}\n")


def _named_global(tmp_path, repo, monkeypatch):
    (tmp_path / "named.cfg").write_text(LFS_PLAIN)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(tmp_path / "named.cfg"))


def _attribute(tmp_path, repo):
    _global(tmp_path, LFS_PLAIN)
    (repo / ".gitattributes").write_text("*.md filter=lfs diff=lfs merge=lfs -text\n")


#: Counter cases of the order: each keeps a not-free answer under Claude Code, at the base and at the head.
KEEP = {
    "another value of clean": lambda t, r, m: _global(t, LFS_PLAIN.replace("git-lfs clean -- %f", "git-lfs clean %f")),
    "another value of smudge": lambda t, r, m: _global(t, LFS_PLAIN.replace("smudge -- %f", "smudge -- %f --x")),
    "another value of required": lambda t, r, m: _global(t, LFS_PLAIN.replace("required = true", "required = yes")),
    "the block in the local file": lambda t, r, m: (r / ".git" / "config").write_text(
        (r / ".git" / "config").read_text() + LFS_PLAIN),
    "the block from an include in the work tree": lambda t, r, m: _include_in_work_tree(t, r),
    "the block in a file GIT_CONFIG_GLOBAL names": lambda t, r, m: _named_global(t, r, m),
    "core.fsmonitor with a path": lambda t, r, m: _global(t, f"[core]\n\tfsmonitor = {t / 'fsm.sh'}\n"),
    "core.fsmonitor true in the local file": lambda t, r, m: (r / ".git" / "config").write_text(
        (r / ".git" / "config").read_text() + "[core]\n\tfsmonitor = true\n"),
    "an attribute assigns the filter to a tracked path": lambda t, r, m: _attribute(t, r),
}


@pytest.mark.parametrize("form", ["git -C {R} status --short --branch", "git -C {R} diff", "git -C {R} add notes.md",
                                  "git commit -m one"])
@pytest.mark.parametrize("case", sorted(KEEP))
def test_D74_control_a_counter_case_keeps_its_answer(tmp_path, monkeypatch, case, form):
    repo = d71._repo(tmp_path, declaration=None)
    KEEP[case](tmp_path, repo, monkeypatch)
    decision, reasons = _decide(repo, form, tmp_path)
    assert decision in ("ask", "deny") and not any(r.startswith("free_") for r in reasons), (case, form, reasons)


@_gv.needs_git(2, 42, "git var names the configuration and attribute files git reads")
def test_D74_an_untracked_path_the_attribute_names_keeps_add_but_not_status(tmp_path):
    """git add runs the clean filter for an untracked path an attribute assigns it to; git status lists such a path and
    hashes none of it, so the read form stays free."""
    repo = d71._repo(tmp_path, declaration=None)
    _global(tmp_path, LFS_PLAIN)
    (repo / ".git" / "info" / "attributes").write_text("*.bin filter=lfs -text\n")
    (repo / "new.bin").write_text("x\n")
    assert _decide(repo, "git -C {R} add notes.md", tmp_path)[0] == "ask"
    assert _decide(repo, "git -C {R} status --short", tmp_path) == ("pass", ["free_after_read_profile"])


@pytest.mark.parametrize("form", ["git checkout topic", "git switch topic", "git merge --no-edit topic",
                                  "git rebase main"])
def test_D74_control_a_form_of_d71_that_brings_another_tree_keeps_its_ask(tmp_path, form):
    """A form that checks out, merges or rebases onto another commit reads that commit's attributes, which the check
    does not read: the block counts there as any filter does."""
    repo = d71._repo(tmp_path)
    _global(tmp_path, LFS_PLAIN)
    decision, reasons = _decide(repo, form, tmp_path)
    assert decision == "ask" and "free_work_profile" not in reasons, (form, reasons)


@pytest.mark.parametrize("form", ["git -C {R} ls-remote origin", "git -C {R} ls-remote --heads origin",
                                  "git -C {R} worktree add {T}/wt"])
def test_D74_control_fsmonitor_true_keeps_the_forms_it_was_not_measured_for(tmp_path, form):
    """ls-remote (D59) and worktree add (D40) were not among the measured forms: fsmonitor true still asks there."""
    repo = d71._repo(tmp_path, declaration=None)
    _global(tmp_path, "[core]\n\tfsmonitor = true\n")
    decision, reasons = _decide(repo, form, tmp_path)
    assert decision == "ask" and not any(r.startswith("free_") for r in reasons), (form, reasons)


@_gv.needs_git(2, 42, "git var names the configuration and attribute files git reads")
def test_D74_own_file_is_the_scope_file_git_reads_without_an_include(tmp_path, monkeypatch):
    repo = d71._repo(tmp_path, declaration=None)
    monkeypatch.delenv("GIT_CONFIG_NOSYSTEM")     # git var names no system file while it is set
    system = subprocess.run(["git", "var", "GIT_CONFIG_SYSTEM"], capture_output=True, text=True, timeout=60,
                            check=True).stdout.strip()
    deadline = time.monotonic() + 60
    assert gate._own_file("system", f"file:{system}", str(repo), deadline, {})
    assert not gate._own_file("system", f"file:{system}", str(repo), deadline, {"GIT_CONFIG_SYSTEM": system})
    assert gate._own_file("global", f"file:{tmp_path / 'home' / '.gitconfig'}", str(repo), deadline, {})
    assert not gate._own_file("global", f"file:{repo / 'lfs.cfg'}", str(repo), deadline, {})
    for scope in ("local", "worktree", "command"):
        assert not gate._own_file(scope, f"file:{tmp_path / 'home' / '.gitconfig'}", str(repo), deadline, {})
        assert not gate._own_file(scope, f"file:{system}", str(repo), deadline, {})   # the scope decides first
    assert not gate._own_file("command", "command line:", str(repo), deadline, {})


def test_D74_fsmonitor_counts_where_git_has_its_daemon(tmp_path, monkeypatch):
    """Where `git fsmonitor--daemon status` does not say the daemon is unsupported, git would start it, which D74 did not
    measure: core.fsmonitor true is not known there."""
    repo = d71._repo(tmp_path, declaration=None)
    _global(tmp_path, "[core]\n\tfsmonitor = true\n")
    origin = f"file:{tmp_path / 'home' / '.gitconfig'}"
    deadline = time.monotonic() + 60
    real = gate._run_git

    def with_daemon(repo_, args, deadline_, stdin=None):
        if tuple(args) == ("fsmonitor--daemon", "status"):
            return subprocess.CompletedProcess(args, 1, b"", b"fsmonitor-daemon is not watching\n")
        return real(repo_, args, deadline_, stdin)

    named = {k: os.environ[k] for k in ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM") if k in os.environ}
    assert gate._fsmonitor_known("global", origin, "true", str(repo), deadline, named) is DAEMON_ABSENT
    monkeypatch.setattr(gate, "_run_git", with_daemon)
    assert gate._fsmonitor_known("global", origin, "true", str(repo), deadline, named) is False
    assert _decide(repo, "git -C {R} status --short", tmp_path)[0] == "ask"


@pytest.mark.skipif(shutil.which("git-lfs") is None, reason="git-lfs is not installed")
@pytest.mark.parametrize("flags", [(), ("--skip-smudge",)])
def test_D74_the_known_values_are_those_git_lfs_install_writes(tmp_path, flags):
    home = tmp_path / "lfs_home"
    home.mkdir()
    env = {"PATH": os.environ["PATH"], "HOME": str(home), "GIT_CONFIG_NOSYSTEM": "1"}
    subprocess.run(["git", "lfs", "install", *flags], cwd=home, env=env, capture_output=True, timeout=60, check=True)
    listed = subprocess.run(["git", "config", "--global", "--list"], cwd=home, env=env, capture_output=True, text=True,
                            timeout=60, check=True).stdout.splitlines()
    entries = dict(line.split("=", 1) for line in listed if line.startswith("filter.lfs."))
    assert sorted(entries) == sorted(gate._LFS_KNOWN)
    assert all(value in gate._LFS_KNOWN[key] for key, value in entries.items()), entries
