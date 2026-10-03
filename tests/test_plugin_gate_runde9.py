"""Review Runde 9 (stand ca7482ef): one regression test per finding, each exactly the review's case.

Owner choice B (2026-10-03) removed the free list: every git form that acts on a repository asks under Claude Code
(reason `git_form_not_free`) and is denied under Codex, whatever the repository holds, and only the bare
`git --version` stays free. These tests judge the gate's verdict for the review's cases R9-2, R9-3, R9-5 and R9-6
and for the one free form. The only programs they start are marker scripts inside the test folder, and only where a
test first shows that plain git starts the marker, so the case is not vacuous. Red against ca7482ef, green after.
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

_PROGRAM_ENV = ["EDITOR", "GIT_ASKPASS", "GIT_EDITOR", "GIT_EXEC_PATH", "GIT_EXTERNAL_DIFF", "GIT_PAGER",
                "GIT_PROXY_COMMAND", "GIT_SSH", "GIT_SSH_COMMAND", "PAGER", "SSH_ASKPASS", "VISUAL"]


@pytest.fixture(autouse=True)
def _clean_git_config(monkeypatch):
    for key in [k for k in os.environ if k.startswith("GIT_CONFIG")] + _PROGRAM_ENV:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", os.devnull)


def _git(repo: pathlib.Path, *args: str, check: bool = True, env: dict | None = None,
         stdin: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.org", *args],
                          check=check, capture_output=True, text=True, timeout=60, input=stdin,
                          env=None if env is None else {**os.environ, **env})


def _repo(tmp_path: pathlib.Path) -> pathlib.Path:
    """A plain repository with one commit a.txt, no hook and no helper."""
    repo = tmp_path / "r"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    (repo / "a.txt").write_text("a\n", encoding="utf-8")
    _git(repo, "add", "a.txt")
    _git(repo, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "base")
    return repo


def _marker_program(tmp_path: pathlib.Path, marker: pathlib.Path, name: str) -> pathlib.Path:
    """A script inside the test folder that leaves marker when something starts it. It reads no input, so a
    long-running filter protocol ends with an error instead of waiting."""
    program = tmp_path / name
    program.write_text(f"#!/bin/sh\ntouch {shlex.quote(str(marker))}\nexit 1\n", encoding="utf-8")
    program.chmod(0o700)
    return program


def _deadline() -> float:
    return gate.time.monotonic() + 30


def _not_free(command: str, repo: pathlib.Path) -> bool:
    """The form asks under Claude Code with the reason that no git form is free, and Codex denies it."""
    claude = gate.decide(command, str(repo), _deadline())
    codex = gate.decide(command, str(repo), _deadline(), host="codex")
    if claude is None or codex is None or claude.decision != "ask":
        return False
    denied = gate.answer(codex.decision, codex.text, host="codex")["hookSpecificOutput"]["permissionDecision"]
    return "git_form_not_free" in {v.reason_id for v in claude.verdicts} and denied == "deny"


# --- R9-2: numeric true values start the signing or verification program ---------------------------------------

def _signed_head(repo: pathlib.Path) -> None:
    """HEAD becomes a commit with a synthetic signature field, as in the review's measurement; git verifies it
    with the configured gpg.program when it shows signatures."""
    tree = _git(repo, "rev-parse", "HEAD^{tree}").stdout.strip()
    parent = _git(repo, "rev-parse", "HEAD").stdout.strip()
    body = (f"tree {tree}\nparent {parent}\nauthor t <t@example.org> 1 +0000\ncommitter t <t@example.org> 1 +0000\n"
            "gpgsig -----BEGIN PGP SIGNATURE-----\n \n iQ==\n -----END PGP SIGNATURE-----\n\nsigned\n")
    oid = _git(repo, "hash-object", "-t", "commit", "-w", "--stdin", stdin=body).stdout.strip()
    _git(repo, "update-ref", "refs/heads/main", oid)


@pytest.mark.parametrize("command", ["git log -n 1", "git show HEAD"])
@pytest.mark.parametrize("value", ["2", "1k", "0x1"])
def test_r9_2_a_numeric_true_log_show_signature_asks(tmp_path, value, command):
    """R9-2, first case: with log.showSignature of 2, 1k or 0x1, `git log -n 1` and `git show HEAD` got no gate
    answer while git started the configured gpg.program. The anti-vacuity half: plain git starts the marker."""
    repo, marker = _repo(tmp_path), tmp_path / "marker-gpg"
    _signed_head(repo)
    _git(repo, "config", "log.showSignature", value)
    _git(repo, "config", "gpg.program", str(_marker_program(tmp_path, marker, "gpg.sh")))
    assert _not_free(command, repo), (value, command)
    assert not marker.exists(), "the gate started the verification program"
    _git(repo, *shlex.split(command)[1:], check=False)
    assert marker.exists(), "git does not start gpg.program for this value; the case would be vacuous"


def _prepared_commit(repo: pathlib.Path) -> None:
    """A staged change and a prepared message, so a bare `git commit` with GIT_EDITOR=true needs no editor."""
    (repo / "a.txt").write_text("a\nb\n", encoding="utf-8")
    _git(repo, "add", "a.txt")
    (repo / ".git" / "MERGE_MSG").write_text("msg\n", encoding="utf-8")


@pytest.mark.parametrize("value", ["2", "1k", "0x1"])
def test_r9_2_a_numeric_true_commit_gpg_sign_asks(tmp_path, value):
    """R9-2, second case: commit.gpgSign with the same numbers started the marker on a bare `git commit` with no
    gate answer. The anti-vacuity half: plain git starts it (the signing then fails, as in the review)."""
    repo, marker = _repo(tmp_path), tmp_path / "marker-gpg"
    _git(repo, "config", "commit.gpgSign", value)
    _git(repo, "config", "gpg.program", str(_marker_program(tmp_path, marker, "gpg.sh")))
    _prepared_commit(repo)
    assert _not_free("git commit", repo), value
    assert not marker.exists(), "the gate started the signing program"
    _git(repo, "commit", check=False, env={"GIT_EDITOR": "true"})
    assert marker.exists(), "git does not start gpg.program for this value; the case would be vacuous"


def test_r9_2_tag_gpg_sign_asks_too(tmp_path):
    """R9-2, the review's proposal names tag.gpgSign as well: `git tag -m x v1` with tag.gpgSign=2 asks. The
    anti-vacuity half: plain git starts the marker."""
    repo, marker = _repo(tmp_path), tmp_path / "marker-gpg"
    _git(repo, "config", "tag.gpgSign", "2")
    _git(repo, "config", "gpg.program", str(_marker_program(tmp_path, marker, "gpg.sh")))
    assert _not_free("git tag -m x v1", repo)
    assert not marker.exists()
    _git(repo, "tag", "-m", "x", "v1", check=False)
    assert marker.exists(), "git does not start gpg.program for tag.gpgSign=2; the case would be vacuous"


# --- R9-3: drivers with an empty name, selected by an empty attribute value ---------------------------------------

def _stash_conflict(repo: pathlib.Path) -> None:
    """A stash whose change to a.txt conflicts with a later commit, so `git stash apply` merges a.txt."""
    (repo / "a.txt").write_text("stash\n", encoding="utf-8")
    _git(repo, "stash", "-q")
    (repo / "a.txt").write_text("other\n", encoding="utf-8")
    _git(repo, "-c", "commit.gpgsign=false", "commit", "-q", "-am", "other")


_R9_3 = [("filter", "clean", "git add a.txt"), ("filter", "smudge", "git restore a.txt"),
         ("filter", "process", "git add a.txt"), ("diff", "command", "git diff -- a.txt"),
         ("diff", "textconv", "git diff -- a.txt"), ("merge", "driver", "git stash apply")]


@pytest.mark.parametrize("family, kind, command", _R9_3, ids=[f"{f}..{k}" for f, k, _ in _R9_3])
@pytest.mark.parametrize("driver", ["", "named"], ids=["empty-name", "named-control"])
def test_r9_3_a_driver_selected_by_an_attribute_asks(tmp_path, family, kind, command, driver):
    """R9-3: `<family>..<kind>` with the attribute `<family>=` for a.txt started the marker while the gate gave no
    answer; the same with the name `named` asked (the review's control). Both ask now. The anti-vacuity half:
    plain git starts the marker through the attribute."""
    repo, marker = _repo(tmp_path), tmp_path / "marker-driver"
    (repo / ".gitattributes").write_text(f"a.txt {family}={driver}\n", encoding="utf-8")
    if family == "merge":
        _git(repo, "add", ".gitattributes")
        _git(repo, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "attributes")
        _stash_conflict(repo)
    else:
        (repo / "a.txt").write_text("a\nchanged\n", encoding="utf-8")
    program = str(_marker_program(tmp_path, marker, "driver.sh")) + (" %O %A %B" if family == "merge" else "")
    _git(repo, "config", f"{family}.{driver}.{kind}", program)
    assert _not_free(command, repo), (family, kind, driver)
    assert not marker.exists(), "the gate started the driver"
    _git(repo, *shlex.split(command)[1:], check=False)
    assert marker.exists(), "git does not start the driver through the attribute; the case would be vacuous"


# --- R9-5: automatic maintenance after git commit ------------------------------------------------------------------

def test_r9_5_git_commit_with_a_recent_objects_hook_asks(tmp_path):
    """R9-5: a bare `git commit` got no gate answer and then started gc.recentObjectsHook through automatic
    maintenance (three packs, gc.auto=1, gc.autoPackLimit=1, gc.autoDetach=false, gc.pruneExpire=now, a prepared
    message and GIT_EDITOR=true; the reviewer's measurement under git 2.51.1). The form asks now, whatever the
    configuration holds. No anti-vacuity half here: under git 2.43.0 the same setup runs the maintenance but not
    the hook (measured in Nachtrag 23), so the hook is never run by this test."""
    repo, marker = _repo(tmp_path), tmp_path / "marker-recent-objects"
    for i in range(3):
        (repo / f"f{i}").write_text(f"{i}\n", encoding="utf-8")
        _git(repo, "add", f"f{i}")
        _git(repo, "-c", "commit.gpgsign=false", "commit", "-q", "-m", f"f{i}")
        _git(repo, "repack", "-q", "-d")
    for key, value in (("gc.auto", "1"), ("gc.autoPackLimit", "1"), ("gc.autoDetach", "false"),
                       ("gc.pruneExpire", "now"),
                       ("gc.recentObjectsHook", str(_marker_program(tmp_path, marker, "hook.sh")))):
        _git(repo, "config", key, value)
    _prepared_commit(repo)
    assert _not_free("git commit", repo)
    assert not marker.exists()


# --- R9-6: the original substitution probe of R8-3 -----------------------------------------------------------------

def test_r9_6_the_original_substitution_probe_asks(tmp_path):
    """R9-6: the reviewer's original command of the R8-3 counterprobe, `git status --short "$(printf x)"`, asks
    (the test of Nachtrag 22 used `echo $(git status --short)` instead)."""
    assert _not_free('git status --short "$(printf x)"', _repo(tmp_path))


# --- the one free form: the bare `git --version`, as exactly that text ---------------------------------------------

def test_only_the_bare_git_version_is_free(tmp_path):
    repo = _repo(tmp_path)
    for host in ("claude", "codex"):
        assert gate.decide("git --version", str(repo), _deadline(), host=host) is None, host
        assert gate.decide("git --version", str(tmp_path), _deadline(), host=host) is None, host   # no repository


@pytest.mark.parametrize("command", [
    "/usr/bin/git --version", "./git --version", "env git --version", "command git --version", "nice git --version",
    "true && git --version", "git --version; true", "cd . && git --version", "git --version | cat",
    "git --version &", "echo $(git --version)", "x=`git --version`", "sh -c 'git --version'",
    "bash -lc 'git --version'", "(git --version)", "LC_ALL=C git --version", "GIT_DIR=x git --version",
    "git --version > out.txt", "git --version 2>&1", '"git" --version', "git '--version'", "git --version\n",
    "git --version --build-options", "git -C . --version", "git", "git --help"])
def test_git_version_in_any_other_spelling_is_not_free(tmp_path, command):
    """Owner choice B: no program path, wrapper, chain, pipeline, background job, substitution, nested shell,
    subshell, prefix assignment, redirection, quoting, further option or predecessor. Each such form asks under
    Claude Code and is denied under Codex."""
    assert _not_free(command, _repo(tmp_path)), command


_EVERYDAY = ["git status", "git add a.txt", "git diff", "git log --oneline -n 3", "git show HEAD", "git commit",
             "git commit -m msg", "git checkout side", "git switch -c topic", "git fetch origin", "git branch -a",
             "git stash list", "git blame a.txt", "git restore a.txt", "git tag -l", "git rev-parse HEAD",
             "cd . && git status", "git status && git log --oneline -n 1", "git add -A && git commit -m msg"]


@pytest.mark.parametrize("command", _EVERYDAY)
def test_no_everyday_form_of_the_runde_7_measurement_is_free(tmp_path, command):
    """The 19 everyday forms of the Nachtrag 19b measurement, the state review Runde 7 read: each asks under
    Claude Code and is denied under Codex, in a clean repository."""
    repo = _repo(tmp_path)
    claude = gate.decide(command, str(repo), _deadline())
    codex = gate.decide(command, str(repo), _deadline(), host="codex")
    assert claude is not None and claude.decision == "ask", command
    assert codex is not None and gate.answer(codex.decision, codex.text, host="codex")[
        "hookSpecificOutput"]["permissionDecision"] == "deny", command


# --- R9-1: every intermediate component of a committed path is a real directory ------------------------------------

def _run_evidence(repo: pathlib.Path, out: pathlib.Path) -> tuple[int, dict]:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("PROOFBUNDLE_", "PYTEST_"))}
    argv = [sys.executable, str(GATE), "run-evidence", "--repo", str(repo), "--out", str(out), "--",
            sys.executable, "-m", "pytest", "-q", "tests/"]
    proc = subprocess.run(argv, capture_output=True, text=True, env=env, cwd=repo.parent, timeout=300, check=False)
    return proc.returncode, json.loads(proc.stdout)


_LINK_TEST = 'from pathlib import Path\n\n\ndef test_pkg_is_a_link():\n    assert Path("pkg").is_symlink()\n'


def _ignored_pkg_repo(tmp_path: pathlib.Path, test: str = _LINK_TEST) -> pathlib.Path:
    """The review's repository: a committed `.gitignore` line `pkg`, a force-added pkg/helper.py, and a test
    that demands that pkg is a symbolic link. HEAD holds a real directory, so the test fails there."""
    repo = tmp_path / "repo"
    (repo / "pkg").mkdir(parents=True)
    (repo / "tests").mkdir()
    _git(repo, "init", "-q", "-b", "main")
    (repo / ".gitignore").write_text("pkg\n", encoding="utf-8")
    (repo / "pkg" / "helper.py").write_text("HELPER = 1\n", encoding="utf-8")
    (repo / "tests" / "test_pkg.py").write_text(test, encoding="utf-8")
    _git(repo, "add", ".gitignore", "tests/test_pkg.py")
    _git(repo, "add", "-f", "pkg/helper.py")
    _git(repo, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "pkg is a directory")
    return repo


def _outside_copy(tmp_path: pathlib.Path) -> pathlib.Path:
    outside = tmp_path / "outside-pkg"
    outside.mkdir()
    (outside / "helper.py").write_text("HELPER = 1\n", encoding="utf-8")   # the same leaf bytes
    return outside


def test_r9_1_a_committed_directory_replaced_by_a_link_gives_no_evidence(tmp_path):
    """R9-1, the review's case: the working pkg replaced by a link to an outside directory with the same leaf
    bytes. lstat of the leaf alone found no difference, the ignore rule hid the link, and run-evidence gave exit 0
    and green_run, 1 of 1 passed, for the unchanged HEAD on which the test fails. Now the intermediate component is
    checked and the run is refused before it starts. The control: the run on HEAD is red. The anti-vacuity half:
    with the link, plain pytest passes."""
    repo = _ignored_pkg_repo(tmp_path)
    code, report = _run_evidence(repo, tmp_path / "control.json")
    assert (code, report["outcome"], report["reason_id"]) == (1, "no_evidence", "run_failed"), report
    shutil.rmtree(repo / "pkg")
    os.symlink(str(_outside_copy(tmp_path)), repo / "pkg")
    code, report = _run_evidence(repo, tmp_path / "statement.json")
    assert (code, report["outcome"], report["reason_id"]) == (1, "no_evidence", "tree_not_clean"), report
    assert "pkg" in report["message"] and "symbolic link" in report["message"], report["message"]
    plain = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/"], cwd=repo,
                           capture_output=True, text=True, timeout=120, check=False,
                           env={k: v for k, v in os.environ.items() if not k.startswith(("PROOFBUNDLE_", "PYTEST_"))})
    assert plain.returncode == 0, "the test does not pass on the linked tree; the case would be vacuous"


def test_r9_1_a_run_that_replaces_a_committed_directory_by_a_link_gives_no_evidence(tmp_path):
    """R9-1, the proposal's second half, after the run: a test that replaces pkg by a link to an outside directory
    with the same bytes passes, and the check after the run refuses it, so no statement names HEAD."""
    outside = _outside_copy(tmp_path)
    test = ("import os, shutil\nfrom pathlib import Path\n\n\ndef test_swap():\n    shutil.rmtree('pkg')\n"
            f"    os.symlink({str(outside)!r}, 'pkg')\n    assert Path('pkg').is_symlink()\n")
    repo = _ignored_pkg_repo(tmp_path, test)
    code, report = _run_evidence(repo, tmp_path / "statement.json")
    assert (code, report["outcome"], report["reason_id"]) == (1, "no_evidence", "tree_changed"), report
    assert (repo / "pkg").is_symlink()


@pytest.mark.parametrize("path", [b"a/../x.txt", b"./x.txt", b"a//x.txt"])
def test_r9_1_a_path_component_that_cannot_be_checked_is_refused(tmp_path, monkeypatch, path):
    """R9-1, components that cannot be checked safely (a function contract: git writes no such tree path in a
    checkout, so the listing is planted)."""
    oid = "0" * 40
    listing = subprocess.CompletedProcess([], 0, b"100644 blob " + oid.encode() + b"\t" + path + b"\0", b"")
    monkeypatch.setattr(gate, "_refuse_partial_clone", lambda repo, deadline: None)
    monkeypatch.setattr(gate, "_git", lambda *args, **kwargs: listing)
    problem = gate._working_tree_problem(str(tmp_path), oid, _deadline())
    assert problem is not None and "cannot check safely" in problem, problem
