"""Review Runde 8 (stand 76d88966): one regression test per finding, each exactly the review's case.

These tests judge the gate's verdict (or, for run-evidence, the producer's). The only programs they start are
marker scripts inside the test folder, and only where a test first shows that plain git starts the marker, so
the case is not vacuous. Red against 76d88966, green after.
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

#: The program-selecting variables the gate reads from the hook's environment (as tests/test_plugin_gate_runde6b.py).
_PROGRAM_ENV = ["EDITOR", "GIT_ASKPASS", "GIT_EDITOR", "GIT_EXEC_PATH", "GIT_EXTERNAL_DIFF", "GIT_PAGER",
                "GIT_PROXY_COMMAND", "GIT_SSH", "GIT_SSH_COMMAND", "PAGER", "SSH_ASKPASS", "VISUAL"]


@pytest.fixture(autouse=True)
def _clean_git_config(monkeypatch):
    for key in [k for k in os.environ if k.startswith("GIT_CONFIG")] + _PROGRAM_ENV + ["GIT_NO_LAZY_FETCH"]:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", os.devnull)


def _git(repo: pathlib.Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.org",
                           "-c", "commit.gpgsign=false", *args], check=True, capture_output=True,
                          text=True).stdout.strip()


def _write(path: pathlib.Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _marker_program(directory: pathlib.Path, marker: pathlib.Path, name: str, body: str = "") -> pathlib.Path:
    """A script inside the test folder that leaves marker when something starts it."""
    directory.mkdir(parents=True, exist_ok=True)
    program = directory / name
    program.write_text(f"#!/bin/sh\ntouch {shlex.quote(str(marker))}\n{body}exit 0\n", encoding="utf-8")
    program.chmod(0o700)
    return program


def _deadline() -> float:
    return gate.time.monotonic() + 30


def _decision(command: str, repo: pathlib.Path, host: str = "claude") -> tuple[str | None, str]:
    outcome = gate.decide(command, str(repo), _deadline(), host=host)
    if outcome is None:
        return None, ""
    return outcome.decision, outcome.text


def _repo(tmp_path: pathlib.Path, name: str = "r") -> pathlib.Path:
    """A plain repository with one commit and a bare remote `origin`, no hook and no helper."""
    repo, bare = tmp_path / name, tmp_path / f"{name}.git"
    repo.mkdir(parents=True)
    _git(repo, "init", "-q", "-b", "main")
    _write(repo / "a.txt", "a\n")
    _git(repo, "add", "a.txt")
    _git(repo, "commit", "-q", "-m", "base")
    _git(repo, "init", "-q", "--bare", str(bare))
    _git(repo, "remote", "add", "origin", str(bare))
    return repo


# --- R8-1: run-evidence names the tree it tested -----------------------------------------------------------------

def _run_evidence(repo: pathlib.Path, out: pathlib.Path, *command: str) -> tuple[int, dict]:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("PROOFBUNDLE_", "PYTEST_"))}
    argv = [sys.executable, str(GATE), "run-evidence", "--repo", str(repo), "--out", str(out), "--",
            *(command or (sys.executable, "-m", "pytest", "-q", "tests/"))]
    proc = subprocess.run(argv, capture_output=True, text=True, env=env, cwd=repo.parent, timeout=300, check=False)
    return proc.returncode, json.loads(proc.stdout)


def _value_repo(tmp_path: pathlib.Path) -> pathlib.Path:
    """HEAD holds VALUE = 1 and a test that demands VALUE == 2, so a run on HEAD is red."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _write(repo / "value.py", "VALUE = 1\n")
    _write(repo / "tests" / "test_value.py",
           "import sys, pathlib\nsys.path.insert(0, str(pathlib.Path(__file__).parent.parent))\n"
           "from value import VALUE\n\n\ndef test_value():\n    assert VALUE == 2\n")
    _write(repo / ".gitattributes", "value.py filter=fix\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "red at HEAD")
    return repo


def test_r8_1_the_red_head_control_gives_no_evidence(tmp_path):
    """R8-1, first row of the review's table: HEAD holds VALUE = 1, the test demands VALUE == 2; the run fails."""
    repo = _value_repo(tmp_path)
    code, report = _run_evidence(repo, tmp_path / "statement.json")
    assert (code, report["outcome"], report["reason_id"]) == (1, "no_evidence", "run_failed"), report
    assert report["run"]["exit_code"] == 1 and report["run"]["counts"]["failed"] == 1


def test_r8_1_a_clean_filter_that_restores_head_does_not_make_another_working_file_evidence(tmp_path):
    """R8-1, the review's case: only the working file says VALUE = 2, a clean filter writes VALUE = 1 back while
    staging. run-evidence ran the filter, found the working tree equal to HEAD, ran the green test on the working
    file and wrote a statement that names HEAD. Now the working bytes are compared and the run is refused before
    it starts; the filter never runs. The anti-vacuity half: plain git staging starts the filter."""
    repo = _value_repo(tmp_path)
    marker = tmp_path / "marker-clean-filter"
    clean = _marker_program(tmp_path / "bin", marker, "clean-filter.sh", "cat >/dev/null\nprintf 'VALUE = 1\\n'\n")
    _git(repo, "config", "filter.fix.clean", str(clean))
    _write(repo / "value.py", "VALUE = 2\n")
    out = tmp_path / "statement.json"
    code, report = _run_evidence(repo, out)
    assert (code, report["outcome"], report["reason_id"]) == (1, "no_evidence", "tree_not_clean"), report
    assert "value.py" in report["message"], report
    assert not out.exists()
    assert not marker.exists(), "run-evidence started the clean filter"
    subprocess.run(["git", "-C", str(repo), "add", "value.py"], capture_output=True, check=False)
    assert marker.exists(), "the clean filter is not live for a plain git; the case would be vacuous"


def test_r8_1_neither_fsmonitor_nor_post_index_change_starts_while_the_tree_is_compared(tmp_path):
    """R8-1, the review's side finding: the old staging of the working tree started core.fsmonitor and the
    post-index-change hook, even before a missing test program was refused. Neither starts now, neither for a
    missing program nor around a green run. The anti-vacuity half: plain git staging starts both."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _write(repo / "tests" / "test_green.py", "def test_green():\n    assert True\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "green")
    fsmonitor, hook = tmp_path / "marker-fsmonitor", tmp_path / "marker-post-index-change"
    _git(repo, "config", "core.fsmonitor", str(_marker_program(tmp_path / "bin", fsmonitor, "fsmonitor.sh")))
    _marker_program(repo / ".git" / "hooks", hook, "post-index-change")
    code, report = _run_evidence(repo, tmp_path / "s1.json", "no-such-pytest-program-r8", "-q")
    assert (code, report["reason_id"]) == (1, "no_program"), report
    code, report = _run_evidence(repo, tmp_path / "s2.json")
    assert (code, report["outcome"]) == (0, "evidence"), report
    assert not fsmonitor.exists(), "run-evidence started core.fsmonitor"
    assert not hook.exists(), "run-evidence started the post-index-change hook"
    subprocess.run(["git", "-C", str(repo), "add", "-A"], capture_output=True, check=False,
                   env={**os.environ, "GIT_INDEX_FILE": str(tmp_path / "probe-index")})
    assert fsmonitor.exists() or hook.exists(), "neither marker is live for a plain git; the case would be vacuous"


# --- R8-4: the file that leads git to the shared configuration and hooks --------------------------------------

def _write_decision(path: pathlib.Path, cwd: pathlib.Path, host: str = "claude") -> str | None:
    outcome = gate.decide_write("Write", {"file_path": str(path), "content": ".\n"}, str(cwd), _deadline(), host=host)
    return None if outcome is None else outcome.decision


@pytest.mark.parametrize("state", ["missing", "present"])
def test_r8_4_a_write_to_commondir_of_a_normal_repository_asks(tmp_path, state):
    """R8-4: a synthetic Write on the missing or present .git/commondir got no answer; git takes the shared
    configuration and hooks from the directory commondir names (gitrepository-layout(5))."""
    repo = _repo(tmp_path)
    if state == "present":
        (repo / ".git" / "commondir").write_text(".\n", encoding="utf-8")
    assert _write_decision(repo / ".git" / "commondir", repo) == "ask"


def test_r8_4_a_write_to_commondir_of_a_linked_worktree_asks(tmp_path):
    """R8-4: the present commondir of a linked worktree got no answer either, while its .git file and
    .git/config ask. The anti-vacuity half: git resolves the worktree's common directory through that file."""
    repo = _repo(tmp_path)
    worktree = tmp_path / "linked"
    _git(repo, "worktree", "add", "-q", "-b", "side", str(worktree))
    gitdir = pathlib.Path(_git(worktree, "rev-parse", "--path-format=absolute", "--git-dir"))
    commondir = gitdir / "commondir"
    assert commondir.is_file(), "precondition: a linked worktree has a commondir"
    assert _write_decision(commondir, worktree) == "ask"
    assert _write_decision(worktree / ".git", worktree) == "ask"   # the control the review names
    common = _git(worktree, "rev-parse", "--path-format=absolute", "--git-common-dir")
    assert pathlib.Path(common) == (gitdir / commondir.read_text(encoding="utf-8").strip()).resolve()


# --- R8-5: a program path named git without a subcommand -----------------------------------------------------

@pytest.mark.parametrize("words", ["", " --version"], ids=["no-subcommand", "version"])
def test_r8_5_a_program_path_named_git_is_not_free_without_a_subcommand(tmp_path, words):
    """R8-5: a program path whose basename is git, with no subcommand or with --version, got no answer and the
    local marker program ran; the same path with `status --short` asks. The early return for the bare form
    skipped the binding check. The anti-vacuity half: the path does run the marker. The bare `git --version`
    stays free (the control the review names)."""
    repo, marker = _repo(tmp_path), tmp_path / "marker-path-git"
    program = _marker_program(tmp_path / "bin", marker, "git")
    decision, text = _decision(f"{shlex.quote(str(program))}{words}", repo)
    assert decision == "ask", text
    assert _decision(f"{shlex.quote(str(program))} status --short", repo)[0] == "ask"
    assert _decision("git --version", repo) == (None, "")
    assert not marker.exists()
    subprocess.run([str(program), *words.split()], capture_output=True, check=False)
    assert marker.exists(), "the program at the path is not live; the case would be vacuous"


# --- R8-6: git's value semantics, untrimmed, and the valueless pager key ---------------------------------------

@pytest.mark.parametrize("word", ["on", "off", "yes", "no", "0", "1"])
def test_r8_6_a_padded_boolean_word_in_core_fsmonitor_is_a_command_and_asks(tmp_path, word):
    """R8-6: core.fsmonitor stored as ` on ` (and ` off `, ` yes `, ` no `, ` 0 `, ` 1 `) was trimmed into a
    boolean word and stayed free; git compares untrimmed and starts the local command `on`. The anti-vacuity
    half: a plain git status starts the marker program of that name."""
    repo, marker = _repo(tmp_path), tmp_path / f"marker-fsmonitor-{word}"
    _marker_program(tmp_path / "bin", marker, word)
    _git(repo, "config", "core.fsmonitor", f" {word} ")
    decision, text = _decision("git status --short", repo)
    assert decision == "ask", text
    assert not marker.exists(), "the gate started the fsmonitor command"
    env = {**os.environ, "PATH": f"{tmp_path / 'bin'}{os.pathsep}{os.environ['PATH']}"}
    subprocess.run(["git", "-C", str(repo), "status", "--short"], capture_output=True, check=False, env=env,
                   timeout=60)
    assert marker.exists(), f"git does not start the command ' {word} '; the case would be vacuous"


def _status_on_a_terminal(repo: pathlib.Path) -> None:
    """git status with its output on a local pseudo terminal, where git pages."""
    master, slave = os.openpty()
    try:
        env = {k: v for k, v in os.environ.items() if k != "GIT_PAGER_IN_USE"}
        subprocess.run(["git", "-C", str(repo), "status"], stdin=subprocess.DEVNULL, stdout=slave,
                       stderr=subprocess.DEVNULL, check=False, env=env, timeout=60)
    finally:
        os.close(slave)
        os.close(master)


def test_r8_6_a_valueless_pager_key_is_true_and_asks(tmp_path):
    """R8-6: pager.status without a value, together with a configured core.pager, stayed free; a key without a
    value is true (git-config(1)), and git status on a terminal starts core.pager. The anti-vacuity half: without
    the key git status starts no pager and the gate stays free; with it git starts the marker."""
    repo, marker = _repo(tmp_path), tmp_path / "marker-pager"
    _git(repo, "config", "core.pager", str(_marker_program(tmp_path / "bin", marker, "pager.sh", "cat >/dev/null\n")))
    assert _decision("git status", repo) == (None, "")
    _status_on_a_terminal(repo)
    assert not marker.exists(), "git status pages without pager.status; the case would not isolate the key"
    with (repo / ".git" / "config").open("a", encoding="utf-8") as config:
        config.write("[pager]\n\tstatus\n")
    assert _git(repo, "config", "--bool", "pager.status") == "true"
    decision, text = _decision("git status", repo)
    assert decision == "ask", text
    assert not marker.exists(), "the gate started the pager"
    _status_on_a_terminal(repo)
    assert marker.exists(), "git status does not start core.pager on a terminal; the case would be vacuous"
