"""Review of 2026-10-09, F1: the CI done check gives its verdict for the commit under review, not for the working
state the test command left behind.

Measured by the reviewer at 91a52faa: the commit holds VALUE = 0 and a test that needs 1, the test command writes
VALUE = 1 into the checkout and runs the tests there, the receipt says git_clean false, and the job's done-check, which
read the working state, exited 0; the pre-push hook with the same receipt exited 1 (stale_receipt). Now the job names
the commit it checked out (`--at-commit`, from the event, never HEAD, which the test command could move), and at a
commit a receipt counts only for a clean run on exactly that commit's tree: git_clean true, git_hash the commit,
git_tree its tree.

The job's steps are run here as the runner runs them: each `run` script from the template with `bash -e`, its `env`
with the template's own expressions filled in, `checked` a repository made in the test and `gate` this checkout. Only
`python` (this interpreter) and `uv` (a shim that starts the plugin's server with this interpreter) are put on PATH;
the test command is a small emitter that signs a receipt with the job's key for the state it finds, as the package's
pytest plugin does.

Counter-probes: a receipt for a changed working tree, a test command that moves HEAD to another commit, and a signed
receipt with git_clean false whose working tree id equals the commit's tree all fail; a clean run on the commit
passes. Red against 91a52faa.
"""
from __future__ import annotations

import base64
import json
import os
import pathlib
import shutil
import subprocess
import sys
import textwrap
import time

import pytest

import proofbundle

import test_plugin_done_check as dc
from _plugin_env import plugin_env

gate = dc.gate
ROOT = dc.ROOT
WORKFLOW = ROOT / "plugins" / "proofbundle" / "ci" / "proofbundle-evidence.yml"
COMMIT_EXPRESSION = "${{ github.event.pull_request.head.sha || github.sha }}"

pytestmark = [pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed"),
              pytest.mark.skipif(shutil.which("bash") is None, reason="bash is not installed")]

#: The emitter the test commands run: it signs a pytest receipt for the git state of its working directory, the way
#: the package's pytest plugin does (git_clean true only when the working tree is HEAD's tree), and writes it where
#: PROOFBUNDLE_OUT says (a directory takes the default file name). Arguments: the pytest arguments the run names.
EMITTER = textwrap.dedent('''\
    import base64, json, os, sys, time
    sys.path.insert(0, os.environ["GATE_HOOKS"])
    import proofbundle_gate as gate
    from proofbundle.emit import load_signer
    from proofbundle.evalclaim import build_eval_claim, emit_eval_receipt
    args = sys.argv[1:]
    state = gate.working_state(os.getcwd(), time.monotonic() + 60)
    clean = state["worktree"] == state["tree"]
    git = {"git_hash": state["commit"], "git_tree": state["tree"], "git_clean": clean}
    if not clean:
        git["git_worktree_tree"] = state["worktree"]
    provenance = {"harness": "pytest", "exit_status": 0, "tests_ran": 1, "tests_passed": 1, "n_passed": 1,
                  "n_failed": 0, "n_error": 0, "n_skipped": 0, "n_xfailed": 0, "n_xpassed": 0,
                  "pytest_args": args, "pytest_addopts": os.environ.get("PYTEST_ADDOPTS", ""), "n_deselected": 0,
                  **git}
    claim, _ = build_eval_claim(suite="pytest", suite_version="9", metric="pass_rate", comparator=">=",
                                threshold="1", score="1", n=1, model_id="gitCommit:" + state["commit"],
                                dataset_id="pytest-suite", issuer="", timestamp="2026-10-09T08:00:00+00:00",
                                provenance=provenance)
    out = os.environ["PROOFBUNDLE_OUT"]
    if out.endswith("/") or os.path.isdir(out):
        out = os.path.join(out, "proofbundle_pytest_receipt.json")
    with open(out, "w", encoding="utf-8") as handle:
        json.dump(emit_eval_receipt(claim, load_signer(os.environ["PROOFBUNDLE_KEY"])), handle)
    print("receipt written to", out)
''')


@pytest.fixture(autouse=True)
def _clean_git_environment(monkeypatch):
    for key in [k for k in os.environ if k.startswith("GIT_")]:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", os.devnull)


def done_steps() -> list[dict]:
    yaml = pytest.importorskip("yaml")
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    return workflow["jobs"]["done"]["steps"]


def _step(name: str) -> dict:
    (step,) = [s for s in done_steps() if s.get("name") == name]
    return step


class Job:
    """One run of the template's done job against a repository made in the test: the two steps after the checkouts
    and the installs, `Run the tests with a receipt` and the step that checks the receipt."""

    def __init__(self, tmp_path: pathlib.Path, keys: dc.Keys):
        self.tmp = tmp_path
        self.workspace = tmp_path / "workspace"
        self.workspace.mkdir()
        self.checked = self.workspace / "checked"
        self.runner_temp = tmp_path / "runner-temp"
        self.runner_temp.mkdir()
        (self.workspace / "gate").symlink_to(ROOT, target_is_directory=True)
        self.bin = tmp_path / "job-bin"
        self.bin.mkdir()
        (self.bin / "python").write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n', encoding="utf-8")
        (self.bin / "uv").write_text(f'#!/bin/sh\nwhile [ "$1" != "--script" ]; do shift; done\nshift\n'
                                     f'exec "{sys.executable}" "$@"\n', encoding="utf-8")
        for tool in ("python", "uv"):
            (self.bin / tool).chmod(0o755)
        self.emitter = tmp_path / "emit_receipt.py"
        self.emitter.write_text(EMITTER, encoding="utf-8")
        self.keys = keys
        self.key_b64 = base64.b64encode(keys.signer.private_bytes_raw()).decode()

    def environment(self) -> dict:
        package_root = str(pathlib.Path(proofbundle.__file__).resolve().parent.parent)
        env = plugin_env(PATH=os.pathsep.join([str(self.bin), os.environ.get("PATH", "")]),
                   RUNNER_TEMP=str(self.runner_temp), GATE_HOOKS=str(ROOT / "plugins" / "proofbundle" / "hooks"),
                   EMIT=str(self.emitter), PROOFBUNDLE_GATE_DIR=str(self.tmp / "gate-dir"),
                   PYTHONDONTWRITEBYTECODE="1")
        env["PYTHONPATH"] = os.pathsep.join(p for p in (package_root, os.environ.get("PYTHONPATH")) if p)
        for name in ("CLAUDE_PLUGIN_DATA", "PROOFBUNDLE_OUT", "PROOFBUNDLE_KEY", "PROOFBUNDLE_EMIT",
                     "PROOFBUNDLE_RECEIPT_DIR"):
            env.pop(name, None)
        return env

    def expressions(self, commit: str, test_command: str) -> dict:
        return {"${{ secrets.PROOFBUNDLE_DONE_KEY }}": self.key_b64,
                "${{ inputs.done-test-command }}": test_command,
                COMMIT_EXPRESSION: commit}

    def run_step(self, step: dict, commit: str, test_command: str) -> subprocess.CompletedProcess:
        env = self.environment()
        known = self.expressions(commit, test_command)
        for name, value in (step.get("env") or {}).items():
            assert value in known, f"the harness does not know the expression {value!r} of step {step['name']!r}"
            env[name] = known[value]
        cwd = self.workspace / step["working-directory"] if "working-directory" in step else self.workspace
        return subprocess.run(["bash", "-e", "-c", step["run"]], cwd=cwd, env=env, capture_output=True, text=True,
                              timeout=300, check=False)

    def run(self, test_command: str, commit: str | None = None) -> tuple[subprocess.CompletedProcess, dict | None]:
        """The test step, then the check step, for the commit under review (HEAD of `checked` now, unless named)."""
        commit = commit or dc._git(self.checked, "rev-parse", "HEAD")
        tests = self.run_step(_step("Run the tests with a receipt"), commit, test_command)
        assert tests.returncode == 0, tests.stderr
        check = self.run_step(done_steps()[-1], commit, test_command)
        report = None
        start = check.stdout.find("{")
        if start >= 0:
            report = json.loads(check.stdout[start:])
        return check, report


@pytest.fixture
def keys(tmp_path: pathlib.Path) -> dc.Keys:
    return dc.Keys(tmp_path)


@pytest.fixture
def job(tmp_path: pathlib.Path, keys: dc.Keys) -> Job:
    """The job, with `checked` a repository whose HEAD holds VALUE = 0, a test that needs VALUE == 1 and the one-check
    done section."""
    job = Job(tmp_path, keys)
    path = job.checked
    path.mkdir()
    dc._git(path, "init", "-q", "-b", "main")
    dc._write(path / "src" / "module.py", "VALUE = 0\n")
    dc._write(path / "test_value.py", "from src.module import VALUE\n\n\ndef test_value():\n    assert VALUE == 1\n")
    dc._declare_done(path, keys.public)
    dc._commit(path, "VALUE = 0 and a test that needs 1")
    return job


# --- the reviewer's case and its neighbours ----------------------------------------------------------------------

def test_a_receipt_for_a_working_tree_the_test_command_changed_fails(job):
    """F1 as measured: the test command writes VALUE = 1 into the checkout, the receipt says git_clean false. Red at
    91a52faa, where the job's done-check exited 0."""
    check, report = job.run("printf 'VALUE = 1\\n' > src/module.py && python \"$EMIT\"")
    assert (check.returncode, report["verdict"], report["reason_id"]) == (1, "deny", "stale_receipt"), check.stderr
    assert "the tests ran on tree" in report["message"] and "the tree of the commit under review is tree" \
        in report["message"], report["message"]
    assert report["head"] == dc._git(job.checked, "rev-parse", "HEAD")


def test_a_clean_run_on_the_commit_under_review_passes(job):
    """The positive counter-probe: nothing changed, the receipt names the commit's tree, the job passes."""
    check, report = job.run('python "$EMIT"')
    assert (check.returncode, report["verdict"], report["reason_id"]) == (0, "pass", "done"), check.stderr
    tree = dc._git(job.checked, "rev-parse", "HEAD^{tree}")
    assert tree in report["message"]


def test_a_test_command_that_moves_head_does_not_choose_the_commit_checked(job):
    """The commit under review comes from the event, never from HEAD: a test command that commits other content and
    runs the tests there leaves a clean receipt for another commit, and the job fails. Red at 91a52faa."""
    reviewed = dc._git(job.checked, "rev-parse", "HEAD")
    command = ("printf 'VALUE = 1\\n' > src/module.py && git -c user.name=t -c user.email=t@example.org "
               "-c commit.gpgsign=false commit -q -am other && python \"$EMIT\"")
    check, report = job.run(command, commit=reviewed)
    assert dc._git(job.checked, "rev-parse", "HEAD") != reviewed, "the test command moved HEAD"
    assert (check.returncode, report["verdict"], report["reason_id"]) == (1, "deny", "stale_receipt"), check.stderr
    assert report["head"] == reviewed


def test_a_change_the_test_command_reverts_before_it_signs_still_counts_as_the_commit(job):
    """The receipt is for the state the tests ran on, which the emitter measures when it signs; a command that changes
    a file and puts it back before signing leaves a clean receipt for the commit. Named so the boundary is seen: the
    job checks what the receipt names, not what the test command did in between."""
    check, report = job.run("cp src/module.py \"$RUNNER_TEMP/keep\" && printf 'VALUE = 1\\n' > src/module.py && "
                            "cp \"$RUNNER_TEMP/keep\" src/module.py && python \"$EMIT\"")
    assert (check.returncode, report["verdict"]) == (0, "pass"), check.stderr


# --- the rule at a commit, in the gate ----------------------------------------------------------------------------

def _crafted_receipt(repo: pathlib.Path, signer, commit: str, tree: str, worktree: str) -> pathlib.Path:
    return dc._receipt(repo, signer, provenance_git={"git_hash": commit, "git_tree": tree, "git_clean": False,
                                                     "git_worktree_tree": worktree})


def test_at_a_commit_a_receipt_with_git_clean_false_never_passes(job, keys):
    """A signed receipt with git_clean false whose working tree id equals the commit's tree names a run that was not on
    the commit itself, whatever the ids say; at a commit only a clean run counts. Red at 91a52faa (pass)."""
    repo = job.checked
    commit, tree = dc._git(repo, "rev-parse", "HEAD"), dc._git(repo, "rev-parse", "HEAD^{tree}")
    _crafted_receipt(repo, keys.signer, commit, tree, tree)
    result = gate.done_evaluation(str(repo), time.monotonic() + 120, at_commit=commit)
    assert result["verdict"].decision == "deny" and result["verdict"].reason_id == "stale_receipt", \
        result["verdict"].detail
    assert "git_clean" in result["verdict"].detail


def test_at_a_commit_a_clean_receipt_for_that_commit_passes(job, keys):
    repo = job.checked
    dc._receipt(repo, keys.signer)
    commit = dc._git(repo, "rev-parse", "HEAD")
    result = gate.done_evaluation(str(repo), time.monotonic() + 120, at_commit=commit)
    assert result["verdict"].decision == "pass", result["verdict"].detail


def test_the_working_state_check_still_takes_a_run_with_uncommitted_changes(job, keys):
    """The end of a session checks the working state (owner choice K1 C): there a receipt with git_clean false for the
    working tree as it is now still passes. Only the check at a commit requires a clean run."""
    repo = job.checked
    dc._write(repo / "src" / "module.py", "VALUE = 1\n")
    dc._receipt(repo, keys.signer)
    assert gate.done_evaluation(str(repo), time.monotonic() + 120)["verdict"].decision == "pass"


# --- the command line and the template ------------------------------------------------------------------------------

def done_check(env: dict, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-I", str(dc.GATE), "done-check", *args], capture_output=True, text=True,
                          env=env, timeout=180, check=False)


def test_done_check_takes_at_commit_and_reads_the_commit_not_the_working_tree(job, keys, env):
    repo = job.checked
    commit = dc._git(repo, "rev-parse", "HEAD")
    dc._write(repo / "src" / "module.py", "VALUE = 1\n")
    receipt = dc._receipt(repo, keys.signer, out=job.tmp / "receipt.json")
    assert done_check(env, "--repo", str(repo), "--receipt", str(receipt)).returncode == 0  # the working state
    at = done_check(env, "--repo", str(repo), "--receipt", str(receipt), "--at-commit", commit)
    assert at.returncode == 1 and json.loads(at.stdout)["reason_id"] == "stale_receipt", at.stderr
    dc._write(repo / "src" / "module.py", "VALUE = 0\n")
    clean = dc._receipt(repo, keys.signer, out=job.tmp / "clean.json")
    assert done_check(env, "--repo", str(repo), "--receipt", str(clean), "--at-commit", commit).returncode == 0


@pytest.mark.parametrize("args", [["--at-commit", ""], ["--at-commit"], ["--at-commit", "a", "--at-commit", "b"]])
def test_a_wrong_at_commit_is_a_wrong_call(job, env, args):
    proc = done_check(env, "--repo", str(job.checked), *args)
    assert proc.returncode == 2 and "--at-commit REV" in proc.stderr and proc.stdout == ""


def test_an_at_commit_that_names_no_commit_fails(job, env):
    proc = done_check(env, "--repo", str(job.checked), "--at-commit", "0" * 40)
    assert proc.returncode == 1 and json.loads(proc.stdout)["reason_id"] == "gate_error"


def test_the_check_step_names_the_commit_from_the_event_through_env():
    step = done_steps()[-1]
    assert step["env"]["COMMIT"] == COMMIT_EXPRESSION
    assert '--at-commit "$COMMIT"' in step["run"]
    assert "HEAD" not in step["run"], "HEAD is what the test command may have moved"
    (checked,) = [s["with"] for s in done_steps() if s.get("with", {}).get("path") == "checked"]
    assert checked["ref"] == COMMIT_EXPRESSION, "the job checks the commit it checked out"


@pytest.fixture
def env(tmp_path: pathlib.Path) -> dict:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "uv").write_text(f'#!/bin/sh\nwhile [ "$1" != "--script" ]; do shift; done\nshift\n'
                                f'exec "{sys.executable}" "$@"\n', encoding="utf-8")
    (bin_dir / "uv").chmod(0o755)
    package_root = str(pathlib.Path(proofbundle.__file__).resolve().parent.parent)
    clean = plugin_env(PATH=os.pathsep.join([str(bin_dir), os.environ.get("PATH", "")]))
    clean["PYTHONPATH"] = os.pathsep.join(p for p in (package_root, os.environ.get("PYTHONPATH")) if p)
    clean["PROOFBUNDLE_GATE_DIR"] = str(tmp_path / "gate-dir")
    clean.pop("CLAUDE_PLUGIN_DATA", None)
    return clean


def test_the_expressions_the_harness_fills_are_the_templates_own():
    """The harness fills only expressions the template uses, so the job run here is the template's job."""
    text = WORKFLOW.read_text(encoding="utf-8")
    for expression in ("${{ secrets.PROOFBUNDLE_DONE_KEY }}", "${{ inputs.done-test-command }}", COMMIT_EXPRESSION):
        assert expression in text
