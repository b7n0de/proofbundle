"""The done check of the plugin gate: the end of a session only with a receipt for the current state (DECISIONS.md,
D26).

Every receipt here is signed with a test key made in the test. The gate's verifier is the plugin's own server,
started through a `uv` shim with this interpreter and this checkout's package, as in tests/test_plugin_ci_check.py.

Properties checked:
- a repository without a declaration, or whose declaration names no done check, blocks nothing and the hook
  prints nothing (NOT MEASURED);
- with a done check the session ends only for a receipt that verifies under the policy at HEAD, says that every
  test passed (comparator >=, threshold 1, passed true, at least one test, pytest exit status 0) and names the
  tree of the working state now; every other case blocks with one line that names what is missing and the
  command that delivers it;
- the working state is read from raw bytes and agrees with git's own tree id for the same files;
- `done-check` exits 0 only for a pass, 1 otherwise, 2 for a wrong call; `done-init` sets the check up and
  stages it; the Stop hook is wired as a command hook.
"""
from __future__ import annotations

import base64
import json
import os
import pathlib
import shutil
import subprocess
import sys
import time

import pytest

import proofbundle
from proofbundle.emit import generate_signer
from proofbundle.evalclaim import build_eval_claim, emit_eval_receipt

ROOT = pathlib.Path(__file__).resolve().parent.parent
PLUGIN = ROOT / "plugins" / "proofbundle"
GATE = PLUGIN / "hooks" / "proofbundle_gate.py"

_bytecode, sys.dont_write_bytecode = sys.dont_write_bytecode, True
sys.path.insert(0, str(GATE.parent))
import proofbundle_gate as gate  # noqa: E402

sys.path.pop(0)
sys.dont_write_bytecode = _bytecode

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")

RECEIPT = gate.DONE_RECEIPT
POLICY = gate.DONE_POLICY


@pytest.fixture(autouse=True)
def _clean_git_config(monkeypatch):
    for key in [k for k in os.environ if k.startswith("GIT_CONFIG")]:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", os.devnull)


def _git(repo: pathlib.Path, *args: str, env: dict | None = None) -> str:
    return subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.org",
                           "-c", "commit.gpgsign=false", *args], check=True, capture_output=True, text=True,
                          env=env).stdout.strip()


def _write(path: pathlib.Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(obj if isinstance(obj, str) else json.dumps(obj), encoding="utf-8")


def _commit(repo: pathlib.Path, message: str = "c") -> None:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "--allow-empty", "-m", message)


def _git_tree_of_working_state(repo: pathlib.Path) -> str:
    """git's own tree id of the working state (no filter is configured here): HEAD's files as they are now and
    every other file git does not ignore, outside the untracked evidence folder and bytecode caches."""
    index = repo.parent / "probe-index"
    env = dict(os.environ, GIT_INDEX_FILE=str(index))
    _git(repo, "read-tree", "HEAD", env=env)
    _git(repo, "add", "-A", "--", ".", ":(exclude).proofbundle", ":(exclude,glob)**/__pycache__/**", env=env)
    tree = _git(repo, "write-tree", env=env)
    index.unlink()
    return tree


class Keys:
    def __init__(self, root: pathlib.Path):  # noqa: ARG002 - one key pair per test
        self.signer = generate_signer()
        self.public = base64.b64encode(self.signer.public_key().public_bytes_raw()).decode()


def _policy(public: str) -> dict:
    return {"schema": "proofbundle/trust-policy/v0.1", "policy_id": "done-test",
            "allowed_issuers": [{"public_key_b64": public}], "signature": {"require_expected_signer": True}}


def _declare_done(repo: pathlib.Path, public: str, evidence=()) -> None:
    _write(repo / POLICY, _policy(public))
    _write(repo / gate.DECLARATION, {"schema": gate.DECLARATION_SCHEMA, "evidence": list(evidence),
                                     "done": {"receipt": RECEIPT, "policy": POLICY}})


def _receipt(repo: pathlib.Path, signer, *, passed_tests=3, failed=0, threshold="1", exit_status=None,
             provenance_git=None, out: pathlib.Path | None = None) -> pathlib.Path:
    """A pytest receipt as the package's plugin writes it, with the git state of the working tree now."""
    ran = passed_tests + failed
    state = gate.working_state(str(repo), time.monotonic() + 60)
    if provenance_git is None:
        clean = state["worktree"] == state["tree"]
        provenance_git = {"git_hash": state["commit"], "git_tree": state["tree"], "git_clean": clean}
        if not clean:
            provenance_git["git_worktree_tree"] = state["worktree"]
    provenance = {"harness": "pytest", "exit_status": (1 if failed else 0) if exit_status is None else exit_status,
                  "tests_ran": ran, "tests_passed": passed_tests, "n_passed": passed_tests, "n_failed": failed,
                  "n_error": 0, "n_skipped": 0, "n_xfailed": 0, "n_xpassed": 0, **provenance_git}
    score = format(passed_tests / ran, ".6f").rstrip("0").rstrip(".") or "0"
    claim, _ = build_eval_claim(suite="pytest", suite_version="9", metric="pass_rate", comparator=">=",
                                threshold=threshold, score=score, n=ran, model_id=f"gitCommit:{state['commit']}",
                                dataset_id="pytest-suite", issuer="", timestamp="2026-10-08T12:00:00+00:00",
                                provenance=provenance)
    target = out or (repo / RECEIPT)
    _write(target, emit_eval_receipt(claim, signer))
    return target


@pytest.fixture
def env(tmp_path: pathlib.Path) -> dict:
    """PATH with a `uv` that runs the plugin server with this interpreter and this checkout's package."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "uv").write_text(f'#!/bin/sh\nwhile [ "$1" != "--script" ]; do shift; done\nshift\n'
                                f'exec "{sys.executable}" "$@"\n', encoding="utf-8")
    (bin_dir / "uv").chmod(0o755)
    package_root = str(pathlib.Path(proofbundle.__file__).resolve().parent.parent)
    clean = dict(os.environ, PATH=os.pathsep.join([str(bin_dir), os.environ.get("PATH", "")]))
    clean["PYTHONPATH"] = os.pathsep.join(p for p in (package_root, os.environ.get("PYTHONPATH")) if p)
    clean["PROOFBUNDLE_GATE_DIR"] = str(tmp_path / "gate-dir")
    clean.pop("CLAUDE_PLUGIN_DATA", None)
    return clean


@pytest.fixture
def repo(tmp_path: pathlib.Path) -> pathlib.Path:
    path = tmp_path / "repo"
    path.mkdir()
    _git(path, "init", "-q", "-b", "main")
    _write(path / "test_ok.py", "def test_ok():\n    assert True\n")
    _write(path / "src" / "module.py", "VALUE = 1\n")
    _commit(path)
    return path


@pytest.fixture
def keys(tmp_path: pathlib.Path) -> Keys:
    return Keys(tmp_path)


@pytest.fixture
def declared(repo: pathlib.Path, keys: Keys) -> pathlib.Path:
    _declare_done(repo, keys.public)
    _commit(repo, "declare the done check")
    return repo


def stop(env: dict, cwd: pathlib.Path, event: dict | None = None) -> tuple[int, dict | None, str]:
    event = {"hook_event_name": "Stop", "session_id": "s", "cwd": str(cwd), "stop_hook_active": False} \
        if event is None else event
    proc = subprocess.run([sys.executable, "-I", str(GATE), "stop"], input=json.dumps(event), capture_output=True,
                          text=True, env=env, cwd=cwd, timeout=180, check=False)
    return proc.returncode, (json.loads(proc.stdout) if proc.stdout.strip() else None), proc.stderr


def blocked(answer: dict | None) -> str:
    assert answer is not None and answer["decision"] == "block", answer
    reason = answer["reason"]
    assert "\n" not in reason and reason == answer["systemMessage"]
    assert reason.startswith("proofbundle done check: ")
    assert "Never weaken the declaration, the policy or the key" in reason
    return reason


# --- nothing declared: NOT MEASURED, no block ----------------------------------------------------------------------

def test_without_a_declaration_the_end_is_not_blocked_and_nothing_is_printed(env, repo):
    code, answer, _ = stop(env, repo)
    assert (code, answer) == (0, None)


def test_a_declaration_without_a_done_check_blocks_nothing(env, repo, keys):
    _write(repo / gate.DECLARATION, {"schema": gate.DECLARATION_SCHEMA, "evidence": []})
    _commit(repo)
    assert stop(env, repo)[:2] == (0, None)


def test_outside_a_repository_nothing_is_blocked(env, tmp_path):
    plain = tmp_path / "plain"
    plain.mkdir()
    assert stop(env, plain)[:2] == (0, None)


# --- the three cases of the evals, and their neighbours ------------------------------------------------------------

def test_a_green_receipt_for_the_current_tree_lets_the_session_end(env, declared, keys):
    _receipt(declared, keys.signer)
    code, answer, _ = stop(env, declared)
    assert code == 0 and set(answer) == {"systemMessage"}
    assert "done." in answer["systemMessage"] and _git(declared, "rev-parse", "HEAD^{tree}") in answer["systemMessage"]
    assert "not that the tests test anything" in answer["systemMessage"]


def test_a_green_receipt_for_another_tree_blocks(env, declared, keys):
    _receipt(declared, keys.signer)
    _write(declared / "src" / "module.py", "VALUE = 2\n")
    _commit(declared, "change")
    reason = blocked(stop(env, declared)[1])
    assert "the tests ran on tree" in reason and "PROOFBUNDLE_EMIT=1 PROOFBUNDLE_THRESHOLD=1" in reason
    assert "python -m pytest" in reason


def test_a_file_changed_after_the_run_blocks(env, declared, keys):
    _receipt(declared, keys.signer)
    _write(declared / "src" / "module.py", "VALUE = 3\n")
    assert "the tests ran on tree" in blocked(stop(env, declared)[1])


def test_red_tests_block(env, declared, keys):
    _receipt(declared, keys.signer, passed_tests=2, failed=1)
    assert "the tests did not pass" in blocked(stop(env, declared)[1])


def test_a_lower_threshold_that_signs_passed_for_a_failing_test_blocks(env, declared, keys):
    _receipt(declared, keys.signer, passed_tests=3, failed=1, threshold="0.5")
    assert "does not require every test to pass" in blocked(stop(env, declared)[1])


def test_a_run_that_did_not_exit_0_blocks_even_at_a_full_pass_rate(env, declared, keys):
    _receipt(declared, keys.signer, exit_status=3)
    assert "did not exit 0" in blocked(stop(env, declared)[1])


def test_no_receipt_blocks_with_the_command_that_delivers_it(env, declared):
    reason = blocked(stop(env, declared)[1])
    assert "no test run left a receipt" in reason
    assert f"PROOFBUNDLE_OUT={RECEIPT}" in reason
    assert "PROOFBUNDLE_KEY=" + str(pathlib.Path(env["PROOFBUNDLE_GATE_DIR"]) / gate.DONE_KEY_FILE) in reason


def test_a_receipt_signed_by_a_key_the_policy_does_not_pin_blocks(env, declared):
    _receipt(declared, generate_signer())
    assert "does not verify under the done policy" in blocked(stop(env, declared)[1])


def test_a_tampered_receipt_blocks(env, declared, keys):
    path = _receipt(declared, keys.signer)
    bundle = json.loads(path.read_text())
    claim = json.loads(base64.b64decode(bundle["payload_b64"]))
    claim["provenance"]["git_tree"] = "0" * 40
    bundle["payload_b64"] = base64.b64encode(json.dumps(claim).encode()).decode()
    _write(path, bundle)
    assert "does not verify" in blocked(stop(env, declared)[1])


def test_a_receipt_that_names_no_git_state_blocks(env, declared, keys):
    _receipt(declared, keys.signer, provenance_git={})
    assert "names no git state" in blocked(stop(env, declared)[1])


def test_an_uncommitted_state_with_its_own_receipt_ends_and_a_later_change_blocks(env, declared, keys):
    _write(declared / "src" / "module.py", "VALUE = 4\n")
    _write(declared / "src" / "new.py", "NEW = 1\n")
    _receipt(declared, keys.signer)
    claim = json.loads(base64.b64decode(json.loads((declared / RECEIPT).read_text())["payload_b64"]))
    assert claim["provenance"]["git_clean"] is False
    assert claim["provenance"]["git_worktree_tree"] == _git_tree_of_working_state(declared)
    assert stop(env, declared)[1].keys() == {"systemMessage"}
    _git(declared, "add", "src")                               # the same bytes, committed; the receipt stays out
    _git(declared, "commit", "-q", "-m", "the same bytes")    # the tested tree is now HEAD's tree
    assert stop(env, declared)[1].keys() == {"systemMessage"}
    _write(declared / "src" / "new.py", "NEW = 2\n")
    blocked(stop(env, declared)[1])


def test_a_declaration_only_in_the_working_tree_blocks(env, repo, keys):
    _declare_done(repo, keys.public)
    assert "not committed" in blocked(stop(env, repo)[1])


def test_a_working_state_that_cannot_be_read_as_files_blocks(env, declared, keys, tmp_path):
    _receipt(declared, keys.signer)
    outside = tmp_path / "outside"
    shutil.copytree(declared / "src", outside)
    shutil.rmtree(declared / "src")
    os.symlink(outside, declared / "src")
    assert "src, which is a link or not a directory" in blocked(stop(env, declared)[1])


def test_a_receipt_that_is_a_link_blocks(env, declared, keys, tmp_path):
    real = _receipt(declared, keys.signer, out=tmp_path / "elsewhere.json")
    os.symlink(real, declared / RECEIPT)
    assert "not a regular file" in blocked(stop(env, declared)[1])


def test_an_input_that_is_not_a_stop_event_blocks(env, declared):
    code, answer, _ = stop(env, declared, {"hook_event_name": "PreToolUse", "cwd": str(declared)})
    assert "not a Stop event" in blocked(answer)


def test_a_malformed_done_section_blocks(env, repo, keys):
    _write(repo / gate.DECLARATION, {"schema": gate.DECLARATION_SCHEMA, "evidence": [],
                                     "done": {"receipt": "receipt.json", "policy": POLICY}})
    _commit(repo)
    assert "must lie under .proofbundle/" in blocked(stop(env, repo)[1])


# --- the working state agrees with git -----------------------------------------------------------------------------

def test_the_working_state_tree_id_agrees_with_git(repo):
    _write(repo / "src" / "module.py", "VALUE = 5\n")
    (repo / "test_ok.py").chmod(0o755)
    _write(repo / "deep" / "er" / "file.txt", "x\n")
    os.symlink("src/module.py", repo / "link")
    (repo / ".proofbundle").mkdir()
    _write(repo / ".proofbundle" / "untracked.json", "{}")
    _write(repo / "__pycache__" / "m.cpython-311.pyc", "\0")
    state = gate.working_state(str(repo), time.monotonic() + 60)
    assert state["worktree"] == _git_tree_of_working_state(repo) != state["tree"]


def test_a_clean_filter_does_not_make_a_changed_file_clean(repo):
    """The defect class of review Runde 8 (R8-1), for the done check's own reading of the working tree."""
    _write(repo / "value.txt", "AAAA\n")
    _write(repo / ".gitattributes", "value.txt filter=back\n")
    _commit(repo)
    _git(repo, "config", "filter.back.clean", "sed s/BBBB/AAAA/")
    _write(repo / "value.txt", "BBBB\n")
    assert _git(repo, "status", "--porcelain") == ""
    state = gate.working_state(str(repo), time.monotonic() + 60)
    assert state["worktree"] != state["tree"]


# --- a done-only declaration gates no push -------------------------------------------------------------------------

def test_a_declaration_with_only_a_done_check_is_inactive_for_a_push(declared):
    verdict = gate._evaluate_tree(str(declared), _git(declared, "rev-parse", "HEAD"), time.monotonic() + 60,
                                  "HEAD", "")
    assert (verdict.decision, verdict.reason_id) == ("inactive", "done_only")


# --- done-check (CI) and done-init (setup) -------------------------------------------------------------------------

def _done_check(env, *args):
    return subprocess.run([sys.executable, "-I", str(GATE), "done-check", *args], capture_output=True, text=True,
                          env=env, timeout=180, check=False)


def test_done_check_exits_0_only_for_a_pass(env, declared, keys, tmp_path):
    outside = _receipt(declared, keys.signer, out=tmp_path / "ci" / "receipt.json")
    proc = _done_check(env, "--repo", str(declared), "--receipt", str(outside))
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["verdict"] == "pass"
    _write(declared / "src" / "module.py", "VALUE = 6\n")
    _commit(declared)
    proc = _done_check(env, "--repo", str(declared), "--receipt", str(outside))
    assert proc.returncode == 1 and json.loads(proc.stdout)["reason_id"] == "stale_receipt"


def test_done_check_fails_where_no_done_check_is_declared_and_refuses_a_wrong_call(env, repo):
    assert _done_check(env, "--repo", str(repo)).returncode == 1
    assert _done_check(env).returncode == 2
    assert _done_check(env, "--repo", str(repo), "--bogus", "x").returncode == 2
    assert _done_check(env, "--repo", str(repo), "--receipt", "").returncode == 2


def test_done_init_sets_the_check_up_and_its_key_signs_a_receipt_that_ends_the_session(env, repo):
    proc = subprocess.run([sys.executable, "-I", str(GATE), "done-init", "--repo", str(repo)], capture_output=True,
                          text=True, env=env, timeout=180, check=False)
    assert proc.returncode == 0, proc.stderr
    key = pathlib.Path(env["PROOFBUNDLE_GATE_DIR"]) / gate.DONE_KEY_FILE
    assert key.stat().st_mode & 0o777 == 0o600 and key.stat().st_size == 32
    staged = _git(repo, "diff", "--cached", "--name-only").splitlines()
    assert sorted(staged) == sorted([".proofbundle/.gitignore", gate.DECLARATION, POLICY])
    assert "git commit" in proc.stdout and "PROOFBUNDLE_KEY=" + str(key) in proc.stdout
    _git(repo, "commit", "-q", "-m", "declare the done check")
    from proofbundle.emit import load_signer
    _receipt(repo, load_signer(str(key)))
    assert _git(repo, "status", "--porcelain") == ""           # the receipt is ignored, the tree stays clean
    assert stop(env, repo)[1].keys() == {"systemMessage"}
    again = subprocess.run([sys.executable, "-I", str(GATE), "done-init", "--repo", str(repo)], capture_output=True,
                           text=True, env=env, timeout=180, check=False)
    assert again.returncode == 1 and "already declares a done check" in again.stderr


def test_the_stop_hook_is_a_command_hook():
    hooks = json.loads((PLUGIN / "hooks" / "hooks.json").read_text())["hooks"]
    (entry,) = hooks["Stop"]
    (hook,) = entry["hooks"]
    assert hook["type"] == "command" and "matcher" not in entry
    assert hook["command"].startswith('python3 -I "${CLAUDE_PLUGIN_ROOT}/hooks/proofbundle_gate.py" stop ||')
    assert "exit 2" in hook["command"]
