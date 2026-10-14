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
from _plugin_env import plugin_env

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
    env = plugin_env(GIT_INDEX_FILE=str(index))
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
             provenance_git=None, out: pathlib.Path | None = None, selection: dict | None = None) -> pathlib.Path:
    """A pytest receipt as the package's plugin writes it, with the git state of the working tree now and, when
    given, how pytest was asked to run (pytest_args, pytest_addopts, n_deselected)."""
    ran = passed_tests + failed
    state = gate.working_state(str(repo), time.monotonic() + 60)
    if provenance_git is None:
        clean = state["worktree"] == state["tree"]
        provenance_git = {"git_hash": state["commit"], "git_tree": state["tree"], "git_clean": clean}
        if not clean:
            provenance_git["git_worktree_tree"] = state["worktree"]
    provenance = {"harness": "pytest", "exit_status": (1 if failed else 0) if exit_status is None else exit_status,
                  "tests_ran": ran, "tests_passed": passed_tests, "n_passed": passed_tests, "n_failed": failed,
                  "n_error": 0, "n_skipped": 0, "n_xfailed": 0, "n_xpassed": 0, **(selection or {}), **provenance_git}
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
    clean = plugin_env(PATH=os.pathsep.join([str(bin_dir), os.environ.get("PATH", "")]))
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


def test_a_green_receipt_for_another_commit_blocks_and_names_both(env, declared, keys):
    _receipt(declared, keys.signer)
    named = _git(declared, "rev-parse", "HEAD^{tree}")
    _write(declared / "src" / "module.py", "VALUE = 2\n")
    _commit(declared, "change")
    reason = blocked(stop(env, declared)[1])
    assert "check tests is stale: the receipt names commit" in reason
    assert named[:12] in reason and _git(declared, "rev-parse", "HEAD^{tree}")[:12] in reason
    assert "PROOFBUNDLE_EMIT=1 PROOFBUNDLE_THRESHOLD=1" in reason and "python -m pytest" in reason


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
    _git(declared, "commit", "-q", "-m", "the same bytes")    # the tested tree is now HEAD's tree, the commit is new
    assert "the receipt names commit" in blocked(stop(env, declared)[1])
    _receipt(declared, keys.signer)                            # a run on the new commit ends the session
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


# --- the order: required checks, their selection, allowed paths (D28, N1 and N2) -----------------------------------

UNIT = {"id": "unit", "args": ["tests/unit"], "receipt": ".proofbundle/receipts/unit.json"}
INTEGRATION = {"id": "integration", "args": ["tests/integration"], "receipt": ".proofbundle/receipts/integration.json"}


def _selection(check: dict, **changes) -> dict:
    return {"pytest_args": list(check["args"]), "pytest_addopts": "", "n_deselected": 0, **changes}


def _declare_order(repo: pathlib.Path, public: str, checks=(UNIT, INTEGRATION), **extra) -> None:
    _write(repo / POLICY, _policy(public))
    _write(repo / gate.DECLARATION, {"schema": gate.DECLARATION_SCHEMA, "evidence": [],
                                     "done": {"policy": POLICY, "checks": list(checks), **extra}})


def _run(repo: pathlib.Path, signer, check: dict, **kwargs) -> pathlib.Path:
    return _receipt(repo, signer, out=kwargs.pop("out", repo / check["receipt"]),
                    selection=kwargs.pop("selection", _selection(check)), **kwargs)


@pytest.fixture
def ordered(repo: pathlib.Path, keys: Keys) -> pathlib.Path:
    _declare_order(repo, keys.public)
    _commit(repo, "the order: two checks")
    return repo


def test_an_order_with_two_checks_names_the_missing_one_and_its_command(env, ordered, keys):
    _run(ordered, keys.signer, UNIT)
    reason = blocked(stop(env, ordered)[1])
    assert "check integration is missing: no test run left a receipt" in reason
    assert ("Next: run PYTEST_ADDOPTS= PROOFBUNDLE_EMIT=1 PROOFBUNDLE_THRESHOLD=1 "
            "PROOFBUNDLE_OUT=.proofbundle/receipts/integration.json PROOFBUNDLE_KEY=") in reason
    assert reason.count("python -m pytest tests/integration.") == 1 and "also open" not in reason
    _run(ordered, keys.signer, INTEGRATION)
    code, answer, _ = stop(env, ordered)
    assert code == 0 and set(answer) == {"systemMessage"}
    assert "done. 2 checks (unit, integration)" in answer["systemMessage"]


def test_every_open_check_is_listed_after_the_first(env, ordered):
    reason = blocked(stop(env, ordered)[1])
    assert "check unit is missing" in reason and "also open: integration (missing)" in reason


def test_a_receipt_of_one_check_does_not_stand_for_another(env, ordered, keys):
    _run(ordered, keys.signer, UNIT)
    _run(ordered, keys.signer, UNIT, out=ordered / INTEGRATION["receipt"])
    reason = blocked(stop(env, ordered)[1])
    assert 'check integration is other selection: the receipt\'s run had the pytest arguments ["tests/unit"]' in reason


@pytest.mark.parametrize(("changes", "expected"), [
    ({"pytest_addopts": "-k fast"}, "PYTEST_ADDOPTS '-k fast'"),
    ({"n_deselected": 2}, "deselected 2 tests"),
    ({"pytest_args": ["tests/unit", "-k", "fast"]}, '["tests/unit", "-k", "fast"]'),
])
def test_a_run_with_another_selection_blocks(env, ordered, keys, changes, expected):
    _run(ordered, keys.signer, INTEGRATION)
    _run(ordered, keys.signer, UNIT, selection=_selection(UNIT, **changes))
    reason = blocked(stop(env, ordered)[1])
    assert "check unit is other selection" in reason and expected in reason


def test_a_receipt_that_does_not_name_its_selection_blocks_under_an_order(env, ordered, keys):
    _run(ordered, keys.signer, INTEGRATION)
    _run(ordered, keys.signer, UNIT, selection={})
    assert "does not name how pytest was asked to run" in blocked(stop(env, ordered)[1])


def test_missing_foreign_stale_and_manipulated_receipts_each_block(env, ordered, keys):
    """The four counter-probes of the milestone, one check at a time, the other check green."""
    _run(ordered, keys.signer, INTEGRATION)
    assert "check unit is missing" in blocked(stop(env, ordered)[1])
    _run(ordered, generate_signer(), UNIT)                                       # foreign: another key
    assert "check unit is unverified: it does not verify under the done policy" in blocked(stop(env, ordered)[1])
    path = _run(ordered, keys.signer, UNIT)                                      # manipulated: payload changed
    bundle = json.loads(path.read_text())
    claim = json.loads(base64.b64decode(bundle["payload_b64"]))
    claim["provenance"]["n_deselected"] = 0
    claim["n"] = claim["n"] + 1
    bundle["payload_b64"] = base64.b64encode(json.dumps(claim).encode()).decode()
    _write(path, bundle)
    assert "check unit is unverified" in blocked(stop(env, ordered)[1])
    _run(ordered, keys.signer, UNIT)
    assert stop(env, ordered)[1].keys() == {"systemMessage"}
    _write(ordered / "src" / "module.py", "VALUE = 7\n")                         # stale: the state moved on
    reason = blocked(stop(env, ordered)[1])
    assert "check unit is stale: the tests ran on tree" in reason and "also open: integration (stale)" in reason


def test_red_tests_of_one_check_block(env, ordered, keys):
    _run(ordered, keys.signer, INTEGRATION)
    _run(ordered, keys.signer, UNIT, passed_tests=2, failed=1)
    assert "check unit is red: the receipt says the tests did not pass" in blocked(stop(env, ordered)[1])


@pytest.mark.parametrize("done", [
    {"policy": POLICY, "checks": []},
    {"policy": POLICY, "checks": [UNIT, UNIT]},
    {"policy": POLICY, "checks": [dict(UNIT, id="Unit")]},
    {"policy": POLICY, "checks": [dict(UNIT, args="tests/unit")]},
    {"policy": POLICY, "checks": [dict(UNIT, args=[""])]},
    {"policy": POLICY, "checks": [dict(UNIT, receipt="receipts/unit.json")]},
    {"policy": POLICY, "checks": [dict(UNIT, receipt=POLICY)]},
    {"policy": POLICY, "checks": [dict(UNIT, receipt=gate.DONE_STATE)]},
    {"policy": POLICY, "checks": [UNIT, dict(INTEGRATION, receipt=UNIT["receipt"])]},
    {"policy": POLICY, "checks": [UNIT], "paths": []},
    {"policy": POLICY, "checks": [UNIT], "paths": ["/abs"]},
    {"policy": POLICY, "checks": [UNIT], "max_blocks": 0},
    {"policy": POLICY, "checks": [UNIT], "max_blocks": 8},
    {"policy": POLICY, "checks": [UNIT], "max_blocks": True},
    {"policy": POLICY, "checks": [UNIT], "extra": 1},
    {"policy": POLICY, "receipt": RECEIPT, "checks": [UNIT]},
    {"policy": POLICY, "checks": [dict(UNIT, more=1)]},
])
def test_a_malformed_order_blocks_and_is_refused_by_the_parser(env, repo, keys, done):
    _write(repo / POLICY, _policy(keys.public))
    _write(repo / gate.DECLARATION, {"schema": gate.DECLARATION_SCHEMA, "evidence": [], "done": done})
    _commit(repo)
    with pytest.raises(gate.GateError):
        gate._done_section(done)
    assert "the check reached no verdict" in blocked(stop(env, repo)[1])


def test_the_one_check_form_reads_as_one_check_without_a_selection():
    done = gate._done_section({"receipt": RECEIPT, "policy": POLICY})
    assert done["checks"] == [{"id": "tests", "args": None, "receipt": RECEIPT}]
    assert (done["paths"], done["max_blocks"]) == (None, 3)


def test_paths_outside_the_order_block_and_the_base_is_the_commit_that_set_it(env, repo, keys):
    _declare_order(repo, keys.public, checks=(UNIT,), paths=["src/*"])
    _commit(repo, "the order")
    base = _git(repo, "rev-parse", "HEAD")
    _write(repo / "src" / "module.py", "VALUE = 8\n")
    _run(repo, keys.signer, UNIT)
    assert stop(env, repo)[1].keys() == {"systemMessage"}
    assert f"no path outside the order changed since {base[:12]}" in stop(env, repo)[1]["systemMessage"]
    _write(repo / "test_ok.py", "def test_ok():\n    assert 1\n")
    _run(repo, keys.signer, UNIT)
    reason = blocked(stop(env, repo)[1])
    assert f"check paths is outside paths: the work changes paths the order does not allow since {base[:12]}: " \
           "test_ok.py" in reason
    assert "Next: undo the changes outside the allowed paths, or ask the owner to change the order" in reason


def test_a_changed_policy_is_a_path_outside_the_order(env, repo, keys):
    _declare_order(repo, keys.public, checks=(UNIT,), paths=["src/*"])
    _commit(repo, "the order")
    policy = json.loads((repo / POLICY).read_text())
    policy["policy_id"] = "changed"
    _write(repo / POLICY, policy)
    _write(repo / "src" / "module.py", "VALUE = 8\n")   # work in the order's paths, so only the policy is open
    _commit(repo, "a changed policy")
    _run(repo, keys.signer, UNIT)
    assert "since" in blocked(stop(env, repo)[1]) and POLICY in blocked(stop(env, repo)[1])


# --- the return path: a blocker after blocks without progress, and the counters (D28, N3 and N5) -------------------

def _done_file(repo: pathlib.Path, name: str) -> dict:
    return json.loads((repo / name).read_text())


def test_after_max_blocks_without_progress_a_blocker_is_written_and_the_session_ends(env, repo, keys):
    _declare_order(repo, keys.public, max_blocks=2)
    _commit(repo, "the order")
    _run(repo, keys.signer, UNIT)
    blocked(stop(env, repo)[1])
    blocked(stop(env, repo)[1])
    code, answer, _ = stop(env, repo)
    assert code == 0 and set(answer) == {"systemMessage"}
    assert answer["systemMessage"].startswith("proofbundle done check: NOT DONE. The same open points stayed open "
                                              "through 2 blocks")
    assert gate.DONE_BLOCKER in answer["systemMessage"] and "check integration is missing" in answer["systemMessage"]
    blocker = _done_file(repo, gate.DONE_BLOCKER)
    assert blocker["verdict"] == "NOT DONE" and blocker["head"] == _git(repo, "rev-parse", "HEAD")
    assert blocker["tree"] == _git(repo, "rev-parse", "HEAD^{tree}") and blocker["clean"] is True
    assert [(c["id"], c["status"]) for c in blocker["checks"]] == [("unit", "green"), ("integration", "missing")]
    assert "python -m pytest tests/integration" in blocker["checks"][1]["command"]
    assert stop(env, repo)[1].keys() == {"systemMessage"}                       # it stays ended, not blocked again
    metrics = _done_file(repo, gate.DONE_METRICS)
    assert (metrics["blocked"], metrics["blockers"], metrics["missing_checks"], metrics["done"]) == (2, 1, 2, 0)
    _run(repo, keys.signer, INTEGRATION)                                         # the step is made up
    assert "done. 2 checks" in stop(env, repo)[1]["systemMessage"]
    metrics = _done_file(repo, gate.DONE_METRICS)
    assert (metrics["completed_after_block"], metrics["done"]) == (1, 1)
    assert not (repo / gate.DONE_BLOCKER).exists()


def test_progress_resets_the_count(env, repo, keys):
    _declare_order(repo, keys.public, max_blocks=1)
    _commit(repo, "the order")
    blocked(stop(env, repo)[1])                                                  # unit and integration missing
    _run(repo, keys.signer, UNIT)
    blocked(stop(env, repo)[1])                                                  # one fewer open point: progress
    assert _done_file(repo, gate.DONE_STATE)["blocks"] == 1
    assert "NOT DONE" in stop(env, repo)[1]["systemMessage"]


def test_another_session_starts_its_own_count(env, repo, keys):
    _declare_order(repo, keys.public, max_blocks=1)
    _commit(repo, "the order")
    event = {"hook_event_name": "Stop", "session_id": "first", "cwd": str(repo), "stop_hook_active": False}
    blocked(stop(env, repo, event)[1])
    blocked(stop(env, repo, dict(event, session_id="second"))[1])


def test_the_done_files_are_not_part_of_the_working_state_and_a_link_is_not_followed(env, repo, keys, tmp_path):
    _declare_order(repo, keys.public, checks=(UNIT,))
    _commit(repo, "the order")
    outside = tmp_path / "outside.json"
    outside.write_text("unchanged")
    os.symlink(outside, repo / gate.DONE_METRICS)
    blocked(stop(env, repo)[1])
    assert outside.read_text() == "unchanged" and not (repo / gate.DONE_METRICS).is_symlink()
    _run(repo, keys.signer, UNIT)
    assert "done. 1 check (unit)" in stop(env, repo)[1]["systemMessage"]


def test_counters_need_no_network_and_name_each_open_kind(env, ordered, keys):
    _run(ordered, generate_signer(), UNIT)
    blocked(stop(env, ordered)[1])
    metrics = _done_file(ordered, gate.DONE_METRICS)
    assert metrics["open"] == {"unverified": 1, "missing": 1} and metrics["missing_checks"] == 1
    assert metrics["schema"] == "proofbundle-plugin/done-metrics/v0.1"


# --- TaskCompleted, Claude Code (D28, N3) ---------------------------------------------------------------------------

def task_completed(env: dict, cwd: pathlib.Path, event: dict | None = None) -> subprocess.CompletedProcess:
    event = {"hook_event_name": "TaskCompleted", "session_id": "s", "cwd": str(cwd), "task_id": "1",
             "task_subject": "finish"} if event is None else event
    return subprocess.run([sys.executable, "-I", str(GATE), "task-completed"], input=json.dumps(event),
                          capture_output=True, text=True, env=env, cwd=cwd, timeout=180, check=False)


def test_task_completed_keeps_the_task_open_with_the_same_line_and_lets_it_close_when_done(env, ordered, keys):
    proc = task_completed(env, ordered)
    assert proc.returncode == 0 and proc.stderr == ""
    assert proc.stdout.startswith("proofbundle done check: check unit is missing") and proc.stdout.count("\n") == 1
    _run(ordered, keys.signer, UNIT)
    _run(ordered, keys.signer, INTEGRATION)
    proc = task_completed(env, ordered)
    assert (proc.returncode, proc.stdout, proc.stderr) == (0, "", "")
    assert _done_file(ordered, gate.DONE_METRICS)["task_blocked"] == 1


def test_task_completed_without_a_done_check_and_on_a_wrong_event(env, repo):
    assert (task_completed(env, repo).returncode, task_completed(env, repo).stdout) == (0, "")
    proc = task_completed(env, repo, {"hook_event_name": "Stop", "cwd": str(repo)})
    assert proc.returncode == 0 and "not a TaskCompleted event" in proc.stdout


def test_the_task_completed_hook_wraps_the_check_and_blocks_when_it_cannot_run(env, ordered, tmp_path):
    (entry,) = json.loads((PLUGIN / "hooks" / "hooks.json").read_text())["hooks"]["TaskCompleted"]
    (hook,) = entry["hooks"]
    assert hook["type"] == "command" and "matcher" not in entry and " task-completed) || " in hook["command"]
    event = json.dumps({"hook_event_name": "TaskCompleted", "cwd": str(ordered), "session_id": "s"})
    real = subprocess.run(["sh", "-c", hook["command"]], input=event, capture_output=True, text=True,
                          env=dict(env, CLAUDE_PLUGIN_ROOT=str(PLUGIN)), cwd=ordered, timeout=180, check=False)
    assert real.returncode == 2 and real.stderr.startswith("proofbundle done check: check unit is missing")
    assert "could not run" not in real.stderr
    broken = subprocess.run(["sh", "-c", hook["command"]], input=event, capture_output=True, text=True,
                            env=dict(env, CLAUDE_PLUGIN_ROOT=str(tmp_path / "absent")), cwd=ordered, timeout=60,
                            check=False)
    assert broken.returncode == 2 and "the check could not run, so the task stays open" in broken.stderr
    _write(ordered / UNIT["receipt"], "{}")                         # the line is the gate's, whatever the receipt holds
    passed = subprocess.run(["sh", "-c", hook["command"]], input=event, capture_output=True, text=True,
                            env=dict(env, CLAUDE_PLUGIN_ROOT=str(PLUGIN)), cwd=ordered, timeout=180, check=False)
    assert passed.returncode == 2 and passed.stderr.count("\n") == 1


# --- one Stop hook for both hosts (D28) -----------------------------------------------------------

#: The fields Codex reads from a Stop hook's JSON (codex-rs/hooks/src/schema.rs, StopCommandOutputWire with the
#: universal fields, deny_unknown_fields; read in the source fetched 2026-09-30).
CODEX_STOP_FIELDS = {"continue", "stopReason", "suppressOutput", "systemMessage", "decision", "reason"}


def test_codex_runs_the_same_stop_hook_from_the_same_folder():
    manifest = json.loads((PLUGIN / ".codex-plugin" / "plugin.json").read_text())
    (entry,) = manifest["hooks"]["hooks"]["Stop"]
    (hook,) = entry["hooks"]
    assert hook["type"] == "command" and "matcher" not in entry
    assert hook["command"].startswith('python3 -I "${PLUGIN_ROOT}/hooks/proofbundle_gate.py" stop --host codex ||')
    assert "exit 2" in hook["command"]


def test_every_stop_answer_is_one_codex_reads_and_none_sets_continue(env, repo, keys):
    _declare_order(repo, keys.public, checks=(UNIT,), max_blocks=1)
    _commit(repo, "the order")
    event = {"hook_event_name": "Stop", "session_id": "s", "turn_id": "t", "cwd": str(repo), "stop_hook_active": False,
             "transcript_path": None, "model": "m", "permission_mode": "default", "last_assistant_message": None}
    answers = []
    for step in ("block", "blocker", "error", "pass"):
        if step == "error":
            proc = subprocess.run([sys.executable, "-I", str(GATE), "stop", "--host", "codex"], input="not json",
                                  capture_output=True, text=True, env=env, cwd=repo, timeout=180, check=False)
        else:
            if step == "pass":
                _run(repo, keys.signer, UNIT)
            proc = subprocess.run([sys.executable, "-I", str(GATE), "stop", "--host", "codex"],
                                  input=json.dumps(event), capture_output=True, text=True, env=env, cwd=repo,
                                  timeout=180, check=False)
        assert proc.returncode == 0
        answers.append(json.loads(proc.stdout))
    for answer in answers:
        assert set(answer) <= CODEX_STOP_FIELDS and "continue" not in answer
    assert [a.get("decision") for a in answers] == ["block", None, "block", None]
    assert "NOT DONE" in answers[1]["systemMessage"] and "done." in answers[3]["systemMessage"]


# --- done-check in CI with several receipts ------------------------------------------------------------------------

def test_done_check_reads_a_folder_of_receipts_for_an_order(env, ordered, keys, tmp_path):
    folder = tmp_path / "ci-receipts"
    for check in (UNIT, INTEGRATION):
        _receipt(ordered, keys.signer, out=folder / f"{check['id']}.json", selection=_selection(check))
    proc = _done_check(env, "--repo", str(ordered), "--receipt-dir", str(folder))
    assert proc.returncode == 0, proc.stderr
    proc = _done_check(env, "--repo", str(ordered), "--receipt", str(folder / "unit.json"))
    assert proc.returncode == 1 and "--receipt-dir" in json.loads(proc.stdout)["message"]
    assert _done_check(env, "--repo", str(ordered), "--receipt", "x", "--receipt-dir", "y").returncode == 2


# --- the done check as an in-toto Statement v1 in DSSE (D29) -------------------------------------

def _key_file(keys: Keys, tmp_path: pathlib.Path) -> pathlib.Path:
    from proofbundle.emit import save_signer
    path = tmp_path / "keys" / "done-test.key"                 # a test key, outside the repository
    path.parent.mkdir(exist_ok=True)
    save_signer(keys.signer, str(path))
    return path


def done_statement(env, repo, key, out, uri="git+https://example.org/owner/repo", *more):
    return subprocess.run([sys.executable, "-I", str(GATE), "done-statement", "--repo", str(repo), "--key", str(key),
                           "--out", str(out), "--resource-uri", uri, *more], capture_output=True, text=True, env=env,
                          timeout=180, check=False)


def test_a_passing_done_check_on_a_clean_state_writes_a_verification_summary(env, ordered, keys, tmp_path):
    for check in (UNIT, INTEGRATION):
        _run(ordered, keys.signer, check)
    out = tmp_path / "done.intoto.json"
    proc = done_statement(env, ordered, _key_file(keys, tmp_path), out)
    assert proc.returncode == 0, proc.stderr
    envelope = json.loads(out.read_text())
    assert envelope["payloadType"] == "application/vnd.in-toto+json" and len(envelope["signatures"]) == 1
    public = keys.signer.public_key().public_bytes_raw()
    assert envelope["signatures"][0]["keyid"] == __import__("hashlib").sha256(public).hexdigest()
    statement = json.loads(base64.b64decode(envelope["payload"]))
    assert statement["_type"] == "https://in-toto.io/Statement/v1"
    assert statement["predicateType"] == "https://slsa.dev/verification_summary/v1"
    assert statement["subject"] == [{"name": "git+https://example.org/owner/repo",
                                     "digest": {"gitCommit": _git(ordered, "rev-parse", "HEAD"),
                                                "gitTree": _git(ordered, "rev-parse", "HEAD^{tree}")}}]
    predicate = statement["predicate"]
    payloads = [base64.b64decode(json.loads((ordered / c["receipt"]).read_text())["payload_b64"])
                for c in (UNIT, INTEGRATION)]
    assert predicate["inputAttestations"] == [{"digest": {"sha256": __import__("hashlib").sha256(b).hexdigest()}}
                                              for b in payloads]
    assert predicate["verificationResult"] == "PASSED" and predicate["verifiedLevels"] == ["SLSA_SOURCE_LEVEL_UNEVALUATED"]
    assert predicate["policy"]["digest"]["sha256"] == __import__("hashlib").sha256((ordered / POLICY).read_bytes()).hexdigest()
    assert predicate["policy"]["digest"]["gitBlob"] == _git(ordered, "rev-parse", f"HEAD:{POLICY}")
    from proofbundle.dsse import pae
    keys.signer.public_key().verify(base64.b64decode(envelope["signatures"][0]["sig"]),
                                    pae(envelope["payloadType"], base64.b64decode(envelope["payload"])))


def test_no_statement_without_a_pass_on_a_clean_state(env, ordered, keys, tmp_path):
    key = _key_file(keys, tmp_path)
    out = tmp_path / "done.intoto.json"
    _run(ordered, keys.signer, UNIT)
    proc = done_statement(env, ordered, key, out)
    assert proc.returncode == 1 and "does not pass" in proc.stderr and not out.exists()
    _write(ordered / "src" / "module.py", "VALUE = 9\n")
    for check in (UNIT, INTEGRATION):
        _run(ordered, keys.signer, check)
    assert stop(env, ordered)[1].keys() == {"systemMessage"}                     # done on an uncommitted state
    proc = done_statement(env, ordered, key, out)
    assert proc.returncode == 1 and "differs from HEAD" in proc.stderr and not out.exists()


@pytest.mark.parametrize("uri", ["https://user:token@example.org/repo", "not a uri", "relative/path"])
def test_a_resource_uri_with_user_information_or_no_scheme_is_refused(env, ordered, keys, tmp_path, uri):
    proc = done_statement(env, ordered, _key_file(keys, tmp_path), tmp_path / "x.json", uri)
    assert proc.returncode == 1 and "--resource-uri must" in proc.stderr


def test_the_statement_is_not_written_through_a_link(env, ordered, keys, tmp_path):
    for check in (UNIT, INTEGRATION):
        _run(ordered, keys.signer, check)
    target = tmp_path / "elsewhere.json"
    target.write_text("unchanged")
    os.symlink(target, tmp_path / "link.json")
    proc = done_statement(env, ordered, _key_file(keys, tmp_path), tmp_path / "link.json")
    assert proc.returncode == 1 and "not a regular file" in proc.stderr and target.read_text() == "unchanged"


# --- a foreign reader of the statement (D29) -----------------------------------------------------

#: An interpreter with securesystemslib 1.5.1 and in-toto-attestation 0.9.3 (with protobuf 7.36.2), the versions
#: measured on 2026-10-08. The foreign reader runs only where the environment names it and is skipped otherwise,
#: never passed, as in tests/test_receipt_cose_foreign.py. securesystemslib verifies the DSSE signature with the test
#: key; in-toto-attestation reads and validates the Statement v1 and its predicate as a generic object. Its VSA v1
#: binding refuses the SLSA VSA v1.2 shape itself: it types verifiedLevels as one string where the specification has
#: an array, and has no verifier.version (measured, runs2/probe_map_vsa_mediatype.txt). The test holds that refusal,
#: so a release of the binding that reads the specification's shape turns it red on purpose.
FOREIGN_INTOTO = os.environ.get("PROOFBUNDLE_FOREIGN_INTOTO_PYTHON")

_FOREIGN_READER = r"""
import json, sys
from google.protobuf import json_format
from securesystemslib.dsse import Envelope
from securesystemslib.signer import SSlibKey
from in_toto_attestation.v1 import statement_pb2
from in_toto_attestation.v1.statement import Statement
from in_toto_attestation.predicates.vsa.v1 import vsa_pb2
import securesystemslib, in_toto_attestation, google.protobuf
with open(sys.argv[1]) as handle:
    envelope = Envelope.from_dict(json.load(handle))
key = SSlibKey(sys.argv[2], "ed25519", "ed25519", {"public": sys.argv[3]})
try:
    verified = sorted(envelope.verify([key], 1))
except Exception as exc:
    verified = "refused: " + type(exc).__name__
statement = json_format.Parse(envelope.payload, statement_pb2.Statement())
Statement.copy_from_pb(statement).validate()
predicate = json_format.MessageToDict(statement.predicate)
binding = {}
for mode, lenient in (("strict", False), ("ignore_unknown_fields", True)):
    try:
        json_format.ParseDict(predicate, vsa_pb2.VerificationSummary(), ignore_unknown_fields=lenient)
        binding[mode] = "read"
    except json_format.ParseError as exc:
        binding[mode] = "refused: " + str(exc).splitlines()[0]
print(json.dumps({"verified": verified, "payload_type": envelope.payload_type,
                  "subject": [dict(s.digest) for s in statement.subject], "predicate_type": statement.predicate_type,
                  "result": predicate["verificationResult"], "levels": predicate["verifiedLevels"],
                  "inputs": [i["digest"] for i in predicate["inputAttestations"]], "vsa_binding": binding,
                  "versions": {"securesystemslib": securesystemslib.__version__,
                               "protobuf": google.protobuf.__version__}}))
"""


@pytest.mark.skipif(not FOREIGN_INTOTO, reason="PROOFBUNDLE_FOREIGN_INTOTO_PYTHON names no foreign reader")
def test_securesystemslib_verifies_the_envelope_and_in_toto_attestation_reads_the_summary(env, ordered, keys,
                                                                                          tmp_path):
    for check in (UNIT, INTEGRATION):
        _run(ordered, keys.signer, check)
    out = tmp_path / "done.intoto.json"
    assert done_statement(env, ordered, _key_file(keys, tmp_path), out).returncode == 0
    public = keys.signer.public_key().public_bytes_raw()
    keyid = json.loads(out.read_text())["signatures"][0]["keyid"]
    clean = plugin_env(without=("PYTHONPATH", "PYTHONHOME"))

    def read(path: pathlib.Path, key_hex: str) -> dict:
        proc = subprocess.run([FOREIGN_INTOTO, "-I", "-c", _FOREIGN_READER, str(path), keyid, key_hex],
                              capture_output=True, text=True, env=clean, timeout=120, check=False)
        assert proc.returncode == 0, proc.stderr
        return json.loads(proc.stdout)

    seen = read(out, public.hex())
    assert seen["verified"] == [keyid] and seen["payload_type"] == "application/vnd.in-toto+json"
    assert seen["subject"] == [{"gitCommit": _git(ordered, "rev-parse", "HEAD"),
                                "gitTree": _git(ordered, "rev-parse", "HEAD^{tree}")}]
    assert seen["predicate_type"] == "https://slsa.dev/verification_summary/v1" and seen["result"] == "PASSED"
    assert len(seen["inputs"]) == 2 and seen["levels"] == ["SLSA_SOURCE_LEVEL_UNEVALUATED"]
    # protobuf reads a Struct's keys in no fixed order, so the strict refusal names whichever of the two fields the
    # binding lacks it meets first (both measured); with unknown fields ignored only the array type is left
    assert seen["vsa_binding"]["strict"].startswith(("refused: Failed to parse verifier field",
                                                     "refused: Failed to parse verifiedLevels field"))
    assert seen["vsa_binding"]["ignore_unknown_fields"].startswith("refused: Failed to parse verifiedLevels field")
    assert seen["versions"]["securesystemslib"] == "1.5.1"
    assert read(out, generate_signer().public_key().public_bytes_raw().hex())["verified"].startswith("refused")
    envelope = json.loads(out.read_text())
    changed = json.loads(base64.b64decode(envelope["payload"]))
    changed["predicate"]["verificationResult"] = "FAILED"
    envelope["payload"] = base64.b64encode(json.dumps(changed).encode()).decode()
    (tmp_path / "changed.json").write_text(json.dumps(envelope))
    assert read(tmp_path / "changed.json", public.hex())["verified"].startswith("refused")
