"""Review of 2026-10-09, F6: every refusal of the done check counts toward max_blocks, also one that comes early.

Measured by the reviewer at 91a52faa: order_base_not_measured returned before the check named its open points, and
the Stop hook counted a block only where open points were named, so a shallow clone blocked at every stop and never
reached the blocker. The class: every early return that refuses without structured open points, and a check that
fails. Now each refusal is the one open point of its result (`declaration`, `policy`, `state`, `paths`), a failure of
the check (`gate_error`, `internal_error`) is the open point `done-check` of the result it had reached, and the Stop
hook counts every deny that names a repository: after max_blocks blocks without progress the blocker is written and
the session ends without a done verdict. Where no order could be read, the default limit (3) applies.

Counter-probes, under Claude Code and Codex: a shallow clone cut before the order, a working tree that cannot be read
as files, a missing policy, an uncommitted declaration, a malformed done section, a policy that pins no signer; and
that removing the cause lets the check go on as before. Red against 91a52faa.
"""
from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys

import pytest

import test_plugin_done_check as dc
import test_plugin_gate_nordstern_b as nb
from _gate_answer import parsed, run_hook

gate = dc.gate
UNIT = dc.UNIT
pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
env = nb.env
keys = nb.keys
_clean_git_environment = nb._clean_git_environment

IGNORE = ".proofbundle/receipts/\n.proofbundle/done-state.json\n.proofbundle/done-metrics.json\n.proofbundle/done-blocker.json\n"


def stop(env: dict, cwd: pathlib.Path, host: str = "claude") -> dict | None:
    event = {"hook_event_name": "Stop", "session_id": "s", "cwd": str(cwd), "stop_hook_active": False}
    argv = [sys.executable, "-I", str(dc.GATE), "stop"] + (["--host", "codex"] if host == "codex" else [])
    proc, entry = run_hook(argv, json.dumps(event), env, cwd=cwd, timeout=180)
    assert proc.returncode == 0, proc.stderr
    return parsed(proc, entry)   # D53: Silent for a passed end, with its log line


def ends_in_the_blocker(env: dict, repo: pathlib.Path, limit: int, status: str, host: str = "claude") -> dict:
    """`limit` blocks, then the blocker: the session ends NOT DONE and the blocker names `status`."""
    for _ in range(limit):
        answer = stop(env, repo, host)
        assert answer is not None and answer.get("decision") == "block", answer
    answer = stop(env, repo, host)
    assert answer is not None and set(answer) == {"systemMessage"}, answer
    assert answer["systemMessage"].startswith(f"proofbundle done check: NOT DONE. The same open points stayed open "
                                              f"through {limit} blocks"), answer
    blocker = json.loads((repo / gate.DONE_BLOCKER).read_text(encoding="utf-8"))
    assert [p["status"] for p in blocker["open"]] == [status], blocker["open"]
    again = stop(env, repo, host)
    assert again is not None and set(again) == {"systemMessage"}, again  # it stays ended, not blocked again
    return blocker


def _repo(tmp_path: pathlib.Path, name: str = "repo") -> pathlib.Path:
    path = tmp_path / name
    path.mkdir()
    dc._git(path, "init", "-q", "-b", "main")
    dc._write(path / "test_ok.py", "def test_ok():\n    assert True\n")
    dc._write(path / "src" / "module.py", "VALUE = 1\n")
    dc._write(path / ".gitignore", IGNORE)
    dc._commit(path, "base")
    return path


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_a_shallow_clone_cut_before_the_order_ends_in_the_blocker(env, tmp_path, keys, host):
    """The reviewer's case. Red at 91a52faa: it blocked at every stop."""
    source = _repo(tmp_path, "source")
    dc._declare_order(source, keys.public, checks=(UNIT,), paths=["src/*"], max_blocks=2)
    dc._commit(source, "the order")
    dc._write(source / "src" / "module.py", "VALUE = 2\n")
    dc._commit(source, "the work")
    shallow = tmp_path / "shallow"
    subprocess.run(["git", "clone", "-q", "--depth", "1", f"file://{source}", str(shallow)], check=True,
                   capture_output=True, timeout=60)
    dc._run(shallow, keys.signer, UNIT)
    blocker = ends_in_the_blocker(env, shallow, 2, "order_base_not_measured", host)
    assert blocker["paths"] == ["src/*"] and blocker["order_base"] is None
    assert "git fetch --unshallow" in blocker["open"][0]["command"]


def test_a_working_tree_that_cannot_be_read_as_files_ends_in_the_blocker(env, tmp_path, keys):
    repo = _repo(tmp_path)
    dc._declare_order(repo, keys.public, checks=(UNIT,), paths=["src/*"], max_blocks=1)
    dc._commit(repo, "the order")
    (repo / "src" / "module.py").unlink()
    os.mkfifo(repo / "src" / "module.py")
    blocker = ends_in_the_blocker(env, repo, 1, "state_not_measured")
    assert "neither a regular file nor a link" in blocker["open"][0]["detail"]


def test_a_missing_policy_ends_in_the_blocker(env, tmp_path, keys):
    repo = _repo(tmp_path)
    dc._declare_order(repo, keys.public, checks=(UNIT,), max_blocks=1)
    (repo / dc.POLICY).unlink()
    dc._commit(repo, "an order without its policy")
    blocker = ends_in_the_blocker(env, repo, 1, "missing_file")
    assert blocker["open"][0]["id"] == "policy"


def test_an_uncommitted_declaration_ends_in_the_blocker_after_the_default_limit(env, tmp_path, keys):
    repo = _repo(tmp_path)
    dc._declare_order(repo, keys.public, checks=(UNIT,), max_blocks=1)   # not committed: its limit is not read
    blocker = ends_in_the_blocker(env, repo, gate.DEFAULT_MAX_BLOCKS, "declaration_not_committed")
    assert blocker["open"][0]["command"] == f"commit {gate.DECLARATION}"


def test_a_malformed_done_section_ends_in_the_blocker_after_the_default_limit(env, tmp_path, keys):
    repo = _repo(tmp_path)
    dc._write(repo / gate.DECLARATION, {"schema": gate.DECLARATION_SCHEMA, "evidence": [],
                                        "done": {"policy": dc.POLICY, "checks": [], "max_blocks": 1}})
    dc._commit(repo, "a malformed order")
    blocker = ends_in_the_blocker(env, repo, gate.DEFAULT_MAX_BLOCKS, "gate_error")
    assert blocker["open"][0]["id"] == "done-check"


def test_a_policy_that_pins_no_signer_ends_in_the_blocker_after_the_orders_limit(env, tmp_path, keys):
    repo = _repo(tmp_path)
    dc._declare_order(repo, keys.public, checks=(UNIT,), max_blocks=1)
    dc._write(repo / dc.POLICY, {"schema": "proofbundle/trust-policy/v0.1", "policy_id": "open",
                                 "allowed_issuers": [], "signature": {"require_expected_signer": False}})
    dc._commit(repo, "an order whose policy pins no signer")
    dc._run(repo, keys.signer, UNIT)
    blocker = ends_in_the_blocker(env, repo, 1, "gate_error")
    assert "does not pin a signer" in blocker["open"][0]["detail"]


def test_removing_the_cause_lets_the_check_go_on(env, tmp_path, keys):
    """After a blocker for a missing policy, committing the policy and running the check ends in done; the blocker is
    removed, as after any other block."""
    repo = _repo(tmp_path)
    dc._declare_order(repo, keys.public, checks=(UNIT,), max_blocks=1)
    policy = (repo / dc.POLICY).read_text(encoding="utf-8")
    (repo / dc.POLICY).unlink()
    dc._commit(repo, "an order without its policy")
    ends_in_the_blocker(env, repo, 1, "missing_file")
    dc._write(repo / dc.POLICY, policy)
    dc._commit(repo, "the policy")
    dc._run(repo, keys.signer, UNIT)
    answer = stop(env, repo)
    assert dc.done_end(answer) and "done. 1 check (unit)" in dc.done_message(env, repo), answer
    assert not (repo / gate.DONE_BLOCKER).exists()


def test_a_failure_before_the_repository_is_known_still_blocks(env, tmp_path):
    """Input that is not a Stop event names no repository: the hook blocks and counts nothing."""
    proc = subprocess.run([sys.executable, "-I", str(dc.GATE), "stop"], input="not json", capture_output=True,
                          text=True, env=env, cwd=tmp_path, timeout=60, check=False)
    answer = json.loads(proc.stdout)
    assert proc.returncode == 0 and answer["decision"] == "block"
