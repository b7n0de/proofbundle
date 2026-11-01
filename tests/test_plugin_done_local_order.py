"""D38: a done order outside the work tree, judged for every repository it names.

Account A's pilot at 35214a8c (finding 20261015T1725Z) measured two gaps. Stop and TaskCompleted judged only the repository
of the hook's cwd, so a session working in a clone with `git -C <clone>` from a fixed directory never had the clone's
order checked. And an order kept only in the work tree (variant E: `.proofbundle/` in `.git/info/exclude`) blocked every
end, a valid receipt included, while a committed order (variant C) put `.proofbundle/` into the pull request.

Properties: a local order, made with `done-order` into the gate directory, holds the whole order outside the work tree;
Stop and TaskCompleted judge every repository with a local order, whatever the cwd; an order that changed after the
gate first read it blocks; the committed order of D28 stays as it is; no order, no intervention.

RED at 14a5feb1 for the local order (variant E), the end judged from outside the clone and the changed order; the
controls (variant C, no order) are green there and after. Each case runs the gate as the host starts it.
"""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys

import pytest

import test_plugin_done_check as d
from _gate_answer import parsed, run_hook
from _owner_state import owner_state_protected  # noqa: F401 - D128: a person's local done order is read

pytestmark = d.pytestmark
_clean_git_config = d._clean_git_config
env, repo, keys, declared = d.env, d.repo, d.keys, d.declared
gate, GATE = d.gate, d.GATE


def _done_order(env: dict, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-I", str(GATE), "done-order", *args], capture_output=True, text=True,
                          env=env, timeout=180, check=False)


def _variant_e(repo: pathlib.Path, public: str) -> None:
    """Account A's variant E: the declaration and the policy only in the work tree, `.proofbundle/` excluded locally."""
    with open(repo / ".git" / "info" / "exclude", "a", encoding="utf-8") as handle:
        handle.write("/.proofbundle/\n")
    d._declare_done(repo, public)


def _local_order(env: dict, repo: pathlib.Path, public: str) -> pathlib.Path:
    _variant_e(repo, public)
    made = _done_order(env, "--repo", str(repo))
    assert made.returncode == 0, made.stderr
    (order,) = (pathlib.Path(env["PROOFBUNDLE_GATE_DIR"]) / gate.DONE_ORDERS_DIR).glob("*[0-9a-f].json")
    return order


def _stop(env: dict, cwd: pathlib.Path, host: str = "claude") -> dict | None:
    event = {"hook_event_name": "Stop", "session_id": "s", "cwd": str(cwd), "stop_hook_active": False}
    args = [] if host == "claude" else ["--host", host]
    proc, entry = run_hook([sys.executable, "-I", str(GATE), "stop", *args], json.dumps(event), env, cwd=cwd,
                           timeout=180)
    assert proc.returncode == 0, proc.stderr
    return parsed(proc, entry)   # D53: Silent for a passed end, with its log line


def _session_dir(tmp_path: pathlib.Path) -> pathlib.Path:
    """The fixed directory a session runs from, outside the clone and outside any repository."""
    path = tmp_path / "session"
    path.mkdir(exist_ok=True)
    return path


def test_D38_variant_E_a_local_order_ends_with_a_valid_receipt_and_blocks_without(env, repo, keys):
    _local_order(env, repo, keys.public)
    reason = d.blocked(_stop(env, repo))
    assert "check tests is missing" in reason and "declaration is not committed" not in reason, reason
    d._receipt(repo, keys.signer)
    answer = _stop(env, repo)
    assert answer is not None and "decision" not in answer, answer
    assert d.done_end(answer), answer
    assert d._git(repo, "status", "--porcelain", "--ignored=no") == "", "nothing of the order is in the work tree"


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_D38_stop_from_a_directory_outside_the_clone_blocks_on_its_open_order(env, repo, keys, tmp_path, host):
    order = _local_order(env, repo, keys.public)
    session = _session_dir(tmp_path)
    reason = d.blocked(_stop(env, session, host))
    # D49 as sharpened by follow-up note 21: the order by its name, never the root it records
    assert f"the local done order {order.name[:12]}: check tests is missing" in reason, reason
    assert str(repo.resolve()) not in reason, reason
    d._receipt(repo, keys.signer)
    answer = _stop(env, session, host)
    assert d.done_end(answer), answer


def test_D38_task_completed_from_outside_the_clone_keeps_the_task_open(env, repo, keys, tmp_path):
    _local_order(env, repo, keys.public)
    proc = d.task_completed(env, _session_dir(tmp_path))
    assert proc.returncode == 0 and proc.stdout.startswith("proofbundle done check: the local done order "), proc
    d._receipt(repo, keys.signer)
    proc = d.task_completed(env, _session_dir(tmp_path))
    assert (proc.returncode, proc.stdout) == (0, ""), proc


def test_D38_an_order_changed_after_the_first_read_blocks(env, repo, keys, tmp_path):
    order = _local_order(env, repo, keys.public)
    d._receipt(repo, keys.signer)
    assert d.done_end(_stop(env, repo)), "the order as written ends the session"
    doc = json.loads(order.read_text(encoding="utf-8"))
    doc["done"]["receipt"] = ".proofbundle/other_receipt.json"
    order.write_text(json.dumps(doc), encoding="utf-8")
    for cwd in (repo, _session_dir(tmp_path)):
        reason = d.blocked(_stop(env, cwd))
        assert "changed after the gate first read it" in reason, reason


def test_D38_sibling_an_order_removed_or_without_the_gates_record_blocks(env, repo, keys, tmp_path):
    order = _local_order(env, repo, keys.public)
    d._receipt(repo, keys.signer)
    seen = order.with_name(order.name.replace(".json", ".seen.json"))
    record = seen.read_bytes()
    seen.unlink()
    assert "the gate has no record of its digest" in d.blocked(_stop(env, _session_dir(tmp_path)))
    seen.write_bytes(record)
    order.unlink()
    assert "the order is not" in d.blocked(_stop(env, _session_dir(tmp_path)))


def test_D38_an_order_whose_clone_is_gone_blocks_until_a_person_removes_it(env, repo, keys, tmp_path):
    _local_order(env, repo, keys.public)
    moved = repo.with_name("moved")
    repo.rename(moved)
    reason = d.blocked(_stop(env, _session_dir(tmp_path)))
    assert "git does not find the repository it names" in reason, reason
    removed = _done_order(env, "--remove", "--repo", str(repo))
    assert removed.returncode == 0, removed.stderr
    assert _stop(env, _session_dir(tmp_path)) is None


def test_D38_an_order_entirely_outside_the_work_tree_keeps_the_receipts_out_of_commits(env, repo, keys, tmp_path):
    """Property 1: the declaration and the policy lie outside the clone; the order keeps nothing in it, and the receipt
    and the hook's own files are excluded locally, so `git add -A` takes none of them."""
    outside = tmp_path / "order-source"
    d._declare_done(outside, keys.public)
    made = _done_order(env, "--repo", str(repo), "--declaration", str(outside / gate.DECLARATION),
                       "--policy", str(outside / gate.DONE_POLICY))
    assert made.returncode == 0 and "info/exclude" in made.stdout, made
    d.blocked(_stop(env, _session_dir(tmp_path)))
    d._receipt(repo, keys.signer)
    assert d.done_end(_stop(env, _session_dir(tmp_path)))
    d._git(repo, "add", "-A")
    assert d._git(repo, "diff", "--cached", "--name-only") == "", "no file of the order reaches a commit"


def test_D38_a_committed_order_and_a_local_order_of_one_repository_both_count(env, declared, keys, tmp_path):
    outside = tmp_path / "order-source"
    d._declare_done(outside, keys.public)
    made = _done_order(env, "--repo", str(declared), "--declaration", str(outside / gate.DECLARATION),
                       "--policy", str(outside / gate.DONE_POLICY))
    assert made.returncode == 0 and made.stdout.startswith("wrote the local done order"), made
    d.blocked(_stop(env, declared))
    d._receipt(declared, keys.signer)
    assert d.done_end(_stop(env, declared))


def test_D38_an_existing_order_is_replaced_only_on_request_and_the_replacement_is_recorded(env, repo, keys):
    order = _local_order(env, repo, keys.public)
    again = _done_order(env, "--repo", str(repo))
    assert again.returncode == 1 and "--replace" in again.stderr
    replaced = _done_order(env, "--repo", str(repo), "--replace")
    assert replaced.returncode == 0 and "replacement" in replaced.stdout, replaced
    seen = json.loads(order.with_name(order.name.replace(".json", ".seen.json")).read_text(encoding="utf-8"))
    assert len(seen["replaced"]) == 1


# --- controls, green before and after -------------------------------------------------------------------------------

def test_D38_control_variant_C_the_committed_order_works_as_before(env, declared, keys):
    reason = d.blocked(_stop(env, declared))
    assert "check tests is missing" in reason
    d._receipt(declared, keys.signer)
    answer = _stop(env, declared)
    assert d.done_end(answer), answer


def test_D38_control_variant_E_without_a_local_order_still_blocks_as_uncommitted(env, repo, keys):
    _variant_e(repo, keys.public)
    d._receipt(repo, keys.signer)
    assert "declaration is not committed" in d.blocked(_stop(env, repo))


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_D38_control_without_any_order_the_end_is_not_touched(env, repo, tmp_path, host):
    assert _stop(env, repo, host) is None
    assert _stop(env, _session_dir(tmp_path), host) is None
    assert d.task_completed(env, _session_dir(tmp_path)).stdout == ""
