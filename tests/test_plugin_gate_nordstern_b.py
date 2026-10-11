"""Owner choice Nordstern B (2026-10-08): an order that names paths is done only with a change in those paths.

Measured in the real Claude Code run Lauf 1 of KARTEN-01 (2026-10-08): the agent changed nothing, ran both checks with
receipts, and the Stop hook said done, because the receipts named the unchanged state and no path outside the order
had changed. Now, where the order names paths, the done check also requires a change in them between the tree of the
commit that declared the order and the state the receipts are for: the working state at the end of a session (owner
choice K1 C), the tree of the pushed commit at a push. Without one, the end of the session blocks with the missing
work named (`no_change`) and a push is denied. An order without paths is as before. Where the declaring commit cannot
be determined (a shallow clone cut before it, too long a history), the check is NOT MEASURED, never a pass.

Counter-probes: no change, a change only outside the paths, a change in the paths, an order without paths, a shallow
clone; and that a later change to the declaration which leaves the order as it is does not move the base. Red against
31031eb6, where the unchanged state passed.
"""
from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys
import time

import pytest

import proofbundle
import test_plugin_done_check as dc

gate = dc.gate
GATE = dc.GATE
UNIT = dc.UNIT
pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")


@pytest.fixture(autouse=True)
def _clean_git_environment(monkeypatch):
    for key in [k for k in os.environ if k.startswith("GIT_")]:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", os.devnull)


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
    clean["CLAUDE_PLUGIN_DATA"] = clean["PLUGIN_DATA"] = str(tmp_path / "logs")
    return clean


@pytest.fixture
def keys(tmp_path: pathlib.Path) -> dc.Keys:
    return dc.Keys(tmp_path)


@pytest.fixture
def repo(tmp_path: pathlib.Path, keys: dc.Keys) -> pathlib.Path:
    """A repository whose second commit declares an order with one check and the paths src/*; main tracks a bare
    remote that holds that commit."""
    path = tmp_path / "repo"
    path.mkdir()
    dc._git(path, "init", "-q", "-b", "main")
    dc._write(path / "test_ok.py", "def test_ok():\n    assert True\n")
    dc._write(path / "src" / "module.py", "VALUE = 1\n")
    dc._write(path / "docs" / "notes.md", "notes\n")
    dc._write(path / ".gitignore", ".proofbundle/receipts/\n.proofbundle/done-state.json\n.proofbundle/done-metrics.json\n"
                                   ".proofbundle/done-blocker.json\n")
    dc._commit(path, "base")
    dc._declare_order(path, keys.public, checks=(UNIT,), paths=["src/*"])
    dc._commit(path, "the order")
    subprocess.run(["git", "init", "--bare", "-q", str(tmp_path / "remote.git")], check=True, timeout=60)
    dc._git(path, "remote", "add", "origin", str(tmp_path / "remote.git"))
    for rule in ("+refs/tags/*:refs/recorded/origin/tags/*", "+refs/refs/*:refs/recorded/origin/refs/*"):
        dc._git(path, "config", "--add", "remote.origin.fetch", rule)   # what git push also matches (R8-2)
    dc._git(path, "push", "-q", "-u", "origin", "main")
    return path


def _receipts(repo: pathlib.Path, keys: dc.Keys) -> None:
    dc._run(repo, keys.signer, UNIT)


def _evaluate(repo: pathlib.Path, at_commit: str | None = None) -> dict:
    return gate.done_evaluation(str(repo), time.monotonic() + 120, at_commit=at_commit)


def _first_open(result: dict) -> str:
    return result["open"][0]["status"] if result["open"] else ""


# --- the end of a session (the working state, K1 C) -------------------------------------------------------------

def test_no_change_blocks_with_the_missing_work_named(env, repo, keys):
    _receipts(repo, keys)
    reason = dc.blocked(dc.stop(env, repo)[1])
    base = dc._git(repo, "rev-parse", "HEAD")
    assert "check paths is no change: nothing in the paths the order names (src/*) changed" in reason
    assert f"since {base[:12]}, the commit that declared the order, so the work the order asks for is missing" in reason
    assert "Next: do the work the order asks for in src/*, then run the checks again." in reason
    assert _evaluate(repo)["verdict"].reason_id == "no_change"


def test_a_change_only_outside_the_paths_blocks_as_missing_work_and_outside(env, repo, keys):
    dc._write(repo / "docs" / "notes.md", "other notes\n")
    _receipts(repo, keys)
    reason = dc.blocked(dc.stop(env, repo)[1])
    assert "check paths is no change" in reason and "also open: paths (outside paths)" in reason
    result = _evaluate(repo)
    assert [p["status"] for p in result["open"]] == ["no_change", "outside_paths"]
    assert result["open"][1]["outside"] == ["docs/notes.md"]


def test_a_change_in_the_paths_passes_committed_or_not(env, repo, keys):
    dc._write(repo / "src" / "module.py", "VALUE = 2\n")         # uncommitted: the working state counts (K1 C)
    _receipts(repo, keys)
    code, answer, _ = dc.stop(env, repo)
    assert code == 0 and set(answer) == {"systemMessage"}, answer
    base = dc._git(repo, "rev-parse", "HEAD")
    assert f"no path outside the order changed since {base[:12]}, the commit that declared it, and 1 path in it did" \
        in answer["systemMessage"]
    dc._commit(repo, "the work")
    _receipts(repo, keys)
    assert dc.stop(env, repo)[0] == 0 and _evaluate(repo)["verdict"].decision == "pass"


def test_missing_work_comes_before_missing_receipts(env, repo):
    result = _evaluate(repo)
    assert [p["status"] for p in result["open"]] == ["no_change", "missing"]


def test_an_order_without_paths_is_as_before(env, tmp_path, keys):
    path = tmp_path / "plain"
    path.mkdir()
    dc._git(path, "init", "-q", "-b", "main")
    dc._write(path / "test_ok.py", "def test_ok():\n    assert True\n")
    dc._declare_order(path, keys.public, checks=(UNIT,))
    dc._commit(path, "an order without paths")
    dc._run(path, keys.signer, UNIT)
    code, answer, _ = dc.stop(env, path)
    assert code == 0 and "done. 1 check (unit)" in answer["systemMessage"], answer
    assert "the commit that declared" not in answer["systemMessage"]


# --- which commit declared the order ----------------------------------------------------------------------------

def test_a_later_change_of_the_declaration_that_keeps_the_order_does_not_move_the_base(repo, keys):
    declared = dc._git(repo, "rev-parse", "HEAD")
    dc._write(repo / "src" / "module.py", "VALUE = 2\n")
    dc._commit(repo, "the work")
    doc = json.loads((repo / gate.DECLARATION).read_text(encoding="utf-8"))
    doc["evidence"] = []                                          # rewritten, the done section kept as it is
    (repo / gate.DECLARATION).write_text(json.dumps(doc, indent=2), encoding="utf-8")
    dc._commit(repo, "rewrite the declaration, same order")
    done = gate.parse_done((repo / gate.DECLARATION).read_bytes())
    assert gate.order_base(str(repo), dc._git(repo, "rev-parse", "HEAD"), done, time.monotonic() + 60) == (declared, "")


def test_a_new_order_moves_the_base(repo, keys):
    dc._write(repo / "src" / "module.py", "VALUE = 2\n")
    dc._commit(repo, "the work")
    dc._declare_order(repo, keys.public, checks=(UNIT,), paths=["src/*", "docs/*"])
    dc._commit(repo, "a new order")
    head = dc._git(repo, "rev-parse", "HEAD")
    done = gate.parse_done((repo / gate.DECLARATION).read_bytes())
    assert gate.order_base(str(repo), head, done, time.monotonic() + 60) == (head, "")
    _receipts(repo, keys)
    assert _first_open(_evaluate(repo)) == "no_change", "the work before the new order does not count for it"


def test_an_order_declared_in_the_root_commit_has_that_commit_as_its_base(tmp_path, keys):
    path = tmp_path / "root"
    path.mkdir()
    dc._git(path, "init", "-q", "-b", "main")
    dc._write(path / "src" / "module.py", "VALUE = 1\n")
    dc._declare_order(path, keys.public, checks=(UNIT,), paths=["src/*"])
    dc._commit(path, "root with the order")
    head = dc._git(path, "rev-parse", "HEAD")
    done = gate.parse_done((path / gate.DECLARATION).read_bytes())
    assert gate.order_base(str(path), head, done, time.monotonic() + 60) == (head, "")


def test_in_a_shallow_clone_cut_before_the_order_the_check_is_not_measured(env, tmp_path, repo, keys):
    dc._write(repo / "src" / "module.py", "VALUE = 2\n")
    dc._commit(repo, "the work")
    dc._git(repo, "push", "-q", "origin", "main")
    shallow = tmp_path / "shallow"
    subprocess.run(["git", "clone", "-q", "-b", "main", "--depth", "1", f"file://{tmp_path / 'remote.git'}", str(shallow)],
                   check=True, capture_output=True, timeout=60)
    dc._run(shallow, keys.signer, UNIT)
    result = _evaluate(shallow)
    assert result["verdict"].decision == "deny" and result["verdict"].reason_id == "order_base_not_measured"
    assert result["verdict"].detail.startswith("NOT MEASURED: the history is cut at")
    reason = dc.blocked(dc.stop(env, shallow)[1])
    assert "a shallow clone" in reason and "git fetch --unshallow" in reason


def test_in_a_shallow_clone_deep_enough_the_base_is_found(tmp_path, repo, keys):
    dc._write(repo / "src" / "module.py", "VALUE = 2\n")
    dc._commit(repo, "the work")
    dc._git(repo, "push", "-q", "origin", "main")
    shallow = tmp_path / "deep"
    subprocess.run(["git", "clone", "-q", "-b", "main", "--depth", "3", f"file://{tmp_path / 'remote.git'}", str(shallow)],
                   check=True, capture_output=True, timeout=60)
    dc._run(shallow, keys.signer, UNIT)
    assert _evaluate(shallow)["verdict"].decision == "pass"


def test_past_the_walk_limit_the_check_is_not_measured(repo, keys, monkeypatch):
    for n in range(3):
        doc = json.loads((repo / gate.DECLARATION).read_text(encoding="utf-8"))
        (repo / gate.DECLARATION).write_text(json.dumps(doc, indent=n + 1), encoding="utf-8")
        dc._commit(repo, f"rewrite {n}")
    monkeypatch.setattr(gate, "MAX_ORDER_WALK", 2)
    done = gate.parse_done((repo / gate.DECLARATION).read_bytes())
    base, why = gate.order_base(str(repo), dc._git(repo, "rev-parse", "HEAD"), done, time.monotonic() + 60)
    assert base is None and "more than 2 commits changed" in why


# --- a push: the tree of the pushed commit ---------------------------------------------------------------------

def _level2(env: dict, repo: pathlib.Path) -> subprocess.CompletedProcess:
    line = f"refs/heads/main {dc._git(repo, 'rev-parse', 'HEAD')} refs/heads/main {dc._git(repo, 'rev-parse', 'origin/main')}\n"
    return subprocess.run([sys.executable, "-I", str(GATE), "pre-push", "origin", "remote.git"], input=line,
                          capture_output=True, text=True, cwd=str(repo), env=env, timeout=180, check=False)


def _level1(env: dict, repo: pathlib.Path) -> dict:
    event = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(repo),
                        "tool_input": {"command": "git push origin main"}})
    proc = subprocess.run([sys.executable, "-I", str(GATE)], input=event, capture_output=True, text=True, env=env,
                          timeout=180, check=False)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def test_a_push_of_a_commit_without_a_change_in_the_paths_is_denied_at_both_levels(env, repo, keys):
    dc._write(repo / "docs" / "notes.md", "other notes\n")
    dc._commit(repo, "only notes")
    _receipts(repo, keys)
    answer = _level1(env, repo)
    assert answer["hookSpecificOutput"]["permissionDecision"] == "deny", answer
    assert "no change" in answer["systemMessage"] and "the tree the push sends" in answer["systemMessage"]
    proc = _level2(env, repo)
    assert proc.returncode == 1 and "no change" in proc.stderr, proc.stderr


def test_a_push_of_a_commit_with_the_work_passes_at_both_levels(env, repo, keys):
    """Level 2 passes the push of the work. Level 1 does not deny it: the done check at the sent commit showed no
    failure, and since R9-1 the push asks at the destination check."""
    dc._write(repo / "src" / "module.py", "VALUE = 2\n")
    dc._commit(repo, "the work")
    _receipts(repo, keys)
    answer = _level1(env, repo)
    assert answer["hookSpecificOutput"].get("permissionDecision") == "ask", answer
    assert "git push also matches" in answer["systemMessage"] and "showed no failure" in answer["systemMessage"]
    assert _level2(env, repo).returncode == 0


def test_an_uncommitted_change_does_not_count_for_the_push(env, repo, keys):
    dc._write(repo / "docs" / "notes.md", "other notes\n")
    dc._commit(repo, "only notes")
    dc._write(repo / "src" / "module.py", "VALUE = 2\n")         # the work, not committed
    head = dc._git(repo, "rev-parse", "HEAD")
    assert _first_open(_evaluate(repo, at_commit=head)) == "no_change"
