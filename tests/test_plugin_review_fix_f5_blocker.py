"""Review of 2026-10-09, F5: the blocker names every open point of the last verdict.

Measured by the reviewer at 91a52faa, and in the host runs codex_run_nochange (2026-10-08, KARTEN-02) and
codex_sandbox-nochange (KARTEN-03): the agent changed nothing in the order's paths, both checks were green, and the
blocker written after three blocks listed only the checks, all verified, and `outside_paths: []`. The one open point,
no_change, was not in it, nor were the paths the order names or the commit it was compared with. And where no_change
came first, the paths outside the order were lost too, because the blocker read the first `paths` point only.

Now the blocker carries `open`, every open point in the verdict's order with its status, what it found, the command
that closes it and, for outside_paths, the paths; `paths`, the order's patterns; and `order_base`, the commit that
declared the order. `checks` and `outside_paths` stay. Red against 91a52faa.
"""
from __future__ import annotations

import json
import pathlib
import shutil

import pytest

import test_plugin_done_check as dc
import test_plugin_gate_nordstern_b as nb

gate = dc.gate
UNIT = dc.UNIT
INTEGRATION = dc.INTEGRATION
pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
env = nb.env
keys = nb.keys
_clean_git_environment = nb._clean_git_environment


@pytest.fixture
def repo(tmp_path: pathlib.Path, keys) -> pathlib.Path:
    """An order with the check unit, the paths src/* and max_blocks 1, declared in the second commit."""
    path = tmp_path / "repo"
    path.mkdir()
    dc._git(path, "init", "-q", "-b", "main")
    dc._write(path / "test_ok.py", "def test_ok():\n    assert True\n")
    dc._write(path / "src" / "module.py", "VALUE = 1\n")
    dc._write(path / "docs" / "notes.md", "notes\n")
    dc._write(path / ".gitignore", ".proofbundle/receipts/\n.proofbundle/done-state.json\n.proofbundle/done-metrics.json\n"
                                   ".proofbundle/done-blocker.json\n")
    dc._commit(path, "base")
    dc._declare_order(path, keys.public, checks=(UNIT,), paths=["src/*"], max_blocks=1)
    dc._commit(path, "the order")
    return path


def _blocker_after_the_limit(env: dict, repo: pathlib.Path) -> dict:
    dc.blocked(dc.stop(env, repo)[1])
    code, answer, _ = dc.stop(env, repo)
    assert code == 0 and set(answer) == {"systemMessage"} and "NOT DONE" in answer["systemMessage"], answer
    return json.loads((repo / gate.DONE_BLOCKER).read_text(encoding="utf-8"))


def test_the_blocker_names_a_missing_change_and_the_paths_outside_together(env, repo, keys):
    """The reviewer's case: green checks, nothing changed in src/*, a change in docs/. Red at 91a52faa: the blocker
    named neither no_change nor docs/notes.md."""
    dc._write(repo / "docs" / "notes.md", "other notes\n")
    dc._run(repo, keys.signer, UNIT)
    blocker = _blocker_after_the_limit(env, repo)
    base = dc._git(repo, "rev-parse", "HEAD")
    assert [(p["id"], p["status"]) for p in blocker["open"]] == [("paths", "no_change"), ("paths", "outside_paths")]
    no_change, outside = blocker["open"]
    assert "nothing in the paths the order names (src/*) changed" in no_change["detail"]
    assert no_change["command"] == "do the work the order asks for in src/*, then run the checks again"
    assert outside["outside"] == ["docs/notes.md"] and "docs/notes.md" in outside["detail"]
    assert blocker["outside_paths"] == ["docs/notes.md"]
    assert blocker["paths"] == ["src/*"] and blocker["order_base"] == base
    assert [(c["id"], c["status"]) for c in blocker["checks"]] == [("unit", "green")]


def test_the_blocker_names_a_missing_change_alone(env, repo, keys):
    """The host runs' case: green checks and no change anywhere. Red at 91a52faa: the blocker read as if all were
    verified."""
    dc._run(repo, keys.signer, UNIT)
    blocker = _blocker_after_the_limit(env, repo)
    assert [(p["id"], p["status"]) for p in blocker["open"]] == [("paths", "no_change")]
    assert blocker["outside_paths"] == []


def test_the_blocker_names_open_checks_after_the_paths(env, repo):
    blocker = _blocker_after_the_limit(env, repo)
    assert [(p["id"], p["status"]) for p in blocker["open"]] == [("paths", "no_change"), ("unit", "missing")]
    assert "python -m pytest tests/unit" in blocker["open"][1]["command"]


def test_an_order_without_paths_names_its_checks_and_no_paths(env, tmp_path, keys):
    path = tmp_path / "plain"
    path.mkdir()
    dc._git(path, "init", "-q", "-b", "main")
    dc._declare_order(path, keys.public, checks=(UNIT, INTEGRATION), max_blocks=1)
    dc._commit(path, "an order without paths")
    dc._run(path, keys.signer, UNIT)
    blocker = _blocker_after_the_limit(env, path)
    assert [(p["id"], p["status"]) for p in blocker["open"]] == [("integration", "missing")]
    assert (blocker["paths"], blocker["order_base"], blocker["outside_paths"]) == (None, None, [])

