"""Review of 2026-10-09, F4: the done job checks out the commit under review with its whole history.

Measured by the reviewer at 91a52faa: the checkout `checked` of the job done had no fetch-depth, so
actions/checkout fetched one commit, and an order that names paths, whose base is the commit that declared it,
ended in order_base_not_measured. Now the checkout fetches the whole history (fetch-depth: 0), as the gate checkout
already does.

actions/checkout itself is not run here. The counter-probe makes the two checkouts it makes with git: one commit
fetched (`--depth 1`, what the template did) and the whole history (what fetch-depth: 0 does), and runs the job's two
steps on each (tests/test_plugin_review_fix_f1_ci_commit.py). The shallow one is NOT MEASURED, the full one passes;
the template assertion is red against 91a52faa.
"""
from __future__ import annotations

import subprocess

import pytest

import test_plugin_done_check as dc
import test_plugin_review_fix_f1_ci_commit as f1

UNIT = {"id": "unit", "args": ["tests/unit"], "receipt": ".proofbundle/receipts/unit.json"}
COMMAND = 'PROOFBUNDLE_OUT="${PROOFBUNDLE_RECEIPT_DIR:?}/unit.json" python "$EMIT" tests/unit'

pytestmark = f1.pytestmark
keys = f1.keys
_clean_git_environment = f1._clean_git_environment


@pytest.fixture
def source(tmp_path, keys):
    """A repository whose first commit declares an order with the paths src/* and whose second commit does the work."""
    path = tmp_path / "source"
    path.mkdir()
    dc._git(path, "init", "-q", "-b", "main")
    dc._write(path / "tests" / "unit" / "test_a.py", "def test_a():\n    assert True\n")
    dc._write(path / "src" / "module.py", "VALUE = 1\n")
    dc._declare_order(path, keys.public, checks=(UNIT,), paths=["src/*"])
    dc._commit(path, "the order")
    dc._write(path / "src" / "module.py", "VALUE = 2\n")
    dc._commit(path, "the work")
    return path


def _checkout(job: f1.Job, source, depth: int | None) -> str:
    """The commit under review in job.checked, fetched as actions/checkout fetches it: one commit (depth 1) or the
    whole history (fetch-depth: 0)."""
    commit = dc._git(source, "rev-parse", "HEAD")
    job.checked.mkdir()
    dc._git(job.checked, "init", "-q")
    fetch = ["fetch", "-q", "--no-tags"] + (["--depth", str(depth)] if depth else []) + [f"file://{source}"]
    dc._git(job.checked, *fetch, "+refs/heads/main:refs/remotes/origin/main")
    dc._git(job.checked, "checkout", "-q", "--detach", commit)
    return commit


def test_one_commit_fetched_leaves_the_order_base_not_measured(tmp_path, keys, source):
    job = f1.Job(tmp_path, keys)
    commit = _checkout(job, source, depth=1)
    assert subprocess.run(["git", "-C", str(job.checked), "rev-parse", "--is-shallow-repository"], capture_output=True,
                          text=True, check=True).stdout.strip() == "true"
    check, report = job.run(COMMAND, commit=commit)
    assert (check.returncode, report["reason_id"]) == (1, "order_base_not_measured"), check.stderr


def test_the_whole_history_lets_the_order_pass(tmp_path, keys, source):
    job = f1.Job(tmp_path, keys)
    commit = _checkout(job, source, depth=None)
    check, report = job.run(COMMAND, commit=commit)
    assert (check.returncode, report["verdict"]) == (0, "pass"), check.stderr
    assert "1 path in it did" in report["message"]


def test_the_checked_checkout_fetches_the_whole_history():
    """Red at 91a52faa: no fetch-depth, so actions/checkout fetched one commit."""
    (checked,) = [s["with"] for s in f1.done_steps() if s.get("with", {}).get("path") == "checked"]
    assert checked["fetch-depth"] == 0
    assert checked["ref"] == f1.COMMIT_EXPRESSION and checked["persist-credentials"] is False
