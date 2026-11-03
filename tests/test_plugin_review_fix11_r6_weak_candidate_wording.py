"""Review round 11 of 2026-10-12, R11-6: a weak destination candidate is not described as a determined write.

Measured by the reviewer at 3bbbf66f: the remote and the source at A, on the remote refs/remotes/refs/heads/main at A,
recorded locally with +refs/remotes/*:refs/recorded/origin/remotes/*; then, without a new fetch, on the remote
refs/heads/refs/heads/main created at A and refs/heads/main deleted; locally an empty commit B; the hook for
`git push origin main`, then the real push. The verdict ask/push_not_measured was right, but the text said git writes
refs/remotes/refs/heads/main instead; git moved refs/heads/refs/heads/main.

The review's wording replaces the weak alternative of `match`, verbatim. Red against 6d37fa1c.
"""
from __future__ import annotations

import json
import subprocess

import test_plugin_gate_n2c_push_done as n2c
import test_plugin_review_fix10_r3_weak_candidate_text as r3

pytestmark = n2c.pytestmark
env = n2c.env
_clean_git_environment = n2c._clean_git_environment

WEAK = "refs/remotes/refs/heads/main"
WORDING = (f"git push matches {WEAK} for refs/heads/main only weakly: a weak match counts only when no strong match "
           "exists on the remote, whose current refs the gate does not read")


def _reviewers_case(env, tmp_path):
    r = r3._recorded_beside(env, tmp_path, WEAK)
    a = r3._on_remote(tmp_path, "rev-parse", "refs/heads/main").stdout.strip()
    assert r3._on_remote(tmp_path, "update-ref", "refs/heads/refs/heads/main", a).returncode == 0
    assert r3._on_remote(tmp_path, "update-ref", "-d", "refs/heads/main").returncode == 0
    n2c._git(r.path, "commit", "-q", "--allow-empty", "-m", "B")
    r.make("valid")   # the done receipt of the fixture, for B
    return r, a


def test_the_answer_uses_the_reviewers_wording_for_a_weak_candidate(env, tmp_path):
    r, _a = _reviewers_case(env, tmp_path)
    answer, entry = n2c._level1(env, r.path, command="git push origin main")
    text = json.dumps(answer, ensure_ascii=False)
    assert (entry["verdict"], entry["reason_ids"]) == ("ask", ["push_not_measured"]), entry
    assert WORDING in text, text
    assert f"it writes {WEAK} instead" not in text and "refuses the push" not in text, text


def test_git_moves_another_strong_match_than_the_recorded_weak_one(env, tmp_path):
    """Non-vacuous: with main gone and refs/heads/refs/heads/main on the remote, git moves the latter, not the weak
    candidate the repository records."""
    r, a = _reviewers_case(env, tmp_path)
    push = subprocess.run(["git", "-C", str(r.path), "push", "--porcelain", "--no-verify", "origin", "main"],
                          capture_output=True, text=True, timeout=60, check=False)
    assert push.returncode == 0, push.stderr
    b = n2c._rev(r.path, "HEAD")
    assert r3._on_remote(tmp_path, "rev-parse", "refs/heads/refs/heads/main").stdout.strip() == b
    assert r3._on_remote(tmp_path, "rev-parse", WEAK).stdout.strip() == a
