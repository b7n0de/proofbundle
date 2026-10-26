"""Nachtrag 43, point 3 (owner choice O28-4 of 2026-10-20): a write in the form of D67 has no receipt, and M5 counts it.

The pilot reads a write only from a simple command of literal words (_pilot_shell_action, D55); the gate decides the form
of D67 (`GH=gh; $GH pr merge 7`) as the merge it is, and the pilot writes no receipt for it (finding of PLUGIN_N28B,
O28-4). The owner's choice: so leave it in the first pilot, M5 counts such a write. The case: the merge in that form is
asked, gets no receipt, arrives, and counts under M5 with no row of a decision; the same merge written out gets its
receipt and its row (control).

Green at f5540aad and after: the case shows what the pilot does, it changes nothing. The reconciliation applies the
profile the records keep, which needs the decision verifier of main 22aa954e; an interpreter whose proofbundle does not
have it skips this file, as for the tests of D57.
"""
from __future__ import annotations

import inspect
import json
import sys

import pytest

import test_plugin_z405_observer as o
from proofbundle.decision import verify_decision_receipt

p1, pd, pr, gate = o.p1, o.pd, o.pr, o.gate
sys.path.insert(0, str(o.PILOT))
import reconcile as rc  # noqa: E402

sys.path.pop(0)

pytestmark = pytest.mark.skipif("now" not in inspect.signature(verify_decision_receipt).parameters,
                                reason="the profile github-write/1 needs the decision verifier of main 22aa954e "
                                       "(verify_decision_receipt with now=); this proofbundle does not have it")


def merge_event(event_id: int, actor: int, number: int, at: str, repo: str = o.REPO) -> dict:
    """A PullRequestEvent of a merge as GET /repos/{owner}/{repo}/events lists it (GitHub's documented shape)."""
    return {"id": str(event_id), "type": "PullRequestEvent", "public": True, "created_at": at,
            "actor": {"id": actor, "login": o.AGENT_LOGIN if actor == o.AGENT_GITHUB_ID else "someone"},
            "repo": {"id": 1, "name": repo},
            "payload": {"action": "closed", "number": number,
                        "pull_request": {"number": number, "merged": True, "merge_commit_sha": "c" * 40}}}


def observe(records, tmp_path, events, start, name="run-1"):
    folder = o.recorded(tmp_path, events, name=f"recorded-{name}")
    return o.run_observer(records, folder, start, o.now_plus(120), run=name)


# --- O28-4: a write in the form of D67 has no receipt, M5 counts it ------------------------------------------------

D67_MERGE = f"GH=gh; $GH pr merge 7 -R {o.REPO}"
LITERAL_MERGE = f"gh pr merge 7 -R {o.REPO}"


def test_O28_4_a_merge_in_the_form_of_d67_has_no_receipt_and_counts_under_m5(tmp_path, monkeypatch):
    pd._clean_git_environment.__wrapped__(monkeypatch)
    env = pd.env.__wrapped__(tmp_path)
    start = o.now_plus(-60)
    records = o.start_records(env, tmp_path)
    r = pd.Repo(tmp_path)
    proc = p1.level1(env, r.path, D67_MERGE)
    assert proc.returncode == 0 and json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"] == "ask", proc
    assert p1.receipts_in(records) == []
    observe(records, tmp_path, [merge_event(1, o.AGENT_GITHUB_ID, 7, o.now_plus(0))], start)
    result = rc.reconcile(pr.Records(records))
    assert (result["M5"], result["decisions"]) == (1, [])
    assert [(u["type"], u["target"]) for u in result["unapproved_effects"]] == \
        [("PullRequestEvent", f"https://github.com/{o.REPO}/pull/7")]


def test_O28_4_control_the_merge_written_out_gets_its_receipt(tmp_path, monkeypatch):
    pd._clean_git_environment.__wrapped__(monkeypatch)
    env = pd.env.__wrapped__(tmp_path)
    start = o.now_plus(-60)
    records = o.start_records(env, tmp_path)
    r = pd.Repo(tmp_path)
    proc = p1.level1(env, r.path, LITERAL_MERGE)
    assert proc.returncode == 0 and json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"] == "ask", proc
    (receipt,) = p1.receipts_in(records)
    assert p1.predicate_of(receipt)["decision"]["verdict"] == "ESCALATE"
    observe(records, tmp_path, [merge_event(1, o.AGENT_GITHUB_ID, 7, o.now_plus(0))], start)
    result = rc.reconcile(pr.Records(records))
    (row,) = result["decisions"]
    assert (row["verdict"], row["surface"], row["M1"]) == ("ESCALATE", "github.merge", "arrived")
