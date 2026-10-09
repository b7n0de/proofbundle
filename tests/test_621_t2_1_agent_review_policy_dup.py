"""6.2.1 T2-1: load_policy does not read a duplicate key last-wins.

PROPERTY: a policy file that carries the same key twice is not a policy. A reader that takes the last value
and one that takes the first would otherwise decide differently over the same bytes; the digest binds the
bytes, not the reading. Measured at 419e07f2: `{"blocking":["COVERAGE_PARTIAL"],"blocking":[]}` lifts the
blocking list (accept, ok, safe), and so does the escaped spelling `\\u0062locking`.

The controls show that the policy axis acts otherwise: the same blocking list written once blocks, an open
list written once lets the review through.
"""
from __future__ import annotations

import pytest

from proofbundle import agent_review as AR

import test_agent_review_zeitsemantik as Z


def _partial_pred() -> dict:
    p = Z._pred_v02(timeClaims=Z.REVIEW_CLAIM)
    p["coverage"] = {"status": "PARTIAL", "knownGaps": ["only one file read"]}
    p["limitationCodes"] = ["COVERAGE_PARTIAL", "IDENTITY_UNBOUND", "NOT_QUALITY_ATTESTATION",
                            "TIME_SELF_DECLARED"]
    return p


def _policy(tmp_path, name: str, text: str):
    f = tmp_path / f"{name}.json"
    f.write_bytes(text.encode("utf-8"))
    return f


DUPLICATES = {
    "plain": '{"name":"test","blocking":["COVERAGE_PARTIAL"],"blocking":[]}',
    "escaped": '{"name":"test","blocking":["COVERAGE_PARTIAL"],"\\u0062locking":[]}',
    "never_blocking": '{"name":"test","blocking":["COVERAGE_PARTIAL"],'
                      '"never_blocking":[],"never_blocking":[]}',
    "name": '{"name":"a","name":"b","blocking":["COVERAGE_PARTIAL"]}',
}


@pytest.mark.parametrize("case", sorted(DUPLICATES))
def test_load_policy_refuses_a_duplicate_key(tmp_path, case):
    f = _policy(tmp_path, case, DUPLICATES[case])
    with pytest.raises(AR.AgentReviewError):
        AR.load_policy(f)


@pytest.mark.parametrize("case", ["plain", "escaped"])
def test_a_duplicated_blocking_list_never_reaches_accept(tmp_path, case):
    """The consequence, not only the form: whoever writes the blocking list twice never gets accept."""
    f = _policy(tmp_path, case, DUPLICATES[case])
    try:
        pol = AR.load_policy(f)
    except AR.AgentReviewError:
        return
    _, r = Z._lauf_v02(_partial_pred(), policy=pol)
    assert r["policy_decision"] != "accept", (pol.get("blocking"), r["policy_decision"])
    assert r["ok"] is False
    assert (r.get("automation") or {}).get("safeForAutomation") is not True


def test_control_a_single_blocking_list_blocks(tmp_path):
    pol = AR.load_policy(_policy(tmp_path, "block", '{"name":"test","blocking":["COVERAGE_PARTIAL"]}'))
    _, r = Z._lauf_v02(_partial_pred(), policy=pol)
    assert r["policy_decision"] == "reject"
    assert r["ok"] is False
    assert (r.get("automation") or {}).get("safeForAutomation") is False


def test_control_a_single_open_list_lets_it_through(tmp_path):
    pol = AR.load_policy(_policy(tmp_path, "open", '{"name":"test","blocking":[]}'))
    _, r = Z._lauf_v02(_partial_pred(), policy=pol)
    assert r["policy_decision"] == "accept"
    assert r["ok"] is True
    assert (r.get("automation") or {}).get("safeForAutomation") is True


def test_control_the_default_policy_loads(tmp_path):
    pol = AR.load_policy()
    assert pol["_digest"].startswith("sha256:")
