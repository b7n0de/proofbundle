"""B4 renewal policy and triggers — the three regressions, plus the shipped example policy.

  * overdue_renewal_warns_or_fails_per_policy
  * watch_only_last_ats_in_policy
  * policy_no_network_fetch_by_default
"""
from __future__ import annotations

import json
import pathlib

from proofbundle.renewal import (
    RenewalPolicy,
    build_initial_sequence,
    evaluate_renewal_policy,
    renew_hashtree,
)

DATA = ["a" * 64, "b" * 64]
_EXAMPLE = pathlib.Path(__file__).resolve().parents[1] / "docs" / "adr" / "renewal_policy.example.json"


def _seq(time: int = 1000, alg: str = "sha256"):
    return build_initial_sequence(DATA, hash_alg=alg, time=time)


def test_within_policy_is_pass() -> None:
    policy = RenewalPolicy(max_ats_age=1000)
    res = evaluate_renewal_policy(_seq(time=1000), policy=policy, now=1500)  # age 500 < 1000
    assert res.ok
    assert all(c.ok for c in res.checks)


def test_overdue_renewal_warns_per_policy() -> None:
    policy = RenewalPolicy(max_ats_age=1000, strictness="warn")
    res = evaluate_renewal_policy(_seq(time=1000), policy=policy, now=5000)  # age 4000 > 1000
    # WARN: overdue is surfaced but does not hard-fail
    assert res.ok
    assert any("overdue" in c.detail and "WARN" in c.detail for c in res.checks)


def test_overdue_renewal_fails_per_policy() -> None:
    policy = RenewalPolicy(max_ats_age=1000, strictness="fail")
    res = evaluate_renewal_policy(_seq(time=1000), policy=policy, now=5000)
    assert not res.ok  # FAIL strictness → hard fail


def test_deprecated_alg_is_overdue_regardless_of_age() -> None:
    # a fresh ATS on a policy-deprecated hash is still overdue (the hash, not the clock, is the trigger)
    policy = RenewalPolicy(deprecated_algs=frozenset({"sha256"}), strictness="fail")
    res = evaluate_renewal_policy(_seq(time=1000), policy=policy, now=1001)  # age 1
    assert not res.ok


def test_watch_only_last_ats_in_policy() -> None:
    # an OLD first ATS does not trigger when the NEWEST ATS is fresh — only the last ATS is watched
    seq = _seq(time=1000, alg="sha256")
    seq = renew_hashtree(seq, DATA, new_hash_alg="sha512", time=9000)  # newest is fresh
    policy = RenewalPolicy(max_ats_age=1000, strictness="fail")
    res = evaluate_renewal_policy(seq, policy=policy, now=9500)  # newest age 500 < 1000
    assert res.ok
    # and a deprecated FIRST-chain alg does not trigger either, since the newest chain is sha512
    policy2 = RenewalPolicy(deprecated_algs=frozenset({"sha256"}), strictness="fail")
    assert evaluate_renewal_policy(seq, policy=policy2, now=9500).ok


def test_policy_no_network_fetch_by_default() -> None:
    # prove no network: block socket.socket during the evaluation
    import socket
    seq = _seq(time=1000)
    policy = RenewalPolicy(max_ats_age=1000, strictness="warn")
    real = socket.socket

    def _bomb(*a, **k):
        raise AssertionError("evaluate_renewal_policy must not open a socket")

    socket.socket = _bomb  # type: ignore[assignment]
    try:
        res = evaluate_renewal_policy(seq, policy=policy, now=1200)
    finally:
        socket.socket = real  # type: ignore[assignment]
    assert res.ok


def test_shipped_example_policy_loads_and_evaluates() -> None:
    obj = json.loads(_EXAMPLE.read_text())
    policy = RenewalPolicy.from_dict(obj)
    assert "sha1" in policy.deprecated_algs
    assert policy.strictness == "warn"
    # a very old ATS is overdue under the shipped max_ats_age
    old = _seq(time=0)
    res = evaluate_renewal_policy(old, policy=policy, now=10**12)
    assert any("overdue" in c.detail for c in res.checks)


def test_from_dict_rejects_bad_strictness() -> None:
    import pytest
    with pytest.raises(Exception):
        RenewalPolicy.from_dict({"strictness": "explode"})
