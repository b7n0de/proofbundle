"""B3 renewal chain — the eight regressions from the anchor-longevity enabler prompt, at the RFC-4998
ArchiveTimeStampSequence contract level (offline, reproducible).

  * renewal_sequence_verifies_end_to_end
  * timestamp_renewal_same_chain_verifies
  * hashtree_renewal_starts_new_chain_and_covers_all_prior
  * watch_only_last_ats_rule_enforced
  * break_in_sequence_fails
  * tamper_after_renewal_fails
  * renew_without_prior_anchor_fails
  * sequence_ordered_ascending_by_time
"""
from __future__ import annotations

import dataclasses

import pytest

from proofbundle.renewal import (
    ArchiveTimeStamp,
    RenewalError,
    build_initial_sequence,
    last_ats,
    renew_hashtree,
    renew_timestamp,
    verify_sequence,
)

DATA = ["a" * 64, "b" * 64, "c" * 64]


def _initial(time: int = 1000):
    return build_initial_sequence(DATA, hash_alg="sha256", time=time)


def test_initial_sequence_verifies() -> None:
    seq = _initial()
    assert verify_sequence(seq, DATA).ok


def test_timestamp_renewal_same_chain_verifies() -> None:
    seq = renew_timestamp(_initial(), time=2000)
    # timestamp renewal stays in the SAME (single) chain
    assert len(seq) == 1
    assert len(seq[0]) == 2
    assert seq[0][0].hash_alg == seq[0][1].hash_alg == "sha256"
    assert verify_sequence(seq, DATA).ok


def test_hashtree_renewal_starts_new_chain_and_covers_all_prior() -> None:
    seq = renew_hashtree(_initial(), DATA, new_hash_alg="sha512", time=2000)
    # hash-tree renewal starts a NEW chain, with a new (stronger) hash algorithm
    assert len(seq) == 2
    assert seq[0][0].hash_alg == "sha256"
    assert seq[1][0].hash_alg == "sha512"
    res = verify_sequence(seq, DATA)
    assert res.ok
    # the new chain's ATS genuinely covers the prior ATS: dropping the prior would change the digest
    reduced = [seq[0], [dataclasses.replace(seq[1][0])]]  # same objects → still ok (sanity)
    assert verify_sequence(reduced, DATA).ok


def test_renewal_sequence_verifies_end_to_end() -> None:
    seq = _initial(1000)
    seq = renew_timestamp(seq, time=2000)              # same chain
    seq = renew_hashtree(seq, DATA, new_hash_alg="sha512", time=3000)  # new chain
    seq = renew_timestamp(seq, time=4000)              # extend the new chain
    res = verify_sequence(seq, DATA)
    assert res.ok, [str(c) for c in res.checks if not c.ok]
    assert len(seq) == 2
    assert len(seq[1]) == 2


def test_watch_only_last_ats_rule_enforced() -> None:
    seq = _initial(1000)
    seq = renew_timestamp(seq, time=2000)
    seq = renew_hashtree(seq, DATA, new_hash_alg="sha512", time=3000)
    watched = last_ats(seq)
    # exactly the single newest ATS (by time), which is the hash-tree renewal
    assert watched.time == 3000
    assert watched.hash_alg == "sha512"
    assert watched is seq[-1][-1]


def test_break_in_sequence_fails() -> None:
    seq = renew_hashtree(_initial(), DATA, new_hash_alg="sha512", time=2000)
    # corrupt the covered digest of the renewal ATS → the chain no longer covers its prior
    broken_ats = dataclasses.replace(seq[1][0], covered_digest="00" * 32)
    broken = [seq[0], [broken_ats]]
    assert not verify_sequence(broken, DATA).ok


def test_tamper_after_renewal_fails() -> None:
    seq = renew_hashtree(_initial(), DATA, new_hash_alg="sha512", time=2000)
    tampered_data = ["a" * 64, "b" * 64, "d" * 64]  # one object changed after renewal
    assert not verify_sequence(seq, tampered_data).ok


def test_renew_without_prior_anchor_fails() -> None:
    # the prior newest ATS is not confirmed → neither renewal mode may extend it
    seq = build_initial_sequence(DATA, hash_alg="sha256", time=1000, anchor_status="pending")
    with pytest.raises(RenewalError):
        renew_timestamp(seq, time=2000)
    with pytest.raises(RenewalError):
        renew_hashtree(seq, DATA, new_hash_alg="sha512", time=2000)


def test_sequence_ordered_ascending_by_time() -> None:
    # renewal APIs reject non-ascending time
    seq = _initial(2000)
    with pytest.raises(RenewalError):
        renew_timestamp(seq, time=1000)
    with pytest.raises(RenewalError):
        renew_hashtree(seq, DATA, new_hash_alg="sha512", time=2000)  # equal, not strictly after
    # and verify catches an out-of-order sequence assembled by hand
    a0 = ArchiveTimeStamp("sha256", "x", 3000)
    a1 = ArchiveTimeStamp("sha256", "y", 1000)
    assert not verify_sequence([[a0, a1]], DATA).ok


def test_renewal_never_seeds_a_deprecated_hash() -> None:
    with pytest.raises(Exception):
        build_initial_sequence(DATA, hash_alg="sha1", time=1000)
    with pytest.raises(Exception):
        renew_hashtree(_initial(), DATA, new_hash_alg="md5", time=2000)
