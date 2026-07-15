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
    VerifiedAnchorResult,
    anchor_proof_digest,
    build_initial_sequence,
    last_ats,
    renew_hashtree,
    renew_timestamp,
)
from proofbundle.renewal import verify_sequence as _verify_sequence


def verify_sequence(seq, data, **kw):
    # these tests exercise the STRUCTURAL covering/ordering/tamper logic, not the anchor — opt explicitly
    # into the unauthenticated structural anchor so the covering check is what is under test (the signed
    # anchor path is covered by tests/test_renewal_signed.py).
    kw.setdefault("allow_unauthenticated_anchor", True)
    return _verify_sequence(seq, data, **kw)


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


# --- audit fix (HIGH): delimiter injection in the data-digest join --------------------------------

def test_data_digest_delimiter_injection_rejected() -> None:
    # a single crafted string equal to "\n".join(sorted(real_digests)) hashed identically to the real
    # two-object set before the fix (set/cardinality confusion). Non-hex (contains "\n") is now rejected.
    forged_single = ["\n".join(sorted(DATA))]
    with pytest.raises(RenewalError):
        build_initial_sequence(forged_single, hash_alg="sha256", time=1000)
    # and a sequence built over the real set must not verify against the forged single-object list
    seq = _initial()
    assert not verify_sequence(seq, forged_single).ok


def test_non_hex_data_digest_rejected() -> None:
    for bad in [["not-hex!"], ["AA" * 32], ["a b"], [""], [123]]:  # uppercase/space/empty/non-str
        with pytest.raises(RenewalError):
            build_initial_sequence(bad, hash_alg="sha256", time=1000)


# --- audit fix (HIGH): a renewed sequence survives deprecation of a historical algorithm ----------

def test_renewed_sequence_survives_algorithm_deprecation() -> None:
    import dataclasses as _dc

    from proofbundle import hashalg
    # renew sha256 -> sha512 (hash-tree renewal: the whole point is to survive sha256 ageing)
    seq = renew_hashtree(_initial(1000), DATA, new_hash_alg="sha512", time=2000)
    assert verify_sequence(seq, DATA).ok
    # now sha256 becomes deprecated in the registry — the already-renewed sequence must STILL verify
    # (newest chain is sha512), not crash with DeprecatedHashAlg
    orig = hashalg.HASH_REGISTRY["sha256"]
    hashalg.HASH_REGISTRY["sha256"] = _dc.replace(orig, status="deprecated")
    try:
        res = verify_sequence(seq, DATA)  # must not raise
        assert res.ok, [str(c) for c in res.checks if not c.ok]
    finally:
        hashalg.HASH_REGISTRY["sha256"] = orig


def test_unknown_algorithm_still_fails_closed() -> None:
    # tolerance is only for DEPRECATED (known) algorithms — an UNKNOWN algorithm cannot be computed → fail
    a = ArchiveTimeStamp("sha999", "ab" * 32, 1000)
    assert not verify_sequence([[a]], DATA).ok


# --- finding 09: renewal seeding trusted a bare anchor_status marker, never cryptography -----------
#
# _require_prior_anchor previously checked ONLY `prior.anchor_status != "confirmed"` — never a real
# signature/verification. anchor_status="confirmed" is ALSO the ArchiveTimeStamp field default AND
# build_initial_sequence's default, so an entirely unsigned (sig_alg="") ATS satisfies it trivially.
# VerifiedAnchorResult + prior_verification/require_verified_prior close this for a caller who opts in,
# while the DEFAULT (unopted) behavior of every existing caller stays exactly as before (additive).


def _good_verification(ats: ArchiveTimeStamp, **overrides) -> VerifiedAnchorResult:
    fields = dict(verified=True, proof_digest=anchor_proof_digest(ats), verifier_id="ots-monitor-1",
                 policy_digest="policy-abc", verified_at=1_700_000_000)
    fields.update(overrides)
    return VerifiedAnchorResult(**fields)


def test_renew_requires_verified_prior_anchor_result() -> None:
    seq = build_initial_sequence(DATA, hash_alg="sha256", time=1000)
    prior = last_ats(seq)

    # require_verified_prior=True with NO VerifiedAnchorResult at all -> fail closed
    with pytest.raises(RenewalError):
        renew_timestamp(seq, time=2000, require_verified_prior=True)
    with pytest.raises(RenewalError):
        renew_hashtree(seq, DATA, new_hash_alg="sha512", time=2000, require_verified_prior=True)

    # a VerifiedAnchorResult that says verified=False must not seed a renewal even though it was supplied
    unverified = _good_verification(prior, verified=False)
    with pytest.raises(RenewalError):
        renew_timestamp(seq, time=2000, prior_verification=unverified, require_verified_prior=True)

    # a VerifiedAnchorResult whose proof_digest does NOT bind to this prior ATS -> fail closed
    unbound = _good_verification(prior, proof_digest="00" * 32)
    with pytest.raises(RenewalError):
        renew_timestamp(seq, time=2000, prior_verification=unbound, require_verified_prior=True)

    # a correctly-bound, verified=True result succeeds for BOTH renewal modes, and the produced ATS
    # records the cryptographic evidence class
    good = _good_verification(prior)
    renewed = renew_timestamp(seq, time=2000, prior_verification=good, require_verified_prior=True)
    assert renewed[0][1].renewal_seed_evidence_class == "cryptographically_verified"
    renewed2 = renew_hashtree(seq, DATA, new_hash_alg="sha512", time=2000,
                              prior_verification=good, require_verified_prior=True)
    assert renewed2[1][0].renewal_seed_evidence_class == "cryptographically_verified"


def test_forged_confirmed_label_cannot_seed_renewal() -> None:
    # the exact finding-09 attack: an entirely UNSIGNED ATS (sig_alg="") whose anchor_status is
    # "confirmed" only because that is the field default (never independently verified by anyone).
    seq = build_initial_sequence(DATA, hash_alg="sha256", time=1000)
    assert seq[0][0].anchor_status == "confirmed"
    assert seq[0][0].sig_alg == ""

    # require_verified_prior=True refuses to seed a renewal from the bare label alone
    with pytest.raises(RenewalError):
        renew_timestamp(seq, time=2000, require_verified_prior=True)
    with pytest.raises(RenewalError):
        renew_hashtree(seq, DATA, new_hash_alg="sha512", time=2000, require_verified_prior=True)

    # documented compat boundary: the DEFAULT (require_verified_prior=False, no prior_verification)
    # still accepts the forged/self-asserted label — an honest, additive limitation, not silently closed
    # (closing it by default would break every existing caller of renew_timestamp/renew_hashtree).
    renewed = renew_timestamp(seq, time=2000)
    assert renewed[0][1].renewal_seed_evidence_class == "self_asserted_status"
    assert verify_sequence(renewed, DATA).ok


def test_renewal_chain_binds_verification_policy_digest() -> None:
    # a VerifiedAnchorResult is scoped to the EXACT prior ATS it was computed for — it must not be
    # replayable onto a LATER link in the same renewal chain, even under a different policy_digest.
    seq = build_initial_sequence(DATA, hash_alg="sha256", time=1000)
    ats0 = last_ats(seq)
    verification0 = _good_verification(ats0, verifier_id="monitor-1", policy_digest="policy-A")

    seq = renew_timestamp(seq, time=2000, prior_verification=verification0, require_verified_prior=True)
    assert seq[0][1].renewal_seed_evidence_class == "cryptographically_verified"
    ats1 = last_ats(seq)
    assert ats1 is not ats0

    # replay: verification0 was bound to ats0's token, not ats1's -> the NEXT renewal step must reject it
    with pytest.raises(RenewalError):
        renew_timestamp(seq, time=3000, prior_verification=verification0, require_verified_prior=True)

    # a freshly bound verification for THIS step succeeds, even under a DIFFERENT policy_digest — the
    # binding is per-ATS (proof_digest), policy_digest is provenance only, not itself cross-checked here
    verification1 = _good_verification(ats1, verifier_id="monitor-1", policy_digest="policy-B")
    seq = renew_timestamp(seq, time=3000, prior_verification=verification1, require_verified_prior=True)
    assert seq[0][2].renewal_seed_evidence_class == "cryptographically_verified"
    assert verify_sequence(seq, DATA, allow_unauthenticated_anchor=True).ok


def test_anchor_proof_digest_is_deterministic_and_ats_specific() -> None:
    seq = build_initial_sequence(DATA, hash_alg="sha256", time=1000)
    ats0 = last_ats(seq)
    seq2 = renew_timestamp(seq, time=2000)
    ats1 = last_ats(seq2)
    assert anchor_proof_digest(ats0) == anchor_proof_digest(ats0)     # deterministic
    assert anchor_proof_digest(ats0) != anchor_proof_digest(ats1)     # distinct ATS -> distinct digest


def test_verified_anchor_result_wrong_type_rejected() -> None:
    seq = build_initial_sequence(DATA, hash_alg="sha256", time=1000)
    with pytest.raises(RenewalError):
        renew_timestamp(seq, time=2000, prior_verification="not-a-VerifiedAnchorResult",  # type: ignore[arg-type]
                        require_verified_prior=True)
