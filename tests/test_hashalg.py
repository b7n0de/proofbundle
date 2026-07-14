"""B2 hash-agility: the four regressions from the anchor-longevity enabler prompt, plus the
supporting registry/dual-hash behaviour. Red-first: these encode the fail-closed contract before the
module exists.

Contract (ADR 0006, RFC 7696 agility + RFC 6920 named-hash registry model):
  * dual_hash_verify_passes        — a receipt carrying two matching digests (a current + a second
                                     current alg) verifies.
  * missing_hashalg_id_fails       — no implicit SHA-256; an absent/empty alg id is a fail-closed error.
  * unknown_hashalg_fails          — an alg id not in the registry is a fail-closed error.
  * deprecated_hashalg_fails_per_policy — a deprecated alg (sha1/md5) fails under the default policy and
                                     only resolves when the caller explicitly opts into legacy verify.
"""
from __future__ import annotations

import hashlib

import pytest

from proofbundle.hashalg import (
    DeprecatedHashAlg,
    HashAlgError,
    MissingHashAlgId,
    UnknownHashAlg,
    compute_digest,
    compute_dual_hash,
    resolve_hash_alg,
    verify_dual_hash,
)


# --- resolve: explicit id, no implicit default -------------------------------------------------

def test_resolve_current_alg_returns_spec() -> None:
    spec = resolve_hash_alg("sha256")
    assert spec.id == "sha256"
    assert spec.digest_size == 32
    assert spec.status == "current"
    # aligns with the ERS digestAlgorithm OID (RFC 4998) so B3 builds directly on it
    assert spec.ers_oid == "2.16.840.1.101.3.4.2.1"


def test_missing_hashalg_id_fails() -> None:
    # no implicit SHA-256 — an absent id is fail-closed, never defaulted
    with pytest.raises(MissingHashAlgId):
        resolve_hash_alg("")
    with pytest.raises(MissingHashAlgId):
        resolve_hash_alg(None)  # type: ignore[arg-type]


def test_unknown_hashalg_fails() -> None:
    with pytest.raises(UnknownHashAlg):
        resolve_hash_alg("sha999")
    with pytest.raises(UnknownHashAlg):
        resolve_hash_alg("not-a-hash")


def test_deprecated_hashalg_fails_per_policy() -> None:
    # default policy rejects a weak hash
    with pytest.raises(DeprecatedHashAlg):
        resolve_hash_alg("sha1")
    with pytest.raises(DeprecatedHashAlg):
        resolve_hash_alg("md5")
    # a legacy-verify caller may explicitly opt in — the alg is known, just weak
    legacy = resolve_hash_alg("sha1", allow_deprecated=True)
    assert legacy.id == "sha1"
    assert legacy.status == "deprecated"


def test_all_hashalg_errors_share_base() -> None:
    for exc in (MissingHashAlgId, UnknownHashAlg, DeprecatedHashAlg):
        assert issubclass(exc, HashAlgError)


# --- compute + dual-hash ------------------------------------------------------------------------

def test_compute_digest_matches_hashlib() -> None:
    data = b"proofbundle anchor payload"
    assert compute_digest(data, "sha256") == hashlib.sha256(data).hexdigest()
    assert compute_digest(data, "sha512") == hashlib.sha512(data).hexdigest()
    assert compute_digest(data, "sha3-256") == hashlib.sha3_256(data).hexdigest()


def test_compute_digest_rejects_missing_and_deprecated() -> None:
    with pytest.raises(MissingHashAlgId):
        compute_digest(b"x", "")
    with pytest.raises(DeprecatedHashAlg):
        compute_digest(b"x", "sha1")


def test_compute_dual_hash_produces_two_current_digests() -> None:
    data = b"dual-hash new receipt"
    digests = compute_dual_hash(data, ("sha256", "sha512"))
    assert set(digests) == {"sha256", "sha512"}
    assert digests["sha256"] == hashlib.sha256(data).hexdigest()
    assert digests["sha512"] == hashlib.sha512(data).hexdigest()


def test_compute_dual_hash_requires_two_distinct_current_algs() -> None:
    # a single alg is not a dual hash
    with pytest.raises(HashAlgError):
        compute_dual_hash(b"x", ("sha256",))
    # duplicate alg is not two independent digests
    with pytest.raises(HashAlgError):
        compute_dual_hash(b"x", ("sha256", "sha256"))
    # a deprecated alg cannot be part of a new receipt's dual hash
    with pytest.raises(DeprecatedHashAlg):
        compute_dual_hash(b"x", ("sha256", "sha1"))


def test_dual_hash_verify_passes() -> None:
    data = b"the exact payload bytes"
    digests = compute_dual_hash(data, ("sha256", "sha3-256"))
    res = verify_dual_hash(data, digests)
    assert res.ok is True
    # every declared digest was checked, not just one
    assert {c.name for c in res.checks} >= {"hashalg:sha256", "hashalg:sha3-256"}
    assert all(c.ok for c in res.checks)


def test_dual_hash_verify_fails_on_any_mismatch() -> None:
    data = b"the exact payload bytes"
    digests = compute_dual_hash(data, ("sha256", "sha512"))
    digests["sha512"] = "00" * 64  # tamper one leg
    res = verify_dual_hash(data, digests)
    assert res.ok is False


def test_dual_hash_verify_fails_when_no_current_alg() -> None:
    # a bag of only-deprecated digests must not pass, even if the bytes match
    data = b"legacy only"
    digests = {"sha1": hashlib.sha1(data).hexdigest()}
    res = verify_dual_hash(data, digests)
    assert res.ok is False


def test_dual_hash_verify_fails_on_unknown_alg() -> None:
    data = b"x"
    digests = {"sha256": hashlib.sha256(data).hexdigest(), "sha999": "ab" * 32}
    res = verify_dual_hash(data, digests)
    assert res.ok is False


def test_dual_hash_verify_rejects_empty_digest_map() -> None:
    res = verify_dual_hash(b"x", {})
    assert res.ok is False
