"""B2 hash-agility — an explicit registry of hash algorithms with fail-closed resolution and a
dual-hash helper (ADR 0006).

Why this module exists. proofbundle's surfaces already DECLARE their hash construction per artifact
(``merkle.hash_alg = "sha256-rfc6962"``, ``contentRootAlg = "jcs-sha256-v1"``, a checkpoint's
``hashAlg``). What was missing for long-term evidence is a single agility layer: one registry that
says which hash PRIMITIVES are allowed, which are deprecated, and a resolver that NEVER silently
defaults a missing/unknown/weak algorithm — the exact place an algorithm-confusion attack would hide
(RFC 7696 §2.1; ADR 0002 §2 warns of the same at the content-root level). The algorithm id maps to the
RFC 4998 (ERS) ``digestAlgorithm`` OID, so the B3 renewal chain builds directly on this registry.

Model: the IANA Named Information Hash Algorithm registry (RFC 6920) — an id, a status
(``current`` / ``deprecated``), and enough to compute and size the digest. Deprecation follows the NIST
transition (SHA-1 retired; SHA-256/384/512 and the SHA-3 family current — NIST FIPS 180-4 / 202,
SP 800-131A).

Fail-closed contract:
  * an absent/empty id is ``MissingHashAlgId`` — there is NO implicit SHA-256;
  * an id not in the registry is ``UnknownHashAlg``;
  * a deprecated id is ``DeprecatedHashAlg`` unless the caller explicitly opts into legacy verification
    (``allow_deprecated=True``) — a verifier may need to read an old receipt, but nothing NEW is ever
    produced with a weak hash, and a dual-hash's PASS requires at least one current algorithm.
"""
from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Optional

from .errors import Check, ProofBundleError, VerificationResult

__all__ = [
    "HASH_REGISTRY",
    "HashAlg",
    "HashAlgError",
    "MissingHashAlgId",
    "UnknownHashAlg",
    "DeprecatedHashAlg",
    "resolve_hash_alg",
    "compute_digest",
    "compute_dual_hash",
    "verify_dual_hash",
]


class HashAlgError(ProofBundleError):
    """Base class for every hash-agility failure (a subclass of ``ProofBundleError``)."""


class MissingHashAlgId(HashAlgError):
    """No algorithm id was given. Fail-closed: proofbundle never defaults a missing hash to SHA-256."""


class UnknownHashAlg(HashAlgError):
    """The algorithm id is not in ``HASH_REGISTRY``. Fail-closed: an unknown hash is never trusted."""


class DeprecatedHashAlg(HashAlgError):
    """The algorithm is known but deprecated and the caller did not opt into legacy verification."""


@dataclass(frozen=True)
class HashAlg:
    """One registry entry: how to compute the digest, its size, its status, and its ERS OID.

    ``ers_oid`` is the RFC 4998 ``digestAlgorithm`` ``AlgorithmIdentifier`` OID, so a renewal chain (B3)
    references the same identity this registry defines. ``hashlib_name`` is the ``hashlib.new`` name."""

    id: str
    hashlib_name: str
    digest_size: int
    status: str  # "current" | "deprecated"
    ers_oid: str

    def new(self) -> "hashlib._Hash":
        return hashlib.new(self.hashlib_name)


# The allowed hash primitives. SHA-256/384/512 (FIPS 180-4) and SHA3-256/512 (FIPS 202) are current;
# SHA-1 and MD5 are deprecated (kept only so a verifier can READ and clearly reject a legacy receipt).
# OIDs are the NIST/RFC AlgorithmIdentifier values used by RFC 4998 digestAlgorithm.
HASH_REGISTRY: dict[str, HashAlg] = {
    "sha256": HashAlg("sha256", "sha256", 32, "current", "2.16.840.1.101.3.4.2.1"),
    "sha384": HashAlg("sha384", "sha384", 48, "current", "2.16.840.1.101.3.4.2.2"),
    "sha512": HashAlg("sha512", "sha512", 64, "current", "2.16.840.1.101.3.4.2.3"),
    "sha3-256": HashAlg("sha3-256", "sha3_256", 32, "current", "2.16.840.1.101.3.4.2.8"),
    "sha3-512": HashAlg("sha3-512", "sha3_512", 64, "current", "2.16.840.1.101.3.4.2.10"),
    "sha1": HashAlg("sha1", "sha1", 20, "deprecated", "1.3.14.3.2.26"),
    "md5": HashAlg("md5", "md5", 16, "deprecated", "1.2.840.113549.2.5"),
}


def resolve_hash_alg(alg_id: Optional[str], *, allow_deprecated: bool = False) -> HashAlg:
    """Resolve an algorithm id to its registry entry, fail-closed.

    Raises ``MissingHashAlgId`` for an absent/empty id (no implicit default), ``UnknownHashAlg`` for an
    id not in the registry, and ``DeprecatedHashAlg`` for a weak algorithm unless ``allow_deprecated``.
    """
    if not alg_id or not isinstance(alg_id, str):
        raise MissingHashAlgId(
            "a hash algorithm id is required — proofbundle never defaults a missing hash to SHA-256")
    spec = HASH_REGISTRY.get(alg_id)
    if spec is None:
        raise UnknownHashAlg(
            f"unknown hash algorithm {alg_id!r} — not in the allowed registry "
            f"({', '.join(sorted(HASH_REGISTRY))})")
    if spec.status == "deprecated" and not allow_deprecated:
        raise DeprecatedHashAlg(
            f"hash algorithm {alg_id!r} is deprecated and rejected by default; a legacy verifier must "
            "opt in explicitly (allow_deprecated=True)")
    return spec


def compute_digest(data: bytes, alg_id: str, *, allow_deprecated: bool = False) -> str:
    """Hex digest of ``data`` under ``alg_id`` (fail-closed on missing/unknown/deprecated)."""
    spec = resolve_hash_alg(alg_id, allow_deprecated=allow_deprecated)
    h = spec.new()
    h.update(data)
    return h.hexdigest()


def compute_dual_hash(data: bytes, alg_ids: Sequence[str]) -> dict[str, str]:
    """Digests of ``data`` under two or more DISTINCT CURRENT algorithms — for a NEW receipt.

    A dual hash lets an old receipt survive the deprecation of one hash: as long as a second,
    independent current hash still binds the same bytes, the evidence keeps its force while a renewal
    (B3) migrates it. A new receipt therefore requires at least two distinct current algorithms; a
    deprecated algorithm is rejected outright (nothing new is produced with a weak hash)."""
    seen: dict[str, HashAlg] = {}
    for alg_id in alg_ids:
        spec = resolve_hash_alg(alg_id)  # current-only: no allow_deprecated on the produce path
        if spec.id in seen:
            raise HashAlgError(f"dual hash needs DISTINCT algorithms, {spec.id!r} was given twice")
        seen[spec.id] = spec
    if len(seen) < 2:
        raise HashAlgError(
            "a dual hash needs at least two distinct current algorithms "
            "(e.g. sha256 + sha512 or sha256 + sha3-256)")
    return {alg_id: compute_digest(data, alg_id) for alg_id in seen}


def verify_dual_hash(data: bytes, digests: Mapping[str, str]) -> VerificationResult:
    """Verify that EVERY declared digest binds ``data``, and that at least one is a CURRENT algorithm.

    Fail-closed: an empty map fails; an unknown algorithm fails; a single mismatching leg fails the
    whole result; a bag of only-deprecated digests fails even when the bytes match (a legacy-only
    receipt has lost its force and must be renewed, not silently accepted). A deprecated leg is checked
    (``allow_deprecated``) so its presence is visible, but it cannot by itself carry a PASS."""
    result = VerificationResult()
    if not isinstance(digests, Mapping) or not digests:
        result.checks.append(Check("hashalg:dual", False,
                                   "digests must be a non-empty mapping of alg -> hex"))
        return result

    current_ok = 0
    for alg_id, expected in digests.items():
        try:
            spec = resolve_hash_alg(alg_id, allow_deprecated=True)
        except HashAlgError as exc:
            result.checks.append(Check(f"hashalg:{alg_id}", False, str(exc)))
            continue
        actual = compute_digest(data, alg_id, allow_deprecated=True)
        match = isinstance(expected, str) and actual == expected.lower()
        detail = "digest matches" if match else "digest mismatch"
        if match and spec.status == "deprecated":
            detail = "digest matches but algorithm is deprecated (does not carry a PASS on its own)"
        result.checks.append(Check(f"hashalg:{alg_id}", match, detail))
        if match and spec.status == "current":
            current_ok += 1

    all_match = all(c.ok for c in result.checks)
    if all_match and current_ok == 0:
        result.checks.append(Check(
            "hashalg:current-binding", False,
            "no CURRENT-algorithm digest binds the payload — a legacy-only receipt must be renewed"))
    return result
