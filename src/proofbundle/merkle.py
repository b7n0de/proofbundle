"""RFC 6962 / RFC 9162 Merkle tree hashing, inclusion and consistency proofs.

This module implements the Certificate Transparency Merkle tree exactly as
specified in RFC 6962 (updated by RFC 9162), so bundles verify against the same
primitives used by Sigstore Rekor, Certificate Transparency and tlog-tiles.

Leaf hash:  SHA-256(0x00 || data)
Node hash:  SHA-256(0x01 || left || right)

Only the verification functions (``root_from_inclusion``, ``verify_inclusion``,
``verify_consistency``) are part of the stable public API. The tree builder and
proof generators are provided so tests and examples can produce real proofs and
so callers can anchor their own evidence, but a production log would generate
these on the server side.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import List

__all__ = [
    "leaf_hash",
    "merkle_tree_hash",
    "inclusion_proof",
    "consistency_proof",
    "root_from_inclusion",
    "verify_inclusion",
    "verify_consistency",
]


def leaf_hash(data: bytes) -> bytes:
    """RFC 6962 leaf hash: SHA-256(0x00 || data)."""
    return hashlib.sha256(b"\x00" + data).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    """RFC 6962 interior node hash: SHA-256(0x01 || left || right)."""
    return hashlib.sha256(b"\x01" + left + right).digest()


def _largest_power_of_two_less_than(n: int) -> int:
    """Largest power of two k such that k < n <= 2k, for n >= 2."""
    if n < 2:
        raise ValueError("n must be >= 2")
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def merkle_tree_hash(leaves: List[bytes]) -> bytes:
    """Merkle Tree Hash (MTH) over a list of leaf *data* values (RFC 6962 2.1)."""
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaf_hash(leaves[0])
    k = _largest_power_of_two_less_than(n)
    return _node_hash(merkle_tree_hash(leaves[:k]), merkle_tree_hash(leaves[k:]))


def inclusion_proof(leaves: List[bytes], index: int) -> List[bytes]:
    """Audit path for ``leaves[index]`` (siblings ordered leaf to root)."""
    n = len(leaves)
    if not 0 <= index < n:
        raise ValueError("index out of range")
    return _inclusion(leaves, index)


def _inclusion(leaves: List[bytes], m: int) -> List[bytes]:
    n = len(leaves)
    if n == 1:
        return []
    k = _largest_power_of_two_less_than(n)
    if m < k:
        return _inclusion(leaves[:k], m) + [merkle_tree_hash(leaves[k:])]
    return _inclusion(leaves[k:], m - k) + [merkle_tree_hash(leaves[:k])]


def consistency_proof(leaves: List[bytes], first: int) -> List[bytes]:
    """Consistency proof between tree sizes ``first`` and ``len(leaves)`` (RFC 6962 2.1.2)."""
    second = len(leaves)
    if not 0 < first <= second:
        raise ValueError("require 0 < first <= len(leaves)")
    return _subproof(first, leaves, True)


def _subproof(m: int, leaves: List[bytes], b: bool) -> List[bytes]:
    n = len(leaves)
    if m == n:
        return [] if b else [merkle_tree_hash(leaves)]
    k = _largest_power_of_two_less_than(n)
    if m <= k:
        return _subproof(m, leaves[:k], b) + [merkle_tree_hash(leaves[k:])]
    return _subproof(m - k, leaves[k:], False) + [merkle_tree_hash(leaves[:k])]


def root_from_inclusion(
    leaf_index: int, tree_size: int, computed_leaf_hash: bytes, proof: List[bytes]
) -> bytes:
    """Recompute the tree root from an inclusion proof (RFC 9162 2.1.3.2)."""
    if not 0 <= leaf_index < tree_size:
        raise ValueError("leaf_index out of range for tree_size")
    fn = leaf_index
    sn = tree_size - 1
    r = computed_leaf_hash
    for p in proof:
        if sn == 0:
            raise ValueError("inclusion proof too long")
        if (fn & 1) == 1 or fn == sn:
            r = _node_hash(p, r)
            if (fn & 1) == 0:
                while (fn & 1) == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = _node_hash(r, p)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        raise ValueError("inclusion proof too short")
    return r


def verify_inclusion(
    leaf_data: bytes,
    leaf_index: int,
    tree_size: int,
    proof: List[bytes],
    expected_root: bytes,
) -> bool:
    """Return True iff ``leaf_data`` is included at ``leaf_index`` under ``expected_root``."""
    try:
        computed = root_from_inclusion(leaf_index, tree_size, leaf_hash(leaf_data), proof)
    except ValueError:
        return False
    return hmac.compare_digest(computed, expected_root)


def verify_consistency(
    first_size: int,
    second_size: int,
    proof: List[bytes],
    first_root: bytes,
    second_root: bytes,
) -> bool:
    """Return True iff ``first_root`` is a consistent prefix of ``second_root`` (RFC 9162 2.1.4.2)."""
    if first_size <= 0 or first_size > second_size:
        return False
    if first_size == second_size:
        return not proof and hmac.compare_digest(first_root, second_root)
    path = list(proof)
    # If first is an exact power of two, prepend first_root to the path.
    if first_size & (first_size - 1) == 0:
        path = [first_root] + path
    if not path:
        return False
    fn = first_size - 1
    sn = second_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = path[0]
    sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if (fn & 1) == 1 or fn == sn:
            fr = _node_hash(c, fr)
            sr = _node_hash(c, sr)
            if (fn & 1) == 0:
                while (fn & 1) == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = _node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return (
        fn == 0
        and hmac.compare_digest(fr, first_root)
        and hmac.compare_digest(sr, second_root)
    )
