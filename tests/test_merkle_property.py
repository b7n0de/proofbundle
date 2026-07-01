"""Property-based tests for the RFC 6962 Merkle logic (Hypothesis).

Complements the fixed round-trip + external-vector tests: for randomly sized trees
(up to several hundred leaves) and every leaf index, an inclusion proof pulled from
the tree must verify against the tree root; and a consistency proof between any
earlier size and the full size must verify. hypothesis is a dev dependency only.
"""
from __future__ import annotations

import unittest

try:
    from hypothesis import given, settings
    from hypothesis import strategies as st
except ImportError:  # pragma: no cover - dev-only dependency
    given = None

from proofbundle import merkle


def _leaves(n: int) -> list[bytes]:
    return [f"leaf-{i}".encode() for i in range(n)]


if given is not None:

    class TestMerkleProperties(unittest.TestCase):
        @settings(max_examples=200, deadline=None)
        @given(st.integers(min_value=1, max_value=400), st.data())
        def test_inclusion_proof_roundtrips(self, size, data):
            leaves = _leaves(size)
            index = data.draw(st.integers(min_value=0, max_value=size - 1))
            root = merkle.merkle_tree_hash(leaves)
            proof = merkle.inclusion_proof(leaves, index)
            self.assertTrue(
                merkle.verify_inclusion(leaves[index], index, size, proof, root),
                msg=f"inclusion failed size={size} index={index}")

        @settings(max_examples=200, deadline=None)
        @given(st.integers(min_value=2, max_value=400), st.data())
        def test_consistency_proof_roundtrips(self, size, data):
            leaves = _leaves(size)
            first = data.draw(st.integers(min_value=1, max_value=size))
            first_root = merkle.merkle_tree_hash(leaves[:first])
            second_root = merkle.merkle_tree_hash(leaves)
            proof = merkle.consistency_proof(leaves, first)
            self.assertTrue(
                merkle.verify_consistency(first, size, proof, first_root, second_root),
                msg=f"consistency failed first={first} size={size}")

        @settings(max_examples=100, deadline=None)
        @given(st.integers(min_value=1, max_value=200), st.data())
        def test_tampered_leaf_is_rejected(self, size, data):
            leaves = _leaves(size)
            index = data.draw(st.integers(min_value=0, max_value=size - 1))
            root = merkle.merkle_tree_hash(leaves)
            proof = merkle.inclusion_proof(leaves, index)
            self.assertFalse(
                merkle.verify_inclusion(b"TAMPERED", index, size, proof, root),
                msg=f"tampered leaf wrongly accepted size={size} index={index}")


if __name__ == "__main__":
    unittest.main()
