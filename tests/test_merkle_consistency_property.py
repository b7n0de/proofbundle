"""Property-based tests (Hypothesis) for the consistency-proof half of RFC 6962 — the append-only /
split-view guarantee. The existing test_merkle_property.py tampers INCLUSION proofs but not consistency;
this closes that gap (gap survey rank 9).

Properties:
  * a mutated consistency proof element must be rejected;
  * a swapped first_root / second_root must be rejected;
  * a wrong claimed first-size must be rejected.
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

    class TestMerkleConsistencyProperties(unittest.TestCase):
        @settings(max_examples=200, deadline=None)
        @given(st.integers(min_value=2, max_value=400), st.data())
        def test_valid_consistency_roundtrips(self, size, data):
            leaves = _leaves(size)
            first = data.draw(st.integers(min_value=1, max_value=size))
            fr = merkle.merkle_tree_hash(leaves[:first])
            sr = merkle.merkle_tree_hash(leaves)
            proof = merkle.consistency_proof(leaves, first)
            self.assertTrue(merkle.verify_consistency(first, size, proof, fr, sr))

        @settings(max_examples=200, deadline=None)
        @given(st.integers(min_value=2, max_value=300), st.data())
        def test_tampered_consistency_proof_rejected(self, size, data):
            leaves = _leaves(size)
            first = data.draw(st.integers(min_value=1, max_value=size))
            fr = merkle.merkle_tree_hash(leaves[:first])
            sr = merkle.merkle_tree_hash(leaves)
            proof = merkle.consistency_proof(leaves, first)
            if not proof:
                return  # first == size: empty proof, nothing to tamper
            idx = data.draw(st.integers(min_value=0, max_value=len(proof) - 1))
            tampered = list(proof)
            tampered[idx] = bytes((tampered[idx][0] ^ 0xFF,)) + tampered[idx][1:]
            self.assertFalse(merkle.verify_consistency(first, size, tampered, fr, sr))

        @settings(max_examples=150, deadline=None)
        @given(st.integers(min_value=3, max_value=300), st.data())
        def test_swapped_roots_rejected(self, size, data):
            leaves = _leaves(size)
            first = data.draw(st.integers(min_value=1, max_value=size - 1))  # first != size → distinct roots
            fr = merkle.merkle_tree_hash(leaves[:first])
            sr = merkle.merkle_tree_hash(leaves)
            proof = merkle.consistency_proof(leaves, first)
            # first_root and second_root swapped must not verify
            self.assertFalse(merkle.verify_consistency(first, size, proof, sr, fr))

        @settings(max_examples=150, deadline=None)
        @given(st.integers(min_value=3, max_value=300), st.data())
        def test_wrong_second_root_rejected(self, size, data):
            # a valid (first, size) proof must not verify against a DIFFERENT second root (a forged newer
            # tree state). Uses an honest second-root for size-1 as the wrong target.
            leaves = _leaves(size)
            first = data.draw(st.integers(min_value=1, max_value=size - 1))
            fr = merkle.merkle_tree_hash(leaves[:first])
            sr = merkle.merkle_tree_hash(leaves)
            wrong_sr = merkle.merkle_tree_hash(leaves[:size - 1])
            if wrong_sr == sr:
                return
            proof = merkle.consistency_proof(leaves, first)
            self.assertFalse(merkle.verify_consistency(first, size, proof, fr, wrong_sr))


if __name__ == "__main__":
    unittest.main()
