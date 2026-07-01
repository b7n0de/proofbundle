import unittest

from proofbundle import merkle


class TestInclusion(unittest.TestCase):
    def test_roundtrip_all_sizes(self):
        for n in range(1, 33):
            leaves = [f"leaf-{i}".encode() for i in range(n)]
            root = merkle.merkle_tree_hash(leaves)
            for i in range(n):
                proof = merkle.inclusion_proof(leaves, i)
                self.assertTrue(
                    merkle.verify_inclusion(leaves[i], i, n, proof, root),
                    msg=f"n={n} i={i}",
                )

    def test_tampered_leaf_fails(self):
        leaves = [f"leaf-{i}".encode() for i in range(8)]
        root = merkle.merkle_tree_hash(leaves)
        proof = merkle.inclusion_proof(leaves, 3)
        self.assertFalse(merkle.verify_inclusion(b"wrong", 3, 8, proof, root))

    def test_wrong_index_fails(self):
        leaves = [f"leaf-{i}".encode() for i in range(8)]
        root = merkle.merkle_tree_hash(leaves)
        proof = merkle.inclusion_proof(leaves, 3)
        self.assertFalse(merkle.verify_inclusion(leaves[3], 4, 8, proof, root))

    def test_wrong_root_fails(self):
        leaves = [f"leaf-{i}".encode() for i in range(8)]
        proof = merkle.inclusion_proof(leaves, 3)
        self.assertFalse(
            merkle.verify_inclusion(leaves[3], 3, 8, proof, b"\x00" * 32)
        )


class TestConsistency(unittest.TestCase):
    def test_roundtrip_all_pairs(self):
        for n in range(1, 25):
            leaves = [f"l-{i}".encode() for i in range(n)]
            root_n = merkle.merkle_tree_hash(leaves)
            for m in range(1, n + 1):
                root_m = merkle.merkle_tree_hash(leaves[:m])
                proof = merkle.consistency_proof(leaves, m)
                self.assertTrue(
                    merkle.verify_consistency(m, n, proof, root_m, root_n),
                    msg=f"m={m} n={n}",
                )

    def test_tampered_first_root_fails(self):
        leaves = [f"l-{i}".encode() for i in range(10)]
        root_10 = merkle.merkle_tree_hash(leaves)
        proof = merkle.consistency_proof(leaves, 5)
        bad = merkle.merkle_tree_hash([b"x"] * 5)
        self.assertFalse(merkle.verify_consistency(5, 10, proof, bad, root_10))


if __name__ == "__main__":
    unittest.main()
