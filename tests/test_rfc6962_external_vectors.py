"""Verify proofbundle's Merkle logic against EXTERNAL RFC 6962 test vectors.

These vectors do not come from proofbundle itself — they are vendored from an
independent RFC 6962 implementation (see tests/fixtures/rfc6962_vectors.json →
`source` + `commit`). Passing them proves the Merkle logic is RFC-conformant, not
merely self-consistent. The round-trip and Hypothesis property tests cover
self-consistency; this covers external conformance.

Fixture shape (tests/fixtures/rfc6962_vectors.json):
  {
    "source": "<repo URL>", "commit": "<hash>", "note": "...",
    "inclusion": [
      {"leaves_hex": ["..", ".."], "leaf_index": 1, "tree_size": 4,
       "root_hex": "..", "proof_hex": ["..", ".."]}
    ],
    "consistency": [
      {"leaves_hex": [...], "first": 3, "second": 7,
       "first_root_hex": "..", "second_root_hex": "..", "proof_hex": [".."]}
    ]
  }
Leaves are given as hex of the raw leaf DATA (proofbundle applies the RFC 6962
leaf hash 0x00||data itself).
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path

from proofbundle import merkle

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "rfc6962_vectors.json"


def _load():
    if not FIXTURE.exists():
        return None
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


@unittest.skipIf(_load() is None, "external RFC 6962 vectors not vendored yet (tests/fixtures/rfc6962_vectors.json)")
class TestExternalRfc6962Vectors(unittest.TestCase):
    def setUp(self):
        self.data = _load()

    def test_source_is_documented(self):
        self.assertTrue(self.data.get("source"), "vectors must document their source repo")

    def test_inclusion_vectors(self):
        cases = self.data.get("inclusion", [])
        self.assertTrue(cases, "expected at least one external inclusion vector")
        for i, c in enumerate(cases):
            leaves = [bytes.fromhex(h) for h in c["leaves_hex"]]
            proof = [bytes.fromhex(h) for h in c["proof_hex"]]
            root = bytes.fromhex(c["root_hex"])
            # proofbundle recomputes the root from the leaf DATA + proof and must match.
            self.assertTrue(
                merkle.verify_inclusion(leaves[c["leaf_index"]], c["leaf_index"], c["tree_size"], proof, root),
                msg=f"external inclusion vector #{i} failed")
            # and its own tree hash over the leaves must equal the stated root.
            self.assertEqual(merkle.merkle_tree_hash(leaves), root, f"tree-hash mismatch on vector #{i}")

    def test_consistency_vectors(self):
        # NOTE: transparency-dev's testdata/consistency/ files are EMPTY at the pinned commit, so these
        # consistency vectors are computed for the SAME canonical 8-leaf tree; each `second_root_hex` is
        # anchored to the EXTERNALLY-published size-8 root (see the assertion below), so a broken
        # consistency verifier fails against external truth — not merely self-consistent.
        cases = self.data.get("consistency", [])
        self.assertTrue(cases, "expected at least one consistency vector (must not be a vacuous pass)")
        external_size8_root = self.data["inclusion"][0]["root_hex"]
        for i, c in enumerate(cases):
            proof = [bytes.fromhex(h) for h in c["proof_hex"]]
            fr, sr = bytes.fromhex(c["first_root_hex"]), bytes.fromhex(c["second_root_hex"])
            # the target (size-8) root MUST be the externally-published canonical root
            self.assertEqual(c["second_root_hex"], external_size8_root,
                             f"consistency vector #{i} second_root is not the external published root")
            self.assertTrue(merkle.verify_consistency(c["first"], c["second"], proof, fr, sr),
                            msg=f"consistency vector #{i} failed")
            # negative: a tampered proof element must be rejected (the verifier is not trivially accepting)
            if proof:
                bad = list(proof)
                bad[0] = bytes((bad[0][0] ^ 0xFF,)) + bad[0][1:]
                self.assertFalse(merkle.verify_consistency(c["first"], c["second"], bad, fr, sr),
                                 msg=f"consistency vector #{i} accepted a tampered proof")


if __name__ == "__main__":
    unittest.main()
