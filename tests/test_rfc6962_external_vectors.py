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
        for i, c in enumerate(self.data.get("consistency", [])):
            proof = [bytes.fromhex(h) for h in c["proof_hex"]]
            self.assertTrue(
                merkle.verify_consistency(c["first"], c["second"], proof,
                                          bytes.fromhex(c["first_root_hex"]), bytes.fromhex(c["second_root_hex"])),
                msg=f"external consistency vector #{i} failed")


if __name__ == "__main__":
    unittest.main()
