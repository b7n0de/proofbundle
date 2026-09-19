"""Two readings of the same specification, two roots — one vector each, and each fells the other.

WHY VECTORS AND NOT AN ASSERTION ABOUT THE CODE. Finding 4 by Henri Sirkkavaara in the Last Call
on the CCF profile: section 2.1 defines the Merkle Tree Hash, section 3.2 defines the leaf
computation, and a reader who applies both in sequence hashes every leaf twice. The question is
not which reading is nicer but which one this implementation ships, and a root is the only answer
that cannot be argued with.

THE DECISION, and it is not a preference. RFC 6962 2.1 defines MTH over the list of DATA entries
D[n], and the single-entry case is itself the leaf hash: MTH({d(0)}) = SHA-256(0x00 || d(0)).
`merkle_tree_hash` does exactly that, and the public verification surface `verify_inclusion` takes
`leaf_data` and applies `leaf_hash` itself. Reading A is therefore the one this product ships;
reading B builds a tree over SHA-256(0x00 || SHA-256(0x00 || data)), which no log ever built.

EACH VECTOR FELLS THE OTHER READING. The root under A is not merely different from the root under
B — an implementation that follows B cannot produce the A vector from the same entries, and the
reverse holds too. That is what makes these two values a catch and not a snapshot: pin only one
and a silent switch to the other reading still passes.

THE INPUT IS FIXED AND PRINTED. Five entries, deliberately not a power of two, because a balanced
tree hides a difference at the split point behind a symmetric shape.
"""
from __future__ import annotations

import unittest

from proofbundle.merkle import inclusion_proof, leaf_hash, merkle_tree_hash, verify_inclusion

#: The same five entries the measurement tool uses, so the two can be held against each other.
ENTRIES: tuple[bytes, ...] = (
    b"entry-0: the first eval run",
    b"entry-1: the second eval run",
    b"entry-2: a run that was aborted",
    b"entry-3: the run that was published",
    b"entry-4: a fifth entry, so the tree is uneven",
)

#: Reading A, section 2.1 alone: the data entries go to MTH, which applies the leaf hash itself.
#: THIS IS THE READING THIS IMPLEMENTATION SHIPS.
WURZEL_LESART_A = "72458930727ef63aeb4e6c92adcdc57b5e601d73a6c7415b6c00427ccc848fae"

#: Reading B, section 3.2 first and 2.1 after: the caller computes the leaf hashes and hands those
#: to MTH, so every leaf is hashed twice. Pinned so a silent move to this reading is a red test,
#: not a mystery about a root that stopped matching.
WURZEL_LESART_B = "b3ee65c562d59fb97800e62bfa60ff82fdbbe1945f0817544da0ed3c817f56b9"


class TestZweiLesartenZweiWurzeln(unittest.TestCase):

    def test_lesart_a_ist_die_ausgelieferte(self):
        self.assertEqual(merkle_tree_hash(list(ENTRIES)).hex(), WURZEL_LESART_A)

    def test_lesart_b_ergibt_eine_andere_wurzel(self):
        doppelt = [leaf_hash(e) for e in ENTRIES]
        self.assertEqual(merkle_tree_hash(doppelt).hex(), WURZEL_LESART_B)

    def test_die_zwei_wurzeln_sind_verschieden(self):
        """The whole point. If these ever coincide, the two sections stopped diverging and every
        sentence written about this finding needs re-measuring."""
        self.assertNotEqual(WURZEL_LESART_A, WURZEL_LESART_B)

    def test_jeder_vektor_faellt_die_andere_lesart(self):
        """The catch, stated as the two implications that matter.

        An implementation following B cannot produce the A vector from these entries, and one
        following A cannot produce the B vector. Pinning a single root would leave a silent switch
        between the readings undetected in one of the two directions."""
        unter_a = merkle_tree_hash(list(ENTRIES)).hex()
        unter_b = merkle_tree_hash([leaf_hash(e) for e in ENTRIES]).hex()
        self.assertEqual(unter_a, WURZEL_LESART_A)
        self.assertNotEqual(unter_a, WURZEL_LESART_B, "reading A must not reach the B vector")
        self.assertEqual(unter_b, WURZEL_LESART_B)
        self.assertNotEqual(unter_b, WURZEL_LESART_A, "reading B must not reach the A vector")

    def test_die_oeffentliche_pruefflaeche_akzeptiert_nur_lesart_a(self):
        """The decision is not only in a docstring, it is observable at the product's edge.

        `verify_inclusion` takes raw payload bytes and applies the leaf hash itself. It therefore
        verifies against the reading-A root and refuses the reading-B root, for the same leaf, the
        same index and the same proof. That is the measurement that settles which reading ships."""
        beweis = inclusion_proof(list(ENTRIES), 0)
        self.assertTrue(verify_inclusion(ENTRIES[0], 0, len(ENTRIES), beweis,
                                         bytes.fromhex(WURZEL_LESART_A)))
        self.assertFalse(verify_inclusion(ENTRIES[0], 0, len(ENTRIES), beweis,
                                          bytes.fromhex(WURZEL_LESART_B)))

    def test_lesart_b_ist_genau_der_doppelt_angewandte_blatt_hash(self):
        """Names the CAUSE, so the finding does not shrink to two opaque hex strings."""
        einmal = leaf_hash(ENTRIES[0])
        self.assertEqual(leaf_hash(einmal), merkle_tree_hash([einmal]))


if __name__ == "__main__":
    unittest.main()
