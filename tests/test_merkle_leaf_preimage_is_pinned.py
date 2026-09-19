"""The leaf preimage is the raw payload, and the other reading of the same document must fail.

WHAT THIS ANSWERS. Finding 4 of the Last Call on the CCF profile asks whether the Merkle Tree Hash
definition in one section and the leaf computation in another can be read together, and whether a
reader who applies both gets a different root. Measured against the shipped reader: yes.

    reading A, MTH over the raw entries          72458930727ef63a...
    reading B, MTH over pre-computed leaves      b3ee65c562d59fb9...

RFC 6962 settles which one is meant. MTH is defined over the list of DATA entries and applies the
leaf hash itself, so a caller hands MTH the payloads. Reading B hashes every leaf twice and builds
the tree over SHA-256(0x00 || SHA-256(0x00 || data)). SPEC.md section 5 now says this in words;
this file is the executable half, so the sentence cannot quietly leave the document.

WHY THE EXPECTED ROOT IS RECOMPUTED HERE AND NOT IMPORTED. A vector taken from the module under
test compares the module to itself and would survive any change made to both at once. The expected
value below is derived from hashlib with its own recursion, a different error geometry, and no
import of the tree builder.

HONEST LIMIT. One fixed input of five entries against this checkout. It pins what this reader does
and what the document now says; it is not a statement about every conforming implementation.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from proofbundle.merkle import leaf_hash, merkle_tree_hash

REPO = Path(__file__).resolve().parents[1]

#: Five entries, deliberately not a power of two. A balanced tree hides a difference at the split
#: point behind a symmetric shape, and three entries never reach the uneven right subtree.
ENTRIES: tuple[bytes, ...] = (
    b"entry-0: the first eval run",
    b"entry-1: the second eval run",
    b"entry-2: a run that was aborted",
    b"entry-3: the run that was published",
    b"entry-4: a fifth entry, so the tree is uneven",
)


def _independent_mth(entries: list[bytes]) -> bytes:
    """RFC 6962 MTH written out here, from hashlib, with no import of the tree builder."""
    if not entries:
        return hashlib.sha256(b"").digest()
    if len(entries) == 1:
        return hashlib.sha256(b"\x00" + entries[0]).digest()
    k = 1
    while k * 2 < len(entries):
        k *= 2
    left = _independent_mth(entries[:k])
    right = _independent_mth(entries[k:])
    return hashlib.sha256(b"\x01" + left + right).digest()


#: The vector for the pinned reading, computed by the independent function above.
VECTOR_READING_A = _independent_mth(list(ENTRIES))


def test_VECTOR_reading_a_is_what_the_shipped_reader_builds():  # noqa: N802
    """The pinned reading: MTH receives the raw payloads and applies the leaf hash itself."""
    assert merkle_tree_hash(list(ENTRIES)) == VECTOR_READING_A
    assert VECTOR_READING_A.hex().startswith("72458930727ef63a"), VECTOR_READING_A.hex()


def test_VECTOR_reading_b_must_FAIL_against_the_pinned_root():  # noqa: N802
    """The other reading of the same document, and the point of this contract.

    A caller who performs the leaf computation first and hands the results to MTH gets a root that
    is NOT the one the log published. The wrong vector has to fail, otherwise the decision in
    SPEC.md would be a preference rather than a rule.
    """
    reading_b = merkle_tree_hash([leaf_hash(e) for e in ENTRIES])
    assert reading_b != VECTOR_READING_A, (
        "the two readings agree, so this reader no longer distinguishes them and the pinned "
        "sentence in SPEC.md has lost its subject")
    assert reading_b.hex().startswith("b3ee65c562d59fb9"), reading_b.hex()


def test_reading_b_is_exactly_the_double_hash_and_not_some_other_difference():
    """WHY the roots differ, not merely THAT they differ.

    Without this, the case above would also pass if the two readings differed for an unrelated
    reason, and the explanation in SPEC.md would be unsupported.
    """
    twice = hashlib.sha256(b"\x00" + leaf_hash(ENTRIES[0])).digest()
    assert leaf_hash(leaf_hash(ENTRIES[0])) == twice
    assert merkle_tree_hash([leaf_hash(e) for e in ENTRIES]) == _independent_mth(
        [leaf_hash(e) for e in ENTRIES])


@pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 6, 7, 8, 9])
def test_the_two_readings_differ_at_every_tree_shape_above_one_entry(n: int):
    """A single fixed input could be a lucky shape. Every size from one to nine is checked.

    At n = 1 the tree is the leaf itself, so double hashing still changes the root; the case is
    kept rather than skipped, because a reader who expects an exception there should see one here.
    """
    entries = list(ENTRIES[:n]) if n <= len(ENTRIES) else [
        f"entry-{i}: generated".encode() for i in range(n)]
    a = merkle_tree_hash(entries)
    b = merkle_tree_hash([leaf_hash(e) for e in entries])
    assert a != b, f"the readings agree at n={n}, so the difference is shape-dependent"


def test_THE_DECISION_STAYS_IN_THE_DOCUMENT():  # noqa: N802
    """SPEC.md must keep saying which reading is meant, and must name the preimage.

    A decision that lives only in a test is not a specification. If the paragraph is removed or
    softened, this goes red and the removal has to be deliberate.
    """
    # WHITESPACE IS NORMALISED FIRST. The sentences below are wrapped in the document, so a
    # literal search would break on a reflow rather than on a change of meaning, and a contract
    # that hangs on a line break is a contract about typography.
    spec = " ".join((REPO / "SPEC.md").read_text(encoding="utf-8").split())
    assert "The leaf preimage, pinned (normative)." in spec, (
        "SPEC.md no longer pins the leaf preimage")
    assert "RAW entry" in spec, "SPEC.md no longer says the preimage is the raw payload"
    assert "SHA-256(0x00 || SHA-256(0x00 || leaf_data))" in spec, (
        "SPEC.md no longer names the double-hashed construction it rejects")
    assert "MUST NOT accept a root computed the second way" in spec, (
        "SPEC.md no longer forbids the other reading")
