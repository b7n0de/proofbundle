#!/usr/bin/env python3
"""Two readings of the same document, two Merkle roots — measured against the shipped reader.

WHAT THIS ANSWERS. Henri Sirkkavaara, finding 4 in the Last Call on the CCF profile: the Merkle
Tree Hash definition in section 2.1 and the leaf computation in section 3.2 of the same document
can be read together, and a reader who applies both hashes each leaf twice. The question is
whether that produces a different root in a real implementation, not in principle.

THE SUBJECT IS THE SHIPPED READER, not a model of one. This script imports
``proofbundle.merkle`` from the checkout it is pointed at and calls the shipped functions. A
reimplementation would answer a question about this script instead of about the product.

THE TWO READINGS, stated before the run so the result cannot be fitted to them:

  Reading A, section 2.1 alone. MTH is defined over a list of DATA entries, and the leaf hash
  SHA-256(0x00 || data) is applied by MTH itself. A caller hands over the payloads.

  Reading B, section 3.2 first, then 2.1. The leaf computation is read as a separate step the
  caller performs, and its results are then handed to MTH as the tree's leaves.

If MTH applies the leaf hash internally, reading B hashes every leaf twice: the tree is built over
SHA-256(0x00 || SHA-256(0x00 || data)) instead of SHA-256(0x00 || data). A reader who follows both
sections in order then does not get the tree the log built.

NO CLAIM RESTS ON A GATE VERDICT. Version 6.0.0 carries PARTIAL_GATE_NO_WITHSTANDS. What follows
is a measurement, not a seal, and it says only what the two printed roots say.

HONEST LIMIT. One fixed input of five entries against one checkout. It says what this reader does,
not what every conforming implementation must do.

Exit code: 0 if the two readings agree, 1 if they differ, 2 on a usage error or a checkout whose
module does not import or raises when the readings call it.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

#: The input is fixed and printed with the result, so anyone can recompute both roots by hand.
#: Five entries, deliberately not a power of two: a balanced tree would hide a difference at the
#: split point behind a symmetric shape, and three would not exercise the uneven right subtree.
ENTRIES: tuple[bytes, ...] = (
    b"entry-0: the first eval run",
    b"entry-1: the second eval run",
    b"entry-2: a run that was aborted",
    b"entry-3: the run that was published",
    b"entry-4: a fifth entry, so the tree is uneven",
)


def _load_merkle(checkout: Path):
    """Import the SHIPPED module from the given checkout, never a copy of it."""
    src = checkout / "src"
    if not (src / "proofbundle" / "merkle.py").is_file():
        # A usage error, so exit 2 as the docstring says: `SystemExit(<text>)` exits 1, which here
        # reads as "the two readings differ" (a sweep for that class, 2026-09-26).
        print(f"no proofbundle/merkle.py under {src}", file=sys.stderr)
        raise SystemExit(2)
    sys.path.insert(0, str(src))
    # A module that is there and does not import is the same kind of stop: its traceback exited 1,
    # "the two readings differ" (a review lens, measured 2026-09-26 with a merkle.py that did not parse).
    try:
        import proofbundle.merkle as m  # noqa: E402
    except Exception as exc:  # noqa: BLE001 - whatever the checkout raises on import, it is not measured
        print(f"proofbundle.merkle under {src} does not import: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
    return m


def reading_a(m, entries: tuple[bytes, ...]) -> bytes:
    """Section 2.1 alone: hand MTH the raw data entries, as the module's own docstring says."""
    return m.merkle_tree_hash(list(entries))


def reading_b(m, entries: tuple[bytes, ...]) -> bytes:
    """Section 3.2 first: compute each leaf, then hand the leaves to MTH."""
    leaves = [m.leaf_hash(e) for e in entries]
    return m.merkle_tree_hash(leaves)


def measure(checkout: Path) -> dict:
    m = _load_merkle(checkout)
    a, b = reading_a(m, ENTRIES), reading_b(m, ENTRIES)

    # A third value, computed here from the primitives rather than through MTH, showing WHY the
    # two differ when they differ: under reading B the leaf hash lands on an already-hashed leaf.
    twice = hashlib.sha256(b"\x00" + m.leaf_hash(ENTRIES[0])).digest()

    return {
        "schema": "proofbundle.merkle_two_readings.v1",
        "checkout": str(checkout),
        "entries": [e.decode("utf-8") for e in ENTRIES],
        "entry_count": len(ENTRIES),
        "reading_a_section_2_1": a.hex(),
        "reading_b_section_3_2_then_2_1": b.hex(),
        "roots_differ": a != b,
        "leaf_hashed_once": m.leaf_hash(ENTRIES[0]).hex(),
        "leaf_hashed_twice": twice.hex(),
        "reading_b_hashes_each_leaf_twice": m.leaf_hash(m.leaf_hash(ENTRIES[0])) == twice,
        "verdict": "TWO_ROOTS" if a != b else "ONE_ROOT",
        "reason": (
            "The two readings of the same document produce DIFFERENT roots over the same input. "
            "MTH applies the leaf hash itself, so performing the section 3.2 leaf computation "
            "first hashes every leaf twice."
            if a != b else
            "Both readings produce the SAME root over this input. On this implementation the two "
            "sections do not diverge."),
        "limit": (
            "Measured over one fixed input of five entries against one checkout. It says what "
            "this reader does, not what every conforming implementation must do, and it rests on "
            "no gate verdict."),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--checkout", default=".",
                    help="path to a proofbundle checkout (the directory holding src/proofbundle)")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    # The whole measurement, not the import alone: a module that imports and then raises when called
    # (a missing `leaf_hash`, an error inside `merkle_tree_hash`) ended with a traceback and exit 1,
    # "the two readings differ" (a review lens on the stack, run 7, measured 2026-09-26).
    try:
        e = measure(Path(a.checkout).resolve())
    except Exception as exc:  # noqa: BLE001 - whatever the checkout's module raises, it is not measured
        print(f"the checkout under {a.checkout} does not measure: {type(exc).__name__}: {exc}",
              file=sys.stderr)
        return 2
    if a.json:
        print(json.dumps(e, ensure_ascii=False, indent=2))
    else:
        print(f"input: {e['entry_count']} entries, fixed in this file")
        print(f"  reading A (2.1 alone)          {e['reading_a_section_2_1']}")
        print(f"  reading B (3.2 then 2.1)       {e['reading_b_section_3_2_then_2_1']}")
        print(f"  they differ: {e['roots_differ']}   ->  {e['verdict']}")
        print(f"  {e['reason']}")
        print(f"  limit: {e['limit']}")
    return 1 if e["roots_differ"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
