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

Exit code: 0 if the two readings agree, 1 if they differ, 2 when the checkout is not measured: a
usage error, or a module that does not import, raises whatever it raises, ends the process, or
returns something that is no root. The checkout's module runs in a CHILD process of this tool, which
hands its readings back on a channel of their own, a file in a fresh temporary directory; this
process decides the exit code and prints the document. Exit 0 or 1 therefore needs a child that
exited 0 and left one complete, well-formed record; a child that exits with another code, ends by a
signal, runs longer than the time it is given, or leaves no record, a garbled one or more than one,
is exit 2 with the reason on stderr. Measured on 2026-09-26 before this was so, each in the
measuring process itself: an `asyncio.CancelledError` or a `GeneratorExit` from the module ended
the run with a traceback and exit 1; a root of a `bytes` subclass whose `hex()` returns an object
did the same from `json.dumps`; `atexit.register(print, ...)` on import, or a thread printing later,
put a line after the JSON document; and `os._exit(0)` in a call exited 0, "the readings agree",
with no output.

What the module prints goes to this tool's stderr, whenever it prints it and whether through
`print` or straight to file descriptor 1, because the child's stdout is this tool's stderr; so
`--json` stays one JSON document. A `KeyboardInterrupt` in this tool's own process comes from the
user and ends the run as Python ends it; one the module raises ends the child and is exit 2.
Named limit: the child is given the channel's path, so a module that reads its process's arguments
can write a record of its own there; a record that is not well-formed is refused, a well-formed one
is not told apart.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import signal
import subprocess
import sys
import tempfile
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


class NotMeasured(Exception):
    """The checkout was not measured, and the text says why. It exits 2, never a verdict code."""


def _load_merkle(checkout: Path):
    """Import the SHIPPED module from the given checkout, never a copy of it."""
    src = checkout / "src"
    if not (src / "proofbundle" / "merkle.py").is_file():
        # A usage error, so exit 2 as the docstring says: `SystemExit(<text>)` exits 1, which here
        # reads as "the two readings differ" (a sweep for that class, 2026-09-26).
        raise NotMeasured(f"no proofbundle/merkle.py under {src}")
    sys.path.insert(0, str(src))
    # A module that is there and does not import is the same kind of stop: its traceback exited 1,
    # "the two readings differ" (a review lens, measured 2026-09-26 with a merkle.py that did not parse).
    # `SystemExit` is not an `Exception`: a module that calls `sys.exit(1)` on import ended this tool
    # with 1 and no output at all (two review lenses on the stack, run 8, measured 2026-09-26), and
    # neither is a `GeneratorExit`. This runs in the child, where any of them can only be the module's.
    try:
        import proofbundle.merkle as m  # noqa: E402
    except BaseException as exc:  # noqa: BLE001 - whatever the checkout does on import, it is not measured
        raise NotMeasured(f"proofbundle.merkle under {src} does not import: {_said(exc)}") from None
    return m


def reading_a(m, entries: tuple[bytes, ...]) -> bytes:
    """Section 2.1 alone: hand MTH the raw data entries, as the module's own docstring says."""
    return m.merkle_tree_hash(list(entries))


def reading_b(m, entries: tuple[bytes, ...]) -> bytes:
    """Section 3.2 first: compute each leaf, then hand the leaves to MTH."""
    leaves = [m.leaf_hash(e) for e in entries]
    return m.merkle_tree_hash(leaves)


#: The record the child hands back, and the one schema it may carry.
CHILD_SCHEMA = "proofbundle.merkle_two_readings.child.v1"
_READINGS = ("reading_a", "reading_b", "leaf_once", "leaf_twice")
_HEX = re.compile(r"\A(?:[0-9a-f]{2})*\Z")
#: A record is four digests and their names; a channel larger than this is not a record.
_CHANNEL_CAP = 64 * 1024
#: The child hashes five short entries; a child that runs longer than this is not measuring.
CHILD_SECONDS = 300


def _root(value, what: str) -> str:
    """A reading as the bytes the module returned, hex-encoded here and not by the value itself: a
    `bytes` subclass whose `hex()` returned an object broke the document (measured 2026-09-26)."""
    if not issubclass(type(value), bytes):
        raise NotMeasured(f"{what} returned {type(value).__name__}, not bytes")
    return bytes.hex(value)


def _readings(checkout: Path) -> dict:
    """The four values the document is built from, taken through the SHIPPED module (the child)."""
    m = _load_merkle(checkout)
    return {"reading_a": _root(reading_a(m, ENTRIES), "merkle_tree_hash under reading A"),
            "reading_b": _root(reading_b(m, ENTRIES), "merkle_tree_hash under reading B"),
            "leaf_once": _root(m.leaf_hash(ENTRIES[0]), "leaf_hash"),
            "leaf_twice": _root(m.leaf_hash(m.leaf_hash(ENTRIES[0])), "leaf_hash over a leaf hash")}


def _said(exc: BaseException) -> str:
    try:
        return f"{type(exc).__name__}: {exc}"
    except BaseException:  # noqa: BLE001 - an exception whose text raises is still named
        return f"{type(exc).__name__} (its text could not be read)"


def _child(checkout: Path, channel: Path) -> int:
    """Run in the child process: measure, and write ONE record to the channel, whatever happens.

    Whatever the module raises is named in the record, `BaseException` included: a `GeneratorExit`,
    an `asyncio.CancelledError`, a `SystemExit`, a `KeyboardInterrupt`. The user's interrupt reaches
    the parent as well and ends the run there, so a record is only read when it came from the module."""
    try:
        record = {"schema": CHILD_SCHEMA, "readings": _readings(checkout)}
    except NotMeasured as stop:
        record = {"schema": CHILD_SCHEMA, "not_measured": str(stop)}
    except BaseException as exc:  # noqa: BLE001 - whatever the checkout's module does, it is not measured
        record = {"schema": CHILD_SCHEMA,
                  "not_measured": f"the checkout under {checkout} does not measure: {_said(exc)}"}
    channel.write_text(json.dumps(record), encoding="ascii")
    return 0


def _refuse_constant(name: str):
    raise ValueError(f"{name} is no JSON value")


def _record(channel: Path) -> dict:
    """The child's record, read strictly: one JSON object in the one schema, and nothing after it."""
    try:
        with channel.open("rb") as fh:
            raw = fh.read(_CHANNEL_CAP + 1)
    except OSError as exc:
        raise NotMeasured(f"the measuring child left no record ({exc.strerror})") from None
    if len(raw) > _CHANNEL_CAP:
        raise NotMeasured(f"the child's record is larger than {_CHANNEL_CAP} bytes, so it is no record")
    try:
        record = json.loads(raw.decode("ascii"), parse_constant=_refuse_constant)
    except (UnicodeDecodeError, ValueError) as exc:
        raise NotMeasured(f"the child's record does not read as one JSON document: {exc}") from None
    if not isinstance(record, dict) or record.get("schema") != CHILD_SCHEMA:
        raise NotMeasured("the child's record does not carry its schema")
    if set(record) == {"schema", "not_measured"} and isinstance(record["not_measured"], str):
        raise NotMeasured(record["not_measured"])
    readings = record.get("readings")
    if set(record) != {"schema", "readings"} or not isinstance(readings, dict) \
            or set(readings) != set(_READINGS) \
            or not all(isinstance(readings[k], str) and _HEX.match(readings[k]) for k in _READINGS):
        raise NotMeasured("the child's record is not the four readings as hex, so it is garbled")
    return readings


def _ended(returncode: int) -> str:
    if returncode < 0:
        try:
            return f"signal {signal.Signals(-returncode).name}"
        except ValueError:
            return f"signal {-returncode}"
    return f"exit code {returncode}"


def _take_readings(checkout: Path) -> dict:
    """Start the child, wait for it, and read its record; every way that is not a clean record is a stop."""
    with tempfile.TemporaryDirectory(prefix="merkle-two-readings-") as tmp:
        channel = Path(tmp) / "readings.json"
        command = [sys.executable, "-B", str(Path(__file__).resolve()), "--child", str(channel),
                   "--checkout", str(checkout)]
        sys.stdout.flush()
        sys.stderr.flush()
        try:
            out = sys.stderr.fileno()          # the child's stdout IS this tool's stderr
        except (AttributeError, OSError, ValueError):
            out = None
        try:
            proc = subprocess.run(command, stdin=subprocess.DEVNULL,
                                  stdout=out if out is not None else subprocess.PIPE,
                                  stderr=out if out is not None else subprocess.STDOUT,
                                  timeout=CHILD_SECONDS, check=False)
        except subprocess.TimeoutExpired:
            raise NotMeasured(f"the measuring child did not finish within {CHILD_SECONDS} s") from None
        except OSError as exc:
            raise NotMeasured(f"the measuring child did not start: {exc.strerror}") from None
        if out is None and proc.stdout:
            sys.stderr.write(proc.stdout.decode("utf-8", "backslashreplace"))
        if proc.returncode != 0:
            raise NotMeasured(f"the measuring child ended with {_ended(proc.returncode)}, so what it "
                              "left is not a measurement")
        return _record(channel)


def measure(checkout: Path) -> dict:
    """The document, built in this process from the readings the child took of the SHIPPED module."""
    r = _take_readings(checkout)
    a, b = r["reading_a"], r["reading_b"]

    # A third value, computed here from the primitives rather than through MTH, showing WHY the
    # two differ when they differ: under reading B the leaf hash lands on an already-hashed leaf.
    twice = hashlib.sha256(b"\x00" + bytes.fromhex(r["leaf_once"])).hexdigest()

    return {
        "schema": "proofbundle.merkle_two_readings.v1",
        "checkout": str(checkout),
        "entries": [e.decode("utf-8") for e in ENTRIES],
        "entry_count": len(ENTRIES),
        "reading_a_section_2_1": a,
        "reading_b_section_3_2_then_2_1": b,
        "roots_differ": a != b,
        "leaf_hashed_once": r["leaf_once"],
        "leaf_hashed_twice": twice,
        "reading_b_hashes_each_leaf_twice": r["leaf_twice"] == twice,
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
    ap.add_argument("--child", metavar="CHANNEL", help=argparse.SUPPRESS)
    a = ap.parse_args(argv)
    if a.child:
        return _child(Path(a.checkout).resolve(), Path(a.child))
    # The module runs in a child process, and this process judges what comes back (a review of the
    # stack at 1ecc2aca, measured 2026-09-26): a `BaseException` that is no `Exception`, a root whose
    # own `hex()` misbehaves, output after the document and `os._exit` each got past the in-process
    # guards, the last as exit 0. A `KeyboardInterrupt` here is the user's and ends the run.
    try:
        e = measure(Path(a.checkout).resolve())
    except NotMeasured as stop:
        print(stop, file=sys.stderr)
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
