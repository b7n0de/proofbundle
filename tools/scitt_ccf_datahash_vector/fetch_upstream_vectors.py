#!/usr/bin/env python3
"""Fetch the two upstream SCITT CCF vectors at their pinned commit, and verify them.

WHY A FETCHER AND NOT A COPY. `data-hash-vector.json` and `data-hash-tag-vector.json` are
Nicholas Vokes' artefacts, contributed to the `scitt@ietf.org` list. Re-publishing someone
else's files inside this repository would make this directory look like their source, and it
is not. Fetching them at a pinned commit keeps the provenance where it belongs.

AND IT MAKES THE CHECK PART OF THE REPRODUCTION. A vendored copy is trusted silently; a fetch
with a digest comparison states, every single run, that the bytes are the ones the list saw.
The expected digests below were measured on 2026-09-04 against the sizes and digests stated
in the mail itself.

FAIL-CLOSED: a size or digest mismatch aborts and writes nothing. A vector that is not the
published one is not a weaker input, it is a different question.
"""
from __future__ import annotations

import hashlib
import sys
import urllib.request
from pathlib import Path

COMMIT = "db33ff3ff8ed439b3ebd97e5ef96facd7f49b65a"
BASE = (f"https://raw.githubusercontent.com/CSOAI-ORG/councilof-ai/{COMMIT}"
        "/public/interop/scrapi-ccf")

#: name -> (size in bytes, sha256) — as stated on the list and measured on 2026-09-04.
EXPECTED = {
    "data-hash-vector.json": (
        3243, "e137d34fb25246c5f9e09fe8a293ac1952a3c86d9a48a8b7ccb085c6bbffc72b"),
    "data-hash-tag-vector.json": (
        2415, "d8a03d6aa7398c24bf8f902cd22535256842d4018e650579a0446e4e99743fdb"),
}


def main() -> int:
    here = Path(__file__).resolve().parent
    for name, (size, digest) in EXPECTED.items():
        url = f"{BASE}/{name}"
        try:
            with urllib.request.urlopen(url, timeout=30) as fh:   # noqa: S310 — pinned https
                raw = fh.read()
        except OSError as exc:
            print(f"NOT MEASURABLE: {name} could not be fetched ({exc}). "
                  "This is not a verdict about the vector.", file=sys.stderr)
            return 2
        got = hashlib.sha256(raw).hexdigest()
        if len(raw) != size or got != digest:
            print(f"MISMATCH for {name}: {len(raw)} B / {got}\n"
                  f"  expected      {size} B / {digest}\n"
                  "  Nothing written. These are not the bytes the list saw.", file=sys.stderr)
            return 1
        (here / name).write_bytes(raw)
        print(f"  {name:26s} {len(raw):5d} B  {got[:16]}…  matches")
    print("Both vectors fetched at the pinned commit and verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
