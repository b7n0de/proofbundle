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

THE DIGESTS ARE THE PIN, A SOURCE IS ONLY TRANSPORT. Measured 2026-09-25: the pinned commit
answers HTTP 404 for both files, and so does the GitHub API for the repository itself. The
author's site, which his mail names as the vector's address, still serves both files, and they
match the digests below byte for byte. So the fetcher asks the sources in order and takes the
first one that is reachable. An unreachable source moves on to the next one; a reachable source
that serves different bytes stops everything, because that is a finding, not an outage. The
output names which source served each file, so a line that says "upstream" is upstream.
"""
from __future__ import annotations

import hashlib
import sys
import urllib.request
from pathlib import Path

COMMIT = "db33ff3ff8ed439b3ebd97e5ef96facd7f49b65a"

#: (label, base URL), asked in this order.
SOURCES = (
    ("pinned commit",
     f"https://raw.githubusercontent.com/CSOAI-ORG/councilof-ai/{COMMIT}/public/interop/scrapi-ccf"),
    ("author's site", "https://councilof.ai/interop/scrapi-ccf"),
)

#: Measured 2026-09-25: the author's site answers 403 to urllib's default User-Agent and 200 to
#: this one, with the same bytes. The header names the tool instead of imitating a browser.
USER_AGENT = "proofbundle-vector-fetch/1 (+https://github.com/b7n0de/proofbundle)"

#: name -> (size in bytes, sha256) — as stated on the list and measured on 2026-09-04.
EXPECTED = {
    "data-hash-vector.json": (
        3243, "e137d34fb25246c5f9e09fe8a293ac1952a3c86d9a48a8b7ccb085c6bbffc72b"),
    "data-hash-tag-vector.json": (
        2415, "d8a03d6aa7398c24bf8f902cd22535256842d4018e650579a0446e4e99743fdb"),
}


def fetch_one(name: str, size: int, digest: str, sources=SOURCES, opener=urllib.request.urlopen):
    """(bytes, label, unreachable) for the first reachable source, or (None, None, unreachable).

    Raises ValueError when a reachable source serves bytes that do not match the pin.
    """
    unreachable = []
    for label, base in sources:
        try:
            req = urllib.request.Request(f"{base}/{name}", headers={"User-Agent": USER_AGENT})
            with opener(req, timeout=30) as fh:   # noqa: S310 — fixed https
                raw = fh.read()
        except OSError as exc:
            unreachable.append(f"{label}: {exc}")
            continue
        got = hashlib.sha256(raw).hexdigest()
        if len(raw) != size or got != digest:
            raise ValueError(f"MISMATCH for {name} from {label}: {len(raw)} B / {got}\n"
                             f"  expected      {size} B / {digest}\n"
                             "  Nothing written. These are not the bytes the list saw.")
        return raw, label, unreachable
    return None, None, unreachable


def main() -> int:
    here = Path(__file__).resolve().parent
    fetched = {}
    for name, (size, digest) in EXPECTED.items():
        try:
            raw, label, unreachable = fetch_one(name, size, digest)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        if raw is None:
            print(f"NOT MEASURABLE: {name} could not be fetched from any source "
                  f"({'; '.join(unreachable)}). This is not a verdict about the vector.",
                  file=sys.stderr)
            return 2
        fetched[name] = (raw, label, unreachable)
    # Written only once BOTH are verified, so a half-fetched pair never lands on disk.
    for name, (raw, label, unreachable) in fetched.items():
        (here / name).write_bytes(raw)
        skipped = f", not reachable: {'; '.join(unreachable)}" if unreachable else ""
        print(f"  {name:26s} {len(raw):5d} B  {hashlib.sha256(raw).hexdigest()[:16]}…  matches"
              f"  (served by the {label}{skipped})")
    print("Both vectors fetched and verified against the digests stated on the list.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
