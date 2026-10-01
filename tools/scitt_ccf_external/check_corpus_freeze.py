#!/usr/bin/env python3
"""Check the freeze of the policy-boundary corpus, rounds 1 to 3, against a hash given from outside.

Run from the repository root at the freeze commit, with Python's standard library and git only:

    python3 tools/scitt_ccf_external/check_corpus_freeze.py --expect <sha256 of the freeze file>

The freeze file, tools/scitt_ccf_external/CORPUS_FREEZE_rounds_1_to_3.sha256, has one line per tracked file
of differential_corpus, differential_corpus_round2 and differential_corpus_round3, in sha256sum form
("<64 lowercase hex>  <path>"), paths relative to the repository root, sorted bytewise by path, LF line ends.
It does not list itself; it lies outside the three directories.

The expected hash is an argument on purpose. A check that compared the file only with a hash stored next to it
in the tree would pass when both were replaced together, so it would not bind the corpus to the hash a reader
was given elsewhere. Without --expect the check stops; it never falls back to the value in the README.

In order, stopping at the first deviation:
  1. the SHA-256 of the freeze file equals --expect;
  2. every line has the sha256sum form, the paths are sorted bytewise, and no path appears twice;
  3. the listed paths are exactly the files `git ls-files` reports under the three directories, nothing
     missing and nothing extra;
  4. every listed file exists, is readable and has the listed SHA-256.

Exit 0 when all four hold, 1 at the first deviation (named on stdout), 2 when the check cannot run as asked
(no --expect, a malformed --expect, no git checkout at the root).

`--write` regenerates the freeze file from `git ls-files` and prints its SHA-256. It is how the file was made;
it is not part of the check.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FREEZE = "tools/scitt_ccf_external/CORPUS_FREEZE_rounds_1_to_3.sha256"
DIRS = tuple(f"tools/scitt_ccf_external/{d}"
             for d in ("differential_corpus", "differential_corpus_round2", "differential_corpus_round3"))
_LINE = re.compile(r"([0-9a-f]{64})  ([^\n\\]+)")
_HEX = re.compile(r"[0-9a-f]{64}")


class Deviation(Exception):
    """The first difference between the freeze file and the tree."""


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _tracked() -> list[str]:
    out = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z", "--", *DIRS],
                         capture_output=True, check=True).stdout
    return sorted((p.decode("utf-8") for p in out.split(b"\0") if p), key=lambda s: s.encode("utf-8"))


def write() -> str:
    lines = [f"{_sha256_file(ROOT / p)}  {p}\n" for p in _tracked()]
    (ROOT / FREEZE).write_bytes("".join(lines).encode("utf-8"))
    return _sha256_file(ROOT / FREEZE)


def check(expect: str) -> int:
    freeze = ROOT / FREEZE
    try:
        data = freeze.read_bytes()
    except OSError as e:
        raise Deviation(f"freeze file {FREEZE} not readable: {e}") from None
    got = hashlib.sha256(data).hexdigest()
    if got != expect:
        raise Deviation(f"manifest hash {got} differs from the expected {expect}")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise Deviation(f"{FREEZE} is not UTF-8") from None
    if not text.endswith("\n") or "\r" in text:
        raise Deviation(f"{FREEZE} does not end every line with a single LF")
    listed: list[tuple[str, str]] = []
    seen: set[str] = set()
    for n, line in enumerate(text[:-1].split("\n"), start=1):
        m = _LINE.fullmatch(line)
        if not m:
            raise Deviation(f"line {n} is not in sha256sum form: {line!r}")
        digest, path = m.groups()
        if path in seen:
            raise Deviation(f"line {n}: duplicate path {path}")
        if listed and path.encode("utf-8") < listed[-1][1].encode("utf-8"):
            raise Deviation(f"line {n}: {path} is not sorted bytewise after {listed[-1][1]}")
        seen.add(path)
        listed.append((digest, path))
    tracked = _tracked()
    tracked_set = set(tracked)
    for p in tracked:
        if p not in seen:
            raise Deviation(f"tracked file not in the freeze file: {p}")
    for _, p in listed:
        if p not in tracked_set:
            raise Deviation(f"listed file is not tracked under the three directories: {p}")
    for digest, p in listed:
        try:
            have = _sha256_file(ROOT / p)
        except OSError as e:
            raise Deviation(f"listed file missing or unreadable: {p} ({e.strerror})") from None
        if have != digest:
            raise Deviation(f"changed file: {p} has {have}, the freeze file lists {digest}")
    return len(listed)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--expect", help="the SHA-256 of the freeze file, as given to the reader")
    ap.add_argument("--write", action="store_true", help="regenerate the freeze file and print its SHA-256")
    a = ap.parse_args(argv)
    try:
        subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--is-inside-work-tree"],
                       capture_output=True, check=True)
    except (OSError, subprocess.CalledProcessError):
        print(f"cannot run: {ROOT} is not a git checkout")
        return 2
    if a.write:
        print(write())
        return 0
    if not a.expect:
        print("cannot run: the expected SHA-256 of the freeze file is missing, pass --expect <sha256>")
        return 2
    if not _HEX.fullmatch(a.expect):
        print(f"cannot run: --expect is not 64 lowercase hex characters: {a.expect!r}")
        return 2
    try:
        n = check(a.expect)
    except Deviation as d:
        print(f"FREEZE CHECK FAILED: {d}")
        return 1
    print(f"freeze check passed: manifest {a.expect}, {n} files, each equal to its line")
    return 0


if __name__ == "__main__":
    sys.exit(main())
