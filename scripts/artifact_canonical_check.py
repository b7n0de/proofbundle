#!/usr/bin/env python3
"""Ask a BUILT artifact whether it came out of the canonical build path.

The gap this closes was measured on 2026-09-11 and recorded as register item 7: the CI
enforces the build path for every pull request, and `test_reproducible_build_361.py` binds
the normaliser hermetically — but NOTHING examines an artifact that is already lying on
disk. That is exactly where the readiness artifacts of 2026-09-09 slipped through: built
locally, without the normalised timestamps (nine distinct ZIP mtimes against one), filed,
and nobody noticed.

The trick is not to check the PATH — a path leaves no trace in its output — but the
PROPERTIES the path produces, which are all readable from the bytes:

  sdist   every member mtime identical · uid and gid zero · uname and gname empty ·
          members sorted by name · gzip header timestamp zeroed
  wheel   every entry carries the same date_time

Three verdicts, never two. CANONICAL means every property held. NOT_CANONICAL names the
property that failed and its evidence. NOT_APPLICABLE means this is not a shape we know —
and that is not a pass. Collapsing the third into the first is how a checker starts
approving files it never looked at.
"""
from __future__ import annotations

import argparse
import gzip
import json
import struct
import tarfile
import zipfile
from pathlib import Path

CANONICAL, NOT_CANONICAL, NOT_APPLICABLE = "CANONICAL", "NOT_CANONICAL", "NOT_APPLICABLE"


def _gzip_header_mtime(p: Path) -> int | None:
    """Bytes 4..8 of a gzip header are the timestamp. The build path zeroes it."""
    with p.open("rb") as fh:
        kopf = fh.read(10)
    if len(kopf) < 10 or kopf[:2] != b"\x1f\x8b":
        return None
    return struct.unpack("<I", kopf[4:8])[0]


def pruefe_sdist(p: Path) -> dict:
    befunde: list[str] = []
    mtimes: set[int] = set()
    uids: set[int] = set()
    unames: set[str] = set()
    namen: list[str] = []
    with gzip.open(p, "rb") as roh, tarfile.open(fileobj=roh, mode="r|") as tf:
        for m in tf:
            mtimes.add(int(m.mtime))
            uids.add(m.uid)
            uids.add(m.gid)
            unames.add(m.uname)
            unames.add(m.gname)
            namen.append(m.name)
    if len(mtimes) != 1:
        befunde.append(f"member mtimes differ: {len(mtimes)} distinct values "
                       f"(canonical: exactly 1)")
    if uids != {0}:
        befunde.append(f"uid/gid not zeroed: {sorted(uids)} — build-host identity leaks")
    if unames - {""}:
        befunde.append(f"uname/gname not empty: {sorted(unames - {''})}")
    if namen != sorted(namen):
        befunde.append("members are not sorted by name")
    kopf = _gzip_header_mtime(p)
    if kopf != 0:
        befunde.append(f"gzip header timestamp is {kopf}, canonical is 0")
    return {"kind": "sdist", "members": len(namen), "distinct_mtimes": len(mtimes),
            "gzip_header_mtime": kopf, "findings": befunde}


def pruefe_wheel(p: Path) -> dict:
    befunde: list[str] = []
    with zipfile.ZipFile(p) as zf:
        stempel = {zi.date_time for zi in zf.infolist()}
        n = len(zf.infolist())
    if len(stempel) != 1:
        befunde.append(f"entry timestamps differ: {len(stempel)} distinct values "
                       f"(canonical: exactly 1) — this is the shape the readiness "
                       f"artifacts of 2026-09-09 had, nine against one")
    return {"kind": "wheel", "entries": n, "distinct_timestamps": len(stempel),
            "findings": befunde}


def pruefe(p: Path) -> dict:
    if not p.is_file():
        return {"path": str(p), "verdict": NOT_APPLICABLE,
                "reason": "not a regular file", "findings": []}
    if p.name.endswith(".tar.gz"):
        d = pruefe_sdist(p)
    elif p.name.endswith(".whl"):
        d = pruefe_wheel(p)
    else:
        return {"path": str(p), "verdict": NOT_APPLICABLE,
                "reason": f"unknown artifact shape: {p.name} — NOT a pass, this file was "
                          "not examined", "findings": []}
    d["path"] = str(p)
    d["verdict"] = CANONICAL if not d["findings"] else NOT_CANONICAL
    d["reason"] = ("every canonical property holds" if not d["findings"]
                   else f"{len(d['findings'])} property/properties failed")
    return d


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("artifacts", type=Path, nargs="+")
    p.add_argument("--json", action="store_true")
    p.add_argument("--require-applicable", action="store_true",
                   help="exit 1 on NOT_APPLICABLE too — an unexamined file is not a pass")
    a = p.parse_args(argv)
    ergebnisse = [pruefe(x) for x in a.artifacts]
    if a.json:
        print(json.dumps(ergebnisse, indent=2))
    else:
        for d in ergebnisse:
            print(f"{d['verdict']:15s} {Path(d['path']).name}  —  {d['reason']}")
            for f in d["findings"]:
                print(f"    {f}")
    schlecht = sum(1 for d in ergebnisse if d["verdict"] == NOT_CANONICAL)
    unklar = sum(1 for d in ergebnisse if d["verdict"] == NOT_APPLICABLE)
    if not a.json:
        print(f"\n{len(ergebnisse)} artifact(s) · {schlecht} NOT_CANONICAL · {unklar} NOT_APPLICABLE")
    if schlecht:
        return 1
    return 1 if (unklar and a.require_applicable) else 0


if __name__ == "__main__":
    raise SystemExit(main())
