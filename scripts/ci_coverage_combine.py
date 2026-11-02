#!/usr/bin/env python3
"""The closing step of the CI job `coverage`: check the data of every part, then combine it.

    python scripts/ci_coverage_combine.py --data-dir coverage-data --parts 7 --result "$PARTS_RESULT" \
        --source src/proofbundle
    python -m coverage report -m --fail-under=83

WHY. Owner choice of 2026-11-02 (order DELTA-COVERAGE-IN-TEILEN-01): `coverage` ran the whole suite on one
runner and set the end of every run, 101.7 min at main c8b5b285 (run 41466807258, suite step 100.4 min) and
92.1 min at pull request 454 (run 41444424659), while the parts of `test (3.12)` took 13.2 to 19.6 min. The
suite now runs in the matrix job `coverage-part`, split by the same plugin and weights as `test`
(scripts/ci_test_part.py), and each part uploads its data file. This job keeps the name `coverage`, so the
`needs` of `mutation` and `all-checks-passed` and the ruleset stay as they are.

WHAT A PART CAN DO WRONG, AND WHAT THIS SCRIPT DOES ABOUT IT. A combined report over fewer parts than ran is a
smaller suite that looks like the whole one, so every way to lose a part fails here, before the floor:

  - the matrix did not succeed (`--result` is anything but `success`: failure, cancelled, skipped, empty);
  - a part's file is missing, or a file is there that no part writes;
  - a file is empty, is no coverage data, measured no file at all, or names files but holds no executed line
    (coverage records a file name without lines through `touch_file`, and a name alone is no measurement);
  - a file measured a file outside `--source`, the directory the suite measures (`--cov=src/proofbundle`): data
    of another checkout or of another source is not the measure of this suite, and the floor would judge it;
  - two files were written by different versions of coverage, or by another version than this one;
  - no part at all: `--parts` below 1 is a usage error, never a green combine over nothing.

Only then are the files combined (`coverage combine --keep`) into the data file the report reads. The floor
itself stays the command it always was, on its own line in the workflow, so a reader sees it there.

WHAT THESE CHECKS DO NOT SHOW. They validate the artifact names, the coverage writer versions, and that every
measured file lies in the source. They do not establish which tests produced the data: that every part ran its
share of the suite is held where the share is made, by the part plugin and its contract
(tests/test_ci_test_parts_cover_the_suite.py).

The contract over this script and over the two jobs is tests/test_coverage_parts_cover_the_suite.py.
Exit 0 combined, 1 refused, 2 usage error.
"""
from __future__ import annotations

import argparse
import os
import pathlib
import sqlite3
import subprocess
import sys

#: The name of a part's data file in the artifact directory; `{part}` is 1 to K.
NAME = ".coverage.part-{part}"


def _writer_version(path: pathlib.Path) -> str:
    """The version of coverage that wrote the data file, from its own `meta` table."""
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        row = con.execute("SELECT value FROM meta WHERE key = 'version'").fetchone()
    finally:
        con.close()
    if not row or not str(row[0]).strip():
        raise ValueError("the data names no version of coverage")
    return str(row[0])


def _measured(path: pathlib.Path) -> tuple[list[str], int]:
    """The source files the data file names, as coverage recorded them (absolute, symbolic links resolved), and
    how many executed lines it holds over them."""
    import coverage  # noqa: PLC0415 - the closing job installs coverage, the module is read only here
    data = coverage.CoverageData(basename=str(path))
    data.read()
    files = sorted(data.measured_files())
    return files, sum(len(data.lines(f) or ()) for f in files)


def _inside(name: str, root: str) -> bool:
    """Whether a measured file lies in the source directory `root` (both absolute, links resolved)."""
    return os.path.realpath(name).startswith(root + os.sep)


def check(data_dir: pathlib.Path, parts: int, result: str, running_version: str, source: pathlib.Path) -> list[str]:
    """Every reason not to combine; empty means the data of all `parts` parts is there and sound."""
    if parts < 1:
        return [f"--parts {parts}: zero parts are never a combined coverage"]
    problems = []
    if result != "success":
        problems.append(f"the matrix coverage-part ended with {result or 'no result'!r}, not 'success'")
    expected = {NAME.format(part=p) for p in range(1, parts + 1)}
    present = {p.name for p in data_dir.glob(".coverage*")} if data_dir.is_dir() else set()
    for name in sorted(expected - present, key=lambda n: int(n.rsplit("-", 1)[1])):
        problems.append(f"{name} is missing: that part's data did not arrive")
    for name in sorted(present - expected):
        problems.append(f"{name} is no part's data file (expected {NAME.format(part='1')} to "
                        f"{NAME.format(part=parts)})")
    root = os.path.realpath(source)
    versions = {}
    for name in sorted(expected & present, key=lambda n: int(n.rsplit("-", 1)[1])):
        path = data_dir / name
        if path.stat().st_size == 0:
            problems.append(f"{name} is empty")
            continue
        try:
            versions[name] = _writer_version(path)
            files, executed = _measured(path)
        except Exception as exc:  # noqa: BLE001 - any unreadable file is a refused part, never a crash
            problems.append(f"{name} is not readable coverage data: {type(exc).__name__}: {exc}")
            continue
        outside = [f for f in files if not _inside(f, root)]
        if not files:
            problems.append(f"{name} measured no file")
        elif outside:
            problems.append(f"{name} measured {len(outside)} file(s) outside {source}, the first {outside[0]!r}")
        elif executed == 0:
            problems.append(f"{name} names {len(files)} file(s) but holds no executed line")
        else:
            print(f"{name}: {executed} executed lines in {len(files)} files of {source}, written by coverage "
                  f"{versions[name]}")
    for name, version in sorted(versions.items()):
        if version != running_version:
            problems.append(f"{name} was written by coverage {version}, this job runs {running_version}")
    return problems


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data-dir", required=True, type=pathlib.Path)
    ap.add_argument("--parts", required=True, type=int)
    ap.add_argument("--result", required=True, help="needs.coverage-part.result of the closing job")
    ap.add_argument("--source", required=True, type=pathlib.Path,
                    help="the directory the suite measures (--cov), relative to the checkout; every measured file "
                         "of every part must lie in it")
    a = ap.parse_args(argv)
    if a.parts < 1:
        print(f"::error title=coverage::--parts {a.parts}: zero parts are never a combined coverage")
        return 2
    if not a.source.is_dir():
        print(f"::error title=coverage::--source {a.source} is no directory of this checkout")
        return 2
    import coverage  # noqa: PLC0415
    problems = check(a.data_dir, a.parts, a.result.strip(), coverage.__version__, a.source)
    if problems:
        for p in problems:
            print(f"::error title=coverage::{p}")
        print(f"coverage: {len(problems)} reason(s) not to combine; the floor is not judged over a partial suite")
        return 1
    files = [str(a.data_dir / NAME.format(part=p)) for p in range(1, a.parts + 1)]
    r = subprocess.run([sys.executable, "-m", "coverage", "combine", "--keep", *files], check=False)
    if r.returncode != 0:
        print(f"::error title=coverage::coverage combine ended with {r.returncode}")
        return 1
    print(f"coverage: combined the data of {a.parts} of {a.parts} parts")
    return 0


if __name__ == "__main__":
    sys.exit(main())
