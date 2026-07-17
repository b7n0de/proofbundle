#!/usr/bin/env python3
"""WP-B — pytest is the NORMATIVE runner + a locked test manifest (no silent test shrink).

The 3.6.0 acceptance (EXT-P1-06) has two halves and this gate enforces both mechanically:

  1. **pytest is the normative runner.** The historical `unittest discover` path silently MISSED
     the pytest-only modules (bare ``def test_*`` functions, parametrize, fixtures) — a real finding
     was 47 security tests invisible to the unittest gate. This gate re-derives, fresh each run, how
     many test modules carry NO ``unittest`` import (the pytest-only class) and asserts the locked
     floor is still met — so a regression that quietly drops pytest-only coverage is a CI FAIL, not a
     silent narrowing.

  2. **A locked test manifest.** The count of tests pytest COLLECTS must not fall below a committed
     floor (``tests/test_manifest_lock.json``) without an explicit, reviewed bump of that floor. An
     unintended drop (a module that stops collecting, a deleted suite, a broken import that silently
     de-selects a file) is exactly the "silent test schwund" EXT-P1-06 forbids.

No-Fake / fail-closed design:
  * The floor is a FLOOR, never an exact equality — adding tests is always fine; only a DROP fails.
  * The count is taken from pytest's own ``--collect-only`` (the normative runner), parsed from its
    "N tests collected" summary; a collection ERROR (not just a low count) is a hard FAIL, because a
    collection error is the classic way a whole file silently disappears from the run.
  * Raising the floor is a deliberate, committed edit to the lock file, surfaced in review — the gate
    prints the exact new floor to record when the live count exceeds the locked one.

CLI:
  python scripts/test_manifest_gate.py [--json] [--update] [--tests-dir tests]

``--update`` rewrites the lock file to the current live counts (a reviewed action, run by a human when
tests are intentionally added). Exit 0 iff every floor is met and collection is clean.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
LOCK_PATH = REPO / "tests" / "test_manifest_lock.json"
_COLLECTED_RE = re.compile(r"(\d+)\s+tests?\s+collected")
_ERROR_RE = re.compile(r"(\d+)\s+errors?\b")


def pytest_only_modules(tests_dir: Path) -> list[str]:
    """Every ``tests/test_*.py`` whose SOURCE does not import ``unittest`` — the class the legacy
    unittest-discover runner cannot see. Re-derived fresh each run (no hand-maintained list)."""
    out: list[str] = []
    for path in sorted(tests_dir.glob("test_*.py")):
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        if not re.search(r"^\s*(?:import\s+unittest|from\s+unittest\b)", text, re.MULTILINE):
            out.append(path.name)
    return out


def collect_count(tests_dir: Path) -> tuple[int, int, str]:
    """Run pytest's own collection (the normative runner) and return (collected, errors, raw_tail).

    A non-zero error count OR an unparseable summary is surfaced to the caller as a FAIL condition —
    a collection error is how a file silently drops out of the run, the exact regression WP-B guards.
    """
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider",
         str(tests_dir)],
        cwd=str(REPO), capture_output=True, text=True,
        env={**_env()},
    )
    tail = "\n".join((proc.stdout or "").strip().splitlines()[-4:])
    m = _COLLECTED_RE.search(proc.stdout or "")
    collected = int(m.group(1)) if m else -1
    em = _ERROR_RE.search(proc.stdout or "")
    errors = int(em.group(1)) if em else 0
    # pytest exits non-zero on collection errors even with tests collected; treat that as errors>0.
    if proc.returncode not in (0,) and errors == 0 and collected >= 0:
        errors = max(errors, 1)
    return collected, errors, tail


def _env() -> dict:
    import os
    e = dict(os.environ)
    src = str(REPO / "src")
    e["PYTHONPATH"] = src + (":" + e["PYTHONPATH"] if e.get("PYTHONPATH") else "")
    return e


def load_lock(path: Path = LOCK_PATH) -> dict:
    if not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def evaluate(tests_dir: Path | None = None, lock_path: Path = LOCK_PATH) -> dict:
    tests_dir = tests_dir or (REPO / "tests")
    lock = load_lock(lock_path)
    floor_tests = int(lock.get("min_collected_tests", 0))
    floor_pytest_only = int(lock.get("min_pytest_only_modules", 0))

    collected, errors, tail = collect_count(tests_dir)
    pyonly = pytest_only_modules(tests_dir)

    problems: list[str] = []
    if collected < 0:
        problems.append(f"could not parse pytest collection summary; tail:\n{tail}")
    if errors:
        problems.append(f"pytest reported {errors} collection error(s) — a file silently dropped "
                        f"from the run is a FAIL (WP-B); tail:\n{tail}")
    if collected >= 0 and collected < floor_tests:
        problems.append(f"collected {collected} tests < locked floor {floor_tests} "
                        "(unintended test shrink — a suite stopped collecting, or the floor needs a "
                        "reviewed bump via --update)")
    if len(pyonly) < floor_pytest_only:
        problems.append(f"{len(pyonly)} pytest-only module(s) < locked floor {floor_pytest_only} "
                        "(pytest-only coverage regressed — the unittest-invisible class shrank)")

    return {
        "schema": "proofbundle.test_manifest_gate.v1",
        "ok": not problems,
        "collected": collected,
        "errors": errors,
        "min_collected_tests": floor_tests,
        "pytest_only_modules": len(pyonly),
        "min_pytest_only_modules": floor_pytest_only,
        "headroom_tests": (collected - floor_tests) if collected >= 0 else None,
        "problems": problems,
    }


def _write_lock(tests_dir: Path, lock_path: Path) -> dict:
    collected, errors, tail = collect_count(tests_dir)
    if collected < 0 or errors:
        raise SystemExit(f"refusing to lock an unclean collection (collected={collected}, "
                         f"errors={errors}); tail:\n{tail}")
    pyonly = pytest_only_modules(tests_dir)
    lock = {
        "schema": "proofbundle.test_manifest_lock.v1",
        "note": "WP-B locked test manifest. FLOORs, never exact counts: adding tests is always fine; "
                "a drop below these is a CI FAIL (no silent test schwund). Raising a floor is a "
                "deliberate, reviewed edit (run scripts/test_manifest_gate.py --update).",
        "min_collected_tests": collected,
        "min_pytest_only_modules": len(pyonly),
        "recorded_live_counts": {"collected": collected, "pytest_only_modules": len(pyonly)},
    }
    lock_path.write_text(json.dumps(lock, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return lock


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--json", action="store_true")
    p.add_argument("--update", action="store_true",
                   help="rewrite the lock file to the current live counts (a reviewed human action)")
    p.add_argument("--tests-dir", type=Path, default=REPO / "tests")
    args = p.parse_args(argv)

    if args.update:
        lock = _write_lock(args.tests_dir, LOCK_PATH)
        print(f"[test-manifest] locked floor: {lock['min_collected_tests']} tests, "
              f"{lock['min_pytest_only_modules']} pytest-only module(s) -> {LOCK_PATH.name}")
        return 0

    result = evaluate(args.tests_dir)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"[test-manifest] collected={result['collected']} "
              f"(floor {result['min_collected_tests']}, headroom {result['headroom_tests']}) · "
              f"pytest-only={result['pytest_only_modules']} (floor {result['min_pytest_only_modules']}) · "
              f"{'OK' if result['ok'] else 'FAIL'}")
        for pr in result["problems"]:
            print("  -", pr)
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
