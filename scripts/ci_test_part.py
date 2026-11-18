"""Pytest plugin for the CI job `test`: run one part of the suite.

    python -m pytest -q --numprocesses=auto --dist=worksteal -p scripts.ci_test_part --ci-part=2/6

WHY. Owner order of 2026-10-30 (accelerator first): the legs of the job `test` took 37 to 99 minutes
in the suite step alone (measured through the GitHub API at 1e050a1d and f407cfea), and test (3.14)
was the long path of every landing. Each leg now runs in parts, side by side.

WHAT STAYS. pytest still collects the whole suite in every part, from the same command and the same
configuration, exactly as `python -m pytest` does. Only after collection does this plugin keep the
items of the units that belong to the part (see below) and deselect the rest, the way `-k`
deselects. The runner and the collection stay as they are; what a part does not run, another part
of the same leg runs.

THE ASSIGNMENT IS BY UNIT AND IT IS A PARTITION BY CONSTRUCTION. A unit is a test file, except for
the few tests the weights list one by one: measured at c8b8eb8e, 23 tests that each run the whole
audit matrix took about 200 to 230 s apiece, 4.8 of the suite's 6.6 thousand seconds, and twelve of
them live in one file. Such a test is a unit of its own; the rest of its file is one unit. Every
collected item belongs to exactly one unit, and every unit goes to exactly one part: the units are
sorted by their measured weight (heaviest first, then by name) and each goes to the part that
carries the least so far (lowest number on a tie). The weights only steer the balance; a file
without a weight gets the median file weight and still lands in exactly one part. Part 1 starts
with an offset, because it also runs the checks of the job that are not the suite. The assignment
is a pure function of the collected node ids, so every part and every xdist worker of one leg
computes the same one.

WHAT IS DIFFERENT FROM ONE PROCESS. The parts run in separate jobs, so module and class fixtures and
any state global to a process apply per part, not per leg. That was already true across the xdist
workers of one leg.

FAIL CLOSED. A malformed `--ci-part` is a usage error, never a silent full or empty run. A part that
keeps no test makes pytest exit 5 ("no tests ran"), which fails the step. Without `--ci-part` the
plugin changes nothing.

The contract over all of this is tests/test_ci_test_parts_cover_the_suite.py.
"""
from __future__ import annotations

import json
import math
import pathlib
import re
import statistics

import pytest

WEIGHTS = pathlib.Path(__file__).with_name("ci_test_part_weights.json")
_PART = re.compile(r"([1-9][0-9]*)/([1-9][0-9]*)")


def parse_part(text: str) -> tuple[int, int]:
    """(part, parts) of `I/K`; a usage error for anything else, including I outside 1..K."""
    m = _PART.fullmatch(text or "")
    if not m:
        raise pytest.UsageError(f"--ci-part expects I/K with positive integers, got {text!r}")
    part, parts = int(m.group(1)), int(m.group(2))
    if part > parts:
        raise pytest.UsageError(f"--ci-part {text!r}: part {part} is not one of 1 to {parts}")
    return part, parts


def file_of(nodeid: str) -> str:
    """The file a collected item comes from: its node id up to the first `::`."""
    return nodeid.split("::", 1)[0]


def unit_of(nodeid: str, tests: dict[str, float]) -> str:
    """The unit of a collected item: the item itself when the weights list it, else its file."""
    return nodeid if nodeid in tests else file_of(nodeid)


def load_weights(path: pathlib.Path = WEIGHTS) -> tuple[dict[str, float], dict[str, float], float]:
    """(seconds per file, seconds per test listed alone, offset of part 1) from the weights file. A
    missing or malformed file is a usage error: the parts would still be a partition, but the balance
    would be a guess."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        files = {str(k): float(v) for k, v in data["seconds"].items()}
        tests = {str(k): float(v) for k, v in data["tests"].items()}
        offset = float(data["part_one_offset_seconds"])
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        raise pytest.UsageError(f"the weights of the CI parts cannot be read from {path}: {exc}") from exc
    # A weight is a duration: finite and not negative. JSON reads `1e309` as infinity and `NaN` as not a number, and
    # `v < 0` let both through (first reading of PR 440, Z7).
    if not files or any(not math.isfinite(v) or v < 0 for v in [*files.values(), *tests.values(), offset]):
        raise pytest.UsageError(f"the weights in {path} are empty, negative or not finite")
    return files, tests, offset


def assign(units, parts: int, files: dict[str, float], tests: dict[str, float] | None = None,
           offset: float = 0.0) -> dict[str, int]:
    """Part number (1 to `parts`) of every unit, by greedy longest-first packing over the weights."""
    if parts < 1:
        raise ValueError(f"parts must be positive, got {parts}")
    tests = tests or {}
    default = statistics.median(files.values()) if files else 1.0
    weight = {u: tests[u] if u in tests else files.get(u, default) for u in set(units)}
    loads = [0.0] * parts
    loads[0] = offset
    result: dict[str, int] = {}
    for u in sorted(weight, key=lambda u: (-weight[u], u)):
        j = min(range(parts), key=lambda i: (loads[i], i))
        result[u] = j + 1
        loads[j] += weight[u]
    return result


def pytest_addoption(parser):
    parser.getgroup("ci-part").addoption(
        "--ci-part", default=None, metavar="I/K",
        help="run only the test files of part I of K (CI job `test`); see scripts/ci_test_part.py")


def pytest_configure(config):
    text = config.getoption("ci_part")
    if text is not None:
        config._ci_part = parse_part(text)
        config._ci_weights = load_weights()


@pytest.hookimpl(trylast=True)
def pytest_collection_modifyitems(session, config, items):
    if config.getoption("ci_part") is None:
        return
    part, parts = config._ci_part
    files, tests, offset = config._ci_weights
    where = assign((unit_of(i.nodeid, tests) for i in items), parts, files, tests, offset)
    keep = [i for i in items if where[unit_of(i.nodeid, tests)] == part]
    drop = [i for i in items if where[unit_of(i.nodeid, tests)] != part]
    if drop:
        config.hook.pytest_deselected(items=drop)
    items[:] = keep
