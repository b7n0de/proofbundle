Head of this branch: `7bb5168`, with `origin/main` merged in. One file, 45 added lines.

## Where this came from

It came from a test that went red on pull request 256, on a branch that does not touch this file.

```
test (3.14)   FAILED   negative Prozessspitze -290816
```

The honest question was not "which test" but "does it belong to the branch". So only the failed check was re-run, without changing a line, and it came back green. Same tree, same command, different result: the failure hangs on the environment, not on the branch, and 256 could merge on a measured path rather than a plausible one.

**That would have been the comfortable place to stop.** "Flaky, re-ran, green" closes the merge and leaves the defect standing. The defect is real.

## The defect

`VmHWM` is a high-water mark. Two docstrings in this very file state it "faellt NIE", never falls. The run refuted that premise by MEASURING a fall.

`_prozess_spitze` knew two states: measured, and not available. A fall was pressed into the first one and came out as a negative number, which then travelled on as if it were a measurement. A peak of `-290816` bytes is not a small peak or an odd peak. It is the absence of a measurement wearing the shape of one.

## The fix

A third state. A negative peak is reported as `NICHT MESSBAR` with both values and their difference, and **why** it fell is not invented:

```
if nachher < vorher:
    # A NEGATIVE PEAK IS NOT A MEASUREMENT, it is a refuted premise.
    # WHY IT FELL IS UNKNOWN and is not invented here.
    return -1, (f"NICHT MESSBAR: VmHWM fell, before {vorher} B, after {nachher} B, difference ...")
```

The two docstrings that claimed the mark never falls are corrected in the same commit, because a comment that contradicts a measured run is the more expensive half of this class: the next reader believes the comment.

## What is measured, and what is not

Measured: `tests/test_budget_kostenkurve.py`, 141 cases, 98.49 s, exit 0 on this head. The pre-push gates are green (ruff, mypy, claims hygiene, doc links, new-lines-English).

NOT measured, and stated rather than guessed: **why** the high-water mark fell in that CI run. Candidates exist (a container reporting a fresh cgroup, a kernel accounting reset, a reused runner), and none of them was measured here, so none is claimed. The fix does not need the cause; it needs to stop reporting a non-measurement as a number.

Also not claimed: that this makes the suite deterministic. It makes ONE honest state visible where there was a misleading number.

## A measurement note about this branch

Read with `git diff origin/main..HEAD` before the merge, this branch appeared to delete 2782 lines across 17 files. It does not. It was based on an older main, and that direction of the diff shows main's newer files as deletions. Measured across the merge base, the change is one file and 45 lines. The number was real and it answered another question.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

