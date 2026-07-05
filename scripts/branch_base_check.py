#!/usr/bin/env python3
"""Advisory branch-base check (FEHLER D, 2026-07-05).

Warns when a PR branch was forked from a release tag (`vX.Y.Z`) instead of `main`/`release/*`.
A tag-based branch predates every later `## [Unreleased]` CHANGELOG section, so it re-conflicts on
`CHANGELOG.md` on every PR. This check is **advisory only** — it emits a GitHub warning annotation and
a step-summary note, but ALWAYS exits 0 (never fails the build). No gate-softening: it does not block
anything; it only surfaces a cause of avoidable friction.

Env:
  BRANCH_BASE_REF   the intended base branch (default "main")
  BRANCH_HEAD_SHA   the PR head sha (default: current HEAD)

Usage:  python scripts/branch_base_check.py
"""
from __future__ import annotations

import os
import re
import subprocess
import sys

_TAG_RE = re.compile(r"^v\d")


def _git(*args: str) -> str:
    r = subprocess.run(["git", *args], capture_output=True, text=True, timeout=15)
    return r.stdout.strip() if r.returncode == 0 else ""


def _warn(msg: str) -> None:
    print(f"::warning title=Branch base::{msg}")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        try:
            with open(summary, "a", encoding="utf-8") as fh:
                fh.write(f"> ⚠️ **Branch base**: {msg}\n")
        except OSError:
            pass


def _run() -> None:
    base_ref = os.environ.get("BRANCH_BASE_REF", "main")
    head = os.environ.get("BRANCH_HEAD_SHA") or _git("rev-parse", "HEAD")
    if not head:
        print("[branch-base] no HEAD sha available — skipping (advisory)")
        return

    # The fork point of the PR branch off its base.
    fork = _git("merge-base", f"origin/{base_ref}", head)
    if not fork:
        print(f"[branch-base] cannot compute merge-base with origin/{base_ref} — skipping (advisory)")
        return

    # Is the branch behind base? If the fork point IS the current base tip, the branch is up to date
    # and there is NO CHANGELOG re-conflict — even if that commit happens to carry a release tag (right
    # after a release, main's tip == the release-tag commit). Only a BEHIND branch re-conflicts, so we
    # never warn about a tag on an up-to-date branch (6-lens review L1: avoid the false positive).
    base_tip = _git("rev-parse", f"origin/{base_ref}")
    behind = bool(base_tip) and fork != base_tip

    tags_at_fork = [t for t in _git("tag", "--points-at", fork).splitlines() if _TAG_RE.match(t)]
    if tags_at_fork and behind:
        _warn(
            f"this PR branch forks from release tag {tags_at_fork} at {fork[:12]} and is behind "
            f"'{base_ref}'; branch from '{base_ref}' instead. Fix: git rebase --onto origin/{base_ref} "
            f"{tags_at_fork[0]} <branch>. Forking from a tag re-conflicts on CHANGELOG.md every PR (FEHLER D).")
        return
    if behind:
        n = _git("rev-list", "--count", f"{fork}..origin/{base_ref}") or "?"
        _warn(f"this PR branch is behind origin/{base_ref} by {n} commit(s) since {fork[:12]}; "
              f"consider merging/rebasing onto '{base_ref}' to avoid CHANGELOG.md conflicts.")
        return

    print(f"[branch-base] OK — up to date with '{base_ref}' at {fork[:12]} (no re-conflict risk).")


def main() -> int:
    # ADVISORY contract: ALWAYS exit 0 as a property of the SCRIPT itself, not only of the workflow's
    # continue-on-error. Any error (git timeout, subprocess failure) → advisory note + exit 0.
    try:
        _run()
    except Exception as exc:  # noqa: BLE001 — advisory must never fail the build
        print(f"[branch-base] advisory check errored ({exc!r}) — treating as OK (exit 0)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
