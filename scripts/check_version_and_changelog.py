#!/usr/bin/env python3
"""check_version_and_changelog.py — release-integrity gate for proofbundle.

Closes the "merged but never released / version drift" class (the M2 security fix and the 811-vs-817
typo both sat unreleased on main because nothing enforced this). Three checks:

  1. VERSION SINGLE-SOURCING: pyproject.toml, src/proofbundle/__init__.py and CITATION.cff MUST agree.
  2. CHANGELOG DOCUMENTS THE VERSION: the current version has a `## [<version>]` section in CHANGELOG.md.
  3. POST-TAG DRIFT (the M2 catcher): if there are non-trivial commits since the last release tag AND the
     version was NOT bumped past that tag, CHANGELOG.md MUST carry an `## [Unreleased]` section — otherwise
     work is sitting on main undelivered with no changelog trace. Git-gated: skipped (with a note) when git
     history / tags are unavailable (e.g. a shallow checkout without tags), never a false failure.

Exit 0 = OK, 1 = violation. stdlib only, offline, no third-party deps.

Usage: python3 scripts/check_version_and_changelog.py [--repo <path>]
"""
from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path

# Commit-subject prefixes that do NOT require a changelog entry (docs/tooling/meta).
_TRIVIAL_PREFIX = re.compile(r"^(chore|ci|docs|test|style|build|refactor|merge)\b", re.IGNORECASE)


def _read(p: Path) -> str:
    return p.read_text(encoding="utf-8") if p.is_file() else ""


def _pyproject_version(repo: Path) -> str | None:
    m = re.search(r'(?m)^\s*version\s*=\s*["\']([0-9]+\.[0-9]+\.[0-9]+[^"\']*)["\']', _read(repo / "pyproject.toml"))
    return m.group(1) if m else None


def _init_version(repo: Path) -> str | None:
    m = re.search(r'(?m)^\s*__version__\s*=\s*["\']([0-9]+\.[0-9]+\.[0-9]+[^"\']*)["\']',
                  _read(repo / "src" / "proofbundle" / "__init__.py"))
    return m.group(1) if m else None


def _citation_version(repo: Path) -> str | None:
    m = re.search(r'(?m)^\s*version\s*:\s*["\']?([0-9]+\.[0-9]+\.[0-9]+[^"\'\s]*)', _read(repo / "CITATION.cff"))
    return m.group(1) if m else None


def _changelog_headings(repo: Path) -> list[str]:
    # Every `## [x.y.z]` or `## [Unreleased]` heading, in file order.
    return re.findall(r"(?m)^##\s*\[([^\]]+)\]", _read(repo / "CHANGELOG.md"))


def _git(repo: Path, *args: str) -> tuple[int, str]:
    try:
        r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=15)
        return r.returncode, r.stdout.strip()
    except Exception:  # noqa: BLE001
        return 1, ""


def _semver_tuple(v: str) -> tuple:
    core = v.split("-")[0].split("+")[0]
    parts = core.split(".")
    return tuple(int(x) if x.isdigit() else 0 for x in (parts + ["0", "0", "0"])[:3])


def check(repo: Path) -> list[str]:
    problems: list[str] = []
    pv, iv, cv = _pyproject_version(repo), _init_version(repo), _citation_version(repo)

    # 1. Single-sourcing
    if not pv:
        problems.append("pyproject.toml [project].version not found")
    versions = {"pyproject": pv, "__init__": iv, "CITATION.cff": cv}
    distinct = {v for v in versions.values() if v}
    if len(distinct) > 1:
        problems.append(f"version disagreement across sources: {versions}")

    version = pv or iv or cv
    headings = _changelog_headings(repo)

    # 2. CHANGELOG documents the current version
    if version and version not in headings:
        problems.append(f"CHANGELOG.md has no `## [{version}]` section for the current version "
                        f"(headings seen: {headings[:5]})")

    # 3. Post-tag drift (M2 catcher), git-gated
    rc, last_tag_raw = _git(repo, "describe", "--tags", "--abbrev=0")
    if rc != 0 or not last_tag_raw:
        print("check_version_and_changelog: NOTE post-tag-drift check skipped (no git tags available)")
    else:
        last_tag = last_tag_raw.lstrip("v")
        rc2, log = _git(repo, "log", "--format=%s", f"{last_tag_raw}..HEAD")
        nontrivial = [s for s in log.splitlines() if s.strip() and not _TRIVIAL_PREFIX.match(s.strip())]
        version_bumped = bool(version) and _semver_tuple(version) > _semver_tuple(last_tag)
        has_unreleased = any(h.strip().lower() == "unreleased" for h in headings)
        if nontrivial and not version_bumped and not has_unreleased:
            problems.append(
                f"{len(nontrivial)} non-trivial commit(s) since tag {last_tag_raw} but the version was not bumped "
                f"and CHANGELOG.md has no `## [Unreleased]` section — undelivered work with no changelog trace "
                f"(e.g. {nontrivial[:3]})")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser(description="proofbundle release-integrity gate")
    ap.add_argument("--repo", default=".", help="repo root (default: cwd)")
    a = ap.parse_args()
    problems = check(Path(a.repo).resolve())
    if problems:
        print("check_version_and_changelog: FAIL")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("check_version_and_changelog: OK — version single-sourced, changelog current, no undelivered drift")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
