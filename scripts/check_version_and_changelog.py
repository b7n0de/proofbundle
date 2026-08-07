#!/usr/bin/env python3
"""check_version_and_changelog.py — release-integrity gate for proofbundle.

Closes the "merged but never released / version drift" class (the M2 security fix and the 811-vs-817
typo both sat unreleased on main because nothing enforced this). Six checks:

  1. VERSION SINGLE-SOURCING: pyproject.toml, src/proofbundle/__init__.py and CITATION.cff MUST agree.
  2. CHANGELOG DOCUMENTS THE VERSION: the current version has a `## [<version>]` section in CHANGELOG.md.
  3. POST-TAG DRIFT (the M2 catcher): if there are non-trivial commits since the last release tag AND the
     version was NOT bumped past that tag, CHANGELOG.md MUST carry an `## [Unreleased]` section — otherwise
     work is sitting on main undelivered with no changelog trace. Git-gated: skipped (with a note) when git
     history / tags are unavailable (e.g. a shallow checkout without tags), never a false failure.
  4. TRACKED PROSE PLACES: every place that states the *current* version in prose (see _TRACKED_PLACES)
     MUST state the source version. A place whose anchor phrase has vanished is a failure too, not a
     silent pass — a gate that stops finding its anchor stops gating.
  5. EXTERNAL SURFACES (opt-in, --external): PyPI and the project page must state the same version.
  6. UNDECLARED PLACES: a tracked file that states a *current* version while not being a declared
     place in _TRACKED_PLACES is a finding. Check 4 can only watch what someone remembered to
     declare; a new sentence that starts claiming the current release is invisible to it, and the
     place nobody declared is exactly the one that goes stale. Historical forms ("since X.Y.Z",
     "as of X.Y.Z") do not match — only claim shapes that mean "this is the current release".

EVERY NUMBER NAMES ITS OBJECT AND ITS SOURCE. Not "version 0.49.1" but "markdownlint-cli 0.49.1,
read from package.json". A bare number is real and still says nothing: on 2026-08-07 a single day
produced a library version reported as a CLI version, a bundling threshold read from the wrong call,
and an exit code that belonged to `tail`. Each number was correct about something other than the
thing it was named for. The output below therefore always carries the object a number describes and
the file it was read from. (The example deliberately uses a foreign tool's version: an illustration
that spells out this project's current release would itself become a place that goes stale.)

WHAT THIS DOES NOT TOUCH, deliberately: historical statements. "since v3.7.0", "as of v3.7.0" and old
CHANGELOG headings record *when* something became true. Bumping them would turn a fact into a lie, so
they are not in _TRACKED_PLACES and must never be added to it.

THREE STATES, not two. An external surface that cannot be reached is `NICHT MESSBAR` — it is neither a
pass nor a failure. Without --require-external it does not fail the run, and it never counts as green:
the summary line says what was actually verified. --require-external turns not-measurable into a
failure and belongs in the release checklist, where "we could not look" must block.

Exit 0 = OK, 1 = violation. stdlib only; checks 1-4 are offline, check 5 needs the network and only
runs when asked.

Usage: python3 scripts/check_version_and_changelog.py [--repo <path>] [--external] [--require-external]
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import urllib.error
import urllib.request
from pathlib import Path

# Commit-subject prefixes that do NOT require a changelog entry (docs/tooling/meta).
_TRIVIAL_PREFIX = re.compile(r"^(chore|ci|docs|test|style|build|refactor|merge)\b", re.IGNORECASE)

_SEMVER = r"([0-9]+\.[0-9]+\.[0-9]+)"

# Check 4 — prose that states the CURRENT version and must therefore track the source.
# Each entry: (path, anchor regex with one capture group, human description of the anchor).
# Only add a place here if it means "this is the current release". Never add a "since"/"as of"
# statement: those are history, and a gate that bumps history manufactures false claims.
_TRACKED_PLACES = [
    ("RELEASE.md", re.compile(r"current:\s*v?" + _SEMVER), "the `(current: X.Y.Z)` note"),
    ("docs/readiness_pack/PROGRESS.md",
     re.compile(r"current release:\s*v?" + _SEMVER), "the `(current release: X.Y.Z)` note"),
]

# Check 6 — shapes that mean "this IS the current release". Deliberately narrow: "since X.Y.Z" and
# "as of X.Y.Z" record history and must never match, or the sweep would demand that facts be bumped.
_CURRENT_CLAIM = re.compile(
    r"(?:current|latest)(?:\s+(?:release|version))?\s*:?\s*v?" + _SEMVER, re.IGNORECASE)
# Not swept: test fixtures state wrong versions ON PURPOSE, and audit artifacts are frozen history.
_SWEEP_EXCLUDE_PREFIXES = ("tests/", "audit_artifacts/")

_PYPI_JSON = "https://pypi.org/pypi/proofbundle/json"
_PROJECT_PAGE = "https://b7n0de.com/proofbundle/"
# The page states the published version as `PyPI latest <code>X.Y.Z</code>` (and `PyPI-latest` in the
# German string table). Every occurrence must agree: one translated string left behind is exactly the
# drift this checks for.
_PAGE_VERSION = re.compile(r"PyPI[- ]latest\s*<code>\s*" + _SEMVER + r"\s*</code>", re.IGNORECASE)

NICHT_MESSBAR = "NICHT MESSBAR"


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


def _source_version(repo: Path) -> tuple[str | None, str]:
    """The source version AND the file it was read from.

    Returned together on purpose: a version without its origin is the defect class this gate exists
    to catch. Callers must not re-derive the number separately — that is how two call sites end up
    reporting different values for "the version".
    """
    for datei, leser in (("pyproject.toml", _pyproject_version),
                         ("src/proofbundle/__init__.py", _init_version),
                         ("CITATION.cff", _citation_version)):
        v = leser(repo)
        if v:
            return v, datei
    return None, "no source file carried a version"


def _changelog_headings(repo: Path) -> list[str]:
    # Every `## [x.y.z]` or `## [Unreleased]` heading, in file order.
    return re.findall(r"(?m)^##\s*\[([^\]]+)\]", _read(repo / "CHANGELOG.md"))


def _git(repo: Path, *args: str) -> tuple[int, str]:
    try:
        r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=15)
        return r.returncode, r.stdout.strip()
    except Exception:  # noqa: BLE001
        return 1, ""


_RELEASE_TAG_GLOB = "v[0-9]*"
_RELEASE_TAG_RE = re.compile(r"^v?[0-9]+\.[0-9]+\.[0-9]+")


def _last_release_tag(repo: Path) -> tuple[str | None, str]:
    """The most recent RELEASE tag reachable from HEAD, plus a reason when there is none.

    WHY THIS IS NOT `git describe --tags`: measured in this repo on 2026-08-07, that returned
    `corpus-review-2026-07-25-iter10` — a review tag. `_semver_tuple` reads it as (0, 0, 0), so any
    real version compares as "bumped past it", and check 3 passed while a non-trivial commit sat
    undelivered with no `## [Unreleased]` section. The check did not fail; it stopped applying, and
    silence looked exactly like agreement. A gate anchored on "the latest tag" is anchored on
    whatever anyone tagged last.

    Three states, not two: a release tag, no tags at all, or tags that exist but none of them is a
    release. The third is reported in its own words instead of being folded into the second.
    """
    rc, raw = _git(repo, "describe", "--tags", "--abbrev=0", "--match", _RELEASE_TAG_GLOB)
    if rc == 0 and raw and _RELEASE_TAG_RE.match(raw):
        return raw, ""
    rc_any, any_tag = _git(repo, "describe", "--tags", "--abbrev=0")
    if rc_any != 0 or not any_tag:
        return None, "no git tags available"
    return None, (f"tags exist but none is a release tag reachable from HEAD "
                  f"(latest reachable tag: {any_tag})")


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

    version, herkunft = _source_version(repo)
    headings = _changelog_headings(repo)

    # 2. CHANGELOG documents the current version
    if version and version not in headings:
        problems.append(f"CHANGELOG.md has no `## [{version}]` section for the current version "
                        f"(headings seen: {headings[:5]})")

    # 3. Post-tag drift (M2 catcher), git-gated
    last_tag_raw, tag_note = _last_release_tag(repo)
    if not last_tag_raw:
        print(f"check_version_and_changelog: NOTE post-tag-drift check skipped ({tag_note})")
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

    # 4. Tracked prose places state the current version
    # 6. Places that state a current version without being declared
    if version:
        problems.extend(check_tracked_places(repo, version, herkunft))
        problems.extend(check_undeclared_places(repo))
    return problems


def _tracked_files(repo: Path) -> list[str]:
    """Tracked files only. An untracked scratch file is not a claim this repo makes — reading one as
    a repo statement is the same defect this gate reports about numbers."""
    rc, out = _git(repo, "ls-files")
    return out.splitlines() if rc == 0 else []


def check_undeclared_places(repo: Path) -> list[str]:
    """Find "this is the current release" claims outside _TRACKED_PLACES.

    Check 4 watches the places somebody declared. This one watches for places nobody did: a sentence
    that starts stating the current release is, from that moment, a place that can go stale, and
    nothing was looking at it. The finding asks for a decision (declare it, or reword it), because a
    sweep cannot know whether a claim is meant to be current.
    """
    declared = {rel for rel, _, _ in _TRACKED_PLACES}
    problems: list[str] = []
    for rel in _tracked_files(repo):
        if rel in declared or rel.startswith(_SWEEP_EXCLUDE_PREFIXES):
            continue
        p = repo / rel
        try:
            text = p.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue                      # binary or unreadable: no claim to read, not a failure
        for nr, zeile in enumerate(text.splitlines(), 1):
            treffer = _CURRENT_CLAIM.search(zeile)
            if treffer:
                problems.append(
                    f"{rel}:{nr}: states a current version ({treffer.group(1)}, in "
                    f"\"{treffer.group(0).strip()}\") but is not a declared place. Either add it to "
                    f"_TRACKED_PLACES so it is kept current, or reword it so it does not claim to be.")
                break                     # one finding per file is enough to force the decision
    return problems


def check_tracked_places(repo: Path, version: str, herkunft: str = "the source file") -> list[str]:
    """Every declared "this is the current release" statement must name `version`.

    A missing file or a vanished anchor phrase is a failure, not a pass: if the sentence was
    reworded, nobody is checking that place any more and the gate would go quietly blind.
    """
    problems: list[str] = []
    for rel, pattern, beschreibung in _TRACKED_PLACES:
        path = repo / rel
        if not path.is_file():
            problems.append(f"{rel}: tracked version place is missing (expected {beschreibung})")
            continue
        found = pattern.findall(_read(path))
        if not found:
            problems.append(
                f"{rel}: {beschreibung} was not found — the anchor moved or was reworded, so this "
                f"place is no longer being checked. Fix the file or update _TRACKED_PLACES.")
            continue
        wrong = sorted({v for v in found if v != version})
        if wrong:
            problems.append(f"{rel}: {beschreibung} states {wrong} but the source version is "
                            f"{version}, read from {herkunft}")
    return problems


def _fetch(url: str, timeout: float) -> str | None:
    """Fetch a URL as text. None on ANY failure — unreachable is a state, not an exception."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "proofbundle-version-gate"})
        with urllib.request.urlopen(req, timeout=timeout) as r:   # noqa: S310 (fixed https URLs)
            return r.read().decode("utf-8", "replace")
    except (urllib.error.URLError, OSError, ValueError, TimeoutError):
        return None


def check_external(version: str, timeout: float = 15.0,
                   herkunft: str = "the source file") -> list[tuple[str, str, str]]:
    """Compare the source version against PyPI and the project page.

    Returns (surface, state, detail) with state in {"OK", "ABWEICHUNG", NICHT_MESSBAR}.
    Never raises: a network that is down must not decide a release question by accident.
    """
    ergebnisse: list[tuple[str, str, str]] = []

    roh = _fetch(_PYPI_JSON, timeout)
    if roh is None:
        ergebnisse.append(("PyPI", NICHT_MESSBAR, f"{_PYPI_JSON} not reachable"))
    else:
        try:
            veroeffentlicht = json.loads(roh)["info"]["version"]
        except (ValueError, KeyError, TypeError):
            ergebnisse.append(("PyPI", NICHT_MESSBAR, "response was not the expected JSON shape"))
        else:
            ergebnisse.append(("PyPI", "OK" if veroeffentlicht == version else "ABWEICHUNG",
                               f"PyPI states {veroeffentlicht} (published sdist/wheel version), "
                               f"source states {version}, read from {herkunft}"))

    seite = _fetch(_PROJECT_PAGE, timeout)
    if seite is None:
        ergebnisse.append(("project page", NICHT_MESSBAR, f"{_PROJECT_PAGE} not reachable"))
    else:
        genannt = sorted(set(_PAGE_VERSION.findall(seite)))
        if not genannt:
            # Also NICHT MESSBAR, not a pass: an empty body (a redirect that was not followed, or a
            # reworded page) must never read as agreement.
            ergebnisse.append(("project page", NICHT_MESSBAR,
                               "no `PyPI latest <code>X.Y.Z</code>` statement found on the page"))
        elif genannt == [version]:
            ergebnisse.append(("project page", "OK",
                               f"page states {version} as `PyPI latest`, matching {version} "
                               f"read from {herkunft}"))
        else:
            ergebnisse.append(("project page", "ABWEICHUNG",
                               f"page states {genannt} as `PyPI latest`, source states {version}, "
                               f"read from {herkunft}"))
    return ergebnisse


def main() -> int:
    ap = argparse.ArgumentParser(description="proofbundle release-integrity gate")
    ap.add_argument("--repo", default=".", help="repo root (default: cwd)")
    ap.add_argument("--external", action="store_true",
                    help="also compare against PyPI and the project page (needs the network)")
    ap.add_argument("--require-external", action="store_true",
                    help="with --external: treat NICHT MESSBAR as a failure (for the release checklist)")
    ap.add_argument("--timeout", type=float, default=15.0, help="per-request timeout for --external")
    a = ap.parse_args()
    repo = Path(a.repo).resolve()
    problems = check(repo)

    version, herkunft = _source_version(repo)

    aussen: list[tuple[str, str, str]] = []
    if a.external or a.require_external:
        if not version:
            problems.append("cannot check external surfaces: no source version found")
        else:
            aussen = check_external(version, a.timeout, herkunft)
            print("external surfaces:")
            for name, state, detail in aussen:
                print(f"  - {name}: {state} ({detail})")
            for name, state, detail in aussen:
                if state == "ABWEICHUNG":
                    problems.append(f"{name} disagrees with the source version: {detail}")
                elif state == NICHT_MESSBAR and a.require_external:
                    problems.append(f"{name} is {NICHT_MESSBAR} and --require-external was given: {detail}")

    if problems:
        print("check_version_and_changelog: FAIL")
        for p in problems:
            print(f"  - {p}")
        return 1

    # The number names its object and its source, here too: an OK line that does not say WHICH
    # version was verified leaves the reader to assume one.
    quelle = f"source version {version}, read from {herkunft}"
    geprueft = ("single-sourced across pyproject.toml/__init__.py/CITATION.cff, tracked places "
                "current, changelog carries the section, no undelivered post-tag drift, "
                "no undeclared place claiming a current version")
    if not aussen:
        print(f"check_version_and_changelog: OK — {quelle}; {geprueft}. "
              f"External surfaces NOT checked (neither --external nor --require-external given).")
    elif any(s == NICHT_MESSBAR for _, s, _ in aussen):
        offen = ", ".join(n for n, s, _ in aussen if s == NICHT_MESSBAR)
        print(f"check_version_and_changelog: OK — {quelle}; {geprueft}. "
              f"NOT verified ({NICHT_MESSBAR}): {offen}.")
    else:
        print(f"check_version_and_changelog: OK — {quelle}; {geprueft}; external surfaces agree.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
