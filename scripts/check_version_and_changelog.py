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

# EINE Regel fuer beide Stellen dieser Datei, und der Name sagt jetzt, was sie kann.
#
# WARUM SIE SICH GEAENDERT HAT: das alte Muster war reines SemVer und konnte eine
# PEP-440-Post-Release nicht ausdruecken. Aus "5.1.0.post1" las es "5.1.0" und verglich das gegen
# die (korrekt gelesene) volle Quellversion — FAIL in BEIDE Richtungen, gemessen 04.09.2026: die
# Dokumente sagen 5.1.0 -> FAIL, sie sagen 5.1.0.post1 -> AUCH FAIL. Ein Tor, das eine gueltige
# Versionsform strukturell nicht bestehen kann, ist keine Pruefung, sondern eine Sperre.
#
# ABGEDECKT sind die PEP-440-Formen, die dieses Projekt wirklich fuehrt: die drei Zahlen, dazu
# optional eine Vorabversion (a/b/rc + Zahl, RELEASE.md dokumentiert 2.0.0b1), eine Post-Release
# (.postN) und eine Entwicklungsfassung (.devN). Die ZAHL nach dem Suffix ist PFLICHT — "5.1.0.post"
# ohne sie ist keine Version, und ein Muster, das sie optional macht, wuerde Tippfehler durchwinken.
_SEMVER = (r"([0-9]+\.[0-9]+\.[0-9]+"
           r"(?:\.?(?:a|b|rc)[0-9]+)?"
           r"(?:\.post[0-9]+)?"
           r"(?:\.dev[0-9]+)?)"
           # KEIN alphanumerisches Zeichen danach. Ohne diese Grenze las das Muster aus
           # "proofbundle 5.1.0b7n0de.com" die Zeichenfolge "5.1.0b7" — es hielt den ANFANG
           # UNSERES EIGENEN Markennamens fuer eine Beta-Nummer. Gemessen 04.09.2026 von einer
           # Gegenlese-Linse; im Bestand heute kein Vorkommen, aber ausgerechnet diese Marke
           # beginnt mit "b" plus Ziffer. Die Grenze verwirft solche Treffer ganz, statt einen
           # verstuemmelten zu liefern: eine halbe Version ist schlimmer als keine.
           r"(?![0-9A-Za-z])")

# Check 4 — prose that states the CURRENT version and must therefore track the source.
# Each entry: (path, anchor regex with one capture group, human description of the anchor).
# Only add a place here if it means "this is the current release". Never add a "since"/"as of"
# statement: those are history, and a gate that bumps history manufactures false claims.
#
# README.md IS DECLARED, by an owner decision on 2026-09-23. Check 6 found its four release claims
# and asked for exactly this choice: declare them, reword them, or name an exception. Declared, they
# are kept current by Check 4 at every bump instead of being reported as undeclared.
#
# EACH ANCHOR NAMES THIS PROJECT, not just a shape. Check 4 reads every match in the file and
# demands the source version of each, so an anchor as wide as the Check 6 shape would demand that
# `pip install <another package>==<its version>` be raised to this release. The shape asks "is this
# a release claim?"; the anchor asks "is this OUR release claim?".
#
# THE HEADLINE CARRIES THE VERSION TWICE, as link text and in the tag URL, and the anchor captures
# both. Bound to the URL alone, a headline raised halfway (new URL, old text) would read as current,
# and the front page would name one release while linking to another.
#
# THE PROPERTY IS "README PINS NO RELEASE OF THIS PROJECT BUT THE CURRENT ONE", in whatever form.
# Three review lenses on 2026-09-25 showed why it is stated that way and not as a list of
# instruction forms. The first found that an unbound install anchor turned a prose sentence
# recalling an older command red. Binding the anchors to the start of an instruction line then
# traded that false red for a silent miss: a stale `- pip install`, `pip3`, `sudo pip`,
# `pip install -U`, `pipx`, `poetry add`, `py -m pip` or table-cell instruction next to a raised
# canonical line matched no anchor, and Check 6 reads an older number as history. Each round closed
# the forms the last lens named, and the next lens named more. A list of forms does not close; a
# property does, and a silent miss costs more than a loud red.
#
# So every pinned reference to this project in README.md must name the current release: a
# `proofbundle==X.Y.Z` pin in whatever command it stands, a URL into this repository at tag
# `vX.Y.Z`, and a link to a release tag. A sentence that recalls an older release with a pin turns
# red at the next bump, and the remedy is to reword it, for example by linking the changelog,
# never to raise it. That keeps the rule above: history is not bumped, it is simply not written as a
# pin on the front page.
#
# THE LIMIT, stated because a lens executed it: the anchors trust that a matching line is a visible
# one. A correct copy of the headline hidden in an HTML comment, next to a visible headline reworded
# into another form, passes both checks. That is concealment rather than drift, and no anchor over
# the text can tell a rendered line from an unrendered one.
_TRACKED_PLACES = [
    ("RELEASE.md", re.compile(r"current:\s*v?" + _SEMVER), "the `(current: X.Y.Z)` note"),
    ("docs/readiness_pack/PROGRESS.md",
     re.compile(r"current release:\s*v?" + _SEMVER), "the `(current release: X.Y.Z)` note"),
    ("README.md",
     re.compile(r"(?m)^\*\*\[v?" + _SEMVER
                + r"\]\(https://github\.com/b7n0de/proofbundle/releases/tag/v?" + _SEMVER + r"\)"),
     "the release headline `**[vX.Y.Z](…/releases/tag/vX.Y.Z)`, link text and tag URL"),
    ("README.md",
     re.compile(r"(?<![\w.-])proofbundle(?:\[[A-Za-z0-9_,.-]+\])?\s*==\s*v?" + _SEMVER),
     "every `proofbundle==X.Y.Z` pin, in whatever command it stands"),
    ("README.md",
     re.compile(r"(?:raw\.githubusercontent\.com|github\.com)/b7n0de/proofbundle/"
                r"(?:(?:blob|tree|raw)/)?v" + _SEMVER + r"/"),
     "every URL into this repository pinned to a release tag `vX.Y.Z`"),
    ("README.md",
     re.compile(r"github\.com/b7n0de/proofbundle/releases/tag/v?" + _SEMVER),
     "every link to a release tag of this project"),
]

# Check 6 — shapes that mean "this IS the current release". Deliberately narrow: "since X.Y.Z" and
# "as of X.Y.Z" record history and must never match, or the sweep would demand that facts be bumped.
_CURRENT_CLAIM = re.compile(
    r"(?:current|latest)(?:\s+(?:release|version))?\s*:?\s*v?" + _SEMVER, re.IGNORECASE)

# A CLAIM IS NOT A WORD. Measured 2026-09-23 against README.md at origin/main: it states the
# current release in SEVEN lines and FOUR shapes, and `_CURRENT_CLAIM` matched none of them,
# because not one carries the word "current" or "latest". Their forms, with the version written
# as a placeholder — see the paragraph below on why this comment may not spell it out:
#
#     **[vX.Y.Z](…/releases/tag/vX.Y.Z) · Beta · …**
#     python -m pip install proofbundle==X.Y.Z
#     https://raw.githubusercontent.com/b7n0de/proofbundle/vX.Y.Z/examples/example_bundle.json
#
# AND THIS COMMENT ALMOST BECAME THE DEFECT IT DESCRIBES. Written with the real version in the
# examples, the first run of the new rule reported TWO findings: README.md — the intended one —
# and this file, line 101. The sweep cannot tell a claim from a quotation of one, and the module
# head already says why that matters: an illustration that spells out this project's own release
# becomes a place that goes stale. The existing example above obeys that rule by using a foreign
# tool's version; this one obeys it with placeholders. No carve-out for this file: a checker that
# exempts itself stops checking the file most likely to quote claims.
#
# Check 6 exists precisely so that "the place nobody declared" cannot go stale unwatched — and it
# was watching for one sentence form while the most consequential statements in the project's
# front page used three others. Bump the version and leave this file alone, and the gate stays
# green while the README still tells a reader to install the old release.
#
# NAMED SHAPES, NOT ONE BIG PATTERN: the finding then says WHICH kind of claim it found, and the
# reader knows whether to bump it, declare it, or reword it. One fused regex would report a hit
# and leave that question open.
#
# THE PRICE IS MEASURED, because a sweep that floods gets switched off: over every tracked file
# outside the excluded prefixes, these three shapes hit FOUR times, all of them in README.md.
# That is the file the finding is about. Those four lines are declared places now (see
# _TRACKED_PLACES), so on the real tree this sweep reports none of them and Check 4 keeps them.
#
# WHAT IS DELIBERATELY NOT HERE: a bare mention like `docs/release_scope/6.1.0.md` names a
# document, and `since v6.1.0` records history. Neither says "this is the release you get", and a
# gate that demanded they be bumped would manufacture false claims — the rule the module head
# states and this addition keeps.
# THE SHAPE ALONE CLAIMS NOTHING — the number decides. Found 2026-09-23 by a cross-reading lens,
# with executed counter-examples:
#
#   "pip uninstall package==<older release>"              an instruction to REMOVE
#   "[<older release> release notes](…/releases/tag/…)"    a citation of HISTORY
#   ".../package/v<older release>/examples/…"              the same as a raw URL
#
# (Placeholders here too, for the same reason as above: with the numbers spelled out, the sweep
# reported these three comment lines. An example that spells out the shape IS the shape.)
#
# The first version reported all three. For the second and third, **both offered remedies would be
# wrong**: declaring one would make a correct historical statement get raised to the current
# release in future, turning a fact into a lie, exactly the damage the module head warns about.
# Rewording would rewrite correct history for no reason.
#
# THE DISTINCTION THAT CARRIES: a WORD such as "current" claims currency on its own, whatever
# number stands beside it, so a line "current release: <older release>" is a STALE currency claim
# and belongs in a report. A SHAPE claims it only when the number is the current one; if an older
# one stands there, it is history.
#
# (This example is a placeholder as well, because the rule caught it on its own first run: with a
# spelled-out number the sweep reported this very line. The word-based shape fires independently of
# the number, which is the point, so it cannot tell a quotation from a claim. Third case of the
# same class in one day.)
#
# Each shape therefore carries a `nur_aktuelle` field. Check 6 reports a shape line only when its
# number equals the source version — then it is an undeclared currency claim that goes stale at the
# next bump. What happens to a DECLARED place afterwards is Check 4's job: it keeps that one
# current. The division of labour was already there; my first version walked past it.
#
# `\binstall` with a word boundary, because `install\s+` otherwise matches the tail of
# `uninstall` — measured against "pip uninstall proofbundle==6.0.0", which was reported as a
# currency claim.
_CLAIM_SHAPES = [
    ("install pin", re.compile(r"\binstall\s+[^\s]*==\s*v?" + _SEMVER, re.IGNORECASE), True,
     "an install instruction pinned to a version — a reader acts on it, so it goes stale the "
     "moment the version moves"),
    ("release tag link", re.compile(r"/releases?/tag/v?" + _SEMVER, re.IGNORECASE), True,
     "a link to a release tag, presented as the release this project is at"),
    ("version-pinned URL", re.compile(r"/v" + _SEMVER + r"/", re.IGNORECASE), True,
     "a URL pinned to a version tag — it keeps serving the old content after a bump"),
    ("current/latest phrase", _CURRENT_CLAIM, False,
     "a sentence stating the current release in words — the wording claims currency whatever "
     "number follows, so a stale one is a finding too"),
]
# Not swept: test fixtures state wrong versions ON PURPOSE, and audit artifacts are frozen history.
# Signed receipts are frozen too: a version inside one cannot be kept current without breaking its
# signature, so a finding there would ask for a remedy that does not exist. They are also exactly
# what release-integrity.yml does not run for, and a gate that reads files its only runner skips
# gives a verdict that depends on what else happened to change in the same push.
_SWEEP_EXCLUDE_PREFIXES = ("tests/", "audit_artifacts/", "receipts/")

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
    """The TOP-LEVEL `version:` of CITATION.cff, bound to the structure and not to the order.

    The first version of this allowed leading whitespace and took the first match. CITATION.cff
    carries two version keys: the top-level one, which is the package version, and an INDENTED one
    inside the identifiers block, which names the revision an older DOI was deposited for.
    Measured 2026-09-20: line 18 `version: 6.1.0` and line 40 `    version: 6.0.0`. The reader
    returned the right one only because line 18 comes first, and no test constructed a file where
    it does not. Reorder the blocks, or add an older revision above, and a release gate would read
    a historical number as the version being shipped.

    A top-level key has no indentation, and that is the property rather than the position.
    """
    m = re.search(r'(?m)^version\s*:\s*["\']?([0-9]+\.[0-9]+\.[0-9]+[^"\'\s]*)',
                  _read(repo / "CITATION.cff"))
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
    """Vergleichsschluessel nach PEP 440. Zwei Gegenlese-Linsen haben die erste Fassung widerlegt.

    FUND 1, die Vorabphasen. Sie bekamen ALLE denselben Rang und wurden nur nach ihrer Nummer
    geordnet. Gemessen: `_semver_tuple("1.0.0b1") == _semver_tuple("1.0.0rc1")` — identisch, also
    nicht unterscheidbar — und `_semver_tuple("2.0.0a3") > _semver_tuple("2.0.0b1")`, was falsch
    ist: JEDE Alpha liegt vor JEDER Beta. Nicht hypothetisch, RELEASE.md dokumentiert echte
    2.0.0b1/b2/b3-Tags dieses Projekts.

    FUND 2, zusammengesetzte Suffixe. `5.1.0.post1.dev2` ergab dasselbe wie `5.1.0.post1`, das
    zweite Suffix fiel weg — die `elif`-Kette nahm das erste und verwarf den Rest.

    DIE ORDNUNG, die PEP 440 verlangt, und sie ist nicht symmetrisch:
        X.Y.Z.devN  <  X.Y.ZaN.devM  <  X.Y.ZaN  <  X.Y.ZbN  <  X.Y.ZrcN
                    <  X.Y.Z  <  X.Y.Z.postN
    Zwei Asymmetrien tragen das: FEHLT die Vorabversion, sortiert das NACH allen Vorabversionen
    (die Freigabe kommt zuletzt) — ausser wenn nur eine Entwicklungsfassung da ist, dann DAVOR.
    Und ein fehlendes `dev` sortiert NACH einem vorhandenen. Wer beide Faelle mit derselben Null
    belegt, dreht die Ordnung an genau diesen Stellen um.
    """
    _VOR, _NACH = -(10 ** 9), 10 ** 9
    core = v.split("-")[0].split("+")[0]
    m = re.match(r"^([0-9]+)\.([0-9]+)\.([0-9]+)"
                 r"(?:\.?(a|b|rc)([0-9]+))?"
                 r"(?:\.post([0-9]+))?"
                 r"(?:\.dev([0-9]+))?$", core)
    if not m:
        # UNVERAENDERT fuer alles, was keine Version ist (Review-Tags etwa). Die Zahl der Glieder
        # muss trotzdem stimmen, sonst sind Treffer und Fallback nicht vergleichbar.
        parts = core.split(".")
        haupt = tuple(int(x) if x.isdigit() else 0 for x in (parts + ["0", "0", "0"])[:3])
        return haupt + (_NACH, 0, _VOR, _NACH)
    haupt = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    vorab, post, dev = m.group(4), m.group(6), m.group(7)
    if vorab is not None:
        vorab_key = ({"a": 0, "b": 1, "rc": 2}[vorab], int(m.group(5)))
    elif post is None and dev is not None:
        vorab_key = (_VOR, 0)          # eine reine Entwicklungsfassung liegt VOR jeder Vorabversion
    else:
        vorab_key = (_NACH, 0)         # keine Vorabversion heisst: die Freigabe selbst, sie kommt zuletzt
    post_key = _VOR if post is None else int(post)
    dev_key = _NACH if dev is None else int(dev)
    return haupt + vorab_key + (post_key, dev_key)


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


def check_undeclared_places(repo: Path, version: str | None = None) -> list[str]:
    """Find "this is the current release" claims outside _TRACKED_PLACES.

    Check 4 watches the places somebody declared. This one watches for places nobody did: a sentence
    that starts stating the current release is, from that moment, a place that can go stale, and
    nothing was looking at it. The finding asks for a decision (declare it, or reword it), because a
    sweep cannot know whether a claim is meant to be current.

    `version` is the source version; without it, it is read here. It decides the shape-based
    patterns (see `_CLAIM_SHAPES`): a shape carrying an OLDER number cites history and is not a
    finding.
    """
    if version is None:
        version, _ = _source_version(repo)
    # A DECLARATION COVERS ONE PATTERN, NOT A WHOLE FILE.
    #
    # FOUND 2026-09-23 by a cross-reading lens, by execution rather than by guess: this used to read
    # `declared = {rel for rel, _, _ in _TRACKED_PLACES}` with `if rel in declared: continue` below
    # it. Declaring a file for ONE pattern took it out of this sweep ENTIRELY.
    #
    # The lens measured that on the nearest case: declare README.md for the tag link — exactly the
    # remedy my own owner card offers as option A — and `check_undeclared_places` afterwards returns
    # NOTHING, although three further places of the same class stand unchanged in the same file.
    # Check 4 then checks only the one declared pattern; the three siblings are unobserved from that
    # moment on.
    #
    # That is WORSE than the starting state: undetected before, permanently silenced by a
    # declaration afterwards — and the sweep reported quiet.
    #
    # From now on a declaration covers the LINE its anchor matches and nothing else. Another claim
    # shape in the same file stays visible.
    declared_patterns: dict[str, list] = {}
    for rel_d, pattern_d, _ in _TRACKED_PLACES:
        declared_patterns.setdefault(rel_d, []).append(pattern_d)
    problems: list[str] = []
    for rel in _tracked_files(repo):
        if rel.startswith(_SWEEP_EXCLUDE_PREFIXES):
            continue
        angemeldet = declared_patterns.get(rel, [])
        p = repo / rel
        try:
            text = p.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue                      # binary or unreadable: no claim to read, not a failure
        gefunden = False
        for nr, zeile in enumerate(text.splitlines(), 1):
            # The LINE a declared anchor matches is covered: Check 4 keeps that one current.
            # Every other line of the same file stays the subject of this sweep.
            if any(p.search(zeile) for p in angemeldet):
                continue
            for form, muster, nur_aktuelle, beschreibung in _CLAIM_SHAPES:
                treffer = muster.search(zeile)
                if not treffer:
                    continue
                # A SHAPE carrying an older number is history, not a claim.
                if nur_aktuelle and version and treffer.group(1) != version:
                    continue
                problems.append(
                    f"{rel}:{nr}: states a current version ({treffer.group(1)}) as a {form} — "
                    f"{beschreibung} — in \"{treffer.group(0).strip()}\", but is not a declared "
                    f"place. Either add it to _TRACKED_PLACES so it is kept current, or reword it "
                    f"so it does not claim to be.")
                gefunden = True
                break
            if gefunden:
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
        # An anchor with two captures (the README headline) yields pairs; every captured number is
        # a statement of the version, so each one is compared, not only the first.
        found = [v for hit in pattern.findall(_read(path))
                 for v in (hit if isinstance(hit, tuple) else (hit,))]
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
