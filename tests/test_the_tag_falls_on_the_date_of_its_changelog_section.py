"""The release tag falls on the date the CHANGELOG section of its version names, in UTC (finding A8-1).

CHANGELOG.md names a date in the heading of every release, `## [6.5.0] - 2026-11-08`. Nothing compared it with the
day the tag fell: an annotated tag v6.5.0 dated 2026-11-06 on the tree of 65bd4b7a left the version gate at exit 0,
and so did the pre-tag gates of release.yml, which read the section but not its date. Read over the release tags
v5.0.0 to v6.4.0 of this repository, eight of the nine with a section fell in UTC on another day than its date,
and v5.1.0.post1 has no section.

The property held here: where the clone holds the annotated tag v<version> of the tree's version, its tagger date in
UTC is the date of the `## [<version>]` heading in the tree the tag points to. `--tag <name>` makes the check
mandatory, as release.yml runs it: the tag must exist, be annotated, name the tree's version, and its section must
carry a real calendar date. Without `--tag`, a clone with no such tag has nothing to compare and says so in a note,
and a lightweight tag is noted rather than judged, since release.yml refuses it on its own and the drift check reads
lightweight tags in its fixtures.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts" / "check_version_and_changelog.py"
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
VERSION = "6.5.0"
DATE = "2026-11-08"


def _heading_default() -> str:
    return f"## [{VERSION}] - {DATE}"


def _git(repo: Path, *args: str, env: dict | None = None) -> subprocess.CompletedProcess:
    full = {**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, **(env or {})}
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, env=full, check=True)


def _tree(repo: Path, heading: str | None = None, unreleased_only: bool = False) -> None:
    """A tree of version 6.5.0 that every other check of the gate passes, committed in a fresh repository."""
    (repo / "src" / "proofbundle").mkdir(parents=True)
    (repo / "pyproject.toml").write_text(f'[project]\nname = "proofbundle"\nversion = "{VERSION}"\n', encoding="utf-8")
    (repo / "src" / "proofbundle" / "__init__.py").write_text(f'__version__ = "{VERSION}"\n', encoding="utf-8")
    (repo / "CITATION.cff").write_text(f"cff-version: 1.2.0\nversion: {VERSION}\n", encoding="utf-8")
    (repo / "RELEASE.md").write_text(
        f"# Release\n\nthe stable default has moved on to the 3.x line (current: {VERSION}) and so on.\n",
        encoding="utf-8")
    (repo / "docs" / "readiness_pack").mkdir(parents=True)
    (repo / "docs" / "readiness_pack" / "PROGRESS.md").write_text(
        f"# Progress\n\nThe denominator is the distance from 3.3.0 (current release: {VERSION}) to stable.\n",
        encoding="utf-8")
    (repo / "README.md").write_text(
        f"## Current release\n\n"
        f"**[v{VERSION}](https://github.com/b7n0de/proofbundle/releases/tag/v{VERSION}) · Beta**\n\n"
        f"    python -m pip install proofbundle=={VERSION}\n", encoding="utf-8")
    entry = "A release. Semantics do not change.\n\n- something\n\n"
    if unreleased_only:
        sections = f"## [Unreleased]\n\n{entry}"
    else:
        sections = f"## [Unreleased]\n\n{heading if heading is not None else _heading_default()}\n\n{entry}"
    (repo / "CHANGELOG.md").write_text(
        f"# Changelog\n\n{sections}## [6.4.0] - 2026-10-27\n\nThe release before.\n\n- older\n", encoding="utf-8")
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "add", "-A")
    _git(repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "release: 6.5.0",
         env={"GIT_COMMITTER_DATE": "2026-11-07T10:00:00+0000", "GIT_AUTHOR_DATE": "2026-11-07T10:00:00+0000"})


def _tag(repo: Path, when: str | None, name: str = f"v{VERSION}") -> None:
    """An annotated tag dated `when` (git's date form with its offset), or a lightweight tag when `when` is None."""
    if when is None:
        _git(repo, "tag", name)
    else:
        _git(repo, "-c", "user.name=t", "-c", "user.email=t@t", "tag", "-a", name, "-m", f"proofbundle {VERSION}",
             env={"GIT_COMMITTER_DATE": when})


def _gate(repo: Path, *extra: str) -> tuple[int, str]:
    p = subprocess.run([sys.executable, "-B", str(GATE), "--repo", str(repo), *extra],
                       capture_output=True, text=True, cwd=str(repo))
    assert "Traceback" not in p.stderr, p.stderr
    return p.returncode, p.stdout + p.stderr


def test_a_tag_on_another_day_than_its_section_turns_the_gate_red(tmp_path):
    """The measurement of A8-1 as a case: an annotated tag dated two days before its section, exit 0 on 65bd4b7a."""
    _tree(tmp_path)
    _tag(tmp_path, "2026-11-06T12:00:00+0000")
    rc, out = _gate(tmp_path)
    assert rc == 1, out
    assert "2026-11-06" in out and DATE in out and f"v{VERSION}" in out, out


def test_control_a_tag_on_the_day_of_its_section_stays_green(tmp_path):
    _tree(tmp_path)
    _tag(tmp_path, "2026-11-08T12:00:00+0000")
    rc, out = _gate(tmp_path)
    assert rc == 0, out


@pytest.mark.parametrize("when", [
    "2026-11-09T12:00:00+0000",   # one day late
    "2026-11-07T12:00:00+0000",   # one day early
    "2026-11-07T23:59:59+0000",   # the last second before midnight UTC
    "2026-11-09T00:00:00+0000",   # midnight UTC that ends the day
    "2026-11-08T00:30:00+0100",   # the 8th on the tagger's clock, 23:30 on the 7th in UTC
    "2026-11-08T23:30:00-0100",   # the 8th on the tagger's clock, 00:30 on the 9th in UTC
], ids=["one day late", "one day early", "23:59:59 UTC before", "00:00:00 UTC after", "local 8th, UTC 7th",
        "local 8th, UTC 9th"])
def test_a_planted_deviation_of_one_day_in_utc_is_red(tmp_path, when):
    _tree(tmp_path)
    _tag(tmp_path, when)
    for extra in ((), ("--tag", f"v{VERSION}")):
        rc, out = _gate(tmp_path, *extra)
        assert rc == 1, (extra, out)


@pytest.mark.parametrize("when", [
    "2026-11-08T00:00:00+0000",   # midnight UTC that opens the day
    "2026-11-08T23:59:59+0000",   # the last second of the day
    "2026-11-07T23:30:00-0100",   # the 7th on the tagger's clock, 00:30 on the 8th in UTC
    "2026-11-09T00:30:00+0100",   # the 9th on the tagger's clock, 23:30 on the 8th in UTC
], ids=["00:00:00 UTC", "23:59:59 UTC", "local 7th, UTC 8th", "local 9th, UTC 8th"])
def test_the_edges_of_the_day_in_utc_are_green(tmp_path, when):
    _tree(tmp_path)
    _tag(tmp_path, when)
    rc, out = _gate(tmp_path, "--tag", f"v{VERSION}")
    assert rc == 0, out
    assert f"tag v{VERSION} falls on {DATE} UTC" in out, out


def test_a_lightweight_tag_is_refused_when_the_release_names_it(tmp_path):
    _tree(tmp_path)
    _tag(tmp_path, None)
    rc, out = _gate(tmp_path, "--tag", f"v{VERSION}")
    assert rc == 1 and "annotated" in out, out


def test_control_a_lightweight_tag_without_tag_is_a_note_not_a_verdict(tmp_path):
    _tree(tmp_path)
    _tag(tmp_path, None)
    rc, out = _gate(tmp_path)
    assert rc == 0, out
    assert "check 8" in out and "annotated" in out, out


@pytest.mark.parametrize("heading,words", [
    (f"## [{VERSION}]", "names no date"),
    (f"## [{VERSION}] - YYYY-MM-DD", "names no date"),
    (f"## [{VERSION}] - 2026-11-31", "no calendar date"),
    (f"## [{VERSION}] - 2026-11-08 trailing words", "names no date"),
], ids=["no date", "the placeholder", "no calendar day", "words after the date"])
def test_a_section_without_a_readable_date_is_red(tmp_path, heading, words):
    _tree(tmp_path, heading=heading)
    _tag(tmp_path, "2026-11-08T12:00:00+0000")
    rc, out = _gate(tmp_path, "--tag", f"v{VERSION}")
    assert rc == 1 and words in out, out


def test_control_a_note_in_brackets_after_the_date_is_read_as_the_older_headings_write_it(tmp_path):
    _tree(tmp_path, heading=f"## [{VERSION}] - {DATE} (the profile a stranger can read · MINOR)")
    _tag(tmp_path, "2026-11-08T12:00:00+0000")
    rc, out = _gate(tmp_path, "--tag", f"v{VERSION}")
    assert rc == 0, out


def test_a_version_only_under_unreleased_has_no_date_to_tag_on(tmp_path):
    _tree(tmp_path, unreleased_only=True)
    _tag(tmp_path, "2026-11-08T12:00:00+0000")
    rc, out = _gate(tmp_path, "--tag", f"v{VERSION}")
    assert rc == 1 and f"## [{VERSION}]" in out, out


def test_the_named_tag_must_exist_and_name_the_version_of_the_tree(tmp_path):
    _tree(tmp_path)
    rc, out = _gate(tmp_path, "--tag", f"v{VERSION}")
    assert rc == 1 and "no tag" in out, out
    _tag(tmp_path, "2026-11-08T12:00:00+0000", name="v6.5.1")
    rc, out = _gate(tmp_path, "--tag", "v6.5.1")
    assert rc == 1 and "6.5.1" in out and VERSION in out, out


def test_control_no_tag_of_the_version_is_a_note_before_the_tag(tmp_path):
    _tree(tmp_path)
    rc, out = _gate(tmp_path)
    assert rc == 0, out
    assert "check 8" in out and f"no tag v{VERSION}" in out, out


def test_the_section_is_read_in_the_tree_the_tag_points_to(tmp_path):
    """A later commit that moves the date to the tag's day does not repair a tag that fell on another day."""
    _tree(tmp_path)
    _tag(tmp_path, "2026-11-09T12:00:00+0000")
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(changelog.read_text(encoding="utf-8").replace(DATE, "2026-11-09"), encoding="utf-8")
    _git(tmp_path, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-am", "docs: move the date")
    rc, out = _gate(tmp_path, "--tag", f"v{VERSION}")
    assert rc == 1 and DATE in out, out


def _steps(text: str) -> list[str]:
    """The `- name:` steps of release.yml in file order, each with the lines under it."""
    steps: list[str] = []
    for line in text.splitlines():
        if re.match(r"^ {6}- (name|uses):", line):
            steps.append(line)
        elif steps:
            steps[-1] += "\n" + line
    return steps


def test_release_yml_runs_the_tag_date_check_before_the_build_and_every_upload():
    steps = _steps(RELEASE_WORKFLOW.read_text(encoding="utf-8"))
    call = 'python scripts/check_version_and_changelog.py --repo . --tag "$GITHUB_REF_NAME"'
    checking = [i for i, s in enumerate(steps) if call in s]
    assert len(checking) == 1, f"release.yml runs the tag date check {len(checking)} times"
    first_build = next(i for i, s in enumerate(steps) if "python -m build" in s or "Build sdist" in s)
    uploads = [i for i, s in enumerate(steps) if re.search(r"upload-artifact|gh-action-pypi-publish|action-gh-release|"
                                                           r"gh release|attest-build-provenance", s)]
    assert uploads, "release.yml names no upload step; the reading of the steps no longer holds"
    assert checking[0] < first_build and all(checking[0] < i for i in uploads), (checking, first_build, uploads)
