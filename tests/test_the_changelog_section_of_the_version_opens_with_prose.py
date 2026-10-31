"""The CHANGELOG section of the version being released opens with prose before its first subsection.

RELEASE.md asks in its release gate that "the CHANGELOG entry says explicitly whether semantics
change". The release-integrity gate checked only that a `## [<version>]` heading exists. The dry run
of 6.5.0 (finding K6) renamed `## [Unreleased]` to `## [6.5.0]` the way a release preparation does,
and the heading stood directly over `### Added`: the gate stayed green, and so did the suite.

Whether a paragraph says the right thing about semantics is a reading, not a pattern. What the gate
can hold is that the section of the version opens with text at all, as 6.4.0 does with its two
opening paragraphs. Older sections are history and are not read, and an `[Unreleased]` block may open
with a subsection, because it is not yet an entry.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "chk_k6", Path(__file__).resolve().parents[1] / "scripts" / "check_version_and_changelog.py")
chk = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(chk)

VERSION = "3.0.1"


def _repo(t: Path, changelog: str) -> Path:
    """A tree that passes every other check of the gate, with the given CHANGELOG."""
    (t / "src" / "proofbundle").mkdir(parents=True, exist_ok=True)
    (t / "docs" / "readiness_pack").mkdir(parents=True, exist_ok=True)
    (t / "pyproject.toml").write_text(f'[project]\nname = "proofbundle"\nversion = "{VERSION}"\n',
                                      encoding="utf-8")
    (t / "src" / "proofbundle" / "__init__.py").write_text(f'__version__ = "{VERSION}"\n', encoding="utf-8")
    (t / "CITATION.cff").write_text(f"cff-version: 1.2.0\nversion: {VERSION}\n", encoding="utf-8")
    (t / "RELEASE.md").write_text(f"# Release\n\n(current: {VERSION}) and so on.\n", encoding="utf-8")
    (t / "docs" / "readiness_pack" / "PROGRESS.md").write_text(
        f"# Progress\n\nfrom 3.3.0 (current release: {VERSION}) to stable.\n", encoding="utf-8")
    (t / "README.md").write_text(
        f"**[v{VERSION}](https://github.com/b7n0de/proofbundle/releases/tag/v{VERSION}) · Beta**\n\n"
        f"    python -m pip install proofbundle=={VERSION}\n", encoding="utf-8")
    (t / "CHANGELOG.md").write_text(changelog, encoding="utf-8")
    return t


def _opening_findings(problems: list[str]) -> list[str]:
    return [p for p in problems if "CHANGELOG.md" in p and "opens" in p]


def test_RED_a_version_section_that_opens_with_a_subsection_is_a_finding(tmp_path):
    """The case of the dry run: the release heading stands directly over `### Added`."""
    probs = chk.check(_repo(tmp_path, f"# Changelog\n\n## [{VERSION}] - 2026-10-31\n\n### Added\n\n- x\n\n"
                                      "## [3.0.0] - 2026-10-01\n\nThe first release.\n"))
    found = _opening_findings(probs)
    assert len(found) == 1 and f"[{VERSION}]" in found[0], probs


def test_RED_an_empty_version_section_is_a_finding(tmp_path):
    probs = chk.check(_repo(tmp_path, f"# Changelog\n\n## [{VERSION}] - 2026-10-31\n\n"
                                      "## [3.0.0] - 2026-10-01\n\nThe first release.\n"))
    assert len(_opening_findings(probs)) == 1, probs


def test_a_section_that_opens_with_a_paragraph_passes(tmp_path):
    probs = chk.check(_repo(tmp_path, f"# Changelog\n\n## [{VERSION}] - 2026-10-31\n\n"
                                      f"{VERSION} is a patch release following 3.0.0. Semantics do not change.\n\n"
                                      "### Fixed\n\n- x\n"))
    assert probs == [], probs


def test_an_older_section_is_history_and_is_not_read(tmp_path):
    """Only the section of the version being released is held; an older one stays as it was written."""
    probs = chk.check(_repo(tmp_path, f"# Changelog\n\n## [{VERSION}] - 2026-10-31\n\nA patch release.\n\n"
                                      "## [3.0.0] - 2026-10-01\n\n### Added\n\n- y\n"))
    assert probs == [], probs


def test_an_unreleased_block_above_may_open_with_a_subsection(tmp_path):
    probs = chk.check(_repo(tmp_path, "# Changelog\n\n## [Unreleased]\n\n### Added\n\n- z\n\n"
                                      f"## [{VERSION}] - 2026-10-31\n\nA patch release.\n\n### Fixed\n\n- x\n"))
    assert probs == [], probs
