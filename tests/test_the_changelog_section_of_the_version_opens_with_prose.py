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


# ── what GitHub renders as no paragraph is no opening (reading of 2026-11-01, sol-pro, P1 and P2) ─────────────────
#
# The first form held any line that is not blank. A thematic break, an HTML comment, a link reference definition, a
# code block and a setext heading are lines that are not blank, and none of them renders as an opening paragraph.

_NO_PARAGRAPH = {
    "thematic break": "---\n",
    "thematic break of stars": "* * *\n",
    "empty comment": "<!---->\n",
    "comment over two lines": "<!-- a note\nfor the release -->\n",
    "link reference definition": "[x]: /target\n",
    "empty fence": "```\n```\n",
    "fence with text inside": "```\nSemantics do not change.\n```\n",
    "tilde fence": "~~~\nSemantics do not change.\n~~~\n",
    "indented code": "    Semantics do not change.\n",
    "setext heading with dashes": "Semantics\n-\n",
    "setext heading with equals": "Semantics\n===\n",
}


def test_RED_what_renders_as_no_paragraph_does_not_open_the_section(tmp_path):
    for name, opening in _NO_PARAGRAPH.items():
        t = tmp_path / name.replace(" ", "_")
        t.mkdir()
        probs = chk.check(_repo(t, f"# Changelog\n\n## [{VERSION}] - 2026-10-31\n\n{opening}\n### Added\n\n- x\n"))
        assert len(_opening_findings(probs)) == 1, (name, probs)


def test_a_paragraph_after_a_comment_or_a_break_still_opens_the_section(tmp_path):
    """The other side: what renders as no paragraph is passed over, and the paragraph after it counts. A setext
    heading is not passed over; it is a heading and ends the opening (the next case)."""
    for name, opening in ((k, v) for k, v in _NO_PARAGRAPH.items() if not k.startswith("setext")):
        t = tmp_path / name.replace(" ", "_")
        t.mkdir()
        probs = chk.check(_repo(t, f"# Changelog\n\n## [{VERSION}] - 2026-10-31\n\n{opening}\n"
                                   f"{VERSION} is a patch release. Semantics do not change.\n\n### Fixed\n\n- x\n"))
        assert probs == [], (name, probs)


def test_a_setext_heading_ends_the_opening_like_a_subsection(tmp_path):
    """A paragraph after a setext heading stands under a heading, as one after `### Added` does."""
    for underline in ("-", "==="):
        t = tmp_path / f"setext_{len(underline)}"
        t.mkdir()
        probs = chk.check(_repo(t, f"# Changelog\n\n## [{VERSION}] - 2026-10-31\n\nNotes\n{underline}\n\n"
                                   "Semantics do not change.\n"))
        assert len(_opening_findings(probs)) == 1, (underline, probs)


def test_a_paragraph_followed_by_a_list_item_is_still_a_paragraph(tmp_path):
    """A list item after a line of text is no setext underline; the line stays a paragraph."""
    probs = chk.check(_repo(tmp_path, f"# Changelog\n\n## [{VERSION}] - 2026-10-31\n\n"
                                      "Semantics do not change.\n- one note\n\n### Fixed\n\n- x\n"))
    assert probs == [], probs


def test_RED_a_version_heading_that_stands_twice_is_a_finding_in_both_orders(tmp_path):
    """P2: the first form read the first of two sections and passed over the other one."""
    leer, gut = f"## [{VERSION}]\n\n### Added\n\n- x\n\n", f"## [{VERSION}]\n\nSemantics do not change.\n\n"
    for name, body in (("empty first", leer + gut), ("empty second", gut + leer)):
        t = tmp_path / name.replace(" ", "_")
        t.mkdir()
        probs = chk.check(_repo(t, "# Changelog\n\n" + body + "## [3.0.0] - 2026-10-01\n\nThe first release.\n"))
        twice = [p for p in probs if "CHANGELOG.md" in p and "twice" in p]
        assert len(twice) == 1, (name, probs)
