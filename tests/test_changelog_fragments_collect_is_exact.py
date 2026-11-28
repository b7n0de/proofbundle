"""`collect` writes exactly the expected `## [Unreleased]` block, byte for byte, and then has no effect.

The fixed fragments cover the cases of the order: a subsection that exists (its lines stay first), a
subsection that does not exist yet and is created at its place in `SECTIONS`, two fragments of one
section in file-name order, a fragment of two lines, and a subsection the tool does not know, which
keeps its place. A second `collect` without fragments leaves CHANGELOG.md byte for byte as it was.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "changelog_fragments", Path(__file__).resolve().parents[1] / "scripts" / "changelog_fragments.py")
frag = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(frag)

_BEFORE = (
    "# Changelog\n"
    "\n"
    "Intro.\n"
    "\n"
    "## [Unreleased]\n"
    "\n"
    "### Security\n"
    "\n"
    "- **Existing security line.** Text.\n"
    "\n"
    "### Notes\n"
    "\n"
    "- A subsection the tool does not know.\n"
    "\n"
    "### Fixed\n"
    "\n"
    "- **Existing fix.** Text.\n"
    "\n"
    "## [1.0.0] - 2026-01-01\n"
    "\n"
    "The first release.\n"
    "\n"
    "### Added\n"
    "\n"
    "- **Everything.** Text.\n"
)

_FRAGMENTS = {
    "zeta.fixed.md": "- **Fix Z.** Text.\n",
    "alpha.fixed.md": "- **Fix A.** Text.\n",
    "beta.added.md": "- **Added B.** First line.\n  Second line of the same item.\n",
    "gamma.security.md": "- **Security G.** Text.\n",
}

_AFTER = (
    "# Changelog\n"
    "\n"
    "Intro.\n"
    "\n"
    "## [Unreleased]\n"
    "\n"
    "### Security\n"
    "\n"
    "- **Existing security line.** Text.\n"
    "- **Security G.** Text.\n"
    "\n"
    "### Added\n"
    "\n"
    "- **Added B.** First line.\n"
    "  Second line of the same item.\n"
    "\n"
    "### Notes\n"
    "\n"
    "- A subsection the tool does not know.\n"
    "\n"
    "### Fixed\n"
    "\n"
    "- **Existing fix.** Text.\n"
    "- **Fix A.** Text.\n"
    "- **Fix Z.** Text.\n"
    "\n"
    "## [1.0.0] - 2026-01-01\n"
    "\n"
    "The first release.\n"
    "\n"
    "### Added\n"
    "\n"
    "- **Everything.** Text.\n"
)


def _repo(tmp_path: Path, changelog: str, fragments: dict) -> Path:
    (tmp_path / "CHANGELOG.md").write_bytes(changelog.encode("utf-8"))
    d = tmp_path / "changelog.d"
    d.mkdir()
    (d / "README.md").write_text("# Fragments\n", encoding="utf-8")
    for name, text in fragments.items():
        (d / name).write_bytes(text.encode("utf-8"))
    return tmp_path


def test_collect_writes_the_expected_section_byte_for_byte(tmp_path):
    repo = _repo(tmp_path, _BEFORE, _FRAGMENTS)
    assert frag.main(["collect", "--repo", str(repo)]) == 0
    assert (repo / "CHANGELOG.md").read_bytes() == _AFTER.encode("utf-8")
    assert sorted(p.name for p in (repo / "changelog.d").iterdir()) == ["README.md"]


def test_a_second_collect_changes_nothing(tmp_path):
    repo = _repo(tmp_path, _BEFORE, _FRAGMENTS)
    assert frag.main(["collect", "--repo", str(repo)]) == 0
    first = (repo / "CHANGELOG.md").read_bytes()
    assert frag.main(["collect", "--repo", str(repo)]) == 0
    assert (repo / "CHANGELOG.md").read_bytes() == first


def test_collect_creates_the_unreleased_heading_above_the_first_release(tmp_path):
    before = "# Changelog\n\nIntro.\n\n## [1.0.0] - 2026-01-01\n\nThe first release.\n"
    repo = _repo(tmp_path, before, {"one.changed.md": "- **Changed.** Text.\n"})
    assert frag.main(["collect", "--repo", str(repo)]) == 0
    assert (repo / "CHANGELOG.md").read_text(encoding="utf-8") == (
        "# Changelog\n\nIntro.\n\n## [Unreleased]\n\n### Changed\n\n- **Changed.** Text.\n\n"
        "## [1.0.0] - 2026-01-01\n\nThe first release.\n")


def test_collect_on_a_finding_writes_nothing(tmp_path):
    repo = _repo(tmp_path, _BEFORE, {**_FRAGMENTS, "bad.fixed.md": ""})
    assert frag.main(["collect", "--repo", str(repo)]) == 1
    assert (repo / "CHANGELOG.md").read_bytes() == _BEFORE.encode("utf-8")
    assert len(list((repo / "changelog.d").iterdir())) == len(_FRAGMENTS) + 2


def test_collect_into_the_changelog_of_this_tree_keeps_every_older_byte(tmp_path):
    """On a copy of this repository's CHANGELOG.md, collect changes only the `## [Unreleased]` block."""
    real = Path(__file__).resolve().parents[1] / "CHANGELOG.md"
    text = real.read_text(encoding="utf-8")
    repo = _repo(tmp_path, text, {"x.fixed.md": "- **X.** Text.\n"})
    assert frag.main(["collect", "--repo", str(repo)]) == 0
    after = (repo / "CHANGELOG.md").read_text(encoding="utf-8")
    cut_before = text.index("\n## [", text.index("## [Unreleased]") + 1)
    cut_after = after.index("\n## [", after.index("## [Unreleased]") + 1)
    assert after[cut_after:] == text[cut_before:]
    assert after[:cut_after].endswith("- **X.** Text.\n")
