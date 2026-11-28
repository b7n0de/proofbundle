"""`changelog_fragments.py check` refuses each kind of bad fragment with exit 1, and this tree passes.

Per kind one case: a name that is not `<stem>.<section>.md`, a section the CHANGELOG does not use,
and an empty file. The content rules that collect relies on are held as well: LF line ends, a last
line that ends, a first line that opens a list item, no empty line and no heading. A valid fragment
and the README of the folder pass, and so does a repository without the folder.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location("changelog_fragments", REPO / "scripts" / "changelog_fragments.py")
frag = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(frag)


def _with(tmp_path: Path, name: str, content: bytes) -> Path:
    d = tmp_path / "changelog.d"
    d.mkdir()
    (d / "README.md").write_text("# Fragments\n", encoding="utf-8")
    (d / name).write_bytes(content)
    return tmp_path


@pytest.mark.parametrize("name", ["Fix-A.fixed.md", "fix_a.fixed.md", "fixed.md", "fix-a.fixed.txt",
                                  "-fix.fixed.md", "fix-a.fixed.md.bak", "a" * 65 + ".fixed.md"])
def test_a_wrong_name_is_refused(tmp_path, name, capsys):
    repo = _with(tmp_path, name, b"- **Fix.** Text.\n")
    findings = frag.check(repo)
    assert len(findings) == 1 and "the name is not <stem>.<section>.md" in findings[0], findings
    assert frag.main(["check", "--repo", str(repo)]) == 1


@pytest.mark.parametrize("section", ["notes", "bugfix", "verification"])
def test_an_unknown_section_is_refused(tmp_path, section):
    repo = _with(tmp_path, f"fix-a.{section}.md", b"- **Fix.** Text.\n")
    findings = frag.check(repo)
    assert len(findings) == 1 and f"unknown section {section!r}" in findings[0], findings
    assert frag.main(["check", "--repo", str(repo)]) == 1


@pytest.mark.parametrize("content", [b"", b"\n", b" \n\n"])
def test_an_empty_file_is_refused(tmp_path, content):
    repo = _with(tmp_path, "fix-a.fixed.md", content)
    assert frag.check(repo) == ["changelog.d/fix-a.fixed.md: the fragment is empty"]
    assert frag.main(["check", "--repo", str(repo)]) == 1


@pytest.mark.parametrize("content, finding", [
    (b"- **Fix.** Text.", "the last line does not end with LF"),
    (b"- **Fix.** Text.\r\n", "carries a CR"),
    (b"**Fix.** Text.\n", "does not open a list item"),
    (b"- **Fix.** Text.\n\n- **Other.** Text.\n", "line 2 is empty"),
    (b"- **Fix.** Text.\n### Added\n", "line 2 is a heading"),
    (b"- **Fix.** Text.\n## [9.9.9] - 2026-01-01\n", "line 2 is a heading"),
    (b"- \xff\n", "not UTF-8"),
])
def test_content_that_breaks_the_structure_is_refused(tmp_path, content, finding):
    repo = _with(tmp_path, "fix-a.fixed.md", content)
    findings = frag.check(repo)
    assert any(finding in f for f in findings), findings
    assert frag.main(["check", "--repo", str(repo)]) == 1


def test_a_valid_fragment_passes(tmp_path):
    repo = _with(tmp_path, "issue-557.security.md", b"- **Fix.** Text.\n  Continued.\n- **Two.** Text.\n")
    assert frag.check(repo) == []
    assert frag.main(["check", "--repo", str(repo)]) == 0


def test_a_repository_without_the_folder_passes(tmp_path):
    assert frag.check(tmp_path) == []
    assert frag.main(["check", "--repo", str(tmp_path)]) == 0


def test_the_fragments_of_this_tree_pass_the_check():
    """The pull request that adds a bad fragment turns this test red, without a new CI step."""
    if not (REPO / ".git").exists():
        pytest.skip("no repository checkout; changelog.d/ is not shipped in the sdist")
    assert (REPO / "changelog.d" / "README.md").is_file()
    assert frag.check(REPO) == []
