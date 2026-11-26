"""Two fragments from two branches merge without a conflict where two direct entries conflict.

THE PROBLEM, measured on the open pull requests of 2026-11-26: pull requests that each merge cleanly
on main conflicted with each other in CHANGELOG.md alone, because each wrote its lines at the top of
`## [Unreleased]`. A fragment is a file of its own, so the same two changes touch no common line.

The catch case runs first and must conflict, or the test would prove nothing: two branches that add a
line at the same place under `## [Unreleased]`, merged with `git merge-tree --write-tree`, exit 1 with
CHANGELOG.md as the conflicting path. The same two changes as fragments exit 0. Both run in a fresh
throwaway repository, and the fragments are checked with scripts/changelog_fragments.py on the merge.
"""
from __future__ import annotations

import importlib.util
import os
import subprocess
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "changelog_fragments", Path(__file__).resolve().parents[1] / "scripts" / "changelog_fragments.py")
frag = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(frag)

_BASE = ("# Changelog\n\n## [Unreleased]\n\n### Fixed\n\n- **An earlier fix.** Text.\n\n"
         "## [1.0.0] - 2026-01-01\n\nThe first release.\n\n### Added\n\n- **Everything.** Text.\n")


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid",
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, env=env)


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "r"
    repo.mkdir()
    assert _git(repo, "init", "-q", "-b", "main").returncode == 0
    (repo / "CHANGELOG.md").write_text(_BASE, encoding="utf-8")
    (repo / "changelog.d").mkdir()
    (repo / "changelog.d" / "README.md").write_text("# Fragments\n", encoding="utf-8")
    _git(repo, "add", "-A")
    assert _git(repo, "commit", "-qm", "base").returncode == 0
    return repo


def _branch(repo: Path, name: str, change) -> None:
    assert _git(repo, "switch", "-q", "-c", name, "main").returncode == 0
    change(repo)
    _git(repo, "add", "-A")
    assert _git(repo, "commit", "-qm", name).returncode == 0
    assert _git(repo, "switch", "-q", "main").returncode == 0


def _merge_tree(repo: Path, a: str, b: str) -> subprocess.CompletedProcess:
    probe = _git(repo, "merge-tree", "-h")
    if "--write-tree" not in probe.stdout + probe.stderr:
        pytest.skip("git without `merge-tree --write-tree` (git 2.38 or later)")
    return _git(repo, "merge-tree", "--write-tree", "--name-only", a, b)


def _direct(line: str):
    def change(repo: Path) -> None:
        p = repo / "CHANGELOG.md"
        p.write_text(p.read_text(encoding="utf-8").replace("### Fixed\n\n", f"### Fixed\n\n{line}\n", 1),
                     encoding="utf-8")
    return change


def _fragment(name: str, line: str):
    def change(repo: Path) -> None:
        (repo / "changelog.d" / name).write_text(line + "\n", encoding="utf-8")
    return change


def test_two_direct_entries_at_the_same_place_conflict(tmp_path):
    repo = _repo(tmp_path)
    _branch(repo, "a", _direct("- **Fix A.** Text."))
    _branch(repo, "b", _direct("- **Fix B.** Text."))
    out = _merge_tree(repo, "a", "b")
    assert out.returncode == 1, out
    assert "CHANGELOG.md" in out.stdout.splitlines()[1:], out.stdout


def test_two_fragments_from_two_branches_merge_without_conflict(tmp_path):
    repo = _repo(tmp_path)
    _branch(repo, "a", _fragment("fix-a.fixed.md", "- **Fix A.** Text."))
    _branch(repo, "b", _fragment("fix-b.fixed.md", "- **Fix B.** Text."))
    out = _merge_tree(repo, "a", "b")
    assert out.returncode == 0, out
    tree = out.stdout.splitlines()[0]
    merged = tmp_path / "merged"
    merged.mkdir()
    archive = subprocess.run(["git", "-C", str(repo), "archive", tree], capture_output=True, check=True)
    subprocess.run(["tar", "-x", "-C", str(merged)], input=archive.stdout, check=True)
    assert frag.check(merged) == []
    assert [p.name for p in frag.fragment_paths(merged)] == ["fix-a.fixed.md", "fix-b.fixed.md"]
