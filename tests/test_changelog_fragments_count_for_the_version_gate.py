"""Check 3 of the version gate accepts a fragment in `changelog.d/` as the changelog trace.

Check 3 asks for an `## [Unreleased]` heading when non-trivial commits follow the last release tag
and the version was not bumped. With fragments a pull request writes no line in CHANGELOG.md, so the
fragment counts as the trace too. The four cases, in a throwaway repository: a fragment without the
heading passes; the heading without a fragment passes as before; neither fails as before, with the
same words the gate used; a file in `changelog.d/` that is no fragment (the README) is no trace.
"""
from __future__ import annotations

import importlib.util
import os
import subprocess
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "chk", Path(__file__).resolve().parents[1] / "scripts" / "check_version_and_changelog.py")
chk = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(chk)


def _g(t: Path, *a: str) -> subprocess.CompletedProcess:
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid",
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}
    return subprocess.run(["git", "-C", str(t), *a], capture_output=True, text=True, env=env)


def _repo(t: Path, headings: list[str]) -> None:
    (t / "src" / "proofbundle").mkdir(parents=True)
    (t / "pyproject.toml").write_text('[project]\nname = "proofbundle"\nversion = "3.0.0"\n', encoding="utf-8")
    (t / "src" / "proofbundle" / "__init__.py").write_text('__version__ = "3.0.0"\n', encoding="utf-8")
    (t / "CITATION.cff").write_text("cff-version: 1.2.0\nversion: 3.0.0\n", encoding="utf-8")
    body = "# Changelog\n\n" + "".join(
        f"## [{h}] - 2026-07-12\n\nA release. Semantics do not change.\n\n- something\n\n" for h in headings)
    (t / "CHANGELOG.md").write_text(body, encoding="utf-8")
    (t / "RELEASE.md").write_text(
        "# Release\n\nthe stable default has moved on to the 3.x line (current: 3.0.0) and so on.\n", encoding="utf-8")
    (t / "docs" / "readiness_pack").mkdir(parents=True)
    (t / "docs" / "readiness_pack" / "PROGRESS.md").write_text(
        "# Progress\n\nThe denominator is the distance from 3.3.0 (current release: 3.0.0) to stable.\n",
        encoding="utf-8")
    (t / "README.md").write_text(
        "## Current release\n\n"
        "**[v3.0.0](https://github.com/b7n0de/proofbundle/releases/tag/v3.0.0) · Beta**\n\n"
        "    python -m pip install proofbundle==3.0.0\n"
        "    curl -fsSLo x.json \\\n"
        "      https://raw.githubusercontent.com/b7n0de/proofbundle/v3.0.0/examples/x.json\n", encoding="utf-8")
    (t / "changelog.d").mkdir()
    (t / "changelog.d" / "README.md").write_text("# Fragments\n", encoding="utf-8")
    _g(t, "init", "-q", "-b", "main")
    _g(t, "add", "-A")
    assert _g(t, "commit", "-qm", "release: 3.0.0").returncode == 0
    assert _g(t, "tag", "v3.0.0").returncode == 0


def _fix_after_the_tag(t: Path, fragment: bool) -> None:
    (t / "src" / "proofbundle" / "adapters.py").write_text("# security fix\n", encoding="utf-8")
    if fragment:
        (t / "changelog.d" / "m2.security.md").write_text("- **The fix.** Text.\n", encoding="utf-8")
    _g(t, "add", "-A")
    assert _g(t, "commit", "-qm", "security(M2): fix").returncode == 0


def _drift(problems: list[str]) -> list[str]:
    return [p for p in problems if "non-trivial" in p]


def test_a_fragment_without_the_heading_satisfies_check_3(tmp_path):
    _repo(tmp_path, ["3.0.0"])
    _fix_after_the_tag(tmp_path, fragment=True)
    assert _drift(chk.check(tmp_path)) == []


def test_the_heading_without_a_fragment_satisfies_check_3_as_before(tmp_path):
    _repo(tmp_path, ["Unreleased", "3.0.0"])
    _fix_after_the_tag(tmp_path, fragment=False)
    assert _drift(chk.check(tmp_path)) == []


def test_neither_heading_nor_fragment_fails_check_3_as_before(tmp_path):
    _repo(tmp_path, ["3.0.0"])
    _fix_after_the_tag(tmp_path, fragment=False)
    found = _drift(chk.check(tmp_path))
    assert len(found) == 1, found
    assert "no `## [Unreleased]` section" in found[0] and "no changelog trace" in found[0], found


def test_a_file_that_is_no_fragment_is_no_trace(tmp_path):
    _repo(tmp_path, ["3.0.0"])
    (tmp_path / "changelog.d" / "notes.txt").write_text("- **Text.**\n", encoding="utf-8")
    _fix_after_the_tag(tmp_path, fragment=False)
    assert len(_drift(chk.check(tmp_path))) == 1
