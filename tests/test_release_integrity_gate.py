"""Tests for scripts/check_version_and_changelog.py — the release-integrity gate.

Bidirectional: a consistent release state passes; each drift class (version disagreement, missing
changelog section, post-tag undelivered work) fails. The post-tag-drift case uses a real throwaway git
repo so the M2-style "merged but never released" bug is caught by a durable test, not just live.
"""
from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "chk", Path(__file__).resolve().parents[1] / "scripts" / "check_version_and_changelog.py")
chk = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(chk)


def _write_repo(t: Path, version: str, changelog_headings: list[str]) -> None:
    (t / "src" / "proofbundle").mkdir(parents=True, exist_ok=True)
    (t / "pyproject.toml").write_text(f'[project]\nname = "proofbundle"\nversion = "{version}"\n', encoding="utf-8")
    (t / "src" / "proofbundle" / "__init__.py").write_text(f'__version__ = "{version}"\n', encoding="utf-8")
    (t / "CITATION.cff").write_text(f"cff-version: 1.2.0\nversion: {version}\n", encoding="utf-8")
    body = "# Changelog\n\n" + "".join(f"## [{h}] - 2026-07-12\n\n- something\n\n" for h in changelog_headings)
    (t / "CHANGELOG.md").write_text(body, encoding="utf-8")


def test_consistent_release_passes(tmp_path):
    _write_repo(tmp_path, "3.0.1", ["3.0.1", "3.0.0"])
    assert chk.check(tmp_path) == []   # no git → part 3 skipped, parts 1+2 clean


def test_version_disagreement_fails(tmp_path):
    _write_repo(tmp_path, "3.0.1", ["3.0.1"])
    (tmp_path / "src" / "proofbundle" / "__init__.py").write_text('__version__ = "3.0.0"\n', encoding="utf-8")
    probs = chk.check(tmp_path)
    assert any("disagreement" in p for p in probs), probs


def test_changelog_missing_current_version_fails(tmp_path):
    _write_repo(tmp_path, "3.0.1", ["3.0.0"])   # bumped to 3.0.1 but no [3.0.1] section
    probs = chk.check(tmp_path)
    assert any("no `## [3.0.1]`" in p for p in probs), probs


def test_post_tag_undelivered_drift_fails(tmp_path):
    # The M2 catcher: tag v3.0.0, then a non-trivial commit, version NOT bumped, no [Unreleased] → FAIL.
    t = tmp_path

    def g(*a):
        return subprocess.run(["git", "-C", str(t), *a], capture_output=True, text=True)

    g("init", "-q", "-b", "main")
    g("config", "user.email", "t@t")
    g("config", "user.name", "t")
    _write_repo(t, "3.0.0", ["3.0.0"])
    g("add", "-A")
    g("commit", "-qm", "release: 3.0.0")
    g("tag", "v3.0.0")
    (t / "src" / "proofbundle" / "adapters.py").write_text("# security fix\n", encoding="utf-8")
    g("add", "-A")
    g("commit", "-qm", "security(M2): strip evaluation_result_id from the EEE digest")
    probs = chk.check(t)
    assert any("non-trivial" in p and "no `## [Unreleased]`" in p for p in probs), probs


def test_post_tag_drift_ok_when_unreleased_present(tmp_path):
    # Same as above but with an [Unreleased] section → the drift is documented → OK.
    t = tmp_path

    def g(*a):
        return subprocess.run(["git", "-C", str(t), *a], capture_output=True, text=True)

    g("init", "-q", "-b", "main")
    g("config", "user.email", "t@t")
    g("config", "user.name", "t")
    _write_repo(t, "3.0.0", ["Unreleased", "3.0.0"])
    g("add", "-A")
    g("commit", "-qm", "release: 3.0.0")
    g("tag", "v3.0.0")
    (t / "src" / "proofbundle" / "adapters.py").write_text("# security fix\n", encoding="utf-8")
    g("add", "-A")
    g("commit", "-qm", "security(M2): fix")
    assert chk.check(t) == []


if __name__ == "__main__":
    raise SystemExit(__import__("pytest").main([__file__, "-q"]))
