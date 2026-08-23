"""Tests for scripts/check_version_and_changelog.py — the release-integrity gate.

Bidirectional: a consistent release state passes; each drift class (version disagreement, missing
changelog section, post-tag undelivered work, a stale prose place, a vanished anchor, an external
surface that disagrees) fails. The post-tag-drift case uses a real throwaway git repo so the M2-style
"merged but never released" bug is caught by a durable test, not just live.

The external-surface tests never touch the network: `_fetch` is replaced, so "unreachable" is a state
the test can produce on purpose. That matters, because the interesting case is precisely the one that
cannot be provoked on a healthy machine.
"""
from __future__ import annotations

import importlib.util
import json
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
    _write_tracked_places(t, version)


def _write_tracked_places(t: Path, version: str) -> None:
    """The prose places that state the CURRENT version, in the shape the gate anchors on."""
    (t / "RELEASE.md").write_text(
        f"# Release\n\nthe stable default has moved on to the 3.x line (current: {version}) and so on.\n",
        encoding="utf-8")
    (t / "docs" / "readiness_pack").mkdir(parents=True, exist_ok=True)
    (t / "docs" / "readiness_pack" / "PROGRESS.md").write_text(
        f"# Progress\n\nThe denominator is the distance from 3.3.0 (current release: {version}) to stable.\n",
        encoding="utf-8")


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


def test_review_tag_does_not_disable_the_drift_check(tmp_path):
    """A non-release tag must not switch check 3 off.

    Measured in the real repo on 2026-08-07: `git describe --tags` returned a corpus review tag,
    `_semver_tuple` read it as (0, 0, 0), every real version compared as "bumped past it", and a
    non-trivial commit sat undelivered with no [Unreleased] section while the gate reported OK.
    """
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
    g("tag", "corpus-review-2026-07-25-iter10")        # the tag that used to blind the check

    assert chk._last_release_tag(t)[0] == "v3.0.0"
    probs = chk.check(t)
    assert any("non-trivial" in p and "v3.0.0" in p for p in probs), probs


def test_no_release_tag_at_all_is_reported_separately(tmp_path):
    # Tags exist, none of them a release: that is its own state, not "no tags".
    t = tmp_path

    def g(*a):
        return subprocess.run(["git", "-C", str(t), *a], capture_output=True, text=True)

    g("init", "-q", "-b", "main")
    g("config", "user.email", "t@t")
    g("config", "user.name", "t")
    _write_repo(t, "3.0.0", ["3.0.0"])
    g("add", "-A")
    g("commit", "-qm", "release: 3.0.0")
    g("tag", "corpus-review-2026-07-25-iter10")

    tag, grund = chk._last_release_tag(t)
    assert tag is None
    assert "none is a release tag" in grund, grund


# --------------------------------------------------------------------------------------------
# Check 4: the prose places that state the CURRENT version
# --------------------------------------------------------------------------------------------

def test_stale_prose_place_fails(tmp_path):
    # The source was bumped and RELEASE.md was not followed through — the drift this gate exists for.
    _write_repo(tmp_path, "3.0.1", ["3.0.1"])
    (tmp_path / "RELEASE.md").write_text(
        "# Release\n\nthe stable default has moved on (current: 3.0.0) and so on.\n", encoding="utf-8")
    probs = chk.check(tmp_path)
    assert any("RELEASE.md" in p and "3.0.0" in p and "3.0.1" in p for p in probs), probs


def test_stale_second_prose_place_fails(tmp_path):
    # Two places, and only one of them left behind: the gate must name the one that is wrong.
    _write_repo(tmp_path, "3.0.1", ["3.0.1"])
    (tmp_path / "docs" / "readiness_pack" / "PROGRESS.md").write_text(
        "# Progress\n\nfrom 3.3.0 (current release: 3.0.0) to stable.\n", encoding="utf-8")
    probs = chk.check(tmp_path)
    assert any("PROGRESS.md" in p for p in probs), probs
    assert not any("RELEASE.md" in p for p in probs), probs


def test_vanished_anchor_fails_instead_of_passing_quietly(tmp_path):
    # The sentence was reworded, so nothing matches any more. A gate that stops finding its anchor
    # must say so — silence here would look exactly like agreement.
    _write_repo(tmp_path, "3.0.1", ["3.0.1"])
    (tmp_path / "RELEASE.md").write_text("# Release\n\nno version statement here at all.\n", encoding="utf-8")
    probs = chk.check(tmp_path)
    assert any("RELEASE.md" in p and "not found" in p for p in probs), probs


def test_missing_tracked_file_fails(tmp_path):
    _write_repo(tmp_path, "3.0.1", ["3.0.1"])
    (tmp_path / "docs" / "readiness_pack" / "PROGRESS.md").unlink()
    probs = chk.check(tmp_path)
    assert any("PROGRESS.md" in p and "missing" in p for p in probs), probs


def test_citation_disagreement_fails(tmp_path):
    # Named explicitly because CITATION.cff is the place a human forgets: it is not code and not prose.
    _write_repo(tmp_path, "3.0.1", ["3.0.1"])
    (tmp_path / "CITATION.cff").write_text("cff-version: 1.2.0\nversion: 3.0.0\n", encoding="utf-8")
    probs = chk.check(tmp_path)
    assert any("disagreement" in p for p in probs), probs


def test_historical_statements_are_not_touched(tmp_path):
    # "since v3.7.0" records WHEN something became true. Bumping it would manufacture a false claim,
    # so a file full of historical mentions must not produce a single finding.
    _write_repo(tmp_path, "3.0.1", ["3.0.1"])
    (tmp_path / "INTEGRATIONS.md").write_text(
        "sample-count provenance since v3.7.0; corpus 56/56 as of v3.2.0.\n", encoding="utf-8")
    assert chk.check(tmp_path) == []


# --------------------------------------------------------------------------------------------
# Check 5: the external surfaces, with three states
# --------------------------------------------------------------------------------------------

def _fake_fetch(mapping):
    """Replace chk._fetch with a lookup. None means 'not reachable'."""
    def fetch(url, timeout):          # noqa: ARG001
        return mapping.get(url)
    return fetch


def _page(version):
    return f'<dt>Version</dt><dd>PyPI latest <code>{version}</code>, classifier 4</dd>'


def test_external_agreement_is_ok(monkeypatch):
    monkeypatch.setattr(chk, "_fetch", _fake_fetch({
        chk._PYPI_JSON: json.dumps({"info": {"version": "3.7.0"}}),
        chk._PROJECT_PAGE: _page("3.7.0"),
    }))
    assert [(n, s) for n, s, _ in chk.check_external("3.7.0")] == [("PyPI", "OK"), ("project page", "OK")]


def test_external_pypi_disagreement_is_a_finding(monkeypatch):
    monkeypatch.setattr(chk, "_fetch", _fake_fetch({
        chk._PYPI_JSON: json.dumps({"info": {"version": "3.6.2"}}),
        chk._PROJECT_PAGE: _page("3.7.0"),
    }))
    zustaende = dict((n, s) for n, s, _ in chk.check_external("3.7.0"))
    assert zustaende["PyPI"] == "ABWEICHUNG"


def test_external_page_disagreement_is_a_finding(monkeypatch):
    monkeypatch.setattr(chk, "_fetch", _fake_fetch({
        chk._PYPI_JSON: json.dumps({"info": {"version": "3.7.0"}}),
        chk._PROJECT_PAGE: _page("3.6.2"),
    }))
    zustaende = dict((n, s) for n, s, _ in chk.check_external("3.7.0"))
    assert zustaende["project page"] == "ABWEICHUNG"


def test_page_with_two_language_variants_out_of_step_is_a_finding(monkeypatch):
    # The realistic failure: the English string table is bumped and the German one is not.
    monkeypatch.setattr(chk, "_fetch", _fake_fetch({
        chk._PYPI_JSON: json.dumps({"info": {"version": "3.7.0"}}),
        chk._PROJECT_PAGE: _page("3.7.0") + " ... " + 'PyPI-latest <code>3.6.2</code>',
    }))
    zustaende = dict((n, s) for n, s, _ in chk.check_external("3.7.0"))
    assert zustaende["project page"] == "ABWEICHUNG"


def test_unreachable_external_is_not_measurable_and_never_green(monkeypatch):
    monkeypatch.setattr(chk, "_fetch", _fake_fetch({}))       # nothing reachable
    zustaende = [s for _, s, _ in chk.check_external("3.7.0")]
    assert zustaende == [chk.NICHT_MESSBAR, chk.NICHT_MESSBAR]
    assert "OK" not in zustaende


def test_empty_page_body_is_not_measurable_not_agreement(monkeypatch):
    # An unfollowed redirect yields an empty body. That must never read as "the page agrees".
    monkeypatch.setattr(chk, "_fetch", _fake_fetch({
        chk._PYPI_JSON: json.dumps({"info": {"version": "3.7.0"}}),
        chk._PROJECT_PAGE: "",
    }))
    zustaende = dict((n, s) for n, s, _ in chk.check_external("3.7.0"))
    assert zustaende["project page"] == chk.NICHT_MESSBAR


def test_malformed_pypi_response_is_not_measurable(monkeypatch):
    monkeypatch.setattr(chk, "_fetch", _fake_fetch({
        chk._PYPI_JSON: "<html>not json</html>",
        chk._PROJECT_PAGE: _page("3.7.0"),
    }))
    zustaende = dict((n, s) for n, s, _ in chk.check_external("3.7.0"))
    assert zustaende["PyPI"] == chk.NICHT_MESSBAR


# --------------------------------------------------------------------------------------------
# Check 6: places that claim a current version without being declared
#
# Check 4 can only watch what somebody declared. This is the must-catch for the README case: the
# README states no version today, so a test that "the README number is stale" would be testing a
# sentence that does not exist. What CAN go wrong is that a version claim appears there — and from
# that moment it is a place that can go stale with nothing watching it.
# --------------------------------------------------------------------------------------------

def _git_repo(t: Path, version: str, headings: list[str]):
    def g(*a):
        return subprocess.run(["git", "-C", str(t), *a], capture_output=True, text=True)

    g("init", "-q", "-b", "main")
    g("config", "user.email", "t@t")
    g("config", "user.name", "t")
    _write_repo(t, version, headings)
    return g


def test_undeclared_current_version_claim_in_readme_is_caught(tmp_path):
    g = _git_repo(tmp_path, "3.0.1", ["3.0.1"])
    (tmp_path / "README.md").write_text(
        "# proofbundle\n\nInstall it. The current release: 3.0.0 ships the adapter.\n", encoding="utf-8")
    g("add", "-A")
    g("commit", "-qm", "docs: readme")
    probs = chk.check_undeclared_places(tmp_path)
    assert any("README.md" in p and "3.0.0" in p and "not a declared place" in p for p in probs), probs


def test_undeclared_claim_is_caught_even_when_it_matches_the_source(tmp_path):
    # Subtle and the whole point: agreeing TODAY is not the property. An undeclared place that
    # happens to be right is one release away from being wrong with nobody looking.
    g = _git_repo(tmp_path, "3.0.1", ["3.0.1"])
    (tmp_path / "README.md").write_text("current release: 3.0.1\n", encoding="utf-8")
    g("add", "-A")
    g("commit", "-qm", "docs: readme")
    assert any("README.md" in p for p in chk.check_undeclared_places(tmp_path))


def test_historical_statements_do_not_trip_the_sweep(tmp_path):
    # "since"/"as of" record when something became true. A sweep that demanded they be bumped would
    # manufacture false claims — the exact thing check 4 refuses to do.
    g = _git_repo(tmp_path, "3.0.1", ["3.0.1"])
    (tmp_path / "INTEGRATIONS.md").write_text(
        "sample-count provenance since v3.7.0; corpus 56/56 as of v3.2.0.\n", encoding="utf-8")
    g("add", "-A")
    g("commit", "-qm", "docs: integrations")
    assert chk.check_undeclared_places(tmp_path) == []


def test_declared_places_are_not_reported_twice(tmp_path):
    # RELEASE.md legitimately states the current version and IS declared — check 4 owns it.
    g = _git_repo(tmp_path, "3.0.1", ["3.0.1"])
    g("add", "-A")
    g("commit", "-qm", "init")
    probs = chk.check_undeclared_places(tmp_path)
    assert not any("RELEASE.md" in p or "PROGRESS.md" in p for p in probs), probs


def test_untracked_file_is_not_a_repo_claim(tmp_path):
    # An untracked scratch file is not something the repo says. Reading one as a repo statement is
    # the same defect as reporting a number about the wrong object.
    g = _git_repo(tmp_path, "3.0.1", ["3.0.1"])
    g("add", "-A")
    g("commit", "-qm", "init")
    (tmp_path / "scratch.md").write_text("current release: 2.0.0\n", encoding="utf-8")
    assert chk.check_undeclared_places(tmp_path) == []


# --------------------------------------------------------------------------------------------
# Every number names its object and its source
# --------------------------------------------------------------------------------------------

def test_source_version_carries_its_origin(tmp_path):
    _write_repo(tmp_path, "3.0.1", ["3.0.1"])
    assert chk._source_version(tmp_path) == ("3.0.1", "pyproject.toml")


def test_stale_place_finding_names_where_the_source_was_read(tmp_path):
    _write_repo(tmp_path, "3.0.1", ["3.0.1"])
    (tmp_path / "RELEASE.md").write_text(
        "# Release\n\n(current: 3.0.0) and so on.\n", encoding="utf-8")
    probs = chk.check(tmp_path)
    assert any("read from pyproject.toml" in p for p in probs), probs


def test_external_finding_names_both_objects(monkeypatch):
    monkeypatch.setattr(chk, "_fetch", _fake_fetch({
        chk._PYPI_JSON: json.dumps({"info": {"version": "3.6.2"}}),
        chk._PROJECT_PAGE: _page("3.7.0"),
    }))
    detail = dict((n, d) for n, _, d in chk.check_external("3.7.0", herkunft="pyproject.toml"))
    assert "published sdist/wheel version" in detail["PyPI"]
    assert "read from pyproject.toml" in detail["PyPI"]


if __name__ == "__main__":
    raise SystemExit(__import__("pytest").main([__file__, "-q"]))
