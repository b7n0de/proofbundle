"""The README links that name an artefact of the release name the artefacts of the release being built.

The release-integrity gate keeps the tag in every pinned URL of README.md current (Check 4). Several of
those links carry the release a second time, in a form the tag does not cover: the audit directory and
the residual-risk record by its short number (640 for 6.4.0), the pre-tag receipt by both, and the
release-scope file by name. The dry run of 6.5.0 (finding K5) raised every tag to v6.5.0 and left
`audit_artifacts/640/README.md`, `RESTRISIKO_640.md` and `docs/release_scope/6.4.0.md` behind them; the
gate and the suite stayed green, and the front page would have sent a reader to the audit of the
previous release under the tag of the new one.

A form that is absent is no finding here: the synthetic trees of the gate's other tests carry none of
them. The last test holds the real README to carrying each form, so a reworded link is noticed rather
than unwatched. The earlier risk record names the previous release on purpose and is not read.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location("chk_k5", REPO / "scripts" / "check_version_and_changelog.py")
chk = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(chk)

V = "6.5.0"
URL = f"https://github.com/b7n0de/proofbundle/blob/v{V}"


def _readme(audit: str = "650", risk: str = "650", risk_label: str = V, receipt: str = "650",
            receipt_version: str = V, scope: str = V) -> str:
    """The README forms of a release, each part settable on its own."""
    return (f"**[v{V}](https://github.com/b7n0de/proofbundle/releases/tag/v{V}) · Beta · "
            f"[Audit status and limits]({URL}/audit_artifacts/{audit}/README.md)**\n\n"
            f"[Known limitations for {risk_label}]({URL}/RESTRISIKO_{risk}.md) · "
            f"[Earlier risk record]({URL}/RESTRISIKO_640.md) · "
            f"[Release scope]({URL}/docs/release_scope/{scope}.md)\n\n"
            f"In the tagged tree, check `audit_artifacts/{receipt}/pre_tag_receipt_v{receipt_version}.json`.\n\n"
            f"[Residual risks for {risk_label}]({URL}/RESTRISIKO_{risk}.md)\n\n"
            f"    python -m pip install proofbundle=={V}\n\n"
            f"[Deferred work]({URL}/docs/release_scope/{scope}.md#out) is not a delivered capability.\n")


def _repo(t: Path, readme: str) -> Path:
    """A tree that passes every other check of the gate, with the given README."""
    (t / "src" / "proofbundle").mkdir(parents=True, exist_ok=True)
    (t / "docs" / "readiness_pack").mkdir(parents=True, exist_ok=True)
    (t / "pyproject.toml").write_text(f'[project]\nname = "proofbundle"\nversion = "{V}"\n', encoding="utf-8")
    (t / "src" / "proofbundle" / "__init__.py").write_text(f'__version__ = "{V}"\n', encoding="utf-8")
    (t / "CITATION.cff").write_text(f"cff-version: 1.2.0\nversion: {V}\n", encoding="utf-8")
    (t / "RELEASE.md").write_text(f"# Release\n\n(current: {V}) and so on.\n", encoding="utf-8")
    (t / "docs" / "readiness_pack" / "PROGRESS.md").write_text(
        f"# Progress\n\nfrom 3.3.0 (current release: {V}) to stable.\n", encoding="utf-8")
    (t / "CHANGELOG.md").write_text(f"# Changelog\n\n## [{V}] - 2026-10-31\n\nA feature release.\n",
                                    encoding="utf-8")
    (t / "README.md").write_text(readme, encoding="utf-8")
    return t


def _link_findings(problems: list[str]) -> list[str]:
    return [p for p in problems if p.startswith("README.md:") and "names" in p]


@pytest.mark.parametrize("stale,expected", [
    ({"audit": "640"}, "'640'"),
    ({"risk": "640"}, "'640'"),
    ({"risk_label": "6.4.0"}, "'6.4.0'"),
    ({"receipt": "640"}, "'640'"),
    ({"receipt_version": "6.4.0"}, "'6.4.0'"),
    ({"scope": "6.4.0"}, "'6.4.0'"),
], ids=["audit-dir", "risk-record", "risk-label", "receipt-dir", "receipt-version", "scope-file"])
def test_RED_a_link_left_on_the_previous_release_is_a_finding(tmp_path, stale, expected):
    """The case of the dry run: every tag raised, one artefact of the link left behind."""
    found = _link_findings(chk.check(_repo(tmp_path, _readme(**stale))))
    assert found and all(expected in f for f in found), found


def test_the_links_of_the_release_being_built_pass(tmp_path):
    assert chk.check(_repo(tmp_path, _readme())) == []


def test_the_earlier_risk_record_names_the_previous_release_and_is_not_read(tmp_path):
    """`_readme` always carries `[Earlier risk record](…/RESTRISIKO_640.md)`; the passing case above
    shows it is not read. This one makes that explicit with an older record still."""
    readme = _readme().replace("RESTRISIKO_640.md", "RESTRISIKO_631.md")
    assert chk.check(_repo(tmp_path, readme)) == []


def test_an_absent_form_is_no_finding(tmp_path):
    readme = (f"**[v{V}](https://github.com/b7n0de/proofbundle/releases/tag/v{V}) · Beta**\n\n"
              f"    python -m pip install proofbundle=={V}\n")
    assert chk.check(_repo(tmp_path, readme)) == []


#: Read with a default so that, against a gate without the forms, the cases above fail one by one
#: instead of the whole module failing to collect.
_FORMEN = getattr(chk, "_VERSIONSGEBUNDENE_VERWEISE", [])


def test_the_gate_declares_the_forms():
    assert len(_FORMEN) == 4, f"the gate declares {len(_FORMEN)} version-bound link forms, expected 4"


@pytest.mark.parametrize("muster", [m for _, m, _ in _FORMEN],
                         ids=[b.split("`")[1] if "`" in b else b for b, _, _ in _FORMEN])
def test_the_real_readme_carries_each_form(muster):
    """A form that vanished from the real README is no longer checked; this is where that shows."""
    assert muster.search((REPO / "README.md").read_text(encoding="utf-8")), muster.pattern
