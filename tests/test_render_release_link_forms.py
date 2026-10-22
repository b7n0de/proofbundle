"""RR1 (6.3.1): scripts/render_release.py binds every link form to the described commit and checks its target.

Until 6.3.1 one expression stood for all links on a two-level release page and saw only `[text](path)`. A link with a
title, a target in angle brackets, a reference with its definition and an HTML `<a href>` were neither bound nor
checked: on the page they resolved against the page itself, and a link to a file the described tree lacks rendered
without a word. Each form below is rendered in a throwaway repository whose described commit carries RELEASE.md and not
MISSING.md: with RELEASE.md the page binds the target to the commit, with MISSING.md the render is refused, and with no
target at all the source is refused, in every form. The plain form and a link inside a code span are the controls.

RED at 22aa954e for the four forms and for each link without a target. The plain form is green there and after.
The code span is red at 22aa954e as well: that tree bound and checked a link written inside backticks, so it
rewrote code on the page and refused a source that only showed link syntax.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

import test_render_release as base

BASIS = "https://github.com/b7n0de/proofbundle/blob/"
FORMEN = {
    "inline_with_title": "See [the steps]({ziel} \"the steps\").",
    "angle_brackets": "See [the steps](<{ziel}>).",
    "reference_with_definition": "See [the steps][verify].\n\n[verify]: {ziel} \"the steps\"",
    "html_a_href": "See <a href=\"{ziel}\">the steps</a>.",
}


def _quelle(text: str) -> dict:
    q = base._zwei_ebenen()
    q["selbst_pruefen"] = text
    return q


def _render(text: str):
    with tempfile.TemporaryDirectory() as d:
        w = base._baum_zwei_ebenen(Path(d), quelle=_quelle(text))
        r = base._render_im(w)
        seite = (w / "notes.md").read_text(encoding="utf-8") if r.returncode == 0 else ""
        commit = base.json.loads((w / "release_notes" / "release-source.json").read_text())["release_commit"]
    return r, seite, commit


@pytest.mark.parametrize("form", sorted(FORMEN))
def test_RR1_a_present_target_is_bound_to_the_described_commit(form):
    r, seite, commit = _render(FORMEN[form].format(ziel="RELEASE.md"))
    assert r.returncode == 0, r.stderr
    assert f"{BASIS}{commit}/RELEASE.md" in seite, seite
    teil = seite.split("## Verify this release yourself", 1)[1].split("## What a receipt", 1)[0]
    assert "RELEASE.md" not in teil.replace(f"{BASIS}{commit}/RELEASE.md", ""), teil


@pytest.mark.parametrize("form", sorted(FORMEN))
def test_RR1_a_missing_target_refuses_the_render(form):
    r, _seite, _commit = _render(FORMEN[form].format(ziel="MISSING.md"))
    assert r.returncode == 2, r.stdout
    assert "the page links MISSING.md" in r.stderr, r.stderr


@pytest.mark.parametrize("text", ["See [the steps]().", "See [the steps](<>).", "See [the steps][v].\n\n[v]: <>",
                                  "See <a href=\"\">the steps</a>.", "See <a href=''>the steps</a>."])
def test_RR1_a_link_without_a_target_is_refused(text):
    befunde = base.pruefe(_quelle(text))
    assert any("a link on the page has no target" in b for b in befunde), befunde
    r, _seite, _commit = _render(text)
    assert r.returncode == 2, r.stdout


def test_RR1_control_the_plain_form_is_bound_and_checked():
    r, seite, commit = _render("See [the steps](RELEASE.md).")
    assert r.returncode == 0 and f"]({BASIS}{commit}/RELEASE.md)" in seite, r.stderr
    r, _seite, _commit = _render("See [the steps](MISSING.md).")
    assert r.returncode == 2 and "the page links MISSING.md" in r.stderr, r.stderr


def test_RR1_control_a_link_inside_a_code_span_is_code():
    r, seite, _commit = _render("Write `[the steps](MISSING.md)` in the source.")
    assert r.returncode == 0, r.stderr
    assert "`[the steps](MISSING.md)`" in seite, seite


def _render_eintrag(ziel: str):
    """A fix line that links `ziel` in the form with a title, in the source and in the CHANGELOG line it must be."""
    zeile = f"**A first input is refused.** See [the steps]({ziel} \"the steps\")."
    q = base._zwei_ebenen()
    q["fixes"] = [zeile, q["fixes"][1]]
    changelog = base._CHANGELOG_999.replace("- **A first input is refused.** `first` refuses it.", f"- {zeile}")
    with tempfile.TemporaryDirectory() as d:
        w = base._baum_zwei_ebenen(Path(d), quelle=q, ersetze={"CHANGELOG.md": changelog})
        r = base._render_im(w)
        seite = (w / "notes.md").read_text(encoding="utf-8") if r.returncode == 0 else ""
        commit = base.json.loads((w / "release_notes" / "release-source.json").read_text())["release_commit"]
    return r, seite, commit


def test_RR1_a_link_in_an_entry_line_is_bound_and_checked():
    """The entry lines are page text too (found by mutant R9: leaving them out of the texts the page binds and checks
    kept every other case green)."""
    r, seite, commit = _render_eintrag("RELEASE.md")
    assert r.returncode == 0, r.stderr
    assert f"({BASIS}{commit}/RELEASE.md \"the steps\")" in seite, seite
    r, _seite, _commit = _render_eintrag("MISSING.md")
    assert r.returncode == 2 and "the page links MISSING.md" in r.stderr, r.stderr


def test_RR1_control_an_anchor_of_the_page_is_neither_bound_nor_checked():
    """A target that is an anchor of the page is no path of the tree (found by mutant R10: reading it as a path kept
    every other case green)."""
    r, seite, _commit = _render("See [what a receipt does not prove](#what-a-receipt-does-not-prove).")
    assert r.returncode == 0, r.stderr
    assert "](#what-a-receipt-does-not-prove)" in seite, seite
