"""Check 6 recognises a release claim by its SHAPE, not by one word.

THE FINDING, measured 2026-09-23 against `README.md` on `origin/main`: the file names the current
release in SEVEN lines and FOUR shapes, and `_CURRENT_CLAIM` matched **none** of them, because none
carries the word `current` or `latest`:

    **[vX.Y.Z](…/releases/tag/vX.Y.Z) · Beta · …**
    python -m pip install proofbundle==X.Y.Z
    https://raw.githubusercontent.com/b7n0de/proofbundle/vX.Y.Z/examples/example_bundle.json

Check 6 exists precisely so that "the place nobody declared" does not go stale unobserved. It was
watching one sentence shape while the most consequential statements on the front page used three
others.

CATCH PROOF, run end to end rather than asserted: the source version AND the tracked prose
(`RELEASE.md`, `PROGRESS.md`) raised to the next release, a CHANGELOG section added, and the
**README left untouched**.

    OLD gate (origin/main)   rc=0  GREEN  — "OK — source version <new>"
    NEW gate                 rc=1  RED    — names README.md:27

The old gate reported green while the README offered the previous release for installation eight
times.

THE COUNTER-DIRECTION WEIGHS MORE HERE THAN THE FINDING. The module docstring says explicitly that
historical statements must NOT be touched: "since X.Y.Z" and "as of X.Y.Z" record WHEN something
became true, and a gate that demands they be raised turns a fact into a lie. A pattern that catches
too much is more expensive here than one that catches too little.

Run: python3 -m pytest tests/test_versionstor_sieht_nicht_nur_eine_satzform.py -q
"""
from __future__ import annotations

import importlib.util
import pathlib
import re
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
TOR = REPO / "scripts" / "check_version_and_changelog.py"


def _gate():
    s = importlib.util.spec_from_file_location("_u5_gate", TOR)
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


AKTUELL = "6.1.0"      # the source version on origin/main, which the cases below judge against


def _trifft(text: str, version: str = AKTUELL) -> str | None:
    """The NAME of the shape the CHECKER reports, or None.

    IT GOES THROUGH THE REAL FUNCTION, and that is a CORRECTION this file's own catch proof forced.
    The first version of this helper walked `_CLAIM_SHAPES` and applied the rule "only the current
    number counts" ITSELF, a second implementation of the same logic. Measured: two of four planted
    defects stayed NOT CAUGHT, because they changed the production path while this helper kept using
    its own copy. A test that reimplements the rule tests itself.

    Now a throwaway repository with ONE file is built and `check_undeclared_places` is called on it,
    the same way the gate goes.
    """
    import tempfile
    with tempfile.TemporaryDirectory(prefix="u5_trifft_") as tmp:
        repo = pathlib.Path(tmp)
        (repo / "pyproject.toml").write_text(f'[project]\nversion = "{version}"\n', encoding="utf-8")
        (repo / "DOKU.md").write_text(text + "\n", encoding="utf-8")
        g = _gate()
        g._tracked_files = lambda _repo: ["DOKU.md"]
        funde = g.check_undeclared_places(repo)
    if not funde:
        return None
    for form, _, _, _ in _gate()._CLAIM_SHAPES:
        if f"as a {form} " in funde[0]:
            return form
    return "UNBEKANNTE_FORM"


# ── THE FOUR SHAPES that claim a current release ─────────────────────────────────────────────

@pytest.mark.parametrize("text,erwartete_form", [
    ("python -m pip install proofbundle==6.1.0", "install pin"),
    ("python -m pip install 'proofbundle[eval]==6.1.0'", "install pin"),
    ("[v6.1.0](https://github.com/b7n0de/proofbundle/releases/tag/v6.1.0)", "release tag link"),
    ("https://raw.githubusercontent.com/b7n0de/proofbundle/v6.1.0/examples/x.json",
     "version-pinned URL"),
    ("current release: 6.1.0", "current/latest phrase"),
    ("latest version 6.1.0", "current/latest phrase"),
])
def test_jede_form_einer_release_behauptung_wird_erkannt(text, erwartete_form):
    assert _trifft(text) == erwartete_form


# ── THE COUNTER-DIRECTION: history stays history ─────────────────────────────────────────────

@pytest.mark.parametrize("text", [
    "since v6.1.0 the anchor has been stable",
    "as of 6.1.0 this holds",
    "Behaviour changed in 6.1.0 and has not moved since.",
    "see docs/release_scope/6.1.0.md for what belongs to that release",
    "## [6.1.0] - 2026-09-20",
    "audit_artifacts/610/pre_tag_receipt_v6.1.0.json",
    # Found by cross-reading lens 1, by execution: the first version reported all three.
    "pip uninstall proofbundle==6.0.0",
    # AND the case the word boundary turns on: an instruction to REMOVE the CURRENT release.
    # Without `\\binstall` the pattern matches the tail of "uninstall", and the number comparison
    # does not save it here, because the number IS the current one. This file's own catch proof
    # forced it: with the older number the planted defect "word boundary removed" stayed
    # NOT CAUGHT.
    "pip uninstall proofbundle==6.1.0",
    "[v5.0.0 release notes](https://github.com/b7n0de/proofbundle/releases/tag/v5.0.0)",
    "https://raw.githubusercontent.com/b7n0de/proofbundle/v5.0.0/examples/x.json",
])
def test_historische_und_benennende_formen_werden_NICHT_gefangen(text):
    """A gate that demands a historical statement be raised turns a fact into a lie. That rule is
    in the module docstring, word for word."""
    assert _trifft(text) is None, f"wrongly caught as {_trifft(text)!r}: {text!r}"


def test_eine_release_scope_datei_ist_keine_behauptung_aber_ein_tag_link_schon():
    """These two sit close together and have to be judged differently."""
    assert _trifft("docs/release_scope/6.1.0.md") is None
    assert _trifft("…/releases/tag/v6.1.0") == "release tag link"


# ── THE PRICE, because a flooding sweep gets switched off ─────────────────────────────────────

def test_der_sweep_flutet_nicht():
    """MEASURED BEFORE BUILDING: across every tracked file outside the excluded prefixes the three
    new shapes match FOUR times, all of them in README.md. A reporter that throws dozens of places
    on its first run gets switched off before it shows the first real case.

    THE PRECONDITION COMES FIRST, and it is a CORRECTION (cross-reading lens 2, 2026-09-23):
    without it this case derived its comparison set live from `_CLAIM_SHAPES` and was VACUOUSLY
    TRUE the moment the repair is removed entirely, because an empty set satisfies the statement
    trivially. It then guarded "the repair is there and does not flood" no longer, only "whatever
    is left does not flood". Measured by the counter-probe: with the repair removed it stayed
    green.
    """
    rc = subprocess.run(["git", "-C", str(REPO), "ls-files"], capture_output=True, text=True)
    if rc.returncode != 0:
        pytest.skip("no readable git index")
    g = _gate()
    neue = [(f, m) for f, m, _n, _ in g._CLAIM_SHAPES if f != "current/latest phrase"]
    assert len(neue) >= 3, (
        f"the repair is not here: only {len(neue)} additional shapes. Without this line the rest "
        f"of this case would be vacuously true")
    dateien = set()
    for rel in rc.stdout.splitlines():
        if rel.startswith(g._SWEEP_EXCLUDE_PREFIXES) or rel == str(TOR.relative_to(REPO)):
            continue
        try:
            t = (REPO / rel).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if any(m.search(t) for _, m in neue):
            dateien.add(rel)
    assert len(dateien) <= 3, f"the sweep matches {len(dateien)} files: {sorted(dateien)}"


def test_das_tor_zitiert_sich_nicht_selbst_in_die_falle():
    """On its first run the new rule reported TWO findings: README.md and the checker file itself,
    whose comment quoted the README including a real version number. A sweep cannot tell a claim
    from a quotation of one; the module docstring therefore says an illustration must not spell out
    the file's own release. No exception path for this file: it keeps the rule instead of being
    exempted from it."""
    g = _gate()
    assert len([f for f, _, _n, _ in g._CLAIM_SHAPES]) >= 4, (
        "without the complete list of shapes this case would be vacuously true")
    quelle = TOR.read_text(encoding="utf-8")
    version, _ = g._source_version(REPO)
    assert version, "without a source version this case says nothing"
    # The checker file must not carry its OWN current release in a claim shape.
    for form, muster, _n, _ in g._CLAIM_SHAPES:
        for treffer in muster.findall(quelle):
            assert treffer != version, (
                f"{TOR.name} carries its own release {version} as a {form} — exactly the place "
                f"the sweep is right to report")


def test_ein_ausnahmepfad_fuer_die_prueferdatei_existiert_nicht(tmp_path, monkeypatch):
    """A checker that exempts itself stops checking the file most likely to quote claims.

    BOUND TO THE EFFECT, NOT TO THE SPELLING — and that is a CORRECTION (cross-reading lens 2,
    2026-09-23, with an executed counter-proof). The first version searched the source text for
    `rel ==` plus the file name. The lens built a REAL, working self-exemption, through a
    `Path(__file__).resolve()` comparison instead of a literal, and this case stayed **green**
    while a planted claim in the checker file demonstrably disappeared. Binding to the textual form
    tests how somebody writes, not what the code does.

    Now it is MEASURED: a claim at exactly the path of the checker file must be reported. How an
    exemption would be written is thereby irrelevant.

    THE COPY IS CHECKED, NOT THE ORIGINAL — and that too is a correction, found by this file's own
    catch proof. The second version of this case put the claim into a throwaway file and let the
    ORIGINAL MODULE run over it. An exemption through `Path(__file__)` then compares against the
    original's path and never fires: the planted defect "checker file exempts itself" stayed
    **NOT CAUGHT**. Only when the planted module runs ITSELF does its exemption show.
    """
    rel = "scripts/check_version_and_changelog.py"
    ziel = tmp_path / rel
    ziel.parent.mkdir(parents=True, exist_ok=True)
    quelle = TOR.read_text(encoding="utf-8")
    # The claim sits IN the checker, and the checker that has to find it is this copy.
    ziel.write_text(quelle + "\n# planted claim:\n"
                             "# python -m pip install proofbundle==9.9.9\n", encoding="utf-8")
    s = importlib.util.spec_from_file_location("_u5_gate_kopie", ziel)
    g = importlib.util.module_from_spec(s)
    s.loader.exec_module(g)
    monkeypatch.setattr(g, "_tracked_files", lambda _repo: [rel])
    funde = g.check_undeclared_places(tmp_path)
    assert funde, ("the checker file was NOT swept — it exempts itself, whichever spelling is "
                   "used")
    # What is checked is THAT the file gets swept, not WHICH of its lines reports first: the sweep
    # stops after the first finding per file, and which line that is depends on the content.
    # A self-exemption would have left `funde` EMPTY, and that is the property.
    assert rel in funde[0], funde


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))


# ── A DECLARATION COVERS ONE PATTERN, NOT ONE FILE ───────────────────────────────────────────

def test_eine_anmeldung_legt_die_geschwisterbelege_nicht_stumm(tmp_path, monkeypatch):
    """THE HEAVIEST FINDING of the cross-reading, and it hit the remedy rather than the repair.

    `check_undeclared_places` compared `rel in declared`, file-wide. Declaring a file for ONE
    pattern (exactly the option A my own owner card offers) took it out of the sweep ENTIRELY.
    Measured against README.md: after declaring the tag link the sweep reported NOTHING any more,
    although three further places of the same class stand in it unchanged.

    That is worse than the starting state: undetected before, permanently silenced by a declaration
    afterwards, and the sweep reported quiet.
    """
    g = _gate()
    rel = "DOKU.md"
    (tmp_path / rel).write_text(
        "[v6.1.0](https://github.com/x/y/releases/tag/v6.1.0)\n"
        "python -m pip install paket==6.1.0\n", encoding="utf-8")
    monkeypatch.setattr(g, "_tracked_files", lambda _repo: [rel])

    ohne = g.check_undeclared_places(tmp_path)
    assert ohne and "DOKU.md:1" in ohne[0], ohne

    # Declare the first line — the second MUST stay visible.
    monkeypatch.setattr(g, "_TRACKED_PLACES",
                        [(rel, re.compile(r"/releases/tag/v" + g._SEMVER), "the tag link")])
    mit = g.check_undeclared_places(tmp_path)
    assert mit, ("the declaration silenced the whole file — the second claim is unobserved")
    assert "DOKU.md:2" in mit[0] and "install pin" in mit[0], mit


def test_eine_veraltete_WORTbehauptung_bleibt_ein_fund():
    """The distinction lens 1 forced: a WORD claims currency on its own, whatever number stands
    beside it, so a stale word claim very much IS a finding. Only the SHAPE needs the current
    number in order to be a claim."""
    assert _trifft("current release: 5.0.0") == "current/latest phrase"
    assert _trifft("latest version 5.0.0") == "current/latest phrase"


# ── README.md IS A DECLARED PLACE (owner decision, 2026-09-23) ───────────────────────────────
#
# Check 6 found the four release claims in README.md and asked for a decision: declare, reword, or
# name an exception. The owner chose to declare them. From here on Check 4 holds them at the source
# version, and the cases below bind what that has to mean: a README left behind at a bump is red,
# a headline raised halfway is red, a reworded headline is a vanished anchor, and a number that
# belongs to another package or to an older release is not demanded to move.

NEU = "6.2.0"      # a next release, for trees that are raised on purpose


def _readme(kopf_text: str, kopf_url: str, pin: str, url: str) -> str:
    return (f"## Current release\n\n"
            f"**[v{kopf_text}](https://github.com/b7n0de/proofbundle/releases/tag/v{kopf_url})"
            f" · Beta**\n\n"
            f"python -m pip install proofbundle=={pin}\n"
            f"python -m pip install 'proofbundle[eval]=={pin}'\n"
            f"https://raw.githubusercontent.com/b7n0de/proofbundle/v{url}/examples/x.json\n")


def _readme_funde(tmp_path, readme: str, version: str = NEU) -> list[str]:
    """Check 4 over a tree whose other declared places already name `version`."""
    (tmp_path / "docs" / "readiness_pack").mkdir(parents=True, exist_ok=True)
    (tmp_path / "RELEASE.md").write_text(f"(current: {version})\n", encoding="utf-8")
    (tmp_path / "docs" / "readiness_pack" / "PROGRESS.md").write_text(
        f"(current release: {version})\n", encoding="utf-8")
    (tmp_path / "README.md").write_text(readme, encoding="utf-8")
    return [f for f in _gate().check_tracked_places(tmp_path, version) if f.startswith("README.md")]


def _readme_orte():
    return [(i, rel, beschreibung) for i, (rel, _m, beschreibung)
            in enumerate(_gate()._TRACKED_PLACES) if rel == "README.md"]


def test_the_readme_is_declared_in_its_three_forms():
    """Without this line every case below could pass against a list that no longer names README."""
    assert len(_readme_orte()) == 3, _readme_orte()


@pytest.mark.parametrize("nr", range(len(_gate()._TRACKED_PLACES)),
                         ids=[f"{rel}::{b[:40]}" for rel, _m, b in _gate()._TRACKED_PLACES])
def test_every_declared_place_names_the_source_in_the_real_tree(nr):
    """ONE CASE PER PLACE, with its file in the id. `test_das_echte_repo_besteht_das_echte_tor`
    says THAT something is off; this says WHERE, and it covers every declared place, not a list
    typed next to the declaration."""
    g = _gate()
    rel, muster, beschreibung = g._TRACKED_PLACES[nr]
    version, _ = g._source_version(REPO)
    werte = [v for hit in muster.findall((REPO / rel).read_text(encoding="utf-8"))
             for v in (hit if isinstance(hit, tuple) else (hit,))]
    assert werte, f"{rel}: {beschreibung} is not in the real file any more"
    assert set(werte) == {version}, f"{rel}: {beschreibung} states {sorted(set(werte))}, source {version}"


def test_a_readme_left_behind_at_a_bump_is_red_in_check_4(tmp_path):
    """THE CATCH PROOF of the decision: the source and the other places are raised, README is not.
    Every one of the three forms is named, not just the first."""
    funde = _readme_funde(tmp_path, _readme(AKTUELL, AKTUELL, AKTUELL, AKTUELL))
    assert len(funde) == 3, funde
    for _i, _rel, beschreibung in _readme_orte():
        assert any(beschreibung in f and AKTUELL in f for f in funde), (beschreibung, funde)


def test_CONTROL_a_raised_readme_is_green(tmp_path):
    assert _readme_funde(tmp_path, _readme(NEU, NEU, NEU, NEU)) == []


def test_a_headline_raised_halfway_is_red(tmp_path):
    """New tag URL, old link text: the front page names one release and links to another. An
    anchor bound to the URL alone reads that headline as current."""
    funde = _readme_funde(tmp_path, _readme(AKTUELL, NEU, NEU, NEU))
    assert len(funde) == 1 and "release headline" in funde[0] and AKTUELL in funde[0], funde


def test_a_reworded_headline_is_a_vanished_anchor_not_a_pass(tmp_path):
    readme = _readme(NEU, NEU, NEU, NEU).replace(f"**[v{NEU}]", f"**[Release {NEU}]")
    funde = _readme_funde(tmp_path, readme)
    assert len(funde) == 1 and "was not found" in funde[0] and "release headline" in funde[0], funde


def test_the_readme_anchors_name_this_project_not_a_shape(tmp_path):
    """Check 4 demands the source version of EVERY match in the file. Four decoys that carry a
    version in a release-claim shape but are not this project's current release must therefore not
    match: another package's pin, a descriptive and a bare link to an older release, and another
    project's URL."""
    koeder = ("python -m pip install cbor2==5.9.0\n"
              "[v6.0.0 release notes](https://github.com/b7n0de/proofbundle/releases/tag/v6.0.0)\n"
              "Previous release: [v6.0.0](https://github.com/b7n0de/proofbundle/releases/tag/v6.0.0)\n"
              "https://raw.githubusercontent.com/other/project/v5.0.0/x.json\n")
    g = _gate()
    # PRECONDITION: each decoy IS a release-claim shape with a non-current number, so this case can
    # fail. Measured through the Check 6 shapes, which carry no project name.
    for zeile in koeder.splitlines():
        treffer = [m.search(zeile) for _f, m, _n, _b in g._CLAIM_SHAPES]
        assert any(t and t.group(1) != NEU for t in treffer), f"not a decoy: {zeile!r}"
    assert _readme_funde(tmp_path, _readme(NEU, NEU, NEU, NEU) + koeder) == []


# ── THE WORKFLOW THAT RUNS THE GATE DOES NOT SKIP WHAT THE GATE READS (owner decision B) ──────
#
# `release-integrity.yml` is the only runner of this gate. It ignored '**/*.md' and 'docs/**', so a
# change that touched nothing but prose never ran the check that guards prose. The class is a path
# filter that excludes the files its own check reads; the case binds that property, not the list.

def _glob_regex(glob: str) -> "re.Pattern[str]":
    """GitHub path-filter globs: `**/` spans zero or more directories, `*` stays inside one."""
    teile, i = [], 0
    while i < len(glob):
        if glob.startswith("**/", i):
            teile.append("(?:.*/)?")
            i += 3
        elif glob.startswith("**", i):
            teile.append(".*")
            i += 2
        elif glob[i] == "*":
            teile.append("[^/]*")
            i += 1
        elif glob[i] == "?":
            teile.append("[^/]")
            i += 1
        else:
            teile.append(re.escape(glob[i]))
            i += 1
    return re.compile("".join(teile) + r"\Z")


def _gelesene_dateien() -> list[str]:
    g = _gate()
    return sorted({"pyproject.toml", "src/proofbundle/__init__.py", "CITATION.cff", "CHANGELOG.md",
                   *(rel for rel, _m, _b in g._TRACKED_PLACES)})


def _uebersprungen(ignore: list[str]) -> list[str]:
    return [f"{rel} by {glob!r}" for rel in _gelesene_dateien() for glob in ignore
            if _glob_regex(glob).match(rel)]


def test_the_workflow_does_not_skip_a_file_the_gate_reads():
    yaml = pytest.importorskip("yaml", reason="PyYAML missing: the path filter is NOT measured")
    d = yaml.safe_load((REPO / ".github" / "workflows" / "release-integrity.yml")
                       .read_text(encoding="utf-8"))
    on = d.get(True) or d.get("on")
    listen = {trig: (on.get(trig) or {}).get("paths-ignore", []) for trig in ("push", "pull_request")}
    assert listen["push"] == listen["pull_request"], (
        f"the two triggers filter differently, so a pull request and the push to main answer "
        f"different questions: {listen}")
    for trig, ignore in listen.items():
        assert not _uebersprungen(ignore), f"{trig}: the gate's own inputs are skipped: {_uebersprungen(ignore)}"


def test_CONTROL_the_old_filter_would_have_been_caught():
    """THE COUNTER-DIRECTION. Without it the case above would also pass with a glob matcher that
    matches nothing. The list below is the filter this workflow carried before 2026-09-23."""
    alt = ["**/*.md", "docs/**", "audit_artifacts/**", "receipts/**", ".mailmap"]
    treffer = _uebersprungen(alt)
    assert "README.md by '**/*.md'" in treffer, treffer
    assert "CHANGELOG.md by '**/*.md'" in treffer, treffer
    assert "docs/readiness_pack/PROGRESS.md by 'docs/**'" in treffer, treffer
    assert not _glob_regex("docs/**").match("src/docs.py")
    assert not _glob_regex("*.md").match("docs/x.md"), "a single star crossed a directory"
