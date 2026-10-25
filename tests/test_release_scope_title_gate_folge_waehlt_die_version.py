"""Without a version, a follow-up title chooses the release by the row of its parent, as the parent's
own branch would.

Codex on pull request 417, round one (P2): in a clone that shows no release tag, `main` chooses the
release by the branch alone, among the source version and the scope file above it. A follow-up's
branch stands in no scope file, so the newest candidate was chosen before the parent was looked up,
and a follow-up of a line of the older candidate came back outside the scope with exit 0. With
`--version` the same title was RED. The CI step calls the gate without `--version`.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import shutil

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]

_SCOPE = ("# Release scope - {v}\n\n## In\n\n"
          "| Identifier | Subject | Branch |\n|---|---|---|\n"
          "{rows}\n## Out\n")


def _tree(tmp_path: pathlib.Path, rows: dict[str, list[tuple[str, str]]]) -> pathlib.Path:
    """A root without git, so no tag can be read: the gate, the version reader it loads, a source
    version 6.2.0 with a scope file of its own, and 6.3.0 above it."""
    root = tmp_path / "tree"
    (root / "scripts").mkdir(parents=True)
    for name in ("b7_release_scope_title_gate.py", "check_version_and_changelog.py"):
        shutil.copy2(REPO / "scripts" / name, root / "scripts" / name)
    (root / "pyproject.toml").write_text('[project]\nname = "probe"\nversion = "6.2.0"\n',
                                         encoding="utf-8")
    (root / "docs" / "release_scope").mkdir(parents=True)
    for v, rs in rows.items():
        text = "".join(f"| {k} | something | `{b}` |\n" for k, b in rs)
        (root / "docs" / "release_scope" / f"{v}.md").write_text(_SCOPE.format(v=v, rows=text),
                                                                 encoding="utf-8")
    return root


def _gate(root: pathlib.Path, capsys, branch: str, title: str) -> tuple[int, dict]:
    spec = importlib.util.spec_from_file_location(f"gate_folge_{id(root)}",
                                                  root / "scripts" / "b7_release_scope_title_gate.py")
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    rc = gate.main(["--branch", branch, "--title", title, "--json"])
    return rc, json.loads(capsys.readouterr().out)


TWO = {"6.2.0": [("A1", "fix/a1")], "6.3.0": [("B1", "fix/b1")]}


def test_RED_a_second_identifier_beside_a_follow_up_of_the_older_candidate(tmp_path, capsys):
    """The case of the review: before the fix this was 6.3.0, outside the scope, exit 0."""
    rc, d = _gate(_tree(tmp_path, TWO), capsys, "review/follow-up",
                  "[6.2.0 A1-FOLGE] fix(x): see [6.2.0 L1]")
    assert (d["version"], rc, d["ausserhalb_des_umfangs"]) == ("6.2.0", 1, False), d
    assert "the parent A1 of the follow-up" in d["version_herkunft"], d


def test_a_follow_up_of_the_older_candidate_is_judged_against_its_parent(tmp_path, capsys):
    rc, d = _gate(_tree(tmp_path, TWO), capsys, "review/follow-up", "[6.2.0 A1-FOLGE] fix(x): y")
    assert (d["version"], rc, d["folge_von"], d["kennung_des_zweigs"]) == ("6.2.0", 0, "A1", "A1"), d


def test_a_parent_two_candidates_name_is_not_decided(tmp_path, capsys):
    """Like a branch two candidates name: which release the follow-up belongs to is not decided."""
    both = {"6.2.0": [("A1", "fix/a1")], "6.3.0": [("A1", "fix/a1-next")]}
    rc, d = _gate(_tree(tmp_path, both), capsys, "review/follow-up", "[6.2.0 A1-FOLGE] fix(x): y")
    assert rc == 1 and any("not decided" in g for g in d["gruende"]), d


@pytest.mark.parametrize("title", ["[6.2.0 C9-FOLGE] fix(x): y", "fix(x): no bracket at all"],
                         ids=["parent-in-no-candidate", "no-follow-up"])
def test_without_a_parent_in_a_candidate_the_newest_reports_outside(tmp_path, capsys, title):
    """The control: a follow-up of a line no candidate names, and a title that is no follow-up, stay
    where they stood, outside the newest candidate."""
    rc, d = _gate(_tree(tmp_path, TWO), capsys, "review/follow-up", title)
    assert (d["version"], rc, d["ausserhalb_des_umfangs"]) == ("6.3.0", 0, True), d


def test_the_branch_still_decides_before_the_title(tmp_path, capsys):
    """A branch a candidate names chooses that candidate, whatever the title says; the title is then
    judged against the branch's row, as before."""
    rc, d = _gate(_tree(tmp_path, TWO), capsys, "fix/b1", "[6.2.0 A1-FOLGE] fix(x): y")
    assert (d["version"], rc) == ("6.3.0", 1), d
    assert "judged by the branch" in d["version_herkunft"], d
