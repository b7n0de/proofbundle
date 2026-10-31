"""The release gate asks for no external version surface before the upload.

RELEASE.md answers its release gate before the owner GO. One line of that gate asked for
`scripts/check_version_and_changelog.py --external --require-external`, which compares the source
version with PyPI and with the project page. Before the upload PyPI states the previous release, so
that line could not be green before the GO: the dry run of 6.5.0 measured it on a local probe, exit 1,
PyPI ABWEICHUNG 6.4.0 against 6.5.0. By the owner's choice of 2026-10-31 (card OA-fe25d8f446, answer
A) the gate checks the version places of the tree, and the external check is a line after the publish.

The last test binds the line numbers `docs/version_truth_list.md` names to what RELEASE.md carries
there, because a reference by line number goes stale with every edit above it.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RELEASE = ROOT / "RELEASE.md"
TRUTH_LIST = ROOT / "docs" / "version_truth_list.md"
CHECKER = "scripts/check_version_and_changelog.py"


def _section(text: str, heading: str) -> list[str]:
    """The lines of the `## <heading>` section, up to the next `## ` heading."""
    lines = text.splitlines()
    starts = [i for i, line in enumerate(lines) if line.startswith("## " + heading)]
    assert len(starts) == 1, f"RELEASE.md carries the section `## {heading}` {len(starts)} times"
    rest = lines[starts[0] + 1:]
    end = next((i for i, line in enumerate(rest) if line.startswith("## ")), len(rest))
    return rest[:end]


def test_the_gate_before_the_go_asks_for_no_external_surface():
    gate = _section(RELEASE.read_text(encoding="utf-8"), "Release gate")
    asking = [line for line in gate if CHECKER in line and "--external" in line]
    assert asking == [], f"the gate before the owner GO asks for the external surfaces: {asking}"


def test_the_gate_before_the_go_checks_the_version_places_of_the_tree():
    gate = _section(RELEASE.read_text(encoding="utf-8"), "Release gate")
    assert any(f"{CHECKER} --repo ." in line for line in gate), (
        "the gate before the owner GO no longer runs the version check over the tree")


def _items(lines: list[str]) -> list[str]:
    """The checklist items of a section, each a `- [ ]` line with the indented lines under it."""
    items: list[str] = []
    for line in lines:
        if line.startswith("- [ ]"):
            items.append(line)
        elif items and line.startswith(" ") and line.strip():
            items[-1] += " " + line.strip()
    return items


def test_the_external_check_is_a_line_after_the_publish():
    items = _items(_section(RELEASE.read_text(encoding="utf-8"), "Per release"))
    publish = [i for i, item in enumerate(items) if item.startswith("- [ ] After publish")]
    external = [i for i, item in enumerate(items) if "--external --require-external" in item]
    assert publish, "`Per release` names no step after the publish"
    assert len(external) == 1, f"`Per release` carries the external check {len(external)} times"
    assert external[0] > publish[0], "the external check stands before the publish it depends on"


def test_the_truth_list_names_lines_that_hold_the_check():
    release_lines = RELEASE.read_text(encoding="utf-8").splitlines()
    named = [int(n) for n in re.findall(r"`RELEASE\.md:(\d+)`", TRUTH_LIST.read_text(encoding="utf-8"))]
    assert named, "docs/version_truth_list.md names no line of RELEASE.md"
    for number in named:
        window = " ".join(release_lines[number - 1:number + 2])
        assert CHECKER in window, f"RELEASE.md:{number} does not hold the version check: {window[:120]!r}"
