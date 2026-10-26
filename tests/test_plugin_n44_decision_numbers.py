"""Nachtrag 44, point 3 (owner choice O43-2 of 2026-10-20): every number of DECISIONS.md stands once.

D113 was given on the chain claude/z405-eigener-pilot, behind D112 of the main line; a next rule of the main line would
have taken the same number. The owner's choice: D113 belongs to the chain and the main line counts on from D114. The
line in D113 says so; this file is red where a number of a decision stands twice, so a merge of the chain and the main
line cannot keep two decisions of one number. A level-2 heading that begins with a D number counts in every spelling: one
of another shape than `## D<number>[<letter>]. <title>` is red as well, so no decision escapes the count by its form.
A letter after the number is a number of its own (D24 and D24B).

RED at d5e0720f (the head of PLUGIN_N43): the line of the numbering in D113. The count of the numbers is green there,
as no number stands twice yet; the cases with a text of their own show that it turns red on one that does.
"""
from __future__ import annotations

import collections
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
DECISIONS = ROOT / "plugins" / "proofbundle" / "DECISIONS.md"
#: A level-2 heading that begins with a D number, in any spacing or case: every one of them is a decision.
_HEADING = re.compile(r"^##(?!#)\s*[Dd]\s*\d")
_ID = re.compile(r"^## D(\d+[A-Z]?)\. \S")


def problems(text: str) -> list[str]:
    """What breaks the numbering: a number given twice, and a heading of a decision of another shape."""
    found, numbers = [], []
    for number, line in enumerate(text.splitlines(), 1):
        if not _HEADING.match(line):
            continue
        matched = _ID.match(line)
        if matched is None:
            found.append(f"line {number}: a decision heading of another shape")
        else:
            numbers.append(matched.group(1))
    found += [f"D{n} stands {k} times" for n, k in collections.Counter(numbers).items() if k > 1]
    return found


def _section(text: str, number: str) -> str:
    return text.split(f"\n## D{number}. ", 1)[1].split("\n## ", 1)[0]


def test_O43_2_every_number_of_a_decision_stands_once():
    text = DECISIONS.read_text(encoding="utf-8")
    assert problems(text) == []


def test_O43_2_D113_belongs_to_the_chain_and_the_main_line_counts_on_from_D114():
    line = [x for x in _section(DECISIONS.read_text(encoding="utf-8"), "113").splitlines() if "O43-2" in x]
    assert len(line) == 1 and all(w in line[0] for w in ("D113", "chain", "main line", "D114")), line


def test_O43_2_a_number_given_twice_is_red():
    text = "# Decisions\n\n## D112. One\n\ntext\n\n## D113. Two\n\ntext\n\n## D113. Three\n"
    assert problems(text) == ["D113 stands 2 times"]


def test_O43_2_a_letter_after_the_number_is_a_number_of_its_own_and_counts_too():
    assert problems("## D24. One\n## D24B. Two\n") == []
    assert problems("## D24B. One\n## D24B. Two\n") == ["D24B stands 2 times"]


def test_O43_2_a_decision_heading_of_another_shape_does_not_escape_the_count():
    for heading in ("## D113: Two", "## D 113. Two", "##D113. Two", "## d113. Two", "## D113.Two", "##  D113. Two"):
        assert problems(f"## D113. One\n{heading}\n") == ["line 2: a decision heading of another shape"], heading


def test_O43_2_a_subheading_and_a_heading_of_no_decision_are_no_number():
    text = "## The declaration\n\n## D3. One\n\n### D3, two forms after a state check\n\n#### D3 again\n"
    assert problems(text) == []
