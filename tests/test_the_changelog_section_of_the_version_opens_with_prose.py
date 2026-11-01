"""The CHANGELOG section of the version being released opens with prose before its first subsection.

RELEASE.md asks in its release gate that "the CHANGELOG entry says explicitly whether semantics
change". The release-integrity gate checked only that a `## [<version>]` heading exists. The dry run
of 6.5.0 (finding K6) renamed `## [Unreleased]` to `## [6.5.0]` the way a release preparation does,
and the heading stood directly over `### Added`: the gate stayed green, and so did the suite.

Whether a paragraph says the right thing about semantics is a reading, not a pattern. What the gate
can hold is that the section of the version opens with text at all, as 6.4.0 does with its two
opening paragraphs. Older sections are history and are not read, and an `[Unreleased]` block may open
with a subsection, because it is not yet an entry.
"""
from __future__ import annotations

import importlib.util
import itertools
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "chk_k6", Path(__file__).resolve().parents[1] / "scripts" / "check_version_and_changelog.py")
chk = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(chk)

VERSION = "3.0.1"


def _repo(t: Path, changelog: str) -> Path:
    """A tree that passes every other check of the gate, with the given CHANGELOG."""
    (t / "src" / "proofbundle").mkdir(parents=True, exist_ok=True)
    (t / "docs" / "readiness_pack").mkdir(parents=True, exist_ok=True)
    (t / "pyproject.toml").write_text(f'[project]\nname = "proofbundle"\nversion = "{VERSION}"\n',
                                      encoding="utf-8")
    (t / "src" / "proofbundle" / "__init__.py").write_text(f'__version__ = "{VERSION}"\n', encoding="utf-8")
    (t / "CITATION.cff").write_text(f"cff-version: 1.2.0\nversion: {VERSION}\n", encoding="utf-8")
    (t / "RELEASE.md").write_text(f"# Release\n\n(current: {VERSION}) and so on.\n", encoding="utf-8")
    (t / "docs" / "readiness_pack" / "PROGRESS.md").write_text(
        f"# Progress\n\nfrom 3.3.0 (current release: {VERSION}) to stable.\n", encoding="utf-8")
    (t / "README.md").write_text(
        f"**[v{VERSION}](https://github.com/b7n0de/proofbundle/releases/tag/v{VERSION}) · Beta**\n\n"
        f"    python -m pip install proofbundle=={VERSION}\n", encoding="utf-8")
    (t / "CHANGELOG.md").write_text(changelog, encoding="utf-8")
    return t


def _opening_findings(problems: list[str]) -> list[str]:
    return [p for p in problems if "CHANGELOG.md" in p and "opens" in p]


def test_RED_a_version_section_that_opens_with_a_subsection_is_a_finding(tmp_path):
    """The case of the dry run: the release heading stands directly over `### Added`."""
    probs = chk.check(_repo(tmp_path, f"# Changelog\n\n## [{VERSION}] - 2026-10-31\n\n### Added\n\n- x\n\n"
                                      "## [3.0.0] - 2026-10-01\n\nThe first release.\n"))
    found = _opening_findings(probs)
    assert len(found) == 1 and f"[{VERSION}]" in found[0], probs


def test_RED_an_empty_version_section_is_a_finding(tmp_path):
    probs = chk.check(_repo(tmp_path, f"# Changelog\n\n## [{VERSION}] - 2026-10-31\n\n"
                                      "## [3.0.0] - 2026-10-01\n\nThe first release.\n"))
    assert len(_opening_findings(probs)) == 1, probs


def test_a_section_that_opens_with_a_paragraph_passes(tmp_path):
    probs = chk.check(_repo(tmp_path, f"# Changelog\n\n## [{VERSION}] - 2026-10-31\n\n"
                                      f"{VERSION} is a patch release following 3.0.0. Semantics do not change.\n\n"
                                      "### Fixed\n\n- x\n"))
    assert probs == [], probs


def test_an_older_section_is_history_and_is_not_read(tmp_path):
    """Only the section of the version being released is held; an older one stays as it was written."""
    probs = chk.check(_repo(tmp_path, f"# Changelog\n\n## [{VERSION}] - 2026-10-31\n\nA patch release.\n\n"
                                      "## [3.0.0] - 2026-10-01\n\n### Added\n\n- y\n"))
    assert probs == [], probs


def test_an_unreleased_block_above_may_open_with_a_subsection(tmp_path):
    probs = chk.check(_repo(tmp_path, "# Changelog\n\n## [Unreleased]\n\n### Added\n\n- z\n\n"
                                      f"## [{VERSION}] - 2026-10-31\n\nA patch release.\n\n### Fixed\n\n- x\n"))
    assert probs == [], probs


# ── what GitHub renders as no paragraph is no opening (reading of 2026-11-01, sol-pro, P1 and P2) ─────────────────
#
# The first form held any line that is not blank. A thematic break, an HTML comment, a link reference definition, a
# code block and a setext heading are lines that are not blank, and none of them renders as an opening paragraph.

_NO_PARAGRAPH = {
    "thematic break": "---\n",
    "thematic break of stars": "* * *\n",
    "empty comment": "<!---->\n",
    "comment over two lines": "<!-- a note\nfor the release -->\n",
    "link reference definition": "[x]: /target\n",
    "empty fence": "```\n```\n",
    "fence with text inside": "```\nSemantics do not change.\n```\n",
    "tilde fence": "~~~\nSemantics do not change.\n~~~\n",
    "indented code": "    Semantics do not change.\n",
    "setext heading with dashes": "Semantics\n-\n",
    "setext heading with equals": "Semantics\n===\n",
}


def test_RED_what_renders_as_no_paragraph_does_not_open_the_section(tmp_path):
    for name, opening in _NO_PARAGRAPH.items():
        t = tmp_path / name.replace(" ", "_")
        t.mkdir()
        probs = chk.check(_repo(t, f"# Changelog\n\n## [{VERSION}] - 2026-10-31\n\n{opening}\n### Added\n\n- x\n"))
        assert len(_opening_findings(probs)) == 1, (name, probs)


def test_a_paragraph_after_a_comment_or_a_break_still_opens_the_section(tmp_path):
    """The other side: what renders as no paragraph is passed over, and the paragraph after it counts. A setext
    heading is not passed over; it is a heading and ends the opening (the next case)."""
    for name, opening in ((k, v) for k, v in _NO_PARAGRAPH.items() if not k.startswith("setext")):
        t = tmp_path / name.replace(" ", "_")
        t.mkdir()
        probs = chk.check(_repo(t, f"# Changelog\n\n## [{VERSION}] - 2026-10-31\n\n{opening}\n"
                                   f"{VERSION} is a patch release. Semantics do not change.\n\n### Fixed\n\n- x\n"))
        assert probs == [], (name, probs)


def test_a_setext_heading_ends_the_opening_like_a_subsection(tmp_path):
    """A paragraph after a setext heading stands under a heading, as one after `### Added` does."""
    for underline in ("-", "==="):
        t = tmp_path / f"setext_{len(underline)}"
        t.mkdir()
        probs = chk.check(_repo(t, f"# Changelog\n\n## [{VERSION}] - 2026-10-31\n\nNotes\n{underline}\n\n"
                                   "Semantics do not change.\n"))
        assert len(_opening_findings(probs)) == 1, (underline, probs)


def test_a_paragraph_followed_by_a_list_item_is_still_a_paragraph(tmp_path):
    """A list item after a line of text is no setext underline; the line stays a paragraph."""
    probs = chk.check(_repo(tmp_path, f"# Changelog\n\n## [{VERSION}] - 2026-10-31\n\n"
                                      "Semantics do not change.\n- one note\n\n### Fixed\n\n- x\n"))
    assert probs == [], probs


def test_RED_a_version_heading_that_stands_twice_is_a_finding_in_both_orders(tmp_path):
    """P2: the first form read the first of two sections and passed over the other one."""
    leer, gut = f"## [{VERSION}]\n\n### Added\n\n- x\n\n", f"## [{VERSION}]\n\nSemantics do not change.\n\n"
    for name, body in (("empty first", leer + gut), ("empty second", gut + leer)):
        t = tmp_path / name.replace(" ", "_")
        t.mkdir()
        probs = chk.check(_repo(t, "# Changelog\n\n" + body + "## [3.0.0] - 2026-10-01\n\nThe first release.\n"))
        twice = [p for p in probs if "CHANGELOG.md" in p and "twice" in p]
        assert len(twice) == 1, (name, probs)


# ── a paragraph is recognised for what it is (second reading of 2026-11-01, sol-pro, P1 and two P2) ───────────────
#
# The fix of the first reading named five forms that are no paragraph and took every other line for one. A list, a
# block quote and an HTML block were none of the five and passed. A paragraph is now recognised positively.

_OTHER_BLOCKS = {
    "bullet list": "- x\n",
    "plus list": "+ x\n",
    "ordered list": "1. x\n",
    "ordered list with a parenthesis": "1) x\n",
    "block quote": "> Semantics do not change.\n",
    "html block": "<div>\nSemantics do not change.\n</div>\n",
    "details block": "<details>\n",
    "a complete tag alone on its line": "<span>\n",
    "table": "| change | semantics |\n| --- | --- |\n| x | none |\n",
}


def test_RED_another_block_than_a_paragraph_does_not_open_the_section(tmp_path):
    for name, opening in _OTHER_BLOCKS.items():
        t = tmp_path / name.replace(" ", "_")
        t.mkdir()
        probs = chk.check(_repo(t, f"# Changelog\n\n## [{VERSION}] - 2026-10-31\n\n{opening}\n### Added\n\n- x\n"))
        assert len(_opening_findings(probs)) == 1, (name, probs)


def test_RED_text_after_an_invalid_closing_fence_stays_code():
    """CommonMark: a closing fence carries only blanks after its characters; `` ```x `` closes nothing."""
    assert not chk._opens_with_a_paragraph(["```", "```not-a-closing-fence", "Semantics do not change."])
    assert not chk._opens_with_a_paragraph(["````", "```", "Semantics do not change."]), "a shorter fence closes nothing"
    assert chk._opens_with_a_paragraph(["```", "code", "```  ", "Semantics do not change."]), "blanks may follow"


def test_RED_an_invalid_link_reference_definition_starts_with_a_bracket_and_is_a_finding():
    """Third reading: these lines render as paragraph text, and the check took them for an opening. Since the owner's
    answer on its card an opening starts with a word or a number, so they are findings, the price `_OPENING` names."""
    for line in ("[x]: <", "[]: /target", "[x]:", "[x]: /target \"title"):
        assert not chk._opens_with_a_paragraph([line]), line
    for line in ("[x]: /target", "[x]: <a b>", "[x]: /target \"title\"", "[x]: /target 'title'", "[x]: /t (title)"):
        assert not chk._opens_with_a_paragraph([line]), line


def test_RED_a_version_heading_inside_a_fence_or_a_comment_is_no_duplicate(tmp_path):
    for name, verdeckt in (("fence", f"```\n## [{VERSION}]\n```\n"), ("comment", f"<!--\n## [{VERSION}]\n-->\n")):
        t = tmp_path / name
        t.mkdir()
        probs = chk.check(_repo(t, f"# Changelog\n\n## [{VERSION}]\n\nSemantics do not change.\n\n{verdeckt}"))
        assert not [p for p in probs if "twice" in p], (name, probs)


def test_an_opening_that_starts_with_markup_is_a_finding_and_one_that_starts_with_a_word_or_a_number_passes():
    """The owner's answer after the third reading: only an opening that starts with a letter or a digit that begins no
    list item counts. One that starts with markup, a bracket or a tag renders as a paragraph and is a finding all the
    same; its fix is to begin the opening with a word."""
    for line in ("**Semantics do not change.**", "`proofbundle` 3.0.1 is a patch release.",
                 "<span>Semantics</span> do not change.", "[A link](https://example.invalid) opens the entry.",
                 "*Semantics* do not change.", "\"Semantics\" do not change.", "(Semantics) do not change."):
        assert not chk._opens_with_a_paragraph([line]), line
    for line in ("Semantics do not change.", "3.0.1 is a patch release.", "2026 brought one change.",
                 "   Semantics do not change.", "1234567890. is no list item, the marker has at most nine digits."):
        assert chk._opens_with_a_paragraph([line]), line


# ── the opening is a narrow form (third reading of 2026-11-01, sol-pro, three P1, and the owner's answer A) ──────────
#
# Each reading found the next edge of a hand-made CommonMark reader. An opening now starts with a word or a number
# after at most three spaces and no tab, everything else is a finding, and markdown-it is the oracle for what the check
# accepts.


def test_RED_a_space_and_a_tab_is_indented_code_and_opens_nothing():
    """A tab counts to the next multiple of four columns: a space or three and then a tab are four, and the line is
    code. The check knew only four spaces or a tab at the start."""
    for prefix in (" \t", "  \t", "   \t"):
        assert not chk._opens_with_a_paragraph([prefix + "Semantics do not change."]), repr(prefix)


def test_RED_a_link_reference_over_two_lines_renders_nothing():
    """A link reference definition may take its destination or its title from the next line; it renders nothing. The
    check took the first line, or the title, for paragraph text."""
    assert not chk._opens_with_a_paragraph(["[x]:", "/target"])
    assert not chk._opens_with_a_paragraph(["[x]: /target", "\"title\""])


def test_RED_a_comment_start_indented_four_columns_is_code_and_hides_no_duplicate(tmp_path):
    """`    <!--` is indented code, no comment: a second version heading after it is a duplicate. The check took the
    line for a comment start and hid everything after it."""
    probs = chk.check(_repo(tmp_path, f"# Changelog\n\n## [{VERSION}]\n\nSemantics do not change.\n\n    <!--\n\n"
                                      f"## [{VERSION}]\n\n### Added\n\n- x\n"))
    assert len([p for p in probs if "CHANGELOG.md" in p and "twice" in p]) == 1, probs


#: Lines a section can start with, and lines that can follow them, as the corpus of the differential case.
_PREFIXES = ("", " ", "   ", "    ", "\t", " \t", "   \t")
_STARTS = ("Semantics do not change.", "3.0.1 is a patch release.", "2026 brought one change.", "x", "1. x", "1) x",
           "1.", "1234567890. x", "- x", "+ x", "* x", "> x", "# x", "####### x", "<!-- a note -->", "<!--", "<div>",
           "<span>", "<span>x</span> y", "[x]: /target", "[x]:", "[x]: (", "[x]: <", "```", "~~~", "a | b", "| a | b |",
           "\"quoted\"", "(paren)", "**bold**", "`code`", "---", "***", "===", "_x_", "\\# escaped", "&amp; entity",
           "<?php", "\u00e9t\u00e9", "\u2192 arrow")
_NEXT = ("", "Text follows.", "===", "---", "| --- | --- |", "--- | ---", "- item", "/target", "\"title\"",
         "    indented", "> quote", "```")
_PASSED_OVER = ("", "---", "<!-- a note -->", "[x]: /target", "    code")


def _first_block(tokens) -> str | None:
    """The type of the first block markdown-it renders that the check does not pass over: thematic breaks, comments,
    indented and fenced code are passed over, as the check's docstring names them; link reference definitions render
    no token."""
    for token in tokens:
        if token.nesting == -1 or token.type in ("inline", "hr", "code_block", "fence"):
            continue
        if token.type == "html_block" and token.content.lstrip().startswith("<!--"):
            continue
        return token.type
    return None


def test_every_opening_the_check_accepts_renders_as_a_paragraph_in_markdown_it():
    """The differential case of the owner's answer: over a generated corpus of section starts, every start the check
    accepts renders, in markdown-it with the CommonMark preset and GitHub's tables, as a paragraph after what the check
    passes over. markdown-it is the version .github/pr-form-requirements.txt pins; where it is not installed the case
    is a visible skip."""
    markdown_it = pytest.importorskip("markdown_it")
    md = markdown_it.MarkdownIt("commonmark").enable("table")
    accepted = 0
    for before, prefix, start, after in itertools.product(_PASSED_OVER, _PREFIXES, _STARTS, _NEXT):
        lines = ([before, ""] if before else []) + [prefix + start] + ([after] if after else [])
        if chk._opens_with_a_paragraph(lines):
            accepted += 1
            assert _first_block(md.parse("\n".join(lines) + "\n")) == "paragraph_open", lines
    assert accepted > 0
    assert chk._opens_with_a_paragraph(["Semantics do not change."])


# ── the opening paragraph is read up to its blank line (fourth reading of 2026-11-01, sol-pro, two P1, and the owner's
# answer A on card OA-37bc271387) ────────────────────────────────────────────────────────────────────────────────────
#
# A setext heading takes its text from every line of a paragraph, and a no-break space is no blank in CommonMark. The
# check looked at one line after the opening, and stripped Unicode blanks before `<!--`.


def test_RED_a_setext_heading_over_two_lines_opens_nothing():
    """markdown-it renders `Text`, `Text`, `---` as one heading. The check looked only at the line after the first."""
    for underline in ("---", "==="):
        assert not chk._opens_with_a_paragraph(["Semantics do", "not change.", underline]), underline
    assert not chk._opens_with_a_paragraph(["Semantics do not change.", " ", "---"]), "a no-break space is no blank"


def test_RED_a_no_break_space_before_a_comment_start_hides_no_duplicate(tmp_path):
    """` <!--` is paragraph text, no comment start: a second version heading after it is a duplicate."""
    probs = chk.check(_repo(tmp_path, f"# Changelog\n\n## [{VERSION}]\n\nSemantics do not change.\n\n <!--\n\n"
                                      f"## [{VERSION}]\n\n### Added\n\n- x\n"))
    assert len([p for p in probs if "CHANGELOG.md" in p and "twice" in p]) == 1, probs


def test_RED_a_line_that_runs_on_into_a_setext_underline_is_passed_over_nowhere():
    """The extended corpus of the answer A: `[x]: (` matched the link reference pattern and `---` the thematic break,
    while markdown-it renders both lines as one setext heading. A link reference or a break is passed over only where a
    blank line ends it."""
    assert not chk._opens_with_a_paragraph(["[x]: (", "---", "", "Semantics do not change."])


def test_RED_a_link_reference_right_above_the_opening_is_a_finding_the_price_of_the_rule():
    """The price of the rule above, named on the card: a valid link reference directly above the opening renders
    nothing, and is a finding all the same; its fix is a blank line between them."""
    assert not chk._opens_with_a_paragraph(["[x]: /target", "Semantics do not change."])
    assert chk._opens_with_a_paragraph(["[x]: /target", "", "Semantics do not change."])


def test_RED_a_unicode_line_separator_ends_no_line_of_the_changelog(tmp_path):
    """CommonMark ends a line at LF, CR or CRLF only; str.splitlines also splits at U+2028, U+2029 and U+0085, the class
    the pin case of the plugin met in its sixth reading. `Text<U+2028>---` is one line of a paragraph, no setext
    heading."""
    for sep in (" ", " ", "\u0085"):
        t = tmp_path / f"sep_{ord(sep):04x}"
        t.mkdir()
        probs = chk.check(_repo(t, f"# Changelog\n\n## [{VERSION}] - 2026-10-31\n\nSemantics do not change.{sep}---\n\n"
                                   "### Fixed\n\n- x\n"))
        assert probs == [], (repr(sep), probs)


#: The extended corpus of the answer A: a second line after the start, no-break and ideographic spaces, and a start
#: that a following line continues.
_STARTS_2 = _STARTS + (" x", " <!--", "　Semantics do not change.", "Semantics do")
_NEXT_2 = _NEXT + (" ", "not change.", " <!--")
_THEN = ("", "---", "===", "Text follows.", " ")


def test_the_differential_case_holds_over_two_following_lines_and_unicode_blanks():
    """The differential case over the extended corpus: every start the check accepts, followed by two lines, renders in
    markdown-it as a paragraph after what the check passes over."""
    markdown_it = pytest.importorskip("markdown_it")
    md = markdown_it.MarkdownIt("commonmark").enable("table")
    accepted, wrong = 0, []
    for before, prefix, start, after, then in itertools.product(_PASSED_OVER, _PREFIXES, _STARTS_2, _NEXT_2, _THEN):
        lines = ([before, ""] if before else []) + [prefix + start, after, then]
        if chk._opens_with_a_paragraph(lines):
            accepted += 1
            if _first_block(md.parse("\n".join(lines) + "\n")) != "paragraph_open":
                wrong.append(lines)
    assert wrong == [], (len(wrong), wrong[:5])
    assert accepted > 0
