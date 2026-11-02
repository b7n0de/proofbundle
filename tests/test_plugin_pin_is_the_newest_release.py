"""The plugin pins the newest release of proofbundle that this tree records as released (slice pin640).

The gate and the plugin's MCP server verify through `uv run --script`, which installs the one version a script header
pins: the header of server/proofbundle_mcp.py and, in hooks/proofbundle_gate.py, PINNED_PROOFBUNDLE (the verifier the
done statement names) and the headers of the two signing tools the gate writes (_SIGN_TOOL, _KEY_TOOL). DECISIONS.md,
D11 calls that version the plugin's only pin. Read on 2026-10-31 at claude/landung-guard-g3 14bc2fd3: all four named
6.3.0, while CHANGELOG.md records 6.4.0 as released on 2026-10-27, the tag v6.4.0 stands and PyPI serves the package.

The property held here: the four pins name one version; it is the newest version CHANGELOG.md records as released, the
first section after [Unreleased]; and every `proofbundle==X.Y.Z` the plugin's own files write names that version. A
later release turns this test red until the pin follows it, so the pin cannot fall behind in silence. A changelog whose
sections after [Unreleased] are not releases with calendar dates, newest first, or whose newest release is a
pre-release or lower than a stable release below it, stops the case rather than choose a pin.
"""
from __future__ import annotations

import ast
import datetime
import pathlib
import re
import sys

import pytest
from packaging.version import InvalidVersion, Version

ROOT = pathlib.Path(__file__).resolve().parent.parent
PLUGIN = ROOT / "plugins" / "proofbundle"
SERVER = PLUGIN / "server" / "proofbundle_mcp.py"
GATE = PLUGIN / "hooks" / "proofbundle_gate.py"
CHANGELOG = ROOT / "CHANGELOG.md"

_HEADER_PIN = re.compile(r'^# dependencies = \["proofbundle==(\d+\.\d+\.\d+)"\]$', re.M)
_HEADING = re.compile(r" {0,3}##(?:[ \t]+(.*)|[ \t]*)")
_LINE_END = re.compile(r"\r\n|\r|\n")
_CLOSING = re.compile(r"(?:^|[ \t]+)#+[ \t]*$")
_FENCE = re.compile(r" {0,3}(`{3,}|~{3,})")
_SECTION = re.compile(r"\[([^\]]+)\](.*)")
_DATED = re.compile(r" - (\d{4})-(\d{2})-(\d{2})(?:\s+\(.*\))?\s*")
_ANY_PIN = re.compile(r"proofbundle==(\d+\.\d+\.\d+)")
#: The starts of the HTML blocks of CommonMark 0.31.2, types 1 to 7 (a lone complete tag is type 7). Lines inside such a
#: block are no headings, and the reader does not model where a block ends, so a changelog that opens one stops the case.
_HTML_BLOCK = re.compile(
    r" {0,3}(?:<(?:script|pre|style|textarea)(?:[\s>]|$)|<!--|<\?|<![A-Za-z]|<!\[CDATA\["
    r"|</?(?:address|article|aside|base|basefont|blockquote|body|caption|center|col|colgroup|dd|details|dialog|dir"
    r"|div|dl|dt|fieldset|figcaption|figure|footer|form|frame|frameset|h[1-6]|head|header|hr|html|iframe|legend|li"
    r"|link|main|menu|menuitem|nav|noframes|ol|optgroup|option|p|param|search|section|summary|table|tbody|td|tfoot"
    r"|th|thead|title|tr|track|ul)(?:[\s/>]|$)"
    r"|</?[A-Za-z][A-Za-z0-9-]*(?:\s+[^<>]*)?/?>[ \t]*$)", re.IGNORECASE)
#: A line of = or - after a line of text makes that text a setext heading, which the reader does not read.
_SETEXT_UNDERLINE = re.compile(r" {0,3}(?:=+|-+)[ \t]*")


def _headings(text: str) -> list[str]:
    """The level-two headings outside fenced code, as CommonMark 0.31.2 reads the two forms involved. A fence opens with
    three or more backticks or tildes after at most three spaces; a backtick fence whose info string holds a backtick is
    none. It closes with a line of the same character, at least as long, followed by spaces and tabs only; an unclosed
    fence runs to the end of the file. A line ends at a line feed, a carriage return or both; a heading's ## is
    followed by a space or a tab, and a closing sequence of # after a space or a tab is no part of it. This is no
    Markdown reader beyond that: CHANGELOG.md writes its sections as ATX headings `## [...]` at the start of a line. A
    block the reader does not model and that can hide a heading or make one stops the case: an HTML block or a setext
    heading (a pre-run of the reading of the pin on main, Codex, P2), and an indented heading, which a list item before
    it may hold (a generator against markdown-it); indented code, block quotes and list items are not read."""
    found, fence, previous = [], None, ""
    for line in _LINE_END.split(text):
        opened = _FENCE.match(line)
        if fence is not None:
            if opened and opened.group(1)[0] == fence[0] and len(opened.group(1)) >= len(fence) \
                    and not line[opened.end():].strip(" \t"):
                fence = None
            previous = ""
            continue
        if opened and not (opened.group(1)[0] == "`" and "`" in line[opened.end():]):
            fence = opened.group(1)
            previous = ""
            continue
        assert not _HTML_BLOCK.match(line), f"the changelog opens an HTML block, which the pin case does not read: {line!r}"
        heading = _HEADING.fullmatch(line)
        # An indented heading may belong to a list item before it, where CommonMark nests it; the reader models no list.
        assert not (heading and line[:1] == " "), \
            f"the changelog indents a heading, which may sit in a list item the pin case does not read: {line!r}"
        assert not (_SETEXT_UNDERLINE.fullmatch(line) and previous.strip(" \t") and not _HEADING.fullmatch(previous)), \
            f"the changelog makes a setext heading of {previous!r}, which the pin case does not read"
        if heading:
            found.append(_CLOSING.sub("", heading.group(1) or "").strip(" \t"))
        previous = line
    return found


def _newest_release() -> str:
    """The first section after [Unreleased]: a stable X.Y.Z with a real calendar date and no higher stable release
    below it. Every level-two heading outside fenced code is a section in brackets, and every section after
    [Unreleased] is a release with a version and a real date (a note in brackets may follow it), newest first: the
    dates do not rise downwards. The history may interleave lines (1.9.2 came out between 2.0.0b2 and 2.0.0b1), so the
    order of the versions alone is not read. A changelog of another structure stops the case rather than choose a
    pin."""
    sections = []
    for heading in _headings(CHANGELOG.read_text(encoding="utf-8")):
        bracketed = _SECTION.fullmatch(heading)
        assert bracketed, f"the level-two section '{heading}' is no section of a version in brackets"
        sections.append(bracketed.groups())
    assert sections and sections[0][0] == "Unreleased", f"CHANGELOG.md does not open with [Unreleased]: {sections[:2]}"
    assert len(sections) > 1, "CHANGELOG.md records no released version"
    dates, versions = [], []
    for name, tail in sections[1:]:
        dated = _DATED.fullmatch(tail)
        assert dated, f"the release {name} names no date"
        try:
            dates.append(datetime.date(*map(int, dated.groups())))
        except ValueError as exc:
            raise AssertionError(f"the release {name} names no calendar date: {tail.strip()}") from exc
        try:
            versions.append(Version(name))
        except InvalidVersion as exc:
            raise AssertionError(f"the section {name} names no version") from exc
    assert all(a >= b for a, b in zip(dates, dates[1:])), f"the releases are not in date order, newest first: {dates}"
    newest = sections[1][0]
    assert re.fullmatch(r"\d+\.\d+\.\d+", newest), f"the newest release {newest} is no stable X.Y.Z"
    higher = [str(v) for v in versions[1:] if not v.is_prerelease and v > versions[0]]
    assert not higher, f"a stable release below {newest} is newer by version, so the order is broken: {higher}"
    return newest


def _assigned_strings(source: str, names: tuple[str, ...]) -> dict[str, list[str | None]]:
    """Every assignment to one of `names` anywhere in the module, read from its syntax tree, with its value where the
    value is a string literal and None otherwise; a pin is read from what the module assigns, not from one spelling."""
    found: dict[str, list[str | None]] = {name: [] for name in names}
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            targets, value = [node.target], None if isinstance(node, ast.AugAssign) else node.value
        else:
            continue
        literal = value.value if isinstance(value, ast.Constant) and isinstance(value.value, str) else None
        for target in targets:
            for leaf in ast.walk(target):
                if isinstance(leaf, ast.Name) and leaf.id in found:
                    found[leaf.id].append(literal if target is leaf else None)
    return found


def _pins() -> dict[str, list[str]]:
    """The four pins. The gate assigns each of PINNED_PROOFBUNDLE, _SIGN_TOOL and _KEY_TOOL exactly once, to a string
    literal (a pre-run of the reading of the pin on main, Codex, P2: a later assignment in other quotes went unseen)."""
    gate = _assigned_strings(GATE.read_text(encoding="utf-8"), ("PINNED_PROOFBUNDLE", "_SIGN_TOOL", "_KEY_TOOL"))
    for name, values in gate.items():
        assert len(values) == 1 and values[0] is not None, \
            f"the gate assigns {name} {len(values)} time(s), and the pin is one string literal assigned once: {values}"
    return {"server header": _HEADER_PIN.findall(SERVER.read_text(encoding="utf-8")),
            "gate PINNED_PROOFBUNDLE": gate["PINNED_PROOFBUNDLE"],
            "gate tool headers": _HEADER_PIN.findall(gate["_SIGN_TOOL"][0]) + _HEADER_PIN.findall(gate["_KEY_TOOL"][0])}


_HEAD = "# Changelog\n\n## [Unreleased]\n\n"


def _changelog(tmp_path: pathlib.Path, monkeypatch, text: str) -> None:
    path = tmp_path / "CHANGELOG.md"
    path.write_text(text, encoding="utf-8")
    monkeypatch.setattr(sys.modules[__name__], "CHANGELOG", path)


@pytest.mark.parametrize("text, words", [
    (_HEAD + "## [9.9.9] - 2026-02-30\n\n## [6.4.0] - 2026-10-27\n", "date"),
    ("# Changelog\n\n## [6.4.0] - 2026-10-27\n", "Unreleased"),
    (_HEAD + "## [7.0.0b1] - 2026-11-02\n\n## [6.4.0] - 2026-10-27\n", "stable"),
    (_HEAD + "## [6.3.0] - 2026-10-14\n\n## [6.4.0] - 2026-10-27\n", "order"),
    (_HEAD + "## [6.4.0]\n\n## [6.3.1] - 2026-10-21\n", "date"),
    (_HEAD + "## [6.3.2] - 2026-10-28\n\n## [6.4.0] - 2026-10-27\n", "newer by version"),
    (_HEAD + "## 7.0.0 - 2026-11-02\n\n## [6.4.0] - 2026-10-27\n", "section"),
], ids=["an impossible date", "no Unreleased section", "a pre-release first", "releases out of order",
        "a release without a date", "an older line on top", "a section without brackets"])
def test_a_changelog_whose_release_structure_does_not_hold_stops_the_case(tmp_path, monkeypatch, text, words):
    """First reading of the bundle that lands this case (sol-pro, P2): the first match of a pattern anywhere in the file
    stood for the newest release. A changelog whose sections after [Unreleased] are not releases with real dates in
    descending order now stops the case instead of choosing a pin."""
    _changelog(tmp_path, monkeypatch, text)
    with pytest.raises(AssertionError, match=words):
        _newest_release()


def test_control_a_well_formed_changelog_names_its_newest_stable_release(tmp_path, monkeypatch):
    """The history may hold a release with a note after its date, pre-releases below the newest release, and lines
    that interleave (1.9.2 came out between 2.0.0b2 and 2.0.0b1, as CHANGELOG.md records)."""
    _changelog(tmp_path, monkeypatch, _HEAD + "## [6.4.0] - 2026-10-27\n\n## [6.3.1] - 2026-10-21 (patch)\n\n"
                                              "## [2.0.0b2] - 2026-07-05  (BETA / pre-release)\n\n"
                                              "## [1.9.2] - 2026-07-05\n\n## [2.0.0b1] - 2026-07-02  (BETA)\n")
    assert _newest_release() == "6.4.0"


def test_control_a_heading_like_line_in_a_fence_is_no_section(tmp_path, monkeypatch):
    """Third reading of the bundle that lands this case (sol-pro, P2): a release text may show a heading in fenced code;
    that line is no level-two heading, and a real heading without brackets still stops the case (above)."""
    _changelog(tmp_path, monkeypatch, _HEAD + "## [6.4.0] - 2026-10-27\n\n```markdown\n## example\n```\n\n"
                                              "~~~~\n## another\n~~~~\n\n## [6.3.1] - 2026-10-21\n")
    assert _newest_release() == "6.4.0"


def test_control_a_fence_closes_only_with_spaces_or_tabs_after_its_characters(tmp_path, monkeypatch):
    """Fourth reading (sol-pro, P2): a no-break space after the backticks is no blank of a closing fence, so the fence
    stays open and the heading-like line after it is still code."""
    _changelog(tmp_path, monkeypatch, _HEAD + "## [6.4.0] - 2026-10-27\n\n```markdown\n```\u00a0\n## example\n```\n\n"
                                              "## [6.3.1] - 2026-10-21\n")
    assert _newest_release() == "6.4.0"


def test_a_backtick_in_the_info_string_opens_no_fence_and_hides_no_release(tmp_path, monkeypatch):
    """Fourth reading (sol-pro, P2): a backtick line whose info string holds a backtick opens no fence, so a release
    heading after it is read; here a higher stable release below the first, which stops the case."""
    _changelog(tmp_path, monkeypatch, _HEAD + "## [6.4.0] - 2026-10-27\n\n```markdown`sample\n\n"
                                              "## [9.0.0] - 2026-10-20\n")
    with pytest.raises(AssertionError, match="newer by version"):
        _newest_release()


def test_control_a_unicode_line_separator_is_no_line_ending(tmp_path, monkeypatch):
    """Fifth reading (sol-pro, P2): CommonMark ends a line at a line feed, a carriage return or both, not at U+2028,
    U+2029 or U+0085; text after such a character stays on the line, so a fence it follows is not closed."""
    for separator in ("\u2028", "\u2029", "\u0085"):
        _changelog(tmp_path, monkeypatch, _HEAD + "## [6.4.0] - 2026-10-27\n\n```markdown\n```" + separator +
                   "## example\n```\n\n## [6.3.1] - 2026-10-21\n")
        assert _newest_release() == "6.4.0", repr(separator)


def test_a_tab_after_the_opening_marks_is_a_heading_and_is_read(tmp_path, monkeypatch):
    """The same class, found in the sweep of the helper: CommonMark takes a tab after the opening ## of an ATX heading
    as a space takes it, so a release heading written so is read; here a higher stable release below the first."""
    _changelog(tmp_path, monkeypatch, _HEAD + "## [6.4.0] - 2026-10-27\n\n##\t[9.0.0] - 2026-10-20\n")
    with pytest.raises(AssertionError, match="newer by version"):
        _newest_release()


def test_control_a_closing_sequence_of_hashes_is_no_part_of_the_heading(tmp_path, monkeypatch):
    """Found in the comparison with markdown-it: an ATX heading may end with a closing sequence of #, after a space or a
    tab and followed by blanks only; CommonMark drops it, so `## [6.4.0] - 2026-10-27 ##` is the release 6.4.0."""
    _changelog(tmp_path, monkeypatch, _HEAD + "## [6.4.0] - 2026-10-27 ##   \n\n## [6.3.1] - 2026-10-21\t#\n")
    assert _newest_release() == "6.4.0"


@pytest.mark.parametrize("text, words", [
    (_HEAD + "<!--\n## [7.0.0] - 2026-11-02\n-->\n## [6.4.0] - 2026-10-27\n", "HTML"),
    (_HEAD + "<div>\n## [7.0.0] - 2026-11-02\n</div>\n\n## [6.4.0] - 2026-10-27\n", "HTML"),
    (_HEAD + "\n<span>\n## [7.0.0] - 2026-11-02\n\n## [6.4.0] - 2026-10-27\n", "HTML"),
    (_HEAD + "[7.0.0] - 2026-11-02\n---\n\n## [6.4.0] - 2026-10-27\n", "setext"),
    (_HEAD + "## [6.4.0] - 2026-10-27\n\n[7.0.0] - 2026-11-02\n===\n", "setext"),
    (_HEAD + "- item\n   ## [7.0.0] - 2026-11-02\n\n## [6.4.0] - 2026-10-27\n", "indent"),
], ids=["a comment", "an HTML block of a block tag", "a lone tag after a blank line", "a setext heading with dashes",
        "a setext heading with equals", "an indented heading in a list item"])
def test_a_block_the_reader_does_not_read_stops_the_case(tmp_path, monkeypatch, text, words):
    """A pre-run of the reading of this pin on main (Codex, P2): a heading line inside an HTML comment was read as a
    release, and a setext heading that renders as a level-two heading was not read at all. CommonMark hides lines in an
    HTML block and makes a line underlined by = or - a heading. The reader models neither, so a changelog that holds
    one stops the case rather than choose a pin from a structure it does not read."""
    _changelog(tmp_path, monkeypatch, text)
    with pytest.raises(AssertionError, match=words):
        _newest_release()


def test_control_a_tag_inside_a_line_of_text_is_no_html_block(tmp_path, monkeypatch):
    """CHANGELOG.md carries such a line (an option `<card>` named at the start of a continued sentence): a tag followed by
    text on its line starts no HTML block, and a line of dashes after a blank line is a thematic break, no heading."""
    _changelog(tmp_path, monkeypatch, _HEAD + "## [6.4.0] - 2026-10-27\n\n- `decision verify`\n  <card> [--check R]` "
                                              "mirrors `prereg`.\n\n---\n\n## [6.3.1] - 2026-10-21\n")
    assert _newest_release() == "6.4.0"


def test_a_second_assignment_of_a_pin_is_found(tmp_path, monkeypatch):
    """The same pre-run (Codex, P2): `_pins` read each pin by one spelling, so a later assignment of PINNED_PROOFBUNDLE
    in single quotes, which wins at import, left the three checks green. The pins are read from the gate's syntax
    tree, and a name assigned more than once, or not to a string, fails the agreement."""
    gate = tmp_path / "proofbundle_gate.py"
    gate.write_text(GATE.read_text(encoding="utf-8") + "\nPINNED_PROOFBUNDLE = '6.3.0'\n", encoding="utf-8")
    monkeypatch.setattr(sys.modules[__name__], "GATE", gate)
    with pytest.raises(AssertionError):
        test_the_four_pins_name_one_version()


def test_the_four_pins_name_one_version():
    pins = _pins()
    assert [len(pins["server header"]), len(pins["gate PINNED_PROOFBUNDLE"]), len(pins["gate tool headers"])] == [
        1, 1, 2], pins
    assert len({version for found in pins.values() for version in found}) == 1, pins


def test_the_pin_is_the_newest_release_the_changelog_records():
    newest = _newest_release()
    pins = _pins()
    assert {version for found in pins.values() for version in found} == {newest}, (newest, pins)


def test_every_pin_the_plugin_writes_names_that_version():
    newest = _newest_release()
    stale = []
    for path in sorted(PLUGIN.rglob("*")):
        if not path.is_file() or path.suffix not in (".py", ".md", ".json", ".sh", ".yaml", ".toml"):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        stale += [f"{path.relative_to(ROOT)}: proofbundle=={v}" for v in _ANY_PIN.findall(text) if v != newest]
    assert not stale, (newest, stale)
