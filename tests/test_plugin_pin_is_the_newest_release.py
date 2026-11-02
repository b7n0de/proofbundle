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
import importlib.util
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

#: The inline script metadata block of PEP 723, by its reference expression; `uv run --script` installs what it names.
_SCRIPT_BLOCK = re.compile(r"(?m)^# /// (?P<type>[a-zA-Z0-9-]+)$\s(?P<content>(^#(| .*)$\s)+)^# ///$")
_REQUIRES_PYTHON = re.compile(r'requires-python = "[^"\\]*"')
_DEPENDENCY_PIN = re.compile(r'dependencies = \["proofbundle==(\d+\.\d+\.\d+)"\]')
_HEADING = re.compile(r" {0,3}##(?:[ \t]+(.*)|[ \t]*)")
_LINE_END = re.compile(r"\r\n|\r|\n")
_CLOSING = re.compile(r"(?:^|[ \t]+)#+[ \t]*$")
_FENCE = re.compile(r" {0,3}(`{3,}|~{3,})")
_SECTION = re.compile(r"\[([^\]]+)\](.*)")
_DATED = re.compile(r" - (\d{4})-(\d{2})-(\d{2})(?:\s+\(.*\))?\s*")
#: A pin of proofbundle as a requirement may write it: the name in any case, extras, blanks around == or ===, and a
#: version with what PEP 440 may append (a third pre-run of the reading of the pin on main, Codex, P2).
_ANY_PIN = re.compile(r"proofbundle(?:\s*\[[^\]]*\])?\s*===?\s*(\d+(?:\.\d+)*(?:[-_.+!]?[A-Za-z0-9]+)*)", re.IGNORECASE)
#: The starts of the HTML blocks of CommonMark 0.31.2, types 1 to 6, which may interrupt a paragraph. Lines inside such a
#: block are no headings, and the reader does not model where a block ends, so a changelog that opens one stops the case.
_HTML_BLOCK = re.compile(
    r" {0,3}(?:<(?:script|pre|style|textarea)(?:[\s>]|$)|<!--|<\?|<![A-Za-z]|<!\[CDATA\["
    r"|</?(?:address|article|aside|base|basefont|blockquote|body|caption|center|col|colgroup|dd|details|dialog|dir"
    r"|div|dl|dt|fieldset|figcaption|figure|footer|form|frame|frameset|h[1-6]|head|header|hr|html|iframe|legend|li"
    r"|link|main|menu|menuitem|nav|noframes|ol|optgroup|option|p|param|search|section|summary|table|tbody|td|tfoot"
    r"|th|thead|title|tr|track|ul)(?:[\s/>]|$))", re.IGNORECASE)
#: A complete open or closing tag in the raw HTML of CommonMark 0.31.2 (section 6.6), in the expression markdown-it 4.2.0
#: writes in markdown_it/common/html_re.py: an attribute's value may be unquoted or quoted, and a quoted one may hold `>`,
#: while an `=` without a value makes no tag (a sixth pre-run of the reading of the pin on main, Codex, P2).
_ATTRIBUTE = r"""(?:\s+[a-zA-Z_:][a-zA-Z0-9:._-]*(?:\s*=\s*(?:[^"'=<>`\x00-\x20]+|'[^']*'|"[^"]*"))?)"""
#: Alone on its line such a tag starts an HTML block of type 7, which cannot interrupt a paragraph (a fifth pre-run, Codex,
#: P2). Outside a paragraph any tag name stops the case: the specification leaves a closing script, pre, style or
#: textarea tag out of type 7, and markdown-it does not.
_HTML_TYPE7 = re.compile(r" {0,3}(?:<[A-Za-z][A-Za-z0-9-]*" + _ATTRIBUTE + r"*\s*/?>|</[A-Za-z][A-Za-z0-9-]*\s*>)\s*")
#: A line of = or - after a line of text makes that text a setext heading, which the reader does not read.
_SETEXT_UNDERLINE = re.compile(r" {0,3}(?:=+|-+)[ \t]*")
#: A line that interrupts a paragraph or ends it: a blank line, an ATX heading of any level, a thematic break, a block
#: quote, a bullet item with content, or an ordered item numbered 1 with content, in up to nine digits with leading zeros
#: (an item of another number, or an empty one, cannot interrupt a paragraph; a seventh pre-run of the reading of the
#: pin on main, Codex, P2). Fences and HTML blocks of types 1 to 6 interrupt one too; the reader handles them before it
#: asks.
_NO_PARAGRAPH = re.compile(r"[ \t]*| {0,3}(?:#{1,6}(?:[ \t].*)?|(?:\*[ \t]*){3,}|(?:-[ \t]*){3,}|(?:_[ \t]*){3,}"
                           r"|>.*|[-+*][ \t]+\S.*|0{0,8}1[.)][ \t]+\S.*)")
#: A blank line, an ATX heading or a thematic break: none of them holds a paragraph.
_BLANK_HEADING_OR_BREAK = re.compile(r"[ \t]*| {0,3}(?:#{1,6}(?:[ \t].*)?|(?:\*[ \t]*){3,}|(?:-[ \t]*){3,}"
                                     r"|(?:_[ \t]*){3,})")
#: A line indented by four columns or more, which outside a paragraph is indented code: it ends none and starts none.
_INDENTED_CODE = re.compile(r" {0,3}\t| {4}")
#: The marker of a block quote or of a list item, empty or of any number, with the one space or tab after it; the rest of
#: the line is the first line of the quote or the item.
_CONTAINER = re.compile(r" {0,3}(?:>[ \t]?|(?:[-+*]|\d{1,9}[.)])(?:[ \t]|$))")
#: A line that opens with a bracket may be a link reference definition, which is no paragraph, or the start of one.
_LINK_LABEL = re.compile(r" {0,3}\[")


def _fence_opened(line: str) -> re.Match | None:
    """The fence a line opens: three or more backticks or tildes after at most three spaces, where the info string of a
    backtick fence holds no backtick. Both the reader and `_starts` ask here, so the two cannot differ (a generator
    against markdown-it found 188 differences where `_starts` took `` ``` x`y `` for a fence)."""
    opened = _FENCE.match(line)
    return opened if opened and not (opened.group(1)[0] == "`" and "`" in line[opened.end():]) else None


def _starts(line: str) -> str:
    """What `line` starts where no paragraph runs: "none" for a blank line, a heading, a break, indented code, a fence or
    an HTML block; for a block quote or a list item "container" when its first line is paragraph text, a paragraph a
    later line may continue lazily, else what that first line starts; "open" for a line that may be a link reference
    definition; and "paragraph" for paragraph text."""
    if _BLANK_HEADING_OR_BREAK.fullmatch(line) or _INDENTED_CODE.match(line):
        return "none"
    if _fence_opened(line) or _HTML_BLOCK.match(line) or _HTML_TYPE7.fullmatch(line):
        return "none"
    marker = _CONTAINER.match(line)
    if marker:
        inner = _starts(line[marker.end():])
        return "container" if inner == "paragraph" else inner
    return "open" if _LINK_LABEL.match(line) else "paragraph"


def _after(state: str, line: str) -> str:
    """Whether a paragraph runs after `line`, as far as the line and the state before it tell: "paragraph" at the top
    level, "container" inside a block quote or a list item, "none", or "open" where the reader cannot tell. A paragraph
    continues, inside a container lazily, until a blank line or a block that interrupts it; "open" stays open until
    then; after that, or where none runs, the line starts what `_starts` says."""
    if state != "none" and not _NO_PARAGRAPH.fullmatch(line):
        return state
    return _starts(line)


def _headings(text: str) -> list[str]:
    """The level-two headings outside fenced code, as CommonMark 0.31.2 reads the two forms involved. A fence opens with
    three or more backticks or tildes after at most three spaces; a backtick fence whose info string holds a backtick is
    none. It closes with a line of the same character, at least as long, followed by spaces and tabs only; an unclosed
    fence runs to the end of the file. A line ends at a line feed, a carriage return or both; a heading's ## is
    followed by a space or a tab, and a closing sequence of # after a space or a tab is no part of it. This is no
    Markdown reader beyond that: CHANGELOG.md writes its sections as ATX headings `## [...]` at the start of a line. A
    block the reader does not model and that can hide a heading or make one stops the case: an HTML block or a setext
    heading (a pre-run of the reading of the pin on main, Codex, P2), and an indented heading or fence, which a list
    item before it may hold (a generator against markdown-it, a second pre-run); indented code, block quotes and list
    items are not read. Whether a paragraph runs, at the top level or lazily inside a block quote or a list item,
    decides two of these: an underline makes a setext heading only after one at the top level, and a lone tag starts an
    HTML block only outside one; where the reader cannot tell, both stop the case."""
    found, fence, previous, state = [], None, "", "none"
    for line in _LINE_END.split(text):
        opened = _FENCE.match(line)
        if fence is not None:
            if opened and opened.group(1)[0] == fence[0] and len(opened.group(1)) >= len(fence) \
                    and not line[opened.end():].strip(" \t"):
                fence = None
            continue
        if _fence_opened(line):
            # An indented fence may belong to a list item before it, where it hides no heading after the item.
            assert line[:1] != " ", \
                f"the changelog indents a fence, which may sit in a list item the pin case does not read: {line!r}"
            fence = opened.group(1)
            state = "none"
            continue
        assert not (_HTML_BLOCK.match(line) or (_HTML_TYPE7.fullmatch(line) and state in ("none", "open"))), \
            f"the changelog opens an HTML block, which the pin case does not read: {line!r}"
        heading = _HEADING.fullmatch(line)
        # An indented heading may belong to a list item before it, where CommonMark nests it; the reader models no list.
        assert not (heading and line[:1] == " "), \
            f"the changelog indents a heading, which may sit in a list item the pin case does not read: {line!r}"
        assert not (_SETEXT_UNDERLINE.fullmatch(line) and state in ("paragraph", "open")), \
            f"the changelog makes a setext heading of {previous!r}, which the pin case does not read"
        if heading:
            found.append(_CLOSING.sub("", heading.group(1) or "").strip(" \t"))
        state = _after(state, line)
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
    """Every binding of one of `names` anywhere in the module, read from its syntax tree: a name stored or deleted (by
    an assignment of any kind, an assignment expression, a for, with or comprehension target, del), an import alias, a
    function or class name, and an except or match capture. A binding carries its value where it is a module-level
    assignment of a string literal to the name alone, and None otherwise; a pin is read from what the module binds, not
    from one spelling (two pre-runs of the reading of the pin on main, Codex, P2)."""
    tree = ast.parse(source)
    literal = {id(node.targets[0]): node.value.value for node in tree.body
               if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
               and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)}
    found: dict[str, list[str | None]] = {name: [] for name in names}
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            bound = (node.id, literal.get(id(node)))
        elif isinstance(node, ast.alias):
            bound = ((node.asname or node.name).split(".")[0], None)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound = (node.name, None)
        elif isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) and node.name:
            bound = (node.name, None)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            bound = (node.rest, None)
        else:
            continue
        if bound[0] in found:
            found[bound[0]].append(bound[1])
    return found


def _script_pin(text: str, where: str) -> str:
    """The proofbundle pin of the one inline script metadata block (PEP 723) of a script, the block `uv run --script`
    reads; a dependency line elsewhere in the script is a comment and pins nothing. The block holds requires-python and
    one dependency line that pins proofbundle alone, and another form stops the case rather than read a pin from it (a
    third pre-run of the reading of the pin on main, Codex, P2: the headers of the two tools were counted together, so a
    dependency line after the code of one hid a stale pin in the block of the other)."""
    blocks = [block for block in _SCRIPT_BLOCK.finditer(text) if block.group("type") == "script"]
    opened = re.findall(r"(?m)^# /// script$", text)
    assert len(blocks) == len(opened) == 1, f"{where} holds {len(opened)} script metadata block(s), and uv reads one"
    lines = [line[2:] if line.startswith("# ") else line[1:] for line in blocks[0].group("content").splitlines()]
    pins = [_DEPENDENCY_PIN.fullmatch(line) for line in lines if line.strip() and not _REQUIRES_PYTHON.fullmatch(line)]
    assert len(pins) == 1 and pins[0], \
        f"the metadata block of {where} holds more than requires-python and one pin of proofbundle alone: {lines}"
    return pins[0].group(1)


def _imported_gate():
    """The gate as its host imports it, under a name of its own; the tests of the gate load it the same way."""
    spec = importlib.util.spec_from_file_location("_pin_case_gate", GATE)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        del sys.modules[spec.name]
    return module


def _pins() -> dict[str, list[str]]:
    """The four pins. The gate assigns each of PINNED_PROOFBUNDLE, _SIGN_TOOL and _KEY_TOOL exactly once, to a string
    literal (a pre-run of the reading of the pin on main, Codex, P2: a later assignment in other quotes went unseen),
    and each name holds that literal once the gate is imported (a fourth pre-run: a write through globals() binds no
    name in the syntax tree). Each script's pin is read from its own metadata block."""
    gate = _assigned_strings(GATE.read_text(encoding="utf-8"), ("PINNED_PROOFBUNDLE", "_SIGN_TOOL", "_KEY_TOOL"))
    for name, values in gate.items():
        assert len(values) == 1 and values[0] is not None, \
            f"the gate assigns {name} {len(values)} time(s), and the pin is one string literal assigned once: {values}"
    imported = _imported_gate()
    for name, values in gate.items():
        assert getattr(imported, name, None) == values[0], \
            f"the gate holds another {name} once imported than the literal it assigns: {getattr(imported, name, None)!r}"
    return {"server header": [_script_pin(SERVER.read_text(encoding="utf-8"), "server/proofbundle_mcp.py")],
            "gate PINNED_PROOFBUNDLE": gate["PINNED_PROOFBUNDLE"],
            "gate tool headers": [_script_pin(gate[name][0], name) for name in ("_SIGN_TOOL", "_KEY_TOOL")]}


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
    (_HEAD + "## [6.4.0] - 2026-10-27\n\n- x\n  ```\n## [7.0.0] - 2026-10-26\n", "fence"),
    (_HEAD + "## [6.4.0] - 2026-10-27\n\n[x]: /u\n<a>\n## [7.0.0] - 2026-11-02\n", "HTML"),
    (_HEAD + "## [6.4.0] - 2026-10-27\n\n</script>\n## [7.0.0] - 2026-11-02\n", "HTML"),
    (_HEAD + "## [6.4.0] - 2026-10-27\n\n[7.0.0] - 2026-11-02\n2. x\n---\n", "setext"),
    (_HEAD + "<a x=\">\">\n## [9.0.0] - 2026-11-02\n\n## [6.4.0] - 2026-10-27\n", "HTML"),
    (_HEAD + "## [6.4.0] - 2026-10-27\n\n``` x`y\n---\n", "setext"),
], ids=["a comment", "an HTML block of a block tag", "a lone tag after a blank line", "a setext heading with dashes",
        "a setext heading with equals", "an indented heading in a list item", "an indented fence in a list item",
        "a lone tag after a link reference definition", "a lone closing script tag",
        "an underline after an ordered item that continues a paragraph", "a lone tag with a quoted > in a value",
        "an underline after a backtick line that opens no fence"])
def test_a_block_the_reader_does_not_read_stops_the_case(tmp_path, monkeypatch, text, words):
    """A pre-run of the reading of this pin on main (Codex, P2): a heading line inside an HTML comment was read as a
    release, and a setext heading that renders as a level-two heading was not read at all. CommonMark hides lines in an
    HTML block and makes a line underlined by = or - a heading. The reader models neither, so a changelog that holds
    one stops the case rather than choose a pin from a structure it does not read."""
    _changelog(tmp_path, monkeypatch, text)
    with pytest.raises(AssertionError, match=words):
        _newest_release()


@pytest.mark.parametrize("text", [
    "## [Unreleased]\n## [6.4.0] - 2026-10-27\nx\n<a>\n",
    "## [Unreleased]\n\n## [6.4.0] - 2026-10-27\n\nsee\n</a>\n<br/>\n\n## [6.3.1] - 2026-10-21\n",
], ids=["an opening tag", "a closing tag and an empty element"])
def test_control_a_lone_tag_after_paragraph_text_continues_the_paragraph(tmp_path, monkeypatch, text):
    """A fifth pre-run of the reading of the pin on main (Codex, P2): a complete tag alone on its line starts an HTML
    block of type 7 only where no paragraph runs, since that type cannot interrupt a paragraph (CommonMark 0.31.2,
    section 4.6). After a line of text it continues the paragraph, and the reader must not stop there."""
    _changelog(tmp_path, monkeypatch, text)
    assert _newest_release() == "6.4.0"


@pytest.mark.parametrize("text", [
    "## [Unreleased]\n\n<a b=>\n\n## [6.4.0] - 2026-10-27\n",
    "## [Unreleased]\n## [6.4.0] - 2026-10-27\n> x\nx\n===\n",
    "## [Unreleased]\n## [6.4.0] - 2026-10-27\nx\n01. x\n===\n",
    "## [Unreleased]\n## [6.4.0] - 2026-10-27\nx\n000000001) x\n===\n",
    "## [Unreleased]\n## [6.4.0] - 2026-10-27\n<p/\n",
], ids=["a tag without its attribute value", "an underline that lazily continues a quoted paragraph",
        "an item numbered 01 interrupts a paragraph", "an item numbered 1 in nine digits interrupts a paragraph",
        "a block tag name followed by a slash without >"])
def test_control_a_line_the_reader_can_place_does_not_stop_the_case(tmp_path, monkeypatch, text):
    """A sixth pre-run of the reading of the pin on main (Codex, P2): `<a b=>` is no tag in CommonMark, since an
    attribute's `=` needs a value, so the line is paragraph text; and `===` after a quoted paragraph and a line that
    continues it lazily continues that paragraph too (CommonMark 0.31.2, example 93). Neither may stop the case. A
    seventh pre-run (Codex, P2): an ordered item numbered 1 with leading zeros interrupts a paragraph as `1.` does, and
    an underline after it continues the item's paragraph."""
    _changelog(tmp_path, monkeypatch, text)
    assert _newest_release() == "6.4.0"


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


@pytest.mark.parametrize("planted", [
    'if (PINNED_PROOFBUNDLE := "6.3.0"):\n    pass\n',
    'for PINNED_PROOFBUNDLE in ("6.3.0",):\n    pass\n',
    "from os import sep as PINNED_PROOFBUNDLE\n",
    "def _SIGN_TOOL():\n    pass\n",
    "with open(__file__) as _KEY_TOOL:\n    pass\n",
], ids=["an assignment expression", "a for target", "an import alias", "a function name", "a with target"])
def test_any_other_binding_of_a_pin_name_is_found(tmp_path, monkeypatch, planted):
    """A second pre-run of the reading of the pin on main (Codex, P2): an assignment expression rebinds
    PINNED_PROOFBUNDLE at import and went unseen, since only assignment statements were read. Every form that binds one
    of the three names (assignment expression, for and with targets, an import alias, a function name) counts."""
    gate = tmp_path / "proofbundle_gate.py"
    gate.write_text(GATE.read_text(encoding="utf-8") + "\n" + planted, encoding="utf-8")
    monkeypatch.setattr(sys.modules[__name__], "GATE", gate)
    with pytest.raises(AssertionError):
        test_the_four_pins_name_one_version()


def test_each_tool_is_read_from_its_own_metadata_block(tmp_path, monkeypatch):
    """A third pre-run of the reading of the pin on main (Codex, P2): the tool headers were counted together, so a second
    dependency line after the code of _SIGN_TOOL hid a pin `proofbundle ==6.3.0` in the metadata block of _KEY_TOOL. Each
    tool's pin is the one requirement of its own inline script metadata block."""
    source = GATE.read_text(encoding="utf-8")
    tools = _assigned_strings(source, ("_SIGN_TOOL", "_KEY_TOOL"))
    sign, key = tools["_SIGN_TOOL"][0], tools["_KEY_TOOL"][0]
    header = re.search(r'^# dependencies = \["proofbundle==[^"]*"\]$', sign, re.M).group(0)
    assert source.count(sign) == source.count(key) == 1 and header in key
    planted = source.replace(key, key.replace(header, '# dependencies = ["proofbundle ==0.0.0"]', 1))
    planted = planted.replace(sign, sign + header + "\n")
    gate = tmp_path / "proofbundle_gate.py"
    gate.write_text(planted, encoding="utf-8")
    monkeypatch.setattr(sys.modules[__name__], "GATE", gate)
    with pytest.raises(AssertionError):
        test_the_four_pins_name_one_version()


def test_a_pin_written_with_spaces_or_extras_is_found():
    """The same pre-run: `proofbundle ==6.3.0` is a valid requirement, and the search for stale pins did not see it."""
    assert _ANY_PIN.findall("proofbundle ==6.3.0, proofbundle[eval] == 6.2.0") == ["6.3.0", "6.2.0"]


def test_control_an_atx_heading_before_a_thematic_break_is_read(tmp_path, monkeypatch):
    """The same pre-run: a line of dashes after a heading of any level is a thematic break, no setext underline."""
    _changelog(tmp_path, monkeypatch, "## [Unreleased]\n## [6.4.0] - 2026-10-27\n### Notes\n---\n")
    assert _newest_release() == "6.4.0"


def test_control_a_thematic_break_after_indented_code_is_read(tmp_path, monkeypatch):
    """A fourth pre-run of the reading of the pin on main (Codex, P2): a line of dashes after a line of indented code is a
    thematic break, since indented code ends no paragraph and starts none (CommonMark 0.31.2, example 115)."""
    _changelog(tmp_path, monkeypatch, "## [Unreleased]\n## [6.4.0] - 2026-10-27\n\n    x\n---\n\n\tcode\n===\n")
    assert _newest_release() == "6.4.0"


@pytest.mark.parametrize("planted", [
    'globals()["PINNED_PROOFBUNDLE"] = "0.0.0"\n',
    'exec("_KEY_TOOL = _KEY_TOOL + \'# changed\'")\n',
], ids=["through globals()", "through exec"])
def test_a_pin_rewritten_through_the_module_namespace_is_found(tmp_path, monkeypatch, planted):
    """The same pre-run (Codex, P2): `globals()["PINNED_PROOFBUNDLE"] = "0.0.0"` binds no name in the syntax tree and
    changes the pin the gate holds once it is imported. Each of the three names holds its one literal after import."""
    gate = tmp_path / "proofbundle_gate.py"
    gate.write_text(GATE.read_text(encoding="utf-8") + "\n" + planted, encoding="utf-8")
    monkeypatch.setattr(sys.modules[__name__], "GATE", gate)
    with pytest.raises(AssertionError):
        test_the_four_pins_name_one_version()


@pytest.mark.parametrize("name", ["install.yml", "Dockerfile", "notes.txt"])
def test_a_stale_pin_in_any_text_file_of_the_plugin_is_found(tmp_path, monkeypatch, name):
    """An eighth pre-run of the reading of the pin on main (Codex, P2): the search for stale pins read files by a list of
    endings, so a `.yml` file, a file without an ending or one of any other kind went unread. It reads every file of the
    plugin that holds no NUL byte."""
    _changelog(tmp_path, monkeypatch, "## [Unreleased]\n\n## [6.4.0] - 2026-10-27\n")
    plugin = tmp_path / "plugins" / "proofbundle"
    plugin.mkdir(parents=True)
    (plugin / name).write_text("run: uv run --with proofbundle==6.3.0 python\n", encoding="utf-8")
    monkeypatch.setattr(sys.modules[__name__], "ROOT", tmp_path)
    monkeypatch.setattr(sys.modules[__name__], "PLUGIN", plugin)
    with pytest.raises(AssertionError, match="6.3.0"):
        test_every_pin_the_plugin_writes_names_that_version()


def test_control_a_binary_file_of_the_plugin_is_not_read_for_pins(tmp_path, monkeypatch):
    """A file that holds a NUL byte is no text the plugin writes for a reader, such as a compiled module; the search for
    stale pins leaves it out."""
    _changelog(tmp_path, monkeypatch, "## [Unreleased]\n\n## [6.4.0] - 2026-10-27\n")
    plugin = tmp_path / "plugins" / "proofbundle"
    plugin.mkdir(parents=True)
    (plugin / "module.pyc").write_bytes(b"\0\0proofbundle==6.3.0\0")
    monkeypatch.setattr(sys.modules[__name__], "ROOT", tmp_path)
    monkeypatch.setattr(sys.modules[__name__], "PLUGIN", plugin)
    test_every_pin_the_plugin_writes_names_that_version()


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
