#!/usr/bin/env python3
"""A pull request that carries a release-scope line names that line's identifier in its title.

WHY THIS GATE EXISTS. `docs/release_scope/<version>.md` maps each scope item to its own branch:
one identifier, one branch, one pull request. Without a gate that mapping is a promise in a
document — readable, and unenforced. The landing card counts what landed by reading identifiers
out of the pull-request titles on main, so a title without its identifier is not a cosmetic
omission: it makes the item invisible to the count that is supposed to track it.

Owner decision 2026-09-14: the title form is English, `[<version> <ID>] type(scope): subject`,
exactly one identifier per pull request.

WHAT THIS GATE DOES NOT DO, said plainly. It judges the BRANCH, not the diff. A pull request whose
head branch is named in the scope file must carry that line's identifier; a branch the scope file
does not name is not judged here at all, and is reported as such rather than as a pass. Deciding
"does this diff touch scope content" from the changed files would be a second, weaker oracle over
the same question, and a guess dressed as a measurement is worse than a stated limit.

THE RIDERS ARE AN EXCEPTION BY CONSTRUCTION, not by a hand-kept list. Scope lines whose branch
column says "mit X", "= X" or names no branch at all ride along with another item. They have no
branch of their own, so no pull request can ever match them, so they can never trigger this gate.
That is the same exception the order names, derived from the file instead of copied out of it —
a copied list is a second truth that ages the moment the file moves.

Exit: 0 green · 1 RED, with the reason. Never a third outcome: a gate that cannot measure and
says so quietly reads, in a pull-request check list, exactly like one that passed.
"""
from __future__ import annotations

import argparse
import html
import importlib.util
import json
import pathlib
import re
import unicodedata

REPO =pathlib.Path(__file__).resolve().parents[1]

#: An identifier from the scope file: a letter, an optional dot or dash, an optional SECOND
#: letter, digits, optionally a sub-part. Covers A1, A5.1, B-3, N1-1a, N2-3a, S65-5, Z.278, R-A1.
#:
#: THE SECOND LETTER WAS ADDED 2026-09-19, and the way it was found matters more than the change.
#: The owner decision renamed three RESTRISIKO lines to R-A1, R-A2, R-A3 to end an ambiguity: the
#: names A1, A2, A3 led two lines each. After the rename the file check reported GREEN, no
#: collisions -- and it was wrong. This expression did not match `R-A1`, so all three lines were
#: dropped before they could collide with anything. The count fell from 56 lines to 53 and the
#: verdict turned green on the way. Whoever reads only the verdict sees a fix; whoever reads the
#: count sees three lines that stopped existing. The collision had not been resolved, it had been
#: made invisible.
_KENNUNG = r"[A-Z]\.?-?[A-Z]?\d+(?:[.\-][0-9a-z]+)*"

#: THE WHOLE TITLE FORM, anchored at both ends. The contract in the module docstring above reads
#: `[<version> <ID>] type(scope): subject`, exactly one identifier, at the start.
#:
#: UNTIL 2026-09-16 THIS WAS AN UNANCHORED `findall`, which asks a different question altogether,
#: namely whether a bracket of this version appears anywhere in the title. Measured at head
#: 1077c3d, three titles passed green: `WRONG PREFIX [6.1.0 N3-1] nonsense`, then
#: `irgendwas [6.1.0 N3-1]` with no subject form at all, and
#: `[6.1.0 N3-1] [6.0.1 R1] feat(scope): subject` carrying a second identifier of a FOREIGN
#: version, which went uncounted because only matches of the current version were counted. Three
#: titles, all green, none conforming. Codex round one raised it; it was re-measured here, and it
#: reaches further than reported, because the third form was not in the report.
#: THE SEPARATORS ARE PLAIN SPACES, not `\s`, and the title is ONE line. Both were measured on
#: the first version of this expression, by running it rather than by reading it.
#:
#: `\s` in Python matches U+00A0 and U+2009 as well, so `[6.1.0<narrow space>A1] feat(x): y`
#: passed. The landing card reads identifiers out of titles with its own reader, and two readers
#: that disagree about what a space is will disagree about which line landed. A separator that
#: looks like a space and is not one is exactly the kind of difference this gate exists to catch.
#:
#: And `\s` matches a newline, so `[6.1.0 A1] feat(x): y\nanything at all` passed as well:
#: the form bound the first line and said nothing about the rest. A pull-request title is one
#: line; whatever follows a line break was never judged, and a rule that stops at the first
#: newline judges a prefix while claiming to judge a title.
_TITELFORM = re.compile(
    rf"^\[ *(?P<version>[0-9]+(?:\.[0-9]+)*) +(?P<kennung>{_KENNUNG}) *\]"
    r" +(?P<typ>[a-z][a-z0-9]*)(?:\([^()]+\))?: +\S[^\r\n]*\Z")

#: EVERY identifier bracket in the title, whatever its version. The old expression counted only
#: the current one, so a second bracket of a foreign version stayed invisible, which is exactly the
#: ambiguity that "exactly one identifier" was written against.
_JEDE_KLAMMER = re.compile(rf"\[ *[0-9]+(?:\.[0-9]+)* +{_KENNUNG} *\]")

#: Where the scope ends. Everything after that (Out, rationales, owner doors) is NOT the set
#: against which a pull request is checked — those are lines that are explicitly not being built.
_ENDE_DES_UMFANGS = re.compile(r"^##\s+Out\b", re.M)

#: A scope file is named by the release it scopes: `docs/release_scope/<major>.<minor>.<patch>.md`.
_UMFANGSDATEI = re.compile(r"^([0-9]+)\.([0-9]+)\.([0-9]+)\.md$")

#: A source version that names a release which is out: three numbers, optionally a post-release.
#: A pre-release or a local suffix says the release is not out yet, and which scope that leaves
#: open is not guessed here.
_FREIGEGEBEN = re.compile(r"^([0-9]+)\.([0-9]+)\.([0-9]+)(?:\.post[0-9]+)?$")


def _tag_stand(wurzel: pathlib.Path, version: str) -> str:
    """Whether this clone SHOWS `v<version>`: "da", "fehlt", or the reason the tags cannot be read.
    A clone that shows no release tag at all (the CI checkout at depth 1 fetches none) says
    nothing about any tag, so that is not "fehlt".

    "fehlt" MEANS NOT SHOWN HERE, NOT ABSENT UPSTREAM (Codex on pull request 294, round four, P1).
    `git tag --list` lists the tags this clone holds; a clone whose tags were fetched in part shows
    `v6.1.0` and not `v6.2.0` whether or not `v6.2.0` exists. Only "da" is a fact about the release;
    the callers read "fehlt" as not knowing."""
    import subprocess  # noqa: PLC0415
    try:
        r = subprocess.run(["git", "-C", str(wurzel), "tag", "--list", "v[0-9]*"],
                           capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as e:
        return f"git could not be asked: {type(e).__name__}"
    if r.returncode != 0:
        return "not a git repository, or git refused the question"
    tags = set(r.stdout.split())
    if not tags:
        return "this clone shows no release tag"
    return "da" if f"v{version}" in tags else "fehlt"


def umfangskandidaten_ohne_tags(wurzel: pathlib.Path = REPO) -> list[str]:
    """The releases a run without `--version` may be judging when this clone does not show the
    source version's tag, because the tags cannot be read or because `v<source>` is not among the
    ones it shows: the source version, which has its own scope file, and the oldest scope file
    above it. Empty when the source version has no scope file of its own (then
    `naechste_umfangsversion` decides without tags), when its tag is shown here (then the next
    scope file decides alone), or when the version cannot be read."""
    version, _ = naechste_umfangsversion(wurzel)
    if version is not None:
        return []
    leser = pathlib.Path(__file__).resolve().parent / "check_version_and_changelog.py"
    try:
        spec = importlib.util.spec_from_file_location("_release_integrity_version_k", leser)
        modul = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(modul)
        quelle = modul._pyproject_version(wurzel)
        namen = sorted(p.name for p in (wurzel / "docs" / "release_scope").iterdir() if p.is_file())
    except Exception:  # noqa: BLE001 - no candidates; the caller keeps its NOT MEASURABLE
        return []
    m = _FREIGEGEBEN.match(quelle) if isinstance(quelle, str) else None
    if m is None or ".post" in quelle:
        return []
    draussen = tuple(int(x) for x in m.groups())
    eigene = ".".join(str(x) for x in draussen)
    if f"{eigene}.md" not in namen or _tag_stand(wurzel, eigene) == "da":
        # Only a tag this clone SHOWS decides by itself, and a NOT MEASURABLE it leaves (no scope
        # file above a tagged source) stays one. A tag not shown here opens the candidates, whether
        # the tags cannot be read at all or the clone holds some of them: a tag not fetched is not
        # a tag that does not exist (Codex on pull request 294, round four, P1).
        return []
    darueber = sorted(v for v in (tuple(int(x) for x in t.groups())
                                  for t in map(_UMFANGSDATEI.match, namen) if t) if v > draussen)
    return [eigene] + ([".".join(str(x) for x in darueber[0])] if darueber else [])


def naechste_umfangsversion(wurzel: pathlib.Path = REPO) -> tuple[str | None, str]:
    """The release a run WITHOUT `--version` judges, and how it was found: (version, origin).

    THE DEFAULT WAS A TYPED NUMBER, "6.1.0", in this gate and in the landing card, and a typed
    release number goes stale at the release it names. Measured on 2026-09-27 at 351fce0c, the head
    of the 6.2.0 cut: the CI step calls this gate without `--version`, so it judged every pull
    request against the scope of a release that was already out. A pull request from
    `fix/the-commit-pattern-holds-at-the-verify-boundary`, the branch of line R-B1 of 6.2.0, came
    back green and "outside the scope"; with `--version 6.2.0` the same call is RED and asks for
    `[6.2.0 R-B1]`.

    THE RULE: the OLDEST scope file whose version is above the source version, `[project] version`
    in `pyproject.toml`. The source version is the release that is out, and the next scope file
    above it is the release being built. When the next release raises the source version, the
    answer moves with it, so there is no number here to keep in step.

    WHY NOT GIT TAGS ALONE, though "the newest scope file without a tag" was the first candidate. The
    CI job that calls this gate checks out at depth 1 and fetches no tag, so there every scope file
    looks untagged. And with tags visible that rule still picks wrongly in both directions: the
    NEWEST untagged scope file is the release after next (6.3.0 while 6.2.0 is being built), the
    OLDEST untagged one is 3.7.1, a patch scope that never shipped.

    THE ONE QUESTION A TAG ANSWERS (Codex on pull request 294, round three, P1): when the source
    version has a scope file of its own, is it out or being built? RELEASE.md bumps the version in
    the release-prep pull request and tags after the merge, so the version alone cannot tell. And
    only a tag this clone SHOWS answers it (round four, P1): `git tag --list` lists the tags a clone
    holds, so a clone whose tags were fetched in part shows `v6.1.0` without `v6.2.0` whether or not
    `v6.2.0` is out. Measured at 5a9ddc06 with the source at 6.2.0 and only `v6.1.0` in the clone: a
    branch that only the 6.3.0 scope names was judged against 6.2.0, outside the scope, exit 0. So
    `v<source>` shown here, the answer is the scope file above; not shown, whether because the
    clone shows no tag at all or because it shows others, NOT MEASURABLE, and the gate's `main`
    then judges the branch by whichever of the two scope files names it
    (`umfangskandidaten_ohne_tags`). The landing card counts one release and has no branch to
    choose by, so there it stays NOT MEASURABLE until the tag is fetched or `--version` is given.

    THE SOURCE VERSION IS READ BY THE RELEASE-INTEGRITY GATE'S OWN READER,
    `scripts/check_version_and_changelog.py::_pyproject_version`, loaded from beside this file, not by
    a second reader here. The first version of this rule parsed pyproject.toml with `tomllib`, and
    `tomli` below Python 3.11. That is an import outside the standard library of 3.10, the floor of
    this repository, and `tests/test_release_tooling_refuses_weak_pinned_keys.py` refuses it there
    (measured in CI at caccdbad, crypto-floor: `tomllib` and `tomli` seen, not in the table). A table
    entry would be stale on 3.11 and later, where `tomllib` is standard. The release-integrity gate
    already reads this version, and it is the reading a release is checked against, so this rule
    reads the same one.

    Not measurable, with the reason in the second value: the reader not loadable, an unreadable or
    version-less pyproject.toml, a source version that is not a released one, a source version
    with a scope file of its own whose tag this clone does not show, or no scope file above it.
    """
    leser = pathlib.Path(__file__).resolve().parent / "check_version_and_changelog.py"
    try:
        spec = importlib.util.spec_from_file_location("_release_integrity_version", leser)
        if spec is None or spec.loader is None:
            raise ImportError(f"no loader for {leser}")
        modul = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(modul)
        quelle = modul._pyproject_version(wurzel)
    except Exception as e:  # noqa: BLE001 - not knowing the source version blocks, it never passes
        return None, (f"NOT MEASURABLE: the source version in pyproject.toml cannot be read with "
                      f"{leser.name} ({type(e).__name__}: {e})")
    m = _FREIGEGEBEN.match(quelle) if isinstance(quelle, str) else None
    if m is None:
        return None, (f"NOT MEASURABLE: the source version {quelle!r} in pyproject.toml is not a "
                      "released version (X.Y.Z, optionally .postN), so which scope comes next is "
                      "not decided here")
    draussen = tuple(int(x) for x in m.groups())
    try:
        namen = sorted(p.name for p in (wurzel / "docs" / "release_scope").iterdir() if p.is_file())
    except OSError as e:
        return None, f"NOT MEASURABLE: docs/release_scope is not readable ({type(e).__name__}: {e})"
    # A SOURCE VERSION WITH A SCOPE FILE OF ITS OWN IS OUT ONLY ONCE ITS TAG EXISTS (Codex on pull
    # request 294, round three, P1, measured with pyproject.toml at 6.2.0). RELEASE.md bumps the
    # version inside the release-prep pull request and tags after the merge, so between the bump and
    # the tag the source version names the release being built, and "the oldest scope file above
    # it" judged a 6.2.0 correction against 6.3.0: outside the scope, and green. The tag is the one
    # fact that tells the two states apart. A post-release (`X.Y.Z.postN`) says `X.Y.Z` is out.
    #
    # AND ONLY A TAG THIS CLONE SHOWS IS THAT FACT (round four, P1). Round three read a tag missing
    # from a clone that shows other tags as a tag that does not exist, and a partial fetch made that
    # a pass: 6.2.0 judged while `v6.2.0` may be out upstream. Not shown here is not knowing.
    eigene = ".".join(str(x) for x in draussen)
    if f"{eigene}.md" in namen and ".post" not in quelle:
        stand = _tag_stand(wurzel, eigene)
        if stand != "da":
            warum = (f"this clone shows release tags and not v{eigene}, and a tag it has not "
                     "fetched may exist upstream" if stand == "fehlt" else stand)
            return None, (f"NOT MEASURABLE: the source version {quelle} has its own scope file, "
                          f"and whether v{eigene} is tagged cannot be read here ({warum}); tagged, "
                          f"the release being built is the next scope file, untagged it is {eigene}")
    darueber = sorted(v for v in (tuple(int(x) for x in t.groups())
                                  for t in map(_UMFANGSDATEI.match, namen) if t) if v > draussen)
    if not darueber:
        return None, (f"NOT MEASURABLE: no scope file above the source version {quelle} in "
                      f"docs/release_scope ({namen}); the release being built has no scope file")
    version = ".".join(str(x) for x in darueber[0])
    return version, (f"derived: the oldest scope file above the source version {quelle} "
                     "in pyproject.toml")


def lies_umfang(pfad: pathlib.Path) -> tuple[dict[str, list[str]], list[str], str]:
    """(Branch -> LIST of identifiers, riders, state). Only the In section counts.

    A LIST, BECAUSE A MAPPING IN EITHER DIRECTION CAN LOSE DATA. The first version mapped
    identifier -> branch and silently overwrote as soon as two lines carried the same identifier —
    and the 6.1.0 scope does exactly that three times (A1, A2, A3). The second version reversed
    the direction and lost data the mirror-image way, as soon as two lines named the same branch.
    Both times the loss was SILENT. A list loses nothing, and the ambiguity becomes a finding
    instead of an absence. Both versions were caught by the contract itself, not by reading.

    NOTE: AN IDENTIFIER DOES NOT IDENTIFY A LINE. Measured on the 6.1.0 scope: A1, A2 and A3 each
    lead TWO different lines, one from the collective order and one from RESTRISIKO_600, with a
    different subject and a different branch. The return value here therefore reliably maps only
    branch -> identifier (branches are unique); the reverse direction is ambiguous and is reported
    by `pruefe_umfangsdatei` as a finding about the FILE, rather than silently overwritten.

    Returns three things, because three different questions hang on it: which branch belongs to
    which identifier, which lines have no branch of their own at all (and can therefore never be a
    pull request), and whether the file was readable at all. The third is the most important: an
    empty mapping from a missing file looks like an empty mapping from an empty scope, and the two
    mean the opposite of each other.
    """
    try:
        text = pfad.read_text(encoding="utf-8")
    except OSError as e:
        return {}, [], f"NICHT MESSBAR: {type(e).__name__}: {e}"
    schnitt = _ENDE_DES_UMFANGS.search(text)
    if schnitt is None:
        # FAIL-CLOSED, and that too was found by the foreign model family. Without the marker, the
        # WHOLE file previously counted as scope — including the lines under "Out", which are
        # explicitly NOT being built. A gate that ENLARGES the set it checks when structure is
        # missing then judges lines nobody wanted to build, and calls that a measurement.
        return {}, [], ("NICHT MESSBAR: kein Abschnitt '## Out' gefunden — ohne ihn ist die Grenze "
                        "des Umfangs nicht bestimmbar, und die ganze Datei als Umfang zu lesen "
                        "waere eine Vergroesserung der Pruefmenge, keine Messung")
    im_umfang = text[: schnitt.start()]
    # ONE READING OF THE IN SECTION, THE ONE GITHUB RENDERS (`_lies_zweige` over `_tabellen_gfm`).
    # The reader, the rule of an unstarted release, the line count and the guard against unreadable
    # lines all read the same tables now. The second round of the lens on pull request 328
    # (2026-10-18) refuted all five of its targets against the line-by-line reading, among them a
    # decoy delimiter above the real header, a row wider or narrower than its header, a row with
    # blank space after its last pipe, a decorated branch cell, and a backticked cell of a table
    # without a branch column read as a branch. Every one of those is a question about the TABLE,
    # and a line does not know its table.
    zu_zweig, mitlaeufer, unlesbar = _lies_zweige(im_umfang)
    if unlesbar:
        return {}, [], f"NICHT MESSBAR: {unlesbar}"
    if not zu_zweig:
        # A RELEASE THAT HAS NOT STARTED NAMES NO BRANCH, and that is a measurement, not a gap.
        # Measured on 2026-10-09 after the tag v6.2.0: the next scope file, 6.3.0, says "(not
        # started)" in its title and heads its In tables `Item | ...` without a branch column, so
        # this reader returned NOT MEASURABLE, and every pull request on main went red on the gate
        # and on the landing card. A file that declares itself not started and has no branch column
        # at all is read as zero branches. A file that has a branch column and no branch the reader
        # can read stays NOT MEASURABLE, declared or not: that is a malformed column, not an
        # unstarted release.
        if _als_nicht_begonnen_ausgewiesen(text, im_umfang):
            return {}, mitlaeufer, "gemessen"
        return {}, mitlaeufer, "NICHT MESSBAR: kein einziger Zweig im In-Abschnitt gefunden"
    return zu_zweig, mitlaeufer, "gemessen"


#: The words by which a scope file declares, in its title, that its release has not started.
_NICHT_BEGONNEN = "(not started)"


#: The STEM by which a header cell names a branch column. A stem, not a word: `branch_name`,
#: `Zweigname`, `HeadBranch`, `Branch1` and `Zweigen` name the same column as `Branch`, and the word
#: boundaries of the first version let every one of them through (lens on pull request 328,
#: 2026-10-18, case T1). A cell the stem matches by accident, such as `Branching`, turns a file NOT
#: MEASURABLE rather than green, which is the only direction a guess may err in here.
_ZWEIGSTAMM = re.compile(r"branch|zweig", re.IGNORECASE)
#: A cell that is a branch name and nothing else, in the lower-case form the branches of this
#: repository take (`fix/a1`, `claude/fix-631-teil2`). An upper-case pair such as `B1/B2` is a
#: rider's reference to two lines, not a branch.
_ZWEIGFORM = re.compile(r"^[a-z0-9][a-z0-9._-]*(?:/[a-z0-9][a-z0-9._-]*)+$")
#: A delimiter cell of a GFM table: dashes, optionally a colon on either side.
_TRENNZELLE = re.compile(r"^:?-+:?$")
#: What may stand in front of a table row on its line: indentation, quote markers, a list marker.
_ZEILENVORSATZ = re.compile(r"^\s*(?:>\s*)*(?:(?:[-*+]|\d+[.)])\s+)?")
#: A list marker inside that prefix; a row that carries one starts a list item and ends a table.
_LISTENMARKE = re.compile(r"(?:^|[\s>])(?:[-*+]|\d+[.)])\s+$")
#: The fence of a fenced code block (CommonMark 4.5): at most three spaces, then three or more
#: backticks or tildes.
_ZAUN = re.compile(r"^ {0,3}(`{3,}|~{3,})")
#: The start of an HTML comment BLOCK (CommonMark 4.6, type 2): `<!--` at the start of a line,
#: after at most three spaces. A comment in the middle of a line is inline and starts no block:
#: `| A1 | x <!-- c --> | `fix/a1` |` is a table row on the page, and a reader that hid the whole
#: line would drop its branch.
_KOMMENTARBLOCK = re.compile(r"^ {0,3}<!--")
#: A line that starts another block and so ends a table (GFM 4.10): a heading, a fence, a thematic
#: break, HTML.
_BLOCKBEGINN = re.compile(r"^ {0,3}(?:#{1,6}(?:[ \t]|$)|`{3,}|~{3,}|<"
                          r"|(?:(?:\*[ \t]*){3,}|(?:-[ \t]*){3,}|(?:_[ \t]*){3,})$)")
#: A branch cell that is exactly one code span whose content carries no backtick.
_CODESPAN = re.compile(r"^(`+)([^`]+)\1$")
#: THE RIDER, AS A POSITIVE GRAMMAR (asked for by round 2 of the lens on pull request 328). A rider
#: cell names the line it rides with (`mit C1`, `with A0`, `= B1/B2`, `B1`), or says that there is
#: none (empty, a dash, `n/a`, `none yet`). Everything else in a branch column is neither a branch
#: nor a rider, and this reader refuses it instead of guessing: `` `fix/a1` (merged)``, a bold or
#: linked branch, `main`, `hotfix-123`, `with fix/a1`. Measured on 2026-10-19 over every scope file
#: on main d3652ba5: each branch cell of each table with a branch column is exactly one code span,
#: so the grammar refuses nothing real.
_MITLAEUFER = re.compile(rf"^(?:(?:(?:mit|with)\s+|=\s*)?{_KENNUNG}"
                         rf"(?:\s*(?:/|,|\+|und|and)\s*{_KENNUNG})*"
                         r"|[-–—]?|n/a|N/A|n\.a\.|(?i:none(?: yet)?))$")
#: Default ignorable code points (Unicode DerivedCoreProperties.txt, Default_Ignorable_Code_Point),
#: as ranges. A renderer shows none of them, so a header cell `Bra<U+034F>nch` is `Branch` on the
#: page; category Cf alone misses U+034F, U+115F, U+3164, U+FE00 to U+FE0F, U+FFA0 and the
#: variation selectors above U+E0100 (lens round 2, case T1: 268 code points slipped where Cf alone
#: was taken out). The ranges are the whole property as Unicode lists it; category Cf is taken out
#: on top.
_IGNORIERBAR = ((0x00AD, 0x00AD), (0x034F, 0x034F), (0x061C, 0x061C), (0x115F, 0x1160),
                (0x17B4, 0x17B5), (0x180B, 0x180F), (0x200B, 0x200F), (0x202A, 0x202E),
                (0x2060, 0x206F), (0x3164, 0x3164), (0xFE00, 0xFE0F), (0xFEFF, 0xFEFF),
                (0xFFA0, 0xFFA0), (0xFFF0, 0xFFF8), (0x1BCA0, 0x1BCA3), (0x1D173, 0x1D17A),
                (0xE0000, 0xE0FFF))


def _ignorierbar(ch: str) -> bool:
    o = ord(ch)
    return any(a <= o <= b for a, b in _IGNORIERBAR) or unicodedata.category(ch) == "Cf"


def _kopfwort(zelle: str) -> str:
    """A header cell as a reader of the page sees its word: entities resolved, inline HTML and
    the markup characters `*`, `_`, `~`, backtick and backslash taken out, NFKC, no default
    ignorable code point, case folded. `&#66;ranch`, `Bra&shy;nch`, `Bra<span></span>nch`,
    `**B**ranch` and full-width letters all read `branch` (lens round 2, T1)."""
    s = re.sub(r"<[^>]*>", "", html.unescape(zelle))
    s = unicodedata.normalize("NFKC", s)
    s = "".join(ch for ch in s if not _ignorierbar(ch))
    return re.sub(r"[*_~`\\]", "", s).casefold()


def _zweigstellen(kopf: list[str]) -> list[int]:
    """The cells of a header that name a branch column (`_ZWEIGSTAMM` over `_kopfwort`)."""
    return [i for i, z in enumerate(kopf) if _ZWEIGSTAMM.search(_kopfwort(z))]


def _zellen_gfm(rest: str) -> list[str]:
    """The cells of a table row as GFM splits them: at every pipe a backslash does not escape, a
    leading and a trailing pipe dropped, each cell trimmed of spaces and tabs only. A pipe inside a
    code span splits as well (GFM 4.10, example 200); a no-break space is no blank space here, so a
    row with one after its last pipe does not end with a pipe."""
    s = rest.strip(" \t")
    teile, akt, i = [], [], 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            akt.append(s[i:i + 2])
            i += 2
            continue
        if s[i] == "|":
            teile.append("".join(akt))
            akt = []
        else:
            akt.append(s[i])
        i += 1
    teile.append("".join(akt))
    if s.startswith("|"):
        teile = teile[1:]
    if len(teile) > 1 and s.endswith("|") and not _entwertet(s, len(s) - 1):
        teile = teile[:-1]
    return [t.strip(" \t") for t in teile]


def _entwertet(s: str, i: int) -> bool:
    """Whether the character at `i` is escaped by an odd run of backslashes before it."""
    n = 0
    while i - n - 1 >= 0 and s[i - n - 1] == "\\":
        n += 1
    return n % 2 == 1


def _vorsatz(zeile: str) -> tuple[str, str]:
    m = _ZEILENVORSATZ.match(zeile)
    return zeile[:m.end()], zeile[m.end():]


def _kanonisch(zeile: str) -> bool:
    """A row in the one form this reader reads: `|` at the start of the line, nothing in front of
    it, and an unescaped `|` as the last character but spaces and tabs."""
    rechts = zeile.rstrip(" \t")
    return (zeile.startswith("|") and rechts.endswith("|")
            and not _entwertet(rechts, len(rechts) - 1))


def _ist_trenner(rest: str) -> bool:
    if "|" not in rest:
        return False
    zellen = _zellen_gfm(rest)
    return bool(zellen) and all(_TRENNZELLE.match(z) for z in zellen)


def _maske(zeilen: list[str]) -> tuple[list[bool], str | None]:
    """(True for every line in which GitHub renders no table, why the mask is not measurable or
    None). Masked are the lines of a fenced code block and of an HTML comment block: a table there
    is code, or invisible, on the page (lens round 2, case T2, where each turned a real unstarted
    scope NOT MEASURABLE).

    AN INDENTED CODE BLOCK IS NOT MASKED, on purpose. Four spaces after a blank line are code at the
    top level and a continuation inside a list item, and a reader that cannot tell the two apart and
    hides the lines would drop the branches of a table in a list. Unmasked, such a table is read in
    a form this reader does not read, and a branch column there is NOT MEASURABLE, which is the
    direction a guess may err in here.

    A FENCE OR A COMMENT THAT NEVER CLOSES IS NOT MEASURABLE. On the page it runs to the end of the
    document and takes every table after it along; in a scope file that is a mistake, and the
    branches after it would go unread."""
    maske = [False] * len(zeilen)
    zaun, kommentar = None, None
    for i, z in enumerate(zeilen):
        rest = _vorsatz(z)[1]
        if kommentar is not None:
            maske[i] = True
            if "-->" in z:
                kommentar = None
            continue
        if zaun is not None:
            maske[i] = True
            m = _ZAUN.match(z) or _ZAUN.match(rest)
            if m and m.group(1)[0] == zaun[1][0] and len(m.group(1)) >= len(zaun[1]) and not (
                    z.strip() if _ZAUN.match(z) else rest.strip()).strip(zaun[1][0]):
                zaun = None
            continue
        m = _ZAUN.match(z) or _ZAUN.match(rest)
        if m:
            zaun, maske[i] = (i, m.group(1)), True
            continue
        if _KOMMENTARBLOCK.match(z) or _KOMMENTARBLOCK.match(rest):
            maske[i] = True
            if "-->" not in z[z.index("<!--") + 4:]:
                kommentar = i
    if zaun is not None:
        return maske, (f"the fenced block opened at line {zaun[0] + 1} of the In section never "
                       "closes, so every table after it is code on the page and its branches would "
                       "go unread")
    if kommentar is not None:
        return maske, (f"the HTML comment opened at line {kommentar + 1} of the In section never "
                       "closes, so every table after it is invisible on the page and its branches "
                       "would go unread")
    return maske, None


def _tabellen_gfm(im_umfang: str) -> dict:
    """Every table of the In section as GitHub renders it (GFM 4.10): a header row directly above
    a delimiter row with the SAME number of cells, then every following line until a blank line or
    the start of another block.

    Returns {"tabellen": [{kopf, zeilen: [(cells, line)], kanonisch, nummern, kopf_nr}],
    "waisen": [(cells, line, number)], "unlesbar": why the section is not measurable, or None}. A
    waise is a line that starts with `|` and stands in no table, such as a row cut off from its
    table by a blank line. A line that only looks like a delimiter but has another number of cells
    than the row above it starts no table, so a decoy delimiter above the real header decides
    nothing (lens round 2, case T1-A). The lines are split as CommonMark splits them, a lone CR
    included."""
    zeilen = re.split(r"\r\n|\r|\n", im_umfang)
    maske, unlesbar = _maske(zeilen)
    tabellen, i = [], 0
    while i < len(zeilen) - 1:
        if maske[i] or maske[i + 1]:
            i += 1
            continue
        k_vor, k_rest = _vorsatz(zeilen[i])
        t_vor, t_rest = _vorsatz(zeilen[i + 1])
        if "|" not in k_rest or not _ist_trenner(t_rest) or k_vor.count(">") != t_vor.count(">"):
            i += 1
            continue
        kopf = _zellen_gfm(k_rest)
        if len(kopf) != len(_zellen_gfm(t_rest)):
            i += 1
            continue
        tab = {"kopf": kopf, "zeilen": [], "nummern": {i, i + 1}, "kopf_nr": i,
               "kanonisch": _kanonisch(zeilen[i]) and _kanonisch(zeilen[i + 1])}
        j = i + 2
        while j < len(zeilen) and not maske[j]:
            vor, rest = _vorsatz(zeilen[j])
            if (not rest.strip(" \t") or vor.count(">") != k_vor.count(">")
                    or _BLOCKBEGINN.match(rest) or (_LISTENMARKE.search(vor) and vor != k_vor)):
                break
            tab["zeilen"].append((_zellen_gfm(rest), zeilen[j]))
            tab["kanonisch"] = tab["kanonisch"] and _kanonisch(zeilen[j])
            tab["nummern"].add(j)
            j += 1
        tabellen.append(tab)
        i = j
    tabellen_zeilen = {n for t in tabellen for n in t["nummern"]}
    waisen = [(_zellen_gfm(_vorsatz(z)[1]), z, n) for n, z in enumerate(zeilen)
              if n not in tabellen_zeilen and not maske[n] and _vorsatz(z)[1].startswith("|")]
    return {"tabellen": tabellen, "waisen": waisen, "unlesbar": unlesbar}


def _kennung_der_zeile(zellen: list[str]) -> str | None:
    """The identifier that leads a row, read from its first cell as every reader here reads it,
    or None."""
    m = re.match(rf"^\**({_KENNUNG})", zellen[0]) if zellen else None
    return m.group(1) if m else None


def _lies_zweige(im_umfang: str) -> tuple[dict[str, list[str]], list[str], str | None]:
    """(branch -> identifiers, riders, why not measurable or None) over `_tabellen_gfm`.

    A TABLE WITHOUT A BRANCH COLUMN NAMES NO BRANCH. Its lines with an identifier ride along: they
    have no branch of their own, whatever their last cell holds. The line-by-line reader took a
    backticked last cell of ANY table for a branch, so `| P30 | `make release` |` under
    `| Item | Why |` became the branch `make release` (lens round 2, T3).

    A TABLE WITH A BRANCH COLUMN IS READ WHOLE OR NOT AT ALL. Not measurable, with the reason: a
    branch column that is not the last header cell or that stands in more than one cell; a table in
    a form other than `|` at both ends of every line, at the start of the line (the forms this
    reader does not read); a row with another number of cells than its header (GitHub pads or cuts
    it, so its branch cell is another cell); a row without a readable identifier (its branch would
    leave the count); a branch cell that is neither exactly one code span nor a rider of
    `_MITLAEUFER`.

    A LINE THAT LOOKS LIKE A ROW AND STANDS IN NO TABLE (a waise) is not measurable when it names a
    branch, in a code span or as a cell: GitHub shows it as text, and whether it is a scope line is
    not decided here. Without a branch, and with an identifier in its first cell, it rides along,
    as the line-by-line reader read it, so a row a blank line cut off from its table neither
    vanishes from the count nor turns an unstarted scope NOT MEASURABLE (lens round 2, T2)."""
    zu_zweig: dict[str, list[str]] = {}
    mitlaeufer: list[str] = []
    gelesen = _tabellen_gfm(im_umfang)
    if gelesen["unlesbar"]:
        return {}, [], gelesen["unlesbar"]
    koepfe = {t["kopf_nr"] for t in gelesen["tabellen"]}
    for zellen, z, nr in gelesen["waisen"]:
        if nr + 1 in koepfe and _zweigstellen(zellen):
            # A ROW GLUED ABOVE A HEADER THAT NAMES A BRANCH COLUMN (lens round 2, survivor L24).
            # GitHub takes only the line directly above the delimiter for the header and shows
            # this one as text, so the table below reads without a branch column; whoever wrote it
            # meant one.
            return {}, [], (f"the line {z.strip()[:60]!r} names a branch column and stands glued "
                            "above the header of a table, which GitHub shows as text; whether its "
                            "table assigns branches is not decided here")
        if (any(_ZWEIGFORM.match(c.strip(" ")) for c in re.findall(r"`([^`]+)`", z))
                or any(_ZWEIGFORM.match(c.strip("* ")) for c in zellen)):
            return {}, [], (f"the line {z.strip()[:60]!r} names a branch and stands in no table "
                            "GitHub renders (a blank line or another block cut it off); this "
                            "reader does not guess whether it is a scope line")
        if _kennung_der_zeile(zellen):
            mitlaeufer.append(_kennung_der_zeile(zellen))
    for tab in gelesen["tabellen"]:
        kopf, stellen = tab["kopf"], _zweigstellen(tab["kopf"])
        if not stellen:
            mitlaeufer += [k for k in (_kennung_der_zeile(zellen) for zellen, _z in tab["zeilen"])
                           if k]
            continue
        if any(i != len(kopf) - 1 for i in stellen) or len(stellen) > 1:
            i = next((i for i in stellen if i != len(kopf) - 1), stellen[0])
            return {}, [], (f"the table header {kopf} names a branch column in cell {i + 1} of "
                            f"{len(kopf)}, and this reader reads the last cell only, so the "
                            "branches of that column are not the ones it would read")
        if not tab["kanonisch"]:
            return {}, [], (f"a table whose header names a branch column is in a form this reader "
                            f"skips (header {kopf}); a row is read when it starts with `|` at the "
                            "start of its line and ends with `|`, and a row it skips is a branch "
                            "it never reads")
        for zellen, z in tab["zeilen"]:
            if len(zellen) != len(kopf):
                return {}, [], (f"the row {z.strip()[:60]!r} has {len(zellen)} cells under a "
                                f"header of {len(kopf)}; GitHub pads or cuts such a row, so its "
                                "branch cell is not the one this reader reads")
            kennung = _kennung_der_zeile(zellen)
            if not kennung:
                return {}, [], (f"the row {z.strip()[:60]!r} of a table with a branch column "
                                "carries no readable identifier in its first cell (ohne lesbare "
                                "Kennung); its branch would leave the count unread")
            zelle = zellen[stellen[0]]
            span = _CODESPAN.match(zelle)
            if span:
                # BRANCH -> IDENTIFIER, not the other way round. The reverse direction OVERWRITES
                # silently as soon as two lines carry the same identifier, and the 6.1.0 scope did
                # exactly that three times (A1, A2, A3).
                zu_zweig.setdefault(span.group(2).strip(" "), []).append(kennung)
            elif _MITLAEUFER.match(zelle):
                mitlaeufer.append(kennung)
            elif _ZWEIGFORM.match(zelle.strip("*")):
                return {}, [], (f"the branch cell {zelle!r} of {kennung} names a branch without "
                                "backticks; this reader reads a branch in backticks only and would "
                                "have read this line as a rider")
            else:
                return {}, [], (f"the branch cell {zelle!r} of {kennung} is neither one branch in "
                                "a code span nor a rider (`mit X`, `with X`, `= X`, identifiers, a "
                                "dash, n/a, or empty); this reader does not guess which")
    return zu_zweig, mitlaeufer, None


def _zweigspalte_unlesbar(im_umfang: str) -> str | None:
    """Why `lies_umfang` cannot read the In section, or None (the reason of `_lies_zweige`)."""
    return _lies_zweige(im_umfang)[2]


def _als_nicht_begonnen_ausgewiesen(text: str, im_umfang: str) -> bool:
    """True when the title of the file declares it not started AND no In table heads a branch column.

    The title is the first level-one heading. Both conditions are needed: the declaration alone
    would also cover a file whose branch column the reader cannot read, and that file must stay
    NOT MEASURABLE.

    A BRANCH COLUMN IN ANY POSITION COUNTS (Codex on pull request 327, P2, measured at its head):
    the first version looked only at the LAST header cell, the one `lies_umfang` reads, so a
    declared file headed `| Item | Branch | Why |` counted as having no branch column and its
    branch was judged outside the scope instead of NOT MEASURABLE.

    ONE READING OF A HEADER FOR THE RULE AND FOR THE READER (lens on pull request 328, 2026-10-18).
    The second version found headers by a word with boundaries, so `branch_name` and `Zweigname`
    slipped; it asked every row above a delimiter-shaped row, so a data row over `| - | - |` turned a
    real unstarted scope NOT MEASURABLE; it asked the last cell of EVERY row, so a data row ending in
    `Branch` did the same; and it read only rows that start with `|`, so a table in any other form
    was not seen. The third version took the first delimiter-shaped line of a block for the
    delimiter, so a decoy above the real header hid it (lens round 2, T1-A). Headers come from the
    tables of `_tabellen_gfm` now, the reader reads the same tables (`_lies_zweige`), and a file is
    declared not started only where no header of them names a branch column."""
    titel = next((z for z in text.splitlines() if z.startswith("# ")), "")
    if _NICHT_BEGONNEN not in titel:
        return False
    return not any(_zweigstellen(t["kopf"]) for t in _tabellen_gfm(im_umfang)["tabellen"])


def umfang_nicht_begonnen(pfad: pathlib.Path) -> bool:
    """Whether the scope file at `pfad` is read as a release that has not started: zero branches,
    measured. Callers use it to say so in their verdict instead of a bare "outside the scope"."""
    try:
        text = pfad.read_text(encoding="utf-8")
    except OSError:
        return False
    schnitt = _ENDE_DES_UMFANGS.search(text)
    if schnitt is None:
        return False
    zu_zweig, _mitlaeufer, zustand = lies_umfang(pfad)
    return (zustand == "gemessen" and not zu_zweig
            and _als_nicht_begonnen_ausgewiesen(text, text[: schnitt.start()]))


def fuehrende_kennungen(pfad: pathlib.Path) -> tuple[list[tuple[str, str, str]], str]:
    """Every In-line as (identifier, item, branch column) — LINE BY LINE, without collapsing.

    The counting unit is the LINE, not the identifier and not the branch. Measured on the 6.1.0
    scope: 56 lines, 56 distinct leading identifiers, 9 riders. Whoever counts by branch is short.

    THESE NUMBERS MOVED TWICE, and both moves are named because a stale number here teaches a
    wrong one. 55 lines / 52 identifiers held until 2026-09-18, when P19 landed with pull request
    224 and added one line. The identifiers caught up with the lines on 2026-09-19: three
    RESTRISIKO rows were renamed to R-A1, R-A2, R-A3 (owner card OA-23931230c0), which ended the
    only collision the file had. A number in a docstring is a claim about a measurement; when the
    measurement moves and the claim does not, the claim starts teaching the wrong thing.
    """
    try:
        text = pfad.read_text(encoding="utf-8")
    except OSError as e:
        return [], f"NICHT MESSBAR: {type(e).__name__}: {e}"
    schnitt = _ENDE_DES_UMFANGS.search(text)
    if schnitt is None:
        return [], ("NICHT MESSBAR: kein Abschnitt '## Out' gefunden — die Grenze des Umfangs ist "
                    "nicht bestimmbar")
    # THE SAME TABLES AS THE BRANCH READER (`_tabellen_gfm`), and the same lines: every row with an
    # identifier, of every table and every waise of the In section. The line-by-line count read
    # rows the page does not show as rows and skipped rows it does, so the card could count a
    # line the reader never saw, or miss one it did (lens on pull request 328, round 2, T1).
    gelesen = _tabellen_gfm(text[: schnitt.start()])
    if gelesen["unlesbar"]:
        return [], f"NICHT MESSBAR: {gelesen['unlesbar']}"
    aus: list[tuple[str, str, str]] = []
    for zellen, *_rest in [r for t in gelesen["tabellen"] for r in t["zeilen"]] + gelesen["waisen"]:
        kennung = _kennung_der_zeile(zellen)
        if kennung:
            aus.append((kennung, zellen[0], zellen[-1]))
    return aus, ("gemessen" if aus else "NICHT MESSBAR: keine Zeile im In-Abschnitt gefunden")


#: How many scope rows the last call examined. An empty finding list over ZERO examined rows and one
#: over forty are different facts, and this is where a caller can tell them apart.
ZULETZT_GEPRUEFT = 0


def zeilen_ohne_kennung(pfad: pathlib.Path) -> tuple[list[str], str]:
    """Every In-line whose first column carries NO identifier this module can read.

    THE CLASS, not the instance. Both readers above end their loop with "no match, next line".
    That is the quiet variant of a wrong answer: the line does not become a finding, it stops
    existing. The landing card then counts a scope it cannot see all of, and the count looks
    healthy because nothing complains.

    It was not a hypothetical. On 2026-09-19 the rename to R-A1, R-A2, R-A3 hit exactly this:
    the expression did not know the shape, three lines fell out of the count, and the file check
    answered GREEN -- the collision it was meant to report had disappeared along with the lines
    that caused it. Widening the expression fixes that one shape. This function is what catches
    the NEXT shape nobody thought of, because from here on an unreadable line is reported instead
    of dropped.
    """
    try:
        text = pfad.read_text(encoding="utf-8")
    except OSError as e:
        return [], f"NICHT MESSBAR: {type(e).__name__}: {e}"
    schnitt = _ENDE_DES_UMFANGS.search(text)
    if schnitt is None:
        return [], ("NICHT MESSBAR: kein Abschnitt '## Out' gefunden — die Grenze des Umfangs ist "
                    "nicht bestimmbar")
    aus: list[str] = []
    # ONLY TABLES THAT ASSIGN BRANCHES. The In section also carries the table of the three owner
    # decisions (Karte | Zeit | Entscheid), which names no branch and is not scope. A first
    # version checked every table row and reported eight findings on the only real file -- four
    # header rows and the three owner cards. A guard that fires eight times on the one input it
    # was written for is measuring its own reach, not the file. The header row names the column,
    # so the file itself says which table is which.
    #
    # THE HEADER WORD WAS GERMAN AND THE FILE IS ENGLISH, which made this guard blind on the only
    # file it guards. Measured 2026-09-20 by a counter-reading: `docs/release_scope/6.1.0.md` heads
    # its two In-tables with `| Identifier | PR | Merge commit | Title |` and
    # `| Identifier | Subject | Branch |`. Neither last column is `Zweig`, so `im_umfangstabelle`
    # never became True and this function returned an empty list for the whole file -- not because
    # nothing was unreadable, but because it never entered a table. A guard built against a line
    # that vanishes from a count had itself vanished, silently, at the translation.
    #
    # ZERO examined rows is its own state instead of an empty finding list that reads like a clean
    # one.
    #
    # THE SAME TABLES AS THE BRANCH READER, AND THE SAME HEADER WORD (lens on pull request 328,
    # round 2). A table assigns branches when a header cell carries the stem of `_ZWEIGSTAMM`, read
    # by `_zweigstellen` over the tables of `_tabellen_gfm`. The guard asked the last header cell
    # for one of two exact words, the reader asked every header cell for the stem, so a header
    # `Branch name` was a scope table to one and none to the other.
    global ZULETZT_GEPRUEFT
    gelesen = _tabellen_gfm(text[: schnitt.start()])
    if gelesen["unlesbar"]:
        ZULETZT_GEPRUEFT = 0
        return aus, f"NICHT MESSBAR: {gelesen['unlesbar']}"
    geprueft = 0
    for tab in gelesen["tabellen"]:
        if not _zweigstellen(tab["kopf"]):
            continue
        for zellen, _z in tab["zeilen"]:
            geprueft += 1
            if not _kennung_der_zeile(zellen):
                aus.append((zellen[0] if zellen else "")[:60])
    ZULETZT_GEPRUEFT = geprueft
    if geprueft == 0:
        return aus, ("NICHT MESSBAR: keine Zeile einer Umfangstabelle erreicht — kein Tabellenkopf "
                     f"nennt eine Zweigspalte (Stamm {_ZWEIGSTAMM.pattern!r}), es wurde nichts "
                     "geprueft")
    return aus, "gemessen"


def pruefe_umfangsdatei(pfad: pathlib.Path) -> dict:
    """The file itself: does every identifier lead EXACTLY ONE line?

    This is a statement about the FILE, not about a pull request, and it belongs separately: an
    identifier assigned twice is not a mistake by the author who dutifully writes it into their
    title — it merely makes their title ambiguous. The landing card counts landed lines from
    titles; two lines under one identifier become one there, and the other disappears from the
    number that is supposed to prove it landed.
    """
    zeilen, zustand = fuehrende_kennungen(pfad)
    if zustand != "gemessen":
        return {"schema": "b7n0de.release_scope_datei.v1", "urteil": "ROT",
                "gruende": [f"Umfangsdatei {pfad} {zustand}"], "zeilen": 0,
                "kennungen": 0, "kollisionen": {}}
    von_kennung: dict[str, list[str]] = {}
    for k, punkt, _z in zeilen:
        von_kennung.setdefault(k, []).append(punkt[:60])
    kollisionen = {k: v for k, v in von_kennung.items() if len(v) > 1}
    gruende = [f"Kennung {k!r} fuehrt {len(v)} Zeilen an {v} — ein Titel [{'<version>'} {k}] "
               "zeigt damit auf mehr als eine Zeile, und die Landekarte zaehlt sie als eine"
               for k, v in sorted(kollisionen.items())]
    # A LINE THIS MODULE CANNOT READ IS A FINDING, NOT AN ABSENCE. Without this, an unknown
    # identifier shape leaves the count silently and the verdict gets GREENER, not redder.
    # A GUARD THAT DID NOT RUN IS NOT A GUARD THAT FOUND NOTHING (the sweep for Codex round five on
    # pull request 294). The guard answers NOT MEASURABLE when no table header names a branch
    # column, and its empty list then says nothing about the rows it never reached.
    unlesbar, lage = zeilen_ohne_kennung(pfad)
    if lage != "gemessen":
        gruende.append(f"the guard against lines without a readable identifier did not run over "
                       f"this file ({lage}); a row it never reached is not a row it read")
    elif unlesbar:
        gruende.append(
            f"{len(unlesbar)} Zeile(n) des In-Abschnitts fuehren keine lesbare Kennung {unlesbar} "
            "— sie fallen aus der Zaehlung und die Landekarte kann sie nie zaehlen. Zu tun ist es "
            "in der Umfangsdatei oder am Kennungsmuster, nicht am Titel")
    return {
        "schema": "b7n0de.release_scope_datei.v1",
        "urteil": "gruen" if not gruende else "ROT",
        "gruende": gruende,
        "zeilen": len(zeilen),
        "kennungen": len(von_kennung),
        "zeilen_ohne_kennung": unlesbar,
        "kollisionen": {k: v for k, v in sorted(kollisionen.items())},
    }


def pruefe(*, branch: str, title: str, version: str,
           scope_pfad: pathlib.Path | None = None) -> dict:
    """The verdict. Two-valued, and every RED carries its reason."""
    pfad = scope_pfad or (REPO / "docs" / "release_scope" / f"{version}.md")
    zu_zweig, mitlaeufer, zustand = lies_umfang(pfad)
    gruende: list[str] = []
    if zustand != "gemessen":
        gruende.append(f"Umfangsdatei {pfad} {zustand} — ohne sie ist nicht messbar, ob dieser "
                       "Pull Request eine Umfangszeile traegt; Unkenntnis sperrt")
        return _urteil(branch, title, version, gruende, None, zu_zweig, mitlaeufer, zustand)

    passend = sorted(zu_zweig.get(branch) or [])
    if not passend:
        # NOT A PASS, BUT A STATEMENT ABOUT REACH. The caller should see that nothing was checked
        # here, rather than reading a green checkmark as a statement about the content. A scope
        # that has not started is named as such, so that "outside" is not read as a branch the
        # scope forgot.
        return _urteil(branch, title, version, [], None, zu_zweig, mitlaeufer, zustand,
                       ausserhalb=True,
                       nicht_begonnen=not zu_zweig and umfang_nicht_begonnen(pfad))
    if len(passend) > 1:
        gruende.append(f"der Zweig {branch!r} steht bei MEHREREN Umfangszeilen {passend} — "
                       "ein Zweig je Zeile, sonst zaehlt die Landekarte ihn doppelt oder gar nicht")
        return _urteil(branch, title, version, gruende, None, zu_zweig, mitlaeufer, zustand)

    kennung = passend[0]
    # AN UNREADABLE LINE IS A FINDING ABOUT THE FILE AND IT REACHES THE RUN. Reported in
    # `pruefe_umfangsdatei` alone it would never be seen: CI calls `main`, and `main` calls this
    # function. A guard nobody calls is the same shape of failure it exists to catch.
    unlesbar, _ul = zeilen_ohne_kennung(pfad)
    if _ul != "gemessen":
        gruende.append(f"the guard against lines without a readable identifier did not run over "
                       f"the scope file ({_ul}); a row it never reached is not a row it read")
    elif unlesbar:
        gruende.append(
            f"die Umfangsdatei fuehrt {len(unlesbar)} Zeile(n) ohne lesbare Kennung {unlesbar} — "
            "sie fallen aus der Zaehlung, und kein Titel kann je auf sie zeigen")
    # A collision is a finding about the FILE. It is recorded in the result, but is not held
    # against the pull request's author: they can only write the one identifier that exists.
    datei_urteil = pruefe_umfangsdatei(pfad)
    kollision = kennung in (datei_urteil.get("kollisionen") or {})
    # THE WHOLE FORM, AT THE START, EXACTLY ONE IDENTIFIER, in that order, because each step is
    # what makes the next one meaningful. First, how many identifier brackets does the title carry
    # at all, whatever their version. Then, does the title as a WHOLE match the contract form. Only
    # then, does it name the right identifier.
    alle_klammern = _JEDE_KLAMMER.findall(title)
    if len(alle_klammern) > 1:
        gruende.append(f"der Titel nennt {len(alle_klammern)} Kennungen {alle_klammern} — genau "
                       "eine je Pull Request, sonst ist die Zuordnung zur Umfangszeile mehrdeutig. "
                       "Gezaehlt werden ALLE Versionen, nicht nur die eigene: eine zweite Klammer "
                       "fremder Version macht den Titel genauso mehrdeutig")
    form = _TITELFORM.match(title)
    if not form and not alle_klammern:
        # THE MOST COMMON CASE DESERVES ITS OWN SENTENCE. A title with no bracket at all and a
        # title with a bracket in the wrong place are two different jobs for whoever has to fix
        # them, and one shared shape message for both leaves the author guessing which one they
        # have. An existing case asserted exactly this wording and fell when the two were folded
        # together, and it was right to.
        gruende.append(f"der Titel nennt keine Umfangskennung: erwartet [{version} {kennung}] "
                       f"am Anfang, gelesen {title!r}")
    elif not form:
        gruende.append(
            f"der Titel haelt die Form nicht ein: erwartet [{version} {kennung}] "
            f"type(scope): subject AM ANFANG, gelesen {title!r}. Geprueft wird der ganze Titel, "
            "nicht ob die Klammer irgendwo vorkommt")
    else:
        if form.group("version") != version:
            gruende.append(f"der Titel nennt die Version {form.group('version')!r}, geprueft wird "
                           f"gegen {version!r} — Titel und Umfangsdatei zeigen auf verschiedene "
                           "Releases")
        elif form.group("kennung") != kennung:
            gruende.append(f"der Titel nennt [{version} {form.group('kennung')}], der Zweig "
                           f"{branch!r} gehoert aber zu {kennung} — Titel und Zweig zeigen auf "
                           "verschiedene Zeilen")
    if kollision:
        # RED, and the foreign model family talked me around here (2026-09-16). My first version
        # let a pull request like this through green, with a note: the author can, after all,
        # only write the one identifier that exists. Their objection carries: the PURPOSE of this
        # gate is unambiguous countability, and a title the landing card cannot assign misses it —
        # whoever is at fault. Green here would mean: the pull request is fine, even though its
        # landing is not countable. And the fix stands open, it just is not in the title: split
        # the identifier in the scope file.
        zeilen = (pruefe_umfangsdatei(pfad).get("kollisionen") or {}).get(kennung, [])
        gruende.append(
            f"die Kennung {kennung!r} fuehrt {len(zeilen)} Zeilen der Umfangsdatei an {zeilen} — "
            "ein Titel mit ihr ist nicht zuordenbar, und die Landekarte zaehlt zwei Zeilen als "
            "eine. Zu tun ist es in der Umfangsdatei, nicht im Titel: die Kennung aufteilen")
    d = _urteil(branch, title, version, gruende, kennung, zu_zweig, mitlaeufer, zustand)
    d["kennung_mehrdeutig"] = kollision
    return d


def _urteil(branch, title, version, gruende, kennung, zu_zweig, mitlaeufer, zustand,
            *, ausserhalb: bool = False, nicht_begonnen: bool = False) -> dict:
    gruen = not gruende
    return {
        "schema": "b7n0de.release_scope_title_gate.v1",
        "version": version, "branch": branch, "title": title,
        "urteil": "gruen" if gruen else "ROT",
        "gruende": gruende,
        "kennung_des_zweigs": kennung,
        "ausserhalb_des_umfangs": ausserhalb,
        "umfang_nicht_begonnen": nicht_begonnen,
        "umfang_zustand": zustand,
        "umfangszeilen_mit_zweig": len(zu_zweig),
        "mitlaeufer_ohne_zweig": sorted(mitlaeufer),
        # EXPLICITLY STATED, so that nobody reads more into it than is there.
        "geprueft_wird": "der head-Zweig gegen die Umfangsdatei, NICHT der Diff",
        "nicht_geprueft": ("ob ein Pull Request auf einem nicht genannten Zweig inhaltlich eine "
                           "Umfangszeile beruehrt — das entscheidet dieser Riegel nicht"),
    }


def _nach_dem_zweig(branch: str, kandidaten: list[str], herkunft: str) -> tuple[str | None, str]:
    """Without a source tag this clone shows, the release is chosen by the branch: the one
    candidate whose scope file names it. A branch named by two candidates is ambiguous and not
    measurable; a branch named by none is outside every candidate, and the newest candidate
    reports that.

    A CANDIDATE THIS GATE CANNOT READ DECIDES NOTHING (Codex on pull request 294, round five, P1).
    `lies_umfang` returns an empty mapping together with its NOT MEASURABLE, and this function kept
    the mapping only. Measured at 76f260a2: a 6.2.0 scope naming `fix/a1` without its `## Out`, and a
    readable 6.3.0 scope, judged `fix/a1` against 6.3.0, outside the scope, exit 0. Whether an
    unreadable scope names the branch is not known, so the release is not decided, whichever
    candidate it is and whichever branch is asked about."""
    treffer = []
    for v in kandidaten:
        zu_zweig, _mitlaeufer, zustand = lies_umfang(REPO / "docs" / "release_scope" / f"{v}.md")
        if zustand != "gemessen":
            return None, (f"{herkunft}; the scope file of candidate {v} cannot be read here "
                          f"({zustand}), so whether it names the branch {branch!r} is not known")
        if branch in zu_zweig:
            treffer.append(v)
    if len(treffer) > 1:
        return None, (f"{herkunft}; the branch {branch!r} stands in the scope files of {treffer}, "
                      "so which release it belongs to is not decided")
    gewaehlt = treffer[0] if treffer else kandidaten[-1]
    grund = (f"it stands in the scope file of {gewaehlt} only" if treffer
             else f"it stands in none of {kandidaten}")
    return gewaehlt, f"{herkunft}; judged by the branch: {grund}"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--branch", required=True, help="der head-Zweig des Pull Requests")
    p.add_argument("--title", required=True, help="der Titel des Pull Requests")
    p.add_argument("--version", default=None,
                   help="the release whose scope file judges the title; without it, the oldest "
                        "scope file above the source version in pyproject.toml")
    p.add_argument("--scope", default=None, help="Pfad der Umfangsdatei (sonst aus --version)")
    p.add_argument("--json", action="store_true")
    a = p.parse_args(argv)
    if a.version is None:
        version, herkunft = naechste_umfangsversion()
        kandidaten = umfangskandidaten_ohne_tags() if version is None else []
        if kandidaten:
            version, herkunft = _nach_dem_zweig(a.branch, kandidaten, herkunft)
    else:
        version, herkunft = a.version, "argument --version"
    if version is None:
        # RED, like a missing scope file: without a release to judge against, whether this pull
        # request carries a scope line is not measurable, and not knowing blocks.
        d = _urteil(a.branch, a.title, None,
                    [f"{herkunft}; without a release to judge against, whether this pull request "
                     "carries a scope line is not measurable, and not knowing blocks"],
                    None, {}, [], herkunft)
    else:
        d = pruefe(branch=a.branch, title=a.title, version=version,
                   scope_pfad=pathlib.Path(a.scope) if a.scope else None)
    d["version_herkunft"] = herkunft
    if a.json:
        print(json.dumps(d, ensure_ascii=False, indent=2))
    else:
        marke = "ausserhalb des Umfangs" if d["ausserhalb_des_umfangs"] else (
            d["kennung_des_zweigs"] or "—")
        print(f"release-scope-title: {d['urteil']} · {d['branch']} · {marke}")
        print(f"  version: {d['version']} ({herkunft})")
        if d.get("umfang_nicht_begonnen"):
            print(f"  the scope file of {d['version']} declares itself not started and names no "
                  f"branch, so every branch lies outside its scope")
        for g in d["gruende"]:
            print(f"  ! {g}")
        print(f"  geprueft: {d['geprueft_wird']}")
    return 0 if d["urteil"] == "gruen" else 1


if __name__ == "__main__":
    raise SystemExit(main())
