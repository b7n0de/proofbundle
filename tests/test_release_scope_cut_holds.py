"""The 6.2.0 cut names what the decisions put in it, and every citation in it can be checked.

A review of pull request 294 at 351fce0c reported four classes. Each was re-measured at that commit
before it was fixed, and each has a case here that fails at 351fce0c and passes on the commit that
fixed it; the commit message records both runs.

1. A LIST THAT A DECISION SETS, AND A FILE THAT RECORDS IT, DIVERGE. The cut named neither pull
   request 296, which the owner added to 6.2.0 on the day of the cut, nor #295, which landed on
   main that day. Its counts agreed with its own list, so no count could show the gap; only a
   comparison with the decision can. Pull request 296 was corrected after its review, and the cut
   records it at that head, the one open branch with a head; the head has to lie on its branch.
2. A CITED COMMIT RESOLVES ONLY WITH HISTORY A READER MAY NOT HAVE. The P29 row cited the commit
   that added the conformance harness. It is older than `v6.1.0`, no tag points at it, and a
   shallow clone cannot resolve it (git exits 128), which is how the review met it.
3. A `path:line` REFERENCE POINTS AT OTHER CODE THAN IT NAMES. The R-B4 row quotes three line
   numbers of `src/proofbundle/intoto.py` that were true at `v6.1.0` and hold other code on the
   head of the cut. The quoted text may not change, so the tree they belong to has to be named.
4. A DEFAULT RELEASE NUMBER GOES STALE AT ITS RELEASE. The title gate and the landing card read
   6.1.0 when no version was given, the scope of a release that was already out.

A review of caccdbad reported two more, both P1. Both were measured at caccdbad and at fc1596e5
before they were fixed, and the cases of section 5 fail there and pass on the commit that fixed
them.

5. THE COMMIT READER KNEW ONE WRITTEN FORM. It read lower-case hex only and had no branch for any
   other spelling: git resolves `0ACE3039`, and the reader returned no commit for it, so a commit
   written in upper case that resolves to nothing left every check green. Git reads a hex object
   name in any case, and so does the reader now; a word that looks like a commit and is no form it
   checks is named, never read as no commit.
6. A `path:line` REFERENCE WITHOUT BACKTICKS WAS NOT READ. The reference reader took its tokens
   from backticked spans only, so a line number written in plain prose pointed wherever it pointed
   and nothing checked it. Both are read in one grammar now, and a token that begins like a
   reference and is none of its forms is refused with its name.

A second owner decision of 2026-09-27, recorded at 20:16 UTC, moved three of the frozen fixes, on
six branches, to 6.3.0; a later word froze pull request 296 at the head its last correction left.
Section 1 holds the cut to both in both directions: a moved branch is named nowhere but in the
section of the moved fixes and is not counted among the frozen fixes, a staying one does not stand
under Out, each moved branch stands with the head it moved at, and 296 stands with its frozen head
and as not landed.

A review of 989b582c reported three more blind spots of these readers, each P1, and section 6
has a case for each that fails at 989b582c and passes on the commit that fixed it:

7. THE UNIT SPLITTER DROPPED EVERY LINE THAT STARTS WITH `#`. Headings, and prose lines such as
   "#296 stood at ...", were never read, so a commit that does not resolve or a wrong `path:line`
   on such a line passed. Every line outside a fenced block now belongs to exactly one unit, and a
   fence that never closes is refused.
8. A `path:line` WHOSE PATH STARTS WITH `.` OR HAS NO EXTENSION was neither read nor refused
   (`.github/...:9999`, `./RESTRISIKO_610.md:1-5`, `Makefile:12`). Both are read now.
9. A BRANCH NAME WITHOUT BACKTICKS WAS NOT READ in the sections that decide what is in and out, so a
   moved branch written plainly among the frozen fixes, or a staying one under Out, passed. Branch
   names are read in every spelling, and a moved branch may stand nowhere but under Out.

A review of 346fa924 reported two more, both P1, and each has a case that fails there and passes on
the commit that fixed it:

10. A `path:line` REFERENCE THAT NAMES A TREE WAS CHECKED IN THE WORKING TREE FIRST, so a stale
    citation passed whenever its needle happened to stand at those lines of the checkout. A unit
    that names a tag or a commit is checked in the named trees only now.
11. A BUMPED SOURCE VERSION WAS READ AS A RELEASE THAT IS OUT. RELEASE.md bumps the version in the
    release-prep pull request and tags after the merge, so with `pyproject.toml` at 6.2.0 the gate
    judged 6.3.0 and a 6.2.0 correction came back outside the scope. The tag decides now; where no
    tag can be read, the branch decides between the two candidates.

A review of 5a9ddc06 reported three more, two P1 and one P2, and section 7 has a case for each that
fails at 5a9ddc06 and passes on the commit that fixed it:

12. A TAG THIS CLONE DOES NOT SHOW WAS READ AS A TAG THAT DOES NOT EXIST. `git tag --list` lists
    the tags a clone holds, so with the source at 6.2.0 and only `v6.1.0` fetched, the gate judged
    6.2.0, and a branch that only the 6.3.0 scope names passed outside the scope. Only a tag the
    clone shows decides now; without it the branch decides between the two candidates, and the
    landing card, which has no branch to choose by, is NOT MEASURABLE.
13. A `path:line` REFERENCE PASSED IN ANY TREE ITS UNIT NAMES. A reference is bound to its own tree
    now: the tree named in its own sentence, else the tree its unit names for its path ("the path
    at the tree"), else the working tree where the unit names no tree at all. A reference in a
    unit that names trees and none of them for it is a finding; the cut's R1 and R-B4 rows had one
    each, both lines true in every tree the rows name, and now name `v6.1.0` for them.
14. A FULL CLONE WITHOUT TAGS FAILED THE CASE THAT HOLDS THE LIST OF MAIN AGAINST GIT. It skips
    there now and names the tag it did not have.

A review of 76f260a2 reported one P1, the last round of this pull request, and section 8 has a
case for it and for the two neighbours the sweep found; each fails at 76f260a2 and passes on the
commit that fixed it:

15. AN UNREADABLE CANDIDATE SCOPE WAS READ AS ONE THAT NAMES NOTHING. Without a tag the clone
    shows, the gate judges a branch by the candidate that names it, and a candidate it could not
    read (no `## Out`) answered with an empty mapping, so a branch it names was judged against the
    other candidate and passed outside the scope. An unreadable candidate leaves the release
    undecided now.
16. THE GUARD AGAINST UNREADABLE LINES SAID NOT MEASURABLE AND ITS CALLERS HEARD NOTHING. Both
    callers kept its list and dropped its state, so a scope whose branch column is not headed
    `Branch` or `Zweig` let a row without an identifier vanish in green.
17. THE LANDING CARD DROPPED THE STATE OF THE BRANCH READER, so a scope whose branches it could not
    read counted every line as a rider and answered measured.

The same review's P2, that a shallow clone passes the case that holds the list of main against git
without comparing anything, is recorded in `RESTRISIKO_620.md` and not fixed at this head.

WHAT THIS FILE DOES NOT CHECK: the older scope files (6.1.0 and before), which are records of
their own cuts; whether a reference names the RIGHT symbol, beyond that the symbol it names
stands in the lines it points at; and fenced blocks, which quote tool output and artefact digests
rather than cite. The symbols a reference is checked for are those of its whole row or paragraph,
not of its sentence: the R1 row names what stands at its register lines in the sentence before
the one that cites them, so a sentence-bound reading would refuse a correct row.
"""
from __future__ import annotations

import bisect
import importlib.util
import json
import os
import pathlib
import re
import shutil
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
SCOPE_DIR = REPO / "docs" / "release_scope"
CUT = SCOPE_DIR / "6.2.0.md"
NEXT = SCOPE_DIR / "6.3.0.md"
SCOPE_FILES = (CUT, NEXT)


# -- shared readers ----------------------------------------------------------------------------

def _git(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(REPO), *args], capture_output=True, text=True,
                          timeout=120)


def _commit(rev: str) -> str | None:
    """The full commit a revision names here, or None when this clone cannot resolve it."""
    r = _git("rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}")
    return r.stdout.strip() if r.returncode == 0 and r.stdout.strip() else None


def _is_ancestor(older: str, newer: str) -> bool:
    return _git("merge-base", "--is-ancestor", older, newer).returncode == 0


def _full_history_or_skip() -> None:
    """A clone that is shallow, or no git at all, cannot answer questions about ancestry.

    The skip names that, because a case that cannot measure and says nothing reads like a pass.
    The CI test job checks out with the full history and the tags, so there these cases measure.
    """
    r = _git("rev-parse", "--is-shallow-repository")
    if r.returncode != 0 or r.stdout.strip() != "false":
        pytest.skip(f"NOT MEASURED: no full git history here ({(r.stdout + r.stderr).strip()!r})")


_HEADING = re.compile(r"^#{1,6}(?:[ \t]|$)")


class UnreadableText(AssertionError):
    """Text the unit splitter would have to drop without reading it."""


def _units(text: str) -> list[str]:
    """Table rows and headings one by one, list items with their continuation lines, paragraphs.

    A row or an item is the unit a citation belongs to: a tag named in the same row as a commit is
    the tag that commit is cited as. EVERY LINE OUTSIDE A FENCED BLOCK BELONGS TO EXACTLY ONE UNIT,
    because every reader of this file reads units and nothing else: a line this function drops is
    a line no check sees. A Markdown heading (one to six `#` and a space) is a unit of its own; a
    line that starts with `#` and is no heading, as in "#296 stood at ...", is prose and stays in
    its paragraph. Fenced blocks are left out, because they quote measurements (artefact digests
    among them), not citations; a fence that is opened and never closed would drop the rest of the
    file, so it raises with the line it was opened on.
    """
    units: list[str] = []
    current: list[str] = []
    fence = 0

    def flush() -> None:
        if current:
            units.append("\n".join(current))
            current.clear()

    for number, line in enumerate(text.splitlines(), 1):
        if line.strip().startswith("```"):
            flush()
            fence = 0 if fence else number
            continue
        if fence:
            continue
        if not line.strip():
            flush()
            continue
        if line.startswith("|") or _HEADING.match(line):
            flush()
            units.append(line)
            continue
        if line.startswith("- "):
            flush()
        current.append(line)
    if fence:
        raise UnreadableText(f"the fenced block opened at line {fence} is never closed, so every "
                             f"line after it would go unread")
    flush()
    return units


def _section(text: str, heading_word: str) -> str:
    """The text under the first `## ` heading that contains `heading_word`, up to the next one."""
    m = re.search(rf"(?m)^## [^\n]*{re.escape(heading_word)}[^\n]*\n", text)
    assert m, f"no `## ` heading containing {heading_word!r}: the section this case reads is gone"
    rest = text[m.end():]
    ende = re.search(r"(?m)^## ", rest)
    return rest[: ende.start()] if ende else rest


def _outside(text: str, heading_word: str) -> str:
    """The text without the section `_section` would return; the whole text when there is none."""
    m = re.search(rf"(?m)^## [^\n]*{re.escape(heading_word)}[^\n]*\n", text)
    if not m:
        return text
    ende = re.search(r"(?m)^## ", text[m.end():])
    return text[: m.start()] + (text[m.end() + ende.start():] if ende else "")


def _outside_open(text: str) -> str:
    """The text without the two sections that record heads of open branches: the frozen fixes, and
    the fixes moved to 6.3.0 (`_MOVED`)."""
    return _outside(_outside(text, "frozen fix"), _MOVED)


def _cells(row: str) -> list[str]:
    return [c.strip() for c in row.strip().strip("|").split("|")]


_WORD = re.compile(r"[0-9A-Za-z_]+")
_HEX_WORD = re.compile(r"[0-9A-Fa-f]{7,40}")
_HEX_RUN = re.compile(r"[0-9A-Fa-f]{7,}")
_TAG = re.compile(r"`(v[0-9]+(?:\.[0-9]+)+)`")

#: Words git would read as a hex object name that the scope files use as names, by their exact
#: spelling, each with what it names. It is the one way past the commit reader, so a case below
#: holds every entry to it: it stands in a scope file, and it resolves to no commit.
NOT_A_COMMIT = {
    "Ed25519": "the signature scheme, in the title of pull request 280 in the list of main",
}


class UnreadableCommitWord(AssertionError):
    """A word that looks like a commit reference and is none of the forms the reader checks."""


_NUMBER_WORDS = {w: i for i, w in enumerate(
    "zero one two three four five six seven eight nine ten eleven twelve".split())}


def _number(word: str) -> int:
    """A count as the prose writes it; -1 for a word this reader does not know, which then fails
    the comparison it is used in rather than raising."""
    return int(word) if word.isdigit() else _NUMBER_WORDS.get(word.lower(), -1)


def _flat(text: str) -> str:
    """Prose with its line breaks read as spaces: a sentence the file wraps is one sentence."""
    return re.sub(r"\s+", " ", text)


def _commit_words(unit: str) -> list[tuple[str, str]]:
    """(as written, as git reads it) for every commit reference of a unit.

    Git reads a hex object name in any case. So every word of 7 to 40 hex digits is a commit
    reference, backticked or not, in upper, lower or mixed case, all digits or all letters, and it
    is returned lower-cased, the form git prints. A word in `NOT_A_COMMIT` is skipped by its exact
    spelling. A word that looks like a commit reference and is none of these is not passed over:
    a run of 7 or more hex digits, holding a digit and a letter, that is not a whole word of 7 to
    40 (glued to other characters, or longer than 40 digits) raises with the word named.
    """
    return [(written, read) for written, read, _ in _commit_words_at(unit)]


def _commit_words_at(unit: str) -> list[tuple[str, str, int]]:
    """`_commit_words` with the offset of each word in the unit, so a commit can be placed in the
    sentence that names it (`_bound_trees`)."""
    out = []
    for m in _WORD.finditer(unit):
        word = m.group()
        if word in NOT_A_COMMIT:
            continue
        if _HEX_WORD.fullmatch(word):
            out.append((word, word.lower(), m.start()))
            continue
        for run in _HEX_RUN.findall(word):
            if re.search(r"[0-9]", run) and re.search(r"[A-Fa-f]", run):
                why = ("it is longer than a commit id" if run == word else
                       f"its hex run {run!r} is glued to other characters")
                raise UnreadableCommitWord(f"{word!r} looks like a commit reference and is none "
                                           f"of the forms this reader checks: {why}")
    return out


def _cited_commits(unit: str) -> list[str]:
    """Every commit reference of a unit as git reads it, lower-cased; see `_commit_words`."""
    return [h for _, h in _commit_words(unit)]


# -- 1. every open frozen fix the decisions put into 6.2.0 is named, and the counts match ----------

#: THE DECISION'S SIDE OF THE COMPARISON, typed here on purpose. Derived from the file, it would
#: agree with the file by construction, and the omission this case exists for would pass.
#:
#: What it holds: the open fix branches of the owner's decision of 2026-09-27, 10:04 UTC, option A,
#: as the cut first recorded them (c38fe56d to 351fce0c), plus the addition of the same day, pull
#: request 296, minus the six branches the decision of 20:16 UTC moved to 6.3.0 (`MOVED_HEADS`).
#: The pull request number stands where the decision or the addition gave one; the branch then has
#: to stand in the same row or item as its number.
DECIDED_OPEN = {
    "fix/the-commit-pattern-holds-at-the-verify-boundary": None,
    "fix/a-small-order-key-is-refused-at-every-carrier": 293,
    "fix/a-resolver-promotes-only-on-exact-true": 291,
    "fix/a70-clean-tree-before-binding": 249,
    "claude/cargo-audit-rust-parity": 296,
}

#: The one open branch that stays in 6.2.0 and that the cut records at a head: pull request 296,
#: FROZEN at the head its last correction left and NOT LANDED (owner word of 2026-09-27), read with
#: `git ls-remote` when the cut recorded it. The item has to say both (`_HEAD_STATE`). Every other
#: staying branch stands without a digest, which is the file's rule.
DECIDED_HEADS = {
    "claude/cargo-audit-rust-parity": "2cf9908f8235116a50f424aa43b7ea0828545e16",
}

#: THE DECISION OF 2026-09-27, 20:16 UTC: the six branches of three frozen fixes that left 6.2.0
#: for 6.3.0, each with the head read with `git ls-remote` when the cut recorded the move. Typed
#: here for the same reason as `DECIDED_OPEN`: read from the file, it would agree by construction.
MOVED_HEADS = {
    "fix/every-constant-lookup-on-a-foreign-key-is-classified":
        "eb08ddbcc23955640390f30d68fbc71c92386ffb",
    "fix/script-patterns-end-at-the-value-and-read-githubs-whitespace":
        "184644f6332c44cbba50c76715589ed4eb5f8ccb",
    "fix/whole-value-patterns-read-ascii-digits": "90c5ab485360e364edf380db906170d00b691f3d",
    "fix/a-diff-is-read-in-gits-grammar": "948e4cf2c236801d820d9e5585825a19c5fb3234",
    "fix/the-mutant-guard-reads-a-quoted-path": "f8f1e9e4c768c1777b2a5afd4e7bb52aafcb19c5",
    "fix/git-paths-are-read-as-git-names-them": "6ceb2a15bd77513a025e3ec7e0daddb7d7fd3b1b",
}

#: The heading word of the section that records the move.
_MOVED = "three frozen fixes moved"

#: The other addition of that day, which landed before the cut was written up: the ECDSA
#: inventory, pull request 295. It belongs in the list of what is on main, not among the frozen.
DECIDED_LANDED = (295,)

_BRANCH = re.compile(r"^[a-z0-9]+/[a-z0-9][a-z0-9._-]*$")
_FILE_SUFFIX = re.compile(r"\.(?:py|md|json|toml|ya?ml|txt|cff|rs|html)$")

#: The words a staying branch's recorded head has to stand with: the head is final for this
#: release, and the branch is not yet on main (owner word of 2026-09-27: 296 frozen, not landed).
_HEAD_STATE = ("frozen at", "has not landed")


def _names_branch(unit: str, branch: str) -> bool:
    """Whether a unit names a branch, in any spelling: backticked or plain, in bold, inside a link,
    before a full stop. The name has to stand whole, with no name character on either side."""
    return re.search(rf"(?<![A-Za-z0-9_.-]){re.escape(branch)}(?![A-Za-z0-9_/-]|\.[A-Za-z0-9_-])",
                     unit) is not None


def _branches(unit: str) -> list[str]:
    """Every branch a unit names, once each: the branches of the decisions in any spelling, and
    every other token, backticked or plain, that has the form of a branch and is no file path.

    The first form of these readers took branch names from backticked spans only, so a moved branch
    written plainly among the frozen fixes, or a staying one written plainly under Out, was never
    read and the cut passed. A spelling does not decide whether a branch is named.
    """
    found = [t for t, _ in _tokens(unit) if _BRANCH.match(t) and not _FILE_SUFFIX.search(t)]
    found += [b for b in (*DECIDED_OPEN, *MOVED_HEADS) if _names_branch(unit, b)]
    return list(dict.fromkeys(found))


def _sections(text: str) -> list[tuple[str, str]]:
    """(heading line, text under it) for the text before the first `## ` heading, whose heading is
    empty, and for every `## ` section."""
    parts = re.split(r"(?m)^(## [^\n]*)\n", text)
    return [("", parts[0])] + [(parts[i], parts[i + 1]) for i in range(1, len(parts) - 1, 2)]


def _frozen_fixes(text: str) -> tuple[list[str], list[list[str]], list[str]]:
    """(branches of the table rows, branches per list item, the units) of the frozen section."""
    units = _units(_section(text, "frozen fix"))
    rows, items = [], []
    for unit in units:
        if unit.startswith("|"):
            rows += _branches(_cells(unit)[-1])
        elif unit.startswith("- "):
            branches = _branches(unit)
            if branches:
                items.append(branches)
    return rows, items, units


def frozen_fix_findings(text: str) -> list[str]:
    """Every way the frozen section disagrees with the decision or with its own counts."""
    rows, items, units = _frozen_fixes(text)
    findings = []
    named = (set(rows) | {b for item in items for b in item}
             | {b for u in units for b in _branches(u)})
    for branch, number in DECIDED_OPEN.items():
        if branch not in named:
            findings.append(f"the decision puts {branch} into 6.2.0 and the cut does not name it")
        elif number is not None and not any(_names_branch(u, branch) and f"pull request {number}"
                                            in u for u in units):
            findings.append(f"{branch} stands without its pull request {number} beside it")
    for branch, head in DECIDED_HEADS.items():
        unit = next((u for u in units if _names_branch(u, branch)), "")
        if not any(len(h) >= 8 and head.startswith(h) for h in _cited_commits(unit)):
            findings.append(f"{branch} is frozen at {head} and the cut does not record that head")
        missing = [w for w in _HEAD_STATE if w not in _flat(unit)]
        if unit and missing:
            findings.append(f"{branch} is recorded at a head without the words {missing}")
    for branch in MOVED_HEADS:
        if branch in named:
            findings.append(f"{branch} moved to 6.3.0 and is still counted among the frozen fixes")
    for unit in units:
        heads = [DECIDED_HEADS[b] for b in DECIDED_HEADS if _names_branch(unit, b)]
        for h in _cited_commits(unit):
            if not any(head.startswith(h) for head in heads):
                findings.append(f"an open frozen branch carries a digest ({h}) that is not a head "
                                f"the decision recorded; the file's rule is that none stands while "
                                f"the branch is open")
    section = _flat(_section(text, "frozen fix"))
    subjects, branches = len(items), sum(len(i) for i in items)
    m = re.search(r"(\w+) of them carry a line of this file", section)
    if not m or _number(m.group(1)) != len(rows):
        findings.append(f"the prose counts {m.group(1) if m else 'no'} rows with a line, the table "
                        f"has {len(rows)}")
    m = re.search(r"The other (\w+) carry no line", section)
    if not m or _number(m.group(1)) != subjects:
        findings.append(f"the prose counts {m.group(1) if m else 'no'} other subjects, the list "
                        f"has {subjects}")
    m = re.search(r"these (\w+) branches", section)
    if not m or _number(m.group(1)) != branches:
        findings.append(f"the prose counts {m.group(1) if m else 'no'} branches, the list has "
                        f"{branches}")
    m = re.search(r"(?m)^\| Frozen fixes without a scope row \| (\d+) subjects on (\d+) branches",
                  text)
    if not m or (int(m.group(1)), int(m.group(2))) != (subjects, branches):
        findings.append(f"the accounting reads {m.group(0) if m else 'no row'}, the list has "
                        f"{subjects} subjects on {branches} branches")
    return findings


def moved_findings(text: str) -> list[str]:
    """Every way the section of the moved fixes disagrees with the decision or with its counts.

    A moved branch must stand there with the head it moved at, beside its own name, and nowhere
    else in the file; a branch that stays in 6.2.0 must not stand under any Out section; and no
    digest may stand there that is not a moved head, so the head of a staying branch cannot be
    filed under Out either. Branch names are read in every spelling (`_branches`).
    """
    units = _units(_section(text, _MOVED))
    items = [u for u in units if u.startswith("- ") and _branches(u)]
    findings = []
    for branch, head in MOVED_HEADS.items():
        unit = next((u for u in items if _names_branch(u, branch)), None)
        if unit is None:
            findings.append(f"the decision moved {branch} to 6.3.0 and the section does not "
                            f"name it")
            continue
        beside = re.search(rf"(?<![A-Za-z0-9_.-])`?{re.escape(branch)}`?\s+at\s+`?"
                           rf"([0-9A-Fa-f]{{7,40}})(?![0-9A-Za-z])", unit)
        if not beside or len(beside[1]) < 8 or not head.startswith(beside[1].lower()):
            findings.append(f"{branch} moved at {head} and the section does not record that head "
                            f"beside it ({beside[1] if beside else 'none'})")
    for heading, body in _sections(text):
        where = heading or "the text before the first section"
        for unit in _units(f"{heading}\n{body}" if heading else body):
            for branch in _branches(unit):
                if branch in MOVED_HEADS and _MOVED not in heading:
                    findings.append(f"{branch} moved to 6.3.0 and stands outside the section of "
                                    f"the moved fixes, in {where!r}")
                if branch in DECIDED_OPEN and heading.startswith("## Out"):
                    findings.append(f"{branch} stays in 6.2.0 and stands under Out, in {where!r}")
    moved = set(MOVED_HEADS.values())
    for unit in units:
        for h in _cited_commits(unit):
            if not any(m.startswith(h) for m in moved):
                findings.append(f"a digest under Out ({h}) is no head the decision moved")
    branches = sum(len(_branches(u)) for u in items)
    m = re.search(r"(?m)^\| Frozen fixes moved to 6\.3\.0 \| (\d+) subjects on (\d+) branches",
                  text)
    if not m or (int(m[1]), int(m[2])) != (len(items), branches):
        findings.append(f"the accounting reads {m[0] if m else 'no row'}, the section has "
                        f"{len(items)} subjects on {branches} branches")
    return findings


def _on_main_list(text: str) -> list[tuple[int, str]]:
    return [(int(n), h) for n, h in
            re.findall(r"(?m)^- #([0-9]+) `([0-9A-Fa-f]{7,40})` ",
                       _section(text, "what is on main"))]


def test_every_open_frozen_fix_the_decisions_name_is_in_the_cut_and_the_counts_match():
    findings = frozen_fix_findings(CUT.read_text(encoding="utf-8"))
    assert not findings, "\n".join(findings)


def test_the_moved_fixes_stand_under_out_with_their_heads_and_nowhere_in():
    assert not set(DECIDED_OPEN) & set(MOVED_HEADS), "a branch is typed as staying and as moved"
    findings = moved_findings(CUT.read_text(encoding="utf-8"))
    assert not findings, "\n".join(findings)


def test_catch_proof_in_and_out_cannot_trade_places():
    """Six plants, each on its own copy of the cut. A moved branch put back among the frozen fixes;
    a staying branch put under Out; the head of 296 put under Out in place of a moved head; a moved
    item dropped; and the head of 296 no longer said to be frozen, or said to have landed. Each must
    become a finding."""
    text = CUT.read_text(encoding="utf-8")
    moved, stays = "fix/the-mutant-guard-reads-a-quoted-path", "fix/a70-clean-tree-before-binding"
    out = _section(text, _MOVED)

    def under_out(old: str, new: str) -> str:
        assert old in out, f"{old!r} is not under Out, so there is nothing to plant on"
        return text.replace(out, out.replace(old, new))

    back_in = text.replace(f"`{stays}`.", f"`{stays}`, with `{moved}`.")
    assert back_in != text
    assert any(f"{moved} moved to 6.3.0 and is still counted" in f
               for f in frozen_fix_findings(back_in))
    found = moved_findings(under_out("both ancestors of it.",
                                     f"both ancestors of it, and `{stays}`."))
    assert any(f"{stays} stays in 6.2.0 and stands under Out" in f for f in found), found
    in_head = DECIDED_HEADS["claude/cargo-audit-rust-parity"]
    found = moved_findings(under_out(MOVED_HEADS[moved], in_head))
    assert any(f"a digest under Out ({in_head})" in f for f in found), found
    assert any(f"{moved} moved at" in f for f in found), found
    item = next(u for u in _units(out) if "`fix/every-constant-lookup-on-a-foreign-key" in u)
    found = moved_findings(under_out(item + "\n", ""))
    assert any("does not name it" in f for f in found), found
    assert any("the accounting reads" in f for f in found), found
    for old, new, word in (("It is frozen at", "It stood at", "frozen at"),
                           ("It has not landed", "It has landed", "has not landed")):
        changed = text.replace(old, new)
        assert changed != text, f"{old!r} is not in the cut, so there is nothing to plant on"
        found = frozen_fix_findings(changed)
        assert any("without the words" in f and repr(word) in f for f in found), (old, found)


def test_what_landed_on_the_day_of_the_cut_is_in_the_list_of_main_and_the_counts_match():
    text = CUT.read_text(encoding="utf-8")
    entries = _on_main_list(text)
    numbers = [n for n, _ in entries]
    for n in DECIDED_LANDED:
        assert n in numbers, f"#{n} landed on main with the decision's addition and is not listed"
    head = re.search(r"at `([0-9A-Fa-f]{7,40})`: ([0-9]+) commits since `(v[0-9.]+)`, ([0-9]+) of "
                     r"them on the first-parent line\. All ([0-9]+) are pull requests: ([0-9]+) "
                     r"spelled `Merge pull request #N`, ([0-9]+) spelled `… \(#N\)`, and (\w+) "
                     r"squash", _flat(text))
    assert head, "the sentence that states the counts of the list is gone"
    base, total, since, fp, fp2, merges, squashed, plain = head.groups()
    assert int(fp) == int(fp2) == len(entries) == int(merges) + int(squashed) + _number(plain), (
        f"stated {fp}/{fp2} = {merges} + {squashed} + {plain}, listed {len(entries)}")
    # WITH HISTORY, the list is held against git itself, not only against its own sentence.
    if _git("rev-parse", "--is-shallow-repository").stdout.strip() != "false":
        return
    base_c, since_c = _commit(base), _commit(since)
    # A FULL CLONE MAY HOLD NO TAG (`git clone --no-tags`; Codex on pull request 294, round four,
    # P2). History alone does not give the release tag, so the comparison with git is not measured
    # there, and the skip says so. The commit of main is no tag, and a full clone has it.
    if since_c is None:
        pytest.skip(f"NOT MEASURED: the release tag {since} is not in this clone, so the list of "
                    f"main is held against its own sentence only, not against git")
    assert base_c, f"{base} does not resolve in a full clone"
    assert int(_git("rev-list", "--count", f"{since_c}..{base_c}").stdout) == int(total)
    fp_commits = _git("log", "--first-parent", "--format=%H", f"{since_c}..{base_c}").stdout.split()
    assert len(fp_commits) == int(fp)
    listed = {_commit(h) for _, h in entries}
    assert listed == set(fp_commits), "the list and the first-parent line differ"
    for n, h in entries:
        if n in DECIDED_LANDED:
            subject = _git("log", "-1", "--format=%s", h).stdout
            assert f"#{n}" in subject, f"#{n} is listed with {h}, whose subject is {subject!r}"


def test_catch_proof_a_dropped_frozen_fix_is_found():
    """Planted: the item of pull request 296 removed. The case above must see it."""
    text = CUT.read_text(encoding="utf-8")
    item = next((u for u in _units(_section(text, "frozen fix"))
                 if "`claude/cargo-audit-rust-parity`" in u), None)
    assert item, "the item of pull request 296 is not in the cut, so there is nothing to plant on"
    planted = text.replace(item + "\n", "")
    assert planted != text, "the plant did not take, so this case would prove nothing"
    findings = frozen_fix_findings(planted)
    assert any("claude/cargo-audit-rust-parity" in f for f in findings), findings
    assert any("the list has" in f for f in findings), findings


def test_catch_proof_a_wrong_head_and_a_digest_on_another_branch_are_found():
    """Planted twice: the recorded head of 296 swapped for another digest, and a digest put beside
    a branch the decision records without one. Both must become findings."""
    text = CUT.read_text(encoding="utf-8")
    head = DECIDED_HEADS["claude/cargo-audit-rust-parity"]
    assert head in text, "the head is not in the cut, so there is nothing to plant on"
    other = "0123456789abcdef0123456789abcdef01234567"
    swapped = frozen_fix_findings(text.replace(head, other))
    assert any("does not record that head" in f for f in swapped), swapped
    assert any(other in f for f in swapped), swapped
    beside = frozen_fix_findings(text.replace("`fix/a70-clean-tree-before-binding`.",
                                              f"`fix/a70-clean-tree-before-binding` at `{other}`."))
    assert any(other in f for f in beside), beside


def test_the_frozen_head_lies_on_its_branch():
    """A recorded head is a record only while it can be recomputed: it has to resolve, and where
    this clone carries the branch, the branch has to stand at it or have grown from it. That holds
    for the open head of 296 and for the heads the moved fixes left at."""
    text = CUT.read_text(encoding="utf-8")
    measured = []
    for branch, head in {**DECIDED_HEADS, **MOVED_HEADS}.items():
        assert head in text.lower(), f"{branch}: the cut does not carry the head {head}"
        if _commit(head) is None:
            continue
        tip = _commit(f"refs/remotes/origin/{branch}")
        if tip is None:
            continue
        assert _is_ancestor(head, tip), f"{branch} stands at {tip}, which did not grow from {head}"
        measured.append(branch)
    if not measured:
        pytest.skip(f"NOT MEASURED: no recorded head and its branch are both in this clone "
                    f"({sorted(DECIDED_HEADS)})")


# -- 2. every cited commit resolves, and none needs history older than the file's base -------------

def _base_tag(text: str, name: str) -> str:
    """The release the file measures from, in its own words: "since `vX.Y.Z`". Exactly one."""
    bases = set(re.findall(r"since `(v[0-9]+(?:\.[0-9]+)+)`", text))
    assert len(bases) == 1, f"{name} names {sorted(bases) or 'no'} base release; expected one"
    return bases.pop()


def commits_needing_old_history(text: str, base: str, head: str) -> list[str]:
    """Cited commits a clone with the history since `base` and the named tags cannot resolve.

    A commit is fine when it lies between the base release and the head, or when it is the commit
    of a release tag named in the same row, item or paragraph: a tag and its tree can be fetched at
    depth 1 (`git fetch --depth 1 origin tag <tag>`), a commit inside older history cannot.
    """
    out = []
    for unit in _units(text):
        tags = {c for t in _TAG.findall(unit) if (c := _commit(t))}
        for h in _cited_commits(unit):
            full = _commit(h)
            if full is None:
                continue                      # the case below reports it, with its reason
            if _is_ancestor(full, head) and not _is_ancestor(full, base):
                continue
            if full in tags:
                continue
            out.append(f"{h}: older than the base and not the commit of a tag named beside it")
    return out


def test_every_cited_commit_resolves_and_is_an_ancestor_of_the_cut_head():
    """Every commit outside the frozen section and the section of the moved fixes. A head recorded
    there is the head of an open branch and by nature not an ancestor of the cut; those have their
    own cases above."""
    _full_history_or_skip()
    head = _commit("HEAD")
    seen, problems = 0, []
    for path in SCOPE_FILES:
        for unit in _units(_outside_open(path.read_text(encoding="utf-8"))):
            for written, h in _commit_words(unit):
                seen += 1
                full = _commit(h)
                if full is None:
                    problems.append(f"{path.name}: {written} does not resolve to a commit")
                elif not _is_ancestor(full, head):
                    problems.append(f"{path.name}: {written} is not an ancestor of the head")
    assert seen > 10, f"only {seen} cited commits read: the reader is not reading the files"
    assert not problems, "\n".join(problems)


def test_every_commit_like_word_of_the_scope_files_is_read():
    """Without git, and the frozen section included: every unit of both files goes through the
    commit reader, which names a word it cannot classify instead of reading it as no commit."""
    read = sum(len(_commit_words(unit)) for path in SCOPE_FILES
               for unit in _units(path.read_text(encoding="utf-8")))
    assert read > 10, f"only {read} commit references read: the reader is not reading the files"


def test_a_word_the_reader_takes_for_a_name_stands_in_the_files_and_names_no_commit():
    """`NOT_A_COMMIT` is the one way past the reader, so each entry is held to what it claims: it
    stands in a scope file as spelled, it is skipped only in that spelling, and where this clone has
    the history it resolves to no commit."""
    texts = "\n".join(p.read_text(encoding="utf-8") for p in SCOPE_FILES)
    for word, what in NOT_A_COMMIT.items():
        assert re.search(rf"(?<![0-9A-Za-z_]){re.escape(word)}(?![0-9A-Za-z_])", texts), (
            f"{word} ({what}) stands in no scope file, so its entry lets nothing past")
        assert _cited_commits(f"an {word} key") == [], word
        assert _cited_commits(f"an {word.upper()} key") == [word.lower()], word
    if _git("rev-parse", "--is-shallow-repository").stdout.strip() == "false":
        for word in NOT_A_COMMIT:
            assert _commit(word) is None, f"{word} resolves to a commit here; it is not only a name"


def test_no_cited_commit_needs_history_older_than_the_files_base():
    _full_history_or_skip()
    head = _commit("HEAD")
    problems = []
    for path in SCOPE_FILES:
        text = path.read_text(encoding="utf-8")
        tag = _base_tag(text, path.name)
        base = _commit(tag)
        if base is None:
            pytest.skip(f"NOT MEASURED: the tag {tag} is not in this clone")
        outside = _outside_open(text)
        problems += [f"{path.name}: {p}" for p in commits_needing_old_history(outside, base, head)]
    assert not problems, "\n".join(problems)


def test_catch_proof_an_old_commit_is_found_and_a_named_tag_is_not():
    _full_history_or_skip()
    base = _commit("v6.1.0")
    if base is None:
        pytest.skip("NOT MEASURED: the tag v6.1.0 is not in this clone")
    head = _commit("HEAD")
    older = _commit("v6.1.0^")
    assert older and not _is_ancestor(base, older), "the plant needs a commit older than v6.1.0"
    # Full SHAs, so that no plant is a prefix git finds ambiguous.
    assert commits_needing_old_history(f"the harness arrived with {older}.\n", base, head)
    assert commits_needing_old_history(f"the release commit (`{base}`).\n", base, head)
    assert not commits_needing_old_history(f"the tag `v6.1.0` (`{base}`).\n", base, head)
    assert not commits_needing_old_history(f"the head `{head}`.\n", base, head)


# -- 3. every path:line reference points at the symbol it names, in the tree it names --------------

#: A path as a reference writes it: it may start with `.` (`.github/...`, `./RESTRISIKO_610.md`)
#: and need not carry an extension (`Makefile`). A reference's path must hold a letter, so a time
#: of day (`20:16`) is no reference.
_PATH = r"[A-Za-z0-9_.][A-Za-z0-9_./-]*"
_REF = re.compile(rf"^(?P<path>{_PATH}):(?P<a>[0-9]+)(?:-(?P<b>[0-9]+))?$")
_CONT = re.compile(r"^:(?P<a>[0-9]+)(?:-(?P<b>[0-9]+))?$")
_FILE = re.compile(rf"^{_PATH}\.[A-Za-z0-9]+$")
#: What begins a reference anywhere in a token: a run of path characters holding a letter, at the
#: token's start or after a character that is no path character, then a colon and a digit; or the
#: token's start, a colon and a digit. A token holding it that is no whole reference is refused by
#: name.
_REF_LIKE = re.compile(r"(?:^|[^A-Za-z0-9_./-])(?=[A-Za-z0-9_./-]*[A-Za-z])[A-Za-z0-9_./-]+:[0-9]"
                       r"|^:[0-9]")
_OPEN, _CLOSE = "`([{<\"'*", "`)]}>\"',.;:!?*"


def _is_path(token: str) -> bool:
    return (bool(re.match(rf"^{_PATH}$", token))
            and ("/" in token or bool(_FILE_SUFFIX.search(token))))


def _plain_words(unit: str, start: int, end: int) -> list[tuple[str, bool, int]]:
    """(word, False, offset) for every whitespace-separated word of `unit[start:end]`, with the
    punctuation around it taken off."""
    out = []
    for raw in re.finditer(r"\S+", unit[start:end]):
        word = raw.group().lstrip(_OPEN).rstrip(_CLOSE)
        if word:
            out.append((word, False, start + raw.start()))
    return out


def _tokens_at(unit: str) -> list[tuple[str, bool, int]]:
    """(token, backticked, offset) in the order the unit writes them; see `_tokens`. The offset of a
    backticked token is that of its opening backtick."""
    out: list[tuple[str, bool, int]] = []
    pos = 0
    for m in re.finditer(r"`([^`]+)`", unit):
        out += _plain_words(unit, pos, m.start())
        out.append((m.group(1), True, m.start()))
        pos = m.end()
    return out + _plain_words(unit, pos, len(unit))


def _tokens(unit: str) -> list[tuple[str, bool]]:
    """(token, backticked) in the order the unit writes them.

    Every backticked span is one token. Between the spans every whitespace-separated word is one,
    with the punctuation around it taken off, so a reference written in plain prose is the same
    reference as its backticked form and is not passed over for want of backticks.
    """
    return [(token, ticked) for token, ticked, _ in _tokens_at(unit)]


def _references_at(unit: str) -> tuple[list[tuple[str, int, int, int]], list[str], list[str]]:
    """(references with the offset each is written at, needles, refused) of one unit; the reading
    is `_references`."""
    refs, needles, refused = [], [], []
    last_path = None
    for token, ticked, at in _tokens_at(unit):
        m = _REF.match(token)
        if m and re.search(r"[A-Za-z]", m["path"]):
            if ".." in m["path"].split("/"):
                refused.append(f"{token!r} names a path outside the repository")
                continue
            last_path = m["path"]
            refs.append((m["path"], int(m["a"]), int(m["b"] or m["a"]), at))
            continue
        m = _CONT.match(token)
        if m:
            if last_path:
                refs.append((last_path, int(m["a"]), int(m["b"] or m["a"]), at))
            else:
                refused.append(f"{token!r} continues a path, and no path is named before it")
            continue
        if _REF_LIKE.search(token):
            refused.append(f"{token!r} reads like a path:line reference and is none of the forms "
                           f"this reader checks (`path:N`, `path:N-M`, `:N` after a path)")
            continue
        if not ticked:
            if _FILE.match(token) and _is_path(token):
                last_path = token
            continue
        if _TAG.fullmatch(f"`{token}`"):
            continue                          # a tag names a tree, not a symbol
        if _is_path(token):
            last_path = token
            continue
        if _cited_commits(token) == [token.lower()] or token in ("main", "HEAD"):
            continue                          # a commit or a branch names a tree, not a symbol
        needles += [p.strip() for p in token.split(" / ") if len(p.strip()) >= 3]
    return refs, needles, refused


def _references(unit: str) -> tuple[list[tuple[str, int, int]], list[str], list[str], list[str]]:
    """(references, needles, trees, refused) of one unit.

    A reference is `path:N` or `path:N-M`, and a bare `:N` continues the last path named before it,
    as in "`src/proofbundle/intoto.py` (`:246`, `:424`)". It is read in one grammar with or without
    backticks, and a plain path with an extension counts as the last path named. A path may start
    with `.` and need not have an extension; one that climbs out of the repository with `..` is
    refused. A token that begins like a reference and is none of these forms, or a `:N` with no path
    before it, is refused with its name. A needle is every other backticked name in the unit, split
    at " / ", that is neither a path nor a tree: what the unit says stands there. The trees are
    every tag or commit the unit names, by name; which of them a reference is checked in is decided
    per reference (`_bound_trees`), and a unit that names none is checked in the working tree.
    """
    refs, needles, refused = _references_at(unit)
    trees = [name for group, _ in _trees_at(unit) for name in group]
    return [(p, a, b) for p, a, b, _ in refs], needles, trees, refused


#: A release tag written with its commit, "`v6.1.0` (`dcac5aee`)": ONE tree under two names.
_TAG_AND_COMMIT = re.compile(r"`(v[0-9]+(?:\.[0-9]+)+)`\s*\(`([0-9A-Fa-f]{7,40})`\)")

#: How a unit names the tree of a path's line numbers apart from the sentence that cites them, the
#: form the R-B4 row of the cut uses: the path in backticks, the word "at", and a tree, which is a
#: tag, a tag with its commit in parentheses, or a commit ("`src/proofbundle/intoto.py` at `v6.1.0`
#: (`dcac5aee`)").
_DECLARED = re.compile(rf"`(?P<path>{_PATH})`\s+at\s+`(?P<tree>v[0-9]+(?:\.[0-9]+)+|"
                       rf"[0-9A-Fa-f]{{7,40}})`(?:\s*\(`(?P<commit>[0-9A-Fa-f]{{7,40}})`\))?")


def _trees_at(unit: str) -> list[tuple[tuple[str, ...], int]]:
    """(names, offset) for every tree a unit names, in the order it names them: a backticked release
    tag, a commit word, and a tag written with its commit (`_TAG_AND_COMMIT`), which is one tree
    with two names. The offset is that of the first character of the first name."""
    pairs = {m.start(1): (m[1], m[2].lower()) for m in _TAG_AND_COMMIT.finditer(unit)}
    paired = {m.start(2) for m in _TAG_AND_COMMIT.finditer(unit)}
    out = [(pairs.get(at + 1, (token,)), at + 1) for token, ticked, at in _tokens_at(unit)
           if ticked and _TAG.fullmatch(f"`{token}`")]
    out += [((read,), at) for _, read, at in _commit_words_at(unit) if at not in paired]
    return sorted(out, key=lambda tree: tree[1])


def _declared(unit: str) -> list[tuple[str, tuple[str, ...], int]]:
    """(path, tree names, offset of the tree) for every "`path` at `tree`" of a unit (`_DECLARED`).
    A leading `./` of the path is dropped, as `_lines_at` drops it."""
    out = []
    for m in _DECLARED.finditer(unit):
        if not _is_path(m["path"]):
            continue
        path = m["path"][2:] if m["path"].startswith("./") else m["path"]
        tree = m["tree"] if m["tree"].startswith("v") else m["tree"].lower()
        out.append((path, (tree, m["commit"].lower()) if m["commit"] else (tree,), m.start("tree")))
    return out


def _sentence_ends(unit: str) -> list[int]:
    """The offsets at which the sentences of a unit end: every `|`, which ends a table cell, and
    every `.`, `!` or `?` outside a backticked span that white space or the end of the unit follows.

    A full stop inside a word such as "e.g." ends a sentence too early. That can part a citation
    from the tree beside it, which makes a finding, never a pass."""
    masked = re.sub(r"`[^`]+`", lambda m: "x" * len(m.group()), unit)
    return [i for i, ch in enumerate(masked)
            if ch == "|" or (ch in ".!?" and (i + 1 == len(masked) or masked[i + 1].isspace()))]


def _bound_trees(path: str, at: int, trees: list[tuple[tuple[str, ...], int]],
                 declared: list[tuple[str, tuple[str, ...], int]], ends: list[int]
                 ) -> tuple[list[tuple[str, ...] | None], str]:
    """(the trees a reference at offset `at` is checked in, in each of them; or [] and why).

    A REFERENCE IS BOUND TO THE TREE ITS OWN TEXT NAMES, not to every tree of its unit (Codex on
    pull request 294, round four, P1). Measured at 5a9ddc06: a unit citing `MATCH` at `file.py:1`
    in the tree `abcdef0`, and naming the comparison tree `1234567` as well, passed with `OTHER` at
    `abcdef0:file.py:1`, because `1234567` held `MATCH` there and any tree of the unit could answer.
    The R-B4 row of the cut cites seven lines and names six trees, so a stale line could stay green
    because another named revision happened to match. The binding, in this order:

    1. the trees named in the reference's own sentence (`_sentence_ends`), except a tree the unit
       names for another path ("`other.py` at `abc1234`"); the reference must hold in each;
    2. else the one tree its unit names for its path ("`path` at `tree`", `_DECLARED`), which is how
       the R-B4 row binds the three line numbers its quoted middle column may not change;
    3. else, when the unit names no tree at all, the working tree, as before;
    4. else no tree: the unit names trees and does not say which one this reference belongs to, and
       choosing one would be the guess this binding exists to end. That is a finding.
    """
    rel = path[2:] if path.startswith("./") else path
    for_other = {offset for p, _, offset in declared if p != rel}
    sentence = bisect.bisect_left(ends, at)
    own = [names for names, offset in trees
           if bisect.bisect_left(ends, offset) == sentence and offset not in for_other]
    if own:
        return list(dict.fromkeys(own)), ""
    mine = list(dict.fromkeys(names for p, names, _ in declared if p == rel))
    if len(mine) == 1:
        return mine, ""
    if mine:
        return [], (f"cites no tree in its own sentence, and its unit names {len(mine)} trees "
                    f"for `{path}` ({[' / '.join(t) for t in mine]}), so which one it belongs to "
                    f"is not stated")
    if not trees:
        return [None], ""
    named = sorted({name for names, _ in trees for name in names})
    return [], (f"names no tree in its own sentence, and its unit names the trees {named}; which "
                f"of them its lines are those of is not stated (name the tree in its sentence, or "
                f"write `{path}` at `<tree>` in its unit)")


def _lines_at(tree: str | None, path: str) -> list[str] | None:
    """The lines of a file in the working tree or in a commit's tree; None when it is no file
    there. A leading `./` names the repository root, as it does for git."""
    rel = path[2:] if path.startswith("./") else path
    if tree is None:
        p = REPO / rel
        return p.read_text(encoding="utf-8").splitlines() if p.is_file() else None
    r = _git("cat-file", "blob", f"{tree}:{rel}")
    return r.stdout.splitlines() if r.returncode == 0 else None


def reference_findings(text: str) -> tuple[list[str], list[str]]:
    """(findings, not measured here) for every path:line reference of one scope file.

    Each reference is checked in the trees `_bound_trees` binds it to and must hold in each of
    them. A tag written with its commit is one tree: it is measured where either name resolves, and
    two names that resolve to two commits are a finding. A bound tree no name of which resolves in
    this clone is not measured here, and says so.
    """
    findings, unmeasured = [], []
    for unit in _units(text):
        refs, needles, refused = _references_at(unit)
        findings += refused
        if not refs:
            continue
        trees, declared, ends = _trees_at(unit), _declared(unit), _sentence_ends(unit)
        for path, a, b, at in refs:
            where = f"{path}:{a}-{b}"
            if not needles:
                findings.append(f"{where} stands in a unit that names nothing to find there")
                continue
            bound, why = _bound_trees(path, at, trees, declared, ends)
            if not bound:
                findings.append(f"{where} {why}")
            for names in bound:
                if names is None:
                    tree, named = None, "the working tree"
                else:
                    named = "the tree " + " / ".join(names)
                    commits = {n: c for n in names if (c := _commit(n))}
                    if len(set(commits.values())) > 1:
                        findings.append(f"{where} is bound to {named}, and its names are two "
                                        f"commits ({commits})")
                        continue
                    if not commits:
                        unmeasured.append(f"{where} ({named} is not in this clone)")
                        continue
                    tree = next(iter(commits.values()))
                lines = _lines_at(tree, path)
                span = "\n".join(lines[a - 1:b]) if lines and b <= len(lines) else None
                if span is not None and any(n in span for n in needles):
                    continue
                if lines is None:
                    findings.append(f"{where} names no file in {named}")
                else:
                    findings.append(f"{where} holds none of {needles[:6]} in {named}")
    return findings, unmeasured


def test_every_path_line_reference_points_at_what_it_names():
    findings, unmeasured = [], []
    for path in SCOPE_FILES:
        f, u = reference_findings(path.read_text(encoding="utf-8"))
        findings += [f"{path.name}: {x}" for x in f]
        unmeasured += [f"{path.name}: {x}" for x in u]
    assert not findings, "\n".join(findings)
    if unmeasured:
        pytest.skip("NOT MEASURED here: " + "; ".join(unmeasured))


def test_the_reader_sees_every_reference_of_the_cut():
    """Without this, a reader that found no reference at all would pass the case above. Eight is
    what the cut carried before this fix added three, so the floor holds on both sides of it."""
    refs = [r for u in _units(CUT.read_text(encoding="utf-8")) for r in _references(u)[0]]
    paths = {p for p, _, _ in refs}
    assert {"src/proofbundle/intoto.py", "RESTRISIKO_610.md", "RESTRISIKO_600.md"} <= paths, refs
    assert len(refs) >= 8, refs


def test_catch_proof_a_reference_moved_to_other_lines_is_found():
    text = CUT.read_text(encoding="utf-8")
    planted = text.replace("`RESTRISIKO_610.md:91-108`", "`RESTRISIKO_610.md:1-5`")
    assert planted != text, "the plant did not take"
    findings, _ = reference_findings(planted)
    assert any("RESTRISIKO_610.md:1-5" in f for f in findings), findings


def test_RED_a_reference_that_names_a_tree_is_checked_in_that_tree_only(monkeypatch):
    """Codex on pull request 294, round three, P1, and its measurement taken over: the working tree
    holds `MATCH` at `file.py:1`, the named tree `abcdef0` holds `OTHER`. At 346fa924 the unit that
    names `abcdef0` passed, because the working tree was always searched first. The controls: the
    same unit with the named tree holding `MATCH` passes, and a unit that names no tree is checked
    in the working tree."""
    trees = {None: ["MATCH"], "abcdef0": ["OTHER"]}
    monkeypatch.setitem(globals(), "_lines_at", lambda tree, path: trees.get(tree))
    monkeypatch.setitem(globals(), "_commit", lambda rev: rev if rev == "abcdef0" else None)
    unit = "`MATCH` stands at `file.py:1` in tree `abcdef0`."
    findings, unmeasured = reference_findings(unit)
    assert any(f.startswith("file.py:1-1 holds none of") and "abcdef0" in f for f in findings), (
        findings, unmeasured)
    trees["abcdef0"] = ["MATCH"]
    assert reference_findings(unit) == ([], [])
    trees["abcdef0"] = ["OTHER"]
    assert reference_findings("`MATCH` stands at `file.py:1`.") == ([], [])


def test_the_quoted_middle_column_is_still_the_previous_version_word_for_word():
    """THE CONSTRAINT THE FIX HAD TO KEEP. The file's rule is that the middle column quotes the
    previous version, so a stale line number there is corrected beside it, never inside it."""
    text = CUT.read_text(encoding="utf-8")
    m = re.search(r"stands in the history of this file at `([0-9A-Fa-f]{7,40})`", text)
    assert m, "the file no longer names the commit of its previous version"
    old = _git("show", f"{m.group(1)}:docs/release_scope/6.2.0.md")
    if old.returncode != 0:
        pytest.skip(f"NOT MEASURED: {m.group(1)} is not in this clone")
    before = {c[0]: c[1] for c in (_cells(r) for r in old.stdout.splitlines() if r.startswith("| "))
              if len(c) >= 2}
    checked = 0
    for row in (u for u in _units(_section(text, "what is on main") + _section(text, "frozen fix"))
                if u.startswith("| ")):
        cells = _cells(row)
        if len(cells) < 3 or cells[0] not in before:
            continue
        checked += 1
        assert cells[1] == before[cells[0]] or cells[1].startswith(before[cells[0]] + " "), (
            f"{cells[0]}: the middle column is no longer the previous version's text")
    assert checked >= 10, f"only {checked} quoted rows compared"


# -- 4. without a version, the gate and the card read the release being built ----------------------

_SCOPE_STUB = ("# Release scope - {v}\n\n## In\n\n"
               "| Identifier | Subject | Branch |\n|---|---|---|\n"
               "| A1 | something | `fix/a1` |\n\n## Out\n")


def _tree(tmp_path: pathlib.Path, source_version: str, scopes: tuple[str, ...],
          tags: tuple[str, ...] | None = None, branches: dict[str, str] | None = None
          ) -> pathlib.Path:
    """A throwaway repository root: the two scripts and the version reader they load, as they are,
    a pyproject, some scope files. With `tags` it is a git repository with one commit carrying those
    release tags (an empty tuple: a repository with no tag); without, it is no repository at all,
    like a checkout whose tags cannot be read. `branches` gives a scope file its own branch instead
    of `fix/a1`."""
    root = tmp_path / "tree"
    (root / "scripts").mkdir(parents=True)
    for name in ("b7_release_scope_title_gate.py", "b7_release_scope_landing_card.py",
                 "check_version_and_changelog.py"):
        shutil.copy2(REPO / "scripts" / name, root / "scripts" / name)
    (root / "pyproject.toml").write_text(
        f'[project]\nname = "probe"\nversion = "{source_version}"\n', encoding="utf-8")
    (root / "docs" / "release_scope").mkdir(parents=True)
    for v in scopes:
        text = _SCOPE_STUB.format(v=v)
        if branches and v in branches:
            text = text.replace("`fix/a1`", f"`{branches[v]}`")
        (root / "docs" / "release_scope" / f"{v}.md").write_text(text, encoding="utf-8")
    if tags is not None:
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        for args in (["init", "-q"], ["add", "-A"], ["commit", "-qm", "probe"],
                     *(["tag", t] for t in tags)):
            subprocess.run(["git", "-C", str(root), "-c", "user.name=t", "-c", "user.email=t@t",
                            "-c", "commit.gpgsign=false", *args], check=True, capture_output=True,
                           env=env, timeout=60)
    return root


def _load(path: pathlib.Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _gate_without_version(root: pathlib.Path, capsys) -> tuple[int, dict]:
    gate = _load(root / "scripts" / "b7_release_scope_title_gate.py", f"gate_{id(root)}")
    rc = gate.main(["--branch", "fix/a1", "--title", "[0.0.0 A1] fix(x): y", "--json"])
    return rc, json.loads(capsys.readouterr().out)


def _card_without_version(root: pathlib.Path, monkeypatch) -> dict:
    card = _load(root / "scripts" / "b7_release_scope_landing_card.py", f"card_{id(root)}")
    monkeypatch.setattr(card, "_gelandete_titel", lambda *a, **k: ([], "measured"))
    return card.karte()


SCOPES = ("3.7.1", "6.1.0", "6.2.0", "6.3.0")


#: The release tags of the throwaway trees: every release up to the one named is out.
_TAGS_UP_TO = {"6.1.0": ("v3.7.1", "v6.0.0", "v6.1.0"),
               "6.2.0": ("v3.7.1", "v6.0.0", "v6.1.0", "v6.2.0"),
               "6.3.0": ("v3.7.1", "v6.0.0", "v6.1.0", "v6.2.0", "v6.3.0")}


@pytest.mark.parametrize("source,tags,expected", [("6.1.0", _TAGS_UP_TO["6.1.0"], "6.2.0"),
                                                  ("6.2.0", _TAGS_UP_TO["6.2.0"], "6.3.0"),
                                                  ("6.1.0.post1", _TAGS_UP_TO["6.1.0"], "6.2.0"),
                                                  ("6.1.0.post1", None, "6.2.0")])
def test_without_a_version_the_gate_judges_the_oldest_scope_above_a_tagged_source(
        tmp_path, capsys, source, tags, expected):
    """Not the release that is out, not the release after next, not 3.7.1, a patch scope that never
    shipped. The second row is the next release: the answer moves with the source version. A
    post-release says its base release is out, with or without readable tags."""
    _rc, d = _gate_without_version(_tree(tmp_path, source, SCOPES, tags), capsys)
    assert d["version"] == expected, d


@pytest.mark.parametrize("source,expected", [("6.1.0", "6.2.0"), ("6.2.0", "6.3.0")])
def test_without_a_version_the_card_counts_the_same_release(tmp_path, monkeypatch, source,
                                                             expected):
    d = _card_without_version(_tree(tmp_path, source, SCOPES, _TAGS_UP_TO[source]), monkeypatch)
    assert d.get("version") == expected, d


def test_RED_a_bumped_source_without_its_tag_is_the_release_being_built(tmp_path, capsys,
                                                                        monkeypatch):
    """Codex on pull request 294, round three, P1. RELEASE.md bumps the version inside the
    release-prep pull request and tags after the merge. With pyproject.toml at 6.2.0 and no tag
    v6.2.0, a 6.2.0 correction must be judged against 6.2.0; at 346fa924 the gate and the card
    both judged 6.3.0, and the correction came back outside the scope and green.

    Since round four the missing tag decides nothing by itself (a tag this clone does not show
    may exist upstream), so the gate judges the branch by the candidate that names it, here 6.2.0,
    and the card, which has no branch to choose by, is NOT MEASURABLE rather than counting 6.2.0.
    The 6.3.0 scope carries its own branch, as a real one does; the case where both candidates
    name the branch is in the tagless case below."""
    root = _tree(tmp_path, "6.2.0", SCOPES, _TAGS_UP_TO["6.1.0"], {"6.3.0": "fix/b1"})
    rc, d = _gate_without_version(root, capsys)
    assert d["version"] == "6.2.0", d
    assert rc == 1 and not d["ausserhalb_des_umfangs"], d
    card = _card_without_version(root, monkeypatch)
    assert card["zustand"] == "NOT MEASURABLE" and "v6.2.0" in card["grund"], card


def test_without_readable_tags_the_gate_judges_the_branch_by_the_scope_that_names_it(
        tmp_path, capsys, monkeypatch):
    """A clone that shows no release tag (the CI checkout at depth 1) cannot tell bumped from
    tagged. The gate then judges a branch by whichever candidate names it, refuses a branch both
    name, and the card is NOT MEASURABLE rather than guessing."""
    root = _tree(tmp_path, "6.2.0", ("6.1.0", "6.2.0", "6.3.0"), None,
                 {"6.2.0": "fix/a1", "6.3.0": "fix/b1", "6.1.0": "fix/old"})
    gate = _load(root / "scripts" / "b7_release_scope_title_gate.py", "gate_tagless")
    for branch, title, version, rc_expected in (("fix/a1", "[6.2.0 A1] fix(x): y", "6.2.0", 0),
                                                ("fix/b1", "[6.3.0 A1] fix(x): y", "6.3.0", 0),
                                                ("fix/a1", "[6.3.0 A1] fix(x): y", "6.2.0", 1)):
        rc = gate.main(["--branch", branch, "--title", title, "--json"])
        d = json.loads(capsys.readouterr().out)
        assert (d["version"], rc) == (version, rc_expected), (branch, title, d)
        assert "judged by the branch" in d["version_herkunft"], d
    card = _card_without_version(root, monkeypatch)
    assert card["zustand"] == "NOT MEASURABLE" and "tagged" in json.dumps(card), card
    both = _tree(tmp_path / "both", "6.2.0", ("6.2.0", "6.3.0"), None)
    rc, d = _gate_without_version(both, capsys)
    assert rc == 1 and any("not decided" in g for g in d["gruende"]), d


@pytest.mark.parametrize("source,tags", [("6.3.0", _TAGS_UP_TO["6.3.0"]), ("6.2.0rc1", None),
                                         ("not-a-version", None)])
def test_without_a_scope_above_a_released_source_both_refuse(tmp_path, capsys, monkeypatch, source,
                                                              tags):
    """No scope file above a source that is out, or a source that is no released version: the gate
    is RED with the reason and the card NOT MEASURABLE. Neither falls back to a scope that is out."""
    root = _tree(tmp_path, source, SCOPES, tags)
    rc, d = _gate_without_version(root, capsys)
    assert rc == 1 and d["urteil"] == "ROT", d
    assert any("NOT MEASURABLE" in g for g in d["gruende"]), d["gruende"]
    card = _card_without_version(root, monkeypatch)
    assert card["zustand"] == "NOT MEASURABLE" and card["rc"] == 2, card


def test_an_explicit_version_still_wins(tmp_path, capsys):
    gate = _load(_tree(tmp_path, "6.1.0", SCOPES) / "scripts" / "b7_release_scope_title_gate.py",
                 "gate_explicit")
    gate.main(["--branch", "fix/a1", "--title", "[6.1.0 A1] fix(x): y", "--version", "6.1.0",
               "--json"])
    d = json.loads(capsys.readouterr().out)
    assert d["version"] == "6.1.0" and d["urteil"] == "gruen", d


def test_in_this_tree_the_default_is_a_scope_the_changelog_does_not_record_as_released(
        capsys, monkeypatch):
    """Against the real tree, with an oracle the rule does not use: the changelog's dated release
    headings, and the tags when this clone has them. A clone without tags cannot answer it when the
    source version has a scope file of its own, and says so."""
    if not _git("tag", "--list", "v[0-9]*").stdout.strip():
        pytest.skip("NOT MEASURED: this clone shows no release tag, and the source version has a "
                    "scope file of its own, so bumped and tagged cannot be told apart here")
    _rc, d = _gate_without_version(REPO, capsys)
    v = d["version"]
    assert v, d["gruende"]
    assert (SCOPE_DIR / f"{v}.md").is_file(), v
    changelog = (REPO / "CHANGELOG.md").read_text(encoding="utf-8")
    assert not re.search(rf"(?m)^## \[{re.escape(v)}\] - [0-9]", changelog), (
        f"without a version the gate judges {v}, which the changelog records as released")
    if _git("tag", "--list", "v[0-9]*").stdout.strip():
        assert _commit(f"v{v}") is None, f"without a version the gate judges {v}, which is tagged"
    card = _card_without_version(REPO, monkeypatch)
    assert card.get("version") == v, (card, v)


# -- 5. the review of caccdbad: a commit in any spelling git reads, a reference without backticks --
#
# These cases call only readers and checks that caccdbad already had, so they can be run against
# its readers unchanged; there, every one of them fails. Each plant goes into a copy of the cut, as
# a bullet appended to its last section: a unit of its own, outside every table.

#: A digest no object of this repository starts with; the cases that plant it check that first.
_NOWHERE = "0ace3040"


def _planted(text: str, bullet: str) -> str:
    return text.rstrip("\n") + f"\n- **Planted.** {bullet}\n"


def test_every_hex_spelling_git_accepts_is_read_as_the_commit_it_names():
    """Git resolves `0ACE3039` and `0AcE3039` to the commit `0ace3039` names. Measured at caccdbad
    and at fc1596e5: the reader returned an empty list for both, so nothing after it saw a
    commit."""
    full = "0ace3039d19e5985b1f19149d0a19ecfb2be0d2a"
    spellings = {
        "`0ace3039`": "0ace3039", "`0ACE3039`": "0ace3039", "0AcE3039": "0ace3039",
        "(0ACE3039D19E)": "0ace3039d19e", f"`{full.upper()}`": full, full: full,
        "`caccdbad`": "caccdbad", "1234567": "1234567",
    }
    for written, read in spellings.items():
        assert _cited_commits(f"the head at {written}.") == [read], written


def test_a_word_that_looks_like_a_commit_and_is_no_form_the_reader_checks_is_named():
    """The refusing branch the reader lacked: hex digits glued to other characters, and a hex word
    longer than a commit id, are named rather than read as no commit."""
    for word in ("0ace3039z", "sha1_0ace3039", "0ace3039d19e5985b1f19149d0a19ecfb2be0d2a0"):
        with pytest.raises(AssertionError, match=re.escape(word)):
            _cited_commits(f"the head at `{word}`.")


def test_catch_proof_a_commit_in_any_spelling_is_checked_where_the_files_cite_it(tmp_path,
                                                                                 monkeypatch):
    """The check over the files, run on a copy of the cut with one plant each: an upper-case and a
    mixed-case spelling of a commit that resolves to nothing must be named; a mixed-case spelling
    of a commit that resolves must be read and hold. The history check must name an older commit
    written in upper case."""
    _full_history_or_skip()
    assert _commit(_NOWHERE) is None, f"{_NOWHERE} resolves here, so the plant would prove nothing"
    text = CUT.read_text(encoding="utf-8")
    planted = tmp_path / CUT.name
    monkeypatch.setitem(globals(), "SCOPE_FILES", (planted,))
    for written in (f"`{_NOWHERE.upper()}`", "0AcE3040"):
        assert written.strip("`").lower() == _NOWHERE
        planted.write_text(_planted(text, f"The measured main stands at {written}."),
                           encoding="utf-8")
        with pytest.raises(AssertionError, match=written.strip("`")):
            test_every_cited_commit_resolves_and_is_an_ancestor_of_the_cut_head()
    bullet = "The measured main stands at 0AcE3039."
    assert _cited_commits(bullet) == ["0ace3039"], bullet
    planted.write_text(_planted(text, bullet), encoding="utf-8")
    test_every_cited_commit_resolves_and_is_an_ancestor_of_the_cut_head()
    base, older = _commit("v6.1.0"), _commit("v6.1.0^")
    if base is None or older is None:
        pytest.skip("NOT MEASURED: the tag v6.1.0 and its parent are not in this clone")
    assert commits_needing_old_history(f"the harness arrived with {older.upper()}.\n", base,
                                       _commit("HEAD"))


def test_catch_proof_the_frozen_section_reads_a_digest_in_any_spelling():
    """Without git. A digest in upper case beside a branch the decision records without one must
    be found, and the recorded head of pull request 296 written in upper case is still that head.
    At caccdbad the first passed unseen and the second was reported as a missing head."""
    text = CUT.read_text(encoding="utf-8")
    other = "0123456789ABCDEF0123456789ABCDEF01234567"
    beside = frozen_fix_findings(text.replace("`fix/a70-clean-tree-before-binding`.",
                                              f"`fix/a70-clean-tree-before-binding` at `{other}`."))
    assert any(other.lower() in f for f in beside), beside
    head = DECIDED_HEADS["claude/cargo-audit-rust-parity"]
    assert head in text, "the head is not in the cut, so there is nothing to plant on"
    upper = frozen_fix_findings(text.replace(head, head.upper()))
    assert not upper, upper


def test_catch_proof_a_path_line_reference_without_backticks_is_checked():
    """Three plain forms, each pointing at lines of the register that hold none of what the bullet
    names: `path:N-M` in prose, `:N-M` after a backticked path, and the path in backticks with the
    line outside them. Measured at caccdbad and at fc1596e5: the reader read none of them. The
    first form at the lines that do hold the name must be read and hold."""
    text = CUT.read_text(encoding="utf-8")
    name = "`SMALL-ORDER-KEY-AT-CARRIER-SIGNATURE-01`"
    for bullet in (f"{name} stands at RESTRISIKO_610.md:1-5.",
                   f"{name} stands in `RESTRISIKO_610.md` (:1-5).",
                   f"{name} stands at `RESTRISIKO_610.md`:1-5."):
        findings, _ = reference_findings(_planted(text, bullet))
        assert any(f.startswith("RESTRISIKO_610.md:1-5 ") for f in findings), (bullet, findings)
    bullet = f"{name} stands at RESTRISIKO_610.md:116-141."
    assert _references(bullet)[0] == [("RESTRISIKO_610.md", 116, 141)], bullet
    findings, _ = reference_findings(_planted(text, bullet))
    assert not any("116-141" in f for f in findings), findings


def test_a_token_that_begins_like_a_reference_and_is_none_is_refused_by_name():
    """A line and a column, an en dash for a range, and a continuation with no path before it, in
    prose and in backticks. None is a form the reader checks, so each is refused with its name; at
    caccdbad each was passed over, the backticked ones as names to look for."""
    text = CUT.read_text(encoding="utf-8")
    for token in ("RESTRISIKO_610.md:141:3", "RESTRISIKO_610.md:116\N{EN DASH}141", ":141"):
        for written in (token, f"`{token}`"):
            findings, _ = reference_findings(_planted(
                text, f"`SMALL-ORDER-KEY-AT-CARRIER-SIGNATURE-01` stands at {written}."))
            assert any(repr(token) in f for f in findings), (written, findings)


# -- 6. the review of 989b582c: lines starting with `#`, dotted and bare paths, plain branches -----
#
# Like section 5, these cases call only readers and checks that 989b582c already had, so they run
# against its readers unchanged, and there every one of them fails. Every catch proof carries its
# control: the same form written correctly must stay green, so a reader that refused everything
# would fail here too.

_SIGNATURE_ENTRY = "`SMALL-ORDER-KEY-AT-CARRIER-SIGNATURE-01`"

#: Line forms a writer can use, each once, several starting with `#` and none a table row.
_ODD_LINES = ("# A title", "#296 stood at `0ace3040`.", "### N18, measured at `0ace3040`",
              "## Out, a section", "> quoted `0ace3040`", "* a star item", "1. a numbered item",
              "<!-- 0ace3040 -->", "\tindented", "   ## an indented heading", "#", "###### six")


def _lines_outside_fences(text: str) -> list[str]:
    """The oracle: every line that is not blank, not a fence and not inside a fenced block."""
    out, fence = [], False
    for line in text.splitlines():
        if line.strip().startswith("```"):
            fence = not fence
        elif not fence and line.strip():
            out.append(line)
    return out


def _paragraph(text: str, paragraph: str) -> str:
    return text.rstrip("\n") + "\n\n" + paragraph + "\n"


def test_every_line_outside_a_fence_is_in_exactly_one_unit():
    """THE CLASS OF THE FIRST FINDING: the splitter decides what every reader of this file reads,
    so a line it drops is a line no check sees. Measured at 989b582c: every line starting with `#`
    was dropped, headings and prose alike."""
    texts = [p.read_text(encoding="utf-8") for p in SCOPE_FILES]
    texts += ["\n".join(_ODD_LINES) + "\n",
              "A paragraph\n#296 continues it\n\n- an item\n#297 too\n"]
    for text in texts:
        read = [line for unit in _units(text) for line in unit.split("\n")]
        assert read == _lines_outside_fences(text), text[:80]


def test_a_fence_that_never_closes_is_named():
    with pytest.raises(AssertionError, match="never closed"):
        _units("A paragraph.\n\n```\nthe rest of the file, 0ace3040\n")


def test_catch_proof_a_commit_on_a_line_that_starts_with_a_hash_is_checked(tmp_path, monkeypatch):
    """Planted at the end of a copy of the cut: a prose line starting `#296` that carries a commit
    which resolves to nothing, plain and backticked, and the same commit in a heading. The resolve
    check must name each. The control, a heading citing a commit that resolves, must hold."""
    _full_history_or_skip()
    assert _commit(_NOWHERE) is None, f"{_NOWHERE} resolves here, so the plant would prove nothing"
    text = CUT.read_text(encoding="utf-8")
    planted = tmp_path / CUT.name
    monkeypatch.setitem(globals(), "SCOPE_FILES", (planted,))
    for written, plant in (
            (_NOWHERE.upper(),
             f"The planted head of pull request\n#296 stood at {_NOWHERE.upper()}."),
            (_NOWHERE, f"The planted head of pull request\n#296 stood at `{_NOWHERE}`."),
            (_NOWHERE, f"### A planted heading at `{_NOWHERE}`")):
        planted.write_text(_paragraph(text, plant), encoding="utf-8")
        with pytest.raises(AssertionError, match=written):
            test_every_cited_commit_resolves_and_is_an_ancestor_of_the_cut_head()
    planted.write_text(_paragraph(text, "### A planted heading at `0ace3039`"), encoding="utf-8")
    test_every_cited_commit_resolves_and_is_an_ancestor_of_the_cut_head()


def test_catch_proof_a_reference_on_a_line_that_starts_with_a_hash_is_checked():
    text = CUT.read_text(encoding="utf-8")
    for lines, bad in (("1-5", True), ("116-141", False)):
        findings, _ = reference_findings(_paragraph(
            text, f"The register entry {_SIGNATURE_ENTRY} of pull request\n#293 stands at "
                  f"RESTRISIKO_610.md:{lines}."))
        assert any(f.startswith(f"RESTRISIKO_610.md:{lines} ") for f in findings) == bad, findings


def test_catch_proof_a_path_that_starts_with_a_dot_or_has_no_extension_is_checked():
    """Measured at 989b582c: none of the wrong forms was read or refused, the backticked ones were
    read as names to look for. Each control points at the lines that hold what it names."""
    text = CUT.read_text(encoding="utf-8")
    workflow = ".github/workflows/published-artifact-gate.yml"
    wrong = ((f"{_SIGNATURE_ENTRY} is checked at `{workflow}:9999`.", f"{workflow}:9999-9999 "),
             (f"{_SIGNATURE_ENTRY} is checked at {workflow}:9999.", f"{workflow}:9999-9999 "),
             (f"{_SIGNATURE_ENTRY} stands at ./RESTRISIKO_610.md:1-5.", "./RESTRISIKO_610.md:1-5 "),
             ("`PYTHON ?= python3` is set at Makefile:12.", "Makefile:12-12 "),
             ("`PYTHON ?= python3` is set at `Makefile:12`.", "Makefile:12-12 "),
             ("`PYTHON ?= python3` is set at NOFILE:3.", "NOFILE:3-3 names no file"),
             (f"{_SIGNATURE_ENTRY} stands at ../RESTRISIKO_610.md:116-141.",
              "outside the repository"))
    for bullet, finding in wrong:
        findings, _ = reference_findings(_planted(text, bullet))
        assert any(finding in f for f in findings), (bullet, findings)
    right = (f"The workflow `published-artifact-gate` is named at {workflow}:1.",
             f"{_SIGNATURE_ENTRY} stands at ./RESTRISIKO_610.md:116-141.",
             "`PYTHON ?= python3` is set at `Makefile:3`.")
    for bullet in right:
        assert len(_references(bullet)[0]) == 1, bullet
        findings, _ = reference_findings(_planted(text, bullet))
        assert not findings, (bullet, findings)


def test_catch_proof_a_branch_name_is_read_in_every_spelling():
    """Measured at 989b582c: a moved branch written plainly among the frozen fixes, a staying one
    written plainly under Out, and a moved one named in the decision's own sentence, plain or in
    backticks, all passed. The control is the cut as it stands: no finding from either reader."""
    text = CUT.read_text(encoding="utf-8")
    moved, stays = "fix/a-diff-is-read-in-gits-grammar", "fix/a70-clean-tree-before-binding"
    assert moved in MOVED_HEADS and stays in DECIDED_OPEN

    def planted(old: str, new: str) -> str:
        assert text.count(old) == 1, f"{old!r} is not once in the cut, so nothing to plant on"
        return text.replace(old, new)

    back_in = planted(f"  `{stays}`.\n", f"  `{stays}`.\n- The release-tooling stack: {moved}.\n")
    assert any(f"{moved} moved to 6.3.0 and is still counted" in f
               for f in frozen_fix_findings(back_in)), frozen_fix_findings(back_in)
    under_out = planted("both ancestors of it.\n",
                        f"both ancestors of it.\n- The pre-tag cleanliness gate: {stays}.\n")
    assert any(f"{stays} stays in 6.2.0 and stands under Out" in f
               for f in moved_findings(under_out)), moved_findings(under_out)
    for written in (moved, f"`{moved}`", f"**{moved}**"):
        in_sentence = planted("291, 296 and 249, and then pull request 294",
                              f"291, 296 and 249, the release-tooling stack {written}, and then "
                              f"pull request 294")
        assert any(moved in f for f in moved_findings(in_sentence)), (written,
                                                                     moved_findings(in_sentence))
    assert not frozen_fix_findings(text), frozen_fix_findings(text)
    assert not moved_findings(text), moved_findings(text)


# -- 7. the review of 5a9ddc06: a tag this clone lacks, a citation's own tree, a tagless clone ----
#
# Each case reproduces its finding with the measurement the review gave, and fails at 5a9ddc06.


def test_RED_a_source_tag_this_clone_does_not_show_is_not_read_as_absent(tmp_path, capsys,
                                                                          monkeypatch):
    """Codex on pull request 294, round four, P1, its measurement taken over. `git tag --list`
    lists the tags this clone holds, not the tags that exist. With the source version at 6.2.0,
    only `v6.1.0` in the clone and the scopes 6.2.0 and 6.3.0, a branch that only 6.3.0 names was
    judged against 6.2.0 at 5a9ddc06, outside the scope, exit 0, although `v6.2.0` may be out
    upstream and 6.3.0 the release being built. A source tag this clone does not show decides
    nothing: the branch is judged by the candidate that names it. Only a tag this clone shows
    decides for the next release alone. The card counts one release and cannot know which, so it
    is NOT MEASURABLE there and names the tag."""
    root = _tree(tmp_path, "6.2.0", ("6.2.0", "6.3.0"), ("v6.1.0",), {"6.3.0": "fix/new"})
    gate = _load(root / "scripts" / "b7_release_scope_title_gate.py", "gate_partial_tags")
    for branch, title, version, rc_expected in (("fix/new", "fix(x): y", "6.3.0", 1),
                                                ("fix/new", "[6.3.0 A1] fix(x): y", "6.3.0", 0),
                                                ("fix/a1", "fix(x): y", "6.2.0", 1),
                                                ("fix/a1", "[6.2.0 A1] fix(x): y", "6.2.0", 0)):
        rc = gate.main(["--branch", branch, "--title", title, "--json"])
        d = json.loads(capsys.readouterr().out)
        assert (d["version"], rc, d["ausserhalb_des_umfangs"]) == (version, rc_expected, False), (
            branch, title, d)
    rc = gate.main(["--branch", "chore/elsewhere", "--title", "chore: y", "--json"])
    d = json.loads(capsys.readouterr().out)
    assert rc == 0 and d["ausserhalb_des_umfangs"], d
    card = _card_without_version(root, monkeypatch)
    assert card["zustand"] == "NOT MEASURABLE" and "v6.2.0" in card["grund"], card
    visible = _tree(tmp_path / "visible", "6.2.0", ("6.2.0", "6.3.0"), ("v6.1.0", "v6.2.0"),
                    {"6.3.0": "fix/new"})
    gate = _load(visible / "scripts" / "b7_release_scope_title_gate.py", "gate_visible_tag")
    rc = gate.main(["--branch", "fix/a1", "--title", "fix(x): y", "--json"])
    d = json.loads(capsys.readouterr().out)
    assert (d["version"], rc, d["ausserhalb_des_umfangs"]) == ("6.3.0", 0, True), d
    assert _card_without_version(visible, monkeypatch).get("version") == "6.3.0"


def test_RED_each_citation_is_checked_in_the_tree_its_own_text_names(monkeypatch):
    """Codex on pull request 294, round four, P1, its counter-example taken over: `MATCH` is cited
    at `file.py:1` in the tree `abcdef0`, and the unit also names the comparison tree `1234567`.
    `abcdef0` holds `OTHER` there and `1234567` holds `MATCH`. At 5a9ddc06 every tree of the unit
    was searched and any hit passed, so the citation passed in a tree it does not name. The
    controls: the named tree holding `MATCH` passes whatever the other tree holds; a citation whose
    sentence names no tree, in a unit that names trees, is refused; a row that names its path at a
    tree binds it; and a tag written with its commit is one tree, refused when the two names are
    two commits."""
    lines = {"abcdef0": ["OTHER"], "1234567": ["MATCH"]}
    names = {"abcdef0": "abcdef0", "1234567": "1234567", "v9.9.9": "abcdef0"}
    monkeypatch.setitem(globals(), "_lines_at", lambda tree, path: lines.get(tree))
    monkeypatch.setitem(globals(), "_commit", names.get)
    unit = "`MATCH` stands at `file.py:1` in tree `abcdef0`. The comparison tree is `1234567`."
    findings, unmeasured = reference_findings(unit)
    assert any(f.startswith("file.py:1-1 holds none of") and "abcdef0" in f for f in findings), (
        findings, unmeasured)
    assert not any("1234567" in f for f in findings), findings
    lines.update({"abcdef0": ["MATCH"], "1234567": ["OTHER"]})
    assert reference_findings(unit) == ([], [])
    loose = "`MATCH` stands at `file.py:1`. The trees are `abcdef0` and `1234567`."
    findings, _ = reference_findings(loose)
    assert any(f.startswith("file.py:1-1 ") and "names no tree" in f for f in findings), findings
    declared = ("`MATCH` stands at `file.py:1`. The line numbers are those of `file.py` at "
                "`abcdef0`; `1234567` is the comparison.")
    assert reference_findings(declared) == ([], [])
    lines.update({"abcdef0": ["OTHER"], "1234567": ["MATCH"]})
    assert any(f.startswith("file.py:1-1 holds none of") and "abcdef0" in f
               for f in reference_findings(declared)[0])
    twice = ("`MATCH` stands at `file.py:1`. It is `file.py` at `abcdef0`, or `file.py` at "
             "`1234567`.")
    assert any(f.startswith("file.py:1-1 ") and "2 trees for `file.py`" in f
               for f in reference_findings(twice)[0]), reference_findings(twice)
    pair ="`MATCH` stands at `file.py:1` in `v9.9.9` (`abcdef0`)."
    assert any("abcdef0" in f for f in reference_findings(pair)[0])
    lines["abcdef0"] = ["MATCH"]
    assert reference_findings(pair) == ([], [])
    names["v9.9.9"] = "1234567"
    assert any("two commits" in f for f in reference_findings(pair)[0])


def test_RED_the_list_of_main_is_not_measured_without_its_release_tag(monkeypatch):
    """Codex on pull request 294, round four, P2: a full clone may hold no tag (`git clone
    --no-tags`), and at 5a9ddc06 the case that holds the list of main against git then failed,
    because it checked only for a shallow clone and required `v6.1.0` to resolve. Planted here by
    a resolver that knows no tag; the case must skip and name what it did not measure."""
    _full_history_or_skip()
    real = _commit
    monkeypatch.setitem(globals(), "_commit",
                        lambda rev: None if rev.startswith("v") else real(rev))
    with pytest.raises(pytest.skip.Exception, match="NOT MEASURED"):
        test_what_landed_on_the_day_of_the_cut_is_in_the_list_of_main_and_the_counts_match()


def test_catch_proof_a_line_bound_to_the_wrong_revision_of_the_real_row_is_found():
    """The class of the second finding on the real file: the R-B4 row binds the three line numbers
    of its quoted middle column to `v6.1.0` (`dcac5aee`). Planted: the same row binding them to
    `31816e08`, where the file's previous version stands and the three lines hold other code. The
    row still names `v6.1.0`, for the register, so a reader that lets any tree of the row answer
    passes the plant; the binding must name each of the three lines. The control is the row as it
    stands: none of its seven references is a finding."""
    _full_history_or_skip()
    if _commit("31816e08") is None or _commit("dcac5aee") is None:
        pytest.skip("NOT MEASURED: 31816e08 or dcac5aee is not in this clone")
    text = CUT.read_text(encoding="utf-8")
    row = next(u for u in _units(text) if u.startswith("| R-B4 |"))
    assert len(_references(row)[0]) == 7, _references(row)
    assert reference_findings(row) == ([], [])
    old = "those of `src/proofbundle/intoto.py` at `v6.1.0` (`dcac5aee`)"
    assert old in row and "`RESTRISIKO_610.md` at `v6.1.0`" in row, "nothing to plant on"
    findings, _ = reference_findings(row.replace(old, "those of `src/proofbundle/intoto.py` at "
                                                      "`31816e08`"))
    for line in (246, 424, 551):
        assert any(f.startswith(f"src/proofbundle/intoto.py:{line}-{line} holds none of")
                   and "31816e08" in f for f in findings), (line, findings)
    assert len(findings) == 3, findings


# -- 8. the review of 76f260a2: a reader's NOT MEASURABLE is not an empty result ------------------
#
# Codex on pull request 294, round five, P1: an unreadable candidate scope was collapsed into an
# empty collection. The class is a reader that says NOT MEASURABLE and a caller that keeps only the
# collection it returned. The sweep for it found two more callers of that shape, the two readers of
# the gate's guard against unreadable lines and the landing card's reading of the branches. Each
# case fails at 76f260a2 and passes on the commit that fixed it, and each carries its control.

_NO_OUT = ("# Release scope - {v}\n\n## In\n\n| Identifier | Subject | Branch |\n|---|---|---|\n"
           "| A1 | something | `{b}` |\n")


def test_RED_an_unreadable_candidate_scope_decides_nothing(tmp_path, capsys):
    """Codex on pull request 294, round five, P1, its measurement taken over: the source version at
    6.2.0, no tag the clone shows, a 6.2.0 scope that names `fix/a1` and has no `## Out`, and a
    valid 6.3.0 scope. At 76f260a2 `fix/a1` without an identifier was judged against 6.3.0,
    outside the scope, exit 0: `_nach_dem_zweig` read the unreadable 6.2.0 scope as one that names
    nothing. Either candidate unreadable leaves the release undecided now, for every branch. The
    control is the tagless case of section 4, where both candidates can be read."""
    for broken, named in (("6.2.0", "fix/a1"), ("6.3.0", "fix/b1")):
        root = _tree(tmp_path / broken, "6.2.0", ("6.2.0", "6.3.0"), None, {"6.3.0": "fix/b1"})
        (root / "docs" / "release_scope" / f"{broken}.md").write_text(
            _NO_OUT.format(v=broken, b=named), encoding="utf-8")
        gate = _load(root / "scripts" / "b7_release_scope_title_gate.py",
                     f"gate_unreadable_{broken.replace('.', '_')}")
        for branch in ("fix/a1", "fix/b1", "chore/elsewhere"):
            rc = gate.main(["--branch", branch, "--title", "fix(x): y", "--json"])
            d = json.loads(capsys.readouterr().out)
            assert (rc, d["version"], d["ausserhalb_des_umfangs"]) == (1, None, False), (
                broken, branch, d)
            assert any(f"candidate {broken}" in g and "is not known" in g for g in d["gruende"]), d


_HEAD_NOT_BRANCH = ("# s\n\n## In\n\n| Identifier | Subject | Head |\n|---|---|---|\n"
                    "| A1 | something | `fix/a1` |\n| nameless | a line with no identifier | `fix/x` |\n"
                    "\n## Out\n")


def test_RED_a_guard_that_did_not_run_is_not_a_guard_that_found_nothing(tmp_path):
    """The same class inside the gate. The guard against unreadable lines reports NOT MEASURABLE
    when no table header names a branch column, and both of its callers kept only the list it
    returned. So a scope whose branch column is headed `Head` let its nameless row vanish: at
    76f260a2 `pruefe` was green for `fix/a1` and the file check green, over a row neither read. The
    control is the same file with the column headed `Branch`, where the nameless row is named."""
    gate = _load(REPO / "scripts" / "b7_release_scope_title_gate.py", "gate_guard_state")
    p = tmp_path / "9.9.9.md"
    for head, said in (("Head", "did not run"), ("Branch", "nameless")):
        p.write_text(_HEAD_NOT_BRANCH.replace("| Head |", f"| {head} |"), encoding="utf-8")
        d = gate.pruefe(branch="fix/a1", title="[9.9.9 A1] fix(x): y", version="9.9.9",
                        scope_pfad=p)
        assert d["urteil"] == "ROT" and any(said in g for g in d["gruende"]), (head, d)
        f = gate.pruefe_umfangsdatei(p)
        assert f["urteil"] == "ROT" and any(said in g for g in f["gruende"]), (head, f)


def test_RED_the_card_does_not_count_a_scope_whose_branches_it_cannot_read(tmp_path, monkeypatch):
    """The same class in the landing card. It checked the state of the line reader and dropped the
    state of the branch reader, so a scope whose branch column is written without backticks read
    every line as a rider: at 76f260a2 the card answered measured, with no countable line, where the
    branch reader had said it found no branch at all. The control is the backticked column."""
    for cell, expected in (("fix/a1", "NOT MEASURABLE"), ("`fix/a1`", "gemessen")):
        root = _tree(tmp_path / expected.replace(" ", "_"), "6.1.0", ("6.1.0", "6.2.0"),
                     _TAGS_UP_TO["6.1.0"])
        p = root / "docs" / "release_scope" / "6.2.0.md"
        p.write_text(p.read_text(encoding="utf-8").replace("`fix/a1`", cell), encoding="utf-8")
        card = _card_without_version(root, monkeypatch)
        assert card["zustand"] == expected, (cell, card)
