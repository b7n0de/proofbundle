#!/usr/bin/env python3
"""changelog_fragments.py: one CHANGELOG fragment per pull request, collected at the release cut.

WHY. Every pull request used to write its lines under `## [Unreleased]` at the same place of
CHANGELOG.md. When one lands, every other open pull request conflicts there and needs main merged
in, a new CI run and a new review. A fragment is a file of its own in `changelog.d/`, so two pull
requests never touch the same lines; the release preparation moves all fragments into CHANGELOG.md
in one commit.

A FRAGMENT is `changelog.d/<stem>.<section>.md`:

  stem     lower-case letters, digits and hyphens, starting with a letter or a digit, at most 64
           characters; any unique name, for example the branch slug or the issue number.
  section  one of `security`, `added`, `changed`, `deprecated`, `removed`, `fixed`; it names the
           `### <Section>` subsection under `## [Unreleased]` the lines belong to.
  content  exactly the lines the pull request would otherwise write under that subsection: UTF-8,
           LF line ends, the last line ends with LF, the first line opens a list item (`- `), no
           empty line and no heading.

`changelog.d/README.md` explains this and is not a fragment. Any other file there is a finding.

TWO COMMANDS.

  check    reads every file in `changelog.d/` and reports each finding; exit 1 on a finding, 0 when
           every fragment is valid (also when there is none or the folder is absent).
  collect  runs `check` first and changes nothing on a finding (exit 1). Otherwise it moves every
           fragment under `## [Unreleased]` of CHANGELOG.md, in a fixed order: by section in the
           order of `SECTIONS`, then by file name (code-point order). Lines of a subsection that
           already exists stay first, the fragment lines follow them; a missing subsection is
           created directly after the last subsection that comes earlier in `SECTIONS` (a subsection
           the tool does not know keeps its place); a missing `## [Unreleased]` heading is created
           above the first release heading. Then it removes the collected fragments in the same
           working tree. Without fragments it writes nothing, so a second run changes nothing.

Exit 0 = OK, 1 = finding, 2 = usage error. Standard library only.

Usage: python3 scripts/changelog_fragments.py {check,collect} [--repo <path>]
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path

#: The subsections a fragment may name, in the order `collect` writes them under `## [Unreleased]`.
#: Security comes first as in the 6.6.1 section and the current `## [Unreleased]` block; the other
#: five follow Keep a Changelog 1.1.0, the same set as `ABSCHNITTE` in scripts/render_release.py.
SECTIONS = ("security", "added", "changed", "deprecated", "removed", "fixed")

#: The folder of the fragments, relative to the repository root.
FOLDER = "changelog.d"

#: The one file in the folder that is not a fragment.
README = "README.md"

FRAGMENT_NAME = re.compile(r"^([a-z0-9][a-z0-9-]{0,63})\.(" + "|".join(SECTIONS) + r")\.md$")
_ANY_SECTION_NAME = re.compile(r"^([a-z0-9][a-z0-9-]{0,63})\.([a-z]+)\.md$")
#: A heading in CommonMark: up to three spaces, one to six `#`, then a blank, a tab or the line end.
_HEADING = re.compile(r"^ {0,3}#{1,6}(?:[ \t]|$)")
#: The release headings, as scripts/check_version_and_changelog.py reads them (`_changelog_headings`).
_LEVEL2 = re.compile(r"^##[ \t]+\[([^\]]+)\]")
_LEVEL3 = re.compile(r"^###[ \t]+(.+?)[ \t]*$")


def _title(section: str) -> str:
    return section[0].upper() + section[1:]


def fragment_paths(repo: Path) -> list[Path]:
    """The files in `changelog.d/` whose name is a valid fragment name, in collect order."""
    folder = repo / FOLDER
    if not folder.is_dir():
        return []
    found = []
    for p in folder.iterdir():
        m = FRAGMENT_NAME.match(p.name)
        if m and p.is_file():
            found.append((SECTIONS.index(m.group(2)), p.name, p))
    return [p for _, _, p in sorted(found)]


def check(repo: Path) -> list[str]:
    """Every finding about `changelog.d/`, one line each; an empty list when every fragment is valid."""
    folder = repo / FOLDER
    if not folder.exists():
        return []
    if not folder.is_dir():
        return [f"{FOLDER} is not a folder"]
    findings: list[str] = []
    for p in sorted(folder.iterdir(), key=lambda q: q.name):
        rel = f"{FOLDER}/{p.name}"
        if p.name == README and p.is_file():
            continue
        if not p.is_file() or p.is_symlink():
            findings.append(f"{rel}: not a regular file; the folder holds fragments and {README} only")
            continue
        if not FRAGMENT_NAME.match(p.name):
            m = _ANY_SECTION_NAME.match(p.name)
            if m and m.group(2) not in SECTIONS:
                findings.append(f"{rel}: unknown section {m.group(2)!r}; known: {', '.join(SECTIONS)}")
            else:
                findings.append(f"{rel}: the name is not <stem>.<section>.md (stem: a-z, 0-9 and '-', "
                                f"at most 64 characters, section: {', '.join(SECTIONS)})")
            continue
        findings.extend(f"{rel}: {f}" for f in _content_findings(p.read_bytes()))
    return findings


def _content_findings(raw: bytes) -> list[str]:
    if not raw.strip():
        return ["the fragment is empty"]
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        return [f"not UTF-8 ({exc.reason} at byte {exc.start})"]
    findings = []
    if "\r" in text:
        findings.append("carries a CR; line ends are LF only")
    if not text.endswith("\n"):
        findings.append("the last line does not end with LF")
    lines = text.split("\n")[:-1] if text.endswith("\n") else text.split("\n")
    if lines and not lines[0].startswith("- "):
        findings.append("the first line does not open a list item with '- '")
    for i, line in enumerate(lines, 1):
        if not line.strip():
            findings.append(f"line {i} is empty; a fragment is one block of list lines")
        elif _HEADING.match(line):
            findings.append(f"line {i} is a heading; the section comes from the file name")
    return findings


def _fragment_lines(p: Path) -> list[str]:
    return p.read_text(encoding="utf-8").split("\n")[:-1]


def _render(changelog: str, fragments: dict[str, list[str]]) -> str:
    """CHANGELOG.md text with `fragments` (section -> lines, already in order) under `## [Unreleased]`."""
    if not any(fragments.values()):
        return changelog
    lines = changelog.split("\n")
    heads = [i for i, z in enumerate(lines) if _LEVEL2.match(z)]
    unreleased = next((i for i in heads if _LEVEL2.match(lines[i]).group(1).strip().lower() == "unreleased"), None)
    if unreleased is None:
        at = heads[0] if heads else len(lines)
        lines[at:at] = ["## [Unreleased]", ""]
        unreleased = at
        heads = [i for i, z in enumerate(lines) if _LEVEL2.match(z)]
    end = next((i for i in heads if i > unreleased), len(lines))
    block = lines[unreleased + 1:end]

    # The block is a prose part and a list of subsections, each a title and its lines.
    starts = [i for i, z in enumerate(block) if _LEVEL3.match(z)]
    prose = block[:starts[0]] if starts else block
    subsections = []
    for k, s in enumerate(starts):
        stop = starts[k + 1] if k + 1 < len(starts) else len(block)
        subsections.append([_LEVEL3.match(block[s]).group(1), block[s + 1:stop]])

    for section in SECTIONS:
        new = fragments.get(section) or []
        if not new:
            continue
        title = _title(section)
        hit = next((sub for sub in subsections if sub[0] == title), None)
        if hit is None:
            # Directly after the last known subsection that comes earlier in SECTIONS; without one,
            # before the first known subsection that comes later; without either, at the end.
            rank = SECTIONS.index(section)
            ranks = [SECTIONS.index(sub[0].lower()) if sub[0].lower() in SECTIONS else None
                     for sub in subsections]
            earlier = [k for k, r in enumerate(ranks) if r is not None and r < rank]
            later = [k for k, r in enumerate(ranks) if r is not None and r > rank]
            pos = earlier[-1] + 1 if earlier else (later[0] if later else len(subsections))
            subsections.insert(pos, [title, ["", *new, ""]])
            continue
        body = hit[1]
        while body and not body[-1].strip():
            body.pop()
        if not body:
            body.append("")
        hit[1] = [*body, *new, ""]

    while prose and not prose[-1].strip():
        prose.pop()
    out_block = [*prose, ""] if prose else [""]
    for title, body in subsections:
        out_block.extend([f"### {title}", *body])
    if end < len(lines) and out_block[-1].strip():
        out_block.append("")
    return "\n".join([*lines[:unreleased + 1], *out_block, *lines[end:]])


def collect(repo: Path) -> tuple[list[str], list[str]]:
    """(findings, collected paths). On a finding nothing is written."""
    findings = check(repo)
    if findings:
        return findings, []
    paths = fragment_paths(repo)
    if not paths:
        return [], []
    target = repo / "CHANGELOG.md"
    if not target.is_file():
        return ["CHANGELOG.md is missing; there is nothing to collect into"], []
    fragments: dict[str, list[str]] = {s: [] for s in SECTIONS}
    for p in paths:
        m = FRAGMENT_NAME.match(p.name)
        assert m is not None
        fragments[m.group(2)].extend(_fragment_lines(p))
    old = target.read_bytes().decode("utf-8")
    target.write_bytes(_render(old, fragments).encode("utf-8"))
    for p in paths:
        p.unlink()
    return [], [f"{FOLDER}/{p.name}" for p in paths]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="check or collect the CHANGELOG fragments in changelog.d/")
    ap.add_argument("command", choices=("check", "collect"))
    ap.add_argument("--repo", default=".", help="repository root (default: cwd)")
    args = ap.parse_args(argv)
    repo = Path(args.repo)
    if args.command == "check":
        findings = check(repo)
        for f in findings:
            print(f"changelog_fragments: FINDING {f}")
        n = len(fragment_paths(repo))
        if findings:
            return 1
        print(f"changelog_fragments: OK, {n} fragment(s) in {FOLDER}/ checked")
        return 0
    findings, moved = collect(repo)
    for f in findings:
        print(f"changelog_fragments: FINDING {f}")
    if findings:
        print("changelog_fragments: nothing collected, CHANGELOG.md unchanged")
        return 1
    for name in moved:
        print(f"changelog_fragments: collected {name}")
    print(f"changelog_fragments: OK, {len(moved)} fragment(s) moved under ## [Unreleased]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
