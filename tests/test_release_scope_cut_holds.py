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

WHAT THIS FILE DOES NOT CHECK: the older scope files (6.1.0 and before), which are records of
their own cuts; and whether a reference names the RIGHT symbol, beyond that the symbol it names
stands in the lines it points at.
"""
from __future__ import annotations

import importlib.util
import json
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


def _units(text: str) -> list[str]:
    """Table rows one by one, list items with their continuation lines, and paragraphs.

    A row or an item is the unit a citation belongs to: a tag named in the same row as a commit is
    the tag that commit is cited as. Fenced blocks are left out, because they quote measurements
    (artefact digests among them), not citations.
    """
    units: list[str] = []
    current: list[str] = []
    fence = False

    def flush() -> None:
        if current:
            units.append("\n".join(current))
            current.clear()

    for line in text.splitlines():
        if line.strip().startswith("```"):
            flush()
            fence = not fence
            continue
        if fence:
            continue
        if not line.strip() or line.startswith("#"):
            flush()
            continue
        if line.startswith("|"):
            flush()
            units.append(line)
            continue
        if line.startswith("- "):
            flush()
        current.append(line)
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


def _cells(row: str) -> list[str]:
    return [c.strip() for c in row.strip().strip("|").split("|")]


_HEX = re.compile(r"(?<![0-9A-Za-z])[0-9a-f]{7,40}(?![0-9A-Za-z])")
_TAG = re.compile(r"`(v[0-9]+(?:\.[0-9]+)+)`")

_NUMBER_WORDS = {w: i for i, w in enumerate(
    "zero one two three four five six seven eight nine ten eleven twelve".split())}


def _number(word: str) -> int:
    """A count as the prose writes it; -1 for a word this reader does not know, which then fails
    the comparison it is used in rather than raising."""
    return int(word) if word.isdigit() else _NUMBER_WORDS.get(word.lower(), -1)


def _flat(text: str) -> str:
    """Prose with its line breaks read as spaces: a sentence the file wraps is one sentence."""
    return re.sub(r"\s+", " ", text)


def _cited_commits(unit: str) -> list[str]:
    """Hex runs of 7 to 40 characters with a digit and a letter: what this file cites as commits."""
    return [h for h in _HEX.findall(unit) if re.search(r"[a-f]", h) and re.search(r"[0-9]", h)]


# -- 1. every open frozen fix the decisions put into 6.2.0 is named, and the counts match ----------

#: THE DECISION'S SIDE OF THE COMPARISON, typed here on purpose. Derived from the file, it would
#: agree with the file by construction, and the omission this case exists for would pass.
#:
#: What it holds: the open fix branches of the owner's decision of 2026-09-27, 10:04 UTC, option A,
#: as the cut first recorded them (c38fe56d to 351fce0c), plus the addition of the same day, pull
#: request 296. The pull request number stands where the decision or the addition gave one; the
#: branch then has to stand in the same row or item as its number.
DECIDED_OPEN = {
    "fix/the-commit-pattern-holds-at-the-verify-boundary": None,
    "fix/a-small-order-key-is-refused-at-every-carrier": 293,
    "fix/every-constant-lookup-on-a-foreign-key-is-classified": None,
    "fix/script-patterns-end-at-the-value-and-read-githubs-whitespace": None,
    "fix/whole-value-patterns-read-ascii-digits": None,
    "fix/a-diff-is-read-in-gits-grammar": None,
    "fix/the-mutant-guard-reads-a-quoted-path": None,
    "fix/git-paths-are-read-as-git-names-them": None,
    "fix/a-resolver-promotes-only-on-exact-true": 291,
    "fix/a70-clean-tree-before-binding": 249,
    "claude/cargo-audit-rust-parity": 296,
}

#: The one open branch the cut records at a head: pull request 296, frozen at the head its
#: correction left, one commit on top of the head its review read (`git ls-remote` on 2026-09-27).
#: Every other open branch stands without a digest, which is the file's rule.
DECIDED_HEADS = {
    "claude/cargo-audit-rust-parity": "47adce3ec47ffd403579e49bfc459c6da1a9d677",
}

#: The other addition of that day, which landed before the cut was written up: the ECDSA
#: inventory, pull request 295. It belongs in the list of what is on main, not among the frozen.
DECIDED_LANDED = (295,)

_BRANCH = re.compile(r"^[a-z0-9]+/[a-z0-9][a-z0-9._-]*$")
_FILE_SUFFIX = re.compile(r"\.(?:py|md|json|toml|ya?ml|txt|cff|rs|html)$")


def _frozen_fixes(text: str) -> tuple[list[str], list[list[str]], list[str]]:
    """(branches of the table rows, branches per list item, the units) of the frozen section."""
    units = _units(_section(text, "frozen fix"))
    rows, items = [], []
    for unit in units:
        if unit.startswith("|"):
            last = _cells(unit)[-1]
            if last.startswith("`") and last.endswith("`") and _BRANCH.match(last.strip("`")):
                rows.append(last.strip("`"))
        elif unit.startswith("- "):
            branches = [t for t in re.findall(r"`([^`]+)`", unit)
                        if _BRANCH.match(t) and not _FILE_SUFFIX.search(t)]
            if branches:
                items.append(branches)
    return rows, items, units


def frozen_fix_findings(text: str) -> list[str]:
    """Every way the frozen section disagrees with the decision or with its own counts."""
    rows, items, units = _frozen_fixes(text)
    findings = []
    named = set(rows) | {b for item in items for b in item}
    for branch, number in DECIDED_OPEN.items():
        if branch not in named:
            findings.append(f"the decision puts {branch} into 6.2.0 and the cut does not name it")
        elif number is not None and not any(f"`{branch}`" in u and f"pull request {number}" in u
                                            for u in units):
            findings.append(f"{branch} stands without its pull request {number} beside it")
    for branch, head in DECIDED_HEADS.items():
        unit = next((u for u in units if f"`{branch}`" in u), "")
        if not any(len(h) >= 8 and head.startswith(h) for h in _cited_commits(unit)):
            findings.append(f"{branch} is frozen at {head} and the cut does not record that head")
    for unit in units:
        heads = [DECIDED_HEADS[b] for b in DECIDED_HEADS if f"`{b}`" in unit]
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


def _on_main_list(text: str) -> list[tuple[int, str]]:
    return [(int(n), h) for n, h in
            re.findall(r"(?m)^- #([0-9]+) `([0-9a-f]{7,40})` ", _section(text, "what is on main"))]


def test_every_open_frozen_fix_the_decisions_name_is_in_the_cut_and_the_counts_match():
    findings = frozen_fix_findings(CUT.read_text(encoding="utf-8"))
    assert not findings, "\n".join(findings)


def test_what_landed_on_the_day_of_the_cut_is_in_the_list_of_main_and_the_counts_match():
    text = CUT.read_text(encoding="utf-8")
    entries = _on_main_list(text)
    numbers = [n for n, _ in entries]
    for n in DECIDED_LANDED:
        assert n in numbers, f"#{n} landed on main with the decision's addition and is not listed"
    head = re.search(r"at `([0-9a-f]{7,40})`: ([0-9]+) commits since `(v[0-9.]+)`, ([0-9]+) of "
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
    assert base_c and since_c, f"{base} or {since} does not resolve in a full clone"
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
    this clone carries the branch, the branch has to stand at it or have grown from it."""
    text = CUT.read_text(encoding="utf-8")
    measured = []
    for branch, head in DECIDED_HEADS.items():
        assert head in text, f"{branch}: the cut does not carry the head {head}"
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
    """Every commit outside the frozen section. A head recorded there is the head of an open
    branch and by nature not an ancestor of the cut; it has its own case above."""
    _full_history_or_skip()
    head = _commit("HEAD")
    seen, problems = 0, []
    for path in SCOPE_FILES:
        for unit in _units(_outside(path.read_text(encoding="utf-8"), "frozen fix")):
            for h in _cited_commits(unit):
                seen += 1
                full = _commit(h)
                if full is None:
                    problems.append(f"{path.name}: {h} does not resolve to a commit")
                elif not _is_ancestor(full, head):
                    problems.append(f"{path.name}: {h} is not an ancestor of the head")
    assert seen > 10, f"only {seen} cited commits read: the reader is not reading the files"
    assert not problems, "\n".join(problems)


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
        outside = _outside(text, "frozen fix")
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
    # Full SHAs: a short prefix can happen to be all digits, and the reader rightly skips those.
    assert commits_needing_old_history(f"the harness arrived with {older}.\n", base, head)
    assert commits_needing_old_history(f"the release commit (`{base}`).\n", base, head)
    assert not commits_needing_old_history(f"the tag `v6.1.0` (`{base}`).\n", base, head)
    assert not commits_needing_old_history(f"the head `{head}`.\n", base, head)


# -- 3. every path:line reference points at the symbol it names, in the tree it names --------------

_PATH = r"[A-Za-z0-9_][A-Za-z0-9_./-]*"
_REF = re.compile(rf"^(?P<path>{_PATH}\.[A-Za-z0-9]+):(?P<a>[0-9]+)(?:-(?P<b>[0-9]+))?$")
_CONT = re.compile(r"^:(?P<a>[0-9]+)(?:-(?P<b>[0-9]+))?$")


def _is_path(token: str) -> bool:
    return (bool(re.match(rf"^{_PATH}$", token))
            and ("/" in token or bool(_FILE_SUFFIX.search(token))))


def _references(unit: str) -> tuple[list[tuple[str, int, int]], list[str], list[str]]:
    """(references, needles, trees) of one unit.

    A reference is `path:N` or `path:N-M`, and a bare `:N` continues the last path named before it,
    as in "`src/proofbundle/intoto.py` (`:246`, `:424`)". A needle is every other backticked name in
    the unit, split at " / ", that is neither a path nor a tree: what the unit says stands there.
    The trees are the working tree and every tag or commit the unit names.
    """
    refs, needles, trees = [], [], []
    last_path = None
    for token in re.findall(r"`([^`]+)`", unit):
        m = _REF.match(token)
        if m:
            last_path = m["path"]
            refs.append((m["path"], int(m["a"]), int(m["b"] or m["a"])))
            continue
        m = _CONT.match(token)
        if m and last_path:
            refs.append((last_path, int(m["a"]), int(m["b"] or m["a"])))
            continue
        if _TAG.fullmatch(f"`{token}`"):
            trees.append(token)
            continue
        if _is_path(token):
            last_path = token
            continue
        if _cited_commits(token) == [token] or token in ("main", "HEAD"):
            continue                          # a commit or a branch names a tree, not a symbol
        needles += [p.strip() for p in token.split(" / ") if len(p.strip()) >= 3]
    trees += _cited_commits(unit)
    return refs, needles, trees


def _lines_at(tree: str | None, path: str) -> list[str] | None:
    if tree is None:
        p = REPO / path
        return p.read_text(encoding="utf-8").splitlines() if p.is_file() else None
    r = _git("show", f"{tree}:{path}")
    return r.stdout.splitlines() if r.returncode == 0 else None


def reference_findings(text: str) -> tuple[list[str], list[str]]:
    """(findings, not measured here) for every path:line reference of one scope file."""
    findings, unmeasured = [], []
    for unit in _units(text):
        refs, needles, trees = _references(unit)
        if not refs:
            continue
        resolved = [None] + [c for t in trees if (c := _commit(t))]
        missing = [t for t in trees if _commit(t) is None]
        for path, a, b in refs:
            if not needles:
                findings.append(f"{path}:{a}-{b} stands in a unit that names nothing to find there")
                continue
            hit = False
            for tree in resolved:
                lines = _lines_at(tree, path)
                span = "\n".join(lines[a - 1:b]) if lines and b <= len(lines) else None
                if span is not None and any(n in span for n in needles):
                    hit = True
                    break
            if hit:
                continue
            where = f"{path}:{a}-{b}"
            if missing:
                unmeasured.append(f"{where} (trees not in this clone: {missing})")
            else:
                findings.append(f"{where} holds none of {needles[:6]} in the working tree or in "
                                f"{trees or 'no named tree'}")
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


def test_the_quoted_middle_column_is_still_the_previous_version_word_for_word():
    """THE CONSTRAINT THE FIX HAD TO KEEP. The file's rule is that the middle column quotes the
    previous version, so a stale line number there is corrected beside it, never inside it."""
    text = CUT.read_text(encoding="utf-8")
    m = re.search(r"stands in the history of this file at `([0-9a-f]{7,40})`", text)
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


def _tree(tmp_path: pathlib.Path, source_version: str, scopes: tuple[str, ...]) -> pathlib.Path:
    """A throwaway repository root: the two scripts as they are, a pyproject, some scope files."""
    root = tmp_path / "tree"
    (root / "scripts").mkdir(parents=True)
    for name in ("b7_release_scope_title_gate.py", "b7_release_scope_landing_card.py"):
        shutil.copy2(REPO / "scripts" / name, root / "scripts" / name)
    (root / "pyproject.toml").write_text(
        f'[project]\nname = "probe"\nversion = "{source_version}"\n', encoding="utf-8")
    (root / "docs" / "release_scope").mkdir(parents=True)
    for v in scopes:
        (root / "docs" / "release_scope" / f"{v}.md").write_text(_SCOPE_STUB.format(v=v),
                                                                  encoding="utf-8")
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


@pytest.mark.parametrize("source,expected", [("6.1.0", "6.2.0"), ("6.2.0", "6.3.0"),
                                             ("6.1.0.post1", "6.2.0")])
def test_without_a_version_the_gate_judges_the_oldest_scope_above_the_source(
        tmp_path, capsys, source, expected):
    """Not the release that is out, not the release after next, not 3.7.1, a patch scope that never
    shipped. The second row is the next release: the answer moves with the source version."""
    _rc, d = _gate_without_version(_tree(tmp_path, source, SCOPES), capsys)
    assert d["version"] == expected, d


@pytest.mark.parametrize("source,expected", [("6.1.0", "6.2.0"), ("6.2.0", "6.3.0")])
def test_without_a_version_the_card_counts_the_same_release(tmp_path, monkeypatch, source,
                                                             expected):
    d = _card_without_version(_tree(tmp_path, source, SCOPES), monkeypatch)
    assert d.get("version") == expected, d


@pytest.mark.parametrize("source", ["6.3.0", "6.2.0rc1", "not-a-version"])
def test_without_a_scope_above_a_released_source_both_refuse(tmp_path, capsys, monkeypatch, source):
    """No scope file above the source, or a source that is no released version: the gate is RED
    with the reason and the card NOT MEASURABLE. Neither falls back to a scope that is out."""
    root = _tree(tmp_path, source, SCOPES)
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
    headings, and the tags when this clone has them."""
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
