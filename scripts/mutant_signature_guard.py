#!/usr/bin/env python3
"""Fail-closed guard against mutation-mutant signatures on security paths (incident 2026-07-23).

A mutation probe planted `if False:` in place of the SD-JWT key-binding check in bundle.py and
the mutant survived into the working tree; only a manual diff-before-commit caught it. This guard
is the mechanical version of that manual look: it scans the CHANGE (staged diff or a commit
range) for the three narrow signature classes a left-over mutant takes, and blocks fail-closed.

Signature classes (deliberately narrow and explainable: a safety net, not a linter):

  A  a trivial-truth branch added at a check site:      `if False:` / `if True:` /
     `elif False:` / `elif True:` / `while False:` (also `if False and <original check>:`),
     judged on the syntax tree: the statement Python sees, however its lines are broken
  B  a commented-out verification call: a comment line that, read as Python on its own or joined
     with the comment lines directly below it, is a statement holding a call, anywhere in its expression
     tree, to a callee named for a check (verify/validate/check/compare_digest and their forms):
     `# if not merkle.verify_inclusion(...):`, `# key.from_public_bytes(b).verify(sig, msg)`, a
     call over two commented lines. Prose does not parse and does not match
  C  `return True` as the first statement of a function named for a check (`verify_x`,
     `_verifies`, `is_verified`, `validate`, `check_x`)
  D  a symlink or a gitlink under src/proofbundle, or `src` or `src/proofbundle` itself as one, in
     the judged state: the diff shows a link's text or a commit id, Python runs what it points at,
     which the scan does not reach (a mutant planted outside the security path and linked in was
     reported clean with exit 0, measured 2026-09-26, and so were a symlinked `src` and a gitlink
     under the package). Not diff-scoped on purpose: an existing link would hide every later change
     to its target. No allow marker: a link carries no comment.
  E  compiled code added or changed under src/proofbundle: a `.pyc`, `.pyo`, `.so` or `.pyd` file,
     or anything in a `__pycache__` directory. Python imports it and the guard cannot read it as
     source (a committed `__pycache__/x.cpython-310.pyc` and a sourceless `evil.pyc` were reported
     clean with exit 0, measured 2026-09-26). No allow marker: compiled code carries no comment.

Scope: every file under src/proofbundle/**/*.py and *.pyw (the verification library, every path
there is security-relevant) that the change adds or modifies, judged WHOLE, read as Python reads the
file: from its bytes, with its BOM and its PEP 263 coding cookie. The diff says which files changed;
it does not say which lines mean something new. A change of only the coding-cookie line decodes every
line after it anew, and a change that only removes, or only adds, lines that open and close a string
turns text that stood in the string into statements; each left a `return True` opening a verify
function unreported with exit 0 while only the added lines were judged (a review lens, run 10, and
a sibling measured beside it, 2026-09-26). A changed file there that Python itself cannot decode or
parse is not judged; the run stops fail-closed with the reason.
Legitimate exceptions are possible but must be VISIBLE in the diff: put a `# mutant-guard: allow`
comment on the flagged line or the line directly above it.

Modes:
  --staged        scan the staged diff (pre-commit hook; content read from the index)
  --base <sha>    scan <merge-base(sha, HEAD)>..HEAD (CI; all-zero / missing sha falls back
                  to HEAD~1, and to an empty scan on a root commit; a sha this clone does not
                  have, or one that shares no history with HEAD, stops fail-closed)
  --self-test     prove in a throwaway git repo that every class is caught and that the
                  negative controls stay quiet (the gate-meta-test; CI runs this first)

Exit codes: 0 clean · 1 mutant signature found · 2 internal/usage error (fail closed).
stdlib only, offline.
"""
from __future__ import annotations

import argparse
import ast
import codecs
import contextlib
import io
import re
import subprocess
import sys
import tempfile
import textwrap
import tokenize
import traceback
import unicodedata
import warnings
from pathlib import Path


def _repo_root() -> Path:
    """The repo the guard runs IN (cwd-based): the pre-commit hook and CI both execute at
    the checkout root; anchoring on the script location would scan the wrong repo when
    invoked from elsewhere (e.g. the test fixtures)."""
    proc = subprocess.run(["git", "rev-parse", "--show-toplevel"],
                          capture_output=True, text=True)
    if proc.returncode != 0 or not proc.stdout.strip():
        raise SystemExit("mutant_signature_guard: not inside a git repository (fail closed)")
    return Path(proc.stdout.strip())


#: `.` crosses a newline here: git writes a name with a newline quoted, the header decoder gives the
#: real name back, and without DOTALL `.*` stopped at it, so a mutant in such a file passed with
#: exit 0 (a review lens, measured 2026-09-26). The name ends where the value ends. `.pyw` is source
#: Python imports on Windows, so it is judged as source too.
_SECURITY_PATH = re.compile(r"\Asrc/proofbundle/.*\.pyw?\Z", re.DOTALL)
_ALLOW_MARKER = "mutant-guard: allow"


def _pfad(rel: str) -> str:
    """A name as a line-oriented report prints it: on one line, and with one reading.

    Printed raw, a name with a line break in it starts a line of its own, so a file name can write a
    line that reads like a verdict: a tracked file named `docs/z<LF>  - README.md:1: fake finding.md`
    split one problem of the version gate into two printed items, one blaming README.md (7056ebf6),
    and the four other release tools printed such a name raw as well (a review lens, run 10, measured
    2026-09-26 at 50f3ef33). A name that holds a character that does not print, a double quote or a
    backslash is written in double quotes with backslash escapes; every other name as it is. The same
    function stands in each of the six release tools, held identical by a test.
    """
    if all(c.isprintable() and c not in '"\\' for c in rel):
        return rel
    return '"' + "".join(
        "\\" + c if c in '"\\' else c if c.isprintable() else c.encode("unicode_escape").decode("ascii")
        for c in rel) + '"'


def _auszug(text: str) -> str:
    """A line of a judged file as a report quotes it: as it is when every character prints, and in the
    form `_pfad` writes otherwise, so a separator such as U+2028 in it does not start a report line."""
    return text if text.isprintable() else _pfad(text)


def _unerwartet(exc: BaseException) -> str:
    """An exception no branch of this tool names, as one report line: where it was raised, and its
    type and message. `traceback` makes the message text and says so when it cannot: `str()` of an int
    past Python's limit for writing it in decimal raises in turn. The same function stands in each of
    the six release tools, held identical by a test, so that each ends such a run in its own verdict
    for what it could not judge, and never in the exit code of a finding (a review lens, measured
    2026-09-27 at 53676296)."""
    ort = traceback.extract_tb(exc.__traceback__)[-1:]
    wo = f" at {Path(ort[0].filename).name}:{ort[0].lineno}" if ort else ""
    text = traceback.format_exception_only(type(exc), exc)[-1].strip()
    return f"an unexpected exception{wo}: {_pfad(text[:300])}"


def _trivial_truth_headers(tree: ast.AST) -> list[tuple[int, int]]:
    """Class A on the syntax tree: (first line, last line) of the header of every trivial-truth branch.

    Such a branch is an `if` or `elif` whose condition begins with the constant True or False, or a
    `while` whose condition begins with False: a bool constant that starts where the condition
    starts, which is what the former line pattern `if\\s+(?:False|True)\\b` read (`if True and data:`,
    `if False == x:`). Read per physical line, a branch written over a backslash continuation (`if \\`
    and `True:` on the next line) was reported clean with exit 0 (a review lens, measured 2026-09-26);
    the tree holds the statement Python sees. A name such as `Falsey_thing` is no constant, as before.

    PARENTHESES DO NOT MOVE THE START. The tree places `(True) and data` at its opening parenthesis and
    the constant one column later, so `if (True) and data:` and `while (False) or x:` were reported
    clean with exit 0 (a review lens, run 10, measured 2026-09-26). The first operand is therefore
    followed down, by `_first_operand`, to the first atom of the condition. A unary operator is not
    followed: `if not True:` and `if -True:` begin with an operator, not with the constant, and stay
    outside this class as they were.
    """
    headers = []
    for node in ast.walk(tree):
        if isinstance(node, ast.If):
            truths: tuple[bool, ...] = (True, False)
        elif isinstance(node, ast.While):
            truths = (False,)
        else:
            continue
        test = node.test
        start = (test.lineno, test.col_offset)
        first = _first_operand(test)
        if any(isinstance(n, ast.Constant) and isinstance(n.value, bool) and n.value in truths
               and (n is first or (n.lineno, n.col_offset) == start) for n in ast.walk(test)):
            headers.append((node.lineno, test.end_lineno or test.lineno))
    return sorted(headers)


def _first_operand(node: ast.AST) -> ast.AST:
    """The atom a condition begins with, parentheses aside: the first operand of `and`/`or`, the left
    side of a binary operator or a comparison, what an attribute, a subscript or a call is taken from,
    and the value a conditional expression gives first. Iterative, so a long chain costs no stack."""
    while True:
        if isinstance(node, ast.BoolOp):
            node = node.values[0]
        elif isinstance(node, (ast.BinOp, ast.Compare)):
            node = node.left
        elif isinstance(node, (ast.Attribute, ast.Subscript)):
            node = node.value
        elif isinstance(node, ast.Call):
            node = node.func
        elif isinstance(node, ast.IfExp):
            node = node.body
        else:
            return node


# Class B — commented-out verification CODE. A comment line is read as Python, on its own and joined
# with the comment lines directly below it: the shortest run from it that parses is the statement it
# holds, and it is a finding when that statement holds a call, anywhere in its expression tree, to a
# callee named for a check. Prose that merely names a function keeps words the parser refuses (`# verify_envelope
# (docstring says ...) never gets ...`), commented-out code parses (`# ok = hmac.compare_digest(a, b)`).
# The three false-positive shapes found on real 3.6.0..HEAD history are pinned as negative self-test
# cases below.
#
# THE STATEMENT, NOT ITS FIRST WORDS. The first form took a comment only when the check's name came
# first in it, after at most one `if`, `elif`, `return`, `assert` or `not` and one plain `name =`, and
# only when the comment parsed on its own line. A review lens measured 23 of 61 such forms caught at
# 6614ac32, every miss on main too (2026-09-27): a negated guard clause `# if not
# merkle.verify_inclusion(...):`, a verify called on a call's result, `# Ed25519PublicKey.
# from_public_bytes(...).verify(...)` (the Ed25519 check of signature.py), `bool(verify_anchor(...))`, a
# call over two commented lines, a tuple or subscript target, `##`, `# #`, `await` and a CamelCase name
# each passed with exit 0. Commented out one at a time, 151 of the 294 statements under src/proofbundle
# that call such a callee were caught then; all 294 are now.

#: The name of a check, by its stem, for class B's callee and class C's function: `verif` holds verify,
#: verifies, verified, verification and verifier, `validat` holds validate, validated and validation,
#: `check` holds check, checks and checked. Python binds a name in NFKC form, so a fullwidth `verify` is
#: this name too. The verb `verify` alone missed `_verifies` and `is_verified` opening with `return
#: True` (a review lens, 2026-09-27; demo.py binds `_verifies`).
_VERIFYISH_NAME = re.compile(r"verif|validat|check", re.IGNORECASE)
#: Class B's callee may also be the constant-time comparison a check calls.
_VERIFY_CALLEE = re.compile(r"verif|validat|check|compare_digest", re.IGNORECASE)
#: The longest run of comment lines read as one statement. The longest statement under src/proofbundle
#: that calls such a callee spans 23 lines (measured 2026-09-27).
_MAX_JOINED = 40
#: A clause that continues a compound statement, read after the start it needs.
_CLAUSE_START = {"elif": "if 0:\n    pass\n", "else": "if 0:\n    pass\n",
                 "except": "try:\n    pass\n", "finally": "try:\n    pass\n"}


def _comments(path: str, lines: list[str]) -> list[tuple[int, str, bool]]:
    """(line, text, alone) of every comment of a file, by Python's tokenizer: a `#` inside a string is
    no comment, and one behind code is; `alone` says whether the comment is all of its line. The lines
    are Python's (`_read_as_python`), the CR that ends one taken off, so the tokenizer numbers them as
    the parser did. A file the parser read and the tokenizer does not stops the run fail-closed."""
    text = "\n".join(line[:-1] if line.endswith("\r") else line for line in lines)
    found = []
    try:
        for tok in tokenize.generate_tokens(io.StringIO(text).readline):
            if tok.type == tokenize.COMMENT:
                row, col = tok.start
                found.append((row, tok.string, not lines[row - 1][:col].strip()))
    except (tokenize.TokenError, SyntaxError, ValueError) as exc:
        raise SystemExit(f"mutant_signature_guard: {_pfad(path)}: the tokenizer does not read this file "
                         "as the parser did, so the guard cannot say which of its lines are comments "
                         f"(fail closed): {_pfad(f'{type(exc).__name__}: {exc}')}") from None
    return found


def _code_of(comments: list[str]) -> str:
    """The code a run of comments holds: each one's `#` marks taken off (a run of them and a `:` after
    them, as in `##` and `#:`, and a second level, as in `# #`), then the lines dedented together, so a
    commented-out block keeps the indentation its lines have to each other."""
    bodies = [re.sub(r"^\s*#+:?", "", c) for c in comments]
    while all(b.lstrip().startswith("#") for b in bodies):
        bodies = [re.sub(r"^\s*#+:?", "", b) for b in bodies]
    lines = textwrap.dedent("\n".join(bodies)).split("\n")
    lines[0] = lines[0].lstrip()
    return "\n".join(lines)


def _commented_statement(code: str) -> ast.Module | None:
    """The code as Python parses it, or None when it does not parse. A header is given a body (`# if not
    verify(x):` needs one, also with a comment behind its colon), a last line that ends in a backslash
    loses it (the line it continued was not commented out), and a clause such as `elif` or `except` is
    read after the start it continues. RecursionError and MemoryError pass to the caller, which cannot
    say and stops: a comment `# ok = verify(` with 7000 nested unary minus raised a MemoryError past an
    except clause that named SyntaxError and ValueError, and the guard ended with a traceback and exit
    1, the code of a finding (a review lens, run 10, measured 2026-09-26)."""
    lines = code.rstrip().split("\n")
    if lines[-1].endswith("\\"):
        lines[-1] = lines[-1][:-1].rstrip()
    text = "\n".join(lines)
    readings = [text]
    if ":" in lines[-1]:
        readings.append(text + "\n" + " " * (len(lines[-1]) - len(lines[-1].lstrip()) + 4) + "pass")
    word = re.match(r"\w+", lines[0])
    if word and word.group(0) in _CLAUSE_START:
        readings += [_CLAUSE_START[word.group(0)] + r for r in readings]
    elif word and word.group(0) == "case":
        readings += ["match 0:\n" + textwrap.indent(r, "    ") for r in readings]
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")      # `# re.compile("\d")` warns of an escape; no verdict of ours
        for reading in readings:
            try:
                return ast.parse(reading)
            except (SyntaxError, ValueError):  # ValueError: a NUL byte, which ast.parse refuses on its own
                continue
    return None


def _verify_calls(tree: ast.AST) -> list[str]:
    """The names of the calls in `tree` whose callee is named for a check: a name, or the attribute that
    ends any chain (`merkle.verify_inclusion`, `key.from_public_bytes(b).verify`). A call inside an
    annotation does not count: prose such as `# NOTE: verify(x) ...` parses as a name annotated with the
    call, while code puts the call in the value (`# ok: bool = verify(x)` counts)."""
    in_annotation: set[int] = set()
    for node in ast.walk(tree):
        for annotation in (getattr(node, "annotation", None), getattr(node, "returns", None)):
            if isinstance(annotation, ast.AST):
                in_annotation.update(id(n) for n in ast.walk(annotation))
    names = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and id(node) not in in_annotation:
            func = node.func
            name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else ""
            if _VERIFY_CALLEE.search(name):
                names.append(name)
    return names


def _commented_out_calls(path: str, lines: list[str]) -> list[tuple[int, int]]:
    """Class B over a file's Python lines: (first line, last line) of each comment that holds a call to a
    check. A comment that stands alone on its line is read with the ones directly below it, up to
    `_MAX_JOINED`; the shortest run from it that parses is the statement it holds, and the lines of a run
    that holds such a call are not read again as a start. A run whose text names no check (NFKC, any
    case) cannot hold such a call and is not parsed. A comment behind code on its line is not read: the
    review lens that measured this class left `ok = True  # ok = verify(...)` at the class's boundary."""
    comments = _comments(path, lines)
    alone_at = {row: text for row, text, alone in comments if alone}
    found: list[tuple[int, int]] = []
    covered = 0
    for row, text in alone_at.items():
        if row <= covered:
            continue
        run = [text]
        while len(run) < _MAX_JOINED and row + len(run) in alone_at:
            run.append(alone_at[row + len(run)])
        if not _VERIFY_CALLEE.search(unicodedata.normalize("NFKC", "\n".join(run))):
            continue
        for end in range(len(run)):
            try:
                tree = _commented_statement(_code_of(run[:end + 1]))
            except (RecursionError, MemoryError):
                raise SystemExit(f"mutant_signature_guard: {_pfad(path)}:{row}: a comment nests deeper "
                                 "than the parser reads, so the guard cannot say whether it is "
                                 "commented-out code (fail closed)") from None
            if tree is None:
                continue
            if _verify_calls(tree):
                found.append((row, row + end))
                covered = row + end
            break
    return found


def _git_bytes(*args: str, cwd: Path) -> bytes:
    """git's output as it wrote it, as bytes; a failing call stops fail-closed.

    The stop names the call and git's reason as a name is written (`_pfad`): the call can carry a path
    (`show :<path>`), git echoes a path as it is and writes some reasons over several lines, so
    `fatal: path '<name>' does not exist` wrote a name with a line break as a second line of the stop
    (the sweep of the class a review lens found in the resolver, measured 2026-09-27 at 6614ac32)."""
    proc = subprocess.run(["git", "-C", str(cwd), *args], capture_output=True)
    if proc.returncode != 0:
        raise SystemExit(f"mutant_signature_guard: git {_pfad(' '.join(args[:2]))} failed (fail closed): "
                         f"{_pfad(proc.stderr.decode('utf-8', 'replace').strip()[:200])}")
    return proc.stdout


def _git(*args: str, cwd: Path) -> str:
    """git's output as it wrote it: bytes decoded, with no newline translation.

    Text mode turned a lone CR into a line end. git ends a line at LF only, so one added line
    `x = 1<CR>if False:` came back as two, the second without its `+`, and it was never judged
    (measured 2026-09-26: exit 0 over a staged `if False:` that Python reads as its own statement).
    """
    return _git_bytes(*args, cwd=cwd).decode("utf-8", "surrogateescape")


#: The diff's grammar, pinned against configuration. With `diff.mnemonicPrefix` the new side is
#: `i/` or `w/` instead of `b/`, and with `diff.external` another program writes the diff; either
#: made the guard report clean over a staged `if False:` (measured 2026-09-26). A textconv filter
#: would hand it converted text instead of the source. And a `-diff` or `binary` attribute in a
#: committed `.gitattributes` made git write `Binary files ... differ` instead of the lines, so
#: nothing was added and the guard reported clean, in CI too (measured the same day); `--text`
#: diffs every file as text. With `diff.renames=copies` git wrote a new file as a copy of a changed
#: one and showed only the lines that differ: a copied German `.md` was judged green by the language
#: gate, and a copy that dropped the allow marker above an `if True:` was clean for the guard
#: (measured 2026-09-26 at 1ecc2aca and at main); `--no-renames` makes every line at a new path an
#: added line, a moved file's too.
DIFF_GRAMMAR = ("--text", "--no-ext-diff", "--no-textconv", "--no-color", "--no-renames",
                "--src-prefix=a/", "--dst-prefix=b/")


#: The C escapes git writes inside a quoted path, besides octal `\ooo` for a byte.
_C_ESCAPES = {"a": 7, "b": 8, "t": 9, "n": 10, "v": 11, "f": 12, "r": 13, '"': 34, "\\": 92}


def _git_path(field: str) -> str:
    """A path as a diff header prints it, decoded to the path it names.

    git quotes a path that holds a byte outside printable ASCII (core.quotePath is on by default), a
    double quote, a backslash or a control character: it wraps it in double quotes and writes C
    escapes, octal for each byte (`"b/src/proofbundle/pr\\303\\274fung.py"`). Read verbatim, such a
    path matched no security path, and a staged `if False:` in it was reported clean with exit 0
    (measured 2026-09-26 in a throwaway repository; plain names and names with a space were caught).
    """
    s = field.strip()
    if len(s) < 2 or not (s.startswith('"') and s.endswith('"')):
        return s
    body, out, i = s[1:-1], bytearray(), 0
    while i < len(body):
        c = body[i]
        if c != "\\":
            out += c.encode("utf-8")
            i += 1
        elif body[i + 1:i + 2] in _C_ESCAPES:
            out.append(_C_ESCAPES[body[i + 1]])
            i += 2
        elif len(body[i + 1:i + 4]) == 3 and all(d in "01234567" for d in body[i + 1:i + 4]):
            out.append(int(body[i + 1:i + 4], 8))
            i += 4
        else:
            out += c.encode("utf-8")      # an escape git does not write: kept as it stands
            i += 1
    return out.decode("utf-8", "surrogateescape")


#: A hunk header: old start and count, new start and count; a count left out is 1.
_HUNK = re.compile(r"@@ -[0-9]+(?:,([0-9]+))? \+([0-9]+)(?:,([0-9]+))? @@")


def _added_lines_by_file(diff_text: str) -> dict[str, list[tuple[int, str]]]:
    """Parse a unified diff into {new_path: [(new_lineno, added_line_text), ...]}, in git's grammar.

    Every path the new side of the diff names is a key, with an empty list when its change only
    removes lines: such a change can give the lines that stay a new meaning, so the file is one the
    change touched even though no line of it is added (a review lens, run 10, measured 2026-09-26).

    A line is a header or a hunk line by its POSITION, not by its shape. The hunk header states how
    many old and new lines follow, and exactly those are read as the hunk; everything else is a
    header. Read by shape, an added line `++ 1` (valid Python) came out as `+++ 1`, was taken for a
    header naming the path `1`, and the `if False:` after it was attributed to that path and never
    judged (measured 2026-09-26: exit 0). Lines end at LF only, as git ends them.

    Raises ValueError when the text does not parse that way (a hunk header of another form, or a
    hunk that ends before its count); the callers stop fail-closed on it.
    """
    out: dict[str, list[tuple[int, str]]] = {}
    current: str | None = None
    old_left = new_left = lineno = 0
    for raw in diff_text.split("\n"):
        if old_left or new_left:
            kind = raw[:1]
            if kind == "+" and new_left:
                if current is not None:
                    out.setdefault(current, []).append((lineno, raw[1:]))
                lineno += 1
                new_left -= 1
            elif kind == "-" and old_left:
                old_left -= 1
            elif kind == " " and old_left and new_left:
                lineno += 1
                old_left -= 1
                new_left -= 1
            elif kind != "\\":            # `\ No newline at end of file` is counted by neither side
                raise ValueError(f"a hunk ends before its count at {raw[:60]!r}")
        elif raw.startswith("diff --git "):
            current = None
        elif raw.startswith("+++ "):
            path = _git_path(raw[4:])
            current = None if path == "/dev/null" else path.removeprefix("b/")
            if current is not None:
                out.setdefault(current, [])
        elif raw.startswith("@@"):
            m = _HUNK.match(raw)
            if not m:
                raise ValueError(f"a hunk header git does not write here: {raw[:60]!r}")
            old_left = 1 if m.group(1) is None else int(m.group(1))
            lineno = int(m.group(2))
            new_left = 1 if m.group(3) is None else int(m.group(3))
    if old_left or new_left:
        raise ValueError("the diff ends inside a hunk")
    return out


def _python_lines_of(content: str) -> tuple[list[str], list[range]]:
    """The file's lines as Python numbers them, and for each line git numbers, the Python lines in it.

    Python ends a line at CRLF, a lone CR or LF; git ends one at LF only. A lone CR inside a git
    line therefore starts a new Python line, which is how `x = 1<CR>if False:` is one line to git
    and two statements to Python. The CR of a CRLF stays at the end of its line.

    A UTF-8 BOM before the first line is skipped, as Python skips it: with it in place, `^\\s*`
    did not match a first line `<BOM>if False:`, which Python runs (measured 2026-09-26).
    """
    lines: list[str] = []
    spans: list[range] = []
    for git_line in content.removeprefix("\ufeff").split("\n"):
        pieces = re.split(r"\r(?!\Z)", git_line)
        spans.append(range(len(lines) + 1, len(lines) + 1 + len(pieces)))
        lines.extend(pieces)
    return lines, spans


def _read_as_python(path: str, raw: bytes) -> tuple[ast.Module, list[str], list[range]]:
    """The file as Python reads it: the tree Python builds from its bytes, its lines as Python
    numbers them, and for each line git numbers, the Python lines in it.

    From the BYTES, with the BOM and the PEP 263 coding cookie Python honours. Read as UTF-8, a file
    declaring `# -*- coding: latin-1 -*-` with one byte 0xfc in a string carried a surrogate there,
    the parser refused the text, and a `return True` opening `verify_signature` in that file was
    reported clean with exit 0; in a file declaring `# coding: utf-7`, `+AGkAZg- True:` is `if True:`
    to Python and was reported clean as well (review lenses, measured 2026-09-26). A file Python
    itself cannot decode or parse (a NUL byte, a wrong cookie, a syntax error) is not judged, since
    the guard cannot say what Python would run: the run stops fail-closed with the reason.

    Each git line is decoded in turn, so a line end that exists only in the decoded text (a lone CR,
    or `+AAo-` under UTF-7) starts a new Python line inside its git line. Two checks hold the reading
    to Python's: the lines decoded one by one join to the text of the whole file, and that text
    parses to the same tree, positions included, as the bytes did.
    """
    def stop(reason: str) -> SystemExit:
        return SystemExit(f"mutant_signature_guard: {_pfad(path)}: Python cannot read this file as "
                          f"source, so the guard cannot judge it (fail closed): {reason}")
    try:
        tree = ast.parse(raw)
        encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
        whole = raw.decode(encoding)
    except (SyntaxError, ValueError, LookupError, RecursionError, MemoryError) as exc:
        raise stop(f"{type(exc).__name__}: {exc}") from None
    decoder = codecs.getincrementaldecoder(encoding)()
    git_lines = raw.split(b"\n")
    lines: list[str] = []
    spans: list[range] = []
    parts: list[str] = []
    for i, git_line in enumerate(git_lines):
        last = i == len(git_lines) - 1
        try:
            text = decoder.decode(git_line if last else git_line + b"\n", final=last)
        except UnicodeDecodeError as exc:
            raise stop(f"its line {i + 1} does not decode on its own: {exc}") from None
        parts.append(text)
        if not last:
            if not text.endswith("\n"):
                raise stop(f"its line {i + 1} does not decode on its own where git ends it")
            text = text[:-1]
        pieces = re.split(r"\r\n|\r(?!\Z)|\n", text)
        spans.append(range(len(lines) + 1, len(lines) + 1 + len(pieces)))
        lines.extend(pieces)
    try:
        again = ast.parse(whole)
    except (SyntaxError, ValueError, RecursionError, MemoryError) as exc:
        raise stop(f"the text decoded here as {encoding} does not parse again: "
                   f"{type(exc).__name__}: {exc}") from None
    if "".join(parts) != whole or _tree_shape(again) != _tree_shape(tree):
        raise stop(f"the text decoded here as {encoding} is not the text Python parsed")
    return tree, lines, spans


#: The positions a node carries, compared with its type and fields (what `include_attributes` adds).
_POSITION = ("lineno", "col_offset", "end_lineno", "end_col_offset")


def _tree_shape(tree: ast.AST) -> list[tuple]:
    """A syntax tree as a flat list, node by node in `ast.walk` order: its type, its position, and
    every field, a child as its type and a value as `_field_value` holds it. The order and the child
    types fix the tree, so two trees are the same, positions included, exactly when their shapes are
    equal.

    `ast.dump` answers the same question by recursion. On a file Python compiles, 2000 nested unary
    minus or 1000 terms joined by `+`, it ran out of stack, and the guard stopped with "not the text
    Python parsed", which was not true (measured 2026-09-26 at 50f3ef33). This walk uses no stack.
    """
    shape = []
    for node in ast.walk(tree):
        fields = []
        for name, value in ast.iter_fields(node):
            if isinstance(value, ast.AST):
                fields.append((name, type(value).__name__))
            elif isinstance(value, list):
                fields.append((name, tuple(type(v).__name__ if isinstance(v, ast.AST) else _field_value(v)
                                           for v in value)))
            else:
                fields.append((name, _field_value(value)))
        shape.append((type(node).__name__, *(getattr(node, a, None) for a in _POSITION), tuple(fields)))
    return shape


def _field_value(value: object) -> object:
    """A field value as `_tree_shape` holds it: an int as the number itself, anything else as its `repr`.

    `repr` writes an int in decimal, and Python refuses that past 4300 digits. A changed file binding
    `N = 0x` and 3600 `f` digits, which Python compiles, ended the guard in `--staged` and `--base`, and
    the language gate in both of its forms, with a traceback and exit 1, the code of a finding and of
    ROT (a review lens, measured 2026-09-27 at 53676296). Two ints are compared by value, without any
    text, so two numbers are one shape exactly when they are one number, however long; `type(...) is
    int` keeps `True` apart from `1`, as `repr` did. Every other constant Python parses has a `repr`
    that cannot fail: a float, a complex number, a string or bytes, None and Ellipsis.
    """
    return value if type(value) is int else repr(value)


def _allowlisted(file_lines: list[str], lineno: int, last: int | None = None) -> bool:
    """The marker on the flagged line, on a further line of the same header, or directly above."""
    for candidate in range(lineno - 1, (last or lineno) + 1):
        if 1 <= candidate <= len(file_lines) and _ALLOW_MARKER in file_lines[candidate - 1]:
            return True
    return False


def _class_c_findings(tree: ast.Module, judged: set[int]) -> list[tuple[int, str]]:
    """`return True` as first non-docstring statement of a verify-ish function, if the def or the
    return line is among the judged lines (every line of a file the change touched, see `scan`)."""
    findings: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not _VERIFYISH_NAME.search(node.name):
            continue
        body = node.body
        if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
                and isinstance(body[0].value.value, str):
            body = body[1:]  # skip the docstring
        if not body or not isinstance(body[0], ast.Return):
            continue
        val = body[0].value
        if isinstance(val, ast.Constant) and val.value is True:
            if node.lineno in judged or body[0].lineno in judged:
                findings.append((body[0].lineno,
                                 f"`return True` opens verification function `{node.name}`"))
    return findings


def _file_bytes(path: str, *, staged: bool, cwd: Path) -> bytes:
    """The new side of the diff: the index for --staged, HEAD for --base (the range ends at HEAD, so
    the file on disk is not what the diff describes once the working tree differs)."""
    return _git_bytes("show", f":{path}" if staged else f"HEAD:{path}", cwd=cwd)


def _file_content(path: str, *, staged: bool, cwd: Path) -> str:
    return _file_bytes(path, staged=staged, cwd=cwd).decode("utf-8", "surrogateescape")


#: Tree entries that bring content under src/proofbundle without being a regular file, by git mode.
_NOT_A_FILE = {"120000": "a symlink", "160000": "a gitlink (a submodule)"}
_NO_MARKER = "carries no allow marker"


def _links_on_security_paths(*, staged: bool, cwd: Path) -> list[tuple[str, str, str]]:
    """(path, mode, object) of every entry that is no regular file under src/proofbundle, or on the
    way to it (`src`, `src/proofbundle`), in the judged state: the index for --staged, HEAD for --base.

    The listing starts at `src`, not at src/proofbundle: with `src` a symlink there is no path under
    src/proofbundle at all, and a gitlink was never a symlink. Both passed with exit 0 while Python
    imported the planted code (a review lens, measured 2026-09-26)."""
    if staged:
        listing = _git("ls-files", "-s", "-z", "--", "src", cwd=cwd)   # mode object stage\tpath
    else:
        listing = _git("ls-tree", "-r", "-z", "HEAD", "--", "src", cwd=cwd)  # mode type object\tpath
    found = []
    for entry in listing.split("\0"):
        if "\t" not in entry:
            continue
        meta, path = entry.split("\t", 1)
        fields = meta.split(" ")
        on_the_way = path in ("src", "src/proofbundle") or path.startswith("src/proofbundle/")
        if fields[0] in _NOT_A_FILE and on_the_way:
            found.append((path, fields[0], fields[1] if staged else fields[2]))
    return sorted(found)


def scan(diff_text: str, *, staged: bool, cwd: Path) -> list[str]:
    """Judge every file the change touched under the security path whole, as Python reads it. The
    diff says WHICH files changed and which git lines are new; the lines it adds are held against the
    file, and then every Python line of the file is judged, because a change can give the lines it
    leaves alone a new meaning (see the module docstring). Line numbers and the allow marker are
    Python's.

    Measured when this became so, 2026-09-26: none of the 72 tracked `.py` files under
    src/proofbundle carries a class A, B or C signature when read whole, so judging a changed file
    whole reports no line that was there before. Measured again when class B came to read the
    statement a comment holds and class C the stem of a check's name, 2026-09-27: none of the 72
    does, and none of their 5242 comments holds a call to a check."""
    try:
        per_file = _added_lines_by_file(diff_text)
    except ValueError as exc:
        raise SystemExit(f"mutant_signature_guard: the diff does not parse as git writes it "
                         f"(fail closed): {exc}") from exc
    findings: list[str] = []
    links = _links_on_security_paths(staged=staged, cwd=cwd)
    for path, added in per_file.items():
        # A link's text is no source; the link is class D, below.
        if not _SECURITY_PATH.match(path) or any(path == link for link, _, _ in links):
            continue
        raw = _file_bytes(path, staged=staged, cwd=cwd)
        git_lines = raw.decode("utf-8", "surrogateescape").split("\n")
        for git_no, text in added:
            # The diff and the file are two readings of one state; if they disagree, neither is judged.
            if not 1 <= git_no <= len(git_lines) or git_lines[git_no - 1] != text:
                raise SystemExit(f"mutant_signature_guard: {_pfad(path)}:{git_no}: the diff and the "
                                 f"file disagree about this line (fail closed)")
        tree, file_lines, _ = _read_as_python(path, raw)
        judged = set(range(1, len(file_lines) + 1))
        in_order: list[tuple[int, str]] = []
        for first, last in _trivial_truth_headers(tree):
            if _allowlisted(file_lines, first, last):
                continue
            header = " ".join(file_lines[n - 1].strip() for n in range(first, last + 1))
            in_order.append((first, f"{_pfad(path)}:{first}: trivial-truth branch (`if/elif "
                                    f"False|True` / `while False`) at a check\n    {_auszug(header)}"))
        for first, last in _commented_out_calls(path, file_lines):
            if _allowlisted(file_lines, first, last):
                continue
            in_order.append((first, f"{_pfad(path)}:{first}: commented-out verification call\n"
                                    f"    {_auszug(file_lines[first - 1].strip())}"))
        findings.extend(finding for _, finding in sorted(in_order))
        for lineno, reason in _class_c_findings(tree, judged):
            if not _allowlisted(file_lines, lineno):
                findings.append(f"{_pfad(path)}:{lineno}: {reason}")
    for path, mode, obj in links:
        if mode == "120000":
            target = _file_content(path, staged=staged, cwd=cwd).strip()
            findings.append(f"{_pfad(path)}: {_NOT_A_FILE[mode]} on a security path (to "
                            f"{_pfad(target)}) — the guard reads the link, Python runs its target, which "
                            f"this scan does not reach; a link {_NO_MARKER}, so put the file itself there")
        else:
            findings.append(f"{_pfad(path)}: {_NOT_A_FILE[mode]} on a security path (commit "
                            f"{obj[:12]}) — the diff shows a commit id, Python runs the files under it, "
                            f"which this scan does not reach; a gitlink {_NO_MARKER}, so put the files "
                            "themselves there")
    return findings


#: Class E: what Python imports from under src/proofbundle without it being source. Bytecode is
#: loaded from `__pycache__` in place of the source it claims to come from, or beside it as a
#: sourceless module; `.so` and `.pyd` are extension modules, native code.
_COMPILED_SUFFIXES = (".pyc", ".pyo", ".so", ".pyd")


def _compiled_findings(names: str) -> list[str]:
    """Class E over a `--name-only -z` listing of the paths the change adds or modifies."""
    return [f"{_pfad(name)}: compiled code on a security path — Python imports it, and the guard cannot "
            f"read it as source; compiled code {_NO_MARKER}, so commit the source instead"
            for name in sorted(n for n in names.split("\0") if n)
            if name.endswith(_COMPILED_SUFFIXES) or "__pycache__" in name.split("/")]


def _is_commit(rev: str, cwd: Path) -> bool:
    return subprocess.run(["git", "-C", str(cwd), "rev-parse", "--verify", "--quiet",
                           f"{rev}^{{commit}}"], capture_output=True).returncode == 0


def _resolve_base(base: str, cwd: Path) -> str | None:
    """The merge base of the CI-provided base and HEAD, or None for the one documented honest skip.

    No base given (empty or all-zero, as on a first push or a merge queue entry) means HEAD's parent,
    and a root commit has none: there is nothing to diff, and the run says so. A base that IS given
    but is no commit in this clone, or shares no history with HEAD, stops fail-closed: such a base
    printed "scan skipped honestly" and then "clean" with exit 0 over a range nobody read (a review
    lens, measured 2026-09-26). A shallow clone lacks the base; fetch it.
    """
    if not base or set(base) == {"0"}:
        if not _is_commit("HEAD", cwd):
            raise SystemExit("mutant_signature_guard: HEAD is no commit, so there is no range to "
                             "scan (fail closed)")
        if not _is_commit("HEAD~1", cwd):
            return None
        base = "HEAD~1"
    elif not _is_commit(base, cwd):
        raise SystemExit(f"mutant_signature_guard: the base {base!r} is no commit in this clone, so "
                         "the range cannot be scanned (fail closed); a shallow clone lacks it, fetch it")
    mb = subprocess.run(["git", "-C", str(cwd), "merge-base", base, "HEAD"],
                        capture_output=True, text=True)
    if mb.returncode != 0 or not mb.stdout.strip():
        raise SystemExit(f"mutant_signature_guard: the base {base!r} shares no history with HEAD, so "
                         "the range cannot be scanned (fail closed)")
    return mb.stdout.strip()


def run_staged(cwd: Path) -> list[str]:
    diff = _git("diff", "--cached", "-U0", *DIFF_GRAMMAR, "--", "src/proofbundle", cwd=cwd)
    names = _git("diff", "--cached", "--name-only", "-z", "--no-renames", "--diff-filter=d",
                 "--", "src/proofbundle", cwd=cwd)
    return scan(diff, staged=True, cwd=cwd) + _compiled_findings(names)


def run_base(base: str, cwd: Path) -> list[str]:
    resolved = _resolve_base(base, cwd)
    if resolved is None:
        print("mutant_signature_guard: HEAD is a root commit and no base was given — nothing to "
              "diff, scan skipped honestly")
        return []
    diff = _git("diff", "-U0", *DIFF_GRAMMAR, resolved, "HEAD", "--", "src/proofbundle", cwd=cwd)
    names = _git("diff", "--name-only", "-z", "--no-renames", "--diff-filter=d", resolved, "HEAD",
                 "--", "src/proofbundle", cwd=cwd)
    return scan(diff, staged=False, cwd=cwd) + _compiled_findings(names)


# --- self-test (gate-meta-test: prove each class is caught, and the negatives stay quiet) -----

_BENIGN = '''def verify_thing(data):
    """Real check."""
    if not isinstance(data, dict):
        return False
    return bool(data.get("ok"))


def helper(x):
    # verify the payload first, then compare digests (prose comment, must NOT match)
    return x
'''

_CASES: list[tuple[str, str | bytes, bool]] = [
    # (label, replacement content for src/proofbundle/guarded.py, expect_finding)
    ("A: if False at a check",
     _BENIGN.replace('if not isinstance(data, dict):', 'if False:'), True),
    ("A: if True and original check",
     _BENIGN.replace('if not isinstance(data, dict):', 'if True and data:'), True),
    ("B: commented-out verification call",
     _BENIGN.replace('    return bool(data.get("ok"))',
                     '    # ok = hmac.compare_digest(a, b)\n    return True'), True),
    ("C: return True opens a verify function",
     'def verify_thing(data):\n    return True\n', True),
    ("B: commented-out if-header of a check",
     _BENIGN.replace('if not isinstance(data, dict):',
                     '# if _validate_shape(data):\n    if data is None:'), True),
    # Class B reads the statement a comment holds, not its first words (2026-09-27): each of these two
    # passed with exit 0, the second the Ed25519 check of signature.py.
    ("B: a commented-out negated guard clause",
     _BENIGN.replace('    return bool(data.get("ok"))',
                     '    # if not merkle.verify_inclusion(leaf, index, size, proof, root):\n'
                     '    #     return False\n    return True'), True),
    ("B: a commented-out verify called on a call's result",
     _BENIGN.replace('    return bool(data.get("ok"))',
                     '    # Ed25519PublicKey.from_public_bytes(bytes(key)).verify(bytes(sig), bytes(msg))\n'
                     '    return True'), True),
    ("negative: prose that parses as a name annotated with a call",
     _BENIGN + '\n# NOTE: verify_thing(data)\n', False),
    ("negative: prose naming a function before a parenthetical (real FP shape, dsse.py)",
     _BENIGN + '\n# verify_thing (docstring says only ValueError) never gets a raw error.\n', False),
    ("negative: function name with parens inside prose (real FP shape, outcome.py)",
     _BENIGN + '\n# verify_thing() is the explicit exception variant.\n', False),
    ("negative: code-then-prose narrative (real FP shape, signature.py)",
     _BENIGN + '\n# pub.verify(sig, data) and raised a raw TypeError nobody caught.\n', False),
    ("negative: benign refactor stays quiet",
     _BENIGN.replace('bool(data.get("ok"))', 'bool(data.get("okay"))'), False),
    ("negative: allowlist marker suppresses, visibly",
     _BENIGN.replace('if not isinstance(data, dict):',
                     'if True:  # mutant-guard: allow (fixture, reviewed)'), False),
    # A line is a header by position, not by shape (2026-09-26): `++ 1` is valid Python, and its
    # diff line `+++ 1` once read as a header naming the path `1`.
    ("A: after an added line that looks like a diff header",
     _BENIGN + "++ 1\nif False:\n    pass\n", True),
    # Python ends a line at a lone CR, git does not (2026-09-26).
    ("A: after a lone CR, which Python reads as a line end",
     _BENIGN.replace('    if not isinstance(data, dict):', '    x = 1\r    if False:'), True),
    ("A: behind a BOM on the first line, which Python skips",
     "\ufeffif False:\n    pass\n", True),
    # The statement Python sees, and the file as Python decodes it (2026-09-26).
    ("A: over a backslash continuation",
     _BENIGN.replace('    if not isinstance(data, dict):', '    if \\\n       True:'), True),
    ("C: in a file whose coding cookie says latin-1",
     b"# -*- coding: latin-1 -*-\ns = '\xfc'\ndef verify_thing(data):\n    return True\n", True),
    ("A: in a file whose coding cookie says utf-7",
     "# coding: utf-7\n+AGkAZg- True:\n    pass\n", True),
    # Parentheses around the first operand do not move where the condition starts (2026-09-26).
    ("A: a parenthesized constant as the first operand",
     _BENIGN.replace('if not isinstance(data, dict):', 'if (True) and data:'), True),
    # An int Python compiles and cannot write in decimal, past 4300 digits (2026-09-27).
    ("A: beside an int literal past the decimal digit limit",
     "N = 0x" + "f" * 3600 + "\nif False:\n    pass\n", True),
    ("negative: an int literal past the decimal digit limit alone stays quiet",
     "N = 0x" + "f" * 3600 + "\n", False),
]


def self_test() -> int:
    failures = 0
    with tempfile.TemporaryDirectory(prefix="mutant-guard-selftest-") as tmp:
        repo = Path(tmp)
        _git("init", "-q", cwd=repo)
        _git("config", "user.email", "guard@selftest.local", cwd=repo)
        _git("config", "user.name", "guard-selftest", cwd=repo)
        target = repo / "src" / "proofbundle" / "guarded.py"
        target.parent.mkdir(parents=True)
        target.write_text(_BENIGN, encoding="utf-8")
        outside = repo / "scripts" / "not_security.py"
        outside.parent.mkdir(parents=True)
        outside.write_text("x = 1\n", encoding="utf-8")
        _git("add", "-A", cwd=repo)
        _git("commit", "-q", "-m", "base", cwd=repo)
        for label, content, expect in _CASES:
            target.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
            _git("add", "-A", cwd=repo)
            found = bool(run_staged(repo))
            ok = found == expect
            print(f"  {'ok  ' if ok else 'FAIL'} [{label}] "
                  f"{'caught' if found else 'quiet'} ({'expected' if ok else 'UNEXPECTED'})")
            failures += 0 if ok else 1
            # Unstage FIRST, then restore the file from the index. The other order restored the
            # file from the staged case and left it in the working tree, so the next `add -A`
            # staged it again: the negative control below held only while the last case happened
            # to be one that stays quiet (found 2026-09-26, when a catching case became the last).
            _git("reset", "-q", cwd=repo)
            _git("checkout", "-q", "--", ".", cwd=repo)
        # a change that only removes lines gives the lines it leaves a new meaning (2026-09-26): the
        # two lines that held `return True` in a string go, and it opens the function
        held = 'def verify_thing(data):\n    """\n    return True\n    """\n    return data == 1\n'
        target.write_text(held, encoding="utf-8")
        _git("add", "-A", cwd=repo)
        _git("commit", "-q", "-m", "a string that holds a return", cwd=repo)
        target.write_text(held.replace('    """\n', ""), encoding="utf-8")
        _git("add", "-A", cwd=repo)
        caught = bool(run_staged(repo))
        print(f"  {'ok  ' if caught else 'FAIL'} [C: a change that only removes lines] "
              f"{'caught' if caught else 'quiet'} ({'expected' if caught else 'UNEXPECTED'})")
        failures += 0 if caught else 1
        _git("reset", "-q", cwd=repo)
        _git("checkout", "-q", "--", ".", cwd=repo)
        # negative: the same planted signature OUTSIDE the security path stays quiet
        outside.write_text("if False:\n    pass\n", encoding="utf-8")
        _git("add", "-A", cwd=repo)
        quiet = not run_staged(repo)
        print(f"  {'ok  ' if quiet else 'FAIL'} [negative: non-security path ignored] "
              f"{'quiet' if quiet else 'caught'} ({'expected' if quiet else 'UNEXPECTED'})")
        failures += 0 if quiet else 1
        # a path git quotes in the diff header is read as the path it names (2026-09-26)
        outside.write_text("x = 1\n", encoding="utf-8")
        quoted = repo / "src" / "proofbundle" / "pr\u00fcfung.py"
        quoted.write_text("if False:\n    pass\n", encoding="utf-8")
        _git("add", "-A", cwd=repo)
        caught = bool(run_staged(repo))
        print(f"  {'ok  ' if caught else 'FAIL'} [A: a security path git quotes (non-ASCII name)] "
              f"{'caught' if caught else 'quiet'} ({'expected' if caught else 'UNEXPECTED'})")
        failures += 0 if caught else 1
        # configuration that rewrites the diff's grammar does not blind the guard (2026-09-26)
        quoted.unlink()
        _git("add", "-A", cwd=repo)
        _git("config", "diff.mnemonicPrefix", "true", cwd=repo)
        _git("config", "diff.external", "true", cwd=repo)
        target.write_text(_BENIGN.replace('if not isinstance(data, dict):', 'if False:'),
                          encoding="utf-8")
        _git("add", "-A", cwd=repo)
        caught = bool(run_staged(repo))
        print(f"  {'ok  ' if caught else 'FAIL'} [A: with diff.mnemonicPrefix and diff.external set] "
              f"{'caught' if caught else 'quiet'} ({'expected' if caught else 'UNEXPECTED'})")
        failures += 0 if caught else 1
        # an attribute that makes git print `Binary files differ` does not hide the lines
        (repo / ".gitattributes").write_text("*.py -diff\n", encoding="utf-8")
        _git("add", "-A", cwd=repo)
        caught = bool(run_staged(repo))
        print(f"  {'ok  ' if caught else 'FAIL'} [A: with a committed-style `*.py -diff` attribute] "
              f"{'caught' if caught else 'quiet'} ({'expected' if caught else 'UNEXPECTED'})")
        failures += 0 if caught else 1
        # a symlink on a security path, its target outside the scanned tree (2026-09-26)
        target.write_text(_BENIGN, encoding="utf-8")
        outside.write_text(_BENIGN.replace('if not isinstance(data, dict):', 'if False:'), encoding="utf-8")
        (target.parent / "linked.py").symlink_to("../../scripts/not_security.py")
        _git("add", "-A", cwd=repo)
        caught = any("symlink on a security path" in f for f in run_staged(repo))
        print(f"  {'ok  ' if caught else 'FAIL'} [D: a symlink under src/proofbundle to a file outside] "
              f"{'caught' if caught else 'quiet'} ({'expected' if caught else 'UNEXPECTED'})")
        failures += 0 if caught else 1
        # compiled code on a security path, which Python imports and no scan reads (2026-09-26)
        cache = target.parent / "__pycache__"
        cache.mkdir()
        (cache / "guarded.cpython-310.pyc").write_bytes(b"\x6f\x0d\x0d\x0a" + bytes(12))
        _git("add", "-f", "--", "src/proofbundle/__pycache__/guarded.cpython-310.pyc", cwd=repo)
        caught = any("compiled code on a security path" in f for f in run_staged(repo))
        print(f"  {'ok  ' if caught else 'FAIL'} [E: bytecode in __pycache__ under src/proofbundle] "
              f"{'caught' if caught else 'quiet'} ({'expected' if caught else 'UNEXPECTED'})")
        failures += 0 if caught else 1
    print(f"self-test: {'OK' if failures == 0 else f'FAILED ({failures})'}")
    return 0 if failures == 0 else 1


def _stop(text: str) -> int:
    """A fail-closed stop: its reason on stderr, exit 2. A stderr that refuses the reason does not
    change the exit code."""
    with contextlib.suppress(Exception):
        print(text, file=sys.stderr)
    return 2


def main(argv: list[str] | None = None) -> int:
    # ONE EXIT FOR EVERY FAIL-CLOSED STOP. Each stop raises SystemExit with its reason as text.
    # Uncaught, such a SystemExit would end the run with exit 1, the exit code of a finding, while the
    # docstring says 2: a caller who reads the exit code took "not inside a git repository" or "git
    # diff failed" for a mutant found (a review lens of another model family, measured 2026-09-26).
    #
    # AND EVERY LINE OF `main` STANDS IN THAT CATCH, from the parsed arguments to the printed verdict.
    # The stream set-up and the report stood outside it, so an exception there ended the run with a
    # traceback and exit 1, the code of a finding; the other four release tools also resolved a path
    # outside theirs (a review lens, measured 2026-09-27 at 6614ac32).
    try:
        p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
        mode = p.add_mutually_exclusive_group(required=True)
        mode.add_argument("--staged", action="store_true", help="scan the staged diff (pre-commit)")
        mode.add_argument("--base", metavar="SHA", help="scan merge-base(SHA, HEAD)..HEAD (CI)")
        mode.add_argument("--self-test", action="store_true", help="prove the guard catches each class")
        a = p.parse_args(argv)
        # A path is read as git names it, so a name that is not UTF-8 carries surrogates, and a strict
        # stdout raised on one with exit 1 and a traceback instead of the finding (measured 2026-09-26,
        # a mutant under src/proofbundle/ in a file whose name is the byte 0xff). The four path readers
        # below this change write such a name with backslash escapes; so does this report.
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(errors="backslashreplace")
        if a.self_test:
            return self_test()
        repo = _repo_root()
        findings = run_staged(repo) if a.staged else run_base(a.base, repo)
        if findings:
            print("mutant_signature_guard: BLOCKED: mutation-mutant signature(s) on security paths:")
            for f in findings:
                print(f"  {f}")
            if any(_NO_MARKER not in f for f in findings):
                print("If this is intentional and legitimate, add a visible `# mutant-guard: allow` "
                      "comment on (or directly above) the flagged line so review sees the exception.")
            return 1
        print("mutant_signature_guard: clean, no mutant signatures in the scanned change")
        return 0
    except SystemExit as stop:
        if isinstance(stop.code, str):
            return _stop(stop.code)
        raise                             # argparse's own exit: 2 for a usage error, 0 for --help
    # AN EXCEPTION NO STOP NAMES IS A STOP TOO. Uncaught, such an exception would end the run with exit
    # 1, the code of a finding: an int past the digit limit in a changed file raised in `_tree_shape`,
    # and the guard said "mutant found" by its exit code over a file with no signature in it (a review
    # lens, measured 2026-09-27 at 53676296). It cannot say what it did not judge, so it says that it
    # did not, with exit 2.
    except Exception as exc:  # noqa: BLE001 -- every other exception is no verdict of this guard
        return _stop(f"mutant_signature_guard: the run stopped on {_unerwartet(exc)}, so the change is "
                     "not judged (fail closed)")


if __name__ == "__main__":
    raise SystemExit(main())
