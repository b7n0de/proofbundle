#!/usr/bin/env python3
"""Fail-closed guard against mutation-mutant signatures on security paths (incident 2026-07-23).

A mutation probe planted `if False:` in place of the SD-JWT key-binding check in bundle.py and
the mutant survived into the working tree; only a manual diff-before-commit caught it. This guard
is the mechanical version of that manual look: it scans the CHANGE (staged diff or a commit
range) for the three narrow signature classes a left-over mutant takes, and blocks fail-closed.

Signature classes (deliberately narrow and explainable: a safety net, not a linter):

  A  a trivial-truth branch added at a check site:      `if False:` / `if True:` /
     `elif False:` / `elif True:` / `while False:` (also `if False and <original check>:`),
     judged on the syntax tree: the statement Python sees, however its lines are broken, and the
     constant however it is spelled (a name Python binds to it, such as `False` in fullwidth letters)
  B  a commented-out verification call: a comment line that, read as Python on its own or joined
     with the comment lines directly below it, is a statement holding a call, anywhere in its expression
     tree, to a callee named for a check (verify/validate/check/compare_digest and their forms):
     `# if not merkle.verify_inclusion(...):`, `# key.from_public_bytes(b).verify(sig, msg)`, a
     call over two commented lines, or over a backslash that ends a commented line. Prose does not
     parse and does not match. Nor does a statement that makes no check by what it does as code, which
     is how a Markdown bullet parses: an expression statement that applies `-`, `+` or `~` to a call
     (`# - verify(x)`), a star with a space after it (`# * verify(x)`), or an enumerated item, a method
     call on a one-letter name with a space after the dot (`# a. verify(x)`). `not` before a call, a comparison,
     `and` and `or` stay findings (the class B notes below say why). Reading comments as code is bounded
     by their size; past the bound the file is not judged (exit 2)
  C  `return True` as the first statement of a function named for a check (`verify_x`,
     `_verifies`, `is_verified`, `validate`, `check_x`), the constant however it is spelled
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
parse is not judged; the run stops fail-closed with the reason. One refusal differs between the
versions the package runs on: 3.13 and later refuse a name spelled as `True`, `False` or `None`, which
3.10 to 3.12 read, and the guard reads such a source as 3.10 to 3.12 do on every version (`_parse`),
rewriting only those names. Named limit: the guard's reading relies on CPython's `ast`, with the grammar
and the Unicode tables of the interpreter that runs it, for a changed file and for the code class B reads
in a comment alike. Where the versions differ (a t-string, a type alias, an f-string that nests quotes, a
letter Unicode added later), a file one of them cannot parse stops the run there, and a comment holding
such a form is code, and may be a finding, only on the versions that parse it: an older one reports clean
what a newer one flags (a review lens, run 15, measured 2026-09-27; the U+A7F3 form on main as well).
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
import functools
import io
import itertools
import os
import re
import string
import subprocess
import sys
import tempfile
import textwrap
import tokenize
import traceback
import unicodedata
import warnings
from collections.abc import Callable, Iterator
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
    outside this class as they were. The constant is read as `_bool_constant` reads it, so a name that
    Python binds to True or False counts as the constant.
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
        if any(_bool_constant(n) in truths and (n is first or (n.lineno, n.col_offset) == start)
               for n in ast.walk(test)):
            headers.append((node.lineno, test.end_lineno or test.lineno))
    return sorted(headers)


def _bool_constant(node: ast.AST) -> bool | None:
    """The bool a node is: the constant True or False, or a name whose NFKC form is `True` or `False`.

    Python binds a name in its NFKC form, so `True` written in fullwidth letters is no keyword to the
    parser but the name `True`, and running it loads True from the builtins (3.10 to 3.12; 3.13 and later
    refuse the source, which `_parse` reads as the earlier versions do). Such a `return` opening
    `verify_thing`, and an `if` with `False` written that way at a check, were clean with exit 0, on
    main too (a review lens, run 13, measured 2026-09-27 at a435ba32). Classes A and C read such a name
    as the constant. Any other node is no bool constant (None)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, bool):
        return node.value
    if isinstance(node, ast.Name):
        name = unicodedata.normalize("NFKC", node.id)
        if name in ("True", "False"):
            return name == "True"
    return None


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
#
# A BACKSLASH CONTINUES THE STATEMENT. The run that parses first is not the statement while its last
# line ends in a backslash that joins the next comment line: the search goes on into that line.
# `_commented_statement` drops a backslash that ends the last line it reads, since the line it
# continued may not be commented out (`# ok = hmac.compare_digest(a, b) \` above live code). So the
# Ed25519 check of signature.py, written in this tree's backslash style and commented out,
# `# Ed25519PublicKey.from_public_bytes(bytes(public_key)) \` over `#     .verify(bytes(signature),
# bytes(message))`, ended the search at its first line, which parses and calls no check, while its
# second line, the check, does not parse on its own. It was clean with exit 0 in both modes, and so
# were an assignment, `and`, `return`, `assert`, a conditional expression and a tuple continued that
# way, and the same inside an `if` body (a review lens, run 13, measured 2026-09-27 at a435ba32). The
# other ways a statement goes on past a line that parses alone are a bracket and a string still open,
# and neither parses alone; a string literal after another, or an element after a trailing comma,
# continues a statement only inside such a bracket or behind such a backslash.
#
# A BULLET IS NO STATEMENT OF A CHECK. A Markdown list in a comment parses as code: `#   -
# verify_checkpoint(signed_note, log_vkey)` as a unary minus on the call, `#   * verify(sig)` as a
# starred call, `# a. verify(sig)` as a method call. Two bullets naming entry points, added to the spec
# block of checkpoint.py, were flagged with exit 1 (a review lens, run 13, at a435ba32). It is decided by
# what the statement does as code (`_no_check`): an expression statement whose value applies `-`, `+` or
# `~` to a call turns the check's result into a number nobody reads, and no check does that, inside live
# brackets or outside them. A star counts as a bullet only with the space a bullet has: code writes
# `*verify_each(x)`, which unpacks the check's results as the last element of live brackets. A call on an
# attribute of a one-letter name with a space after the dot is an enumerated item: code writes no space
# there. `not` stays a check, since `# not verify(x)` runs the check as `# verify(x)` does and is a
# condition as an element of live brackets, and so do a comparison, `and` and `or`: prose such as
# `# verify_chain() is idempotent` is still flagged, and an allow marker clears it.
#
# THE WORK IS BOUNDED BY THE SIZE OF THE COMMENTS. Each prefix of a run was parsed until one parsed, so a
# run that parses nowhere cost up to 40 parses of up to 40 lines for each line it starts at: 1312 comment
# lines of 798 bytes, each an unclosed call, took 623.96 s (1,047,007 bytes staged; a review lens, run
# 13, at a435ba32). `_lex` now reads each comment line's code once, as Python's tokenizer reads its
# brackets, strings and backslashes, and a prefix is parsed only where Python could end a statement: with
# no bracket and no string still open, and, after a `try`, once a line of its own indentation follows.
# No longer prefix is parsed after an error no later line repairs: a closing bracket without its opener,
# a string left open, a character that is no token, a backslash with text after it, or a logical line
# that is complete, parses alone in no reading, and is none a later line completes (a decorator, `try`,
# `match`). The search ends there, unless a later line of the run is read at fewer levels of `#`, which
# turns the line with the error into a comment. A search whose first line holds no code at the level it
# is read at ends as well: the first code line below starts a search of its own, and comment lines above
# it make no reading parse that fails without them. Where `_lex` cannot follow a line as the running
# Python does, every prefix after it is parsed, as before. The parsing that remains is bounded:
# `_PARSE_PER_BYTE` bytes handed to the parser per byte of the file's comments, and `_PARSE_FLOOR` more.
# Past that the file is not judged, and the run stops fail-closed with exit 2, never clean.
#
# AND THE WORK ON A TREE IT PARSED IS LINEAR IN THE READING, so the bound on the parsing bounds that work
# too. `_no_check` read the space after a star or a dot with `ast.get_source_segment`, which splits the
# whole reading into lines again at each call; asked once per statement, it cost the number of statements
# times the size of the reading, and the bound counts only the bytes handed to the parser. A review lens,
# run 14, found it at 0b9edc94: one comment line of `a.f(); ` 13000 times, 91,182 bytes staged, ran 259 s
# there with exit 0 on 3.10, and `* f(); ` and `a. f(); ` as long. `_Segments` splits a reading once.

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
#: The start of a logical line that parses alone in no reading and still stands in valid code: a
#: decorator needs the `def` below it, `try` its handler, `match` its cases.
_COMPLETED_LATER = re.compile(r"\s*(?:@|(?:try|match)\b)")
#: A `try` statement: until a line of its own indentation follows it, it has no handler and no reading
#: parses it.
_TRY = re.compile(r"try\b")
#: One group of `#` marks a comment's code opens with: `#`, `##` and `#:` are one each, `# #` is two.
_HASH_GROUP = re.compile(r"\s*#+:?")
#: Where `_lex` stops: a quote, a `#`, a bracket, a backslash, and the three characters that are no
#: token of Python outside a string.
_LEX_STOP = re.compile(r"""['"#()\[\]{}\\?$`]""")
#: The rest of a string after its opening quotes, up to and with its closing quotes. A backslash escapes
#: the character after it; for where a string ends, a raw string reads it the same way.
_STRING_REST = {"'": re.compile(r"(?:[^\\']|\\.)*'"), '"': re.compile(r'(?:[^\\"]|\\.)*"'),
                "'''": re.compile(r"(?:[^\\']|\\.|'(?!''))*'''"),
                '"""': re.compile(r'(?:[^\\"]|\\.|"(?!""))*"""')}
#: The prefixes of an f-string and of a t-string. From Python 3.12 on, a field of one may hold quotes
#: (PEP 701), so `_lex` follows such a string only where every version ends it alike; before 3.12 it ends
#: as any other string does, and a t-string is a name before a string.
_FIELD_PREFIXES = {"f", "rf", "fr", "t", "rt", "tr"}
_FIELDS_NEST = sys.version_info >= (3, 12)
#: The parsing class B may do for one file: `_PARSE_PER_BYTE` bytes handed to the parser per byte of the
#: comments it reads, and `_PARSE_FLOOR` bytes more. Measured 2026-09-27, as the bytes handed to the
#: parser: the 72 files under src/proofbundle take at most 1.034 bytes per byte of comment (`_membership.py`),
#: and each of them commented out whole, line by line, at most 1.093 with `# ` and 1.109 with `#` (`dsse.py`);
#: a MiB of comment lines built to get past `_lex` reaches the bound in 2.0 to 2.6 s at a load average of 16
#: to 22 on 24 cores (3.3 to 4.4 s in a review lens's runs, at a load average of 17 to 54 over its session).
_PARSE_PER_BYTE = 8
_PARSE_FLOOR = 1 << 16


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


def _hash_groups(comment: str) -> list[int]:
    """Where each group of `#` marks a comment opens with ends (`_HASH_GROUP`): the first, and each further
    one while only whitespace stands before its `#`. A run of comments holds the code left when the groups
    all of its lines open with are taken off: `# # x` over `# # y` holds `x` over `y`, and `# # x` over
    `# y` holds `# x` over `y`."""
    ends: list[int] = []
    group = _HASH_GROUP.match(comment)
    while group:
        ends.append(group.end())
        group = _HASH_GROUP.match(comment, group.end())
    return ends


def _dedented(bodies: list[str]) -> str:
    """The code a run of comment bodies holds: its lines dedented together, so a commented-out block keeps
    the indentation its lines have to each other, and its first line without indentation of its own."""
    lines = textwrap.dedent("\n".join(bodies)).split("\n")
    lines[0] = lines[0].lstrip()
    return "\n".join(lines)


#: Python 3.13 and later refuse to build a tree for an identifier whose NFKC form is `True`, `False` or `None`,
#: with a ValueError of this text; 3.10 to 3.12 build it as that name (`_parse`).
_REFUSED_NAME = re.compile(r"identifier field can't represent '(?:True|False|None)' constant")
_CONSTANT_NAMES = frozenset({"True", "False", "None"})
_WORD = re.compile(r"\w+")
_STAND_IN_LETTERS = string.ascii_letters + string.digits


class _NotReadAsBefore313(Exception):
    """A source the running Python refuses for a name spelled as a constant, and `_parse_as_before_313` cannot
    read as 3.10 to 3.12 do. No ValueError, so that no caller takes it for a text that does not parse: each
    stops fail-closed on it."""


def _parse(source: str | bytes) -> ast.Module:
    """The tree `ast.parse` builds, and where a later Python refuses one for a name alone, the tree Python
    3.10 to 3.12 build.

    A name whose NFKC form is `True`, `False` or `None`, written otherwise (`True` in fullwidth letters),
    is a name to 3.10, 3.11 and 3.12, which load the constant through it; 3.13 and later refuse the whole
    source with a ValueError. The package runs on all five, so the verdict must not depend on the one that
    runs the guard, and it did (measured 2026-09-27 at 0b9edc94): `return` with `True` in fullwidth letters
    opening a check was a finding with exit 1 on 3.10 to 3.12 and stopped the run with exit 2 on 3.13 and
    3.14; a comment holding `if` such a `True` `and` a check was a finding on 3.10 to 3.12 and clean with
    exit 0 on 3.13 and 3.14; and a file that binds such a name elsewhere was clean on 3.10 to 3.12 and
    stopped the run on 3.13 and 3.14. Where the running Python refuses a source for that reason, it is read
    as 3.10 to 3.12 read it (`_parse_as_before_313`); every other refusal stays the caller's to judge. That
    holds for a source the versions parse alike; where their grammars or Unicode tables differ, the running
    one decides, here as everywhere in the guard, class B's reading of a comment's code included (an f-string
    that nests quotes, a t-string, a letter Unicode added later): the named limit that the guard's reading
    relies on CPython's `ast` (the module docstring)."""
    try:
        return ast.parse(source)
    except ValueError as exc:
        if not _REFUSED_NAME.search(str(exc)):
            raise
    if isinstance(source, bytes):
        source = source.decode(tokenize.detect_encoding(io.BytesIO(source).readline)[0])
    return _parse_as_before_313(source)


def _parse_as_before_313(text: str) -> ast.Module:
    """`text` as Python 3.10 to 3.12 parse it, on every version where `_parse` reads a source this way.

    THE REWRITE TOUCHES ONLY THE PLACES OF THE REFUSAL: the identifier tokens whose NFKC form is `True`,
    `False` or `None`, spelled otherwise, and never the inside of a string or bytes literal, the text of an
    f-string or a comment. Each becomes an ASCII name of the same length in UTF-8, so every position in the
    tree stays, and the name is the NFKC form of no word and no identifier of the text. The parser stores an
    identifier in its NFKC form, so after the rewrite a stand-in stands exactly where a spelling of its one
    constant stood, and the step back from it is unique. The tree then gets the NFKC form back where it holds
    a stand-in as an identifier, as 3.10 to 3.12 store it, and the text as written where it copies a stretch
    of the source into a string (the `=` of an f-string field).

    The first reading, `_WORD.sub` over the whole text, broke both halves (a review lens, run 15, measured
    2026-09-27 at becdf7d2 on 3.13 and 3.14). It kept a stand-in out of the words as written, so `Q` and 11
    `a` in fullwidth letters, which the parser stores as the stand-in `Qaaaaaaaaaaa`, came back from the tree
    as `True`: `return` such a name, opening a check, was a finding with exit 1 on 3.13 and 3.14 and clean
    on 3.10 to 3.12. And it rewrote the word inside a bytes literal too, where ASCII is legal and a fullwidth
    `True` is not, so a file 3.10 to 3.12 refuse with exit 2 was clean with exit 0 on 3.13 and 3.14, and a
    comment holding such a literal beside a check was a finding there and clean on 3.10 to 3.12.

    THE TOKENIZER FINDS THE TOKENS. From 3.12 on, `tokenize` runs the parser's own tokenizer, so its NAME
    tokens are the identifiers the parser reads, those in the fields of an f-string included, and no text
    of a literal or a comment. Measured on 3.13 and 3.14 for ten spellings in 19 places: every identifier
    was a NAME token, at the line and column where the text holds it; the text of a string, a bytes literal,
    a comment, an f-string and its format spec held none, and nor did `True` in fullwidth letters followed by
    U+00B7, which is one identifier with it. A pattern such as `\\w+` knows none of these boundaries. Before
    3.12 the module reads a name as `\\w+` and an f-string as one string; the rewrite runs there only where
    a test plants the refusal. Where the tokenizer stops at an error, the names before it are rewritten and
    the parser names the error. A source that still refuses a name after the rewrite, or a length whose
    every name is taken, stops fail-closed (`_NotReadAsBefore313`).

    THE WORK IS LINEAR IN THE TEXT, and bounded before it starts: one tokenization, one NFKC form per word
    and per name, and one stand-in per constant and length in UTF-8, at most three per length, each taken
    from one walk over the names of that length that goes on where the last one stopped, so the walks pass
    each taken name at most once. The first reading chose a stand-in per spelling and began each walk at the
    start: 48000 spellings of 16 bytes in a docstring, 816,302 bytes staged, ran 572 s on 3.13 and 569 s on
    3.14 (the same lens). In class B the rewrite runs once per reading the running Python refuses, on the
    reading the parsing bound has already counted."""
    starts: list[int] = []
    lines: list[str] = []
    for line in _SEGMENT_LINE.finditer(text):        # a line ends where the parser ends it: CR LF, CR or LF
        starts.append(line.start())
        body = line.group().rstrip("\r\n")
        lines.append(body + "\n" if body != line.group() else body)
    names: list[tuple[int, str]] = []                  # (where in `text` a name starts, the name as written)
    with contextlib.suppress(tokenize.TokenError, SyntaxError):
        for token in tokenize.generate_tokens(functools.partial(next, iter(lines), "")):
            if token.type == tokenize.NAME:
                names.append((starts[token.start[0] - 1] + token.start[1], token.string))
    taken = {word if word.isascii() else unicodedata.normalize("NFKC", word) for word in set(_WORD.findall(text))}
    refused: list[tuple[int, str, str]] = []           # (where, the name as written, the constant it spells)
    for where, name in names:
        if name.isascii():                             # its own NFKC form, and no spelling of a constant
            taken.add(name)
            continue
        normal = unicodedata.normalize("NFKC", name)
        taken.add(normal)
        if normal in _CONSTANT_NAMES:
            refused.append((where, name, normal))
    fresh: dict[int, Iterator[str]] = {}               # per length in UTF-8: the names not yet walked past
    stand_in: dict[tuple[str, int], str] = {}          # (constant, length in UTF-8) -> the name read in place
    pieces: list[str] = []
    done = 0
    for where, name, normal in refused:
        if text[where:where + len(name)] != name:
            raise _NotReadAsBefore313(f"the tokenizer placed {name!r} where the text does not hold it")
        size = len(name.encode())
        if (normal, size) not in stand_in:
            walk = fresh.setdefault(size, ("Q" + "".join(letters) for letters in
                                           itertools.product(_STAND_IN_LETTERS, repeat=size - 1)))
            chosen = next((candidate for candidate in walk if candidate not in taken), None)
            if chosen is None:
                raise _NotReadAsBefore313(f"no name of {size} bytes is left to read {name!r} as")
            taken.add(chosen)
            stand_in[normal, size] = chosen
        pieces += [text[done:where], stand_in[normal, size]]
        done = where + len(name)
    rewritten = "".join(pieces) + text[done:]
    try:
        tree = ast.parse(rewritten)
    except ValueError as exc:
        if _REFUSED_NAME.search(str(exc)):
            raise _NotReadAsBefore313(f"a name spelled as a constant is left after the rewrite: {exc}") from None
        raise
    constant_of = {chosen: normal for (normal, _), chosen in stand_in.items()}
    in_rewritten, in_text = _Segments(rewritten), _Segments(text)

    def identifier(value: str) -> str:
        if "." not in value:                           # a dotted name is an import's: `a.True` in parts
            return constant_of.get(value, value)
        return ".".join(constant_of.get(part, part) for part in value.split("."))

    # Every node once, each field read once: `ast.walk` reads a node's fields to find its children and the
    # restore read them again, which was half the time of the rewrite of a comment's reading on 3.13.
    todo: list[ast.AST] = [tree]
    while todo:
        node = todo.pop()
        if isinstance(node, ast.Constant):
            # A string is the text of a literal, which the rewrite leaves as written, or a stretch of the source
            # the parser copies (the `=` of an f-string field): that one is the text as written, and it is the
            # only kind whose value is the source at its own position.
            if isinstance(node.value, str) and any(chosen in node.value for chosen in constant_of) \
                    and in_rewritten(node) == node.value:
                node.value = in_text(node)
            continue
        for field in node._fields:
            value = getattr(node, field, None)
            if isinstance(value, ast.AST):
                todo.append(value)
            elif isinstance(value, str):
                setattr(node, field, identifier(value))
            elif isinstance(value, list):
                if value and isinstance(value[0], str):
                    setattr(node, field, [identifier(v) for v in value])
                else:
                    todo.extend(v for v in value if isinstance(v, ast.AST))
    return tree


def _commented_statement(code: str,
                         spend: Callable[[int], None] | None = None) -> tuple[ast.Module, str] | None:
    """The code as Python parses it, with the reading that parsed, or None when it does not parse. A
    header is given a body (`# if not verify(x):` needs one, also with a comment behind its colon), a last
    line that ends in a backslash loses it (the line it continued may not be commented out; the caller
    reads on while a comment line follows), and a clause such as `elif` or `except` is read after the
    start it continues. RecursionError and MemoryError pass to the caller, which cannot say and stops: a
    comment `# ok = verify(` with 7000 nested unary minus raised a MemoryError past an except clause that
    named SyntaxError and ValueError, and the guard ended with a traceback and exit 1, the code of a
    finding (a review lens, run 10, measured 2026-09-26). `spend` is told the size of each reading
    before it is parsed."""
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
            if spend is not None:
                spend(len(reading))
            try:
                return _parse(reading), reading
            except (SyntaxError, ValueError):  # ValueError: a NUL byte, which ast.parse refuses on its own
                continue
    return None


#: A line as `ast.get_source_segment` splits a text: it ends at CR LF, at a lone CR or at LF, and at no other
#: character (`str.splitlines` would also end one at a form feed or a U+2028).
_SEGMENT_LINE = re.compile(r"[^\r\n]*(?:\r\n|\r|\n)|[^\r\n]+")


class _Segments:
    """`ast.get_source_segment(source, node)` for the nodes of one text, with the text split into lines once
    and each line encoded once.

    `ast.get_source_segment` splits the whole text into lines again at each call (on 3.10 and 3.11 character
    by character in a Python loop, from 3.12 on with a pattern, up to the node's last line), so asking it
    once per statement cost the number of statements times the size of the text (the class B notes above),
    on 3.12 as well: one line of `a.f(); ` 8000 times took 13 s there. The text is split here once,
    on first use, where `get_source_segment` splits it, and a node's text is cut from the UTF-8 bytes of its
    lines by the node's positions, which count bytes, as `get_source_segment` cuts it: the same string,
    character for character, which a test holds against `get_source_segment` itself."""

    def __init__(self, source: str) -> None:
        self._source = source
        self._lines: list[str] | None = None
        self._encoded: dict[int, bytes] = {}

    def _text_lines(self) -> list[str]:
        if self._lines is None:
            self._lines = _SEGMENT_LINE.findall(self._source)
        return self._lines

    def _line(self, index: int) -> bytes:
        if index not in self._encoded:
            self._encoded[index] = self._text_lines()[index].encode()
        return self._encoded[index]

    def __call__(self, node: ast.expr) -> str | None:
        try:
            if node.end_lineno is None or node.end_col_offset is None:
                return None
            first, last, start, end = node.lineno - 1, node.end_lineno - 1, node.col_offset, node.end_col_offset
        except AttributeError:                 # a node built without positions, as `get_source_segment` has it
            return None
        if first == last:
            return self._line(first)[start:end].decode()
        return (self._line(first)[start:].decode() + "".join(self._text_lines()[first + 1:last])
                + self._line(last)[:end].decode())


def _verify_calls(tree: ast.AST, source: str | None = None) -> list[str]:
    """The names of the calls in `tree` whose callee is named for a check: a name, or the attribute that
    ends any chain (`merkle.verify_inclusion`, `key.from_public_bytes(b).verify`). A call inside an
    annotation does not count: prose such as `# NOTE: verify(x) ...` parses as a name annotated with the
    call, while code puts the call in the value (`# ok: bool = verify(x)` counts). Nor does a call in an
    expression statement that makes no check by what it does (`_no_check`, read in `source`, the text
    the tree was parsed from). The work is linear in the tree and in `source` (`_Segments`)."""
    segment = None if source is None else _Segments(source)
    left_out: set[int] = set()
    for node in ast.walk(tree):
        for annotation in (getattr(node, "annotation", None), getattr(node, "returns", None)):
            if isinstance(annotation, ast.AST):
                left_out.update(id(n) for n in ast.walk(annotation))
        if isinstance(node, ast.Expr) and _no_check(node.value, segment):
            left_out.update(id(n) for n in ast.walk(node))
    names = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and id(node) not in left_out:
            func = node.func
            name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else ""
            if _VERIFY_CALLEE.search(name):
                names.append(name)
    return names


def _no_check(value: ast.expr, segment: Callable[[ast.expr], str | None] | None) -> bool:
    """Whether an expression statement with this value makes no check, by what it does as code (the class
    B notes above): `-`, `+` or `~` applied to a call; a star with a space after it before a call; or a
    call on an attribute of a one-letter name with a space after the dot, an enumerated item (`a.
    verify(sig)`). The space is read in the node's text, which `segment` gives as `ast.get_source_segment`
    does (`_Segments`); without it, only the first form counts."""
    if isinstance(value, ast.UnaryOp):
        return isinstance(value.op, (ast.USub, ast.UAdd, ast.Invert)) and isinstance(value.operand, ast.Call)
    if segment is None:
        return False
    if isinstance(value, ast.Starred):
        return isinstance(value.value, ast.Call) and re.match(r"\*[ \t]", segment(value) or "") is not None
    func = value.func if isinstance(value, ast.Call) else None
    return isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) and len(func.value.id) == 1 \
        and re.match(r"\w\.[ \t]", segment(func) or "") is not None


def _lex(code: str, state: str) -> tuple[str | None, int, int, bool, bool]:
    """One line of a comment's code as Python's tokenizer leaves it, entered in `state`: "" in code, or the
    quotes of the triple-quoted string the line starts inside.

    Returns the state after the line, the bracket depth it adds, the lowest depth within it, whether it
    holds an error no later line repairs, and whether it ends in a backslash that joins the next line.
    The errors are a single-quoted string left open with no backslash to continue it, a character that is
    no token (`?`, `$`, a backtick) and a backslash with text after it. One more backslash is no such
    text: `_commented_statement` drops a backslash that ends the last line, and `else:\\\\` read with a
    body after it then parses (found by fuzzing this lexer against the parser, 2026-09-27). A closing
    bracket below depth 0 is the caller's to see, which knows the depth the line starts at. The state is
    None where this lexer cannot follow the line as the running Python does: from 3.12 on, an f-string or
    a t-string whose fields `_plain_fields` cannot follow, or that spans lines, and in every version a
    single-quoted string continued over a backslash.
    """
    pos = depth = low = 0
    if state:
        inside = _STRING_REST[state].match(code)
        if not inside:
            return state, 0, 0, False, False
        pos = inside.end()
    while stop := _LEX_STOP.search(code, pos):
        c, i = stop.group(), stop.start()
        pos = i + 1
        if c == "#":
            break
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            low = min(low, depth)
        elif c == "\\":                 # `_commented_statement` drops one backslash that ends a last line
            joins = code[pos:].strip() in ("", "\\")
            return "", depth, low, not joins, joins
        elif c in "?$`":
            return "", depth, low, True, False
        else:
            quote = c * 3 if code.startswith(c * 3, i) else c
            rest = _STRING_REST[quote].match(code, i + len(quote))
            start = i            # the letters before the quote, up to three: a prefix has at most two
            while start > 0 and i - start < 3 and (code[start - 1].isalnum() or code[start - 1] == "_"):
                start -= 1
            if _FIELDS_NEST and code[start:i].lower() in _FIELD_PREFIXES:
                if len(quote) == 3 or not rest or not _plain_fields(code[i + 1:rest.end() - 1]):
                    return None, depth, low, False, False
            elif not rest:
                if len(quote) == 3:
                    return quote, depth, low, False, False
                if (len(code) - len(code.rstrip("\\"))) % 2:
                    return None, depth, low, False, False
                return "", depth, low, True, False
            pos = rest.end()
    return "", depth, low, False, False


def _plain_fields(text: str) -> bool:
    """Whether Python 3.12 and later end an f-string at the quote after `text`, where the versions before
    do: `text` runs from the opening quote to the first quote of the same kind, and that quote ends the
    string only outside a field. So every field in `text` must close in order. Outside a field, `{{` and
    `}}` are text and a backslash escapes the character after it. Inside one, a brace opens or closes, a
    quote of the other kind opens a string that must close before the field does and hold no brace and no
    backslash (a brace in it would miscount the field), and a triple quote, a backslash or a `#` is more
    than this reading follows (False)."""
    depth = i = 0
    while i < len(text):
        c = text[i]
        if not depth:
            if text.startswith(("{{", "}}"), i) or c == "\\":
                i += 2
                continue
            if c == "}":
                return False
            depth += c == "{"
        elif c in "'\"":
            end = text.find(c, i + 1)
            if end < 0 or text.startswith(c * 3, i) or any(x in text[i + 1:end] for x in "{}\\"):
                return False
            i = end
        elif c in "#\\":
            return False
        else:
            depth += (c == "{") - (c == "}")
        i += 1
    return depth == 0


class _Lexed:
    """What `_lex` knows after the lines of one search so far, read at one level of `#` marks: the state
    after them (None once a line could not be followed), their bracket depth, whether an error no later
    line repairs stands in them, whether the last line joins the next, the first line of the logical line
    still open, and the logical line the last line completed, if it did. And, from the text alone: the
    indentation every line with text shares, which `_dedented` takes off, and the least indentation of a
    line with code after the first."""

    def __init__(self) -> None:
        self.state: str | None = ""
        self.depth = 0
        self.broken = self.joined = False
        self.first: int | None = None
        self.completed: tuple[int, int] | None = None
        self.margin = ""
        self.later: int | None = None
        self.lines = 0

    def feed(self, row: int, code: str, lexed: tuple[str | None, int, int, bool, bool] | None) -> None:
        self.completed = None
        indent = code[:len(code) - len(code.lstrip(" \t"))]
        if code[len(indent):]:                      # `textwrap.dedent` reads only spaces and tabs
            self.margin = os.path.commonprefix([self.margin, indent]) if self.lines else indent
            if self.lines and code[len(indent)] != "#":
                self.later = len(indent) if self.later is None else min(self.later, len(indent))
        self.lines += 1
        if self.state is None or lexed is None:
            self.state = None
            return
        if self.first is None and not self.state and not self.depth and not self.joined \
                and code.lstrip()[:1] not in ("", "#"):
            self.first = row
        after, delta, low, broken, joined = lexed
        self.broken = self.broken or broken or self.depth + low < 0
        self.depth += delta
        self.state, self.joined = after, joined
        if after == "" and not self.depth and not joined and self.first is not None:
            self.completed, self.first = (self.first, row), None


def _commented_out_calls(path: str, lines: list[str]) -> list[tuple[int, int]]:
    """Class B over a file's Python lines: (first line, last line) of each comment that holds a call to a
    check. A comment that stands alone on its line is read with the ones directly below it, up to
    `_MAX_JOINED`: the shortest run from it that parses is the statement it holds, unless the run's last
    line ends in a backslash that joins the next comment line, and the lines of a run that holds such a
    call are not read again as a start. A run whose text names no check (NFKC, any case) cannot hold such
    a call and is not parsed, nor is a run `_lex` shows Python cannot end a statement at, and the search
    from a line ends at an error no later line repairs (the class B notes above). A comment behind code on
    its line is not read: the review lens that measured this class left `ok = True  # ok = verify(...)` at
    the class's boundary."""
    comments = _comments(path, lines)
    alone_at = {row: text for row, text, alone in comments if alone}
    groups = {row: _hash_groups(text) for row, text in alone_at.items()}
    names_a_check = {row: bool(_VERIFY_CALLEE.search(unicodedata.normalize("NFKC", text)))
                     for row, text in alone_at.items()}
    allowance = _PARSE_PER_BYTE * sum(len(text) for text in alone_at.values()) + _PARSE_FLOOR
    lexed: dict[tuple[int, int, str], tuple[str | None, int, int, bool, bool]] = {}
    unparsed: set[tuple[int, int, int]] = set()

    def body(row: int, level: int) -> str:
        return alone_at[row][groups[row][level - 1]:]

    def feed(lx: _Lexed, row: int, level: int) -> None:
        key = (row, level, lx.state or "")
        if lx.state is not None and key not in lexed:
            lexed[key] = _lex(body(row, level), lx.state)
        lx.feed(row, body(row, level), lexed.get(key) if lx.state is not None else None)

    def spend(size: int) -> None:
        nonlocal allowance
        allowance -= size
        if allowance < 0:
            raise SystemExit(f"mutant_signature_guard: {_pfad(path)}: reading its comments as code takes "
                             f"more parsing than {_PARSE_PER_BYTE} bytes per byte of comment, the bound of "
                             "this reading, so the guard cannot say whether they hold commented-out code "
                             "(fail closed)")

    def parse(first: int, last: int, level: int) -> tuple[ast.Module, str] | None:
        if (first, last, level) in unparsed:
            return None
        try:
            statement = _commented_statement(_dedented([body(r, level) for r in range(first, last + 1)]),
                                             spend)
        except (RecursionError, MemoryError):
            raise SystemExit(f"mutant_signature_guard: {_pfad(path)}:{first}: a comment nests deeper "
                             "than the parser reads, so the guard cannot say whether it is "
                             "commented-out code (fail closed)") from None
        except _NotReadAsBefore313 as exc:
            raise SystemExit(f"mutant_signature_guard: {_pfad(path)}:{first}: this Python refuses a comment's "
                             "code for a name spelled as a constant, and it cannot be read as 3.10 to 3.12 "
                             f"read it, so the guard cannot say whether it is commented-out code (fail closed): "
                             f"{_pfad(str(exc)[:200])}") from None
        if statement is None:
            unparsed.add((first, last, level))
        return statement

    found: list[tuple[int, int]] = []
    covered = 0
    for row in alone_at:
        if row <= covered:
            continue
        run = [row]
        while len(run) < _MAX_JOINED and run[-1] + 1 in alone_at:
            run.append(run[-1] + 1)
        if not any(names_a_check[r] for r in run):
            continue
        fewest_after, fewest = [], sys.maxsize        # the fewest groups of `#` a later line opens with
        for r in reversed(run):
            fewest_after.append(fewest)
            fewest = min(fewest, len(groups[r]))
        fewest_after.reverse()
        level, lx, dead = sys.maxsize, _Lexed(), False    # dead: no longer prefix parses at this level
        for end, r in enumerate(run):
            if len(groups[r]) < level:                # the run is read at fewer levels now: read it again
                level, lx, dead = len(groups[r]), _Lexed(), False
                for earlier in run[:end]:
                    feed(lx, earlier, level)
                opens_a_try = _TRY.match(body(row, level).lstrip())
            if body(row, level).lstrip()[:1] in ("", "#"):
                break                                   # no code: the first code line starts its own search
            feed(lx, r, level)
            settled = fewest_after[end] >= level        # no later line of the run lowers the level
            dead = dead or lx.broken                    # an error no later line at this level repairs
            if dead or (lx.state is not None and (lx.state or lx.depth)):
                if dead and settled:
                    break
                continue                                # or a bracket or a string still open
            in_the_try = opens_a_try and (lx.later is None or lx.later > len(lx.margin))
            statement = None if in_the_try else parse(row, r, level)
            if statement is not None:
                if _verify_calls(*statement):
                    found.append((row, r))
                    covered = r
                elif end + 1 < len(run) and (lx.joined if lx.state is not None
                                             else body(r, level).rstrip().endswith("\\")):
                    continue                            # the statement goes on into the next comment line
                break
            if lx.completed and not _COMPLETED_LATER.match(body(lx.completed[0], level)) \
                    and parse(lx.completed[0], r, level) is None:
                if settled:
                    break                               # a logical line that parses in no context
                dead = True                             # at this level
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
    parses to the same tree, positions included, as the bytes did. Both parses go through `_parse`, so a
    name spelled as a constant is read on every version as 3.10 to 3.12 read it.
    """
    def stop(reason: str) -> SystemExit:
        return SystemExit(f"mutant_signature_guard: {_pfad(path)}: Python cannot read this file as "
                          f"source, so the guard cannot judge it (fail closed): {reason}")
    try:
        tree = _parse(raw)
        encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
        whole = raw.decode(encoding)
    except (SyntaxError, ValueError, LookupError, RecursionError, MemoryError, _NotReadAsBefore313) as exc:
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
        again = _parse(whole)
    except (SyntaxError, ValueError, RecursionError, MemoryError, _NotReadAsBefore313) as exc:
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
        if _bool_constant(body[0].value) is True:       # also a name Python binds to True
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

def _fullwidth(word: str) -> str:
    """`word` in fullwidth letters, which Python binds as the name the letters spell (NFKC)."""
    return "".join(chr(ord(c) + 0xFEE0) for c in word)


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
    # A backslash that ends a commented line continues its statement, a Markdown bullet makes no check,
    # and a bool constant is the constant however it is spelled (a review lens, run 13, 2026-09-27).
    ("B: the Ed25519 check continued over a backslash, commented out",
     _BENIGN.replace('    return bool(data.get("ok"))',
                     '    # Ed25519PublicKey.from_public_bytes(bytes(key)) \\\n'
                     '    #     .verify(bytes(sig), bytes(msg))\n    return True'), True),
    ("negative: a Markdown bullet list that names checks",
     _BENIGN + "\n# Entry points:\n#   - verify_thing(data)\n#   * verify_thing(data)\n", False),
    ("A: a trivial truth spelled in fullwidth letters",
     _BENIGN.replace('if not isinstance(data, dict):', f'if {_fullwidth("False")}:'), True),
    ("C: `return True` spelled in fullwidth letters",
     f'def verify_thing(data):\n    return {_fullwidth("True")}\n', True),
    # 3.13 and later refuse such a name, and a comment holding one was read as no code there (2026-09-27).
    ("B: a commented-out check behind a constant spelled in fullwidth letters",
     _BENIGN.replace('    return bool(data.get("ok"))',
                     f'    # if {_fullwidth("True")} and verify_thing(data):\n    #     return False\n'
                     '    return True'), True),
    # The name 3.13 and later read such a constant as is no name of the file in its NFKC form: this one was read
    # back as `True` there (a review lens, run 15, 2026-09-27).
    ("negative: a name that spells the stand-in for a constant",
     _BENIGN + f"\ny = {_fullwidth('True')}\n\n\ndef verify_o(d):\n    return {_fullwidth('Qaaaaaaaaaaa')}\n", False),
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
