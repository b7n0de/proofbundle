#!/usr/bin/env python3
"""Fail-closed guard against mutation-mutant signatures on security paths (incident 2026-07-23).

A mutation probe planted `if False:` in place of the SD-JWT key-binding check in bundle.py and
the mutant survived into the working tree; only a manual diff-before-commit caught it. This guard
is the mechanical version of that manual look: it scans the CHANGE (staged diff or a commit
range) for the three narrow signature classes a left-over mutant takes, and blocks fail-closed.

Signature classes (deliberately narrow and explainable: a safety net, not a linter):

  A  a trivial-truth branch added at a check site:      `if False:` / `if True:` /
     `elif False:` / `elif True:` / `while False:` (also `if False and <original check>:`)
  B  a commented-out verification line: a comment whose content reads like a code statement
     calling a verify/validate/check/compare_digest function (prose comments do not match)
  C  `return True` as the first statement of a function whose name says verify/validate/check

Scope: added lines under src/proofbundle/**/*.py (the verification library, every path there is
security-relevant). Legitimate exceptions are possible but must be VISIBLE in the diff: put a
`# mutant-guard: allow` comment on the flagged line or the line directly above it.

Modes:
  --staged        scan the staged diff (pre-commit hook; content read from the index)
  --base <sha>    scan <merge-base(sha, HEAD)>..HEAD (CI; all-zero / missing sha falls back
                  to HEAD~1, and to an empty scan on a root commit)
  --self-test     prove in a throwaway git repo that every class is caught and that the
                  negative controls stay quiet (the gate-meta-test; CI runs this first)

Exit codes: 0 clean · 1 mutant signature found · 2 internal/usage error (fail closed).
stdlib only, offline.
"""
from __future__ import annotations

import argparse
import ast
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path


def _repo_root() -> Path:
    """The repo the guard runs IN (cwd-based): the pre-commit hook and CI both execute at
    the checkout root; anchoring on the script location would scan the wrong repo when
    invoked from elsewhere (e.g. the test fixtures)."""
    proc = subprocess.run(["git", "rev-parse", "--show-toplevel"],
                          capture_output=True, env=_git_environment())
    top = proc.stdout.decode("utf-8", "surrogateescape").strip()
    if proc.returncode != 0 or not top:
        print("mutant_signature_guard: not inside a git repository (fail closed)", file=sys.stderr)
        raise SystemExit(2)
    return Path(top)


# DOTALL and \A ... \Z, because a decoded path can hold a newline: git writes `src/proofbundle/a\nb.py`
# as a quoted header with `\n`, `_git_path` turns that back into the newline, and `.` without DOTALL
# stopped there, so a staged `if False:` under that name was reported clean with exit 0 (Codex on
# pull request 375, 2026-10-17).
_SECURITY_PATH = re.compile(r"\Asrc/proofbundle/.*\.py\Z", re.DOTALL)
_ALLOW_MARKER = "mutant-guard: allow"

# Class A — trivial-truth branch (word-boundary keeps `if Falsey_thing` out).
_TRIVIAL_TRUTH = re.compile(r"^\s*(?:(?:el)?if\s+(?:False|True)\b|while\s+False\b)")

# Class B — commented-out verification CODE, two-stage: a cheap prefilter (a comment whose
# content starts like a statement calling a verify/validate/check/compare_digest function),
# then the decisive test: the content must PARSE as a Python statement. Prose that merely
# names a function keeps trailing English words and fails to parse (`# verify_envelope
# (docstring says ...) never gets ...`), commented-out code parses (`# ok =
# hmac.compare_digest(a, b)`). The three false-positive shapes found on real 3.6.0..HEAD
# history are pinned as negative self-test cases below.
_COMMENTED_VERIFY = re.compile(
    r"^\s*#\s*(?:if\s+|elif\s+|return\s+|assert\s+|not\s+)?(?:[\w.]+\s*=\s*)?"
    r"[\w.]*(?:verify|validate|compare_digest|check)[\w.]*\s*\(")


def _commented_content_parses(text: str) -> bool:
    content = re.sub(r"^\s*#\s?", "", text).strip()
    if content.endswith(":"):
        content += "\n    pass"  # a commented-out `if verify(x):` header needs a body to parse
    try:
        ast.parse(content)
    except SyntaxError:
        return False
    return True

# Class C — verification-function names.
_VERIFYISH_NAME = re.compile(r"(?:verify|validate|check)", re.IGNORECASE)


#: THE ENVIRONMENT OF EVERY GIT CALL IS BUILT, NOT INHERITED (second counter-reading of the fixed form, F2 and F4).
#: The fixed form pinned what the configuration and the attributes could change, and the environment changed it next:
#: `GIT_LITERAL_PATHSPECS`, `GIT_GLOB_PATHSPECS` and `GIT_NOGLOB_PATHSPECS` made the language gate's `*.md` pathspec
#: match nothing, green over a German line, and `GIT_TRACE=/dev/stdout` wrote trace lines into the answer of
#: `rev-parse`, so the range mode reported "scan skipped honestly" with exit 0 over a mutant in the range. git reads
#: more names than a list of names to remove would carry (the receipt chain measured the same, see
#: `scripts/pre_tag_receipt_lib.py`), so the names below pass through, a few are pinned, and nothing else reaches git.
#: The location names stay: inside the pre-commit hook git sets `GIT_INDEX_FILE` for a commit of named paths, and an
#: environment without it let a staged mutant through (measured by the counter-reading). The configuration files stay
#: readable, because the switches and the `-c` pairs below outrank every key that shapes the diff.
_GIT_INHERITED = ("PATH", "SYSTEMROOT", "HOME", "XDG_CONFIG_HOME", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
                  "GIT_CONFIG_NOSYSTEM", "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
                  "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_COMMON_DIR", "GIT_CEILING_DIRECTORIES")
_GIT_PINNED_ENV = {"LC_ALL": "C", "LANG": "C", "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0",
                   "GIT_NO_REPLACE_OBJECTS": "1"}


def _git_environment() -> dict[str, str]:
    """The environment of every git call of this guard, and of the language gate, which takes it from here."""
    env = {k: os.environ[k] for k in _GIT_INHERITED if k in os.environ}
    env.update(_GIT_PINNED_ENV)
    return env


def _git(*args: str, cwd: Path) -> str:
    """git's answer as git wrote it: BYTES, decoded with surrogateescape (second counter-reading, F1 and F3).
    `text=True` decoded strictly and turned a lone CR into a line feed. Under `--text` the bytes of a binary file are
    hunk lines, and one that is not UTF-8 ended the guard with a traceback and exit 1, the code of a finding; and the
    piece after a lone CR fell out of its hunk. A failed call exits 2, as the header promises, not 1 (F6)."""
    proc = subprocess.run(["git", "-C", str(cwd), *args], capture_output=True, env=_git_environment())
    if proc.returncode != 0:
        print(f"mutant_signature_guard: git {' '.join(_subcommand(args))} failed (fail closed): "
              f"{proc.stderr.decode('utf-8', 'replace').strip()[:200]}", file=sys.stderr)
        raise SystemExit(2)
    return proc.stdout.decode("utf-8", "surrogateescape")


def _subcommand(args: tuple[str, ...]) -> tuple[str, ...]:
    """The subcommand and its first argument, past the `-c key=value` pairs and the global switches before it: with
    the pairs in front the message named `-c core.quotePath=true` instead of the command (counter-reading of pull
    request 415, F8)."""
    i = 0
    while i < len(args) and (args[i] == "-c" or args[i].startswith("--")):
        i += 2 if args[i] == "-c" else 1
    return args[i:i + 2]


class DiffNotReadable(Exception):
    """The diff lost the count of a hunk: a line in an open hunk is no line of it. Fail closed, exit 2."""


#: The C escapes git writes inside a quoted path, besides octal `\ooo` for a byte.
_C_ESCAPES = {"a": 7, "b": 8, "t": 9, "n": 10, "v": 11, "f": 12, "r": 13, '"': 34, "\\": 92}


def _git_path(field: str) -> str:
    """A path as a diff header prints it, decoded to the path it names.

    git quotes a path that holds a byte outside printable ASCII (core.quotePath is on by default), a
    double quote, a backslash or a control character: it wraps it in double quotes and writes C
    escapes, octal for each byte (`"b/src/proofbundle/pr\\303\\274fung.py"`). Read verbatim, such a
    path matched no security path, and a staged `if False:` in it was reported clean with exit 0
    (measured 2026-09-26 in a throwaway repository; plain names and names with a space were caught).

    An octal escape is a byte, so git writes at most `\\377`. A larger one (`\\400` to `\\777`) is no
    byte and is kept as it stands, like every escape git does not write; `bytearray.append` raised
    ValueError on it, in the language gate with exit 1, the exit code of a red verdict
    (counter-reading of pull request 375, F2).
    """
    s = field.strip()
    if len(s) < 2 or not (s.startswith('"') and s.endswith('"')):
        return s
    body, out, i = s[1:-1], bytearray(), 0
    while i < len(body):
        c = body[i]
        if c != "\\":
            out += c.encode("utf-8", "surrogateescape")  # a raw byte of the bytes-decoded diff comes back as it was
            i += 1
        elif body[i + 1:i + 2] in _C_ESCAPES:
            out.append(_C_ESCAPES[body[i + 1]])
            i += 2
        elif (len(body[i + 1:i + 4]) == 3 and body[i + 1] in "0123"
              and all(d in "01234567" for d in body[i + 1:i + 4])):
            out.append(int(body[i + 1:i + 4], 8))
            i += 4
        else:
            out += c.encode("utf-8", "surrogateescape")  # an escape git does not write: kept as it stands
            i += 1
    return out.decode("utf-8", "surrogateescape")


def _added_lines_by_file(diff_text: str) -> dict[str, list[tuple[int, str]]]:
    """Parse a -U0 unified diff into {new_path: [(new_lineno, added_line_text), ...]}.

    A HEADER STANDS OUTSIDE A HUNK, AND THE DIFF IS SPLIT AT ITS LINE FEEDS ONLY (counter-reading of
    pull request 375, F10b and F10c, P3, also on main). An added line `++ 1` stands in the diff as
    `+++ 1` and was read as the header of a file `1`, so every added line after it fell outside the
    scope. `splitlines()` also split at a form feed, and an added `\x0cif False:`, which Python reads
    as `if False:`, reached the parser as `+` and an unmarked `if False:`. The hunk header counts the
    lines of its hunk; inside them a line is a line of the hunk, whatever it begins with.

    A LINE THE HUNK CANNOT HOLD ENDS THE READING (counter-reading of pull request 415, F1, P2). With
    `diff.suppressBlankEmpty` git writes an empty context line as an empty line; it counted on neither
    side, the hunk stayed open, the next file's header was taken as hunk content, and a staged
    `if False:` under it was reported clean with exit 0. The guard asks for its diff in a fixed form
    now (`_DIFF_FORM`), and a line in an open hunk that begins with none of `+`, `-`, ` ` and `\\`, or
    a diff that ends inside a hunk, raises DiffNotReadable instead of being passed over.
    """
    out: dict[str, list[tuple[int, str]]] = {}
    current: str | None = None
    lineno = 0
    alt = neu = 0  # lines of the open hunk still to come, on the old side and on the new side
    for nr, raw in enumerate(diff_text.split("\n"), start=1):
        if alt > 0 or neu > 0:
            if raw.startswith("+"):
                if current is not None:
                    out.setdefault(current, []).append((lineno, raw[1:]))
                lineno += 1
                neu -= 1
            elif raw.startswith("-"):
                alt -= 1
            elif raw.startswith(" "):
                lineno += 1
                alt -= 1
                neu -= 1
            elif not raw.startswith("\\"):  # `\ No newline at end of file` counts on neither side
                raise DiffNotReadable(f"line {nr} of the diff stands in an open hunk and is no line of it "
                                      f"({alt} old and {neu} new lines of the hunk still to come)")
            continue
        if raw.startswith("+++ "):
            path = _git_path(raw[4:])
            current = None if path == "/dev/null" else path.removeprefix("b/")
        elif raw.startswith("@@"):
            # GEPRUEFT UND KEIN FUND (Klassen-Sweep 2026-09-07). Diese Suche sieht aus wie die
            # Klasse "Suche ohne Anker entscheidet ueber eine Grenze", ist aber keine: der Hunk-Kopf
            # hat die Form `@@ -alt,n +neu,m @@ <kontext>`, und `+neu` steht damit STRUKTURELL vor
            # jedem `+` aus dem Kontextausschnitt. Ein Anker wurde gebaut und wieder entfernt, weil
            # der Fangnachweis dazu gruen blieb — ein Fix ohne widerlegbaren Defekt ist keine
            # Haertung, sondern eine Behauptung ueber eine Gefahr, die es hier nicht gibt.
            m = re.search(r"\+(\d+)", raw)
            lineno = int(m.group(1)) if m else 0
            n = re.match(r"@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@", raw)
            if n:
                alt, neu = (int(g) if g is not None else 1 for g in n.groups())
        elif raw.startswith("+") and not raw.startswith("+++"):
            if current is not None:
                out.setdefault(current, []).append((lineno, raw[1:]))
            lineno += 1
        elif raw.startswith(" "):
            lineno += 1
    return out


def _allowlisted(file_lines: list[str], lineno: int) -> bool:
    for candidate in (lineno, lineno - 1):
        if 1 <= candidate <= len(file_lines) and _ALLOW_MARKER in file_lines[candidate - 1]:
            return True
    return False


def _py2git(content: str) -> list[int]:
    """The git line of each line Python reads: index = Python's line number, value = git's.

    ONE LINE SPACE, NOT TWO (counter-reading of d017cd6b, H1 and H2, P2). Python ends a line at LF, CR LF
    and a lone CR; git counts LF only. The syntax tree gave its line numbers in Python's space and the
    added lines came in git's, so two lone CR in a comment above a `return True` moved both the def
    and the return out of the change, and a verification function that accepts everything was clean.
    Every number from the syntax tree or the tokenizer goes through this table before it is compared."""
    out, git, i = [0, 1], 1, 0
    while i < len(content):
        c = content[i]
        if c == "\r" and content[i + 1:i + 2] == "\n":
            i += 1
            c = "\n"
        if c == "\n":
            git += 1
            out.append(git)
        elif c == "\r":
            out.append(git)
        i += 1
    return out


def _class_c_findings(content: str, added: set[int]) -> list[tuple[int, str]]:
    """`return True` as first non-docstring statement of a verify-ish function, if the def or
    the return line is part of the change (pre-existing code is out of scope for a diff guard).

    A BYTE ORDER MARK AND A NUL ARE NO REASON TO STAY QUIET (counter-reading of d017cd6b, H8, P3). The
    parser refuses a string that begins with U+FEFF, CPython imports the file, and the SyntaxError
    below turned that into "nothing found" over a live mutant; the mark is stripped before parsing.
    A NUL is a ValueError on Python 3.10 and a SyntaxError from 3.11 on, so it is named before either
    can happen: NOT MEASURABLE, exit 2."""
    findings: list[tuple[int, str]] = []
    if "\x00" in content:
        raise DiffNotReadable("a NUL byte in the source, so its syntax tree is not read here")
    try:
        tree = ast.parse(content.removeprefix("\ufeff"))
    except SyntaxError:
        return []  # unparseable staged state: the test/lint gates own that failure
    git_line = _py2git(content)
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
            if git_line[node.lineno] in added or git_line[body[0].lineno] in added:
                findings.append((git_line[body[0].lineno],
                                 f"`return True` opens verification function `{node.name}`"))
    return findings


def _file_content(path: str, *, staged: bool, cwd: Path) -> str:
    if staged:
        return _git("show", f":{path}", cwd=cwd)
    p = cwd / path
    return p.read_bytes().decode("utf-8", "surrogateescape") if p.is_file() else ""


def _shown(path: str) -> str:
    """The path as a report line shows it: as it stands when every character is printable, else in
    git's quoted form (counter-reading of pull request 375, F4, P3). Printed as decoded, a newline in
    a name began a line of its own, and `::warning::` at the start of a line is a workflow command in
    a GitHub Actions log; a byte that is not UTF-8 reached stdout as a lone surrogate (F3)."""
    if path.isprintable():
        return path
    letters = {v: k for k, v in _C_ESCAPES.items()}
    out = []
    for byte in path.encode("utf-8", "surrogateescape"):
        if byte in letters:
            out.append("\\" + letters[byte])
        elif byte < 0x20 or byte >= 0x7F:
            out.append(f"\\{byte:03o}")
        else:
            out.append(chr(byte))
    return '"' + "".join(out) + '"'


def scan(diff_text: str, *, staged: bool, cwd: Path) -> list[str]:
    findings: list[str] = []
    for path, added in _added_lines_by_file(diff_text).items():
        if not _SECURITY_PATH.match(path):
            continue
        content = _file_content(path, staged=staged, cwd=cwd)
        # A FILE ON A SECURITY PATH THAT IS NOT UTF-8 IS NOT READ HERE (second counter-reading, F1b): its lines and its
        # syntax tree were a traceback with exit 1, the code of a finding; now they are NOT MEASURABLE, exit 2.
        try:
            content.encode("utf-8")
        except UnicodeEncodeError:
            raise DiffNotReadable(f"{_shown(path)} is not UTF-8, so its lines and its syntax tree are not "
                                  "read here") from None
        # git's lines, so the allow marker is looked up where git puts the flagged line: `splitlines()` also split at
        # a form feed, VT, U+2028 or a lone CR, and a reviewed line after one was reported (counter-reading of
        # d017cd6b, H9).
        file_lines = content.split("\n")
        added_nums = {n for n, _ in added}
        for lineno, text in added:
            reason = None
            # A LONE CR ENDS A LINE FOR PYTHON (second counter-reading, F3): git counts lines at line feeds, so
            # `x = 1\rif False:` is one added line to git and two statements to Python. Every piece is checked,
            # and a byte order mark in front of the first one is not part of the statement (H8).
            for piece in text.lstrip("\ufeff").split("\r"):
                if _TRIVIAL_TRUTH.match(piece):
                    reason = "trivial-truth branch (`if/elif False|True` / `while False`) at a check"
                elif _COMMENTED_VERIFY.match(piece) and _commented_content_parses(piece):
                    reason = "commented-out verification call"
                if reason:
                    break
            if reason and not _allowlisted(file_lines, lineno):
                shown_text = text.strip().replace("\r", "\\r")  # a CR in the report would move the line it stands in
                findings.append(f"{_shown(path)}:{lineno}: {reason}\n    {shown_text}")
        for lineno, reason in _class_c_findings(content, added_nums):
            if not _allowlisted(file_lines, lineno):
                findings.append(f"{_shown(path)}:{lineno}: {reason}")
    return findings


def _resolve_base(base: str, cwd: Path) -> str | None:
    """Turn the CI-provided base sha into a usable merge base; honest fallbacks, never a crash."""
    if not base or set(base) == {"0"}:
        base = "HEAD~1"
    probe = subprocess.run(["git", "-C", str(cwd), "rev-parse", "--verify", f"{base}^{{commit}}"],
                           capture_output=True, text=True, env=_git_environment())
    if probe.returncode != 0:
        # ONLY A REVISION GIT DOES NOT KNOW IS THE FALLBACK (counter-reading of d017cd6b, H7, P3): a damaged base
        # object gave the same "nothing to diff" with exit 0 over a mutant in the range. git's message is English
        # here, because the built environment pins LC_ALL=C.
        if "Needed a single revision" not in probe.stderr:
            print(f"mutant_signature_guard: git rev-parse {base} failed (fail closed): {probe.stderr.strip()[:200]}",
                  file=sys.stderr)
            raise SystemExit(2)
        return None
    mb = subprocess.run(["git", "-C", str(cwd), "merge-base", base, "HEAD"],
                        capture_output=True, text=True, env=_git_environment())
    return mb.stdout.strip() if mb.returncode == 0 and mb.stdout.strip() else None


#: THE HEADER PREFIXES ARE NAMED, NOT TAKEN FROM THE CONFIGURATION (counter-reading of pull request
#: 375, F10a, P2). With `diff.mnemonicPrefix` set, git writes `+++ i/src/...` for the staged diff,
#: `removeprefix("b/")` left the `i/` on, no path matched the security scope, and a staged `if False:`
#: was reported clean with exit 0. Prefixes given on the command line win over `diff.mnemonicPrefix`
#: and `diff.noprefix` (measured with git 2.55.0).
_HEADER_PREFIXES = ("--src-prefix=a/", "--dst-prefix=b/")

#: THE HEADER IS ASKED FOR IN GIT'S QUOTED FORM (counter-reading of pull request 375, F1b and F10d,
#: P3). With `core.quotePath=false` git writes a name outside ASCII as it is: the self-test then said
#: OK without its decoder case reaching the decoder, and a name with U+2028 or U+0085 was cut by the
#: line split. The guard reads the form its tests prove, whatever the configuration says.
_QUOTED = ("-c", "core.quotePath=true")

#: THE FORM OF THE HUNKS IS NAMED TOO, NOT TAKEN FROM THE CONFIGURATION OR THE ATTRIBUTES
#: (counter-reading of pull request 415, F1 and F2, P2). `diff.interHunkContext` joins two changes into
#: one hunk across a context line, and `diff.suppressBlankEmpty` writes that line empty when it is
#: empty, which lost the hunk count (see `_added_lines_by_file`). An external diff program
#: (`GIT_EXTERNAL_DIFF`, `diff.external`, the command of a diff driver), the text conversion of a
#: driver, or a `-diff` attribute made git print no hunk at all, so the guard reported clean over a
#: diff it had not read; a `-diff` line in a tracked `.gitattributes` was enough. `--no-color` stood
#: here alone and not in the language gate, which `color.ui=always` blinded the same way. The language
#: gate asks for its diff with the same two tuples. Measured with git 2.55.0, each setting against
#: both; a setting from `GIT_CONFIG_COUNT` or `GIT_CONFIG_PARAMETERS` does not win over `-c`.
#: Replacement refs are switched off three ways, as in the receipt chain (second counter-reading, F5): a local
#: `refs/replace` that pointed the mutant's blob at its harmless predecessor made the range mode clean. Measured with
#: git 2.55.0, the environment name of `_GIT_PINNED_ENV`, `--no-replace-objects` and the `-c` pair each win alone over
#: `core.useReplaceRefs=true` in the repository; `scripts/pre_tag_receipt_lib.py` records a measurement in which the
#: first two lost to it, so all three stand.
#: `core.fsmonitor` is pinned off as in the receipt chain (counter-reading of d017cd6b, H6, P3): a monitor from the
#: global configuration that answered "nothing changed" made the working-tree form of the language gate green over a
#: German line it never read.
_DIFF_FORM = ("--no-replace-objects", "-c", "core.useReplaceRefs=false", "-c", "core.fsmonitor=",
              "-c", "diff.interHunkContext=0", "-c", "diff.suppressBlankEmpty=false")
_DIFF_SWITCHES = ("--no-color", "--no-ext-diff", "--no-textconv", "--text")


def run_staged(cwd: Path) -> list[str]:
    diff = _git(*_QUOTED, *_DIFF_FORM, "diff", "--cached", "-U0", *_DIFF_SWITCHES,
                *_HEADER_PREFIXES, "--", "src/proofbundle", cwd=cwd)
    return scan(diff, staged=True, cwd=cwd)


def run_base(base: str, cwd: Path) -> list[str]:
    resolved = _resolve_base(base, cwd)
    if resolved is None:
        print("mutant_signature_guard: no usable base commit (root commit / unknown sha) — "
              "nothing to diff, scan skipped honestly")
        return []
    diff = _git(*_QUOTED, *_DIFF_FORM, "diff", "-U0", *_DIFF_SWITCHES, *_HEADER_PREFIXES,
                resolved, "HEAD", "--", "src/proofbundle", cwd=cwd)
    return scan(diff, staged=False, cwd=cwd)


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

_CASES: list[tuple[str, str, bool]] = [
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
            target.write_text(content, encoding="utf-8")
            _git("add", "-A", cwd=repo)
            found = bool(run_staged(repo))
            ok = found == expect
            print(f"  {'ok  ' if ok else 'FAIL'} [{label}] "
                  f"{'caught' if found else 'quiet'} ({'expected' if ok else 'UNEXPECTED'})")
            failures += 0 if ok else 1
            _git("checkout", "-q", "--", ".", cwd=repo)
            _git("reset", "-q", cwd=repo)
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
        # a `-diff` attribute makes git print no hunk; the guard asks for text (415 counter-reading, F2)
        quoted.unlink()
        (repo / ".gitattributes").write_text("*.py -diff\n", encoding="utf-8")
        target.write_text(_CASES[0][1], encoding="utf-8")
        _git("add", "-A", cwd=repo)
        caught = bool(run_staged(repo))
        print(f"  {'ok  ' if caught else 'FAIL'} [A: a `-diff` attribute does not hide the change] "
              f"{'caught' if caught else 'quiet'} ({'expected' if caught else 'UNEXPECTED'})")
        failures += 0 if caught else 1
    print(f"self-test: {'OK' if failures == 0 else f'FAILED ({failures})'}")
    return 0 if failures == 0 else 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--staged", action="store_true", help="scan the staged diff (pre-commit)")
    mode.add_argument("--base", metavar="SHA", help="scan merge-base(SHA, HEAD)..HEAD (CI)")
    mode.add_argument("--self-test", action="store_true", help="prove the guard catches each class")
    a = p.parse_args(argv)
    # The fifth reader of the class of the four tools below (counter-reading of pull request 375,
    # F3): a printable name outside ASCII still meets an output encoding that lacks its letter.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="backslashreplace")
    if a.self_test:
        return self_test()
    repo = _repo_root()
    try:
        findings = run_staged(repo) if a.staged else run_base(a.base, repo)
    except DiffNotReadable as exc:
        print(f"mutant_signature_guard: NOT MEASURABLE (fail closed): {exc}")
        return 2
    if findings:
        print("mutant_signature_guard: BLOCKED: mutation-mutant signature(s) on security paths:")
        for f in findings:
            print(f"  {f}")
        print("If this is intentional and legitimate, add a visible `# mutant-guard: allow` "
              "comment on (or directly above) the flagged line so review sees the exception.")
        return 1
    print("mutant_signature_guard: clean, no mutant signatures in the scanned change")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
