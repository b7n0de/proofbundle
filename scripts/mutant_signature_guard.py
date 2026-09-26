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
  D  a symlink or a gitlink under src/proofbundle, or `src` or `src/proofbundle` itself as one, in
     the judged state: the diff shows a link's text or a commit id, Python runs what it points at,
     which the scan does not reach (a mutant planted outside the security path and linked in was
     reported clean with exit 0, measured 2026-09-26, and so were a symlinked `src` and a gitlink
     under the package). Not diff-scoped on purpose: an existing link would hide every later change
     to its target. No allow marker: a link carries no comment.

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
                          capture_output=True, text=True)
    if proc.returncode != 0 or not proc.stdout.strip():
        raise SystemExit("mutant_signature_guard: not inside a git repository (fail closed)")
    return Path(proc.stdout.strip())


#: `.` crosses a newline here: git writes a name with a newline quoted, the header decoder gives the
#: real name back, and without DOTALL `.*` stopped at it, so a mutant in such a file passed with
#: exit 0 (a review lens, measured 2026-09-26). The name ends where the value ends.
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


def _git(*args: str, cwd: Path) -> str:
    """git's output as it wrote it: bytes decoded, with no newline translation.

    Text mode turned a lone CR into a line end. git ends a line at LF only, so one added line
    `x = 1<CR>if False:` came back as two, the second without its `+`, and it was never judged
    (measured 2026-09-26: exit 0 over a staged `if False:` that Python reads as its own statement).
    """
    proc = subprocess.run(["git", "-C", str(cwd), *args], capture_output=True)
    if proc.returncode != 0:
        raise SystemExit(f"mutant_signature_guard: git {' '.join(args[:2])} failed (fail closed): "
                         f"{proc.stderr.decode('utf-8', 'replace').strip()[:200]}")
    return proc.stdout.decode("utf-8", "surrogateescape")


#: The diff's grammar, pinned against configuration. With `diff.mnemonicPrefix` the new side is
#: `i/` or `w/` instead of `b/`, and with `diff.external` another program writes the diff; either
#: made the guard report clean over a staged `if False:` (measured 2026-09-26). A textconv filter
#: would hand it converted text instead of the source. And a `-diff` or `binary` attribute in a
#: committed `.gitattributes` made git write `Binary files ... differ` instead of the lines, so
#: nothing was added and the guard reported clean, in CI too (measured the same day); `--text`
#: diffs every file as text.
DIFF_GRAMMAR = ("--text", "--no-ext-diff", "--no-textconv", "--no-color",
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


def _allowlisted(file_lines: list[str], lineno: int) -> bool:
    for candidate in (lineno, lineno - 1):
        if 1 <= candidate <= len(file_lines) and _ALLOW_MARKER in file_lines[candidate - 1]:
            return True
    return False


def _class_c_findings(content: str, added: set[int]) -> list[tuple[int, str]]:
    """`return True` as first non-docstring statement of a verify-ish function, if the def or
    the return line is part of the change (pre-existing code is out of scope for a diff guard)."""
    findings: list[tuple[int, str]] = []
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return []  # unparseable staged state: the test/lint gates own that failure
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
            if node.lineno in added or body[0].lineno in added:
                findings.append((body[0].lineno,
                                 f"`return True` opens verification function `{node.name}`"))
    return findings


def _file_content(path: str, *, staged: bool, cwd: Path) -> str:
    """The new side of the diff: the index for --staged, HEAD for --base (the range ends at HEAD, so
    the file on disk is not what the diff describes once the working tree differs)."""
    return _git("show", f":{path}" if staged else f"HEAD:{path}", cwd=cwd)


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
    """Judge the added lines as Python reads them: the diff says WHICH git lines are new, the file
    says which Python lines those are. Line numbers and the allow marker are Python's."""
    try:
        per_file = _added_lines_by_file(diff_text)
    except ValueError as exc:
        raise SystemExit(f"mutant_signature_guard: the diff does not parse as git writes it "
                         f"(fail closed): {exc}") from exc
    findings: list[str] = []
    for path, added in per_file.items():
        if not _SECURITY_PATH.match(path):
            continue
        content = _file_content(path, staged=staged, cwd=cwd)
        git_lines = content.split("\n")
        file_lines, spans = _python_lines_of(content)
        added_nums: set[int] = set()
        for git_no, text in added:
            # The diff and the file are two readings of one state; if they disagree, neither is judged.
            if not 1 <= git_no <= len(git_lines) or git_lines[git_no - 1] != text:
                raise SystemExit(f"mutant_signature_guard: {path}:{git_no}: the diff and the file "
                                 f"disagree about this line (fail closed)")
            added_nums.update(spans[git_no - 1])
        for lineno in sorted(added_nums):
            text = file_lines[lineno - 1]
            reason = None
            if _TRIVIAL_TRUTH.match(text):
                reason = "trivial-truth branch (`if/elif False|True` / `while False`) at a check"
            elif _COMMENTED_VERIFY.match(text) and _commented_content_parses(text):
                reason = "commented-out verification call"
            if reason and not _allowlisted(file_lines, lineno):
                findings.append(f"{path}:{lineno}: {reason}\n    {text.strip()}")
        for lineno, reason in _class_c_findings(content, added_nums):
            if not _allowlisted(file_lines, lineno):
                findings.append(f"{path}:{lineno}: {reason}")
    for path, mode, obj in _links_on_security_paths(staged=staged, cwd=cwd):
        if mode == "120000":
            target = _file_content(path, staged=staged, cwd=cwd).strip()
            findings.append(f"{path}: {_NOT_A_FILE[mode]} on a security path (to {target}) — the guard "
                            "reads the link, Python runs its target, which this scan does not reach; a "
                            f"link {_NO_MARKER}, so put the file itself there")
        else:
            findings.append(f"{path}: {_NOT_A_FILE[mode]} on a security path (commit {obj[:12]}) — the "
                            "diff shows a commit id, Python runs the files under it, which this scan "
                            f"does not reach; a gitlink {_NO_MARKER}, so put the files themselves there")
    return findings


def _resolve_base(base: str, cwd: Path) -> str | None:
    """Turn the CI-provided base sha into a usable merge base; honest fallbacks, never a crash."""
    if not base or set(base) == {"0"}:
        base = "HEAD~1"
    probe = subprocess.run(["git", "-C", str(cwd), "rev-parse", "--verify", f"{base}^{{commit}}"],
                           capture_output=True, text=True)
    if probe.returncode != 0:
        return None
    mb = subprocess.run(["git", "-C", str(cwd), "merge-base", base, "HEAD"],
                        capture_output=True, text=True)
    return mb.stdout.strip() if mb.returncode == 0 and mb.stdout.strip() else None


def run_staged(cwd: Path) -> list[str]:
    diff = _git("diff", "--cached", "-U0", *DIFF_GRAMMAR, "--", "src/proofbundle", cwd=cwd)
    return scan(diff, staged=True, cwd=cwd)


def run_base(base: str, cwd: Path) -> list[str]:
    resolved = _resolve_base(base, cwd)
    if resolved is None:
        print("mutant_signature_guard: no usable base commit (root commit / unknown sha) — "
              "nothing to diff, scan skipped honestly")
        return []
    diff = _git("diff", "-U0", *DIFF_GRAMMAR, resolved, "HEAD", "--", "src/proofbundle", cwd=cwd)
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
    # A line is a header by position, not by shape (2026-09-26): `++ 1` is valid Python, and its
    # diff line `+++ 1` once read as a header naming the path `1`.
    ("A: after an added line that looks like a diff header",
     _BENIGN + "++ 1\nif False:\n    pass\n", True),
    # Python ends a line at a lone CR, git does not (2026-09-26).
    ("A: after a lone CR, which Python reads as a line end",
     _BENIGN.replace('    if not isinstance(data, dict):', '    x = 1\r    if False:'), True),
    ("A: behind a BOM on the first line, which Python skips",
     "\ufeffif False:\n    pass\n", True),
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
            # Unstage FIRST, then restore the file from the index. The other order restored the
            # file from the staged case and left it in the working tree, so the next `add -A`
            # staged it again: the negative control below held only while the last case happened
            # to be one that stays quiet (found 2026-09-26, when a catching case became the last).
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
    print(f"self-test: {'OK' if failures == 0 else f'FAILED ({failures})'}")
    return 0 if failures == 0 else 1


def main(argv: list[str] | None = None) -> int:
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


if __name__ == "__main__":
    raise SystemExit(main())
