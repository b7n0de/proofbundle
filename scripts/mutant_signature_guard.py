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
import re
import subprocess
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


_SECURITY_PATH = re.compile(r"^src/proofbundle/.*\.py$")
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
    proc = subprocess.run(["git", "-C", str(cwd), *args],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        raise SystemExit(f"mutant_signature_guard: git {' '.join(args[:2])} failed (fail closed): "
                         f"{proc.stderr.strip()[:200]}")
    return proc.stdout


def _added_lines_by_file(diff_text: str) -> dict[str, list[tuple[int, str]]]:
    """Parse a -U0 unified diff into {new_path: [(new_lineno, added_line_text), ...]}."""
    out: dict[str, list[tuple[int, str]]] = {}
    current: str | None = None
    lineno = 0
    for raw in diff_text.splitlines():
        if raw.startswith("+++ "):
            path = raw[4:].strip()
            current = None if path == "/dev/null" else path.removeprefix("b/")
        elif raw.startswith("@@"):
            m = re.search(r"\+(\d+)", raw)
            lineno = int(m.group(1)) if m else 0
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
    if staged:
        return _git("show", f":{path}", cwd=cwd)
    p = cwd / path
    return p.read_text(encoding="utf-8") if p.is_file() else ""


def scan(diff_text: str, *, staged: bool, cwd: Path) -> list[str]:
    findings: list[str] = []
    for path, added in _added_lines_by_file(diff_text).items():
        if not _SECURITY_PATH.match(path):
            continue
        content = _file_content(path, staged=staged, cwd=cwd)
        file_lines = content.splitlines()
        added_nums = {n for n, _ in added}
        for lineno, text in added:
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
    diff = _git("diff", "--cached", "-U0", "--no-color", "--", "src/proofbundle", cwd=cwd)
    return scan(diff, staged=True, cwd=cwd)


def run_base(base: str, cwd: Path) -> list[str]:
    resolved = _resolve_base(base, cwd)
    if resolved is None:
        print("mutant_signature_guard: no usable base commit (root commit / unknown sha) — "
              "nothing to diff, scan skipped honestly")
        return []
    diff = _git("diff", "-U0", "--no-color", resolved, "HEAD", "--", "src/proofbundle", cwd=cwd)
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
    print(f"self-test: {'OK' if failures == 0 else f'FAILED ({failures})'}")
    return 0 if failures == 0 else 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--staged", action="store_true", help="scan the staged diff (pre-commit)")
    mode.add_argument("--base", metavar="SHA", help="scan merge-base(SHA, HEAD)..HEAD (CI)")
    mode.add_argument("--self-test", action="store_true", help="prove the guard catches each class")
    a = p.parse_args(argv)
    if a.self_test:
        return self_test()
    repo = _repo_root()
    findings = run_staged(repo) if a.staged else run_base(a.base, repo)
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
