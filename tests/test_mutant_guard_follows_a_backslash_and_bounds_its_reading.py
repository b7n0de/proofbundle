"""Class B of the mutant guard follows a backslash, makes nothing of a bullet, and bounds its reading;
classes A and C read a bool constant however it is spelled.

A review lens, run 13 at a435ba32 (2026-09-27), measured four findings, each executed in a throwaway
repository:

- A commented-out check continued over a backslash was clean with exit 0 in both modes, on main too: the
  first line, its backslash dropped, parsed and called no check, and the search stopped there, while the
  line with the check did not parse on its own. The Ed25519 check of `signature.py` in this tree's
  backslash style was one, and seven siblings (an assignment, `and`, `return`, `assert`, a conditional
  expression, a tuple, the same inside an `if` body) were others.
- A Markdown bullet naming a check, `#   - verify_checkpoint(signed_note, log_vkey)`, parsed as a unary
  minus on a call and was flagged with exit 1; so were `* verify(...)` and `a. verify(sig)`.
- 1312 comment lines of 798 bytes, each an unclosed call, took 623.96 s to read.
- `return` with `True` written in fullwidth letters opening `verify_thing`, and `if` with `False` written
  so at a check, parse as names and were clean with exit 0, on main too.

Each case below that shows a finding or its absence was red at a435ba32; the controls keep what must not
change (a real check stays a finding, and a unary operator before a constant stays outside class A).
"""
from __future__ import annotations

import ast
import importlib.util
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "scripts" / "mutant_signature_guard.py"
PKG = ROOT / "src" / "proofbundle"
BS = chr(92)

#: The lens's file: a real check, and a helper whose prose comment names two checks.
BENIGN = (
    "import hmac\n"
    "\n"
    "\n"
    "def verify_thing(data):\n"
    '    """Real check."""\n'
    "    if not isinstance(data, dict):\n"
    "        return False\n"
    '    return bool(data.get("ok"))\n'
    "\n"
    "\n"
    "def helper(x):\n"
    "    # verify the payload first, then compare digests (prose comment, must NOT match)\n"
    "    return x\n"
)
RET = '    return bool(data.get("ok"))'


def planted(text: str) -> str:
    """The lines in front of the last statement of `verify_thing`, which is line 8."""
    return BENIGN.replace(RET, text + "\n" + RET, 1)


def fullwidth(word: str) -> str:
    return "".join(chr(ord(c) + 0xFEE0) for c in word)


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t", *args],
                          capture_output=True, text=True, check=True).stdout.strip()


def _guard(repo: Path, *args: str, timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-B", str(GUARD), *args], cwd=str(repo), capture_output=True,
                          text=True, timeout=timeout)


def _change(tmp_path: Path, before: str, after: str, mode: str, rel: str = "src/proofbundle/guarded.py",
            timeout: int = 120) -> subprocess.CompletedProcess:
    """`before` committed, `after` staged (`--staged`) or committed on top (`--base`), and the guard's run."""
    repo = tmp_path / "r"
    (repo / rel).parent.mkdir(parents=True)
    (repo / rel).write_text(before, encoding="utf-8")
    _git(repo, "init", "-q")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "before")
    base = _git(repo, "rev-parse", "HEAD")
    (repo / rel).write_text(after, encoding="utf-8")
    _git(repo, "add", "-A")
    if mode == "--staged":
        return _guard(repo, "--staged", timeout=timeout)
    _git(repo, "commit", "-q", "-m", "after")
    return _guard(repo, "--base", base, timeout=timeout)


MODES = ["--staged", "--base"]


# -- a backslash continues the statement --------------------------------------------------------------

@pytest.mark.parametrize("mode", MODES)
def test_the_ed25519_check_in_backslash_style_commented_out_is_a_finding(tmp_path, mode):
    """signature.py's check, written over a backslash as this tree writes long calls, then commented out."""
    source = (PKG / "signature.py").read_text(encoding="utf-8")
    call = "Ed25519PublicKey.from_public_bytes(bytes(public_key)).verify(bytes(signature), bytes(message))"
    lines = source.split("\n")
    at = [i for i, line in enumerate(lines) if line.strip() == call]
    assert len(at) == 1, "the statement this proof was written for is not in signature.py once"
    indent = lines[at[0]][:len(lines[at[0]]) - len(lines[at[0]].lstrip())]
    first, second = "Ed25519PublicKey.from_public_bytes(bytes(public_key)) " + BS, "    .verify(bytes(signature), bytes(message))"
    before = lines[:at[0]] + [indent + first, indent + second] + lines[at[0] + 1:]
    after = lines[:at[0]] + [indent + "# " + first, indent + "# " + second] + lines[at[0] + 1:]
    ast.parse("\n".join(before))
    r = _change(tmp_path, "\n".join(before), "\n".join(after), mode, rel="src/proofbundle/signature.py")
    assert r.returncode == 1, r.stdout + r.stderr
    assert f"src/proofbundle/signature.py:{at[0] + 1}: commented-out verification call" in r.stdout, r.stdout


SIBLINGS = [
    ("an assignment continued by an attribute call", "    # ok = key " + BS + "\n    #     .verify(sig, msg)"),
    ("an `and` with compare_digest", "    # ok = data " + BS + "\n    #     and hmac.compare_digest(a, b)"),
    ("a `return` continued by .verify",
     "    # return Ed25519PublicKey.from_public_bytes(pk) " + BS + "\n    #     .verify(sig, msg)"),
    ("an `assert` continued by `and`",
     "    # assert isinstance(sig, bytes) " + BS + "\n    #     and verify_signature(pub, sig, data)"),
    ("a conditional expression", "    # ok = parse(x) " + BS + "\n    #     if verify_signature(pub, sig, data) else None"),
    ("a tuple", "    # return verify_ok " + BS + "\n    #     , check_detail(x)"),
]


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("text", [s[1] for s in SIBLINGS], ids=[s[0] for s in SIBLINGS])
def test_a_check_on_a_continuation_line_is_a_finding(tmp_path, text, mode):
    r = _change(tmp_path, BENIGN, planted(text), mode)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "src/proofbundle/guarded.py:8: commented-out verification call" in r.stdout, r.stdout


@pytest.mark.parametrize("mode", MODES)
def test_a_check_on_a_continuation_line_inside_an_if_body_is_a_finding(tmp_path, mode):
    """The `if` header parses and calls no check; the statement in its body starts at line 9."""
    text = "    # if data:\n    #     ok = key " + BS + "\n    #         .verify(sig, msg)"
    r = _change(tmp_path, BENIGN, planted(text), mode)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "src/proofbundle/guarded.py:9: commented-out verification call" in r.stdout, r.stdout


@pytest.mark.parametrize("text", [
    "    # ok = key " + BS + "\n    #     .from_bytes(b) " + BS + "\n    #     .verify(sig, msg)",
    "    # # ok = key " + BS + "\n    # #     .verify(sig, msg)",
], ids=["three lines over two backslashes", "commented twice"])
def test_a_check_after_more_than_one_backslash_or_level_is_a_finding(tmp_path, text):
    r = _change(tmp_path, BENIGN, planted(text), "--staged")
    assert r.returncode == 1, r.stdout + r.stderr
    assert "src/proofbundle/guarded.py:8: commented-out verification call" in r.stdout, r.stdout


# -- a bullet is no statement of a check --------------------------------------------------------------

@pytest.mark.parametrize("mode", MODES)
def test_a_bullet_list_of_entry_points_in_checkpoint_py_is_quiet(tmp_path, mode):
    """The lens's own form: two bullets added under a line of prose in the spec block of checkpoint.py."""
    source = (PKG / "checkpoint.py").read_text(encoding="utf-8")
    anchor = "#     proofbundle exposes the timestamp and leaves freshness policy to the caller.\n"
    assert source.count(anchor) == 1, "the spec block this proof was written for moved"
    after = source.replace(anchor, anchor + "# Entry points, in the order a verifier calls them:\n"
                           "#   - verify_checkpoint(signed_note, log_vkey)\n"
                           "#   - verify_cosignature(signed_note, witness_vkey)\n")
    r = _change(tmp_path, source, after, mode, rel="src/proofbundle/checkpoint.py")
    assert r.returncode == 0, r.stdout + r.stderr


@pytest.mark.parametrize("text", [
    "    #   * verify_signature(pub, sig, data)",
    "    #   + verify_signature(pub, sig, data)",
    "    # a. verify(sig)",
    "    # ~ check_mask(x)",
    "    # -verify_signature(pub, sig, data)",
], ids=["star bullet", "plus bullet", "enumerated item", "tilde", "minus without a space"])
def test_a_bullet_or_an_enumerated_item_is_quiet(tmp_path, text):
    r = _change(tmp_path, BENIGN, planted(text), "--staged")
    assert r.returncode == 0, r.stdout + r.stderr


@pytest.mark.parametrize("text", [
    "    # *verify_each(items)",
    "    # a.verify(sig)",
    "    # ok. verify(sig)",
    "    # not check_expiry()",
    "    # verify_chain() is idempotent",
    "    # validate_policy() in O(n)",
    "    # verify_chain() or verify_tree()",
    "    # ok = -verify(x)",
    "    # -verify(x) and verify(y)",
    "    ok = all([\n        isinstance(data, dict),\n        # not check_revoked(data)\n    ])",
    "    ok = all([\n        isinstance(data, dict),\n        # *verify_each(data)\n    ])",
], ids=["star without a space unpacks", "a method call", "a two-letter receiver", "not before a call",
        "a comparison", "a membership test", "or", "an assignment of a negation", "and after a bullet",
        "not as the last element of live brackets", "star as the last element of live brackets"])
def test_control_what_is_no_bullet_stays_a_finding(tmp_path, text):
    """`not`, a comparison, `and`, `or`, a star without a space and a method call stay findings: each is a
    shape code gives a check's decision, and the four prose forms flagged since e5bb214c stay flagged."""
    r = _change(tmp_path, BENIGN, planted(text), "--staged")
    assert r.returncode == 1, r.stdout + r.stderr
    assert "commented-out verification call" in r.stdout, r.stdout


# -- the reading is bounded by the size of the comments ----------------------------------------------

def _comment_block(line: str, size: int) -> str:
    return BENIGN + "\n\ndef helper2(x):\n" + line * max(1, (size - len(BENIGN)) // len(line)) + "    return x\n"


def test_a_mib_of_unclosed_calls_is_read_in_seconds(tmp_path):
    """The lens's S-4 form at 1 MiB: 623.96 s at a435ba32. Each line opens a call it does not close, so
    no prefix of a run ends a statement and none is parsed."""
    line = "    # f(x[1:2], " + "verify(a), " * 71 + "\n"
    content = _comment_block(line, 1 << 20)
    started = time.monotonic()
    r = _change(tmp_path, BENIGN, content, "--staged", timeout=60)
    assert r.returncode == 0, r.stdout + r.stderr
    assert time.monotonic() - started < 30


def test_comments_built_to_get_past_the_lexer_stop_fail_closed_in_seconds(tmp_path):
    """A MiB of decorator lines, each valid and each waiting for a `def` that never comes: `_lex` cannot
    rule a prefix out, so the bound on the parsing ends the run, with exit 2 and never clean."""
    line = "    # @f(x[1:2]) or " + "verify(a) or " * 60 + "g\n"
    content = _comment_block(line, 1 << 20)
    started = time.monotonic()
    r = _change(tmp_path, BENIGN, content, "--staged", timeout=60)
    assert r.returncode == 2, r.stdout + r.stderr
    assert "src/proofbundle/guarded.py: reading its comments as code takes more parsing than" in r.stderr
    assert "(fail closed)" in r.stderr and "clean" not in r.stdout
    assert time.monotonic() - started < 30


def _guard_module():
    spec = importlib.util.spec_from_file_location("_guard_bounds_its_reading", GUARD)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _tracked_sources() -> list[str]:
    r = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z", "--", "src/proofbundle"], capture_output=True)
    if r.returncode != 0:
        pytest.skip("NOT MEASURABLE here: this tree is not a git checkout")
    return sorted(n for n in r.stdout.decode("utf-8", "surrogateescape").split("\0") if n.endswith((".py", ".pyw")))


def _parsing_per_comment_byte(guard, rel: str, lines: list[str]) -> float:
    spent = []
    reading = guard._commented_statement

    def counted(code, spend=None):
        def both(size):
            spent.append(size)
            spend(size)
        return reading(code, both)
    guard._commented_statement = counted
    try:
        guard._commented_out_calls(rel, lines)
    finally:
        guard._commented_statement = reading
    comment_bytes = sum(len(text) for _, text, alone in guard._comments(rel, lines) if alone)
    return sum(spent) / max(comment_bytes, 1)


@pytest.mark.parametrize("whole", [False, True], ids=["as it is", "each file commented out whole"])
def test_the_tree_is_read_far_within_the_bound(whole):
    """The bound must never stop a real file: the tree's comments, and each file commented out line by
    line, which is the most code a comment block of this tree can hold, take at most 1.09 bytes of parsing
    per byte of comment (measured 2026-09-27) against a bound of 8."""
    guard = _guard_module()
    worst = 0.0
    for rel in _tracked_sources():
        _, lines, _ = guard._read_as_python(rel, (ROOT / rel).read_bytes())
        if whole:
            lines = [("# " + line) if line.strip() else line for line in lines]
        worst = max(worst, _parsing_per_comment_byte(guard, rel, lines))
    assert worst * 4 <= guard._PARSE_PER_BYTE, worst


def _says_it_cannot_parse(guard, window: list[str]) -> bool:
    lexed = guard._Lexed()
    for row, line in enumerate(window):
        lexed.feed(row, line, guard._lex(line, lexed.state) if lexed.state is not None else None)
    return lexed.state is not None and bool(lexed.broken or lexed.state or lexed.depth)


def test_the_lexer_rules_out_no_run_python_parses():
    """The oracle is Python's parser. Every window of up to four lines of the tree's sources, read as a
    comment's code is read, that `_lex` says cannot end a statement, does not parse in any reading."""
    guard = _guard_module()
    ruled_out, wrong = 0, []
    for rel in _tracked_sources():
        _, lines, _ = guard._read_as_python(rel, (ROOT / rel).read_bytes())
        for start in range(len(lines)):
            for size in range(1, 5):
                window = lines[start:start + size]
                if len(window) < size or not window[0].strip():
                    break
                if _says_it_cannot_parse(guard, window):
                    ruled_out += 1
                    if guard._commented_statement(guard._dedented(window)) is not None:
                        wrong.append(f"{rel}:{start + 1}+{size}")
    assert ruled_out > 1000, ruled_out
    assert wrong == []


# -- a bool constant however it is spelled ------------------------------------------------------------

@pytest.mark.parametrize("mode", MODES)
def test_return_true_in_fullwidth_letters_opening_a_check_is_a_finding(tmp_path, mode):
    after = BENIGN.replace('    """Real check."""\n', '    """Real check."""\n    return ' + fullwidth("True") + "\n")
    r = _change(tmp_path, BENIGN, after, mode)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "src/proofbundle/guarded.py:6: `return True` opens verification function `verify_thing`" in r.stdout


@pytest.mark.parametrize("header", [
    "if " + fullwidth("False") + ":",
    "while " + fullwidth("False") + ":",
    "if " + fullwidth("True") + " and data:",
], ids=["if False", "while False", "if True and"])
def test_a_trivial_truth_in_fullwidth_letters_is_a_finding(tmp_path, header):
    r = _change(tmp_path, BENIGN, BENIGN.replace("if not isinstance(data, dict):", header), "--staged")
    assert r.returncode == 1, r.stdout + r.stderr
    assert "src/proofbundle/guarded.py:6: trivial-truth branch" in r.stdout, r.stdout


@pytest.mark.parametrize("header", ["if not " + fullwidth("True") + ":", "if " + fullwidth("Truth") + ":"],
                         ids=["a unary operator first", "a name that is no constant"])
def test_control_what_class_a_left_out_stays_out(tmp_path, header):
    r = _change(tmp_path, BENIGN, BENIGN.replace("if not isinstance(data, dict):", header), "--staged")
    assert r.returncode == 0, r.stdout + r.stderr


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
