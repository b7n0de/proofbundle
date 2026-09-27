"""Class B of the mutant guard reads the statement a comment holds, and class C the stem of a check's name.

Class B took a comment only when the check's name came first in it, after at most one `if`, `elif`,
`return`, `assert` or `not` and one plain `name =`, and only when the comment parsed on its own line. A
review lens, run 12b at 6614ac32 (2026-09-27), measured 23 of 61 forms of a commented-out verification
call caught, every miss on main as well. The two worst: a negated guard clause, `# if not
merkle.verify_inclusion(...):`, and a verify called on a call's result, `# Ed25519PublicKey.
from_public_bytes(...).verify(...)`, which is the Ed25519 check of `signature.py`; commented out there,
the guard said clean with exit 0 in `--base`, while `# pub.verify(...)` was flagged. Class C read the verb
`verify` in a function's name, so `_verifies` and `is_verified` opening with `return True` passed.

A comment line is now read as Python on its own and joined with the comment lines below it, and a call
anywhere in the statement's expression tree to a callee named for a check is the finding. The forms
below are the lens's, each red at e5bb214c; the real lines are commented out in copies of this tree's
own files; the controls hold prose, a comment behind code (the lens's boundary), and a check named in a
string, quiet. The last tests read the tree itself: none of its comments holds such a call, and every
statement under src/proofbundle that calls a check is caught when it is commented out.
"""
from __future__ import annotations

import ast
import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "scripts" / "mutant_signature_guard.py"
PKG = ROOT / "src" / "proofbundle"
CR = chr(13)

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
    """The comment lines in front of the last statement of `verify_thing`, which is line 8."""
    return BENIGN.replace(RET, text + "\n" + RET, 1)


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t", *args],
                          capture_output=True, text=True, check=True).stdout.strip()


def _guard(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-B", str(GUARD), *args], cwd=str(repo), capture_output=True,
                          text=True, timeout=120)


def _repo(tmp_path: Path, files: dict[str, str | bytes]) -> Path:
    repo = tmp_path / "r"
    for rel, content in files.items():
        p = repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
    _git(repo, "init", "-q")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")
    return repo


def _stage(repo: Path, rel: str, content: str | bytes) -> None:
    (repo / rel).write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
    _git(repo, "add", "-A")


# -- class B: the lens's forms, each clean with exit 0 at e5bb214c ----------------------------------

IN_CLASS = [
    ("B04", "`if not` header with its body", "    # if not verify_signature(pub, sig, data):\n    #     return False"),
    ("B05", "negated guard clause (persample.py:262)",
     "    # if not merkle.verify_inclusion(disclosure_bytes, index, n, proof, root):"),
    ("B06", "negated attribute of a call (evalclaim.py:504)", "    # if not verify_bundle(bundle).ok:"),
    ("B07", "`elif not` header", "    # elif not check_shape(data):"),
    ("B08", "`if not hmac.compare_digest(...)`", "    # if not hmac.compare_digest(expected, actual):"),
    ("B10", "`return not` call", "    # return not verify_signature(pub, sig, data)"),
    ("B12", "`assert not` call", "    # assert not check_revoked(key)"),
    ("B14", "tuple target", "    # result, bundle = verify_receipt_token(token)"),
    ("B15", "annotated target", "    # ok: bool = verify_signature(pub, sig, data)"),
    ("B16", "multi-line call (tlogproof.py:264)",
     "    # inclusion_ok = merkle.verify_inclusion(\n    #     leaf_data, index, size, proof, root)"),
    ("B17", "bare multi-line call", "    # verify_signature(\n    #     pub, sig, data)"),
    ("B19", "double hash", "    ## verify_signature(pub, sig, data)"),
    ("B20", "commented twice", "    # # verify_signature(pub, sig, data)"),
    ("B24", "`await`", "    # ok = await verify_signature_async(pub, sig)"),
    ("B25", "parenthesized condition", "    # if (verify_signature(pub, sig, data)):"),
    ("B26", "call as the second operand", "    # if data and verify_signature(pub, sig, data):"),
    ("B28", "`ok = not <call>`", "    # ok = not verify_signature(pub, sig, data)"),
    ("B29", "`ok = (<call>)`", "    # ok = (verify_signature(pub, sig, data))"),
    ("B39", "verify on a call's result (signature.py:46)",
     "    # Ed25519PublicKey.from_public_bytes(bytes(public_key)).verify(bytes(signature), bytes(message))"),
    ("B40", "verify_message on a call's result (anchors_rfc3161.py:125)",
     "    # builder.build().verify_message(response, canonical_root)"),
    ("B41", "trailing backslash", "    # ok = hmac.compare_digest(a, b) \\"),
    ("B42", "`#:` comment", "    #: verify_signature(pub, sig, data)"),
    ("B43", "chained assignment", "    # x = y = verify_signature(pub, sig, data)"),
    ("B44", "CamelCase callee", "    # ok = VerifySignature(pub, sig, data)"),
    ("B45", "`yield`", "    # yield verify_signature(pub, sig, data)"),
    ("B47", "subscript target (decision.py:679)", '    # r["lineage"] = verify_relationship_edges(edges)'),
    ("B49", "augmented assignment", "    # ok &= verify_signature(pub, sig, data)"),
    ("B50", "`bool()` wrapper (renewal.py:989)", "    # anchored = bool(verify_anchor(newest))"),
    ("B51", "`return bool()` wrapper", "    # return bool(verify_signature(pub, sig, data))"),
    ("B56", "one-line `if not ...: raise`", '    # if not verify_signature(pub, sig, data): raise ValueError("bad")'),
    ("own", "a comment inside the comment behind a header", "    # if not verify_signature(pub, sig, data):  # was on"),
    ("own", "a call over three lines behind a lone CR",
     "    x = 1" + CR + "    # ok = (\n    #     data\n    #     and hmac.compare_digest(a, b))"),
]


@pytest.mark.parametrize("text", [c[2] for c in IN_CLASS], ids=[f"{c[0]} {c[1]}" for c in IN_CLASS])
def test_a_commented_out_check_call_is_a_finding(tmp_path, text):
    repo = _repo(tmp_path, {"src/proofbundle/guarded.py": BENIGN})
    _stage(repo, "src/proofbundle/guarded.py", planted(text))
    r = _guard(repo, "--staged")
    assert r.returncode == 1, r.stdout + r.stderr
    assert "commented-out verification call" in r.stdout, r.stdout


def test_a_commented_out_check_call_in_an_async_def_is_a_finding(tmp_path):
    """The lens's B52."""
    repo = _repo(tmp_path, {"src/proofbundle/guarded.py": BENIGN})
    _stage(repo, "src/proofbundle/guarded.py",
           BENIGN + "\n\nasync def averify(data):\n    # ok = await verify_signature_async(data)\n    return data\n")
    r = _guard(repo, "--staged")
    assert r.returncode == 1, r.stdout + r.stderr
    assert "src/proofbundle/guarded.py:17: commented-out verification call" in r.stdout, r.stdout


# -- the real lines of this tree, commented out in copies of their files -----------------------------

def _statement(tree: ast.Module, match) -> ast.stmt:
    found = [s for s in ast.walk(tree) if isinstance(s, ast.stmt) and match(s)]
    assert len(found) == 1, f"the statement this proof was written for is not in the file once: {len(found)}"
    return found[0]


def _call_to(node: ast.AST, attr: str) -> ast.Call | None:
    return node if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and \
        node.func.attr == attr else None


def _ed25519(s):      # Ed25519PublicKey.from_public_bytes(...).verify(...)
    call = _call_to(getattr(s, "value", None), "verify") if isinstance(s, ast.Expr) else None
    return call is not None and _call_to(call.func.value, "from_public_bytes") is not None


def _rfc3161(s):      # builder.build().verify_message(...)
    call = _call_to(getattr(s, "value", None), "verify_message") if isinstance(s, ast.Expr) else None
    return call is not None and _call_to(call.func.value, "build") is not None


def _negated(attr_or_name: str):
    def match(s):
        if not (isinstance(s, ast.If) and isinstance(s.test, ast.UnaryOp) and isinstance(s.test.op, ast.Not)):
            return False
        inner = s.test.operand.value if isinstance(s.test.operand, ast.Attribute) else s.test.operand
        func = getattr(inner, "func", None)
        return getattr(func, "attr", getattr(func, "id", None)) == attr_or_name
    return match


REAL = [
    ("signature.py", _ed25519, "X01 the Ed25519 verify, called on a call's result"),
    ("anchors_rfc3161.py", _rfc3161, "X04 the RFC 3161 verify_message, called on a call's result"),
    ("persample.py", _negated("verify_inclusion"), "X02 the negated inclusion check with its body"),
    ("evalclaim.py", _negated("verify_bundle"), "X03 the negated bundle check with its body"),
]


@pytest.mark.parametrize("mode", ["--staged", "--base"])
@pytest.mark.parametrize("name,match", [(n, m) for n, m, _ in REAL], ids=[i for _, _, i in REAL])
def test_a_real_check_of_this_tree_commented_out_is_a_finding(tmp_path, name, match, mode):
    source = (PKG / name).read_text(encoding="utf-8")
    stmt = _statement(ast.parse(source), match)
    lines = source.split("\n")
    block = lines[stmt.lineno - 1:stmt.end_lineno]
    indent = min(len(x) - len(x.lstrip()) for x in block if x.strip())
    for i in range(stmt.lineno - 1, stmt.end_lineno):
        if lines[i].strip():
            lines[i] = lines[i][:indent] + "# " + lines[i][indent:]
    lines.insert(stmt.end_lineno, " " * indent + "pass")      # the block the statement stood in keeps a body
    repo = _repo(tmp_path, {f"src/proofbundle/{name}": source})
    base = _git(repo, "rev-parse", "HEAD")
    _stage(repo, f"src/proofbundle/{name}", "\n".join(lines))
    if mode == "--base":
        _git(repo, "commit", "-q", "-m", "the check is commented out")
    r = _guard(repo, *([mode] if mode == "--staged" else [mode, base]))
    assert r.returncode == 1, r.stdout + r.stderr
    assert f"src/proofbundle/{name}:{stmt.lineno}: commented-out verification call" in r.stdout, r.stdout


# -- class C: the stem of a check's name ------------------------------------------------------------

@pytest.mark.parametrize("fn", [
    'def _verifies(bundle):\n    """True iff the bundle verifies OK."""\n    return True\n',
    "def is_verified(data):\n    return True\n",
], ids=["C12 _verifies", "C13 is_verified"])
def test_return_true_opening_an_inflected_check_name_is_a_finding(tmp_path, fn):
    repo = _repo(tmp_path, {"src/proofbundle/guarded.py": BENIGN})
    _stage(repo, "src/proofbundle/guarded.py", BENIGN + "\n\n" + fn)
    r = _guard(repo, "--staged")
    assert r.returncode == 1, r.stdout + r.stderr
    assert "`return True` opens verification function" in r.stdout, r.stdout


def test_return_true_opening_demo_verifies_is_a_finding(tmp_path):
    """The lens's X06: `demo.py` binds `_verifies`, and `return True` after its docstring passed."""
    source = (PKG / "demo.py").read_text(encoding="utf-8")
    fn = _statement(ast.parse(source), lambda s: isinstance(s, ast.FunctionDef) and s.name == "_verifies")
    doc = fn.body[0]
    assert isinstance(doc, ast.Expr) and isinstance(doc.value, ast.Constant), "`_verifies` lost its docstring"
    lines = source.split("\n")
    lines.insert(doc.end_lineno, " " * doc.col_offset + "return True")
    repo = _repo(tmp_path, {"src/proofbundle/demo.py": source})
    _stage(repo, "src/proofbundle/demo.py", "\n".join(lines))
    r = _guard(repo, "--staged")
    assert r.returncode == 1, r.stdout + r.stderr
    assert "`return True` opens verification function `_verifies`" in r.stdout, r.stdout


# -- controls: prose, a comment behind code, a check named in a string --------------------------------

CONTROLS = [
    ("prose naming a function before a parenthetical (dsse.py)",
     "    # verify_thing (docstring says only ValueError) never gets a raw error."),
    ("a function name with parens inside prose (outcome.py)", "    # verify_thing() is the explicit exception variant."),
    ("code-then-prose narrative (signature.py)", "    # pub.verify(sig, data) and raised a raw TypeError nobody caught."),
    ("prose over two lines, each naming a check",
     "    # verify_signature is called by the caller, and\n    # check_shape(data) is not."),
    ("prose that parses as a name annotated with a call", "    # NOTE: verify_thing(data)"),
    ("a commented-out call to a function that is no check", "    # log.info(data)"),
    ("a check named without a call", "    # ok = verify_signature"),
    ("a check named only in a string", '    # raise ValueError("verify_signature failed")'),
    ("a comment behind code (the lens's boundary B23)", "    ok = True  # ok = verify_signature(pub, sig, data)"),
    ("a check call inside a string, not a comment", '    s = """\n    # verify_signature(pub, sig, data)\n    """'),
]


@pytest.mark.parametrize("text", [c[1] for c in CONTROLS], ids=[c[0] for c in CONTROLS])
def test_control_stays_quiet(tmp_path, text):
    repo = _repo(tmp_path, {"src/proofbundle/guarded.py": BENIGN})
    _stage(repo, "src/proofbundle/guarded.py", planted(text))
    r = _guard(repo, "--staged")
    assert r.returncode == 0, r.stdout + r.stderr


# -- the tree itself ----------------------------------------------------------------------------------

def _guard_module():
    spec = importlib.util.spec_from_file_location("_guard_reads_the_statement", GUARD)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _tracked_sources() -> list[str]:
    r = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z", "--", "src/proofbundle"], capture_output=True)
    if r.returncode != 0:
        pytest.skip("NOT MEASURABLE here: this tree is not a git checkout")
    return sorted(n for n in r.stdout.decode("utf-8", "surrogateescape").split("\0") if n.endswith((".py", ".pyw")))


def test_no_comment_of_the_tree_holds_a_check_call_and_no_check_opens_with_return_true():
    """The false-positive measure: a changed file is judged whole, so a finding here would block every
    change to its file."""
    guard = _guard_module()
    findings = []
    for rel in _tracked_sources():
        tree, lines, _ = guard._read_as_python(rel, (ROOT / rel).read_bytes())
        findings += [f"{rel}:{first}" for first, _ in guard._commented_out_calls(rel, lines)]
        findings += [f"{rel}:{n}: {why}" for n, why in guard._class_c_findings(tree, set(range(1, len(lines) + 1)))]
    assert findings == []


def _own_expressions(stmt: ast.stmt):
    for field, value in ast.iter_fields(stmt):
        if field not in ("body", "orelse", "finalbody", "handlers", "cases"):
            yield from (v for v in (value if isinstance(value, list) else [value]) if isinstance(v, ast.AST))


def test_every_statement_of_the_tree_that_calls_a_check_is_caught_commented_out():
    """The class over the tree's own shapes, not the lens's: each statement whose own expressions call a
    callee named for a check, commented out as an editor does it, is a finding at its first line. The
    reader of e5bb214c caught 151 of the 294 there were at this change (measured 2026-09-27)."""
    guard = _guard_module()
    planted_count, missed = 0, []
    for rel in _tracked_sources():
        tree, lines, _ = guard._read_as_python(rel, (ROOT / rel).read_bytes())
        for stmt in ast.walk(tree):
            if not isinstance(stmt, ast.stmt) or isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef,
                                                                   ast.ClassDef)):
                continue
            calls = [n for e in _own_expressions(stmt) for n in ast.walk(e) if isinstance(n, ast.Call)]
            if not guard._verify_calls(ast.Module(body=[ast.Expr(value=c) for c in calls], type_ignores=[])):
                continue
            first, last = stmt.lineno, stmt.end_lineno
            indent = min(len(x) - len(x.lstrip()) for x in lines[first - 1:last] if x.strip())
            commented = [x[:indent] + "# " + x[indent:] if first <= i + 1 <= last and x.strip() else x
                         for i, x in enumerate(lines)]
            planted_count += 1
            if not any(start == first for start, _ in guard._commented_out_calls(rel, commented)):
                missed.append(f"{rel}:{first}")
    assert planted_count >= 200, planted_count
    assert missed == []


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
