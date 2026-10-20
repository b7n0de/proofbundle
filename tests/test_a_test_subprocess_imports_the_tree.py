"""A test that starts a script of this tree in a subprocess hands it this tree's `src`, not the installed package.

SOURCE. The runner comparison for L1 (pull request 393, 20.10.2026) found six cases red only on the station: their
subprocess imported proofbundle from wherever the interpreter found it, and the parent test judged that foreign build.
Measured on 20.10.2026 at main 862f263d: `~/proofbundle/.venv/bin/python` without PYTHONPATH imports
`/home/konrad/proofbundle/src/proofbundle`, the main clone, then detached at 5958c2d5 with `__version__` 6.1.0, so a test
run in any other worktree measured that clone's source in its subprocess; `/usr/bin/python3` finds no proofbundle at
all. Four calls had this form: `tests/test_verdict_contract_example_pins_its_key.py` (twice) and
`tests/test_verdict_contract_example_reads_strict_json.py` start `examples/verdict_contract/*.py`, and
`tests/test_verifier_block.py` starts `conformance/run_conformance.py`, which imports proofbundle in its first lines
and puts `src` on the path only later, inside functions. The house form stands in the same file a few lines below:
`env={**os.environ, "PYTHONPATH": str(REPO / "src")}`.

THE GUARD reads every test file for calls of `subprocess.run`, `check_output`, `check_call`, `call` and `Popen` whose
argument list begins with `sys.executable`. It resolves the script the call starts when the list names it as a path
built from the repository root and string constants, directly, through `str(...)`, or through names bound at module
level or in the function around the call (`EXAMPLE / "check_example.py"`, `runner = REPO / "conformance" /
"run_conformance.py"`), and reads `-m proofbundle...`. Such
a script needs this tree's `src` when one of its top-level statements (also inside a top-level `if`, `try` or `with`,
never inside a function or class) imports proofbundle before any top-level statement puts a path ending in `src` on
`sys.path`. Every call that starts such a script must pass `env=` with `PYTHONPATH` in it, written in the call, in the
function that builds the name it passes, or in a module-level name it passes. A call whose script this guard cannot resolve (a path computed at run
time, a `-c` program) is outside what it reads.
"""
from __future__ import annotations

import ast
import unittest
import warnings
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TESTS = REPO / "tests"
_AUFRUFE = frozenset({"run", "check_output", "check_call", "call", "Popen"})


def _ist_sys_executable(k: ast.AST) -> bool:
    return isinstance(k, ast.Attribute) and k.attr == "executable" and isinstance(k.value, ast.Name) and k.value.id == "sys"


def _ist_wurzel(k: ast.AST) -> bool:
    """`Path(__file__).resolve().parents[1]` and its spellings: an expression over `__file__` that climbs one level
    above `tests/`, i.e. `parents[1]` or `.parent.parent`."""
    text = ast.unparse(k)
    return "__file__" in text and ("parents[1]" in text or text.count(".parent") >= 2)


def _namen(baum: ast.Module) -> dict:
    """Module-level `NAME = expr`, the table the resolver follows."""
    aus = {}
    for k in baum.body:
        if isinstance(k, ast.Assign) and len(k.targets) == 1 and isinstance(k.targets[0], ast.Name):
            aus[k.targets[0].id] = k.value
    return aus


def _pfad(k: ast.AST, namen: dict, tiefe: int = 0) -> str | None:
    """The path relative to the repository root that `k` names, or None when it is not of a form read here."""
    if tiefe > 8:
        return None
    if isinstance(k, ast.Call) and isinstance(k.func, ast.Name) and k.func.id == "str" and len(k.args) == 1:
        return _pfad(k.args[0], namen, tiefe + 1)
    if isinstance(k, ast.Name):
        if k.id in namen:
            return _pfad(namen[k.id], namen, tiefe + 1)
        return None
    if _ist_wurzel(k):
        return ""
    if isinstance(k, ast.BinOp) and isinstance(k.op, ast.Div) and isinstance(k.right, ast.Constant) \
            and isinstance(k.right.value, str):
        links = _pfad(k.left, namen, tiefe + 1)
        return None if links is None else (links + "/" if links else "") + k.right.value
    return None


def _setzt_src(k: ast.AST) -> bool:
    """A statement that puts a path ending in `src` on sys.path (`insert`, `append`, `sys.path[:0] = [...]`)."""
    for n in ast.walk(k):
        ziel = None
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in ("insert", "append") \
                and ast.unparse(n.func.value) == "sys.path":
            ziel = n
        elif isinstance(n, ast.Assign) and any(ast.unparse(t).startswith("sys.path") for t in n.targets):
            ziel = n
        if ziel is not None and any(isinstance(c, ast.Constant) and c.value == "src" for c in ast.walk(ziel)):
            return True
    return False


def _oberste_anweisungen(koerper: list):
    """Top-level statements in order, descending into `if`, `try` and `with`, never into a def or class."""
    for k in koerper:
        if isinstance(k, (ast.If, ast.Try, ast.With)):
            yield from _oberste_anweisungen(getattr(k, "body", []))
            for teil in ("orelse", "finalbody"):
                yield from _oberste_anweisungen(getattr(k, teil, []))
            for h in getattr(k, "handlers", []):
                yield from _oberste_anweisungen(h.body)
        else:
            yield k


def braucht_src(quelle: str) -> bool:
    """Imports this script proofbundle at top level before it puts a `src` on sys.path?"""
    for k in _oberste_anweisungen(ast.parse(quelle).body):
        if _setzt_src(k):
            return False
        if isinstance(k, ast.Import) and any(a.name.split(".")[0] == "proofbundle" for a in k.names):
            return True
        if isinstance(k, ast.ImportFrom) and k.level == 0 and (k.module or "").split(".")[0] == "proofbundle":
            return True
    return False


def _gibt_pythonpath(aufruf: ast.Call, funktion: ast.AST | None, namen: dict) -> bool:
    """`env=` carries PYTHONPATH: in the call, in a module-level name it passes, or in an assignment of the function
    that builds the name it passes."""
    env = next((k.value for k in aufruf.keywords if k.arg == "env"), None)
    if env is None:
        return False
    if "PYTHONPATH" in ast.unparse(env):
        return True
    if isinstance(env, ast.Name):
        if funktion is not None and any(isinstance(n, (ast.Assign, ast.AugAssign)) and "PYTHONPATH" in ast.unparse(n)
                                        and env.id in ast.unparse(n) for n in ast.walk(funktion)):
            return True
        return env.id in namen and "PYTHONPATH" in ast.unparse(namen[env.id])
    return False


def _lokale_namen(funktion: ast.AST | None) -> dict:
    """`NAME = expr` inside the function around the call; it shadows a module-level name of the same spelling."""
    if funktion is None:
        return {}
    return {k.targets[0].id: k.value for k in ast.walk(funktion)
            if isinstance(k, ast.Assign) and len(k.targets) == 1 and isinstance(k.targets[0], ast.Name)}


def befunde(testquelle: str, lies_skript) -> tuple[list, list]:
    """(calls that start a script needing `src` without PYTHONPATH, calls whose script was resolved), each as
    (line, script). `lies_skript(relpfad)` gives the source of a script of the tree or None."""
    baum = ast.parse(testquelle)
    namen = _namen(baum)
    eltern = {}
    for n in ast.walk(baum):
        for c in ast.iter_child_nodes(n):
            eltern[c] = n
    fehlt, gelesen = [], []
    for n in ast.walk(baum):
        if not isinstance(n, ast.Call):
            continue
        f = n.func
        name = f.attr if isinstance(f, ast.Attribute) else (f.id if isinstance(f, ast.Name) else None)
        argv = n.args[0] if n.args else next((k.value for k in n.keywords if k.arg == "args"), None)
        if name not in _AUFRUFE or not isinstance(argv, (ast.List, ast.Tuple)) or not argv.elts \
                or not _ist_sys_executable(argv.elts[0]):
            continue
        funktion = n
        while funktion in eltern and not isinstance(funktion, (ast.FunctionDef, ast.AsyncFunctionDef)):
            funktion = eltern[funktion]
        funktion = funktion if isinstance(funktion, (ast.FunctionDef, ast.AsyncFunctionDef)) else None
        sicht = {**namen, **_lokale_namen(funktion)}
        skript, noetig = None, False
        rest = argv.elts[1:]
        while rest and isinstance(rest[0], ast.Constant) and isinstance(rest[0].value, str) \
                and rest[0].value in ("-B", "-I", "-u", "-E", "-s", "-S", "-X"):
            rest = rest[1:]
        if len(rest) >= 2 and isinstance(rest[0], ast.Constant) and rest[0].value == "-m" \
                and isinstance(rest[1], ast.Constant) and str(rest[1].value).split(".")[0] == "proofbundle":
            skript, noetig = "-m " + rest[1].value, True
        elif rest:
            rel = _pfad(rest[0], sicht)
            if rel and rel.endswith(".py"):
                quelle = lies_skript(rel)
                if quelle is not None:
                    skript, noetig = rel, braucht_src(quelle)
        if skript is None:
            continue
        gelesen.append((n.lineno, skript))
        if noetig and not _gibt_pythonpath(n, funktion, namen):
            fehlt.append((n.lineno, skript))
    return fehlt, gelesen


def _lies(rel: str) -> str | None:
    p = REPO / rel
    return p.read_text(encoding="utf-8") if p.is_file() else None


def _alle() -> tuple[list, list]:
    fehlt, gelesen = [], []
    for datei in sorted(TESTS.rglob("*.py")):
        with warnings.catch_warnings():   # an invalid escape in another test file is that file's business
            warnings.simplefilter("ignore", SyntaxWarning)
            warnings.simplefilter("ignore", DeprecationWarning)
            f, g = befunde(datei.read_text(encoding="utf-8"), _lies)
        rel = str(datei.relative_to(REPO))
        fehlt += [(rel, z, s) for z, s in f]
        gelesen += [(rel, z, s) for z, s in g]
    return fehlt, gelesen


class EveryTestSubprocessOfAScriptOfTheTreeGetsItsSrc(unittest.TestCase):

    def test_no_call_starts_a_script_that_needs_src_without_pythonpath(self):
        fehlt, _ = _alle()
        self.assertEqual(fehlt, [], "pass env={**os.environ, 'PYTHONPATH': str(REPO / 'src')} to these calls")

    def test_control_the_guard_reaches_the_four_calls_that_had_the_form(self):
        # Without this, a resolver that resolves nothing would pass the case above.
        _, gelesen = _alle()
        erreicht = {(d, s) for d, _z, s in gelesen}
        for paar in (("tests/test_verdict_contract_example_pins_its_key.py", "examples/verdict_contract/make_example.py"),
                     ("tests/test_verdict_contract_example_pins_its_key.py", "examples/verdict_contract/check_example.py"),
                     ("tests/test_verdict_contract_example_reads_strict_json.py",
                      "examples/verdict_contract/check_example.py"),
                     ("tests/test_verifier_block.py", "conformance/run_conformance.py")):
            with self.subTest(call=paar):
                self.assertIn(paar, erreicht)
        for skript in ("examples/verdict_contract/check_example.py", "conformance/run_conformance.py"):
            with self.subTest(script=skript):
                self.assertTrue(braucht_src(_lies(skript)), f"{skript} no longer needs src: the guard lost its case")

    def test_control_the_guard_finds_each_planted_form(self):
        skripte = {"tools/a.py": "import sys\nfrom proofbundle import cli\n",
                   "tools/b.py": "import sys\nsys.path.insert(0, str(ROOT / 'src'))\nimport proofbundle\n",
                   "tools/c.py": "def main():\n    import proofbundle\n",
                   "tools/d.py": "try:\n    import proofbundle\nexcept ImportError:\n    pass\n"}
        test = ("import os, subprocess, sys\nfrom pathlib import Path\n"
                "REPO = Path(__file__).resolve().parents[1]\nTOOL = REPO / 'tools'\n"
                "def t1():\n    subprocess.run([sys.executable, str(TOOL / 'a.py')])\n"
                "def t2():\n    subprocess.run([sys.executable, '-B', str(REPO / 'tools' / 'a.py')],"
                " env={**os.environ, 'PYTHONPATH': str(REPO / 'src')})\n"
                "def t3():\n    subprocess.run([sys.executable, str(TOOL / 'b.py')])\n"
                "def t4():\n    subprocess.run([sys.executable, str(TOOL / 'c.py')])\n"
                "def t5():\n    subprocess.check_output([sys.executable, '-m', 'proofbundle.cli', 'verify'])\n"
                "def t6():\n    e = dict(os.environ)\n    e['PYTHONPATH'] = 'src'\n"
                "    subprocess.run([sys.executable, str(TOOL / 'd.py')], env=e)\n"
                "def t7():\n    subprocess.run([sys.executable, str(TOOL / 'd.py')], env=dict(os.environ))\n"
                "def t8():\n    r = REPO / 'tools' / 'a.py'\n    subprocess.run([sys.executable, str(r)])\n"
                "ENV = {**os.environ, 'PYTHONPATH': str(REPO / 'src')}\n"
                "def t9():\n    subprocess.run([sys.executable, str(TOOL / 'a.py')], env=ENV)\n")
        fehlt, gelesen = befunde(test, skripte.get)
        self.assertEqual([s for _z, s in fehlt], ["tools/a.py", "-m proofbundle.cli", "tools/d.py", "tools/a.py"])
        self.assertEqual(len(gelesen), 9)


if __name__ == "__main__":
    unittest.main()
