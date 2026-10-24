"""N405-a, Z405 signer service part 2: no name is bound twice at module level of the plugin's code.

Found by Cowork at cbdbfdc8: the pilot bound `_GH_NUMBER` a second time (its number rule, no leading zero, at most ten
digits) below the read grammar of class b, which binds it as `[0-9]+`. `_GH_READ_ARGS` had already taken the first
object, so the read forms kept their rule, but the name itself was the pilot's for every reader at call time: a later
function or a test reading `_GH_NUMBER` met the other rule, silently. `INTOTO_STATEMENT_TYPE` and `INTOTO_PAYLOAD_TYPE`
were bound twice in the same way, with the same values. The pilot's rule has its own name now, `_PILOT_GH_NUMBER`.

The class is a second binding of one module-level name; the test reads every Python file of the plugin with ast and
collects what each statement outside a function or class binds (assignment, annotated assignment, def, class, import),
the bodies of top-level if, try, for, while and with included; `import a.b` and `import a.c` bind the one package `a`
and count once. A `global` in a function rebinds a module-level name at
call time: none is allowed either. RED at 5840e5aa, the head of Nachtrag 21, for proofbundle_gate.py; green after.
"""
from __future__ import annotations

import ast
import collections
import pathlib
import re

import pytest

import test_plugin_fetch_github_profile as f

ROOT = pathlib.Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "plugins" / "proofbundle"
FILES = sorted(p for p in PLUGIN.rglob("*.py") if "__pycache__" not in p.parts)
gate = f.gate
SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)


def _targets(node: ast.AST):
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Store):
            yield sub.id


def module_bindings(tree: ast.Module) -> dict[str, list[int]]:
    """Each name bound at module level, with the lines of its bindings."""
    bound: dict[str, list[int]] = collections.defaultdict(list)
    packages: set[str] = set()

    def visit(statements):
        for node in statements:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                bound[node.name].append(node.lineno)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    if isinstance(node, ast.Import) and alias.asname is None and "." in alias.name:
                        # `import urllib.error` and `import urllib.request` bind urllib to the one package object:
                        # that counts as one binding, the first
                        package = alias.name.split(".")[0]
                        if package in packages:
                            continue
                        packages.add(package)
                        bound[package].append(node.lineno)
                    else:
                        bound[alias.asname or alias.name.split(".")[0]].append(node.lineno)
            elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                for target in node.targets if isinstance(node, ast.Assign) else [node.target]:
                    for name in _targets(target):
                        bound[name].append(node.lineno)
            elif isinstance(node, (ast.If, ast.For, ast.While, ast.With, ast.Try)):
                if isinstance(node, ast.For):
                    for name in _targets(node.target):
                        bound[name].append(node.lineno)
                if isinstance(node, ast.With):
                    for item in node.items:
                        if item.optional_vars is not None:
                            for name in _targets(item.optional_vars):
                                bound[name].append(node.lineno)
                for field in ("body", "orelse", "finalbody"):
                    visit(getattr(node, field, []))
                for handler in getattr(node, "handlers", []):
                    if handler.name:
                        bound[handler.name].append(handler.lineno)
                    visit(handler.body)
            # a walrus at module level binds as well
            if not isinstance(node, SCOPES):
                for sub in ast.walk(node):
                    if isinstance(sub, ast.NamedExpr):
                        bound[sub.target.id].append(sub.lineno)

    visit(tree.body)
    return bound


def test_the_plugin_has_python_files_to_read():
    names = {p.relative_to(PLUGIN).as_posix() for p in FILES}
    assert {"hooks/proofbundle_gate.py", "server/proofbundle_mcp.py", "pilot/signer_service.py"} <= names, names


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.relative_to(PLUGIN).as_posix())
def test_no_name_is_bound_twice_at_module_level(path):
    twice = {name: lines for name, lines in module_bindings(ast.parse(path.read_text(encoding="utf-8"))).items()
             if len(lines) > 1}
    assert twice == {}, twice


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.relative_to(PLUGIN).as_posix())
def test_no_function_rebinds_a_module_level_name(path):
    found = [(node.lineno, node.names) for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
             if isinstance(node, ast.Global)]
    assert found == [], found


def test_the_scan_finds_a_second_binding():
    """Control: the scan sees the shape N405-a had, a name assigned, used, and assigned again further down."""
    tree = ast.parse("import re\nN = re.compile('[0-9]+')\nT = {'a': N}\ndef f():\n    return N\n"
                     "if True:\n    N = re.compile('[1-9]')\n")
    assert module_bindings(tree)["N"] == [2, 7]
    assert module_bindings(ast.parse("import urllib.error\nimport urllib.request\n"))["urllib"] == [1]
    assert module_bindings(ast.parse("import urllib.error\nurllib = None\n"))["urllib"] == [1, 2]


def test_gh_number_keeps_the_rule_of_the_read_forms():
    assert gate._GH_NUMBER.pattern == "[0-9]+"
    for form in (("pr", "view"), ("pr", "checks"), ("pr", "diff"), ("run", "view"), ("issue", "view")):
        assert gate._GH_READ_ARGS[form] is gate._GH_NUMBER, form
    assert gate._GH_NUMBER.fullmatch("007") and gate._GH_NUMBER.fullmatch("12345678901")


def test_the_pilot_reads_its_number_with_its_own_rule():
    rule = gate._PILOT_GH_NUMBER
    assert rule is not gate._GH_NUMBER and rule.flags & re.ASCII
    assert rule.fullmatch("1") and rule.fullmatch("1234567890")
    assert not rule.fullmatch("007") and not rule.fullmatch("12345678901") and not rule.fullmatch("0")
