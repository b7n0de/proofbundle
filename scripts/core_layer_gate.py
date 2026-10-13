#!/usr/bin/env python3
# BETRIEBSART: ci · .github/workflows/ci.yml runs it in the job core-layer-gate on every push and pull request
"""Core layer gate, step S1 of the verification core split: measure the boundary, block regressions.

WHAT IT MEASURES, at the tree it runs in:

1. THE CORE LIST. The static import closure of the two verification paths named in
   scripts/core_layer_modules.json (today proofbundle.bundle for verify_bundle and proofbundle.decision
   for verify_decision_receipt). Every import statement counts, at any depth of a function, except the
   ones under `if TYPE_CHECKING:`, and those only while no module of the package can change
   `typing.TYPE_CHECKING`. A reached module brings its package initialisation with it, because
   Python runs `__init__.py` before the submodule. The lazy package map of proofbundle/__init__.py is
   not followed: it loads through `importlib` on attribute access, and that access is itself reported
   as a dynamic import of the package initialisation. The computed closure must EQUAL the fixed list.
   A new member is red (a core module gained an edge to a module outside the core), and so is a member
   that is no longer reached (the list only shrinks by an edit someone reviews).

2. FORBIDDEN OPERATIONS IN THE CORE: file access, network, clock, environment, subprocess, randomness,
   eval and exec, dynamic import, and dynamic access that cannot be resolved statically. Every name is
   resolved in its own lexical scope, as Python resolves it, and alias forms are resolved before the
   check: `import os as o`, `from os import getenv as g`, `import builtins`,
   `reader = open`, and `getattr(x, "read_bytes")` with a literal name. A `getattr`, `setattr`,
   `delattr` or `hasattr` with a computed name is a finding of its own, because the gate cannot say
   what it reaches. A method whose name is a file method (`read_bytes`, `open`, `read`, ...) on a
   receiver the gate cannot resolve is a file finding: the gate cannot prove the receiver is no file.
   The same holds for the path methods that read the working or the home directory (`resolve`,
   `absolute`, `expanduser`): on such a receiver they are an environment finding.

3. IMPORT EDGES. Every module a core module imports is on the core list, in the standard library, or a
   named trust boundary, an external distribution listed with a reason in the core list file. A
   forbidden standard-library module (socket, subprocess, importlib, random, tempfile, ...) is a
   finding of its rule even when nothing from it is used.

4. EXCEPTIONS. Each finding is bound to its rule, its module, its operation and the number of times
   it occurs there. The findings must equal the approved baseline in scripts/core_layer_exceptions.json.
   A finding outside the baseline is red even when another entry disappeared in the same change, one
   more occurrence of an approved operation is red, and an entry that occurs less often or no longer is
   red too: the baseline only shrinks by an edit someone reviews. The JSON output carries the number of
   entries and of occurrences per rule, the figures S2 measures its progress against.

WHAT IT IS NOT: a sandbox. A static check sees the agreed boundaries and the forms it resolves. Native
code, callbacks handed in from outside, and anything executed through data stay outside it. A missing
finding is not proof of purity.

Exit codes: 0 green, 1 red, 2 not measurable (an input could not be read or parsed).
"""
from __future__ import annotations

import argparse
import ast
import builtins
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULES_FILE = ROOT / "scripts" / "core_layer_modules.json"
EXCEPTIONS_FILE = ROOT / "scripts" / "core_layer_exceptions.json"
SCHEMA_REPORT = "proofbundle.core_layer_gate.v1"

RULES = ("file", "network", "clock", "environment", "subprocess", "randomness", "eval_exec",
         "dynamic_import", "dynamic_access", "import_edge", "external_dependency")

# Qualified names, matched exactly or as a dotted prefix (`shutil` covers `shutil.copy`).
_FORBIDDEN_NAMES: dict[str, tuple[str, ...]] = {
    "file": (
        "builtins.open", "io.open", "io.open_code", "io.FileIO", "os.open", "os.fdopen", "os.stat",
        "os.lstat", "os.fstat", "os.listdir", "os.scandir", "os.walk", "os.remove", "os.unlink",
        "os.rename", "os.renames", "os.replace", "os.makedirs", "os.mkdir", "os.rmdir",
        "os.removedirs", "os.read", "os.write", "os.truncate", "os.chmod", "os.chown", "os.link",
        "os.symlink", "os.readlink", "os.access", "os.mkfifo", "os.path.exists", "os.path.lexists",
        "os.path.isfile", "os.path.isdir", "os.path.islink", "os.path.ismount", "os.path.getsize",
        "os.path.getmtime", "os.path.getatime", "os.path.getctime", "os.path.realpath",
        "os.path.samefile", "shutil", "tempfile", "glob", "fileinput", "mmap"),
    "network": (
        "socket", "ssl", "http", "urllib.request", "urllib.error", "urllib3", "requests", "httpx",
        "aiohttp", "ftplib", "smtplib", "poplib", "imaplib", "telnetlib", "xmlrpc", "webbrowser"),
    "clock": (
        "time.time", "time.time_ns", "time.monotonic", "time.monotonic_ns", "time.perf_counter",
        "time.perf_counter_ns", "time.process_time", "time.process_time_ns", "time.thread_time",
        "time.thread_time_ns", "time.clock_gettime", "time.clock_gettime_ns",
        "datetime.datetime.now", "datetime.datetime.utcnow", "datetime.datetime.today",
        "datetime.date.today"),
    # The working directory and the home directory are environment too, read IMPLICITLY as well:
    # `abspath` and `relpath` of a relative path and `Path.resolve`/`Path.absolute` read the working
    # directory, `chdir` changes it, `expanduser` reads HOME (Codex thread 4244048849 on pull request 337).
    "environment": (
        "os.environ", "os.environb", "os.getenv", "os.getenvb", "os.putenv", "os.unsetenv",
        "os.getcwd", "os.getcwdb", "os.getlogin", "os.uname", "os.getpid", "os.path.expanduser",
        "os.path.expandvars", "sys.argv", "pathlib.Path.home", "pathlib.Path.cwd", "platform",
        "os.path.abspath", "os.path.relpath", "os.chdir", "os.fchdir", "pathlib.Path.absolute",
        "pathlib.Path.resolve", "pathlib.Path.expanduser"),
    "subprocess": (
        "subprocess", "multiprocessing", "pty", "os.system", "os.popen", "os.fork", "os.forkpty",
        "os.posix_spawn", "os.posix_spawnp", "os.kill", "os.killpg"),
    "randomness": ("random", "secrets", "os.urandom", "os.getrandom", "uuid.uuid1", "uuid.uuid4"),
    "eval_exec": ("builtins.eval", "builtins.exec", "builtins.compile", "builtins.breakpoint"),
    "dynamic_import": ("builtins.__import__", "importlib", "runpy", "pkgutil", "zipimport"),
    "dynamic_access": ("builtins.globals", "builtins.locals", "builtins.vars", "sys.modules"),
}
# `os.exec*` and `os.spawn*` are families, matched by the start of the attribute name.
_FORBIDDEN_FAMILIES = (("subprocess", "os.exec"), ("subprocess", "os.spawn"))
# These read the clock only when called without a time argument.
_CLOCK_WITHOUT_ARGUMENT = {"time.gmtime": 0, "time.localtime": 0, "time.ctime": 0,
                           "time.asctime": 0, "time.strftime": 1}
# Standard-library modules whose mere import is a finding of their rule.
_FORBIDDEN_MODULES = {
    "network": ("socket", "ssl", "http", "urllib.request", "urllib.error", "xmlrpc", "ftplib",
                "smtplib", "poplib", "imaplib", "telnetlib", "webbrowser"),
    "subprocess": ("subprocess", "multiprocessing", "pty"),
    "dynamic_import": ("importlib", "runpy", "pkgutil", "zipimport"),
    "randomness": ("random", "secrets"),
    "file": ("tempfile", "shutil", "glob", "fileinput", "mmap"),
    "environment": ("platform",),
}
# Method names that read or write files when the receiver is a path or a file object. On a receiver
# the gate cannot resolve, the name alone is a finding: absence of proof is not proof of absence.
_FILE_METHODS = frozenset((
    "read_bytes", "read_text", "write_bytes", "write_text", "open", "stat", "lstat", "iterdir",
    "glob", "rglob", "mkdir", "touch", "unlink", "rmdir", "exists", "is_file", "is_dir",
    "is_symlink", "read", "readline", "readlines", "readinto", "write", "writelines", "samefile",
    "chmod", "symlink_to", "hardlink_to"))
# Path methods that read the working directory or the home directory, judged the same way on a receiver
# the gate cannot resolve: `Path("x").resolve()` names no qualified receiver.
_ENVIRONMENT_METHODS = frozenset(("absolute", "resolve", "expanduser"))
_DYNAMIC_ATTRIBUTE_CALLS = ("builtins.getattr", "builtins.setattr", "builtins.delattr",
                            "builtins.hasattr")
_BUILTIN_NAMES = frozenset(dir(builtins))


def _is_ruled_builtin(name: str) -> bool:
    return name in _BUILTIN_NAMES and _rule_of_name(f"builtins.{name}") is not None


class NotMeasurable(Exception):
    """An input the verdict depends on could not be read or parsed."""


def _matches(qual: str, pattern: str) -> bool:
    return qual == pattern or qual.startswith(pattern + ".")


#: One function under the module names it really has: os.path IS posixpath on POSIX and ntpath on Windows, and
#: genericpath holds the functions both share. The concrete Path classes inherit every method of pathlib.Path.
#: A rule written for one spelling binds every spelling only if the name is made canonical first (Codex thread
#: 4245077735 on pull request 339: `PosixPath.resolve(p)` passed while `Path.resolve(p)` was found, and the same
#: held for the file methods and for `posixpath.abspath` and `ntpath.exists`).
_PATH_MODULE_ALIASES = ("posixpath", "ntpath", "genericpath")
_CONCRETE_PATH_CLASSES = ("pathlib.PosixPath", "pathlib.WindowsPath")


def _canonical(qual: str) -> str:
    top, dot, rest = qual.partition(".")
    if dot and top in _PATH_MODULE_ALIASES:
        return f"os.path.{rest}"
    for cls in _CONCRETE_PATH_CLASSES:
        if qual == cls or qual.startswith(cls + "."):
            return "pathlib.Path" + qual[len(cls):]
    return qual


def _rule_of_name(qual: str) -> str | None:
    qual = _canonical(qual)
    for rule, patterns in _FORBIDDEN_NAMES.items():
        if any(_matches(qual, p) for p in patterns):
            return rule
    head, _, attr = qual.rpartition(".")
    if head == "pathlib.Path" and attr in _FILE_METHODS:
        return "file"
    for rule, prefix in _FORBIDDEN_FAMILIES:
        head, _, attr = prefix.rpartition(".")
        q_head, _, q_attr = qual.rpartition(".")
        if q_head == head and q_attr.startswith(attr):
            return rule
    return None


def _rule_of_module(name: str) -> str | None:
    for rule, modules in _FORBIDDEN_MODULES.items():
        if any(_matches(name, m) for m in modules):
            return rule
    return None


# ── the package ────────────────────────────────────────────────────────────────────────────────
def discover(src: Path, package: str) -> dict[str, tuple[Path, bool]]:
    """Every module of the package: dotted name -> (file, is_package)."""
    base = src / package
    if not base.is_dir():
        raise NotMeasurable(f"package directory {base} not found")
    out: dict[str, tuple[Path, bool]] = {}
    for path in sorted(base.rglob("*.py")):
        rel = path.relative_to(src).with_suffix("")
        parts = list(rel.parts)
        is_pkg = parts[-1] == "__init__"
        if is_pkg:
            parts = parts[:-1]
        out[".".join(parts)] = (path, is_pkg)
    return out


def parse(path: Path) -> ast.Module:
    try:
        return ast.parse(path.read_bytes(), filename=str(path))
    except (OSError, SyntaxError, ValueError) as exc:
        raise NotMeasurable(f"{path}: {exc}") from exc


_TYPING_MODULES = ("typing", "typing_extensions")


def type_checking_guards(tree: ast.AST) -> tuple[frozenset[str], frozenset[str]]:
    """The names that really are `typing.TYPE_CHECKING` in this module: (bare names, module aliases).

    A bare name counts only when `from typing import TYPE_CHECKING [as X]` binds it and nothing else
    in the module binds it; a module alias counts only when `import typing [as t]` binds it and nothing
    else does. Anything else that merely ends in TYPE_CHECKING is ordinary code and runs.
    """
    names: set[str] = set()
    modules: set[str] = set()
    other: dict[str, int] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module in _TYPING_MODULES:
            for a in node.names:
                if a.name == "TYPE_CHECKING":
                    names.add(a.asname or a.name)
                else:
                    other[a.asname or a.name] = 1
        elif isinstance(node, ast.ImportFrom):
            for a in node.names:
                other[a.asname or a.name] = 1
        elif isinstance(node, ast.Import):
            for a in node.names:
                bound = a.asname or a.name.split(".")[0]
                if a.name in _TYPING_MODULES and (a.asname or "." not in a.name):
                    modules.add(bound)
                else:
                    other[bound] = 1
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            other[node.id] = 1
        elif isinstance(node, ast.arg):
            other[node.arg] = 1
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            other[node.name] = 1
    if type_checking_may_change(tree):
        return frozenset(), frozenset()
    return frozenset(names - set(other)), frozenset(modules - set(other))


_ATTRIBUTE_WRITERS = ("setattr", "delattr")


def type_checking_may_change(tree: ast.AST) -> bool:
    """Whether this module can change `typing.TYPE_CHECKING` at run time, so that no guard in it, or in any
    module run after it, is evidence of a body that never runs (CODEX-630-K6, sibling).

    `typing.TYPE_CHECKING = True` before `if typing.TYPE_CHECKING:` made the body run while the gate skipped it
    as a type-checking block. Changes the gate sees: an assignment or deletion of any attribute named
    TYPE_CHECKING, a `setattr` or `delattr` whose name is TYPE_CHECKING or not a literal, and a write through a
    module's `__dict__` or `vars()`.
    """
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)) \
                and node.attr in ("TYPE_CHECKING", "__dict__"):
            return True
        if isinstance(node, ast.Subscript) and isinstance(node.ctx, (ast.Store, ast.Del)):
            holder = node.value
            if isinstance(holder, ast.Attribute) and holder.attr == "__dict__":
                return True
            if isinstance(holder, ast.Call) and isinstance(holder.func, ast.Name) and holder.func.id == "vars":
                return True
        if isinstance(node, ast.Call):
            f = node.func
            name = f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else None
            if name in _ATTRIBUTE_WRITERS:
                arg = node.args[1] if len(node.args) >= 2 else None
                if not (isinstance(arg, ast.Constant) and isinstance(arg.value, str)) \
                        or arg.value == "TYPE_CHECKING":
                    return True
    return False


_NO_GUARDS: tuple[frozenset[str], frozenset[str]] = (frozenset(), frozenset())


def _is_type_checking(test: ast.expr, guards: tuple[frozenset[str], frozenset[str]]) -> bool:
    names, modules = guards
    if isinstance(test, ast.Name):
        return test.id in names
    return (isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"
            and isinstance(test.value, ast.Name) and test.value.id in modules)


def runtime_nodes(tree: ast.AST, guards: tuple[frozenset[str], frozenset[str]] | None = None):
    """Every node that can run, skipping the bodies of `if TYPE_CHECKING:` for the real one only."""
    if guards is None:
        guards = type_checking_guards(tree)
    stack = [tree]
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, ast.If) and _is_type_checking(node.test, guards):
            stack.extend(reversed(node.orelse))
            continue
        stack.extend(reversed(list(ast.iter_child_nodes(node))))


def _package_of(modname: str, is_pkg: bool) -> str:
    return modname if is_pkg else modname.rpartition(".")[0]


def _absolute(modname: str, is_pkg: bool, level: int, module: str | None) -> str:
    if level == 0:
        return module or ""
    parts = _package_of(modname, is_pkg).split(".")
    parts = parts[: len(parts) - (level - 1)] if level > 1 else parts
    return ".".join(parts + ([module] if module else []))


def imports_of(tree: ast.AST, modname: str, is_pkg: bool, known: set[str],
               guards: tuple[frozenset[str], frozenset[str]] | None = None) -> list[tuple[str, int]]:
    """(imported module, line) for every runtime import; parents of a dotted name come along."""
    found: list[tuple[str, int]] = []

    def add(name: str, line: int) -> None:
        parts = name.split(".")
        for i in range(1, len(parts) + 1):
            found.append((".".join(parts[:i]), line))

    for node in runtime_nodes(tree, guards):
        if isinstance(node, ast.Import):
            for alias in node.names:
                add(alias.name, node.lineno)
        elif isinstance(node, ast.ImportFrom):
            base = _absolute(modname, is_pkg, node.level, node.module)
            if base:
                add(base, node.lineno)
            for alias in node.names:
                cand = f"{base}.{alias.name}" if base else alias.name
                if cand in known:
                    add(cand, node.lineno)
    return found


def closure(roots: list[str], mods: dict[str, tuple[Path, bool]], package: str,
            trees: dict[str, ast.Module], guards: tuple[frozenset[str], frozenset[str]] | None = None,
            ) -> tuple[dict[str, set[str]], dict[str, dict[str, list[int]]]]:
    """The static closure: member -> roots reaching it, and per member its imports with lines."""
    reached: dict[str, set[str]] = {}
    edges: dict[str, dict[str, list[int]]] = {}
    known = set(mods)
    for root in roots:
        if root not in mods:
            raise NotMeasurable(f"root module {root} is not part of the package")
        queue = [root]
        seen: set[str] = set()
        while queue:
            m = queue.pop()
            if m in seen:
                continue
            seen.add(m)
            reached.setdefault(m, set()).add(root)
            # Python runs every parent package's __init__ before the module itself.
            parts = m.split(".")
            for i in range(1, len(parts)):
                parent = ".".join(parts[:i])
                if parent in mods and parent not in seen:
                    queue.append(parent)
            if m not in trees:
                trees[m] = parse(mods[m][0])
            imp = imports_of(trees[m], m, mods[m][1], known, guards)
            per = edges.setdefault(m, {})
            for target, line in imp:
                per.setdefault(target, []).append(line)
                if (target == package or target.startswith(package + ".")) and target in mods:
                    queue.append(target)
    return reached, edges


# ── names and their resolution ─────────────────────────────────────────────────────────────────
class _Scope:
    __slots__ = ("kind", "parent", "alias", "local", "globals", "nonlocals", "assigns")

    def __init__(self, kind: str, parent: "_Scope | None") -> None:
        self.kind = kind
        self.parent = parent
        self.alias: dict[str, set[str]] = {}
        self.local: set[str] = set()
        self.globals: set[str] = set()
        self.nonlocals: set[str] = set()
        self.assigns: list[tuple[str, ast.expr]] = []


_FUNCTION_LIKE = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
_COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)


class _Names:
    """What each name stands for, resolved in its own lexical scope, as Python resolves it.

    An import or a simple re-binding (`reader = open`) makes an alias in its scope; every other binding
    (a parameter, a loop or `with` target, an assignment the gate cannot resolve, a def or a class)
    shadows the name in that scope only. A scope keeps EVERY alias it makes for a name, not the last one:
    `import os; VALUE = os.getenv("X"); import math as os` read the environment before the re-binding,
    and the gate resolved the earlier use against the later alias (CODEX-630-K6). A use is judged
    against each binding it may meet. A function does not see the scope of the class it is defined
    in; `global` sends a name to the module scope. Where a scope binds a name both ways, the alias wins,
    so an ambiguity is a finding rather than a silence. In a module or a class body no binding hides a
    builtin that a rule names, because there the builtin is used whenever the binding has not run.
    """

    def __init__(self, tree: ast.AST, modname: str, is_pkg: bool,
                 guards: tuple[frozenset[str], frozenset[str]]) -> None:
        self._modname, self._is_pkg, self._guards = modname, is_pkg, guards
        self.module = _Scope("module", None)
        self.scope_of: dict[int, _Scope] = {}
        self._scopes: list[_Scope] = [self.module]
        self._visit(tree, self.module)
        for _ in range(8):
            changed = False
            for s in self._scopes:
                for name, value in s.assigns:
                    new = self._quals(value, s) - s.alias.get(name, set())
                    if new:
                        s.alias.setdefault(name, set()).update(new)
                        changed = True
            if not changed:
                break

    def _new(self, kind: str, parent: _Scope) -> _Scope:
        s = _Scope(kind, parent)
        self._scopes.append(s)
        return s

    def _bind(self, scope: _Scope, name: str) -> None:
        (self.module if name in scope.globals else scope).local.add(name)

    def _args(self, args: ast.arguments, scope: _Scope) -> None:
        for a in (*args.posonlyargs, *args.args, *args.kwonlyargs,
                  *([args.vararg] if args.vararg else []), *([args.kwarg] if args.kwarg else [])):
            self.scope_of[id(a)] = scope
            scope.local.add(a.arg)

    def _visit(self, node: ast.AST, scope: _Scope) -> None:
        self.scope_of[id(node)] = scope
        if isinstance(node, ast.If) and _is_type_checking(node.test, self._guards):
            for child in node.orelse:
                self._visit(child, scope)
            return
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self._bind(scope, node.name)
            for d in node.decorator_list:
                self._visit(d, scope)
            for d in (*node.args.defaults, *[k for k in node.args.kw_defaults if k is not None]):
                self._visit(d, scope)
            inner = self._new("function", scope)
            self._args(node.args, inner)
            for stmt in node.body:
                self._visit(stmt, inner)
            return
        if isinstance(node, ast.Lambda):
            for d in (*node.args.defaults, *[k for k in node.args.kw_defaults if k is not None]):
                self._visit(d, scope)
            inner = self._new("function", scope)
            self._args(node.args, inner)
            self._visit(node.body, inner)
            return
        if isinstance(node, ast.ClassDef):
            self._bind(scope, node.name)
            for d in (*node.decorator_list, *node.bases, *[k.value for k in node.keywords]):
                self._visit(d, scope)
            inner = self._new("class", scope)
            for stmt in node.body:
                self._visit(stmt, inner)
            return
        if isinstance(node, _COMPREHENSIONS):
            inner = self._new("function", scope)
            for i, gen in enumerate(node.generators):
                self._visit(gen.iter, scope if i == 0 else inner)
                self._visit(gen.target, inner)
                for cond in gen.ifs:
                    self._visit(cond, inner)
            for part in ((node.key, node.value) if isinstance(node, ast.DictComp) else (node.elt,)):
                self._visit(part, inner)
            return
        if isinstance(node, ast.Global):
            scope.globals.update(node.names)
        elif isinstance(node, ast.Nonlocal):
            scope.nonlocals.update(node.names)
        elif isinstance(node, ast.Import):
            for a in node.names:
                target = self.module if (a.asname or a.name.split(".")[0]) in scope.globals else scope
                if a.asname:
                    target.alias.setdefault(a.asname, set()).add(a.name)
                else:
                    top = a.name.split(".")[0]
                    target.alias.setdefault(top, set()).add(top)
        elif isinstance(node, ast.ImportFrom):
            base = _absolute(self._modname, self._is_pkg, node.level, node.module)
            for a in node.names:
                if a.name != "*":
                    # `global` sends a from-import to the module scope as it does a plain import
                    bound = a.asname or a.name
                    target = self.module if bound in scope.globals else scope
                    target.alias.setdefault(bound, set()).add(f"{base}.{a.name}" if base else a.name)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            self._bind(scope, node.id)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            self._bind(scope, node.name)
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for tg in targets:
                if isinstance(tg, ast.Name) and node.value is not None:
                    owner = self.module if tg.id in scope.globals else scope
                    owner.assigns.append((tg.id, node.value))
        for child in ast.iter_child_nodes(node):
            self._visit(child, scope)

    def _lookup(self, name: str, scope: _Scope) -> set[str]:
        s: _Scope | None = scope
        first = True
        while s is not None:
            if name in s.globals and s is not self.module:
                s, first = self.module, False
                continue
            if name in s.nonlocals:
                s, first = s.parent, False
                continue
            # A class scope is seen only by code directly in its body, never by a function in it.
            if first or s.kind != "class":
                if name in s.alias or name in s.local:
                    # A function binds a name for its whole body. A module or a class body looks a
                    # name up when the line runs, its own binding first and the builtin after it, and
                    # a binding there may never run (under `if`, in `try`, through `global` in a
                    # function nobody calls). There a builtin with a rule is not hidden by any binding.
                    if s.kind != "function" and _is_ruled_builtin(name):
                        return {f"builtins.{name}"} | s.alias.get(name, set())
                    return set(s.alias.get(name, ()))
            s, first = s.parent, False
        return {f"builtins.{name}"} if name in _BUILTIN_NAMES else set()

    def _quals(self, node: ast.expr, scope: _Scope) -> set[str]:
        if isinstance(node, ast.Name):
            return self._lookup(node.id, scope)
        if isinstance(node, ast.Attribute):
            return {f"{base}.{node.attr}" for base in self._quals(node.value, scope)}
        return set()

    def quals(self, node: ast.expr) -> list[str]:
        """Every qualified name the expression may stand for, sorted; empty when the gate cannot resolve it."""
        return sorted(self._quals(node, self.scope_of.get(id(node), self.module)))


# ── findings ───────────────────────────────────────────────────────────────────────────────────
def findings_of(tree: ast.AST, modname: str, is_pkg: bool,
                guards: tuple[frozenset[str], frozenset[str]] | None = None) -> list[tuple[str, str, int]]:
    """(rule, operation, line) for one core module."""
    if guards is None:
        guards = type_checking_guards(tree)
    names = _Names(tree, modname, is_pkg, guards)
    out: list[tuple[str, str, int]] = []
    parent: dict[int, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parent[id(child)] = node

    for node in runtime_nodes(tree, guards):
        line = getattr(node, "lineno", 0)
        if isinstance(node, ast.Import):
            for a in node.names:
                rule = _rule_of_module(a.name)
                if rule:
                    out.append((rule, f"import {a.name}", line))
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            rule = _rule_of_module(node.module)
            if rule:
                out.append((rule, f"import {node.module}", line))
            for a in node.names:
                rule = _rule_of_name(f"{node.module}.{a.name}")
                if rule and not _rule_of_module(node.module):
                    out.append((rule, f"{node.module}.{a.name}", line))
        elif isinstance(node, ast.Call):
            for q in names.quals(node.func):
                if q in _DYNAMIC_ATTRIBUTE_CALLS and len(node.args) >= 2:
                    name_arg = node.args[1]
                    if isinstance(name_arg, ast.Constant) and isinstance(name_arg.value, str):
                        targets = names.quals(node.args[0])
                        attr = name_arg.value
                        ruled = [(rule, f"{t}.{attr}") for t in targets if (rule := _rule_of_name(f"{t}.{attr}"))]
                        if ruled:
                            out.extend((rule, full, line) for rule, full in ruled)
                        elif not targets and attr in _FILE_METHODS:
                            out.append(("file", f".{attr}", line))
                        elif not targets and attr in _ENVIRONMENT_METHODS:
                            out.append(("environment", f".{attr}", line))
                    else:
                        out.append(("dynamic_access", f"{q.split('.')[-1]}(computed name)", line))
                if q in _CLOCK_WITHOUT_ARGUMENT and len(node.args) <= _CLOCK_WITHOUT_ARGUMENT[q] \
                        and not node.keywords:
                    out.append(("clock", f"{q}()", line))
        elif isinstance(node, (ast.Name, ast.Attribute)) and isinstance(node.ctx, ast.Load):
            up = parent.get(id(node))
            if isinstance(up, ast.Attribute) and up.value is node:
                continue        # only the longest chain is judged, once
            if isinstance(node, ast.Name) and node.id == "__builtins__":
                out.append(("dynamic_access", "__builtins__", line))
                continue
            ruled = [(rule, q) for q in names.quals(node) if (rule := _rule_of_name(q))]
            if ruled:
                out.extend((rule, q, line) for rule, q in ruled)
                continue
            if isinstance(node, ast.Attribute):
                if node.attr == "__dict__":
                    out.append(("dynamic_access", ".__dict__", line))
                elif node.attr in _FILE_METHODS and not names.quals(node.value):
                    out.append(("file", f".{node.attr}", line))
                elif node.attr in _ENVIRONMENT_METHODS and not names.quals(node.value):
                    out.append(("environment", f".{node.attr}", line))
    return out


def external_and_edges(edges: dict[str, list[int]], core: set[str], package: str,
                       boundaries: dict[str, str]) -> list[tuple[str, str, int]]:
    """Import-edge and external-dependency findings for one core module."""
    out: list[tuple[str, str, int]] = []
    stdlib = set(sys.stdlib_module_names) | {"__future__"}
    for target, lines in sorted(edges.items()):
        top = target.split(".")[0]
        if top == package:
            if target not in core:
                out.append(("import_edge", f"import {target}", min(lines)))
        elif top not in stdlib and top not in boundaries:
            out.append(("external_dependency", f"import {top}", min(lines)))
    return out


# ── the verdict ────────────────────────────────────────────────────────────────────────────────
def _read_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_bytes())
    except (OSError, ValueError) as exc:
        raise NotMeasurable(f"{path}: {exc}") from exc
    if not isinstance(data, dict):
        raise NotMeasurable(f"{path}: not a JSON object")
    return data


def measure(root: Path, modules_file: Path) -> dict:
    """Closure and findings at `root`, without comparing them to anything."""
    spec = _read_json(modules_file)
    package = spec.get("package")
    roots = spec.get("roots")
    boundaries = spec.get("trust_boundaries") or {}
    if not isinstance(package, str) or not isinstance(roots, dict) or not roots \
            or not isinstance(boundaries, dict):
        raise NotMeasurable(f"{modules_file}: needs package, roots and trust_boundaries")
    # A trust boundary widens what the core may import, so it is named WITH its reason: a null, an
    # empty string or any other value is no reason and does not count as a boundary.
    unexplained = sorted(k for k, v in boundaries.items() if not (isinstance(v, str) and v.strip()))
    if unexplained:
        raise NotMeasurable(f"{modules_file}: trust boundaries without a reason: {unexplained}")
    mods = discover(root / "src", package)
    trees: dict[str, ast.Module] = {}
    # typing is one module for the whole process: a module of the package that changes TYPE_CHECKING
    # changes it for every core module run after it, so then no guard anywhere skips a body (CODEX-630-K6).
    # A module that does not parse cannot run and changes nothing.
    changers = []
    for m in sorted(mods):
        try:
            trees.setdefault(m, parse(mods[m][0]))
        except NotMeasurable:
            continue
        if type_checking_may_change(trees[m]):
            changers.append(m)
    guards = _NO_GUARDS if changers else None
    reached, edges = closure(sorted(roots), mods, package, trees, guards)
    listed = spec.get("modules")
    if not isinstance(listed, list) or not all(isinstance(m, str) for m in listed):
        raise NotMeasurable(f"{modules_file}: modules must be a list of module names")
    core = set(listed)
    raw: dict[tuple[str, str, str], list[int]] = {}
    for m in sorted(reached):
        for rule, op, line in findings_of(trees[m], m, mods[m][1], guards):
            raw.setdefault((rule, m, op), []).append(line)
        for rule, op, line in external_and_edges(edges.get(m, {}), core, package, boundaries):
            raw.setdefault((rule, m, op), []).append(line)
    return {
        "package": package,
        "roots": dict(sorted(roots.items())),
        "closure": {m: sorted(r) for m, r in sorted(reached.items())},
        "listed": sorted(core),
        "trust_boundaries": dict(sorted(boundaries.items())),
        "type_checking_changed_by": changers,
        "findings": [{"rule": r, "module": m, "operation": op, "count": len(ls),
                      "lines": sorted(set(ls))[:10]}
                     for (r, m, op), ls in sorted(raw.items())],
    }


def judge(measured: dict, exceptions_file: Path) -> dict:
    data = _read_json(exceptions_file)
    entries = data.get("entries")
    if not isinstance(entries, list):
        raise NotMeasurable(f"{exceptions_file}: entries must be a list")
    # THE UNIT IS THE OCCURRENCE, NOT THE OPERATION. An entry binds rule, module and operation AND the
    # number of times the operation occurs there; a second call of an approved operation in the same
    # module is a new finding, and one call fewer is a baseline that has to shrink by a reviewed edit.
    baseline: dict[tuple[str, str, str], int] = {}
    for e in entries:
        if not (isinstance(e, dict) and all(isinstance(e.get(k), str) for k in
                                            ("rule", "module", "operation"))):
            raise NotMeasurable(f"{exceptions_file}: every entry needs rule, module, operation")
        if e["rule"] not in RULES:
            raise NotMeasurable(f"{exceptions_file}: unknown rule {e['rule']!r}")
        n = e.get("count")
        if not (isinstance(n, int) and not isinstance(n, bool) and n >= 1):
            raise NotMeasurable(f"{exceptions_file}: entry {e['module']} {e['operation']} needs a "
                                f"count of at least 1")
        key = (e["rule"], e["module"], e["operation"])
        if key in baseline:
            raise NotMeasurable(f"{exceptions_file}: duplicate entry {key}")
        baseline[key] = n
    found = {(f["rule"], f["module"], f["operation"]): f["count"] for f in measured["findings"]}
    closure_set = set(measured["closure"])
    listed = set(measured["listed"])
    new = sorted(set(found) - set(baseline))
    stale = sorted(set(baseline) - set(found))
    grown = sorted(k for k in set(found) & set(baseline) if found[k] > baseline[k])
    shrunk = sorted(k for k in set(found) & set(baseline) if found[k] < baseline[k])
    core_new = sorted(closure_set - listed)
    core_stale = sorted(listed - closure_set)
    by_rule = {r: 0 for r in RULES}
    occurrences_by_rule = {r: 0 for r in RULES}
    for (r, _, _), n in baseline.items():
        by_rule[r] += 1
        occurrences_by_rule[r] += n
    found_by_rule = {r: 0 for r in RULES}
    for r, _, _ in found:
        found_by_rule[r] += 1
    green = not (new or stale or grown or shrunk or core_new or core_stale)
    return {
        "schema": SCHEMA_REPORT,
        "verdict": "GREEN" if green else "RED",
        "core_modules": len(closure_set),
        "core_by_root": {root: sum(1 for r in measured["closure"].values() if root in r)
                         for root in measured["roots"]},
        "exceptions_by_rule": by_rule,
        "exceptions_total": len(baseline),
        "occurrences_by_rule": occurrences_by_rule,
        "findings_by_rule": found_by_rule,
        "findings_total": len(found),
        "new_findings": [dict(zip(("rule", "module", "operation"), k)) for k in new],
        "stale_exceptions": [dict(zip(("rule", "module", "operation"), k)) for k in stale],
        "grown_findings": [{"rule": k[0], "module": k[1], "operation": k[2], "baseline": baseline[k],
                            "found": found[k]} for k in grown],
        "shrunk_exceptions": [{"rule": k[0], "module": k[1], "operation": k[2],
                               "baseline": baseline[k], "found": found[k]} for k in shrunk],
        "core_list_new": core_new,
        "core_list_stale": core_stale,
        "measured": measured,
    }


def write_baseline(root: Path, modules_file: Path, exceptions_file: Path) -> dict:
    """Rewrite both files from this tree, in that order: first the core list, then, measured against
    the new list, the exceptions. Reasons already written are kept. Returns the final measurement."""
    measured = measure(root, modules_file)
    spec = _read_json(modules_file)
    spec["modules"] = sorted(measured["closure"])
    modules_file.write_text(json.dumps(spec, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    measured = measure(root, modules_file)
    old = _read_json(exceptions_file) if exceptions_file.exists() else {}
    reasons = {(e["rule"], e["module"], e["operation"]): e["reason"]
               for e in old.get("entries", []) if isinstance(e, dict) and e.get("reason")}
    entries = []
    for f in measured["findings"]:
        key = (f["rule"], f["module"], f["operation"])
        entry = {"rule": key[0], "module": key[1], "operation": key[2], "count": f["count"]}
        if key in reasons:
            entry["reason"] = reasons[key]
        entries.append(entry)
    out = {k: v for k, v in old.items() if k != "entries"}
    out["entries"] = entries
    exceptions_file.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n",
                               encoding="utf-8")
    return measured


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, default=ROOT)
    ap.add_argument("--modules-file", type=Path, default=None)
    ap.add_argument("--exceptions-file", type=Path, default=None)
    ap.add_argument("--json", action="store_true", help="print the full report as JSON")
    ap.add_argument("--write-baseline", action="store_true",
                    help="rewrite the core list and the exceptions from this tree (reviewed edit)")
    a = ap.parse_args(argv)
    modules_file = a.modules_file or a.root / "scripts" / "core_layer_modules.json"
    exceptions_file = a.exceptions_file or a.root / "scripts" / "core_layer_exceptions.json"
    try:
        if a.write_baseline:
            measured = write_baseline(a.root, modules_file, exceptions_file)
        else:
            measured = measure(a.root, modules_file)
        report = judge(measured, exceptions_file)
    except NotMeasurable as exc:
        print(f"core-layer-gate: NOT MEASURABLE: {exc}", file=sys.stderr)
        if a.json:
            print(json.dumps({"schema": SCHEMA_REPORT, "verdict": "NOT_MEASURABLE",
                              "reason": str(exc)}, indent=2))
        return 2
    if a.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print(f"core-layer-gate: {report['verdict']} · {report['core_modules']} core modules "
              f"{report['core_by_root']} · {report['exceptions_total']} exceptions "
              f"{ {r: n for r, n in report['exceptions_by_rule'].items() if n} }")
        for f in report["new_findings"]:
            print(f"  NEW finding, not in the baseline: {f['rule']} · {f['module']} · {f['operation']}")
        for f in report["stale_exceptions"]:
            print(f"  STALE exception, no longer found (remove it): {f['rule']} · {f['module']} · "
                  f"{f['operation']}")
        for f in report["grown_findings"]:
            print(f"  MORE occurrences than the baseline ({f['baseline']} -> {f['found']}): "
                  f"{f['rule']} · {f['module']} · {f['operation']}")
        for f in report["shrunk_exceptions"]:
            print(f"  FEWER occurrences than the baseline ({f['baseline']} -> {f['found']}, lower the "
                  f"count): {f['rule']} · {f['module']} · {f['operation']}")
        for m in report["core_list_new"]:
            print(f"  NEW core member, the closure gained an edge: {m}")
        for m in report["core_list_stale"]:
            print(f"  STALE core member, no longer reached (remove it): {m}")
    return 0 if report["verdict"] == "GREEN" else 1


if __name__ == "__main__":
    sys.exit(main())
