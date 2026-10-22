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
   `reader = open`, and `getattr(x, "read_bytes")` with a literal name. A name that another module of
   the package binds is followed there, so a re-export (`from .other import os`) and a star import
   resolve to what the other module bound. A `getattr`, `setattr`, `delattr` or `hasattr` with a
   computed name is a finding of its own, because the gate cannot say what it reaches. The same holds
   for the methods `__getattribute__`, `__setattr__` and `__delattr__` that every object has, and for
   any of these handed on as a value instead of called. A method whose name is a file method
   (`read_bytes`, `open`, `read`, ...) on a receiver the gate cannot resolve is a file finding: the
   gate cannot prove the receiver is no file.
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
import re
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


def _binds(node: ast.AST) -> list[str]:
    """The names a node binds that are no import: an assignment or deletion, a parameter, a def or a class, an
    exception name, a match capture and a type parameter."""
    if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
        return [node.id]
    if isinstance(node, ast.arg):
        return [node.arg]
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return [node.name]
    if isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) and node.name:
        return [node.name]
    if isinstance(node, ast.MatchMapping) and node.rest:
        return [node.rest]
    name = getattr(node, "name", None) if type(node).__name__ in ("TypeVar", "ParamSpec", "TypeVarTuple") else None
    return [name] if isinstance(name, str) else []


def type_checking_guards(tree: ast.AST) -> tuple[frozenset[str], frozenset[str]]:
    """The names that really are `typing.TYPE_CHECKING` in this module: (bare names, module aliases).

    A bare name counts only when `from typing import TYPE_CHECKING [as X]` binds it and nothing else
    in the module binds it; a module alias counts only when `import typing [as t]` binds it and nothing
    else does. Anything else that merely ends in TYPE_CHECKING is ordinary code and runs. Every binding
    counts, an exception name and a match capture as well (`case typing:` binds the subject), and a star
    import from any module but typing may bind any name, so after one no guard of the module counts.
    """
    names: set[str] = set()
    modules: set[str] = set()
    other: dict[str, int] = {}
    star = False
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module in _TYPING_MODULES:
            for a in node.names:
                if a.name == "TYPE_CHECKING":
                    names.add(a.asname or a.name)
                else:
                    other[a.asname or a.name] = 1
        elif isinstance(node, ast.ImportFrom):
            for a in node.names:
                star = star or a.name == "*"
                other[a.asname or a.name] = 1
        elif isinstance(node, ast.Import):
            for a in node.names:
                bound = a.asname or a.name.split(".")[0]
                if a.name in _TYPING_MODULES and (a.asname or "." not in a.name):
                    modules.add(bound)
                else:
                    other[bound] = 1
        else:
            for bound in _binds(node):
                other[bound] = 1
    if star or type_checking_may_change(tree):
        return frozenset(), frozenset()
    return frozenset(names - set(other)), frozenset(modules - set(other))


#: The methods of a namespace mapping that only read it. A positive list on purpose: the writing methods are
#: many (update, setdefault, `__setitem__`, pop, clear and more), and a list of them would hold only the ones
#: somebody thought of.
_NAMESPACE_READS = frozenset({"get", "keys", "items", "values", "copy", "__contains__", "__getitem__", "__len__",
                              "__iter__"})
#: Methods of a string: a string handed to one is read, whatever it says.
_STRING_READS = frozenset({"startswith", "endswith", "find", "rfind", "index", "rindex", "count", "split", "rsplit",
                           "partition", "rpartition", "strip", "lstrip", "rstrip", "removeprefix", "removesuffix"})
#: Callables, by the name they resolve to, that read what they are handed and keep no reference that can write it.
#: Resolved, not matched by spelling: a module's own `def sorted(m): m[...] = True` is no reader.
_READING_CALLS = frozenset(
    {f"builtins.{n}" for n in ("len", "list", "tuple", "sorted", "set", "frozenset", "dict", "iter", "bool", "repr",
                               "str", "ascii", "print", "isinstance", "id", "type", "hash", "format", "any", "all",
                               "min", "max", "sum", "enumerate", "zip", "reversed", "callable", "dir")}
    | {f"builtins.dict.{m}" for m in _NAMESPACE_READS}
    | {"json.dumps", "pprint.pformat", "pprint.pprint", "copy.copy", "copy.deepcopy", "reprlib.repr",
       "inspect.getmembers", "inspect.ismodule", "inspect.isclass", "types.MappingProxyType"})
#: Builtin types: an object one of them builds is no module.
_BUILTIN_TYPES = frozenset(f"builtins.{n}" for n in (
    "dict", "list", "set", "frozenset", "tuple", "str", "bytes", "bytearray", "int", "float", "complex", "bool",
    "object", "type", "super", "range", "slice", "memoryview"))
#: The functions that read, test, set or delete an attribute by its name, under the name they resolve to.
_ATTRIBUTE_FUNCTIONS = {"builtins.getattr": "get", "builtins.hasattr": "has", "builtins.setattr": "set",
                        "builtins.delattr": "del"}
#: The same as methods every object has: kind, and the number of arguments when the method is bound.
_ATTRIBUTE_METHODS = {"__getattribute__": ("get", 1), "__setattr__": ("set", 2), "__delattr__": ("del", 1)}
_NAMESPACE_FUNCTIONS = ("builtins.vars", "builtins.globals", "builtins.locals")
#: Attributes that hand out the namespace of a module: a function's globals, a frame's globals and locals.
_MODULE_NAMESPACE_ATTRIBUTES = ("__globals__", "f_globals", "f_locals")
#: Every attribute that hands out a namespace; in the core each one is dynamic access as `x.__dict__` is.
_NAMESPACE_ATTRIBUTES = ("__dict__", *_MODULE_NAMESPACE_ATTRIBUTES)
#: Calls whose result is a module chosen by name.
_MODULE_CALLS = ("importlib.import_module", "importlib.__import__", "builtins.__import__", "sys.modules.get",
                 "importlib.reload", "inspect.getmodule", "pkgutil.resolve_name")
#: Methods that write the mapping they are called on.
_MAPPING_WRITES = frozenset({"update", "setdefault", "__setitem__", "__delitem__", "pop", "popitem", "__ior__",
                             "__init__"})
#: The flag by its own name, or as the last part of a dotted name: `"typing.TYPE_CHECKING"`, `"typing:TYPE_CHECKING"`.
_FLAG = re.compile(r"(?:[\w.]*[.:])?TYPE_CHECKING")
#: Callables, by the name they resolve to, that format a string they are handed as text and never take it for the
#: name of something to set (Codex on PR 395, round two, P2). Only for that string: they keep their arguments.
_TEXT_SINKS = frozenset({f"logging.{n}" for n in ("debug", "info", "warning", "error", "critical", "exception", "log")}
                        | {"warnings.warn"})


def _attribute_call(node: ast.Call, quals) -> tuple[str, str, ast.expr | None, ast.expr | None, bool] | None:
    """(kind, label, receiver, name, unknown) of a call that reads, tests, sets or deletes an attribute by name:
    getattr, hasattr, setattr and delattr under any name they are bound to, and `__getattribute__`, `__setattr__`
    and `__delattr__` called on the object (`typing.__setattr__(n, v)`), on a class with the object first
    (`object.__setattr__(typing, n, v)`), through `__call__`, or under a name taken from the object
    (`from typing import __setattr__ as put`, where the receiver is None because the gate holds no expression for
    it). `unknown` says the gate cannot tell which argument is the receiver or the name (a starred argument, another
    number of arguments); None for any other call."""
    f = node.func
    while isinstance(f, ast.Attribute) and f.attr == "__call__":    # `getattr.__call__(x, n)` is the same call
        f = f.value
    starred = any(isinstance(a, ast.Starred) for a in node.args)
    found = quals(f)
    for q in found:
        kind = _ATTRIBUTE_FUNCTIONS.get(q)
        if kind:
            label = q.rpartition(".")[2]
            if starred:
                return kind, label, None, None, True
            return kind, label, (node.args[0] if node.args else None), \
                (node.args[1] if len(node.args) > 1 else None), False
    if isinstance(f, ast.Attribute) and f.attr in _ATTRIBUTE_METHODS:
        kind, bound = _ATTRIBUTE_METHODS[f.attr]
        if not starred and not node.keywords:
            if len(node.args) == bound:
                return kind, f.attr, f.value, node.args[0], False
            if len(node.args) == bound + 1:
                return kind, f.attr, node.args[0], node.args[1], False
        return kind, f.attr, None, None, True
    for q in found:
        method = q.rpartition(".")[2]
        if "." in q and method in _ATTRIBUTE_METHODS:
            kind, bound = _ATTRIBUTE_METHODS[method]
            name = None if starred or node.keywords else node.args[0] if len(node.args) == bound \
                else node.args[1] if len(node.args) == bound + 1 else None
            return kind, method, None, name, name is None
    return None


def _literal(node: ast.AST | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _mapping_value(subject: ast.expr | None, key: ast.expr) -> ast.expr | None:
    """The value the key of a mapping pattern matches in a subject that is a dict written out, looked up as Python
    looks it up: equal keys are one key (`1`, `1.0` and `True`), and the last of them wins. None when the gate cannot
    read it: the subject is no dict display, a key is not a literal, or `**other` may bring the key in."""
    if not isinstance(subject, ast.Dict):
        return None
    try:
        wanted = ast.literal_eval(key)
        found = None
        for k, v in zip(subject.keys, subject.values):
            if k is None:
                return None
            have = ast.literal_eval(k)
            if hash(have) == hash(wanted) and have == wanted:
                found = v
        return found
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
        return None


class _ChangeScan:
    """The forms by which one module may change `typing.TYPE_CHECKING`, as (form, line).

    TYPE_CHECKING lives in a module: in typing, or as a module global where `from typing import TYPE_CHECKING`
    bound it. So a write is a change in two cases. It NAMES the flag where it writes: an attribute TYPE_CHECKING set
    or deleted, the flag as the key of an item set or deleted or as the name of an attribute set, as a key or a
    keyword handed to a method that writes a mapping, or a dotted name that ends in it handed to any call
    (`"typing.TYPE_CHECKING"` for a patch helper). The same string as data writes nothing. Or its name or key is one
    the gate cannot read and the object written MAY BE A MODULE. An object may be a module unless the gate shows it
    is none (`no_module`): the first try was a list of module spellings, and the lens on it reached a module through
    `os.sys.modules`, `inspect.getmodule` and a class attribute. A namespace of such an object, the module's own
    `globals()`, a function's `__globals__`, a frame's `f_globals` and `sys.modules` are judged from the read side:
    every use that is not a read counts, and a namespace bound to a name is judged by every use of that name. A
    setter, a getter or a namespace function handed on as a value, and the typing module itself handed on, count
    too, because the gate does not see where they go.
    """

    def __init__(self, tree: ast.AST, modname: str, is_pkg: bool, package: "_Package | None") -> None:
        self.names = _Names(tree, modname, is_pkg, _NO_GUARDS, package)
        self.parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
        self.tree = tree
        self._shown: dict[int, bool] = {}
        self._loads: dict[tuple[int, str], list[ast.Name]] = {}
        for n in ast.walk(tree):
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load):
                s = self.names.binding_scope_of(n)
                if s is not None:
                    self._loads.setdefault((id(s), n.id), []).append(n)

    def no_module(self, expr: ast.expr | None, _open: set[int] | None = None) -> bool:
        """Whether the object `expr` evaluates to is shown to be no module: a literal or a display, a lambda, an
        object a builtin type or a class of this module builds, the first parameter of a method (`self`, `cls`), a
        def or a class, or a name every binding of which is one of these. Everything else may be a module. A cycle
        of assignments shows nothing; each expression is judged once."""
        if expr is None:
            return False
        key = id(expr)
        if key in self._shown:
            return self._shown[key]
        opened = set() if _open is None else _open
        if key in opened:
            return False
        opened.add(key)
        verdict = self._no_module(expr, opened)
        self._shown[key] = verdict
        return verdict

    def _no_module(self, expr: ast.expr, opened: set[int]) -> bool:
        if isinstance(expr, (ast.Constant, ast.JoinedStr, ast.List, ast.Tuple, ast.Set, ast.Dict, ast.ListComp,
                             ast.SetComp, ast.DictComp, ast.GeneratorExp, ast.Lambda)):
            return True
        if isinstance(expr, ast.Call):
            quals = self.names.quals(expr.func)
            if quals and all(q in _BUILTIN_TYPES for q in quals):
                return True
            if isinstance(expr.func, ast.Name):
                s = self.names.binding_scope_of(expr.func)
                return s is not None and expr.func.id in s.classes and s.stores.get(expr.func.id, 0) == 1 \
                    and expr.func.id not in s.alias
            return False
        if isinstance(expr, ast.Name):
            s = self.names.binding_scope_of(expr)
            if s is None:
                return expr.id in _BUILTIN_NAMES and expr.id != "__builtins__"
            if expr.id in s.alias:
                return False
            stores = s.stores.get(expr.id, 0)
            if s.self_name == expr.id and stores == 0:
                return True
            if expr.id in s.defs and stores == 1:
                return True
            values = [v for n, v in s.assigns if n == expr.id]
            return bool(values) and len(values) == stores and all(self.no_module(v, opened) for v in values)
        return False

    def may_be_module(self, expr: ast.expr | None) -> bool:
        return not self.no_module(expr)

    def is_typing(self, expr: ast.AST) -> bool:
        if isinstance(expr, (ast.Name, ast.Attribute)):
            return any(q in _TYPING_MODULES for q in self.names.quals(expr))
        if isinstance(expr, ast.Subscript):
            return "sys.modules" in self.names.quals(expr.value) and _literal(expr.slice) in _TYPING_MODULES
        if isinstance(expr, ast.Call) and expr.args:
            return any(q in _MODULE_CALLS for q in self.names.quals(expr.func)) \
                and _literal(expr.args[0]) in _TYPING_MODULES
        return False

    def namespace_owner(self, node: ast.AST) -> tuple[bool, ast.expr | None] | None:
        """(own, receiver) when the node hands out a namespace mapping, None otherwise. `own` means the namespace is
        a module's for certain: the module's own, a function's globals, a frame's, or `sys.modules`."""
        if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load):
            if node.attr == "__dict__":
                return False, node.value
            if node.attr in _MODULE_NAMESPACE_ATTRIBUTES:
                return True, None
        if isinstance(node, (ast.Name, ast.Attribute)) and isinstance(node.ctx, ast.Load):
            quals = self.names.quals(node)
            if "sys.modules" in quals or any(
                    "." in q and q.rpartition(".")[2] in ("__dict__", *_MODULE_NAMESPACE_ATTRIBUTES) for q in quals):
                return True, None
        if isinstance(node, ast.Call):
            quals = self.names.quals(node.func)
            if "builtins.vars" in quals:
                return (False, node.args[0]) if node.args else (True, None)
            if "builtins.globals" in quals or "builtins.locals" in quals:
                return True, None
            call = _attribute_call(node, self.names.quals)
            if call is not None and call[0] == "get" and _literal(call[3]) in ("__dict__", *_MODULE_NAMESPACE_ATTRIBUTES):
                return False, call[2]
        return None

    def reads_only(self, node: ast.AST, _seen: set[int] | None = None) -> bool:
        """Whether this use of a namespace mapping, or of a module, can only read it."""
        up = self.parents.get(node)
        if isinstance(up, ast.Subscript) and up.value is node:
            return isinstance(up.ctx, ast.Load)
        if isinstance(up, ast.Attribute) and up.value is node:
            return up.attr in _NAMESPACE_READS
        # An operator builds a new value from its operands (`vars(m) | extra`, `"%s" % vars(m)`), `yield from`
        # hands on the keys, not the mapping.
        if isinstance(up, (ast.Compare, ast.UnaryOp, ast.FormattedValue, ast.Expr, ast.Starred, ast.BinOp,
                           ast.YieldFrom)):
            return True
        if isinstance(up, (ast.If, ast.While, ast.Assert)):
            return up.test is node
        if isinstance(up, ast.IfExp):
            return up.test is node or self.reads_only(up, _seen)
        if isinstance(up, ast.BoolOp):       # `ns or {}` hands the operand on as its value
            return self.reads_only(up, _seen)
        if isinstance(up, ast.comprehension):
            return up.iter is node or any(c is node for c in up.ifs)
        if isinstance(up, (ast.For, ast.AsyncFor)):
            return up.iter is node
        if isinstance(up, ast.Dict):
            return any(k is None and v is node for k, v in zip(up.keys, up.values))
        if isinstance(up, ast.keyword):
            call = self.parents.get(up)
            return up.arg is None or (isinstance(call, ast.Call) and self.calls_a_reader(call))
        if isinstance(up, ast.Call) and up.func is not node:
            return self.calls_a_reader(up)
        if isinstance(up, (ast.Assign, ast.AnnAssign)) and up.value is node:
            targets = up.targets if isinstance(up, ast.Assign) else [up.target]
            if len(targets) == 1 and isinstance(targets[0], ast.Name):
                return self._alias_reads_only(targets[0], _seen)
        return False

    def _alias_reads_only(self, target: ast.Name, _seen: set[int] | None) -> bool:
        """A mapping bound to a name is read only when that is the name's one binding in its scope and every use of
        the name reads it (`eigen = object.__getattribute__(x, "__dict__")` followed by `dict.items(eigen)`)."""
        seen = set() if _seen is None else _seen
        if id(target) in seen:
            return False
        seen.add(id(target))
        s = self.names.binding_scope_of(target)
        if s is None or s.stores.get(target.id, 0) != 1 or target.id in s.alias:
            return False
        return all(self.reads_only(use, seen) for use in self._loads.get((id(s), target.id), []))

    def calls_a_reader(self, call: ast.Call) -> bool:
        f = call.func
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Constant) and isinstance(f.value.value, str):
            return f.attr in _STRING_READS or f.attr in ("join", "format")    # `",".join(...)` of a literal
        quals = self.names.quals(f)
        return bool(quals) and all(q in _READING_CALLS for q in quals)

    def _writes_a_mapping(self, call: ast.AST | None) -> bool:
        """A call of a method that writes the mapping it is called on: `m.update(...)`, `m.setdefault(...)`."""
        return isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute) and call.func.attr in _MAPPING_WRITES

    def writes_the_flag(self, node: ast.Constant) -> bool:
        """Whether a string that names the flag stands where it is written: the key of an item set or deleted, the
        name of an attribute set or deleted, a key handed to a method that writes a mapping (`m.update({...})`), or
        a dotted name handed to any call (`patch("typing.TYPE_CHECKING", True)`). The same string as data, in a
        list, a dict that stays where it is or a call that only reads, writes nothing (Codex on PR 395, P2). A
        mapping that carries it into a module's namespace is judged where that namespace is used. A dotted name handed
        to a callable that resolves to a reader (`print`, `json.dumps`) or to a text sink (`logging.info`,
        `warnings.warn`) is text as well (round two, P2); any other callable, a parameter's method among them
        (`monkeypatch.setattr("typing.TYPE_CHECKING", True)`), may set what it names."""
        up = self.parents.get(node)
        if isinstance(up, ast.Subscript) and up.slice is node:
            return isinstance(up.ctx, (ast.Store, ast.Del))
        if isinstance(up, ast.Call) and any(a is node for a in up.args):
            call = _attribute_call(up, self.names.quals)
            if call is not None and call[0] in ("set", "del"):
                return call[3] is node or call[3] is None
            # A callable that resolves to a reader or a text sink takes a dotted name as text (round two, P2).
            quals = self.names.quals(up.func)
            if self.calls_a_reader(up) or (bool(quals) and all(q in _TEXT_SINKS for q in quals)):
                return False
            return "." in node.value or ":" in node.value or self._writes_a_mapping(up)
        if isinstance(up, ast.Dict) and any(k is node for k in up.keys):
            holder = self.parents.get(up)
            return self._writes_a_mapping(holder)
        if isinstance(up, ast.Tuple):
            pair, holder = self.parents.get(up), None
            if isinstance(pair, (ast.List, ast.Tuple)):
                holder = self.parents.get(pair)
            return self._writes_a_mapping(holder)
        return False

    def setter_reaches_a_module(self, receiver: ast.expr | None) -> bool:
        """A setter or getter bound to an object that may be a module, or one taken from a class that works on any
        object it is handed (`object.__setattr__`, `type(x).__setattr__`)."""
        if receiver is None or self.may_be_module(receiver):
            return True
        if isinstance(receiver, ast.Call):
            return "builtins.type" in self.names.quals(receiver.func)
        return any(q in ("builtins.object", "builtins.type") for q in self.names.quals(receiver))

    def handed_on(self, node: ast.AST, up: ast.AST | None) -> bool:
        """Whether a reference is handed on: not called, not read as an attribute holder, not only read, not re-bound
        as a plain alias (the alias is resolved where it is used)."""
        if isinstance(up, ast.Call) and up.func is node:
            return False
        if isinstance(up, ast.Attribute) and up.value is node:
            return False
        if isinstance(up, ast.Assign) and up.value is node and all(isinstance(t, ast.Name) for t in up.targets):
            return False
        return not self.reads_only(node)

    def changes(self) -> list[tuple[str, int]]:
        out: list[tuple[str, int]] = []
        names = self.names
        for node in ast.walk(self.tree):
            line = getattr(node, "lineno", 0)
            up = self.parents.get(node)
            if isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)):
                if node.attr == "TYPE_CHECKING":
                    out.append(("TYPE_CHECKING set as an attribute", line))
                elif node.attr == "__dict__" and self.may_be_module(node.value):
                    out.append(("the namespace of an object that may be a module replaced", line))
            elif isinstance(node, ast.keyword) and node.arg == "TYPE_CHECKING" and self._writes_a_mapping(up):
                out.append(("TYPE_CHECKING as a keyword of a write", line))
            elif isinstance(node, ast.Constant) and isinstance(node.value, str) and _FLAG.fullmatch(node.value) \
                    and self.writes_the_flag(node):
                out.append(("TYPE_CHECKING named by a write", line))
            owner = self.namespace_owner(node)
            if owner is not None and (owner[0] or self.may_be_module(owner[1])) and not self.reads_only(node) \
                    and not (not owner[0] and self._handed_back(node, up, owner[1])):
                out.append(("a namespace that may be a module's, used other than by reading", line))
            if isinstance(node, ast.Call):
                call = _attribute_call(node, names.quals)
                if call is not None:
                    kind, label, receiver, name, unknown = call
                    attr = _literal(name)
                    if kind in ("set", "del") and attr is None and self.setter_reaches_a_module(receiver):
                        out.append((f"{label} with a name the gate cannot read, on an object that may be a module",
                                    line))
                    elif kind == "get" and attr in ("__setattr__", "__delattr__", "__getattribute__") \
                            and self.setter_reaches_a_module(receiver):
                        out.append((f"getattr of {attr}, on an object that may be a module", line))
                if self.is_typing(node) and self.handed_on(node, up) and not self._judged_elsewhere(node, up):
                    out.append(("the typing module handed on", line))
            elif isinstance(node, (ast.Name, ast.Attribute, ast.Subscript)) and isinstance(node.ctx, ast.Load):
                if isinstance(node, (ast.Name, ast.Attribute)) and self.handed_on(node, up):
                    quals = names.quals(node)
                    if any(q in ("builtins.setattr", "builtins.delattr", "builtins.getattr", *_NAMESPACE_FUNCTIONS)
                           for q in quals):
                        out.append(("an attribute or namespace function handed on as a value", line))
                    elif isinstance(node, ast.Attribute) and node.attr in _ATTRIBUTE_METHODS \
                            and self.setter_reaches_a_module(node.value):
                        out.append((f"{node.attr} of an object that may be a module, handed on as a value", line))
                if isinstance(node, ast.Attribute) and node.attr in _ATTRIBUTE_METHODS \
                        and isinstance(up, ast.Assign) and up.value is node and self.setter_reaches_a_module(node.value):
                    out.append((f"{node.attr} of an object that may be a module, bound to a name", line))
                if self.is_typing(node) and self.handed_on(node, up) and not self._judged_elsewhere(node, up):
                    out.append(("the typing module handed on", line))
        return out

    def _handed_back(self, node: ast.AST, up: ast.AST | None, receiver: ast.expr | None) -> bool:
        """The namespace of a parameter returned or yielded to the caller, `return vars(x)`: the caller handed `x`
        in and could take its namespace itself, so it gains nothing it did not hold. A namespace of any other
        object, a module named by an import among them, is no such case."""
        if not isinstance(up, (ast.Return, ast.Yield, ast.YieldFrom)) or not isinstance(receiver, ast.Name):
            return False
        s = self.names.binding_scope_of(receiver)
        return s is not None and s.kind == "function" and receiver.id in s.local \
            and s.stores.get(receiver.id, 0) == 0 and receiver.id not in s.alias and receiver.id not in s.defs

    def _judged_elsewhere(self, node: ast.AST, up: ast.AST | None) -> bool:
        """The module as the receiver of a namespace function or an attribute function: judged there."""
        if not isinstance(up, ast.Call):
            return False
        if self.namespace_owner(up) is not None:
            return True
        call = _attribute_call(up, self.names.quals)
        return call is not None and call[2] is node


def type_checking_changes(tree: ast.AST, modname: str = "", is_pkg: bool = False,
                          package: "_Package | None" = None) -> list[tuple[str, int]]:
    """Every form by which this module may change `typing.TYPE_CHECKING`, as (form, line); see _ChangeScan."""
    return _ChangeScan(tree, modname, is_pkg, package).changes()


def type_checking_may_change(tree: ast.AST, modname: str = "", is_pkg: bool = False,
                             package: "_Package | None" = None) -> bool:
    """Whether this module can change `typing.TYPE_CHECKING` at run time, so that no guard in it, or in any
    module run after it, is evidence of a body that never runs (CODEX-630-K6, sibling).

    `typing.TYPE_CHECKING = True` before `if typing.TYPE_CHECKING:` made the body run while the gate skipped it
    as a type-checking block. Codex on PR 393 (P1) found the same through a method of the namespace,
    `typing.__dict__.update({...})`. The lens on PR 393 (three P2, 6.3.1) found that the check knew one spelling
    of each operation: `getattr(typing, "__dict__")`, `typing.__setattr__`, `object.__setattr__` and a renamed
    `setattr` made the body run unseen, and a read such as `print(vars(x))` in any module of the package turned
    every guard off. The lens on the first fix found more spellings it did not read, and a check whether an object
    may be a module that was a list of module spellings. The forms are resolved as Python resolves the names, and
    an object counts as a possible module unless it is shown to be none (_ChangeScan). A module whose form is
    reviewed by name in the core list file (`type_checking_reviewed`, see measure) changes no guard.

    What stays out of reach: an attribute read by a computed name from a module, `getattr(module, name)`, which
    may hand out its namespace or its setter (the lazy table of proofbundle/__init__.py reads a module attribute
    this way); a method called through its class with a module as its first argument (`C.f(typing)`, where `self`
    counts as no module); and code the gate does not parse, such as a string run by exec.
    """
    return bool(type_checking_changes(tree, modname, is_pkg, package))


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
    __slots__ = ("kind", "parent", "alias", "local", "globals", "nonlocals", "assigns", "stores", "defs",
                 "classes", "self_name")

    def __init__(self, kind: str, parent: "_Scope | None") -> None:
        self.kind = kind
        self.parent = parent
        self.alias: dict[str, set[str]] = {}
        self.local: set[str] = set()
        self.globals: set[str] = set()
        self.nonlocals: set[str] = set()
        self.assigns: list[tuple[str, ast.expr]] = []
        #: How often each name is bound here by a statement (not as a parameter), and which are a def or a class.
        self.stores: dict[str, int] = {}
        self.defs: set[str] = set()
        self.classes: set[str] = set()
        #: The first parameter of a method defined directly in a class body (`self`, `cls`), None elsewhere.
        self.self_name: str | None = None


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
                 guards: tuple[frozenset[str], frozenset[str]], package: "_Package | None" = None) -> None:
        self._modname, self._is_pkg, self._guards, self._package = modname, is_pkg, guards, package
        self.module = _Scope("module", None)
        self.scope_of: dict[int, _Scope] = {}
        self._scopes: list[_Scope] = [self.module]
        #: The modules a star import of this module reads, absolute: each may bind any name it exports here.
        self.stars: list[str] = []
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
        target = self.module if name in scope.globals else scope
        target.local.add(name)
        target.stores[name] = target.stores.get(name, 0) + 1

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
            (self.module if node.name in scope.globals else scope).defs.add(node.name)
            for d in node.decorator_list:
                self._visit(d, scope)
            for d in (*node.args.defaults, *[k for k in node.args.kw_defaults if k is not None]):
                self._visit(d, scope)
            inner = self._new("function", scope)
            self._args(node.args, inner)
            positional = (*node.args.posonlyargs, *node.args.args)
            static = any(isinstance(d, ast.Name) and d.id == "staticmethod" for d in node.decorator_list)
            if scope.kind == "class" and positional and not static:
                inner.self_name = positional[0].arg
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
            owner = self.module if node.name in scope.globals else scope
            owner.defs.add(node.name)
            owner.classes.add(node.name)
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
                if a.name == "*":
                    # Python allows a star import only at module level; it binds what the module exports.
                    if base:
                        self.stars.append(base)
                else:
                    # `global` sends a from-import to the module scope as it does a plain import
                    bound = a.asname or a.name
                    target = self.module if bound in scope.globals else scope
                    target.alias.setdefault(bound, set()).add(f"{base}.{a.name}" if base else a.name)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            self._bind(scope, node.id)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            self._bind(scope, node.name)
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            self._bind(scope, node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            self._bind(scope, node.rest)
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for tg in targets:
                if isinstance(tg, ast.Name) and node.value is not None:
                    owner = self.module if tg.id in scope.globals else scope
                    owner.assigns.append((tg.id, node.value))
        elif isinstance(node, ast.NamedExpr) and isinstance(node.target, ast.Name):
            owner = self.module if node.target.id in scope.globals else scope
            owner.assigns.append((node.target.id, node.value))
        elif isinstance(node, ast.Match):
            for case in node.cases:
                self._match_binds(case.pattern, node.subject, scope)
        for child in ast.iter_child_nodes(node):
            self._visit(child, scope)

    def _match_binds(self, pattern: ast.AST, value: ast.expr | None, scope: _Scope) -> None:
        """What a match capture binds, as far as the gate can read it (Codex on PR 395, P1). `case name:` and
        `case <pattern> as name:` bind the value matched there, every alternative of `case a | b:` matches the
        same value, an element of `case [a, b]:` is the element at its place when the subject is a list or a
        tuple written out, and the value of `case {"k": a}:` is the value of that key when the subject is a dict
        written out with literal keys (round two, P1). Any other capture binds a value the gate cannot read; the
        generic walk binds its name. That includes a capture in a class pattern, `case C(a):`, which binds an
        attribute of the subject: the gate reads no attribute of an object, as it reads none in `a = C(x).item`."""
        if isinstance(pattern, ast.MatchAs):
            if pattern.name and value is not None:
                owner = self.module if pattern.name in scope.globals else scope
                owner.assigns.append((pattern.name, value))
            if pattern.pattern is not None:
                self._match_binds(pattern.pattern, value, scope)
        elif isinstance(pattern, ast.MatchOr):
            for alternative in pattern.patterns:
                self._match_binds(alternative, value, scope)
        elif isinstance(pattern, ast.MatchSequence):
            fits = isinstance(value, (ast.List, ast.Tuple)) and len(value.elts) == len(pattern.patterns) \
                and not any(isinstance(e, ast.Starred) for e in value.elts) \
                and not any(isinstance(sub, ast.MatchStar) for sub in pattern.patterns)
            for i, sub in enumerate(pattern.patterns):
                self._match_binds(sub, value.elts[i] if fits else None, scope)
        elif isinstance(pattern, ast.MatchMapping):
            # `**rest` binds a new dict, never a module; the generic walk binds its name.
            for key, sub in zip(pattern.keys, pattern.patterns):
                self._match_binds(sub, _mapping_value(value, key), scope)
        else:
            for sub in ast.iter_child_nodes(pattern):
                if isinstance(sub, ast.pattern):
                    self._match_binds(sub, None, scope)

    def _star_bound(self, name: str, guesses: bool = True) -> set[str]:
        """What a star import of this module may bind `name` to: the name in each module it reads, when that module
        exports it (the names of a literal `__all__`, else every name that does not start with an underscore).

        A module of the package is asked whether it binds the name at all. A module outside the package cannot be
        asked, so its name is a GUESS: a guess serves the rules (`from os import *` makes `getenv` the environment
        read it is), but it does not make a receiver resolved (the lens on the class fix, G-2: a guessed qualified
        name on `handle.read()` hid the file finding the unresolved receiver gives)."""
        out = set()
        for src in self.stars:
            exported = self._package.exports(src) if self._package is not None else None
            if not ((name in exported) if exported is not None else not name.startswith("_")):
                continue
            inside = self._package is not None and self._package.knows(src)
            if inside and not self._package.binds(src, name):
                continue
            if inside or guesses:
                out.add(f"{src}.{name}")
        return out

    def _binding_scope(self, name: str, scope: _Scope) -> _Scope | None:
        """The scope whose binding of `name` a use in `scope` meets, the walk of _lookup; None for a builtin."""
        s: _Scope | None = scope
        first = True
        while s is not None:
            if name in s.globals and s is not self.module:
                s, first = self.module, False
                continue
            if name in s.nonlocals:
                s, first = s.parent, False
                continue
            if (first or s.kind != "class") and (name in s.alias or name in s.local):
                return s
            s, first = s.parent, False
        return None

    def _lookup(self, name: str, scope: _Scope, guesses: bool = True) -> set[str]:
        s = self._binding_scope(name, scope)
        # A star import binds at module level when its line runs, so a use that reaches the module scope may meet it.
        star = self._star_bound(name, guesses) if s is None or s is self.module else set()
        if s is not None:
            # A function binds a name for its whole body. A module or a class body looks a
            # name up when the line runs, its own binding first and the builtin after it, and
            # a binding there may never run (under `if`, in `try`, through `global` in a
            # function nobody calls). There a builtin with a rule is not hidden by any binding.
            if s.kind != "function" and _is_ruled_builtin(name):
                return {f"builtins.{name}"} | s.alias.get(name, set()) | star
            return set(s.alias.get(name, ())) | star
        return ({f"builtins.{name}"} if name in _BUILTIN_NAMES else set()) | star

    def _quals(self, node: ast.expr, scope: _Scope, guesses: bool = True) -> set[str]:
        if isinstance(node, ast.Name):
            return self._lookup(node.id, scope, guesses)
        if isinstance(node, ast.Attribute):
            return {f"{base}.{node.attr}" for base in self._quals(node.value, scope, guesses)}
        return set()

    def quals(self, node: ast.expr, guesses: bool = True) -> list[str]:
        """Every qualified name the expression may stand for, sorted; empty when the gate cannot resolve it. A name
        that another module of the package binds is followed there (_Package.expand). Without `guesses`, a name a
        star import from outside the package might bind does not count (see _star_bound)."""
        found = self._quals(node, self.scope_of.get(id(node), self.module), guesses)
        if self._package is not None:
            found = set().union(*(self._package.expand(q) for q in found)) if found else found
        return sorted(found)

    def binding_scope_of(self, node: ast.Name) -> _Scope | None:
        """The scope whose binding this use of a name meets; None for a builtin or an unbound name."""
        return self._binding_scope(node.id, self.scope_of.get(id(node), self.module))

    def assigned_values(self, node: ast.Name) -> list[ast.expr]:
        """The expressions assigned to the name in the scope whose binding this use meets."""
        s = self.binding_scope_of(node)
        return [v for n, v in s.assigns if n == node.id] if s is not None else []

    def module_binding(self, name: str) -> set[str]:
        """What this module binds `name` to at module level, as another module that imports it meets it."""
        return set(self.module.alias.get(name, ())) | self._star_bound(name)

    def binds_at_module(self, name: str, _seen: set[str] | None = None) -> bool:
        """Whether this module binds `name` at module level, itself or through a star import of the package."""
        return name in self.module.alias or name in self.module.local or bool(self._star_bound(name, guesses=False))


class _Package:
    """The module-level bindings of every module of the package, so a name one module imports from another is
    resolved where it was bound: `from .other import os`, `from .other import getenv` where other imported it,
    and a star import (CODEX-630-K6, the binding half of the lens on PR 393)."""

    def __init__(self, mods: dict[str, tuple[Path, bool]], trees: dict[str, ast.Module]) -> None:
        self._mods, self._trees = mods, trees
        self._names: dict[str, _Names | None] = {}
        self._exports: dict[str, frozenset[str] | None] = {}
        self._memo: dict[str, set[str]] = {}
        self._asked: dict[str, bool] = {}

    def _names_of(self, module: str) -> _Names | None:
        if module not in self._names:
            self._names[module] = None
            tree = self._trees.get(module)
            if tree is None:
                try:
                    tree = self._trees[module] = parse(self._mods[module][0])
                except NotMeasurable:
                    tree = None
            if tree is not None:
                self._names[module] = _Names(tree, module, self._mods[module][1], _NO_GUARDS, self)
        return self._names[module]

    def knows(self, module: str) -> bool:
        return module in self._mods

    def binds(self, module: str, name: str) -> bool:
        """Whether a module of the package binds `name` at module level. A star cycle between modules ends at the
        first module asked twice, which then counts as binding the name (the gate cannot say it does not)."""
        key = f"{module}\0{name}"
        if key in self._asked:
            return self._asked[key]
        self._asked[key] = True
        names = self._names_of(module)
        self._asked[key] = names is None or names.binds_at_module(name)
        return self._asked[key]

    def exports(self, module: str) -> frozenset[str] | None:
        """The names of a literal `__all__` that the module binds once and never changes; None otherwise."""
        if module not in self._exports:
            self._exports[module] = None
            tree = self._trees.get(module)
            if tree is None and module in self._mods:
                try:
                    tree = self._trees[module] = parse(self._mods[module][0])
                except NotMeasurable:
                    tree = None
            if tree is not None:
                writes = [n for n in ast.walk(tree) if isinstance(n, ast.Name) and n.id == "__all__"
                          and not isinstance(n.ctx, ast.Load)]
                uses = [n for n in ast.walk(tree) if isinstance(n, ast.Name) and n.id == "__all__"]
                assign = [s for s in tree.body if isinstance(s, ast.Assign)
                          and any(isinstance(t, ast.Name) and t.id == "__all__" for t in s.targets)]
                if len(writes) == 1 and len(uses) == 1 and len(assign) == 1 \
                        and isinstance(assign[0].value, (ast.List, ast.Tuple)) \
                        and all(_literal(e) is not None for e in assign[0].value.elts):
                    self._exports[module] = frozenset(_literal(e) for e in assign[0].value.elts)
        return self._exports[module]

    def expand(self, qual: str, _seen: set[str] | None = None) -> set[str]:
        """The qualified name and every name it stands for where a module of the package binds its first part."""
        if _seen is None and qual in self._memo:
            return self._memo[qual]
        seen = set() if _seen is None else _seen
        out = {qual}
        if qual not in seen and len(seen) < 4096:
            seen.add(qual)
            parts = qual.split(".")
            for i in range(len(parts) - 1, 0, -1):
                module = ".".join(parts[:i])
                if module in self._mods:
                    names = self._names_of(module)
                    for bound in (names.module_binding(parts[i]) if names is not None else ()):
                        out |= self.expand(".".join([bound, *parts[i + 1:]]), seen)
                    break
        if _seen is None:
            self._memo[qual] = out
        return out


# ── findings ───────────────────────────────────────────────────────────────────────────────────
def findings_of(tree: ast.AST, modname: str, is_pkg: bool,
                guards: tuple[frozenset[str], frozenset[str]] | None = None,
                package: _Package | None = None) -> list[tuple[str, str, int]]:
    """(rule, operation, line) for one core module."""
    if guards is None:
        guards = type_checking_guards(tree)
    names = _Names(tree, modname, is_pkg, guards, package)
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
            # Every spelling of an attribute function: getattr and its kin under any name they are bound to, and
            # `__getattribute__`, `__setattr__`, `__delattr__` on the object or on a class (the lens on PR 393).
            call = _attribute_call(node, names.quals)
            if call is not None:
                kind, label, receiver, name_arg, unknown = call
                attr = _literal(name_arg)
                if attr is not None:
                    targets = names.quals(receiver) if receiver is not None else []
                    # A receiver counts as resolved only by a binding the gate knows, not by a guess from a star
                    # import of a module outside the package (the lens on the class fix, G-2).
                    known = names.quals(receiver, guesses=False) if receiver is not None else []
                    ruled = [(rule, f"{t}.{attr}") for t in targets if (rule := _rule_of_name(f"{t}.{attr}"))]
                    if ruled:
                        out.extend((rule, full, line) for rule, full in ruled)
                    elif attr in _NAMESPACE_ATTRIBUTES and kind != "has":
                        out.append(("dynamic_access", f".{attr}", line))
                    elif not known and attr in _FILE_METHODS:
                        out.append(("file", f".{attr}", line))
                    elif not known and attr in _ENVIRONMENT_METHODS:
                        out.append(("environment", f".{attr}", line))
                elif name_arg is not None or unknown:
                    out.append(("dynamic_access", f"{label}(computed name)", line))
            for q in names.quals(node.func):
                if q in _CLOCK_WITHOUT_ARGUMENT and len(node.args) <= _CLOCK_WITHOUT_ARGUMENT[q] \
                        and not node.keywords:
                    out.append(("clock", f"{q}()", line))
        elif isinstance(node, ast.Attribute) and node.attr in _NAMESPACE_ATTRIBUTES \
                and isinstance(node.ctx, (ast.Store, ast.Del)):
            out.append(("dynamic_access", f".{node.attr}", line))
        elif isinstance(node, (ast.Name, ast.Attribute)) and isinstance(node.ctx, ast.Load):
            up = parent.get(id(node))
            if isinstance(up, ast.Attribute) and up.value is node:
                # Only the longest chain is judged, once. A namespace in the middle of it is dynamic access of its
                # own: `x.__dict__.get(...)` reaches the mapping as `x.__dict__[...]` does.
                if isinstance(node, ast.Attribute) and node.attr in _NAMESPACE_ATTRIBUTES:
                    out.append(("dynamic_access", f".{node.attr}", line))
                continue
            if isinstance(node, ast.Name) and node.id == "__builtins__":
                out.append(("dynamic_access", "__builtins__", line))
                continue
            quals = names.quals(node)
            ruled = [(rule, q) for q in quals if (rule := _rule_of_name(q))]
            if ruled:
                out.extend((rule, q, line) for rule, q in ruled)
                continue
            # An attribute function handed on as a value: the gate does not see the call it ends up in.
            called = isinstance(up, ast.Call) and up.func is node
            handed = [q.rpartition(".")[2] for q in quals if q in _ATTRIBUTE_FUNCTIONS]
            if not called and (handed or (isinstance(node, ast.Attribute) and node.attr in _ATTRIBUTE_METHODS)):
                out.append(("dynamic_access", f"{handed[0] if handed else node.attr}(as a value)", line))
                continue
            if isinstance(node, ast.Attribute):
                if node.attr in _NAMESPACE_ATTRIBUTES:
                    out.append(("dynamic_access", f".{node.attr}", line))
                elif node.attr in _FILE_METHODS and not names.quals(node.value, guesses=False):
                    out.append(("file", f".{node.attr}", line))
                elif node.attr in _ENVIRONMENT_METHODS and not names.quals(node.value, guesses=False):
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


_RECURSION_LIMIT = 6000


def _reviewed_changes(spec: dict, modules_file: Path) -> dict[tuple[str, str], tuple[int, str]]:
    """The reviewed changes of the guard: (module, form) -> (count, reason).

    The gate cannot show of every object that it is no module, so a write with a computed name into an object it
    cannot place counts as a possible change of TYPE_CHECKING, and one such module turns every guard off. A reviewer
    who has read the write and knows its object is no module names it here, bound to its module, its form and the
    number of times the form occurs, with the reason. One more occurrence, one fewer, or a form that is gone, is
    red until the entry is edited, as the exceptions file works. An entry without a reason is not measurable."""
    entries = spec.get("type_checking_reviewed", [])
    if not isinstance(entries, list):
        raise NotMeasurable(f"{modules_file}: type_checking_reviewed must be a list")
    out: dict[tuple[str, str], tuple[int, str]] = {}
    for e in entries:
        ok = isinstance(e, dict) and all(isinstance(e.get(k), str) and e[k].strip() for k in ("module", "form", "reason"))
        n = e.get("count") if isinstance(e, dict) else None
        if not ok or not (isinstance(n, int) and not isinstance(n, bool) and n >= 1):
            raise NotMeasurable(f"{modules_file}: every reviewed guard change needs module, form, a count of at "
                                f"least 1 and a reason")
        key = (e["module"], e["form"])
        if key in out:
            raise NotMeasurable(f"{modules_file}: reviewed guard change named twice: {key}")
        out[key] = (n, e["reason"])
    return out


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
    reviewed = _reviewed_changes(spec, modules_file)
    # The reading of names recurses with the nesting of the source; a module nested deeper than the gate can
    # read is not measurable, never a crash and never a pass (the lens on the class fix, G-3).
    sys.setrecursionlimit(max(sys.getrecursionlimit(), _RECURSION_LIMIT))
    changes: dict[str, list[list]] = {}
    changers: list[str] = []
    approved: list[dict] = []
    seen_reviews: dict[tuple[str, str], int] = {}
    for m in sorted(mods):
        try:
            trees.setdefault(m, parse(mods[m][0]))
        except NotMeasurable:
            continue
    whole = _Package(mods, trees)
    for m in sorted(trees):
        try:
            found = type_checking_changes(trees[m], m, mods[m][1], whole)
        except RecursionError as exc:
            raise NotMeasurable(f"{mods[m][0]}: nested deeper than the gate reads") from exc
        if not found:
            continue
        changes[m] = [[form, line] for form, line in found[:10]]
        per_form: dict[str, list[int]] = {}
        for form, line in found:
            per_form.setdefault(form, []).append(line)
        unreviewed = False
        for form, lines in sorted(per_form.items()):
            seen_reviews[(m, form)] = len(lines)
            if (m, form) in reviewed and reviewed[(m, form)][0] == len(lines):
                approved.append({"module": m, "form": form, "count": len(lines), "lines": lines[:10]})
            else:
                unreviewed = True
        if unreviewed:
            changers.append(m)
    stale_reviews = [{"module": m, "form": f, "count": n, "found": seen_reviews.get((m, f), 0)}
                     for (m, f), (n, _) in sorted(reviewed.items()) if seen_reviews.get((m, f), 0) != n]
    guards = _NO_GUARDS if changers else None
    reached, edges = closure(sorted(roots), mods, package, trees, guards)
    listed = spec.get("modules")
    if not isinstance(listed, list) or not all(isinstance(m, str) for m in listed):
        raise NotMeasurable(f"{modules_file}: modules must be a list of module names")
    core = set(listed)
    raw: dict[tuple[str, str, str], list[int]] = {}
    for m in sorted(reached):
        try:
            for rule, op, line in findings_of(trees[m], m, mods[m][1], guards, whole):
                raw.setdefault((rule, m, op), []).append(line)
        except RecursionError as exc:
            raise NotMeasurable(f"{mods[m][0]}: nested deeper than the gate reads") from exc
        for rule, op, line in external_and_edges(edges.get(m, {}), core, package, boundaries):
            raw.setdefault((rule, m, op), []).append(line)
    return {
        "package": package,
        "roots": dict(sorted(roots.items())),
        "closure": {m: sorted(r) for m, r in sorted(reached.items())},
        "listed": sorted(core),
        "trust_boundaries": dict(sorted(boundaries.items())),
        "type_checking_changed_by": changers,
        "type_checking_changes": changes,
        "type_checking_reviewed": approved,
        "type_checking_reviewed_stale": stale_reviews,
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
    stale_reviews = measured.get("type_checking_reviewed_stale", [])
    green = not (new or stale or grown or shrunk or core_new or core_stale or stale_reviews)
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
        "stale_reviewed_changes": stale_reviews,
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
        for r in report["stale_reviewed_changes"]:
            print(f"  STALE reviewed guard change ({r['count']} reviewed, {r['found']} found): {r['module']} · "
                  f"{r['form']}")
    return 0 if report["verdict"] == "GREEN" else 1


if __name__ == "__main__":
    sys.exit(main())
