#!/usr/bin/env python3
# BETRIEBSART: ci · .github/workflows/ci.yml runs it in the job core-layer-gate on every push and pull request
"""Core layer gate, step S1 of the verification core split: measure the boundary, block regressions.

WHAT IT MEASURES, at the tree it runs in:

1. THE CORE LIST. The static import closure of the two verification paths named in
   scripts/core_layer_modules.json (today proofbundle.bundle for verify_bundle and proofbundle.decision
   for verify_decision_receipt). Every import statement counts, at any depth of a function, except the
   ones under `if TYPE_CHECKING:`. A reached module brings its package initialisation with it, because
   Python runs `__init__.py` before the submodule. The lazy package map of proofbundle/__init__.py is
   not followed: it loads through `importlib` on attribute access, and that access is itself reported
   as a dynamic import of the package initialisation. The computed closure must EQUAL the fixed list.
   A new member is red (a core module gained an edge to a module outside the core), and so is a member
   that is no longer reached (the list only shrinks by an edit someone reviews).

2. FORBIDDEN OPERATIONS IN THE CORE: file access, network, clock, environment, subprocess, randomness,
   eval and exec, dynamic import, and dynamic access that cannot be resolved statically. Alias forms
   are resolved before the check: `import os as o`, `from os import getenv as g`, `import builtins`,
   `reader = open`, and `getattr(x, "read_bytes")` with a literal name. A `getattr`, `setattr`,
   `delattr` or `hasattr` with a computed name is a finding of its own, because the gate cannot say
   what it reaches. A method whose name is a file method (`read_bytes`, `open`, `read`, ...) on a
   receiver the gate cannot resolve is a file finding: the gate cannot prove the receiver is no file.

3. IMPORT EDGES. Every module a core module imports is on the core list, in the standard library, or a
   named trust boundary, an external distribution listed with a reason in the core list file. A
   forbidden standard-library module (socket, subprocess, importlib, random, tempfile, ...) is a
   finding of its rule even when nothing from it is used.

4. EXCEPTIONS. Each finding is bound to its rule, its module and its operation. The set of findings
   must equal the approved baseline in scripts/core_layer_exceptions.json. A finding outside the
   baseline is red even when another entry disappeared in the same change, and a baseline entry that no
   longer occurs is red too: the baseline only shrinks by an edit someone reviews. The JSON output
   carries the number of entries per rule, which is the figure S2 measures its progress against.

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
    "environment": (
        "os.environ", "os.environb", "os.getenv", "os.getenvb", "os.putenv", "os.unsetenv",
        "os.getcwd", "os.getcwdb", "os.getlogin", "os.uname", "os.getpid", "os.path.expanduser",
        "os.path.expandvars", "sys.argv", "pathlib.Path.home", "pathlib.Path.cwd", "platform"),
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
_DYNAMIC_ATTRIBUTE_CALLS = ("builtins.getattr", "builtins.setattr", "builtins.delattr",
                            "builtins.hasattr")
_BUILTIN_NAMES = frozenset(dir(builtins))


class NotMeasurable(Exception):
    """An input the verdict depends on could not be read or parsed."""


def _matches(qual: str, pattern: str) -> bool:
    return qual == pattern or qual.startswith(pattern + ".")


def _rule_of_name(qual: str) -> str | None:
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


def _is_type_checking(test: ast.expr) -> bool:
    return ((isinstance(test, ast.Name) and test.id == "TYPE_CHECKING")
            or (isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"))


def runtime_nodes(tree: ast.AST):
    """Every node that can run, skipping the bodies of `if TYPE_CHECKING:`."""
    stack = [tree]
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, ast.If) and _is_type_checking(node.test):
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


def imports_of(tree: ast.AST, modname: str, is_pkg: bool, known: set[str]) -> list[tuple[str, int]]:
    """(imported module, line) for every runtime import; parents of a dotted name come along."""
    found: list[tuple[str, int]] = []

    def add(name: str, line: int) -> None:
        parts = name.split(".")
        for i in range(1, len(parts) + 1):
            found.append((".".join(parts[:i]), line))

    for node in runtime_nodes(tree):
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
            trees: dict[str, ast.Module]) -> tuple[dict[str, set[str]], dict[str, dict[str, list[int]]]]:
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
            imp = imports_of(trees[m], m, mods[m][1], known)
            per = edges.setdefault(m, {})
            for target, line in imp:
                per.setdefault(target, []).append(line)
                if (target == package or target.startswith(package + ".")) and target in mods:
                    queue.append(target)
    return reached, edges


# ── names and their resolution ─────────────────────────────────────────────────────────────────
class _Names:
    """What each local name of one module stands for, after imports and simple re-binding."""

    def __init__(self, tree: ast.AST, modname: str, is_pkg: bool) -> None:
        self.alias: dict[str, str] = {}
        self.local: set[str] = set()
        assigns: list[tuple[str, ast.expr]] = []
        stored: set[str] = set()
        for node in runtime_nodes(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.asname:
                        self.alias[a.asname] = a.name
                    else:
                        top = a.name.split(".")[0]
                        self.alias[top] = top
            elif isinstance(node, ast.ImportFrom):
                base = _absolute(modname, is_pkg, node.level, node.module)
                for a in node.names:
                    if a.name == "*":
                        continue
                    self.alias[a.asname or a.name] = f"{base}.{a.name}" if base else a.name
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                self.local.add(node.name)
            elif isinstance(node, ast.arg):
                self.local.add(node.arg)
            elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
                stored.add(node.id)
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for t in targets:
                    if isinstance(t, ast.Name) and node.value is not None:
                        assigns.append((t.id, node.value))
        # Re-binding to a fixpoint: `reader = open` makes `reader` stand for builtins.open.
        for _ in range(8):
            changed = False
            for name, value in assigns:
                q = self.qual(value)
                if q and self.alias.get(name) != q:
                    self.alias[name] = q
                    changed = True
            if not changed:
                break
        # Every other binding shadows a builtin of the same name: a loop variable, a `with` target,
        # an unpacked tuple, an assignment the gate could not resolve.
        self.local |= {n for n in stored if n not in self.alias}

    def qual(self, node: ast.expr) -> str | None:
        if isinstance(node, ast.Name):
            if node.id in self.alias:
                return self.alias[node.id]
            if node.id in _BUILTIN_NAMES and node.id not in self.local:
                return f"builtins.{node.id}"
            return None
        if isinstance(node, ast.Attribute):
            base = self.qual(node.value)
            return f"{base}.{node.attr}" if base else None
        return None


# ── findings ───────────────────────────────────────────────────────────────────────────────────
def findings_of(tree: ast.AST, modname: str, is_pkg: bool) -> list[tuple[str, str, int]]:
    """(rule, operation, line) for one core module."""
    names = _Names(tree, modname, is_pkg)
    out: list[tuple[str, str, int]] = []
    parent: dict[int, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parent[id(child)] = node

    for node in runtime_nodes(tree):
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
            q = names.qual(node.func)
            if q in _DYNAMIC_ATTRIBUTE_CALLS and len(node.args) >= 2:
                name_arg = node.args[1]
                if isinstance(name_arg, ast.Constant) and isinstance(name_arg.value, str):
                    target = names.qual(node.args[0])
                    attr = name_arg.value
                    full = f"{target}.{attr}" if target else None
                    rule = _rule_of_name(full) if full else None
                    if rule:
                        out.append((rule, full or attr, line))
                    elif target is None and attr in _FILE_METHODS:
                        out.append(("file", f".{attr}", line))
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
            q = names.qual(node)
            if q:
                rule = _rule_of_name(q)
                if rule:
                    out.append((rule, q, line))
                    continue
            if isinstance(node, ast.Attribute):
                if node.attr == "__dict__":
                    out.append(("dynamic_access", ".__dict__", line))
                elif node.attr in _FILE_METHODS and names.qual(node.value) is None:
                    out.append(("file", f".{node.attr}", line))
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
    mods = discover(root / "src", package)
    trees: dict[str, ast.Module] = {}
    reached, edges = closure(sorted(roots), mods, package, trees)
    listed = spec.get("modules")
    if not isinstance(listed, list) or not all(isinstance(m, str) for m in listed):
        raise NotMeasurable(f"{modules_file}: modules must be a list of module names")
    core = set(listed)
    raw: dict[tuple[str, str, str], list[int]] = {}
    for m in sorted(reached):
        for rule, op, line in findings_of(trees[m], m, mods[m][1]):
            raw.setdefault((rule, m, op), []).append(line)
        for rule, op, line in external_and_edges(edges.get(m, {}), core, package, boundaries):
            raw.setdefault((rule, m, op), []).append(line)
    return {
        "package": package,
        "roots": dict(sorted(roots.items())),
        "closure": {m: sorted(r) for m, r in sorted(reached.items())},
        "listed": sorted(core),
        "trust_boundaries": dict(sorted(boundaries.items())),
        "findings": [{"rule": r, "module": m, "operation": op, "count": len(ls),
                      "lines": sorted(set(ls))[:10]}
                     for (r, m, op), ls in sorted(raw.items())],
    }


def judge(measured: dict, exceptions_file: Path) -> dict:
    data = _read_json(exceptions_file)
    entries = data.get("entries")
    if not isinstance(entries, list):
        raise NotMeasurable(f"{exceptions_file}: entries must be a list")
    baseline: set[tuple[str, str, str]] = set()
    for e in entries:
        if not (isinstance(e, dict) and all(isinstance(e.get(k), str) for k in
                                            ("rule", "module", "operation"))):
            raise NotMeasurable(f"{exceptions_file}: every entry needs rule, module, operation")
        if e["rule"] not in RULES:
            raise NotMeasurable(f"{exceptions_file}: unknown rule {e['rule']!r}")
        key = (e["rule"], e["module"], e["operation"])
        if key in baseline:
            raise NotMeasurable(f"{exceptions_file}: duplicate entry {key}")
        baseline.add(key)
    found = {(f["rule"], f["module"], f["operation"]) for f in measured["findings"]}
    closure_set = set(measured["closure"])
    listed = set(measured["listed"])
    new = sorted(found - baseline)
    stale = sorted(baseline - found)
    core_new = sorted(closure_set - listed)
    core_stale = sorted(listed - closure_set)
    by_rule = {r: 0 for r in RULES}
    for r, _, _ in baseline:
        by_rule[r] += 1
    found_by_rule = {r: 0 for r in RULES}
    for r, _, _ in found:
        found_by_rule[r] += 1
    green = not (new or stale or core_new or core_stale)
    return {
        "schema": SCHEMA_REPORT,
        "verdict": "GREEN" if green else "RED",
        "core_modules": len(closure_set),
        "core_by_root": {root: sum(1 for r in measured["closure"].values() if root in r)
                         for root in measured["roots"]},
        "exceptions_by_rule": by_rule,
        "exceptions_total": len(baseline),
        "findings_by_rule": found_by_rule,
        "findings_total": len(found),
        "new_findings": [dict(zip(("rule", "module", "operation"), k)) for k in new],
        "stale_exceptions": [dict(zip(("rule", "module", "operation"), k)) for k in stale],
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
        entry = {"rule": key[0], "module": key[1], "operation": key[2]}
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
        for m in report["core_list_new"]:
            print(f"  NEW core member, the closure gained an edge: {m}")
        for m in report["core_list_stale"]:
            print(f"  STALE core member, no longer reached (remove it): {m}")
    return 0 if report["verdict"] == "GREEN" else 1


if __name__ == "__main__":
    sys.exit(main())
