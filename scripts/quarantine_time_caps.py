#!/usr/bin/env python3
"""Every test with a fixed time cap in seconds, and whether it stands on the quarantine list.

WHY. A test with a fixed cap in seconds passes on one machine and fails on a slower one, and a CI runner under 3.14
is a slower one: the owner named two such caps on 2026-10-25, the 300 seconds around the candidate matrix in
tests/test_c12_1_nicht_anwendbar_vor_dem_tag.py and the cost curve of `renewal_work`. The quarantine list
(`.github/test_quarantine.json`, read by tests/_quarantine.py) lets such a test run and report without blocking
until its deadline. This check finds the caps and says, for each test that has one, whether it is on the list.

WHAT COUNTS AS A TIME CAP, read from the syntax tree of every test module under tests/:
- `timeout=<seconds>` in any call (subprocess.run, communicate, wait, a queue, a join), the seconds a number or a
  module constant bound to one;
- `@pytest.mark.timeout(<seconds>)`, `signal.alarm(<seconds>)`, `signal.setitimer(<which>, <seconds>)`;
- an asserted comparison of a clock reading with a number: one side reads `time.perf_counter`, `time.monotonic`,
  `time.time` or `time.process_time` (or their `_ns` forms), directly or through a name the same function binds from
  it, and the other side holds a number;
- an asserted comparison with a constant in seconds: a module constant bound to a number whose name ends in `_S`,
  `_SEC`, `_SECS`, `_SECONDS` or `_SEKUNDEN`, directly or through a name the function binds from it.
Asserted means the test of an `assert` statement or the arguments of `assertLess`, `assertLessEqual`, `assertGreater`
or `assertGreaterEqual`. A comparison in an `if` steers the test (a repetition, a skip) and is no cap by itself.
A cap counts for a test when it stands in the test's own body, in a function or method of the same module the test
calls by name (`helper(...)`, `self.helper(...)`), transitively, or in a fixture of the same module the test names as
a parameter.

WHAT IT DOES NOT SEE, named: a cap in a helper of another module, a cap computed at run time from something that is
neither a number nor a seconds constant, a clock read only in another module, a bound an `if` checks before a
`pytest.fail`. An asserted comparison with a seconds constant over synthetic numbers (a catch proof of a cost check)
counts as a cap too; the report shows its line.

OUTPUT. One block per test with a cap: its node id, each cap (line, kind, seconds, the function it stands in) and its
place on the list (in force through the deadline, expired, or NOT ON THE LIST); then every entry of the list that
names no test function of the tree, every expired entry, and every entry with a parameter id that pytest does not
collect for its function. Exit 0 with the report; 1 when the list is malformed, an entry names no test function of
the tree, an entry has expired, an entry's parameter id names no collected case, or the cases of such a function
cannot be collected; 2 on a usage error.

Usage: quarantine_time_caps.py [--tree <dir>] [--list <file>] [--today YYYY-MM-DD] [--json]
"""
from __future__ import annotations

import argparse
import ast
import datetime as dt
import importlib.util
import json
import re
import sys
import warnings
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CLOCKS = {"perf_counter", "perf_counter_ns", "monotonic", "monotonic_ns", "time", "time_ns", "process_time",
          "process_time_ns"}
SECONDS_NAME = re.compile(r"[A-Z][A-Z0-9_]*_(S|SEC|SECS|SECONDS|SEKUNDEN)")
_ORDER = (ast.Lt, ast.LtE, ast.Gt, ast.GtE)
_ASSERT_ORDER = {"assertLess", "assertLessEqual", "assertGreater", "assertGreaterEqual"}


def _quarantine_module(tree: Path):
    """tests/_quarantine.py of the tree: the one reader of the list, shared with the run."""
    spec = importlib.util.spec_from_file_location("_quarantine_list_reader", tree / "tests" / "_quarantine.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod          # a dataclass looks its module up while it is built
    spec.loader.exec_module(mod)
    return mod


def _number(node: ast.AST) -> float | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)) and not isinstance(node.value, bool):
        return float(node.value)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        n = _number(node.operand)
        return -n if n is not None else None
    return None


class _Module:
    """The facts of one module the caps are read from."""

    def __init__(self, tree: ast.Module):
        self.numbers: dict[str, float] = {}
        self.clock_names: set[str] = set()
        for node in tree.body:
            targets = (node.targets if isinstance(node, ast.Assign)
                       else [node.target] if isinstance(node, ast.AnnAssign) and node.value is not None else [])
            value = getattr(node, "value", None)
            n = _number(value) if value is not None else None
            for t in targets:
                if isinstance(t, ast.Name) and n is not None:
                    self.numbers[t.id] = n
            if isinstance(node, ast.ImportFrom) and node.module == "time":
                self.clock_names |= {a.asname or a.name for a in node.names if a.name in CLOCKS}

    def seconds_constants(self) -> dict[str, float]:
        return {k: v for k, v in self.numbers.items() if SECONDS_NAME.fullmatch(k)}

    def is_clock_call(self, node: ast.AST) -> bool:
        if not isinstance(node, ast.Call):
            return False
        f = node.func
        return ((isinstance(f, ast.Attribute) and f.attr in CLOCKS and isinstance(f.value, ast.Name)
                 and f.value.id == "time")
                or (isinstance(f, ast.Name) and f.id in self.clock_names))

    def value(self, node: ast.AST) -> float | None:
        n = _number(node)
        if n is None and isinstance(node, ast.Name):
            n = self.numbers.get(node.id)
        return n


def _caps_in(fn: ast.AST, mod: _Module) -> list[dict]:
    """The caps that stand in one function's body (nested bodies included)."""
    caps: list[dict] = []
    seconds = mod.seconds_constants()
    clocked: set[str] = set()
    secs: dict[str, set[str]] = {}    # a name the function binds -> the seconds constants it was bound from

    def mentions(node: ast.AST, names: set[str]) -> bool:
        return any(isinstance(x, ast.Name) and x.id in names for x in ast.walk(node))

    def reads_clock(node: ast.AST) -> bool:
        return any(mod.is_clock_call(x) for x in ast.walk(node)) or mentions(node, clocked)

    def constants_in(node: ast.AST) -> set[str]:
        out = set()
        for x in ast.walk(node):
            if isinstance(x, ast.Name):
                out |= {x.id} if x.id in seconds else secs.get(x.id, set())
        return out

    def reads_seconds(node: ast.AST) -> bool:
        return bool(constants_in(node))

    # The names a function binds from a clock reading or from a seconds constant, in the order it binds them.
    for _ in range(3):
        for node in ast.walk(fn):
            if isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)) and node.value is not None:
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                names = {t.id for t in targets if isinstance(t, ast.Name)}
                if reads_clock(node.value):
                    clocked |= names
                if reads_seconds(node.value):
                    for n in names:
                        secs.setdefault(n, set()).update(constants_in(node.value))

    asserted = {id(x) for a in ast.walk(fn) if isinstance(a, ast.Assert) for x in ast.walk(a.test)}

    def number_of(sides: list[ast.AST]) -> str:
        return next(f"{v:g}" for v in (mod.value(s) for s in sides) if v is not None)

    def constants_of(sides: list[ast.AST]) -> str:
        return ", ".join(f"{k} = {seconds[k]:g}" for k in sorted(set().union(*(constants_in(s) for s in sides))))

    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg == "timeout":
                    v = mod.value(kw.value)
                    if v is not None:
                        caps.append({"line": node.lineno, "kind": "timeout=", "seconds": f"{v:g}"})
            f = node.func
            name = f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else ""
            if name == "alarm" and node.args and mod.value(node.args[0]) is not None:
                caps.append({"line": node.lineno, "kind": "signal.alarm", "seconds": f"{mod.value(node.args[0]):g}"})
            if name == "setitimer" and len(node.args) > 1 and mod.value(node.args[1]) is not None:
                caps.append({"line": node.lineno, "kind": "signal.setitimer",
                             "seconds": f"{mod.value(node.args[1]):g}"})
            if name in _ASSERT_ORDER and len(node.args) >= 2:
                sides = list(node.args[:2])
                if any(reads_clock(s) for s in sides) and any(mod.value(s) is not None for s in sides):
                    caps.append({"line": node.lineno, "kind": "clock against a number", "seconds": number_of(sides)})
                elif any(reads_seconds(s) for s in sides):
                    caps.append({"line": node.lineno, "kind": "seconds constant", "seconds": constants_of(sides)})
        elif (isinstance(node, ast.Compare) and id(node) in asserted
              and any(isinstance(op, _ORDER) for op in node.ops)):
            sides = [node.left, *node.comparators]
            if any(reads_clock(s) for s in sides) and any(mod.value(s) is not None for s in sides):
                caps.append({"line": node.lineno, "kind": "clock against a number", "seconds": number_of(sides)})
            elif any(reads_seconds(s) for s in sides):
                caps.append({"line": node.lineno, "kind": "seconds constant", "seconds": constants_of(sides)})
    for d in getattr(fn, "decorator_list", []):
        if (isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and d.func.attr == "timeout"
                and "mark" in ast.unparse(d.func) and d.args and mod.value(d.args[0]) is not None):
            caps.append({"line": d.lineno, "kind": "mark.timeout", "seconds": f"{mod.value(d.args[0]):g}"})
    return caps


def _is_fixture(fn: ast.AST) -> bool:
    return any("fixture" in ast.unparse(d) for d in getattr(fn, "decorator_list", []))


def caps_of_module(path: Path, rel: str) -> dict[str, list[dict]]:
    """node id of each test function of one module -> its caps, with the function each cap stands in."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"), filename=rel)
    mod = _Module(tree)
    functions: dict[str, ast.AST] = {}          # "name" for module functions, "Class.name" for methods
    tests: dict[str, tuple[str, ast.AST]] = {}   # node id -> (key in functions, node)
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions[node.name] = node
            if node.name.startswith("test"):
                tests[f"{rel}::{node.name}"] = (node.name, node)
        elif isinstance(node, ast.ClassDef):
            for sub in node.body:
                if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    functions[f"{node.name}.{sub.name}"] = sub
                    if sub.name.startswith("test"):
                        tests[f"{rel}::{node.name}::{sub.name}"] = (f"{node.name}.{sub.name}", sub)
    own = {k: _caps_in(fn, mod) for k, fn in functions.items()}

    def callees(key: str) -> set[str]:
        fn, cls = functions[key], key.split(".")[0] if "." in key else None
        out = set()
        for x in ast.walk(fn):
            if isinstance(x, ast.Call):
                f = x.func
                if isinstance(f, ast.Name) and f.id in functions:
                    out.add(f.id)
                elif (isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id in ("self", "cls")
                      and cls and f"{cls}.{f.attr}" in functions):
                    out.add(f"{cls}.{f.attr}")
        for a in getattr(fn, "args", ast.arguments()).args:
            if a.arg in functions and _is_fixture(functions[a.arg]):
                out.add(a.arg)
        return out - {key}

    result: dict[str, list[dict]] = {}
    for nodeid, (key, _) in tests.items():
        seen, stack, caps = {key}, [key], []
        while stack:
            k = stack.pop()
            caps += [dict(c, where=k.replace(".", "::")) for c in own[k] if dict(c, where=k.replace(".", "::")) not in caps]
            for c in sorted(callees(k)):
                if c not in seen:
                    seen.add(c)
                    stack.append(c)
        if caps:
            result[nodeid] = sorted(caps, key=lambda c: (c["where"] != key.replace(".", "::"), c["line"]))
    return result


def all_test_functions(tree: Path) -> set[str]:
    out = set()
    for p in sorted((tree / "tests").rglob("test_*.py")):
        rel = p.relative_to(tree).as_posix()
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", SyntaxWarning)
                t = ast.parse(p.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:
            continue
        for node in t.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test"):
                out.add(f"{rel}::{node.name}")
            elif isinstance(node, ast.ClassDef):
                out |= {f"{rel}::{node.name}::{s.name}" for s in node.body
                        if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef)) and s.name.startswith("test")}
    return out


def collected_cases(tree: Path, functions: list[str]) -> tuple[set[str], list[str]]:
    """The node ids pytest collects in `tree` for each of the test functions named, and the functions whose collection
    could not be read. A parameter id is what pytest makes of the arguments at collection, so it is read from a
    collection of the function, not from its source."""
    import subprocess  # noqa: PLC0415
    cases: set[str] = set()
    unread: list[str] = []
    for fn in sorted(set(functions)):
        try:
            r = subprocess.run([sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider", fn],
                               cwd=tree, capture_output=True, text=True, timeout=600)
        except (OSError, subprocess.SubprocessError) as exc:
            unread.append(f"{fn} ({type(exc).__name__})")
            continue
        found = {ln.strip() for ln in r.stdout.splitlines() if ln.strip().startswith(fn + "[")}
        if r.returncode != 0 or not found:
            unread.append(f"{fn} (pytest --collect-only rc {r.returncode}, {len(found)} parametrized cases)")
        cases |= found
    return cases, unread


def check(tree: Path, list_file: Path, today: dt.date) -> tuple[dict, int]:
    q = _quarantine_module(tree)
    try:
        entries = q.load(list_file) or []
    except q.ListError as exc:
        return {"error": str(exc)}, 1
    caps: dict[str, list[dict]] = {}
    for p in sorted((tree / "tests").rglob("test_*.py")):
        rel = p.relative_to(tree).as_posix()
        try:
            caps.update(caps_of_module(p, rel))
        except SyntaxError as exc:
            caps[rel] = [{"line": exc.lineno or 0, "kind": "NOT MEASURABLE: the module does not parse", "seconds": "",
                          "where": ""}]
    functions = all_test_functions(tree)
    rows = []
    for nodeid in sorted(caps):
        listed = [e for e in entries if e.test.split("[")[0] == nodeid]
        place = ([f"{'in force through' if e.in_force(today) else 'EXPIRED on'} {e.deadline} as {e.test}"
                  f" (owner {e.owner})" for e in listed] or ["NOT ON THE LIST"])
        rows.append({"test": nodeid, "caps": caps[nodeid], "list": place})
    ghosts = [e.test for e in entries if e.test.split("[")[0] not in functions]
    # AN EXPIRED ENTRY IS RED (the reading of 8ec67d5a, P1): past its deadline it marks nothing, a passing test leaves
    # the run green, and the entry would stay on the list unseen. Red here stops the job `test` until it leaves.
    expired = [f"{e.test} (expired on {e.deadline}, owner {e.owner})" for e in entries if not e.in_force(today)]
    # A PARAMETER ID IS CHECKED AGAINST THE COLLECTED CASES (the reading of 8ec67d5a, P2): by the function name alone
    # a typo in the id passed while the plugin covered no test.
    parametrized = [e.test for e in entries if "[" in e.test and e.test.split("[")[0] in functions]
    cases, unread = collected_cases(tree, [t.split("[")[0] for t in parametrized]) if parametrized else (set(), [])
    report = {"tree": str(tree), "list": str(list_file), "today": today.isoformat(), "tests_with_a_cap": rows,
              "listed_without_a_cap": [e.test for e in entries
                                       if e.test.split("[")[0] in functions and e.test.split("[")[0] not in caps],
              "entries_naming_no_test": ghosts, "entries_expired": expired,
              "entries_naming_no_collected_case": [t for t in parametrized if t not in cases],
              "collection_not_readable": unread}
    red = ghosts or expired or report["entries_naming_no_collected_case"] or unread
    return report, (1 if red else 0)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--tree", type=Path, default=REPO)
    p.add_argument("--list", type=Path, default=None, help="default: <tree>/.github/test_quarantine.json")
    p.add_argument("--today", type=dt.date.fromisoformat, default=None, help="default: today in UTC")
    p.add_argument("--json", action="store_true")
    a = p.parse_args(argv)
    tree = a.tree.resolve()
    report, rc = check(tree, a.list or tree / ".github" / "test_quarantine.json",
                       a.today or dt.datetime.now(dt.timezone.utc).date())
    if a.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return rc
    if "error" in report:
        print(f"quarantine-time-caps: the list is malformed: {report['error']}")
        return rc
    rows = report["tests_with_a_cap"]
    on = sum(1 for r in rows if r["list"] != ["NOT ON THE LIST"])
    print(f"quarantine-time-caps: {len(rows)} test functions carry a fixed time cap in seconds; {on} of them are on "
          f"the list {report['list']}")
    for r in rows:
        print(f"{r['test']}  [{'; '.join(r['list'])}]")
        for c in r["caps"]:
            print(f"    line {c['line']}  {c['kind']}  {c['seconds']}  in {c['where']}")
    for t in report["listed_without_a_cap"]:
        print(f"listed, but no time cap found: {t}")
    for t in report["entries_naming_no_test"]:
        print(f"LISTED, BUT NO SUCH TEST FUNCTION IN THE TREE: {t}")
    for t in report["entries_expired"]:
        print(f"EXPIRED, IT BLOCKS UNTIL IT LEAVES THE LIST: {t}")
    for t in report["entries_naming_no_collected_case"]:
        print(f"LISTED, BUT PYTEST COLLECTS NO SUCH CASE: {t}")
    for t in report["collection_not_readable"]:
        print(f"NOT MEASURABLE, THE CASES OF THIS FUNCTION COULD NOT BE COLLECTED: {t}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
