"""The counter-reading of pull request 420 at 9031df5e: the reading of a name, the limit of a binding, `__new__`, the
lines of a reviewed change and a modules file nested too deep.

F1 (P1): `string_of` read every binding of a name again at every use, so `i = 0`, eight `i = i + 1` and `code[i]` took
66 s where main takes 0.1 s, and `idlelib/pyparse.py` 203 s. F2 (P2): past 64 names a binding dropped the names that
came later, so an `os` bound after 64 other names read the environment unseen where main reports it. F4 (P2): a
`__new__` under `if` or `try`, in a tuple or loop target, or set after the class made the class build a module while
it counted as plain. F5 (P3): a factory with many annotated inner functions was searched once per annotation. F6
(P3): the reviewed change read its lines with `splitlines`, so a form feed moved the line it compared. F7 (P3): a
modules file nested too deep stopped the gate with a traceback.

The synthetic packages follow `build` in tests/test_core_layer_gate_sees_every_spelling.py; the environment value is a
test value set for one child process.
"""
from __future__ import annotations

import ast
import builtins
import importlib.util
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts" / "core_layer_gate.py"
PKG = "probepkg"

pytestmark = pytest.mark.skipif(not GATE.is_file(), reason="scripts/core_layer_gate.py is not in this tree")


def _load_gate():
    spec = importlib.util.spec_from_file_location("core_layer_gate_of_the_counter_reading_420", GATE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def build(tmp_path: Path, files: dict[str, str], reviewed=None) -> list[str]:
    src = tmp_path / "src" / PKG
    src.mkdir(parents=True)
    (src / "__init__.py").write_text("", encoding="utf-8")
    for rel, body in files.items():
        (src / rel).write_text(body, encoding="utf-8")
    modules = tmp_path / "modules.json"
    spec = {"schema": "proofbundle.core_layer_modules.v1", "package": PKG, "roots": {"probepkg.core": "probe"},
            "trust_boundaries": {}, "modules": ["probepkg", "probepkg.core"]}
    if reviewed is not None:
        spec["type_checking_reviewed"] = reviewed
    modules.write_text(json.dumps(spec), encoding="utf-8")
    exc = tmp_path / "exceptions.json"
    exc.write_text(json.dumps({"entries": []}), encoding="utf-8")
    return ["--root", str(tmp_path), "--modules-file", str(modules), "--exceptions-file", str(exc)]


def gate(args: list[str], timeout: float = 120) -> tuple[int, dict]:
    r = subprocess.run([sys.executable, "-B", str(GATE), *args, "--json"], capture_output=True, text=True,
                       timeout=timeout)
    return r.returncode, json.loads(r.stdout)


def found(report: dict) -> set[tuple[str, str]]:
    return {(f["rule"], f["operation"]) for f in report["measured"]["findings"]}


def run_module(tmp_path: Path, code: str) -> str:
    """What the package really does when it runs, in a child process with a test value for X."""
    env = {**os.environ, "PYTHONPATH": str(tmp_path / "src"), "X": "TEST_ONLY"}
    r = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True, timeout=60, env=env,
                       cwd=str(tmp_path))
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


# ── F1: the string a name is, read once per scope, name and depth ───────────────────────────────────────────────

def test_F1_a_counter_assigned_again_and_again_is_read_in_time(tmp_path):
    """Ten times `i = i + 1`, then `code[i]`: at 9031df5e over 100 s, on main 0.1 s."""
    core = "i = 0\n" + "i = i + 1\n" * 10 + "code = 'abcdefghijklmnop'\nVALUE = code[i]\n"
    args = build(tmp_path, {"core.py": core})
    assert run_module(tmp_path, "import probepkg.core as c; print(c.VALUE)") == "k"
    started = time.monotonic()
    rc, report = gate(args, timeout=60)
    assert (rc, report["verdict"]) == (0, "GREEN"), report
    assert time.monotonic() - started < 30


def test_F1_a_name_read_deep_first_is_read_again_where_it_is_shallow():
    """The record is kept per depth: reading `a20` reads `a10` at depth 10, where the nine links below it run past the
    limit of 16, so the answer for `a10` there is none. Read at the top, `a10` is nine links from its literal and is the
    dotted name. A record per scope and name alone hands the answer cut short at depth 10 to the reading at the top, and
    the write by `a10` is missed."""
    gate_module = _load_gate()
    chain = 'a1 = "typing.TYPE_CHECKING"\n' + "".join(f"a{i} = a{i - 1}\n" for i in range(2, 21))
    code = "from unittest import mock\n" + chain + "mock.patch(a20, True)\nmock.patch(a10, True)\n"
    changes = gate_module.type_checking_changes(ast.parse(code))
    line_of_a10 = code.count("\n")
    assert ("TYPE_CHECKING named by a write", line_of_a10) in changes, changes


# ── F2: a name bound after many others ──────────────────────────────────────────────────────────────────────────

def _fillers() -> list[str]:
    """Names with no rule of the gate, each a qualified name of its own a binding may stand for: the builtins without
    a rule, and the constants of `math`."""
    gate_module = _load_gate()
    named = [n for n in dir(builtins) if n.islower() and not n.startswith("_") and not gate_module._is_ruled_builtin(n)
             and f"builtins.{n}" not in gate_module._ATTRIBUTE_FUNCTIONS]
    return named + [f"math.{n}" for n in ("pi", "e", "tau", "inf", "nan")]


def test_F2_an_os_bound_after_more_than_64_names_is_still_the_environment(tmp_path):
    fillers = _fillers()
    assert len(fillers) >= 64, f"{len(fillers)} fillers: the case needs 64 names before os, or it proves nothing"
    core = "import math, os\n" + "".join(f"x = {n}\n" for n in fillers) + "x = os\nVALUE = x.getenv('X')\n"
    args = build(tmp_path, {"core.py": core})
    assert run_module(tmp_path, "import probepkg.core as c; print(c.VALUE)") == "TEST_ONLY"
    rc, report = gate(args)
    assert (rc, report["verdict"]) == (1, "RED"), report
    assert ("environment", "os.getenv") in found(report), report["measured"]["findings"]


# ── F4: `__new__` in any form ───────────────────────────────────────────────────────────────────────────────────

#: The module comes from `inspect.getmodule`, never as the name `typing` handed on, which is a form of its own and
#: would make every case red without the reading of `__new__`.
_NEW = "staticmethod(lambda cls: inspect.getmodule(typing.Any))"
_CLASS = "import inspect, typing\nclass E:\n{body}{after}x = E()\nsetattr(x, 'type_checking'.upper(), True)\n"
NEW_FORMS = {
    "under if in the body": ("    if True:\n        def __new__(cls):\n            return inspect.getmodule(typing.Any)\n",
                             ""),
    "under try in the body": (f"    try:\n        __new__ = {_NEW}\n    except Exception:\n        pass\n", ""),
    "a tuple target in the body": (f"    (__new__, y) = ({_NEW}, 1)\n", ""),
    "a loop target in the body": (f"    for __new__ in [{_NEW}]:\n        pass\n", ""),
    "set after the class": ("    pass\n", f"E.__new__ = {_NEW}\n"),
    "set by setattr after the class": ("    pass\n", f"setattr(E, '__new__', {_NEW})\n"),
    "set by setattr with a built name": ("    pass\n", f"setattr(E, '__ne' + 'w__', {_NEW})\n"),
    "set by setattr with a name bound to the string": ("    pass\n", f"N = '__new__'\nsetattr(E, N, {_NEW})\n"),
    # The second counter-reading of pull request 420 (F1, P2): a match capture binds `__new__` as an assignment does,
    # and an f-string builds the name as a concatenation does.
    "a match capture in the body": (f"    match {_NEW}:\n        case __new__:\n            pass\n", ""),
    "a match capture in a sequence": (f"    match ({_NEW},):\n        case (__new__,):\n            pass\n", ""),
    "set by setattr with a name built by an f-string": ("    pass\n", f"setattr(E, f'__{{\"new\"}}__', {_NEW})\n"),
}


@pytest.mark.parametrize("body, after", list(NEW_FORMS.values()), ids=list(NEW_FORMS))
def test_F4_a_class_with_a_new_in_any_form_may_build_a_module(body, after):
    code = _CLASS.format(body=body, after=after)
    namespace: dict = {}
    built = code.replace("setattr(x, 'type_checking'.upper(), True)\n", "")   # the write itself does not run here
    exec(compile(built, "<probe>", "exec"), namespace)
    assert namespace["x"] is namespace["typing"], "the class must build the module, or the case proves nothing"
    assert _load_gate().type_checking_changes(ast.parse(code)), code


def test_F4_CONTROL_a_plain_class_builds_no_module():
    code = _CLASS.format(body="    pass\n", after="")
    assert _load_gate().type_checking_changes(ast.parse(code)) == []


_GETATTR = "import inspect, typing\nm = inspect.getmodule(typing.Any)\ngetattr(m, {name})('TYPE_CHECKING', True)\n"


@pytest.mark.parametrize("name", ["'__setattr__'", "'__set' + 'attr__'", "f'__{\"setattr\"}__'"],
                         ids=["the literal", "built by concatenation", "built by an f-string"])
def test_second_F1_neighbour_a_getattr_of_setattr_on_a_module_is_seen_with_a_built_name(name):
    """A neighbour of F1 in the same class, a name read only as a literal: `getattr(m, "__set" + "attr__")` on the
    module `typing` set TYPE_CHECKING while the gate, on main as well, saw no change. The literal is the control."""
    code = _GETATTR.format(name=name)
    namespace: dict = {}
    exec(compile(code.replace("('TYPE_CHECKING', True)", ""), "<probe>", "exec"), namespace)
    assert namespace["m"] is namespace["typing"], "the receiver must be the module, or the case proves nothing"
    assert _load_gate().type_checking_changes(ast.parse(code)), code


# ── the second counter-reading, F2: no input ends the gate without its report ─────────────────────────────────────

def _conditionals(n: int) -> str:
    return "c = True\nx = 1" + " if c else 1" * n + "\n"


def test_second_F2_a_chain_of_conditionals_near_the_limit_ends_with_the_report(tmp_path):
    """`x = 1 if c else 1 if c else ...`: one or two lengths just below the limit of the first reading passed it and
    ended in the closure with a traceback and exit 1 (3.10 at 1995, 3.12 at 1996 and 1997). Every length of the window
    on every interpreter gives the JSON report, GREEN or NOT MEASURABLE, never exit 1."""
    verdicts = {}
    for n in range(1985, 2006):
        folder = tmp_path / str(n)
        folder.mkdir()
        r = subprocess.run([sys.executable, "-B", str(GATE), *build(folder, {"core.py": _conditionals(n)}), "--json"],
                           capture_output=True, text=True, timeout=120)
        try:
            verdicts[n] = (r.returncode, json.loads(r.stdout)["verdict"])
        except ValueError:
            verdicts[n] = (r.returncode, "NO REPORT")
    assert set(verdicts.values()) <= {(0, "GREEN"), (2, "NOT_MEASURABLE")}, verdicts


def test_second_F2_CONTROL_a_shorter_chain_is_green(tmp_path):
    rc, report = gate(build(tmp_path, {"core.py": _conditionals(1900)}))
    assert (rc, report["verdict"]) == (0, "GREEN"), report


# ── F5: the function around a postponed annotation, searched once ───────────────────────────────────────────────

def test_F5_a_factory_with_many_annotated_inner_functions_is_read_in_time(tmp_path):
    """700 annotated inner functions under `from __future__ import annotations`: at 9031df5e quadratic, about 2 min."""
    inner = "".join(f"    def f{i}(x: int) -> int:\n        return x\n    typing.get_type_hints(f{i})\n"
                    for i in range(700))
    core = "from __future__ import annotations\nimport typing\ndef factory():\n" + inner + "    return 1\n"
    args = build(tmp_path, {"core.py": core})
    started = time.monotonic()
    rc, report = gate(args, timeout=90)
    assert (rc, report["verdict"]) == (0, "GREEN"), report
    assert time.monotonic() - started < 45


# ── F6: the lines of a reviewed change, as `ast` counts them ────────────────────────────────────────────────────

_FORM = "a namespace that may be a module's, used other than by reading"
_APPROVED = 'own = object.__getattribute__(target, "__dict__")'
_REVIEWED = [{"module": "probepkg.demo", "form": _FORM, "count": 1, "source": [_APPROVED],
              "reason": "fills the namespace of objects this module builds"}]
_CORE = "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    import subprocess\n"
_HONEST = "def fill(target, items):\n    own = object.__getattribute__(target, \"__dict__\")\n    for k, v in items:\n" \
          "        own[k] = v\n"


def test_F6_CONTROL_the_honest_reviewed_line_stays_approved(tmp_path):
    rc, report = gate(build(tmp_path, {"core.py": _CORE, "demo.py": _HONEST}, reviewed=_REVIEWED))
    assert (rc, report["verdict"]) == (0, "GREEN"), report
    assert len(report["measured"]["type_checking_reviewed"]) == 1


def test_F6_a_form_feed_does_not_move_the_line_a_reviewed_change_is_bound_to(tmp_path):
    """The reviewed text stands one line above the edited write, inside a string after a form feed. Read with
    `splitlines` the form feed made one more line, the reviewed text was read as the line of the write, and the edited
    write stayed approved while `typing.TYPE_CHECKING` was True after the import."""
    trick = ('S = """' + chr(12) + "\n" + _APPROVED + '\n""";own = object.__getattribute__(__import__("typing"), '
             '"__dict__")\nfor k, v in [("TYPE_" + "CHECKING", True)]:\n    own[k] = v\n')
    args = build(tmp_path, {"core.py": _CORE, "demo.py": trick}, reviewed=_REVIEWED)
    assert run_module(tmp_path, "import probepkg.demo, typing; print(typing.TYPE_CHECKING)") == "True"
    rc, report = gate(args)
    assert (rc, report["verdict"]) == (1, "RED"), report
    assert report["stale_reviewed_changes"], report
    assert report["measured"]["type_checking_reviewed"] == [], report["measured"]["type_checking_reviewed"]


# ── F7: a modules file nested too deep ──────────────────────────────────────────────────────────────────────────

def test_F7_a_modules_file_nested_too_deep_is_not_measurable(tmp_path):
    args = build(tmp_path, {"core.py": "VALUE = 1\n"})
    (tmp_path / "modules.json").write_text("[" * 200000 + "]" * 200000, encoding="utf-8")
    rc, report = gate(args)
    assert (rc, report["verdict"]) == (2, "NOT_MEASURABLE"), report
