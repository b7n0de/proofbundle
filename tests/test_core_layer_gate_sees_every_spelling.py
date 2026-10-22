"""The class behind the three limits K6 kept in 6.3.1 (the lens on pull request 393, measured at b7f6a3b0): the
core layer gate judged an operation by the one spelling it knew.

Another spelling of the same write was judged as nothing. `getattr(typing, "__dict__").update(...)`,
`typing.__setattr__(...)`, `object.__setattr__(typing, ...)` and a renamed `setattr` made a type-checking block
run while the gate skipped it, and a name bound by a star import, a re-export or a match capture was resolved
against the binding the gate knew. The other direction was a false alarm: a read of an object's namespace in a
module outside the core, such as `print(vars(x))` or `x.__dict__ is None`, counted as a possible change of
`TYPE_CHECKING` and turned every type-checking guard of the package off.

Each write case runs the module first: the guarded import happens, measured by executing it, and only then is the
gate asked. The synthetic packages follow `build` in tests/test_core_layer_gate.py; the environment value is a test
value set for one child process.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts" / "core_layer_gate.py"
PKG = "probepkg"

pytestmark = pytest.mark.skipif(not GATE.is_file(), reason="scripts/core_layer_gate.py is not in this tree")


def build(tmp_path: Path, files: dict[str, str], listed=("probepkg", "probepkg.core"), reviewed=None) -> list[str]:
    src = tmp_path / "src" / PKG
    src.mkdir(parents=True)
    (src / "__init__.py").write_text("", encoding="utf-8")
    for rel, body in files.items():
        (src / rel).write_text(textwrap.dedent(body), encoding="utf-8")
    modules = tmp_path / "modules.json"
    spec = {"schema": "proofbundle.core_layer_modules.v1", "package": PKG, "roots": {"probepkg.core": "probe"},
            "trust_boundaries": {}, "modules": list(listed)}
    if reviewed is not None:
        spec["type_checking_reviewed"] = reviewed
    modules.write_text(json.dumps(spec), encoding="utf-8")
    exc = tmp_path / "exceptions.json"
    exc.write_text(json.dumps({"entries": []}), encoding="utf-8")
    return ["--root", str(tmp_path), "--modules-file", str(modules), "--exceptions-file", str(exc)]


def gate(args: list[str]) -> tuple[int, dict]:
    r = subprocess.run([sys.executable, "-B", str(GATE), *args, "--json"], capture_output=True, text=True,
                       timeout=120)
    return r.returncode, json.loads(r.stdout)


def found(report: dict) -> set[tuple[str, str]]:
    return {(f["rule"], f["operation"]) for f in report["measured"]["findings"]}


def run_core(tmp_path: Path, code: str) -> str:
    """What the core module really does when it runs, in a child process with a test value for X."""
    env = {**os.environ, "PYTHONPATH": str(tmp_path / "src"), "X": "TEST_ONLY"}
    r = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True, timeout=60,
                       env=env, cwd=str(tmp_path))
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


_RUNS_THE_BLOCK = "import probepkg.core as c; print(hasattr(c, 'subprocess'))"
_MODULE_GUARD = "import typing\n{}\nif typing.TYPE_CHECKING:\n    import subprocess\n"
_BARE_GUARD = "from typing import TYPE_CHECKING\n{}\nif TYPE_CHECKING:\n    import subprocess\n"
_NAME = 'name = "TYPE_" + "CHECKING"\n'

# ── writes the gate did not see: each one runs the guarded block ──────────────────────────────────────────────────

#: P2 2 and 3 of the lens, and the neighbours a sweep of the same class found: every spelling of reaching a module's
#: namespace or of setting one of its attributes, with the name written out and with a name the gate cannot read.
WRITE_SPELLINGS = {
    "getattr __dict__, a method": _MODULE_GUARD.format('getattr(typing, "__dict__").update(TYPE_CHECKING=True)'),
    "getattr __dict__, an item": _MODULE_GUARD.format('getattr(typing, "__dict__")["TYPE_CHECKING"] = True'),
    "object.__getattribute__ __dict__": _MODULE_GUARD.format(
        'object.__getattribute__(typing, "__dict__").update(TYPE_CHECKING=True)'),
    "the module's own __getattribute__": _MODULE_GUARD.format(
        'typing.__getattribute__("__dict__")["TYPE_CHECKING"] = True'),
    "module.__setattr__": _MODULE_GUARD.format('typing.__setattr__("TYPE_CHECKING", True)'),
    "object.__setattr__": _MODULE_GUARD.format('object.__setattr__(typing, "TYPE_CHECKING", True)'),
    "type(module).__setattr__": _MODULE_GUARD.format('type(typing).__setattr__(typing, "TYPE_CHECKING", True)'),
    "a renamed setattr": _MODULE_GUARD.format('put = setattr\nput(typing, "TYPE_CHECKING", True)'),
    "setattr imported under another name": _MODULE_GUARD.format(
        'from builtins import setattr as put\nput(typing, "TYPE_CHECKING", True)'),
    "a bound __setattr__ taken as a value": _MODULE_GUARD.format(
        'put = typing.__setattr__\nput("TYPE_CHECKING", True)'),
    "setattr handed to partial": _MODULE_GUARD.format(
        'import functools\nfunctools.partial(setattr, typing, "TYPE_CHECKING")(True)'),
    "a renamed vars": _MODULE_GUARD.format("ns = vars\nns(typing).update(TYPE_CHECKING=True)"),
    "vars imported under another name": _MODULE_GUARD.format(
        "from builtins import vars as ns\nns(typing).update(TYPE_CHECKING=True)"),
    "builtins.vars": _MODULE_GUARD.format("import builtins\nbuiltins.vars(typing).update(TYPE_CHECKING=True)"),
    "a renamed globals": _BARE_GUARD.format('g = globals\ng()["TYPE_CHECKING"] = True'),
    "a reading builtin shadowed by a writer": _MODULE_GUARD.format(
        'def sorted(m):\n    m["TYPE_CHECKING"] = True\nsorted(typing.__dict__)'),
    "a reading class shadowed by a writer": _MODULE_GUARD.format(
        'class list:\n    def __init__(self, m):\n        m["TYPE_CHECKING"] = True\nlist(typing.__dict__)'),
    "the name handed to a helper": _MODULE_GUARD.format(
        'def put(m, n):\n    setattr(m, n, True)\nput(typing, "TYPE_CHECKING")'),
    # A name the gate cannot read: the object written is a module, so the write counts.
    "computed, module.__setattr__": _MODULE_GUARD.format(_NAME + "typing.__setattr__(name, True)"),
    "computed, object.__setattr__": _MODULE_GUARD.format(_NAME + "object.__setattr__(typing, name, True)"),
    "computed, setattr": _MODULE_GUARD.format(_NAME + "setattr(typing, name, True)"),
    "computed, getattr __dict__": _MODULE_GUARD.format(_NAME + 'getattr(typing, "__dict__")[name] = True'),
    "computed, object.__getattribute__": _MODULE_GUARD.format(
        _NAME + 'object.__getattribute__(typing, "__dict__")[name] = True'),
    "computed, vars": _MODULE_GUARD.format(_NAME + "vars(typing)[name] = True"),
    "computed, sys.modules": _MODULE_GUARD.format(_NAME + 'import sys\nsys.modules["typing"].__dict__[name] = True'),
    "computed, sys.modules through a name": _MODULE_GUARD.format(
        _NAME + 'import sys\nm = sys.modules["typing"]\nvars(m)[name] = True'),
    "computed, sys.modules through a walrus": _MODULE_GUARD.format(
        _NAME + 'import sys\nwhich = "typ" + "ing"\nif (m := sys.modules[which]):\n    vars(m)[name] = True'),
    "computed, the module handed to a library function": _MODULE_GUARD.format(
        _NAME + "import functools\ndef _f():\n    pass\nsetattr(_f, name, True)\nfunctools.update_wrapper(typing, _f)"),
    "computed, a module's namespace returned": _MODULE_GUARD.format(
        _NAME + "def ns():\n    return typing.__dict__\nns()[name] = True"),
    "computed, an alias of the namespace": _MODULE_GUARD.format(_NAME + "ns = vars(typing)\nns[name] = True"),
    "computed, a reading builtin shadowed by a writer": _MODULE_GUARD.format(
        _NAME + "def sorted(m):\n    m[name] = True\nsorted(typing.__dict__)"),
    "computed, globals handed to partial": _BARE_GUARD.format(
        _NAME + "import functools\nns = functools.partial(globals)\nns()[name] = True"),
    "computed, importlib": _MODULE_GUARD.format(
        _NAME + 'import importlib\nvars(importlib.import_module("typing"))[name] = True'),
    "computed, globals": _BARE_GUARD.format(_NAME + "globals()[name] = True"),
    "computed, the module handed to a helper": _MODULE_GUARD.format(
        _NAME + "def put(m, n):\n    setattr(m, n, True)\nput(typing, name)"),
}

#: P2 3, the binding half: a name bound where the gate did not look, so the guard it trusted is another object.
REBINDING_THE_GUARD = {
    "a match capture of the module": (
        "import typing\nclass _Flag:\n    TYPE_CHECKING = True\nmatch _Flag:\n    case typing:\n        pass\n"
        "if typing.TYPE_CHECKING:\n    import subprocess\n", {}),
    "a match capture of the flag": (
        "from typing import TYPE_CHECKING\nmatch True:\n    case TYPE_CHECKING:\n        pass\n"
        "if TYPE_CHECKING:\n    import subprocess\n", {}),
    "an exception name": (
        "from typing import TYPE_CHECKING\ntry:\n    raise ValueError\nexcept ValueError as TYPE_CHECKING:\n"
        "    if TYPE_CHECKING:\n        import subprocess\n", {}),
    "a star import of the flag": (
        "from typing import TYPE_CHECKING\nfrom .other import *\nif TYPE_CHECKING:\n    import subprocess\n",
        {"other.py": "TYPE_CHECKING = True\n"}),
    "a star import of the module": (
        "import typing\nfrom .other import *\nif typing.TYPE_CHECKING:\n    import subprocess\n",
        {"other.py": "class typing:\n    TYPE_CHECKING = True\n"}),
}


@pytest.mark.parametrize("code", list(WRITE_SPELLINGS.values()), ids=list(WRITE_SPELLINGS))
def test_RED_every_spelling_of_a_write_to_the_guard_is_seen(tmp_path, code):
    args = build(tmp_path, {"core.py": code})
    assert run_core(tmp_path, _RUNS_THE_BLOCK) == "True"
    rc, report = gate(args)
    assert (rc, report["verdict"]) == (1, "RED"), report["measured"]["findings"]
    assert ("subprocess", "import subprocess") in found(report)
    assert report["measured"]["type_checking_changed_by"] == ["probepkg.core"]


@pytest.mark.parametrize("case", list(REBINDING_THE_GUARD.values()), ids=list(REBINDING_THE_GUARD))
def test_RED_a_guard_rebound_where_the_gate_did_not_look_is_no_guard(tmp_path, case):
    code, extra = case
    listed = ("probepkg", "probepkg.core", *(f"probepkg.{n[:-3]}" for n in extra))
    args = build(tmp_path, {"core.py": code, **extra}, listed=listed)
    assert run_core(tmp_path, _RUNS_THE_BLOCK) == "True"
    rc, report = gate(args)
    assert (rc, report["verdict"]) == (1, "RED"), report["measured"]["findings"]
    assert ("subprocess", "import subprocess") in found(report)


# ── reads and writes that change no guard: none of them may turn the guards off ─────────────────────────────────────

_HONEST_CORE = "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    import subprocess\n"

#: P2 1 of the lens: the fourteen read forms of fp_real.py, in a module outside the core. Twelve of them turned the
#: gate red at b7f6a3b0, `len(x.__dict__)` and the loop over `vars(x)` were the two that stayed green.
READS_OUTSIDE_THE_CORE = {
    "a truth test": "def _p(x):\n    if vars(x):\n        return 1\n",
    "bool()": "def _p(x):\n    return bool(vars(x))\n",
    "print()": "def _p(x):\n    print(vars(x))\n",
    "an f-string": "def _p(x):\n    return f'{vars(x)}'\n",
    "dict unpacking": "def _p(x):\n    return {**vars(x)}\n",
    "a comparison of two namespaces": "def _p(self, o):\n    return self.__dict__ == o.__dict__\n",
    "len()": "def _p(x):\n    return len(x.__dict__)\n",
    "json.dumps()": "import json\ndef _p(x):\n    return json.dumps(vars(x))\n",
    "an identity test": "def _p(x):\n    return x.__dict__ is None\n",
    "isinstance()": "def _p(x):\n    return isinstance(vars(x), dict)\n",
    "a loop": "def _p(x):\n    return [k for k in vars(x)]\n",
    "not": "def _p(x):\n    return not vars(x)\n",
    "a return": "def _p(x):\n    return vars(x)\n",
    "repr()": "def _p(x):\n    return repr(x.__dict__)\n",
}

#: Reads of a module's own namespace: they change nothing either.
READS_OF_A_MODULE = {
    "print() of vars(typing)": "import typing\ndef _p():\n    print(vars(typing))\n",
    "a truth test of typing.__dict__": "import typing\ndef _p():\n    return 1 if typing.__dict__ else 0\n",
    "json of the sorted names": "import json, typing\ndef _p():\n    return json.dumps(sorted(vars(typing)))\n",
    "an identity test": "import typing\ndef _p():\n    return typing.__dict__ is None\n",
    "the flag compared by name": 'def _p(name):\n    return name == "TYPE_CHECKING"\n',
    "the flag read by getattr": 'import typing\ndef _p():\n    return getattr(typing, "TYPE_CHECKING")\n',
    "the module handed to a reader": "import types, typing\ndef _p():\n    return isinstance(typing, types.ModuleType)\n",
    "a module imported by name, read": (
        'import importlib\ndef _p():\n    return vars(importlib.import_module("typing")).get("Any")\n'),
}

#: Writes into an object that is no module: TYPE_CHECKING lives in a module, so they cannot reach it. The last one is
#: the form of src/proofbundle/canonical.py, which fills the namespace of a copy it built.
WRITES_INTO_AN_OBJECT = {
    "self.__dict__.update": "class C:\n    def __init__(self, **kw):\n        self.__dict__.update(kw)\n",
    "an item of self.__dict__": "class C:\n    def set(self, k, v):\n        self.__dict__[k] = v\n",
    "vars(self) by item": "class C:\n    def set(self, k, v):\n        vars(self)[k] = v\n",
    "object.__setattr__ on self": "class C:\n    def set(self, k, v):\n        object.__setattr__(self, k, v)\n",
    "a literal object.__setattr__": 'class C:\n    def __init__(self, v):\n        object.__setattr__(self, "v", v)\n',
    "an object a local class builds": "class C:\n    pass\ndef fill(k, v):\n    c = C()\n    setattr(c, k, v)\n",
    "an object a builtin type builds": "def fill(k, v):\n    d = dict()\n    object.__setattr__(d, k, v)\n",
    "a walrus-bound object a builtin type builds": (
        "def fill(k, v):\n    if (d := dict()) is not None:\n        object.__setattr__(d, k, v)\n"),
    "a name rebound from the same object": (
        "def fill(k, v):\n    d = dict()\n    e = d\n    if k:\n        e = d\n    object.__setattr__(e, k, v)\n"),
}


@pytest.mark.parametrize("code", [*READS_OUTSIDE_THE_CORE.values(), *READS_OF_A_MODULE.values(),
                                  *WRITES_INTO_AN_OBJECT.values()],
                         ids=[*(f"read: {k}" for k in READS_OUTSIDE_THE_CORE),
                              *(f"module read: {k}" for k in READS_OF_A_MODULE),
                              *(f"object write: {k}" for k in WRITES_INTO_AN_OBJECT)])
def test_CONTROL_a_use_that_changes_no_guard_keeps_the_guards(tmp_path, code):
    rc, report = gate(build(tmp_path, {"core.py": _HONEST_CORE, "demo.py": code}))
    assert report["measured"]["type_checking_changed_by"] == [], report["measured"].get("type_checking_changes")
    assert (rc, report["verdict"], found(report)) == (0, "GREEN", set())


# ── bindings the gate did not resolve: an environment read it reported as nothing ─────────────────────────────────

#: P2 3, the star import, with the neighbours that share its cause: a name bound in another module of the package
#: was not followed there, so `os` resolved to the binding the gate knew in this module.
BINDINGS_FROM_ELSEWHERE = {
    "a star import of the package": (
        'import math as os\nfrom .other import *\nVALUE = os.getenv("X")\n', {"other.py": "import os\n"}),
    "a re-exported module": ('from .other import os\nVALUE = os.getenv("X")\n', {"other.py": "import os\n"}),
    "a re-exported function": (
        'from .other import getenv\nVALUE = getenv("X")\n', {"other.py": "from os import getenv\n"}),
    "a re-export of a re-export": (
        'from .other import read\nVALUE = read("X")\n',
        {"other.py": "from .third import getenv as read\n", "third.py": "from os import getenv\n"}),
    "a star import of the standard library": ('from os import *\nVALUE = getenv("X")\n', {}),
    "a match capture": (
        'import os as _real\nimport math as os\nmatch _real:\n    case os:\n        pass\nVALUE = os.getenv("X")\n',
        {}),
    # Codex on PR 395, P1: a capture inside a sequence pattern, in the module the name is imported from.
    "a nested match capture in another module": (
        'from .other import os\nVALUE = os.getenv("X")\n',
        {"other.py": "import os as real\nmatch [real]:\n    case [os]:\n        pass\n"}),
    "an or-pattern in another module": (
        'from .other import os\nVALUE = os.getenv("X")\n',
        {"other.py": "import os as real\nmatch [real]:\n    case [os] | [_, os]:\n        pass\n"}),
    # Codex on PR 395, round two, P1: a capture inside a mapping pattern, and its neighbours in a mapping.
    "a mapping pattern in another module": (
        'from .other import os\nVALUE = os.getenv("X")\n',
        {"other.py": 'import os as real\nmatch {"k": real}:\n    case {"k": os}:\n        pass\n'}),
    "a mapping pattern that takes the second key": (
        'from .other import os\nVALUE = os.getenv("X")\n',
        {"other.py": 'import os as real\nmatch {"j": 1, "k": real}:\n    case {"k": os}:\n        pass\n'}),
    "a mapping pattern inside a sequence pattern": (
        'from .other import os\nVALUE = os.getenv("X")\n',
        {"other.py": 'import os as real\nmatch [{"k": real}]:\n    case [{"k": os}]:\n        pass\n'}),
    "a mapping pattern whose key a later one replaces": (
        'from .other import os\nVALUE = os.getenv("X")\n',
        {"other.py": 'import math, os as real\nmatch {"k": math, "k": real}:\n    case {"k": os}:\n        pass\n'}),
    "a mapping pattern whose key is equal under another spelling": (
        'from .other import os\nVALUE = os.getenv("X")\n',
        {"other.py": 'import os as real\nmatch {1: real}:\n    case {True: os}:\n        pass\n'}),
}


@pytest.mark.parametrize("case", list(BINDINGS_FROM_ELSEWHERE.values()), ids=list(BINDINGS_FROM_ELSEWHERE))
def test_RED_a_name_bound_elsewhere_is_resolved_where_it_was_bound(tmp_path, case):
    code, extra = case
    listed = ("probepkg", "probepkg.core", *(f"probepkg.{n[:-3]}" for n in extra))
    args = build(tmp_path, {"core.py": code, **extra}, listed=listed)
    assert run_core(tmp_path, "import probepkg.core as c; print(c.VALUE)") == "TEST_ONLY"
    rc, report = gate(args)
    assert (rc, report["verdict"]) == (1, "RED"), report["measured"]["findings"]
    assert ("environment", "os.getenv") in {(f["rule"], f["operation"]) for f in report["measured"]["findings"]
                                            if f["module"] == "probepkg.core"}


_LOCAL_READER = "class _Reader:\n    @staticmethod\n    def getenv(key):\n        return key\n{name} = _Reader\n"

#: Without `__all__` a star import binds no name that starts with an underscore, and with `__all__` only the names it
#: lists. In both cases the other module binds the name to `os`, so a star import that bound it would read the
#: environment; it does not, the run reads the local class.
STAR_IMPORTS_THAT_DO_NOT_BIND = {
    "a private name": (_LOCAL_READER.format(name="_m") + 'from .other import *\nVALUE = _m.getenv("X")\n',
                       {"other.py": "import os as _m\n"}),
    "a name outside __all__": (_LOCAL_READER.format(name="dropped")
                               + 'from .other import *\nVALUE = dropped.getenv("X")\n',
                               {"other.py": "__all__ = ['kept']\nimport os as dropped\nkept = 1\n"}),
}


#: The other direction of the mapping pattern: a capture binds the value of its own key, not every value of the subject.
#: The key named in the pattern holds a local class, so the run reads no environment and the gate stays green.
MAPPING_CAPTURES_OF_ANOTHER_KEY = {
    "a mapping pattern that takes a local class": (
        'from .other import os\nVALUE = os.getenv("X")\n',
        {"other.py": _LOCAL_READER.format(name="_r")
         + 'import os as real\nmatch {"k": real, "j": _r}:\n    case {"j": os}:\n        pass\n'}),
}


@pytest.mark.parametrize("case", list(MAPPING_CAPTURES_OF_ANOTHER_KEY.values()), ids=list(MAPPING_CAPTURES_OF_ANOTHER_KEY))
def test_CONTROL_a_mapping_capture_binds_the_value_of_its_key(tmp_path, case):
    code, extra = case
    args = build(tmp_path, {"core.py": code, **extra}, listed=("probepkg", "probepkg.core", "probepkg.other"))
    assert run_core(tmp_path, "import probepkg.core as c; print(c.VALUE)") == "X"
    rc, report = gate(args)
    assert (rc, report["verdict"], found(report)) == (0, "GREEN", set()), report["measured"]["findings"]


@pytest.mark.parametrize("case", list(STAR_IMPORTS_THAT_DO_NOT_BIND.values()), ids=list(STAR_IMPORTS_THAT_DO_NOT_BIND))
def test_CONTROL_a_star_import_binds_only_what_its_module_exports(tmp_path, case):
    code, extra = case
    args = build(tmp_path, {"core.py": code, **extra}, listed=("probepkg", "probepkg.core", "probepkg.other"))
    assert run_core(tmp_path, "import probepkg.core as c; print(c.VALUE)") == "X"
    rc, report = gate(args)
    assert (rc, report["verdict"], found(report)) == (0, "GREEN", set()), report["measured"]["findings"]


def test_CONTROL_a_harmless_re_export_stays_green(tmp_path):
    rc, report = gate(build(tmp_path, {"core.py": "from .other import cos\nVALUE = cos(0)\n",
                                       "other.py": "from math import cos\n"},
                            listed=("probepkg", "probepkg.core", "probepkg.other")))
    assert (rc, report["verdict"], found(report)) == (0, "GREEN", set())


# ── the same spellings inside the core: dynamic access the gate did not count ──────────────────────────────────────

#: Neighbours in `findings_of`: a namespace reached through getattr or `__getattribute__` is dynamic access as
#: `x.__dict__` is, a name the gate cannot read is a finding whichever spelling carries it, and an attribute function
#: handed on as a value is a call the gate cannot see.
DYNAMIC_SPELLINGS = {
    "getattr __dict__": ('def f(x):\n    return getattr(x, "__dict__")\n', ".__dict__"),
    "object.__getattribute__ __dict__": ('def f(x):\n    return object.__getattribute__(x, "__dict__")\n',
                                        ".__dict__"),
    "a namespace replaced": ("def f(x, d):\n    x.__dict__ = d\n", ".__dict__"),
    "a method of a namespace": ('def f(x):\n    return x.__dict__.get("a")\n', ".__dict__"),
    "a file method through __getattribute__": (
        'from pathlib import Path\ndef f(p):\n    return object.__getattribute__(Path(p), "read_bytes")()\n',
        ".read_bytes"),
    "__getattribute__ with a computed name": (
        "def f(x, n):\n    return x.__getattribute__(n)\n", "__getattribute__(computed name)"),
    "object.__setattr__ with a computed name": (
        "def f(x, n, v):\n    object.__setattr__(x, n, v)\n", "__setattr__(computed name)"),
    "getattr with a starred name": ("def f(pair):\n    return getattr(*pair)\n", "getattr(computed name)"),
    "getattr handed on as a value": (
        "import functools\ndef f(x):\n    return functools.partial(getattr, x)\n", "getattr(as a value)"),
}


@pytest.mark.parametrize("case", list(DYNAMIC_SPELLINGS.values()), ids=list(DYNAMIC_SPELLINGS))
def test_RED_every_spelling_of_dynamic_access_in_the_core_is_a_finding(tmp_path, case):
    code, operation = case
    rc, report = gate(build(tmp_path, {"core.py": code}))
    assert rc == 1
    assert (("file" if operation == ".read_bytes" else "dynamic_access"), operation) in found(report), \
        report["measured"]["findings"]


def test_CONTROL_a_literal_setter_on_the_object_itself_is_no_finding(tmp_path):
    rc, report = gate(build(tmp_path, {"core.py": 'class C:\n    def __init__(self, v):\n'
                                                  '        object.__setattr__(self, "v", v)\n'
                                                  '        hasattr(self, "__dict__")\n'}))
    assert (rc, report["verdict"], found(report)) == (0, "GREEN", set())


# ── the lens on the first fix (one iteration, targets set in advance) ──────────────────────────────────────────────

#: Writes the first fix did not see. The check whether an object may be a module was a list of module spellings, so
#: a module reached any other way counted as no module; at 4490fbda a `setattr` with a computed name counted on any
#: object, so those forms are a regression of the first fix. Each one runs the guarded block.
FOUND_BY_THE_LENS = {
    "a dotted name for a patch helper": _MODULE_GUARD.format(
        'import unittest.mock\nunittest.mock.patch("typing.TYPE_CHECKING", True).start()'),
    "a function's __globals__": _MODULE_GUARD.format(_NAME + "typing.cast.__globals__[name] = True"),
    "the module's own function's __globals__": _BARE_GUARD.format(
        _NAME + "def _f():\n    pass\n_f.__globals__[name] = True"),
    "a frame's f_globals": _BARE_GUARD.format(_NAME + "import sys\nsys._getframe().f_globals[name] = True"),
    "__getattribute__ taken as a value": _MODULE_GUARD.format(
        _NAME + 'g = typing.__getattribute__\ng("__dict__")[name] = True'),
    "__dict__ imported from the module": _MODULE_GUARD.format(
        _NAME + "from typing import __dict__ as ns\nns[name] = True"),
    "__setattr__ imported from the module": _MODULE_GUARD.format(
        _NAME + "from typing import __setattr__ as put\nput(name, True)"),
    "__setattr__ through __call__": _MODULE_GUARD.format(_NAME + "typing.__setattr__.__call__(name, True)"),
    "a module through os.sys.modules": _MODULE_GUARD.format(
        _NAME + 'import os\nsetattr(os.sys.modules["typing"], name, True)'),
    "a module through getattr(sys, 'modules')": _MODULE_GUARD.format(
        _NAME + 'import sys\nsetattr(getattr(sys, "modules")["typing"], name, True)'),
    "a module through inspect.getmodule": _MODULE_GUARD.format(
        _NAME + "import inspect\nsetattr(inspect.getmodule(typing.Any), name, True)"),
    "a module held by a class attribute": _MODULE_GUARD.format(
        _NAME + "class _Holder:\n    m = typing\nsetattr(_Holder.m, name, True)"),
    "a module through pkgutil.resolve_name": _MODULE_GUARD.format(
        _NAME + 'import pkgutil\nsetattr(pkgutil.resolve_name("typing"), name, True)'),
    "the typing entry of sys.modules replaced": (
        "import sys\nclass _Flag:\n    TYPE_CHECKING = True\nsys.modules['typing'] = _Flag\nimport typing\n"
        "if typing.TYPE_CHECKING:\n    import subprocess\n"),
}


@pytest.mark.parametrize("code", list(FOUND_BY_THE_LENS.values()), ids=list(FOUND_BY_THE_LENS))
def test_RED_a_write_the_lens_found_is_seen(tmp_path, code):
    args = build(tmp_path, {"core.py": code})
    assert run_core(tmp_path, _RUNS_THE_BLOCK) == "True"
    rc, report = gate(args)
    assert (rc, report["verdict"]) == (1, "RED"), report["measured"]["findings"]
    assert ("subprocess", "import subprocess") in found(report)
    assert report["measured"]["type_checking_changed_by"] == ["probepkg.core"]


#: False alarms of the first fix the lens measured: reads of the typing module and strings that only test.
READS_THE_LENS_FOUND = {
    "dir() of the module": "import typing\ndef _p():\n    return dir(typing)\n",
    "a truth test of the module": "import typing\ndef _p():\n    if typing:\n        return 1\n",
    "a truth test of sys.modules.get": "import sys\ndef _p():\n    if sys.modules.get('typing'):\n        return 1\n",
    "inspect.getmembers of the module": "import inspect, typing\ndef _p():\n    return inspect.getmembers(typing)\n",
    "a string method on the name": "def _p(s):\n    return s.startswith('TYPE_CHECKING')\n",
    "a dict union with a module's namespace": "import json\ndef _p(extra):\n    return vars(json) | extra\n",
    "a module's namespace formatted": "import json\ndef _p():\n    return '%s' % vars(json)\n",
    "the names of a module joined": "import json\ndef _p():\n    return ','.join(vars(json))\n",
    "the names of a module yielded": "import json\ndef _p():\n    yield from vars(json)\n",
    "a read-only view of a module's namespace": (
        "import json, types\ndef _p():\n    return types.MappingProxyType(vars(json))\n"),
    # Codex on PR 395, P2: the flag's name as data writes nothing.
    "the name as a key of a dict that stays": "CONFIG = {'TYPE_CHECKING': False}\n",
    "the name as a keyword of an unknown call": "def _p(configure):\n    return configure(TYPE_CHECKING=False)\n",
    "the name in a list": "RESERVED = ['TYPE_CHECKING', 'Any']\n",
    "the name handed to a logger": "def _p(log):\n    log('TYPE_CHECKING')\n",
    # Codex on PR 395, round two, P2: a dotted name handed to a call that only reads or formats it writes nothing.
    "a dotted name handed to print": 'print("typing.TYPE_CHECKING")\n',
    "a dotted name handed to json.dumps": "import json\ndef _p():\n    return json.dumps('typing.TYPE_CHECKING')\n",
    "a dotted name formatted by a literal": "def _p():\n    return 'flag {}'.format('typing.TYPE_CHECKING')\n",
    "a dotted name handed to logging": "import logging\ndef _p():\n    logging.info('typing.TYPE_CHECKING')\n",
    "a dotted name handed to warnings.warn": "import warnings\ndef _p():\n    warnings.warn('typing:TYPE_CHECKING')\n",
}

#: Forms that count ON PURPOSE: the gate cannot show the object is no module, or does not see where a setter goes.
#: Each one turns the guards off, as a write with a computed name on any object did at 4490fbda.
COUNTS_ON_PURPOSE = {
    "setattr with a computed name on a parameter": "def put(obj, k, v):\n    setattr(obj, k, v)\n",
    "the namespace of a parameter filled by name": (
        "def fill(target, items):\n    own = object.__getattribute__(target, \"__dict__\")\n"
        "    for k, v in items:\n        own[k] = v\n"),
    "setattr handed to a callback": "def t(self, mod):\n    self.addCleanup(setattr, mod, 'yaml', 1)\n",
    "the flag written into a parameter by name": "def put(m):\n    m['TYPE_CHECKING'] = True\n",
    "the flag as a keyword of an update": "def put(m):\n    m.update(TYPE_CHECKING=True)\n",
    "the flag as a key of an update": "def put(m):\n    m.update({'TYPE_CHECKING': True})\n",
    "setattr on an imported object": "from .settings import config\ndef put(k, v):\n    setattr(config, k, v)\n",
    # The reader of round two is resolved, not matched by spelling: a parameter's method and a print the module
    # defines itself may set what the dotted name says.
    "a dotted name handed to a parameter's method": (
        "def t(monkeypatch):\n    monkeypatch.setattr('typing.TYPE_CHECKING', True)\n"),
    "a dotted name handed to a print the module defines": (
        "import unittest.mock\ndef print(target):\n    unittest.mock.patch(target, True).start()\n"
        "print('typing.TYPE_CHECKING')\n"),
    "a dotted name handed to a logging the module rebinds": (
        "import unittest.mock as logging\ndef _p():\n    logging.patch('typing.TYPE_CHECKING', True).start()\n"),
}


@pytest.mark.parametrize("code", list(READS_THE_LENS_FOUND.values()), ids=list(READS_THE_LENS_FOUND))
def test_CONTROL_a_read_the_lens_found_keeps_the_guards(tmp_path, code):
    rc, report = gate(build(tmp_path, {"core.py": _HONEST_CORE, "demo.py": code}))
    assert report["measured"]["type_checking_changed_by"] == [], report["measured"].get("type_checking_changes")
    assert (rc, report["verdict"], found(report)) == (0, "GREEN", set())


@pytest.mark.parametrize("code", list(COUNTS_ON_PURPOSE.values()), ids=list(COUNTS_ON_PURPOSE))
def test_RED_a_form_the_gate_cannot_place_counts_as_a_change(tmp_path, code):
    rc, report = gate(build(tmp_path, {"core.py": _HONEST_CORE, "demo.py": code, "settings.py": "config = 1\n"}))
    assert report["measured"]["type_checking_changed_by"] == ["probepkg.demo"]
    assert (rc, report["verdict"]) == (1, "RED")


# ── a change of the guard reviewed by name ─────────────────────────────────────────────────────────────────────────

_REVIEWED_FORM = "a namespace that may be a module's, used other than by reading"
_FILL = COUNTS_ON_PURPOSE["the namespace of a parameter filled by name"]


def _review(count=1, reason="fills the namespace of objects this module builds; no module is ever a target",
            form=_REVIEWED_FORM):
    entry = {"module": "probepkg.demo", "form": form, "count": count}
    if reason is not None:
        entry["reason"] = reason
    return [entry]


def test_CONTROL_a_reviewed_change_keeps_the_guards(tmp_path):
    rc, report = gate(build(tmp_path, {"core.py": _HONEST_CORE, "demo.py": _FILL}, reviewed=_review()))
    assert report["measured"]["type_checking_changed_by"] == []
    assert [r["module"] for r in report["measured"]["type_checking_reviewed"]] == ["probepkg.demo"]
    assert (rc, report["verdict"], found(report)) == (0, "GREEN", set())


@pytest.mark.parametrize("kind", ["one occurrence more than reviewed", "a reviewed form that is gone"])
def test_RED_a_review_that_does_not_match_is_red(tmp_path, kind):
    code = _FILL + _FILL.replace("def fill", "def fill_again") if kind.startswith("one") else _HONEST_CORE
    rc, report = gate(build(tmp_path, {"core.py": _HONEST_CORE, "demo.py": code}, reviewed=_review()))
    assert (rc, report["verdict"]) == (1, "RED")
    assert report["stale_reviewed_changes"], report
    if kind.startswith("one"):
        assert report["measured"]["type_checking_changed_by"] == ["probepkg.demo"]


@pytest.mark.parametrize("entry", [_review(reason=None), _review(reason="  "), _review(count=0)],
                         ids=["no reason", "a blank reason", "count 0"])
def test_a_review_without_a_reason_or_a_count_is_not_measurable(tmp_path, entry):
    rc, report = gate(build(tmp_path, {"core.py": _HONEST_CORE, "demo.py": _FILL}, reviewed=entry))
    assert (rc, report["verdict"]) == (2, "NOT_MEASURABLE")


def test_the_one_reviewed_change_of_the_package_is_canonical_with_its_reason():
    spec = json.loads((ROOT / "scripts" / "core_layer_modules.json").read_text(encoding="utf-8"))
    reviewed = spec.get("type_checking_reviewed", [])
    assert [(e["module"], e["count"]) for e in reviewed] == [("proofbundle.canonical", 1)]
    assert "object.__new__" in reviewed[0]["reason"] and "no module" in reviewed[0]["reason"].lower()


# ── the reading itself: star imports, depth, time, `__call__` ──────────────────────────────────────────────────────

#: A star import credited every public name to its module, so a receiver it does not bind counted as resolved and
#: the file finding of an unresolved receiver was lost (the lens, G-2).
STAR_IMPORTS_THAT_BIND_NOTHING = {
    "a module of the package": ({"core.py": "from .other import *\nhandle = make()\nhandle.read()\n",
                                 "other.py": "def make():\n    return None\n"}, ("file", ".read")),
    "the standard library": ({"core.py": "from math import *\nhandle = cos(0)\nhandle.read_bytes()\n"},
                             ("file", ".read_bytes")),
}


@pytest.mark.parametrize("case", list(STAR_IMPORTS_THAT_BIND_NOTHING.values()), ids=list(STAR_IMPORTS_THAT_BIND_NOTHING))
def test_RED_a_star_import_does_not_resolve_a_receiver_it_does_not_bind(tmp_path, case):
    files, finding = case
    listed = ("probepkg", "probepkg.core", *(f"probepkg.{n[:-3]}" for n in files if n != "core.py"))
    rc, report = gate(build(tmp_path, files, listed=listed))
    assert finding in found(report), report["measured"]["findings"]


def test_CONTROL_a_long_expression_outside_the_core_is_read(tmp_path):
    """1200 terms imported and ran; the reading of names recursed once per term and crashed (the lens, G-3)."""
    long = "X = " + " + ".join(["1"] * 1200) + "\n"
    rc, report = gate(build(tmp_path, {"core.py": _HONEST_CORE, "demo.py": long}))
    assert (rc, report["verdict"]) == (0, "GREEN"), report


def test_CONTROL_chains_of_reassigned_names_are_judged_in_time(tmp_path):
    """Each name judged once. The lens measured eight names, each assigned eight times from the next, at 28.8 s on the
    first fix, which followed every assignment again on every path (G-4)."""
    import time
    lines = ["def f(k, v, make):"] + [f"    n{i} = {f'n{i + 1}' if i < 7 else 'make()'}" for i in range(8)
                                      for _ in range(8)] + ["    setattr(n0, k, v)"]
    start = time.monotonic()
    rc, report = gate(build(tmp_path, {"core.py": _HONEST_CORE, "demo.py": "\n".join(lines) + "\n"}))
    assert time.monotonic() - start < 20
    assert report["verdict"] in ("GREEN", "RED")


def test_RED_an_attribute_function_called_through___call___is_judged(tmp_path):
    rc, report = gate(build(tmp_path, {"core.py": 'import os\ndef f():\n    return getattr.__call__(os, "environ")\n'}))
    assert ("environment", "os.environ") in found(report), report["measured"]["findings"]


def test_RED_a_frame_namespace_in_the_core_is_dynamic_access(tmp_path):
    rc, report = gate(build(tmp_path, {"core.py": "def f(frame):\n    return frame.f_globals.get('__name__')\n"}))
    assert ("dynamic_access", ".f_globals") in found(report)
