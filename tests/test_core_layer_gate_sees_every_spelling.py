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
    # F7 of the counter-reading of pull request 395: a union with an operand the gate does not know hands the namespace to
    # that operand's `__ror__`. A read of the lens on the first fix until then; the union with a dict written out stays one.
    "a dict union with a module's namespace and a parameter": "import json\ndef _p(extra):\n    return vars(json) | extra\n",
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
            form=_REVIEWED_FORM, source=('own = object.__getattribute__(target, "__dict__")',)):
    entry = {"module": "probepkg.demo", "form": form, "count": count, "source": list(source)}
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


# ── the counter-reading of 159c75dd (one lens, targets set in advance): bindings Python makes and the gate did not ──

#: F1, F2, F3 and F5 of that reading: each core reads the environment through a binding Python makes, and the gate
#: resolved the name against another scope or not at all. Each one runs first and returns the test value.
BINDINGS_PYTHON_MAKES = {
    "F1 an assignment under nonlocal": (
        "import os\ndef outer():\n    o = None\n    def inner():\n        nonlocal o\n        o = os\n"
        "    inner()\n    return o.getenv('X')\nVALUE = outer()\n", ("environment", "os.getenv")),
    "F1 an import under nonlocal": (
        "def outer():\n    o = None\n    def inner():\n        nonlocal o\n        import os as o\n"
        "    inner()\n    return o.getenv('X')\nVALUE = outer()\n", ("environment", "os.getenv")),
    "F1 nonlocal through two functions": (
        "import os\ndef outer():\n    def middle():\n        def inner():\n            nonlocal o\n            o = os\n"
        "        inner()\n    middle()\n    return o.getenv('X')\n    o = None\nVALUE = None\n"
        "def run():\n    return outer()\n", ("environment", "os.getenv")),
    "F2 a walrus in a list comprehension": (
        "import os\n[(o := os) for _ in [0]]\nVALUE = o.getenv('X')\n", ("environment", "os.getenv")),
    "F2 a walrus in a generator in a function": (
        "import os\ndef f():\n    any((o := os) for _ in [0])\n    return o.getenv('X')\nVALUE = f()\n",
        ("environment", "os.getenv")),
    "F3 a literal getattr in a chain": (
        "import os\nVALUE = getattr(os, 'path').expandvars('$X')\n", ("environment", "os.path.expandvars")),
    "F3 two literal getattrs": (
        "import os\nVALUE = getattr(getattr(os, 'path'), 'expandvars')('$X')\n",
        ("environment", "os.path.expandvars")),
    "F3 a bound __getattribute__": (
        "import os\nVALUE = os.__getattribute__('path').expandvars('$X')\n", ("environment", "os.path.expandvars")),
    "F3 object.__getattribute__": (
        "import os\nVALUE = object.__getattribute__(os, 'path').expandvars('$X')\n",
        ("environment", "os.path.expandvars")),
    "F5 an annotation under a local alias": (
        "def outer():\n    import os as o\n    def inner(x: o.getenv('X')):\n        pass\n"
        "    return inner.__annotations__['x']\nVALUE = outer()\n", ("environment", "os.getenv")),
    # The second reading, on 7046cbfb (F-A, P1): the binding went to the right scope, its value was read in that
    # scope too, where a name only the inner function binds is nothing.
    "F-A a lazy import under global": (
        "_os = None\ndef _load():\n    global _os\n    import os\n    _os = os\ndef read():\n    _load()\n"
        "    return _os.getenv('X')\nVALUE = read()\n", ("environment", "os.getenv")),
    "F-A a local import under nonlocal": (
        "def outer():\n    o = None\n    def inner():\n        nonlocal o\n        import os\n        o = os\n"
        "    inner()\n    return o.getenv('X')\nVALUE = outer()\n", ("environment", "os.getenv")),
    "F-A an alias chain through global": (
        "import os\ndef outer():\n    global g\n    o = None\n    def inner():\n        nonlocal o\n        o = os\n"
        "    inner()\n    g = o\nouter()\nVALUE = g.getenv('X')\n", ("environment", "os.getenv")),
}


@pytest.mark.parametrize("case", list(BINDINGS_PYTHON_MAKES.values()), ids=list(BINDINGS_PYTHON_MAKES))
def test_RED_a_binding_python_makes_is_resolved_where_python_makes_it(tmp_path, case):
    code, finding = case
    args = build(tmp_path, {"core.py": code})
    probe = "import probepkg.core as c; print(c.run() if c.VALUE is None else c.VALUE)"
    assert run_core(tmp_path, probe) == "TEST_ONLY"
    rc, report = gate(args)
    assert (rc, report["verdict"]) == (1, "RED"), report["measured"]["findings"]
    assert finding in found(report), report["measured"]["findings"]


#: F1, F2 and F4 on the guard: each one runs the type-checking block, and the gate kept the guard.
GUARD_WRITES_THE_READING_FOUND = {
    "F1 the module bound under nonlocal": _MODULE_GUARD.format(
        _NAME + "def outer():\n    m = 1\n    def inner():\n        nonlocal m\n        m = typing\n"
        "    inner()\n    setattr(m, name, True)\nouter()"),
    "F2 the module bound by a walrus in a comprehension": _MODULE_GUARD.format(
        _NAME + "import inspect\nm = 1\n[(m := inspect.getmodule(typing.Any)) for _ in [0]]\nsetattr(m, name, True)"),
}


@pytest.mark.parametrize("code", list(GUARD_WRITES_THE_READING_FOUND.values()), ids=list(GUARD_WRITES_THE_READING_FOUND))
def test_RED_a_guard_write_through_a_binding_python_makes_is_seen(tmp_path, code):
    args = build(tmp_path, {"core.py": code})
    assert run_core(tmp_path, _RUNS_THE_BLOCK) == "True"
    rc, report = gate(args)
    assert (rc, report["verdict"]) == (1, "RED"), report["measured"]["findings"]
    assert ("subprocess", "import subprocess") in found(report)
    assert report["measured"]["type_checking_changed_by"] == ["probepkg.core"]


def test_RED_a_parameter_re_bound_only_when_it_is_None_may_still_be_a_module(tmp_path):
    """F4 of the reading, in its own form: the helper is in one module and the caller hands it the typing module from
    another, by a call the gate does not read as typing, so only the parameter can carry the finding. `if m is None:
    m = {}` made the parameter "no module" and the helper's write by a computed name counted as nothing."""
    files = {"core.py": _HONEST_CORE,
             "util.py": "def put(m, n):\n    if m is None:\n        m = {}\n    setattr(m, n, True)\n",
             "other.py": "import inspect, typing\nfrom .util import put\nput(inspect.getmodule(typing.Any), 'TYPE_' + 'CHECKING')\n"}
    args = build(tmp_path, files)
    assert run_core(tmp_path, "import probepkg.other\n" + _RUNS_THE_BLOCK) == "True"
    rc, report = gate(args)
    assert (rc, report["verdict"]) == (1, "RED"), report["measured"]["findings"]
    assert "probepkg.util" in report["measured"]["type_checking_changed_by"]


#: Codex on 395, round three, P1: the default of a three-argument getattr is a possible result. At bb0b163f the call
#: read as `x.name` alone, so its receiver counted as resolved; the base gate of main found the first one.
GETATTR_DEFAULTS = {
    "an unresolved default before a file method": (
        "import math\ndef read(handle):\n    return getattr(math, 'missing', handle).read()\n", ("file", ".read")),
    "a module as the default": (
        "import os\nVALUE = getattr(os, 'missing_attribute', os.path).expandvars('$X')\n",
        ("environment", "os.path.expandvars")),
    # Codex on 395, round four, P1: an unresolved default keeps the known result beside it; at c3eb4c09 it erased it.
    "None as the default keeps the attribute": (
        "import os\nVALUE = getattr(os, 'path', None).abspath('.')\n", ("environment", "os.path.abspath")),
    "None as the default keeps the clock": (
        "import datetime\nVALUE = getattr(datetime, 'datetime', None).now()\n", ("clock", "datetime.datetime.now")),
    # Codex on 395, round five, P1: an unknown receiver keeps the marker beside a known default; at ba4bee28 the
    # known `math` was the only result, and the file finding of main was lost.
    "an unknown receiver with a known default": (
        "import math\ndef read(holder):\n    return getattr(holder, 'stream', math).read()\n", ("file", ".read")),
    # The sibling the same round names: the environment methods ask the same receiver question.
    "an unknown receiver with a known default before an environment method": (
        "import math\ndef where(holder):\n    return getattr(holder, 'path', math).resolve()\n",
        ("environment", ".resolve")),
}


@pytest.mark.parametrize("case", list(GETATTR_DEFAULTS.values()), ids=list(GETATTR_DEFAULTS))
def test_RED_the_default_of_a_getattr_is_a_possible_result(tmp_path, case):
    code, finding = case
    rc, report = gate(build(tmp_path, {"core.py": code}))
    assert (rc, report["verdict"]) == (1, "RED"), report["measured"]["findings"]
    assert finding in found(report), report["measured"]["findings"]


#: Codex on 395, round three, P2: a reader that another module of the package imports stays a reader. At bb0b163f the
#: package name it came through stood beside it, so `print("typing.TYPE_CHECKING")` counted as a write and turned the
#: guards off; the base gate of main stayed green. The guard is held in the findings and in the import closure.
READERS_THROUGH_THE_PACKAGE = {
    "print re-exported, the guarded import": (
        {"core.py": "from .other import print\nfrom typing import TYPE_CHECKING\nprint('typing.TYPE_CHECKING')\n"
                    "if TYPE_CHECKING:\n    import subprocess\n",
         "other.py": "from builtins import print\n"}, ("probepkg", "probepkg.core", "probepkg.other")),
    "json.dumps re-exported, the guarded import": (
        {"core.py": "from .other import dumps\nfrom typing import TYPE_CHECKING\nVALUE = dumps('typing.TYPE_CHECKING')\n"
                    "if TYPE_CHECKING:\n    import subprocess\n",
         "other.py": "from json import dumps\n"}, ("probepkg", "probepkg.core", "probepkg.other")),
    "print re-exported, a guarded module of the package": (
        {"core.py": "from .other import print\nfrom typing import TYPE_CHECKING\nprint('typing.TYPE_CHECKING')\n"
                    "if TYPE_CHECKING:\n    from . import extra\n",
         "other.py": "from builtins import print\n", "extra.py": "X = 1\n"}, ("probepkg", "probepkg.core", "probepkg.other")),
}


@pytest.mark.parametrize("case", list(READERS_THROUGH_THE_PACKAGE.values()), ids=list(READERS_THROUGH_THE_PACKAGE))
def test_CONTROL_a_reader_imported_through_the_package_keeps_the_guards(tmp_path, case):
    files, listed = case
    rc, report = gate(build(tmp_path, files, listed=listed))
    assert report["measured"]["type_checking_changed_by"] == [], report["measured"].get("type_checking_changes")
    assert (rc, report["verdict"], found(report), report["core_list_new"]) == (0, "GREEN", set(), []), report


#: The other direction in the core: the same bindings to an object that reads nothing make no finding.
BINDINGS_THAT_READ_NOTHING = {
    "a literal getattr with a harmless default": "import math\nVALUE = getattr(math, 'tau', math.pi)\n",
    "nonlocal to a builtin": (
        "def outer():\n    o = None\n    def inner():\n        nonlocal o\n        o = len\n    inner()\n"
        "    return o('ab')\nVALUE = outer()\n"),
    "a walrus in a comprehension to a builtin": "[(o := len) for _ in [0]]\nVALUE = o('ab')\n",
    "a literal getattr of a harmless name": "import math\nVALUE = getattr(math, 'pi')\n",
}


@pytest.mark.parametrize("code", list(BINDINGS_THAT_READ_NOTHING.values()), ids=list(BINDINGS_THAT_READ_NOTHING))
def test_CONTROL_a_binding_python_makes_to_a_harmless_object_stays_green(tmp_path, code):
    rc, report = gate(build(tmp_path, {"core.py": _HONEST_CORE + code}))
    assert (rc, report["verdict"], found(report)) == (0, "GREEN", set()), report["measured"]["findings"]


@pytest.mark.parametrize("chain", [
    "".join(["os"] + [".__getattribute__(os, 'a')"] * 20),
    "".join(["os"] + [".__getattribute__('a')"] * 1500),
], ids=["twenty two-argument __getattribute__ calls", "1500 one-argument __getattribute__ calls"])
def test_CONTROL_a_chain_of_literal_attribute_reads_is_read_in_time(tmp_path, chain):
    """F-E of the second reading: the literal attribute read of 7046cbfb resolved the receiver of a two-argument
    `__getattribute__` twice, once as a possible getattr and once as the class, so each link doubled the work (twenty
    links took 69 s), and every call of a chain resolved the chain below it again (1500 links, 63 s)."""
    import time
    start = time.monotonic()
    rc, report = gate(build(tmp_path, {"core.py": _HONEST_CORE + f"import os\nx = {chain}\n"}))
    assert time.monotonic() - start < 20
    assert report["verdict"] in ("GREEN", "RED")


def test_CONTROL_a_method_that_re_binds_self_keeps_the_guards(tmp_path):
    """F4's limit: the first parameter of a method stays no module, also where the method re-binds it to an object of
    its own class, so a method that fills its own object by name turns no guard off."""
    demo = ("class C:\n    def set(self, k, v):\n        if k is None:\n            self = C()\n"
            "        object.__setattr__(self, k, v)\n")
    rc, report = gate(build(tmp_path, {"core.py": _HONEST_CORE, "demo.py": demo}))
    assert report["measured"]["type_checking_changed_by"] == [], report["measured"].get("type_checking_changes")
    assert (rc, report["verdict"], found(report)) == (0, "GREEN", set())


# ── the follow-up of the first counter-reading of pull request 395 (report at 159c75dd): F6 to F15 ───────────────────

_RUNS_AFTER_DEMO = "import probepkg.demo\n" + _RUNS_THE_BLOCK

#: F6 (P2): a dotted name for a patch helper that is not one literal. Each one runs the guarded block.
DOTTED_NAMES_BUILT_FROM_CONSTANTS = {
    "a name bound to the literal": (
        {"demo.py": "import unittest.mock\nTARGET = 'typing.TYPE_CHECKING'\nunittest.mock.patch(TARGET, True).start()\n"}),
    "a concatenation": (
        {"demo.py": "import unittest.mock\nunittest.mock.patch('typing.' + 'TYPE_CHECKING', True).start()\n"}),
    "a join of literals": (
        {"demo.py": "import unittest.mock\nunittest.mock.patch('.'.join(['typing', 'TYPE_CHECKING']), True).start()\n"}),
    "an f-string over a bound literal": (
        {"demo.py": "import unittest.mock\nflag = 'TYPE_CHECKING'\nunittest.mock.patch(f'typing.{flag}', True).start()\n"}),
    "a literal bound in another module": (
        {"demo.py": "import unittest.mock\nfrom .consts import TARGET\nunittest.mock.patch(TARGET, True).start()\n",
         "consts.py": "TARGET = 'typing.TYPE_CHECKING'\n"}),
}


@pytest.mark.parametrize("files", list(DOTTED_NAMES_BUILT_FROM_CONSTANTS.values()),
                         ids=list(DOTTED_NAMES_BUILT_FROM_CONSTANTS))
def test_RED_F6_a_dotted_name_built_from_constants_names_the_flag(tmp_path, files):
    args = build(tmp_path, {"core.py": _HONEST_CORE, **files})
    assert run_core(tmp_path, _RUNS_AFTER_DEMO) == "True"
    rc, report = gate(args)
    assert (rc, report["verdict"]) == (1, "RED"), report["measured"].get("type_checking_changes")
    assert "probepkg.demo" in report["measured"]["type_checking_changed_by"]


def test_CONTROL_F6_a_dotted_name_built_from_other_constants_writes_nothing(tmp_path):
    demo = ("import unittest.mock\nTARGET = 'json.' + 'dumps'\ndef _p():\n    return unittest.mock.patch(TARGET)\n"
            "NAMES = '.'.join(['typing', 'Any'])\n")
    rc, report = gate(build(tmp_path, {"core.py": _HONEST_CORE, "demo.py": demo}))
    assert report["measured"]["type_checking_changed_by"] == [], report["measured"].get("type_checking_changes")
    assert (rc, report["verdict"], found(report)) == (0, "GREEN", set())


_W = ("import typing\nname = 'TYPE_' + 'CHECKING'\nclass W:\n"
      "    def __eq__(self, other):\n        other[name] = True\n        return True\n"
      "    def __or__(self, other):\n        other[name] = True\n        return other\n"
      "    __ror__ = __or__\n    __hash__ = None\n")

#: F7 (a) (P2): an operand with operators of its own receives the namespace; the operator builds nothing new there.
OPERATORS_OF_THE_OTHER_OPERAND = {
    "== with a class of the module": _W + "W() == vars(typing)\n",
    "| with __ror__": _W + "vars(typing) | W()\n",
    "| with __or__ on __dict__": _W + "W() | typing.__dict__\n",
}


@pytest.mark.parametrize("demo", list(OPERATORS_OF_THE_OTHER_OPERAND.values()), ids=list(OPERATORS_OF_THE_OTHER_OPERAND))
def test_RED_F7_an_operator_of_the_other_operand_may_write_the_namespace(tmp_path, demo):
    args = build(tmp_path, {"core.py": _HONEST_CORE, "demo.py": demo})
    assert run_core(tmp_path, _RUNS_AFTER_DEMO) == "True"
    rc, report = gate(args)
    assert (rc, report["verdict"]) == (1, "RED"), report["measured"].get("type_checking_changes")
    assert report["measured"]["type_checking_changed_by"] == ["probepkg.demo"]


#: The other direction of F7 (a): an operand the gate knows builds a new value and hands the namespace to nobody.
OPERATORS_OF_KNOWN_OPERANDS = {
    "a union with a dict written out": "import json\ndef _p():\n    return vars(json) | {'a': 1}\n",
    "a union with a dict a builtin builds": "import json\ndef _p():\n    return vars(json) | dict(a=1)\n",
    "a membership test in the namespace": "import json\ndef _p(x):\n    return x in vars(json)\n",
    "a comparison with a literal": "import json\ndef _p():\n    return vars(json) == {}\n",
}


@pytest.mark.parametrize("demo", list(OPERATORS_OF_KNOWN_OPERANDS.values()), ids=list(OPERATORS_OF_KNOWN_OPERANDS))
def test_CONTROL_F7_an_operator_of_a_known_operand_reads(tmp_path, demo):
    rc, report = gate(build(tmp_path, {"core.py": _HONEST_CORE, "demo.py": demo}))
    assert report["measured"]["type_checking_changed_by"] == [], report["measured"].get("type_checking_changes")
    assert (rc, report["verdict"], found(report)) == (0, "GREEN", set())


_MODULE_BY_CLASS = "import inspect, typing\nname = 'TYPE_' + 'CHECKING'\n"

#: F7 (b) (P2), the limit the CHANGELOG of 7046cbfb names: a class of the module that builds something else than an
#: object of its own.
CLASSES_THAT_BUILD_A_MODULE = {
    "__new__": _MODULE_BY_CLASS + (
        "class C:\n    def __new__(cls):\n        return inspect.getmodule(typing.Any)\n"
        "x = C()\nsetattr(x, name, True)\n"),
    "a metaclass": _MODULE_BY_CLASS + (
        "class M(type):\n    def __call__(cls):\n        return inspect.getmodule(typing.Any)\n"
        "class C(metaclass=M):\n    pass\nx = C()\nsetattr(x, name, True)\n"),
    "a base with __new__": _MODULE_BY_CLASS + (
        "class B:\n    def __new__(cls):\n        return inspect.getmodule(typing.Any)\n"
        "class C(B):\n    pass\nx = C()\nsetattr(x, name, True)\n"),
    "a class decorator": _MODULE_BY_CLASS + (
        "def deco(cls):\n    return lambda: inspect.getmodule(typing.Any)\n"
        "@deco\nclass C:\n    pass\nx = C()\nsetattr(x, name, True)\n"),
}


@pytest.mark.parametrize("demo", list(CLASSES_THAT_BUILD_A_MODULE.values()), ids=list(CLASSES_THAT_BUILD_A_MODULE))
def test_RED_F7_a_class_that_builds_a_module_is_no_proof_of_no_module(tmp_path, demo):
    args = build(tmp_path, {"core.py": _HONEST_CORE, "demo.py": demo})
    assert run_core(tmp_path, _RUNS_AFTER_DEMO) == "True"
    rc, report = gate(args)
    assert (rc, report["verdict"]) == (1, "RED"), report["measured"].get("type_checking_changes")
    assert report["measured"]["type_checking_changed_by"] == ["probepkg.demo"]


def test_CONTROL_F7_a_plain_class_of_the_module_builds_no_module(tmp_path):
    """K3 of the report: a class with no `__new__`, no metaclass, no decorator and a plain base builds its object."""
    demo = ("class B:\n    pass\nclass C(B):\n    def __init__(self):\n        self.v = 1\n"
            "def fill(k, v):\n    c = C()\n    setattr(c, k, v)\n")
    rc, report = gate(build(tmp_path, {"core.py": _HONEST_CORE, "demo.py": demo}))
    assert report["measured"]["type_checking_changed_by"] == [], report["measured"].get("type_checking_changes")
    assert (rc, report["verdict"], found(report)) == (0, "GREEN", set())


def test_RED_F8_a_reviewed_change_is_bound_to_its_source(tmp_path):
    """F8 (P2): the review bound (module, form, count), so the write could be pointed at another object at the same
    count and stay approved. It is bound to the source of each line the form occurs on now."""
    other = _FILL.replace("object.__getattribute__(target,", "object.__getattribute__(__import__('typing'),")
    assert other != _FILL
    rc, report = gate(build(tmp_path, {"core.py": _HONEST_CORE, "demo.py": other}, reviewed=_review()))
    assert (rc, report["verdict"]) == (1, "RED"), report["measured"].get("type_checking_reviewed")
    assert report["stale_reviewed_changes"], report


def test_the_reason_of_the_reviewed_change_names_the_lines_it_stands_on():
    """F8, the text: the reason named canonical.py:739 and :668, one line before the write and the `object.__new__`."""
    spec = json.loads((ROOT / "scripts" / "core_layer_modules.json").read_text(encoding="utf-8"))
    reason = spec["type_checking_reviewed"][0]["reason"]
    lines = (ROOT / "src" / "proofbundle" / "canonical.py").read_text(encoding="utf-8").splitlines()
    import re
    for n in (int(x) for x in re.findall(r"canonical\.py:(\d+)", reason)):
        assert any(word in lines[n - 1] for word in ("__getattribute__", "object.__new__", "_paketklasse")), (
            n, lines[n - 1])


@pytest.mark.parametrize("bad", ["except E, ValueError:\n    pass\n", "x = = 1\n"], ids=["3.14 syntax", "no syntax"])
def test_F9_a_module_outside_the_core_the_gate_cannot_parse_is_not_measurable(tmp_path, bad):
    """F9 (P2): a module outside the core that did not parse was passed over with exit 0 and no trace in the report;
    under another Python it may run and change the guard."""
    rc, report = gate(build(tmp_path, {"core.py": _HONEST_CORE, "demo.py": bad}))
    assert (rc, report["verdict"]) == (2, "NOT_MEASURABLE"), report


@pytest.mark.parametrize("spelling", ["Path('x').cwd()", "Path('x').home()"])
def test_RED_F10_a_listed_directory_read_through_an_instance_is_seen(tmp_path, spelling):
    """F10 (P2): `pathlib.Path.cwd` and `pathlib.Path.home` are listed, the same read through an instance was not."""
    code = f"from pathlib import Path\nVALUE = {spelling}\n"
    args = build(tmp_path, {"core.py": code})
    assert run_core(tmp_path, "import probepkg.core as c; print(c.VALUE.is_absolute())") == "True"
    rc, report = gate(args)
    assert (rc, report["verdict"]) == (1, "RED"), report["measured"]["findings"]
    assert any(rule == "environment" for rule, _ in found(report)), report["measured"]["findings"]


@pytest.mark.parametrize("where", ["core.py", "demo.py"])
def test_F11_a_module_too_deep_for_the_parser_is_not_measurable(tmp_path, where):
    """F11 (P3): `ast.parse` raised RecursionError on a long expression, and the gate stopped with a traceback and
    exit 1 instead of exit 2 with its report."""
    files = {"core.py": _HONEST_CORE, where: "X = " + "+".join(["1"] * 100000) + "\n"}
    rc, report = gate(build(tmp_path, files))
    assert (rc, report["verdict"]) == (2, "NOT_MEASURABLE"), report


def test_RED_F12_a_long_alias_chain_in_reverse_order_is_followed(tmp_path):
    """F12 (P3): the aliases were resolved for eight rounds and then left as they stood, so a chain of nine or more
    assignments written last link first read the environment unseen. The loop runs the chain until it holds."""
    k = 14
    names = " = ".join(f"a{i}" for i in range(k))
    chain = "".join(f"    a{i} = a{i - 1}\n" for i in range(k - 1, 0, -1))
    code = f"import os\n{names} = None\nfor _ in range({k + 2}):\n{chain}    a0 = os\nVALUE = a{k - 1}.getenv('X')\n"
    args = build(tmp_path, {"core.py": code})
    assert run_core(tmp_path, "import probepkg.core as c; print(c.VALUE)") == "TEST_ONLY"
    rc, report = gate(args)
    assert (rc, report["verdict"]) == (1, "RED"), report["measured"]["findings"]
    assert ("environment", "os.getenv") in found(report)


def test_F8_a_review_without_the_source_it_binds_is_not_measurable(tmp_path):
    """F8: the source of each line is part of the review, as the reason is."""
    entry = [{k: v for k, v in _review()[0].items() if k != "source"}]
    rc, report = gate(build(tmp_path, {"core.py": _HONEST_CORE, "demo.py": _FILL}, reviewed=entry))
    assert (rc, report["verdict"]) == (2, "NOT_MEASURABLE")


# ── the follow-up of the second counter-reading of pull request 395 (report at 7046cbfb): F-B, F-C and F-D ───────────

_RUNS_VALUE = "import probepkg.core as c; print(c.VALUE)"
_C = "c = len('a') == 1\n"

#: F-B (P2): the literal attribute read knew fewer spellings than `_attribute_call`, so these reads stood for nothing
#: and the expansion of `$X` read the environment unseen. The first three are the lens's FB-1 to FB-3, the other four
#: the same gap in the spellings `_attribute_call` reads under a name or through `__call__`.
LITERAL_READS_OF_EVERY_SPELLING = {
    "FB-1 getattr through __call__": "import os\nVALUE = getattr.__call__(os, 'path').expandvars('$X')\n",
    "FB-2 the __getattribute__ of type(x)": "import os\nVALUE = type(os).__getattribute__(os, 'path').expandvars('$X')\n",
    "FB-3 the __getattribute__ of ModuleType": (
        "import os\nimport types\nVALUE = types.ModuleType.__getattribute__(os, 'path').expandvars('$X')\n"),
    "a bound __getattribute__ through __call__": "import os\nVALUE = os.__getattribute__.__call__('path').expandvars('$X')\n",
    "a bound __getattribute__ bound to a name": "import os\nga = os.__getattribute__\nVALUE = ga('path').expandvars('$X')\n",
    "object.__getattribute__ bound to a name": (
        "import os\nga = object.__getattribute__\nVALUE = ga(os, 'path').expandvars('$X')\n"),
    "__getattribute__ imported from the module": (
        "import os\nfrom os import __getattribute__ as ga\nVALUE = ga('path').expandvars('$X')\n"),
}


@pytest.mark.parametrize("code", list(LITERAL_READS_OF_EVERY_SPELLING.values()), ids=list(LITERAL_READS_OF_EVERY_SPELLING))
def test_RED_FB_every_spelling_of_a_literal_read_carries_its_name_on(tmp_path, code):
    args = build(tmp_path, {"core.py": code})
    assert run_core(tmp_path, _RUNS_VALUE) == "TEST_ONLY"
    rc, report = gate(args)
    assert (rc, report["verdict"]) == (1, "RED"), report["measured"]["findings"]
    assert ("environment", "os.path.expandvars") in found(report), report["measured"]["findings"]


def test_FB_a_module_as_the_default_of_a_getattr_is_the_clock_it_reads(tmp_path):
    """FB-5 of the second reading: red at 7046cbfb, held since c3eb4c09 (Codex round three), kept here as the lens wrote it."""
    args = build(tmp_path, {"core.py": "import time\nimport types\nVALUE = getattr(types, 'nonexistent_attr', time).time()\n"})
    assert float(run_core(tmp_path, _RUNS_VALUE)) > 0
    rc, report = gate(args)
    assert (rc, report["verdict"]) == (1, "RED"), report["measured"]["findings"]
    assert ("clock", "time.time") in found(report)


#: F-C (P3): a conditional, a boolean and an assignment expression give one of their values, and a binding or a receiver
#: written as one of them stood for nothing.
VALUES_AN_EXPRESSION_GIVES = {
    "FC-1 a conditional expression bound to a name": "import math\nimport os\n" + _C + "o = os if c else math\nVALUE = o.getenv('X')\n",
    "FC-2 a boolean expression bound to a name": "import os\no = None or os\nVALUE = o.getenv('X')\n",
    "FC-3 an assignment expression bound to a name": "import os\no = (p := os)\nVALUE = o.getenv('X')\n",
    "FC-4 an assignment expression as the receiver": "import os\nVALUE = (p := os).getenv('X')\n",
    "a conditional expression as the receiver": "import math\nimport os\n" + _C + "VALUE = (os if c else math).getenv('X')\n",
    "a boolean and as the receiver": "import os\n" + _C + "VALUE = (c and os).getenv('X')\n",
}


@pytest.mark.parametrize("code", list(VALUES_AN_EXPRESSION_GIVES.values()), ids=list(VALUES_AN_EXPRESSION_GIVES))
def test_RED_FC_a_value_an_expression_may_give_is_resolved(tmp_path, code):
    args = build(tmp_path, {"core.py": code})
    assert run_core(tmp_path, _RUNS_VALUE) == "TEST_ONLY"
    rc, report = gate(args)
    assert (rc, report["verdict"]) == (1, "RED"), report["measured"]["findings"]
    assert ("environment", "os.getenv") in found(report), report["measured"]["findings"]


@pytest.mark.parametrize("code", [
    "import math\nVALUE = (math if len('a') else None).floor(1.5)\n",
    "import math\nVALUE = (None or math).floor(1.5)\n",
    "import math\nVALUE = (m := math).floor(1.5)\n",
], ids=["a conditional", "a boolean", "an assignment expression"])
def test_CONTROL_FC_an_expression_of_harmless_objects_stays_green(tmp_path, code):
    rc, report = gate(build(tmp_path, {"core.py": _HONEST_CORE + code}))
    assert (rc, report["verdict"], found(report)) == (0, "GREEN", set()), report["measured"]["findings"]


#: F-D (P3): a receiver the gate reads through a call counted as resolved once `_quals` read literal attribute calls, and
#: the file finding main makes on a receiver it cannot resolve was lost (FD-1, FD-3). The same held through a binding,
#: and would hold for the expressions F-C reads; each one reads a file object or names a method that opens one.
RECEIVERS_MAIN_JUDGED_BY_THE_METHOD = {
    "FD-1 getattr(sys, 'stdin').read": ("import sys\nVALUE = getattr(sys, 'stdin').read(0)\n", "repr(c.VALUE)", "''",
                                        ("file", ".read")),
    "FD-3 getattr(zipfile, 'ZipFile').open": ("import zipfile\nVALUE = getattr(zipfile, 'ZipFile').open\n",
                                              "c.VALUE.__qualname__", "ZipFile.open", ("file", ".open")),
    "the getattr result bound to a name": ("import sys\ns = getattr(sys, 'stdin')\nVALUE = s.read(0)\n", "repr(c.VALUE)",
                                           "''", ("file", ".read")),
    "a conditional expression as the receiver": (
        "import sys\n" + _C + "s = sys.stdout if c else sys.stderr\nVALUE = s.write('')\n", "repr(c.VALUE)", "0",
        ("file", ".write")),
    "an assignment expression as the receiver": ("import sys\nVALUE = (s := sys.stdin).read(0)\n", "repr(c.VALUE)", "''",
                                                 ("file", ".read")),
}


@pytest.mark.parametrize("case", list(RECEIVERS_MAIN_JUDGED_BY_THE_METHOD.values()), ids=list(RECEIVERS_MAIN_JUDGED_BY_THE_METHOD))
def test_RED_FD_a_receiver_read_through_an_expression_keeps_the_finding_of_main(tmp_path, case):
    code, show, shown, finding = case
    args = build(tmp_path, {"core.py": code})
    assert run_core(tmp_path, f"import probepkg.core as c; print({show})") == shown
    rc, report = gate(args)
    assert (rc, report["verdict"]) == (1, "RED"), report["measured"]["findings"]
    assert finding in found(report), report["measured"]["findings"]


_ANNOTATED = ("import os\ndef outer():\n    o = os\n    def inner(x: o.getenv('X')) -> None:\n        return None\n"
              "    return inner\nVALUE = outer()\n")
_POSTPONED = "from __future__ import annotations\n"


@pytest.mark.parametrize("code, shown, verdict", [
    (_POSTPONED + _ANNOTATED, "o.getenv('X')", "RED"),
    (_ANNOTATED, "TEST_ONLY", "RED"),
    (_POSTPONED + "import os\ndef inner(x: os.getenv('X')) -> None:\n    return None\nVALUE = inner\n", "os.getenv('X')", "RED"),
], ids=["postponed, a name of the enclosing function", "evaluated, where the def runs",
        "postponed, a name of the module that get_type_hints reads"])
def test_FD_an_annotation_under_postponed_evaluation_is_read_where_its_string_is_read(tmp_path, code, shown, verdict):
    """FD-4 (P3) of the second counter-reading of pull request 395: under `from __future__ import annotations` the
    annotation of a nested function stays a string, and nothing evaluates it here. It is a finding all the same, as on
    main (owner card OA-2d52c8b607, option A): every way of telling that no caller hands its names to an evaluator came
    out open, so the gate reads it in the scope around the def as well. Evaluated, it runs where the def runs.
    Postponed, `typing.get_type_hints` reads the string in the globals of the module, so a name of the module scope
    counts too."""
    args = build(tmp_path, {"core.py": code})
    assert run_core(tmp_path, "import probepkg.core as c; print(c.VALUE.__annotations__['x'])") == shown
    rc, report = gate(args)
    assert report["verdict"] == verdict, report["measured"]["findings"]
    assert (("environment", "os.getenv") in found(report)) == (verdict == "RED")


# ── Codex, round one on pull request 420: three places where this branch judged an input weaker than main ──────────


def _gate_module():
    import importlib.util
    spec = importlib.util.spec_from_file_location("_clg_420", GATE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_a_name_that_grows_around_a_cycle_stays_bounded():
    """Codex thread 4370601942 (P2): `p = os; p = p.path; p = p.os` doubled the names of `p` in every round, and the
    rounds count every name the module binds, so twelve unrelated assignments ran the gate out of memory without its
    report, where main reports GREEN. The names stay bounded, and past the bound `p` stands for an unresolved value."""
    import ast
    m = _gate_module()
    source = "import os\np = os\np = p.path\np = p.os\n" + "".join(f"a{i} = {i}\n" for i in range(12))
    names = m._Names(ast.parse(source), "probepkg.helper", False, m._NO_GUARDS)
    held = names.module.alias["p"]
    # The bound is the limit and the marker, not a number of its own (the counter-reading of pull request 420, F2,
    # raised the limit from 64 to 4096).
    assert len(held) <= m._ALIAS_LIMIT + 1, len(held)
    assert m._UNRESOLVED in held
    assert {"os", "os.path"} <= held, "the names the gate can follow are kept"


def test_a_reading_that_runs_out_of_memory_is_not_measurable(monkeypatch, tmp_path):
    """The same thread, the class: no input ends the gate without its report. A MemoryError of the reading is NOT
    MEASURABLE, exit 2 with the JSON verdict, as every other unreadable input is."""
    import contextlib
    import io
    m = _gate_module()

    def _out_of_memory(*_a, **_k):
        raise MemoryError("planted")
    monkeypatch.setattr(m, "_measure", _out_of_memory)
    args = build(tmp_path, {"core.py": ""})
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        rc = m.main([*args, "--json"])
    assert rc == 2
    assert json.loads(out.getvalue())["verdict"] == "NOT_MEASURABLE"


_HANDED = ("from __future__ import annotations\nimport inspect\nimport os\nimport typing\n"
           "def factory():\n    o = os\n    def inner(x: o.getenv('X')):\n        return x\n    return {}\n"
           "VALUE = factory()\n")


@pytest.mark.parametrize("call", [
    "inspect.get_annotations(inner, eval_str=True, locals={'o': o})",
    "typing.get_type_hints(inner, localns={'o': o})",
    "typing.get_type_hints(inner, None, {'o': o})",
], ids=["inspect, locals", "get_type_hints, localns", "get_type_hints, positional"])
def test_RED_a_postponed_annotation_read_in_a_namespace_the_function_hands_in(tmp_path, call):
    """Codex thread 4370601943 (P2): read in the module scope only, a postponed annotation that the function around
    the def evaluates in a namespace of its own read the environment while the gate reported nothing, and main
    reported it. FD-4 above keeps its verdict: without such a call the alias of the function is never met."""
    code = _HANDED.replace("    return {}\n", f"    return {call}\n")
    args = build(tmp_path, {"core.py": code})
    if call.startswith("inspect"):
        assert run_core(tmp_path, "import probepkg.core as c; print(c.VALUE['x'])") == "TEST_ONLY"
    rc, report = gate(args)
    assert (rc, report["verdict"]) == (1, "RED"), report["measured"]["findings"]
    assert ("environment", "os.getenv") in found(report), report["measured"]["findings"]


#: Counts the calls of `os.getenv` while the package is imported, without a read of its own in the module.
_COUNTED = ("import os; calls = []; real = os.getenv; os.getenv = lambda *a: (calls.append(a), real(*a))[1]; "
            "import probepkg.core; print(len(calls))")
_FACTORY = ("from __future__ import annotations\nimport functools, inspect, os, typing\n{before}def factory():\n"
            "    o = os\n    def inner(x: type(o.getenv('X'))):\n        return x\n{body}{after}")
#: (lines before the factory, the end of the factory, lines after it, the first Python that runs the form).
HANDED_ELSEWHERE = {
    "inspect.signature with locals": (
        "", "    return inspect.signature(inner, eval_str=True, locals={'o': o})\n", "VALUE = factory()\n", (3, 10)),
    "inspect.Signature.from_callable with locals": (
        "", "    return inspect.Signature.from_callable(inner, eval_str=True, locals={'o': o})\n", "VALUE = factory()\n",
        (3, 10)),
    "functools.partial of get_type_hints": (
        "", "    return functools.partial(typing.get_type_hints, localns={'o': o})(inner)\n", "VALUE = factory()\n",
        (3, 10)),
    "a helper of the module hands the namespace": (
        "def hints(f, ns):\n    return typing.get_type_hints(f, localns=ns)\n", "    return hints(inner, {'o': o})\n",
        "VALUE = factory()\n", (3, 10)),
    "the caller of the factory hands it": (
        "", "    return inner, {'o': o}\n", "f, ns = factory()\nVALUE = typing.get_type_hints(f, localns=ns)\n", (3, 10)),
    "annotationlib.ForwardRef.evaluate with locals": (
        "import annotationlib\n",
        "    return annotationlib.ForwardRef(inner.__annotations__['x']).evaluate(locals={'o': o})\n",
        "VALUE = factory()\n", (3, 14)),
    "typing.evaluate_forward_ref with locals": (
        "", "    return typing.evaluate_forward_ref(typing.ForwardRef(inner.__annotations__['x']), locals={'o': o})\n",
        "VALUE = factory()\n", (3, 14)),
}


@pytest.mark.parametrize("before, body, after, since", list(HANDED_ELSEWHERE.values()), ids=list(HANDED_ELSEWHERE))
def test_RED_a_postponed_annotation_read_in_a_namespace_handed_in_any_way(tmp_path, before, body, after, since):
    """The counter-reading of pull request 420, F3 (P2): the namespace was seen only where the function around the def
    calls `get_type_hints`, `inspect.get_annotations` or `annotationlib.get_annotations` with it. Seven more ways read
    the environment where the gate reported GREEN and main reports `os.getenv`: `inspect.signature` and
    `inspect.Signature.from_callable`, `functools.partial` of an evaluator, a helper of the module, the caller of the
    factory, and on 3.14 `ForwardRef.evaluate` and `typing.evaluate_forward_ref`. The gate reads the source only, so
    each form is judged under every Python; it runs where the Python has the function."""
    args = build(tmp_path, {"core.py": _FACTORY.format(before=before, body=body, after=after)})
    if sys.version_info >= since:
        assert run_core(tmp_path, _COUNTED) == "1"
    rc, report = gate(args)
    assert (rc, report["verdict"]) == (1, "RED"), report["measured"]["findings"]
    assert ("environment", "os.getenv") in found(report), report["measured"]["findings"]


def _has_typing_extensions_get_annotations() -> bool:
    import importlib.util
    if importlib.util.find_spec("typing_extensions") is None:
        return False
    import typing_extensions
    return hasattr(typing_extensions, "get_annotations")


#: foxtrot's lens on 93c21dda: forms outside the list of the gate, each (lines before the factory, the end of the
#: factory, lines after it, whether this Python runs the form). The evaluation in the frame of the factory is a
#: neighbour of the same class.
HANDED_OUTSIDE_THE_LIST = {
    "a ForwardRef in a list, evaluated by position": (
        "", "    refs = [typing.ForwardRef(inner.__annotations__['x'])]\n"
            "    return refs[0]._evaluate(None, {'o': o}, frozenset())\n", "VALUE = factory()\n",
        sys.version_info < (3, 12)),
    "a ForwardRef from a helper of the module, evaluated by position": (
        "def mk(s):\n    return typing.ForwardRef(s)\n",
        "    return mk(inner.__annotations__['x'])._evaluate(None, {'o': o}, frozenset())\n", "VALUE = factory()\n",
        sys.version_info < (3, 12)),
    "typing_extensions.get_annotations with locals": (
        "import typing_extensions\n",
        "    return typing_extensions.get_annotations(inner, eval_str=True, locals={'o': o})\n", "VALUE = factory()\n",
        _has_typing_extensions_get_annotations()),
    # Unpacked from a dict, the namespace has no keyword the gate reads; only the name of the evaluator counts.
    "typing_extensions.get_annotations with the namespace unpacked from a dict": (
        "import typing_extensions\n",
        "    return typing_extensions.get_annotations(inner, **{'eval_str': True, 'locals': {'o': o}})\n",
        "VALUE = factory()\n", _has_typing_extensions_get_annotations()),
    "eval of the annotation with a namespace": (
        "", "    return eval(inner.__annotations__['x'], None, {'o': o})\n", "VALUE = factory()\n", True),
    "eval of the annotation in the frame of the factory": (
        "", "    return eval(inner.__annotations__['x'])\n", "VALUE = factory()\n", True),
    "eval taken as a value": (
        "", "    return functools.partial(eval, inner.__annotations__['x'])({'o': o})\n", "VALUE = factory()\n", True),
    "get_type_hints with the namespace unpacked from a dict": (
        "", "    return typing.get_type_hints(inner, **{'localns': {'o': o}})\n", "VALUE = factory()\n", True),
    # foxtrot's lens on ec754b36: a namespace by position to a callee no list names.
    "typing._eval_type with the namespace by position": (
        "", "    return typing._eval_type(typing.ForwardRef(inner.__annotations__['x']), None, {'o': o})\n",
        "VALUE = factory()\n", sys.version_info < (3, 14)),
    "getattr of _evaluate with the namespace by position": (
        "", "    return getattr(typing.ForwardRef(inner.__annotations__['x']), '_evaluate')(None, {'o': o}, frozenset())\n",
        "VALUE = factory()\n", sys.version_info < (3, 12)),
    "operator.methodcaller of _evaluate": (
        "import operator\n",
        "    return operator.methodcaller('_evaluate', None, {'o': o}, frozenset())"
        "(typing.ForwardRef(inner.__annotations__['x']))\n", "VALUE = factory()\n", sys.version_info < (3, 12)),
    # A namespace that maps the name to the module's own `os`: the alias of the factory is never read.
    "get_type_hints with the module's os under the name of the alias": (
        "", "    return typing.get_type_hints(inner, localns={'o': os})\n", "VALUE = factory()\n", True),
}


@pytest.mark.parametrize("before, body, after, runs", list(HANDED_OUTSIDE_THE_LIST.values()),
                         ids=list(HANDED_OUTSIDE_THE_LIST))
def test_RED_a_postponed_annotation_read_by_a_callee_the_list_did_not_name(tmp_path, before, body, after, runs):
    """foxtrot's lenses on 93c21dda and ec754b36, the class of F3: whether a namespace reaches an evaluator was decided
    by the spelling of the callee, and then by what the call hands. A ForwardRef the gate cannot trace to its class,
    `typing_extensions.get_annotations`, `eval`, a namespace by position to `typing._eval_type`, `getattr` or
    `operator.methodcaller`, and a namespace that maps the name to the module's `os` read the environment where main
    reports `os.getenv`, and the gate said GREEN or lost the finding. The gate now reads the annotation in the scope
    around the def always (owner card OA-2d52c8b607, option A)."""
    args = build(tmp_path, {"core.py": _FACTORY.format(before=before, body=body, after=after)})
    if runs:
        assert run_core(tmp_path, _COUNTED) == "1"
    rc, report = gate(args)
    assert (rc, report["verdict"]) == (1, "RED"), report["measured"]["findings"]
    assert ("environment", "os.getenv") in found(report), report["measured"]["findings"]


def test_reading_postponed_annotations_leaves_the_names_of_every_call_as_they_were():
    """A search over the module once narrowed the set `_quals` keeps in `_memo` in place (`quals &= ...`, at
    3d3cd280), so afterwards `len` stood for nothing, `len(sys.modules)` became a use of a namespace other than by
    reading, and the gate was RED on this tree. Whatever reads the postponed annotations reads names, it never
    changes them."""
    import ast
    m = _gate_module()
    source = ("from __future__ import annotations\nimport sys\ndef outer():\n    def inner(x: int) -> None:\n"
              "        return None\n    return inner\nN = len(sys.modules)\n")
    tree = ast.parse(source)
    names = m._Names(tree, "probepkg.core", False, m._NO_GUARDS)
    call = next(n for n in ast.walk(tree) if isinstance(n, ast.Call) and getattr(n.func, "id", None) == "len")
    assert names.quals(call.func) == ["builtins.len"]


def test_RED_a_namespace_handed_by_keyword_to_a_helper_of_another_module(tmp_path):
    """The class itself: no callee needs to be recognised, here a helper in another module of the package that hands
    the namespace on to `typing.get_type_hints`. The annotation is read in the scope around the def always."""
    helper = "import typing\ndef hints(f, localns):\n    return typing.get_type_hints(f, localns=localns)\n"
    core = _FACTORY.format(before="from .hints import hints\n", body="    return hints(inner, localns={'o': o})\n",
                           after="VALUE = factory()\n")
    args = build(tmp_path, {"core.py": core, "hints.py": helper})
    assert run_core(tmp_path, _COUNTED) == "1"
    rc, report = gate(args)
    assert (rc, report["verdict"]) == (1, "RED"), report["measured"]["findings"]
    assert ("environment", "os.getenv") in found(report), report["measured"]["findings"]


_DIAMOND_CORE ="from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    import subprocess\n"


@pytest.mark.parametrize("helper, verdict", [
    ("class B:\n    pass\nclass C(B):\n    pass\nclass D(B):\n    pass\nclass E(C, D):\n    pass\n"
     "def f(k, v):\n    setattr(E(), k, v)\n", "GREEN"),
    ("class B:\n    pass\nclass C(B):\n    pass\nclass D(B):\n    def __new__(cls):\n        return object.__new__(cls)\n"
     "class E(C, D):\n    pass\ndef f(k, v):\n    setattr(E(), k, v)\n", "RED"),
], ids=["a diamond of plain classes", "the same diamond, one side with __new__"])
def test_a_shared_base_is_no_cycle(tmp_path, helper, verdict):
    """Codex thread 4370601946 (P2): one set for all bases made the second edge to a shared base a cycle, so a diamond
    of plain classes built a possible module, a setattr on it turned every guard of the package off, and the guarded
    import that never runs was red, where main is GREEN. The other direction: a side with its own `__new__` keeps the
    class a possible module."""
    args = build(tmp_path, {"core.py": _DIAMOND_CORE, "helper.py": helper})
    shown = run_core(tmp_path, "import probepkg.core as c, probepkg.helper as h; print(hasattr(c, 'subprocess'))")
    assert shown == "False"
    rc, report = gate(args)
    assert report["verdict"] == verdict, report["measured"]
