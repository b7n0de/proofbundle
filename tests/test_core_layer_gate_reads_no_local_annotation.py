"""The annotation of a variable in a function body never runs, and the core layer gate read it as code (FD-4l).

PEP 526: in a function scope an annotation is never evaluated nor stored; `x: o.getenv("X") = 1` evaluates the value and
not the annotation. The gate walked every node and reported the read of the environment that never happens, at `main`
and at the head of pull request 395 alike (measured in the follow-up of 395, delivery 11 of
CLOUD-640-BESCHLEUNIGER-AUF-MAIN-01, where it was named and left for its own change).

The counter-cases are annotations that do run: at module level and in a class body, where they are evaluated when the
statement runs (from Python 3.14 on, when they are read), and the annotations of a function's parameters, which run
where the def runs or, postponed, when `typing.get_type_hints` or `inspect.get_annotations` reads the string. Each one
runs first and shows the read; the gate keeps reporting it.
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


def build(tmp_path: Path, code: str) -> list[str]:
    src = tmp_path / "src" / PKG
    src.mkdir(parents=True)
    (src / "__init__.py").write_text("", encoding="utf-8")
    (src / "core.py").write_text(textwrap.dedent(code), encoding="utf-8")
    modules = tmp_path / "modules.json"
    modules.write_text(json.dumps({"schema": "proofbundle.core_layer_modules.v1", "package": PKG,
                                   "roots": {"probepkg.core": "probe"}, "trust_boundaries": {},
                                   "modules": ["probepkg", "probepkg.core"]}), encoding="utf-8")
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
    r = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True,
                       text=True, timeout=60, env=env, cwd=str(tmp_path))
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


#: The annotation of a local variable: the value runs, the annotation never does (the module counts the calls of a
#: wrapped `os.getenv` to show it).
NEVER_RUN = {
    "an alias of the function": "import os\ndef f():\n    o = os\n    x: o.getenv('X') = 1\n    return x\nVALUE = f()\n",
    "a name of the module": "import os\ndef f():\n    x: os.getenv('X') = 1\n    return x\nVALUE = f()\n",
    "without a value": "import os\ndef f():\n    x: os.getenv('X')\n    return 1\nVALUE = f()\n",
    "a target that is an attribute": (
        "import os\nclass C:\n    pass\ndef f():\n    c = C()\n    c.x: os.getenv('X') = 1\n    return c.x\nVALUE = f()\n"),
    "in a method": "import os\nclass C:\n    def m(self):\n        x: os.getenv('X') = 1\n        return x\nVALUE = C().m()\n",
    "in a nested function": (
        "import os\ndef f():\n    def g():\n        x: os.getenv('X') = 1\n        return x\n    return g()\nVALUE = f()\n"),
}

#: Runs the module with `os.getenv` wrapped, and prints the value and how often `os.getenv` was called.
_COUNTED = ("import os; calls = []; real = os.getenv; os.getenv = lambda *a: (calls.append(a), real(*a))[1]; "
            "import probepkg.core as c; print(c.VALUE, len(calls))")


@pytest.mark.parametrize("code", list(NEVER_RUN.values()), ids=list(NEVER_RUN))
def test_RED_the_annotation_of_a_local_variable_is_not_read_as_code(tmp_path, code):
    args = build(tmp_path, code)
    assert run_core(tmp_path, _COUNTED) == "1 0"
    rc, report = gate(args)
    assert (rc, report["verdict"], found(report)) == (0, "GREEN", set()), report["measured"]["findings"]


#: Annotations that run: each one reads the environment, and the gate keeps reporting it.
STILL_RUN = {
    "at module level": ("import os\nx: os.getenv('X') = 1\n", "import inspect; print(inspect.get_annotations(c)['x'])",
                        "TEST_ONLY"),
    "in a class body": ("import os\nclass C:\n    x: os.getenv('X') = 1\nVALUE = C.__annotations__['x']\n",
                        "print(c.VALUE)", "TEST_ONLY"),
    "a class body in a function": (
        "import os\ndef f():\n    class C:\n        x: os.getenv('X') = 1\n    return C.__annotations__['x']\nVALUE = f()\n",
        "print(c.VALUE)", "TEST_ONLY"),
    "a parameter": ("import os\ndef f(x: os.getenv('X')):\n    return x\nVALUE = f.__annotations__['x']\n",
                    "print(c.VALUE)", "TEST_ONLY"),
    "a parameter, postponed and read by get_annotations": (
        "from __future__ import annotations\nimport os\ndef f(x: os.getenv('X')):\n    return x\n",
        "import inspect; print(inspect.get_annotations(c.f, eval_str=True)['x'])", "TEST_ONLY"),
    "the value of a local annotated assignment": (
        "import os\ndef f():\n    x: int = os.getenv('X')\n    return x\nVALUE = f()\n", "print(c.VALUE)", "TEST_ONLY"),
}


@pytest.mark.parametrize("case", list(STILL_RUN.values()), ids=list(STILL_RUN))
def test_CONTROL_an_annotation_that_runs_stays_a_finding(tmp_path, case):
    code, show, shown = case
    args = build(tmp_path, code)
    assert run_core(tmp_path, f"import probepkg.core as c; {show}") == shown
    rc, report = gate(args)
    assert (rc, report["verdict"]) == (1, "RED"), report["measured"]["findings"]
    assert ("environment", "os.getenv") in found(report), report["measured"]["findings"]
