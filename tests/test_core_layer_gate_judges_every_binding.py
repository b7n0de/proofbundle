"""K6 (Codex defect search on the 6.3.0 candidate 98b168b9, CODEX-630-K6): the core layer gate judges a use
against every binding it may meet, and skips a type-checking block only while nothing can change the guard.

The gate kept one alias per name and scope, the last one: `import os; VALUE = os.getenv("X"); import math as os`
read the environment at import, and the gate resolved the earlier `os.getenv` against `math` and said GREEN
with exit 0 (measured at 98b168b9 and f6ea5cc3). The sibling: `typing.TYPE_CHECKING = True` before
`if typing.TYPE_CHECKING:` runs the block, and the gate skipped it as a type-checking block. Both are a static
assumption about state used as the run-time truth. The synthetic packages follow `build` in
tests/test_core_layer_gate.py; the environment value is a test value set for one child process.
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


def build(tmp_path: Path, files: dict[str, str], exceptions=()) -> list[str]:
    src = tmp_path / "src" / PKG
    src.mkdir(parents=True)
    (src / "__init__.py").write_text("", encoding="utf-8")
    for rel, body in files.items():
        (src / rel).write_text(textwrap.dedent(body), encoding="utf-8")
    modules = tmp_path / "modules.json"
    modules.write_text(json.dumps({"schema": "proofbundle.core_layer_modules.v1", "package": PKG,
                                   "roots": {"probepkg.core": "probe"}, "trust_boundaries": {},
                                   "modules": ["probepkg", "probepkg.core"]}), encoding="utf-8")
    exc = tmp_path / "exceptions.json"
    exc.write_text(json.dumps({"entries": [{"rule": r, "module": m, "operation": o, "count": n}
                                           for r, m, o, n in exceptions]}), encoding="utf-8")
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


T6 = """
    import os
    VALUE = os.getenv("X")
    import math as os
"""


def test_RED_an_earlier_use_is_judged_against_the_binding_it_met(tmp_path):
    """T6."""
    args = build(tmp_path, {"core.py": T6})
    assert run_core(tmp_path, "import probepkg.core as c; print(c.VALUE)") == "TEST_ONLY"
    rc, report = gate(args)
    assert (rc, report["verdict"]) == (1, "RED")
    assert ("environment", "os.getenv") in found(report)
    approved = build(tmp_path / "approved", {"core.py": T6},
                     exceptions=[("environment", "probepkg.core", "os.getenv", 1)])
    assert gate(approved)[0] == 0, "the read is the one approved occurrence"


def test_CONTROL_without_the_rebinding_the_same_use_is_red(tmp_path):
    rc, report = gate(build(tmp_path, {"core.py": 'import os\nVALUE = os.getenv("X")\n'}))
    assert (rc, report["verdict"]) == (1, "RED")


def test_CONTROL_the_approved_exception_makes_the_plain_read_green(tmp_path):
    args = build(tmp_path, {"core.py": 'import os\nVALUE = os.getenv("X")\n'},
                 exceptions=[("environment", "probepkg.core", "os.getenv", 1)])
    assert gate(args)[0] == 0


def test_CONTROL_a_pure_call_stays_green(tmp_path):
    rc, report = gate(build(tmp_path, {"core.py": "import math\nX = math.cos(0)\n"}))
    assert (rc, report["verdict"], found(report)) == (0, "GREEN", set())


def test_CONTROL_a_rebinding_between_harmless_modules_stays_green(tmp_path):
    rc, report = gate(build(tmp_path, {"core.py": "import math\nimport os as m\nimport math as m\nX = m.cos(0)\n"}))
    assert (rc, report["verdict"], found(report)) == (0, "GREEN", set())


def test_RED_a_from_import_sent_to_the_module_by_global_is_counted_where_it_is_used(tmp_path):
    """The same class one step over in the same file: `global` sent a plain import to the module scope, but a
    from-import stayed in the function, so another function's use of the name resolved to nothing. The import
    line itself is a finding, so the use went missing from the count: an exception approving one occurrence
    stayed green over any number of reads, where the module-level form of the same code needs two."""
    code = """
        def setup():
            global ge
            from os import getenv as ge
        def read():
            return ge("X")
    """
    rc, report = gate(build(tmp_path, {"core.py": code},
                            exceptions=[("environment", "probepkg.core", "os.getenv", 1)]))
    assert (rc, report["verdict"]) == (1, "RED"), report["measured"]["findings"]
    assert [g["found"] for g in report["grown_findings"]] == [2]


def test_RED_a_type_checking_guard_the_module_sets_is_not_a_type_checking_block(tmp_path):
    """The sibling Codex measured: the block runs."""
    code = """
        import typing
        typing.TYPE_CHECKING = True
        if typing.TYPE_CHECKING:
            import subprocess
    """
    args = build(tmp_path, {"core.py": code})
    assert run_core(tmp_path, "import probepkg.core as c; print(hasattr(c, 'subprocess'))") == "True"
    rc, report = gate(args)
    assert (rc, report["verdict"]) == (1, "RED")
    assert ("subprocess", "import subprocess") in found(report)


def test_RED_the_module_level_reading_does_not_skip_a_guard_its_module_sets():
    """`findings_of` and `imports_of` read one module on their own, without the package scan of `measure`; they
    too must not take a guard the module itself sets for a type-checking block."""
    import ast
    import importlib.util
    spec = importlib.util.spec_from_file_location("_k6_core_layer_gate", GATE)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)
    tree = ast.parse("import typing\ntyping.TYPE_CHECKING = True\nif typing.TYPE_CHECKING:\n    import subprocess\n")
    assert ("subprocess", "import subprocess") in {(r, o) for r, o, _line in module.findings_of(tree, "p.core", False)}
    assert "subprocess" in {m for m, _line in module.imports_of(tree, "p.core", False, set())}


def test_RED_a_guard_changed_through_setattr_is_not_a_type_checking_block(tmp_path):
    rc, report = gate(build(tmp_path, {"core.py": """
        import typing
        setattr(typing, "TYPE_CHECKING", True)
        from typing import TYPE_CHECKING
        if TYPE_CHECKING:
            import subprocess
    """}))
    assert (rc, report["verdict"]) == (1, "RED")
    assert ("subprocess", "import subprocess") in found(report)


def test_RED_another_module_of_the_package_that_changes_the_guard_unguards_the_core(tmp_path):
    """typing is one module per process: a package module that sets the flag changes it for the core."""
    args = build(tmp_path, {
        "other.py": "import typing\ntyping.TYPE_CHECKING = True\n",
        "core.py": "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    import subprocess\n",
    })
    assert run_core(tmp_path, "import probepkg.other, probepkg.core as c; print(hasattr(c, 'subprocess'))") == "True"
    rc, report = gate(args)
    assert (rc, report["verdict"]) == (1, "RED")
    assert ("subprocess", "import subprocess") in found(report)
    assert report["measured"]["type_checking_changed_by"] == ["probepkg.other"]


def test_CONTROL_a_guard_nothing_changes_still_skips_its_block(tmp_path):
    rc, report = gate(build(tmp_path, {
        "core.py": "import typing\nfrom typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    import subprocess\n"
                   "if typing.TYPE_CHECKING:\n    import socket\n"}))
    assert (rc, report["verdict"], found(report)) == (0, "GREEN", set())
    assert report["measured"].get("type_checking_changed_by", []) == []
