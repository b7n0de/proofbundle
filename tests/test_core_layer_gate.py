"""Contract of scripts/core_layer_gate.py, the S1 gate of the verification core split.

The eight counter-probes are the ones of the review of 2026-10-10 (question 3). Each was run there
against the inventory script `messung/seiteneffekte_ast.py` and was NOT reported by it. Here each one
is built as a small package and must come back from the gate as a finding of its rule. The positive
controls show the gate can also say green, so a gate that flags everything does not pass this file.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GATE_PATH = ROOT / "scripts" / "core_layer_gate.py"
_spec = importlib.util.spec_from_file_location("core_layer_gate", GATE_PATH)
gate = importlib.util.module_from_spec(_spec)
sys.modules["core_layer_gate"] = gate
_spec.loader.exec_module(gate)

PKG = "probepkg"


def build(tmp_path: Path, files: dict[str, str], *, roots=("probepkg.core",), boundaries=None,
          listed=None, exceptions=()) -> tuple[Path, Path, Path]:
    """A synthetic package under tmp_path/src, plus its core list and exceptions file."""
    src = tmp_path / "src" / PKG
    src.mkdir(parents=True)
    (src / "__init__.py").write_text("", encoding="utf-8")
    for rel, body in files.items():
        p = src / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(body), encoding="utf-8")
    modules_file = tmp_path / "modules.json"
    modules_file.write_text(json.dumps({
        "schema": "proofbundle.core_layer_modules.v1", "package": PKG,
        "roots": {r: "probe" for r in roots}, "trust_boundaries": boundaries or {},
        "modules": list(listed or [])}), encoding="utf-8")
    exceptions_file = tmp_path / "exceptions.json"
    exceptions_file.write_text(json.dumps({"entries": [
        {"rule": e[0], "module": e[1], "operation": e[2], "count": e[3] if len(e) > 3 else 1}
        for e in exceptions]}), encoding="utf-8")
    return tmp_path, modules_file, exceptions_file


def run(tmp_path, files, **kw) -> dict:
    root, modules_file, exceptions_file = build(tmp_path, files, **kw)
    return gate.judge(gate.measure(root, modules_file), exceptions_file)


def found(report: dict) -> set[tuple[str, str, str]]:
    return {(f["rule"], f["module"], f["operation"]) for f in report["measured"]["findings"]}


# ── the eight counter-probes of the review ─────────────────────────────────────────────────────

def test_probe1_clock_behind_an_import_alias(tmp_path):
    r = run(tmp_path, {"core.py": """
        import time as clock
        from datetime import datetime as Clock
        def now():
            return clock.time(), Clock.now()
    """})
    assert ("clock", "probepkg.core", "time.time") in found(r)
    assert ("clock", "probepkg.core", "datetime.datetime.now") in found(r)
    assert r["verdict"] == "RED"


def test_probe2_environment_behind_os_alias_or_from_import(tmp_path):
    r = run(tmp_path, {"core.py": """
        import os as o
        from os import getenv
        def env():
            return o.environ.get("X"), getenv("Y")
    """})
    assert ("environment", "probepkg.core", "os.environ.get") in found(r)
    assert ("environment", "probepkg.core", "os.getenv") in found(r)


def test_probe3_file_through_builtins_io_and_rebinding(tmp_path):
    r = run(tmp_path, {"core.py": "import builtins\n"
                                  "import io\n"
                                  "reader = open\n"
                                  "def load(p):\n"
                                  "    return builtins.open(p), io.open(p)\n"
                                  "def load_again(p):\n"
                                  "    return reader(p)\n"})
    ops = {o for rule, m, o in found(r) if rule == "file"}
    assert {"builtins.open", "io.open"} <= ops
    # `reader = open` resolves: the call through `reader` on line 7 is the builtin open. The line is
    # asserted, not a count, because the reference to `open` on line 3 is a finding of its own.
    lines = next(f["lines"] for f in r["measured"]["findings"]
                 if (f["rule"], f["operation"]) == ("file", "builtins.open"))
    assert 7 in lines, lines


def test_probe4_getattr_with_a_literal_and_a_read_through_a_parameter(tmp_path):
    r = run(tmp_path, {"core.py": """
        from pathlib import Path
        def load(path, source):
            return getattr(Path(path), "read_bytes")(), source.read()
    """})
    assert ("file", "probepkg.core", ".read_bytes") in found(r)
    assert ("file", "probepkg.core", ".read") in found(r)


def test_probe5_importlib_import_module(tmp_path):
    r = run(tmp_path, {"core.py": """
        import importlib
        def fetch():
            return importlib.import_module("urllib.request")
    """})
    assert ("dynamic_import", "probepkg.core", "import importlib") in found(r)
    assert ("dynamic_import", "probepkg.core", "importlib.import_module") in found(r)


def test_probe6a_internal_reading_helper_is_followed(tmp_path):
    r = run(tmp_path, {
        "core.py": "from .helper import load\n",
        "helper.py": "def load(p):\n    with open(p, 'rb') as f:\n        return f.read()\n",
    }, listed=["probepkg", "probepkg.core"])
    assert "probepkg.helper" in r["measured"]["closure"]
    assert ("file", "probepkg.helper", "builtins.open") in found(r)
    # The helper is not on the core list: the edge to it is red on its own.
    assert r["core_list_new"] == ["probepkg.helper"]
    assert ("import_edge", "probepkg.core", "import probepkg.helper") in found(r)


def test_probe6b_external_reading_helper_is_an_unnamed_boundary(tmp_path):
    r = run(tmp_path, {"core.py": "import somelib\n"})
    assert ("external_dependency", "probepkg.core", "import somelib") in found(r)
    named = run(tmp_path / "named", {"core.py": "import somelib\n"},
                boundaries={"somelib": "named for this test"})
    assert ("external_dependency", "probepkg.core", "import somelib") not in found(named)


def test_probe7_package_initialiser_of_an_imported_submodule(tmp_path):
    r = run(tmp_path, {
        "core.py": "from .sub import mod\n",
        "sub/__init__.py": "import os\nMODE = os.environ.get('MODE')\n",
        "sub/mod.py": "VALUE = 1\n",
    })
    assert "probepkg.sub" in r["measured"]["closure"]
    assert ("environment", "probepkg.sub", "os.environ.get") in found(r)


def test_probe8_file_method_name_on_an_unresolvable_receiver(tmp_path):
    """The inventory script reported this one as a file hit without file access. The gate reports it
    too, on purpose: it cannot prove the receiver is no file, and an exception names it if it is not."""
    r = run(tmp_path, {"core.py": """
        class Memory:
            def read_bytes(self):
                return b"literal"
        def load():
            return Memory().read_bytes()
    """})
    assert ("file", "probepkg.core", ".read_bytes") in found(r)


# ── the exception file only shrinks ────────────────────────────────────────────────────────────

def test_a_swapped_exception_entry_is_red(tmp_path):
    """Same number of entries, one gone and one new: red, with both named."""
    r = run(tmp_path, {"core.py": "import time\ndef f():\n    return time.time()\n"},
            listed=["probepkg", "probepkg.core"],
            exceptions=[("clock", "probepkg.core", "time.monotonic")])
    assert r["verdict"] == "RED"
    assert r["new_findings"] == [{"rule": "clock", "module": "probepkg.core", "operation": "time.time"}]
    assert r["stale_exceptions"] == [
        {"rule": "clock", "module": "probepkg.core", "operation": "time.monotonic"}]


def test_the_matching_exception_entry_is_green(tmp_path):
    r = run(tmp_path, {"core.py": "import time\ndef f():\n    return time.time()\n"},
            listed=["probepkg", "probepkg.core"],
            exceptions=[("clock", "probepkg.core", "time.time")])
    assert r["verdict"] == "GREEN"
    assert r["exceptions_by_rule"]["clock"] == 1


def test_an_exception_that_no_longer_occurs_is_red_on_its_own(tmp_path):
    """Nothing new, one entry gone: still red, so the baseline shrinks only by a reviewed edit."""
    r = run(tmp_path, {"core.py": "X = 1\n"}, listed=["probepkg", "probepkg.core"],
            exceptions=[("clock", "probepkg.core", "time.time")])
    assert r["new_findings"] == [] and r["core_list_new"] == []
    assert r["stale_exceptions"] == [
        {"rule": "clock", "module": "probepkg.core", "operation": "time.time"}]
    assert r["verdict"] == "RED"


def test_a_core_member_no_longer_reached_is_red(tmp_path):
    r = run(tmp_path, {"core.py": "X = 1\n", "gone.py": "Y = 2\n"},
            listed=["probepkg", "probepkg.core", "probepkg.gone"])
    assert r["verdict"] == "RED"
    assert r["core_list_stale"] == ["probepkg.gone"]


# ── the four findings of the Codex review of pull request 333, each built as its probe ──────────

def test_a_second_occurrence_of_an_approved_operation_is_red(tmp_path):
    """Codex P1: an approved `open` must not cover a second `open` in the same module."""
    r = run(tmp_path, {"core.py": "def a(p):\n    return open(p)\ndef b(p):\n    return open(p)\n"},
            listed=["probepkg", "probepkg.core"],
            exceptions=[("file", "probepkg.core", "builtins.open", 1)])
    assert r["verdict"] == "RED"
    assert r["grown_findings"] == [{"rule": "file", "module": "probepkg.core",
                                    "operation": "builtins.open", "baseline": 1, "found": 2}]


def test_one_occurrence_fewer_is_red_until_the_count_is_lowered(tmp_path):
    r = run(tmp_path, {"core.py": "def a(p):\n    return open(p)\n"},
            listed=["probepkg", "probepkg.core"],
            exceptions=[("file", "probepkg.core", "builtins.open", 2)])
    assert r["verdict"] == "RED"
    assert r["shrunk_exceptions"][0]["found"] == 1


def test_a_parameter_in_one_function_does_not_hide_the_builtin_in_another(tmp_path):
    """Codex P1: name resolution is per lexical scope, not one set for the module."""
    r = run(tmp_path, {"core.py": """
        def harmless(open):
            return open
        def leak(path):
            return open(path)
        class Holder:
            open = None
            def method(self, path):
                return open(path)
    """})
    lines = next(f["lines"] for f in r["measured"]["findings"]
                 if (f["rule"], f["operation"]) == ("file", "builtins.open"))
    assert lines == [5, 9], lines


# The class behind the scope finding, as a property over every form of binding: a binding hides a
# builtin only where Python would use it. A function binds a name for its whole body, so a binding in
# one function never reaches another. A module or a class body looks the name up when the line runs,
# so a binding there may not have run, and a builtin a rule names stays a finding.
_SIBLING_BINDINGS = {
    "parameter": "def other(open):\n    return open\n",
    "loop target": "def other(xs):\n    for open in xs:\n        pass\n",
    "with target": "def other(c):\n    with c as open:\n        pass\n",
    "exception name": "def other():\n    try:\n        pass\n    except Exception as open:\n        pass\n",
    "import alias": "def other():\n    import io as open\n    return open\n",
    "assignment": "def other():\n    open = None\n    return open\n",
    "comprehension variable": "def other(xs):\n    return [open for open in xs]\n",
    "walrus target": "def other(xs):\n    if (open := xs):\n        return open\n",
    "lambda parameter": "other = lambda open: open\n",
    "nested def": "def other():\n    def open():\n        pass\n    return open\n",
    "class attribute": "class Other:\n    open = None\n",
}

_UNCERTAIN_BINDINGS = {
    "assignment under if": "if False:\n    open = None\n",
    "global in a function nobody calls": "def never():\n    global open\n    open = None\n",
    "loop over nothing": "for open in ():\n    pass\n",
    "def under if": "if False:\n    def open(p):\n        return p\n",
    "import in try": "try:\n    from io import open\nexcept ImportError:\n    pass\n",
}


@pytest.mark.parametrize("form", sorted(_SIBLING_BINDINGS))
def test_a_binding_in_a_sibling_scope_does_not_hide_the_builtin(tmp_path, form):
    r = run(tmp_path, {"core.py": _SIBLING_BINDINGS[form] + "def leak(path):\n    return open(path)\n"})
    assert ("file", "probepkg.core", "builtins.open") in found(r), form


@pytest.mark.parametrize("form", sorted(_UNCERTAIN_BINDINGS))
def test_a_module_level_binding_that_may_not_run_does_not_hide_the_builtin(tmp_path, form):
    r = run(tmp_path, {"core.py": _UNCERTAIN_BINDINGS[form] + "def leak(path):\n    return open(path)\n"})
    assert ("file", "probepkg.core", "builtins.open") in found(r), form


def test_a_class_body_binding_that_may_not_run_does_not_hide_the_builtin(tmp_path):
    r = run(tmp_path, {"core.py": "class C:\n    if False:\n        open = None\n    data = open('x')\n"})
    assert ("file", "probepkg.core", "builtins.open") in found(r)


def test_only_the_real_typing_type_checking_skips_a_body(tmp_path):
    """Codex P2: a flag that merely ends in TYPE_CHECKING is ordinary code and runs."""
    r = run(tmp_path, {"core.py": """
        import typing
        class RuntimeFlag:
            TYPE_CHECKING = True
        if RuntimeFlag.TYPE_CHECKING:
            import subprocess
        if typing.TYPE_CHECKING:
            import socket
    """})
    assert ("subprocess", "probepkg.core", "import subprocess") in found(r)
    assert not any(o == "import socket" for _, _, o in found(r))
    bare = run(tmp_path / "bare", {"core.py": "TYPE_CHECKING = True\nif TYPE_CHECKING:\n    import subprocess\n"})
    assert ("subprocess", "probepkg.core", "import subprocess") in found(bare)


@pytest.mark.parametrize("reason", [None, "", "   ", 7])
def test_a_trust_boundary_needs_a_reason(tmp_path, reason):
    """Codex P2: a boundary without a reason is not a boundary, the run is not measurable."""
    root, modules_file, exceptions_file = build(tmp_path, {"core.py": "import somelib\n"},
                                                boundaries={"somelib": reason})
    rc = gate.main(["--root", str(root), "--modules-file", str(modules_file),
                    "--exceptions-file", str(exceptions_file)])
    assert rc == 2


# ── positive controls: the gate can say green ──────────────────────────────────────────────────

def test_a_clean_core_is_green(tmp_path):
    r = run(tmp_path, {"core.py": """
        import hashlib
        import json
        import urllib.parse
        from typing import TYPE_CHECKING
        if TYPE_CHECKING:
            import subprocess
        def digest(data: bytes) -> str:
            return hashlib.sha256(json.dumps(urllib.parse.quote(data)).encode()).hexdigest()
    """}, listed=["probepkg", "probepkg.core"])
    assert found(r) == set()
    assert r["verdict"] == "GREEN"


def test_a_shadowed_builtin_and_a_clock_call_with_an_argument_are_not_findings(tmp_path):
    r = run(tmp_path, {"core.py": """
        import time
        def make():
            return lambda p: p
        def f(ts):
            open = make()
            return open(ts), time.gmtime(ts)
    """}, listed=["probepkg", "probepkg.core"])
    assert found(r) == set()


def test_a_clock_call_without_its_argument_is_a_finding(tmp_path):
    r = run(tmp_path, {"core.py": "import time\ndef f():\n    return time.gmtime()\n"})
    assert ("clock", "probepkg.core", "time.gmtime()") in found(r)


def test_a_computed_getattr_is_a_finding(tmp_path):
    r = run(tmp_path, {"core.py": "def f(obj, name):\n    return getattr(obj, name)\n"})
    assert ("dynamic_access", "probepkg.core", "getattr(computed name)") in found(r)


# ── the real tree and the command line ─────────────────────────────────────────────────────────

def test_the_gate_is_green_on_this_tree_and_counts_its_exceptions():
    out = subprocess.run([sys.executable, str(GATE_PATH), "--json"], capture_output=True,
                         text=True, cwd=ROOT)
    report = json.loads(out.stdout)
    assert out.returncode == 0, (report.get("new_findings"), report.get("stale_exceptions"),
                                 report.get("core_list_new"), report.get("core_list_stale"))
    assert report["verdict"] == "GREEN"
    entries = json.loads((ROOT / "scripts" / "core_layer_exceptions.json").read_text())["entries"]
    for rule in gate.RULES:
        assert report["exceptions_by_rule"][rule] == sum(1 for e in entries if e["rule"] == rule)
    assert report["exceptions_total"] == len(entries)
    for rule in gate.RULES:
        assert report["occurrences_by_rule"][rule] == sum(e["count"] for e in entries
                                                           if e["rule"] == rule)


def test_the_named_exception_for_the_process_origin_carries_its_reason():
    entries = json.loads((ROOT / "scripts" / "core_layer_exceptions.json").read_text())["entries"]
    origin = [e for e in entries if (e["rule"], e["module"], e["operation"])
              == ("randomness", "proofbundle.errors", "os.urandom")]
    assert len(origin) == 1 and "binding" in origin[0].get("reason", "")


@pytest.mark.parametrize("broken", ["not json", "[]", '{"entries": [{"rule": "nope", '
                                                       '"module": "m", "operation": "o"}]}'])
def test_an_unreadable_exception_file_is_not_measurable(tmp_path, broken):
    root, modules_file, exceptions_file = build(tmp_path, {"core.py": "X = 1\n"})
    exceptions_file.write_text(broken, encoding="utf-8")
    rc = gate.main(["--root", str(root), "--modules-file", str(modules_file),
                    "--exceptions-file", str(exceptions_file)])
    assert rc == 2
