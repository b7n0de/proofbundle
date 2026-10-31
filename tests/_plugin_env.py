"""The environment a plugin test gives a process or the gate.

A plugin test hands neither a process nor the gate in-process the caller's environment. A token, an askpass program
or a GIT_ value the caller set reaches neither the gate under test nor the output of a failing test, and a run with
them set ends as a run without them. Two pieces hold that:

* `withhold_caller_environment`, a module-scoped autouse fixture tests/conftest.py imports, takes every name but
  those in FIXED out of os.environ before the first fixture of a plugin test module and puts them back after its last
  test. A process a test starts without env=, and the gate a test calls in-process, see the fixed list and what the
  test set itself. It also puts the proofbundle this test process imports first on PYTHONPATH, so that a child running
  code of this tree reads the same package.
* `plugin_env(**values)` builds the environment a test hands a process or the gate explicitly: the names in FIXED as
  they stand, the GIT_ and PROOFBUNDLE_ values the case set (with the caller's withheld, only the case's are left),
  and `values`, where None takes a name out. `without` names prefixes the result leaves out.

tests/test_plugin_env_guard.py holds both: no plugin test passes os.environ, a copy of it or a mapping built from it
to a process or the gate, except the named places, and planted cases show the guard finds each form."""
from __future__ import annotations

import importlib.util
import os
import pathlib
import sys

import pytest

#: The names a plugin test keeps from its caller. UV_OFFLINE and UV_CACHE_DIR carry no secret and let the pinned
#: verifier start from uv's cache (owner answer of follow-up note 8); a proxy name and a certificate path stay out.
FIXED = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "PYTHONPATH", "UV_OFFLINE", "UV_CACHE_DIR")
#: The prefixes of the names plugin_env carries when the case set them.
CASE_PREFIXES = ("GIT_", "PROOFBUNDLE_")
#: pytest's own name, set by pytest for each phase; it is neither the caller's nor the case's, and plugin_env leaves it
#: out.
PYTEST_OWN = "PYTEST_CURRENT_TEST"
#: Files the selection tests/test_*plugin*, tests/test_*gate*, tests/test_codex* catches that test no plugin code: the
#: library's pytest plugin, the release and audit gates, the Codex thread check. They keep their caller's environment.
NOT_PLUGIN = frozenset({
    "test_cargo_audit_gate", "test_codex_funde_248_20260923", "test_codex_threads_check",
    "test_gate_population_and_nested_leaf", "test_gate_qualification_harness", "test_iter9_deepgate_round4",
    "test_pre_tag_gate_eigenschaften", "test_pre_tag_receipt_gate", "test_pretag_gate_state_typed_l5_g6_01",
    "test_pytest_plugin", "test_relation_gate_distance_invariance", "test_release_integrity_gate",
    "test_release_scope_title_gate", "test_rust_parity_gate",
})
#: Files outside that selection that name the plugin since the plugin line came into main's tree: main's
#: strict decoding guard scans plugins/, and the docs defaults test classifies the plugin's README. They are plugin
#: tests and run without their caller's names.
ALSO_PLUGIN = frozenset({"test_strict_decoding_guard", "test_integration_docs_name_only_defaults_the_code_has"})
#: The beginnings of a name that make a module a plugin test by its name alone.
PLUGIN_PREFIXES = ("test_plugin_", "test_claude_code_plugin", "test_codex_plugin")
#: Texts that name the plugin. A module the selection catches by a word of its name ("gate", "plugin", test_codex) and
#: that has no plugin prefix is a plugin test only where it carries one of them: a test of the library named after one
#: of its own gates is none, and main brings such names in (test_core_layer_gate_judges_every_binding,
#: test_pr_form_gate). A text is a spelling, so the list fails open on one it does not know; the guard reads the syntax
#: tree instead (tests/test_plugin_env_guard.py, _touches_the_plugin) and is red where this list misses a module.
MARKERS = ("plugins/proofbundle", '"plugins"', "'plugins'", ".claude-plugin", ".codex-plugin", "proofbundle_gate",
           "pin_state_schleuse", "proofbundle_answered", "proofbundle_secrets", "proofbundle_mcp",
           "import test_plugin_", "from test_plugin_", "import test_claude_code_plugin", "import test_codex_plugin")

_withheld = 0


def is_plugin_test(path: os.PathLike | str) -> bool:
    """A test module of the plugin: one of ALSO_PLUGIN, a name with a plugin prefix, or a name the selection catches
    that carries a text naming the plugin, and never one of NOT_PLUGIN. A module whose text does not read keeps the
    stricter answer and counts as one."""
    p = pathlib.Path(path)
    if p.suffix != ".py" or not p.name.startswith("test_") or p.stem in NOT_PLUGIN:
        return False
    if p.stem in ALSO_PLUGIN or p.stem.startswith(PLUGIN_PREFIXES):
        return True
    rest = p.stem[len("test_"):]
    if not ("plugin" in rest or "gate" in rest or p.stem.startswith("test_codex")):
        return False
    try:
        text = p.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return True
    return any(marker in text for marker in MARKERS)


@pytest.fixture(scope="module", autouse=True)
def withhold_caller_environment(request):
    """For a plugin test module: every name but FIXED (and pytest's own) out of os.environ while the module runs."""
    global _withheld
    if not is_plugin_test(request.path):
        yield
        return
    with pytest.MonkeyPatch.context() as patch:
        for name in [n for n in os.environ if n not in FIXED and n != PYTEST_OWN]:
            patch.delenv(name)
        # pytest's pythonpath option, which the witness passes (-o pythonpath=src), puts src/ on sys.path of this
        # process only; a child started without PYTHONPATH imported the proofbundle its interpreter has installed
        # (measured on the witness of 31 October 2026: 6.0.0, without proofbundle._plain_value)
        spec = importlib.util.find_spec("proofbundle")
        if spec is not None and spec.origin:
            root = str(pathlib.Path(spec.origin).resolve().parent.parent)
            patch.setenv("PYTHONPATH", os.pathsep.join(p for p in (root, os.environ.get("PYTHONPATH")) if p))
        _withheld += 1
        try:
            yield
        finally:
            _withheld -= 1


def put_stand_in_uv_on_path(bin_dir: pathlib.Path, monkeypatch) -> str:
    """Put bin_dir, which holds the test's stand-in `uv`, first on this process's PATH and return that PATH; write the
    stand-in when bin_dir holds none. The gate a test calls in-process looks `uv` up on this process's PATH
    (verify_items, shutil.which), not in the environment the test hands a process. A runner without a `uv` of its own,
    as the CI runner and the witness are, found none there."""
    bin_dir.mkdir(parents=True, exist_ok=True)
    uv = bin_dir / "uv"
    if not uv.exists():
        uv.write_text(f'#!/bin/sh\nwhile [ "$1" != "--script" ]; do shift; done\nshift\nexec "{sys.executable}" "$@"\n',
                      encoding="utf-8")
        uv.chmod(0o700)
    path = os.pathsep.join([str(bin_dir), os.environ.get("PATH", "")])
    monkeypatch.setenv("PATH", path)
    return path


def plugin_env(*, without: tuple[str, ...] = (), **values: str | None) -> dict[str, str]:
    """The environment for a process or the gate: FIXED as it stands, the case's GIT_ and PROOFBUNDLE_ values, then
    `values` (None removes a name). Names starting with an entry of `without` are left out before `values` apply.
    Outside a plugin test module the caller's GIT_ and PROOFBUNDLE_ values are not withheld, so it refuses."""
    if not _withheld:
        raise RuntimeError("plugin_env() outside a plugin test module: the caller's environment is not withheld here")
    if isinstance(without, str):
        raise TypeError("without= takes a tuple of prefixes, not one string")
    env = {name: os.environ[name] for name in FIXED if name in os.environ}
    for name in os.environ:
        if name.startswith(CASE_PREFIXES):
            env[name] = os.environ[name]
    for name in [n for n in env if n.startswith(tuple(without))]:
        del env[name]
    for name, value in values.items():
        if value is None:
            env.pop(name, None)
        else:
            env[name] = value
    return env
