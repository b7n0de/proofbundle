"""The environment a plugin test gives a process or the gate (Nachtrag 6 to FIX-18 part B, point 1).

A plugin test hands neither a process nor the gate in-process the caller's environment. A token, an askpass program
or a GIT_ value the caller set reaches neither the gate under test nor the output of a failing test, and a run with
them set ends as a run without them. Two pieces hold that:

* `withhold_caller_environment`, a module-scoped autouse fixture tests/conftest.py imports, takes every name but
  those in FIXED out of os.environ before the first fixture of a plugin test module and puts them back after its last
  test. A process a test starts without env=, and the gate a test calls in-process, see the fixed list and what the
  test set itself.
* `plugin_env(**values)` builds the environment a test hands a process or the gate explicitly: the names in FIXED as
  they stand, the GIT_ and PROOFBUNDLE_ values the case set (with the caller's withheld, only the case's are left),
  and `values`, where None takes a name out. `without` names prefixes the result leaves out.

tests/test_plugin_env_guard.py holds both: no plugin test passes os.environ, a copy of it or a mapping built from it
to a process or the gate, except the named places, and planted cases show the guard finds each form."""
from __future__ import annotations

import os
import pathlib

import pytest

#: The names a plugin test keeps from its caller.
FIXED = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "PYTHONPATH")
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

_withheld = 0


def is_plugin_test(path: os.PathLike | str) -> bool:
    """A test module of the plugin: a name the selection catches and not one of NOT_PLUGIN."""
    p = pathlib.Path(path)
    if p.suffix != ".py" or not p.name.startswith("test_") or p.stem in NOT_PLUGIN:
        return False
    rest = p.stem[len("test_"):]
    return "plugin" in rest or "gate" in rest or p.stem.startswith("test_codex")


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
        _withheld += 1
        try:
            yield
        finally:
            _withheld -= 1


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
