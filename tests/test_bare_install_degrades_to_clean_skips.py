"""N18: a bare install must degrade to clean skips, not to a collection error.

`pyproject.toml` promises, in the comment on the `test` extra, that "a bare `[eval]` install
degrades to clean skips (the optional-dep test modules guard their hypothesis/PyYAML imports and
skip at module level, never a collection error)". MEASURED 2026-09-23 against the published 6.1.0
sdist, that promise was false:

    pip install proofbundle-6.1.0.tar.gz        # no extras
    python -m pytest                            # in the extracted sdist
    -> ERROR tests/test_action_input_injection.py
       tests/test_action_input_injection.py:21: import yaml
       ModuleNotFoundError: No module named 'yaml'
       Interrupted: 1 error during collection
       19 skipped, 1 error

One unguarded line, and pytest abandons the whole run. 19 of some four thousand tests had been
collected. Five sibling modules guarded the same dependency correctly; this one did not.

WHY THE CLASS AND NOT THE LINE. Fixing the import closes today's instance and leaves tomorrow's
open: the next module that adds `import yaml` at top level reopens it, and nothing would say so.
The case below therefore asserts the PROPERTY over every test module, and it reads the set of
optional dependencies from `pyproject.toml` rather than from a list typed here. A typed list is a
second statement about which dependencies are optional, and two statements drift.

WHY IT WAS INVISIBLE. `.github/workflows/published-artifact-gate.yml` carries a step whose comment
says it pins exactly this invariant. The step installs the `[test]` extra and only then runs
pytest, so the bare case never executes there. A gate whose stated guarantee is broader than what
it runs reports green over a case it did not try.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TESTS = REPO / "tests"
PYPROJECT = REPO / "pyproject.toml"

#: Distribution names that map to a different import name.
_IMPORTNAME = {"PyYAML": "yaml", "sd-jwt": "sd_jwt", "inspect_ai": "inspect_ai"}
#: Always present with the runner itself; guarding it would be noise.
_IMMER_DA = {"pytest"}


def _verteilungsnamen(block: str) -> set[str]:
    """The distribution names in a TOML list block, without their version constraints."""
    return set(re.findall(r"[\"']([^\"'<>=!~ ]+)", block))


def _block(text: str, muster: str) -> str | None:
    m = re.search(muster, text, re.M | re.S)
    return m.group(1) if m else None


def _optionale_importnamen() -> set[str]:
    """The import names a BARE install does not provide.

    NOT SIMPLY THE `test` EXTRA, and that was a measured defect. Codex, review of 2026-09-23:
    `rfc8785` is a CORE dependency and ALSO listed in both the `eval` and the `test` extra. The
    first version added every non-pytest member of `test` to the supposedly absent set, so a module
    containing only `import rfc8785` was reported unguarded although the bare `[eval]` environment
    the workflow builds provides it and collects it fine. A false red, and it would have been read
    as a defect in the package rather than in this case.

    THE SET THIS CASE IS ABOUT is what `test` adds ON TOP of what the bare install already has, so
    the core dependencies and the `eval` extra are subtracted. The subtraction is derived from
    `pyproject.toml` for the same reason the rest is: a second statement about what is optional
    would drift from the first.
    """
    text = PYPROJECT.read_text(encoding="utf-8")
    roh_test = _block(text, r"^test\s*=\s*\[(.*?)\]")
    if roh_test is None:
        raise AssertionError(
            "the `test` extra is not in pyproject.toml — this case reads the optional set from "
            "there on purpose, and a missing source is not a clearance")
    vorhanden = set(_IMMER_DA)
    for muster in (r"^dependencies\s*=\s*\[(.*?)\]", r"^eval\s*=\s*\[(.*?)\]"):
        block = _block(text, muster)
        if block is None:
            raise AssertionError(
                f"pyproject.toml carries no block matching {muster!r} — without it this case cannot "
                "say what the bare install already provides, and guessing would make it lie")
        vorhanden |= _verteilungsnamen(block)
    namen = set()
    for roh in _verteilungsnamen(roh_test):
        if roh in vorhanden:
            continue
        namen.add(_IMPORTNAME.get(roh, roh.replace("-", "_")))
    return namen


class EinNacktesInstallierenBrichtDieSammlungNicht(unittest.TestCase):

    def test_the_test_extra_is_readable_and_not_empty(self):
        """Without this the sweep below could pass over an empty set and say nothing.

        A run that measured nothing looks exactly like a run that found nothing, and this file
        exists because of a promise that was green while untested.
        """
        namen = _optionale_importnamen()
        self.assertTrue(namen, "no optional import names derived from the `test` extra")
        self.assertIn("yaml", namen, "PyYAML is in the `test` extra and must map to `yaml`")

    def test_no_test_module_imports_an_optional_dependency_unguarded(self):
        """THE PROPERTY, over every test module, not over the one that failed.

        A module may use an optional dependency; it must not make collection depend on it.
        `pytest.importorskip` at module level turns a missing dependency into a skip, which is
        what the promise in `pyproject.toml` says happens.
        """
        namen = _optionale_importnamen()
        verstoesse = []
        for f in sorted(TESTS.rglob("*.py")):
            text = f.read_text(encoding="utf-8", errors="replace")
            for name in namen:
                top = re.search(rf"^(?:import {re.escape(name)}\b|from {re.escape(name)}[\. ])",
                                text, re.M)
                if not top:
                    continue
                # THE GUARD MUST COME FIRST, and that is the whole property. Codex, review of
                # 2026-09-23: this search ran over the WHOLE file, so `import yaml` on line 1
                # followed by `yaml = pytest.importorskip("yaml")` on line 50 reported no
                # violation, while executing that module without PyYAML raises ModuleNotFoundError
                # before line 50 is ever reached. Every optional dependency checked here had that
                # same false-green path — in the one case whose reason for existing is to catch a
                # false green.
                guarded = re.search(rf"importorskip\(\s*[\"']{re.escape(name)}[\"']", text)
                if not guarded or guarded.start() > top.start():
                    zeile = text[: top.start()].count("\n") + 1
                    wo = ("unguarded" if not guarded else
                          f"guarded only at line {text[: guarded.start()].count(chr(10)) + 1}, "
                          f"which is AFTER the import and therefore never reached")
                    verstoesse.append(f"{f.relative_to(REPO)}:{zeile} imports {name} {wo}")
        self.assertFalse(
            verstoesse,
            "a bare install would abandon collection on these modules instead of skipping them:\n  "
            + "\n  ".join(verstoesse))

    def test_counter_direction_a_guarded_module_is_accepted(self):
        """Without this the sweep would also pass for a rule that rejects every use.

        The property is not "do not use optional dependencies"; it is "do not make collection
        depend on them". At least one module must use one AND be accepted.
        """
        namen = _optionale_importnamen()
        gefunden = [
            f.relative_to(REPO)
            for f in sorted(TESTS.rglob("*.py"))
            for name in namen
            if re.search(rf"importorskip\(\s*[\"']{re.escape(name)}[\"']",
                         f.read_text(encoding="utf-8", errors="replace"))
        ]
        self.assertTrue(
            gefunden,
            "no module guards an optional dependency at all — then the sweep above proves nothing, "
            "because it would be green over an empty set")


if __name__ == "__main__":
    unittest.main()


# ───────── Two Codex findings on PR 253, both against the checker itself ─────────


class TheSweepMeasuresWhatABareInstallReallyLacks(unittest.TestCase):
    """FINDING A: `rfc8785` is a core dependency AND appears in both `eval` and `test`.

    The first version treated every non-pytest member of `test` as absent, so a module containing
    only `import rfc8785` counted as unguarded although the bare `[eval]` environment the workflow
    builds provides it and collects it without complaint. A false red, and it would have looked
    like a defect in the package rather than one in this case.
    """

    def test_a_shared_dependency_does_not_count_as_absent(self):
        namen = _optionale_importnamen()
        self.assertNotIn("rfc8785", namen,
                         "rfc8785 is in [project] dependencies and in the eval extra, so the bare "
                         "install has it and it is nothing optional here")

    def test_counter_direction_the_genuinely_optional_ones_remain(self):
        """WITHOUT THIS CASE a subtraction that removes EVERYTHING would pass, over an empty set."""
        namen = _optionale_importnamen()
        for erwartet in ("yaml", "hypothesis", "jsonschema", "sd_jwt"):
            self.assertIn(erwartet, namen,
                          f"{erwartet} is only in the test extra and must be checked")


class TheGuardMustPrecedeTheImport(unittest.TestCase):
    """FINDING B, guard-order blindness, and the more serious of the two.

    The search ran over the WHOLE file. `import yaml` on line 1 and
    `yaml = pytest.importorskip("yaml")` on line 50 reported no violation, while executing that
    module without PyYAML raises ModuleNotFoundError long before line 50 is reached. Every optional
    dependency checked here had that same false-green path, in the one case whose reason for
    existing is to catch a false green.
    """

    def _sweep(self, quelle: str) -> list[str]:
        """Run the sweep against ONE invented module text, without touching the repository."""
        namen = _optionale_importnamen()
        verstoesse = []
        for name in namen:
            top = re.search(rf"^(?:import {re.escape(name)}\b|from {re.escape(name)}[\. ])",
                            quelle, re.M)
            if not top:
                continue
            guarded = re.search(rf"importorskip\(\s*[\"\']{re.escape(name)}[\"\']", quelle)
            if not guarded or guarded.start() > top.start():
                verstoesse.append(name)
        return verstoesse

    def test_a_guard_after_the_import_saves_nothing(self):
        spaet = 'import yaml\n\n\ndef f():\n    pass\n\n\nyaml = pytest.importorskip("yaml")\n'
        self.assertEqual(self._sweep(spaet), ["yaml"],
                         "a guard AFTER the import is never reached at runtime and must not pass "
                         "the sweep")

    def test_counter_direction_the_right_order_is_accepted(self):
        """WITHOUT THIS CASE a rule that rejects EVERY use would pass and still be wrong."""
        frueh = 'import pytest\n\nyaml = pytest.importorskip("yaml")\n\nimport yaml\n'
        self.assertEqual(self._sweep(frueh), [],
                         "with the guard before the import the property holds")

    def test_counter_direction_no_use_at_all_is_no_finding(self):
        self.assertEqual(self._sweep("x = 1\n"), [])
