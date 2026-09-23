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


def _optionale_importnamen() -> set[str]:
    """The import names a BARE install does not provide, read from the `test` extra."""
    text = PYPROJECT.read_text(encoding="utf-8")
    m = re.search(r"^test\s*=\s*\[(.*?)\]", text, re.M | re.S)
    if not m:
        raise AssertionError(
            "the `test` extra is not in pyproject.toml — this case reads the optional set from "
            "there on purpose, and a missing source is not a clearance")
    namen = set()
    for roh in re.findall(r"[\"']([^\"'<>=!~ ]+)", m.group(1)):
        if roh in _IMMER_DA:
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
                guarded = re.search(rf"importorskip\(\s*[\"']{re.escape(name)}[\"']", text)
                if not guarded:
                    zeile = text[: top.start()].count("\n") + 1
                    verstoesse.append(f"{f.relative_to(REPO)}:{zeile} imports {name} unguarded")
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
