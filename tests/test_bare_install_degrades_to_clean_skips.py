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

import ast
import importlib.util
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


def _faengt_importfehler(handler: ast.ExceptHandler) -> bool:
    """Does this `except` clause catch a failing import?

    `except ImportError`, `except ModuleNotFoundError`, `except Exception`, a tuple containing any of
    them, and a bare `except` all do. Anything narrower does not, and then the import can still
    abandon collection.
    """
    faengt = {"ImportError", "ModuleNotFoundError", "Exception", "BaseException"}
    if handler.type is None:                       # bare except
        return True
    kandidaten = (handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type])
    for k in kandidaten:
        name = (k.id if isinstance(k, ast.Name) else
                k.attr if isinstance(k, ast.Attribute) else "")
        if name in faengt:
            return True
    return False


def _nur_fuer_typpruefer(test: ast.expr) -> bool:
    """Is this branch dead at runtime, so an import inside it cannot break collection?

    `if TYPE_CHECKING:` and `if typing.TYPE_CHECKING:` are the shapes that matter; `if False:` is
    included because it is the same statement with the constant written out.
    """
    if isinstance(test, ast.Name) and test.id == "TYPE_CHECKING":
        return True
    if isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING":
        return True
    return isinstance(test, ast.Constant) and test.value is False


def _modul_skip_zeile(baum: ast.Module) -> int | None:
    """The line of a module-level `skip(..., allow_module_level=True)`, or None.

    READ FROM THE TREE, NOT FROM THE TEXT, and un's cross-reading of 2026-09-24 is why. The first
    version searched `pytest\\.skip\\(.*allow_module_level=True` with a regular expression, and three
    valid spellings escaped it: `from pytest import skip` then a bare `skip(...)`, a call split over
    several lines, and `allow_module_level = True` written with spaces. Each of those is a correct
    module-level skip reported as a violation — a false RED, which is the safer direction and still a
    wrong answer.

    It was also the same asymmetry as everywhere else in this round. One side of the comparison read
    the syntax tree, the other scanned text. Both sides read the tree now.

    MODULE LEVEL ONLY, and that was a gap I nearly wrote past. The first version walked the whole
    tree, so a `skip(..., allow_module_level=True)` inside a FUNCTION would have counted, and a skip
    in a function does not run during collection, so it guards nothing. I noticed it while writing the
    case for this and started to dodge it with a disabled assertion instead of fixing it. The
    statements are filtered the same way `_kandidaten` filters them.
    """
    for oben in baum.body:
        if isinstance(oben, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        for knoten in ast.walk(oben):
            if not isinstance(knoten, ast.Call):
                continue
            ruf = knoten.func
            name = (ruf.attr if isinstance(ruf, ast.Attribute) else
                    ruf.id if isinstance(ruf, ast.Name) else "")
            if name != "skip":
                continue
            for kw in knoten.keywords:
                if kw.arg == "allow_module_level" and isinstance(kw.value, ast.Constant) \
                        and kw.value.value is True:
                    return knoten.lineno
    return None


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


class EinNichtAusgelieferteSkriptIstDIESELBEKlasse(unittest.TestCase):
    """THE NEIGHBOUR OF THE RULE ABOVE, and it cost a red cleanroom job to find.

    The sweep above protects collection from a missing optional DEPENDENCY. Collection can depend on
    a missing REPOSITORY FILE in exactly the same way, and nothing said so. Measured 2026-09-24:
    `tests/test_render_release.py` did `sys.path.insert(..., "scripts")` and then imported
    `render_release` at module level. `MANIFEST.in` names every shipped `scripts/` file one by one,
    by owner requirement of 2026-09-06, and it does not name that one — a release-notes renderer is a
    maintainer tool no consumer needs. So the hermetic cleanroom installed the extracted sdist, ran
    `pytest --collect-only`, hit the absent module and exited 2.

    Same shape, same consequence, different missing thing. A guard that knows only one of the two
    reports green over the other, which is what happened.

    THE RULE: a test module may import a repository script, but it must not make COLLECTION depend on
    one the sdist does not ship. The way through is the PATH FORM,
    `importlib.util.spec_from_file_location` against an absolute path.

    WHY NOT A MODULE-LEVEL SKIP, WHICH IS WHAT I BUILT FIRST AND WHAT THIS CLASS ORIGINALLY SAID.
    `tests/test_kein_blanker_import_eines_nicht_ausgelieferten.py` is the class guard for exactly this
    incident, it predates this case, and it prescribes the path form. I did not look for it before
    writing a neighbour rule, so the full suite of 2026-09-24 went red on it while this case was green
    — two guards over one class, disagreeing on the remedy.

    ITS REMEDY IS ALSO THE BETTER ONE, and the reason is measured rather than stylistic. The path form
    raises `FileNotFoundError` carrying `.filename`, and `tests/conftest.py` turns that into a skip
    ONLY after asking `_verteilung_sollte_enthalten`: a file the distribution list DOES name and that
    is nevertheless absent stays loud, because that is a packaging error. A per-module
    `if not SKRIPT.is_file(): pytest.skip(...)` cannot ask that question. It skips in both cases, so it
    would convert a broken sdist into a green run — which is precisely what the docstring of
    `_verteilung_sollte_enthalten` warns about, one level up: the guard against abandoned collection
    would have disarmed the guard against false packaging. A module-level skip is therefore NOT
    accepted here, and the case below pins that in all four spellings of it.
    """

    def _kandidaten(self, wurzel: Path | None = None) -> list[tuple[Path, str, int]]:
        """Test modules that import something living in `scripts/`, and WHERE they do it.

        THE FIRST VERSION REQUIRED A LITERAL `sys.path.insert(... "scripts" ...)` AND WAS WRONG.
        An adversarial lens refuted it on 2026-09-24 with three shapes, each proven by a real
        `pytest --collect-only` ending in `Interrupted: 1 error during collection`:

            importlib.import_module("render_release")      not seen at all
            sys.path.append(...) instead of .insert(...)   not seen at all
            sys.path.insert(0, str(SKRIPT_ORDNER))         the word `scripts` was on the line
                                                          ABOVE, so the expression missed it

        All three abandon collection exactly as the reported incident did. A guard that recognises
        one spelling of how a directory reaches `sys.path` is describing that spelling, not the
        property — which is the class this whole file stands against, turned on the newest case in
        it.

        SO THE PATH MANIPULATION IS NO LONGER PART OF THE TEST. What matters is that a module-level
        import names something that exists as `scripts/<name>.py`; HOW the path got there is the
        caller's business and has as many spellings as Python allows. Measured before dropping it:
        of the 41 modules under `scripts/`, none shadows a stdlib name, so widening this way adds no
        false positive from a coincidental name.

        AND IT READS THE SYNTAX TREE, NOT THE TEXT, because the widened expressions immediately
        flagged this docstring. The examples above contain the literal call they describe, so a text
        scanner reported the guard's own documentation as a violation — the same class one more time,
        a reader that cannot tell prose from code. `ast` also answers something no expression can:
        whether the import sits at MODULE level, where it runs during collection, or inside a
        function, where it does not and therefore is not this property's business.

        THE ROOT IS A PARAMETER ON BOTH SIDES, and getting that wrong was a real defect, measured by
        `hermetic-cleanroom` on 2026-09-24. This scan read its test modules from the root it was
        GIVEN and then asked whether `REPO / "scripts" / <name>.py` exists, which is the module-level
        constant. In a checkout that file is there, so every invented case produced a candidate and
        every subtest passed. In the extracted sdist it is not there, so nine positive subtests
        silently read `[]` and the job went red, on a run whose subject was something else entirely.

        `tests/test_kein_blanker_import_eines_nicht_ausgelieferten.py` carries that same sentence in
        the docstring of `_pfadeintraege`, about its own first version, and I would have had it for
        free by reading the guard for this class before writing a neighbour for it.
        """
        wurzel = wurzel or REPO
        aus = []
        for f in sorted((wurzel / "tests").rglob("*.py")):
            try:
                baum = ast.parse(f.read_text(encoding="utf-8", errors="replace"), filename=str(f))
            except SyntaxError:
                continue
            for knoten in baum.body:                       # MODULE LEVEL ONLY, by construction
                for name, zeile in self._namen_im_knoten(knoten):
                    if (wurzel / "scripts" / f"{name}.py").is_file():
                        aus.append((f, f"scripts/{name}.py", zeile))
        return aus

    @staticmethod
    def _erfundener_baum(d: Path, quelle: str) -> Path:
        """A self-contained tree for one invented module, root-shaped like the repository.

        Every invented case builds BOTH halves it needs, the test module and the script it imports,
        so no case borrows a fact from the real tree. That borrowing is what broke in the cleanroom.
        """
        (d / "tests").mkdir(parents=True, exist_ok=True)
        (d / "scripts").mkdir(parents=True, exist_ok=True)
        (d / "scripts" / "render_release.py").write_text("WERT = 1\n", encoding="utf-8")
        (d / "tests" / "test_erfunden.py").write_text(quelle, encoding="utf-8")
        return d

    @staticmethod
    def _namen_im_knoten(knoten: ast.stmt) -> list[tuple[str, int]]:
        """Imported names in one module-level statement, including the dynamic forms.

        A statement at module level may be an `if`, a `try` or a `with` whose body still runs during
        collection, so those are descended into. A `FunctionDef` or `ClassDef` body is NOT, because
        an import there runs when the function is called, and this property is about collection.
        """
        aus: list[tuple[str, int]] = []
        if isinstance(knoten, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return aus
        # A CAUGHT IMPORT DOES NOT ABANDON COLLECTION, so it is not this property's business. un,
        # cross-reading of 2026-09-24: `try: import x` with an `except ImportError` around it was
        # reported as a violation although the module collects fine. That is a false RED — the safer
        # direction, but still a wrong answer, and a guard that cries over correct code gets ignored.
        #
        # THE SAME GOES FOR A BRANCH THAT NEVER RUNS. `if TYPE_CHECKING:` is deliberately dead at
        # runtime, and an import there cannot break collection either.
        if isinstance(knoten, ast.Try) and any(
                _faengt_importfehler(h) for h in knoten.handlers):
            return aus
        if isinstance(knoten, ast.If) and _nur_fuer_typpruefer(knoten.test):
            return aus
        for k in ast.walk(knoten):
            if isinstance(k, ast.Import):
                aus += [(a.name.split(".")[0], k.lineno) for a in k.names]
            elif isinstance(k, ast.ImportFrom) and k.module and not k.level:
                aus.append((k.module.split(".")[0], k.lineno))
            elif isinstance(k, ast.Call) and k.args and isinstance(k.args[0], ast.Constant) \
                    and isinstance(k.args[0].value, str):
                ruf = k.func
                gerufen = (ruf.attr if isinstance(ruf, ast.Attribute) else
                           ruf.id if isinstance(ruf, ast.Name) else "")
                if gerufen in {"import_module", "__import__"}:
                    aus.append((k.args[0].value.split(".")[0], k.lineno))
        return aus

    def _ausgeliefert(self) -> set[str]:
        """The shipped `scripts/` set, read as DIRECTIVES rather than scraped with one expression.

        WHY NOT THE ONE EXPRESSION IT STARTED AS. An adversarial lens ran this against a real
        `python -m build --sdist` on 2026-09-24 and the sets matched, 36 of 36, symmetric difference
        zero. It then named four forms that would make the same expression wrong LATER, and measured
        each in isolation:

            include scripts/a.py scripts/b.py     only the first path was seen
            <two spaces>include scripts/c.py      the line dropped out entirely
            recursive-include scripts *.py        the whole set went invisible
            include scripts/e.py + exclude same   reported shipped although excluded

        None of the four is in the file today, so this is a hole being closed rather than a defect
        being fixed. But a derivation that is right only for the current spelling of its input is the
        class this whole file stands against, so it now reads the directives: leading whitespace is
        stripped, every path on a line counts, `exclude` and `prune` SUBTRACT, and a directive that
        would make the set unknowable fails loudly instead of returning a smaller set.
        """
        return self._ausgeliefert_aus((REPO / "MANIFEST.in").read_text(encoding="utf-8"))

    def _ausgeliefert_aus(self, text: str) -> set[str]:
        """The parsing, separable from the file, so the four forms above can be measured."""
        drin: set[str] = set()
        draussen: set[str] = set()
        for roh in text.splitlines():
            zeile = roh.strip()
            if not zeile or zeile.startswith("#"):
                continue
            teile = zeile.split()
            direktive, pfade = teile[0], teile[1:]
            if direktive in {"graft", "recursive-include", "recursive-exclude", "global-include",
                             "global-exclude"} and any(
                    p == "scripts" or p.startswith("scripts/") for p in pfade):
                self.fail(
                    f"MANIFEST.in line {roh.strip()!r} uses `{direktive}` over `scripts`, so this "
                    f"case can no longer tell a shipped file from an unshipped one. The owner "
                    f"requirement of 2026-09-06 replaced a `graft scripts` with an explicit list; a "
                    f"return to a wildcard form is the finding, not something to work around here")
            ziel = drin if direktive == "include" else (
                draussen if direktive in {"exclude", "prune"} else None)
            if ziel is None:
                continue
            ziel.update(p for p in pfade if p.startswith("scripts/"))
        return drin - draussen

    def test_der_messaufbau_findet_ueberhaupt_etwas(self):
        """[ZAEHLT] An empty candidate list would make the case below pass over nothing."""
        self.assertTrue(self._kandidaten(),
                        "no test module imports a repository script, so the sweep below would be "
                        "green without having looked at anything")

    def test_keine_sammlung_haengt_an_einem_nicht_ausgelieferten_skript(self):
        """A module-level import of an unshipped script is the finding, with no local way out.

        THERE IS NO SKIP EXCEPTION HERE ANY MORE, and removing it is the reconciliation with the class
        guard named in this class's docstring. An earlier version accepted a module-level
        `skip(..., allow_module_level=True)` placed before the import, which made this case green on
        a module the class guard still reported. Measured before the removal: of the 8 test modules
        that import a repository script, all 8 import a SHIPPED one, so nothing in this tree relied on
        that exception and dropping it turns nothing red.
        """
        ausgeliefert = self._ausgeliefert()
        verstoesse = [f"{f.relative_to(REPO)}:{stelle} imports {kand} at module level"
                      for f, kand, stelle in self._kandidaten() if kand not in ausgeliefert]
        self.assertFalse(
            verstoesse,
            "the extracted sdist would abandon collection on these modules, because the script they "
            "import is not in MANIFEST.in. The way through is the path form, "
            "`importlib.util.spec_from_file_location`, which raises FileNotFoundError with a "
            "filename, so tests/conftest.py can tell a never-shipped file from a packaging error:\n  "
            + "\n  ".join(verstoesse))

    def test_die_drei_umgehungen_der_linse_werden_gefunden(self):
        """THE THREE SHAPES THAT REFUTED THE FIRST VERSION, each pinned as its own subtest.

        An adversarial lens ran these on 2026-09-24 and proved every one with a real
        `pytest --collect-only` ending in `Interrupted: 1 error during collection` — the same
        abandonment as the incident this class exists for. The first version saw none of them,
        because it required a literal `sys.path.insert(... "scripts" ...)` before it would look at a
        file at all.

        A fourth shape is here as the counter-direction, and it is the one that stops this from
        becoming a blanket refusal: an import INSIDE a function does not run during collection, so it
        is not this property's business and must NOT be reported.
        """
        import tempfile
        formen = {
            "importlib.import_module": (
                "import importlib, sys\nfrom pathlib import Path\n"
                "sys.path.insert(0, str(Path(__file__).parents[1] / 'scripts'))\n"
                "m = importlib.import_module('render_release')\n", True),
            "sys.path.append statt insert": (
                "import sys\nfrom pathlib import Path\n"
                "sys.path.append(str(Path(__file__).parents[1] / 'scripts'))\n"
                "import render_release\n", True),
            "Pfad ueber eine Variable": (
                "import sys\nfrom pathlib import Path\n"
                "ORDNER = Path(__file__).parents[1] / 'scripts'\n"
                "sys.path.insert(0, str(ORDNER))\nimport render_release\n", True),
            "Gegenrichtung, Import in einer Funktion": (
                "def f():\n    import render_release\n    return render_release\n", False),
        }
        for name, (quelle, erwartet) in formen.items():
            with self.subTest(form=name):
                with tempfile.TemporaryDirectory() as d:
                    treffer = self._kandidaten(wurzel=self._erfundener_baum(Path(d), quelle))
                self.assertEqual(
                    bool(treffer), erwartet,
                    f"{name}: expected {'a candidate' if erwartet else 'no candidate'}, "
                    f"read {treffer}")

    def test_die_drei_falschen_rot_von_un_werden_nicht_mehr_gemeldet(self):
        """THREE FALSE REDS un's CROSS-READING FOUND, each pinned with its counter-direction.

        A false red is the safer direction and still a wrong answer: a guard that cries over correct
        code gets ignored, and then it is no longer a guard. All three were reported as violations
        although the module collects fine.

        The fourth finding of that reading is NOT here, because it was measured and refuted:
        `exclude-package-data` in `pyproject.toml` was said to remove a file from the sdist while
        `MANIFEST.in` still lists it. Measured with two real `python -m build --sdist` runs over the
        same tree, the file stays in the tarball both with and without that key — it governs the
        installed package, not the sdist file list.
        """
        import tempfile
        formen = {
            "try/except ImportError faengt den Import": (
                "try:\n    import render_release\nexcept ImportError:\n    render_release = None\n",
                False),
            "try/except Exception faengt auch": (
                "try:\n    import render_release\nexcept Exception:\n    pass\n", False),
            "if TYPE_CHECKING laeuft nie": (
                "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    import render_release\n",
                False),
            "Gegenrichtung, try ohne passenden handler": (
                "try:\n    import render_release\nexcept ValueError:\n    pass\n", True),
            "Gegenrichtung, ein echtes if laeuft": (
                "import os\nif os.environ.get('X'):\n    import render_release\n", True),
        }
        for name, (quelle, erwartet) in formen.items():
            with self.subTest(form=name):
                with tempfile.TemporaryDirectory() as d:
                    treffer = self._kandidaten(wurzel=self._erfundener_baum(Path(d), quelle))
                self.assertEqual(
                    bool(treffer), erwartet,
                    f"{name}: expected {'a candidate' if erwartet else 'no candidate'}, "
                    f"read {treffer}")

    def test_ein_modulweiter_skip_ist_KEIN_ausweg_in_vier_schreibweisen(self):
        """THE DECISION AGAINST THE SKIP, stated over every spelling rather than over one.

        A module-level skip DOES prevent the collection error, so this is not a claim that it fails to
        work. It is a claim that it answers a narrower question than `tests/conftest.py` asks: the
        module knows only whether the file is there, while conftest also asks whether the distribution
        SAYS it should be there, and keeps a packaging error loud. A per-module skip cannot make that
        distinction and would turn a broken sdist green.

        un's cross-reading of 2026-09-24 named four spellings that escaped a regular expression, and
        the detector still recognises all four — which is what makes these subtests worth something.
        Each module here carries a CORRECT module-level skip before the import and is nevertheless
        reported, so the finding cannot be explained away as a detector that missed the skip.
        """
        import tempfile
        skips = {
            "pytest.skip mit Punkt": 'import pytest\npytest.skip("x", allow_module_level=True)\n',
            "from pytest import skip": 'from pytest import skip\nskip("x", allow_module_level=True)\n',
            "ueber mehrere Zeilen": 'import pytest\npytest.skip(\n    "x",\n    allow_module_level=True,\n)\n',
            "mit Leerzeichen um das Gleich": 'import pytest\npytest.skip("x", allow_module_level = True)\n',
        }
        for name, kopf in skips.items():
            with self.subTest(form=name):
                self.assertIsNotNone(_modul_skip_zeile(ast.parse(kopf)),
                                     f"{name}: the detector no longer sees this module-level skip, so "
                                     f"the assertion below would pass for the wrong reason")
                with tempfile.TemporaryDirectory() as d:
                    baum = self._erfundener_baum(Path(d), kopf + "import render_release\n")
                    self.assertTrue(self._kandidaten(wurzel=baum),
                                    f"{name}: a module-level skip must not buy an exception from this "
                                    f"rule — the path form is the way through")
        # COUNTER-DIRECTION for the detector itself: without the keyword it is not a module-level skip,
        # and a skip inside a function does not run during collection at all.
        self.assertIsNone(_modul_skip_zeile(ast.parse('import pytest\npytest.skip("x")\n')),
                          "a skip without allow_module_level is not a module-level skip")
        self.assertIsNone(
            _modul_skip_zeile(ast.parse('import pytest\ndef f():\n    pytest.skip("x", '
                                        'allow_module_level=True)\n')),
            "a skip inside a function does not run during collection and guards nothing")

    def test_gegenrichtung_die_pfadform_ist_kein_befund(self):
        """THE REMEDY MUST PASS, or the rule above is a rule with no way to satisfy it.

        Measured executably rather than assumed: `spec_from_file_location` against an absent path
        raises `FileNotFoundError` whose `.filename` is that path, which is exactly the shape
        `tests/conftest.py::_fehlende_datei_aus` reads before it decides between an honest skip and a
        loud packaging error.
        """
        import tempfile
        pfadform = ('import importlib.util, sys\nfrom pathlib import Path\n'
                    'S = Path(__file__).parents[1] / "scripts" / "render_release.py"\n'
                    '_spec = importlib.util.spec_from_file_location("_rr", S)\n'
                    '_m = importlib.util.module_from_spec(_spec)\n'
                    'sys.modules["_rr"] = _m\n_spec.loader.exec_module(_m)\n')
        with tempfile.TemporaryDirectory() as d:
            baum = self._erfundener_baum(Path(d), pfadform)
            self.assertEqual(self._kandidaten(wurzel=baum), [],
                             "the prescribed remedy is reported as a violation, so the rule cannot be "
                             "satisfied at all")
        with tempfile.TemporaryDirectory() as d:
            spec = importlib.util.spec_from_file_location("_weg", str(Path(d) / "fehlt.py"))
            modul = importlib.util.module_from_spec(spec)
            with self.assertRaises(FileNotFoundError) as gefangen:
                spec.loader.exec_module(modul)
        self.assertEqual(gefangen.exception.filename, str(Path(d) / "fehlt.py"),
                         "the path form no longer names the missing file, so conftest could not tell "
                         "a never-shipped file from a packaging error")

    def test_die_zwei_wahrheiten_ueber_das_ausgelieferte_stimmen_ueberein(self):
        """TWO GROUND TRUTHS FOR ONE CLASS, and they have drifted in this tree before.

        This case derives the shipped set from `MANIFEST.in`, the DECLARATION. The class guard and
        `tests/conftest.py` both read `*.egg-info/SOURCES.txt`, the RESULT of setuptools' computation,
        because the two are recorded as having diverged here (Restrisiko S27: a deleted MANIFEST line
        survived in an old SOURCES.txt). Each choice has its reason — the result is what a consumer
        actually receives, the declaration is readable without a build having happened — and keeping
        both means a divergence would make one guard green while the other is red, over the same file.

        So the divergence is measured instead of left to be discovered. Without SOURCES.txt the
        question is NOT MEASURABLE, and that is a skip with a reason, not a pass.
        """
        listen = (sorted(REPO.glob("*/*.egg-info/SOURCES.txt"))
                  + sorted(REPO.glob("*.egg-info/SOURCES.txt")))
        quelle = next((p for p in listen if p.read_text(encoding="utf-8").strip()), None)
        if quelle is None:
            self.skipTest("NOT MEASURABLE: no SOURCES.txt in the tree. One `python -m build --sdist` "
                          "creates it. An absent basis is not a clearance.")
        gelistet = {z.strip() for z in quelle.read_text(encoding="utf-8").splitlines() if z.strip()}
        aus_manifest = self._ausgeliefert()
        self.assertTrue(any(e.startswith("scripts/") for e in gelistet),
                        f"{quelle.relative_to(REPO)} names no scripts/ entry at all, so the comparison "
                        f"below would be green over an empty set")
        nur_manifest = sorted(aus_manifest - gelistet)
        nur_sources = sorted(e for e in gelistet if e.startswith("scripts/")
                             and e not in aus_manifest)
        self.assertEqual(
            (nur_manifest, nur_sources), ([], []),
            f"the declaration and the computed file list disagree about scripts/. Only in "
            f"MANIFEST.in: {nur_manifest}. Only in {quelle.name}: {nur_sources}. One of the two "
            f"guards over this class would be green while the other is red")

    def test_der_uebergebene_baum_entscheidet_BEIDE_seiten(self):
        """THE PROPERTY THAT BROKE IN THE CLEANROOM, pinned so it cannot break silently again.

        The scan asks two questions, where the test modules are and whether the imported name exists
        as a script. Until 2026-09-24 the first read the root it was given and the second read the
        module-level `REPO`. A checkout satisfies both by accident, so nothing showed; the extracted
        sdist has no `scripts/render_release.py`, and every invented case went quietly empty. Nine
        subtests read `[]` and reported it as a failed expectation, on a job about something else.

        Measured here over TWO trees that differ in exactly one file, so the case says which side
        decides rather than only that something changed.
        """
        import tempfile
        quelle = "import render_release\n"
        with tempfile.TemporaryDirectory() as d:
            baum = self._erfundener_baum(Path(d), quelle)
            self.assertTrue(self._kandidaten(wurzel=baum),
                            "with the script present in the GIVEN tree there must be a candidate")
            (baum / "scripts" / "render_release.py").unlink()
            self.assertEqual(self._kandidaten(wurzel=baum), [],
                             "the script is absent from the given tree, so nothing may be reported; "
                             "reading REPO here is what made the cleanroom run go red")

    def test_die_eigene_dokumentation_ist_kein_verstoss(self):
        """THE FALSE POSITIVE THE WIDENING PRODUCED, before `ast` replaced the expressions.

        The docstrings in this class quote the very calls they describe. A text scanner therefore
        reported the guard's own documentation as a violation — the same class one more time, a
        reader that cannot tell prose from code. Measured: this file is not among the candidates,
        although its text contains both `import_module(` and an import of the script by name.
        """
        eigene = [str(f) for f, _, _ in self._kandidaten() if f.name == Path(__file__).name]
        self.assertEqual(eigene, [],
                         "this file's own prose is being read as code again")

    def test_die_vier_formen_der_linse_werden_richtig_gelesen(self):
        """THE FOUR FORMS AN ADVERSARIAL LENS NAMED ON 2026-09-24, each as its own case.

        The lens compared this derivation against a real `python -m build --sdist` and the sets
        matched, 36 of 36. It then measured four spellings that would have made the one-expression
        version wrong later. None of them is in the file today, which is why these cases carry
        invented input rather than the real one: a hole is closed by showing the new reader handles
        the shape, not by waiting for the shape to arrive.
        """
        faelle = {
            "zwei Pfade auf einer Zeile": ("include scripts/a.py scripts/b.py\n",
                                           {"scripts/a.py", "scripts/b.py"}),
            "fuehrender Leerraum": ("  include scripts/c.py\n", {"scripts/c.py"}),
            "exclude nimmt zurueck": ("include scripts/e.py\nexclude scripts/e.py\n", set()),
            "prune nimmt zurueck": ("include scripts/f.py\nprune scripts/f.py\n", set()),
            "ein Kommentar zaehlt nicht": ("# include scripts/g.py\n", set()),
            "eine fremde Direktive zaehlt nicht": ("graft tests\ninclude scripts/h.py\n",
                                                   {"scripts/h.py"}),
        }
        for name, (text, erwartet) in faelle.items():
            with self.subTest(form=name):
                self.assertEqual(self._ausgeliefert_aus(text), erwartet)

    def test_ein_wildcard_ueber_scripts_faellt_laut(self):
        """The fifth form, and the only one that must REFUSE rather than parse.

        A wildcard over `scripts` makes the shipped set unknowable from the file, so returning a
        smaller set would be the quiet wrong answer. The owner requirement of 2026-09-06 replaced a
        `graft scripts` with an explicit list; a return to any wildcard form over that directory is
        the finding.
        """
        for zeile in ("graft scripts", "recursive-include scripts *.py",
                      "global-include scripts/*.py", "recursive-exclude scripts *.pyc"):
            with self.subTest(direktive=zeile):
                with self.assertRaises(AssertionError):
                    self._ausgeliefert_aus(zeile + "\n")

    def test_gegenrichtung_die_echte_datei_ergibt_dieselbe_menge_wie_der_alte_ausdruck(self):
        """WITHOUT THIS the hardening could have changed the answer on the real input.

        The lens's sdist comparison was made against the one-expression version. This pins that the
        directive reader agrees with it on the file as it stands, so that measurement still covers
        the code that is here now.
        """
        text = (REPO / "MANIFEST.in").read_text(encoding="utf-8")
        alt = set(re.findall(r"^include (scripts/\S+)", text, re.M))
        self.assertEqual(self._ausgeliefert_aus(text), alt,
                         "the directive reader and the expression it replaces disagree on the real "
                         "MANIFEST.in, so the sdist comparison no longer covers this code")
        self.assertEqual(len(alt), 36,
                         "the lens measured 36 shipped scripts against a real build; a different "
                         "number here means the file moved and that measurement needs redoing")

    def test_gegenrichtung_ein_ausgeliefertes_skript_ist_kein_befund(self):
        """WITHOUT THIS a rule that rejected every script import would pass the catch above.

        Measured: at least one test module imports a script MANIFEST.in does ship, and it is not a
        finding. If that stops being true the sweep has become a blanket refusal.
        """
        ausgeliefert = self._ausgeliefert()
        gedeckt = [k for _, k, _ in self._kandidaten() if k in ausgeliefert]
        self.assertTrue(gedeckt,
                        "no test module imports a SHIPPED script, so the rule above cannot be shown "
                        "to distinguish shipped from unshipped")
