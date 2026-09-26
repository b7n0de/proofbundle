"""src/ holds one package, `proofbundle`, and the sweeps rooted at src/proofbundle rely on it.

WHERE THIS COMES FROM. Gate run 4 on the OTS cap (bb33a87d, 229-4-01). pyproject.toml finds packages
under `src` with no include list, so a second top-level package there ships with the distribution. A
file in `src/_probe/` read an OTS proof over the cap, and the sweeps of the cap's test file, rooted at
`src/proofbundle`, saw nothing. That test file reads `src` now. Eight other test files walk
`src/proofbundle`, the membership, never-raise and truthiness guards among them: five with `rglob`,
two with `glob`, one with `pkgutil.iter_modules` (an AST search on 2026-09-26 that follows the
receiver of each call through the module's assignments; an earlier sentence here said nine with
`rglob`, from a text search, gate run 5 on 3a8413f8, 229-5-03). This case holds the premise they rely
on. If `src/` gains a second package, it turns red, and those walks have to be widened first.

WHAT SHIPS, measured rather than assumed. `namespaces` is true by default in pyproject configuration,
so a directory needs no `__init__.py`: setuptools' own finder (`PEP420PackageFinder`, setuptools 69.5.1
and 79.0.1) takes every directory whose name holds no dot, except the names it always excludes. A bare
module directly under `src/` does NOT ship: pyproject configuration discovers packages, not top-level
modules. The first version of `_shipped_roots` counted such a module and would have turned red over a
file that no distribution carries (gate run 5, 229-5-02, measured with a real wheel build).
"""
from __future__ import annotations

import fnmatch
import pathlib
import tempfile
import unittest

REPO = pathlib.Path(__file__).resolve().parents[1]

#: `setuptools.discovery.PackageFinder.ALWAYS_EXCLUDE` as of setuptools 69.5.1 and 79.0.1; the case
#: `test_the_model_is_setuptools_own_finder` holds this copy to the installed setuptools where there is one.
_ALWAYS_EXCLUDE = ("ez_setup", "*__pycache__")


def _shipped_roots(src: pathlib.Path) -> list:
    """The top-level packages `packages.find` with `where = ["src"]`, namespaces on and no include or
    exclude list picks up under `src`: every directory whose name holds no dot, except the names
    setuptools always excludes. Files, a bare module among them, do not ship."""
    return sorted(p.name for p in src.iterdir()
                  if p.is_dir() and "." not in p.name
                  and not any(fnmatch.fnmatchcase(p.name, pat) for pat in _ALWAYS_EXCLUDE))


def _synthetic_src(d: pathlib.Path) -> pathlib.Path:
    """A `src` with a package, a namespace directory, a name setuptools finds although it cannot be
    imported, and everything that does not ship: a cache, install metadata, a hidden directory, the
    always-excluded `ez_setup`, a bare module and two data files, one without a dot in its name, so
    that it is the directory test and not the dot test that leaves the files out."""
    src = d / "src"
    for name in ("proofbundle", "_probe", "with-dash", "__pycache__", "proofbundle.egg-info", ".hidden",
                 "ez_setup"):
        (src / name).mkdir(parents=True)
    (src / "proofbundle" / "__init__.py").write_text("")
    (src / "loose.py").write_text("")
    (src / "data.txt").write_text("")
    (src / "NOTES").write_text("")
    return src


def _toml():
    try:
        import tomllib
    except ImportError:  # Python 3.10
        try:
            import tomli as tomllib
        except ImportError:
            return None
    return tomllib


class SrcHoldsOnePackage(unittest.TestCase):

    def test_src_holds_the_one_package(self):
        self.assertEqual(_shipped_roots(REPO / "src"), ["proofbundle"],
                         "a second entry under src/ ships with the distribution; widen every sweep "
                         "rooted at src/proofbundle before it lands")

    def test_the_premise_pyproject_finds_packages_under_src(self):
        """If `where` moves, this guard reads the wrong directory; if an include list appears, it is
        stricter than the distribution and should be revisited."""
        toml = _toml()
        if toml is None:
            self.skipTest("NOT MEASURABLE: neither tomllib nor tomli is importable here; the premise was "
                          "NOT checked")
        with open(REPO / "pyproject.toml", "rb") as fh:
            find = toml.load(fh)["tool"]["setuptools"]["packages"]["find"]
        self.assertEqual(find.get("where"), ["src"])
        # The model below is exact only without these: an include or exclude list makes the
        # distribution narrower than the model, namespaces = false drops directories without
        # `__init__.py`.
        self.assertNotIn("include", find)
        self.assertNotIn("exclude", find)
        self.assertIsNot(find.get("namespaces", True), False)

    def test_a_second_package_is_seen_and_what_does_not_ship_is_not(self):
        """Positive control, both directions: the three directories setuptools takes, and none of what it
        leaves out."""
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(_shipped_roots(_synthetic_src(pathlib.Path(d))),
                             ["_probe", "proofbundle", "with-dash"])

    def test_the_model_is_setuptools_own_finder(self):
        """The model against the finder the build uses, on the synthetic tree and on this `src`, and the
        excluded names against the installed setuptools. setuptools is not installed in every
        environment that runs the suite (Python 3.12 venvs carry none), so this case says when it did
        not run."""
        try:
            from setuptools.discovery import PackageFinder, PEP420PackageFinder
        except ImportError:
            self.skipTest("NOT MEASURABLE: setuptools is not importable here; the model was NOT held to "
                          "the finder")
        self.assertEqual(tuple(PackageFinder.ALWAYS_EXCLUDE), _ALWAYS_EXCLUDE)
        with tempfile.TemporaryDirectory() as d:
            for src in (_synthetic_src(pathlib.Path(d)), REPO / "src"):
                with self.subTest(src=src.name if src.parent != REPO else "repo"):
                    found = PEP420PackageFinder.find(where=str(src))
                    self.assertEqual(_shipped_roots(src), sorted({p.split(".")[0] for p in found}))


if __name__ == "__main__":
    unittest.main()
