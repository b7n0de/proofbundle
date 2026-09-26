"""src/ holds one package, `proofbundle`, and the sweeps rooted at src/proofbundle rely on it.

WHERE THIS COMES FROM. Gate run 4 on the OTS cap (bb33a87d, 229-4-01). pyproject.toml finds packages
under `src` with no include list, so a second top-level package there ships with the distribution. A
file in `src/_probe/` read an OTS proof over the cap, and the sweeps of the cap's test file, rooted at
`src/proofbundle`, saw nothing. That test file reads `src` now. By a text search on 2026-09-26, nine
test files walked `src/proofbundle` with `rglob`, the membership, never-raise and truthiness guards
among them; this case holds the premise the others rely on. If `src/` gains a second package or a
module, it turns red, and those sweeps have to be widened before anything else lands.

`namespaces` is true by default in pyproject configuration, so a directory needs no `__init__.py` to
ship: every entry under `src/` counts, except caches and install metadata.
"""
from __future__ import annotations

import pathlib
import tempfile
import unittest

REPO = pathlib.Path(__file__).resolve().parents[1]


def _shipped_roots(src: pathlib.Path) -> list:
    """What `packages.find` with `where = ["src"]` and no include list can pick up under `src`."""
    return sorted(p.name for p in src.iterdir()
                  if p.name != "__pycache__" and not p.name.endswith((".egg-info", ".dist-info")))


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
        self.assertNotIn("include", find)

    def test_a_second_package_or_a_module_is_seen(self):
        """Positive control: a directory without `__init__.py` and a bare module both count."""
        with tempfile.TemporaryDirectory() as d:
            src = pathlib.Path(d)
            for name in ("proofbundle", "_probe", "__pycache__", "proofbundle.egg-info"):
                (src / name).mkdir()
            (src / "loose.py").write_text("")
            self.assertEqual(_shipped_roots(src), ["_probe", "loose.py", "proofbundle"])


if __name__ == "__main__":
    unittest.main()
