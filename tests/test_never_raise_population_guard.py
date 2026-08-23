"""The never-raise family property must walk the tree, not a maintained list.

WHY THIS EXISTS. `tests/test_never_raise_surface_family_property.py` is the executable form of the
never-raise class: no public surface may terminate with a raw exception on hostile input. It carries
its own regression floor on the DENOMINATOR (`test_discovery_finds_the_expected_surface_family`), and
that floor is real — but it guards against the denominator *collapsing*, not against it being
*incomplete by construction*. The module list `_MODULES` is hand-maintained, so a module added to the
package is silently outside the property until somebody remembers to add it.

MEASURED, 2026-08-16, on `main` @ ac0688c. Two identical planted defects in throwaway copies:

    raise in anchors.verify_anchors        (module IS in _MODULES)  -> FAILED (errors=1), caught
    raise in anchors_ots.verify_openti...  (module is NOT)          -> Ran 5 tests, OK, NOT caught

The property is correct over the set it walks. That set was 36 modules while the package shipped 50,
and the difference held 11 surfaces matching the property's own name pattern — one of them a live
contract violation (`anchors_rfc3161.verify_rfc3161` raises `AttributeError` on a non-dict `frozen`
or `rp_trust`, which is exactly what `register_anchor_type` forbids third-party authors from doing).

WHY A SEPARATE FILE AND NOT AN ASSERTION IN THE PROPERTY ITSELF. A test cannot be the guard of its
own blind spot — it is the victim. This guard asks a different question than the property does: not
"does every surface behave" but "does the property's population equal the tree's". Keeping them apart
means a future edit that shrinks `_MODULES` fails HERE, loudly, instead of silently making the
property cheaper to pass.

This guard deliberately derives BOTH sides from the same source the property uses, so it cannot drift
from it: the module list and the name pattern are imported from the property module rather than
re-declared here. Re-declaring them would create a second copy of the same truth, which is the class
of defect this file exists to prevent.
"""
from __future__ import annotations

import importlib
import inspect
import pathlib
import unittest

_SRC = pathlib.Path(__file__).resolve().parents[1] / "src" / "proofbundle"

# Import the property module's OWN definitions. Never re-declare them: two copies of one truth drift,
# and a drifted guard would pass while the thing it guards is wrong.
_prop = importlib.import_module("tests.test_never_raise_surface_family_property")
_MODULES = set(_prop._MODULES)
_NAME_PATTERN = _prop._NAME_PATTERN


def _package_modules() -> set[str]:
    """Every shipped module name, from the tree — the ground truth the population is measured against.

    SUBPACKAGES INCLUDED (2026-08-17). The first version globbed `*.py` at the top level only, so a
    module inside a subpackage was outside the ground truth — and therefore outside the guard that
    exists to prove nothing is outside. The guard against an incomplete population was itself
    incomplete by construction, one level down. Measured on the merged tree: `glob` finds 50 modules,
    `rglob` finds 56; the six are the five `adapters.*` and `experimental.enclave`. Of those six,
    exactly ONE carries a matching surface (`experimental.enclave.verify_enclave_attestation`) — so
    the gap's honest size is one member, not six, and it is a shipped module with a documented import
    path and its own CLI subcommand (`verify-enclave`).

    THE FILESYSTEM, NOT `pkgutil.walk_packages`, and the reason is measured rather than cited.
    `walk_packages` must IMPORT each package to read its `__path__`, which pulls side effects (the
    experimental preview warning) into a discovery step that should have none. It also carries a
    documented mutable-default memo (CPython #127318) — that one did NOT reproduce here (three calls,
    62 modules each), so it is named as a reason to prefer the simpler route, not as a bug we hit.
    `rglob` reads names off disk: no imports, no memo, no side effects, and it stays in the idiom this
    file already used.

    A private subpackage (`_foo/`) stays out, and a subpackage's own `__init__.py` enters under the
    package name, because a package can carry surfaces just like a module can.
    """
    aus: set[str] = set()
    for p in _SRC.rglob("*.py"):
        rel = p.relative_to(_SRC)
        if any(teil.startswith("_") for teil in rel.parts[:-1]):
            continue                                        # privates Unterpaket
        if rel.stem.startswith("_"):
            if rel.stem == "__init__" and len(rel.parts) > 1:
                aus.add(".".join(rel.parts[:-1]))           # das Unterpaket SELBST
            continue
        aus.add(".".join(rel.with_suffix("").parts))
    return aus


def _never_raise_surfaces_in(mod_name: str) -> list[str]:
    """Functions DEFINED in this module whose name matches the property's own family pattern.

    `__module__` is checked so a name merely imported into the module does not count as one of its
    surfaces — otherwise a re-export would inflate every module's apparent population.
    """
    try:
        mod = importlib.import_module(f"proofbundle.{mod_name}")
    except Exception:  # noqa: BLE001 — an optional-extra module that will not import is out of scope
        return []
    return sorted(
        n for n, f in vars(mod).items()
        if not n.startswith("_")
        and _NAME_PATTERN.match(n)
        and inspect.isfunction(f)
        and getattr(f, "__module__", "") == f"proofbundle.{mod_name}"
    )


class TestNeverRaisePopulationIsDerivedFromTheTree(unittest.TestCase):

    def test_no_shipped_surface_sits_outside_the_property(self):
        """The invariant: every never-raise-shaped surface in the package is inside the population.

        A failure here does NOT mean the surface misbehaves. It means nobody has ever asked whether it
        does — which is the more expensive state, because a green property is read as covering it.
        """
        aussen: dict[str, list[str]] = {}
        for mod_name in sorted(_package_modules() - _MODULES):
            treffer = _never_raise_surfaces_in(mod_name)
            if treffer:
                aussen[mod_name] = treffer
        gesamt = sum(len(v) for v in aussen.values())
        self.assertEqual(
            aussen, {},
            f"{gesamt} never-raise surface(s) in {len(aussen)} module(s) are outside the property's "
            f"population, so the property has never entered them: {aussen}. "
            "Add the module to _MODULES in tests/test_never_raise_surface_family_property.py — and "
            "expect the property to go red if the surface actually violates the contract, which is "
            "the point.")

    def test_the_population_names_only_modules_that_exist(self):
        """The other direction: a module listed but no longer shipped makes the population lie the
        other way — it inflates the apparent denominator with names that walk nothing."""
        verwaist = sorted(_MODULES - _package_modules())
        self.assertEqual(verwaist, [],
                         f"_MODULES names {len(verwaist)} module(s) that the package does not ship: "
                         f"{verwaist}. The denominator counts them and nothing walks them.")

    def test_this_guard_actually_discriminates(self):
        """Bidirectional validation: the guard must be able to FAIL, or its green means nothing.

        A guard whose predicate can only ever pass is decoration. This exercises the comparison with a
        deliberately wrong population and requires it to detect the difference.
        """
        paket = _package_modules()
        self.assertTrue(paket, "no shipped modules discovered — the ground truth itself is broken")
        # A population missing a module that HAS surfaces must be detectable.
        kandidaten = [m for m in sorted(paket) if _never_raise_surfaces_in(m)]
        self.assertTrue(kandidaten, "no module with never-raise surfaces found — the pattern matched nothing")
        kuenstlich = set(kandidaten[1:])          # drop one module that provably has surfaces
        fehlend = {m: _never_raise_surfaces_in(m) for m in (paket - kuenstlich) if _never_raise_surfaces_in(m)}
        self.assertNotEqual(fehlend, {},
                            "the comparison did not notice a module removed from the population — "
                            "this guard cannot fail and therefore proves nothing")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
