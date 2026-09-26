"""A path the distribution's MANIFEST.in promises, and that is absent, is a packaging failure, not a skip.

WHERE THIS COMES FROM. Deep gate against main 5b53ab3e, finding L6-Z195-01 (P2, jury 3 of 3). From an
extracted sdist, `tests/conftest.py` skips a whole test module when the module names a root-relative
path that is absent. It never asked whether the distribution was supposed to carry that path.
Measured with one appended line, `exclude examples/trust_policy_strict.json`, while `graft examples`
still stood: tests/test_trust_policy.py went from 47 passed to 47 skipped as "repo-context", and the
whole shipped suite stayed rc=0. SOURCES.txt cannot tell this apart, because an `exclude` removes the
path from it as well. MANIFEST.in can: it states what the sdist promises.

WHAT IS PINNED. The rule on throwaway trees, both directions: a pruned path still makes a module
repo-context; a promised path that is absent does not, whichever of `graft`, `include` or
`recursive-include` promised it, and it wins over a pruned path read by the same module. Without a
MANIFEST.in the old rule stands, so the last case binds that the distribution carries its own.
"""
from __future__ import annotations

import importlib.util
import pathlib
import shutil
import tempfile
import unittest

REPO = pathlib.Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location("_cf_versprochen", REPO / "tests" / "conftest.py")
cf = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(cf)

MANIFEST = """# a comment line: graft commented_out
graft examples
include docs/NAMED.md
recursive-include receipts/agent_review *.receipt.json
prune tools
"""


class APromisedAbsenceIsNotRepoContext(unittest.TestCase):

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        (self.tmp / "tests").mkdir()
        (self.tmp / "MANIFEST.in").write_text(MANIFEST, encoding="utf-8")

    def _module(self, *paths: str) -> pathlib.Path:
        lines = ["from pathlib import Path", "REPO = Path(__file__).parents[1]"]
        lines += [f"X{i} = REPO / {p!r}" for i, p in enumerate(paths)]
        p = self.tmp / "tests" / "test_x.py"
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return p

    def test_a_pruned_path_still_makes_the_module_repo_context(self):
        for rel in ("SPEC.md", "tools/pb_verify_rs/crosscheck.py", ".github/workflows/ci.yml"):
            with self.subTest(path=rel):
                self.assertIs(cf.modul_ist_repo_kontext(self._module(rel), wurzel=self.tmp), True)

    def test_a_promised_path_that_is_absent_is_not_repo_context(self):
        for rel, promise in (("examples/trust_policy_strict.json", "graft"),
                             ("docs/NAMED.md", "include"),
                             ("receipts/agent_review/r.receipt.json", "recursive-include")):
            with self.subTest(promise=promise):
                self.assertIs(cf._manifest_verspricht(rel, self.tmp), True)
                self.assertIs(cf.modul_ist_repo_kontext(self._module(rel), wurzel=self.tmp), False)

    def test_a_promised_absence_wins_over_a_pruned_one_in_the_same_module(self):
        p = self._module("SPEC.md", "examples/trust_policy_strict.json")
        self.assertIs(cf.modul_ist_repo_kontext(p, wurzel=self.tmp), False)

    def test_near_misses_are_not_promises(self):
        for rel in ("examples_other/a.json",                  # a sibling that shares the prefix
                    "receipts/agent_review/r.block.txt",      # a recursive-include pattern it misses
                    "docs/OTHER.md",                           # not the included name
                    "commented_out/a.json"):                   # a commented line promises nothing
            with self.subTest(path=rel):
                self.assertIs(cf._manifest_verspricht(rel, self.tmp), False)
                self.assertIs(cf.modul_ist_repo_kontext(self._module(rel), wurzel=self.tmp), True)

    def test_without_a_manifest_the_old_rule_stands(self):
        (self.tmp / "MANIFEST.in").unlink()
        self.assertIs(cf.modul_ist_repo_kontext(self._module("examples/a.json"), wurzel=self.tmp), True)


class TheDistributionCarriesItsManifest(unittest.TestCase):
    """Runs in the checkout and from the extracted sdist alike: without MANIFEST.in the rule above
    has no basis and falls back to the old one, so the file must travel with the tests."""

    def test_manifest_in_is_present(self):
        self.assertTrue((REPO / "MANIFEST.in").is_file(),
                        "MANIFEST.in is missing from this tree; the promise check in tests/conftest.py "
                        "cannot tell a packaging failure from a deliberate prune without it")


if __name__ == "__main__":
    unittest.main()
