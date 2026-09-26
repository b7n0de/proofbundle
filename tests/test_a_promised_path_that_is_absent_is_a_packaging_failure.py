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
MANIFEST.in and without a PKG-INFO the old rule stands; a distribution (it carries PKG-INFO) promises its
template and what setuptools adds by itself, so the case that binds "the sdist carries MANIFEST.in" can
no longer be skipped by the rule it guards (gate lens 227-B, 227B-01). The lines are read as setuptools
reads them, proven by vectors a real `build_sdist` produced (gate lens 227-A, 227A-01, 227A-03, 227A-04),
and a negative line does not withdraw a promise, which is how an accidental `exclude` is caught. What
setuptools' build_py ships without a template line (the modules of the packages pyproject.toml's discovery
finds, the declared package data) is promised as well (gate run 2, lens 227-A, 227-2-01); the vectors hold
that against a real `build_sdist` too.
"""
from __future__ import annotations

import importlib.util
import json
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

    def test_a_distribution_without_its_template_does_not_skip_the_guard(self):
        """227B-01: measured from a real sdist with MANIFEST.in deleted, the module that binds its
        presence was skipped as repo-context, because it names the missing file. setuptools puts the
        template into every sdist, so a distribution promises it."""
        (self.tmp / "MANIFEST.in").unlink()
        (self.tmp / "PKG-INFO").write_text("Metadata-Version: 2.1\nName: proofbundle\n", encoding="utf-8")
        for rel in ("MANIFEST.in", "pyproject.toml", "README.md", "LICENSE"):
            with self.subTest(path=rel):
                self.assertIs(cf._manifest_verspricht(rel, self.tmp), True)
                self.assertIs(cf.modul_ist_repo_kontext(self._module(rel), wurzel=self.tmp), False)
        self.assertIs(cf._manifest_verspricht("examples/a.json", self.tmp), False)   # no template, no graft

    def test_a_module_build_py_ships_is_promised(self):
        """227-2-01, measured by the lens from a tree built like this one: this repository's template
        never names `src/`, and a module a test names by path was skipped as repo-context when it was
        missing. With this repository's own MANIFEST.in and pyproject.toml, a missing package module
        and missing package data are promised; a file build_py would not ship is not."""
        shutil.copy(REPO / "MANIFEST.in", self.tmp / "MANIFEST.in")
        shutil.copy(REPO / "pyproject.toml", self.tmp / "pyproject.toml")
        (self.tmp / "PKG-INFO").write_text("Metadata-Version: 2.1\nName: proofbundle\n", encoding="utf-8")
        (self.tmp / "src" / "proofbundle").mkdir(parents=True)
        (self.tmp / "src" / "proofbundle" / "__init__.py").write_text("", encoding="utf-8")
        for rel in ("src/proofbundle/agent_review.py", "src/proofbundle/py.typed",
                    "src/proofbundle/policies/strict.json", "src/proofbundle/adapters/agt_receipt.py"):
            with self.subTest(path=rel):
                self.assertIs(cf._manifest_verspricht(rel, self.tmp), True)
                self.assertIs(cf.modul_ist_repo_kontext(self._module(rel), wurzel=self.tmp), False)
        for rel in ("src/proofbundle/notes.md", "src/stray.py", "src/proofbundle/policies/x.txt"):
            with self.subTest(path=rel):
                self.assertIs(cf._manifest_verspricht(rel, self.tmp), False)

    def test_a_negative_line_does_not_withdraw_a_promise(self):
        """By design, and the reason is the defect itself: `graft examples` then `exclude` of one file
        is what L6-Z195-01 planted. A reader that let the exclude win would skip that file again."""
        (self.tmp / "MANIFEST.in").write_text(
            MANIFEST + "exclude examples/trust_policy_strict.json\nprune examples\n"
                       "global-exclude *.json\nrecursive-exclude receipts *\n", encoding="utf-8")
        for rel in ("examples/trust_policy_strict.json", "receipts/agent_review/r.receipt.json"):
            with self.subTest(path=rel):
                self.assertIs(cf._manifest_verspricht(rel, self.tmp), True)


_VEKTOREN = REPO / "tests" / "fixtures" / "manifest_semantics" / "vectors.json"


class TheManifestIsReadAsSetuptoolsReadsIt(unittest.TestCase):
    """Gate lens 227-A built four templates the first reader read differently from setuptools: a
    continued `recursive-include` promised nothing (227A-01, the defect again), `*` crossed `/`
    (227A-03), inline comment words became patterns (227A-04). The oracle is setuptools itself:
    `tests/fixtures/manifest_semantics/erzeuge_vektoren.py` built a real sdist for each template with
    `setuptools.build_meta` and recorded which candidate files it carries; every candidate must be
    promised exactly when the sdist carried it."""

    def test_every_vector_setuptools_produced(self):
        daten = json.loads(_VEKTOREN.read_text(encoding="utf-8"))
        self.assertGreaterEqual(len(daten["cases"]), 10, "too few vectors to hold anything")
        self.assertGreaterEqual(int(daten["setuptools"].split(".")[0]), 68,
                                "the vectors must come from a setuptools that can build this project")
        for name, fall in daten["cases"].items():
            with tempfile.TemporaryDirectory() as tmp:
                wurzel = pathlib.Path(tmp)
                # the tree an sdist of this case is: what setuptools shipped, then its template and
                # project file (build_py's reading needs the project file and, without namespaces, the
                # __init__.py files it shipped)
                for rel in fall["shipped"]:
                    (wurzel / rel).parent.mkdir(parents=True, exist_ok=True)
                    (wurzel / rel).write_text("x\n", encoding="utf-8")
                (wurzel / "MANIFEST.in").write_text(fall["template"], encoding="utf-8")
                (wurzel / "pyproject.toml").write_text(fall["pyproject"], encoding="utf-8")
                for rel in daten["candidates"]:
                    with self.subTest(case=name, path=rel):
                        self.assertIs(cf._manifest_verspricht(rel, wurzel), rel in fall["shipped"],
                                      f"setuptools {'shipped' if rel in fall['shipped'] else 'left out'} "
                                      f"{rel!r} under {fall['template']!r}")

    def test_the_vectors_measure_something(self):
        """Counter-direction: each of the four findings is a case where the first reader and setuptools
        disagree, so the vectors must contain such a disagreement for each, or they prove nothing."""
        daten = json.loads(_VEKTOREN.read_text(encoding="utf-8"))
        faelle = daten["cases"]
        self.assertIn("receipts/agent_review/r1.receipt.json", faelle["continuation"]["shipped"])   # 227A-01
        self.assertNotIn("docs/adr/nested.md", faelle["star_stays_in_its_segment"]["shipped"])      # 227A-03
        self.assertNotIn("noise", faelle["inline_comments"]["shipped"])                             # 227A-04
        self.assertIn("examples/.hidden.json", faelle["hidden_files_are_not_ignored"]["shipped"])
        # 227-2-01: build_py ships package modules and declared package data without a template line
        self.assertIn("src/vektorpaket/mod.py", faelle["no_template_lines"]["shipped"])
        self.assertIn("src/vektorpaket/data/a.json", faelle["no_template_lines"]["shipped"])
        self.assertIn("src/vektorpaket/sub/deep.py", faelle["no_template_lines"]["shipped"])
        self.assertNotIn("src/vektorpaket/sub/deep.py", faelle["find_excludes_a_subpackage"]["shipped"])
        self.assertNotIn("src/vektorpaket/sub/deep.py", faelle["find_without_namespaces"]["shipped"])
        for fall in faelle.values():
            self.assertNotIn("src/vektorpaket/data/b.txt", fall["shipped"])
            self.assertNotIn("src/loose.py", fall["shipped"])


class TheDistributionCarriesItsManifest(unittest.TestCase):
    """Runs in the checkout and from the extracted sdist alike. Without MANIFEST.in the rule above loses
    the template's promises, so the file must travel with the tests. Since 227B-01 this case is no longer
    skipped by that rule when the file is missing: a distribution promises its template."""

    def test_manifest_in_is_present(self):
        self.assertTrue((REPO / "MANIFEST.in").is_file(),
                        "MANIFEST.in is missing from this tree; the promise check in tests/conftest.py "
                        "cannot tell a packaging failure from a deliberate prune without it")


if __name__ == "__main__":
    unittest.main()
