"""3.6.1 — the published sdist ships its tests' runtime assets (PB-2026-0717-02).

The v3.6.0 sdist shipped tests/ WITHOUT their runtime assets (fixtures, schemas, examples, conformance
corpus, formal-model results, the scripts the tests invoke) → the full sdist pytest aborted with 13
collection errors. The fix is a MANIFEST.in per-directory allowlist that grafts exactly those assets.

This test is the deterministic guard on the allowlist (building + installing the sdist and running the
full collect is verified manually / in CI, not in a unit test — too slow and network-adjacent). It
asserts MANIFEST.in grafts every required test-runtime directory and prunes the non-sdist material
(tools/ = the 138M Rust verifier tree, a category error to ship in a Python sdist).
"""
import pathlib
import unittest

_REPO = pathlib.Path(__file__).resolve().parents[1]
_MANIFEST = _REPO / "MANIFEST.in"

# Every top-level directory the shipped tests import from / read at collection time. Derived from the
# 13 v3.6.0 collection errors (tests/fixtures, schemas, examples, conformance, formal, scripts,
# docs/readiness_pack). An explicit allowlist, NOT "graft everything" (Befund C: avoid the bloat trap).
_REQUIRED_GRAFTS = ("tests", "schemas", "examples", "conformance", "formal", "scripts",
                    "docs/readiness_pack")
# The exact shipped-example file the renewal-policy test loads — included by path, not a graft
# (PKG-2026-0718-02), so the sdist carries the example without the ADR markdowns.
_REQUIRED_INCLUDES = ("docs/adr/renewal_policy.example.json",)
# Never ship: the Rust verifier + its build tree (runs from a git checkout with a toolchain, never the
# Python sdist), and repo/CI meta.
_REQUIRED_PRUNES = ("tools",)


class SdistManifestAllowlist(unittest.TestCase):
    def setUp(self):
        self.assertTrue(_MANIFEST.is_file(), "MANIFEST.in is required so the sdist ships test assets")
        self.lines = [ln.strip() for ln in _MANIFEST.read_text(encoding="utf-8").splitlines()
                      if ln.strip() and not ln.strip().startswith("#")]

    def test_published_sdist_contains_all_test_runtime_assets(self):
        grafts = {ln.split(None, 1)[1] for ln in self.lines if ln.startswith("graft ")}
        for d in _REQUIRED_GRAFTS:
            self.assertIn(d, grafts, f"MANIFEST.in must `graft {d}` so the sdist tests can collect")

    def test_shipped_example_policy_is_included_by_path(self):
        # PKG-2026-0718-02: the renewal-policy test loads docs/adr/renewal_policy.example.json from the sdist.
        includes = {ln.split(None, 1)[1] for ln in self.lines if ln.startswith("include ")}
        for f in _REQUIRED_INCLUDES:
            self.assertIn(f, includes, f"MANIFEST.in must `include {f}` so the sdist ships the example")

    def test_rust_tree_is_not_shipped_in_sdist(self):
        prunes = {ln.split(None, 1)[1] for ln in self.lines if ln.startswith("prune ")}
        for d in _REQUIRED_PRUNES:
            self.assertIn(d, prunes, f"MANIFEST.in must `prune {d}` (not a Python-sdist artifact)")

    def test_bytecode_and_native_sources_excluded(self):
        blob = " ".join(self.lines)
        self.assertIn("global-exclude", blob)
        self.assertTrue(any("*.py[cod]" in ln or "*.pyc" in ln for ln in self.lines),
                        "MANIFEST.in must global-exclude compiled bytecode")

    def test_repo_context_tests_skip_outside_a_checkout(self):
        # PKG-2026-0718-01 (RE-GATE): the "self-testable" claim is honest only because the repo-context
        # tests (which read pruned .github/tools/SPEC material) SKIP outside a checkout instead of failing.
        # Enforce that the mechanism EXISTS and is well-formed (a real check, not a wording promise). This
        # runs BOTH in the repo AND from an extracted sdist, so it must be context-INDEPENDENT: it asserts
        # the skip set is populated + well-formed and that the repo-detection helper is callable and agrees
        # with the markers actually present in the current tree (whichever context that is).
        from conftest import _REPO_CONTEXT_TESTS, _REPO_ONLY_MARKERS, _REPO_ROOT, running_in_repo_checkout
        self.assertTrue(_REPO_CONTEXT_TESTS, "the repo-context skip set must be populated")
        self.assertTrue(all("::" in t for t in _REPO_CONTEXT_TESTS),
                        "each entry must be 'module_stem::test_method'")
        expected = any((_REPO_ROOT / m).exists() for m in _REPO_ONLY_MARKERS)
        self.assertEqual(running_in_repo_checkout(), expected,
                         "repo-detection must match the markers actually present in the current tree")


if __name__ == "__main__":
    unittest.main()
