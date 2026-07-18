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

    def test_rust_tree_is_not_shipped_in_sdist(self):
        prunes = {ln.split(None, 1)[1] for ln in self.lines if ln.startswith("prune ")}
        for d in _REQUIRED_PRUNES:
            self.assertIn(d, prunes, f"MANIFEST.in must `prune {d}` (not a Python-sdist artifact)")

    def test_bytecode_and_native_sources_excluded(self):
        blob = " ".join(self.lines)
        self.assertIn("global-exclude", blob)
        self.assertTrue(any("*.py[cod]" in ln or "*.pyc" in ln for ln in self.lines),
                        "MANIFEST.in must global-exclude compiled bytecode")


if __name__ == "__main__":
    unittest.main()
