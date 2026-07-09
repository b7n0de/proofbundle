"""Doc-truth guards — metrics in the docs must not be able to go stale (six-lens review F5/SH4)."""
import importlib.util
import re
import unittest
from pathlib import Path

from proofbundle import SPEC_REVISION

REPO = Path(__file__).resolve().parents[1]
_dl_spec = importlib.util.spec_from_file_location("doc_link_check", REPO / "scripts" / "doc_link_check.py")
doc_link_check = importlib.util.module_from_spec(_dl_spec)
_dl_spec.loader.exec_module(doc_link_check)


class TestDocsTruth(unittest.TestCase):
    def test_readme_carries_no_hardcoded_test_count(self):
        # F5: the README stated "303 tests" while the suite had grown past it. A hardcoded count
        # goes stale on every added test. Removed (not tracked by hand) — this guard keeps it gone:
        # a "<N> tests" phrase in the README is a stale-metric regression.
        readme = (REPO / "README.md").read_text(encoding="utf-8")
        # ignore fenced code blocks (a CLI sample line is not a prose metric)
        prose = re.sub(r"```.*?```", "", readme, flags=re.DOTALL)
        hits = re.findall(r"\b\d+\s+tests?\b", prose, flags=re.IGNORECASE)
        self.assertEqual(hits, [], f"README carries a hardcoded, stale-prone test count: {hits}")

    def test_citation_version_matches_pyproject(self):
        # F6/SH4: CITATION.cff stated version 0.7.0 while pyproject shipped 1.9.1 — a stale version
        # travels into every citation. Pin them together so a release bump cannot drift them apart
        # (the RELEASE.md checklist requires bumping both).
        cff = (REPO / "CITATION.cff").read_text(encoding="utf-8")
        pyproject = (REPO / "pyproject.toml").read_text(encoding="utf-8")
        cff_v = re.search(r"(?m)^version:\s*([^\s#]+)", cff)
        py_v = re.search(r'(?m)^version\s*=\s*"([^"]+)"', pyproject)
        self.assertIsNotNone(cff_v, "CITATION.cff has no version")
        self.assertIsNotNone(py_v, "pyproject.toml has no version")
        self.assertEqual(cff_v.group(1).strip('"'), py_v.group(1),
                         "CITATION.cff version must equal pyproject version (bump both together)")

    def test_spec_revision_matches_spec_md(self):
        # WP-B1 (closes #28): `proofbundle --version` reports SPEC_REVISION as the pinned SPEC.md
        # revision it implements. If the two drift apart, --version would silently lie about which
        # spec text this build actually matches — pin them together like CITATION.cff/pyproject above.
        spec_md = (REPO / "SPEC.md").read_text(encoding="utf-8")
        m = re.search(r"(?m)^Revision:\s*(\S+)", spec_md)
        self.assertIsNotNone(m, "SPEC.md has no top-of-file 'Revision:' line")
        self.assertEqual(SPEC_REVISION, m.group(1),
                         "SPEC_REVISION (src/proofbundle/__init__.py) must equal SPEC.md's Revision: line")

    def test_no_broken_internal_doc_links(self):
        # SH5: a Markdown link to a local file that 404s reads as abandonment for a tool that sells
        # reviewability. The shipped docs must have zero broken internal links.
        out = doc_link_check.check()
        self.assertGreater(out["checked"], 0, "link checker found no local links to check — is it wired up?")
        self.assertEqual(out["broken"], [], f"broken internal doc link(s): {out['broken']}")


if __name__ == "__main__":
    unittest.main()
