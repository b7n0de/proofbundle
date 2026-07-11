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

    def test_init_version_matches_pyproject(self):
        # 2026-07-09 release incident: `__init__.py::__version__` was bumped to 2.0.0 for the tag, but
        # `pyproject.toml::version` (the value the WHEEL is built from) was left at 2.0.0b3. The build
        # therefore produced proofbundle-2.0.0b3, `skip-existing` skipped it, and 2.0.0 never reached
        # PyPI while every other check went green. This pins the runtime `--version` string to the
        # built distribution version so that drift is a red test, not a silent failed release.
        pyproject = (REPO / "pyproject.toml").read_text(encoding="utf-8")
        init_py = (REPO / "src" / "proofbundle" / "__init__.py").read_text(encoding="utf-8")
        py_v = re.search(r'(?m)^version\s*=\s*"([^"]+)"', pyproject)
        init_v = re.search(r'(?m)^__version__\s*=\s*"([^"]+)"', init_py)
        self.assertIsNotNone(py_v, "pyproject.toml has no version")
        self.assertIsNotNone(init_v, "__init__.py has no __version__")
        self.assertEqual(init_v.group(1), py_v.group(1),
                         "__init__.py __version__ must equal pyproject version (the wheel is built "
                         "from pyproject; a drift ships the wrong version to PyPI)")

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

    def test_docs_references_are_current(self):
        # WP-N2 reference hygiene, pinned so the three audited drifts cannot return:
        # (d) ValiChord moved — the old topeuph-ai URL is dead/wrong everywhere;
        # (e) SD-JWT VC is at draft-17/IESG — no doc/code comment may still cite draft-15/-16 as current
        #     (the historical CHANGELOG is exempt: it records what WAS true);
        # (f) the enclave preview install must not pin a stale beta that predates the stable release.
        for rel in ("INTEROP.md", "INTEGRATIONS.md"):
            text = (REPO / rel).read_text(encoding="utf-8")
            self.assertNotIn("topeuph-ai/ValiChord", text, f"{rel}: stale ValiChord URL")
            self.assertIn("github.com/ValiChord/ValiChord", text, f"{rel}: canonical ValiChord URL missing")
        sdjwt_issue = (REPO / "src" / "proofbundle" / "sdjwt_issue.py").read_text(encoding="utf-8")
        self.assertIn("sd-jwt-vc-17", sdjwt_issue, "sdjwt_issue.py must cite the current draft revision")
        self.assertNotIn("draft-15", sdjwt_issue)
        enclave_doc = (REPO / "docs" / "EXPERIMENTAL_ENCLAVE.md").read_text(encoding="utf-8")
        self.assertNotIn("2.0.0b1", enclave_doc, "EXPERIMENTAL_ENCLAVE.md pins a stale beta install")

    def test_non_claims_covers_decision_authorization_boundary(self):
        # WP-N2(c): NON_CLAIMS.md must state the decision boundary — a verified ALLOW is a record,
        # never an authorization/bearer token — and name the replay countermeasure. The decision
        # verify CLI help carries the same sentence.
        non_claims = (REPO / "docs" / "NON_CLAIMS.md").read_text(encoding="utf-8")
        self.assertIn("not an authorization", non_claims)
        self.assertIn("bearer token", non_claims)
        self.assertIn("require_audience", non_claims)
        self.assertIn("require_nonce", non_claims)
        self.assertIn("TEE", non_claims)
        from proofbundle.cli import build_parser
        import io as _io
        from contextlib import redirect_stdout as _rs
        parser = build_parser()
        buf = _io.StringIO()
        try:
            with _rs(buf):
                parser.parse_args(["decision", "verify", "--help"])
        except SystemExit:
            pass
        self.assertIn("NOT an authorization or bearer token", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
