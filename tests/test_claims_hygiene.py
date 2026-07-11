"""Claims-hygiene gate — the docs must not carry un-negated overclaims (six-lens review §15)."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("claims_hygiene_check", REPO / "scripts" / "claims_hygiene_check.py")
ch = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ch)


class TestClaimsHygiene(unittest.TestCase):
    def test_real_docs_are_clean(self):
        # The shipped docs must pass the gate — this is the tool whose product is honest scoping.
        self.assertEqual(ch.main(["--json"]), 0, "the repository docs carry an un-negated overclaim")

    def test_un_negated_forbidden_phrase_is_a_violation(self):
        with tempfile.TemporaryDirectory() as d:
            for text in ("proofbundle proves correctness of the eval.",
                         "The receipt is audit-proof.",
                         "It is quantum-safe.",
                         "This is the industry standard for receipts.",
                         "It is compliance ready today."):
                p = Path(d) / "x.md"
                p.write_text(text, encoding="utf-8")
                self.assertTrue(ch.scan_file(p), f"must flag: {text!r}")

    def test_negated_forbidden_phrase_is_allowed(self):
        with tempfile.TemporaryDirectory() as d:
            for text in ("A receipt does not prove correctness.",
                         "proofbundle is not quantum-safe (Ed25519).",
                         "It never proves the number is true.",
                         "This is not audit-proof and makes no compliance claim."):
                p = Path(d) / "x.md"
                p.write_text(text, encoding="utf-8")
                self.assertEqual(ch.scan_file(p), [], f"negated form must be allowed: {text!r}")

    def test_code_fence_and_inline_code_skipped(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "x.md"
            p.write_text("```\nproves correctness\n```\nUse `quantum-safe` as a literal flag name.",
                         encoding="utf-8")
            self.assertEqual(ch.scan_file(p), [], "code fences / inline code are not prose")


class TestGateHonesty(unittest.TestCase):
    """WP-N1 — the gate itself must be honest: a listed-but-missing doc is a FAIL, never a silent
    skip (6 of 16 default entries were silently skipped for months), and the scan set matches the
    repository exactly."""

    def test_every_default_doc_exists_and_scan_covers_all(self):
        missing = [rel for rel in ch._DEFAULT_DOCS if not (REPO / rel).is_file()]
        self.assertEqual(missing, [], "default scan set lists non-existent docs (silent-skip regression)")
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = ch.main(["--json"])
        self.assertEqual(rc, 0)
        import json as _json
        out = _json.loads(buf.getvalue())
        self.assertEqual(out["scanned"], len(ch._DEFAULT_DOCS),
                         "scanned must equal the full default scan set — nothing silently skipped")
        self.assertEqual(out["missing"], [])

    def test_listed_but_missing_path_fails(self):
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = ch.main(["--json", "docs/DOES_NOT_EXIST_ANYWHERE.md"])
        self.assertEqual(rc, 1, "a listed-but-missing doc must FAIL the gate, never a silent skip")
        import json as _json
        out = _json.loads(buf.getvalue())
        self.assertEqual(out["verdict"], "FAIL")
        self.assertIn("docs/DOES_NOT_EXIST_ANYWHERE.md", out["missing"])

    def test_injected_overclaim_in_every_listed_doc_fails(self):
        # WP-N1 acceptance: an injected "safe to deploy" in EVERY listed doc must be caught — proving
        # each doc is really scanned (the exact regression the silent skip hid).
        with tempfile.TemporaryDirectory() as d:
            for rel in ch._DEFAULT_DOCS:
                src = (REPO / rel).read_text(encoding="utf-8")
                p = Path(d) / Path(rel).name
                p.write_text(src + "\n\nThe model is safe to deploy.\n", encoding="utf-8")
                hits = ch.scan_file(p)
                self.assertTrue(any(v["phrase"] == "safe to deploy" for v in hits),
                                f"injected overclaim not caught in {rel}")

    def test_soft_wrapped_negation_is_exonerated(self):
        # The negation and the forbidden phrase sit on different physical lines of ONE sentence —
        # exactly docs/NON_CLAIMS.md's real layout. Must NOT flag.
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "x.md"
            p.write_text("- **Safety.** A threshold is a threshold on one suite, not a statement that a\n"
                         "  model is safe to deploy.\n", encoding="utf-8")
            self.assertEqual(ch.scan_file(p), [], "a soft-wrapped in-sentence negation must exonerate")
            # counter-test: the same wrapped layout WITHOUT a negation must still flag
            p.write_text("- **Safety.** A passing threshold means that a\n  model is safe to deploy.\n",
                         encoding="utf-8")
            self.assertTrue(ch.scan_file(p), "soft-unwrap must not swallow a real violation")

    def test_block_boundaries_still_separate_sentences(self):
        # A negation in a PREVIOUS bullet/heading must NOT exonerate the next block.
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "x.md"
            p.write_text("- It does not prove truth\n- The model is safe to deploy\n", encoding="utf-8")
            self.assertTrue(ch.scan_file(p), "a new list item is a new sentence — no cross-block exoneration")

    def test_trustless_needs_scoping_or_negation(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "x.md"
            p.write_text("The timestamp is trustless.\n", encoding="utf-8")
            self.assertTrue(ch.scan_file(p), "positive 'trustless' must flag")
            p.write_text("The time is trust-minimized (Bitcoin PoW time).\n", encoding="utf-8")
            self.assertEqual(ch.scan_file(p), [], "the scoped wording is the allowed form")
            p.write_text("This does not make the anchor trustless.\n", encoding="utf-8")
            self.assertEqual(ch.scan_file(p), [], "negated 'trustless' is allowed")


if __name__ == "__main__":
    unittest.main()
