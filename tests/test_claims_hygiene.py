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


if __name__ == "__main__":
    unittest.main()
