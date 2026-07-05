"""O6 spec-diff probe: every predicateType / payloadType literal used in the code is asserted against
the documented constant, so a typo can never drift the code away from the spec silently."""
import pathlib
import unittest

from proofbundle.intoto import (
    EVAL_RESULT_PREDICATE_TYPE,
    INTOTO_STATEMENT_PAYLOAD_TYPE,
    SVR_PREDICATE_TYPE,
)

ROOT = pathlib.Path(__file__).resolve().parent.parent


class TestIntotoSpecDiff(unittest.TestCase):
    def test_code_constants_are_exact(self):
        # The SVR + DSSE literals are FIXED by the in-toto spec — an exact match, not a doc lookup.
        self.assertEqual(SVR_PREDICATE_TYPE, "https://in-toto.io/attestation/svr/v0.1")
        self.assertEqual(INTOTO_STATEMENT_PAYLOAD_TYPE, "application/vnd.in-toto+json")
        # The eval-result type is a vendor namespace until registered upstream.
        self.assertEqual(EVAL_RESULT_PREDICATE_TYPE, "https://b7n0de.com/attestation/eval-result/v0.1")

    def test_implementation_doc_matches_code(self):
        # IN_TOTO_PROFILE.md documents exactly what the code emits (no drift between doc and code).
        profile = (ROOT / "docs" / "IN_TOTO_PROFILE.md").read_text(encoding="utf-8")
        self.assertIn(EVAL_RESULT_PREDICATE_TYPE, profile)
        self.assertIn(SVR_PREDICATE_TYPE, profile)
        self.assertIn(INTOTO_STATEMENT_PAYLOAD_TYPE, profile)

    def test_upstream_draft_uses_the_intoto_namespace_and_notes_the_vendor_alias(self):
        # The ready-to-submit spec draft proposes the in-toto.io type but names the vendor alias honestly.
        draft = (ROOT / "docs" / "upstream" / "eval-result.md").read_text(encoding="utf-8")
        self.assertIn("https://in-toto.io/attestation/eval-result/v0.1", draft)
        self.assertIn(EVAL_RESULT_PREDICATE_TYPE, draft)   # the vendor alias is disclosed, not hidden


if __name__ == "__main__":
    unittest.main()
