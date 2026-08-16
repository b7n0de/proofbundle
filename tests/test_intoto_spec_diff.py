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


class TestSubmittedPredicateInvariants(unittest.TestCase):
    """Both docs must keep saying what in-toto/attestation#575 actually says.

    WHY THIS EXISTS. On 2026-08-07 an external audit found that the PR description scoped `anchors[]`
    out while the spec text still carried it. Aligning our two copies fixed that instance — and left
    the class wide open, because nothing checked that they stay aligned. They had drifted apart
    silently once already: both still listed `anchors` as a predicate field, neither carried the
    absence rule, and one claimed the PR was not yet opened.

    Deliberately NOT a byte-for-byte comparison against the upstream file: it lives in a different
    repository, so a test that reads it would pass or fail depending on what happens to be checked
    out next to this one. These are the invariants instead — each one a sentence the submission
    makes, each one a thing a future edit could quietly drop.
    """

    def _docs(self):
        return {
            "docs/IN_TOTO_PROFILE.md": (ROOT / "docs" / "IN_TOTO_PROFILE.md").read_text(encoding="utf-8"),
            "docs/upstream/eval-result.md": (ROOT / "docs" / "upstream" / "eval-result.md").read_text(encoding="utf-8"),
        }

    def test_anchors_is_not_listed_as_a_predicate_field(self):
        # Prose about time anchors is fine — the concept is real and comes later. What must not come
        # back is `anchors` AS A FIELD: in the schema block, in the field list, or as a table row.
        feld_formen = ('"anchors"', "`anchors` _(array", "`anchors` *(array", "| `anchors` |")
        for pfad, text in self._docs().items():
            for form in feld_formen:
                self.assertNotIn(form, text, f"{pfad} lists anchors as a predicate field ({form!r}); "
                                             f"#575 deliberately scopes it out")

    def test_both_docs_carry_the_absence_rule(self):
        for pfad, text in self._docs().items():
            self.assertIn("absence of an optional field", text,
                          f"{pfad} lost the absence rule (absence means no claim, never a default)")

    def test_both_docs_state_passed_as_a_signed_threshold_verdict(self):
        for pfad, text in self._docs().items():
            self.assertIn("signed threshold verdict", text,
                          f"{pfad} no longer says that `passed` is a signed threshold verdict — "
                          f"without a disclosed value it is not recomputable")

    def test_both_docs_call_assurancelevel_issuer_declared(self):
        for pfad, text in self._docs().items():
            self.assertTrue("issuer-declared" in text or "issuer declared" in text,
                            f"{pfad} no longer marks assuranceLevel as issuer-declared")

    def test_both_docs_carry_the_harness_digest_and_its_non_claim(self):
        for pfad, text in self._docs().items():
            self.assertIn("DigestSet", text, f"{pfad} lost the optional harness DigestSet")
            self.assertIn("detection performance", text,
                          f"{pfad} lost the non-claim that a harness digest says nothing about "
                          f"detection performance")

    def test_the_mirror_names_the_pr_as_the_source_of_truth(self):
        # The copy must not drift into looking authoritative. It also must not keep claiming the PR
        # is unopened, which is how it read until 2026-08-07.
        draft = (ROOT / "docs" / "upstream" / "eval-result.md").read_text(encoding="utf-8")
        self.assertIn("575", draft, "the mirror does not name the PR it mirrors")
        self.assertIn("source of truth", draft,
                      "the mirror does not say which side wins when the two differ")
        self.assertNotIn("NOT yet opened as", draft, "the mirror still claims the PR is unopened")


if __name__ == "__main__":
    unittest.main()
