"""Three negative cases, run against a real receipt for a real Codex answer.

WHY A REAL ONE. The binding tests in `tests/test_agent_review_binding_semantics.py` build their
receipts in the test, with a throwaway key and a made-up subject. They show the verifier's rules;
they do not show that a receipt this repository actually published, for an answer that actually
stands on GitHub, is refused when the answer, the subject or the key is wrong. That is the claim a
reader of such an answer relies on, so it is measured here on one of them.

THE TRUST RULE comes from outside the receipt: the key file named in `subject.json`, and the
subject a reader expects, recorded from the pull request. Checking a receipt against values taken
out of the receipt itself would check nothing.

The three cases, each with the reaction it must get:

1. The answer's bound bytes changed: the body digest no longer matches and the receipt is not
   usable.
2. A validly signed receipt presented for another head: the subject no longer matches.
3. A key outside the trust rule: no trusted statement results.

WHAT THE RECEIPT DOES NOT BIND, and it is pinned here so that it cannot be read into case 1. The
body digest is taken with the disclosure block, the text between the agent-review markers, replaced
by a token. This receipt carries no disclosureCoreDigest, as its known gaps state, so a change
inside that block is NOT refused by it (Codex on this pull request, round one). The last case says
so as a measurement: if the receipt ever does bind the block, that case fails and this paragraph is
wrong.

A precondition case first shows that the same receipt IS usable with the right answer, subject
and key; without it, three refusals could come from a receipt that fails for any reason at all.
"""
from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
from proofbundle import agent_review as AR  # noqa: E402

FIXTURE = REPO / "tests" / "fixtures" / "p28_real_receipt"


def _load():
    subject = json.loads((FIXTURE / "subject.json").read_text(encoding="utf-8"))
    env = json.loads((REPO / subject["receipt"]).read_text(encoding="utf-8"))
    key = bytes.fromhex((REPO / subject["trusted_key"]).read_text(encoding="utf-8").strip())
    body = (REPO / subject["answer"]["file"]).read_bytes().decode("utf-8")
    return subject, env, key, body


def _verify(env, key, body, context):
    sc = dict(context, bodyCoreDigest=AR.body_core_digest(body))
    return AR.verify_agent_review(env, key, strict=True, observed_body=body,
                                  expected_subject_digest=AR._subject_digest({"subjectContext": sc}))


class ThreeNegativeCasesOnARealReceipt(unittest.TestCase):

    def setUp(self):
        self.subject, self.env, self.key, self.body = _load()
        self.context = self.subject["subjectContext"]

    def _block(self):
        begin, end = "<!-- proofbundle:agent-review:begin -->", "<!-- proofbundle:agent-review:end -->"
        return self.body[self.body.index(begin):self.body.index(end) + len(end)]

    def test_precondition_the_real_receipt_is_usable_as_published(self):
        r = _verify(self.env, self.key, self.body, self.context)
        self.assertIs(r["ok"], True, r["errors"])
        self.assertEqual(r["body_core_digest_match"], "MATCH")
        self.assertEqual(r["expected_subject_match"], "MATCH")

    def test_1_changed_bound_answer_bytes_are_refused(self):
        for label, changed in (("one word", self.body.replace("Confirmed", "Refuted", 1)),
                               ("a trailing space", self.body + " "),
                               ("a verdict line", self.body.replace("Verdict Confirmed",
                                                                    "Verdict Refuted", 1))):
            with self.subTest(change=label):
                self.assertNotEqual(changed, self.body, "the change must change something")
                self.assertIn(self._block(), changed, "the change must fall outside the block")
                # a reader derives everything from the text in front of them
                r = _verify(self.env, self.key, changed, self.context)
                self.assertIs(r["ok"], False)
                self.assertEqual(r["body_core_digest_match"], "MISMATCH")

    def test_the_disclosure_block_is_not_bound_by_this_receipt(self):
        """The named limit, measured: an edit between the markers leaves the receipt usable."""
        begin, end = "<!-- proofbundle:agent-review:begin -->", "<!-- proofbundle:agent-review:end -->"
        i, j = self.body.index(begin), self.body.index(end)
        self.assertIn("Tier 1", self.body[i:j], "the edit below must fall inside the block")
        changed = self.body[:i] + self.body[i:j].replace("Tier 1", "Tier 9", 1) + self.body[j:]
        self.assertNotEqual(changed, self.body)
        r = _verify(self.env, self.key, changed, self.context)
        self.assertEqual(r["body_core_digest_match"], "MATCH")
        self.assertEqual(r["disclosure_core_digest_match"], "ABSENT_IN_RECEIPT")
        self.assertIs(r["ok"], True, r["errors"])

    def test_2_a_receipt_presented_for_another_head_is_refused(self):
        other = copy.deepcopy(self.context)
        other["headSha"] = self.subject["another_head"]
        self.assertNotEqual(other["headSha"], self.context["headSha"])
        r = _verify(self.env, self.key, self.body, other)
        self.assertIs(r["ok"], False)
        self.assertEqual(r["expected_subject_match"], "MISMATCH")
        self.assertIs(r["subject_binding_ok"], False)

    def test_3_a_key_outside_the_trust_rule_yields_no_trusted_statement(self):
        stranger = Ed25519PrivateKey.from_private_bytes(bytes(range(32))).public_key()
        stranger_bytes = stranger.public_bytes_raw()
        self.assertNotEqual(stranger_bytes, self.key)
        r = _verify(self.env, stranger_bytes, self.body, self.context)
        self.assertIs(r["ok"], False)
        self.assertIs(r["internal_consistency_ok"], False)


if __name__ == "__main__":
    unittest.main()
