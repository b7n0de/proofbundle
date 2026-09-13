"""A statement with more than one subject binds to NONE of them silently — on both sides of the invariant.

THE CLASS (deep gate 2026-09-05, finding L4-02, P2). ``subject_binding.classify_subject`` read
``subject[0]`` and compared it to the re-derived predicate digest. For a statement carrying
``[derived, foreign]`` that comparison SUCCEEDS: mode ``DERIVED``, ``matches`` True,
``subject_derived_ok`` True under ``require_derived_subject``, and the outcome path reached
``safeForAutomation: true`` — while the very same bytes attached as a ``--with-related`` TARGET were
already reported ``ambiguous`` by the resolver (``cli._load_related`` refuses to bind subject[0] since
PB-2026-0717-01). One invariant, two answers, decided by which side of the seam the statement arrived on.

The verdict was also ORDER-DEPENDENT, which is how the defect announces itself: ``[foreign, derived]``
came back EXTERNAL_ATTESTED and failed, ``[derived, foreign]`` came back DERIVED and passed. The same
two subjects, the same predicate, a different verdict because of the order the issuer happened to write.

THE PROPERTY: ``len(subject) != 1`` is its own mode, AMBIGUOUS, on every path that classifies a subject;
``matches`` is False; ``require_derived_subject`` fails closed with exit 2; the verdict does not depend
on the order of the entries. ANTI-PARITY: a single DERIVED subject still classifies DERIVED and passes.
"""
from __future__ import annotations

import base64
import copy
import json
import pathlib
import tempfile
import unittest

from proofbundle import canonical, dsse
from proofbundle.cli import _load_related, main as cli_main
from proofbundle.decision import build_decision_statement, verify_decision_receipt
from proofbundle.emit import generate_signer
from proofbundle.outcome import build_outcome_statement, verify_outcome_receipt
from proofbundle.relation_statement import build_relation_statement, verify_relation_statement
from proofbundle.subject_binding import (
    SubjectBindingError,
    classify_subject,
    require_derived_subject,
    subject_cardinality,
)

INTOTO = "application/vnd.in-toto+json"
HEX_B = "b" * 64
FOREIGN = {"name": "foreign-artifact", "digest": {"sha256": HEX_B}}

DEC_PRED = {
    "schemaVersion": "0.1.0", "decisionId": "urn:uuid:d", "decisionType": "preActionAuthorization",
    "decidedAt": "2026-07-17T00:00:00Z", "decisionMaker": {"id": "dm"}, "agent": {"id": "a"},
    "principal": {"id": "p"},
    "proposedAction": {"actionType": "tool.call", "parametersDigest": {"sha256": "0" * 64}},
    "inputSnapshot": [],
    "policyBoundary": {"policyEngine": "opa", "policyId": "p", "policyDigest": {"sha256": "0" * 64},
                       "decisionPath": "data.allow"},
    "evidenceRefs": [], "decision": {"verdict": "ALLOW", "reasonCodes": ["OK"]},
}
OUT_PRED = {
    "schemaVersion": "0.1.0", "outcomeId": "urn:uuid:o", "decisionRef": {"sha256": "1" * 64},
    "executor": {"id": "ex", "keyId": "kid-exec"}, "requestedActionDigest": {"sha256": "1" * 64},
    "effectDigest": {"sha256": "1" * 64}, "status": "executed",
    "performedAt": "2026-07-17T00:00:00Z", "policyPurpose": "outcome",
}
REL_PRED = {"schemaVersion": "0.1.0", "statementId": "ms",
            "relationships": [{"relation": "supersedes",
                               "targetReceiptDigest": {"digestAlgorithm": "jcs-sha256-v1",
                                                       "digest": HEX_B}}]}


def _sign(statement: dict, signer) -> dict:
    return dsse.sign_envelope(canonical.canonicalize_statement(statement), signer, payload_type=INTOTO)


def _both_orders(statement: dict) -> dict:
    """The SAME two subjects, written in both orders. A correct verdict cannot tell them apart."""
    first = copy.deepcopy(statement)
    first["subject"] = [statement["subject"][0], FOREIGN]
    second = copy.deepcopy(statement)
    second["subject"] = [FOREIGN, statement["subject"][0]]
    return {"derived_first": first, "derived_second": second}


class ClassifySubjectCardinality(unittest.TestCase):
    def setUp(self):
        self.signer = generate_signer()
        self.pub = self.signer.public_key().public_bytes_raw()
        self.pub64 = base64.b64encode(self.pub).decode()

    def test_more_than_one_subject_is_AMBIGUOUS_in_both_orders(self):
        for label, stmt in _both_orders(build_decision_statement(DEC_PRED)).items():
            with self.subTest(order=label):
                c = classify_subject(stmt)
                self.assertEqual(c["mode"], "AMBIGUOUS", c)
                self.assertFalse(c["matches"])
                self.assertEqual(c["subject_count"], 2)
                self.assertIsNone(c["declared_sha256"],
                                  "a declared digest was read out of an ambiguous subject array")

    def test_a_single_derived_subject_still_classifies_DERIVED(self):
        """ANTI-PARITY. Without this, `mode = AMBIGUOUS` for everything would pass the test above."""
        c = classify_subject(build_decision_statement(DEC_PRED))
        self.assertEqual(c["mode"], "DERIVED")
        self.assertTrue(c["matches"])

    def test_zero_subjects_stays_EXTERNAL_ATTESTED_not_ambiguous(self):
        """Absent and ambiguous are DIFFERENT defects (nothing to speak about vs. undecided which).
        The resolver has kept them apart since PB-2026-0717-01; this side must not collapse them."""
        stmt = build_decision_statement(DEC_PRED)
        stmt["subject"] = []
        self.assertEqual(classify_subject(stmt)["mode"], "EXTERNAL_ATTESTED")
        self.assertEqual(subject_cardinality(stmt), 0)

    def test_require_derived_subject_raises_and_names_the_cardinality(self):
        stmt = _both_orders(build_decision_statement(DEC_PRED))["derived_first"]
        with self.assertRaises(SubjectBindingError) as ctx:
            require_derived_subject(stmt)
        self.assertIn("AMBIGUOUS", str(ctx.exception))

    def test_META_reading_subject_zero_again_is_caught(self):
        """PLANT-AND-MUST-CATCH: with the cardinality check removed, `[derived, foreign]` classifies
        DERIVED again. The meta-test reconstructs exactly the pre-fix comparison and asserts that the
        SHIPPED classifier disagrees with it — so a silent revert cannot pass."""
        from proofbundle.subject_binding import derive_subject_digest
        stmt = _both_orders(build_decision_statement(DEC_PRED))["derived_first"]
        pre_fix_declared = stmt["subject"][0]["digest"]["sha256"]        # what the old code read
        self.assertEqual(pre_fix_declared, derive_subject_digest(stmt["predicate"]),
                         "the pre-fix shape no longer reproduces — this meta-test measures nothing")
        self.assertNotEqual(classify_subject(stmt)["mode"], "DERIVED",
                            "subject[0] is being bound again — the class is re-opened")


class EveryVerifyPathFailsClosed(unittest.TestCase):
    """decision · outcome · relation-statement: one invariant, one answer, both orders."""

    def setUp(self):
        self.signer = generate_signer()
        self.pub = self.signer.public_key().public_bytes_raw()
        self.pub64 = base64.b64encode(self.pub).decode()
        self.td = pathlib.Path(tempfile.mkdtemp(prefix="l4_02_"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.td, ignore_errors=True))

    def _write(self, name, obj) -> str:
        p = self.td / name
        p.write_text(json.dumps(obj), encoding="utf-8")
        return str(p)

    def test_decision_verify_fails_closed_in_both_orders(self):
        for label, stmt in _both_orders(build_decision_statement(DEC_PRED)).items():
            with self.subTest(order=label):
                r = verify_decision_receipt(_sign(stmt, self.signer), self.pub,
                                            require_derived_subject=True)
                self.assertEqual(r["subject_binding"]["mode"], "AMBIGUOUS", r["subject_binding"])
                self.assertFalse(r["subject_derived_ok"])
                self.assertFalse(r["ok"])

    def test_outcome_verify_fails_closed_and_blocks_automation(self):
        """The finding's own measurement: safeForAutomation was TRUE on a multi-subject outcome."""
        for label, stmt in _both_orders(build_outcome_statement(OUT_PRED)).items():
            with self.subTest(order=label):
                r = verify_outcome_receipt(_sign(stmt, self.signer), self.pub,
                                           require_derived_subject=True)
                self.assertEqual(r["subject_binding"]["mode"], "AMBIGUOUS")
                self.assertFalse(r["subject_derived_ok"])
                self.assertFalse(r["automation"]["safeForAutomation"],
                                 "an ambiguous subject reached safeForAutomation=true")

    def test_relation_statement_verify_fails_closed_in_both_orders(self):
        for label, stmt in _both_orders(build_relation_statement(REL_PRED)).items():
            with self.subTest(order=label):
                r = verify_relation_statement(_sign(stmt, self.signer), self.pub,
                                              require_derived_subject=True)
                self.assertEqual(r["subject_binding"]["mode"], "AMBIGUOUS")
                self.assertFalse(r["subject_derived_ok"])
                self.assertFalse(r["ok"])

    def test_the_cli_exits_2_and_agrees_with_the_resolver(self):
        """BOTH SIDES OF THE SEAM, on the same bytes: the statement under verification and the same
        statement attached as a target must reach the same word."""
        import contextlib
        import io
        stmt = _both_orders(build_outcome_statement(OUT_PRED))["derived_first"]
        env = _sign(stmt, self.signer)
        path = self._write("outcome_multi.json", env)
        out = io.StringIO()
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                rc = cli_main(["outcome", "verify", path, "--pub", self.pub64, "--json",
                               "--require-derived-subject"])
        except SystemExit as e:  # pragma: no cover
            rc = e.code
        self.assertEqual(rc, 2, out.getvalue())
        self.assertEqual(json.loads(out.getvalue())["subject_binding"]["mode"], "AMBIGUOUS")
        related, _errs = _load_related([path], self.pub, None)
        self.assertEqual(list(related.values())[0]["subject_digest_state"], "ambiguous",
                         "the resolver and the verifier disagree about the same bytes")

    def test_a_single_subject_receipt_still_passes_the_gate(self):
        """ANTI-PARITY on the verify paths: the ordinary receipt is untouched."""
        r = verify_decision_receipt(_sign(build_decision_statement(DEC_PRED), self.signer), self.pub,
                                    require_derived_subject=True)
        self.assertEqual(r["subject_binding"]["mode"], "DERIVED")
        self.assertTrue(r["subject_derived_ok"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
