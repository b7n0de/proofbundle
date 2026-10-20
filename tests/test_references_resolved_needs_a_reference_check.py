"""`automation.referencesResolved` is True only when a reference check ran.

WHERE THIS COMES FROM. Finding L1-SEM-02 of the deep gate of 2026-07-31 (branch
fix/never-raise-message-rendering, which never landed): `referencesResolved` was vacuously true when nothing
was resolved. The second reading of the SEM-03 change measured it again on main 570dd164 on 2026-10-18:
`automation_summary` returned True with every reference field None, and so did a signed decision receipt
whose `evidenceRefs` is empty. The owner decided the same day (OA-59340782ce, A) to carry the fix.

WHAT IS PINNED. With every listed reference field None the dimension is None, as with no field listed; one
True among Nones is True; one unresolved field is False and blocks. `safeForAutomation` and the blockers
are the same as before in every case: only the label of a dimension in which no check ran moves.

Run against main 570dd164, every case whose name does not start with `test_control` fails; the controls
pass there and here.
"""
from __future__ import annotations

import copy
import itertools
import json
import pathlib
import unittest

from proofbundle.automation_verdict import automation_summary
from proofbundle.emit import generate_signer

REPO = pathlib.Path(__file__).resolve().parents[1]
_GRUND = {"crypto_ok": True, "structure_ok": True}


def _checks(namen: list) -> dict:
    return {"crypto": "crypto_ok", "structure": "structure_ok", "policy": None, "references": namen}


class TheSummary(unittest.TestCase):

    def test_every_reference_field_none_reads_none(self):
        for namen in (["a"], ["a", "b"], ["evidence_bound", "audience_ok", "nonce_ok"]):
            with self.subTest(references=namen):
                r = automation_summary({**_GRUND, **dict.fromkeys(namen)}, required_checks=_checks(namen))
                self.assertIsNone(r["referencesResolved"])
                self.assertIs(r["safeForAutomation"], True)
                self.assertEqual(r["automationBlockers"], [])

    def test_a_listed_field_absent_from_the_result_reads_none(self):
        """An absent field reads as None, so a result that carries none of its reference fields ran no
        reference check either."""
        r = automation_summary(dict(_GRUND), required_checks=_checks(["a", "b"]))
        self.assertIsNone(r["referencesResolved"])
        self.assertIs(r["safeForAutomation"], True)

    def test_control_a_verdict_among_nones_is_read(self):
        for werte, erwartet, blockiert in (((True, None), True, False), ((None, True), True, False),
                                          ((False, None), False, True), ((True, False), False, True)):
            with self.subTest(werte=werte):
                r = automation_summary({**_GRUND, "a": werte[0], "b": werte[1]}, required_checks=_checks(["a", "b"]))
                self.assertIs(r["referencesResolved"], erwartet)
                self.assertIs("REFERENCES_NOT_RESOLVED" in r["automationBlockers"], blockiert)

    def test_control_no_field_listed_and_a_foreign_shape_are_as_before(self):
        self.assertIsNone(automation_summary(dict(_GRUND), required_checks=_checks([]))["referencesResolved"])
        fremd = automation_summary(dict(_GRUND), required_checks=_checks("evidence_bound"))
        self.assertIs(fremd["referencesResolved"], False)
        self.assertIn("REFERENCES_NOT_RESOLVED", fremd["automationBlockers"])

    def test_control_the_blockers_follow_only_an_unresolved_field(self):
        """The oracle of this file, independent of the code: a reference blocks exactly when one listed
        field is neither None nor True. Over every combination of None, True and False for three fields."""
        namen = ["a", "b", "c"]
        for werte in itertools.product((None, True, False), repeat=3):
            with self.subTest(werte=werte):
                r = automation_summary({**_GRUND, **dict(zip(namen, werte))}, required_checks=_checks(namen))
                blockiert = any(w is False for w in werte)
                self.assertIs(r["safeForAutomation"], not blockiert)
                self.assertEqual(r["automationBlockers"], ["REFERENCES_NOT_RESOLVED"] if blockiert else [])


class TheDecisionPath(unittest.TestCase):

    def test_a_signed_decision_receipt_without_evidence_refs_reads_none(self):
        from proofbundle.decision import emit_decision_receipt, verify_decision_receipt
        sk = generate_signer()
        pub = sk.public_key().public_bytes_raw()
        base = json.loads((REPO / "examples" / "decision_receipt_deny.json").read_text(encoding="utf-8"))
        pred = copy.deepcopy(base)
        pred["evidenceRefs"] = []
        r = verify_decision_receipt(emit_decision_receipt(pred, sk, strict=True), pub, strict=True)
        self.assertIs(r["crypto_ok"], True, r["errors"])
        self.assertIsNone(r["automation"]["referencesResolved"], r["automation"])

    def test_control_the_example_with_its_evidence_reads_true(self):
        from proofbundle.decision import emit_decision_receipt, verify_decision_receipt
        sk = generate_signer()
        pub = sk.public_key().public_bytes_raw()
        base = json.loads((REPO / "examples" / "decision_receipt_deny.json").read_text(encoding="utf-8"))
        r = verify_decision_receipt(emit_decision_receipt(base, sk, strict=True), pub, strict=True)
        self.assertIs(r["crypto_ok"], True, r["errors"])
        self.assertIs(r["automation"]["referencesResolved"], True, r["automation"])


if __name__ == "__main__":
    unittest.main()
