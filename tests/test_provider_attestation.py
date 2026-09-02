"""Provider attestation adapter: the shim from provider evidence to the EAT we already verify."""
from __future__ import annotations

import copy
import unittest

from proofbundle.experimental import provider_attestation as PA


def _evidence(**over):
    ev = {
        "runtime_quote": "tdx+nvidia-quote",
        "response_binding": {"request_hash": "a" * 64, "response_hash": "b" * 64},
        "attested_model_hash": "c" * 64,
        "verifier_key": b"\x01\x02\x03",
        "client_nonce": "our-nonce",
        "attestation_result_jws": "h.p.s",
    }
    ev.update(over)
    return ev


class RequiredPartsAreNamedIndividually(unittest.TestCase):
    def test_complete_evidence(self):
        self.assertTrue(PA.evidence_completeness(_evidence())["complete"])

    def test_a_missing_runtime_quote_is_named(self):
        ev = _evidence()
        del ev["runtime_quote"]
        self.assertEqual(PA.evidence_completeness(ev)["missing_required"], ["runtime_quote"])

    def test_a_missing_response_binding_is_named(self):
        ev = _evidence()
        del ev["response_binding"]
        self.assertEqual(PA.evidence_completeness(ev)["missing_required"], ["response_binding"])

    def test_a_half_binding_does_not_count(self):
        """A request hash without a response hash binds nothing."""
        ev = _evidence(response_binding={"request_hash": "a" * 64})
        self.assertEqual(PA.evidence_completeness(ev)["missing_required"], ["response_binding"])

    def test_a_model_name_beside_the_structure_is_not_model_identity(self):
        ev = _evidence()
        del ev["attested_model_hash"]
        ev["model"] = "some-model-name"
        self.assertEqual(PA.evidence_completeness(ev)["missing_required"], ["model_identity"])

    def test_a_runtime_hash_also_establishes_model_identity(self):
        ev = _evidence()
        del ev["attested_model_hash"]
        ev["attested_runtime_hash"] = "d" * 64
        self.assertTrue(PA.evidence_completeness(ev)["complete"])

    def test_unverifiable_is_distinct_from_absent(self):
        ev = _evidence()
        del ev["verifier_key"]
        parts = PA.evidence_completeness(ev)["parts"]
        self.assertEqual(parts["verifiable"], "unverifiable")
        self.assertNotEqual(parts["verifiable"], "absent")

    def test_a_missing_client_nonce_is_reported_but_not_fatal(self):
        ev = _evidence()
        del ev["client_nonce"]
        c = PA.evidence_completeness(ev)
        self.assertEqual(c["parts"]["client_nonce"], "absent")
        self.assertTrue(c["complete"])

    def test_non_mapping_evidence(self):
        self.assertFalse(PA.evidence_completeness("not a dict")["complete"])


class TheBindingTiesEvidenceToThisAnswer(unittest.TestCase):
    def test_ready_when_everything_lines_up(self):
        self.assertTrue(PA.to_attestation_result_input(_evidence(), expected_binding="B")["ready"])

    def test_evidence_for_a_different_answer_is_refused(self):
        ev = _evidence()
        ev["response_binding"]["receipt_binding"] = "SOME-OTHER-BINDING"
        out = PA.to_attestation_result_input(ev, expected_binding="B")
        self.assertFalse(out["ready"])
        self.assertIn("different answer", out["detail"])

    def test_a_matching_binding_is_accepted(self):
        ev = _evidence()
        ev["response_binding"]["receipt_binding"] = "B"
        self.assertTrue(PA.to_attestation_result_input(ev, expected_binding="B")["ready"])

    def test_no_attestation_result_means_not_ready(self):
        ev = _evidence()
        del ev["attestation_result_jws"]
        self.assertFalse(PA.to_attestation_result_input(ev, expected_binding="B")["ready"])

    def test_no_verifier_key_means_not_ready(self):
        ev = _evidence()
        del ev["verifier_key"]
        out = PA.to_attestation_result_input(ev, expected_binding="B")
        self.assertFalse(out["ready"])
        self.assertIn("unchecked signature", out["detail"])


class AssuranceFailsClosedDownward(unittest.TestCase):
    def test_verified_evidence_is_provider_attested(self):
        self.assertEqual(PA.assurance_for(_evidence(), verification_ok=True)["assurance"],
                         "provider_attested")

    def test_unchecked_verification_is_not_attestation(self):
        r = PA.assurance_for(_evidence(), verification_ok=None)
        self.assertEqual(r["assurance"], "self_reported")
        self.assertIn("NOT PERFORMED", r["reason"])

    def test_failed_verification_is_not_attestation(self):
        self.assertEqual(PA.assurance_for(_evidence(), verification_ok=False)["assurance"],
                         "self_reported")

    def test_no_evidence_at_all(self):
        self.assertEqual(PA.assurance_for(None, verification_ok=True)["assurance"],
                         "self_reported")

    def test_incomplete_evidence_cannot_be_promoted_by_a_passing_check(self):
        ev = _evidence()
        del ev["response_binding"]
        self.assertEqual(PA.assurance_for(ev, verification_ok=True)["assurance"], "self_reported")


class TheEvidenceDigestIsStable(unittest.TestCase):
    def test_same_evidence_same_digest(self):
        self.assertEqual(PA.provider_evidence_digest(_evidence()),
                         PA.provider_evidence_digest(_evidence()))

    def test_key_order_does_not_move_it(self):
        a = _evidence()
        b = {k: a[k] for k in reversed(list(a))}
        self.assertEqual(PA.provider_evidence_digest(a), PA.provider_evidence_digest(b))

    def test_a_changed_value_moves_it(self):
        a = _evidence()
        b = copy.deepcopy(a)
        b["attested_model_hash"] = "e" * 64
        self.assertNotEqual(PA.provider_evidence_digest(a), PA.provider_evidence_digest(b))

    def test_bytes_do_not_raise(self):
        """Found by the module's own first run: the verifier key is bytes."""
        PA.provider_evidence_digest({"k": b"\x00\xff"})


if __name__ == "__main__":
    unittest.main()
