"""3.2.0 O4 Verification Summary — fail-closed validate + DSSE round-trip + No-Overclaim honesty.

unittest-style to match the repo's `python -m unittest discover`.
"""
from __future__ import annotations

import base64
import copy
import json
import unittest

from proofbundle import dsse
from proofbundle.emit import generate_signer
from proofbundle.verification_summary import (
    INTOTO_STATEMENT_PAYLOAD_TYPE,
    VerificationSummaryError,
    _rfc8785_bytes,
    build_summary_statement,
    emit_verification_summary,
    validate_summary_predicate,
    verify_verification_summary,
)

_R = "d" * 64


def _pred(**over) -> dict:
    p = {
        "schemaVersion": "0.1.0",
        "summaryId": "summary-0001",
        "producedAt": "2026-07-14T10:00:00Z",
        "producer": {"id": "verifier://example/summarizer"},
        "levels": [
            {"kind": "eval", "receiptRef": {"sha256": "a" * 64}, "status": "VERIFIED",
             "evidenceClass": "authorship_integrity", "checks": ["crypto", "merkle"]},
            {"kind": "decision", "receiptRef": {"sha256": "b" * 64}, "status": "VERIFIED",
             "evidenceClass": "decision_claim"},
            {"kind": "outcome", "receiptRef": {"sha256": "c" * 64}, "status": "VERIFIED",
             "evidenceClass": "outcome_claim"},
        ],
        "nonClaims": [
            "does not prove the eval number is true",
            "does not prove the decision was correct",
            "does not prove the effect was good or desired",
        ],
    }
    p.update(over)
    return p


def _keys():
    s = generate_signer()
    return s, s.public_key().public_bytes_raw()


def _repayload(env: dict, statement: dict) -> dict:
    env = copy.deepcopy(env)
    env["payload"] = base64.b64encode(json.dumps(statement).encode()).decode()
    return env


class TestSummaryValidate(unittest.TestCase):
    def test_valid_predicate(self):
        self.assertEqual(validate_summary_predicate(_pred()), [])

    def test_nonclaims_mandatory(self):
        p = _pred()
        del p["nonClaims"]
        errs = validate_summary_predicate(p)
        self.assertTrue(any("nonClaims" in e for e in errs), errs)

    def test_empty_nonclaims_rejected(self):
        errs = validate_summary_predicate(_pred(nonClaims=[]))
        self.assertTrue(any("nonClaims" in e for e in errs), errs)

    def test_unknown_field_fails_closed(self):
        errs = validate_summary_predicate(_pred(extra=1))
        self.assertTrue(any("additionalProperties" in e for e in errs), errs)

    def test_bad_level_kind_fails(self):
        p = _pred()
        p["levels"][0]["kind"] = "receiver"
        errs = validate_summary_predicate(p)
        self.assertTrue(any("kind" in e for e in errs), errs)

    def test_bad_status_fails(self):
        p = _pred()
        p["levels"][0]["status"] = "MAYBE"
        errs = validate_summary_predicate(p)
        self.assertTrue(any("status" in e for e in errs), errs)

    def test_not_evaluated_level_may_omit_receiptref(self):
        # a NOT_EVALUATED level legitimately references no receipt → structurally valid.
        p = _pred()
        p["levels"][0] = {"kind": "eval", "status": "NOT_EVALUATED", "evidenceClass": "authorship_integrity"}
        self.assertEqual(validate_summary_predicate(p), [])

    def test_empty_levels_rejected(self):
        errs = validate_summary_predicate(_pred(levels=[]))
        self.assertTrue(any("levels" in e for e in errs), errs)

    def test_emit_rejects_invalid(self):
        s, _ = _keys()
        with self.assertRaises(VerificationSummaryError):
            emit_verification_summary(_pred(nonClaims=[]), s)


class TestSummaryVerify(unittest.TestCase):
    def test_roundtrip_green(self):
        s, pub = _keys()
        env = emit_verification_summary(_pred(), s)
        r = verify_verification_summary(env, pub, strict=True)
        self.assertTrue(r["ok"], r)
        self.assertTrue(r["crypto_ok"] and r["structure_ok"] and r["predicate_type_ok"])
        self.assertTrue(r["levels_consistent"])

    def test_tamper_breaks_crypto(self):
        s, pub = _keys()
        env = emit_verification_summary(_pred(), s)
        forged = _repayload(env, build_summary_statement(_pred(summaryId="X")))
        r = verify_verification_summary(forged, pub)
        self.assertFalse(r["ok"])
        self.assertFalse(r["crypto_ok"])

    def test_wrong_key_fails(self):
        s, _ = _keys()
        _, other = _keys()
        env = emit_verification_summary(_pred(), s)
        r = verify_verification_summary(env, other)
        self.assertFalse(r["ok"])

    def test_predicate_type_confusion_fails(self):
        s, pub = _keys()
        stmt = build_summary_statement(_pred())
        stmt["predicateType"] = "https://in-toto.io/attestation/vulns"
        env = dsse.sign_envelope(_rfc8785_bytes(stmt), s, payload_type=INTOTO_STATEMENT_PAYLOAD_TYPE)
        r = verify_verification_summary(env, pub)
        self.assertFalse(r["predicate_type_ok"])
        self.assertFalse(r["ok"])

    def test_verified_without_receiptref_is_inconsistent(self):
        # honesty check (levels_consistent): a level marked VERIFIED WITHOUT a receiptRef passes structural
        # validate (receiptRef is optional) but must fail verify — a summary cannot claim to have verified a
        # receipt it does not reference. This is signed+verified end to end (real fail path, not tautology).
        s, pub = _keys()
        p = _pred()
        p["levels"][0] = {"kind": "eval", "status": "VERIFIED", "evidenceClass": "authorship_integrity"}
        self.assertEqual(validate_summary_predicate(p), [])   # structurally valid
        env = emit_verification_summary(p, s)                 # emits fine
        r = verify_verification_summary(env, pub, strict=True)
        self.assertFalse(r["levels_consistent"])
        self.assertFalse(r["ok"])
        self.assertTrue(any("VERIFIED" in e and "receiptRef" in e for e in r["errors"]), r["errors"])

    def test_not_evaluated_without_receiptref_stays_consistent(self):
        # counter-side: a NOT_EVALUATED level without receiptRef is NOT an inconsistency (no over-fire).
        s, pub = _keys()
        p = _pred()
        p["levels"][0] = {"kind": "eval", "status": "NOT_EVALUATED", "evidenceClass": "authorship_integrity"}
        env = emit_verification_summary(p, s)
        r = verify_verification_summary(env, pub, strict=True)
        self.assertTrue(r["levels_consistent"])
        self.assertTrue(r["ok"], r)


if __name__ == "__main__":
    unittest.main()
